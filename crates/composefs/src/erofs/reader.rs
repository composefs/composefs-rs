//! EROFS image reading and parsing functionality.
//!
//! This module provides safe parsing and navigation of EROFS filesystem
//! images, including inode traversal, directory reading, and object
//! reference collection for garbage collection.

use core::mem::size_of;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::ops::Range;
use std::os::unix::ffi::OsStrExt;

use anyhow::Context;
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, KnownLayout, little_endian::U32};

use super::{
    composefs::OverlayMetacopy,
    format::{
        self, BLOCK_BITS, COMPOSEFS_MAGIC, CompactInodeHeader, ComposefsHeader, DataLayout,
        DirectoryEntryHeader, ExtendedInodeHeader, InodeXAttrHeader, MAGIC_V1, ModeField, S_IFBLK,
        S_IFCHR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, Superblock, VERSION, XATTR_PREFIXES,
        XAttrHeader,
    },
};
use crate::MAX_INLINE_CONTENT;
use crate::fsverity::FsVerityHashValue;
use crate::generic_tree::LeafId;
use crate::tree;

/// Rounds up a value to the nearest multiple of `to`
pub fn round_up(n: usize, to: usize) -> usize {
    (n + to - 1) & !(to - 1)
}

/// Common interface for accessing inode header fields across different layouts
pub trait InodeHeader {
    /// Returns the data layout method used by this inode
    fn data_layout(&self) -> Result<DataLayout, ErofsReaderError>;
    /// Returns the extended attribute inode count
    fn xattr_icount(&self) -> u16;
    /// Returns the file mode
    fn mode(&self) -> ModeField;
    /// Returns the file size in bytes
    fn size(&self) -> u64;
    /// Returns the union field value (block address, device number, etc.)
    fn u(&self) -> u32;
    /// Returns the number of hard links
    fn nlink(&self) -> u32;

    /// Returns the device number (alias for u())
    fn rdev(&self) -> u32 {
        self.u()
    }

    /// Returns true if this inode is a whiteout entry (character device with rdev == 0).
    fn is_whiteout(&self) -> bool {
        let mode = self.mode().0.get();
        (mode & S_IFMT == S_IFCHR) && (self.rdev() == 0)
    }

    /// Calculates the number of additional bytes after the header
    fn additional_bytes(&self, blkszbits: u8) -> Result<usize, ErofsReaderError> {
        let block_size: usize = 1usize
            .checked_shl(blkszbits.into())
            .ok_or_else(|| ErofsReaderError::InvalidImage("blkszbits overflow".into()))?;
        let data_layout = self.data_layout()?;
        Ok(self.xattr_size()
            + match data_layout {
                DataLayout::FlatPlain => 0,
                DataLayout::FlatInline => {
                    let size = usize::try_from(self.size()).map_err(|_| {
                        ErofsReaderError::InvalidImage("inode size too large for platform".into())
                    })?;
                    size % block_size
                }
                DataLayout::ChunkBased => 4,
            })
    }

    /// Calculates the size of the extended attributes section
    fn xattr_size(&self) -> usize {
        match self.xattr_icount() {
            0 => 0,
            n => (n as usize - 1) * 4 + 12,
        }
    }
}

impl InodeHeader for ExtendedInodeHeader {
    fn data_layout(&self) -> Result<DataLayout, ErofsReaderError> {
        self.format.try_into().map_err(|_| {
            ErofsReaderError::InvalidImage("invalid data layout in inode format".into())
        })
    }

    fn xattr_icount(&self) -> u16 {
        self.xattr_icount.get()
    }

    fn mode(&self) -> ModeField {
        self.mode
    }

    fn size(&self) -> u64 {
        self.size.get()
    }

    fn u(&self) -> u32 {
        self.u.get()
    }

    fn nlink(&self) -> u32 {
        self.nlink.get()
    }
}

impl InodeHeader for CompactInodeHeader {
    fn data_layout(&self) -> Result<DataLayout, ErofsReaderError> {
        self.format.try_into().map_err(|_| {
            ErofsReaderError::InvalidImage("invalid data layout in inode format".into())
        })
    }

    fn xattr_icount(&self) -> u16 {
        self.xattr_icount.get()
    }

    fn mode(&self) -> ModeField {
        self.mode
    }

    fn size(&self) -> u64 {
        self.size.get() as u64
    }

    fn u(&self) -> u32 {
        self.u.get()
    }

    fn nlink(&self) -> u32 {
        self.nlink.get().into()
    }
}

/// Extended attribute entry with header and variable-length data
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct XAttr {
    /// Extended attribute header
    pub header: XAttrHeader,
    /// Variable-length data containing name suffix and value
    pub data: [u8],
}

/// Inode structure with header and variable-length data
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct Inode<Header: InodeHeader> {
    /// Inode header (compact or extended)
    pub header: Header,
    /// Variable-length data containing xattrs and inline content
    pub data: [u8],
}

/// Extended attributes section of an inode
#[repr(C)]
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
pub struct InodeXAttrs {
    /// Extended attributes header
    pub header: InodeXAttrHeader,
    /// Variable-length data containing shared xattr refs and local xattrs
    pub data: [u8],
}

impl XAttrHeader {
    /// Calculates the total size of this xattr including padding
    pub fn calculate_n_elems(&self) -> usize {
        round_up(self.name_len as usize + self.value_size.get() as usize, 4)
    }
}

impl XAttr {
    /// Parses an xattr from a byte slice, returning the xattr and remaining bytes
    pub fn from_prefix(data: &[u8]) -> Result<(&XAttr, &[u8]), ErofsReaderError> {
        let header =
            XAttrHeader::ref_from_bytes(data.get(..4).ok_or(ErofsReaderError::OutOfBounds)?)
                .map_err(|_| ErofsReaderError::OutOfBounds)?;
        Self::ref_from_prefix_with_elems(data, header.calculate_n_elems())
            .map_err(|_| ErofsReaderError::OutOfBounds)
    }

    /// Returns the attribute name suffix
    pub fn suffix(&self) -> Result<&[u8], ErofsReaderError> {
        self.data
            .get(..self.header.name_len as usize)
            .ok_or(ErofsReaderError::OutOfBounds)
    }

    /// Returns the attribute value
    pub fn value(&self) -> Result<&[u8], ErofsReaderError> {
        let name_len = self.header.name_len as usize;
        let value_size = self.header.value_size.get() as usize;
        self.data
            .get(name_len..name_len + value_size)
            .ok_or(ErofsReaderError::OutOfBounds)
    }

    /// Returns the padding bytes after the value
    pub fn padding(&self) -> Result<&[u8], ErofsReaderError> {
        let end = self.header.name_len as usize + self.header.value_size.get() as usize;
        self.data.get(end..).ok_or(ErofsReaderError::OutOfBounds)
    }
}

/// Operations on inode data
pub trait InodeOps {
    /// Returns the extended attributes section if present
    fn xattrs(&self) -> Result<Option<&InodeXAttrs>, ErofsReaderError>;
    /// Returns the inline data portion
    fn inline(&self) -> Option<&[u8]>;
    /// Returns the raw range of block IDs used by this inode without
    /// validating against the image size.
    ///
    /// Callers that iterate blocks should prefer [`Image::inode_blocks`] which
    /// validates the range.
    fn raw_blocks(&self, blkszbits: u8) -> Result<Range<u64>, ErofsReaderError>;
}

impl<Header: InodeHeader> InodeHeader for &Inode<Header> {
    fn data_layout(&self) -> Result<DataLayout, ErofsReaderError> {
        self.header.data_layout()
    }

    fn xattr_icount(&self) -> u16 {
        self.header.xattr_icount()
    }

    fn mode(&self) -> ModeField {
        self.header.mode()
    }

    fn size(&self) -> u64 {
        self.header.size()
    }

    fn u(&self) -> u32 {
        self.header.u()
    }

    fn nlink(&self) -> u32 {
        self.header.nlink()
    }
}

impl<Header: InodeHeader> InodeOps for &Inode<Header> {
    fn xattrs(&self) -> Result<Option<&InodeXAttrs>, ErofsReaderError> {
        match self.header.xattr_size() {
            0 => Ok(None),
            n => {
                let data = self.data.get(..n).ok_or(ErofsReaderError::OutOfBounds)?;
                Ok(Some(
                    InodeXAttrs::ref_from_bytes(data).map_err(|_| ErofsReaderError::OutOfBounds)?,
                ))
            }
        }
    }

    fn inline(&self) -> Option<&[u8]> {
        let data = self.data.get(self.header.xattr_size()..)?;

        if data.is_empty() {
            return None;
        }

        Some(data)
    }

    fn raw_blocks(&self, blkszbits: u8) -> Result<Range<u64>, ErofsReaderError> {
        let size = self.header.size();
        let block_size: u64 = 1u64
            .checked_shl(blkszbits.into())
            .ok_or_else(|| ErofsReaderError::InvalidImage("blkszbits overflow".into()))?;
        let start = self.header.u() as u64;
        let data_layout = self.header.data_layout()?;

        Ok(match data_layout {
            DataLayout::FlatPlain => Range {
                start,
                end: start
                    .checked_add(size.div_ceil(block_size))
                    .ok_or_else(|| ErofsReaderError::InvalidImage("block range overflow".into()))?,
            },
            DataLayout::FlatInline => Range {
                start,
                end: start
                    .checked_add(size / block_size)
                    .ok_or_else(|| ErofsReaderError::InvalidImage("block range overflow".into()))?,
            },
            DataLayout::ChunkBased => Range { start, end: start },
        })
    }
}

// this lets us avoid returning Box<dyn InodeOp> from Image.inode()
// but ... wow.
/// Inode type enum allowing static dispatch for different header layouts
#[derive(Debug)]
pub enum InodeType<'img> {
    /// Compact inode with 32-byte header
    Compact(&'img Inode<CompactInodeHeader>),
    /// Extended inode with 64-byte header
    Extended(&'img Inode<ExtendedInodeHeader>),
}

impl InodeHeader for InodeType<'_> {
    fn u(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.u(),
            Self::Extended(inode) => inode.u(),
        }
    }

    fn size(&self) -> u64 {
        match self {
            Self::Compact(inode) => inode.size(),
            Self::Extended(inode) => inode.size(),
        }
    }

    fn xattr_icount(&self) -> u16 {
        match self {
            Self::Compact(inode) => inode.xattr_icount(),
            Self::Extended(inode) => inode.xattr_icount(),
        }
    }

    fn data_layout(&self) -> Result<DataLayout, ErofsReaderError> {
        match self {
            Self::Compact(inode) => inode.data_layout(),
            Self::Extended(inode) => inode.data_layout(),
        }
    }

    fn mode(&self) -> ModeField {
        match self {
            Self::Compact(inode) => inode.mode(),
            Self::Extended(inode) => inode.mode(),
        }
    }

    fn nlink(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.nlink(),
            Self::Extended(inode) => inode.nlink(),
        }
    }
}

impl InodeOps for InodeType<'_> {
    fn xattrs(&self) -> Result<Option<&InodeXAttrs>, ErofsReaderError> {
        match self {
            Self::Compact(inode) => inode.xattrs(),
            Self::Extended(inode) => inode.xattrs(),
        }
    }

    fn inline(&self) -> Option<&[u8]> {
        match self {
            Self::Compact(inode) => inode.inline(),
            Self::Extended(inode) => inode.inline(),
        }
    }

    fn raw_blocks(&self, blkszbits: u8) -> Result<Range<u64>, ErofsReaderError> {
        match self {
            Self::Compact(inode) => inode.raw_blocks(blkszbits),
            Self::Extended(inode) => inode.raw_blocks(blkszbits),
        }
    }
}

/// Parsed EROFS image with references to key structures
#[derive(Debug)]
pub struct Image<'i> {
    /// Raw image bytes
    pub image: &'i [u8],
    /// Composefs header
    pub header: &'i ComposefsHeader,
    /// Block size in bits
    pub blkszbits: u8,
    /// Block size in bytes
    pub block_size: usize,
    /// Superblock
    pub sb: &'i Superblock,
    /// Inode metadata region
    pub inodes: &'i [u8],
    /// Extended attributes region
    pub xattrs: &'i [u8],
    /// When true, enforce composefs-specific invariants.
    composefs_restricted: bool,
}

/// Default maximum image size (1 GiB). Composefs images are metadata-only
/// and should never approach this in practice.
pub const DEFAULT_MAX_IMAGE_SIZE: usize = 1 << 30;

impl<'img> Image<'img> {
    /// Opens an EROFS image from raw bytes, rejecting images larger than
    /// [`DEFAULT_MAX_IMAGE_SIZE`].
    pub fn open(image: &'img [u8]) -> Result<Self, ErofsReaderError> {
        Self::open_max_size(image, DEFAULT_MAX_IMAGE_SIZE)
    }

    /// Opens an EROFS image with a caller-specified maximum size.
    pub fn open_max_size(image: &'img [u8], max_size: usize) -> Result<Self, ErofsReaderError> {
        if image.len() > max_size {
            return Err(ErofsReaderError::InvalidImage(format!(
                "image size {} exceeds maximum {max_size}",
                image.len(),
            )));
        }
        let header = ComposefsHeader::ref_from_prefix(image)
            .map_err(|_| ErofsReaderError::InvalidImage("cannot parse header".into()))?
            .0;
        let sb_data = image.get(1024..).ok_or_else(|| {
            ErofsReaderError::InvalidImage("image too small for superblock".into())
        })?;
        let sb = Superblock::ref_from_prefix(sb_data)
            .map_err(|_| ErofsReaderError::InvalidImage("cannot parse superblock".into()))?
            .0;
        let blkszbits = sb.blkszbits;
        if blkszbits as u32 >= usize::BITS {
            return Err(ErofsReaderError::InvalidImage(format!(
                "blkszbits {blkszbits} >= platform word size {}",
                usize::BITS
            )));
        }
        let block_size = 1usize << blkszbits;
        let inodes_start = (sb.meta_blkaddr.get() as usize)
            .checked_mul(block_size)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let xattrs_start = (sb.xattr_blkaddr.get() as usize)
            .checked_mul(block_size)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let inodes = image
            .get(inodes_start..)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let xattrs = image
            .get(xattrs_start..)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        Ok(Image {
            image,
            header,
            blkszbits,
            block_size,
            sb,
            inodes,
            xattrs,
            composefs_restricted: false,
        })
    }

    /// Enable composefs-specific validation.
    ///
    /// Composefs images are metadata-only EROFS images with well-known
    /// structural constraints.  When enabled, the parser enforces:
    ///
    /// Checked eagerly (in this method):
    /// - Composefs header magic and version fields
    /// - EROFS superblock magic and `blkszbits == 12`
    /// - No unsupported EROFS features (compression, multi-device,
    ///   fragments, 48-bit addressing, metabox, etc.)
    /// - `meta_blkaddr == 0`, `extslots == 0`, `packed_nid == 0`
    /// - No custom xattr prefixes
    ///
    /// Checked during inode traversal (`inode_blocks`, `erofs_to_filesystem`):
    /// - For non-ChunkBased inodes, `size` must not exceed the image size
    /// - Inline regular files must be ≤ `MAX_INLINE_CONTENT` (512 bytes)
    /// - Metacopy xattrs must be well-formed when present
    pub fn restrict_to_composefs(mut self) -> Result<Self, ErofsReaderError> {
        // Validate composefs header
        if self.header.magic != COMPOSEFS_MAGIC {
            return Err(ErofsReaderError::InvalidImage(format!(
                "bad composefs magic: expected {:#x}, got {:#x}",
                COMPOSEFS_MAGIC.get(),
                self.header.magic.get(),
            )));
        }
        if self.header.version != VERSION {
            return Err(ErofsReaderError::InvalidImage(format!(
                "bad EROFS format version in composefs header: expected {}, got {}",
                VERSION.get(),
                self.header.version.get(),
            )));
        }
        // Note: we don't enforce composefs_version here because C mkcomposefs
        // writes version 0 while the Rust writer uses version 2.  Both are valid.

        // Validate EROFS superblock magic
        if self.sb.magic != MAGIC_V1 {
            return Err(ErofsReaderError::InvalidImage(format!(
                "bad EROFS magic: expected {:#x}, got {:#x}",
                MAGIC_V1.get(),
                self.sb.magic.get(),
            )));
        }
        if self.blkszbits != BLOCK_BITS {
            return Err(ErofsReaderError::InvalidImage(format!(
                "composefs requires blkszbits={BLOCK_BITS}, got {}",
                self.blkszbits,
            )));
        }

        // Reject unknown or unsupported feature_compat flags.
        let compat = self.sb.feature_compat.get();
        let unknown_compat = compat & !format::FEATURE_COMPAT_SUPPORTED;
        if unknown_compat != 0 {
            return Err(ErofsReaderError::InvalidImage(format!(
                "unsupported feature_compat flags: {unknown_compat:#x}",
            )));
        }

        // Reject all feature_incompat flags except CHUNKED_FILE (used for
        // external files).  This blocks compression, multi-device, fragments,
        // 48-bit addressing, metabox, and any future features.
        let incompat = self.sb.feature_incompat.get();
        let unsupported_incompat = incompat & !format::FEATURE_INCOMPAT_CHUNKED_FILE;
        if unsupported_incompat != 0 {
            return Err(ErofsReaderError::InvalidImage(format!(
                "unsupported feature_incompat flags: {unsupported_incompat:#x}",
            )));
        }

        // composefs is uncompressed
        if self.sb.available_compr_algs.get() != 0 {
            return Err(ErofsReaderError::InvalidImage(
                "composefs does not support compression".into(),
            ));
        }

        // No multi-device support
        if self.sb.extra_devices.get() != 0 {
            return Err(ErofsReaderError::InvalidImage(format!(
                "composefs does not support multi-device (extra_devices={})",
                self.sb.extra_devices.get(),
            )));
        }

        // No superblock extension slots
        if self.sb.extslots != 0 {
            return Err(ErofsReaderError::InvalidImage(format!(
                "composefs does not support extslots (extslots={})",
                self.sb.extslots,
            )));
        }

        // No packed/fragment inode
        if self.sb.packed_nid.get() != 0 {
            return Err(ErofsReaderError::InvalidImage(format!(
                "composefs does not support packed inodes (packed_nid={})",
                self.sb.packed_nid.get(),
            )));
        }

        // Inodes start in block 0 (shared with the superblock)
        if self.sb.meta_blkaddr.get() != 0 {
            return Err(ErofsReaderError::InvalidImage(format!(
                "composefs requires meta_blkaddr=0, got {}",
                self.sb.meta_blkaddr.get(),
            )));
        }

        // No custom xattr prefixes
        if self.sb.xattr_prefix_count != 0 {
            return Err(ErofsReaderError::InvalidImage(format!(
                "composefs does not support custom xattr prefixes (count={})",
                self.sb.xattr_prefix_count,
            )));
        }

        self.composefs_restricted = true;
        Ok(self)
    }

    /// Returns an inode by its ID
    pub fn inode(&self, id: u64) -> Result<InodeType<'_>, ErofsReaderError> {
        let offset = usize::try_from(id)
            .ok()
            .and_then(|id| id.checked_mul(32))
            .ok_or(ErofsReaderError::InvalidInode(id))?;
        let inode_data = self
            .inodes
            .get(offset..)
            .ok_or(ErofsReaderError::InvalidInode(id))?;
        let first_byte = *inode_data
            .first()
            .ok_or(ErofsReaderError::InvalidInode(id))?;
        if first_byte & 1 != 0 {
            let header = ExtendedInodeHeader::ref_from_bytes(
                inode_data
                    .get(..64)
                    .ok_or(ErofsReaderError::InvalidInode(id))?,
            )
            .map_err(|_| ErofsReaderError::InvalidInode(id))?;
            Ok(InodeType::Extended(
                Inode::<ExtendedInodeHeader>::ref_from_prefix_with_elems(
                    inode_data,
                    header.additional_bytes(self.blkszbits)?,
                )
                .map_err(|_| ErofsReaderError::InvalidInode(id))?
                .0,
            ))
        } else {
            let header = CompactInodeHeader::ref_from_bytes(
                inode_data
                    .get(..32)
                    .ok_or(ErofsReaderError::InvalidInode(id))?,
            )
            .map_err(|_| ErofsReaderError::InvalidInode(id))?;
            Ok(InodeType::Compact(
                Inode::<CompactInodeHeader>::ref_from_prefix_with_elems(
                    inode_data,
                    header.additional_bytes(self.blkszbits)?,
                )
                .map_err(|_| ErofsReaderError::InvalidInode(id))?
                .0,
            ))
        }
    }

    /// Returns a shared extended attribute by its ID
    pub fn shared_xattr(&self, id: u32) -> Result<&XAttr, ErofsReaderError> {
        let start = (id as usize)
            .checked_mul(4)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let xattr_data = self
            .xattrs
            .get(start..)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let header =
            XAttrHeader::ref_from_bytes(xattr_data.get(..4).ok_or(ErofsReaderError::OutOfBounds)?)
                .map_err(|_| ErofsReaderError::OutOfBounds)?;
        Ok(
            XAttr::ref_from_prefix_with_elems(xattr_data, header.calculate_n_elems())
                .map_err(|_| ErofsReaderError::OutOfBounds)?
                .0,
        )
    }

    /// Returns a data block by its ID
    pub fn block(&self, id: u64) -> Result<&[u8], ErofsReaderError> {
        let start = usize::try_from(id)
            .ok()
            .and_then(|id| id.checked_mul(self.block_size))
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let end = start
            .checked_add(self.block_size)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        self.image
            .get(start..end)
            .ok_or(ErofsReaderError::OutOfBounds)
    }

    /// Returns a data block by its ID as a DataBlock reference
    pub fn data_block(&self, id: u64) -> Result<&DataBlock, ErofsReaderError> {
        DataBlock::ref_from_bytes(self.block(id)?).map_err(|_| ErofsReaderError::OutOfBounds)
    }

    /// Returns a directory block by its ID
    pub fn directory_block(&self, id: u64) -> Result<&DirectoryBlock, ErofsReaderError> {
        DirectoryBlock::ref_from_bytes(self.block(id)?).map_err(|_| ErofsReaderError::OutOfBounds)
    }

    /// Returns the root directory inode
    pub fn root(&self) -> Result<InodeType<'_>, ErofsReaderError> {
        self.inode(self.sb.root_nid.get() as u64)
    }

    /// Returns the block range for an inode, validated against the image size.
    ///
    /// This prevents crafted images from producing astronomically large block
    /// ranges that would cause iteration timeouts.
    pub fn inode_blocks(&self, inode: &InodeType) -> Result<Range<u64>, ErofsReaderError> {
        // In composefs mode, non-ChunkBased inodes store all their data
        // within the image (inline or in data blocks), so their size
        // cannot exceed the image size.  ChunkBased (external) files are
        // exempt — their size reflects the real file on the underlying fs.
        if self.composefs_restricted {
            let layout = inode.data_layout()?;
            if !matches!(layout, DataLayout::ChunkBased) {
                let size = inode.size();
                if size > self.image.len() as u64 {
                    return Err(ErofsReaderError::InvalidImage(format!(
                        "inode size {size} exceeds image size {}",
                        self.image.len(),
                    )));
                }
            }
        }
        let range = inode.raw_blocks(self.blkszbits)?;
        if !range.is_empty() {
            let max_block = (self.image.len() / self.block_size) as u64;
            if range.end > max_block {
                return Err(ErofsReaderError::InvalidImage(format!(
                    "inode block range {}..{} exceeds image ({max_block} blocks)",
                    range.start, range.end,
                )));
            }
        }
        Ok(range)
    }

    /// Finds a child directory entry by name within a directory inode.
    ///
    /// Returns the nid (inode number) of the child if found.
    pub fn find_child_nid(
        &self,
        parent_nid: u64,
        name: &[u8],
    ) -> Result<Option<u64>, ErofsReaderError> {
        let inode = self.inode(parent_nid)?;
        if let Some(inline) = inode.inline()
            && let Ok(block) = DirectoryBlock::ref_from_bytes(inline)
        {
            for entry in block.entries()? {
                let entry = entry?;
                if entry.name == name {
                    return Ok(Some(entry.nid()));
                }
            }
        }
        for blkid in self.inode_blocks(&inode)? {
            let block = self.directory_block(blkid)?;
            for entry in block.entries()? {
                let entry = entry?;
                if entry.name == name {
                    return Ok(Some(entry.nid()));
                }
            }
        }
        Ok(None)
    }
}

// TODO: there must be an easier way...
#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C)]
struct Array<T>([T]);

impl InodeXAttrs {
    /// Returns the array of shared xattr IDs
    pub fn shared(&self) -> Result<&[U32], ErofsReaderError> {
        Ok(
            &Array::ref_from_prefix_with_elems(&self.data, self.header.shared_count as usize)
                .map_err(|_| ErofsReaderError::OutOfBounds)?
                .0
                .0,
        )
    }

    /// Returns an iterator over local (non-shared) xattrs
    pub fn local(&self) -> Result<XAttrIter<'_>, ErofsReaderError> {
        let offset = (self.header.shared_count as usize)
            .checked_mul(4)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let data = self
            .data
            .get(offset..)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        Ok(XAttrIter { data })
    }
}

/// Iterator over local extended attributes
#[derive(Debug)]
pub struct XAttrIter<'img> {
    data: &'img [u8],
}

impl<'img> Iterator for XAttrIter<'img> {
    type Item = Result<&'img XAttr, ErofsReaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.data.is_empty() {
            match XAttr::from_prefix(self.data) {
                Ok((result, rest)) => {
                    self.data = rest;
                    Some(Ok(result))
                }
                Err(e) => {
                    self.data = &[]; // stop iteration on error
                    Some(Err(e))
                }
            }
        } else {
            None
        }
    }
}

/// Data block containing file content
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct DataBlock(pub [u8]);

/// Directory block containing directory entries
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct DirectoryBlock(pub [u8]);

impl DirectoryBlock {
    /// Returns the directory entry header at the given index
    pub fn get_entry_header(&self, n: usize) -> Result<&DirectoryEntryHeader, ErofsReaderError> {
        let start = n
            .checked_mul(size_of::<DirectoryEntryHeader>())
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let end = start
            .checked_add(size_of::<DirectoryEntryHeader>())
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let entry_data = self
            .0
            .get(start..end)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        DirectoryEntryHeader::ref_from_bytes(entry_data).map_err(|_| ErofsReaderError::OutOfBounds)
    }

    /// Returns all directory entry headers as a slice
    pub fn get_entry_headers(&self) -> Result<&[DirectoryEntryHeader], ErofsReaderError> {
        let n = self.n_entries()?;
        Ok(&Array::ref_from_prefix_with_elems(&self.0, n)
            .map_err(|_| ErofsReaderError::OutOfBounds)?
            .0
            .0)
    }

    /// Returns the number of entries in this directory block
    pub fn n_entries(&self) -> Result<usize, ErofsReaderError> {
        let first = self.get_entry_header(0)?;
        let offset = first.name_offset.get();
        if offset == 0 || !offset.is_multiple_of(12) {
            return Err(ErofsReaderError::InvalidImage(
                "invalid directory entry name_offset".into(),
            ));
        }
        Ok(offset as usize / 12)
    }

    /// Returns an iterator over directory entries
    pub fn entries(&self) -> Result<DirectoryEntries<'_>, ErofsReaderError> {
        let length = self.n_entries()?;
        Ok(DirectoryEntries {
            block: self,
            length,
            position: 0,
        })
    }
}

// High-level iterator interface
/// A single directory entry with header and name
#[derive(Debug)]
pub struct DirectoryEntry<'a> {
    /// Directory entry header
    pub header: &'a DirectoryEntryHeader,
    /// Entry name
    pub name: &'a [u8],
}

impl DirectoryEntry<'_> {
    /// Returns the inode ID (nid) that this directory entry points to.
    pub fn nid(&self) -> u64 {
        self.header.inode_offset.get()
    }
}

/// Iterator over directory entries in a directory block
#[derive(Debug)]
pub struct DirectoryEntries<'d> {
    block: &'d DirectoryBlock,
    length: usize,
    position: usize,
}

impl<'d> Iterator for DirectoryEntries<'d> {
    type Item = Result<DirectoryEntry<'d>, ErofsReaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position < self.length {
            let result = (|| {
                let header = self.block.get_entry_header(self.position)?;
                let name_start = header.name_offset.get() as usize;
                self.position += 1;

                let name = if self.position == self.length {
                    let with_padding = self
                        .block
                        .0
                        .get(name_start..)
                        .ok_or(ErofsReaderError::OutOfBounds)?;
                    let end = with_padding.partition_point(|c| *c != 0);
                    with_padding
                        .get(..end)
                        .ok_or(ErofsReaderError::OutOfBounds)?
                } else {
                    let next = self.block.get_entry_header(self.position)?;
                    let name_end = next.name_offset.get() as usize;
                    self.block
                        .0
                        .get(name_start..name_end)
                        .ok_or(ErofsReaderError::OutOfBounds)?
                };

                Ok(DirectoryEntry { header, name })
            })();

            if result.is_err() {
                // Stop iteration on error
                self.position = self.length;
            }
            Some(result)
        } else {
            None
        }
    }
}

/// Errors that can occur when reading EROFS images
#[derive(Error, Debug)]
pub enum ErofsReaderError {
    /// Invalid EROFS image data
    #[error("Invalid image: {0}")]
    InvalidImage(String),
    /// Invalid inode ID
    #[error("Invalid inode: {0}")]
    InvalidInode(u64),
    /// Offset or index out of bounds
    #[error("Offset out of bounds")]
    OutOfBounds,
    /// Directory has multiple hard links (not allowed)
    #[error("Hardlinked directories detected")]
    DirectoryHardlinks,
    /// Directory nesting exceeds maximum depth
    #[error("Maximum directory depth exceeded")]
    DepthExceeded,
    /// The '.' entry is invalid
    #[error("Invalid '.' entry in directory")]
    InvalidSelfReference,
    /// The '..' entry is invalid
    #[error("Invalid '..' entry in directory")]
    InvalidParentReference,
    /// File type in directory entry doesn't match inode
    #[error("File type in dirent doesn't match type in inode")]
    FileTypeMismatch,
    /// Duplicate directory entry name
    #[error("Duplicate directory entry {0:?}")]
    DuplicateEntry(Box<OsStr>),
}

type ReadResult<T> = Result<T, ErofsReaderError>;

/// Collects object references from an EROFS image for garbage collection
#[derive(Debug)]
pub struct ObjectCollector<ObjectID: FsVerityHashValue> {
    visited_nids: HashSet<u64>,
    nids_to_visit: BTreeSet<u64>,
    objects: HashSet<ObjectID>,
}

impl<ObjectID: FsVerityHashValue> ObjectCollector<ObjectID> {
    fn visit_xattr(&mut self, attr: &XAttr) -> Result<(), ErofsReaderError> {
        // This is the index of "trusted".  See XATTR_PREFIXES in format.rs.
        if attr.header.name_index != 4 {
            return Ok(());
        }
        if attr.suffix()? != b"overlay.metacopy" {
            return Ok(());
        }
        if let Ok(value) = OverlayMetacopy::read_from_bytes(attr.value()?)
            && value.valid()
        {
            self.objects.insert(value.digest);
        }
        Ok(())
    }

    fn visit_xattrs(&mut self, img: &Image, xattrs: &InodeXAttrs) -> ReadResult<()> {
        for id in xattrs.shared()? {
            self.visit_xattr(img.shared_xattr(id.get())?)?;
        }
        for attr in xattrs.local()? {
            self.visit_xattr(attr?)?;
        }
        Ok(())
    }

    fn visit_directory_block(&mut self, block: &DirectoryBlock) -> ReadResult<()> {
        for entry in block.entries()? {
            let entry = entry?;
            if entry.name != b"." && entry.name != b".." {
                let nid = entry.nid();
                if !self.visited_nids.contains(&nid) {
                    self.nids_to_visit.insert(nid);
                }
            }
        }
        Ok(())
    }

    fn visit_nid(&mut self, img: &Image, nid: u64) -> ReadResult<()> {
        let first_time = self.visited_nids.insert(nid);
        assert!(first_time); // should not have been added to the "to visit" list otherwise

        let inode = img.inode(nid)?;

        if let Some(xattrs) = inode.xattrs()? {
            self.visit_xattrs(img, xattrs)?;
        }

        if inode.mode().is_dir() {
            for blkid in img.inode_blocks(&inode)? {
                self.visit_directory_block(img.directory_block(blkid)?)?;
            }

            if let Some(inline) = inode.inline() {
                let inline_block = DirectoryBlock::ref_from_bytes(inline)
                    .map_err(|_| ErofsReaderError::OutOfBounds)?;
                self.visit_directory_block(inline_block)?;
            }
        }

        Ok(())
    }
}

/// Collects all object references from an EROFS image
///
/// This function walks the directory tree and extracts fsverity object IDs
/// from overlay.metacopy xattrs for garbage collection purposes.
///
/// Returns a set of all referenced object IDs.
pub fn collect_objects<ObjectID: FsVerityHashValue>(image: &[u8]) -> ReadResult<HashSet<ObjectID>> {
    let img = Image::open(image)?.restrict_to_composefs()?;
    let mut this = ObjectCollector {
        visited_nids: HashSet::new(),
        nids_to_visit: BTreeSet::new(),
        objects: HashSet::new(),
    };

    // nids_to_visit is initialized with the root directory.  Visiting directory nids will add
    // more nids to the "to visit" list.  Keep iterating until it's empty.
    this.nids_to_visit.insert(img.sb.root_nid.get() as u64);
    while let Some(nid) = this.nids_to_visit.pop_first() {
        this.visit_nid(&img, nid)?;
    }
    Ok(this.objects)
}

/// Construct the full xattr name from a prefix index and suffix.
fn construct_xattr_name(xattr: &XAttr) -> Result<Vec<u8>, ErofsReaderError> {
    let prefix = *XATTR_PREFIXES
        .get(xattr.header.name_index as usize)
        .ok_or_else(|| {
            ErofsReaderError::InvalidImage(format!(
                "xattr name_index {} out of range",
                xattr.header.name_index
            ))
        })?;
    let suffix = xattr.suffix()?;
    let mut full_name = Vec::with_capacity(prefix.len() + suffix.len());
    full_name.extend_from_slice(prefix);
    full_name.extend_from_slice(suffix);
    Ok(full_name)
}

/// Build a `tree::Stat` from an erofs inode, reversing the xattr namespace
/// transformations applied by the writer:
/// - Strips `trusted.overlay.metacopy` and `trusted.overlay.redirect`
/// - Unescapes `trusted.overlay.overlay.X` back to `trusted.overlay.X`
fn stat_from_inode_for_tree(img: &Image, inode: &InodeType) -> anyhow::Result<tree::Stat> {
    let (st_mode, st_uid, st_gid, st_mtim_sec, st_mtim_nsec) = match inode {
        InodeType::Compact(inode) => (
            inode.header.mode.0.get() as u32 & 0o7777,
            inode.header.uid.get() as u32,
            inode.header.gid.get() as u32,
            // Compact inodes don't store mtime; the writer uses build_time
            // but for round-trip purposes, 0 matches what was written for
            // compact headers (the writer always uses ExtendedInodeHeader)
            0i64,
            img.sb.build_time_nsec.get(),
        ),
        InodeType::Extended(inode) => (
            inode.header.mode.0.get() as u32 & 0o7777,
            inode.header.uid.get(),
            inode.header.gid.get(),
            inode.header.mtime.get() as i64,
            inode.header.mtime_nsec.get(),
        ),
    };

    let mut xattrs = BTreeMap::new();

    if let Some(xattrs_section) = inode.xattrs()? {
        // Process shared xattrs
        for id in xattrs_section.shared()? {
            let xattr = img.shared_xattr(id.get())?;
            if let Some((name, value)) = transform_xattr(xattr)? {
                xattrs.insert(name, value);
            }
        }
        // Process local xattrs
        for xattr in xattrs_section.local()? {
            let xattr = xattr?;
            if let Some((name, value)) = transform_xattr(xattr)? {
                xattrs.insert(name, value);
            }
        }
    }

    Ok(tree::Stat {
        st_mode,
        st_uid,
        st_gid,
        st_mtim_sec,
        st_mtim_nsec,
        xattrs,
    })
}

/// Transform a single xattr, reversing writer escaping.
/// Returns None for internal overlay xattrs that should be stripped.
#[allow(clippy::type_complexity)]
fn transform_xattr(xattr: &XAttr) -> anyhow::Result<Option<(Box<OsStr>, Box<[u8]>)>> {
    let full_name = construct_xattr_name(xattr)?;

    // Skip internal overlay xattrs added by the writer
    if full_name == b"trusted.overlay.metacopy" || full_name == b"trusted.overlay.redirect" {
        return Ok(None);
    }

    // Unescape: trusted.overlay.overlay.X -> trusted.overlay.X
    if let Some(rest) = full_name.strip_prefix(b"trusted.overlay.overlay.") {
        let mut unescaped = b"trusted.overlay.".to_vec();
        unescaped.extend_from_slice(rest);
        let name = Box::from(OsStr::from_bytes(&unescaped));
        let value = Box::from(xattr.value()?);
        return Ok(Some((name, value)));
    }
    // Skip all other trusted.overlay.* xattrs (internal to composefs)
    if full_name.starts_with(b"trusted.overlay.") {
        return Ok(None);
    }

    // Keep all non-trusted.overlay.* xattrs
    let name = Box::from(OsStr::from_bytes(&full_name));
    let value = Box::from(xattr.value()?);
    Ok(Some((name, value)))
}

/// Extract file data from an inode (inline and block data combined).
fn extract_all_file_data(img: &Image, inode: &InodeType) -> anyhow::Result<Vec<u8>> {
    let file_size = (inode.size() as usize).min(img.image.len());
    if file_size == 0 {
        return Ok(Vec::new());
    }

    let mut data = Vec::with_capacity(file_size);

    // Read block data first
    for blkid in img.inode_blocks(inode)? {
        let block = img.block(blkid)?;
        data.extend_from_slice(block);
    }

    // Read inline data
    if let Some(inline) = inode.inline() {
        data.extend_from_slice(inline);
    }

    data.truncate(file_size);
    Ok(data)
}

/// Try to extract a metacopy digest from an inode's xattrs.
///
/// When `strict` is true (composefs-restricted mode), a
/// `trusted.overlay.metacopy` xattr with an invalid format is an error
/// rather than being silently ignored.
fn extract_metacopy_digest<ObjectID: FsVerityHashValue>(
    img: &Image,
    inode: &InodeType,
) -> anyhow::Result<Option<ObjectID>> {
    let strict = img.composefs_restricted;
    let Some(xattrs_section) = inode.xattrs()? else {
        return Ok(None);
    };

    for id in xattrs_section.shared()? {
        let xattr = img.shared_xattr(id.get())?;
        if let Some(digest) = check_metacopy_xattr(xattr, strict)? {
            return Ok(Some(digest));
        }
    }
    for xattr in xattrs_section.local()? {
        let xattr = xattr?;
        if let Some(digest) = check_metacopy_xattr(xattr, strict)? {
            return Ok(Some(digest));
        }
    }
    Ok(None)
}

/// Check if a single xattr is a valid overlay.metacopy and return the digest.
///
/// When `strict` is true, a `trusted.overlay.metacopy` xattr that cannot be
/// parsed or fails validation is an error.  In non-strict mode, such xattrs
/// are silently ignored (returning `Ok(None)`).
fn check_metacopy_xattr<ObjectID: FsVerityHashValue>(
    xattr: &XAttr,
    strict: bool,
) -> anyhow::Result<Option<ObjectID>> {
    // name_index 4 = "trusted.", suffix = "overlay.metacopy"
    if xattr.header.name_index != 4 {
        return Ok(None);
    }
    if xattr.suffix()? != b"overlay.metacopy" {
        return Ok(None);
    }
    // At this point we know the xattr is named trusted.overlay.metacopy.
    let value_bytes = xattr.value()?;
    let value = match OverlayMetacopy::<ObjectID>::read_from_bytes(value_bytes) {
        Ok(v) => v,
        Err(_) if strict => {
            anyhow::bail!(
                "malformed trusted.overlay.metacopy xattr: \
                 expected {} bytes, got {}",
                size_of::<OverlayMetacopy<ObjectID>>(),
                value_bytes.len(),
            );
        }
        Err(_) => return Ok(None),
    };
    if value.valid() {
        return Ok(Some(value.digest.clone()));
    }
    if strict {
        anyhow::bail!(
            "invalid trusted.overlay.metacopy: \
             version={}, len={}, flags={}, digest_algo={} \
             (expected version=0, len={}, flags=0, digest_algo={})",
            value.version(),
            value.len(),
            value.flags(),
            value.digest_algo(),
            size_of::<OverlayMetacopy<ObjectID>>(),
            ObjectID::ALGORITHM.kernel_id(),
        );
    }
    Ok(None)
}

/// Result of scanning a directory's entries, separating '.' and '..' from
/// the normal children.
struct DirEntries<'a> {
    /// The nid that '.' points to, if present.
    dot_nid: Option<u64>,
    /// The nid that '..' points to, if present.
    dotdot_nid: Option<u64>,
    /// Child entries (everything except '.' and '..').
    children: Vec<(&'a [u8], u64)>,
}

/// Collect directory entries from an inode, separating '.' and '..' from
/// the normal children.
fn dir_entries<'a>(
    img: &'a Image<'a>,
    dir_inode: &'a InodeType<'a>,
) -> anyhow::Result<DirEntries<'a>> {
    let mut result = DirEntries {
        dot_nid: None,
        dotdot_nid: None,
        children: Vec::new(),
    };

    // Closure that processes a single entry
    let mut process_entry = |entry: DirectoryEntry<'a>| {
        if entry.name == b"." {
            result.dot_nid = Some(entry.nid());
        } else if entry.name == b".." {
            result.dotdot_nid = Some(entry.nid());
        } else {
            result.children.push((entry.name, entry.nid()));
        }
    };

    // Block-based entries
    for blkid in img.inode_blocks(dir_inode)? {
        let block = img.directory_block(blkid)?;
        for entry in block.entries()? {
            process_entry(entry?);
        }
    }

    // Inline entries
    if let Some(data) = dir_inode.inline()
        && let Ok(block) = DirectoryBlock::ref_from_bytes(data)
    {
        for entry in block.entries()? {
            process_entry(entry?);
        }
    }

    Ok(result)
}

/// Maximum directory nesting depth. PATH_MAX is 4096 on Linux, and directory names
/// must be at least 2 bytes (1 char + separator), so the theoretical max is PATH_MAX / 2.
const MAX_DIRECTORY_DEPTH: usize = 4096 / 2;

/// Per-leaf nlink tracking for post-traversal validation.
struct NlinkEntry {
    /// The on-disk nlink value from the inode header.
    expected: u32,
    /// The leaf ID for looking up actual nlink from the filesystem.
    leaf_id: LeafId,
}

/// Mutable state threaded through the recursive directory traversal.
struct TreeBuilder<ObjectID: FsVerityHashValue> {
    /// Map from nid to first-seen LeafId for hardlink detection.
    hardlinks: HashMap<u64, LeafId>,
    /// Map from nid to nlink tracking entry for post-traversal validation.
    nlink_tracker: HashMap<u64, NlinkEntry>,
    /// Accumulated leaves for the filesystem being built.
    leaves: Vec<tree::Leaf<ObjectID>>,
}

impl<ObjectID: FsVerityHashValue> TreeBuilder<ObjectID> {
    fn new() -> Self {
        Self {
            hardlinks: HashMap::new(),
            nlink_tracker: HashMap::new(),
            leaves: Vec::new(),
        }
    }

    /// Push a new leaf and return its LeafId.
    fn push_leaf(&mut self, stat: tree::Stat, content: tree::LeafContent<ObjectID>) -> LeafId {
        let id = LeafId(self.leaves.len());
        self.leaves.push(tree::Leaf { stat, content });
        id
    }
}

/// Recursively populate a `tree::Directory` from an erofs directory inode.
///
/// `dir_nid` and `parent_nid` are used to validate that the '.' and '..'
/// entries point to the correct inodes.
fn populate_directory<ObjectID: FsVerityHashValue>(
    img: &Image,
    dir_nid: u64,
    parent_nid: u64,
    dir_inode: &InodeType,
    dir: &mut tree::Directory<ObjectID>,
    builder: &mut TreeBuilder<ObjectID>,
    depth: usize,
) -> anyhow::Result<()> {
    if depth >= MAX_DIRECTORY_DEPTH {
        return Err(ErofsReaderError::DepthExceeded.into());
    }

    let dir_result = dir_entries(img, dir_inode)?;

    // Validate '.' and '..' entries
    match dir_result.dot_nid {
        Some(nid) if nid != dir_nid => {
            return Err(ErofsReaderError::InvalidSelfReference.into());
        }
        None => {
            return Err(ErofsReaderError::InvalidSelfReference.into());
        }
        _ => {}
    }
    match dir_result.dotdot_nid {
        Some(nid) if nid != parent_nid => {
            return Err(ErofsReaderError::InvalidParentReference.into());
        }
        None => {
            return Err(ErofsReaderError::InvalidParentReference.into());
        }
        _ => {}
    }

    let mut n_subdirs: u32 = 0;
    for (name_bytes, nid) in dir_result.children {
        let name = OsStr::from_bytes(name_bytes);
        let child_inode = img.inode(nid)?;

        if child_inode.mode().is_dir() {
            n_subdirs = n_subdirs
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("too many subdirectories"))?;
            let child_stat = stat_from_inode_for_tree(img, &child_inode)?;
            let mut child_dir = tree::Directory::new(child_stat);
            populate_directory(
                img,
                nid,
                dir_nid,
                &child_inode,
                &mut child_dir,
                builder,
                depth + 1,
            )
            .with_context(|| format!("reading directory {:?}", name))?;
            if !dir.insert(name, tree::Inode::Directory(Box::new(child_dir))) {
                return Err(ErofsReaderError::DuplicateEntry(Box::from(name)).into());
            }
        } else {
            // Check if this is a hardlink (same nid seen before)
            if let Some(&existing_leaf_id) = builder.hardlinks.get(&nid) {
                if !dir.insert(name, tree::Inode::leaf(existing_leaf_id)) {
                    return Err(ErofsReaderError::DuplicateEntry(Box::from(name)).into());
                }
                continue;
            }

            let stat = stat_from_inode_for_tree(img, &child_inode)?;
            let mode = child_inode.mode().0.get();
            let file_type = mode & S_IFMT;

            let content = match file_type {
                S_IFREG => {
                    if let Some(digest) = extract_metacopy_digest::<ObjectID>(img, &child_inode)? {
                        tree::LeafContent::Regular(tree::RegularFile::External(
                            digest,
                            child_inode.size(),
                        ))
                    } else {
                        if img.composefs_restricted {
                            let size = child_inode.size();
                            if size > MAX_INLINE_CONTENT as u64 {
                                anyhow::bail!(
                                    "inline regular file {:?} has size {} \
                                     (max {MAX_INLINE_CONTENT})",
                                    name,
                                    size,
                                );
                            }
                        }
                        let data = extract_all_file_data(img, &child_inode)?;
                        tree::LeafContent::Regular(tree::RegularFile::Inline(data.into()))
                    }
                }
                S_IFLNK => {
                    let target_data = child_inode.inline().unwrap_or(&[]);
                    if target_data.len() > crate::SYMLINK_MAX {
                        anyhow::bail!(
                            "symlink target for {:?} is {} bytes (max {})",
                            name,
                            target_data.len(),
                            crate::SYMLINK_MAX,
                        );
                    }
                    let target = OsStr::from_bytes(target_data);
                    tree::LeafContent::Symlink(Box::from(target))
                }
                S_IFBLK => tree::LeafContent::BlockDevice(child_inode.u() as u64),
                S_IFCHR => tree::LeafContent::CharacterDevice(child_inode.u() as u64),
                S_IFIFO => tree::LeafContent::Fifo,
                S_IFSOCK => tree::LeafContent::Socket,
                _ => anyhow::bail!("unknown file type {:#o} for {:?}", file_type, name),
            };

            let leaf_id = builder.push_leaf(stat, content);

            // Track for hardlink detection if nlink > 1
            let on_disk_nlink = child_inode.nlink();
            if on_disk_nlink > 1 {
                builder.hardlinks.insert(nid, leaf_id);
            }

            // Track for post-traversal nlink validation
            builder
                .nlink_tracker
                .entry(nid)
                .or_insert_with(|| NlinkEntry {
                    expected: on_disk_nlink,
                    leaf_id,
                });

            if !dir.insert(name, tree::Inode::leaf(leaf_id)) {
                return Err(ErofsReaderError::DuplicateEntry(Box::from(name)).into());
            }
        }
    }

    // Validate directory nlink: should be 2 (for '.' and parent's '..')
    // plus one for each child subdirectory's '..' pointing back.
    let expected_nlink = n_subdirs
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("directory nlink overflow"))?;
    let actual_nlink = dir_inode.nlink();
    if actual_nlink != expected_nlink {
        anyhow::bail!(
            "directory nlink mismatch: on-disk nlink is {actual_nlink}, \
             expected {expected_nlink} (2 + {n_subdirs} subdirectories)",
        );
    }

    Ok(())
}

/// Converts an EROFS image into a `tree::FileSystem`.
///
/// This is the inverse of `mkfs_erofs`: it reads an EROFS image and
/// reconstructs the tree structure, including proper handling of hardlinks
/// (via `Rc` sharing), xattr namespace transformations, and metacopy-based
/// external file references.
///
/// Validates structural invariants including:
/// - '.' and '..' entries point to the correct directories
/// - Directory nlink matches 2 + number of subdirectories
/// - Leaf nlink matches the number of references in the tree
pub fn erofs_to_filesystem<ObjectID: FsVerityHashValue>(
    image_data: &[u8],
) -> anyhow::Result<tree::FileSystem<ObjectID>> {
    let img = Image::open(image_data)?.restrict_to_composefs()?;
    let root_nid = img.sb.root_nid.get() as u64;
    let root_inode = img.inode(root_nid)?;

    let root_stat = stat_from_inode_for_tree(&img, &root_inode)?;
    let mut root = tree::Directory::new(root_stat);

    let mut builder = TreeBuilder::new();

    // Root's '..' points to itself
    populate_directory(
        &img,
        root_nid,
        root_nid,
        &root_inode,
        &mut root,
        &mut builder,
        0,
    )
    .context("reading root directory")?;

    let fs = tree::FileSystem {
        root,
        leaves: builder.leaves,
    };

    let nlink_map = fs.nlinks();
    builder.nlink_tracker.iter().try_for_each(|(nid, entry)| {
        let tree_nlink = nlink_map[entry.leaf_id.0];
        if entry.expected != tree_nlink {
            anyhow::bail!(
                "nlink mismatch for inode nid {nid}: on-disk nlink is {}, \
                 but found {tree_nlink} reference(s) in the directory tree",
                entry.expected,
            );
        }
        Ok(())
    })?;

    debug_assert!(
        fs.fsck().is_ok(),
        "erofs_to_filesystem produced invalid filesystem"
    );
    Ok(fs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dumpfile::{dumpfile_to_filesystem, write_dumpfile},
        erofs::writer::mkfs_erofs,
        fsverity::Sha256HashValue,
    };
    use std::collections::HashMap;

    /// Returns whether `fsck.erofs` is available on the system.
    /// The result is cached so the lookup only happens once.
    fn have_fsck_erofs() -> bool {
        static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *AVAILABLE.get_or_init(|| {
            std::process::Command::new("fsck.erofs")
                .arg("--help")
                .output()
                .is_ok()
        })
    }

    /// Run `fsck.erofs` on an image and return whether it passed.
    /// Returns `None` if `fsck.erofs` is not installed.
    fn run_fsck_erofs(image: &[u8]) -> Option<bool> {
        if !have_fsck_erofs() {
            return None;
        }

        let temp_dir = tempfile::TempDir::new().unwrap();
        let image_path = temp_dir.path().join("test.erofs");
        std::fs::write(&image_path, image).unwrap();

        let output = std::process::Command::new("fsck.erofs")
            .arg(&image_path)
            .output()
            .expect("fsck.erofs was detected but failed to run");
        Some(output.status.success())
    }

    /// Helper to validate that directory entries can be read correctly
    fn validate_directory_entries(img: &Image, nid: u64, expected_names: &[&str]) {
        let inode = img.inode(nid).unwrap();
        assert!(inode.mode().is_dir(), "Expected directory inode");

        let mut found_names = Vec::new();

        // Read inline entries if present
        if let Some(inline) = inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries().unwrap() {
                let entry = entry.unwrap();
                let name = std::str::from_utf8(entry.name).unwrap();
                found_names.push(name.to_string());
            }
        }

        // Read block entries
        for blkid in img.inode_blocks(&inode).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries().unwrap() {
                let entry = entry.unwrap();
                let name = std::str::from_utf8(entry.name).unwrap();
                found_names.push(name.to_string());
            }
        }

        // Sort for comparison (entries should include . and ..)
        found_names.sort();
        let mut expected_sorted: Vec<_> = expected_names.iter().map(|s| s.to_string()).collect();
        expected_sorted.sort();

        assert_eq!(
            found_names, expected_sorted,
            "Directory entries mismatch for nid {nid}"
        );
    }

    #[test]
    fn test_empty_directory() {
        // Create filesystem with empty directory
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/empty_dir 0 40755 2 0 0 0 1000.0 - - -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image).unwrap();

        // Root should have . and .. and empty_dir
        let root_nid = img.sb.root_nid.get() as u64;
        validate_directory_entries(&img, root_nid, &[".", "..", "empty_dir"]);

        // Find empty_dir entry
        let root_inode = img.root().unwrap();
        let mut empty_dir_nid = None;
        if let Some(inline) = root_inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries().unwrap() {
                let entry = entry.unwrap();
                if entry.name == b"empty_dir" {
                    empty_dir_nid = Some(entry.nid());
                    break;
                }
            }
        }
        for blkid in img.inode_blocks(&root_inode).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries().unwrap() {
                let entry = entry.unwrap();
                if entry.name == b"empty_dir" {
                    empty_dir_nid = Some(entry.nid());
                    break;
                }
            }
        }

        let empty_dir_nid = empty_dir_nid.expect("empty_dir not found");
        validate_directory_entries(&img, empty_dir_nid, &[".", ".."]);
    }

    #[test]
    fn test_directory_with_inline_entries() {
        // Create filesystem with directory that has a few entries (should be inline)
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/dir1 0 40755 2 0 0 0 1000.0 - - -
/dir1/file1 5 100644 1 0 0 0 1000.0 - hello -
/dir1/file2 5 100644 1 0 0 0 1000.0 - world -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image).unwrap();

        // Find dir1
        let root_inode = img.root().unwrap();
        let mut dir1_nid = None;
        if let Some(inline) = root_inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries().unwrap() {
                let entry = entry.unwrap();
                if entry.name == b"dir1" {
                    dir1_nid = Some(entry.nid());
                    break;
                }
            }
        }
        for blkid in img.inode_blocks(&root_inode).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries().unwrap() {
                let entry = entry.unwrap();
                if entry.name == b"dir1" {
                    dir1_nid = Some(entry.nid());
                    break;
                }
            }
        }

        let dir1_nid = dir1_nid.expect("dir1 not found");
        validate_directory_entries(&img, dir1_nid, &[".", "..", "file1", "file2"]);
    }

    #[test]
    fn test_directory_with_many_entries() {
        // Create a directory with many entries to force block storage
        let mut dumpfile = String::from("/ 0 40755 2 0 0 0 1000.0 - - -\n");
        dumpfile.push_str("/bigdir 0 40755 2 0 0 0 1000.0 - - -\n");

        // Add many files to force directory blocks
        for i in 0..100 {
            dumpfile.push_str(&format!(
                "/bigdir/file{i:03} 5 100644 1 0 0 0 1000.0 - hello -\n"
            ));
        }

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(&dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image).unwrap();

        // Find bigdir
        let root_inode = img.root().unwrap();
        let mut bigdir_nid = None;
        if let Some(inline) = root_inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries().unwrap() {
                let entry = entry.unwrap();
                if entry.name == b"bigdir" {
                    bigdir_nid = Some(entry.nid());
                    break;
                }
            }
        }
        for blkid in img.inode_blocks(&root_inode).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries().unwrap() {
                let entry = entry.unwrap();
                if entry.name == b"bigdir" {
                    bigdir_nid = Some(entry.nid());
                    break;
                }
            }
        }

        let bigdir_nid = bigdir_nid.expect("bigdir not found");

        // Build expected names
        let mut expected: Vec<String> = vec![".".to_string(), "..".to_string()];
        for i in 0..100 {
            expected.push(format!("file{i:03}"));
        }
        let expected_refs: Vec<&str> = expected.iter().map(|s| s.as_str()).collect();

        validate_directory_entries(&img, bigdir_nid, &expected_refs);
    }

    #[test]
    fn test_nested_directories() {
        // Test deeply nested directory structure
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/a 0 40755 2 0 0 0 1000.0 - - -
/a/b 0 40755 2 0 0 0 1000.0 - - -
/a/b/c 0 40755 2 0 0 0 1000.0 - - -
/a/b/c/file.txt 5 100644 1 0 0 0 1000.0 - hello -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image).unwrap();

        // Navigate through the structure
        let root_nid = img.sb.root_nid.get() as u64;
        validate_directory_entries(&img, root_nid, &[".", "..", "a"]);

        let a_nid = img
            .find_child_nid(root_nid, b"a")
            .unwrap()
            .expect("a not found");
        validate_directory_entries(&img, a_nid, &[".", "..", "b"]);

        let b_nid = img
            .find_child_nid(a_nid, b"b")
            .unwrap()
            .expect("b not found");
        validate_directory_entries(&img, b_nid, &[".", "..", "c"]);

        let c_nid = img
            .find_child_nid(b_nid, b"c")
            .unwrap()
            .expect("c not found");
        validate_directory_entries(&img, c_nid, &[".", "..", "file.txt"]);
    }

    #[test]
    fn test_mixed_entry_types() {
        // Test directory with various file types
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/mixed 0 40755 2 0 0 0 1000.0 - - -
/mixed/regular 10 100644 1 0 0 0 1000.0 - content123 -
/mixed/symlink 7 120777 1 0 0 0 1000.0 /target - -
/mixed/fifo 0 10644 1 0 0 0 1000.0 - - -
/mixed/subdir 0 40755 2 0 0 0 1000.0 - - -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image).unwrap();

        let root_inode = img.root().unwrap();
        let mut mixed_nid = None;
        if let Some(inline) = root_inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries().unwrap() {
                let entry = entry.unwrap();
                if entry.name == b"mixed" {
                    mixed_nid = Some(entry.nid());
                    break;
                }
            }
        }
        for blkid in img.inode_blocks(&root_inode).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries().unwrap() {
                let entry = entry.unwrap();
                if entry.name == b"mixed" {
                    mixed_nid = Some(entry.nid());
                    break;
                }
            }
        }

        let mixed_nid = mixed_nid.expect("mixed not found");
        validate_directory_entries(
            &img,
            mixed_nid,
            &[".", "..", "regular", "symlink", "fifo", "subdir"],
        );
    }

    #[test]
    fn test_collect_objects_traversal() {
        // Test that object collection properly traverses all directories
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/dir1 0 40755 2 0 0 0 1000.0 - - -
/dir1/file1 5 100644 1 0 0 0 1000.0 - hello -
/dir2 0 40755 2 0 0 0 1000.0 - - -
/dir2/subdir 0 40755 2 0 0 0 1000.0 - - -
/dir2/subdir/file2 5 100644 1 0 0 0 1000.0 - world -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);

        // This should traverse all directories without error
        let result = collect_objects::<Sha256HashValue>(&image);
        assert!(
            result.is_ok(),
            "Failed to collect objects: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_pr188_empty_inline_directory() -> anyhow::Result<()> {
        // Regression test for https://github.com/containers/composefs-rs/pull/188
        //
        // The bug: ObjectCollector::visit_inode at lines 553-554 unconditionally does:
        //   let tail = DirectoryBlock::ref_from_bytes(inode.inline()).unwrap();
        //   self.visit_directory_block(tail);
        //
        // When inode.inline() is empty, DirectoryBlock::ref_from_bytes succeeds but then
        // visit_directory_block calls n_entries() which panics trying to read 12 bytes
        // from an empty slice.
        //
        // This test generates an erofs image using C mkcomposefs, which creates directories
        // with empty inline sections (unlike the Rust implementation which always includes
        // . and .. entries).

        // Generate a C-generated erofs image using mkcomposefs
        let dumpfile_content = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/empty_dir 0 40755 2 0 0 0 1000.0 - - -
"#;

        // Create temporary files for dumpfile and erofs output
        let temp_dir = tempfile::TempDir::new()?;
        let temp_dir = temp_dir.path();
        let dumpfile_path = temp_dir.join("pr188_test.dump");
        let erofs_path = temp_dir.join("pr188_test.erofs");

        // Write dumpfile
        std::fs::write(&dumpfile_path, dumpfile_content).expect("Failed to write test dumpfile");

        // Run mkcomposefs to generate erofs image
        let output = std::process::Command::new("mkcomposefs")
            .arg("--from-file")
            .arg(&dumpfile_path)
            .arg(&erofs_path)
            .output()
            .expect("Failed to run mkcomposefs - is it installed?");

        assert!(
            output.status.success(),
            "mkcomposefs failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Read the generated erofs image
        let image = std::fs::read(&erofs_path).expect("Failed to read generated erofs");

        // The C mkcomposefs creates directories with empty inline sections.
        let r = collect_objects::<Sha256HashValue>(&image).unwrap();
        assert_eq!(r.len(), 0);

        Ok(())
    }

    #[test]
    fn test_round_trip_basic() {
        // Full round-trip: dumpfile -> tree -> erofs -> read back -> validate
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/file1 5 100644 1 0 0 0 1000.0 - hello -
/file2 6 100644 1 0 0 0 1000.0 - world! -
/dir1 0 40755 2 0 0 0 1000.0 - - -
/dir1/nested 8 100644 1 0 0 0 1000.0 - content1 -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image).unwrap();

        // Verify root entries
        let root_nid = img.sb.root_nid.get() as u64;
        validate_directory_entries(&img, root_nid, &[".", "..", "file1", "file2", "dir1"]);

        // Collect all entries and verify structure
        let mut entries_map: HashMap<Vec<u8>, u64> = HashMap::new();
        let root_inode = img.root().unwrap();

        if let Some(inline) = root_inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries().unwrap() {
                let entry = entry.unwrap();
                entries_map.insert(entry.name.to_vec(), entry.nid());
            }
        }

        for blkid in img.inode_blocks(&root_inode).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries().unwrap() {
                let entry = entry.unwrap();
                entries_map.insert(entry.name.to_vec(), entry.nid());
            }
        }

        // Verify we can read file contents
        let file1_nid = entries_map
            .get(b"file1".as_slice())
            .expect("file1 not found");
        let file1_inode = img.inode(*file1_nid).unwrap();
        assert!(!file1_inode.mode().is_dir());
        assert_eq!(file1_inode.size(), 5);

        let inline_data = file1_inode.inline();
        assert_eq!(inline_data, Some(b"hello".as_slice()));
    }

    /// Helper: round-trip a dumpfile through erofs and compare the result.
    fn round_trip_dumpfile(input: &str) -> (String, String) {
        let fs_orig = dumpfile_to_filesystem::<Sha256HashValue>(input).unwrap();

        let mut orig_output = Vec::new();
        write_dumpfile(&mut orig_output, &fs_orig).unwrap();
        let orig_str = String::from_utf8(orig_output).unwrap();

        let image = mkfs_erofs(&fs_orig);
        let fs_rt = erofs_to_filesystem::<Sha256HashValue>(&image).unwrap();

        let mut rt_output = Vec::new();
        write_dumpfile(&mut rt_output, &fs_rt).unwrap();
        let rt_str = String::from_utf8(rt_output).unwrap();

        (orig_str, rt_str)
    }

    #[test]
    fn test_erofs_to_filesystem_empty_root() {
        let dumpfile = "/ 0 40755 2 0 0 0 1000.0 - - -\n";
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_inline_files() {
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/empty 0 100644 1 0 0 0 1000.0 - - -
/hello 5 100644 1 0 0 0 1000.0 - hello -
/world 6 100644 1 0 0 0 1000.0 - world! -
"#;
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_symlinks() {
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/link1 7 120777 1 0 0 0 1000.0 /target - -
/link2 11 120777 1 0 0 0 1000.0 /other/path - -
"#;
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_nested_dirs() {
        let dumpfile = r#"/ 0 40755 3 0 0 0 1000.0 - - -
/a 0 40755 3 0 0 0 1000.0 - - -
/a/b 0 40755 3 0 0 0 1000.0 - - -
/a/b/c 0 40755 2 0 0 0 1000.0 - - -
/a/b/c/file.txt 5 100644 1 0 0 0 1000.0 - hello -
/a/b/other 3 100644 1 0 0 0 1000.0 - abc -
"#;
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_devices_and_fifos() {
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/blk 0 60660 1 0 0 2049 1000.0 - - -
/chr 0 20666 1 0 0 1025 1000.0 - - -
/fifo 0 10644 1 0 0 0 1000.0 - - -
"#;
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_xattrs() {
        let dumpfile = "/ 0 40755 2 0 0 0 1000.0 - - - security.selinux=system_u:object_r:root_t:s0\n\
             /file 5 100644 1 0 0 0 1000.0 - hello - user.myattr=myvalue\n";
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_escaped_overlay_xattrs() {
        // The writer escapes trusted.overlay.X to trusted.overlay.overlay.X.
        // Round-tripping must preserve the original xattr name.
        let dumpfile = "/ 0 40755 2 0 0 0 1000.0 - - -\n\
             /file 5 100644 1 0 0 0 1000.0 - hello - trusted.overlay.custom=val\n";
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_external_file() {
        // External file with a known fsverity digest.
        // Use a size much larger than the image to verify that
        // restrict_to_composefs() allows large sizes for ChunkBased
        // (external) files — their size reflects the real file on
        // the underlying filesystem, not data stored in the image.
        let digest = "a".repeat(64);
        let pathname = format!("{}/{}", &digest[..2], &digest[2..]);
        let dumpfile = format!(
            "/ 0 40755 2 0 0 0 1000.0 - - -\n\
             /ext 1000000000 100644 1 0 0 0 1000.0 {pathname} - {digest}\n"
        );
        let (orig, rt) = round_trip_dumpfile(&dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_hardlinks() {
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/original 11 100644 2 0 0 0 1000.0 - hello_world -
/hardlink 0 @120000 2 0 0 0 0.0 /original - -
"#;

        let fs_orig = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs_orig);
        let fs_rt = erofs_to_filesystem::<Sha256HashValue>(&image).unwrap();

        // Verify hardlink sharing via LeafId
        {
            let orig_id = fs_rt.root.leaf_id(OsStr::new("original")).unwrap();
            let hardlink_id = fs_rt.root.leaf_id(OsStr::new("hardlink")).unwrap();
            assert_eq!(
                orig_id, hardlink_id,
                "hardlink entries should share the same LeafId"
            );
        }

        // Verify dumpfile round-trips correctly
        let mut orig_output = Vec::new();
        write_dumpfile(&mut orig_output, &fs_orig).unwrap();
        let orig_str = String::from_utf8(orig_output).unwrap();

        let mut rt_output = Vec::new();
        write_dumpfile(&mut rt_output, &fs_rt).unwrap();
        let rt_str = String::from_utf8(rt_output).unwrap();
        assert_eq!(orig_str, rt_str);
    }

    #[test]
    fn test_erofs_to_filesystem_mixed_types() {
        let dumpfile = r#"/ 0 40755 3 0 0 0 1000.0 - - -
/blk 0 60660 1 0 6 259 1000.0 - - -
/chr 0 20666 1 0 6 1025 1000.0 - - -
/dir 0 40755 2 42 42 0 2000.0 - - -
/dir/nested 3 100644 1 42 42 0 2000.0 - abc -
/fifo 0 10644 1 0 0 0 1000.0 - - -
/hello 5 100644 1 1000 1000 0 1500.0 - hello -
/link 7 120777 1 0 0 0 1000.0 /target - -
"#;
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_restrict_to_composefs_rejects_unsupported_features() {
        // Build a minimal valid composefs image (just a root directory).
        let dumpfile = "/ 0 40755 2 0 0 0 1000.0 - - -\n";
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let base_image = mkfs_erofs(&fs);

        // Sanity: the unmodified image passes restrict_to_composefs().
        Image::open(&base_image)
            .unwrap()
            .restrict_to_composefs()
            .expect("unmodified image should be accepted");

        // Superblock starts at byte 1024 in the image.
        const SB_OFFSET: usize = 1024;

        // Field offsets within the Superblock struct (repr(C), all LE).
        const FEATURE_COMPAT: usize = SB_OFFSET + 8; // U32
        const EXTSLOTS: usize = SB_OFFSET + 13; // u8
        const FEATURE_INCOMPAT: usize = SB_OFFSET + 80; // U32
        const AVAILABLE_COMPR_ALGS: usize = SB_OFFSET + 84; // U16
        const EXTRA_DEVICES: usize = SB_OFFSET + 86; // U16
        const META_BLKADDR: usize = SB_OFFSET + 40; // U32
        const XATTR_PREFIX_COUNT: usize = SB_OFFSET + 91; // u8
        const PACKED_NID: usize = SB_OFFSET + 96; // U64

        /// A mutation to apply to the image bytes before calling
        /// restrict_to_composefs().
        enum Mutation {
            U8(usize, u8),
            U16(usize, u16),
            U32(usize, u32),
            U64(usize, u64),
        }

        struct Case {
            name: &'static str,
            mutation: Mutation,
            expected_substr: &'static str,
        }

        let cases = [
            Case {
                name: "feature_incompat: LZ4_0PADDING",
                mutation: Mutation::U32(FEATURE_INCOMPAT, 0x1),
                expected_substr: "unsupported feature_incompat",
            },
            Case {
                name: "feature_incompat: DEVICE_TABLE",
                mutation: Mutation::U32(FEATURE_INCOMPAT, 0x8),
                expected_substr: "unsupported feature_incompat",
            },
            Case {
                name: "feature_incompat: FRAGMENTS",
                mutation: Mutation::U32(FEATURE_INCOMPAT, 0x20),
                expected_substr: "unsupported feature_incompat",
            },
            Case {
                name: "feature_compat: unknown bit",
                mutation: Mutation::U32(FEATURE_COMPAT, 0x100),
                expected_substr: "unsupported feature_compat",
            },
            Case {
                name: "available_compr_algs != 0",
                mutation: Mutation::U16(AVAILABLE_COMPR_ALGS, 1),
                expected_substr: "compression",
            },
            Case {
                name: "extra_devices != 0",
                mutation: Mutation::U16(EXTRA_DEVICES, 1),
                expected_substr: "multi-device",
            },
            Case {
                name: "extslots != 0",
                mutation: Mutation::U8(EXTSLOTS, 1),
                expected_substr: "extslots",
            },
            Case {
                name: "packed_nid != 0",
                mutation: Mutation::U64(PACKED_NID, 1),
                expected_substr: "packed",
            },
            Case {
                name: "meta_blkaddr != 0",
                mutation: Mutation::U32(META_BLKADDR, 1),
                expected_substr: "meta_blkaddr",
            },
            Case {
                name: "xattr_prefix_count != 0",
                mutation: Mutation::U8(XATTR_PREFIX_COUNT, 1),
                expected_substr: "xattr prefixes",
            },
        ];

        for case in &cases {
            let mut image = base_image.clone();
            match case.mutation {
                Mutation::U8(off, val) => image[off] = val,
                Mutation::U16(off, val) => {
                    image[off..off + 2].copy_from_slice(&val.to_le_bytes());
                }
                Mutation::U32(off, val) => {
                    image[off..off + 4].copy_from_slice(&val.to_le_bytes());
                }
                Mutation::U64(off, val) => {
                    image[off..off + 8].copy_from_slice(&val.to_le_bytes());
                }
            }

            // Image::open() may itself reject certain mutations (e.g.
            // meta_blkaddr pointing past the image), so accept errors
            // from either open() or restrict_to_composefs().
            let result = Image::open(&image).and_then(|img| img.restrict_to_composefs());
            let err = result.expect_err(&format!("{}: should have been rejected", case.name,));
            let msg = format!("{err}");
            assert!(
                msg.contains(case.expected_substr),
                "{}: expected error containing {:?}, got: {msg}",
                case.name,
                case.expected_substr,
            );
        }
    }

    #[test]
    fn test_rejects_corrupted_dot_and_dotdot() {
        // Build a valid image and corrupt directory '.' and '..' entries
        // to verify they are rejected by erofs_to_filesystem().
        let dumpfile = r#"/ 4096 40755 3 0 0 0 1000.0 - - -
/dir 4096 40755 2 0 0 0 1000.0 - - -
/file 5 100644 1 0 0 0 1000.0 - hello -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let base_image = mkfs_erofs(&fs);

        // Sanity: unmodified image round-trips fine
        erofs_to_filesystem::<Sha256HashValue>(&base_image)
            .expect("unmodified image should be accepted");
        if let Some(ok) = run_fsck_erofs(&base_image) {
            assert!(ok, "fsck.erofs should accept unmodified image");
        }

        // Find the byte positions of '.' entry nids in the image.
        // Directory entries are stored inline after the inode header + xattrs.
        // Each DirectoryEntryHeader is 12 bytes, with inode_offset at byte 0 (U64).
        // Entries are sorted by name, so '.' comes first, then '..'.
        let img = Image::open(&base_image).unwrap();
        let root_nid = img.sb.root_nid.get() as u64;

        // Find the child directory's nid
        let dir_nid = img.find_child_nid(root_nid, b"dir").unwrap().unwrap();

        // Locate the child directory's inline data in the raw image.
        // The inode is at inodes_start + nid * 32, and the inline data
        // follows the header + xattrs.
        let dir_inode = img.inode(dir_nid).unwrap();
        let dir_inline = dir_inode.inline().unwrap();

        // Get byte offset of the inline data within the image
        let inline_ptr = dir_inline.as_ptr() as usize;
        let image_ptr = base_image.as_ptr() as usize;
        let inline_offset = inline_ptr - image_ptr;
        drop(img);

        // The inline directory block contains entries sorted by name.
        // For /dir, entries are: '.', '..'.
        // Each DirectoryEntryHeader is 12 bytes with inode_offset (U64) at offset 0.

        struct Case {
            name: &'static str,
            // Byte offset of the inode_offset field to corrupt, relative to inline_offset
            entry_byte_offset: usize,
            expected_error: &'static str,
        }

        let cases = [
            Case {
                name: "corrupted '.' entry",
                entry_byte_offset: 0, // first entry's inode_offset
                expected_error: "'.'",
            },
            Case {
                name: "corrupted '..' entry",
                entry_byte_offset: 12, // second entry's inode_offset
                expected_error: "'..'",
            },
        ];

        for case in &cases {
            let mut image = base_image.clone();
            let offset = inline_offset + case.entry_byte_offset;
            // Write a bogus nid (0xDEAD) that doesn't match the directory's own nid
            image[offset..offset + 8].copy_from_slice(&0xDEADu64.to_le_bytes());

            let result = erofs_to_filesystem::<Sha256HashValue>(&image);
            let err = result.expect_err(&format!("{}: should have been rejected", case.name));
            let msg = format!("{err:#}");
            assert!(
                msg.contains(case.expected_error),
                "{}: expected error containing {:?}, got: {msg}",
                case.name,
                case.expected_error,
            );

            // Cross-check with fsck.erofs if available
            if let Some(ok) = run_fsck_erofs(&image) {
                assert!(
                    !ok,
                    "{}: fsck.erofs should also reject this corruption",
                    case.name,
                );
            }
        }
    }

    #[test]
    fn test_rejects_corrupted_nlink() {
        // Build a valid image and corrupt a leaf inode's nlink field to
        // verify nlink validation catches the mismatch.
        let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/file 5 100644 1 0 0 0 1000.0 - hello -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let base_image = mkfs_erofs(&fs);

        // Sanity check
        erofs_to_filesystem::<Sha256HashValue>(&base_image)
            .expect("unmodified image should be accepted");

        // Find the file inode and corrupt its nlink field.
        let img = Image::open(&base_image).unwrap();
        let root_nid = img.sb.root_nid.get() as u64;
        let file_nid = img.find_child_nid(root_nid, b"file").unwrap().unwrap();

        // Compute byte offset of the file's inode in the image
        let block_size = img.block_size;
        let meta_start = img.sb.meta_blkaddr.get() as usize * block_size;
        let inode_byte_offset = meta_start + file_nid as usize * 32;
        let is_extended = base_image[inode_byte_offset] & 1 != 0;
        drop(img);

        let mut image = base_image.clone();
        if is_extended {
            // ExtendedInodeHeader.nlink is U32 at byte offset 44
            let nlink_offset = inode_byte_offset + 44;
            image[nlink_offset..nlink_offset + 4].copy_from_slice(&5u32.to_le_bytes());
        } else {
            // CompactInodeHeader.nlink is U16 at byte offset 6
            let nlink_offset = inode_byte_offset + 6;
            image[nlink_offset..nlink_offset + 2].copy_from_slice(&5u16.to_le_bytes());
        }

        let result = erofs_to_filesystem::<Sha256HashValue>(&image);
        let err = result.expect_err("corrupted nlink should be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("nlink mismatch"),
            "expected nlink mismatch error, got: {msg}",
        );

        // Note: fsck.erofs (as of 1.9) does not validate nlink counts --
        // it reads nlink from disk and trusts it.  We intentionally go
        // further here.
    }

    #[test]
    fn test_rejects_corrupted_directory_nlink() {
        // Build a valid image and corrupt a directory inode's nlink to
        // verify directory nlink validation.
        let dumpfile = r#"/ 4096 40755 3 0 0 0 1000.0 - - -
/dir 4096 40755 2 0 0 0 1000.0 - - -
/file 5 100644 1 0 0 0 1000.0 - hello -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let base_image = mkfs_erofs(&fs);

        // Sanity check
        erofs_to_filesystem::<Sha256HashValue>(&base_image)
            .expect("unmodified image should be accepted");

        // Find the child directory inode and corrupt its nlink
        let img = Image::open(&base_image).unwrap();
        let root_nid = img.sb.root_nid.get() as u64;
        let dir_nid = img.find_child_nid(root_nid, b"dir").unwrap().unwrap();

        let block_size = img.block_size;
        let meta_start = img.sb.meta_blkaddr.get() as usize * block_size;
        let inode_byte_offset = meta_start + dir_nid as usize * 32;
        let is_extended = base_image[inode_byte_offset] & 1 != 0;
        drop(img);

        let mut image = base_image.clone();
        if is_extended {
            // ExtendedInodeHeader.nlink is U32 at byte offset 44
            let nlink_offset = inode_byte_offset + 44;
            image[nlink_offset..nlink_offset + 4].copy_from_slice(&99u32.to_le_bytes());
        } else {
            // CompactInodeHeader.nlink is U16 at byte offset 6
            let nlink_offset = inode_byte_offset + 6;
            image[nlink_offset..nlink_offset + 2].copy_from_slice(&99u16.to_le_bytes());
        }

        let result = erofs_to_filesystem::<Sha256HashValue>(&image);
        let err = result.expect_err("corrupted directory nlink should be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("nlink mismatch"),
            "expected directory nlink mismatch error, got: {msg}",
        );

        // Note: fsck.erofs (as of 1.9) does not validate nlink counts.
    }

    #[test]
    fn test_inode_blocks_rejects_oversized_range() {
        // Build a minimal valid EROFS image, then corrupt the root inode's
        // size field to an astronomically large value.  blocks() must
        // reject it instead of producing a trillion-element iterator.
        //
        // The corrupted size must be a multiple of block_size so that
        // additional_bytes() (which uses `size % block_size` for FlatInline)
        // stays the same and the inode still parses successfully.
        let dumpfile = "/ 0 40755 1 0 0 0 0.0 - - -\n";
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let mut image = mkfs_erofs(&fs);

        let img = Image::open(&image).unwrap();
        let root_nid = img.sb.root_nid.get() as usize;
        let block_size = img.block_size;
        let meta_start = img.sb.meta_blkaddr.get() as usize * block_size;
        let inode_offset = meta_start + root_nid * 32;
        // Determine inode layout from the first byte
        let is_extended = image[inode_offset] & 1 != 0;
        drop(img);

        // Use a huge size that is a multiple of block_size (4096) so inline
        // tail size stays 0 and the inode remains parseable.
        let huge_size: u64 = (block_size as u64) * 1_000_000_000;

        if is_extended {
            // ExtendedInodeHeader.size is a U64 at byte offset 8
            let size_offset = inode_offset + 8;
            image[size_offset..size_offset + 8].copy_from_slice(&huge_size.to_le_bytes());
        } else {
            // CompactInodeHeader.size is a U32 at byte offset 8
            let size_offset = inode_offset + 8;
            let truncated = huge_size as u32;
            image[size_offset..size_offset + 4].copy_from_slice(&truncated.to_le_bytes());
        }

        let img = Image::open(&image).unwrap();
        let root = img.root().unwrap();
        let result = img.inode_blocks(&root);
        assert!(
            result.is_err(),
            "blocks() should reject oversized block range"
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exceeds image"), "unexpected error: {err}");
    }

    mod proptest_tests {
        use super::*;
        use crate::fsverity::Sha512HashValue;
        use crate::test::proptest_strategies::{build_filesystem, filesystem_spec};
        use proptest::prelude::*;

        /// Round-trip a FileSystem through erofs and compare dumpfile output.
        fn round_trip_filesystem<ObjectID: FsVerityHashValue>(
            fs_orig: &tree::FileSystem<ObjectID>,
        ) {
            let mut orig_output = Vec::new();
            write_dumpfile(&mut orig_output, fs_orig).unwrap();

            let image = mkfs_erofs(fs_orig);
            let fs_rt = erofs_to_filesystem::<ObjectID>(&image).unwrap();

            let mut rt_output = Vec::new();
            write_dumpfile(&mut rt_output, &fs_rt).unwrap();

            similar_asserts::assert_eq!(
                String::from_utf8_lossy(&orig_output),
                String::from_utf8_lossy(&rt_output)
            );
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn test_erofs_round_trip_sha256(spec in filesystem_spec()) {
                let fs = build_filesystem::<Sha256HashValue>(spec);
                round_trip_filesystem(&fs);
            }

            #[test]
            fn test_erofs_round_trip_sha512(spec in filesystem_spec()) {
                let fs = build_filesystem::<Sha512HashValue>(spec);
                round_trip_filesystem(&fs);
            }
        }
    }

    /// Regression test for a fuzzer-found crash where duplicate directory entry
    /// names caused orphaned leaves (the second insert silently replaced the
    /// first in the BTreeMap, leaving the first leaf unreferenced).
    #[test]
    fn test_duplicate_dirent_rejected() {
        // Build a valid image with two files
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/aaa 5 100644 1 0 0 0 1000.0 - hello -
/bbb 5 100644 1 0 0 0 1000.0 - world -
"#;
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);

        // Sanity: the unmodified image round-trips fine
        erofs_to_filesystem::<Sha256HashValue>(&image).unwrap();

        // Corrupt the image: rename "bbb" to "aaa" so there's a duplicate
        let mut bad = image.clone();
        let needle = b"bbb";
        let pos = bad
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("filename not found in image");
        bad[pos..pos + needle.len()].copy_from_slice(b"aaa");

        let err = erofs_to_filesystem::<Sha256HashValue>(&bad).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Duplicate directory entry"),
            "unexpected error: {msg}"
        );
    }
}
