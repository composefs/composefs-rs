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
        self, BLOCK_BITS, COMPOSEFS_MAGIC, COMPOSEFS_VERSION, COMPOSEFS_VERSION_V0,
        COMPOSEFS_VERSION_V1, CompactInodeHeader, ComposefsHeader, DataLayout,
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
        // Reject unknown composefs versions.
        //   0 = V1 (C-compatible, no user whiteouts)
        //   1 = V1 (C-compatible, user whiteouts present — C bumps version when it
        //           encounters a char-device-rdev-0 entry in the input tree)
        //   2 = V2 (Rust-native format)
        let cv = self.header.composefs_version.get();
        if cv != COMPOSEFS_VERSION.get()
            && cv != COMPOSEFS_VERSION_V1.get()
            && cv != COMPOSEFS_VERSION_V0.get()
        {
            return Err(ErofsReaderError::InvalidImage(format!(
                "unknown composefs_version {cv} (expected 0, 1, or {})",
                COMPOSEFS_VERSION.get(),
            )));
        }

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
    /// Returns a byte slice of the image at `[offset, offset+len)`, validating
    /// that both the offset and the range lie within the image.
    ///
    /// This is the single choke point for all raw byte accesses derived from
    /// image fields (block addresses, xattr offsets, etc.).  All callers that
    /// compute `blkaddr * block_size + delta` should go through here rather
    /// than slicing `self.image` directly.
    pub fn image_slice(&self, offset: usize, len: usize) -> Result<&[u8], ErofsReaderError> {
        let end = offset
            .checked_add(len)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        self.image
            .get(offset..end)
            .ok_or(ErofsReaderError::OutOfBounds)
    }

    /// Returns a block by its ID as a raw byte slice, validated against the image size.
    pub fn block(&self, id: u64) -> Result<&[u8], ErofsReaderError> {
        let start = usize::try_from(id)
            .ok()
            .and_then(|id| id.checked_mul(self.block_size))
            .ok_or(ErofsReaderError::OutOfBounds)?;
        self.image_slice(start, self.block_size)
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

    /// Performs a full structural fsck of the image metadata by traversing the
    /// entire inode tree.
    ///
    /// This is separate from [`Self::restrict_to_composefs`], which only checks
    /// superblock and header fields without any traversal.  Call this when you
    /// want a thorough integrity check (e.g. during repository fsck) rather than
    /// just the cheap open-time validation.
    ///
    /// Currently checks:
    /// - V1 images: no FlatInline symlink inode has a block-boundary layout that
    ///   old Linux kernels (< 6.12) would reject with `EFSCORRUPTED` (`EUCLEAN`).
    /// - Epoch-invariant rules (see [`Self::validate_epoch_invariants`]).
    pub fn fsck_metadata(&self) -> Result<(), ErofsReaderError> {
        self.validate_v1_inline_layout()?;
        self.validate_epoch_invariants()
    }

    /// Validates epoch-invariant structural rules that must hold for every
    /// well-formed composefs image depending on its format epoch.
    ///
    /// **Epoch1** (`composefs_version` 0 or 1 — compact inodes, BFS, whiteout table):
    /// 1. The root directory must contain exactly 256 entries with 2-hex-char names
    ///    (the whiteout stub table slots, 00–ff).  Each slot may be occupied by
    ///    either a native whiteout stub (char-device rdev=0,0), an escaped whiteout
    ///    (regular file + `trusted.overlay.overlay.whiteout` xattr), or a
    ///    pre-existing user entry that shadowed the stub during image creation.
    /// 2. No native whiteout (char-device rdev=0,0) may appear outside the root
    ///    stub table.
    ///
    /// **Epoch2** (`composefs_version` 2 — extended inodes, DFS, no whiteout table):
    /// 1. The root directory must contain no entries with a 2-hex-char name that
    ///    are native whiteouts or escaped whiteouts (i.e., no stub-pattern entries).
    /// 2. No escaped whiteout (regular file + `trusted.overlay.overlay.whiteout`
    ///    xattr) may appear anywhere in the tree.
    fn validate_epoch_invariants(&self) -> Result<(), ErofsReaderError> {
        let cv = self.header.composefs_version.get();
        let is_epoch1 =
            cv == format::COMPOSEFS_VERSION_V0.get() || cv == format::COMPOSEFS_VERSION_V1.get();
        let is_epoch2 = cv == format::COMPOSEFS_VERSION.get();

        // Only validate images with a known composefs_version; images opened
        // without restrict_to_composefs() may have an arbitrary version field.
        if !is_epoch1 && !is_epoch2 {
            return Ok(());
        }

        let root_nid = self.sb.root_nid.get() as u64;

        // Helper: return true iff a name is exactly two *lowercase* hex digits.
        // The stub table uses lowercase names (00..ff) generated by format!("{:02x}").
        // Uppercase hex names (e.g. "AB") are distinct entries and are not stub slots.
        let is_lowercase_hex2 = |name: &[u8]| -> bool {
            name.len() == 2
                && name
                    .iter()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        };

        // --- Walk all directories (BFS) ---
        // We use an explicit stack to avoid recursion depth issues.
        let mut stack = vec![root_nid];
        let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();

        // Track the number of hex-named root entries (used for Epoch1 check 1).
        // Each of the 256 slots (00..ff) must appear exactly once.
        let mut root_hex_slots: std::collections::HashSet<[u8; 2]> =
            std::collections::HashSet::new();

        while let Some(dir_nid) = stack.pop() {
            if !visited.insert(dir_nid) {
                continue;
            }

            let dir_inode = match self.inode(dir_nid) {
                Ok(i) => i,
                Err(_) => continue,
            };

            if !dir_inode.mode().is_dir() {
                continue;
            }

            let is_root = dir_nid == root_nid;

            // Collect children from both block-based and inline directory data.
            let mut children: Vec<(Vec<u8>, u64)> = Vec::new();

            if let Ok(range) = self.inode_blocks(&dir_inode) {
                for blkid in range {
                    if let Ok(block) = self.directory_block(blkid)
                        && let Ok(entries) = block.entries()
                    {
                        for entry in entries.flatten() {
                            if entry.name != b"." && entry.name != b".." {
                                children.push((entry.name.to_vec(), entry.nid()));
                            }
                        }
                    }
                }
            }

            if let Some(inline) = dir_inode.inline()
                && let Ok(block) = DirectoryBlock::ref_from_bytes(inline)
                && let Ok(entries) = block.entries()
            {
                for entry in entries.flatten() {
                    if entry.name != b"." && entry.name != b".." {
                        children.push((entry.name.to_vec(), entry.nid()));
                    }
                }
            }

            for (name, child_nid) in children {
                let child_inode = match self.inode(child_nid) {
                    Ok(i) => i,
                    Err(_) => continue,
                };

                // Track hex-named root entries for Epoch1 stub table check.
                if is_epoch1 && is_root && is_lowercase_hex2(&name) {
                    root_hex_slots.insert([name[0], name[1]]);
                }

                // Recurse into subdirectories.
                if child_inode.mode().is_dir() {
                    stack.push(child_nid);
                    continue;
                }

                let is_native_whiteout = child_inode.is_whiteout();
                let is_escaped = is_escaped_v1_whiteout(self, &child_inode)
                    .map_err(|e| ErofsReaderError::InvalidImage(e.to_string()))?;

                if is_epoch1 {
                    if !is_root && is_native_whiteout {
                        // Epoch1 must not have native whiteouts outside the root stub table.
                        return Err(ErofsReaderError::InvalidImage(
                            "Epoch1 image contains native whiteout outside root stubs".into(),
                        ));
                    }
                } else {
                    // is_epoch2: native whiteouts (char-device 0,0) are valid user
                    // whiteouts regardless of their name or location.  The only thing
                    // that must not appear is an *escaped* whiteout (regular file +
                    // trusted.overlay.overlay.whiteout xattr), which is a V1-only
                    // encoding and has no place in a V2 image.
                    if is_escaped {
                        return Err(ErofsReaderError::InvalidImage(
                            "Epoch2 image contains escaped whiteout".into(),
                        ));
                    }
                }
            }
        }

        // Epoch1: every hex slot 00..ff must be present in the root.
        // The writer fills missing slots with stub entries; slots occupied by
        // pre-existing user content are also valid (the stub was skipped).
        if is_epoch1 && root_hex_slots.len() != 256 {
            return Err(ErofsReaderError::InvalidImage(format!(
                "Epoch1 image has {} hex-named root entries, expected 256 (00–ff)",
                root_hex_slots.len(),
            )));
        }

        Ok(())
    }

    /// Validates that the image does not contain FlatInline inodes with a layout
    /// that old Linux kernels (< 6.12) would reject with `EFSCORRUPTED` (`EUCLEAN`).
    ///
    /// Only V1 (C-compatible, `composefs_version` = 0 or 1) images are expected to be
    /// mounted on kernels that may predate the 6.12 fix; V2 images use a different
    /// block-boundary strategy that is frozen for digest stability, so this check
    /// is deliberately restricted to V1.
    ///
    /// The kernel's pre-6.12 fast-symlink path checks:
    /// ```text
    /// (inode_offset % block_size) + inode_and_xattr_size + inline_size > block_size
    /// ```
    /// and returns `-EFSCORRUPTED` if true.  This method returns an error for any
    /// inode where that condition holds.
    fn validate_v1_inline_layout(&self) -> Result<(), ErofsReaderError> {
        // Only applies to V1 (C-compatible) images: composefs_version 0 (no user
        // whiteouts) or 1 (user whiteouts present).  V2 images (composefs_version=2)
        // use a frozen layout strategy and are never mounted on pre-6.12 kernels.
        let cv = self.header.composefs_version.get();
        if cv >= format::COMPOSEFS_VERSION.get() {
            return Ok(());
        }

        let block_size = self.block_size as u64;

        // Walk all reachable inodes from the root rather than iterating raw nid slots.
        // The inode table is not densely packed — gaps arise from padding — so
        // iterating 0..sb.inos by slot can hit mid-inode bytes that accidentally
        // parse as valid-looking headers with garbage xattr_icount values.
        let mut stack = vec![self.sb.root_nid.get() as u64];
        let mut visited = std::collections::HashSet::new();

        while let Some(nid) = stack.pop() {
            if !visited.insert(nid) {
                continue;
            }
            let inode = match self.inode(nid) {
                Ok(i) => i,
                Err(_) => continue,
            };

            // Recurse into directories to find all symlink inodes.
            if inode.mode().is_dir() {
                // Collect child nids from both inline and block directory data.
                let mut child_nids: Vec<u64> = Vec::new();
                if let Some(inline) = inode.inline()
                    && let Ok(block) = DirectoryBlock::ref_from_bytes(inline)
                    && let Ok(entries) = block.entries()
                {
                    for entry in entries.flatten() {
                        let name = entry.name;
                        if name == b"." || name == b".." {
                            continue;
                        }
                        child_nids.push(entry.nid());
                    }
                }
                if let Ok(range) = self.inode_blocks(&inode) {
                    for blkid in range {
                        if let Ok(block) = self.directory_block(blkid)
                            && let Ok(entries) = block.entries()
                        {
                            for entry in entries.flatten() {
                                let name = entry.name;
                                if name == b"." || name == b".." {
                                    continue;
                                }
                                child_nids.push(entry.nid());
                            }
                        }
                    }
                }
                stack.extend(child_nids);
                continue;
            }

            // Only the pre-6.12 symlink fast-path checks the block boundary.
            let mode = inode.mode().0.get();
            if mode & S_IFMT != S_IFLNK {
                continue;
            }

            let layout = match inode.data_layout() {
                Ok(l) => l,
                Err(_) => continue,
            };
            if !matches!(layout, DataLayout::FlatInline) {
                continue; // symlink stored out-of-band (long target > block_size)
            }

            let inline_size = inode.size() % block_size;
            if inline_size == 0 {
                continue;
            }

            // nid * 32 is the byte offset from meta_start (which is 0 for composefs).
            let inode_offset = nid
                .checked_mul(32)
                .ok_or_else(|| ErofsReaderError::InvalidImage("nid overflow".into()))?;
            let inode_pos_in_block = inode_offset % block_size;

            let header_size: u64 = match &inode {
                InodeType::Compact(_) => size_of::<CompactInodeHeader>() as u64,
                InodeType::Extended(_) => size_of::<ExtendedInodeHeader>() as u64,
            };
            let xattr_size = inode.xattr_size() as u64;
            let inode_and_xattr_size = header_size.checked_add(xattr_size).ok_or_else(|| {
                ErofsReaderError::InvalidImage("inode+xattr size overflow".into())
            })?;

            let total = inode_pos_in_block
                .checked_add(inode_and_xattr_size)
                .and_then(|t| t.checked_add(inline_size))
                .ok_or_else(|| {
                    ErofsReaderError::InvalidImage("inline layout size overflow".into())
                })?;
            if total > block_size {
                return Err(ErofsReaderError::InvalidImage(format!(
                    "inode at nid {nid} (FlatInline symlink, inode_pos_in_block={inode_pos_in_block}, \
                     inode_and_xattr_size={inode_and_xattr_size}, inline_size={inline_size}) \
                     would trigger EUCLEAN on kernels older than 6.12: \
                     {inode_pos_in_block} + {inode_and_xattr_size} + {inline_size} = {total} > {block_size}"
                )));
            }
        }

        Ok(())
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

/// Check if an inode is a V1 escaped whiteout (a regular file carrying the
/// `trusted.overlay.overlay.whiteout` xattr added by the V1 writer).
///
/// C composefs v1.0.8 converts char-device-rdev-0 entries to regular files
/// on write (whiteout escaping).  The reader must reverse this.
fn is_escaped_v1_whiteout(img: &Image, inode: &InodeType) -> anyhow::Result<bool> {
    let file_type = inode.mode().0.get() & S_IFMT;
    if file_type != S_IFREG {
        return Ok(false);
    }

    let Some(xattrs_section) = inode.xattrs()? else {
        return Ok(false);
    };

    // Check shared xattrs
    for id in xattrs_section.shared()? {
        let xattr = img.shared_xattr(id.get())?;
        let full_name = construct_xattr_name(xattr)?;
        if full_name == format::XATTR_OVERLAY_WHITEOUT {
            return Ok(true);
        }
    }
    // Check local xattrs
    for xattr in xattrs_section.local()? {
        let xattr = xattr?;
        let full_name = construct_xattr_name(xattr)?;
        if full_name == format::XATTR_OVERLAY_WHITEOUT {
            return Ok(true);
        }
    }
    Ok(false)
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
        if attr.header.name_index != 4 {
            return Ok(());
        }
        let suffix = attr.suffix()?;
        if suffix == b"overlay.metacopy" {
            if let Ok(value) = OverlayMetacopy::read_from_bytes(attr.value()?)
                && value.valid()
            {
                self.objects.insert(value.digest);
            }
        } else if suffix == b"overlay.redirect" {
            let value = attr.value()?;
            let path = value.strip_prefix(b"/").unwrap_or(value);
            if let Ok(id) = ObjectID::from_object_pathname(path) {
                self.objects.insert(id);
            }
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
    img.fsck_metadata()?;
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
            // Compact inodes don't store mtime; use superblock build_time
            // (the writer sets build_time = min mtime across all inodes)
            img.sb.build_time.get() as i64,
            // and build_time_nsec for the nanosecond component
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

    // Skip internal overlay xattrs added by the writer (metacopy/redirect
    // are composefs-internal and should not be exposed to readers).
    if full_name == format::XATTR_OVERLAY_METACOPY || full_name == format::XATTR_OVERLAY_REDIRECT {
        return Ok(None);
    }

    // V1 whiteout escaping artifacts: strip these internal xattrs.
    // XATTR_OVERLAY_WHITEOUT signals the inode is a whiteout (handled separately).
    // The *_WHITEOUTS, *_OPAQUE, and user-namespace variants are parent-dir markers
    // added by the V1 writer that are composefs-internal.
    // Note: XATTR_OVERLAY_OPAQUE must be listed explicitly here because the general
    // unescape handler below would otherwise expose it as trusted.overlay.opaque.
    if full_name == format::XATTR_OVERLAY_WHITEOUT
        || full_name == format::XATTR_OVERLAY_WHITEOUTS
        || full_name == format::XATTR_OVERLAY_OPAQUE
        || full_name == format::XATTR_USERXATTR_WHITEOUT
        || full_name == format::XATTR_USERXATTR_WHITEOUTS
        || full_name == format::XATTR_USERXATTR_OPAQUE
    {
        return Ok(None);
    }

    // Unescape: trusted.overlay.overlay.X -> trusted.overlay.X
    if let Some(rest) = full_name.strip_prefix(format::XATTR_OVERLAY_ESCAPED_PREFIX) {
        let mut unescaped = format::XATTR_OVERLAY_PREFIX.to_vec();
        unescaped.extend_from_slice(rest);
        let name = Box::from(OsStr::from_bytes(&unescaped));
        let value = Box::from(xattr.value()?);
        return Ok(Some((name, value)));
    }
    // Skip all other trusted.overlay.* xattrs (internal to composefs)
    if full_name.starts_with(format::XATTR_OVERLAY_PREFIX) {
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

/// Try to extract the object ID from a redirect xattr (`trusted.overlay.redirect`).
///
/// The redirect value is a path like `/55/90e94b...` from which we parse
/// the object ID.  Returns `None` if no redirect xattr is present.
fn extract_redirect_object_id<ObjectID: FsVerityHashValue>(
    img: &Image,
    inode: &InodeType,
) -> anyhow::Result<Option<ObjectID>> {
    let Some(xattrs_section) = inode.xattrs()? else {
        return Ok(None);
    };

    for id in xattrs_section.shared()? {
        let xattr = img.shared_xattr(id.get())?;
        if let Some(obj) = check_redirect_xattr(xattr)? {
            return Ok(Some(obj));
        }
    }
    for xattr in xattrs_section.local()? {
        let xattr = xattr?;
        if let Some(obj) = check_redirect_xattr(xattr)? {
            return Ok(Some(obj));
        }
    }
    Ok(None)
}

fn check_redirect_xattr<ObjectID: FsVerityHashValue>(
    xattr: &XAttr,
) -> anyhow::Result<Option<ObjectID>> {
    if xattr.header.name_index != 4 {
        return Ok(None);
    }
    if xattr.suffix()? != b"overlay.redirect" {
        return Ok(None);
    }
    let value = xattr.value()?;
    let path = value.strip_prefix(b"/").unwrap_or(value);
    match ObjectID::from_object_pathname(path) {
        Ok(id) => Ok(Some(id)),
        Err(_) => Ok(None),
    }
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
    if value_bytes.is_empty() {
        return Ok(None);
    }
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

        // Skip overlay whiteout entries — but only in the root directory.
        // C composefs only skips hex-named (00–ff) chardev(0,0) entries in root
        // (lcfs-writer-erofs.c: "Skip real whiteouts (00-ff)").
        // A chardev(0,0) in a subdirectory is a legitimate device node.
        //
        // In V1 images the writer escapes whiteouts to regular files with
        // trusted.overlay.overlay.whiteout xattr, so we must check both
        // the native chardev form and the escaped regular-file form.
        let is_root_dir = dir_nid == img.sb.root_nid.get() as u64;
        let is_escaped_whiteout = is_escaped_v1_whiteout(img, &child_inode)?;
        let is_native_whiteout = child_inode.is_whiteout();
        if is_root_dir
            && (is_native_whiteout || is_escaped_whiteout)
            && name_bytes.len() == 2
            && name_bytes.iter().all(|b| b.is_ascii_hexdigit())
        {
            continue;
        }

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

            // V1 images escape whiteouts (char dev rdev=0) to regular files.
            // The is_escaped_whiteout flag was computed above (before the
            // root-dir skip check), so check it before the file-type match.
            let content = if is_escaped_whiteout {
                tree::LeafContent::CharacterDevice(0)
            } else {
                match file_type {
                    S_IFREG => {
                        if let Some(digest) =
                            extract_metacopy_digest::<ObjectID>(img, &child_inode)?
                        {
                            tree::LeafContent::Regular(tree::RegularFile::External(
                                digest,
                                child_inode.size(),
                            ))
                        } else if let Some(id) =
                            extract_redirect_object_id::<ObjectID>(img, &child_inode)?
                        {
                            tree::LeafContent::Regular(tree::RegularFile::ExternalNoVerity(
                                id,
                                child_inode.size(),
                            ))
                        } else if child_inode.data_layout()? == DataLayout::ChunkBased {
                            tree::LeafContent::Regular(tree::RegularFile::Sparse(
                                child_inode.size(),
                            ))
                        } else {
                            if img.composefs_restricted
                                && img.header.composefs_version == COMPOSEFS_VERSION
                            {
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
                        let target_data = extract_all_file_data(img, &child_inode)?;
                        if img.composefs_restricted
                            && img.header.composefs_version == COMPOSEFS_VERSION
                            && target_data.len() > crate::SYMLINK_MAX
                        {
                            anyhow::bail!(
                                "symlink target for {:?} is {} bytes (max {})",
                                name,
                                target_data.len(),
                                crate::SYMLINK_MAX,
                            );
                        }
                        let target = OsStr::from_bytes(&target_data);
                        tree::LeafContent::Symlink(Box::from(target))
                    }
                    S_IFBLK => tree::LeafContent::BlockDevice(child_inode.u() as u64),
                    S_IFCHR => tree::LeafContent::CharacterDevice(child_inode.u() as u64),
                    S_IFIFO => tree::LeafContent::Fifo,
                    S_IFSOCK => tree::LeafContent::Socket,
                    _ => anyhow::bail!("unknown file type {:#o} for {:?}", file_type, name),
                }
            };

            // Hardlinked whiteouts are semantically invalid: a whiteout represents the
            // absence of a file in an overlay, so nlink > 1 is meaningless.
            let on_disk_nlink = child_inode.nlink();
            if matches!(content, tree::LeafContent::CharacterDevice(0)) && on_disk_nlink > 1 {
                anyhow::bail!(
                    "invalid composefs image: whiteout inode {:?} has nlink > 1",
                    name
                );
            }

            let leaf_id = builder.push_leaf(stat, content);

            // Track for hardlink detection if nlink > 1
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
        erofs::writer::{ValidatedFileSystem, mkfs_erofs},
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
        let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());
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
        let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());
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
        let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());
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
        let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());
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
        let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());
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
        let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());

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
        let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());
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

        let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs_orig).unwrap());
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
        let mut vfs_orig = ValidatedFileSystem::new(fs_orig).unwrap();
        let image = mkfs_erofs(&mut vfs_orig);
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
        write_dumpfile(&mut orig_output, &vfs_orig.0).unwrap();
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
        let base_image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());

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
        let base_image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());

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
            let entry_start = inline_offset + case.entry_byte_offset;
            // Write a bogus nid (0xDEAD) that doesn't match the directory's own nid
            // Use zerocopy to get a typed &mut DirectoryEntryHeader instead of raw bytes.
            let hdr = DirectoryEntryHeader::mut_from_bytes(
                &mut image[entry_start..entry_start + size_of::<DirectoryEntryHeader>()],
            )
            .expect("entry slice must be a valid DirectoryEntryHeader");
            hdr.inode_offset = zerocopy::little_endian::U64::new(0xDEAD);

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
        let base_image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());

        // Sanity check
        erofs_to_filesystem::<Sha256HashValue>(&base_image)
            .expect("unmodified image should be accepted");

        // Find the file inode and corrupt its nlink field.
        let img = Image::open(&base_image).unwrap();
        let root_nid = img.sb.root_nid.get() as u64;
        let file_nid = img.find_child_nid(root_nid, b"file").unwrap().unwrap();

        // Use the typed Image API to locate the inode slot without raw byte arithmetic.
        let inode = img.inode(file_nid).unwrap();
        let is_extended = matches!(inode, InodeType::Extended(_));
        let inodes_start = img.image.len() - img.inodes.len();
        let inode_slot_start = inodes_start + file_nid as usize * 32;
        drop(inode);
        drop(img);

        let mut image = base_image.clone();
        let slot = &mut image[inode_slot_start..];
        if is_extended {
            let hdr =
                ExtendedInodeHeader::mut_from_bytes(&mut slot[..size_of::<ExtendedInodeHeader>()])
                    .expect("inode slot must be a valid ExtendedInodeHeader");
            hdr.nlink = zerocopy::little_endian::U32::new(5);
        } else {
            let hdr =
                CompactInodeHeader::mut_from_bytes(&mut slot[..size_of::<CompactInodeHeader>()])
                    .expect("inode slot must be a valid CompactInodeHeader");
            hdr.nlink = zerocopy::little_endian::U16::new(5);
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
        let base_image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());

        // Sanity check
        erofs_to_filesystem::<Sha256HashValue>(&base_image)
            .expect("unmodified image should be accepted");

        // Find the child directory inode and corrupt its nlink
        let img = Image::open(&base_image).unwrap();
        let root_nid = img.sb.root_nid.get() as u64;
        let dir_nid = img.find_child_nid(root_nid, b"dir").unwrap().unwrap();

        // Use the typed Image API to locate the inode slot without raw byte arithmetic.
        let inode = img.inode(dir_nid).unwrap();
        let is_extended = matches!(inode, InodeType::Extended(_));
        let inodes_start = img.image.len() - img.inodes.len();
        let inode_slot_start = inodes_start + dir_nid as usize * 32;
        drop(inode);
        drop(img);

        let mut image = base_image.clone();
        let slot = &mut image[inode_slot_start..];
        if is_extended {
            let hdr =
                ExtendedInodeHeader::mut_from_bytes(&mut slot[..size_of::<ExtendedInodeHeader>()])
                    .expect("inode slot must be a valid ExtendedInodeHeader");
            hdr.nlink = zerocopy::little_endian::U32::new(99);
        } else {
            let hdr =
                CompactInodeHeader::mut_from_bytes(&mut slot[..size_of::<CompactInodeHeader>()])
                    .expect("inode slot must be a valid CompactInodeHeader");
            hdr.nlink = zerocopy::little_endian::U16::new(99);
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
        let mut image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());

        let img = Image::open(&image).unwrap();
        let root_nid = img.sb.root_nid.get() as u64;
        let block_size = img.block_size;

        // Use the typed Image API to locate the inode slot without raw byte arithmetic.
        let inode = img.inode(root_nid).unwrap();
        let is_extended = matches!(inode, InodeType::Extended(_));
        let inodes_start = img.image.len() - img.inodes.len();
        let inode_slot_start = inodes_start + root_nid as usize * 32;
        drop(inode);
        drop(img);

        // Use a huge size that is a multiple of block_size (4096) so inline
        // tail size stays 0 and the inode remains parseable.
        let huge_size: u64 = (block_size as u64) * 1_000_000_000;

        let slot = &mut image[inode_slot_start..];
        if is_extended {
            let hdr =
                ExtendedInodeHeader::mut_from_bytes(&mut slot[..size_of::<ExtendedInodeHeader>()])
                    .expect("inode slot must be a valid ExtendedInodeHeader");
            hdr.size = zerocopy::little_endian::U64::new(huge_size);
        } else {
            let hdr =
                CompactInodeHeader::mut_from_bytes(&mut slot[..size_of::<CompactInodeHeader>()])
                    .expect("inode slot must be a valid CompactInodeHeader");
            hdr.size = zerocopy::little_endian::U32::new(huge_size as u32);
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
        use crate::erofs::{format::FormatVersion, writer::mkfs_erofs_versioned};
        use crate::fsverity::Sha512HashValue;
        use crate::test::proptest_strategies::{
            FsSpec, build_filesystem, build_unusual_filesystem, filesystem_spec,
            unusual_filesystem_spec,
        };
        use proptest::prelude::*;

        /// Round-trip a FileSystem through V2 erofs and compare dumpfile output.
        ///
        /// V2 EROFS does not store mtime nanoseconds: the on-disk `mtime_nsec`
        /// field is always zero.  Build the expected dumpfile from a copy of the
        /// filesystem with `mtime_nsec` zeroed so the comparison reflects what
        /// V2 actually stores, not what the in-memory tree carries.
        fn round_trip_filesystem<ObjectID: FsVerityHashValue>(spec: FsSpec) {
            // fs_write → source for the EROFS image.
            // fs_expected → reference with mtime_nsec=0, matching V2 on-disk format.
            let fs_write = build_filesystem::<ObjectID>(spec.clone());
            let mut fs_expected = build_filesystem::<ObjectID>(spec);
            // V2 EROFS does not store mtime nanoseconds; zero them before comparing.
            fs_expected.for_each_stat_mut(|s| s.st_mtim_nsec = 0);

            let mut expected_output = Vec::new();
            write_dumpfile(&mut expected_output, &fs_expected).unwrap();

            let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs_write).unwrap());
            let fs_rt = erofs_to_filesystem::<ObjectID>(&image).unwrap();

            let mut rt_output = Vec::new();
            write_dumpfile(&mut rt_output, &fs_rt).unwrap();

            similar_asserts::assert_eq!(
                String::from_utf8_lossy(&expected_output),
                String::from_utf8_lossy(&rt_output)
            );
        }

        /// Round-trip a FileSystem through V1 erofs and compare dumpfile output.
        ///
        /// V1 uses compact inodes (when mtime matches the minimum), BFS ordering,
        /// and includes overlay whiteout character device entries in the root.
        /// The writer adds `trusted.overlay.opaque` to the root; the reader strips
        /// internal overlay xattrs. Whiteout char-device entries (00–ff in root)
        /// are also stripped, matching C composefs reader behaviour.
        fn round_trip_filesystem_v1<ObjectID: FsVerityHashValue>(spec: FsSpec) {
            // Build two separate filesystems from the same spec so we avoid
            // Rc::strong_count issues from sharing leaf Rcs.
            let fs_write = build_filesystem::<ObjectID>(spec.clone());
            let fs_expected = build_filesystem::<ObjectID>(spec);

            // The writer internally adds trusted.overlay.opaque=y to root and
            // the 256 V1 whiteout stubs; the reader strips all trusted.overlay.*
            // but the reader strips all trusted.overlay.* xattrs that aren't
            // escaped user xattrs. So the expected filesystem should NOT have it.

            // Generate the V1 image from the write filesystem.
            let image = mkfs_erofs_versioned(
                &mut ValidatedFileSystem::new(fs_write).unwrap(),
                FormatVersion::V1,
            );

            // Validate the layout invariant: no FlatInline inode should
            // trigger EUCLEAN on kernels < 6.12. This catches the
            // block-boundary bug even when proptest doesn't generate a
            // case large enough to trip it at mount time.
            Image::open(&image)
                .unwrap()
                .fsck_metadata()
                .expect("V1 image should have valid inline layout for pre-6.12 kernels");

            // Read back from the image.
            let fs_rt = erofs_to_filesystem::<ObjectID>(&image).unwrap();

            // Compare via dumpfile serialization.
            let mut expected_output = Vec::new();
            write_dumpfile(&mut expected_output, &fs_expected).unwrap();

            let mut rt_output = Vec::new();
            write_dumpfile(&mut rt_output, &fs_rt).unwrap();

            if expected_output != rt_output {
                let expected_str = String::from_utf8_lossy(&expected_output);
                let rt_str = String::from_utf8_lossy(&rt_output);
                panic!(
                    "V1 round-trip mismatch:\n--- expected ---\n{expected_str}\n--- got ---\n{rt_str}"
                );
            }
        }

        /// Verify that C composefs-info can parse an EROFS image we generated,
        /// and that its dump output matches our Rust reader's interpretation.
        ///
        /// This is the critical compatibility test: it proves that EROFS images
        /// produced by our writer are consumable by the C implementation.
        fn verify_c_composefs_info_reads_image(image: &[u8]) {
            use std::io::Write;

            // Validate layout invariant before testing C reader compatibility.
            Image::open(image)
                .unwrap()
                .fsck_metadata()
                .expect("image should have valid inline layout for pre-6.12 kernels");

            // Write image to a tempfile
            let mut tmp = tempfile::NamedTempFile::new().unwrap();
            tmp.write_all(image).unwrap();
            tmp.flush().unwrap();

            // Run C composefs-info dump on the image with a timeout.
            let child = std::process::Command::new("composefs-info")
                .arg("dump")
                .arg(tmp.path())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();

            let output = {
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let _ = tx.send(child.wait_with_output());
                });
                rx.recv_timeout(std::time::Duration::from_secs(10))
                    .expect("composefs-info timed out after 10 seconds")
                    .unwrap()
            };

            if !output.status.success() {
                panic!(
                    "C composefs-info dump failed (exit {:?}):\nstderr: {}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr),
                );
            }

            let c_dump = String::from_utf8(output.stdout).expect("C dump should be valid UTF-8");

            // Get our Rust reader's interpretation of the same image
            let fs_rt = erofs_to_filesystem::<Sha256HashValue>(image).unwrap();
            let mut rust_dump_bytes = Vec::new();
            write_dumpfile(&mut rust_dump_bytes, &fs_rt).unwrap();
            let rust_dump = String::from_utf8(rust_dump_bytes).unwrap();

            // Parse both dumps into structured entries, then normalize and
            // compare. This avoids fragile string munging and lets the
            // dumpfile parser handle escaping, field splitting, etc.
            //
            // Apply the C reader empty-xattr workaround to the Rust dump as
            // well: we are testing C-reader compatibility here, so we strip
            // the same entries C would silently drop. Rust-only round-trip
            // tests (test_erofs_round_trip_*) compare dumpfiles directly
            // without this workaround, catching Rust writer bugs without masking them.
            let c_entries = parse_c_dump(&c_dump);
            let rust_entries = parse_c_dump(&rust_dump);

            similar_asserts::assert_eq!(c_entries, rust_entries);
        }

        /// Parse a dump produced by C composefs-info and normalize for comparison.
        ///
        /// Applies the empty-xattr workaround for the known C reader bug: the
        /// inline-xattr loop uses strict `<` instead of `<=` when checking the
        /// end pointer, so it silently skips the last entry whenever it is exactly
        /// 4 bytes (header only: name_len=0, value_size=0). This occurs for
        /// system.posix_acl_access/default with empty values, where the prefix
        /// index encodes the full key leaving a zero-length suffix.
        fn parse_c_dump(dump: &str) -> Vec<String> {
            normalize_dump(dump, true)
        }

        /// Parse a dump produced by our Rust reader and normalize for comparison.
        ///
        /// Does NOT apply the C reader empty-xattr workaround — Rust output must
        /// be left unfiltered so any Rust writer bugs producing empty xattrs are
        /// caught rather than silently masked.
        ///
        /// For C compat tests, use [`parse_c_dump`] on both sides so the
        /// comparison accounts for the known C reader limitation.

        fn normalize_dump(dump: &str, strip_empty_xattrs: bool) -> Vec<String> {
            use crate::dumpfile_parse::{Entry, Item};
            use std::os::unix::ffi::OsStrExt;

            dump.lines()
                .filter(|line| !line.is_empty())
                .filter_map(|line| {
                    let mut entry = Entry::parse(line).unwrap_or_else(|e| {
                        panic!("Failed to parse dump line: {e}\n  line: {line}")
                    });

                    // C composefs-info (lcfs_build_node_from_image) unconditionally
                    // treats any chardev with rdev=0 as a whiteout and skips it,
                    // returning ENOTSUP regardless of where in the tree it appears:
                    //
                    //   if (type == S_IFCHR && node->inode.st_rdev == 0) {
                    //       errno = ENOTSUP;
                    //       return NULL;
                    //   }
                    //
                    // Our Rust reader preserves chardev(0,0) entries in subdirectories
                    // (it only strips the root-level 00–ff overlay whiteout stubs).
                    // Strip all chardev(0,0) entries from both sides of the comparison
                    // so the test reflects what C actually outputs.
                    if let Item::Device { rdev: 0, .. } = entry.item {
                        if (entry.mode & 0o170000) == 0o20000 {
                            return None;
                        }
                    }

                    if strip_empty_xattrs {
                        entry.xattrs.retain(|x| !x.value.is_empty());
                    }
                    // Strip overlay xattrs that the C reader keeps but our Rust reader
                    // strips as composefs-internal:
                    // - user.overlay.opaque: OVERLAY_XATTR_USERXATTR_OPAQUE, kept by C
                    // - trusted.overlay.opaque: the C reader unescapes
                    //   trusted.overlay.overlay.opaque to this; Rust strips the
                    //   escaped form before unescaping so it never appears in Rust
                    //   output.  Normalizing both sides makes the comparison test
                    //   semantic content rather than internal overlay state.
                    entry.xattrs.retain(|x| {
                        x.key.as_bytes() != b"user.overlay.opaque"
                            && x.key.as_bytes() != b"trusted.overlay.opaque"
                    });
                    Some(entry.to_string())
                })
                .collect()
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(200))]

            #[test]
            fn test_erofs_round_trip_sha256(spec in filesystem_spec()) {
                round_trip_filesystem::<Sha256HashValue>(spec);
            }

            #[test]
            fn test_erofs_round_trip_sha512(spec in filesystem_spec()) {
                round_trip_filesystem::<Sha512HashValue>(spec);
            }

            #[test]
            fn test_erofs_round_trip_v1_sha256(spec in filesystem_spec()) {
                round_trip_filesystem_v1::<Sha256HashValue>(spec);
            }

            #[test]
            fn test_erofs_round_trip_v1_sha512(spec in filesystem_spec()) {
                round_trip_filesystem_v1::<Sha512HashValue>(spec);
            }

        }

        /// Verify C composefs-info can parse random V1 (C-compatible) EROFS
        /// images generated by our writer, and that its dump output matches
        /// our Rust reader's interpretation.
        #[test_with::executable(composefs-info)]
        #[test]
        fn test_c_composefs_info_reads_v1() {
            let mut runner =
                proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(200));
            runner
                .run(&filesystem_spec(), |spec| {
                    let fs = build_filesystem::<Sha256HashValue>(spec);
                    let image = mkfs_erofs_versioned(
                        &mut ValidatedFileSystem::new(fs).unwrap(),
                        FormatVersion::V1,
                    );
                    verify_c_composefs_info_reads_image(&image);
                    Ok(())
                })
                .unwrap();
        }

        /// Verify C composefs-info can parse random V2 (Rust-native) EROFS
        /// images generated by our writer.
        #[test_with::executable(composefs-info)]
        #[test]
        fn test_c_composefs_info_reads_v2() {
            let mut runner =
                proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(200));
            runner
                .run(&filesystem_spec(), |spec| {
                    let fs = build_filesystem::<Sha256HashValue>(spec);
                    let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());
                    verify_c_composefs_info_reads_image(&image);
                    Ok(())
                })
                .unwrap();
        }

        /// Verify C composefs-info can parse random V2 EROFS images generated from
        /// unusual content (whiteout escaping, ACLs, multiple overlay xattrs, large
        /// external files, cross-type hardlinks), and that its dump output matches
        /// our Rust reader's interpretation.
        ///
        /// Mirrors `test_v1_binary_identical_unusual_content` but for V2 images
        /// where byte-for-byte C identity is not the goal (V2 is Rust-native);
        /// instead we verify semantic equivalence via normalized dump comparison.
        #[test_with::executable(composefs-info)]
        #[test]
        fn test_c_composefs_info_reads_v2_unusual() {
            let mut runner =
                proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(200));
            runner
                .run(&unusual_filesystem_spec(), |spec| {
                    let fs = build_unusual_filesystem::<Sha256HashValue>(spec);
                    let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());
                    verify_c_composefs_info_reads_image(&image);
                    Ok(())
                })
                .unwrap();
        }

        /// Run `debug_img` on an image and return the structured dump as a String.
        fn debug_dump(image: &[u8]) -> String {
            use crate::erofs::debug::debug_img;
            let mut out = Vec::new();
            debug_img(&mut out, image).expect("debug_img failed");
            String::from_utf8(out).expect("debug_img produced non-UTF8")
        }

        /// Diff two debug dumps, returning a unified-diff-style string of the differences.
        fn diff_debug_dumps(label_a: &str, a: &str, label_b: &str, b: &str) -> String {
            use std::fmt::Write;
            let a_lines: Vec<&str> = a.lines().collect();
            let b_lines: Vec<&str> = b.lines().collect();
            let mut out = String::new();
            let max = a_lines.len().max(b_lines.len());
            let mut diffs = 0usize;
            for i in 0..max {
                let la = a_lines.get(i).copied().unwrap_or("<missing>");
                let lb = b_lines.get(i).copied().unwrap_or("<missing>");
                if la != lb {
                    diffs += 1;
                    if diffs <= 40 {
                        writeln!(out, "line {i}:").unwrap();
                        writeln!(out, "  {label_a}: {la}").unwrap();
                        writeln!(out, "  {label_b}: {lb}").unwrap();
                    }
                }
            }
            if diffs > 40 {
                writeln!(out, "... and {} more differing lines", diffs - 40).unwrap();
            }
            if diffs == 0 {
                out.push_str("(no differences)");
            }
            out
        }

        /// Run C `mkcomposefs --from-file -` on a dumpfile string and return the raw image bytes.
        fn c_mkcomposefs_from_dumpfile(dumpfile: &str) -> Vec<u8> {
            use std::io::{Read, Seek, SeekFrom, Write};
            // Write dumpfile to a tempfile
            let mut tf = tempfile::tempfile().unwrap();
            tf.write_all(dumpfile.as_bytes()).unwrap();
            tf.seek(SeekFrom::Start(0)).unwrap();
            // Run mkcomposefs --from-file - -
            let out_tf = tempfile::tempfile().unwrap();
            let mut child = std::process::Command::new("mkcomposefs")
                .args(["--from-file", "-", "-"])
                .stdin(std::process::Stdio::from(tf))
                .stdout(std::process::Stdio::from(out_tf.try_clone().unwrap()))
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .expect("failed to spawn mkcomposefs");
            let status = child.wait().unwrap();
            assert!(status.success(), "mkcomposefs failed: {status}");
            let mut out_tf = out_tf;
            out_tf.seek(SeekFrom::Start(0)).unwrap();
            let mut bytes = Vec::new();
            out_tf.read_to_end(&mut bytes).unwrap();
            bytes
        }

        /// Verify that our Rust V1 writer produces byte-for-byte identical EROFS images
        /// to C mkcomposefs for the same user-level input.
        ///
        /// This is a stronger check than `test_c_composefs_info_reads_v1`: instead of
        /// comparing parsed dump output (which won't catch wrong binary layout like the
        /// EUCLEAN block-boundary bug), we compare raw image bytes. If our V1 writer
        /// disagrees with the C reference even on a single padding byte, this fails.
        ///
        /// The test mirrors the production flow: C receives a dumpfile of the user-level
        /// tree (no whiteout stubs) and adds the 256 stubs internally; the Rust V1 writer
        /// also adds the stubs automatically during image generation.
        ///
        /// On failure the structural diff from `debug_img` is printed to make the
        /// divergence immediately obvious without a separate manual step.
        #[test_with::executable(mkcomposefs)]
        #[test]
        fn test_v1_binary_identical_to_c_mkcomposefs() {
            let mut runner =
                proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(200));
            runner
                .run(&filesystem_spec(), |spec| {
                    // Build two independent filesystems from the same spec:
                    //   fs_c  — user entries only, serialized as dumpfile and fed to
                    //           C mkcomposefs (which adds the 256 whiteout stubs internally)
                    //   fs_rs — user entries only, fed directly to our Rust V1 writer
                    //           (the writer adds the 256 whiteout stubs automatically)
                    //
                    // Using the same spec for both ensures the user-level content matches.
                    let fs_c = build_filesystem::<Sha256HashValue>(spec.clone());
                    let fs_rs = build_filesystem::<Sha256HashValue>(spec);

                    // Serialize the pre-whiteout tree for C (no stubs in dumpfile)
                    let mut dumpfile_bytes = Vec::new();
                    write_dumpfile(&mut dumpfile_bytes, &fs_c).unwrap();
                    let dumpfile = String::from_utf8(dumpfile_bytes).unwrap();

                    // Get C mkcomposefs binary output (C adds stubs internally)
                    let c_image = c_mkcomposefs_from_dumpfile(&dumpfile);

                    // Get our Rust V0 writer binary output (stubs added automatically by writer)
                    let rust_image = mkfs_erofs_versioned(
                        &mut ValidatedFileSystem::new(fs_rs).unwrap(),
                        FormatVersion::V0,
                    );

                    if c_image != rust_image.as_ref() {
                        let c_debug = debug_dump(&c_image);
                        let rust_debug = debug_dump(&rust_image);
                        similar_asserts::assert_eq!(
                            c_debug,
                            rust_debug,
                            "binary mismatch (c={} bytes, rust={} bytes)\ndumpfile:\n{dumpfile}",
                            c_image.len(),
                            rust_image.len(),
                        );
                    }
                    Ok(())
                })
                .unwrap();
        }

        /// Binary-compatibility test using the unusual-content generator.
        ///
        /// Covers corner cases in the V1 writer that the ordinary random generator almost
        /// never exercises: whiteout escaping, multiple trusted.overlay.* xattrs per inode,
        /// system.posix_acl_access (HAS_ACL flag), large external file sizes, and
        /// cross-type hardlinks (to symlinks, whiteouts, devices, FIFOs).
        ///
        /// Runs 64 cases against C mkcomposefs byte-for-byte.
        #[test_with::executable(mkcomposefs)]
        #[test]
        fn test_v1_binary_identical_unusual_content() {
            let mut runner =
                proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(200));
            runner
                .run(&unusual_filesystem_spec(), |spec| {
                    let fs_c = build_unusual_filesystem::<Sha256HashValue>(spec.clone());
                    let fs_rs = build_unusual_filesystem::<Sha256HashValue>(spec);

                    let mut dumpfile_bytes = Vec::new();
                    write_dumpfile(&mut dumpfile_bytes, &fs_c).unwrap();
                    let dumpfile = String::from_utf8(dumpfile_bytes).unwrap();

                    let c_image = c_mkcomposefs_from_dumpfile(&dumpfile);
                    // C mkcomposefs defaults to --max-version=1, auto-bumping
                    // from V0 to V1 when whiteouts (chardev rdev=0) are present.
                    let has_whiteout = fs_rs
                        .leaves
                        .iter()
                        .any(|leaf| matches!(leaf.content, tree::LeafContent::CharacterDevice(0)));
                    let version = if has_whiteout {
                        FormatVersion::V1
                    } else {
                        FormatVersion::V0
                    };
                    let rust_image = mkfs_erofs_versioned(
                        &mut ValidatedFileSystem::new(fs_rs).unwrap(),
                        version,
                    );

                    if c_image != rust_image.as_ref() {
                        let c_debug = debug_dump(&c_image);
                        let rust_debug = debug_dump(&rust_image);
                        similar_asserts::assert_eq!(
                            c_debug,
                            rust_debug,
                            "binary mismatch (c={} bytes, rust={} bytes)\ndumpfile:\n{dumpfile}",
                            c_image.len(),
                            rust_image.len(),
                        );
                    }
                    Ok(())
                })
                .unwrap();
        }

        /// Diagnostic: dump the structural diff between C mkcomposefs and our Rust V1
        /// writer for a known-failing minimal case (large flat directory, no xattrs).
        ///
        /// This test is `#[ignore]` — run it manually with:
        ///   cargo test -p composefs --lib -- erofs::reader::tests::proptest_tests::test_v1_binary_diff_diagnostic --ignored --nocapture
        ///
        /// It uses `debug_img` (our injective EROFS structure dumper) to show exactly
        /// which fields diverge between the two images, making it easy to pinpoint
        /// the bug in the writer without manually parsing hex dumps.
        #[test_with::executable(mkcomposefs)]
        #[test]
        #[ignore]
        fn test_v1_binary_diff_diagnostic() {
            // Known-failing proptest case: use the exact dumpfile from a proptest failure.
            // The flow matches the proptest exactly:
            //   - fs_c is built from spec and serialized to dumpfile (no stubs) for C
            //   - fs_rs is built from the same spec and fed to the Rust V1 writer
            //     (which adds the 256 whiteout stubs automatically)
            let dumpfile = "\
/ 0 40000 3 0 0 0 0.0 - - -\n\
/B 0 47123 2 32924 6322 0 334277904.419157028 - - - user.test_3=\\x14\\x11\\xf5\\xbe\\xf0\\x1f\\x15<\\\\\\x84Gu(\\x17T\\xdb\\xca\\xd5\n\
/B/\\x06\\xc3} 43 102747 1 14780 50024 0 1909128638.32940851 - X\\xb8\\xac\\xf9[\\x8br\\x1a\\x11\\xed\\x96]\\x9c\\xed\\xba\\x8f\\x13\\xcc/i\\x12\\x7fE\\x18\\xf8n\\xaeV_E\\x8bS]x\\x93/g\\x92\\x0f?\\xd8\\xf4\\xf5 - security.capability=r\\x93\\x84\\x18M user.test_3=&+\\xf2\\xee\\x89sz user.test_4=\n\
/B/\\x1f\\xe3\\x17\\xcb\\xe9\\x81\\x9aT\\xd2\\x13\\x19\\xf2\\xaf\\xee\\x20\\xba\\xb3 43 102274 1 41061 21812 0 446804811.557100600 - <\\x10@Z\\x00\\xc5\\xf9\\xca\\xe1=\\xfc\\xe0\\x81)p\\xa4\\x9f\\xa8\\x18+\\x88\\x0e\\xc3\\xa2\\xdf0\\x82*\\xc2q[x\\x86\\x88\\x80\\xf1]b$\\\\\\x1f]\\xeb - system.posix_acl_access= trusted.test_0=\\x92 trusted.test_2=\\\\\\xec\\x83\\x89\\x85\"\\xf9\\x9b\\xbc\\xa5\\xb0\\xef\\xbcC\\xe8Z\\x88F\\x83\\x17 user.test_1=\\xc4\\xc1\\x08\\xff\\xfa\\xd3\\xed\\xad\\x9bS6f\\tS\\x8d\n\
/B/#\\xcd\\x17\\xb2\\xf0\\x03g\\xea\\x87iI\\xe3{_\\xe1 7 100554 1 50668 49879 0 1545457558.133147722 - \\xb6\\xa1$?\\xd2:\\xb9 - system.posix_acl_default=\\x97\\xde\\xd1S;,; user.test_4=\\xf7\\x82S\\xa5\\xc3,?\\x98\\x84p\\xbf\\x14&\\x91+\\x8e\\xdb\n\
/B/3\\xf4\\xf5\\xc2e\\x07\\xb5\\xacC\\xa1 45 106705 1 56683 56444 0 1577642975.579080132 - \\xdf[\\x83j\\x1e\\x99\\xd8\\xc0[\\x8ba\\xc0f\\xec\\xe0\\x8b*\\xee\\x031\\x91\\x0f38\\x0f\\x08\\xc0\\xcd\\xa9\\x1a^\\x90]\\xc9!>\\xa9S*\\x94\\x8c\\x17\\xa8h\\xc3 - security.ima=E\\x04L\\tb@9\\x07!h) trusted.overlay.custom=~\\x16\\x1f-\\xfc\\xa3\\x07\\x17\\xd1\\xa0 trusted.test_2=O\n\
/B/Eap_z828H.-6-_S 0 14476 1 4557 40071 0 206142614.191638235 - - - security.ima=H\\xfd\\x9e&\\x9a:\\xe5\\x93\\xa4 system.posix_acl_access=N\\x1c|\\xc7$O3\\x198%\\xb4\\xe8 trusted.overlay.origin=Y+\\xa4\\xd1\\x16r\\xdd|\\xfaG user.test_4=\n\
/B/Gv7O_..._.faB2-_-22dNscP_eGqkxP35_.0l.w.hfrZXl_v4h.MGEE7___GGF221-V-__WgP-h-6Th_NIB_._j.-U.Qj_2_iA.P_3_-_..9.1oxn4_mM_6XEAJ196_.6Z9iR_YM-Wr0L_.kz.icFqb_EzB27-___AC7bGW_.t_rwee8rtQ4_0rD_t1-J__5iR.r1_8cNUQXai5w4.e2_G-.7j.DyiD__Rfv6Lhgfzn-QFr_-J 44 124140 1 29304 30605 0 620161379.796821778 ____SlN/.yp1zAst_-P/5_RO_-cy7O_Z__310L__d2yo - -\n\
/B/IP-_jBs 1 126270 1 31623 24545 0 1072774021.893731176 \\xcb - -\n\
/B/KAS.d8m.y6U 16 125603 1 24529 17343 0 340236667.19836524 9\\x14\\xe2{\\xe9[\\x96q\\x08h;\\xc8\\x83\\xa4\\xb3\\xb9 - - trusted.overlay.origin=b\\xec'\\x8c\\x16\\xea\\xcb\\x10\\xc8\\xbe\\x18\\xf7*\\x0c\\x04\\xb8\\xb1 trusted.overlay.overlay.nested= trusted.test_1=e\\x08#\n\
/B/Mp 27 106753 1 37244 13252 0 91373000.857571176 - OV\\x8e!\\xfdw9I\\xab\\x8f\\x9a;!\\xb4]f\\n]\\xc8\\x7f\\xa5\\x94\\x07\\xd4%\\x97\\x85 -\n\
/B/Ze.7.-.9_._Ocl1k2_ 46 107670 1 14097 58513 0 488459452.877162371 - \\xc1\\x17\\x1d\\xa7\\x14S)\\xcd}\\xc9/~\\xa4d\\x1cN\\xbeN\\x184\\x90\\xa9A\\x12\\x8bY/(\\x1a,%\"\\xe3\\xb3\\xf2\\x86\\xec\\x20\\xf6\"Ug;\\x84\\\\A - trusted.overlay.origin=\\xfe\\xda7D\\xbf\\xb0\\xe9\\x9ct0Q user.test_4=-\\xdc\n\
/B/]\\x05\\x19i\\x97\\xeb\\x8c\\xc4k\\x02\\\\jB`j\\x8f\\xb4\\xb6\\xfbw5\\xef\\xf3\\x0fd 0 23230 1 31997 45657 7135 105859383.867998730 - - - system.posix_acl_default=\\xb1p\\x96\\xe45\\xdcC\\x8bI\\x0e\\xfd#\\x8d\n\
/B/_tvW.__t_l_-jK.4j 554649 106606 1 29300 51208 0 705049404.750293896 e5/39a0e32972ef85332212be14f7b863409d9e4113f80603285d1cd52a852822 - e539a0e32972ef85332212be14f7b863409d9e4113f80603285d1cd52a852822 user.test_4=\\xbf\\xbbL\\xe9\\xbc\\x92$\\xa3\\xf9\\xc6\\x06.\\x3d^\n\
/B/q._v.T_.Mba__ 32 122305 1 29088 34366 0 881062039.274688283 _C_Kn1_.r_.IK/TGai6_zqLoTt___w_e - - trusted.overlay.overlay.nested=6\\x03\\xee\\xff\\xdbI\\xdcu(\\\\\\xe1\\x9a\\xee\\xd3e\\x06 user.test_2=\\x9a\\xc4$\\xe1\n\
/B/u 25 105023 2 14652 44878 0 294073763.291036424 - \\x84R\\xd6@\\x0e\\x8b\\x04\\xb4(e\\x93\\xe9\\x86\\xdc\\x03\\xc7\\xbf\\xe1,OmC\\xe9U\\xf1 - trusted.overlay.origin=\\xc4mH\\x9a\n\
/B/\\x81X\\xef\\r\\xce\\x12\\xf4U(p\\xc3\\xb2\\x19\\xe3r\\xd2v9\\x1c\\x02\\xca 46 121141 1 3272 11859 0 1219611767.718731195 jfsk35_Gz__n4tv4xzFFcj_.Z_AV__IJS_k_1I__FuSb.2 - - security.selinux= trusted.overlay.upper=\\x07\\xe8\\xa1%\\xbe\\xb0\\xc8)\\xcf\\xc2\\xf8\\xbah\\x19\\xae_\\xccH\\x9f\\xf0 trusted.test_1=i\\xe6\\xd9\\xd0 user.test_2=\\xc8\\xa0K\\xb2\\xa0V\\xb0\\xb7\\xd1\\xec(\\x95\\xfe\\xbb`\n\
/B/\\xc4\\xf8\\x92\\xc2}<4\\xc8\\xec\\xd2\\xa5\\xe6\\x9ee\\xf0\\x95\\xf8<r\\x0fe\\xbf&\\x97\\x18\\x1a\\x1b\\x8f 29 105203 1 56956 48331 0 1117763015.98007445 - \\xdc\\xf4P\\x19S\\x8b\\x8a}\\xcd\\x12\\xb8\\x0cG\\xf3\\xf3\\x03]Z\\x20\\x17p\\xae\\xb5*K}&\\xf2\\xa5 - trusted.overlay.custom=^\\x83\\xb3\\xfb\\x08\\xa1\\xd8\\x9b~\\x88\\x8aRXZ\\xd7\\xa1c\\xbe trusted.overlay.origin=\\x05\\xb8\n\
/m.A3Q_rRtSZ20o_ 0 @120000 - - - - 0.0 /B/u - -\n";

            // C receives the dumpfile directly and adds the 256 whiteout stubs internally.
            // Our Rust writer also adds them automatically when producing V1 output.
            let fs_rs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();

            let c_image = c_mkcomposefs_from_dumpfile(dumpfile);
            let rust_image = mkfs_erofs_versioned(
                &mut ValidatedFileSystem::new(fs_rs).unwrap(),
                FormatVersion::V1,
            );

            let c_debug = debug_dump(&c_image);
            let rust_debug = debug_dump(&rust_image);

            println!("=== C mkcomposefs ({} bytes) ===", c_image.len());
            println!("{c_debug}");
            println!("=== Rust V1 writer ({} bytes) ===", rust_image.len());
            println!("{rust_debug}");
            println!("=== Structural diff (c vs rust) ===");
            println!("{}", diff_debug_dumps("c", &c_debug, "rust", &rust_debug));

            assert_eq!(
                c_image,
                rust_image.as_ref(),
                "images differ — see structural diff above"
            );
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
        let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());

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

    /// Regression test for the block-boundary EUCLEAN bug (bug.md).
    ///
    /// Old kernels (< 6.12) return EFSCORRUPTED from erofs_fill_symlink() when:
    ///   (inode_offset % block_size) + inode_and_xattr_size + symlink_len > block_size
    ///
    /// The V1 writer previously used the wrong condition (derived from the
    /// non-symlink branch of the C reference) and padded the wrong target
    /// (inline_start rather than inode_start), silently producing images that
    /// would EUCLEAN on CentOS Stream 9 (kernel 5.14) for symlinks with large
    /// SELinux xattrs such as those in /etc/pki/ca-trust/extracted/pem/directory-hash/.
    ///
    /// This test:
    ///  1. Builds a V1 image that forces a symlink inode near a block boundary
    ///     by packing enough filler inodes before it.
    ///  2. Asserts the validator passes (writer fixed the layout).
    ///  3. Asserts the symlink round-trips correctly.
    ///
    /// The construction: inode table starts at offset 1152. We add enough
    /// compact filler inodes (FIFOs, 32 bytes each with min mtime) to push
    /// the subsequent symlink to a position where the old code would have
    /// placed it straddling the 4096-byte boundary.
    #[test]
    fn test_v1_symlink_block_boundary_euclean_regression() {
        use crate::erofs::{format::FormatVersion, writer::mkfs_erofs_versioned};

        // A realistic SELinux label of the kind found on ca-trust symlinks.
        // 76 bytes — enough that header(64) + xattr(~140) + symlink(23) > 4096
        // when the inode starts near offset 3968 within a block.
        let selinux_label = "system_u:object_r:cert_t:s0\x00".repeat(2);
        // Trim to exactly 56 bytes so xattr body is predictable
        let selinux_label = &selinux_label[..selinux_label.len().min(56)];

        // Build the dumpfile: root + many compact filler FIFOs + the victim symlink.
        //
        // Filler FIFOs: mtime=0, no xattrs → compact inode (32 bytes each in V1).
        // The inode table starts at 1152. We need to fill up to offset ~3968 within
        // some 4096-block, which is (3968 - 1152) % 4096 = 2816 bytes = 88 compact inodes
        // in the first block.  Add a few more to cross into block 1 and land the
        // victim at the right position in block 1.
        //
        // We overshoot slightly and rely on the writer's fix to pad correctly.
        // The validator then confirms no inode violates the kernel condition.
        let mut dumpfile = String::from("/ 0 40755 2 0 0 0 0.0 - - -\n");
        for i in 0..120usize {
            dumpfile.push_str(&format!("/filler{i:03} 0 10644 1 0 0 0 0.0 - - -\n"));
        }
        // Victim: symlink with a large SELinux xattr.
        let target = "/etc/pki/ca-trust/source"; // 24-byte target
        let target_len = target.len();
        let xattr_val_hex: String = selinux_label
            .bytes()
            .map(|b| format!("\\x{b:02x}"))
            .collect();
        dumpfile.push_str(&format!(
            "/victim {target_len} 120777 1 0 0 0 0.0 {target} - - security.selinux={xattr_val_hex}\n"
        ));

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(&dumpfile).unwrap();
        let image = mkfs_erofs_versioned(
            &mut ValidatedFileSystem::new(fs).unwrap(),
            FormatVersion::V1,
        );

        // The validator must pass: the writer should have padded the inode
        // to a block boundary so the kernel condition is never violated.
        Image::open(&image)
            .unwrap()
            .fsck_metadata()
            .expect("V1 writer should produce valid inline layout (block-boundary fix)");

        // The symlink target must round-trip correctly.
        let fs_rt =
            erofs_to_filesystem::<Sha256HashValue>(&image).expect("image should parse cleanly");
        let victim_id = fs_rt
            .root
            .leaf_id(std::ffi::OsStr::new("victim"))
            .expect("victim symlink not found in round-tripped filesystem");
        let link_target = match &fs_rt.leaves[victim_id.0].content {
            crate::tree::LeafContent::Symlink(t) => t.clone(),
            other => panic!("victim should be a symlink, got {other:?}"),
        };
        assert_eq!(
            link_target.as_ref(),
            std::ffi::OsStr::new(target),
            "symlink target mismatch after V1 round-trip"
        );
    }

    /// Tests that `fsck_metadata` catches a V1 image where symlink
    /// padding was suppressed, causing the inode+inline data to cross a block
    /// boundary.  Uses `WriterFaults` to inject the fault rather than raw byte
    /// surgery, so the image is otherwise structurally coherent.
    #[test]
    fn test_v1_inline_layout_validator_catches_bad_layout() {
        use crate::erofs::{
            format::FormatVersion,
            writer::{WriterFaults, mkfs_erofs_versioned, mkfs_erofs_with_faults},
        };

        // Layout math (all sizes in bytes, block_size = 4096):
        //
        // A symlink crosses a block boundary when:
        //   symlink_pos % 4096 + 32 (inode) + target_len > 4096
        //   => symlink_pos % 4096 > 4096 - 32 - target_len
        //
        // With target_len = SYMLINK_MAX = 1024 (crate::SYMLINK_MAX):
        //   symlink_pos % 4096 > 3040  (i.e. slot >= 96 within a block)
        //
        // Inode table layout (V1):
        //   Bytes 0..1152  : composefs header (32 B) + pad to 1024 + EROFS superblock (128 B)
        //                    = 36 slots (NID 0-35)
        //   NID 36         : root inode (32 B inode header)
        //   NID 36 inline  : root dir entries (inline, variable)
        //
        // With 50 filler files named "f00".."f49" (sort before "link"):
        //   - 51 dirents: 51 * 12 = 612 B
        //   - names: 50*3 + 4 = 154 B
        //   - total inline: 766 B
        //   - root occupies: 32 + ~766 = 798 B (slot-padded)
        //   - 50 empty files: 50 * 32 = 1600 B
        //   - symlink (without block-boundary padding): NID 113, pos_in_block=3616
        //     3616 + 32 + 1024 = 4672 > 4096 → crossing condition ✓
        //
        // Note: the *good* image places the symlink at pos_in_block == 0 because
        // the writer correctly pads it to a block boundary.  We verify crossing
        // by checking the *bad* image (padding suppressed) instead.

        // filler_count=50 places the symlink at NID 113 (pos_in_block=3616).
        // Without the block-boundary padding: 3616 + 32 + 1024 = 4672 > 4096 ✓
        // The assertion below verifies this whenever the test runs.
        let filler_count = 50usize;
        let mut lines = String::from("/ 0 40755 2 0 0 0 0.0 - - -\n");
        for i in 0..filler_count {
            lines.push_str(&format!("/f{i:02} 0 100644 1 0 0 0 0.0 - - -\n"));
        }
        let target = "a".repeat(crate::SYMLINK_MAX);
        lines.push_str(&format!(
            "/link {len} 120777 1 0 0 0 0.0 {target} - -\n",
            len = target.len(),
            target = target,
        ));
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(&lines).unwrap();
        let mut vfs = ValidatedFileSystem::new(fs).unwrap();

        // The good image must pass validation.
        let good_image = mkfs_erofs_versioned(&mut vfs, FormatVersion::V1);
        Image::open(&good_image)
            .unwrap()
            .fsck_metadata()
            .expect("valid image should pass");

        // Build the faulted image (symlink pad suppressed).
        let mut faults = WriterFaults::new(42);
        faults.skip_symlink_pad_rate = 1.0; // always skip padding
        let bad_image = mkfs_erofs_with_faults(&mut vfs, FormatVersion::V1, faults);

        // Confirm the symlink in the bad image actually crosses a block boundary —
        // i.e. the fault injection put the symlink at a dangerous slot.
        {
            let img = Image::open(&bad_image).unwrap();
            let root_nid = img.sb.root_nid.get() as u64;
            let link_nid = img
                .find_child_nid(root_nid, b"link")
                .unwrap()
                .expect("link nid not found");
            let link_offset = (link_nid * 32) as usize;
            let pos_in_block = link_offset % 4096;
            assert!(
                pos_in_block + 32 + crate::SYMLINK_MAX > 4096,
                "symlink at pos_in_block={pos_in_block} does not cross a block boundary \
                 in the bad image (32+{symlink_max}={total} ≤ 4096); \
                 increase filler_count (currently {filler_count})",
                symlink_max = crate::SYMLINK_MAX,
                total = 32 + crate::SYMLINK_MAX,
            );
        }

        // The faulted image must fail validation.
        let result = Image::open(&bad_image).unwrap().fsck_metadata();
        assert!(
            result.is_err(),
            "validator should reject image with suppressed symlink padding"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("EUCLEAN") || msg.contains("nid"),
            "error should mention EUCLEAN or nid, got: {msg}"
        );
    }

    /// B2: Files with a negative `st_mtim_sec` (pre-epoch mtime) must not corrupt
    /// the V1 superblock `build_time` field.
    ///
    /// `calculate_min_mtime` casts `st_mtim_sec as u64`.  A value of -1 wraps to
    /// `u64::MAX`, which is larger than any positive timestamp, so positive mtimes
    /// are correctly selected as the minimum.  This test verifies that a filesystem
    /// containing one inode with mtime = -1 and one with mtime = 1000 produces a
    /// V1 image whose superblock `build_time` equals 1000.
    #[test]
    fn test_negative_mtime_does_not_corrupt_build_time() {
        use std::{collections::BTreeMap, ffi::OsStr};

        use crate::{
            erofs::{format::FormatVersion, writer::mkfs_erofs_versioned},
            fsverity::Sha256HashValue,
            generic_tree::{LeafContent, Stat},
            tree::{self, RegularFile},
        };

        let root_stat = Stat {
            st_mode: 0o40755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 1000,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        };

        let mut fs = tree::FileSystem::<Sha256HashValue>::new(root_stat);

        // Inode with negative mtime (-1).  As u64 this wraps to u64::MAX, which
        // is larger than 1000, so it should NOT win the minimum comparison.
        let neg_stat = Stat {
            st_mode: 0o100644,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: -1,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        };
        let leaf_id = fs.push_leaf(
            neg_stat,
            LeafContent::Regular(RegularFile::Inline(Box::new([]))),
        );
        fs.root
            .insert(OsStr::new("neg"), tree::Inode::leaf(leaf_id));

        let image = mkfs_erofs_versioned(
            &mut ValidatedFileSystem::new(fs).unwrap(),
            FormatVersion::V1,
        );
        let img = Image::open(&image).expect("failed to open V1 image");

        // The superblock build_time must be 1000 (the root mtime), not u64::MAX or 0.
        assert_eq!(
            img.sb.build_time.get(),
            1000,
            "build_time should be the positive minimum mtime (1000), \
             not the wrapped negative value"
        );
    }

    /// B3: Directories with enough entries to span multiple 4096-byte blocks must
    /// survive a round-trip through the V2 EROFS writer.
    ///
    /// Each dirent is 12 bytes (header) + name length bytes.  With 50 entries of
    /// 90-byte names: 50 × (12 + 90) = 5100 bytes > 4096, which forces
    /// `Directory::from_entries` to split across at least two blocks.
    ///
    /// This test verifies that all entry names survive the round-trip intact.
    #[test]
    fn test_multiblock_directory_round_trip() {
        use std::{collections::BTreeMap, ffi::OsStr};

        use crate::{
            erofs::writer::mkfs_erofs,
            fsverity::Sha256HashValue,
            generic_tree::{LeafContent, Stat},
            tree::{self, RegularFile},
        };

        let root_stat = Stat {
            st_mode: 0o40755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 1000,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        };

        let leaf_stat = Stat {
            st_mode: 0o100644,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 1000,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        };

        let mut fs = tree::FileSystem::<Sha256HashValue>::new(root_stat.clone());

        const N: usize = 50;
        let mut expected_names: Vec<String> = vec![".".into(), "..".into()];

        // Build a subdirectory with N entries, each with a 90-byte name.
        // N × (12 + 90) = 5100 bytes — forces a multi-block directory.
        let mut subdir = tree::Directory::<Sha256HashValue>::new(root_stat);
        for i in 0..N {
            let name = format!("{:0>90}", i);
            let leaf_id = fs.push_leaf(
                leaf_stat.clone(),
                LeafContent::Regular(RegularFile::Inline(Box::new([]))),
            );
            subdir.insert(OsStr::new(&name), tree::Inode::leaf(leaf_id));
            expected_names.push(name);
        }

        fs.root.insert(
            OsStr::new("bigdir"),
            tree::Inode::Directory(Box::new(subdir)),
        );

        let image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());
        let img = Image::open(&image).expect("failed to open image");

        // Locate "bigdir" in root
        let root_nid = img.sb.root_nid.get() as u64;
        let bigdir_nid = img
            .find_child_nid(root_nid, b"bigdir")
            .expect("find_child_nid error")
            .expect("bigdir not found in root");

        // Collect all entry names from bigdir (blocks + inline)
        let bigdir_inode = img.inode(bigdir_nid).unwrap();
        let mut found_names: Vec<String> = Vec::new();
        if let Some(inline) = bigdir_inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries().unwrap() {
                let entry = entry.unwrap();
                found_names.push(String::from_utf8(entry.name.to_vec()).unwrap());
            }
        }
        for blkid in img.inode_blocks(&bigdir_inode).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries().unwrap() {
                let entry = entry.unwrap();
                found_names.push(String::from_utf8(entry.name.to_vec()).unwrap());
            }
        }

        found_names.sort();
        expected_names.sort();

        assert_eq!(
            found_names, expected_names,
            "multi-block directory lost entries after round-trip"
        );

        // Verify the image is a valid EROFS filesystem that can be round-tripped
        let _fs_rt = erofs_to_filesystem::<Sha256HashValue>(&image)
            .expect("erofs_to_filesystem failed on multi-block directory image");

        // Sanity: verify the image passes fsck.erofs if available
        if let Some(ok) = run_fsck_erofs(&image) {
            assert!(
                ok,
                "fsck.erofs reported errors in multi-block directory image"
            );
        }
    }

    /// `ValidatedFileSystem::new` must reject a hardlinked whiteout.
    /// A whiteout (chardev rdev=0) with nlink > 1 is semantically invalid.
    #[test]
    fn test_hardlinked_whiteout_writer_rejects() {
        use std::ffi::OsStr;

        use crate::{
            erofs::writer::ValidatedFileSystem,
            fsverity::Sha256HashValue,
            generic_tree::{LeafContent, Stat},
            tree,
        };

        let root_stat = Stat {
            st_mode: 0o40755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 1000,
            st_mtim_nsec: 0,
            xattrs: Default::default(),
        };
        let whiteout_stat = Stat {
            st_mode: 0o20000,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 1000,
            st_mtim_nsec: 0,
            xattrs: Default::default(),
        };

        let mut fs = tree::FileSystem::<Sha256HashValue>::new(root_stat);
        let leaf_id = fs.push_leaf(whiteout_stat, LeafContent::CharacterDevice(0));
        fs.root
            .insert(OsStr::new("whiteout"), tree::Inode::leaf(leaf_id));
        fs.root.insert(
            OsStr::new("hardlink_to_whiteout"),
            tree::Inode::leaf(leaf_id),
        );

        let result = ValidatedFileSystem::new(fs);
        assert!(
            result.is_err(),
            "ValidatedFileSystem::new should reject hardlinked whiteout"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("whiteout inode has nlink > 1"),
            "unexpected error message: {err}"
        );
    }

    // ── Epoch-invariant validation tests ──────────────────────────────────────

    /// Helper: build a simple filesystem from a dumpfile and write it as an
    /// Epoch2 (V2) EROFS image.
    fn build_epoch2_image(dumpfile: &str) -> Box<[u8]> {
        use crate::erofs::writer::{ValidatedFileSystem, mkfs_erofs};
        let fs = crate::dumpfile::dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap())
    }

    /// Helper: build a filesystem from a dumpfile and write it as an Epoch1 (V1)
    /// EROFS image.
    fn build_epoch1_image(dumpfile: &str) -> Box<[u8]> {
        use crate::erofs::writer::ValidatedFileSystem;
        use crate::erofs::{format::FormatVersion, writer::mkfs_erofs_versioned};
        let fs = crate::dumpfile::dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        mkfs_erofs_versioned(
            &mut ValidatedFileSystem::new(fs).unwrap(),
            FormatVersion::V1,
        )
    }

    /// An Epoch2 image produced by the Rust writer must pass epoch-invariant validation.
    #[test]
    fn test_epoch2_image_passes_epoch_invariants() {
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/file 5 100644 1 0 0 0 1000.0 - hello -
/dir 0 40755 2 0 0 0 1000.0 - - -
/dir/nested 3 100644 1 0 0 0 1000.0 - abc -
"#;
        let image = build_epoch2_image(dumpfile);
        Image::open(&image)
            .unwrap()
            .fsck_metadata()
            .expect("Epoch2 image should pass epoch-invariant validation");
    }

    /// An Epoch1 image produced by the Rust V1 writer must pass epoch-invariant
    /// validation (exactly 256 root stubs, no native whiteouts elsewhere).
    #[test]
    fn test_epoch1_image_passes_epoch_invariants() {
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/file 5 100644 1 0 0 0 1000.0 - hello -
/dir 0 40755 2 0 0 0 1000.0 - - -
/dir/nested 3 100644 1 0 0 0 1000.0 - abc -
"#;
        let image = build_epoch1_image(dumpfile);
        Image::open(&image)
            .unwrap()
            .fsck_metadata()
            .expect("Epoch1 image should pass epoch-invariant validation");
    }

    /// An Epoch2 image must not contain escaped whiteouts (regular file +
    /// trusted.overlay.overlay.whiteout xattr). We craft one by building a V1
    /// image with a user whiteout (which gets escaped in V1) and patching
    /// composefs_version → 2, then verify that validate_epoch_invariants rejects it.
    #[test]
    fn test_epoch2_image_with_escaped_whiteout_fails_epoch_invariants() {
        use crate::erofs::format::FormatVersion;
        use crate::erofs::writer::{ValidatedFileSystem, mkfs_erofs_versioned};
        use crate::generic_tree::{LeafContent, Stat};
        use std::ffi::OsStr;

        // Build a filesystem with a user whiteout (char-device rdev=0). When
        // written as V1, the writer escapes it to a regular file + xattr.
        let mut fs = crate::tree::FileSystem::<Sha256HashValue>::new(Stat {
            st_mode: 0o755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 0,
            st_mtim_nsec: 0,
            xattrs: Default::default(),
        });
        let wh_id = fs.push_leaf(
            Stat {
                st_mode: 0o777,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                st_mtim_nsec: 0,
                xattrs: Default::default(),
            },
            LeafContent::CharacterDevice(0), // rdev=0 → whiteout
        );
        fs.root
            .insert(OsStr::new("mywhiteout"), crate::tree::Inode::leaf(wh_id));

        let mut image = mkfs_erofs_versioned(
            &mut ValidatedFileSystem::new(fs).unwrap(),
            FormatVersion::V1,
        )
        .to_vec();

        // Patch composefs_version → 2; the escaped whiteout xattr is still present.
        const COMPOSEFS_VERSION_OFFSET: usize = 12;
        image[COMPOSEFS_VERSION_OFFSET..COMPOSEFS_VERSION_OFFSET + 4]
            .copy_from_slice(&2u32.to_le_bytes());

        let result = Image::open(&image).unwrap().fsck_metadata();
        let err = result.expect_err("Epoch2 image with escaped whiteout should be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("escaped whiteout") || msg.contains("Epoch2"),
            "expected escaped-whiteout error, got: {msg}",
        );
    }

    /// An Epoch1 image with fewer than 256 root stubs must be rejected.
    /// We craft this by building a V2 (Epoch2) image and patching
    /// composefs_version → 1, turning it into an "Epoch1" image that lacks the
    /// 256 required stubs.
    #[test]
    fn test_epoch1_image_missing_stubs_fails_epoch_invariants() {
        // A V2 image has no stubs at all.  Patching its composefs_version to 1
        // makes the validator treat it as Epoch1 and count 0 stubs (≠ 256).
        let dumpfile = "/ 0 40755 2 0 0 0 1000.0 - - -\n";
        let mut image = build_epoch2_image(dumpfile).to_vec();

        // composefs_version is at offset 12 in ComposefsHeader (4th U32).
        const COMPOSEFS_VERSION_OFFSET: usize = 12;
        image[COMPOSEFS_VERSION_OFFSET..COMPOSEFS_VERSION_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());

        let result = Image::open(&image).unwrap().fsck_metadata();
        let err = result.expect_err("Epoch1 image missing stubs should be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("hex-named") || msg.contains("256") || msg.contains("Epoch1"),
            "expected stub-count error, got: {msg}",
        );
    }

    /// The reader must reject an image with a hardlinked whiteout.
    ///
    /// We build a valid image with a hardlinked chardev(rdev=1), which the writer
    /// accepts.  We then patch the inode's `u` field (rdev) from 1 to 0 in the raw
    /// image bytes, turning it into a whiteout on-disk while leaving nlink > 1.
    /// The reader must detect this and return an error.
    #[test]
    fn test_hardlinked_whiteout_reader_rejects() {
        use std::ffi::OsStr;

        use crate::{
            fsverity::Sha256HashValue,
            generic_tree::{LeafContent, Stat},
            tree,
        };

        let root_stat = Stat {
            st_mode: 0o40755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 1000,
            st_mtim_nsec: 0,
            xattrs: Default::default(),
        };
        let chardev_stat = Stat {
            st_mode: 0o20000,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 1000,
            st_mtim_nsec: 0,
            xattrs: Default::default(),
        };

        let mut fs = tree::FileSystem::<Sha256HashValue>::new(root_stat);
        // Use rdev=1 (not a whiteout) so the writer accepts the hardlink.
        let leaf_id = fs.push_leaf(chardev_stat, LeafContent::CharacterDevice(1));
        fs.root
            .insert(OsStr::new("chardev"), tree::Inode::leaf(leaf_id));
        fs.root.insert(
            OsStr::new("hardlink_to_chardev"),
            tree::Inode::leaf(leaf_id),
        );

        use crate::erofs::writer::mkfs_erofs;
        let base_image = mkfs_erofs(&mut ValidatedFileSystem::new(fs).unwrap());

        // Sanity: the unpatched image must be accepted.
        erofs_to_filesystem::<Sha256HashValue>(&base_image)
            .expect("unmodified image with rdev=1 hardlink should be accepted");

        // Locate the chardev inode in the image using the erofs Image API.
        let img = Image::open(&base_image).unwrap();
        let root_nid = img.sb.root_nid.get() as u64;
        let chardev_nid = img
            .find_child_nid(root_nid, b"chardev")
            .unwrap()
            .expect("chardev entry must exist");

        // Parse the inode via the Image API to learn its layout (compact vs
        // extended) and locate its slot in the image.  We record what we need
        // before releasing the shared borrow so we can take `&mut` afterwards.
        let inode = img.inode(chardev_nid).unwrap();
        let is_extended = matches!(inode, InodeType::Extended(_));
        // The inode region is the `inodes` sub-slice of `image`; the slot for
        // NID n starts at n*32 bytes into that region.
        let inodes_start = img.image.len() - img.inodes.len();
        let inode_slot_start = inodes_start + chardev_nid as usize * 32;
        drop(inode);
        drop(img);

        // Mutate a copy of the image: set the `u` field (rdev) from 1 → 0,
        // turning the chardev into a whiteout on-disk while leaving nlink > 1.
        // Use zerocopy to reinterpret the slot bytes as the concrete header type
        // so we get a typed `&mut` rather than raw byte arithmetic.
        let mut image = base_image.to_vec();
        let slot = &mut image[inode_slot_start..];
        if is_extended {
            use core::mem::size_of;
            let hdr =
                ExtendedInodeHeader::mut_from_bytes(&mut slot[..size_of::<ExtendedInodeHeader>()])
                    .expect("inode slot must be a valid ExtendedInodeHeader");
            assert_eq!(hdr.u.get(), 1, "expected rdev=1 before patching");
            hdr.u = zerocopy::little_endian::U32::new(0);
        } else {
            use core::mem::size_of;
            let hdr =
                CompactInodeHeader::mut_from_bytes(&mut slot[..size_of::<CompactInodeHeader>()])
                    .expect("inode slot must be a valid CompactInodeHeader");
            assert_eq!(hdr.u.get(), 1, "expected rdev=1 before patching");
            hdr.u = zerocopy::little_endian::U32::new(0);
        }

        // The reader must reject the patched image.
        let result = erofs_to_filesystem::<Sha256HashValue>(&image);
        let err = result.expect_err("reader should reject image with hardlinked whiteout");
        let err_msg = format!("{err:#}");
        assert!(
            err_msg.contains("nlink"),
            "error message should mention nlink, got: {err_msg}"
        );
    }
}
