//! EROFS image generation and writing functionality.
//!
//! This module provides functionality to generate EROFS filesystem images
//! from composefs tree structures, handling inode layout, directory blocks,
//! and metadata serialization.

use std::{
    collections::{BTreeMap, HashMap},
    mem::size_of,
    os::unix::ffi::OsStrExt,
};

use log::trace;
use xxhash_rust::xxh32::xxh32;
use zerocopy::{Immutable, IntoBytes};

use crate::{
    erofs::{composefs::OverlayMetacopy, format, reader::round_up},
    fsverity::FsVerityHashValue,
    generic_tree::LeafId,
    tree,
};

#[derive(Clone, Copy, Debug)]
enum Offset {
    Header,
    Superblock,
    Inode,
    InodesEnd,
    XAttr,
    Block,
    End,
}

trait Output {
    fn note_offset(&mut self, offset_type: Offset);
    fn get(&self, offset_type: Offset, idx: usize) -> usize;
    fn write(&mut self, data: &[u8]);
    fn pad(&mut self, alignment: usize);
    fn len(&self) -> usize;

    fn get_div(&self, offset_type: Offset, idx: usize, div: usize) -> usize {
        let offset = self.get(offset_type, idx);
        assert_eq!(offset % div, 0);
        offset / div
    }

    fn get_nid(&self, idx: usize) -> u64 {
        self.get_div(Offset::Inode, idx, 32) as u64
    }

    fn get_xattr_v1(&self, idx: usize) -> u32 {
        // V1: Calculate relative offset within xattr block, matching C implementation.
        // C formula: (inodes_end % BLKSIZ + xattr_offset_from_inodes_end) / 4
        let absolute_offset = self.get(Offset::XAttr, idx);
        let inodes_end = self.get(Offset::InodesEnd, 0);
        let offset_within_block = inodes_end % format::BLOCK_SIZE as usize;
        let xattr_offset_from_inodes_end = absolute_offset - inodes_end;
        ((offset_within_block + xattr_offset_from_inodes_end) / 4) as u32
    }

    fn get_xattr_v2(&self, idx: usize) -> u32 {
        // V2: Simple absolute offset / 4
        self.get_div(Offset::XAttr, idx, 4).try_into().unwrap()
    }

    fn write_struct(&mut self, st: impl IntoBytes + Immutable) {
        self.write(st.as_bytes());
    }
}

/// Extended attribute stored in EROFS format.
///
/// The derived Ord sorts by (prefix, suffix, value) which is used for V2.
/// For V1, use `cmp_by_full_key` which sorts by full key name (prefix string + suffix)
/// to match C mkcomposefs behavior.
#[derive(PartialOrd, PartialEq, Eq, Ord, Clone)]
struct XAttr {
    prefix: u8,
    suffix: Box<[u8]>,
    value: Box<[u8]>,
}

impl XAttr {
    /// Returns the full key name (prefix + suffix) for V1 comparison purposes.
    fn full_key(&self) -> Vec<u8> {
        let prefix_str = format::XATTR_PREFIXES[self.prefix as usize];
        let mut key = Vec::with_capacity(prefix_str.len() + self.suffix.len());
        key.extend_from_slice(prefix_str);
        key.extend_from_slice(&self.suffix);
        key
    }

    /// Compare by full key name (prefix string + suffix), then by value.
    /// This matches C mkcomposefs `cmp_xattr` which uses `strcmp(na->key, nb->key)`.
    fn cmp_by_full_key(&self, other: &Self) -> std::cmp::Ordering {
        match self.full_key().cmp(&other.full_key()) {
            std::cmp::Ordering::Equal => self.value.cmp(&other.value),
            ord => ord,
        }
    }
}

#[derive(Clone, Default)]
struct InodeXAttrs {
    shared: Vec<usize>,
    local: Vec<XAttr>,
    filter: u32,
}

#[derive(Debug)]
struct DirEnt<'a> {
    name: &'a [u8],
    inode: usize,
    file_type: format::FileType,
}

#[derive(Debug, Default)]
struct Directory<'a> {
    blocks: Box<[Box<[DirEnt<'a>]>]>,
    inline: Box<[DirEnt<'a>]>,
    size: u64,
    nlink: usize,
}

#[derive(Debug)]
struct Leaf<'a, ObjectID: FsVerityHashValue> {
    content: &'a tree::LeafContent<ObjectID>,
    nlink: usize,
}

#[derive(Debug)]
enum InodeContent<'a, ObjectID: FsVerityHashValue> {
    Directory(Directory<'a>),
    Leaf(Leaf<'a, ObjectID>),
}

struct Inode<'a, ObjectID: FsVerityHashValue> {
    stat: &'a tree::Stat,
    xattrs: InodeXAttrs,
    content: InodeContent<'a, ObjectID>,
}

impl XAttr {
    pub fn write(&self, output: &mut impl Output) {
        output.write_struct(format::XAttrHeader {
            name_len: self.suffix.len() as u8,
            name_index: self.prefix,
            value_size: (self.value.len() as u16).into(),
        });
        output.write(&self.suffix);
        output.write(&self.value);
        output.pad(4);
    }
}

impl InodeXAttrs {
    fn add(&mut self, name: &[u8], value: &[u8]) {
        for (idx, prefix) in format::XATTR_PREFIXES.iter().enumerate().rev() {
            if let Some(suffix) = name.strip_prefix(*prefix) {
                self.filter |= 1 << (xxh32(suffix, format::XATTR_FILTER_SEED + idx as u32) % 32);
                self.local.push(XAttr {
                    prefix: idx as u8,
                    suffix: Box::from(suffix),
                    value: Box::from(value),
                });
                return;
            }
        }
        unreachable!("{:?}", std::str::from_utf8(name)); // worst case: we matched the empty prefix (0)
    }

    fn write(&self, output: &mut impl Output, version: format::FormatVersion) {
        if self.filter != 0 {
            trace!("  write xattrs block");
            output.write_struct(format::InodeXAttrHeader {
                name_filter: (!self.filter).into(),
                shared_count: self.shared.len() as u8,
                ..Default::default()
            });
            for idx in &self.shared {
                trace!("    shared {} @{}", idx, output.len());
                let xattr_ref = match version {
                    format::FormatVersion::V1 => output.get_xattr_v1(*idx),
                    format::FormatVersion::V2 => output.get_xattr_v2(*idx),
                };
                output.write(&xattr_ref.to_le_bytes());
            }
            for attr in &self.local {
                trace!("    local @{}", output.len());
                attr.write(output);
            }
        }
        // our alignment is equal to xattr alignment: no need to pad
    }
}

impl<'a> Directory<'a> {
    pub fn from_entries(entries: Vec<DirEnt<'a>>) -> Self {
        let mut blocks = vec![];
        let mut rest = vec![];

        let mut n_bytes = 0u64;
        let mut nlink = 0;

        trace!("Directory with {} items", entries.len());

        // The content of the directory is fixed at this point so we may as well split it into
        // blocks.  This lets us avoid measuring and re-measuring.
        for entry in entries.into_iter() {
            let entry_size: u64 = (size_of::<format::DirectoryEntryHeader>() + entry.name.len())
                .try_into()
                .unwrap();
            assert!(entry_size <= 4096);

            trace!("    {:?}", entry.file_type);

            if matches!(entry.file_type, format::FileType::Directory) {
                nlink += 1;
            }

            n_bytes += entry_size;
            if n_bytes <= 4096 {
                rest.push(entry);
            } else {
                // It won't fit, so we need to store the existing entries in a block.
                trace!("    block {}", rest.len());
                blocks.push(rest.into_boxed_slice());

                // Start over
                rest = vec![entry];
                n_bytes = entry_size;
            }
        }

        // Don't try to store more than 2048 bytes of tail data
        if n_bytes > 2048 {
            blocks.push(rest.into_boxed_slice());
            rest = vec![];
            n_bytes = 0;
        }

        trace!(
            "  blocks {} inline {} inline_size {n_bytes}",
            blocks.len(),
            rest.len()
        );

        let block_size: u64 = format::BLOCK_SIZE.into();
        let size = block_size * blocks.len() as u64 + n_bytes;
        Self {
            blocks: blocks.into_boxed_slice(),
            inline: rest.into_boxed_slice(),
            size,
            nlink,
        }
    }

    fn write_block(&self, output: &mut impl Output, block: &[DirEnt]) {
        trace!("    write dir block {} @{}", block.len(), output.len());
        let mut nameofs = size_of::<format::DirectoryEntryHeader>() * block.len();

        for entry in block {
            trace!(
                "      entry {:?} name {} @{}",
                entry.file_type,
                nameofs,
                output.len()
            );
            output.write_struct(format::DirectoryEntryHeader {
                name_offset: (nameofs as u16).into(),
                inode_offset: output.get_nid(entry.inode).into(),
                file_type: entry.file_type.into(),
                ..Default::default()
            });
            nameofs += entry.name.len();
        }

        for entry in block {
            trace!("      name @{}", output.len());
            output.write(entry.name.as_bytes());
        }
    }

    fn write_inline(&self, output: &mut impl Output) {
        trace!(
            "  write inline len {} expected size {} of {}",
            self.inline.len(),
            self.size % 4096,
            self.size
        );
        self.write_block(output, &self.inline);
    }

    fn write_blocks(&self, output: &mut impl Output) {
        let block_size: usize = format::BLOCK_SIZE.into();
        for block in &self.blocks {
            assert_eq!(output.len() % block_size, 0);
            self.write_block(output, block);
            output.pad(block_size);
        }
    }

    fn inode_meta(&self, block_offset: usize) -> (format::DataLayout, u32, u64, usize) {
        let (layout, u) = if self.inline.is_empty() {
            (format::DataLayout::FlatPlain, block_offset as u32 / 4096)
        } else if !self.blocks.is_empty() {
            (format::DataLayout::FlatInline, block_offset as u32 / 4096)
        } else {
            (format::DataLayout::FlatInline, 0)
        };
        (layout, u, self.size, self.nlink)
    }
}

/// Calculates the chunk format bits for an external file based on its size.
///
/// For EROFS chunk-based inodes, the `u` field contains the chunk format
/// which encodes the chunk size as `chunkbits - BLOCK_BITS`.
///
/// The algorithm matches the C implementation:
/// 1. Calculate chunkbits = ilog2(size - 1) + 1
/// 2. Clamp to at least BLOCK_BITS (12)
/// 3. Clamp to at most BLOCK_BITS + 31 (max representable)
/// 4. Return chunkbits - BLOCK_BITS
fn compute_chunk_format(file_size: u64) -> u32 {
    const BLOCK_BITS: u32 = format::BLOCK_BITS as u32;
    const CHUNK_FORMAT_BLKBITS_MASK: u32 = 0x001F; // 31

    // Compute the chunkbits to use for the file size.
    // We want as few chunks as possible, but not an unnecessarily large chunk.
    let mut chunkbits = if file_size > 1 {
        // ilog2(file_size - 1) + 1
        64 - (file_size - 1).leading_zeros()
    } else {
        1
    };

    // At least one logical block
    if chunkbits < BLOCK_BITS {
        chunkbits = BLOCK_BITS;
    }

    // Not larger chunks than max possible
    if chunkbits - BLOCK_BITS > CHUNK_FORMAT_BLKBITS_MASK {
        chunkbits = CHUNK_FORMAT_BLKBITS_MASK + BLOCK_BITS;
    }

    chunkbits - BLOCK_BITS
}

impl<ObjectID: FsVerityHashValue> Leaf<'_, ObjectID> {
    fn inode_meta(&self, version: format::FormatVersion) -> (format::DataLayout, u32, u64, usize) {
        let (layout, u, size) = match &self.content {
            tree::LeafContent::Regular(tree::RegularFile::Inline(data)) => {
                if data.is_empty() {
                    (format::DataLayout::FlatPlain, 0, data.len() as u64)
                } else {
                    (format::DataLayout::FlatInline, 0, data.len() as u64)
                }
            }
            tree::LeafContent::Regular(tree::RegularFile::External(.., size)) => {
                // V1: compute chunk format from file size
                // V2: hardcode 31 (origin/main behavior)
                let chunk_format = match version {
                    format::FormatVersion::V1 => compute_chunk_format(*size),
                    format::FormatVersion::V2 => 31,
                };
                (format::DataLayout::ChunkBased, chunk_format, *size)
            }
            tree::LeafContent::CharacterDevice(rdev) | tree::LeafContent::BlockDevice(rdev) => {
                (format::DataLayout::FlatPlain, *rdev as u32, 0)
            }
            tree::LeafContent::Fifo | tree::LeafContent::Socket => {
                (format::DataLayout::FlatPlain, 0, 0)
            }
            tree::LeafContent::Symlink(target) => {
                assert!(
                    target.len() <= crate::SYMLINK_MAX,
                    "symlink target is {} bytes (max {})",
                    target.len(),
                    crate::SYMLINK_MAX,
                );
                (format::DataLayout::FlatInline, 0, target.len() as u64)
            }
        };
        (layout, u, size, self.nlink)
    }

    fn write_inline(&self, output: &mut impl Output) {
        output.write(match self.content {
            tree::LeafContent::Regular(tree::RegularFile::Inline(data)) => data,
            tree::LeafContent::Regular(tree::RegularFile::External(..)) => b"\xff\xff\xff\xff", // null chunk
            tree::LeafContent::Symlink(target) => target.as_bytes(),
            _ => &[],
        });
    }
}

impl<ObjectID: FsVerityHashValue> Inode<'_, ObjectID> {
    fn file_type(&self) -> format::FileType {
        match &self.content {
            InodeContent::Directory(..) => format::FileType::Directory,
            InodeContent::Leaf(leaf) => match &leaf.content {
                tree::LeafContent::Regular(..) => format::FileType::RegularFile,
                tree::LeafContent::CharacterDevice(..) => format::FileType::CharacterDevice,
                tree::LeafContent::BlockDevice(..) => format::FileType::BlockDevice,
                tree::LeafContent::Fifo => format::FileType::Fifo,
                tree::LeafContent::Socket => format::FileType::Socket,
                tree::LeafContent::Symlink(..) => format::FileType::Symlink,
            },
        }
    }

    /// Check if this inode can use compact format (32 bytes instead of 64).
    ///
    /// Compact format is used when:
    /// - mtime matches min_mtime (stored in superblock build_time)
    /// - nlink, uid, gid fit in u16
    /// - size fits in u32
    fn fits_in_compact(&self, min_mtime: (u64, u32), size: u64, nlink: usize) -> bool {
        // mtime (both sec and nsec) must match the minimum (which will be stored in superblock
        // build_time / build_time_nsec). The C implementation requires both to match.
        if self.stat.st_mtim_sec as u64 != min_mtime.0 {
            return false;
        }
        if self.stat.st_mtim_nsec != min_mtime.1 {
            return false;
        }

        // nlink must fit in u16
        if nlink > u16::MAX as usize {
            return false;
        }

        // uid and gid must fit in u16
        if self.stat.st_uid > u16::MAX as u32 || self.stat.st_gid > u16::MAX as u32 {
            return false;
        }

        // size must fit in u32
        if size > u32::MAX as u64 {
            return false;
        }

        true
    }

    fn write_inode(
        &self,
        output: &mut impl Output,
        idx: usize,
        version: format::FormatVersion,
        min_mtime: (u64, u32),
    ) {
        let (layout, u, size, nlink) = match &self.content {
            InodeContent::Directory(dir) => dir.inode_meta(output.get(Offset::Block, idx)),
            InodeContent::Leaf(leaf) => leaf.inode_meta(version),
        };

        let xattr_size = {
            let mut xattr = FirstPass::default();
            self.xattrs.write(&mut xattr, version);
            xattr.offset
        };

        // V1: compact inodes when possible; V2: always extended
        let use_compact =
            version == format::FormatVersion::V1 && self.fits_in_compact(min_mtime, size, nlink);

        let inode_header_size = if use_compact {
            size_of::<format::CompactInodeHeader>()
        } else {
            size_of::<format::ExtendedInodeHeader>()
        };

        // We need to make sure the inline part doesn't overlap a block boundary
        output.pad(32);
        if matches!(layout, format::DataLayout::FlatInline) {
            let block_size = u64::from(format::BLOCK_SIZE);
            let inode_and_xattr_size: u64 = (inode_header_size + xattr_size).try_into().unwrap();

            match version {
                format::FormatVersion::V1 => {
                    // V1: C mkcomposefs logic from compute_erofs_inode_padding_for_tail()
                    let current_pos: u64 = output.len().try_into().unwrap();
                    let inline_start = current_pos + inode_and_xattr_size;
                    let inline_size = size % block_size;
                    let block_remainder = block_size - (inline_start % block_size);

                    if block_remainder < inline_size {
                        let pad_size = (block_remainder.div_ceil(32) * 32) as usize;
                        let pad = vec![0; pad_size];
                        trace!("added pad {}", pad.len());
                        output.write(&pad);
                    }
                }
                format::FormatVersion::V2 => {
                    // V2: origin/main algorithm
                    let inline_start: u64 = output.len().try_into().unwrap();
                    let inline_start = inline_start + inode_and_xattr_size;
                    let end_of_metadata = inline_start - 1;
                    let inline_end = inline_start + (size % block_size);
                    if end_of_metadata / block_size != inline_end / block_size {
                        let pad_size = (block_size - end_of_metadata % block_size) as usize;
                        let pad = vec![0; pad_size];
                        trace!("added pad {}", pad.len());
                        output.write(&pad);
                        output.pad(32);
                    }
                }
            }
        }

        let xattr_icount: u16 = match xattr_size {
            0 => 0,
            n => (1 + (n - 12) / 4) as u16,
        };

        output.note_offset(Offset::Inode);

        if use_compact {
            let format = format::InodeLayout::Compact | layout;

            trace!(
                "write compact inode {idx} nid {} {:?} {:?} xattrsize{xattr_size} icount{} inline{} @{}",
                output.len() / 32,
                format,
                self.file_type(),
                xattr_icount,
                size % 4096,
                output.len()
            );

            // V1: use sequential ino
            let ino = idx as u32;

            output.write_struct(format::CompactInodeHeader {
                format,
                xattr_icount: xattr_icount.into(),
                mode: self.file_type() | self.stat.st_mode,
                nlink: (nlink as u16).into(),
                size: (size as u32).into(),
                reserved: 0.into(),
                u: u.into(),
                ino: ino.into(),
                uid: (self.stat.st_uid as u16).into(),
                gid: (self.stat.st_gid as u16).into(),
                reserved2: [0; 4],
            });
        } else {
            let format = format::InodeLayout::Extended | layout;

            trace!(
                "write extended inode {idx} nid {} {:?} {:?} xattrsize{xattr_size} icount{} inline{} @{}",
                output.len() / 32,
                format,
                self.file_type(),
                xattr_icount,
                size % 4096,
                output.len()
            );

            // V1 uses the BFS index as i_ino (matching C mkcomposefs behaviour).
            // V2 uses the NID (byte offset / 32) for 32-bit stat compatibility.
            let ino = match version {
                format::FormatVersion::V1 => idx as u32,
                format::FormatVersion::V2 => (output.len() / 32) as u32,
            };

            output.write_struct(format::ExtendedInodeHeader {
                format,
                xattr_icount: xattr_icount.into(),
                mode: self.file_type() | self.stat.st_mode,
                size: size.into(),
                u: u.into(),
                ino: ino.into(),
                uid: self.stat.st_uid.into(),
                gid: self.stat.st_gid.into(),
                mtime: (self.stat.st_mtim_sec as u64).into(),
                mtime_nsec: self.stat.st_mtim_nsec.into(),
                nlink: (nlink as u32).into(),
                ..Default::default()
            });
        }

        self.xattrs.write(output, version);

        match &self.content {
            InodeContent::Directory(dir) => dir.write_inline(output),
            InodeContent::Leaf(leaf) => leaf.write_inline(output),
        };

        output.pad(32);
    }

    fn write_blocks(&self, output: &mut impl Output) {
        if let InodeContent::Directory(dir) = &self.content {
            dir.write_blocks(output);
        }
    }
}

struct InodeCollector<'a, ObjectID: FsVerityHashValue> {
    inodes: Vec<Inode<'a, ObjectID>>,
    hardlinks: HashMap<LeafId, usize>,
    fs: &'a tree::FileSystem<ObjectID>,
    nlink_map: Vec<u32>,
}

impl<'a, ObjectID: FsVerityHashValue> InodeCollector<'a, ObjectID> {
    fn push_inode(&mut self, stat: &'a tree::Stat, content: InodeContent<'a, ObjectID>) -> usize {
        let mut xattrs = InodeXAttrs::default();

        // We need to record extra xattrs for some files.  These come first.
        if let InodeContent::Leaf(Leaf {
            content: tree::LeafContent::Regular(tree::RegularFile::External(id, ..)),
            ..
        }) = content
        {
            xattrs.add(
                b"trusted.overlay.metacopy",
                OverlayMetacopy::new(id).as_bytes(),
            );

            let redirect = format!("/{}", id.to_object_pathname());
            xattrs.add(b"trusted.overlay.redirect", redirect.as_bytes());
        }

        // Add the normal xattrs.  They're already listed in sorted order.
        for (name, value) in stat.xattrs.iter() {
            let name = name.as_bytes();

            if let Some(escapee) = name.strip_prefix(b"trusted.overlay.") {
                let escaped = [b"trusted.overlay.overlay.", escapee].concat();
                xattrs.add(&escaped, value);
            } else {
                xattrs.add(name, value);
            }
        }

        // Allocate an inode for ourselves.  At first we write all xattrs as local.  Later (after
        // we've determined which xattrs ought to be shared) we'll come and move some of them over.
        let inode = self.inodes.len();
        self.inodes.push(Inode {
            stat,
            xattrs,
            content,
        });
        inode
    }

    fn collect_leaf(&mut self, leaf_id: LeafId) -> usize {
        let nlink = self.nlink_map[leaf_id.0] as usize;

        if nlink > 1
            && let Some(inode) = self.hardlinks.get(&leaf_id)
        {
            return *inode;
        }

        let leaf = self.fs.leaf(leaf_id);
        let inode = self.push_inode(
            &leaf.stat,
            InodeContent::Leaf(Leaf {
                content: &leaf.content,
                nlink,
            }),
        );

        if nlink > 1 {
            self.hardlinks.insert(leaf_id, inode);
        }

        inode
    }

    fn insert_sorted(
        entries: &mut Vec<DirEnt<'a>>,
        name: &'a [u8],
        inode: usize,
        file_type: format::FileType,
    ) {
        let entry = DirEnt {
            name,
            inode,
            file_type,
        };
        let point = entries.partition_point(|e| e.name < entry.name);
        entries.insert(point, entry);
    }

    /// Collect inodes using depth-first traversal (V2 / origin/main behavior).
    fn collect_dir(&mut self, dir: &'a tree::Directory<ObjectID>, parent: usize) -> usize {
        // The root inode number needs to fit in a u16.  That more or less compels us to write the
        // directory inode before the inode of the children of the directory.  Reserve a slot.
        let me = self.push_inode(&dir.stat, InodeContent::Directory(Directory::default()));

        let mut entries = vec![];

        for (name, inode) in dir.sorted_entries() {
            let child = match inode {
                tree::Inode::Directory(dir) => self.collect_dir(dir, me),
                tree::Inode::Leaf(leaf_id, _) => self.collect_leaf(*leaf_id),
            };
            entries.push(DirEnt {
                name: name.as_bytes(),
                inode: child,
                file_type: self.inodes[child].file_type(),
            });
        }

        // We're expected to add those, too
        Self::insert_sorted(&mut entries, b".", me, format::FileType::Directory);
        Self::insert_sorted(&mut entries, b"..", parent, format::FileType::Directory);

        // Now that we know the actual content, we can write it to our reserved slot
        self.inodes[me].content = InodeContent::Directory(Directory::from_entries(entries));
        me
    }

    /// Collect all inodes using queue-based breadth-first traversal (V1).
    ///
    /// This algorithm matches the C mkcomposefs `lcfs_compute_tree()` function which uses
    /// a linked-list queue to process directories. All nodes at depth N are assigned inode
    /// numbers before any nodes at depth N+1.
    fn collect_tree(&mut self, root: &'a tree::Directory<ObjectID>) {
        use std::collections::VecDeque;

        let root_inode = self.push_inode(&root.stat, InodeContent::Directory(Directory::default()));
        let mut queue: VecDeque<(&'a tree::Directory<ObjectID>, usize, usize)> = VecDeque::new();
        queue.push_back((root, root_inode, root_inode));

        while let Some((dir, parent, me)) = queue.pop_front() {
            let mut entries = vec![];

            for (name, inode) in dir.sorted_entries() {
                match inode {
                    tree::Inode::Directory(subdir) => {
                        let child = self.push_inode(
                            &subdir.stat,
                            InodeContent::Directory(Directory::default()),
                        );
                        queue.push_back((subdir, me, child));
                        entries.push(DirEnt {
                            name: name.as_bytes(),
                            inode: child,
                            file_type: format::FileType::Directory,
                        });
                    }
                    tree::Inode::Leaf(leaf_id, _) => {
                        let child = self.collect_leaf(*leaf_id);
                        entries.push(DirEnt {
                            name: name.as_bytes(),
                            inode: child,
                            file_type: self.inodes[child].file_type(),
                        });
                    }
                }
            }

            Self::insert_sorted(&mut entries, b".", me, format::FileType::Directory);
            Self::insert_sorted(&mut entries, b"..", parent, format::FileType::Directory);

            self.inodes[me].content = InodeContent::Directory(Directory::from_entries(entries));
        }
    }

    pub fn collect(
        fs: &'a tree::FileSystem<ObjectID>,
        version: format::FormatVersion,
    ) -> Vec<Inode<'a, ObjectID>> {
        let mut this = Self {
            inodes: vec![],
            hardlinks: HashMap::new(),
            fs,
            nlink_map: fs.nlinks(),
        };

        match version {
            format::FormatVersion::V1 => this.collect_tree(&fs.root),
            format::FormatVersion::V2 => {
                let root_inode = this.collect_dir(&fs.root, 0);
                assert_eq!(root_inode, 0);
            }
        }

        this.inodes
    }
}

/// Takes a list of inodes where each inode contains only local xattr values, determines which
/// xattrs (key, value) pairs appear more than once, and shares them.
///
/// For V1: sorts locals by full key, reverses shared table, uses InodesEnd-relative xattr offsets.
/// For V2: uses natural BTreeMap order (derived Ord), ascending shared table.
fn share_xattrs(
    inodes: &mut [Inode<impl FsVerityHashValue>],
    version: format::FormatVersion,
) -> Vec<XAttr> {
    let mut xattrs: BTreeMap<XAttr, usize> = BTreeMap::new();

    // V1: sort local xattrs by full key to match C behavior
    // V2: don't sort (insertion order is fine, BTreeMap handles shared ordering)
    if version == format::FormatVersion::V1 {
        for inode in inodes.iter_mut() {
            inode.xattrs.local.sort_by(|a, b| a.cmp_by_full_key(b));
        }
    }

    // Collect all xattrs from the inodes
    for inode in inodes.iter() {
        for attr in &inode.xattrs.local {
            if let Some(count) = xattrs.get_mut(attr) {
                *count += 1;
            } else {
                xattrs.insert(attr.clone(), 1);
            }
        }
    }

    // Share only xattrs with more than one user
    xattrs.retain(|_k, v| *v > 1);

    match version {
        format::FormatVersion::V1 => {
            // C mkcomposefs sorts shared xattrs by full key string (strcmp), then writes
            // them in DESCENDING order in the shared xattr block.  Our BTreeMap is ordered
            // by (prefix_index, suffix, value) which differs from strcmp order when prefix
            // indices don't sort the same way as prefix strings (e.g. "security."=6 sorts
            // numerically after "trusted."=4, but 'security.' < 'trusted.' lexicographically).
            // Collect into a Vec, sort by full key ascending, then reverse = descending.
            let mut sorted: Vec<_> = xattrs.into_iter().collect();
            sorted.sort_by(|(a, _), (b, _)| a.cmp_by_full_key(b));
            let n_shared = sorted.len();
            // Assign indices in descending order: first entry on disk gets the highest ref.
            // After reversal, sorted[0] (ascending-smallest) ends up last on disk.
            // We iterate ascending-sorted and assign index = n-1-i so that the entry
            // written LAST (smallest key in ascending order) gets the SMALLEST index.
            // Reconstruct a map for the lookup phase below.
            let xattrs: BTreeMap<XAttr, usize> = sorted
                .iter()
                .enumerate()
                .map(|(i, (k, _))| (k.clone(), n_shared - 1 - i))
                .collect();

            // Visit each inode and change local xattrs into shared xattrs
            for inode in inodes.iter_mut() {
                inode.xattrs.local.retain(|attr| {
                    if let Some(idx) = xattrs.get(attr) {
                        inode.xattrs.shared.push(*idx);
                        false
                    } else {
                        true
                    }
                });
            }

            // Return in descending full-key order (last in ascending = first written)
            sorted.reverse();
            sorted.into_iter().map(|(k, _)| k).collect()
        }
        format::FormatVersion::V2 => {
            // Ascending order: sequential index assignment
            for (idx, value) in xattrs.values_mut().enumerate() {
                *value = idx;
            }

            // Visit each inode and change local xattrs into shared xattrs
            for inode in inodes.iter_mut() {
                inode.xattrs.local.retain(|attr| {
                    if let Some(idx) = xattrs.get(attr) {
                        inode.xattrs.shared.push(*idx);
                        false
                    } else {
                        true
                    }
                });
            }

            // Return in ascending order (natural BTreeMap order)
            xattrs.into_keys().collect()
        }
    }
}

fn write_erofs(
    output: &mut impl Output,
    inodes: &[Inode<impl FsVerityHashValue>],
    xattrs: &[XAttr],
    version: format::FormatVersion,
    min_mtime: (u64, u32),
) {
    // Determine build_time based on format version
    // V1: use minimum mtime across all inodes for reproducibility
    // V2: use 0 (not used)
    let (build_time, build_time_nsec) = match version {
        format::FormatVersion::V1 => min_mtime,
        format::FormatVersion::V2 => (0, 0),
    };

    // Write composefs header
    output.note_offset(Offset::Header);
    output.write_struct(format::ComposefsHeader {
        magic: format::COMPOSEFS_MAGIC,
        version: format::VERSION,
        flags: 0.into(),
        composefs_version: version.composefs_version(),
        ..Default::default()
    });
    output.pad(1024);

    // Write superblock
    output.note_offset(Offset::Superblock);
    // V1: set xattr_blkaddr to computed value; V2: leave as 0
    let xattr_blkaddr = match version {
        format::FormatVersion::V1 => {
            (output.get(Offset::InodesEnd, 0) / format::BLOCK_SIZE as usize) as u32
        }
        format::FormatVersion::V2 => 0,
    };
    output.write_struct(format::Superblock {
        magic: format::MAGIC_V1,
        blkszbits: format::BLOCK_BITS,
        feature_compat: (format::FEATURE_COMPAT_MTIME | format::FEATURE_COMPAT_XATTR_FILTER).into(),
        root_nid: (output.get_nid(0) as u16).into(),
        inos: (inodes.len() as u64).into(),
        blocks: ((output.get(Offset::End, 0) / usize::from(format::BLOCK_SIZE)) as u32).into(),
        build_time: build_time.into(),
        build_time_nsec: build_time_nsec.into(),
        xattr_blkaddr: xattr_blkaddr.into(),
        ..Default::default()
    });

    // Write inode table
    for (idx, inode) in inodes.iter().enumerate() {
        // The inode may add padding to itself, so it notes its own offset
        inode.write_inode(output, idx, version, min_mtime);
    }

    // Mark end of inode table (slot-aligned)
    output.pad(32);
    output.note_offset(Offset::InodesEnd);

    // Write shared xattr table
    for xattr in xattrs {
        output.note_offset(Offset::XAttr);
        xattr.write(output);
    }

    // Write blocks from inodes that have them
    output.pad(4096);
    for inode in inodes.iter() {
        output.note_offset(Offset::Block);
        inode.write_blocks(output);
    }

    // That's it
    output.note_offset(Offset::End);
}

#[derive(Default)]
struct Layout {
    offset_types: Vec<usize>,
    offsets: Vec<usize>,
}

#[derive(Default)]
struct FirstPass {
    offset: usize,
    layout: Layout,
}

struct SecondPass {
    output: Vec<u8>,
    layout: Layout,
}

impl Output for SecondPass {
    fn note_offset(&mut self, _offset_type: Offset) {
        /* no-op */
    }

    fn get(&self, offset_type: Offset, idx: usize) -> usize {
        let start = self.layout.offset_types[offset_type as usize];
        self.layout.offsets[start + idx]
    }

    fn write(&mut self, data: &[u8]) {
        self.output.extend_from_slice(data);
    }

    fn pad(&mut self, alignment: usize) {
        self.output
            .resize(round_up(self.output.len(), alignment), 0);
    }

    fn len(&self) -> usize {
        self.output.len()
    }
}

impl Output for FirstPass {
    fn note_offset(&mut self, offset_type: Offset) {
        while self.layout.offset_types.len() <= offset_type as usize {
            self.layout.offset_types.push(self.layout.offsets.len());
        }
        assert_eq!(self.layout.offset_types.len(), offset_type as usize + 1);

        trace!(
            "{:?} #{} @{}",
            offset_type,
            self.layout.offsets.len() - self.layout.offset_types[offset_type as usize],
            self.offset
        );
        self.layout.offsets.push(self.offset);
    }

    fn get(&self, _: Offset, _: usize) -> usize {
        0 // We don't know offsets in the first pass, so fake it
    }

    fn write(&mut self, data: &[u8]) {
        self.offset += data.len();
    }

    fn pad(&mut self, alignment: usize) {
        self.offset = round_up(self.offset, alignment);
    }

    fn len(&self) -> usize {
        self.offset
    }
}

/// Calculates the minimum mtime across all inodes in the collection.
///
/// This is used for V1 compatibility where build_time is set to the
/// minimum mtime for reproducibility.
fn calculate_min_mtime(inodes: &[Inode<impl FsVerityHashValue>]) -> (u64, u32) {
    let mut min_sec = u64::MAX;
    let mut min_nsec = 0u32;

    for inode in inodes {
        let mtime_sec = inode.stat.st_mtim_sec as u64;
        if mtime_sec < min_sec || (mtime_sec == min_sec && inode.stat.st_mtim_nsec < min_nsec) {
            min_sec = mtime_sec;
            min_nsec = inode.stat.st_mtim_nsec;
        }
    }

    // Handle empty inode list
    if min_sec == u64::MAX {
        min_sec = 0;
    }

    (min_sec, min_nsec)
}

/// Creates an EROFS filesystem image from a composefs tree using the default format (V2).
///
/// This function performs a two-pass generation:
/// 1. First pass determines the layout and sizes of all structures
/// 2. Second pass writes the actual image data
///
/// Returns the complete EROFS image as a byte array.
pub fn mkfs_erofs<ObjectID: FsVerityHashValue>(fs: &tree::FileSystem<ObjectID>) -> Box<[u8]> {
    mkfs_erofs_versioned(fs, format::FormatVersion::default())
}

/// Creates an EROFS filesystem image from a composefs tree with an explicit format version.
///
/// The `version` parameter controls the format version:
/// - `FormatVersion::V1`: C mkcomposefs compatible (composefs_version=0, compact inodes, BFS)
/// - `FormatVersion::V2`: Current default (composefs_version=2, extended inodes, DFS)
///
/// Returns the complete EROFS image as a byte array.
pub fn mkfs_erofs_versioned<ObjectID: FsVerityHashValue>(
    fs: &tree::FileSystem<ObjectID>,
    version: format::FormatVersion,
) -> Box<[u8]> {
    // Create the intermediate representation: flattened inodes and shared xattrs
    let mut inodes = InodeCollector::collect(fs, version);

    // For V1, add trusted.overlay.opaque xattr to root directory.
    // This is done after collection (and thus after xattr escaping) to match
    // the C implementation behavior.
    if version == format::FormatVersion::V1 && !inodes.is_empty() {
        inodes[0].xattrs.add(b"trusted.overlay.opaque", b"y");
    }

    let xattrs = share_xattrs(&mut inodes, version);

    // Calculate minimum mtime for V1 build_time
    let min_mtime = calculate_min_mtime(&inodes);

    // Do a first pass with the writer to determine the layout
    let mut first_pass = FirstPass::default();
    write_erofs(&mut first_pass, &inodes, &xattrs, version, min_mtime);

    // Do a second pass with the writer to get the actual bytes
    let mut second_pass = SecondPass {
        output: vec![],
        layout: first_pass.layout,
    };
    write_erofs(&mut second_pass, &inodes, &xattrs, version, min_mtime);

    // That's it
    second_pass.output.into_boxed_slice()
}

/// Creates an EROFS filesystem image using the default format version (V2)
///
/// This is a convenience function equivalent to calling
/// `mkfs_erofs(fs)`.
///
/// Returns the complete EROFS image as a byte array.
pub fn mkfs_erofs_default<ObjectID: FsVerityHashValue>(
    fs: &tree::FileSystem<ObjectID>,
) -> Box<[u8]> {
    mkfs_erofs(fs)
}
