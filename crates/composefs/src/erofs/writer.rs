//! EROFS image generation and writing functionality.
//!
//! This module provides functionality to generate EROFS filesystem images
//! from composefs tree structures, handling inode layout, directory blocks,
//! and metadata serialization.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    mem::size_of,
    os::unix::ffi::OsStrExt,
    rc::Rc,
};

use log::trace;
use xxhash_rust::xxh32::xxh32;
use zerocopy::{Immutable, IntoBytes};

use crate::{
    erofs::{composefs::OverlayMetacopy, format, reader::round_up},
    fsverity::FsVerityHashValue,
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

    fn get_xattr(&self, idx: usize) -> u32 {
        // Calculate relative offset within xattr block, matching C implementation.
        // C formula: (inodes_end % BLKSIZ + xattr_offset_from_inodes_end) / 4
        let absolute_offset = self.get(Offset::XAttr, idx);
        let inodes_end = self.get(Offset::InodesEnd, 0);
        let offset_within_block = inodes_end % format::BLOCK_SIZE as usize;
        let xattr_offset_from_inodes_end = absolute_offset - inodes_end;
        ((offset_within_block + xattr_offset_from_inodes_end) / 4) as u32
    }

    fn write_struct(&mut self, st: impl IntoBytes + Immutable) {
        self.write(st.as_bytes());
    }
}

/// Extended attribute stored in EROFS format.
///
/// Note: Ord is implemented to match C mkcomposefs behavior - xattrs are sorted
/// in ascending alphabetical order by full key name (prefix + suffix), then by
/// value. This ensures bit-for-bit compatibility with the C implementation.
/// See `cmp_xattr` in lcfs-writer.c which uses `strcmp(na->key, nb->key)`.
#[derive(Clone)]
struct XAttr {
    prefix: u8,
    suffix: Box<[u8]>,
    value: Box<[u8]>,
}

impl XAttr {
    /// Returns the full key name (prefix + suffix) for comparison purposes.
    fn full_key(&self) -> Vec<u8> {
        let prefix_str = format::XATTR_PREFIXES[self.prefix as usize];
        let mut key = Vec::with_capacity(prefix_str.len() + self.suffix.len());
        key.extend_from_slice(prefix_str);
        key.extend_from_slice(&self.suffix);
        key
    }
}

impl PartialEq for XAttr {
    fn eq(&self, other: &Self) -> bool {
        self.full_key() == other.full_key() && self.value == other.value
    }
}

impl Eq for XAttr {}

impl PartialOrd for XAttr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for XAttr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Match C mkcomposefs: sort in ascending order by key, then by value
        // C code in cmp_xattr: strcmp(na->key, nb->key) = ascending order
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

    fn write(&self, output: &mut impl Output) {
        if self.filter != 0 {
            trace!("  write xattrs block");
            output.write_struct(format::InodeXAttrHeader {
                name_filter: (!self.filter).into(),
                shared_count: self.shared.len() as u8,
                ..Default::default()
            });
            for idx in &self.shared {
                trace!("    shared {} @{}", idx, output.len());
                output.write(&output.get_xattr(*idx).to_le_bytes());
            }
            // Local xattrs are already sorted in ascending order by share_xattrs()
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
    fn inode_meta(&self) -> (format::DataLayout, u32, u64, usize) {
        let (layout, u, size) = match &self.content {
            tree::LeafContent::Regular(tree::RegularFile::Inline(data)) => {
                if data.is_empty() {
                    (format::DataLayout::FlatPlain, 0, data.len() as u64)
                } else {
                    (format::DataLayout::FlatInline, 0, data.len() as u64)
                }
            }
            tree::LeafContent::Regular(tree::RegularFile::External(.., size)) => {
                let chunk_format = compute_chunk_format(*size);
                (format::DataLayout::ChunkBased, chunk_format, *size)
            }
            tree::LeafContent::CharacterDevice(rdev) | tree::LeafContent::BlockDevice(rdev) => {
                (format::DataLayout::FlatPlain, *rdev as u32, 0)
            }
            tree::LeafContent::Fifo | tree::LeafContent::Socket => {
                (format::DataLayout::FlatPlain, 0, 0)
            }
            tree::LeafContent::Symlink(target) => {
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
    fn fits_in_compact(&self, min_mtime_sec: u64, size: u64, nlink: usize) -> bool {
        // mtime must match the minimum (which will be stored in superblock build_time)
        if self.stat.st_mtim_sec as u64 != min_mtime_sec {
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
        // For V1_0: use sequential inode numbering (idx)
        // For V1_1: use offset-based numbering (calculated after inode header is written)
        let use_sequential_ino = version == format::FormatVersion::V1_0;
        let (layout, u, size, nlink) = match &self.content {
            InodeContent::Directory(dir) => dir.inode_meta(output.get(Offset::Block, idx)),
            InodeContent::Leaf(leaf) => leaf.inode_meta(),
        };

        let xattr_size = {
            let mut xattr = FirstPass::default();
            self.xattrs.write(&mut xattr);
            xattr.offset
        };

        // Determine if we can use compact inode format (V1_0 only)
        let use_compact = version == format::FormatVersion::V1_0
            && self.fits_in_compact(min_mtime.0, size, nlink);

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
            let current_pos: u64 = output.len().try_into().unwrap();
            let inline_start = current_pos + inode_and_xattr_size;
            let inline_size = size % block_size;

            // Calculate how much space remains in the current block for inline data.
            // This matches C mkcomposefs logic in compute_erofs_inode_padding_for_tail().
            let block_remainder = block_size - (inline_start % block_size);

            if block_remainder < inline_size {
                // Not enough room in current block for inline data. Add padding so that
                // the inode header ends at a block boundary and inline data starts fresh.
                // Round up to inode slot size (32 bytes) to maintain alignment.
                let pad_size = (block_remainder.div_ceil(32) * 32) as usize;
                let pad = vec![0; pad_size];
                trace!("added pad {}", pad.len());
                output.write(&pad);
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

            // For V1_0, use sequential ino; for V1_1, use offset-based ino
            let ino = if use_sequential_ino {
                idx as u32
            } else {
                (output.len() / 32) as u32
            };

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

            // For V1_0, use sequential ino; for V1_1, use offset-based ino
            let ino = if use_sequential_ino {
                idx as u32
            } else {
                (output.len() / 32) as u32
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
                nlink: (nlink as u32).into(),
                ..Default::default()
            });
        }

        self.xattrs.write(output);

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
    hardlinks: HashMap<*const tree::Leaf<ObjectID>, usize>,
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
        for (name, value) in RefCell::borrow(&stat.xattrs).iter() {
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

    fn collect_leaf(&mut self, leaf: &'a Rc<tree::Leaf<ObjectID>>) -> usize {
        let nlink = Rc::strong_count(leaf);

        if nlink > 1 {
            if let Some(inode) = self.hardlinks.get(&Rc::as_ptr(leaf)) {
                return *inode;
            }
        }

        let inode = self.push_inode(
            &leaf.stat,
            InodeContent::Leaf(Leaf {
                content: &leaf.content,
                nlink,
            }),
        );

        if nlink > 1 {
            self.hardlinks.insert(Rc::as_ptr(leaf), inode);
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

    /// Collect all inodes using queue-based breadth-first traversal.
    ///
    /// This algorithm matches the C mkcomposefs `lcfs_compute_tree()` function which uses
    /// a linked-list queue to process directories. All nodes at depth N are assigned inode
    /// numbers before any nodes at depth N+1, producing a specific ordering:
    ///
    /// For a tree like:
    /// ```text
    /// /
    /// ├── a/
    /// │   ├── b/
    /// │   │   └── file1
    /// │   └── file2
    /// └── x/
    ///     └── y/
    ///         └── file3
    /// ```
    ///
    /// BFS ordering: /, a, x, a/b, a/file2, x/y, a/b/file1, x/y/file3
    /// (DFS would be: /, a, a/b, a/b/file1, a/file2, x, x/y, x/y/file3)
    ///
    /// This ordering is used for both V1_0 (C-compatible) and V1_1 (Rust-native) formats
    /// to maintain consistency and enable bit-for-bit compatibility with C mkcomposefs
    /// when using V1_0 format. While V1_1 could technically use a different ordering,
    /// using the same BFS approach simplifies the implementation and ensures predictable
    /// behavior across format versions.
    fn collect_tree(&mut self, root: &'a tree::Directory<ObjectID>) {
        use std::collections::VecDeque;

        // Queue entries: (directory, parent_inode, my_inode)
        // For root, parent is self (inode 0)
        let root_inode = self.push_inode(&root.stat, InodeContent::Directory(Directory::default()));
        let mut queue: VecDeque<(&'a tree::Directory<ObjectID>, usize, usize)> = VecDeque::new();
        queue.push_back((root, root_inode, root_inode));

        while let Some((dir, parent, me)) = queue.pop_front() {
            let mut entries = vec![];

            for (name, inode) in dir.sorted_entries() {
                match inode {
                    tree::Inode::Directory(subdir) => {
                        // Reserve a slot for the subdirectory and add to queue for later
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
                    tree::Inode::Leaf(leaf) => {
                        let child = self.collect_leaf(leaf);
                        entries.push(DirEnt {
                            name: name.as_bytes(),
                            inode: child,
                            file_type: self.inodes[child].file_type(),
                        });
                    }
                }
            }

            // Add . and .. entries
            Self::insert_sorted(&mut entries, b".", me, format::FileType::Directory);
            Self::insert_sorted(&mut entries, b"..", parent, format::FileType::Directory);

            // Update the reserved slot with actual content
            self.inodes[me].content = InodeContent::Directory(Directory::from_entries(entries));
        }
    }

    pub fn collect(fs: &'a tree::FileSystem<ObjectID>) -> Vec<Inode<'a, ObjectID>> {
        let mut this = Self {
            inodes: vec![],
            hardlinks: HashMap::new(),
        };

        // Use queue-based breadth-first traversal to match C mkcomposefs inode ordering
        this.collect_tree(&fs.root);

        this.inodes
    }
}

/// Takes a list of inodes where each inode contains only local xattr values, determines which
/// xattrs (key, value) pairs appear more than once, and shares them.
///
/// The shared xattr table is returned in descending alphabetical order to match C mkcomposefs,
/// which uses `xattrs_ht_sort` with `strcmp(v2->key, v1->key)` (reverse alphabetical).
///
/// The per-inode shared xattr indices are added in ascending alphabetical order (sorted by xattr
/// key), matching C mkcomposefs which iterates through `node->xattrs` in sorted order.
fn share_xattrs(inodes: &mut [Inode<impl FsVerityHashValue>]) -> Vec<XAttr> {
    let mut xattrs: BTreeMap<XAttr, usize> = BTreeMap::new();

    // First, sort all local xattrs in each inode to match C behavior.
    // C mkcomposefs sorts xattrs in ascending order via cmp_xattr before processing.
    for inode in inodes.iter_mut() {
        inode.xattrs.local.sort();
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

    // C mkcomposefs writes shared xattrs in descending order (reverse alphabetical).
    // We need to assign indices based on this reversed order.
    let n_shared = xattrs.len();
    for (idx, value) in xattrs.values_mut().enumerate() {
        // Assign indices in reverse order: last item gets index 0, first gets n-1
        *value = n_shared - 1 - idx;
    }

    // Visit each inode and change local xattrs into shared xattrs.
    // Since local xattrs are now sorted, shared indices will be added in ascending order.
    for inode in inodes.iter_mut() {
        inode.xattrs.local.retain(|attr| {
            if let Some(idx) = xattrs.get(attr) {
                inode.xattrs.shared.push(*idx);
                false // drop the local xattr: we converted it
            } else {
                true // retain the local xattr: we didn't convert it
            }
        });
    }

    // Return shared xattrs in descending order (reverse of BTreeMap's ascending order)
    let mut result: Vec<_> = xattrs.into_keys().collect();
    result.reverse();
    result
}

fn write_erofs(
    output: &mut impl Output,
    inodes: &[Inode<impl FsVerityHashValue>],
    xattrs: &[XAttr],
    version: format::FormatVersion,
    min_mtime: (u64, u32),
) {
    // Determine build_time based on format version
    // V1_0: use minimum mtime across all inodes for reproducibility
    // V1_1: use 0 (not used)
    let (build_time, build_time_nsec) = match version {
        format::FormatVersion::V1_0 => min_mtime,
        format::FormatVersion::V1_1 => (0, 0),
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
    let xattr_blkaddr = (output.get(Offset::InodesEnd, 0) / format::BLOCK_SIZE as usize) as u32;
    output.write_struct(format::Superblock {
        magic: format::MAGIC_V1,
        blkszbits: format::BLOCK_BITS,
        feature_compat: format::FEATURE_COMPAT_MTIME | format::FEATURE_COMPAT_XATTR_FILTER,
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
/// This is used for Format 1.0 compatibility where build_time is set to the
/// minimum mtime for reproducibility.
fn calculate_min_mtime(inodes: &[Inode<impl FsVerityHashValue>]) -> (u64, u32) {
    let mut min_sec = u64::MAX;
    let mut min_nsec = 0u32;

    for inode in inodes {
        let mtime_sec = inode.stat.st_mtim_sec as u64;
        if mtime_sec < min_sec {
            min_sec = mtime_sec;
            // When we find a new minimum second, use its nsec
            // Note: st_mtim_nsec would need to be tracked if we want nsec precision
            // For now, we use 0 for nsec as the stat structure may not have it
            min_nsec = 0;
        }
    }

    // Handle empty inode list
    if min_sec == u64::MAX {
        min_sec = 0;
    }

    (min_sec, min_nsec)
}

/// Creates an EROFS filesystem image from a composefs tree
///
/// This function performs a two-pass generation:
/// 1. First pass determines the layout and sizes of all structures
/// 2. Second pass writes the actual image data
///
/// The `version` parameter controls the format version:
/// - `FormatVersion::V1_0`: Uses composefs_version=0 and sets build_time to min mtime
/// - `FormatVersion::V1_1`: Uses composefs_version=2 (current default)
///
/// Returns the complete EROFS image as a byte array.
pub fn mkfs_erofs<ObjectID: FsVerityHashValue>(
    fs: &tree::FileSystem<ObjectID>,
    version: format::FormatVersion,
) -> Box<[u8]> {
    // Create the intermediate representation: flattened inodes and shared xattrs
    let mut inodes = InodeCollector::collect(fs);

    // For Format 1.0, add trusted.overlay.opaque xattr to root directory.
    // This is done after collection (and thus after xattr escaping) to match
    // the C implementation behavior.
    if version == format::FormatVersion::V1_0 && !inodes.is_empty() {
        inodes[0].xattrs.add(b"trusted.overlay.opaque", b"y");
    }

    let xattrs = share_xattrs(&mut inodes);

    // Calculate minimum mtime for V1_0 build_time
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

/// Creates an EROFS filesystem image using the default format version (V1_1)
///
/// This is a convenience function equivalent to calling
/// `mkfs_erofs(fs, FormatVersion::default())`.
///
/// Returns the complete EROFS image as a byte array.
pub fn mkfs_erofs_default<ObjectID: FsVerityHashValue>(
    fs: &tree::FileSystem<ObjectID>,
) -> Box<[u8]> {
    mkfs_erofs(fs, format::FormatVersion::default())
}
