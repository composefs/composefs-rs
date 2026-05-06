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
        self.get_div(Offset::XAttr, idx, 4).try_into().unwrap()
    }

    fn write_struct(&mut self, st: impl IntoBytes + Immutable) {
        self.write(st.as_bytes());
    }
}

#[derive(PartialOrd, PartialEq, Eq, Ord, Clone)]
struct XAttr {
    prefix: u8,
    suffix: Box<[u8]>,
    value: Box<[u8]>,
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
                (format::DataLayout::ChunkBased, 31, *size)
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

    fn write_inode(&self, output: &mut impl Output, idx: usize) {
        let (layout, u, size, nlink) = match &self.content {
            InodeContent::Directory(dir) => dir.inode_meta(output.get(Offset::Block, idx)),
            InodeContent::Leaf(leaf) => leaf.inode_meta(),
        };

        let xattr_size = {
            let mut xattr = FirstPass::default();
            self.xattrs.write(&mut xattr);
            xattr.offset
        };

        // We need to make sure the inline part doesn't overlap a block boundary
        output.pad(32);
        if matches!(layout, format::DataLayout::FlatInline) {
            let block_size = u64::from(format::BLOCK_SIZE);
            let inode_and_xattr_size: u64 = (size_of::<format::ExtendedInodeHeader>() + xattr_size)
                .try_into()
                .unwrap();
            let inline_start: u64 = output.len().try_into().unwrap();
            let inline_start = inline_start + inode_and_xattr_size;
            let end_of_metadata = inline_start - 1;
            let inline_end = inline_start + (size % block_size);
            if end_of_metadata / block_size != inline_end / block_size {
                // If we proceed, then we'll violate the rule about crossing block boundaries.
                // The easiest thing to do is to add padding so that the inline data starts close
                // to the start of a fresh block boundary, while ensuring inode alignment.
                // pad_size is always < block_size (4096), so fits in usize
                let pad_size = (block_size - end_of_metadata % block_size) as usize;
                let pad = vec![0; pad_size];
                trace!("added pad {}", pad.len());
                output.write(&pad);
                output.pad(32);
            }
        }

        let format = format::InodeLayout::Extended | layout;

        trace!(
            "write inode {idx} nid {} {:?} {:?} xattrsize{xattr_size} icount{} inline{} @{}",
            output.len() / 32,
            format,
            self.file_type(),
            match xattr_size {
                0 => 0,
                n => (1 + (n - 12) / 4) as u16,
            },
            size % 4096,
            output.len()
        );

        output.note_offset(Offset::Inode);
        output.write_struct(format::ExtendedInodeHeader {
            format,
            xattr_icount: match xattr_size {
                0 => 0,
                n => (1 + (n - 12) / 4) as u16,
            }
            .into(),
            mode: self.file_type() | self.stat.st_mode,
            size: size.into(),
            u: u.into(),
            ino: ((output.len() / 32) as u32).into(),
            uid: self.stat.st_uid.into(),
            gid: self.stat.st_gid.into(),
            mtime: (self.stat.st_mtim_sec as u64).into(),
            mtime_nsec: self.stat.st_mtim_nsec.into(),
            nlink: (nlink as u32).into(),
            ..Default::default()
        });

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
    hardlinks: HashMap<LeafId, usize>,
    fs: &'a tree::FileSystem<ObjectID>,
    nlink_map: &'a [u32],
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

    pub fn collect(
        fs: &'a tree::FileSystem<ObjectID>,
        nlink_map: &'a [u32],
    ) -> Vec<Inode<'a, ObjectID>> {
        let mut this = Self {
            inodes: vec![],
            hardlinks: HashMap::new(),
            fs,
            nlink_map,
        };

        // '..' of the root directory is the root directory again
        let root_inode = this.collect_dir(&fs.root, 0);
        assert_eq!(root_inode, 0);

        this.inodes
    }
}

/// Takes a list of inodes where each inode contains only local xattr values, determines which
/// xattrs (key, value) pairs appear more than once, and shares them.
fn share_xattrs(inodes: &mut [Inode<impl FsVerityHashValue>]) -> Vec<XAttr> {
    let mut xattrs: BTreeMap<XAttr, usize> = BTreeMap::new();

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

    // Repurpose the refcount field as an index lookup
    for (idx, value) in xattrs.values_mut().enumerate() {
        *value = idx;
    }

    // Visit each inode and change local xattrs into shared xattrs
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

    // Return the shared xattrs as a vec
    xattrs.into_keys().collect()
}

fn write_erofs(
    output: &mut impl Output,
    inodes: &[Inode<impl FsVerityHashValue>],
    xattrs: &[XAttr],
) {
    // Write composefs header
    output.note_offset(Offset::Header);
    output.write_struct(format::ComposefsHeader {
        magic: format::COMPOSEFS_MAGIC,
        version: format::VERSION,
        flags: 0.into(),
        composefs_version: format::COMPOSEFS_VERSION,
        ..Default::default()
    });
    output.pad(1024);

    // Write superblock
    output.note_offset(Offset::Superblock);
    output.write_struct(format::Superblock {
        magic: format::MAGIC_V1,
        blkszbits: format::BLOCK_BITS,
        feature_compat: (format::FEATURE_COMPAT_MTIME | format::FEATURE_COMPAT_XATTR_FILTER).into(),
        root_nid: (output.get_nid(0) as u16).into(),
        inos: (inodes.len() as u64).into(),
        blocks: ((output.get(Offset::End, 0) / usize::from(format::BLOCK_SIZE)) as u32).into(),
        ..Default::default()
    });

    // Write inode table
    for (idx, inode) in inodes.iter().enumerate() {
        // The inode may add padding to itself, so it notes its own offset
        inode.write_inode(output, idx);
    }

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

/// Creates an EROFS filesystem image from a composefs tree
///
/// This function performs a two-pass generation:
/// 1. First pass determines the layout and sizes of all structures
/// 2. Second pass writes the actual image data
///
/// Returns the complete EROFS image as a byte array.
pub fn mkfs_erofs<ObjectID: FsVerityHashValue>(fs: &tree::FileSystem<ObjectID>) -> Box<[u8]> {
    // Create the intermediate representation: flattened inodes and shared xattrs
    let nlink_map = fs.nlinks();
    let mut inodes = InodeCollector::collect(fs, &nlink_map);
    let xattrs = share_xattrs(&mut inodes);

    // Do a first pass with the writer to determine the layout
    let mut first_pass = FirstPass::default();
    write_erofs(&mut first_pass, &inodes, &xattrs);

    // Do a second pass with the writer to get the actual bytes
    let mut second_pass = SecondPass {
        output: vec![],
        layout: first_pass.layout,
    };
    write_erofs(&mut second_pass, &inodes, &xattrs);

    // That's it
    second_pass.output.into_boxed_slice()
}
