//! Debug implementations and utilities for EROFS on-disk format structures.
//!
//! This module provides [`fmt::Debug`] implementations for EROFS format and
//! reader types, as well as tools for inspecting and debugging EROFS filesystem
//! images, including detailed structure dumping and space usage analysis.

use std::{
    cmp::Ordering,
    collections::BTreeMap,
    ffi::OsStr,
    fmt,
    mem::discriminant,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::Result;
use zerocopy::FromBytes;

use super::format::{self, CompactInodeHeader, ComposefsHeader, ExtendedInodeHeader, Superblock};
use super::reader::{
    DataBlock, DirectoryBlock, Image, Inode, InodeHeader, InodeOps, InodeType, XAttr,
};

/// Converts any reference to a thin pointer (as usize)
/// Used for address calculations in various outputs
macro_rules! addr {
    ($ref: expr_2021) => {
        &raw const (*$ref) as *const u8 as usize
    };
}

macro_rules! write_with_offset {
    ($fmt: expr_2021, $base: expr_2021, $label: expr_2021, $ref: expr_2021) => {{
        let offset = addr!($ref) - addr!($base);
        writeln!($fmt, "{offset:+8x}     {}: {:?}", $label, $ref)
    }};
}

macro_rules! write_fields {
    ($fmt: expr_2021, $base: expr_2021, $struct: expr_2021, $field: ident) => {{
        let value = &$struct.$field;
        let default = if false { value } else { &Default::default() };
        if value != default {
            write_with_offset!($fmt, $base, stringify!($field), value)?;
        }
    }};
    ($fmt: expr_2021, $base: expr_2021, $struct: expr_2021, $head: ident; $($tail: ident);+) => {{
        write_fields!($fmt, $base, $struct, $head);
        write_fields!($fmt, $base, $struct, $($tail);+);
    }};
}

impl fmt::Debug for CompactInodeHeader {
    // Injective (ie: accounts for every byte in the input)
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "CompactInodeHeader")?;
        write_fields!(f, self, self,
            format; xattr_icount; mode; reserved; size; u; ino; uid; gid; nlink; reserved2);
        Ok(())
    }
}

impl fmt::Debug for ExtendedInodeHeader {
    // Injective (ie: accounts for every byte in the input)
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "ExtendedInodeHeader")?;
        write_fields!(f, self, self,
            format; xattr_icount; mode; reserved; size; u; ino; uid;
            gid; mtime; mtime_nsec; nlink; reserved2);
        Ok(())
    }
}

impl fmt::Debug for ComposefsHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "ComposefsHeader")?;
        write_fields!(f, self, self,
            magic; flags; version; composefs_version; unused
        );
        Ok(())
    }
}

impl fmt::Debug for Superblock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Superblock")?;
        write_fields!(f, self, self,
            magic; checksum; feature_compat; blkszbits; extslots; root_nid; inos; build_time;
            build_time_nsec; blocks; meta_blkaddr; xattr_blkaddr; uuid; volume_name;
            feature_incompat; available_compr_algs; extra_devices; devt_slotoff; dirblkbits;
            xattr_prefix_count; xattr_prefix_start; packed_nid; xattr_filter_reserved; reserved2
        );
        Ok(())
    }
}

fn utf8_or_hex(data: &[u8]) -> String {
    if let Ok(string) = std::str::from_utf8(data) {
        format!("{string:?}")
    } else {
        hex::encode(data)
    }
}

fn hexdump(f: &mut impl fmt::Write, data: &[u8], rel: usize) -> fmt::Result {
    let start = match rel {
        0 => 0,
        ptr => data.as_ptr() as usize - ptr,
    };
    let end = start + data.len();
    let start_row = start / 16;
    let end_row = end.div_ceil(16);

    for row in start_row..end_row {
        let row_start = row * 16;
        let row_end = row * 16 + 16;
        write!(f, "{row_start:+8x}  ")?;

        for idx in row_start..row_end {
            if start <= idx && idx < end {
                write!(f, "{:02x} ", data[idx - start])?;
            } else {
                write!(f, "   ")?;
            }
            if idx % 8 == 7 {
                write!(f, " ")?;
            }
        }
        write!(f, "|")?;

        for idx in row_start..row_end {
            if start <= idx && idx < end {
                let c = data[idx - start];
                if c.is_ascii() && !c.is_ascii_control() {
                    write!(f, "{}", c as char)?;
                } else {
                    write!(f, ".")?;
                }
            } else {
                write!(f, " ")?;
            }
        }
        writeln!(f, "|")?;
    }

    Ok(())
}

impl fmt::Debug for XAttr {
    // Injective (ie: accounts for every byte in the input)
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let prefix = format::XATTR_PREFIXES
            .get(self.header.name_index as usize)
            .and_then(|p| std::str::from_utf8(p).ok())
            .unwrap_or("?");
        let suffix = self.suffix().map_err(|_| fmt::Error)?;
        let value = self.value().map_err(|_| fmt::Error)?;
        let padding = self.padding().map_err(|_| fmt::Error)?;
        write!(
            f,
            "({} {} {}) {}{} = {}",
            self.header.name_index,
            self.header.name_len,
            self.header.value_size,
            prefix,
            utf8_or_hex(suffix),
            utf8_or_hex(value),
        )?;
        if padding.iter().any(|c| *c != 0) {
            write!(f, " {:?}", padding)?;
        }
        Ok(())
    }
}

impl<T: fmt::Debug + InodeHeader> fmt::Debug for Inode<T> {
    // Injective (ie: accounts for every byte in the input)
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.header, f)?;

        if let Some(xattrs) = self.xattrs().map_err(|_| fmt::Error)? {
            write_fields!(f, self, xattrs.header, name_filter; shared_count; reserved);

            let shared = xattrs.shared().map_err(|_| fmt::Error)?;
            if !shared.is_empty() {
                write_with_offset!(f, self, "shared xattrs", shared)?;
            }

            for xattr in xattrs.local().map_err(|_| fmt::Error)? {
                let xattr = xattr.map_err(|_| fmt::Error)?;
                write_with_offset!(f, self, "xattr", xattr)?;
            }
        }

        // We want to print one of four things for inline data:
        //   - no data: print nothing
        //   - directory data: dump the entries
        //   - small inline text string: print it
        //   - otherwise, hexdump
        let Some(inline) = self.inline() else {
            // No inline data
            return Ok(());
        };

        // Directory dump
        if self.header.mode().is_dir() {
            let dir = DirectoryBlock::ref_from_bytes(inline).map_err(|_| fmt::Error)?;
            let offset = addr!(dir) - addr!(self);
            return write!(
                f,
                "     +{offset:02x} --- inline directory entries ---{dir:#?}"
            );
        }

        // Small string (<= 128 bytes, utf8, no control characters).
        if inline.len() <= 128
            && !inline.iter().any(|c| c.is_ascii_control())
            && let Ok(string) = std::str::from_utf8(inline)
        {
            return write_with_offset!(f, self, "inline", string);
        }

        // Else, hexdump data block
        hexdump(f, inline, &raw const self.header as usize)
    }
}

impl fmt::Debug for DirectoryBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for entry in self.entries().map_err(|_| fmt::Error)? {
            let entry = entry.map_err(|_| fmt::Error)?;
            writeln!(f)?;
            write_fields!(f, self, entry.header, inode_offset; name_offset; file_type; reserved);
            writeln!(
                f,
                "{:+8x}     # name: {}",
                entry.header.name_offset.get(),
                utf8_or_hex(entry.name)
            )?;
        }
        // TODO: trailing junk inside of st_size
        // TODO: padding up to block or inode boundary
        Ok(())
    }
}

impl fmt::Debug for DataBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hexdump(f, &self.0, 0)
    }
}

// This is basically just a fancy fat pointer type
#[allow(missing_debug_implementations)]
enum SegmentType<'img> {
    Header(&'img ComposefsHeader),
    Superblock(&'img Superblock),
    CompactInode(&'img Inode<CompactInodeHeader>),
    ExtendedInode(&'img Inode<ExtendedInodeHeader>),
    XAttr(&'img XAttr),
    DataBlock(&'img DataBlock),
    DirectoryBlock(&'img DirectoryBlock),
}

// TODO: Something for `enum_dispatch` would be good here, but I couldn't get it working...
impl SegmentType<'_> {
    fn addr(&self) -> usize {
        match self {
            SegmentType::Header(h) => addr!(*h),
            SegmentType::Superblock(sb) => addr!(*sb),
            SegmentType::CompactInode(i) => addr!(*i),
            SegmentType::ExtendedInode(i) => addr!(*i),
            SegmentType::XAttr(x) => addr!(*x),
            SegmentType::DataBlock(b) => addr!(*b),
            SegmentType::DirectoryBlock(b) => addr!(*b),
        }
    }

    fn size(&self) -> usize {
        match self {
            SegmentType::Header(h) => size_of_val(*h),
            SegmentType::Superblock(sb) => size_of_val(*sb),
            SegmentType::CompactInode(i) => size_of_val(*i),
            SegmentType::ExtendedInode(i) => size_of_val(*i),
            SegmentType::XAttr(x) => size_of_val(*x),
            SegmentType::DataBlock(b) => size_of_val(*b),
            SegmentType::DirectoryBlock(b) => size_of_val(*b),
        }
    }

    fn typename(&self) -> &'static str {
        match self {
            SegmentType::Header(..) => "header",
            SegmentType::Superblock(..) => "superblock",
            SegmentType::CompactInode(..) => "compact inode",
            SegmentType::ExtendedInode(..) => "extended inode",
            SegmentType::XAttr(..) => "shared xattr",
            SegmentType::DataBlock(..) => "data block",
            SegmentType::DirectoryBlock(..) => "directory block",
        }
    }
}

#[allow(missing_debug_implementations)]
struct ImageVisitor<'img> {
    image: &'img Image<'img>,
    visited: BTreeMap<usize, (SegmentType<'img>, Vec<Box<Path>>)>,
}

impl<'img> ImageVisitor<'img> {
    fn note(&mut self, segment: SegmentType<'img>, path: Option<&Path>) -> Result<bool> {
        let offset = segment.addr() - self.image.image.as_ptr() as usize;
        match self.visited.entry(offset) {
            std::collections::btree_map::Entry::Occupied(mut e) => {
                let (existing, paths) = e.get_mut();
                if discriminant(existing) != discriminant(&segment)
                    || existing.addr() != segment.addr()
                    || existing.size() != segment.size()
                {
                    anyhow::bail!(
                        "conflicting segments at offset {offset:#x}: \
                         existing {:?} vs new {:?}",
                        discriminant(existing),
                        discriminant(&segment)
                    );
                }
                if let Some(path) = path {
                    paths.push(Box::from(path));
                }
                Ok(true)
            }
            std::collections::btree_map::Entry::Vacant(e) => {
                let mut paths = vec![];
                if let Some(path) = path {
                    paths.push(Box::from(path));
                }
                e.insert((segment, paths));
                Ok(false)
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn visit_image(
        image: &'img Image<'img>,
    ) -> Result<BTreeMap<usize, (SegmentType<'img>, Vec<Box<Path>>)>> {
        let mut this = Self {
            image,
            visited: BTreeMap::new(),
        };
        this.note(SegmentType::Header(image.header), None)?;
        this.note(SegmentType::Superblock(image.sb), None)?;

        // Iterative traversal: push (nid, path) pairs rather than recursing.
        // The previous mutual recursion (visit_inode ↔ visit_directory_block)
        // had no depth limit and would stack-overflow on deeply nested images.
        // Deduplication is by byte offset via note(), so cycles and hardlinks
        // are safe: note() returns true on a second visit and we skip children.
        let mut stack: Vec<(u64, PathBuf)> =
            vec![(image.sb.root_nid.get() as u64, PathBuf::from("/"))];

        while let Some((id, path)) = stack.pop() {
            let inode = this.image.inode(id)?;
            let segment = match inode {
                InodeType::Compact(inode) => SegmentType::CompactInode(inode),
                InodeType::Extended(inode) => SegmentType::ExtendedInode(inode),
            };
            if this.note(segment, Some(&path))? {
                // Already visited this byte offset — additional path recorded, skip children.
                continue;
            }

            if let Some(xattrs) = inode.xattrs()? {
                for xid in xattrs.shared()? {
                    this.note(
                        SegmentType::XAttr(this.image.shared_xattr(xid.get())?),
                        Some(&path),
                    )?;
                }
            }

            if inode.mode().is_dir() {
                if let Some(inline) = inode.inline() {
                    let inline_block = DirectoryBlock::ref_from_bytes(inline)
                        .map_err(|_| anyhow::anyhow!("invalid inline directory block"))?;
                    for entry in inline_block.entries()? {
                        let entry = entry?;
                        if entry.name != b"." && entry.name != b".." {
                            stack.push((
                                entry.header.inode_offset.get(),
                                path.join(OsStr::from_bytes(entry.name)),
                            ));
                        }
                    }
                }
                for blkid in this.image.inode_blocks(&inode)? {
                    let block = this.image.directory_block(blkid)?;
                    for entry in block.entries()? {
                        let entry = entry?;
                        if entry.name != b"." && entry.name != b".." {
                            stack.push((
                                entry.header.inode_offset.get(),
                                path.join(OsStr::from_bytes(entry.name)),
                            ));
                        }
                    }
                    this.note(SegmentType::DirectoryBlock(block), Some(&path))?;
                }
            } else {
                for blkid in this.image.inode_blocks(&inode)? {
                    let block = this.image.data_block(blkid)?;
                    this.note(SegmentType::DataBlock(block), Some(&path))?;
                }
            }
        }

        Ok(this.visited)
    }
}

fn addto<T: Clone + Eq + Ord>(map: &mut BTreeMap<T, usize>, key: &T, count: usize) {
    if let Some(value) = map.get_mut(key) {
        *value += count;
    } else {
        map.insert(key.clone(), count);
    }
}

/// Dumps unassigned or padding regions in the image.
///
/// Distinguishes between zero-filled padding and unknown content.
pub fn dump_unassigned(
    output: &mut impl std::io::Write,
    offset: usize,
    unassigned: &[u8],
) -> Result<()> {
    if unassigned.iter().all(|c| *c == 0) {
        writeln!(output, "{offset:08x} Padding")?;
        writeln!(
            output,
            "{:+8x}     # {} nul bytes",
            unassigned.len(),
            unassigned.len()
        )?;
        writeln!(output)?;
    } else {
        writeln!(output, "{offset:08x} Unknown content")?;
        let mut dump = String::new();
        hexdump(&mut dump, unassigned, 0)?;
        writeln!(output, "{dump}")?;
    }
    Ok(())
}

/// Dumps a detailed debug view of an EROFS image.
///
/// Walks the entire image structure, outputting formatted information about
/// all inodes, blocks, xattrs, and padding. Also produces space usage statistics.
pub fn debug_img(output: &mut impl std::io::Write, data: &[u8]) -> Result<()> {
    let image = Image::open(data)?;
    let visited = ImageVisitor::visit_image(&image)?;

    let inode_start = (image.sb.meta_blkaddr.get() as usize)
        .checked_mul(image.block_size)
        .ok_or_else(|| anyhow::anyhow!("inode start offset overflow"))?;
    let xattr_start = (image.sb.xattr_blkaddr.get() as usize)
        .checked_mul(image.block_size)
        .ok_or_else(|| anyhow::anyhow!("xattr start offset overflow"))?;

    let mut space_stats = BTreeMap::new();
    let mut padding_stats = BTreeMap::new();

    let mut last_segment_type = "";
    let mut offset = 0;
    for (start, (segment, paths)) in visited {
        let segment_type = segment.typename();
        addto(&mut space_stats, &segment_type, segment.size());

        match offset.cmp(&start) {
            Ordering::Less => {
                if let Some(unassigned) = data.get(offset..start) {
                    dump_unassigned(output, offset, unassigned)?;
                    addto(
                        &mut padding_stats,
                        &(last_segment_type, segment_type),
                        start - offset,
                    );
                }
                offset = start;
            }
            Ordering::Greater => {
                writeln!(output, "*** Overlapping segments!")?;
                writeln!(output)?;
                offset = start;
            }
            _ => {}
        }

        last_segment_type = segment_type;

        for path in paths {
            writeln!(
                output,
                "# Filename {}",
                utf8_or_hex(path.as_os_str().as_bytes())
            )?;
        }

        match segment {
            SegmentType::Header(header) => {
                writeln!(output, "{offset:08x} {header:?}")?;
            }
            SegmentType::Superblock(sb) => {
                writeln!(output, "{offset:08x} {sb:?}")?;
            }
            SegmentType::CompactInode(inode) => {
                writeln!(output, "# nid #{}", offset.saturating_sub(inode_start) / 32)?;
                writeln!(output, "{offset:08x} {inode:#?}")?;
            }
            SegmentType::ExtendedInode(inode) => {
                writeln!(output, "# nid #{}", offset.saturating_sub(inode_start) / 32)?;
                writeln!(output, "{offset:08x} {inode:#?}")?;
            }
            SegmentType::XAttr(xattr) => {
                writeln!(
                    output,
                    "# xattr #{}",
                    offset.saturating_sub(xattr_start) / 4
                )?;
                writeln!(output, "{offset:08x} {xattr:?}")?;
            }
            SegmentType::DirectoryBlock(block) => {
                writeln!(output, "# block #{}", offset / image.block_size)?;
                writeln!(output, "{offset:08x} Directory block{block:?}")?;
            }
            SegmentType::DataBlock(block) => {
                writeln!(output, "# block #{}", offset / image.block_size)?;
                writeln!(output, "{offset:08x} Data block\n{block:?}")?;
            }
        }

        offset += segment.size();
    }

    if offset < data.len() {
        let unassigned = &data[offset..];
        dump_unassigned(output, offset, unassigned)?;
        addto(
            &mut padding_stats,
            &(last_segment_type, "eof"),
            unassigned.len(),
        );
        offset = data.len();
        writeln!(output)?;
    }

    if offset > data.len() {
        writeln!(output, "*** Segments past EOF!")?;
        offset = data.len();
    }

    writeln!(output, "Space statistics (total size {offset}B):")?;
    for (key, value) in space_stats {
        writeln!(
            output,
            "  {key} = {value}B, {:.2}%",
            (100. * value as f64) / (offset as f64)
        )?;
    }
    for ((from, to), value) in padding_stats {
        writeln!(
            output,
            "  padding {from} -> {to} = {value}B, {:.2}%",
            (100. * value as f64) / (offset as f64)
        )?;
    }

    Ok(())
}
