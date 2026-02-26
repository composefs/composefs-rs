//! EROFS image dumping in composefs-dump(5) format.
//!
//! This module provides functionality to walk an EROFS image and output
//! entries in the composefs dumpfile text format, compatible with the
//! C composefs-info tool.

use std::{
    collections::HashMap,
    ffi::OsStr,
    fmt::{self, Write as FmtWrite},
    io::Write,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::Result;
use zerocopy::FromBytes;

use super::{
    composefs::OverlayMetacopy,
    format::{self, DataLayout, S_IFBLK, S_IFCHR, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG},
    reader::{DirectoryBlock, Image, InodeHeader, InodeOps, InodeType, XAttr},
};
use crate::fsverity::{FsVerityHashValue, Sha256HashValue};

/// The xattr that marks an overlay whiteout stored as a regular file
const OVERLAY_XATTR_ESCAPED_WHITEOUT: &[u8] = b"trusted.overlay.overlay.whiteout";

/// Writes `-` to indicate an empty field
fn write_empty(writer: &mut impl fmt::Write) -> fmt::Result {
    writer.write_str("-")
}

/// Core escaping logic with options for different contexts
fn write_escaped_core(
    writer: &mut impl fmt::Write,
    bytes: &[u8],
    escape_equal: bool,
    escape_lone_dash: bool,
) -> fmt::Result {
    // Handle lone dash case
    if escape_lone_dash && bytes.len() == 1 && bytes[0] == b'-' {
        return write!(writer, "\\x2d");
    }

    for c in bytes {
        let c = *c;

        match c {
            b'\\' => writer.write_str("\\\\")?,
            b'\n' => writer.write_str("\\n")?,
            b'\r' => writer.write_str("\\r")?,
            b'\t' => writer.write_str("\\t")?,
            b'=' if escape_equal => write!(writer, "\\x{c:02x}")?,
            // Printable ASCII (excluding space which is < '!')
            c if (b'!'..=b'~').contains(&c) => writer.write_char(c as char)?,
            // Everything else (including space, control chars, high bytes)
            _ => write!(writer, "\\x{c:02x}")?,
        }
    }

    Ok(())
}

/// Escapes bytes according to composefs-dump(5) format.
/// Outputs `-` for empty bytes (used for empty fields).
/// Does NOT escape `=` (for paths/payloads).
fn write_escaped(writer: &mut impl fmt::Write, bytes: &[u8]) -> fmt::Result {
    if bytes.is_empty() {
        return write_empty(writer);
    }
    write_escaped_core(writer, bytes, false, false)
}

/// Escapes bytes for content fields.
/// Outputs `-` for empty bytes.
/// Escapes a lone `-` as `\x2d`.
/// Does NOT escape `=`.
fn write_escaped_content(writer: &mut impl fmt::Write, bytes: &[u8]) -> fmt::Result {
    if bytes.is_empty() {
        return write_empty(writer);
    }
    write_escaped_core(writer, bytes, false, true)
}

/// Escapes bytes for xattr names/values.
/// Does NOT output `-` for empty bytes.
/// Escapes `=` as `\x3d`.
fn write_escaped_xattr(writer: &mut impl fmt::Write, bytes: &[u8]) -> fmt::Result {
    write_escaped_core(writer, bytes, true, false)
}

/// Checks if an inode is a whiteout entry (internal to composefs, should not be dumped)
///
/// Whiteout entries are character devices with rdev == 0. They are used for
/// overlayfs whiteout tracking and should be filtered from dump output.
fn is_whiteout(inode: &InodeType<'_>) -> bool {
    let mode = inode.mode().0.get();
    let ifmt = mode & S_IFMT;
    // Character device with rdev == 0 is a whiteout
    (ifmt == S_IFCHR) && (inode.rdev() == 0)
}

/// Reconstructs full xattr name from prefix index and suffix
fn xattr_full_name(name_index: u8, suffix: &[u8]) -> Vec<u8> {
    let prefix = if (name_index as usize) < format::XATTR_PREFIXES.len() {
        format::XATTR_PREFIXES[name_index as usize]
    } else {
        b""
    };
    let mut full_name = Vec::with_capacity(prefix.len() + suffix.len());
    full_name.extend_from_slice(prefix);
    full_name.extend_from_slice(suffix);
    full_name
}

/// Context for dump operation, tracking hardlinks
struct DumpContext<'img> {
    image: &'img Image<'img>,
    /// Maps nid to the first path where it was seen (for hardlink tracking)
    seen_nids: HashMap<u64, PathBuf>,
    /// Optional filters for top-level entries
    filters: &'img [String],
}

impl<'img> DumpContext<'img> {
    fn new(image: &'img Image<'img>, filters: &'img [String]) -> Self {
        Self {
            image,
            seen_nids: HashMap::new(),
            filters,
        }
    }

    /// Checks if an xattr should be included in dump output.
    /// Returns Some(name, value) with possibly transformed name, or None to skip.
    fn transform_xattr(&self, name: &[u8], value: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        // trusted.overlay. prefix
        const OVERLAY_PREFIX: &[u8] = b"trusted.overlay.";
        // trusted.overlay.overlay. is the escape prefix (one extra "overlay.")
        const ESCAPE_PREFIX: &[u8] = b"trusted.overlay.overlay.";
        // trusted. prefix (for unescaping)
        const TRUSTED_PREFIX: &[u8] = b"trusted.";

        // Skip internal composefs xattrs that should never appear in dump output
        // These are handled specially during reading or are internal markers
        if name == b"trusted.overlay.metacopy"
            || name == b"trusted.overlay.redirect"
            || name == b"trusted.overlay.overlay.whiteout"  // ESCAPED_WHITEOUT
            || name == b"trusted.overlay.overlay.whiteouts" // ESCAPED_WHITEOUTS
            || name == b"trusted.overlay.userxattr.whiteout"
            || name == b"trusted.overlay.userxattr.whiteouts"
            || name == b"user.overlay.whiteout"  // USERXATTR_WHITEOUT
            || name == b"user.overlay.whiteouts"
        // USERXATTR_WHITEOUTS
        {
            return None;
        }

        if name.starts_with(OVERLAY_PREFIX) {
            // Check for escaped xattrs that need to be unescaped
            // trusted.overlay.overlay.FOO -> trusted.overlay.FOO
            if name.starts_with(ESCAPE_PREFIX) {
                // Take the suffix after OVERLAY_PREFIX (which includes one "overlay.")
                // and prepend just TRUSTED_PREFIX
                // So: trusted.overlay.overlay.opaque -> trusted. + overlay.opaque -> trusted.overlay.opaque
                let suffix = &name[OVERLAY_PREFIX.len()..]; // "overlay.opaque"
                let mut new_name = Vec::with_capacity(TRUSTED_PREFIX.len() + suffix.len());
                new_name.extend_from_slice(TRUSTED_PREFIX);
                new_name.extend_from_slice(suffix);
                return Some((new_name, value.to_vec()));
            }

            // Skip all other trusted.overlay.* xattrs - they're internal to composefs
            // This includes: opaque, whiteout, whiteouts, etc.
            return None;
        }

        // Keep all non-trusted.overlay.* xattrs (including user.overlay.*)
        Some((name.to_vec(), value.to_vec()))
    }

    /// Collects xattrs from an inode, returning (name, value) pairs in the order
    /// they appear in the EROFS image (inline/local first, then shared).
    fn collect_xattrs(&self, inode: &InodeType<'_>) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut xattrs = Vec::new();

        if let Some(inode_xattrs) = inode.xattrs() {
            // Local (inline) xattrs first - matches C implementation order
            for xattr in inode_xattrs.local() {
                let full_name = xattr_full_name(xattr.header.name_index, xattr.suffix());
                if let Some(pair) = self.transform_xattr(&full_name, xattr.value()) {
                    xattrs.push(pair);
                }
            }

            // Shared xattrs second
            for id in inode_xattrs.shared() {
                let xattr = self.image.shared_xattr(id.get());
                let full_name = xattr_full_name(xattr.header.name_index, xattr.suffix());
                if let Some(pair) = self.transform_xattr(&full_name, xattr.value()) {
                    xattrs.push(pair);
                }
            }
        }

        // Note: We do NOT sort xattrs - we preserve the order from the EROFS image
        // to match the C implementation behavior
        xattrs
    }

    /// Extracts overlay.metacopy xattr to get fsverity digest for external files
    fn get_metacopy_digest(&self, inode: &InodeType<'_>) -> Option<Sha256HashValue> {
        let inode_xattrs = inode.xattrs()?;

        // Check shared xattrs
        for id in inode_xattrs.shared() {
            let xattr = self.image.shared_xattr(id.get());
            if let Some(digest) = self.check_metacopy_xattr(xattr) {
                return Some(digest);
            }
        }

        // Check local xattrs
        for xattr in inode_xattrs.local() {
            if let Some(digest) = self.check_metacopy_xattr(xattr) {
                return Some(digest);
            }
        }

        None
    }

    fn check_metacopy_xattr(&self, xattr: &XAttr) -> Option<Sha256HashValue> {
        // trusted. prefix has index 4
        if xattr.header.name_index != 4 {
            return None;
        }
        if xattr.suffix() != b"overlay.metacopy" {
            return None;
        }
        if let Ok(value) = OverlayMetacopy::<Sha256HashValue>::read_from_bytes(xattr.value()) {
            if value.valid() {
                return Some(value.digest.clone());
            }
        }
        None
    }

    /// Checks if an inode has the escaped whiteout xattr (trusted.overlay.overlay.whiteout)
    /// This is used to transform regular files into character device whiteouts
    fn has_escaped_whiteout_xattr(&self, inode: &InodeType<'_>) -> bool {
        let Some(inode_xattrs) = inode.xattrs() else {
            return false;
        };

        // Check local xattrs
        for xattr in inode_xattrs.local() {
            let full_name = xattr_full_name(xattr.header.name_index, xattr.suffix());
            if full_name == OVERLAY_XATTR_ESCAPED_WHITEOUT {
                return true;
            }
        }

        // Check shared xattrs
        for id in inode_xattrs.shared() {
            let xattr = self.image.shared_xattr(id.get());
            let full_name = xattr_full_name(xattr.header.name_index, xattr.suffix());
            if full_name == OVERLAY_XATTR_ESCAPED_WHITEOUT {
                return true;
            }
        }

        false
    }

    /// Reads file content from blocks and optional inline tail
    /// This handles FlatPlain (blocks only) and FlatInline (blocks + tail) layouts
    fn read_file_content(&self, inode: &InodeType<'_>) -> Vec<u8> {
        let size = inode.size() as usize;
        if size == 0 {
            return vec![];
        }

        let layout = inode.data_layout();
        let blocks: Vec<u64> = inode.blocks(self.image.blkszbits).collect();
        let block_size = self.image.block_size;

        match layout {
            DataLayout::FlatPlain => {
                // All data in blocks, no inline tail
                let mut content = Vec::with_capacity(size);
                for blkid in blocks {
                    content.extend_from_slice(self.image.block(blkid));
                }
                content.truncate(size);
                content
            }
            DataLayout::FlatInline => {
                // Data in blocks + inline tail
                let n_blocks = blocks.len();
                let mut content = Vec::with_capacity(size);
                for blkid in blocks {
                    content.extend_from_slice(self.image.block(blkid));
                }
                // Add inline tail
                if let Some(inline_data) = inode.inline() {
                    content.extend_from_slice(inline_data);
                }
                // Truncate to actual size (inline portion may include padding)
                let inline_size = size % block_size;
                if inline_size > 0 {
                    content.truncate(n_blocks * block_size + inline_size);
                }
                content
            }
            DataLayout::ChunkBased => {
                // External file - no inline content
                vec![]
            }
        }
    }

    /// Writes a dump entry for an inode
    fn write_entry(
        &mut self,
        output: &mut String,
        path: &Path,
        nid: u64,
    ) -> Result<(), fmt::Error> {
        let inode = self.image.inode(nid);
        let mut mode = inode.mode().0.get();
        let mut ifmt = mode & S_IFMT;
        let nlink = inode.nlink();
        let uid = inode.uid();
        let gid = inode.gid();

        // For compact inodes, mtime() returns 0 - use build_time from superblock
        let (mtime, mtime_nsec) = {
            let inode_mtime = inode.mtime();
            if inode_mtime == 0 {
                // Compact inode - use build_time from superblock
                (
                    self.image.sb.build_time.get() as i64,
                    self.image.sb.build_time_nsec.get(),
                )
            } else {
                (inode_mtime, inode.mtime_nsec())
            }
        };

        // Check if this is an escaped whiteout (regular file with trusted.overlay.overlay.whiteout)
        // These need to be transformed back to character device whiteouts
        let is_escaped_whiteout = ifmt == S_IFREG && self.has_escaped_whiteout_xattr(&inode);
        if is_escaped_whiteout {
            // Transform to character device with rdev=0
            mode = (mode & !S_IFMT) | S_IFCHR;
            ifmt = S_IFCHR;
        }

        // Check for hardlink (non-directory with nlink > 1, already seen)
        if !inode.mode().is_dir() && nlink > 1 {
            if let Some(target) = self.seen_nids.get(&nid) {
                // This is a hardlink to an already-seen inode
                write_escaped(output, path.as_os_str().as_bytes())?;
                write!(output, " 0 @120000 - - - - 0.0 ")?;
                write_escaped(output, target.as_os_str().as_bytes())?;
                write!(output, " - -")?;
                return Ok(());
            }
            // First occurrence of this hardlinked inode
            self.seen_nids.insert(nid, path.to_path_buf());
        }

        // Get size based on file type
        // For escaped whiteouts, size is 0 (character device)
        let size = if is_escaped_whiteout { 0 } else { inode.size() };

        // Determine payload and content based on file type
        let (payload, content, digest): (Vec<u8>, Vec<u8>, Option<String>) = if is_escaped_whiteout
        {
            // Whiteout: no payload, content, or digest
            (vec![], vec![], None)
        } else {
            match ifmt {
                S_IFREG => {
                    // Regular file
                    if let Some(metacopy_digest) = self.get_metacopy_digest(&inode) {
                        // External file with fsverity digest
                        let hex = metacopy_digest.to_hex();
                        let object_path = format!("{}/{}", &hex[..2], &hex[2..]);
                        (object_path.into_bytes(), vec![], Some(hex))
                    } else {
                        // Inline or FlatPlain file - read content from blocks + tail
                        let content = self.read_file_content(&inode);
                        (vec![], content, None)
                    }
                }
                S_IFLNK => {
                    // Symlink - target can be inline (short) or in blocks (long)
                    let size = inode.size() as usize;
                    let blocks: Vec<u64> = inode.blocks(self.image.blkszbits).collect();
                    if !blocks.is_empty() {
                        // Long symlink: data is in blocks
                        let mut target = Vec::with_capacity(size);
                        for blkid in blocks {
                            target.extend_from_slice(self.image.block(blkid));
                        }
                        target.truncate(size);
                        (target, vec![], None)
                    } else if let Some(inline_data) = inode.inline() {
                        // Short symlink: data is inline
                        (inline_data.to_vec(), vec![], None)
                    } else {
                        // Empty symlink (shouldn't happen but handle gracefully)
                        (vec![], vec![], None)
                    }
                }
                S_IFDIR => {
                    // Directory - no payload or content
                    (vec![], vec![], None)
                }
                _ => {
                    // Device, FIFO, socket - no payload or content
                    (vec![], vec![], None)
                }
            }
        };

        // Get rdev for device files (escaped whiteouts become chardev with rdev=0)
        let rdev = if is_escaped_whiteout {
            0
        } else {
            match ifmt {
                S_IFBLK | S_IFCHR => inode.rdev() as u64,
                _ => 0,
            }
        };

        // Write the entry
        write_escaped(output, path.as_os_str().as_bytes())?;
        write!(
            output,
            " {size} {mode:o} {nlink} {uid} {gid} {rdev} {mtime}.{mtime_nsec} "
        )?;
        write_escaped(output, &payload)?;
        write!(output, " ")?;
        write_escaped_content(output, &content)?;
        write!(output, " ")?;
        if let Some(d) = digest {
            write!(output, "{d}")?;
        } else {
            write_empty(output)?;
        }

        // Write xattrs
        let xattrs = self.collect_xattrs(&inode);
        for (name, value) in xattrs {
            write!(output, " ")?;
            write_escaped_xattr(output, &name)?;
            write!(output, "=")?;
            // Note: empty xattr values should NOT output "-", just nothing
            write_escaped_xattr(output, &value)?;
        }

        Ok(())
    }

    /// Walks a directory and writes dump entries for all children
    ///
    /// The `depth` parameter is 0 for the root directory's immediate children,
    /// used for applying filters.
    fn walk_directory(
        &mut self,
        output: &mut impl Write,
        path: &mut PathBuf,
        nid: u64,
        depth: usize,
    ) -> Result<()> {
        let inode = self.image.inode(nid);

        // Write this directory's entry first
        let mut entry = String::with_capacity(256);
        self.write_entry(&mut entry, path, nid)?;
        writeln!(output, "{entry}")?;

        // Collect children (skip . and ..)
        let mut children: Vec<(Vec<u8>, u64)> = Vec::new();

        // Inline directory entries
        if let Some(inline) = inode.inline() {
            if !inline.is_empty() {
                if let Ok(inline_block) = DirectoryBlock::ref_from_bytes(inline) {
                    for entry in inline_block.entries() {
                        if entry.name != b"." && entry.name != b".." {
                            children.push((entry.name.to_vec(), entry.header.inode_offset.get()));
                        }
                    }
                }
            }
        }

        // Block directory entries
        for blkid in inode.blocks(self.image.blkszbits) {
            let block = self.image.directory_block(blkid);
            for entry in block.entries() {
                if entry.name != b"." && entry.name != b".." {
                    children.push((entry.name.to_vec(), entry.header.inode_offset.get()));
                }
            }
        }

        // Sort children by name for deterministic output
        children.sort_by(|a, b| a.0.cmp(&b.0));

        // Process children
        for (name, child_nid) in children {
            let child_inode = self.image.inode(child_nid);

            // Skip whiteout entries (internal to composefs)
            if is_whiteout(&child_inode) {
                continue;
            }

            // At depth 0 (root's children), apply filters if any are specified
            if depth == 0 && !self.filters.is_empty() {
                let name_str = String::from_utf8_lossy(&name);
                if !self.filters.iter().any(|f| f == name_str.as_ref()) {
                    continue;
                }
            }

            path.push(OsStr::from_bytes(&name));

            if child_inode.mode().is_dir() {
                self.walk_directory(output, path, child_nid, depth + 1)?;
            } else {
                let mut entry = String::with_capacity(256);
                self.write_entry(&mut entry, path, child_nid)?;
                writeln!(output, "{entry}")?;
            }

            path.pop();
        }

        Ok(())
    }
}

/// Dumps an EROFS image in composefs-dump(5) format
///
/// Walks the entire image tree and outputs each entry in the dumpfile format.
/// Handles hardlinks, xattrs, external files, and all file types.
///
/// If `filters` is provided and non-empty, only top-level entries whose names
/// match one of the filter strings will be included in the output (along with
/// the root directory itself).
pub fn dump_erofs(output: &mut impl Write, image_data: &[u8], filters: &[String]) -> Result<()> {
    let image = Image::open(image_data);
    let mut ctx = DumpContext::new(&image, filters);

    let root_nid = image.sb.root_nid.get() as u64;
    let mut path = PathBuf::from("/");

    ctx.walk_directory(output, &mut path, root_nid, 0)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dumpfile::dumpfile_to_filesystem, erofs::format::FormatVersion, erofs::writer::mkfs_erofs,
    };

    fn roundtrip_test(input: &str) -> String {
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(input).unwrap();
        let image = mkfs_erofs(&fs, FormatVersion::default());
        let mut output = Vec::new();
        dump_erofs(&mut output, &image, &[]).unwrap();
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn test_dump_empty_root() {
        let input = "/ 4096 40755 2 0 0 0 0.0 - - -\n";
        let output = roundtrip_test(input);
        // Output should have a root entry
        assert!(output.starts_with("/ "), "Output: {}", output);
        assert!(output.contains(" 40755 "), "Output: {}", output);
    }

    #[test]
    fn test_dump_with_file() {
        let input = "/ 4096 40755 2 0 0 0 0.0 - - -\n\
                     /file 5 100644 1 0 0 0 0.0 - hello -\n";
        let output = roundtrip_test(input);
        assert!(output.contains("/file "), "Output: {}", output);
        assert!(output.contains(" 100644 "), "Output: {}", output);
        assert!(output.contains(" hello "), "Output: {}", output);
    }

    #[test]
    fn test_dump_with_symlink() {
        let input = "/ 4096 40755 2 0 0 0 0.0 - - -\n\
                     /link 7 120777 1 0 0 0 0.0 /target - -\n";
        let output = roundtrip_test(input);
        assert!(output.contains("/link "), "Output: {}", output);
        assert!(output.contains(" 120777 "), "Output: {}", output);
        assert!(output.contains(" /target "), "Output: {}", output);
    }

    #[test]
    fn test_dump_with_subdirectory() {
        let input = "/ 4096 40755 2 0 0 0 0.0 - - -\n\
                     /subdir 4096 40755 2 0 0 0 0.0 - - -\n\
                     /subdir/file 3 100644 1 0 0 0 0.0 - abc -\n";
        let output = roundtrip_test(input);
        assert!(output.contains("/subdir "), "Output: {}", output);
        assert!(output.contains("/subdir/file "), "Output: {}", output);
    }

    #[test]
    fn test_dump_with_xattr() {
        let input = "/ 4096 40755 2 0 0 0 0.0 - - - user.test=hello\n";
        let output = roundtrip_test(input);
        assert!(output.contains("user.test=hello"), "Output: {}", output);
    }

    #[test]
    fn test_dump_with_filter() {
        let input = "/ 4096 40755 3 0 0 0 0.0 - - -\n\
                     /file1 4 100644 1 0 0 0 0.0 - test -\n\
                     /file2 5 100644 1 0 0 0 0.0 - hello -\n\
                     /dir 4096 40755 2 0 0 0 0.0 - - -\n";
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(input).unwrap();
        let image = mkfs_erofs(&fs, FormatVersion::default());

        // Test with filter for file1 only
        let mut output = Vec::new();
        let filters = vec!["file1".to_string()];
        dump_erofs(&mut output, &image, &filters).unwrap();
        let output_str = String::from_utf8(output).unwrap();

        // Should contain root and file1
        assert!(output_str.contains("/ "), "Output: {}", output_str);
        assert!(output_str.contains("/file1 "), "Output: {}", output_str);
        // Should NOT contain file2 or dir
        assert!(
            !output_str.contains("/file2 "),
            "file2 should be filtered out: {}",
            output_str
        );
        assert!(
            !output_str.contains("/dir "),
            "dir should be filtered out: {}",
            output_str
        );
    }

    #[test]
    fn test_dump_with_multiple_filters() {
        let input = "/ 4096 40755 3 0 0 0 0.0 - - -\n\
                     /file1 4 100644 1 0 0 0 0.0 - test -\n\
                     /file2 5 100644 1 0 0 0 0.0 - hello -\n\
                     /dir 4096 40755 2 0 0 0 0.0 - - -\n\
                     /dir/nested 3 100644 1 0 0 0 0.0 - abc -\n";
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(input).unwrap();
        let image = mkfs_erofs(&fs, FormatVersion::default());

        // Test with filter for file1 and dir
        let mut output = Vec::new();
        let filters = vec!["file1".to_string(), "dir".to_string()];
        dump_erofs(&mut output, &image, &filters).unwrap();
        let output_str = String::from_utf8(output).unwrap();

        // Should contain root, file1, dir, and nested file inside dir
        assert!(output_str.contains("/ "), "Output: {}", output_str);
        assert!(output_str.contains("/file1 "), "Output: {}", output_str);
        assert!(output_str.contains("/dir "), "Output: {}", output_str);
        assert!(
            output_str.contains("/dir/nested "),
            "nested file in dir should be included: {}",
            output_str
        );
        // Should NOT contain file2
        assert!(
            !output_str.contains("/file2 "),
            "file2 should be filtered out: {}",
            output_str
        );
    }
}
