//! Reading and writing composefs dumpfile format.
//!
//! This module provides functionality to serialize filesystem trees into
//! the composefs dumpfile text format (writing), and to convert parsed
//! dumpfile entries back into tree structures (reading).
//!
//! The module handles file metadata, extended attributes, and hardlink tracking.

use std::{
    collections::{BTreeMap, HashMap},
    ffi::{OsStr, OsString},
    fmt,
    io::{BufWriter, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use fn_error_context::context;
use rustix::fs::FileType;

use crate::{
    dumpfile_parse::{Entry, Item},
    fsverity::FsVerityHashValue,
    generic_tree::LeafId,
    tree::{Directory, FileSystem, Inode, LeafContent, RegularFile, Stat},
};

fn write_empty(writer: &mut impl fmt::Write) -> fmt::Result {
    writer.write_str("-")
}

/// Escape a byte slice for a space-delimited dumpfile field.
///
/// This corresponds to `print_escaped_optional` in the C composefs
/// `composefs-info.c`, combining `ESCAPE_STANDARD | ESCAPE_LONE_DASH`.
/// Empty values map to `-` (the "none" sentinel), and a bare `-` is
/// hex-escaped so it is not confused with the sentinel.
///
/// Not appropriate for xattr values — use [`write_escaped_raw`] instead.
fn write_escaped(writer: &mut impl fmt::Write, bytes: &[u8]) -> fmt::Result {
    if bytes.is_empty() {
        return write_empty(writer);
    }

    // Matches C ESCAPE_LONE_DASH: a bare `-` must be escaped because
    // the parser uses `-` as the sentinel for "empty/none".
    if bytes == b"-" {
        return writer.write_str("\\x2d");
    }

    write_escaped_raw(writer, bytes, EscapeEquals::No)
}

/// Whether to escape `=` as `\x3d`.
///
/// The C composefs implementation only escapes `=` in xattr key/value
/// fields where it separates the key from the value.  In other fields
/// (paths, content, payload) `=` is a normal graphic character.
#[derive(Clone, Copy)]
enum EscapeEquals {
    /// Escape `=` — used for xattr key/value fields.
    Yes,
    /// Do not escape `=` — used for paths, content, and payload fields.
    No,
}

/// Escape a byte slice without the `-` sentinel logic.
///
/// This corresponds to `print_escaped` in the C composefs
/// `composefs-info.c`.  Used for xattr values where `-` and empty are
/// valid literal values, not sentinels.
///
/// The `escape_eq` parameter controls whether `=` is escaped (only
/// needed in xattr key/value fields where `=` is a separator).
fn write_escaped_raw(
    writer: &mut impl fmt::Write,
    bytes: &[u8],
    escape_eq: EscapeEquals,
) -> fmt::Result {
    for c in bytes {
        let c = *c;

        // Named escapes matching the C composefs implementation.
        match c {
            b'\\' => writer.write_str("\\\\")?,
            b'\n' => writer.write_str("\\n")?,
            b'\r' => writer.write_str("\\r")?,
            b'\t' => writer.write_str("\\t")?,
            b'=' if matches!(escape_eq, EscapeEquals::Yes) => write!(writer, "\\x{c:02x}")?,
            // Hex-escape non-graphic characters (outside 0x21..=0x7E in POSIX locale).
            c if !(b'!'..=b'~').contains(&c) => write!(writer, "\\x{c:02x}")?,
            c => writer.write_char(c as char)?,
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_entry(
    writer: &mut impl fmt::Write,
    path: &Path,
    stat: &Stat,
    ifmt: FileType,
    size: u64,
    nlink: usize,
    rdev: u64,
    payload: impl AsRef<OsStr>,
    content: &[u8],
    digest: Option<&str>,
) -> fmt::Result {
    let mode = stat.st_mode | ifmt.as_raw_mode();
    let uid = stat.st_uid;
    let gid = stat.st_gid;
    let mtim_sec = stat.st_mtim_sec;
    let mtim_nsec = stat.st_mtim_nsec;

    write_escaped(writer, path.as_os_str().as_bytes())?;
    write!(
        writer,
        " {size} {mode:o} {nlink} {uid} {gid} {rdev} {mtim_sec}.{mtim_nsec} "
    )?;
    write_escaped(writer, payload.as_ref().as_bytes())?;
    write!(writer, " ")?;
    write_escaped(writer, content)?;
    write!(writer, " ")?;
    if let Some(id) = digest {
        write!(writer, "{id}")?;
    } else {
        write_empty(writer)?;
    }

    for (key, value) in &stat.xattrs {
        write!(writer, " ")?;
        write_escaped_raw(writer, key.as_bytes(), EscapeEquals::Yes)?;
        write!(writer, "=")?;
        // Xattr values don't use the `-` sentinel — they're always present
        // when the key=value pair exists, and empty or `-` are valid values.
        write_escaped_raw(writer, value, EscapeEquals::Yes)?;
    }

    Ok(())
}

/// Writes a directory entry to the dumpfile format.
///
/// Writes the metadata for a directory including path, permissions, ownership,
/// timestamps, and extended attributes.
pub fn write_directory(
    writer: &mut impl fmt::Write,
    path: &Path,
    stat: &Stat,
    nlink: usize,
) -> fmt::Result {
    write_entry(
        writer,
        path,
        stat,
        FileType::Directory,
        0,
        nlink,
        0,
        "",
        &[],
        None,
    )
}

/// Writes a leaf node (non-directory) entry to the dumpfile format.
///
/// Handles all types of leaf nodes including regular files (inline and external),
/// device files, symlinks, sockets, and FIFOs.
pub fn write_leaf(
    writer: &mut impl fmt::Write,
    path: &Path,
    stat: &Stat,
    content: &LeafContent<impl FsVerityHashValue>,
    nlink: usize,
) -> fmt::Result {
    match content {
        LeafContent::Regular(RegularFile::Inline(data)) => write_entry(
            writer,
            path,
            stat,
            FileType::RegularFile,
            data.len() as u64,
            nlink,
            0,
            "",
            data,
            None,
        ),
        LeafContent::Regular(RegularFile::External(id, size)) => write_entry(
            writer,
            path,
            stat,
            FileType::RegularFile,
            *size,
            nlink,
            0,
            id.to_object_pathname(),
            &[],
            Some(&id.to_hex()),
        ),
        LeafContent::BlockDevice(rdev) => write_entry(
            writer,
            path,
            stat,
            FileType::BlockDevice,
            0,
            nlink,
            *rdev,
            "",
            &[],
            None,
        ),
        LeafContent::CharacterDevice(rdev) => write_entry(
            writer,
            path,
            stat,
            FileType::CharacterDevice,
            0,
            nlink,
            *rdev,
            "",
            &[],
            None,
        ),
        LeafContent::Fifo => write_entry(
            writer,
            path,
            stat,
            FileType::Fifo,
            0,
            nlink,
            0,
            "",
            &[],
            None,
        ),
        LeafContent::Socket => write_entry(
            writer,
            path,
            stat,
            FileType::Socket,
            0,
            nlink,
            0,
            "",
            &[],
            None,
        ),
        LeafContent::Symlink(target) => write_entry(
            writer,
            path,
            stat,
            FileType::Symlink,
            target.as_bytes().len() as u64,
            nlink,
            0,
            target,
            &[],
            None,
        ),
    }
}

/// Writes a hardlink entry to the dumpfile format.
///
/// Creates a special entry that links the given path to an existing target path
/// that was already written to the dumpfile.  The nlink/uid/gid/rdev/mtime
/// fields are written as `-` (ignored); both the C and Rust parsers detect
/// the `@` hardlink prefix on the mode field and skip parsing the remaining
/// numeric fields.
pub fn write_hardlink(writer: &mut impl fmt::Write, path: &Path, target: &OsStr) -> fmt::Result {
    write_escaped(writer, path.as_os_str().as_bytes())?;
    write!(writer, " 0 @120000 - - - - 0.0 ")?;
    write_escaped(writer, target.as_bytes())?;
    write!(writer, " - -")?;
    Ok(())
}

struct DumpfileWriter<'a, W: Write, ObjectID: FsVerityHashValue> {
    hardlinks: HashMap<LeafId, OsString>,
    fs: &'a FileSystem<ObjectID>,
    nlink_map: &'a [u32],
    writer: &'a mut W,
}

#[context("Writing formatted line to dumpfile")]
fn writeln_fmt(writer: &mut impl Write, f: impl Fn(&mut String) -> fmt::Result) -> Result<()> {
    let mut tmp = String::with_capacity(256);
    f(&mut tmp)?;
    Ok(writeln!(writer, "{tmp}")?)
}

impl<'a, W: Write, ObjectID: FsVerityHashValue> DumpfileWriter<'a, W, ObjectID> {
    fn new(writer: &'a mut W, fs: &'a FileSystem<ObjectID>, nlink_map: &'a [u32]) -> Self {
        Self {
            hardlinks: HashMap::new(),
            fs,
            nlink_map,
            writer,
        }
    }

    #[context("Writing directory to dumpfile: {}", path.display())]
    fn write_dir(&mut self, path: &mut PathBuf, dir: &Directory<ObjectID>) -> Result<()> {
        // nlink is 2 + number of subdirectories
        // this is also true for the root dir since '..' is another self-ref
        let nlink = dir.inodes().fold(2, |count, inode| {
            count + {
                match inode {
                    Inode::Directory(..) => 1,
                    _ => 0,
                }
            }
        });

        writeln_fmt(self.writer, |fmt| {
            write_directory(fmt, path, &dir.stat, nlink)
        })?;

        for (name, inode) in dir.sorted_entries() {
            path.push(name);

            match inode {
                Inode::Directory(dir) => {
                    self.write_dir(path, dir)?;
                }
                Inode::Leaf(leaf_id, _) => {
                    self.write_leaf(path, *leaf_id)?;
                }
            }

            path.pop();
        }
        Ok(())
    }

    #[context("Writing leaf to dumpfile: {}", path.display())]
    fn write_leaf(&mut self, path: &Path, leaf_id: LeafId) -> Result<()> {
        let nlink = self.nlink_map[leaf_id.0] as usize;

        if nlink > 1 {
            // This is a hardlink.  We need to handle that specially.
            if let Some(target) = self.hardlinks.get(&leaf_id) {
                return writeln_fmt(self.writer, |fmt| write_hardlink(fmt, path, target));
            }

            // @path gets modified all the time, so take a copy
            self.hardlinks.insert(leaf_id, OsString::from(&path));
        }

        let leaf = self.fs.leaf(leaf_id);
        writeln_fmt(self.writer, |fmt| {
            write_leaf(fmt, path, &leaf.stat, &leaf.content, nlink)
        })
    }
}

/// Writes a complete filesystem tree to the composefs dumpfile format.
///
/// Serializes the entire filesystem structure including all directories, files,
/// metadata, and handles hardlink tracking automatically.
pub fn write_dumpfile(
    writer: &mut impl Write,
    fs: &FileSystem<impl FsVerityHashValue>,
) -> Result<()> {
    let nlink_map = fs.nlinks();
    let path = PathBuf::from("/");
    dump_single_dir(writer, &fs.root, fs, &nlink_map, path)
}

/// Write a single dir
pub fn dump_single_dir<ObjectID: FsVerityHashValue>(
    writer: &mut impl Write,
    dir: &Directory<ObjectID>,
    fs: &FileSystem<ObjectID>,
    nlink_map: &[u32],
    mut path: PathBuf,
) -> Result<()> {
    // default pipe capacity on Linux is 16 pages (65536 bytes), but
    // sometimes the BufWriter will write more than its capacity...
    let mut buffer = BufWriter::with_capacity(32768, writer);
    let mut dfw = DumpfileWriter::new(&mut buffer, fs, nlink_map);

    dfw.write_dir(&mut path, dir)?;
    buffer.flush()?;

    Ok(())
}

/// Write a single file
pub fn dump_single_file<ObjectID: FsVerityHashValue>(
    writer: &mut impl Write,
    leaf_id: LeafId,
    fs: &FileSystem<ObjectID>,
    nlink_map: &[u32],
    path: PathBuf,
) -> Result<()> {
    // default pipe capacity on Linux is 16 pages (65536 bytes), but
    // sometimes the BufWriter will write more than its capacity...
    let mut buffer = BufWriter::with_capacity(32768, writer);
    let mut dfw = DumpfileWriter::new(&mut buffer, fs, nlink_map);

    dfw.write_leaf(&path, leaf_id)?;
    buffer.flush()?;

    Ok(())
}

// Reading: Converting dumpfile entries to tree structures

/// Convert a dumpfile Entry into tree structures and insert into a FileSystem.
pub fn add_entry_to_filesystem<ObjectID: FsVerityHashValue>(
    fs: &mut FileSystem<ObjectID>,
    entry: Entry<'_>,
    hardlinks: &mut HashMap<PathBuf, LeafId>,
) -> Result<()> {
    let path = entry.path.as_ref();

    // Handle root directory specially
    if path == Path::new("/") {
        let stat = entry_to_stat(&entry)?;
        fs.set_root_stat(stat);
        return Ok(());
    }

    // Split the path into directory and filename
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let filename = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Path has no filename: {path:?}"))?;

    // Helper to push a leaf into the filesystem and return a LeafId
    let push_leaf = |fs: &mut FileSystem<ObjectID>, stat, content| fs.push_leaf(stat, content);

    // Convert the entry to an inode
    let inode = match entry.item {
        Item::Directory { .. } => {
            let stat = entry_to_stat(&entry)?;
            Inode::Directory(Box::new(Directory::new(stat)))
        }
        Item::Hardlink { ref target } => {
            // Look up the target in our hardlinks map and reuse the LeafId
            let existing_id = *hardlinks
                .get(target.as_ref())
                .ok_or_else(|| anyhow::anyhow!("Hardlink target not found: {target:?}"))?;
            Inode::leaf(existing_id)
        }
        Item::RegularInline { ref content, .. } => {
            let stat = entry_to_stat(&entry)?;
            let data: Box<[u8]> = match content {
                std::borrow::Cow::Borrowed(d) => Box::from(*d),
                std::borrow::Cow::Owned(d) => d.clone().into_boxed_slice(),
            };
            let content = LeafContent::Regular(RegularFile::Inline(data));
            let id = push_leaf(fs, stat, content);
            Inode::leaf(id)
        }
        Item::Regular {
            size,
            ref fsverity_digest,
            ..
        } => {
            let stat = entry_to_stat(&entry)?;
            let digest = fsverity_digest
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("External file missing fsverity digest"))?;
            let object_id = ObjectID::from_hex(digest)?;
            let content = LeafContent::Regular(RegularFile::External(object_id, size));
            let id = push_leaf(fs, stat, content);
            Inode::leaf(id)
        }
        Item::Device { rdev, nlink } => {
            // S_IFMT = 0o170000, S_IFBLK = 0o60000, S_IFCHR = 0o20000
            let is_chardev = entry.mode & 0o170000 != 0o60000;
            // A whiteout is a character device with rdev=0; hardlinked whiteouts
            // are invalid because composefs cannot represent them correctly.
            if is_chardev && rdev == 0 && nlink > 1 {
                anyhow::bail!(
                    "invalid dumpfile: whiteout entry {:?} has nlink > 1",
                    entry.path
                );
            }
            let stat = entry_to_stat(&entry)?;
            let content = if !is_chardev {
                LeafContent::BlockDevice(rdev)
            } else {
                LeafContent::CharacterDevice(rdev)
            };
            let id = push_leaf(fs, stat, content);
            Inode::leaf(id)
        }
        Item::Symlink { ref target, .. } => {
            let stat = entry_to_stat(&entry)?;
            let target_os: Box<OsStr> = match target {
                std::borrow::Cow::Borrowed(t) => Box::from(t.as_os_str()),
                std::borrow::Cow::Owned(t) => Box::from(t.as_os_str()),
            };
            let content = LeafContent::Symlink(target_os);
            let id = push_leaf(fs, stat, content);
            Inode::leaf(id)
        }
        Item::Fifo { .. } => {
            let stat = entry_to_stat(&entry)?;
            let content = LeafContent::Fifo;
            let id = push_leaf(fs, stat, content);
            Inode::leaf(id)
        }
        Item::Socket { .. } => {
            let stat = entry_to_stat(&entry)?;
            let content = LeafContent::Socket;
            let id = push_leaf(fs, stat, content);
            Inode::leaf(id)
        }
    };

    // Store LeafIds in the hardlinks map for future hardlink lookups
    if let Inode::Leaf(id, _) = inode {
        hardlinks.insert(path.to_path_buf(), id);
    }

    // We need to get the parent_dir after pushing leaves (borrow checker)
    let parent_dir = if parent == Path::new("/") {
        &mut fs.root
    } else {
        fs.root
            .get_directory_mut(parent.as_os_str())
            .with_context(|| format!("Parent directory not found: {parent:?}"))?
    };

    parent_dir.insert(filename, inode);
    Ok(())
}

/// Convert a dumpfile Entry's metadata into a tree Stat structure.
fn entry_to_stat(entry: &Entry<'_>) -> Result<Stat> {
    let mut xattrs = BTreeMap::new();
    for xattr in &entry.xattrs {
        let key: Box<OsStr> = match &xattr.key {
            std::borrow::Cow::Borrowed(k) => Box::from(*k),
            std::borrow::Cow::Owned(k) => Box::from(k.as_os_str()),
        };
        let value: Box<[u8]> = match &xattr.value {
            std::borrow::Cow::Borrowed(v) => Box::from(*v),
            std::borrow::Cow::Owned(v) => v.clone().into_boxed_slice(),
        };
        xattrs.insert(key, value);
    }

    let nsec = entry.mtime.nsec;
    if nsec >= 1_000_000_000 {
        anyhow::bail!("Invalid mtime nanoseconds: {nsec} (must be < 1_000_000_000)");
    }

    Ok(Stat {
        st_mode: entry.mode & 0o7777, // Keep only permission bits
        st_uid: entry.uid,
        st_gid: entry.gid,
        st_mtim_sec: entry.mtime.sec as i64,
        st_mtim_nsec: nsec as u32,
        xattrs,
    })
}

/// Parse a dumpfile string and build a complete FileSystem.
///
/// The dumpfile must start with a root directory entry (`/`) which provides
/// the root metadata. Returns an error if no root entry is found.
pub fn dumpfile_to_filesystem<ObjectID: FsVerityHashValue>(
    dumpfile: &str,
) -> Result<FileSystem<ObjectID>> {
    let mut lines = dumpfile.lines().peekable();
    let mut hardlinks = HashMap::new();

    // Find the first non-empty line which must be the root entry
    let root_stat = loop {
        match lines.next() {
            Some(line) if line.trim().is_empty() => continue,
            Some(line) => {
                let entry = Entry::parse(line)
                    .with_context(|| format!("Failed to parse dumpfile line: {line}"))?;
                ensure!(
                    entry.path.as_ref() == Path::new("/"),
                    "Dumpfile must start with root directory entry, found: {:?}",
                    entry.path
                );
                break entry_to_stat(&entry)?;
            }
            None => anyhow::bail!("Dumpfile is empty, expected root directory entry"),
        }
    };

    let mut fs = FileSystem::new(root_stat);

    // Process remaining entries
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let entry =
            Entry::parse(line).with_context(|| format!("Failed to parse dumpfile line: {line}"))?;
        add_entry_to_filesystem(&mut fs, entry, &mut hardlinks)?;
    }

    debug_assert!(
        fs.fsck().is_ok(),
        "dumpfile parsing produced invalid filesystem"
    );
    Ok(fs)
}

/// Parse a composefs dumpfile string and validate the resulting filesystem
/// for EROFS serialization.
///
/// Combines [`dumpfile_to_filesystem`] with [`ValidatedFileSystem::new`].
/// Returns an error if the dumpfile is malformed or if the resulting
/// filesystem violates EROFS invariants (e.g. hardlinked whiteouts).
pub fn dumpfile_to_validated_filesystem<ObjectID: FsVerityHashValue>(
    dumpfile: &str,
) -> anyhow::Result<crate::erofs::writer::ValidatedFileSystem<ObjectID>> {
    let fs = dumpfile_to_filesystem(dumpfile)?;
    crate::erofs::writer::ValidatedFileSystem::new(fs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsverity::Sha256HashValue;

    const SIMPLE_DUMP: &str = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/empty_file 0 100644 1 0 0 0 1000.0 - - -
/small_file 5 100644 1 0 0 0 1000.0 - hello -
/symlink 7 120777 1 0 0 0 1000.0 /target - -
"#;

    #[test]
    fn test_simple_dumpfile_conversion() -> Result<()> {
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(SIMPLE_DUMP)?;

        // Check files exist
        assert!(fs.root.lookup(OsStr::new("empty_file")).is_some());
        assert!(fs.root.lookup(OsStr::new("small_file")).is_some());
        assert!(fs.root.lookup(OsStr::new("symlink")).is_some());

        // Check inline file content
        let small_file = fs.as_dir().get_file(OsStr::new("small_file"))?;
        if let RegularFile::Inline(data) = small_file {
            assert_eq!(&**data, b"hello");
        } else {
            panic!("Expected inline file");
        }

        Ok(())
    }

    #[test]
    fn test_hardlinks() -> Result<()> {
        // The nlink/uid/gid/rdev fields on hardlink lines use `-` here,
        // matching the C composefs writer convention.  The parser must
        // accept these without trying to parse them as integers.
        let dumpfile = r#"/ 0 40755 2 0 0 0 1000.0 - - -
/original 11 100644 2 0 0 0 1000.0 - hello_world -
/hardlink1 0 @120000 - - - - 0.0 /original - -
/dir1 0 40755 2 0 0 0 1000.0 - - -
/dir1/hardlink2 0 @120000 - - - - 0.0 /original - -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile)?;

        // Get the original file
        let original = fs.root.lookup(OsStr::new("original")).unwrap();
        let hardlink1 = fs.root.lookup(OsStr::new("hardlink1")).unwrap();

        // Get hardlink2 from dir1
        let dir1 = fs.root.get_directory(OsStr::new("dir1"))?;
        let hardlink2 = dir1.lookup(OsStr::new("hardlink2")).unwrap();

        // All three should be Leaf inodes with the same LeafId
        let original_id = match original {
            Inode::Leaf(id, _) => *id,
            _ => panic!("Expected Leaf inode"),
        };
        let hardlink1_id = match hardlink1 {
            Inode::Leaf(id, _) => *id,
            _ => panic!("Expected Leaf inode"),
        };
        let hardlink2_id = match hardlink2 {
            Inode::Leaf(id, _) => *id,
            _ => panic!("Expected Leaf inode"),
        };

        // They should all share the same LeafId
        assert_eq!(original_id, hardlink1_id);
        assert_eq!(original_id, hardlink2_id);

        // Verify nlink count is 3 (original + 2 hardlinks)
        assert_eq!(fs.nlinks()[original_id.0], 3);

        // Verify content
        if let LeafContent::Regular(RegularFile::Inline(data)) = &fs.leaf(original_id).content {
            assert_eq!(&**data, b"hello_world");
        } else {
            panic!("Expected inline regular file");
        }

        Ok(())
    }

    /// Verify that a symlink whose target is literally "-" survives a
    /// write → parse → write round-trip.  Previously `write_escaped`
    /// did not escape a bare "-", so the parser treated it as "none".
    #[test]
    fn test_symlink_target_dash_round_trip() -> Result<()> {
        let dumpfile = "/ 0 40755 2 0 0 0 0.0 - - -\n\
                         /link 1 120777 1 0 0 0 0.0 \\x2d - -\n";
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile)?;
        let link = fs.root.lookup(OsStr::new("link")).unwrap();
        match link {
            Inode::Leaf(id, _) => match &fs.leaf(*id).content {
                LeafContent::Symlink(target) => assert_eq!(target.as_ref(), OsStr::new("-")),
                other => panic!("expected symlink, got {other:?}"),
            },
            _ => panic!("expected leaf"),
        }

        // Re-serialize and verify it round-trips
        let mut out = Vec::new();
        write_dumpfile(&mut out, &fs)?;
        let out_str = std::str::from_utf8(&out).unwrap();
        let fs2 = dumpfile_to_filesystem::<Sha256HashValue>(out_str)?;
        let mut out2 = Vec::new();
        write_dumpfile(&mut out2, &fs2)?;
        assert_eq!(out, out2);
        Ok(())
    }

    /// Verify that xattrs with empty values and with a value of "-"
    /// both survive a round-trip.  Previously `write_escaped` used
    /// the "-" sentinel for empty bytes, which the xattr parser does
    /// not treat specially.
    #[test]
    fn test_xattr_empty_and_dash_values_round_trip() -> Result<()> {
        let mut xattrs = BTreeMap::new();
        xattrs.insert(
            Box::from(OsStr::new("user.empty")),
            Vec::new().into_boxed_slice(),
        );
        xattrs.insert(
            Box::from(OsStr::new("user.dash")),
            vec![b'-'].into_boxed_slice(),
        );

        let mut fs = FileSystem::<Sha256HashValue>::new(Stat {
            st_mode: 0o755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 0,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        });
        let leaf_id = fs.push_leaf(
            Stat {
                st_mode: 0o644,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                st_mtim_nsec: 0,
                xattrs,
            },
            LeafContent::Regular(RegularFile::Inline(b"test".to_vec().into())),
        );
        fs.root.insert(OsStr::new("f"), Inode::leaf(leaf_id));

        let mut out = Vec::new();
        write_dumpfile(&mut out, &fs)?;
        let out_str = std::str::from_utf8(&out).unwrap();
        let fs2 = dumpfile_to_filesystem::<Sha256HashValue>(out_str)?;
        let mut out2 = Vec::new();
        write_dumpfile(&mut out2, &fs2)?;
        assert_eq!(out, out2, "xattr round-trip mismatch:\n{out_str}");
        Ok(())
    }

    /// Verify that write_dumpfile → dumpfile_to_filesystem round-trips
    /// hardlinks correctly.
    #[test]
    fn test_hardlink_write_round_trip() -> Result<()> {
        let stat = || Stat {
            st_mode: 0o644,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 0,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        };

        let mut fs = FileSystem::<Sha256HashValue>::new(Stat {
            st_mode: 0o755,
            ..stat()
        });
        let leaf_id = fs.push_leaf(
            stat(),
            LeafContent::Regular(RegularFile::Inline(b"data".to_vec().into())),
        );
        // Insert original + hardlink (same LeafId)
        fs.root.insert(OsStr::new("original"), Inode::leaf(leaf_id));
        fs.root.insert(OsStr::new("link"), Inode::leaf(leaf_id));

        let mut out = Vec::new();
        write_dumpfile(&mut out, &fs)?;
        let out_str = std::str::from_utf8(&out).unwrap();

        let fs2 = dumpfile_to_filesystem::<Sha256HashValue>(out_str)?;

        // Verify the hardlink is preserved (same LeafId)
        let orig = fs2.root.lookup(OsStr::new("original")).unwrap();
        let link = fs2.root.lookup(OsStr::new("link")).unwrap();
        match (orig, link) {
            (Inode::Leaf(a, _), Inode::Leaf(b, _)) => assert_eq!(a, b),
            _ => panic!("expected both to be leaves"),
        }

        // And re-serialization is stable
        let mut out2 = Vec::new();
        write_dumpfile(&mut out2, &fs2)?;
        assert_eq!(out, out2);
        Ok(())
    }

    /// A whiteout (chardev, rdev=0) with nlink > 1 must be rejected.
    #[test]
    fn test_hardlinked_whiteout_rejected() {
        // /foo 0 20000 2 0 0 0 0.0 - - -
        //       ^size  ^mode ^nlink ^uid ^gid ^rdev ^mtime ^payload ^digest ^xattrs
        // mode 20000 = S_IFCHR (character device), rdev=0 → whiteout, nlink=2
        let dumpfile = "/ 0 40755 2 0 0 0 0.0 - - -\n\
                         /foo 0 20000 2 0 0 0 0.0 - - -\n";
        let result = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile);
        let err = result.expect_err("hardlinked whiteout must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("nlink"),
            "error should mention nlink, got: {msg}"
        );
    }

    /// Helper to escape bytes through write_escaped and return the result.
    fn escaped(bytes: &[u8]) -> String {
        let mut out = String::new();
        write_escaped(&mut out, bytes).unwrap();
        out
    }

    /// Helper to escape bytes through write_escaped_raw with the given mode.
    fn escaped_raw(bytes: &[u8], eq: EscapeEquals) -> String {
        let mut out = String::new();
        write_escaped_raw(&mut out, bytes, eq).unwrap();
        out
    }

    #[test]
    fn test_named_escapes() {
        // These must use named escapes matching C composefs, not \xHH.
        assert_eq!(escaped_raw(b"\\", EscapeEquals::No), "\\\\");
        assert_eq!(escaped_raw(b"\n", EscapeEquals::No), "\\n");
        assert_eq!(escaped_raw(b"\r", EscapeEquals::No), "\\r");
        assert_eq!(escaped_raw(b"\t", EscapeEquals::No), "\\t");

        // Mixed: named escapes interspersed with literals
        assert_eq!(escaped_raw(b"a\nb", EscapeEquals::No), "a\\nb");
        assert_eq!(escaped_raw(b"\t\n\\", EscapeEquals::No), "\\t\\n\\\\");
    }

    #[test]
    fn test_non_graphic_hex_escapes() {
        // Characters outside 0x21..=0x7E get \xHH
        assert_eq!(escaped_raw(b"\x00", EscapeEquals::No), "\\x00");
        assert_eq!(escaped_raw(b"\x1f", EscapeEquals::No), "\\x1f");
        assert_eq!(escaped_raw(b" ", EscapeEquals::No), "\\x20"); // space = 0x20 < '!'
        assert_eq!(escaped_raw(b"\x7f", EscapeEquals::No), "\\x7f");
        assert_eq!(escaped_raw(b"\xff", EscapeEquals::No), "\\xff");
    }

    #[test]
    fn test_equals_escaping_context() {
        // '=' is literal in normal fields (paths, content, payload)
        assert_eq!(escaped_raw(b"a=b", EscapeEquals::No), "a=b");
        assert_eq!(escaped(b"key=val"), "key=val");

        // '=' is escaped in xattr key/value fields
        assert_eq!(escaped_raw(b"a=b", EscapeEquals::Yes), "a\\x3db");
        assert_eq!(
            escaped_raw(b"overlay.redirect=/foo", EscapeEquals::Yes),
            "overlay.redirect\\x3d/foo"
        );
    }

    #[test]
    fn test_escaped_sentinels() {
        // Empty → "-"
        assert_eq!(escaped(b""), "-");
        // Lone dash → "\x2d"
        assert_eq!(escaped(b"-"), "\\x2d");
        // Dash in context is fine
        assert_eq!(escaped(b"a-b"), "a-b");
    }

    #[test]
    fn test_graphic_chars_literal() {
        // All printable graphic ASCII (0x21..=0x7E) except '\' should be literal
        assert_eq!(escaped_raw(b"!", EscapeEquals::No), "!");
        assert_eq!(escaped_raw(b"~", EscapeEquals::No), "~");
        assert_eq!(escaped_raw(b"abc/def.txt", EscapeEquals::No), "abc/def.txt");
    }

    mod proptest_tests {
        use super::*;
        use crate::fsverity::Sha512HashValue;
        use crate::test::proptest_strategies::{build_filesystem, filesystem_spec};
        use proptest::prelude::*;

        /// Serialize filesystem to dumpfile bytes, returning None if the
        /// output contains non-UTF-8 data (binary filenames) which the
        /// text-based dumpfile parser cannot round-trip.
        fn dumpfile_bytes<ObjectID: FsVerityHashValue>(
            fs: &FileSystem<ObjectID>,
        ) -> Option<Vec<u8>> {
            let mut bytes = Vec::new();
            write_dumpfile(&mut bytes, fs).unwrap();
            // dumpfile_to_filesystem requires &str, so reject non-UTF-8
            std::str::from_utf8(&bytes).ok()?;
            Some(bytes)
        }

        fn round_trip_dumpfile<ObjectID: FsVerityHashValue>(orig_bytes: &[u8]) {
            let orig_str = std::str::from_utf8(orig_bytes).unwrap();
            let fs_rt = dumpfile_to_filesystem::<ObjectID>(orig_str).unwrap();

            let mut rt_bytes = Vec::new();
            write_dumpfile(&mut rt_bytes, &fs_rt).unwrap();

            assert_eq!(orig_bytes, &rt_bytes);
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn test_dumpfile_round_trip_sha256(spec in filesystem_spec()) {
                let fs = build_filesystem::<Sha256HashValue>(spec);
                let bytes = dumpfile_bytes(&fs);
                prop_assume!(bytes.is_some(), "dumpfile can't round-trip binary names");
                round_trip_dumpfile::<Sha256HashValue>(&bytes.unwrap());
            }

            #[test]
            fn test_dumpfile_round_trip_sha512(spec in filesystem_spec()) {
                let fs = build_filesystem::<Sha512HashValue>(spec);
                let bytes = dumpfile_bytes(&fs);
                prop_assume!(bytes.is_some(), "dumpfile can't round-trip binary names");
                round_trip_dumpfile::<Sha512HashValue>(&bytes.unwrap());
            }
        }
    }
}
