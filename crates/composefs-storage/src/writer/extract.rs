//! Tar layer extraction and metadata for exact tar reconstruction.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::{ffi::OsStrExt, fs::FileExt};
use std::path::{Component, Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use cap_std::fs::Dir;
use crc::{CRC_64_GO_ISO, Crc};
use flate2::{Compression, write::GzEncoder};
use openssl::hash::{Hasher, MessageDigest};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Timestamps, XattrFlags};
use rustix::time::Timespec;
use serde_json::json;
use tar_core::{
    EntryType, PaxExtensions,
    parse::{Limits, ParseEvent, ParsedEntry, Parser},
};

use super::records::{self, DIRECTORY, REGULAR, allow_missing};
use super::*;

const IO_SIZE: usize = 64 * 1024;
const HEADER_LIMIT: usize = 2 * 1024 * 1024;
const XATTR_LIMIT: usize = 64 * 1024;
const CRC: Crc<u64> = Crc::<u64>::new(&CRC_64_GO_ISO);
// tar-split/tar/storage/entry.go:FileType and SegmentType.
const SPLIT_FILE: u8 = 1;
const SPLIT_SEGMENT: u8 = 2;

#[derive(Debug, Clone)]
struct Metadata {
    mode: u32,
    uid: u32,
    gid: u32,
    seconds: i64,
    nanos: i64,
    xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

struct DirectoryMetadata {
    metadata: Metadata,
    // When opacity hides inherited metadata, restore the freshly created
    // implicit parent's defaults. Explicit directory headers have no fallback.
    implicit_default: Option<Metadata>,
}

/// Opaque markers hide descendants; recreation also hides the inherited
/// directory's own metadata.
#[derive(PartialEq, Eq)]
enum DirectoryChange {
    Opaque,
    Recreated,
}
impl From<Metadata> for DirectoryMetadata {
    fn from(metadata: Metadata) -> Self {
        Self {
            metadata,
            implicit_default: None,
        }
    }
}

impl Metadata {
    fn directory(dir: &Dir) -> Result<Self> {
        let stat = fs::fstat(dir)?;
        Ok(Self {
            mode: stat.st_mode & 0o7777,
            uid: stat.st_uid,
            gid: stat.st_gid,
            seconds: stat.st_mtime,
            nanos: stat.st_mtime_nsec as i64,
            xattrs: xattrs(dir)?
                .into_iter()
                .filter(|(k, _)| {
                    !k.starts_with(b"trusted.overlay.") && !k.starts_with(b"user.overlay.")
                })
                .collect(),
        })
    }
    fn from_entry(entry: &ParsedEntry<'_>) -> Result<Self> {
        // chown reserves these values for leaving ownership unchanged.
        if entry.uid == u64::from(u32::MAX) {
            return Err(ImportError::Malformed("reserved UID value".into()));
        }
        if entry.gid == u64::from(u32::MAX) {
            return Err(ImportError::Malformed("reserved GID value".into()));
        }
        let mut nanos = 0;
        if let Some(pax) = entry.pax {
            for item in PaxExtensions::new(pax) {
                let item = item.map_err(|e| ImportError::Malformed(e.to_string()))?;
                if item.key_bytes() == b"mtime" {
                    // Each override replaces both whole and fractional seconds.
                    nanos = 0;
                    let value = item
                        .value()
                        .map_err(|e| ImportError::Malformed(e.to_string()))?;
                    if let Some((_, fraction)) = value.split_once('.') {
                        if !fraction.bytes().all(|b| b.is_ascii_digit()) {
                            return Err(ImportError::Malformed(
                                "invalid PAX mtime fraction".into(),
                            ));
                        }
                        let fraction = &fraction[..fraction.len().min(9)];
                        nanos = if fraction.is_empty() {
                            0
                        } else {
                            fraction
                                .parse::<i64>()
                                .map_err(|e| ImportError::Malformed(e.to_string()))?
                                * 10i64.pow(9 - fraction.len() as u32)
                        };
                    }
                }
            }
        }
        let xattrs: BTreeMap<Vec<u8>, Vec<u8>> = entry
            .xattrs
            .iter()
            .filter(|(k, _)| k.as_ref() != b"security.selinux")
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        if xattrs
            .keys()
            .any(|k| k.starts_with(b"trusted.overlay.") || k.starts_with(b"user.overlay."))
        {
            return Err(ImportError::Malformed(
                "OCI entries cannot install overlay control xattrs".into(),
            ));
        }
        Ok(Self {
            mode: entry.mode & 0o7777,
            uid: entry
                .uid
                .try_into()
                .map_err(|_| ImportError::Malformed("UID overflow".into()))?,
            gid: entry
                .gid
                .try_into()
                .map_err(|_| ImportError::Malformed("GID overflow".into()))?,
            seconds: entry
                .mtime
                .try_into()
                .map_err(|_| ImportError::Malformed("mtime overflow".into()))?,
            nanos,
            xattrs,
        })
    }
    fn times(&self) -> Timestamps {
        let mtime = Timespec {
            tv_sec: self.seconds,
            tv_nsec: self.nanos,
        };
        Timestamps {
            last_access: mtime,
            last_modification: mtime,
        }
    }
}

struct SplitWriter<W: Write> {
    stream: W,
    position: u64,
}
impl<W: Write> SplitWriter<W> {
    fn entry(&mut self, mut value: serde_json::Value) -> Result<()> {
        value["position"] = self.position.into();
        self.position += 1;
        serde_json::to_writer(&mut self.stream, &value)?;
        self.stream.write_all(b"\n")?;
        Ok(())
    }
    fn segment(&mut self, bytes: &[u8]) -> Result<()> {
        if !bytes.is_empty() {
            self.entry(json!({"type": SPLIT_SEGMENT, "payload": STANDARD.encode(bytes)}))?;
        }
        Ok(())
    }
    fn file(&mut self, path: &Path, size: u64, crc: u64) -> Result<()> {
        // File records name extracted payloads; the original tar paths remain
        // in raw header segments, independent of this normalized lookup key.
        let name = path.as_os_str().as_bytes();
        let name = if name.is_empty() { b"." } else { name };
        let checksum = (size != 0).then(|| STANDARD.encode(crc.to_be_bytes()));
        let mut entry = json!({
            "type": SPLIT_FILE,
            "size": size,
            "payload": checksum,
        });
        // Match tar-split's SetNameBytes: JSON strings cannot preserve arbitrary
        // Unix path bytes, so invalid UTF-8 uses a base64-encoded name_raw.
        match std::str::from_utf8(name) {
            Ok(name) => entry["name"] = name.into(),
            Err(_) => entry["name_raw"] = STANDARD.encode(name).into(),
        }
        self.entry(entry)
    }
}

struct Source<S> {
    source: S,
    buffer: Vec<u8>,
    offset: usize,
    length: usize,
    file: Option<(File, u64)>,
    eof: bool,
    hash: Hasher,
    bytes: u64,
}
impl<S: LayerSource> Source<S> {
    fn fill(&mut self) -> Result<()> {
        if self.offset != self.length || self.file.is_some() || self.eof {
            return Ok(());
        }
        self.offset = 0;
        self.length = 0;
        match self.source.next_chunk(&mut self.buffer)? {
            None => self.eof = true,
            Some(LayerChunk::Inline(n)) if n > 0 && n <= self.buffer.len() => self.length = n,
            Some(LayerChunk::Inline(_)) => {
                return Err(ImportError::Malformed(
                    "invalid literal chunk length".into(),
                ));
            }
            Some(LayerChunk::File { file, length }) => self.file = Some((file, length)),
        }
        Ok(())
    }
    fn account(&mut self, bytes: &[u8]) -> Result<()> {
        self.hash.update(bytes).map_err(std::io::Error::other)?;
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| ImportError::Malformed("tar size overflow".into()))?;
        Ok(())
    }
    fn literal(&mut self, length: usize) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(length);
        while output.len() < length {
            self.fill()?;
            if self.file.is_some() {
                return Err(ImportError::Malformed(
                    "file reference outside a complete regular-file body".into(),
                ));
            }
            if self.eof {
                return Err(ImportError::Malformed("truncated tar stream".into()));
            }
            let n = (length - output.len()).min(self.length - self.offset);
            output.extend_from_slice(&self.buffer[self.offset..self.offset + n]);
            self.offset += n;
        }
        self.account(&output)?;
        Ok(output)
    }
    fn hash_file(&mut self, file: &File, length: u64, mut copy_to: Option<File>) -> Result<u64> {
        let mut crc = CRC.digest();
        let mut buffer = vec![0; IO_SIZE];
        let mut offset = 0;
        while offset < length {
            let n = ((length - offset).min(buffer.len() as u64)) as usize;
            file.read_exact_at(&mut buffer[..n], offset)?;
            if let Some(target) = &mut copy_to {
                target.write_all(&buffer[..n])?;
            }
            self.account(&buffer[..n])?;
            crc.update(&buffer[..n]);
            offset += n as u64;
        }
        if file.metadata()?.len() != length {
            return Err(ImportError::Malformed(
                "file-backed payload changed length".into(),
            ));
        }
        Ok(crc.finalize())
    }
}

pub(super) struct Extracted {
    pub digest: String,
    pub bytes: u64,
    pub stats: MaterializationStats,
    pub uids: BTreeSet<u32>,
    pub gids: BTreeSet<u32>,
}

// tar-core borrows its header buffer; own the fields needed after reusing it.
struct Entry {
    entry_type: EntryType,
    name: Vec<u8>,
    link: Vec<u8>,
    size: u64,
    metadata: Metadata,
    device: fs::Dev,
}

/// Whiteout markers are empty regular files: the header name carries the
/// entire instruction, so a payload means the entry is not a marker.
fn check_whiteout_marker(entry: &Entry, message: &'static str) -> Result<()> {
    if entry.entry_type != EntryType::Regular || entry.size != 0 {
        return Err(ImportError::Malformed(message.into()));
    }
    Ok(())
}

/// One layer extraction: the destination directories, the tar stream being
/// consumed, and the state accumulated across entries.
struct Extractor<'a, S> {
    root: &'a Dir,
    lowers: &'a [Dir],
    sharing: SharingOptions,
    input: Source<S>,
    split: SplitWriter<GzEncoder<File>>,
    parser: Parser,
    headers: Vec<u8>,
    /// Normalized paths already materialized by this layer.
    seen: HashSet<PathBuf>,
    /// Paths this layer has whited out and not yet recreated.
    whiteouts: HashSet<PathBuf>,
    /// Directories whose inherited metadata this layer hides.
    directory_changes: BTreeMap<PathBuf, DirectoryChange>,
    /// Metadata to restore once every child entry has been written.
    directories: BTreeMap<PathBuf, DirectoryMetadata>,
    stats: MaterializationStats,
    uids: BTreeSet<u32>,
    gids: BTreeSet<u32>,
}

pub(super) fn extract<S: LayerSource>(
    root: &Dir,
    lowers: &[Dir],
    tar_split: File,
    source: S,
    sharing: SharingOptions,
) -> Result<Extracted> {
    Extractor::new(root, lowers, tar_split, source, sharing)?.run()
}

impl<'a, S: LayerSource> Extractor<'a, S> {
    fn new(
        root: &'a Dir,
        lowers: &'a [Dir],
        tar_split: File,
        source: S,
        sharing: SharingOptions,
    ) -> Result<Self> {
        Ok(Self {
            root,
            lowers,
            sharing,
            input: Source {
                source,
                buffer: vec![0; IO_SIZE],
                offset: 0,
                length: 0,
                file: None,
                eof: false,
                hash: Hasher::new(MessageDigest::sha256()).map_err(std::io::Error::other)?,
                bytes: 0,
            },
            split: SplitWriter {
                stream: GzEncoder::new(tar_split, Compression::fast()),
                position: 0,
            },
            parser: Parser::new(Limits {
                max_path_len: Some(4096),
                ..Limits::default()
            }),
            headers: Vec::new(),
            seen: HashSet::new(),
            whiteouts: HashSet::new(),
            directory_changes: BTreeMap::new(),
            directories: BTreeMap::new(),
            stats: MaterializationStats::default(),
            uids: BTreeSet::new(),
            gids: BTreeSet::new(),
        })
    }

    fn run(mut self) -> Result<Extracted> {
        self.prepare_root()?;
        while let Some(entry) = self.read_entry()? {
            self.entry(entry)?;
        }
        self.drain()?;
        self.restore_directories()?;
        self.finish()
    }

    /// The root starts writable for extraction, but its final metadata is
    /// inherited from the parent (or Go's base-layer default), unless tar sets it.
    fn prepare_root(&mut self) -> Result<()> {
        let mut metadata = match self.lowers.first() {
            Some(lower) => Metadata::directory(lower)?,
            None => Metadata::directory(self.root)?,
        };
        if self.lowers.is_empty() {
            metadata.xattrs.clear();
        }
        self.directories.insert(PathBuf::new(), metadata.into());
        fs::fchmod(
            self.root,
            Mode::from_bits_truncate(records::PRIVATE_DIR_MODE),
        )?;
        Ok(())
    }

    /// Consume headers until the next entry, preserving their raw bytes in the
    /// tar-split stream.
    fn read_entry(&mut self) -> Result<Option<Entry>> {
        loop {
            match self
                .parser
                .parse(&self.headers)
                .map_err(|e| ImportError::Malformed(e.to_string()))?
            {
                ParseEvent::NeedData { min_bytes } => {
                    if min_bytes > HEADER_LIMIT || min_bytes <= self.headers.len() {
                        return Err(ImportError::Malformed(
                            "tar headers exceed metadata bound".into(),
                        ));
                    }
                    self.input.fill()?;
                    if self.input.eof && self.headers.is_empty() && self.input.bytes == 0 {
                        return Ok(None);
                    }
                    let more = self.input.literal(min_bytes - self.headers.len())?;
                    self.split.segment(&more)?;
                    self.headers.extend_from_slice(&more);
                }
                ParseEvent::GlobalExtensions { consumed, .. } => {
                    // Go ignores global attributes during extraction. Their raw
                    // headers, payload and padding are already in tar-split.
                    self.headers.drain(..consumed);
                }
                ParseEvent::SparseEntry { .. } => {
                    return Err(ImportError::Malformed(
                        "sparse tar entries are not supported".into(),
                    ));
                }
                ParseEvent::End { .. } => {
                    self.headers.clear();
                    return Ok(None);
                }
                ParseEvent::Entry { entry, .. } => {
                    let metadata = Metadata::from_entry(&entry)?;
                    let entry = Entry {
                        entry_type: entry.entry_type,
                        name: entry.path.to_vec(),
                        link: entry.link_target.as_deref().unwrap_or_default().to_vec(),
                        size: entry.size,
                        metadata,
                        device: fs::makedev(
                            entry.dev_major.unwrap_or(0),
                            entry.dev_minor.unwrap_or(0),
                        ),
                    };
                    self.headers.clear();
                    return Ok(Some(entry));
                }
            }
        }
    }

    /// Materialize one entry and record it in the tar-split stream.
    fn entry(&mut self, entry: Entry) -> Result<()> {
        let path = normalize(&entry.name)?;
        if !self.seen.insert(path.clone()) {
            return Err(ImportError::Malformed(format!(
                "duplicate tar path {path:?}"
            )));
        }
        // Match Go's tar header logger: hardlink headers count, whiteout
        // headers do not. Use the tar basename before path normalization.
        let tar_basename = entry
            .name
            .rsplit(|b| *b == b'/')
            .find(|part| !part.is_empty())
            .unwrap_or_default();
        if !tar_basename.starts_with(b".wh.") {
            self.uids.insert(entry.metadata.uid);
            self.gids.insert(entry.metadata.gid);
        }
        // A whiteout below one of this layer's own whiteouts is unreachable.
        // It is still recorded, so the original tar can be reconstructed.
        let checksum = if self.nested_whiteout(&path) {
            check_whiteout_marker(&entry, "invalid nested whiteout")?;
            0
        } else {
            self.install(&path, &entry)?
        };
        if !matches!(entry.entry_type, EntryType::Regular | EntryType::Continuous)
            && entry.size != 0
        {
            return Err(ImportError::Malformed(
                "non-regular tar entry has a payload".into(),
            ));
        }
        self.split.file(&path, entry.size, checksum)?;
        let padding = ((512 - (entry.size % 512)) % 512) as usize;
        if padding > 0 {
            let bytes = self.input.literal(padding)?;
            self.split.segment(&bytes)?;
        }
        Ok(())
    }

    /// Whether a whiteout entry names a path this layer has already hidden.
    fn nested_whiteout(&self, path: &Path) -> bool {
        let Some(basename) = path.file_name() else {
            return false;
        };
        let basename = basename.as_bytes();
        basename.starts_with(b".wh.")
            && basename != b".wh..wh..opq"
            && path.ancestors().skip(1).any(|p| self.whiteouts.contains(p))
    }

    /// Create the destination object for one entry, returning its payload CRC.
    fn install(&mut self, path: &Path, entry: &Entry) -> Result<u64> {
        if path.as_os_str().is_empty() {
            if entry.entry_type != EntryType::Directory {
                return Err(ImportError::Malformed("non-directory tar root".into()));
            }
            self.directories
                .insert(path.to_owned(), entry.metadata.clone().into());
            return Ok(0);
        }
        let (parent, base) = self.parent(path)?;
        let basename = base.as_bytes();
        // Whiteout entry names are encoded paths, not materialized targets;
        // they can alias targets created by earlier whiteout entries.
        let recreated = !basename.starts_with(b".wh.") && self.whiteouts.remove(path);
        if recreated {
            parent.remove_file(&base)?;
        }
        if entry.entry_type != EntryType::Directory
            && self
                .directories
                .get(path)
                .is_some_and(|d| d.implicit_default.is_some())
        {
            // Earlier entries depend on this directory. Keeping their
            // discarded payloads solely for tar reconstruction is unsupported.
            return Err(ImportError::Malformed(format!(
                "non-directory entry replaces parent of earlier layer entries: {path:?}"
            )));
        }
        if basename == b".wh..wh..opq" {
            check_whiteout_marker(entry, "invalid opaque whiteout")?;
            self.opaque_whiteout(&parent, path)?;
        } else if let Some(target) = basename.strip_prefix(b".wh.") {
            check_whiteout_marker(entry, "invalid whiteout")?;
            self.whiteout(&parent, path, target, &entry.metadata)?;
        } else {
            match entry.entry_type {
                EntryType::Regular | EntryType::Continuous => {
                    return self.regular(&parent, &base, entry.size, &entry.metadata);
                }
                EntryType::Directory => {
                    self.directory(&parent, &base, path, &entry.metadata, recreated)?;
                }
                EntryType::Link => self.hardlink(&parent, &base, &entry.link)?,
                EntryType::Symlink => symlink(&parent, &base, &entry.link, &entry.metadata)?,
                EntryType::Char | EntryType::Block | EntryType::Fifo => {
                    device_node(
                        &parent,
                        &base,
                        entry.entry_type,
                        entry.device,
                        &entry.metadata,
                    )?;
                }
                entry_type => {
                    return Err(ImportError::Malformed(format!(
                        "unsupported tar entry {entry_type:?}"
                    )));
                }
            }
        }
        // Only regular files carry a payload, and so a payload checksum.
        Ok(0)
    }

    /// Install a regular file from a whole-file reference or literal bytes.
    fn regular(
        &mut self,
        parent: &Dir,
        base: &OsStr,
        size: u64,
        metadata: &Metadata,
    ) -> Result<u64> {
        self.input.fill()?;
        let Some((file, length)) = self.input.file.take() else {
            return self.inline_regular(parent, base, size, metadata);
        };
        if length != size {
            return Err(ImportError::Malformed(
                "file reference and tar size disagree".into(),
            ));
        }
        let MaterializedFile {
            hardlinked,
            hash_from,
            copy_to,
        } = materialize(
            parent,
            base,
            file,
            size,
            metadata,
            self.sharing,
            &mut self.stats,
        )?;
        let checksum = self.input.hash_file(&hash_from, size, copy_to)?;
        if !hardlinked {
            apply_metadata(parent, base, metadata, REGULAR)?;
        }
        Ok(checksum)
    }

    fn inline_regular(
        &mut self,
        parent: &Dir,
        base: &OsStr,
        size: u64,
        metadata: &Metadata,
    ) -> Result<u64> {
        let fd = fs::openat(
            parent,
            base,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(records::PRIVATE_FILE_MODE),
        )?;
        let mut file = File::from(fd);
        let mut remaining = size;
        let mut crc = CRC.digest();
        while remaining > 0 {
            let bytes = self.input.literal(remaining.min(IO_SIZE as u64) as usize)?;
            file.write_all(&bytes)?;
            crc.update(&bytes);
            remaining -= bytes.len() as u64;
        }
        apply_metadata(parent, base, metadata, REGULAR)?;
        self.stats.inline_files += 1;
        self.stats.inline_bytes += size;
        Ok(crc.finalize())
    }

    fn directory(
        &mut self,
        parent: &Dir,
        base: &OsStr,
        path: &Path,
        metadata: &Metadata,
        recreated: bool,
    ) -> Result<()> {
        match fs::mkdirat(
            parent,
            base,
            Mode::from_bits_truncate(records::PRIVATE_DIR_MODE),
        ) {
            Ok(()) => {}
            // An implicit parent already created it; O_DIRECTORY|O_NOFOLLOW
            // confirms the existing name really is a directory.
            Err(rustix::io::Errno::EXIST) => {
                records::open_dir(parent, Path::new(base))?;
            }
            Err(e) => return Err(e.into()),
        }
        self.directories
            .insert(path.to_owned(), metadata.clone().into());
        if recreated {
            self.directory_changes
                .insert(path.to_owned(), DirectoryChange::Recreated);
            let dir = records::open_dir(parent, Path::new(base))?;
            fs::fsetxattr(&dir, "trusted.overlay.opaque", b"y", XattrFlags::empty())?;
        }
        Ok(())
    }

    fn hardlink(&self, parent: &Dir, base: &OsStr, link: &[u8]) -> Result<()> {
        // Go does not clamp parent traversal in hardlink targets as it does
        // for absolute entry names.
        let mut target = link;
        while let Some(relative) = target.strip_prefix(b"/") {
            target = relative;
        }
        let target = normalize(target)?;
        if target.as_os_str().is_empty() {
            return Err(ImportError::Malformed("hardlink to tar root".into()));
        }
        let (target_parent, target_base) = existing_parent(self.root, &target)?;
        fs::linkat(&target_parent, target_base, parent, base, AtFlags::empty())?;
        // GNU tar semantics: a hardlink header does not mutate the target
        // inode, including a shared canonical object.
        Ok(())
    }

    /// Hide every lower entry below this layer's copy of the directory.
    fn opaque_whiteout(&mut self, parent: &Dir, path: &Path) -> Result<()> {
        fs::fsetxattr(parent, "trusted.overlay.opaque", b"y", XattrFlags::empty())?;
        self.directory_changes
            .entry(path.parent().unwrap().to_owned())
            .or_insert(DirectoryChange::Opaque);
        Ok(())
    }

    /// Hide a single lower entry with an overlay whiteout device.
    fn whiteout(
        &mut self,
        parent: &Dir,
        path: &Path,
        target: &[u8],
        metadata: &Metadata,
    ) -> Result<()> {
        if target.is_empty() || target == b"." || target == b".." {
            return Err(ImportError::Malformed("invalid whiteout".into()));
        }
        let target = OsStr::from_bytes(target);
        if allow_missing(fs::statat(parent, target, AtFlags::SYMLINK_NOFOLLOW))?.is_some() {
            return Err(ImportError::Malformed(format!(
                "whiteout target already exists in this layer: {:?}",
                path.with_file_name(target)
            )));
        }
        fs::mknodat(parent, target, FileType::CharacterDevice, Mode::empty(), 0)?;
        self.whiteouts.insert(path.with_file_name(target));
        fs::chownat(
            parent,
            target,
            Some(fs::Uid::from_raw(metadata.uid)),
            Some(fs::Gid::from_raw(metadata.gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        // A whiteout is a mode-zero driver control object, not an extracted
        // image inode. Discard inherited ACLs without applying the tar
        // header's mode or xattrs to the device.
        let target_path = proc_path(parent).join(target);
        scrub_inherited_acls(&target_path, &BTreeMap::new())?;
        Ok(())
    }

    /// Open the directory holding `path`, creating any implicit parents.
    fn parent(&mut self, path: &Path) -> Result<(Dir, OsString)> {
        let basename = path
            .file_name()
            .ok_or_else(|| ImportError::Malformed("missing tar path basename".into()))?;
        let mut directory = self.root.try_clone()?;
        let mut prefix = PathBuf::new();
        for part in path.parent().unwrap_or(Path::new("")).components() {
            prefix.push(part.as_os_str());
            let recreated = self.whiteouts.remove(&prefix);
            if recreated {
                directory.remove_file(part.as_os_str())?;
            }
            directory =
                match allow_missing(records::open_dir(&directory, Path::new(part.as_os_str())))? {
                    Some(child) => child,
                    None => {
                        self.implicit_directory(&directory, part.as_os_str(), &prefix, recreated)?
                    }
                };
        }
        Ok((directory, basename.to_owned()))
    }

    /// Create a directory the tar only implies, keeping both the lower
    /// layer's metadata and the default to fall back on when it is hidden.
    fn implicit_directory(
        &mut self,
        parent: &Dir,
        name: &OsStr,
        prefix: &Path,
        recreated: bool,
    ) -> Result<Dir> {
        let inherited = if !recreated
            && !prefix
                .ancestors()
                .skip(1)
                .any(|p| self.directory_changes.contains_key(p))
        {
            lower_directory(self.lowers, prefix)?
        } else {
            None
        };
        let directory = records::create_dir(parent, name, records::DEFAULT_DIR_MODE)?;
        let mut default = Metadata::directory(&directory)?;
        default.xattrs.clear();
        self.directories.insert(
            prefix.to_owned(),
            DirectoryMetadata {
                metadata: inherited.unwrap_or_else(|| default.clone()),
                implicit_default: Some(default),
            },
        );
        if recreated {
            self.directory_changes
                .insert(prefix.to_owned(), DirectoryChange::Recreated);
            fs::fsetxattr(
                &directory,
                "trusted.overlay.opaque",
                b"y",
                XattrFlags::empty(),
            )?;
        }
        Ok(directory)
    }

    /// Retain any bytes following the tar end marker for exact reconstruction.
    fn drain(&mut self) -> Result<()> {
        loop {
            self.input.fill()?;
            if self.input.eof {
                return Ok(());
            }
            let bytes = self.input.literal(self.input.length - self.input.offset)?;
            if bytes.is_empty() {
                return Err(ImportError::Malformed("external data after tar end".into()));
            }
            self.split.segment(&bytes)?;
        }
    }

    /// Children first; restoring directory metadata last preserves mtimes and
    /// allows archives to declare non-writable directories before their files.
    fn restore_directories(&self) -> Result<()> {
        for (path, directory) in self.directories.iter().rev() {
            let hidden = self.directory_changes.get(path) == Some(&DirectoryChange::Recreated)
                || path
                    .ancestors()
                    .skip(1)
                    .any(|p| self.directory_changes.contains_key(p));
            let metadata = if hidden {
                directory
                    .implicit_default
                    .as_ref()
                    .unwrap_or(&directory.metadata)
            } else {
                &directory.metadata
            };
            let (parent, base) = if path.as_os_str().is_empty() {
                (self.root.try_clone()?, OsString::from("."))
            } else {
                existing_parent(self.root, path)?
            };
            apply_metadata(&parent, &base, metadata, DIRECTORY)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Extracted> {
        // Finish the compressed metadata before the transaction's layer-wide
        // syncfs barrier. Extraction does not sync individual files/directories.
        self.split.stream.finish()?;
        let hash = self.input.hash.finish().map_err(std::io::Error::other)?;
        Ok(Extracted {
            digest: format!("sha256:{}", hex::encode(hash)),
            bytes: self.input.bytes,
            stats: self.stats,
            uids: self.uids,
            gids: self.gids,
        })
    }
}

fn symlink(parent: &Dir, base: &OsStr, link: &[u8], metadata: &Metadata) -> Result<()> {
    fs::symlinkat(OsStr::from_bytes(link), parent, base)?;
    apply_metadata(parent, base, metadata, 0o120000)
}

fn device_node(
    parent: &Dir,
    base: &OsStr,
    entry_type: EntryType,
    device: fs::Dev,
    metadata: &Metadata,
) -> Result<()> {
    let (kind, mode) = match entry_type {
        EntryType::Char => (FileType::CharacterDevice, 0o020000),
        EntryType::Block => (FileType::BlockDevice, 0o060000),
        _ => (FileType::Fifo, 0o010000),
    };
    fs::mknodat(
        parent,
        base,
        kind,
        Mode::from_bits_truncate(records::PRIVATE_FILE_MODE),
        device,
    )?;
    apply_metadata(parent, base, metadata, mode)
}

fn normalize(name: &[u8]) -> Result<PathBuf> {
    if name.contains(&0) || name.len() > 4096 {
        return Err(ImportError::Malformed("invalid tar path".into()));
    }
    let mut result = PathBuf::new();
    let path = Path::new(OsStr::from_bytes(name));
    for part in path.components() {
        match part {
            Component::Normal(name) => result.push(name),
            // Like Go's filepath.Clean, absolute paths start at the archive
            // root, and parent segments on absolute paths stop at that root.
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir if result.pop() || path.is_absolute() => {}
            _ => {
                return Err(ImportError::Malformed(format!(
                    "escaping tar path {:?}",
                    OsStr::from_bytes(name)
                )));
            }
        }
    }
    Ok(result)
}

fn existing_parent(root: &Dir, path: &Path) -> Result<(Dir, OsString)> {
    let mut directory = root.try_clone()?;
    for part in path.parent().unwrap_or(Path::new("")).components() {
        directory = records::open_dir(&directory, Path::new(part.as_os_str()))?;
    }
    Ok((
        directory,
        path.file_name()
            .ok_or_else(|| ImportError::Malformed("missing tar path basename".into()))?
            .to_owned(),
    ))
}

/// Find the effective lower directory without traversing symlinks or crossing
/// a lower whiteout/opaque directory. The upper copy must preserve its inode
/// metadata even when the tar only mentions a child.
fn lower_directory(lowers: &[Dir], path: &Path) -> Result<Option<Metadata>> {
    'layers: for lower in lowers {
        let mut dir = lower.try_clone()?;
        let mut opaque = false;
        for component in path.components() {
            let mut value = [0; 8];
            match fs::fgetxattr(&dir, "trusted.overlay.opaque", &mut value) {
                Ok(n) => opaque |= &value[..n] == b"y",
                Err(rustix::io::Errno::NODATA | rustix::io::Errno::OPNOTSUPP) => {}
                Err(e) => return Err(e.into()),
            }
            match allow_missing(records::open_dir(&dir, Path::new(component.as_os_str()))) {
                Ok(Some(child)) => dir = child,
                Ok(None) => {
                    if opaque {
                        return Ok(None);
                    }
                    continue 'layers;
                }
                Err(ImportError::Io(e)) if matches!(e.raw_os_error(), Some(n) if n == rustix::io::Errno::NOTDIR.raw_os_error() || n == rustix::io::Errno::LOOP.raw_os_error()) =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }
        return Ok(Some(Metadata::directory(&dir)?));
    }
    Ok(None)
}

/// Name an open file descriptor for the syscalls that take only a path.
fn proc_path(fd: impl AsFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd()))
}

fn apply_metadata(parent: &Dir, name: &OsStr, metadata: &Metadata, kind: u32) -> Result<()> {
    let stat = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    let path = proc_path(parent).join(name);
    if kind != 0o120000 {
        scrub_inherited_acls(&path, &metadata.xattrs)?;
    }
    if stat.st_uid != metadata.uid || stat.st_gid != metadata.gid {
        fs::chownat(
            parent,
            name,
            Some(fs::Uid::from_raw(metadata.uid)),
            Some(fs::Gid::from_raw(metadata.gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
    }
    if kind != 0o120000 {
        fs::chmodat(
            parent,
            name,
            Mode::from_bits_truncate(metadata.mode),
            AtFlags::empty(),
        )?;
    }

    for (key, value) in &metadata.xattrs {
        let key = OsStr::from_bytes(key);
        match fs::lsetxattr(&path, key, value, XattrFlags::empty()) {
            Ok(()) => {}
            // Match Go's extractor on unsupported filesystems or namespaces.
            Err(rustix::io::Errno::OPNOTSUPP) => {
                tracing::debug!(?path, ?key, "skipping unsupported image xattr");
            }
            Err(e) => return Err(e.into()),
        }
    }
    fs::utimensat(parent, name, &metadata.times(), AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(())
}

/// Host default ACLs must not survive unless the image requests them. chmod
/// alone only changes the ACL mask, leaving named user/group entries behind.
fn scrub_inherited_acls(path: &Path, requested: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<()> {
    for key in [
        b"system.posix_acl_access".as_slice(),
        b"system.posix_acl_default",
    ] {
        if !requested.contains_key(key) {
            match fs::lremovexattr(path, OsStr::from_bytes(key)) {
                Ok(()) => {}
                Err(rustix::io::Errno::NODATA | rustix::io::Errno::OPNOTSUPP) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(())
}

fn xattrs(file: impl AsFd) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut buffer = vec![0; XATTR_LIMIT];
    let n = match fs::flistxattr(&file, &mut buffer) {
        Ok(n) => n,
        Err(rustix::io::Errno::OPNOTSUPP) => return Ok(BTreeMap::new()),
        Err(e) => return Err(e.into()),
    };
    let mut result = BTreeMap::new();
    for key in buffer[..n].split(|b| *b == 0).filter(|s| !s.is_empty()) {
        // Storage labels are host policy and do not participate in image
        // metadata preservation or hardlink compatibility.
        if key == b"security.selinux" {
            continue;
        }
        let mut value = vec![0; XATTR_LIMIT];
        let n = fs::fgetxattr(&file, OsStr::from_bytes(key), &mut value)?;
        value.truncate(n);
        result.insert(key.to_vec(), value);
    }
    Ok(result)
}

fn compatible(file: &File, metadata: &Metadata) -> bool {
    let Ok(stat) = fs::fstat(file) else {
        return false;
    };
    if stat.st_uid != metadata.uid
        || stat.st_gid != metadata.gid
        || stat.st_mode & 0o7777 != metadata.mode
        || stat.st_mtime != metadata.seconds
        || stat.st_mtime_nsec as i64 != metadata.nanos
    {
        return false;
    }
    let Ok(attrs) = xattrs(file) else {
        return false;
    };
    attrs == metadata.xattrs
}

struct MaterializedFile {
    hardlinked: bool,
    hash_from: File,
    copy_to: Option<File>,
}

fn materialize(
    parent: &Dir,
    name: &OsStr,
    source: File,
    size: u64,
    metadata: &Metadata,
    sharing: SharingOptions,
    stats: &mut MaterializationStats,
) -> Result<MaterializedFile> {
    let stat = fs::fstat(&source)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_size < 0
        || stat.st_size as u64 != size
    {
        return Err(ImportError::Malformed(
            "file reference is not a regular file of the declared length".into(),
        ));
    }
    let mut fd = fs::openat(
        parent,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(records::PRIVATE_FILE_MODE),
    )?;
    match fs::ioctl_ficlone(&fd, &source) {
        Ok(()) => {
            stats.reflinked_files += 1;
            stats.reflinked_bytes += size;
            // Hash the cloned inode so both checksums describe the installed
            // bytes even if the source changes after the clone.
            return Ok(MaterializedFile {
                hardlinked: false,
                hash_from: File::from(fd),
                copy_to: None,
            });
        }
        Err(
            rustix::io::Errno::XDEV
            | rustix::io::Errno::OPNOTSUPP
            | rustix::io::Errno::NOTTY
            | rustix::io::Errno::INVAL,
        ) => {}
        Err(e) => return Err(e.into()),
    }
    if sharing.allow_compatible_hardlinks && compatible(&source, metadata) {
        drop(fd);
        parent.remove_file(name)?;
        let path = proc_path(&source);
        match fs::linkat(fs::CWD, &path, parent, name, AtFlags::SYMLINK_FOLLOW) {
            Ok(()) => {
                stats.hardlinked_files += 1;
                stats.hardlinked_bytes += size;
                return Ok(MaterializedFile {
                    hardlinked: true,
                    hash_from: source,
                    copy_to: None,
                });
            }
            Err(
                rustix::io::Errno::XDEV | rustix::io::Errno::MLINK | rustix::io::Errno::OPNOTSUPP,
            ) => {}
            Err(e) => return Err(e.into()),
        }
        fd = fs::openat(
            parent,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(records::PRIVATE_FILE_MODE),
        )?;
    }
    stats.copied_files += 1;
    stats.copied_bytes += size;
    Ok(MaterializedFile {
        hardlinked: false,
        hash_from: source,
        copy_to: Some(File::from(fd)),
    })
}
