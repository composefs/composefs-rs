//! Core ostree on-disk format types and gvariant serialization/deserialization.
//!
//! Defines the Rust representations of ostree objects (commits, directory
//! trees, directory metadata, file headers) and their gvariant wire formats.

use std::fmt;
use std::io::Write;

use anyhow::{Result, anyhow, bail};
use gvariant::aligned_bytes::{A8, AlignedBuf, AlignedSlice, AsAligned, TryAsAligned};
use gvariant::{Marker, Owned, SerializeTo, Structure, Variant, VariantWrap, gv};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use composefs::{fsverity::FsVerityHashValue, util::Sha256Digest};

/// The storage layout of an ostree repository.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum RepoMode {
    /// Objects stored as regular files with original permissions.
    Bare,
    /// Objects stored compressed; used for HTTP serving.
    Archive,
    /// Objects stored as regular files owned by the calling user.
    BareUser,
    /// Like `BareUser` but without xattr or ownership metadata.
    BareUserOnly,
    /// Like `Bare` but xattrs stored in separate sidecar files.
    BareSplitXAttrs,
}

impl std::str::FromStr for RepoMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<RepoMode> {
        Ok(match s {
            "bare" => RepoMode::Bare,
            "archive" | "archive-z2" => RepoMode::Archive,
            "bare-user" => RepoMode::BareUser,
            "bare-user-only" => RepoMode::BareUserOnly,
            "bare-split-xattrs" => RepoMode::BareSplitXAttrs,
            _ => bail!("Unsupported repo mode {}", s),
        })
    }
}

/// The type of an ostree content-addressed object.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ObjectType {
    /// Regular file, symlink, or device node.
    File,
    /// Directory listing mapping names to file/subtree checksums.
    DirTree,
    /// Directory metadata (uid, gid, mode, xattrs).
    DirMeta,
    /// Top-level commit object referencing a root tree.
    Commit,
    /// Marker for a deleted commit.
    TombstoneCommit,
    /// Hard-link placeholder pointing to another object.
    PayloadLink,
    /// Separate xattr storage for a file object.
    FileXAttrs,
    /// Symlink to shared xattr data.
    FileXAttrsLink,
}

impl ObjectType {
    /// Decode from the numeric value used in ostree's on-disk format.
    pub fn from_byte(b: u8) -> Result<Self> {
        Ok(match b {
            1 => ObjectType::File,
            2 => ObjectType::DirTree,
            3 => ObjectType::DirMeta,
            4 => ObjectType::Commit,
            5 => ObjectType::TombstoneCommit,
            7 => ObjectType::PayloadLink,
            8 => ObjectType::FileXAttrs,
            9 => ObjectType::FileXAttrsLink,
            _ => bail!("Unknown object type {b}"),
        })
    }

    /// Returns true for metadata object types (not file content).
    pub fn is_meta(&self) -> bool {
        matches!(
            self,
            ObjectType::DirTree
                | ObjectType::DirMeta
                | ObjectType::Commit
                | ObjectType::TombstoneCommit
        )
    }

    /// Returns the file extension used for this object type on disk.
    pub fn extension(&self, repo_mode: RepoMode) -> &'static str {
        match self {
            ObjectType::File => {
                if repo_mode == RepoMode::Archive {
                    ".filez"
                } else {
                    ".file"
                }
            }
            ObjectType::DirTree => ".dirtree",
            ObjectType::DirMeta => ".dirmeta",
            ObjectType::Commit => ".commit",
            ObjectType::TombstoneCommit => ".commit-tombstone",
            ObjectType::PayloadLink => ".payload-link",
            ObjectType::FileXAttrs => ".file-xattrs",
            ObjectType::FileXAttrsLink => ".file-xattrs-link",
        }
    }
}

pub(crate) fn get_object_pathname(
    mode: RepoMode,
    checksum: &Sha256Digest,
    object_type: ObjectType,
) -> String {
    format!(
        "{:02x}/{}{}",
        checksum[0],
        hex::encode(&checksum[1..]),
        object_type.extension(mode)
    )
}

pub(crate) fn should_inline_file<ObjectID: FsVerityHashValue>(file_size: usize) -> bool {
    file_size <= size_of::<ObjectID>() * 2
}

/// On-disk header prefixed to gvariant data in ostree objects.
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct SizedVariantHeader {
    /// Big-endian size of the following gvariant payload.
    pub size: u32,
    /// Padding for 8-byte alignment.
    pub padding: u32,
}

pub(crate) fn size_prefix(data: &[u8]) -> AlignedBuf {
    let mut buf = AlignedBuf::new();
    let svh = SizedVariantHeader {
        size: u32::to_be(u32::try_from(data.len()).expect("data exceeds u32::MAX")),
        padding: 0,
    };
    buf.with_vec(|v| {
        v.extend_from_slice(svh.as_bytes());
        v.extend_from_slice(data);
    });
    buf
}

pub(crate) fn get_sized_variant_size(data: &[u8]) -> Result<usize> {
    let variant_header_size = size_of::<SizedVariantHeader>();
    let header_data = data
        .get(..variant_header_size)
        .ok_or_else(|| anyhow!("Sized variant too small"))?;

    let aligned: AlignedBuf = header_data.to_vec().into();
    let h = SizedVariantHeader::ref_from_bytes(&aligned)
        .map_err(|e| anyhow!("Sized variant header: {:?}", e))?;
    Ok(u32::from_be(h.size) as usize)
}

pub(crate) fn split_sized_variant(data: &AlignedSlice<A8>) -> Result<(&AlignedSlice<A8>, &[u8])> {
    let variant_size = get_sized_variant_size(data)?;
    let header_size = size_of::<SizedVariantHeader>();
    let total_size = header_size
        .checked_add(variant_size)
        .ok_or_else(|| anyhow!("Sized variant overflow"))?;

    let sized_data: &AlignedSlice<A8> = data
        .get(..total_size)
        .ok_or_else(|| anyhow!("Sized variant too small"))?
        .try_as_aligned()
        .map_err(|_| anyhow!("Sized variant data not aligned"))?;
    let remaining_data = data
        .get(total_size..)
        .ok_or_else(|| anyhow!("Sized variant too small"))?;

    Ok((sized_data, remaining_data))
}

/// Decoded ostree file header (uid, gid, mode, xattrs, symlink target).
#[derive(Debug)]
pub struct OstreeFileHeader {
    /// File size in bytes.
    pub size: u64,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Unix file mode bits.
    pub mode: u32,
    /// Symlink target path (empty string for non-symlinks).
    pub symlink_target: String,
    /// Extended attributes as (name, value) pairs.
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl OstreeFileHeader {
    /// Deserialize from the zlib-sized format used in archive-mode objects.
    pub fn from_zlib_sized(data: &AlignedSlice<A8>) -> Result<Self> {
        let header_size = size_of::<SizedVariantHeader>();
        let variant_data: &AlignedSlice<A8> = data
            .get(header_size..)
            .ok_or_else(|| anyhow!("Zlib file header too small"))?
            .try_as_aligned()
            .map_err(|_| anyhow!("Zlib file header not aligned"))?;

        let gv = gv!("(tuuuusa(ayay))").cast(variant_data.as_aligned());
        let (size, uid, gid, mode, _zero, symlink_target, xattrs_data) = gv.to_tuple();
        let xattrs = xattrs_data
            .iter()
            .map(|x| {
                let (key, value) = x.to_tuple();
                (key.to_vec(), value.to_vec())
            })
            .collect();
        Ok(OstreeFileHeader {
            size: u64::from_be(*size),
            uid: u32::from_be(*uid),
            gid: u32::from_be(*gid),
            mode: u32::from_be(*mode),
            symlink_target: symlink_target.to_str().to_string(),
            xattrs,
        })
    }

    fn xattrs_ref(&self) -> Vec<(&[u8], &[u8])> {
        self.xattrs
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect()
    }

    /// Serializes as the "zlib" format used in archive-mode .filez objects,
    /// which includes the file size, prefixed with a SizedVariantHeader.
    pub fn serialize_zlib_sized(&self) -> AlignedBuf {
        let xattrs = self.xattrs_ref();
        let data = gv!("(tuuuusa(ayay))").serialize_to_vec(&(
            u64::to_be(self.size),
            u32::to_be(self.uid),
            u32::to_be(self.gid),
            u32::to_be(self.mode),
            u32::to_be(0),
            &self.symlink_target,
            &xattrs,
        ));
        size_prefix(&data)
    }

    /// Serializes as the "regular" format used for ostree content checksums,
    /// which omits the file size, prefixed with a SizedVariantHeader.
    pub fn serialize_regular_sized(&self) -> AlignedBuf {
        let xattrs = self.xattrs_ref();
        let data = gv!("(uuuusa(ayay))").serialize_to_vec(&(
            u32::to_be(self.uid),
            u32::to_be(self.gid),
            u32::to_be(self.mode),
            u32::to_be(0),
            &self.symlink_target,
            &xattrs,
        ));
        size_prefix(&data)
    }
}

/// Decoded ostree directory metadata (uid, gid, mode, xattrs).
#[derive(Debug)]
pub struct OstreeDirMeta {
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Unix file mode bits.
    pub mode: u32,
    /// Extended attributes as (name, value) pairs.
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl OstreeDirMeta {
    /// Serialize to raw gvariant data.
    pub fn serialize(&self) -> Vec<u8> {
        let xattrs = self
            .xattrs
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect::<Vec<_>>();
        gv!("(uuua(ayay))").serialize_to_vec(&(
            u32::to_be(self.uid),
            u32::to_be(self.gid),
            u32::to_be(self.mode),
            &xattrs,
        ))
    }

    /// Deserialize from raw gvariant data.
    pub fn from_data(data: &AlignedSlice<A8>) -> Result<Self> {
        let gv = gv!("(uuua(ayay))").cast(data.as_aligned());
        let (uid, gid, mode, xattrs_data) = gv.to_tuple();
        let xattrs = xattrs_data
            .iter()
            .map(|x| {
                let (key, value) = x.to_tuple();
                (key.to_vec(), value.to_vec())
            })
            .collect();
        Ok(OstreeDirMeta {
            uid: u32::from_be(*uid),
            gid: u32::from_be(*gid),
            mode: u32::from_be(*mode),
            xattrs,
        })
    }
}

pub(crate) fn parse_xattr_data(data: &AlignedSlice<A8>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let gv = gv!("a(ayay)").cast(data.as_aligned());
    Ok(gv
        .iter()
        .map(|x| {
            let (key, value) = x.to_tuple();
            (key.to_vec(), value.to_vec())
        })
        .collect())
}

/// Decoded ostree directory tree listing files and subdirectories.
#[derive(Debug)]
pub struct OstreeDirTree {
    /// Files in this directory: (name, content checksum).
    pub files: Vec<(String, Sha256Digest)>,
    /// Subdirectories: (name, tree checksum, dirmeta checksum).
    pub dirs: Vec<(String, Sha256Digest, Sha256Digest)>,
}

impl OstreeDirTree {
    /// Serialize to raw gvariant data.
    ///
    /// Files and directories are sorted by name, matching ostree's
    /// `create_tree_variant_from_hashes` which sorts with `strcmp`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut files: Vec<(&str, [u8; 32])> = self
            .files
            .iter()
            .map(|(name, checksum)| (name.as_str(), *checksum))
            .collect();
        files.sort_by_key(|(name, _)| *name);
        let mut dirs: Vec<(&str, [u8; 32], [u8; 32])> = self
            .dirs
            .iter()
            .map(|(name, tree, meta)| (name.as_str(), *tree, *meta))
            .collect();
        dirs.sort_by_key(|(name, _, _)| *name);
        gv!("(a(say)a(sayay))").serialize_to_vec(&(&files, &dirs))
    }

    /// Deserialize from raw gvariant data.
    pub fn from_data(data: &AlignedSlice<A8>) -> Result<Self> {
        let gv = gv!("(a(say)a(sayay))").cast(data.as_aligned());
        let (files_data, dirs_data) = gv.to_tuple();

        let files = files_data
            .iter()
            .map(|f| {
                let (name, checksum) = f.to_tuple();
                Ok((name.to_str().to_string(), checksum.try_into()?))
            })
            .collect::<Result<Vec<_>>>()?;

        let dirs = dirs_data
            .iter()
            .map(|d| {
                let (name, tree_checksum, meta_checksum) = d.to_tuple();
                Ok((
                    name.to_str().to_string(),
                    tree_checksum.try_into()?,
                    meta_checksum.try_into()?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(OstreeDirTree { files, dirs })
    }
}

/// Decoded ostree commit object with metadata, tree root, and optional parent.
#[derive(Debug)]
pub struct OstreeCommit {
    /// Checksum of the parent commit, if any.
    pub parent_commit: Option<Sha256Digest>,
    /// Commit metadata as (key, value) pairs with preserved variant types.
    pub metadata: Vec<(String, MetadataValue)>,
    /// One-line commit subject.
    pub subject: String,
    /// Extended commit description.
    pub body: String,
    /// Commit timestamp (seconds since Unix epoch).
    pub timestamp: u64,
    /// Checksum of the root directory tree object.
    pub root_tree: Sha256Digest,
    /// Checksum of the root directory metadata object.
    pub root_metadata: Sha256Digest,
}

/// A typed value from an ostree commit metadata dictionary (`a{sv}`).
#[derive(Debug)]
pub enum MetadataValue {
    /// GVariant type `s`.
    String(String),
    /// GVariant type `b`.
    Bool(bool),
    /// GVariant type `u`.
    Uint32(u32),
    /// GVariant type `t`.
    Uint64(u64),
    /// GVariant type `as`.
    StringArray(Vec<String>),
    /// GVariant type `ay`.
    ByteArray(Vec<u8>),
    /// Raw GVariant variant data for types not handled above.
    Other(Owned<Variant>),
}

impl Clone for MetadataValue {
    fn clone(&self) -> Self {
        match self {
            Self::String(s) => Self::String(s.clone()),
            Self::Bool(b) => Self::Bool(*b),
            Self::Uint32(u) => Self::Uint32(*u),
            Self::Uint64(t) => Self::Uint64(*t),
            Self::StringArray(a) => Self::StringArray(a.clone()),
            Self::ByteArray(a) => Self::ByteArray(a.clone()),
            Self::Other(v) => {
                let v: &Variant = v;
                Self::Other(v.to_owned())
            }
        }
    }
}

impl MetadataValue {
    fn from_variant(v: &Variant) -> Self {
        if let Some(s) = v.get(gv!("s")) {
            return Self::String(s.to_str().to_string());
        }
        if let Some(b) = v.get(gv!("b")) {
            return Self::Bool(bool::from(*b));
        }
        if let Some(u) = v.get(gv!("u")) {
            return Self::Uint32(*u);
        }
        if let Some(t) = v.get(gv!("t")) {
            return Self::Uint64(*t);
        }
        if let Some(arr) = v.get(gv!("as")) {
            return Self::StringArray(arr.iter().map(|s| s.to_str().to_string()).collect());
        }
        if let Some(ay) = v.get(gv!("ay")) {
            return Self::ByteArray(ay.to_vec());
        }
        Self::Other(v.to_owned())
    }
}

impl fmt::Display for MetadataValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "{s}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Uint32(u) => write!(f, "{u}"),
            Self::Uint64(t) => write!(f, "{t}"),
            Self::StringArray(arr) => {
                let items: Vec<&str> = arr.iter().map(|s| s.as_str()).collect();
                write!(f, "[{}]", items.join(", "))
            }
            Self::ByteArray(ay) => write!(f, "{}", hex::encode(ay)),
            Self::Other(v) => {
                let (typestr, data) = v.split();
                write!(
                    f,
                    "<{}:{}>",
                    std::str::from_utf8(typestr).unwrap_or("?"),
                    hex::encode(data)
                )
            }
        }
    }
}

impl SerializeTo<Variant> for &MetadataValue {
    fn serialize(self, f: &mut impl Write) -> std::io::Result<usize> {
        match self {
            MetadataValue::String(s) => VariantWrap(gv!("s"), s.as_str()).serialize(f),
            MetadataValue::Bool(b) => VariantWrap(gv!("b"), b).serialize(f),
            MetadataValue::Uint32(u) => VariantWrap(gv!("u"), *u).serialize(f),
            MetadataValue::Uint64(t) => VariantWrap(gv!("t"), *t).serialize(f),
            MetadataValue::StringArray(arr) => {
                let refs: Vec<&str> = arr.iter().map(|s| s.as_str()).collect();
                VariantWrap(gv!("as"), refs).serialize(f)
            }
            MetadataValue::ByteArray(ay) => VariantWrap(gv!("ay"), ay.as_slice()).serialize(f),
            MetadataValue::Other(v) => {
                let v: &Variant = v;
                v.serialize(f)
            }
        }
    }
}

impl OstreeCommit {
    /// Serialize to raw gvariant data.
    pub fn serialize(&self) -> Vec<u8> {
        let metadata: Vec<(&str, &MetadataValue)> =
            self.metadata.iter().map(|(k, v)| (k.as_str(), v)).collect();
        let parent: &[u8] = self
            .parent_commit
            .as_ref()
            .map(|c| c.as_slice())
            .unwrap_or(&[]);
        let related: Vec<(&str, [u8; 32])> = vec![];
        gv!("(a{sv}aya(say)sstayay)").serialize_to_vec(&(
            &metadata,
            parent,
            &related,
            self.subject.as_str(),
            self.body.as_str(),
            u64::to_be(self.timestamp),
            self.root_tree.as_slice(),
            self.root_metadata.as_slice(),
        ))
    }

    /// Deserialize from raw gvariant data.
    pub fn from_data(data: &AlignedSlice<A8>) -> Result<Self> {
        let gv = gv!("(a{sv}aya(say)sstayay)").cast(data.as_aligned());
        let (
            metadata_data,
            parent_checksum,
            _related_objects,
            subject,
            body,
            timestamp,
            root_tree,
            root_metadata,
        ) = gv.to_tuple();

        let parent_commit: Option<Sha256Digest> = parent_checksum.try_into().ok();

        let metadata = metadata_data
            .iter()
            .map(|entry| {
                let (key, value) = entry.to_tuple();
                (key.to_str().to_string(), MetadataValue::from_variant(value))
            })
            .collect();

        Ok(OstreeCommit {
            parent_commit,
            metadata,
            subject: subject.to_str().to_string(),
            body: body.to_str().to_string(),
            timestamp: u64::from_be(*timestamp),
            root_tree: root_tree.try_into()?,
            root_metadata: root_metadata.try_into()?,
        })
    }
}
