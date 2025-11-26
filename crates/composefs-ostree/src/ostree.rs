//! Core ostree on-disk format types and gvariant deserialization.
//!
//! Defines the Rust representations of ostree objects (commits, directory
//! trees, directory metadata, file headers) and their gvariant wire formats.

use anyhow::{Result, anyhow};
use gvariant::aligned_bytes::{A8, AlignedBuf, AlignedSlice, AsAligned, TryAsAligned};
use gvariant::{Marker, Structure, gv};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use composefs::{fsverity::FsVerityHashValue, util::Sha256Digest};

#[derive(Debug, PartialEq, Copy, Clone)]
pub(crate) enum RepoMode {
    Bare,
    Archive,
    BareUser,
    BareUserOnly,
    BareSplitXAttrs,
}

impl std::str::FromStr for RepoMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<RepoMode> {
        match s {
            "bare" => Ok(RepoMode::Bare),
            "archive" | "archive-z2" => Ok(RepoMode::Archive),
            "bare-user" => Ok(RepoMode::BareUser),
            "bare-user-only" => Ok(RepoMode::BareUserOnly),
            "bare-split-xattrs" => Ok(RepoMode::BareSplitXAttrs),
            _ => Err(anyhow!("Unsupported repo mode {}", s)),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub(crate) enum ObjectType {
    File,
    DirTree,
    DirMeta,
    Commit,
    TombstoneCommit,
    PayloadLink,
    FileXAttrs,
    FileXAttrsLink,
}

impl ObjectType {
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

/// On-disk header prefixed to gvariant data in ostree objects
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub(crate) struct SizedVariantHeader {
    size: u32,
    padding: u32,
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
pub(crate) struct OstreeFileHeader {
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub symlink_target: String,
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl OstreeFileHeader {
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
pub(crate) struct OstreeDirMeta {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl OstreeDirMeta {
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
pub(crate) struct OstreeDirTree {
    pub files: Vec<(String, Sha256Digest)>,
    pub dirs: Vec<(String, Sha256Digest, Sha256Digest)>,
}

impl OstreeDirTree {
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
pub(crate) struct OstreeCommit {
    pub parent_commit: Option<Sha256Digest>,
    pub metadata: Vec<(String, String)>,
    pub subject: String,
    pub body: String,
    pub timestamp: u64,
    pub root_tree: Sha256Digest,
    pub root_metadata: Sha256Digest,
}

fn format_variant(v: &gvariant::Variant) -> String {
    if let Some(s) = v.get(gv!("s")) {
        return s.to_str().to_string();
    }
    if let Some(b) = v.get(gv!("b")) {
        return bool::from(*b).to_string();
    }
    if let Some(u) = v.get(gv!("u")) {
        return u.to_string();
    }
    if let Some(t) = v.get(gv!("t")) {
        return t.to_string();
    }
    if let Some(arr) = v.get(gv!("as")) {
        let items: Vec<&str> = arr.iter().map(|s| s.to_str()).collect();
        return format!("[{}]", items.join(", "));
    }
    if let Some(ay) = v.get(gv!("ay")) {
        return hex::encode(ay);
    }
    let (typestr, data) = v.split();
    format!(
        "<{}:{}>",
        std::str::from_utf8(typestr).unwrap_or("?"),
        hex::encode(data)
    )
}

impl OstreeCommit {
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
                (key.to_str().to_string(), format_variant(value))
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
