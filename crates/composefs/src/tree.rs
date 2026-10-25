//! A filesystem tree which stores regular files using the composefs strategy
//! of inlining small files, and having an external fsverity reference for
//! larger ones.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use crate::fsverity::FsVerityHashValue;

pub use crate::generic_tree::{self, ImageError, Stat};

/// Represents a regular file's content storage strategy in composefs.
///
/// Files can be stored inline for small content or externally referenced
/// for larger files using fsverity hashing.
#[derive(Debug, Clone)]
pub enum RegularFile<ObjectID: FsVerityHashValue> {
    /// File content stored inline as raw bytes.
    Inline(Box<[u8]>),
    /// File stored externally, referenced by fsverity hash and size.
    ///
    /// The tuple contains (fsverity hash, file size in bytes).
    /// The fsverity digest is embedded in the overlay metacopy xattr.
    External(ObjectID, u64),
    /// File stored externally at an explicit path, as libcomposefs models it.
    ///
    /// Unlike `External`, the overlay redirect isn't derived from a digest.
    /// This is what the C API produces for a node with a payload, e.g. ostree's
    /// `xx/<checksum>.file` objects.  Build it with [`RegularFile::external`],
    /// which keeps the cases `External` and `Sparse` cover out of it.
    ExternalPath {
        /// The backing file's path relative to the object store root, written
        /// as `/<redirect>` in the overlay redirect xattr.  Without one, no
        /// redirect is written and overlayfs looks the file up by its own path
        /// in the data layers.
        redirect: Option<Box<OsStr>>,
        /// The fsverity digest to embed in the overlay metacopy xattr, if any.
        verity: Option<ObjectID>,
        /// The file size in bytes.
        size: u64,
    },
    /// File with declared size but no content or external reference.
    /// Produces ChunkBased layout with null chunk indices.
    Sparse(u64),
}

impl<ObjectID: FsVerityHashValue> RegularFile<ObjectID> {
    /// Returns the file size in bytes.
    pub fn file_size(&self) -> u64 {
        match self {
            Self::Inline(data) => data.len() as u64,
            Self::External(_, size) | Self::ExternalPath { size, .. } | Self::Sparse(size) => *size,
        }
    }

    /// Builds an external file from an overlay redirect and verity digest,
    /// the way libcomposefs stores them: independently of each other.
    ///
    /// An empty redirect counts as none, as in libcomposefs.  The result is
    /// `External` when the redirect is the digest's object path (the usual
    /// composefs layout), `Sparse` when there is neither, and `ExternalPath`
    /// otherwise.
    pub fn external(redirect: Option<Box<OsStr>>, verity: Option<ObjectID>, size: u64) -> Self {
        let redirect = redirect.filter(|r| !r.is_empty());
        match (redirect, verity) {
            (None, None) => Self::Sparse(size),
            (Some(redirect), Some(id))
                if redirect.as_bytes() == id.to_object_pathname().as_bytes() =>
            {
                Self::External(id, size)
            }
            (redirect, verity) => Self::ExternalPath {
                redirect,
                verity,
                size,
            },
        }
    }

    /// Returns the path of an external file's backing file relative to the
    /// object store root, which the overlay redirect xattr points at: the
    /// object path for `External`, the redirect for `ExternalPath`.
    ///
    /// This is the libcomposefs payload, which `composefs-info` lists.
    pub fn backing_path(&self) -> Option<Cow<'_, OsStr>> {
        match self {
            Self::External(id, _) => Some(Cow::Owned(id.to_object_pathname().into())),
            Self::ExternalPath { redirect, .. } => redirect.as_deref().map(Cow::Borrowed),
            Self::Inline(_) | Self::Sparse(_) => None,
        }
    }

    /// Returns the object backing an external file in a composefs repository.
    ///
    /// For `ExternalPath`, this is the verity digest if set, otherwise the
    /// redirect parsed as an object pathname.  Fails for inline and sparse
    /// files, and for an `ExternalPath` that names no object this way (like
    /// ostree's `xx/<checksum>.file` without a verity digest).
    pub fn repo_object_id(&self) -> anyhow::Result<ObjectID> {
        match self {
            Self::Inline(_) | Self::Sparse(_) => anyhow::bail!("Not an external file"),
            Self::External(id, _) => Ok(id.clone()),
            Self::ExternalPath {
                verity: Some(id), ..
            } => Ok(id.clone()),
            Self::ExternalPath {
                redirect: Some(redirect),
                verity: None,
                ..
            } => ObjectID::from_object_pathname(redirect.as_bytes()).map_err(|e| {
                anyhow::anyhow!("External file path {redirect:?} is not an object: {e}")
            }),
            Self::ExternalPath {
                redirect: None,
                verity: None,
                ..
            } => anyhow::bail!("External file has neither a path nor a verity digest"),
        }
    }
}

// Re-export generic types. Note that we don't need to re-write
// the generic constraint T: FsVerityHashValue here because it will
// be transitively enforced.

/// Content of a leaf node in the filesystem tree, specialized for composefs regular files.
pub type LeafContent<T> = generic_tree::LeafContent<RegularFile<T>>;

/// A leaf node in the filesystem tree (file, symlink, or device), specialized for composefs regular files.
pub type Leaf<T> = generic_tree::Leaf<RegularFile<T>>;

/// A directory in the filesystem tree, specialized for composefs regular files.
pub type Directory<T> = generic_tree::Directory<RegularFile<T>>;

/// An inode representing either a directory or a leaf node, specialized for composefs regular files.
pub type Inode<T> = generic_tree::Inode<RegularFile<T>>;

/// A complete filesystem tree, specialized for composefs regular files.
pub type FileSystem<T> = generic_tree::FileSystem<RegularFile<T>>;

/// A read-only view of a directory paired with its leaves table, specialized for composefs regular files.
pub type DirectoryRef<'a, T> = generic_tree::DirectoryRef<'a, RegularFile<T>>;

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, ffi::OsStr};

    use super::*;
    use crate::fsverity::Sha256HashValue;
    use crate::generic_tree::LeafId;

    // Helper to create a Stat with a specific mtime
    fn stat_with_mtime(mtime: i64) -> Stat {
        Stat {
            st_mode: 0o755,
            st_uid: 1000,
            st_gid: 1000,
            st_mtim_sec: mtime,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        }
    }

    // Helper to create an empty Directory Inode with a specific mtime
    fn new_dir_inode(mtime: i64) -> Inode<Sha256HashValue> {
        Inode::Directory(Box::new(Directory {
            stat: stat_with_mtime(mtime),
            entries: BTreeMap::new(),
        }))
    }

    // Helper for default stat in tests
    fn default_stat() -> Stat {
        Stat {
            st_mode: 0o755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 0,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        }
    }

    #[test]
    fn test_insert_and_get_leaf() {
        let mut leaves: Vec<Leaf<Sha256HashValue>> = Vec::new();
        let leaf_id = LeafId(leaves.len());
        leaves.push(Leaf {
            stat: stat_with_mtime(10),
            content: LeafContent::Regular(super::RegularFile::Inline(Default::default())),
        });

        let mut dir = Directory::<Sha256HashValue>::new(default_stat());
        dir.insert(OsStr::new("file.txt"), Inode::leaf(leaf_id));
        assert_eq!(dir.entries.len(), 1);

        let retrieved_id = dir.leaf_id(OsStr::new("file.txt")).unwrap();
        assert_eq!(retrieved_id, leaf_id);

        let regular_file_content = dir.get_file(OsStr::new("file.txt"), &leaves).unwrap();
        assert!(matches!(
            regular_file_content,
            super::RegularFile::Inline(_)
        ));
    }

    #[test]
    fn test_insert_and_get_directory() {
        let mut dir = Directory::<Sha256HashValue>::new(default_stat());
        let sub_dir_inode = new_dir_inode(20);
        dir.insert(OsStr::new("subdir"), sub_dir_inode);
        assert_eq!(dir.entries.len(), 1);

        let retrieved_subdir = dir.get_directory(OsStr::new("subdir")).unwrap();
        assert_eq!(retrieved_subdir.stat.st_mtim_sec, 20);

        let retrieved_subdir_opt = dir
            .get_directory_opt(OsStr::new("subdir"))
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_subdir_opt.stat.st_mtim_sec, 20);
    }

    #[test]
    fn test_external() {
        let id = Sha256HashValue::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let other = Sha256HashValue::from_hex(
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        )
        .unwrap();
        let object_path = id.to_object_pathname();
        const OSTREE: &str = "8a/5d74.file";
        // (redirect, verity, variant, repo_object_id, backing_path)
        let cases = [
            (
                Some(object_path.as_str()),
                Some(&id),
                "External",
                Some(&id),
                Some(object_path.as_str()),
            ),
            // The verity digest names the repository object, whatever the redirect
            (
                Some(OSTREE),
                Some(&other),
                "ExternalPath",
                Some(&other),
                Some(OSTREE),
            ),
            (
                Some(object_path.as_str()),
                Some(&other),
                "ExternalPath",
                Some(&other),
                Some(object_path.as_str()),
            ),
            (None, Some(&id), "ExternalPath", Some(&id), None),
            (Some(""), Some(&id), "ExternalPath", Some(&id), None),
            (
                Some(object_path.as_str()),
                None,
                "ExternalPath",
                Some(&id),
                Some(object_path.as_str()),
            ),
            // ostree's payload without verity names no repository object
            (Some(OSTREE), None, "ExternalPath", None, Some(OSTREE)),
            (None, None, "Sparse", None, None),
            (Some(""), None, "Sparse", None, None),
        ];
        for (redirect, verity, variant, object, backing_path) in cases {
            let file = RegularFile::external(
                redirect.map(|r| Box::from(OsStr::new(r))),
                verity.cloned(),
                4096,
            );
            let found = match &file {
                RegularFile::External(..) => "External",
                RegularFile::ExternalPath { .. } => "ExternalPath",
                RegularFile::Sparse(..) => "Sparse",
                RegularFile::Inline(..) => "Inline",
            };
            assert_eq!(found, variant, "{redirect:?} {verity:?}");
            assert_eq!(file.file_size(), 4096);
            assert_eq!(file.repo_object_id().ok().as_ref(), object, "{file:?}");
            assert_eq!(
                file.backing_path().as_deref(),
                backing_path.map(OsStr::new),
                "{file:?}"
            );
        }
        let inline = RegularFile::<Sha256HashValue>::Inline(Box::new([1]));
        assert!(inline.repo_object_id().is_err());
        assert_eq!(inline.backing_path(), None);
    }
}
