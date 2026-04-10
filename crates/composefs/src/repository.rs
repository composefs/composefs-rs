//! Content-addressable repository for composefs objects.
//!
//! This module provides a repository abstraction for storing and retrieving
//! content-addressed objects, splitstreams, and images with fs-verity
//! verification and garbage collection support.
//!
//! # Repository Layout
//!
//! A composefs repository is a directory with the following structure:
//!
//! ```text
//! repository/
//! ├── objects/                  # Content-addressed object storage
//! │   ├── 4e/                   # First byte of fs-verity hash (hex)
//! │   │   └── 67eaccd9fd...     # Remaining bytes of hash
//! │   └── ...
//! ├── images/                   # Composefs (erofs) image tracking
//! │   ├── 4e67eaccd9fd... → ../objects/4e/67eaccd9fd...
//! │   └── refs/
//! │       └── myimage → ../../4e67eaccd9fd...
//! └── streams/                  # Splitstream storage
//!     ├── oci-config-sha256:... → ../objects/XX/YYY...
//!     ├── oci-layer-sha256:... → ../objects/XX/YYY...
//!     └── refs/                 # Named references (GC roots)
//!         └── mytarball → ../../oci-layer-sha256:...
//! ```
//!
//! # Object Storage
//!
//! All content is stored in `objects/` using fs-verity hashes as filenames,
//! split into 256 subdirectories (`00`-`ff`) by the first byte for filesystem
//! efficiency. Objects are immutable and deduplicated by content. Every file
//! must have fs-verity enabled (except in "insecure" mode).
//!
//! # Images vs Streams
//!
//! The repository distinguishes between two types of derived content:
//!
//! - **Images** (`images/`): Composefs/erofs filesystem images that can be mounted.
//!   These are tracked separately for security: only images produced by the repository
//!   (via mkcomposefs) should be mounted, to avoid exposing the kernel's filesystem
//!   code to untrusted data.
//!
//! - **Streams** (`streams/`): Splitstreams storing arbitrary data (e.g., OCI
//!   image layers and configs). Symlinks map content identifiers to objects.
//!
//! # References (GC Roots)
//!
//! Both `images/refs/` and `streams/refs/` contain named symlinks that serve as
//! garbage collection roots. Any object reachable from a ref is protected from GC.
//! Refs can be organized hierarchically (e.g., `refs/myapp/layer1`).
//!
//! See [`Repository::name_stream`] for creating stream refs.
//!
//! # Garbage Collection
//!
//! The repository supports garbage collection via [`Repository::gc()`]. Objects
//! not reachable from any reference are deleted. The GC algorithm:
//!
//! 1. Walks all references in `images/refs/` and `streams/refs/` to find roots
//! 2. Transitively follows stream references to find all reachable objects
//! 3. Deletes unreferenced objects, images, and streams
//!
//! # fs-verity Integration
//!
//! When running on a filesystem that supports fs-verity (ext4, btrfs, etc.), objects
//! are stored with fs-verity enabled, providing kernel-level integrity verification.
//! In "insecure" mode, fs-verity is not required, allowing operation on filesystems
//! like tmpfs or overlayfs.
//!
//! # Concurrency
//!
//! The repository uses advisory file locking (flock) to coordinate concurrent access.
//! Opening a repository acquires a shared lock, while garbage collection requires
//! an exclusive lock. This ensures GC cannot run while other processes have the
//! repository open.
//!
//! For more details, see the [repository design documentation](../../../doc/repository.md).

use std::{
    collections::{HashMap, HashSet},
    ffi::{CStr, CString, OsStr, OsString},
    fmt,
    fs::{File, canonicalize},
    io::{BufRead, Read, Write},
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
    sync::Arc,
    thread::available_parallelism,
};

use log::{debug, trace};
use tokio::sync::Semaphore;

use anyhow::{Context, Result, bail, ensure};
use fn_error_context::context;
use once_cell::sync::OnceCell;
use rustix::{
    fs::{
        Access, AtFlags, CWD, Dir, FileType, FlockOperation, Mode, OFlags, accessat, flock, linkat,
        mkdirat, openat, readlinkat, statat, syncfs, unlinkat,
    },
    io::{Errno, Result as ErrnoResult},
};

use crate::{
    fsverity::{
        Algorithm, CompareVerityError, EnableVerityError, FsVerityHashValue, FsVerityHasher,
        MeasureVerityError, compute_verity, enable_verity_maybe_copy, ensure_verity_equal,
        measure_verity, measure_verity_opt,
    },
    mount::{composefs_fsmount, mount_at},
    shared_internals::IO_BUF_CAPACITY,
    splitstream::{SplitStreamReader, SplitStreamWriter},
    util::{ErrnoFilter, proc_self_fd, reopen_tmpfile_ro, replace_symlinkat},
};

/// The filename used for repository metadata.
pub const REPO_METADATA_FILENAME: &str = "meta.json";

/// Errors that can occur when opening a repository.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryOpenError {
    /// `meta.json` is missing and the directory does not appear to be
    /// an existing repository.
    #[error(
        "{REPO_METADATA_FILENAME} not found; this repository must be initialized with `cfsctl init`"
    )]
    MetadataMissing,
    /// `meta.json` is missing but `objects/` exists, indicating an
    /// old-format repository that predates `meta.json`.
    #[error(
        "{REPO_METADATA_FILENAME} not found; this appears to be an old-format repository — run `cfsctl init --reset-metadata` to migrate"
    )]
    OldFormatRepository,
    /// `meta.json` exists but could not be parsed.
    #[error("failed to parse {REPO_METADATA_FILENAME}")]
    MetadataInvalid(#[source] serde_json::Error),
    /// The algorithm in `meta.json` does not match the expected type.
    #[error("repository algorithm {found} does not match expected {expected}")]
    AlgorithmMismatch {
        /// The algorithm found in `meta.json`.
        found: Algorithm,
        /// The algorithm expected for this repository type.
        expected: Algorithm,
    },
    /// The repository format version is newer than this tool supports.
    #[error(
        "unsupported repository format version {found} (this tool supports up to {REPO_FORMAT_VERSION})"
    )]
    UnsupportedVersion {
        /// The version found in `meta.json`.
        found: u32,
    },
    /// The repository requires features this tool does not understand.
    #[error("repository requires unknown incompatible features: {0:?}")]
    IncompatibleFeatures(Vec<String>),
    /// An I/O error occurred while opening or probing the repository.
    #[error(transparent)]
    Io(std::io::Error),
}

impl From<Errno> for RepositoryOpenError {
    fn from(e: Errno) -> Self {
        Self::Io(e.into())
    }
}

impl From<std::io::Error> for RepositoryOpenError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// The current repository format version.
///
/// This is a simple integer that is bumped only for fundamental,
/// incompatible changes to the repository layout.  Finer-grained
/// evolution uses the [`FeatureFlags`] system instead.
pub const REPO_FORMAT_VERSION: u32 = 1;

/// Set of feature flags understood by this version of the code.
///
/// When reading a repository whose metadata lists features not in
/// these sets, the rules are:
///
/// - Unknown **compatible** features are silently ignored.
/// - Unknown **read-only compatible** features allow read operations
///   but prevent any writes (adding objects, creating images, GC, …).
/// - Unknown **incompatible** features cause the repository to be
///   rejected entirely.
///
/// There are currently no defined features.
pub mod known_features {
    /// Compatible features understood by this version.
    pub const COMPAT: &[&str] = &[];
    /// Read-only compatible features understood by this version.
    pub const RO_COMPAT: &[&str] = &[];
    /// Incompatible features understood by this version.
    pub const INCOMPAT: &[&str] = &[];
}

/// Feature flags for a composefs repository.
///
/// Inspired by the ext4/XFS/EROFS on-disk feature model:
///
/// - **compatible**: old tools that don't understand these can still
///   fully read and write the repository.
/// - **read_only_compatible**: old tools can read but must not write.
/// - **incompatible**: old tools must refuse to open the repository.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FeatureFlags {
    /// Features that can be safely ignored by older tools.
    #[serde(default)]
    pub compatible: Vec<String>,

    /// Features that allow reading but prevent writing by older tools.
    #[serde(default)]
    pub read_only_compatible: Vec<String>,

    /// Features that require newer tools; older tools must refuse entirely.
    #[serde(default)]
    pub incompatible: Vec<String>,
}

/// Result of checking repository feature compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureCheck {
    /// All features are understood; full read-write access.
    ReadWrite,
    /// Unknown read-only-compatible features present; read access only.
    /// The vec contains the unknown feature names.
    ReadOnly(Vec<String>),
}

impl FeatureFlags {
    /// Check these flags against the known feature sets.
    ///
    /// Returns an error if any unknown incompatible features are present.
    /// Returns [`FeatureCheck::ReadOnly`] if unknown ro-compat features
    /// are present. Returns [`FeatureCheck::ReadWrite`] otherwise.
    pub fn check(&self) -> Result<FeatureCheck, RepositoryOpenError> {
        // Check incompatible features first
        let unknown_incompat: Vec<String> = self
            .incompatible
            .iter()
            .filter(|f| !known_features::INCOMPAT.contains(&f.as_str()))
            .cloned()
            .collect();
        if !unknown_incompat.is_empty() {
            return Err(RepositoryOpenError::IncompatibleFeatures(unknown_incompat));
        }

        // Check ro-compat features
        let unknown_ro: Vec<String> = self
            .read_only_compatible
            .iter()
            .filter(|f| !known_features::RO_COMPAT.contains(&f.as_str()))
            .cloned()
            .collect();
        if !unknown_ro.is_empty() {
            return Ok(FeatureCheck::ReadOnly(unknown_ro));
        }

        // Compatible features are ignored by definition
        Ok(FeatureCheck::ReadWrite)
    }
}

/// Repository metadata stored in `meta.json` at the repository root.
///
/// This file records the repository's format version, digest algorithm,
/// and feature flags so that tools can detect misconfigured invocations
/// (e.g. opening a sha256 repo with `--hash sha512`) and so the
/// algorithm doesn't need to be specified on every command.
///
/// The versioning model is inspired by Linux filesystem superblocks
/// (ext4, XFS, EROFS): a base version integer for fundamental layout
/// changes, plus three tiers of feature flags for finer-grained
/// evolution.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepoMetadata {
    /// Base repository format version.  Tools must refuse to operate
    /// on a repository whose version exceeds what they understand.
    pub version: u32,

    /// The fs-verity algorithm configuration for this repository.
    pub algorithm: Algorithm,

    /// Feature flags.
    #[serde(default)]
    pub features: FeatureFlags,
}

impl RepoMetadata {
    /// Build metadata for a repository using the given hash type.
    pub fn for_hash<ObjectID: FsVerityHashValue>() -> Self {
        Self {
            version: REPO_FORMAT_VERSION,
            algorithm: Algorithm::for_hash::<ObjectID>(),
            features: FeatureFlags::default(),
        }
    }

    /// Build metadata from an explicit [`Algorithm`].
    pub fn new(algorithm: Algorithm) -> Self {
        Self {
            version: REPO_FORMAT_VERSION,
            algorithm,
            features: FeatureFlags::default(),
        }
    }

    /// Check whether this metadata is compatible with the given hash type.
    ///
    /// Validates the base version, feature flags, and algorithm.
    /// Returns a [`FeatureCheck`] indicating read-write or read-only access.
    pub fn check_compatible<ObjectID: FsVerityHashValue>(
        &self,
    ) -> Result<FeatureCheck, RepositoryOpenError> {
        if self.version > REPO_FORMAT_VERSION {
            return Err(RepositoryOpenError::UnsupportedVersion {
                found: self.version,
            });
        }
        if !self.algorithm.is_compatible::<ObjectID>() {
            return Err(RepositoryOpenError::AlgorithmMismatch {
                found: self.algorithm,
                expected: Algorithm::for_hash::<ObjectID>(),
            });
        }
        let access = self.features.check()?;
        Ok(access)
    }

    /// Serialize to pretty-printed JSON with a trailing newline.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut buf = serde_json::to_vec_pretty(self).context("serializing repository metadata")?;
        buf.push(b'\n');
        Ok(buf)
    }

    /// Deserialize from JSON bytes.
    #[context("Parsing repository metadata JSON")]
    pub fn from_json(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).context("deserializing repository metadata")
    }
}

/// Read the fs-verity algorithm from a repository's `meta.json`.
///
/// This is the public API for determining which algorithm a repository
/// uses before opening it (needed to choose the correct `ObjectID`
/// generic parameter for [`Repository::open_path`]).
///
/// Returns `Ok(None)` when `meta.json` is absent.
#[context("Reading repository algorithm")]
pub fn read_repo_algorithm(repo_fd: &impl AsFd) -> Result<Option<Algorithm>> {
    Ok(read_repo_metadata(repo_fd)?.map(|m| m.algorithm))
}

/// Read `meta.json` from a repository directory fd, if it exists.
///
/// Returns `Ok(None)` when the file is absent.
#[context("Reading repository metadata")]
pub(crate) fn read_repo_metadata(repo_fd: &impl AsFd) -> Result<Option<RepoMetadata>> {
    match openat(
        repo_fd,
        REPO_METADATA_FILENAME,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let meta = serde_json::from_reader(std::io::BufReader::new(File::from(fd)))
                .context("parsing meta.json")?;
            Ok(Some(meta))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(e).context("opening meta.json")?,
    }
}

/// Enable fs-verity on an fd, dispatching to the correct hash type
/// based on the [`Algorithm`].
fn enable_verity_for_algorithm(
    dirfd: &impl AsFd,
    fd: BorrowedFd,
    algorithm: &Algorithm,
) -> Result<()> {
    match algorithm {
        Algorithm::Sha256 { .. } => {
            enable_verity_maybe_copy::<crate::fsverity::Sha256HashValue>(dirfd, fd)
                .context("enabling verity (sha256)")?;
        }
        Algorithm::Sha512 { .. } => {
            enable_verity_maybe_copy::<crate::fsverity::Sha512HashValue>(dirfd, fd)
                .context("enabling verity (sha512)")?;
        }
    }
    Ok(())
}

/// Remove algorithm-specific data from a repository directory.
///
/// Deletes `streams/`, `images/`, and `meta.json` but preserves
/// `objects/` (content-addressed blobs that are algorithm-agnostic).
/// This prepares the repository for re-initialization with a
/// (potentially different) algorithm via [`Repository::init_path`].
///
/// After calling this, streams and images will need to be re-imported.
#[context("Resetting repository metadata at {}", path.as_ref().display())]
pub fn reset_metadata(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    for dir in ["streams", "images"] {
        let p = path.join(dir);
        if p.exists() {
            std::fs::remove_dir_all(&p).with_context(|| format!("removing {}", p.display()))?;
        }
    }
    let meta_path = path.join(REPO_METADATA_FILENAME);
    if meta_path.exists() {
        std::fs::remove_file(&meta_path)
            .with_context(|| format!("removing {}", meta_path.display()))?;
    }
    Ok(())
}

/// Return the default path for the user-owned composefs repository.
pub fn user_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").with_context(|| "$HOME must be set when in user mode")?;
    Ok(PathBuf::from(home).join(".var/lib/composefs"))
}

/// Return the default path for the system-global composefs repository.
pub fn system_path() -> PathBuf {
    PathBuf::from("/sysroot/composefs")
}

/// Write `meta.json` into a repository directory fd.
///
/// This atomically writes (via O_TMPFILE + linkat) the metadata file.
/// It will fail if the file already exists.
///
/// If `enable_verity` is true, fs-verity is enabled on `meta.json`
/// before linking it into place.  This signals to future
/// [`Repository::open_path`] callers that verity is required on all
/// objects.
#[context("Writing repository metadata")]
pub(crate) fn write_repo_metadata(
    repo_fd: &impl AsFd,
    meta: &RepoMetadata,
    enable_verity: bool,
) -> Result<()> {
    let data = meta.to_json()?;

    // Try O_TMPFILE for atomic creation
    match openat(
        repo_fd,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    ) {
        Ok(fd) => {
            let mut file = File::from(fd);
            file.write_all(&data)
                .context("writing metadata to tmpfile")?;
            file.sync_all().context("syncing metadata tmpfile")?;

            let ro_fd = reopen_tmpfile_ro(file).context("re-opening tmpfile read-only")?;

            if enable_verity {
                enable_verity_for_algorithm(repo_fd, ro_fd.as_fd(), &meta.algorithm)
                    .context("enabling verity on meta.json")?;
            }

            linkat(
                CWD,
                proc_self_fd(&ro_fd),
                repo_fd,
                REPO_METADATA_FILENAME,
                AtFlags::SYMLINK_FOLLOW,
            )
            .context("linking meta.json into repository")?;
        }
        Err(Errno::OPNOTSUPP | Errno::NOSYS) => {
            // Fallback: direct create (no tmpfs O_TMPFILE support).
            // Use O_EXCL to avoid overwriting, and fsync to ensure the
            // file is complete on disk before we consider init done.
            let fd = openat(
                repo_fd,
                REPO_METADATA_FILENAME,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o644),
            )
            .context("creating meta.json")?;
            let mut file = File::from(fd);
            file.write_all(&data).context("writing meta.json")?;
            file.sync_all().context("syncing meta.json to disk")?;

            if enable_verity {
                let ro_fd = openat(
                    repo_fd,
                    REPO_METADATA_FILENAME,
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .context("re-opening meta.json for verity")?;
                drop(file);
                enable_verity_for_algorithm(repo_fd, ro_fd.as_fd(), &meta.algorithm)
                    .context("enabling verity on meta.json")?;
            }
        }
        Err(e) => {
            return Err(e).context("creating tmpfile for meta.json")?;
        }
    }
    Ok(())
}

/// How an object was stored in the repository.
///
/// Returned by [`Repository::ensure_object_from_file`] to indicate
/// whether the operation used zero-copy reflinks, a regular copy, or found
/// an existing object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectStoreMethod {
    /// Object was stored via reflink (zero-copy, FICLONE ioctl).
    Reflinked,
    /// Object was stored via hardlink (zero-copy, source file linked directly).
    Hardlinked,
    /// Object was stored via regular file copy (reflink not supported).
    Copied,
    /// Object already existed in the repository (deduplicated).
    AlreadyPresent,
}

/// Per-operation context for [`Repository::ensure_object_from_file`].
///
/// Create one of these at the start of a bulk import operation (e.g. importing
/// all layers of a container image) and pass it to every
/// `ensure_object_from_file` call.  The context caches which
/// `(source_device, dest_device)` pairs do not support reflinks, so that
/// after the first `EOPNOTSUPP` / `EXDEV` on a given pair, subsequent
/// calls skip the FICLONE probe entirely.
///
/// This correctly handles multi-store imports where layers may come from
/// different filesystems: a reflink failure on ext4→xfs does not suppress
/// reflink attempts for a later xfs→xfs pair.
#[derive(Debug, Default)]
pub struct ImportContext {
    /// Device-ID pairs where FICLONE has already failed.  Stored as
    /// `(source_dev, dest_dev)` from `fstat().st_dev`.
    reflink_unsupported_devs: Vec<(u64, u64)>,
}

impl ImportContext {
    /// Check whether reflinks are known to be unsupported for this
    /// source→destination device pair.
    pub(crate) fn is_reflink_unsupported(&self, src_dev: u64, dst_dev: u64) -> bool {
        self.reflink_unsupported_devs
            .iter()
            .any(|&(s, d)| s == src_dev && d == dst_dev)
    }

    /// Record that reflinks are unsupported for this device pair.
    pub(crate) fn mark_reflink_unsupported(&mut self, src_dev: u64, dst_dev: u64) {
        if !self.is_reflink_unsupported(src_dev, dst_dev) {
            self.reflink_unsupported_devs.push((src_dev, dst_dev));
        }
    }
}

/// Call openat() on the named subdirectory of "dirfd", possibly creating it first.
///
/// We assume that the directory will probably exist (ie: we try the open first), and on ENOENT, we
/// mkdirat() and retry.
fn ensure_dir_and_openat(dirfd: impl AsFd, filename: &str, flags: OFlags) -> ErrnoResult<OwnedFd> {
    match openat(
        &dirfd,
        filename,
        flags | OFlags::CLOEXEC | OFlags::DIRECTORY,
        0o666.into(),
    ) {
        Ok(file) => Ok(file),
        Err(Errno::NOENT) => match mkdirat(&dirfd, filename, 0o777.into()) {
            Ok(()) | Err(Errno::EXIST) => openat(
                dirfd,
                filename,
                flags | OFlags::CLOEXEC | OFlags::DIRECTORY,
                0o666.into(),
            ),
            Err(other) => Err(other),
        },
        Err(other) => Err(other),
    }
}

/// A zero-sized proof token confirming that a [`Repository`] is writable.
///
/// Obtained by calling [`Repository::ensure_writable`], which performs a fast
/// `faccessat(2)` check.  Write methods on `Repository` require this token
/// internally so that the writable check is performed exactly once per
/// top-level operation rather than at every leaf call.
///
/// Because the type is zero-sized, passing it around has no runtime cost.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WritableRepo;

/// A content-addressable repository for composefs objects.
///
/// Stores content-addressed objects, splitstreams, and images with fsverity
/// verification. Objects are stored by their fsverity digest, streams by SHA256
/// content hash, and both support named references for persistence across
/// garbage collection.
pub struct Repository<ObjectID: FsVerityHashValue> {
    repository: OwnedFd,
    objects: OnceCell<OwnedFd>,
    write_semaphore: OnceCell<Arc<Semaphore>>,
    insecure: bool,
    metadata: RepoMetadata,
    _data: std::marker::PhantomData<ObjectID>,
}

impl<ObjectID: FsVerityHashValue> std::fmt::Debug for Repository<ObjectID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repository")
            .field("repository", &self.repository)
            .field("objects", &self.objects)
            .field("insecure", &self.insecure)
            .finish_non_exhaustive()
    }
}

impl<ObjectID: FsVerityHashValue> Drop for Repository<ObjectID> {
    fn drop(&mut self) {
        flock(&self.repository, FlockOperation::Unlock).expect("repository unlock failed");
    }
}

/// For Repository::gc_category
enum GCCategoryWalkMode {
    RefsOnly,
    AllEntries,
}

/// Statistics from a garbage collection operation.
///
/// Returned by [`Repository::gc`] to report what was (or would be) removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcResult {
    /// Number of unreferenced objects removed (or that would be removed)
    pub objects_removed: u64,
    /// Total bytes of object data removed (or that would be removed)
    pub objects_bytes: u64,
    /// Number of broken symlinks removed in images/
    pub images_pruned: u64,
    /// Number of broken symlinks removed in streams/
    pub streams_pruned: u64,
}

/// A structured error found during a filesystem consistency check.
///
/// Each variant corresponds to a specific kind of repository integrity problem.
/// The `Display` implementation produces a kebab-case error type prefix followed
/// by the path/context and any relevant details, suitable for both human display
/// and structured logging.
#[derive(Debug, Clone, serde::Serialize, thiserror::Error)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum FsckError {
    #[error("fsck: object-invalid-name: {path}: {detail}")]
    ObjectInvalidName { path: String, detail: String },

    #[error("fsck: object-open-failed: {path}: {detail}")]
    ObjectOpenFailed { path: String, detail: String },

    #[error("fsck: object-digest-mismatch: {path}: measured {measured}")]
    ObjectDigestMismatch { path: String, measured: String },

    #[error("fsck: object-verity-failed: {path}: {detail}")]
    ObjectVerityFailed { path: String, detail: String },

    #[error("fsck: object-verity-missing: {path}")]
    ObjectVerityMissing { path: String },

    #[error("fsck: entry-not-symlink: {path}")]
    EntryNotSymlink { path: String },

    #[error("fsck: broken-symlink: {path}")]
    BrokenSymlink { path: String },

    #[error("fsck: stat-failed: {path}: {detail}")]
    StatFailed { path: String, detail: String },

    #[error("fsck: unexpected-file-type: {path}: {detail}")]
    UnexpectedFileType { path: String, detail: String },

    #[error("fsck: stream-open-failed: {path}: {detail}")]
    StreamOpenFailed { path: String, detail: String },

    #[error("fsck: missing-object-ref: {path}: {object_id}")]
    #[serde(rename_all = "camelCase")]
    MissingObjectRef { path: String, object_id: String },

    #[error("fsck: stream-read-failed: {path}: {detail}")]
    StreamReadFailed { path: String, detail: String },

    #[error("fsck: missing-named-ref: {path}: ref {ref_name}: {object_id}")]
    #[serde(rename_all = "camelCase")]
    MissingNamedRef {
        path: String,
        ref_name: String,
        object_id: String,
    },

    #[error("fsck: object-check-failed: {path}: {object_id}: {detail}")]
    #[serde(rename_all = "camelCase")]
    ObjectCheckFailed {
        path: String,
        object_id: String,
        detail: String,
    },

    #[error("fsck: image-open-failed: {path}: {detail}")]
    ImageOpenFailed { path: String, detail: String },

    #[error("fsck: image-read-failed: {path}: {detail}")]
    ImageReadFailed { path: String, detail: String },

    #[error("fsck: image-invalid: {path}: {detail}")]
    ImageInvalid { path: String, detail: String },

    #[error("fsck: image-missing-object: {path}: {object_id}")]
    #[serde(rename_all = "camelCase")]
    ImageMissingObject { path: String, object_id: String },

    #[error("fsck: metadata-parse-failed: meta.json: {detail}")]
    MetadataParseFailed { detail: String },

    #[error(
        "fsck: metadata-algorithm-mismatch: meta.json: expected {expected}, repository opened as {actual}"
    )]
    MetadataAlgorithmMismatch { expected: String, actual: String },
}

/// Results from a filesystem consistency check.
///
/// Returned by [`Repository::fsck`] to report repository integrity status.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FsckResult {
    pub(crate) has_metadata: bool,
    pub(crate) objects_checked: u64,
    pub(crate) objects_corrupted: u64,
    pub(crate) streams_checked: u64,
    pub(crate) streams_corrupted: u64,
    pub(crate) images_checked: u64,
    pub(crate) images_corrupted: u64,
    pub(crate) broken_links: u64,
    pub(crate) missing_objects: u64,
    pub(crate) errors: Vec<FsckError>,
}

impl FsckResult {
    /// Whether the repository has a `meta.json` file.
    pub fn has_metadata(&self) -> bool {
        self.has_metadata
    }

    /// Returns true if no corruption or errors were found.
    pub fn is_ok(&self) -> bool {
        debug_assert!(
            self.objects_corrupted == 0
                && self.streams_corrupted == 0
                && self.images_corrupted == 0
                && self.broken_links == 0
                && self.missing_objects == 0
                || !self.errors.is_empty(),
            "corruption counters are non-zero but no error messages recorded"
        );
        self.errors.is_empty()
    }

    /// Number of objects verified.
    pub fn objects_checked(&self) -> u64 {
        self.objects_checked
    }

    /// Number of objects with bad fsverity digests.
    pub fn objects_corrupted(&self) -> u64 {
        self.objects_corrupted
    }

    /// Number of streams verified.
    pub fn streams_checked(&self) -> u64 {
        self.streams_checked
    }

    /// Number of streams with issues (bad header, missing refs, etc.).
    pub fn streams_corrupted(&self) -> u64 {
        self.streams_corrupted
    }

    /// Number of images verified.
    pub fn images_checked(&self) -> u64 {
        self.images_checked
    }

    /// Number of images with issues.
    pub fn images_corrupted(&self) -> u64 {
        self.images_corrupted
    }

    /// Number of broken symlinks found.
    pub fn broken_links(&self) -> u64 {
        self.broken_links
    }

    /// Number of missing objects referenced by streams.
    pub fn missing_objects(&self) -> u64 {
        self.missing_objects
    }

    /// Errors found during the check.
    pub fn errors(&self) -> &[FsckError] {
        &self.errors
    }
}

impl fmt::Display for FsckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let metadata_errors = self.errors.iter().any(|e| {
            matches!(
                e,
                FsckError::MetadataParseFailed { .. } | FsckError::MetadataAlgorithmMismatch { .. }
            )
        });
        if metadata_errors {
            writeln!(f, "meta.json: error")?;
        } else if self.has_metadata {
            writeln!(f, "meta.json: ok")?;
        } else {
            writeln!(f, "meta.json: absent")?;
        }
        writeln!(
            f,
            "objects: {}/{} ok",
            self.objects_checked.saturating_sub(self.objects_corrupted),
            self.objects_checked
        )?;
        writeln!(
            f,
            "streams: {}/{} ok",
            self.streams_checked.saturating_sub(self.streams_corrupted),
            self.streams_checked
        )?;
        writeln!(
            f,
            "images: {}/{} ok",
            self.images_checked.saturating_sub(self.images_corrupted),
            self.images_checked
        )?;
        if self.broken_links > 0 {
            writeln!(f, "broken symlinks: {}", self.broken_links)?;
        }
        if self.missing_objects > 0 {
            writeln!(f, "missing objects: {}", self.missing_objects)?;
        }
        if self.errors.is_empty() {
            writeln!(f, "status: ok")?;
        } else {
            writeln!(f, "status: {} error(s)", self.errors.len())?;
            for err in &self.errors {
                writeln!(f, "  - {err}")?;
            }
        }
        Ok(())
    }
}

impl<ObjectID: FsVerityHashValue> Repository<ObjectID> {
    /// Return the objects directory.
    pub fn objects_dir(&self) -> ErrnoResult<&OwnedFd> {
        self.objects
            .get_or_try_init(|| ensure_dir_and_openat(&self.repository, "objects", OFlags::PATH))
    }

    /// Return a shared semaphore for limiting concurrent object writes.
    ///
    /// This semaphore is lazily initialized with `available_parallelism()` permits,
    /// and shared across all operations on this repository. Use this to limit
    /// concurrent I/O when processing multiple files or layers in parallel.
    pub fn write_semaphore(&self) -> Arc<Semaphore> {
        self.write_semaphore
            .get_or_init(|| {
                let max_concurrent = available_parallelism().map(|n| n.get()).unwrap_or(4);
                Arc::new(Semaphore::new(max_concurrent))
            })
            .clone()
    }

    /// Initialize a new repository at the target path and open it.
    ///
    /// Creates the directory (mode 0700) if it does not exist, writes
    /// `meta.json` for the given `algorithm`, and returns the opened
    /// repository together with a flag indicating whether this was a
    /// fresh initialization (`true`) or an idempotent open of an
    /// existing repository with the same algorithm (`false`).
    ///
    /// The `algorithm` must be compatible with this repository's
    /// `ObjectID` type (e.g. `Algorithm::Sha512` for
    /// `Repository<Sha512HashValue>`).
    ///
    /// If `enable_verity` is true, fs-verity is enabled on `meta.json`,
    /// signaling that all objects must also have verity.
    ///
    /// If `meta.json` already exists with a different algorithm, an
    /// error is returned.
    #[context("Initializing repository at {}", path.as_ref().display())]
    pub fn init_path(
        dirfd: impl AsFd,
        path: impl AsRef<Path>,
        algorithm: Algorithm,
        enable_verity: bool,
    ) -> Result<(Self, bool)> {
        let path = path.as_ref();

        if !algorithm.is_compatible::<ObjectID>() {
            bail!(
                "algorithm {} is not compatible with this repository type (expected {})",
                algorithm,
                Algorithm::for_hash::<ObjectID>(),
            );
        }

        mkdirat(&dirfd, path, Mode::from_raw_mode(0o700))
            .or_else(|e| if e == Errno::EXIST { Ok(()) } else { Err(e) })
            .with_context(|| format!("creating repository directory {}", path.display()))?;

        let repo_fd = openat(
            &dirfd,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening repository directory {}", path.display()))?;

        let meta = RepoMetadata::new(algorithm);

        // Try to write meta.json.  If it already exists, check for
        // idempotency: same algorithm is fine, different is an error.
        if let Err(write_err) = write_repo_metadata(&repo_fd, &meta, enable_verity) {
            match read_repo_metadata(&repo_fd)? {
                Some(existing) if existing == meta => {
                    // Idempotent: same config, already initialized.
                    let repo = Self::open_path(dirfd, path)?;
                    return Ok((repo, false));
                }
                Some(existing) => {
                    bail!(
                        "repository already initialized with algorithm '{}'; \
                         cannot re-initialize with '{}'",
                        existing.algorithm,
                        meta.algorithm,
                    );
                }
                None => {
                    // meta.json doesn't exist, so the write failure
                    // was something else — propagate original error.
                    return Err(write_err);
                }
            }
        }

        drop(repo_fd);
        let repo = Self::open_path(dirfd, path)?;
        Ok((repo, true))
    }

    /// Open a repository at the target directory and path.
    ///
    /// `meta.json` is read, parsed, and validated against this
    /// repository's `ObjectID` type.  Parsing or compatibility errors
    /// are propagated immediately so that broken metadata is never
    /// silently ignored.
    ///
    /// The repository's security mode is auto-detected: if `meta.json`
    /// has fs-verity enabled the repo requires verity on all objects
    /// (secure mode).  Otherwise the repository operates in insecure
    /// mode.  Use [`set_insecure`] to override after opening.
    pub fn open_path(
        dirfd: impl AsFd,
        path: impl AsRef<Path>,
    ) -> Result<Self, RepositoryOpenError> {
        let path = path.as_ref();

        // O_PATH isn't enough because flock()
        let repository = openat(dirfd, path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;

        flock(&repository, FlockOperation::LockShared)?;

        // Read, parse, and validate meta.json up front so that broken
        // or incompatible metadata is caught immediately rather than
        // being discovered lazily on first use.
        let (metadata, has_verity) = Self::read_and_probe_metadata(&repository)?;
        metadata.check_compatible::<ObjectID>()?;

        Ok(Self {
            repository,
            objects: OnceCell::new(),
            write_semaphore: OnceCell::new(),
            insecure: !has_verity,
            metadata,
            _data: std::marker::PhantomData,
        })
    }

    /// Read, parse, and probe verity on `meta.json`.
    ///
    /// Returns `Ok((metadata, has_verity))` when the file exists,
    /// and `Err` when absent or on I/O / parse failures.
    fn read_and_probe_metadata(
        repo_fd: &OwnedFd,
    ) -> Result<(RepoMetadata, bool), RepositoryOpenError> {
        let meta_fd = match openat(
            repo_fd,
            REPO_METADATA_FILENAME,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => {
                // Detect old-format repositories that have objects/ but
                // no meta.json.  Use filter_errno so non-ENOENT errors
                // from statat are propagated.
                return Err(
                    match statat(repo_fd, "objects", AtFlags::empty()).filter_errno(Errno::NOENT) {
                        Ok(Some(_)) => RepositoryOpenError::OldFormatRepository,
                        Ok(None) => RepositoryOpenError::MetadataMissing,
                        Err(e) => e.into(),
                    },
                );
            }
            Err(e) => return Err(e.into()),
        };

        // Clone the fd: one for reading, one for the verity probe.
        let read_fd = meta_fd.try_clone()?;
        let meta: RepoMetadata =
            serde_json::from_reader(std::io::BufReader::new(File::from(read_fd)))
                .map_err(RepositoryOpenError::MetadataInvalid)?;

        // Probe verity on the original fd.
        let has_verity = measure_verity_opt::<ObjectID>(&meta_fd)
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .is_some();

        Ok((meta, has_verity))
    }

    /// Open the default user-owned composefs repository.
    #[context("Opening user repository")]
    pub fn open_user() -> Result<Self> {
        Ok(Self::open_path(CWD, user_path()?)?)
    }

    /// Open the default system-global composefs repository.
    #[context("Opening system repository")]
    pub fn open_system() -> Result<Self> {
        Ok(Self::open_path(CWD, system_path())?)
    }

    fn ensure_dir(&self, dir: impl AsRef<Path>) -> ErrnoResult<()> {
        mkdirat(&self.repository, dir.as_ref(), 0o755.into()).or_else(|e| match e {
            Errno::EXIST => Ok(()),
            _ => Err(e),
        })
    }

    /// Asynchronously ensures an object exists in the repository.
    ///
    /// Same as `ensure_object` but runs the operation on a blocking thread pool
    /// to avoid blocking async tasks. Returns the fsverity digest of the object.
    ///
    /// For performance reasons, this function does *not* call fsync() or similar.  After you're
    /// done with everything, call `Repository::sync_async()`.
    #[context("Ensuring object asynchronously")]
    pub async fn ensure_object_async(self: &Arc<Self>, data: Vec<u8>) -> Result<ObjectID> {
        let writable = self.ensure_writable_token()?;
        let self_ = Arc::clone(self);
        tokio::task::spawn_blocking(move || self_.ensure_object_impl(&data, &writable)).await?
    }

    /// Import an object by streaming from a file descriptor into a
    /// tmpfile, without buffering the entire file in memory.
    ///
    /// In insecure mode the verity digest is computed while copying,
    /// avoiding a second read pass.
    #[context("Ensuring object from file descriptor")]
    pub(crate) fn ensure_object_from_fd(&self, source: OwnedFd, size: u64) -> Result<ObjectID> {
        let writable = self.ensure_writable_token()?;
        let tmpfile_fd = self.create_object_tmpfile_impl(&writable)?;

        if self.insecure {
            // Insecure mode: compute verity digest while copying, avoiding
            // a second read of the data in finalize_object_tmpfile_impl.
            let mut hasher = FsVerityHasher::<ObjectID>::new();
            let mut src = std::io::BufReader::with_capacity(IO_BUF_CAPACITY, File::from(source));
            let mut dst = File::from(tmpfile_fd.try_clone()?);

            loop {
                let buf = src.fill_buf()?;
                if buf.is_empty() {
                    break;
                }
                let chunk = &buf[..buf.len().min(FsVerityHasher::<ObjectID>::BLOCK_SIZE)];
                hasher.add_block(chunk);
                dst.write_all(chunk)?;
                let n = chunk.len();
                src.consume(n);
            }
            drop(dst);

            let id = hasher.digest();
            let ro_fd = reopen_tmpfile_ro(File::from(tmpfile_fd))
                .context("Re-opening tmpfile as read-only")?;
            let objects_dir = self.objects_dir().context("Getting objects directory")?;
            let (id, _method) = self.link_tmpfile_as_object(objects_dir, &ro_fd, &id, size)?;
            Ok(id)
        } else {
            // Secure mode: let std::io::copy use copy_file_range for
            // potential reflinks, then finalize_object_tmpfile_impl
            // enables kernel verity and measures the digest.
            let mut src = File::from(source);
            let mut dst = File::from(tmpfile_fd.try_clone()?);
            let copied = std::io::copy(&mut src, &mut dst)?;
            ensure!(copied == size, "Expected {size} bytes, got {copied}");
            drop(dst);

            let (id, _method) =
                self.finalize_object_tmpfile_impl(File::from(tmpfile_fd), size, &writable)?;
            Ok(id)
        }
    }

    /// Create an O_TMPFILE in the objects directory for streaming writes.
    ///
    /// Returns the file descriptor for writing. The caller should write data to this fd,
    /// then call [`finalize_object_tmpfile`](Self::finalize_object_tmpfile) to compute
    /// the verity digest, enable fs-verity, and link the file into the objects directory.
    #[context("Creating object tmpfile")]
    pub fn create_object_tmpfile(&self) -> Result<OwnedFd> {
        let writable = self.ensure_writable_token()?;
        self.create_object_tmpfile_impl(&writable)
    }

    #[context("Creating object tmpfile")]
    pub(crate) fn create_object_tmpfile_impl(&self, _writable: &WritableRepo) -> Result<OwnedFd> {
        let objects_dir = self
            .objects_dir()
            .context("Getting objects directory for tmpfile creation")?;
        let fd = openat(
            objects_dir,
            ".",
            OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .context("Opening temp file in objects directory")?;
        Ok(fd)
    }

    /// Ensure an object exists by reflinking or hardlinking from a source file.
    ///
    /// The fallback chain is: reflink -> hardlink -> copy.
    ///
    /// - **Reflink** (FICLONE): zero-copy clone on btrfs/XFS. Uses a tmpfile.
    /// - **Hardlink**: enables fs-verity on the source file in-place, then
    ///   hardlinks it directly into the objects directory. This avoids all data
    ///   copying on filesystems like ext4 that don't support reflinks.
    /// - **Copy**: regular data copy into a tmpfile as last resort.
    ///
    /// The `ctx` argument accumulates knowledge across calls in the same
    /// import operation.  After the first reflink attempt fails with
    /// `EOPNOTSUPP` / `EXDEV`, the context records this so that subsequent
    /// calls skip straight to the hardlink path.
    ///
    /// This is particularly useful for importing from containers-storage where
    /// we already have the file on disk and want to avoid copying data.
    pub fn ensure_object_from_file(
        &self,
        src: &std::fs::File,
        size: u64,
        ctx: &mut ImportContext,
    ) -> Result<(ObjectID, ObjectStoreMethod)> {
        self.ensure_object_from_file_inner(src, size, true, ctx)
    }

    /// Like [`ensure_object_from_file`](Self::ensure_object_from_file) but
    /// errors if neither reflink nor hardlink succeeds, instead of falling back
    /// to a regular copy.
    ///
    /// Intended for bootc's unified storage path where the composefs repo and
    /// containers-storage are always on the same filesystem, so zero-copy
    /// should always be possible.
    pub fn ensure_object_from_file_zerocopy(
        &self,
        src: &std::fs::File,
        size: u64,
        ctx: &mut ImportContext,
    ) -> Result<(ObjectID, ObjectStoreMethod)> {
        self.ensure_object_from_file_inner(src, size, false, ctx)
    }

    /// Inner implementation for [`ensure_object_from_file`](Self::ensure_object_from_file) and
    /// [`ensure_object_from_file_zerocopy`](Self::ensure_object_from_file_zerocopy).
    ///
    /// When `allow_copy` is false, the copy fallback returns an error instead.
    fn ensure_object_from_file_inner(
        &self,
        src: &std::fs::File,
        size: u64,
        allow_copy: bool,
        ctx: &mut ImportContext,
    ) -> Result<(ObjectID, ObjectStoreMethod)> {
        use rustix::fs::{fstat, ioctl_ficlone};

        let writable = self.ensure_writable_token()?;

        // Determine the source and destination device IDs so we can look up
        // whether this particular filesystem pair supports reflinks.
        let src_dev = fstat(src)?.st_dev;
        let dst_dev = fstat(self.objects_dir()?)?.st_dev;

        // Try reflink first, unless a previous call on this device pair
        // already discovered that FICLONE is unsupported.
        if !ctx.is_reflink_unsupported(src_dev, dst_dev) {
            let tmpfile_fd = self.create_object_tmpfile_impl(&writable)?;
            let tmpfile = File::from(tmpfile_fd);

            match ioctl_ficlone(&tmpfile, src) {
                Ok(()) => {
                    // Reflink succeeded — verify size matches
                    let stat = fstat(&tmpfile)?;
                    anyhow::ensure!(
                        stat.st_size as u64 == size,
                        "Reflink size mismatch: expected {}, got {}",
                        size,
                        stat.st_size
                    );

                    let (object_id, method) = self.finalize_object_tmpfile(tmpfile, size)?;
                    let method = match method {
                        ObjectStoreMethod::Copied => ObjectStoreMethod::Reflinked,
                        other => other,
                    };
                    return Ok((object_id, method));
                }
                Err(Errno::OPNOTSUPP | Errno::XDEV) => {
                    // Record for this device pair so subsequent calls skip.
                    ctx.mark_reflink_unsupported(src_dev, dst_dev);
                    drop(tmpfile);
                }
                Err(e) => {
                    return Err(e).context("Reflinking source file to objects directory")?;
                }
            }
        }

        // Try hardlink: enable verity on the source in-place, then link it
        // directly into objects/. This avoids all data copying.
        match self.try_hardlink_object(src, size) {
            Ok(result) => return Ok(result),
            Err(_) if allow_copy => {
                // Hardlink failed, fall through to copy.
                // Common causes: cross-mount (overlay bind mount), EPERM,
                // or verity enablement failure.
            }
            Err(e) => {
                return Err(e).context(
                    "reflink and hardlink both failed; copy fallback is disabled (zerocopy mode)",
                );
            }
        }

        // Final fallback: copy data into a new tmpfile.
        let tmpfile_fd = self.create_object_tmpfile_impl(&writable)?;
        let mut tmpfile = File::from(tmpfile_fd);
        {
            use std::io::{Seek, SeekFrom};
            let mut src_clone = src.try_clone()?;
            src_clone.seek(SeekFrom::Start(0))?;
            std::io::copy(&mut src_clone, &mut tmpfile)?;
        }

        let (object_id, method) = self.finalize_object_tmpfile(tmpfile, size)?;
        Ok((object_id, method))
    }

    /// Try to hardlink a source file directly into the objects directory.
    ///
    /// Enables fs-verity on the source file in-place, measures the digest to
    /// determine the object ID, then hardlinks the source into `objects/<hash>`.
    ///
    /// Returns an error if verity cannot be enabled, the digest cannot be
    /// measured, or the hardlink fails (e.g. cross-device).
    fn try_hardlink_object(
        &self,
        src: &std::fs::File,
        size: u64,
    ) -> Result<(ObjectID, ObjectStoreMethod)> {
        use crate::fsverity::enable_verity_with_retry;

        let objects_dir = self.objects_dir()?;

        // Enable fs-verity on the source file in-place.
        // This is safe because the caller (bootc/containers-storage) owns the
        // source files and they are immutable image data.
        // AlreadyEnabled is fine — the file was already verity-protected.
        let verity_enabled = match enable_verity_with_retry::<ObjectID>(src) {
            Ok(()) => true,
            Err(EnableVerityError::AlreadyEnabled) => true,
            Err(EnableVerityError::FilesystemNotSupported) if self.insecure => false,
            Err(e) => {
                return Err(e).context("enabling verity on source file for hardlink")?;
            }
        };

        // Get the object ID from the verity digest (kernel-measured or userspace-computed)
        let id: ObjectID = if verity_enabled {
            measure_verity(src).context("measuring verity digest on source file")?
        } else {
            // Insecure mode on a filesystem without verity: compute digest in userspace
            let mut reader = std::io::BufReader::new(
                src.try_clone()
                    .context("cloning fd for digest computation")?,
            );
            Self::compute_verity_digest(&mut reader)
                .context("computing verity digest in insecure mode")?
        };

        // Check if object already exists (dedup)
        let path = id.to_object_pathname();
        match statat(objects_dir, &path, AtFlags::empty()) {
            Ok(stat) if stat.st_size as u64 == size => {
                return Ok((id, ObjectStoreMethod::AlreadyPresent));
            }
            _ => {}
        }

        // Ensure parent directory exists (e.g. objects/4e/)
        let parent_dir = id.to_object_dir();
        let _ = mkdirat(objects_dir, &parent_dir, Mode::from_raw_mode(0o755));

        // Hardlink the source file directly into objects/<hash>.
        // Use AT_EMPTY_PATH to link by fd, which avoids the kernel's
        // may_linkat() restriction that rejects AT_SYMLINK_FOLLOW on
        // /proc/self/fd/<N> magic symlinks for non-root mounts.
        // AT_EMPTY_PATH requires CAP_DAC_READ_SEARCH, which is available
        // when running as root (the expected case for containers-storage).
        match linkat(src, "", objects_dir, &path, AtFlags::EMPTY_PATH) {
            Ok(()) => Ok((id, ObjectStoreMethod::Hardlinked)),
            Err(Errno::EXIST) => Ok((id, ObjectStoreMethod::AlreadyPresent)),
            Err(e) => Err(e).context("hardlinking source file into objects directory")?,
        }
    }

    /// Finalize a tmpfile as an object.
    ///
    /// This method should be called from a blocking context (e.g., `spawn_blocking`)
    /// as it performs synchronous I/O operations.
    ///
    /// This method:
    /// 1. Re-opens the file as read-only
    /// 2. Enables fs-verity on the file (kernel computes digest)
    /// 3. Reads the digest from the kernel
    /// 4. Checks if object already exists (deduplication)
    /// 5. Links the file into the objects directory
    ///
    /// By letting the kernel compute the digest during verity enable, we avoid
    /// reading the file an extra time in userspace.
    #[context("Finalizing object tempfile")]
    pub fn finalize_object_tmpfile(
        &self,
        file: File,
        size: u64,
    ) -> Result<(ObjectID, ObjectStoreMethod)> {
        let writable = self.ensure_writable_token()?;
        self.finalize_object_tmpfile_impl(file, size, &writable)
    }

    #[context("Finalizing object tempfile")]
    pub(crate) fn finalize_object_tmpfile_impl(
        &self,
        file: File,
        size: u64,
        _writable: &WritableRepo,
    ) -> Result<(ObjectID, ObjectStoreMethod)> {
        let ro_fd =
            reopen_tmpfile_ro(file).context("Re-opening tmpfile as read-only for verity")?;

        // Get objects_dir early since we may need it for verity copy
        let objects_dir = self
            .objects_dir()
            .context("Getting objects directory for finalization")?;

        // Enable verity - the kernel reads the file and computes the digest.
        // Use enable_verity_maybe_copy to handle the case where forked processes
        // have inherited writable fds to this file.
        let (ro_fd, verity_enabled) =
            match enable_verity_maybe_copy::<ObjectID>(objects_dir, ro_fd.as_fd()) {
                Ok(None) => (ro_fd, true),
                Ok(Some(new_fd)) => (new_fd, true),
                Err(EnableVerityError::FilesystemNotSupported) if self.insecure => (ro_fd, false),
                Err(EnableVerityError::AlreadyEnabled) => (ro_fd, true),
                Err(other) => return Err(other).context("Enabling verity on tmpfile")?,
            };

        // Get the digest - either from kernel (fast) or compute in userspace (fallback)
        let id: ObjectID = if verity_enabled {
            measure_verity(&ro_fd).context("Measuring verity digest")?
        } else {
            // Insecure mode: compute digest in userspace from ro_fd
            let mut reader = std::io::BufReader::new(File::from(
                ro_fd
                    .try_clone()
                    .context("Cloning fd for digest computation")?,
            ));
            Self::compute_verity_digest(&mut reader)
                .context("Computing verity digest in insecure mode")?
        };

        self.link_tmpfile_as_object(objects_dir, &ro_fd, &id, size)
    }

    /// Link a read-only tmpfile into the objects directory with dedup check.
    ///
    /// If an object with the same digest and size already exists, the
    /// tmpfile is discarded and `AlreadyPresent` is returned.
    fn link_tmpfile_as_object(
        &self,
        objects_dir: &OwnedFd,
        ro_fd: &impl AsFd,
        id: &ObjectID,
        size: u64,
    ) -> Result<(ObjectID, ObjectStoreMethod)> {
        let path = id.to_object_pathname();

        match statat(objects_dir, &path, AtFlags::empty()) {
            Ok(stat) if stat.st_size as u64 == size => {
                return Ok((id.clone(), ObjectStoreMethod::AlreadyPresent));
            }
            _ => {}
        }

        let parent_dir = id.to_object_dir();
        let _ = mkdirat(objects_dir, &parent_dir, Mode::from_raw_mode(0o755));

        match linkat(
            CWD,
            proc_self_fd(ro_fd),
            objects_dir,
            &path,
            AtFlags::SYMLINK_FOLLOW,
        ) {
            Ok(()) => Ok((id.clone(), ObjectStoreMethod::Copied)),
            Err(Errno::EXIST) => Ok((id.clone(), ObjectStoreMethod::AlreadyPresent)),
            Err(e) => Err(e).context("Linking tmpfile into objects directory")?,
        }
    }

    /// Compute fs-verity digest in userspace by reading from a buffered source.
    /// Used as fallback when kernel verity is not available (insecure mode).
    #[context("Computing verity digest in userspace")]
    fn compute_verity_digest(reader: &mut impl std::io::BufRead) -> Result<ObjectID> {
        let mut hasher = FsVerityHasher::<ObjectID>::new();

        loop {
            let buf = reader
                .fill_buf()
                .context("Reading buffer for verity computation")?;
            if buf.is_empty() {
                break;
            }
            // add_block expects at most one block at a time
            let chunk_size = buf.len().min(FsVerityHasher::<ObjectID>::BLOCK_SIZE);
            hasher.add_block(&buf[..chunk_size]);
            reader.consume(chunk_size);
        }

        Ok(hasher.digest())
    }

    /// Store an object with a pre-computed fs-verity ID.
    ///
    /// This is an internal helper that stores data assuming the caller has already
    /// computed the correct fs-verity digest. The digest is verified after storage.
    #[context("Storing object with ID {id:?}")]
    fn store_object_with_id(
        &self,
        data: &[u8],
        id: &ObjectID,
        _writable: &WritableRepo,
    ) -> Result<()> {
        let dirfd = self
            .objects_dir()
            .context("Getting objects directory for storage")?;
        let path = id.to_object_pathname();

        // the usual case is that the file will already exist
        match openat(
            dirfd,
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => {
                // measure the existing file to ensure that it's correct
                // TODO: try to replace file if it's broken?
                match ensure_verity_equal(&fd, id) {
                    Ok(()) => {}
                    Err(CompareVerityError::Measure(MeasureVerityError::VerityMissing))
                        if self.insecure =>
                    {
                        match enable_verity_maybe_copy::<ObjectID>(dirfd, fd.as_fd()) {
                            Ok(Some(fd)) => ensure_verity_equal(&fd, id)
                                .context("Verifying verity after enabling (copied)")?,
                            Ok(None) => ensure_verity_equal(&fd, id)
                                .context("Verifying verity after enabling (original)")?,
                            Err(other) => {
                                Err(other).context("Enabling verity on existing object")?
                            }
                        }
                    }
                    Err(CompareVerityError::Measure(
                        MeasureVerityError::FilesystemNotSupported,
                    )) if self.insecure => {}
                    Err(other) => Err(other).context("Verifying existing object integrity")?,
                }
                return Ok(());
            }
            Err(Errno::NOENT) => {
                // in this case we'll create the file
            }
            Err(other) => {
                return Err(other).context("Checking for existing object in repository")?;
            }
        }

        let fd = ensure_dir_and_openat(dirfd, &id.to_object_dir(), OFlags::RDWR | OFlags::TMPFILE)
            .with_context(|| "Creating tempfile in object subdirectory")?;
        let mut file = File::from(fd);
        file.write_all(data).context("Writing data to tmpfile")?;
        // NB: We should do fdatasync() or fsync() here, but doing this for each file forces the
        // creation of a massive number of journal commits and is a performance disaster.  We need
        // to coordinate this at a higher level.  See .write_stream().
        let ro_fd = reopen_tmpfile_ro(file).context("Re-opening file as read-only for verity")?;

        let ro_fd = match enable_verity_maybe_copy::<ObjectID>(dirfd, ro_fd.as_fd()) {
            Ok(maybe_fd) => {
                let ro_fd = maybe_fd.unwrap_or(ro_fd);
                match ensure_verity_equal(&ro_fd, id) {
                    Ok(()) => ro_fd,
                    Err(CompareVerityError::Measure(
                        MeasureVerityError::VerityMissing
                        | MeasureVerityError::FilesystemNotSupported,
                    )) if self.insecure => ro_fd,
                    Err(other) => Err(other).context("Double-checking verity digest")?,
                }
            }
            Err(EnableVerityError::FilesystemNotSupported) if self.insecure => ro_fd,
            Err(other) => Err(other).context("Enabling verity digest")?,
        };

        match linkat(
            CWD,
            proc_self_fd(&ro_fd),
            dirfd,
            path,
            AtFlags::SYMLINK_FOLLOW,
        ) {
            Ok(()) => {}
            Err(Errno::EXIST) => {
                // TODO: strictly, we should measure the newly-appeared file
            }
            Err(other) => {
                return Err(other).context("Linking created object file");
            }
        }

        Ok(())
    }

    /// Given a blob of data, store it in the repository.
    ///
    /// For performance reasons, this function does *not* call fsync() or similar.  After you're
    /// done with everything, call `Repository::sync()`.
    #[context("Ensuring object exists in repository")]
    pub fn ensure_object(&self, data: &[u8]) -> Result<ObjectID> {
        let writable = self.ensure_writable_token()?;
        self.ensure_object_impl(data, &writable)
    }

    /// Like [`ensure_object`] but requires a [`WritableRepo`] token
    /// instead of performing the check itself.
    ///
    /// This exists so that [`SplitStreamWriter`] (which carries a token)
    /// can store objects without redundant `faccessat` calls.
    #[context("Ensuring object exists in repository")]
    pub(crate) fn ensure_object_impl(
        &self,
        data: &[u8],
        writable: &WritableRepo,
    ) -> Result<ObjectID> {
        let id: ObjectID = compute_verity(data);
        self.store_object_with_id(data, &id, writable)?;
        Ok(id)
    }

    #[context("Opening file '{filename}' with verity verification")]
    fn open_with_verity(&self, filename: &str, expected_verity: &ObjectID) -> Result<OwnedFd> {
        let fd = self
            .openat(filename, OFlags::RDONLY)
            .with_context(|| format!("Opening file '{filename}' in repository"))?;
        match ensure_verity_equal(&fd, expected_verity) {
            Ok(()) => {}
            Err(CompareVerityError::Measure(
                MeasureVerityError::VerityMissing | MeasureVerityError::FilesystemNotSupported,
            )) if self.insecure => {}
            Err(other) => Err(other).context("Verifying file verity digest")?,
        }
        Ok(fd)
    }

    /// Returns whether the repository is in insecure mode.
    ///
    /// This is auto-detected from whether `meta.json` has fs-verity
    /// enabled, but can be overridden with [`set_insecure`].
    pub fn is_insecure(&self) -> bool {
        self.insecure
    }

    /// Mark this repository as insecure, disabling verification of
    /// fs-verity digests.  This allows operation on filesystems
    /// without verity support.
    pub fn set_insecure(&mut self) -> &mut Self {
        self.insecure = true;
        self
    }

    /// Require that this repository has fs-verity enabled.
    ///
    /// Returns an error if the repository was not initialized with
    /// verity on `meta.json`, since there is no mechanism to
    /// retroactively enable verity on existing objects.
    pub fn require_verity(&self) -> Result<()> {
        if self.insecure {
            bail!(
                "repository was not initialized with fs-verity \
                 (hint: re-create with `cfsctl init` on a \
                 verity-capable filesystem)"
            );
        }
        Ok(())
    }

    /// Fast pre-flight check that the repository is writable.
    ///
    /// Uses `faccessat(W_OK)` to catch read-only mounts and permission
    /// issues before starting expensive network or I/O work.  Callers
    /// that want to fail early (e.g. before downloading an image) should
    /// call this; individual write methods already check internally.
    pub fn ensure_writable(&self) -> Result<()> {
        self.ensure_writable_token()?;
        Ok(())
    }

    /// Like [`ensure_writable`] but returns a proof token for internal use.
    pub(crate) fn ensure_writable_token(&self) -> Result<WritableRepo> {
        accessat(&self.repository, ".", Access::WRITE_OK, AtFlags::empty())
            .context("Repository is not writable")?;
        Ok(WritableRepo)
    }

    /// Creates a SplitStreamWriter for writing a split stream.
    /// You should write the data to the returned object and then pass it to .store_stream() to
    /// store the result.
    ///
    /// The writable check is performed here so that callers cannot obtain
    /// a writer without first verifying the repository is writable.
    /// The [`WritableRepo`] token is carried by the writer so that
    /// subsequent object writes skip redundant checks.
    pub fn create_stream(
        self: &Arc<Self>,
        content_type: u64,
    ) -> Result<SplitStreamWriter<ObjectID>> {
        let writable = self.ensure_writable_token()?;
        Ok(SplitStreamWriter::new(self, content_type, writable))
    }

    fn format_object_path(id: &ObjectID) -> String {
        format!("objects/{}", id.to_object_pathname())
    }

    fn format_stream_path(content_identifier: &str) -> String {
        format!("streams/{content_identifier}")
    }

    /// Check if the provided splitstream is present in the repository;
    /// if so, return its fsverity digest.
    #[context("Checking if stream '{content_identifier}' exists")]
    pub fn has_stream(&self, content_identifier: &str) -> Result<Option<ObjectID>> {
        let stream_path = Self::format_stream_path(content_identifier);

        match readlinkat(&self.repository, &stream_path, []) {
            Ok(target) => {
                let bytes = target.as_bytes();
                ensure!(
                    bytes.starts_with(b"../"),
                    "stream symlink has incorrect prefix"
                );
                Ok(Some(
                    ObjectID::from_object_pathname(bytes)
                        .context("Parsing object ID from stream symlink target")?,
                ))
            }
            Err(Errno::NOENT) => Ok(None),
            Err(err) => Err(err).context("Reading stream symlink")?,
        }
    }

    /// Write the given splitstream to the repository with the provided content identifier and
    /// optional reference name.
    ///
    /// This call contains an internal barrier that guarantees that, in event of a crash, either:
    ///  - the named stream (by `content_identifier`) will not be available; or
    ///  - the stream and all of its linked data will be available
    ///
    /// In other words: it will not be possible to boot a system which contained a stream named
    /// `content_identifier` but is missing linked streams or objects from that stream.
    #[context("Writing stream '{content_identifier}' to repository")]
    pub fn write_stream(
        &self,
        writer: SplitStreamWriter<ObjectID>,
        content_identifier: &str,
        reference: Option<&str>,
    ) -> Result<ObjectID> {
        let writable = *writer.writable();
        let object_id = writer.done().context("Finalizing split stream writer")?;

        // Right now we have:
        //   - all of the linked external objects and streams; and
        //   - the binary data of this splitstream itself
        //
        // in the filesystem but but not yet guaranteed to be synced to disk.  This is OK because
        // nobody knows that the binary data of the splitstream is a splitstream yet: it could just
        // as well be a random data file contained in an OS image or something.
        //
        // We need to make sure that all of that makes it to the disk before the splitstream is
        // visible as a splitstream.
        self.sync()?;

        let stream_path = Self::format_stream_path(content_identifier);
        let object_path = Self::format_object_path(&object_id);
        self.symlink_impl(&stream_path, &object_path, &writable)?;

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink_impl(&reference_path, &stream_path, &writable)?;
        }

        Ok(object_id)
    }

    /// Register an already-stored object as a named stream.
    ///
    /// This is useful when using `SplitStreamBuilder` which stores the splitstream
    /// directly via `finish()`. After calling `finish()`, call this method to
    /// sync all data to disk and create the stream symlink.
    ///
    /// This method ensures atomicity: the stream symlink is only created after
    /// all objects have been synced to disk.
    #[context("Registering stream '{content_identifier}' with object ID {object_id:?}")]
    pub async fn register_stream(
        self: &Arc<Self>,
        object_id: &ObjectID,
        content_identifier: &str,
        reference: Option<&str>,
    ) -> Result<()> {
        let writable = self.ensure_writable_token()?;
        self.sync_async().await?;

        let stream_path = Self::format_stream_path(content_identifier);
        let object_path = Self::format_object_path(object_id);
        self.symlink_impl(&stream_path, &object_path, &writable)?;

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink_impl(&reference_path, &stream_path, &writable)?;
        }

        Ok(())
    }

    /// Async version of `write_stream` for use with parallel object storage.
    ///
    /// This method awaits any pending parallel object storage tasks before
    /// finalizing the stream. Use this when you've called `write_external_parallel()`
    /// on the writer.
    #[context("Writing stream '{content_identifier}' to repository (async)")]
    pub async fn write_stream_async(
        self: &Arc<Self>,
        writer: SplitStreamWriter<ObjectID>,
        content_identifier: &str,
        reference: Option<&str>,
    ) -> Result<ObjectID> {
        let writable = *writer.writable();
        let object_id = writer
            .done_async()
            .await
            .context("Finalizing split stream writer (async)")?;

        self.sync_async().await?;

        let stream_path = Self::format_stream_path(content_identifier);
        let object_path = Self::format_object_path(&object_id);
        self.symlink_impl(&stream_path, &object_path, &writable)?;

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink_impl(&reference_path, &stream_path, &writable)?;
        }

        Ok(object_id)
    }

    /// Check if a splitstream with a given name exists in the "refs" in the repository.
    #[context("Checking if named stream '{name}' exists")]
    pub fn has_named_stream(&self, name: &str) -> Result<bool> {
        let stream_path = format!("streams/refs/{name}");

        Ok(statat(&self.repository, &stream_path, AtFlags::empty())
            .filter_errno(Errno::NOENT)
            .with_context(|| format!("Looking for stream '{name}' in repository"))?
            .map(|s| FileType::from_raw_mode(s.st_mode).is_symlink())
            .unwrap_or(false))
    }

    /// Assign a named reference to a stream, making it a GC root.
    ///
    /// Creates a symlink at `streams/refs/{name}` pointing to the stream identified
    /// by `content_identifier`. The stream must already exist in the repository.
    ///
    /// Named references serve two purposes:
    /// 1. They provide human-readable names for streams
    /// 2. They act as GC roots - streams reachable from refs are not garbage collected
    ///
    /// The `name` can include path separators to organize refs hierarchically
    /// (e.g., `myapp/layer1`), and intermediate directories are created automatically.
    #[context("Naming stream '{content_identifier}' as '{name}'")]
    pub fn name_stream(&self, content_identifier: &str, name: &str) -> Result<()> {
        let writable = self.ensure_writable_token()?;
        let stream_path = Self::format_stream_path(content_identifier);
        let reference_path = format!("streams/refs/{name}");
        self.symlink_impl(&reference_path, &stream_path, &writable)?;
        Ok(())
    }

    /// Ensures that the stream with a given content identifier digest exists in the repository.
    ///
    /// This tries to find the stream by the content identifier.  If the stream is already in the
    /// repository, the object ID (fs-verity digest) is read from the symlink.  If the stream is
    /// not already in the repository, a `SplitStreamWriter` is created and passed to `callback`.
    /// On return, the object ID of the stream will be calculated and it will be written to disk
    /// (if it wasn't already created by someone else in the meantime).
    ///
    /// In both cases, if `reference` is provided, it is used to provide a fixed name for the
    /// object.  Any object that doesn't have a fixed reference to it is subject to garbage
    /// collection.  It is an error if this reference already exists.
    ///
    /// On success, the object ID of the new object is returned.  It is expected that this object
    /// ID will be used when referring to the stream from other linked streams.
    #[context("Ensuring stream '{content_identifier}' exists")]
    pub fn ensure_stream<T: Default>(
        self: &Arc<Self>,
        content_identifier: &str,
        content_type: u64,
        callback: impl FnOnce(&mut SplitStreamWriter<ObjectID>) -> Result<T>,
        reference: Option<&str>,
    ) -> Result<(ObjectID, T)> {
        let writable = self.ensure_writable_token()?;
        let stream_path = Self::format_stream_path(content_identifier);

        let (object_id, extra) = match self.has_stream(content_identifier)? {
            Some(id) => (id, T::default()),
            None => {
                let mut writer = self.create_stream(content_type)?;
                let extra = callback(&mut writer).context("Writing stream content via callback")?;
                let id = self.write_stream(writer, content_identifier, reference)?;
                (id, extra)
            }
        };

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink_impl(&reference_path, &stream_path, &writable)?;
        }

        Ok((object_id, extra))
    }

    /// Open a splitstream with the given name.
    #[context("Opening stream '{content_identifier}'")]
    pub fn open_stream(
        &self,
        content_identifier: &str,
        verity: Option<&ObjectID>,
        expected_content_type: Option<u64>,
    ) -> Result<SplitStreamReader<ObjectID>> {
        let file = File::from(if let Some(verity_hash) = verity {
            self.open_object(verity_hash)
                .with_context(|| format!("Opening object '{verity_hash:?}'"))?
        } else {
            let filename = Self::format_stream_path(content_identifier);
            self.openat(&filename, OFlags::RDONLY)
                .with_context(|| format!("Opening ref '{filename}'"))?
        });

        SplitStreamReader::new(file, expected_content_type)
    }

    /// Given an object identifier (a digest), return a read-only file descriptor
    /// for its contents. The fsverity digest is verified (if the repository is not in `insecure` mode).
    #[context("Opening object {id:?}")]
    pub fn open_object(&self, id: &ObjectID) -> Result<OwnedFd> {
        self.open_with_verity(&Self::format_object_path(id), id)
    }

    /// Read the contents of an object into a Vec
    #[context("Reading object {id:?} into memory")]
    pub fn read_object(&self, id: &ObjectID) -> Result<Vec<u8>> {
        let mut data = vec![];
        File::from(self.open_object(id)?)
            .read_to_end(&mut data)
            .context("Reading object data")?;
        Ok(data)
    }

    /// Merges a splitstream into a single continuous stream.
    ///
    /// Opens the named splitstream, resolves all object references, and writes
    /// the complete merged content to the provided writer. Optionally verifies
    /// the splitstream's fsverity digest matches the expected value.
    #[context("Merging splitstream '{content_identifier}'")]
    pub fn merge_splitstream(
        &self,
        content_identifier: &str,
        verity: Option<&ObjectID>,
        expected_content_type: Option<u64>,
        output: &mut impl Write,
    ) -> Result<()> {
        let mut split_stream =
            self.open_stream(content_identifier, verity, expected_content_type)?;
        split_stream.cat(self, output)
    }

    /// Write `data into the repository as an image with the given `name`.
    ///
    /// The fsverity digest is returned.
    ///
    /// # Integrity
    ///
    /// This function is not safe for untrusted users.
    #[context("Writing image to repository")]
    pub fn write_image(&self, name: Option<&str>, data: &[u8]) -> Result<ObjectID> {
        let writable = self.ensure_writable_token()?;
        let object_id = self.ensure_object_impl(data, &writable)?;

        let object_path = Self::format_object_path(&object_id);
        let image_path = format!("images/{}", object_id.to_hex());

        self.symlink_impl(&image_path, &object_path, &writable)?;

        if let Some(reference) = name {
            let ref_path = format!("images/refs/{reference}");
            self.symlink_impl(&ref_path, &image_path, &writable)?;
        }

        Ok(object_id)
    }

    /// Import the data from the provided read into the repository as an image.
    ///
    /// The fsverity digest is returned.
    ///
    /// # Integrity
    ///
    /// This function is not safe for untrusted users.
    #[context("Importing image '{name}' from reader")]
    pub fn import_image<R: Read>(&self, name: &str, image: &mut R) -> Result<ObjectID> {
        let mut data = vec![];
        image
            .read_to_end(&mut data)
            .context("Reading image data from input")?;
        self.write_image(Some(name), &data)
    }

    /// Returns the fd of the image and whether or not verity should be
    /// enabled when mounting it.
    #[context("Opening image '{name}'")]
    pub fn open_image(&self, name: &str) -> Result<(OwnedFd, bool)> {
        let image = self
            .openat(&format!("images/{name}"), OFlags::RDONLY)
            .with_context(|| format!("Opening ref 'images/{name}'"))?;

        if name.contains("/") {
            return Ok((image, true));
        }

        // A name with no slashes in it is taken to be a sha256 fs-verity digest
        match measure_verity::<ObjectID>(&image) {
            Ok(found)
                if found
                    == FsVerityHashValue::from_hex(name)
                        .context("Parsing expected verity hash from image name")? =>
            {
                Ok((image, true))
            }
            Ok(_) => bail!("fs-verity content mismatch"),
            Err(MeasureVerityError::VerityMissing | MeasureVerityError::FilesystemNotSupported)
                if self.insecure =>
            {
                Ok((image, false))
            }
            Err(other) => Err(other).context("Measuring image verity digest")?,
        }
    }

    /// Create a detached mount of an image. This file descriptor can then
    /// be attached via e.g. `move_mount`.
    #[context("Mounting image '{name}'")]
    pub fn mount(&self, name: &str) -> Result<OwnedFd> {
        let (image, enable_verity) = self.open_image(name)?;

        composefs_fsmount(
            image,
            name,
            self.objects_dir()
                .context("Getting objects directory for mount")?,
            enable_verity,
        )
        .context("Creating filesystem mount")
    }

    /// Mount the image with the provided digest at the target path.
    #[context("Mounting image '{name}' at path")]
    pub fn mount_at(&self, name: &str, mountpoint: impl AsRef<Path>) -> Result<()> {
        mount_at(
            self.mount(name)?,
            CWD,
            &canonicalize(mountpoint).context("Canonicalizing mountpoint path")?,
        )
        .context("Attaching mount at target path")
    }

    /// Creates a relative symlink within the repository.
    ///
    /// Computes the correct relative path from the symlink location to the target,
    /// creating any necessary intermediate directories. Atomically replaces any
    /// existing symlink at the specified name.
    pub fn symlink(
        &self,
        name: impl AsRef<Path> + std::fmt::Debug,
        target: impl AsRef<Path> + std::fmt::Debug,
    ) -> anyhow::Result<()> {
        let writable = self.ensure_writable_token()?;
        self.symlink_impl(name, target, &writable)
    }

    #[context("Creating symlink from {name:?} to {target:?}")]
    pub(crate) fn symlink_impl(
        &self,
        name: impl AsRef<Path> + std::fmt::Debug,
        target: impl AsRef<Path> + std::fmt::Debug,
        _writable: &WritableRepo,
    ) -> anyhow::Result<()> {
        let name = name.as_ref();

        let mut symlink_components = name.parent().unwrap().components().peekable();
        let mut target_components = target.as_ref().components().peekable();

        let mut symlink_ancestor = PathBuf::new();

        // remove common leading components
        while symlink_components.peek() == target_components.peek() {
            symlink_ancestor.push(symlink_components.next().unwrap());
            target_components.next().unwrap();
        }

        let mut relative = PathBuf::new();
        // prepend a "../" for each ancestor of the symlink
        // and create those ancestors as we do so
        for symlink_component in symlink_components {
            symlink_ancestor.push(symlink_component);
            self.ensure_dir(&symlink_ancestor)?;
            relative.push("..");
        }

        // now build the relative path from the remaining components of the target
        for target_component in target_components {
            relative.push(target_component);
        }

        // Atomically replace existing symlink
        Ok(replace_symlinkat(&relative, &self.repository, name)?)
    }

    #[context("Reading symlink hash value from {name:?}")]
    fn read_symlink_hashvalue(dirfd: &OwnedFd, name: &CStr) -> Result<ObjectID> {
        let link_content = readlinkat(dirfd, name, []).context("Reading symlink target")?;
        ObjectID::from_object_pathname(link_content.to_bytes())
            .context("Parsing object ID from symlink target")
    }

    #[context("Walking symlink directory")]
    fn walk_symlinkdir(fd: OwnedFd, entry_digests: &mut HashSet<OsString>) -> Result<()> {
        for item in Dir::read_from(&fd).context("Reading directory entries")? {
            let entry = item.context("Reading directory entry")?;
            // NB: the underlying filesystem must support returning filetype via direntry
            // that's a reasonable assumption, since it must also support fsverity...
            match entry.file_type() {
                FileType::Directory => {
                    let filename = entry.file_name();
                    if filename != c"." && filename != c".." {
                        let dirfd = openat(
                            &fd,
                            filename,
                            OFlags::RDONLY | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .context("Opening subdirectory for walking")?;
                        Self::walk_symlinkdir(dirfd, entry_digests)?;
                    }
                }
                FileType::Symlink => {
                    let link_content = readlinkat(&fd, entry.file_name(), [])
                        .context("Reading symlink content")?;
                    let linked_path = Path::new(OsStr::from_bytes(link_content.as_bytes()));
                    if let Some(entry_name) = linked_path.file_name() {
                        entry_digests.insert(entry_name.to_os_string());
                    } else {
                        // Does not have a proper file base name (i.e. "..")
                        // TODO: this case needs to be checked in fsck implementation
                        continue;
                    }
                }
                _ => {
                    bail!("Unexpected file type encountered");
                }
            }
        }

        Ok(())
    }

    /// Open the provided path in the repository.
    fn openat(&self, name: &str, flags: OFlags) -> ErrnoResult<OwnedFd> {
        // Unconditionally add CLOEXEC as we always want it.
        openat(
            &self.repository,
            name,
            flags | OFlags::CLOEXEC,
            Mode::empty(),
        )
    }

    // For a GC category (images / streams), return underlying entry digests and
    // object IDs for each entry
    // Under RefsOnly mode, only entries explicitly referenced in `<category>/refs`
    // directory structure would be walked and returned
    // Under AllEntries mode, all entires will be returned
    // Note that this function assumes all`*/refs/` links link to 1st level entries
    // and all 1st level entries link to object store
    // TODO: fsck the above noted assumption
    #[context("Walking GC category '{category}'")]
    fn gc_category(
        &self,
        category: &str,
        mode: GCCategoryWalkMode,
    ) -> Result<Vec<(ObjectID, String)>> {
        let Some(category_fd) = self
            .openat(category, OFlags::RDONLY | OFlags::DIRECTORY)
            .filter_errno(Errno::NOENT)
            .context(format!("Opening {category} dir in repository"))?
        else {
            return Ok(Vec::new());
        };

        let mut entry_digests = HashSet::new();
        match mode {
            GCCategoryWalkMode::RefsOnly => {
                if let Some(refs) = openat(
                    &category_fd,
                    "refs",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .filter_errno(Errno::NOENT)
                .context(format!("Opening {category}/refs dir in repository"))?
                {
                    Self::walk_symlinkdir(refs, &mut entry_digests)
                        .context("Walking refs symlink directory")?;
                }
            }
            GCCategoryWalkMode::AllEntries => {
                // All first-level link entries should be directly object references
                for item in Dir::read_from(&category_fd).context("Reading category directory")? {
                    let entry = item.context("Reading category directory entry")?;
                    let filename = entry.file_name();
                    if filename != c"refs" && filename != c"." && filename != c".." {
                        if entry.file_type() != FileType::Symlink {
                            bail!("category directory contains non-symlink");
                        }
                        entry_digests.insert(OsString::from(&OsStr::from_bytes(
                            entry.file_name().to_bytes(),
                        )));
                    }
                }
            }
        }

        let objects = entry_digests
            .into_iter()
            .map(|entry_fn| {
                Ok((
                    Self::read_symlink_hashvalue(
                        &category_fd,
                        CString::new(entry_fn.as_bytes())
                            .context("Creating CString from filename")?
                            .as_c_str(),
                    )
                    .context("Reading symlink hash value")?,
                    entry_fn
                        .to_str()
                        .context("str conversion fails")?
                        .to_owned(),
                ))
            })
            .collect::<Result<_>>()?;

        Ok(objects)
    }

    // Remove all broken links from a directory, may operate recursively
    /// Remove broken symlinks from a directory.
    /// If `dry_run` is true, counts but does not remove. Returns the count.
    #[context("Cleaning up broken links")]
    fn cleanup_broken_links(fd: &OwnedFd, recursive: bool, dry_run: bool) -> Result<u64> {
        let mut count = 0;
        for item in Dir::read_from(fd).context("Reading directory for broken links cleanup")? {
            let entry = item.context("Reading directory entry for broken links cleanup")?;
            match entry.file_type() {
                FileType::Directory => {
                    if !recursive {
                        continue;
                    }
                    let filename = entry.file_name();
                    if filename != c"." && filename != c".." {
                        let dirfd = openat(
                            fd,
                            filename,
                            OFlags::RDONLY | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .context("Opening subdirectory for recursive broken link cleanup")?;
                        count += Self::cleanup_broken_links(&dirfd, recursive, dry_run)
                            .context("Cleaning up broken links in subdirectory")?;
                    }
                }

                FileType::Symlink => {
                    let filename = entry.file_name();
                    let result = statat(fd, filename, AtFlags::empty())
                        .filter_errno(Errno::NOENT)
                        .context("Testing for broken links")?;
                    if result.is_none() {
                        count += 1;
                        if !dry_run {
                            unlinkat(fd, filename, AtFlags::empty())
                                .context("Unlinking broken symlink")?;
                        }
                    }
                }

                _ => {
                    bail!("Unexpected file type encountered");
                }
            }
        }
        Ok(count)
    }

    /// Clean up broken links in a gc category. Returns count of links removed.
    #[context("Cleaning up broken links in {category} category")]
    fn cleanup_gc_category(&self, category: &'static str, dry_run: bool) -> Result<u64> {
        let Some(category_fd) = self
            .openat(category, OFlags::RDONLY | OFlags::DIRECTORY)
            .filter_errno(Errno::NOENT)
            .context(format!("Opening {category} dir in repository"))?
        else {
            return Ok(0);
        };
        // Always cleanup first-level first, then the refs
        let mut count = Self::cleanup_broken_links(&category_fd, false, dry_run)
            .with_context(|| format!("Cleaning up broken links in {category}/"))?;
        let ref_fd = openat(
            &category_fd,
            "refs",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .filter_errno(Errno::NOENT)
        .context(format!("Opening {category}/refs to clean up broken links"))?;
        if let Some(ref dirfd) = ref_fd {
            count += Self::cleanup_broken_links(dirfd, true, dry_run).with_context(|| {
                format!("Cleaning up broken links recursively in {category}/refs")
            })?;
        }
        Ok(count)
    }

    // Traverse split streams to resolve all linked objects
    #[context("Walking streams starting from '{stream_name}'")]
    fn walk_streams(
        &self,
        stream_name_map: &HashMap<ObjectID, String>,
        stream_name: &str,
        walked_streams: &mut HashSet<String>,
        objects: &mut HashSet<ObjectID>,
    ) -> Result<()> {
        if walked_streams.contains(stream_name) {
            return Ok(());
        }
        walked_streams.insert(stream_name.to_owned());

        let mut split_stream = self
            .open_stream(stream_name, None, None)
            .context("Opening stream for walking")?;
        // Plain object references, add to live objects set
        split_stream
            .get_object_refs(|id| {
                trace!("   with {id:?}");
                objects.insert(id.clone());
            })
            .context("Getting object references from stream")?;
        // Collect all stream names from named references table to be walked next
        let streams_to_walk: Vec<_> = split_stream.iter_named_refs().collect();
        // Note that stream name from the named references table is not stream name in repository
        // In practice repository name is often table name prefixed with stream types (e.g. oci-config-<table name>)
        // Here we always match objectID to be absolutely sure
        for (stream_name_in_table, stream_object_id) in streams_to_walk {
            trace!(
                "   named reference stream {stream_name_in_table} lives, with {stream_object_id:?}"
            );
            objects.insert(stream_object_id.clone());
            if let Some(stream_name_in_repo) = stream_name_map.get(stream_object_id) {
                self.walk_streams(
                    stream_name_map,
                    stream_name_in_repo,
                    walked_streams,
                    objects,
                )
                .context("Walking referenced stream")?;
            } else {
                // stream is in table but not in repo, the repo is potentially broken, issue a warning
                trace!(
                    "broken repo: named reference stream {stream_name_in_table} not found as stream in repo"
                );
            }
        }
        Ok(())
    }

    /// Given an image, return the set of all objects referenced by it.
    #[context("Collecting objects for image '{name}'")]
    pub fn objects_for_image(&self, name: &str) -> Result<HashSet<ObjectID>> {
        let (image, _) = self.open_image(name)?;
        let mut data = vec![];
        std::fs::File::from(image)
            .read_to_end(&mut data)
            .context("Reading image data")?;
        crate::erofs::reader::collect_objects(&data)
            .context("Collecting objects from erofs image data")
    }

    /// Makes sure all content is written to the repository.
    ///
    /// This is currently just syncfs() on the repository's root directory because we don't have
    /// any better options at present.  This blocks until the data is written out.
    #[context("Syncing repository to disk")]
    pub fn sync(&self) -> Result<()> {
        syncfs(&self.repository).context("Syncing filesystem")?;
        Ok(())
    }

    /// Makes sure all content is written to the repository.
    ///
    /// This is currently just syncfs() on the repository's root directory because we don't have
    /// any better options at present.  This won't return until the data is written out.
    #[context("Syncing repository to disk (async)")]
    pub async fn sync_async(self: &Arc<Self>) -> Result<()> {
        let self_ = Arc::clone(self);
        tokio::task::spawn_blocking(move || self_.sync())
            .await
            .context("Spawning blocking sync task")?
    }

    /// Perform garbage collection, removing unreferenced objects.
    ///
    /// Objects reachable from `images/refs/` or `streams/refs/` are preserved,
    /// plus any `additional_roots` (looked up in both images and streams).
    /// Returns statistics about what was removed.
    ///
    /// # Locking
    ///
    /// An exclusive lock is held for the duration of this operation.
    #[context("Running garbage collection")]
    pub fn gc(&self, additional_roots: &[&str]) -> Result<GcResult> {
        self.ensure_writable_token()?;
        flock(&self.repository, FlockOperation::LockExclusive)
            .context("Acquiring exclusive lock for GC")?;
        self.gc_impl(additional_roots, false)
    }

    /// Preview what garbage collection would remove, without deleting.
    ///
    /// Returns the same statistics that [`gc`](Self::gc) would return,
    /// but no files are actually deleted.
    ///
    /// # Locking
    ///
    /// A shared lock is held for the duration of this operation (readers
    /// are not blocked).
    #[context("Running garbage collection dry run")]
    pub fn gc_dry_run(&self, additional_roots: &[&str]) -> Result<GcResult> {
        // Shared lock is sufficient since we don't modify anything
        flock(&self.repository, FlockOperation::LockShared)
            .context("Acquiring shared lock for GC dry run")?;
        self.gc_impl(additional_roots, true)
    }

    /// Internal GC implementation (lock must already be held).
    #[context("GC implementation (dry_run: {dry_run})")]
    fn gc_impl(&self, additional_roots: &[&str], dry_run: bool) -> Result<GcResult> {
        let mut result = GcResult::default();
        let mut live_objects = HashSet::new();

        // Build set of additional roots (checked in both images and streams)
        let extra_roots: HashSet<_> = additional_roots.iter().map(|s| s.to_string()).collect();

        // Collect images: those in images/refs plus caller-specified roots
        let all_images = self
            .gc_category("images", GCCategoryWalkMode::AllEntries)
            .context("Collecting all images")?;
        let root_images: Vec<_> = self
            .gc_category("images", GCCategoryWalkMode::RefsOnly)
            .context("Collecting image refs")?
            .into_iter()
            .chain(
                all_images
                    .into_iter()
                    .filter(|(_, name)| extra_roots.contains(name)),
            )
            .collect();

        for ref image in root_images {
            trace!("{image:?} lives as an image");
            live_objects.insert(image.0.clone());
            self.objects_for_image(&image.1)
                .with_context(|| format!("Collecting objects for image {}", image.1))?
                .iter()
                .for_each(|id| {
                    trace!("   with {id:?}");
                    live_objects.insert(id.clone());
                });
        }

        // Collect all streams for the name map, then filter to roots
        let all_streams = self
            .gc_category("streams", GCCategoryWalkMode::AllEntries)
            .context("Collecting all streams")?;
        let stream_name_map: HashMap<_, _> = all_streams.iter().cloned().collect();
        let root_streams: Vec<_> = self
            .gc_category("streams", GCCategoryWalkMode::RefsOnly)
            .context("Collecting stream refs")?
            .into_iter()
            .chain(
                all_streams
                    .into_iter()
                    .filter(|(_, name)| extra_roots.contains(name)),
            )
            .collect();

        let mut walked_streams = HashSet::new();
        for stream in root_streams {
            trace!("{stream:?} lives as a stream");
            live_objects.insert(stream.0.clone());
            self.walk_streams(
                &stream_name_map,
                &stream.1,
                &mut walked_streams,
                &mut live_objects,
            )
            .with_context(|| format!("Walking stream {}", stream.1))?;
        }

        // Walk all objects and remove unreferenced ones
        for first_byte in 0x0..=0xff {
            let dirfd = match self.openat(
                &format!("objects/{first_byte:02x}"),
                OFlags::RDONLY | OFlags::DIRECTORY,
            ) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => continue,
                Err(e) => Err(e)?,
            };
            for item in Dir::read_from(&dirfd)
                .with_context(|| format!("Reading objects/{first_byte:02x} directory"))?
            {
                let entry = item.context("Reading object directory entry")?;
                let filename = entry.file_name();
                if filename != c"." && filename != c".." {
                    let id =
                        ObjectID::from_object_dir_and_basename(first_byte, filename.to_bytes())
                            .context("Parsing object ID from directory entry")?;
                    if !live_objects.contains(&id) {
                        // Get file size before removing
                        if let Ok(stat) = statat(&dirfd, filename, AtFlags::empty()) {
                            result.objects_bytes += stat.st_size as u64;
                        }
                        result.objects_removed += 1;

                        debug!(
                            "{}: objects/{first_byte:02x}/{filename:?}",
                            if dry_run { "would remove" } else { "removing" },
                        );

                        if !dry_run {
                            unlinkat(&dirfd, filename, AtFlags::empty()).with_context(|| {
                                format!("Unlinking object {first_byte:02x}/{filename:?}")
                            })?;
                        }
                    } else {
                        trace!("objects/{first_byte:02x}/{filename:?} lives");
                    }
                }
            }
        }

        // Clean up broken symlinks
        result.images_pruned = self
            .cleanup_gc_category("images", dry_run)
            .context("Cleaning up broken image symlinks")?;
        result.streams_pruned = self
            .cleanup_gc_category("streams", dry_run)
            .context("Cleaning up broken stream symlinks")?;

        // Downgrade to shared lock if we had exclusive (for actual GC)
        if !dry_run {
            flock(&self.repository, FlockOperation::LockShared)
                .context("Downgrading to shared lock after GC")?;
        }
        Ok(result)
    }

    /// Check the structural integrity of the repository.
    ///
    /// Walks all objects, streams, and images in the repository, verifying:
    /// - Object fsverity digests match their path-derived identifiers
    /// - Stream and image symlinks resolve to existing objects
    /// - Stream/image refs resolve to valid entries
    /// - Splitstreams have valid headers and reference only existing objects
    ///
    /// Object directories are checked in parallel using `spawn_blocking`,
    /// with concurrency bounded by `available_parallelism()`.
    ///
    /// Returns a [`FsckResult`] summarizing the findings. Does not modify
    /// any repository contents.
    #[context("Running filesystem consistency check")]
    pub async fn fsck(&self) -> Result<FsckResult> {
        let mut result = FsckResult::default();

        // Phase 0: Validate meta.json if present
        self.fsck_metadata(&mut result);

        // Phase 1: Verify all objects (parallel across object subdirectories)
        self.fsck_objects(&mut result)
            .await
            .context("Checking objects")?;

        // Phase 2: Verify stream symlinks and splitstream integrity
        self.fsck_category("streams", &mut result)
            .context("Checking streams")?;

        // Phase 3: Verify image symlinks
        self.fsck_category("images", &mut result)
            .context("Checking images")?;

        Ok(result)
    }

    /// Validate `meta.json`.
    ///
    /// Since `open_path` already requires `meta.json` to exist and be
    /// parseable, this re-reads from disk to verify on-disk integrity
    /// and checks algorithm compatibility.
    fn fsck_metadata(&self, result: &mut FsckResult) {
        match read_repo_metadata(&self.repository) {
            Ok(Some(meta)) => {
                result.has_metadata = true;
                if let Err(e) = meta.check_compatible::<ObjectID>() {
                    result.errors.push(FsckError::MetadataAlgorithmMismatch {
                        expected: meta.algorithm.to_string(),
                        actual: ObjectID::ALGORITHM.hash_name().to_string(),
                    });
                    log::warn!("meta.json algorithm mismatch: {e}");
                }
            }
            Ok(None) => {
                // Should not happen since open_path requires meta.json,
                // but report it if the file was removed after open.
                result.errors.push(FsckError::MetadataParseFailed {
                    detail: format!(
                        "{REPO_METADATA_FILENAME} not found; \
                         expected because repository was opened successfully"
                    ),
                });
            }
            Err(e) => {
                result.errors.push(FsckError::MetadataParseFailed {
                    detail: format!("{e:#}"),
                });
            }
        }
    }

    /// Verify all objects in the repository have correct fsverity digests.
    ///
    /// Each `objects/XX/` subdirectory is checked on a blocking thread via
    /// `tokio::task::spawn_blocking`, with bounded concurrency to avoid
    /// overwhelming the system with I/O.
    async fn fsck_objects(&self, result: &mut FsckResult) -> Result<()> {
        // Cap at available CPUs; the work is a mix of I/O (reading objects)
        // and CPU (computing verity hashes).
        let max_concurrent = available_parallelism().map(|n| n.get()).unwrap_or(4);
        let insecure = self.insecure;

        let mut joinset = tokio::task::JoinSet::new();
        let mut partial_results = Vec::new();

        for first_byte in 0x00..=0xffu8 {
            // Drain completed tasks if we're at the concurrency limit
            while joinset.len() >= max_concurrent {
                partial_results.push(joinset.join_next().await.unwrap()??);
            }

            let dirfd = match self.openat(
                &format!("objects/{first_byte:02x}"),
                OFlags::RDONLY | OFlags::DIRECTORY,
            ) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => continue,
                Err(e) => {
                    Err(e).with_context(|| format!("Opening objects/{first_byte:02x} directory"))?
                }
            };

            joinset
                .spawn_blocking(move || fsck_object_dir::<ObjectID>(dirfd, first_byte, insecure));
        }

        // Drain remaining tasks
        while let Some(output) = joinset.join_next().await {
            partial_results.push(output??);
        }

        // Fold all per-directory results into the main result
        for partial in partial_results {
            result.objects_checked += partial.objects_checked;
            result.objects_corrupted += partial.objects_corrupted;
            result.errors.extend(partial.errors);
        }

        Ok(())
    }

    /// Verify symlink integrity and splitstream/image validity for a category
    /// ("streams" or "images").
    #[context("Checking {category} integrity")]
    fn fsck_category(&self, category: &str, result: &mut FsckResult) -> Result<()> {
        let is_streams = category == "streams";

        let Some(category_fd) = self
            .openat(category, OFlags::RDONLY | OFlags::DIRECTORY)
            .filter_errno(Errno::NOENT)
            .with_context(|| format!("Opening {category} directory"))?
        else {
            return Ok(());
        };

        // Check first-level symlinks: each should point to an existing object
        for item in
            Dir::read_from(&category_fd).with_context(|| format!("Reading {category} directory"))?
        {
            let entry = item.context("Reading directory entry")?;
            let filename = entry.file_name();
            if filename == c"." || filename == c".." || filename == c"refs" {
                continue;
            }

            if is_streams {
                result.streams_checked += 1;
            } else {
                result.images_checked += 1;
            }

            if entry.file_type() != FileType::Symlink {
                if is_streams {
                    result.streams_corrupted += 1;
                } else {
                    result.images_corrupted += 1;
                }
                result.errors.push(FsckError::EntryNotSymlink {
                    path: format!(
                        "{category}/{}",
                        String::from_utf8_lossy(filename.to_bytes())
                    ),
                });
                continue;
            }

            // Check the symlink resolves (follows through to the object)
            match statat(&category_fd, filename, AtFlags::empty()) {
                Ok(_) => {}
                Err(Errno::NOENT) => {
                    result.broken_links += 1;
                    if is_streams {
                        result.streams_corrupted += 1;
                    } else {
                        result.images_corrupted += 1;
                    }
                    result.errors.push(FsckError::BrokenSymlink {
                        path: format!(
                            "{category}/{}",
                            String::from_utf8_lossy(filename.to_bytes())
                        ),
                    });
                    continue;
                }
                Err(e) => {
                    result.errors.push(FsckError::StatFailed {
                        path: format!(
                            "{category}/{}",
                            String::from_utf8_lossy(filename.to_bytes())
                        ),
                        detail: e.to_string(),
                    });
                    continue;
                }
            }

            let name = String::from_utf8_lossy(filename.to_bytes()).to_string();
            if is_streams {
                // Validate splitstream contents
                self.fsck_splitstream(&name, result);
            } else {
                // Validate erofs image structure and object references
                self.fsck_image(&name, result);
            }
        }

        // Check refs/ symlinks
        let refs_fd = match openat(
            &category_fd,
            c"refs",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .filter_errno(Errno::NOENT)
        .with_context(|| format!("Opening {category}/refs directory"))?
        {
            Some(fd) => fd,
            None => return Ok(()),
        };

        self.fsck_refs_dir(&refs_fd, category, "", result)
            .with_context(|| format!("Checking {category}/refs"))
    }

    /// Recursively verify that all ref symlinks resolve to valid entries in the
    /// parent category directory.
    fn fsck_refs_dir(
        &self,
        refs_fd: &OwnedFd,
        category: &str,
        prefix: &str,
        result: &mut FsckResult,
    ) -> Result<()> {
        for item in Dir::read_from(refs_fd)
            .with_context(|| format!("Reading {category}/refs/{prefix} directory"))?
        {
            let entry = item.context("Reading refs directory entry")?;
            let filename = entry.file_name();
            if filename == c"." || filename == c".." {
                continue;
            }

            let name = String::from_utf8_lossy(filename.to_bytes()).to_string();
            let display_path = if prefix.is_empty() {
                format!("{category}/refs/{name}")
            } else {
                format!("{category}/refs/{prefix}/{name}")
            };

            match entry.file_type() {
                FileType::Directory => {
                    let subdir = openat(
                        refs_fd,
                        filename,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .with_context(|| format!("Opening {display_path}"))?;
                    let sub_prefix = if prefix.is_empty() {
                        name.clone()
                    } else {
                        format!("{prefix}/{name}")
                    };
                    self.fsck_refs_dir(&subdir, category, &sub_prefix, result)?;
                }
                FileType::Symlink => {
                    // The ref should ultimately resolve to a file (following
                    // the chain: refs/X -> ../../entry -> ../objects/XX/YY)
                    match statat(refs_fd, filename, AtFlags::empty()) {
                        Ok(_) => {}
                        Err(Errno::NOENT) => {
                            result.broken_links += 1;
                            result.errors.push(FsckError::BrokenSymlink {
                                path: display_path.clone(),
                            });
                        }
                        Err(e) => {
                            result.errors.push(FsckError::StatFailed {
                                path: display_path.clone(),
                                detail: e.to_string(),
                            });
                        }
                    }
                }
                other => {
                    result.errors.push(FsckError::UnexpectedFileType {
                        path: display_path.clone(),
                        detail: format!("{other:?}"),
                    });
                }
            }
        }
        Ok(())
    }

    /// Validate a single splitstream: check header and object references.
    fn fsck_splitstream(&self, stream_name: &str, result: &mut FsckResult) {
        let stream_path = format!("streams/{stream_name}");
        let mut split_stream = match self.open_stream(stream_name, None, None) {
            Ok(s) => s,
            Err(e) => {
                result.streams_corrupted += 1;
                result.errors.push(FsckError::StreamOpenFailed {
                    path: stream_path,
                    detail: e.to_string(),
                });
                return;
            }
        };

        // Check that all object_refs point to existing objects
        let check_result = split_stream.get_object_refs(|id| {
            let obj_path = Self::format_object_path(id);
            match self.openat(&obj_path, OFlags::RDONLY) {
                Ok(_) => {}
                Err(Errno::NOENT) => {
                    result.missing_objects += 1;
                    result.errors.push(FsckError::MissingObjectRef {
                        path: stream_path.clone(),
                        object_id: id.to_hex(),
                    });
                }
                Err(e) => {
                    result.errors.push(FsckError::ObjectCheckFailed {
                        path: stream_path.clone(),
                        object_id: id.to_hex(),
                        detail: e.to_string(),
                    });
                }
            }
        });
        if let Err(e) = check_result {
            result.streams_corrupted += 1;
            result.errors.push(FsckError::StreamReadFailed {
                path: stream_path,
                detail: e.to_string(),
            });
            return;
        }

        // Check that all named refs (stream refs) point to existing objects
        for (ref_name, ref_id) in split_stream.iter_named_refs() {
            // The named ref's object should exist
            let obj_path = Self::format_object_path(ref_id);
            match self.openat(&obj_path, OFlags::RDONLY) {
                Ok(_) => {}
                Err(Errno::NOENT) => {
                    result.missing_objects += 1;
                    result.errors.push(FsckError::MissingNamedRef {
                        path: stream_path.clone(),
                        ref_name: ref_name.to_string(),
                        object_id: ref_id.to_hex(),
                    });
                }
                Err(e) => {
                    result.errors.push(FsckError::ObjectCheckFailed {
                        path: stream_path.clone(),
                        object_id: ref_id.to_hex(),
                        detail: format!("checking named ref '{ref_name}': {e}"),
                    });
                }
            }
            // The stream entry itself should also exist (but don't double-count).
            // Note: the named ref name may not correspond to an actual stream
            // entry.  OCI images use named refs with keys like
            // "config:sha256:..." or layer diff_ids that aren't stream names.
            // We only warn if the object itself is missing (handled above);
            // a missing stream entry with an existing object is benign.
        }
    }

    /// Validate a single erofs image: parse structure, enforce composefs
    /// invariants, and verify all referenced objects exist.
    fn fsck_image(&self, image_name: &str, result: &mut FsckResult) {
        // Read the image data
        let image_path = format!("images/{image_name}");
        let mut data = vec![];
        let fd = match self.openat(&image_path, OFlags::RDONLY) {
            Ok(fd) => fd,
            Err(e) => {
                result.images_corrupted += 1;
                result.errors.push(FsckError::ImageOpenFailed {
                    path: image_path,
                    detail: e.to_string(),
                });
                return;
            }
        };
        if let Err(e) = File::from(fd).read_to_end(&mut data) {
            result.images_corrupted += 1;
            result.errors.push(FsckError::ImageReadFailed {
                path: image_path,
                detail: e.to_string(),
            });
            return;
        }

        // Parse the erofs image with composefs-specific structural validation
        // (header magic, superblock, no unsupported features, etc.) and walk
        // the directory tree to collect all referenced object IDs.
        let objects = match crate::erofs::reader::collect_objects::<ObjectID>(&data) {
            Ok(objects) => objects,
            Err(e) => {
                result.images_corrupted += 1;
                result.errors.push(FsckError::ImageInvalid {
                    path: image_path,
                    detail: e.to_string(),
                });
                return;
            }
        };

        // Verify all referenced objects exist
        for obj_id in &objects {
            let path = Self::format_object_path(obj_id);
            match self.openat(&path, OFlags::RDONLY) {
                Ok(_) => {}
                Err(Errno::NOENT) => {
                    result.missing_objects += 1;
                    result.errors.push(FsckError::ImageMissingObject {
                        path: image_path.clone(),
                        object_id: obj_id.to_hex(),
                    });
                }
                Err(e) => {
                    result.errors.push(FsckError::ObjectCheckFailed {
                        path: image_path.clone(),
                        object_id: obj_id.to_hex(),
                        detail: e.to_string(),
                    });
                }
            }
        }
    }

    /// Returns a borrowed file descriptor for the repository root.
    ///
    /// This allows low-level operations on the repository directory.
    pub fn repo_fd(&self) -> BorrowedFd<'_> {
        self.repository.as_fd()
    }

    /// Return the repository metadata parsed from `meta.json` at open time.
    ///
    /// The metadata was already validated against this repository's
    /// `ObjectID` type when the repository was opened, so no further
    /// compatibility check is needed.
    pub fn metadata(&self) -> &RepoMetadata {
        &self.metadata
    }

    /// Lists all named stream references under a given prefix.
    ///
    /// Returns (name, target) pairs where name is relative to the prefix.
    pub fn list_stream_refs(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        let ref_path = format!("streams/refs/{prefix}");

        let dir_fd = match self.openat(&ref_path, OFlags::RDONLY | OFlags::DIRECTORY) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut refs = Vec::new();
        for item in Dir::read_from(&dir_fd)? {
            let entry = item?;
            let name_bytes = entry.file_name().to_bytes();

            if name_bytes == b"." || name_bytes == b".." {
                continue;
            }

            let name = match std::str::from_utf8(name_bytes) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };

            if let Ok(target) = readlinkat(&dir_fd, name_bytes, vec![])
                && let Ok(target_str) = target.into_string()
            {
                refs.push((name, target_str));
            }
        }

        Ok(refs)
    }
}

/// Verify each object in a single `objects/XX/` subdirectory.
///
/// This is a free function (not a method) so it can be used with
/// `spawn_blocking` — it captures only owned/`Send` values.
fn fsck_object_dir<ObjectID: FsVerityHashValue>(
    dirfd: OwnedFd,
    first_byte: u8,
    insecure: bool,
) -> Result<FsckResult> {
    let mut result = FsckResult::default();

    for item in Dir::read_from(&dirfd)
        .with_context(|| format!("Reading objects/{first_byte:02x} directory"))?
    {
        let entry = item.context("Reading object directory entry")?;
        let filename = entry.file_name();
        if filename == c"." || filename == c".." {
            continue;
        }

        result.objects_checked += 1;

        let expected_id =
            match ObjectID::from_object_dir_and_basename(first_byte, filename.to_bytes()) {
                Ok(id) => id,
                Err(e) => {
                    result.objects_corrupted += 1;
                    result.errors.push(FsckError::ObjectInvalidName {
                        path: format!(
                            "objects/{first_byte:02x}/{}",
                            String::from_utf8_lossy(filename.to_bytes())
                        ),
                        detail: e.to_string(),
                    });
                    continue;
                }
            };

        let fd = match openat(
            &dirfd,
            filename,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(e) => {
                result.objects_corrupted += 1;
                result.errors.push(FsckError::ObjectOpenFailed {
                    path: format!(
                        "objects/{first_byte:02x}/{}",
                        String::from_utf8_lossy(filename.to_bytes())
                    ),
                    detail: e.to_string(),
                });
                continue;
            }
        };

        let Some(measured) =
            fsck_measure_object::<ObjectID>(fd, &expected_id, insecure, &mut result)
        else {
            continue;
        };

        if measured != expected_id {
            result.objects_corrupted += 1;
            result.errors.push(FsckError::ObjectDigestMismatch {
                path: format!("objects/{}", expected_id.to_object_pathname()),
                measured: measured.to_hex(),
            });
        }
    }
    Ok(result)
}

/// Measure the verity digest of a single object file.
///
/// Returns `Some(digest)` on success, or `None` after recording the error
/// in `result` (so the caller can `continue`).
fn fsck_measure_object<ObjectID: FsVerityHashValue>(
    fd: OwnedFd,
    expected_id: &ObjectID,
    insecure: bool,
    result: &mut FsckResult,
) -> Option<ObjectID> {
    if let Ok(digest) = measure_verity::<ObjectID>(&fd) {
        return Some(digest);
    }

    // Kernel measurement failed — in insecure mode, try userspace computation
    if insecure {
        match Repository::<ObjectID>::compute_verity_digest(&mut std::io::BufReader::new(
            File::from(fd),
        )) {
            Ok(digest) => return Some(digest),
            Err(e) => {
                result.objects_corrupted += 1;
                result.errors.push(FsckError::ObjectVerityFailed {
                    path: format!("objects/{}", expected_id.to_object_pathname()),
                    detail: e.to_string(),
                });
                return None;
            }
        }
    }

    // Not insecure — verity is required but missing/unsupported
    result.objects_corrupted += 1;
    result.errors.push(FsckError::ObjectVerityMissing {
        path: format!("objects/{}", expected_id.to_object_pathname()),
    });
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsverity::{Sha256HashValue, Sha512HashValue};
    use crate::test::tempdir;
    use rustix::fs::{CWD, statat};
    use tempfile::TempDir;

    /// Create a test repository in insecure mode (no fs-verity required).
    fn create_test_repo(path: &Path) -> Result<Arc<Repository<Sha512HashValue>>> {
        let (repo, _) = Repository::init_path(CWD, path, Algorithm::SHA512, false)?;
        Ok(Arc::new(repo))
    }

    /// Generate deterministic test data of a given size.
    fn generate_test_data(size: u64, seed: u8) -> Vec<u8> {
        (0..size)
            .map(|i| ((i as u8).wrapping_add(seed)).wrapping_mul(17))
            .collect()
    }

    fn read_links_in_repo<P>(tmp: &TempDir, repo_sub_path: P) -> Result<Option<PathBuf>>
    where
        P: AsRef<Path>,
    {
        let full_path = tmp.path().join("repo").join(repo_sub_path);
        match readlinkat(CWD, &full_path, Vec::new()) {
            Ok(result) => Ok(Some(PathBuf::from(result.to_str()?))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // Does not follow symlinks
    fn test_path_exists_in_repo<P>(tmp: &TempDir, repo_sub_path: P) -> Result<bool>
    where
        P: AsRef<Path>,
    {
        let full_path = tmp.path().join("repo").join(repo_sub_path);
        match statat(CWD, &full_path, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn test_object_exists(tmp: &TempDir, obj: &Sha512HashValue) -> Result<bool> {
        let digest = obj.to_hex();
        let (first_two, remainder) = digest.split_at(2);
        test_path_exists_in_repo(tmp, &format!("objects/{first_two}/{remainder}"))
    }

    #[test]
    fn test_gc_removes_one_stream() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj1 = generate_test_data(32 * 1024, 0xAE);
        let obj2 = generate_test_data(64 * 1024, 0xEA);

        let obj1_id = repo.ensure_object(&obj1)?;
        let obj2_id: Sha512HashValue = compute_verity(&obj2);

        let mut writer = repo.create_stream(0)?;
        writer.write_external(&obj2)?;
        let _stream_id = repo.write_stream(writer, "test-stream", None)?;

        repo.sync()?;

        assert!(test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);

        // Now perform gc - should remove 2 objects (obj1 + obj2) and 1 stream symlink
        let result = repo.gc(&[])?;

        assert!(!test_object_exists(&tmp, &obj1_id)?);
        assert!(!test_object_exists(&tmp, &obj2_id)?);
        assert!(!test_path_exists_in_repo(&tmp, "streams/test-stream")?);

        // Verify GcResult: 3 objects removed (obj1, obj2, splitstream), stream symlink pruned
        assert_eq!(result.objects_removed, 3);
        assert!(result.objects_bytes > 0);
        assert_eq!(result.streams_pruned, 1);
        assert_eq!(result.images_pruned, 0);
        Ok(())
    }

    #[test]
    fn test_gc_keeps_one_stream() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj1 = generate_test_data(32 * 1024, 0xAE);
        let obj2 = generate_test_data(64 * 1024, 0xEA);

        let obj1_id = repo.ensure_object(&obj1)?;
        let obj2_id: Sha512HashValue = compute_verity(&obj2);

        let mut writer = repo.create_stream(0)?;
        writer.write_external(&obj2)?;
        let _stream_id = repo.write_stream(writer, "test-stream", None)?;

        repo.sync()?;

        assert!(test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);

        // Now perform gc - should remove only obj1, keep obj2 and stream
        let result = repo.gc(&["test-stream"])?;

        assert!(!test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);

        // Verify GcResult: only 1 object removed, no symlinks pruned
        assert_eq!(result.objects_removed, 1);
        assert!(result.objects_bytes > 0);
        assert_eq!(result.streams_pruned, 0);
        assert_eq!(result.images_pruned, 0);
        Ok(())
    }

    #[test]
    fn test_gc_keeps_one_stream_from_refs() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj1 = generate_test_data(32 * 1024, 0xAE);
        let obj2 = generate_test_data(64 * 1024, 0xEA);

        let obj1_id = repo.ensure_object(&obj1)?;
        let obj2_id: Sha512HashValue = compute_verity(&obj2);

        let mut writer = repo.create_stream(0)?;
        writer.write_external(&obj2)?;
        let _stream_id = repo.write_stream(writer, "test-stream", Some("ref-name"))?;

        repo.sync()?;

        assert!(test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);

        // Now perform gc - stream is kept via ref, only obj1 removed
        let result = repo.gc(&[])?;

        assert!(!test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);

        // Verify GcResult: 1 object removed, no symlinks pruned (stream has ref)
        assert_eq!(result.objects_removed, 1);
        assert!(result.objects_bytes > 0);
        assert_eq!(result.streams_pruned, 0);
        assert_eq!(result.images_pruned, 0);
        Ok(())
    }

    #[test]
    fn test_gc_keeps_one_stream_from_two_overlapped() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj1 = generate_test_data(32 * 1024, 0xAE);
        let obj2 = generate_test_data(64 * 1024, 0xEA);
        let obj3 = generate_test_data(64 * 1024, 0xAA);
        let obj4 = generate_test_data(64 * 1024, 0xEE);

        let obj1_id = repo.ensure_object(&obj1)?;
        let obj2_id: Sha512HashValue = compute_verity(&obj2);
        let obj3_id: Sha512HashValue = compute_verity(&obj3);
        let obj4_id: Sha512HashValue = compute_verity(&obj4);

        let mut writer1 = repo.create_stream(0)?;
        writer1.write_external(&obj2)?;
        writer1.write_external(&obj3)?;
        let _stream1_id = repo.write_stream(writer1, "test-stream1", None)?;

        let mut writer2 = repo.create_stream(0)?;
        writer2.write_external(&obj2)?;
        writer2.write_external(&obj4)?;
        let _stream2_id = repo.write_stream(writer2, "test-stream2", None)?;

        repo.sync()?;

        assert!(test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_object_exists(&tmp, &obj3_id)?);
        assert!(test_object_exists(&tmp, &obj4_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream1")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream1")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream2")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream2")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);

        // Now perform gc - keep stream1, remove obj1, obj4, and stream2
        let result = repo.gc(&["test-stream1"])?;

        assert!(!test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_object_exists(&tmp, &obj3_id)?);
        assert!(!test_object_exists(&tmp, &obj4_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream1")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream1")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(!test_path_exists_in_repo(&tmp, "streams/test-stream2")?);

        // Verify GcResult: 3 objects removed (obj1, obj4, stream2's splitstream), 1 stream pruned
        assert_eq!(result.objects_removed, 3);
        assert!(result.objects_bytes > 0);
        assert_eq!(result.streams_pruned, 1);
        assert_eq!(result.images_pruned, 0);
        Ok(())
    }

    #[test]
    fn test_gc_keeps_named_references() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj1 = generate_test_data(32 * 1024, 0xAE);
        let obj2 = generate_test_data(64 * 1024, 0xEA);

        let obj1_id = repo.ensure_object(&obj1)?;
        let obj2_id: Sha512HashValue = compute_verity(&obj2);

        let mut writer1 = repo.create_stream(0)?;
        writer1.write_external(&obj2)?;
        let stream1_id = repo.write_stream(writer1, "test-stream1", None)?;

        let mut writer2 = repo.create_stream(0)?;
        writer2.add_named_stream_ref("test-stream1", &stream1_id);
        let _stream2_id = repo.write_stream(writer2, "test-stream2", None)?;

        repo.sync()?;

        assert!(test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream1")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream1")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream2")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream2")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);

        // Now perform gc - stream2 refs stream1, both kept, only obj1 removed
        let result = repo.gc(&["test-stream2"])?;

        assert!(!test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream1")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream1")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream2")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream2")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);

        // Verify GcResult: 1 object removed, no symlinks pruned
        assert_eq!(result.objects_removed, 1);
        assert!(result.objects_bytes > 0);
        assert_eq!(result.streams_pruned, 0);
        assert_eq!(result.images_pruned, 0);
        Ok(())
    }

    #[test]
    fn test_gc_keeps_named_references_with_different_table_name() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj1 = generate_test_data(32 * 1024, 0xAE);
        let obj2 = generate_test_data(64 * 1024, 0xEA);

        let obj1_id = repo.ensure_object(&obj1)?;
        let obj2_id: Sha512HashValue = compute_verity(&obj2);

        let mut writer1 = repo.create_stream(0)?;
        writer1.write_external(&obj2)?;
        let stream1_id = repo.write_stream(writer1, "test-stream1", None)?;

        let mut writer2 = repo.create_stream(0)?;
        writer2.add_named_stream_ref("different-table-name-for-test-stream1", &stream1_id);
        let _stream2_id = repo.write_stream(writer2, "test-stream2", None)?;

        repo.sync()?;

        assert!(test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream1")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream1")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream2")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream2")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);

        // Now perform gc - different table name, but same object ID links them
        let result = repo.gc(&["test-stream2"])?;

        assert!(!test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream1")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream1")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream2")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream2")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);

        // Verify GcResult: 1 object removed, no symlinks pruned
        assert_eq!(result.objects_removed, 1);
        assert!(result.objects_bytes > 0);
        assert_eq!(result.streams_pruned, 0);
        assert_eq!(result.images_pruned, 0);
        Ok(())
    }

    #[test]
    fn test_gc_keeps_one_named_reference_from_two_overlapped() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj1 = generate_test_data(32 * 1024, 0xAE);
        let obj2 = generate_test_data(64 * 1024, 0xEA);
        let obj3 = generate_test_data(64 * 1024, 0xAA);
        let obj4 = generate_test_data(64 * 1024, 0xEE);

        let obj1_id = repo.ensure_object(&obj1)?;
        let obj2_id: Sha512HashValue = compute_verity(&obj2);
        let obj3_id: Sha512HashValue = compute_verity(&obj3);
        let obj4_id: Sha512HashValue = compute_verity(&obj4);

        let mut writer = repo.create_stream(0)?;
        writer.write_external(&obj2)?;
        let stream1_id = repo.write_stream(writer, "test-stream1", None)?;

        let mut writer = repo.create_stream(0)?;
        writer.write_external(&obj3)?;
        let stream2_id = repo.write_stream(writer, "test-stream2", None)?;

        let mut writer = repo.create_stream(0)?;
        writer.write_external(&obj4)?;
        let stream3_id = repo.write_stream(writer, "test-stream3", None)?;

        let mut writer = repo.create_stream(0)?;
        writer.add_named_stream_ref("test-stream1", &stream1_id);
        writer.add_named_stream_ref("test-stream2", &stream2_id);
        let _ref_stream1_id = repo.write_stream(writer, "ref-stream1", None)?;

        let mut writer = repo.create_stream(0)?;
        writer.add_named_stream_ref("test-stream1", &stream1_id);
        writer.add_named_stream_ref("test-stream3", &stream3_id);
        let _ref_stream2_id = repo.write_stream(writer, "ref-stream2", None)?;

        repo.sync()?;

        assert!(test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_object_exists(&tmp, &obj3_id)?);
        assert!(test_object_exists(&tmp, &obj4_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream1")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream1")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream2")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream2")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream3")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream3")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(test_path_exists_in_repo(&tmp, "streams/ref-stream1")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/ref-stream1")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(test_path_exists_in_repo(&tmp, "streams/ref-stream2")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/ref-stream2")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);

        // Now perform gc - ref-stream1 refs stream1+stream2, so keep those and their objects
        let result = repo.gc(&["ref-stream1"])?;

        assert!(!test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_object_exists(&tmp, &obj3_id)?);
        assert!(!test_object_exists(&tmp, &obj4_id)?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream1")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream1")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(test_path_exists_in_repo(&tmp, "streams/test-stream2")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/test-stream2")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(!test_path_exists_in_repo(&tmp, "streams/test-stream3")?);
        assert!(test_path_exists_in_repo(&tmp, "streams/ref-stream1")?);
        let link_target =
            read_links_in_repo(&tmp, "streams/ref-stream1")?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("streams").join(&link_target)
        )?);
        assert!(!test_path_exists_in_repo(&tmp, "streams/ref-stream2")?);

        // Verify GcResult: objects removed include obj1, obj4, plus splitstreams for stream3 and ref-stream2
        assert_eq!(result.objects_removed, 4);
        assert!(result.objects_bytes > 0);
        assert_eq!(result.streams_pruned, 2);
        assert_eq!(result.images_pruned, 0);

        Ok(())
    }

    use crate::tree::{FileSystem, Inode, LeafContent, RegularFile, Stat};

    /// Create a default root stat for test filesystems
    fn test_root_stat() -> Stat {
        Stat {
            st_mode: 0o755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 0,
            xattrs: Default::default(),
        }
    }

    /// Make a test in-memory filesystem that only contains one externally referenced object
    fn make_test_fs(obj: &Sha512HashValue, size: u64) -> FileSystem<Sha512HashValue> {
        let mut fs: FileSystem<Sha512HashValue> = FileSystem::new(test_root_stat());
        let leaf_id = fs.push_leaf(
            Stat {
                st_mode: 0o644,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                xattrs: Default::default(),
            },
            LeafContent::Regular(RegularFile::External(obj.clone(), size)),
        );
        let inode = Inode::leaf(leaf_id);
        fs.root.insert(OsStr::new("data"), inode);
        fs
    }

    #[test]
    fn test_gc_removes_one_image() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj1_size: u64 = 32 * 1024;
        let obj1 = generate_test_data(obj1_size, 0xAE);
        let obj2_size: u64 = 64 * 1024;
        let obj2 = generate_test_data(obj2_size, 0xEA);

        let obj1_id = repo.ensure_object(&obj1)?;
        let obj2_id = repo.ensure_object(&obj2)?;

        let fs = make_test_fs(&obj2_id, obj2_size);
        let image1 = fs.commit_image(&repo, None)?;
        let image1_path = format!("images/{}", image1.to_hex());

        repo.sync()?;

        assert!(test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, &image1_path)?);
        let link_target = read_links_in_repo(&tmp, &image1_path)?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("images").join(&link_target)
        )?);

        // Now perform gc - no refs, so image and both objects removed
        let result = repo.gc(&[])?;

        assert!(!test_object_exists(&tmp, &obj1_id)?);
        assert!(!test_object_exists(&tmp, &obj2_id)?);
        assert!(!test_path_exists_in_repo(&tmp, &image1_path)?);

        // Verify GcResult: 3 objects removed (obj1, obj2, image erofs), 1 image pruned
        assert_eq!(result.objects_removed, 3);
        assert!(result.objects_bytes > 0);
        assert_eq!(result.images_pruned, 1);
        assert_eq!(result.streams_pruned, 0);
        Ok(())
    }

    #[test]
    fn test_gc_keeps_one_image() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj1_size: u64 = 32 * 1024;
        let obj1 = generate_test_data(obj1_size, 0xAE);
        let obj2_size: u64 = 64 * 1024;
        let obj2 = generate_test_data(obj2_size, 0xEA);

        let obj1_id = repo.ensure_object(&obj1)?;
        let obj2_id = repo.ensure_object(&obj2)?;

        let fs = make_test_fs(&obj2_id, obj2_size);
        let image1 = fs.commit_image(&repo, None)?;
        let image1_path = format!("images/{}", image1.to_hex());

        repo.sync()?;

        assert!(test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, &image1_path)?);
        let link_target = read_links_in_repo(&tmp, &image1_path)?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("images").join(&link_target)
        )?);

        // Now perform gc - keep image via additional_roots
        let image1_hex = image1.to_hex();
        let result = repo.gc(&[image1_hex.as_str()])?;

        assert!(!test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, &image1_path)?);
        let link_target = read_links_in_repo(&tmp, &image1_path)?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("images").join(&link_target)
        )?);

        // Verify GcResult: 1 object removed (obj1), no symlinks pruned
        assert_eq!(result.objects_removed, 1);
        assert!(result.objects_bytes > 0);
        assert_eq!(result.images_pruned, 0);
        assert_eq!(result.streams_pruned, 0);
        Ok(())
    }

    #[test]
    fn test_gc_keeps_one_image_from_refs() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj1_size: u64 = 32 * 1024;
        let obj1 = generate_test_data(obj1_size, 0xAE);
        let obj2_size: u64 = 64 * 1024;
        let obj2 = generate_test_data(obj2_size, 0xEA);

        let obj1_id = repo.ensure_object(&obj1)?;
        let obj2_id = repo.ensure_object(&obj2)?;

        let fs = make_test_fs(&obj2_id, obj2_size);
        let image1 = fs.commit_image(&repo, Some("ref-name"))?;
        let image1_path = format!("images/{}", image1.to_hex());

        repo.sync()?;

        assert!(test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, &image1_path)?);
        let link_target = read_links_in_repo(&tmp, &image1_path)?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("images").join(&link_target)
        )?);

        // Now perform gc - image kept via ref, only obj1 removed
        let result = repo.gc(&[])?;

        assert!(!test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_path_exists_in_repo(&tmp, &image1_path)?);
        let link_target = read_links_in_repo(&tmp, &image1_path)?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("images").join(&link_target)
        )?);

        // Verify GcResult: 1 object removed, no symlinks pruned (image has ref)
        assert_eq!(result.objects_removed, 1);
        assert!(result.objects_bytes > 0);
        assert_eq!(result.images_pruned, 0);
        assert_eq!(result.streams_pruned, 0);
        Ok(())
    }

    fn make_test_fs_with_two_files(
        obj1: &Sha512HashValue,
        size1: u64,
        obj2: &Sha512HashValue,
        size2: u64,
    ) -> FileSystem<Sha512HashValue> {
        let mut fs = make_test_fs(obj1, size1);
        let leaf_id = fs.push_leaf(
            Stat {
                st_mode: 0o644,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                xattrs: Default::default(),
            },
            LeafContent::Regular(RegularFile::External(obj2.clone(), size2)),
        );
        let inode = Inode::leaf(leaf_id);
        fs.root.insert(OsStr::new("extra_data"), inode);
        fs
    }

    #[test]
    fn test_gc_keeps_one_image_from_two_overlapped() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj1_size: u64 = 32 * 1024;
        let obj1 = generate_test_data(obj1_size, 0xAE);
        let obj2_size: u64 = 64 * 1024;
        let obj2 = generate_test_data(obj2_size, 0xEA);
        let obj3_size: u64 = 64 * 1024;
        let obj3 = generate_test_data(obj2_size, 0xAA);
        let obj4_size: u64 = 64 * 1024;
        let obj4 = generate_test_data(obj2_size, 0xEE);

        let obj1_id = repo.ensure_object(&obj1)?;
        let obj2_id = repo.ensure_object(&obj2)?;
        let obj3_id = repo.ensure_object(&obj3)?;
        let obj4_id = repo.ensure_object(&obj4)?;

        let fs = make_test_fs_with_two_files(&obj2_id, obj2_size, &obj3_id, obj3_size);
        let image1 = fs.commit_image(&repo, None)?;
        let image1_path = format!("images/{}", image1.to_hex());

        let fs = make_test_fs_with_two_files(&obj2_id, obj2_size, &obj4_id, obj4_size);
        let image2 = fs.commit_image(&repo, None)?;
        let image2_path = format!("images/{}", image2.to_hex());

        repo.sync()?;

        assert!(test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_object_exists(&tmp, &obj3_id)?);
        assert!(test_object_exists(&tmp, &obj4_id)?);
        assert!(test_path_exists_in_repo(&tmp, &image1_path)?);
        let link_target = read_links_in_repo(&tmp, &image1_path)?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("images").join(&link_target)
        )?);
        assert!(test_path_exists_in_repo(&tmp, &image2_path)?);
        let link_target = read_links_in_repo(&tmp, &image2_path)?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("images").join(&link_target)
        )?);

        // Now perform gc - keep image1, remove image2 and its unique objects
        let image1_hex = image1.to_hex();
        let result = repo.gc(&[image1_hex.as_str()])?;

        assert!(!test_object_exists(&tmp, &obj1_id)?);
        assert!(test_object_exists(&tmp, &obj2_id)?);
        assert!(test_object_exists(&tmp, &obj3_id)?);
        assert!(!test_object_exists(&tmp, &obj4_id)?);
        assert!(test_path_exists_in_repo(&tmp, &image1_path)?);
        let link_target = read_links_in_repo(&tmp, &image1_path)?.expect("link is not broken");
        assert!(test_path_exists_in_repo(
            &tmp,
            PathBuf::from("images").join(&link_target)
        )?);
        assert!(!test_path_exists_in_repo(&tmp, &image2_path)?);

        // Verify GcResult: 3 objects removed (obj1, obj4, image2 erofs), 1 image pruned
        assert_eq!(result.objects_removed, 3);
        assert!(result.objects_bytes > 0);
        assert_eq!(result.images_pruned, 1);
        assert_eq!(result.streams_pruned, 0);
        Ok(())
    }

    #[test]
    fn test_ensure_object_from_file() -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};

        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;
        let mut ctx = ImportContext::default();

        let test_data = generate_test_data(64 * 1024, 0xBE);
        let mut temp_file = crate::test::tempfile();
        temp_file.write_all(&test_data)?;
        temp_file.seek(SeekFrom::Start(0))?;

        // First store should return Copied or Reflinked (depending on fs)
        let (object_id, method) =
            repo.ensure_object_from_file(&temp_file, test_data.len() as u64, &mut ctx)?;
        assert_ne!(method, ObjectStoreMethod::AlreadyPresent);
        assert!(test_object_exists(&tmp, &object_id)?);

        // Read back and verify contents match
        let stored_data = repo.read_object(&object_id)?;
        assert_eq!(stored_data, test_data);

        // Second store of same data should return AlreadyPresent
        temp_file.seek(SeekFrom::Start(0))?;
        let (object_id_2, method_2) =
            repo.ensure_object_from_file(&temp_file, test_data.len() as u64, &mut ctx)?;
        assert_eq!(object_id, object_id_2);
        assert_eq!(method_2, ObjectStoreMethod::AlreadyPresent);

        Ok(())
    }

    // ==================== Fsck Tests ====================

    #[tokio::test]
    async fn test_fsck_empty_repo() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let result = repo.fsck().await?;

        assert!(result.is_ok());
        assert_eq!(result.objects_checked, 0);
        assert_eq!(result.objects_corrupted, 0);
        assert_eq!(result.streams_checked, 0);
        assert_eq!(result.streams_corrupted, 0);
        assert_eq!(result.images_checked, 0);
        assert_eq!(result.images_corrupted, 0);
        assert_eq!(result.broken_links, 0);
        assert_eq!(result.missing_objects, 0);
        assert!(result.errors.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_healthy_repo_with_objects() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj1 = generate_test_data(32 * 1024, 0xAE);
        let obj2 = generate_test_data(64 * 1024, 0xEA);

        let _obj1_id = repo.ensure_object(&obj1)?;
        let _obj2_id: Sha512HashValue = compute_verity(&obj2);

        let mut writer = repo.create_stream(0)?;
        writer.write_external(&obj2)?;
        let _stream_id = repo.write_stream(writer, "test-stream", None)?;
        repo.sync()?;

        let result = repo.fsck().await?;

        assert!(result.is_ok(), "fsck should pass: {result}");
        // 3 objects: obj1, obj2, and the splitstream object
        assert!(result.objects_checked >= 3);
        assert_eq!(result.objects_corrupted, 0);
        assert_eq!(result.streams_checked, 1);
        assert_eq!(result.streams_corrupted, 0);
        assert_eq!(result.broken_links, 0);
        assert_eq!(result.missing_objects, 0);
        assert!(result.errors.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_detects_corrupted_object() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj = generate_test_data(32 * 1024, 0xAE);
        let obj_id = repo.ensure_object(&obj)?;
        repo.sync()?;

        // Corrupt the object by replacing the file (objects may be
        // immutable due to fs-verity, so we delete and recreate).
        let hex = obj_id.to_hex();
        let (dir, file) = hex.split_at(2);
        let obj_path = tmp
            .path()
            .join("repo")
            .join(format!("objects/{dir}/{file}"));
        std::fs::remove_file(&obj_path)?;
        std::fs::write(&obj_path, b"corrupted data")?;

        let result = repo.fsck().await?;

        assert!(!result.is_ok(), "fsck should detect corruption");
        assert!(
            result.objects_corrupted > 0,
            "should report corrupted objects"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_string().contains("object-digest-mismatch")),
            "errors should mention digest mismatch: {:?}",
            result.errors
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_detects_broken_stream_link() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj = generate_test_data(64 * 1024, 0xEA);
        let _obj_verity: Sha512HashValue = compute_verity(&obj);

        let mut writer = repo.create_stream(0)?;
        writer.write_external(&obj)?;
        let _stream_id = repo.write_stream(writer, "test-stream", None)?;
        repo.sync()?;

        // The stream symlink points to a splitstream object. Find and
        // read the symlink target, then delete the backing object.
        let stream_symlink = tmp.path().join("repo/streams/test-stream");
        let link_target = std::fs::read_link(&stream_symlink)?;
        // link_target is relative to streams/, e.g. "../objects/XX/YY..."
        let backing_path = tmp.path().join("repo/streams").join(&link_target);
        std::fs::remove_file(&backing_path)?;

        let result = repo.fsck().await?;

        assert!(!result.is_ok(), "fsck should detect broken link");
        assert!(
            result.broken_links > 0,
            "should report broken links: {result}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_detects_missing_stream_object_ref() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj = generate_test_data(64 * 1024, 0xEA);
        let obj_verity: Sha512HashValue = compute_verity(&obj);

        // Create a stream with an external reference to the object.
        // write_external calls ensure_object internally, so the object
        // will exist.
        let mut writer = repo.create_stream(0)?;
        writer.write_external(&obj)?;
        let _stream_id = repo.write_stream(writer, "test-stream", None)?;
        repo.sync()?;

        // Delete the referenced object (but leave the splitstream intact)
        let hex = obj_verity.to_hex();
        let (dir, file) = hex.split_at(2);
        let obj_path = tmp
            .path()
            .join("repo")
            .join(format!("objects/{dir}/{file}"));
        std::fs::remove_file(&obj_path)?;

        let result = repo.fsck().await?;

        assert!(!result.is_ok(), "fsck should detect missing object ref");
        assert!(
            result.missing_objects > 0,
            "should report missing objects: {result}"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_string().contains("missing-object-ref")),
            "errors should mention missing object: {:?}",
            result.errors
        );
        Ok(())
    }

    // ==================== Additional Fsck Gap Tests ====================

    fn open_test_repo_dir(tmp: &tempfile::TempDir) -> cap_std::fs::Dir {
        cap_std::fs::Dir::open_ambient_dir(tmp.path().join("repo"), cap_std::ambient_authority())
            .unwrap()
    }

    #[tokio::test]
    async fn test_fsck_detects_non_symlink_in_streams() -> Result<()> {
        // Exercises fsck_category non-symlink detection (line ~1695).
        // The code checks entry.file_type() != FileType::Symlink and reports
        // "not a symlink" for regular files or directories in streams/.
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;
        repo.sync()?;

        // Create a regular file directly in streams/ (not a symlink)
        let dir = open_test_repo_dir(&tmp);
        dir.create_dir_all("streams")?;
        dir.write("streams/bogus-entry", b"not a symlink")?;

        let result = repo.fsck().await?;

        assert!(!result.is_ok(), "fsck should detect non-symlink in streams");
        assert_eq!(result.streams_corrupted, 1);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_string().contains("entry-not-symlink")),
            "errors should mention non-symlink: {:?}",
            result.errors
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_detects_non_symlink_in_images() -> Result<()> {
        // Exercises fsck_category non-symlink detection for the "images"
        // category (same code path as streams, but counting images_corrupted).
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;
        repo.sync()?;

        let dir = open_test_repo_dir(&tmp);
        dir.create_dir_all("images")?;
        dir.write("images/bogus-image", b"not a symlink")?;

        let result = repo.fsck().await?;

        assert!(!result.is_ok(), "fsck should detect non-symlink in images");
        assert_eq!(result.images_corrupted, 1);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_string().contains("entry-not-symlink")),
            "errors should mention non-symlink: {:?}",
            result.errors
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_detects_broken_ref_symlink() -> Result<()> {
        // Exercises fsck_refs_dir broken symlink detection (line ~1804).
        // Creates a ref symlink that points to a non-existent stream entry,
        // so following the chain refs/X -> ../../stream-entry -> object fails.
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;
        repo.sync()?;

        // Create refs directory under streams
        let dir = open_test_repo_dir(&tmp);
        dir.create_dir_all("streams/refs")?;

        // Create a dangling symlink in refs/
        dir.symlink("../nonexistent-stream", "streams/refs/broken-ref")?;

        let result = repo.fsck().await?;

        assert!(!result.is_ok(), "fsck should detect broken ref symlink");
        assert!(result.broken_links > 0, "should report broken links");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_string().contains("broken-symlink")
                    && e.to_string().contains("refs")),
            "errors should mention broken ref symlink: {:?}",
            result.errors
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_refs_dir_unexpected_file_type() -> Result<()> {
        // Exercises the "unexpected file type" branch in fsck_refs_dir
        // (line ~1817). Regular files in refs/ are neither symlinks nor
        // directories — they should be flagged.
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;
        repo.sync()?;

        let dir = open_test_repo_dir(&tmp);
        dir.create_dir_all("streams/refs")?;

        // Put a regular file directly in refs/
        dir.write("streams/refs/stray-file", b"should not be here")?;

        let result = repo.fsck().await?;

        assert!(!result.is_ok(), "fsck should detect unexpected file type");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_string().contains("unexpected-file-type")),
            "errors should mention unexpected file type: {:?}",
            result.errors
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_refs_dir_recursive() -> Result<()> {
        // Exercises the recursive walk in fsck_refs_dir: creates a nested
        // subdirectory under refs/ with a broken symlink inside to verify
        // the recursion actually descends into subdirs.
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;
        repo.sync()?;

        let dir = open_test_repo_dir(&tmp);
        dir.create_dir_all("streams/refs/nested/deep")?;

        // Broken symlink in the nested directory
        dir.symlink(
            "../../../nonexistent-stream",
            "streams/refs/nested/deep/broken-nested-ref",
        )?;

        let result = repo.fsck().await?;

        assert!(
            !result.is_ok(),
            "fsck should detect broken symlink in nested refs"
        );
        assert!(result.broken_links > 0);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_string().contains("nested/deep")
                    && e.to_string().contains("broken-symlink")),
            "error should reference the nested path: {:?}",
            result.errors
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_detects_invalid_object_filename() -> Result<()> {
        // Exercises fsck_object_dir invalid filename detection (line ~1581).
        // Creates a file with a name that can't be parsed as a hex hash
        // remainder in objects/XX/.
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;
        repo.sync()?;

        let dir = open_test_repo_dir(&tmp);
        dir.create_dir_all("objects/ab")?;
        dir.write("objects/ab/not-a-valid-hex-hash", b"junk")?;

        let result = repo.fsck().await?;

        assert!(
            !result.is_ok(),
            "fsck should detect invalid object filename"
        );
        assert!(result.objects_corrupted > 0);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_string().contains("object-invalid-name")),
            "errors should mention invalid filename: {:?}",
            result.errors
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_detects_broken_image_symlink() -> Result<()> {
        // Exercises the broken symlink path in fsck_category for images
        // (line ~1711). The stream broken-symlink test covers streams;
        // this covers the same logic for images/.
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj_size: u64 = 32 * 1024;
        let obj = generate_test_data(obj_size, 0xBB);
        let obj_id = repo.ensure_object(&obj)?;

        let fs = make_test_fs(&obj_id, obj_size);
        let image_id = fs.commit_image(&repo, None)?;
        repo.sync()?;

        // Delete the backing object that the image symlink points to
        let dir = open_test_repo_dir(&tmp);
        let image_rel = format!("images/{}", image_id.to_hex());
        let link_target = dir.read_link(&image_rel)?;
        let backing_rel = PathBuf::from("images").join(&link_target);
        dir.remove_file(&backing_rel)?;

        let result = repo.fsck().await?;

        assert!(
            !result.is_ok(),
            "fsck should detect broken image symlink: {result}"
        );
        assert!(result.broken_links > 0);
        assert!(result.images_corrupted > 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_detects_missing_named_ref_object() -> Result<()> {
        // Exercises fsck_splitstream named ref checking (line ~1869).
        // Creates a stream with a named ref pointing to a non-existent
        // object, which should be detected as a missing object.
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj = generate_test_data(64 * 1024, 0xEA);

        // Create stream1 that references obj
        let mut writer1 = repo.create_stream(0)?;
        writer1.write_external(&obj)?;
        let stream1_id = repo.write_stream(writer1, "test-stream1", None)?;

        // Create stream2 with a named ref to stream1
        let mut writer2 = repo.create_stream(0)?;
        writer2.add_named_stream_ref("test-stream1", &stream1_id);
        let _stream2_id = repo.write_stream(writer2, "test-stream2", None)?;
        repo.sync()?;

        // Delete the object that the named ref points to (the stream1 splitstream object)
        let hex = stream1_id.to_hex();
        let (prefix, rest) = hex.split_at(2);
        let repo_dir = open_test_repo_dir(&tmp);
        repo_dir.remove_file(format!("objects/{prefix}/{rest}"))?;

        let result = repo.fsck().await?;

        assert!(
            !result.is_ok(),
            "fsck should detect missing named ref object"
        );
        assert!(
            result.missing_objects > 0,
            "should report missing objects: {result}"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_string().contains("missing-named-ref")),
            "errors should mention missing named ref object: {:?}",
            result.errors
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_healthy_repo_with_refs() -> Result<()> {
        // Verifies fsck_refs_dir passes on valid refs. Prior tests only
        // checked that fsck detects broken refs; this confirms a repo
        // with valid refs reports ok.
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj = generate_test_data(64 * 1024, 0xEA);

        let mut writer = repo.create_stream(0)?;
        writer.write_external(&obj)?;
        // write_stream with reference creates a ref symlink
        let _stream_id = repo.write_stream(writer, "test-stream", Some("my-ref"))?;
        repo.sync()?;

        let result = repo.fsck().await?;

        assert!(result.is_ok(), "fsck should pass with valid refs: {result}");
        assert!(result.errors.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_detects_corrupted_splitstream_object() -> Result<()> {
        // Exercises fsck_splitstream failure-to-open path (line ~1829).
        // Corrupts the splitstream object so that open_stream fails to
        // parse it, which is different from a missing external object ref.
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj = generate_test_data(64 * 1024, 0xEA);

        let mut writer = repo.create_stream(0)?;
        writer.write_external(&obj)?;
        let _stream_id = repo.write_stream(writer, "test-stream", None)?;
        repo.sync()?;

        // Find the splitstream object path via the stream symlink
        let dir = open_test_repo_dir(&tmp);
        let link_target = dir.read_link("streams/test-stream")?;
        let backing_rel = PathBuf::from("streams").join(&link_target);

        // Corrupt the splitstream object (not the data object it references)
        dir.remove_file(&backing_rel)?;
        dir.write(&backing_rel, b"corrupted splitstream header")?;

        let result = repo.fsck().await?;

        assert!(
            !result.is_ok(),
            "fsck should detect corrupted splitstream: {result}"
        );
        // The object digest mismatch is detected by object checking,
        // and the stream is also flagged because open_stream will fail
        // or the object refs check will fail.
        assert!(
            result.objects_corrupted > 0 || result.streams_corrupted > 0,
            "should report corruption: {result}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_validates_erofs_image_objects() -> Result<()> {
        // Exercises fsck_image: creates a valid erofs image, then deletes
        // one of its referenced objects. Fsck should detect the missing
        // object via erofs parsing.
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj_size: u64 = 32 * 1024;
        let obj = generate_test_data(obj_size, 0xCC);
        let obj_id = repo.ensure_object(&obj)?;

        let fs = make_test_fs(&obj_id, obj_size);
        let image_id = fs.commit_image(&repo, None)?;
        repo.sync()?;

        // Sanity: fsck passes on a healthy image
        let result = repo.fsck().await?;
        assert!(result.is_ok(), "healthy image should pass fsck: {result}");
        assert!(result.images_checked > 0, "should have checked the image");

        // Delete the object referenced by the erofs image
        let hex = obj_id.to_hex();
        let (prefix, rest) = hex.split_at(2);
        let dir = open_test_repo_dir(&tmp);
        dir.remove_file(format!("objects/{prefix}/{rest}"))?;

        let result = repo.fsck().await?;
        assert!(
            !result.is_ok(),
            "fsck should detect missing object referenced by erofs image: {result}"
        );
        assert!(
            result.missing_objects > 0,
            "should report missing objects: {result}"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_string().contains(&image_id.to_hex())
                    && e.to_string().contains("image-missing-object")),
            "error should reference the image: {:?}",
            result.errors
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_detects_corrupt_erofs_image() -> Result<()> {
        // Exercises fsck_image: corrupts the erofs image data so that
        // parsing fails. The catch_unwind should catch the panic from
        // the current erofs reader.
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let obj_size: u64 = 32 * 1024;
        let obj = generate_test_data(obj_size, 0xDD);
        let obj_id = repo.ensure_object(&obj)?;

        let fs = make_test_fs(&obj_id, obj_size);
        let image_id = fs.commit_image(&repo, None)?;
        repo.sync()?;

        // Corrupt the erofs image data (replace the backing object)
        let hex = image_id.to_hex();
        let (prefix, rest) = hex.split_at(2);
        let dir = open_test_repo_dir(&tmp);
        let obj_path = format!("objects/{prefix}/{rest}");
        dir.remove_file(&obj_path)?;
        dir.write(&obj_path, b"this is not a valid erofs image")?;

        let result = repo.fsck().await?;
        assert!(
            !result.is_ok(),
            "fsck should detect corrupt erofs image: {result}"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_string().contains("image-invalid")
                    || e.to_string().contains("digest mismatch")),
            "error should mention erofs corruption or digest mismatch: {:?}",
            result.errors
        );
        Ok(())
    }

    // ---- Fsck metadata validation tests ----

    #[tokio::test]
    async fn test_fsck_valid_metadata() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let result = repo.fsck().await?;
        assert!(result.is_ok());
        assert!(result.has_metadata());
        assert!(result.errors().is_empty());
        assert!(
            result.to_string().contains("meta.json: ok"),
            "display should show ok: {result}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_fsck_corrupt_metadata() -> Result<()> {
        // Write garbage to meta.json after opening — fsck re-reads from disk.
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let dir = open_test_repo_dir(&tmp);
        // Remove the valid meta.json and replace with garbage
        dir.remove_file(REPO_METADATA_FILENAME)?;
        dir.write(REPO_METADATA_FILENAME, b"not valid json {{")?;

        let result = repo.fsck().await?;
        assert!(!result.is_ok());
        assert!(
            result
                .errors()
                .iter()
                .any(|e| matches!(e, FsckError::MetadataParseFailed { .. }))
        );
        assert!(
            result.to_string().contains("meta.json: error"),
            "display should show error: {result}"
        );
        Ok(())
    }

    #[test]
    fn test_open_path_requires_metadata() {
        // Opening a directory without meta.json should fail with MetadataMissing.
        let tmp = tempdir();
        let path = tmp.path().join("bare-repo");
        mkdirat(CWD, &path, Mode::from_raw_mode(0o755)).unwrap();
        assert!(matches!(
            Repository::<Sha512HashValue>::open_path(CWD, &path),
            Err(RepositoryOpenError::MetadataMissing)
        ));
    }

    #[test]
    fn test_open_path_detects_old_format() {
        // A directory with objects/ but no meta.json → OldFormatRepository.
        let tmp = tempdir();
        let path = tmp.path().join("old-repo");
        mkdirat(CWD, &path, Mode::from_raw_mode(0o755)).unwrap();
        mkdirat(CWD, &path.join("objects"), Mode::from_raw_mode(0o755)).unwrap();
        assert!(matches!(
            Repository::<Sha512HashValue>::open_path(CWD, &path),
            Err(RepositoryOpenError::OldFormatRepository)
        ));
    }

    #[test]
    fn test_open_path_algorithm_mismatch() {
        // Open a sha512 repo as sha256 → AlgorithmMismatch.
        let tmp = tempdir();
        let path = tmp.path().join("sha512-repo");
        Repository::<Sha512HashValue>::init_path(CWD, &path, Algorithm::SHA512, false).unwrap();
        assert!(matches!(
            Repository::<Sha256HashValue>::open_path(CWD, &path),
            Err(RepositoryOpenError::AlgorithmMismatch { .. })
        ));
    }

    // ---- RepoMetadata / FeatureFlags tests ----
    //
    // Basic metadata construction, JSON roundtrip, algorithm compatibility,
    // and read/write are covered by the fsck tests above and the CLI
    // integration tests (init, hash-mismatch, backcompat).  The tests
    // below focus on the three-tier feature-flag compatibility model and
    // JSON serialization of populated feature vectors, which aren't
    // exercised elsewhere.

    #[test]
    fn test_metadata_json_with_features() {
        let mut meta = RepoMetadata::for_hash::<Sha512HashValue>();
        meta.features.compatible.push("some-compat".to_string());
        meta.features
            .read_only_compatible
            .push("some-rocompat".to_string());

        let json = meta.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();

        assert_eq!(parsed["features"]["compatible"][0], "some-compat");
        assert_eq!(
            parsed["features"]["read-only-compatible"][0],
            "some-rocompat"
        );

        // Roundtrip
        let meta2 = RepoMetadata::from_json(&json).unwrap();
        assert_eq!(meta, meta2);
    }

    #[test]
    fn test_feature_flags_unknown_incompat() {
        let mut meta = RepoMetadata::for_hash::<Sha512HashValue>();
        meta.features
            .incompatible
            .push("fancy-new-thing".to_string());
        let err = meta.check_compatible::<Sha512HashValue>().unwrap_err();
        assert!(
            format!("{err}").contains("fancy-new-thing"),
            "error should name the unknown feature: {err}"
        );
    }

    #[test]
    fn test_feature_flags_unknown_ro_compat() {
        let mut meta = RepoMetadata::for_hash::<Sha512HashValue>();
        meta.features
            .read_only_compatible
            .push("new-index".to_string());
        let check = meta.check_compatible::<Sha512HashValue>().unwrap();
        assert_eq!(check, FeatureCheck::ReadOnly(vec!["new-index".to_string()]));
    }

    #[test]
    fn test_feature_flags_unknown_compat_ignored() {
        let mut meta = RepoMetadata::for_hash::<Sha512HashValue>();
        meta.features.compatible.push("optional-hint".to_string());
        assert_eq!(
            meta.check_compatible::<Sha512HashValue>().unwrap(),
            FeatureCheck::ReadWrite
        );
    }

    #[test]
    fn test_object_store_method_variants() {
        // Verify all variants exist and are distinct
        let methods = [
            ObjectStoreMethod::Reflinked,
            ObjectStoreMethod::Hardlinked,
            ObjectStoreMethod::Copied,
            ObjectStoreMethod::AlreadyPresent,
        ];

        for (i, a) in methods.iter().enumerate() {
            for (j, b) in methods.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }

        // Verify Debug impl works
        assert_eq!(format!("{:?}", ObjectStoreMethod::Hardlinked), "Hardlinked");
    }
}
