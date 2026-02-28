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
    fs::{canonicalize, File},
    io::{Read, Write},
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

use anyhow::{bail, ensure, Context, Result};
use fn_error_context::context;
use once_cell::sync::OnceCell;
use rustix::{
    fs::{
        flock, linkat, mkdirat, open, openat, readlinkat, statat, syncfs, unlinkat, AtFlags, Dir,
        FileType, FlockOperation, Mode, OFlags, CWD,
    },
    io::{Errno, Result as ErrnoResult},
};

use crate::{
    fsverity::{
        compute_verity, enable_verity_maybe_copy, ensure_verity_equal, measure_verity,
        CompareVerityError, EnableVerityError, FsVerityHashValue, FsVerityHasher,
        MeasureVerityError,
    },
    mount::{composefs_fsmount, mount_at},
    splitstream::{SplitStreamReader, SplitStreamWriter},
    util::{proc_self_fd, replace_symlinkat, ErrnoFilter},
};

/// How an object was stored in the repository.
///
/// Returned by [`Repository::ensure_object_from_file_with_stats`] to indicate
/// whether the operation used a regular copy or found an existing object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectStoreMethod {
    /// Object was stored via regular file copy.
    Copied,
    /// Object already existed in the repository (deduplicated).
    AlreadyPresent,
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

    /// Open a repository at the target directory and path.
    #[context("Opening repository at {}", path.as_ref().display())]
    pub fn open_path(dirfd: impl AsFd, path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        // O_PATH isn't enough because flock()
        let repository = openat(dirfd, path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .with_context(|| format!("Cannot open composefs repository at {}", path.display()))?;

        flock(&repository, FlockOperation::LockShared)
            .context("Cannot lock composefs repository")?;

        Ok(Self {
            repository,
            objects: OnceCell::new(),
            write_semaphore: OnceCell::new(),
            insecure: false,
            _data: std::marker::PhantomData,
        })
    }

    /// Open the default user-owned composefs repository.
    #[context("Opening user repository")]
    pub fn open_user() -> Result<Self> {
        let home = std::env::var("HOME").with_context(|| "$HOME must be set when in user mode")?;

        Self::open_path(CWD, PathBuf::from(home).join(".var/lib/composefs"))
    }

    /// Open the default system-global composefs repository.
    #[context("Opening system repository")]
    pub fn open_system() -> Result<Self> {
        Self::open_path(CWD, PathBuf::from("/sysroot/composefs".to_string()))
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
        let self_ = Arc::clone(self);
        tokio::task::spawn_blocking(move || self_.ensure_object(&data)).await?
    }

    /// Create an O_TMPFILE in the objects directory for streaming writes.
    ///
    /// Returns the file descriptor for writing. The caller should write data to this fd,
    /// then call `spawn_finalize_object_tmpfile()` to compute the verity digest,
    /// enable fs-verity, and link the file into the objects directory.
    #[context("Creating object tmpfile")]
    pub fn create_object_tmpfile(&self) -> Result<OwnedFd> {
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

    /// Spawn a background task that finalizes a tmpfile as an object.
    ///
    /// The task computes the fs-verity digest by reading the file, enables verity,
    /// and links the file into the objects directory.
    ///
    /// Returns a handle that resolves to the ObjectID (fs-verity digest).
    ///
    /// # Arguments
    /// * `tmpfile_fd` - The O_TMPFILE file descriptor with data already written
    /// * `size` - The exact size in bytes of the data written to the tmpfile
    pub fn spawn_finalize_object_tmpfile(
        self: &Arc<Self>,
        tmpfile_fd: OwnedFd,
        size: u64,
    ) -> tokio::task::JoinHandle<Result<(ObjectID, ObjectStoreMethod)>> {
        let self_ = Arc::clone(self);
        tokio::task::spawn_blocking(move || self_.finalize_object_tmpfile(tmpfile_fd.into(), size))
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
        // Re-open as read-only via /proc/self/fd (required for verity enable)
        let fd_path = proc_self_fd(&file);
        let ro_fd = open(&*fd_path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .context("Re-opening tmpfile as read-only for verity")?;

        // Must close writable fd before enabling verity
        drop(file);

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

        // Check if object already exists
        let path = id.to_object_pathname();

        match statat(objects_dir, &path, AtFlags::empty()) {
            Ok(stat) if stat.st_size as u64 == size => {
                // Object already exists with correct size, skip storage
                return Ok((id, ObjectStoreMethod::AlreadyPresent));
            }
            _ => {}
        }

        // Ensure parent directory exists
        let parent_dir = id.to_object_dir();
        let _ = mkdirat(objects_dir, &parent_dir, Mode::from_raw_mode(0o755));

        // Link the file into the objects directory
        match linkat(
            CWD,
            proc_self_fd(&ro_fd),
            objects_dir,
            &path,
            AtFlags::SYMLINK_FOLLOW,
        ) {
            Ok(()) => Ok((id, ObjectStoreMethod::Copied)),
            Err(Errno::EXIST) => Ok((id, ObjectStoreMethod::AlreadyPresent)), // Race: another task created it
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
    fn store_object_with_id(&self, data: &[u8], id: &ObjectID) -> Result<()> {
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
        // We can't enable verity with an open writable fd, so re-open and close the old one.
        let ro_fd = open(
            proc_self_fd(&file),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("Re-opening file as read-only for verity")?;
        // NB: We should do fdatasync() or fsync() here, but doing this for each file forces the
        // creation of a massive number of journal commits and is a performance disaster.  We need
        // to coordinate this at a higher level.  See .write_stream().
        drop(file);

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
        let id: ObjectID = compute_verity(data);
        self.store_object_with_id(data, &id)?;
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

    /// By default fsverity is required to be enabled on the target
    /// filesystem. Setting this disables verification of digests
    /// and an instance of [`Self`] can be used on a filesystem
    /// without fsverity support.
    pub fn set_insecure(&mut self, insecure: bool) -> &mut Self {
        self.insecure = insecure;
        self
    }

    /// Creates a SplitStreamWriter for writing a split stream.
    /// You should write the data to the returned object and then pass it to .store_stream() to
    /// store the result.
    pub fn create_stream(self: &Arc<Self>, content_type: u64) -> SplitStreamWriter<ObjectID> {
        SplitStreamWriter::new(self, content_type)
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
        self.symlink(&stream_path, &object_path)?;

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink(&reference_path, &stream_path)?;
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
        self.sync_async().await?;

        let stream_path = Self::format_stream_path(content_identifier);
        let object_path = Self::format_object_path(object_id);
        self.symlink(&stream_path, &object_path)?;

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink(&reference_path, &stream_path)?;
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
        let object_id = writer
            .done_async()
            .await
            .context("Finalizing split stream writer (async)")?;

        self.sync_async().await?;

        let stream_path = Self::format_stream_path(content_identifier);
        let object_path = Self::format_object_path(&object_id);
        self.symlink(&stream_path, &object_path)?;

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink(&reference_path, &stream_path)?;
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
        let stream_path = Self::format_stream_path(content_identifier);
        let reference_path = format!("streams/refs/{name}");
        self.symlink(&reference_path, &stream_path)?;
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
        let stream_path = Self::format_stream_path(content_identifier);

        let (object_id, extra) = match self.has_stream(content_identifier)? {
            Some(id) => (id, T::default()),
            None => {
                let mut writer = self.create_stream(content_type);
                let extra =
                    callback(&mut writer).context("Writing stream content via callback")?;
                let id = self.write_stream(writer, content_identifier, reference)?;
                (id, extra)
            }
        };

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink(&reference_path, &stream_path)?;
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
        let object_id = self.ensure_object(data)?;

        let object_path = Self::format_object_path(&object_id);
        let image_path = format!("images/{}", object_id.to_hex());

        self.symlink(&image_path, &object_path)?;

        if let Some(reference) = name {
            let ref_path = format!("images/refs/{reference}");
            self.symlink(&ref_path, &image_path)?;
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
    fn open_image(&self, name: &str) -> Result<(OwnedFd, bool)> {
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
    #[context("Creating symlink from {name:?} to {target:?}")]
    pub fn symlink(
        &self,
        name: impl AsRef<Path> + std::fmt::Debug,
        target: impl AsRef<Path> + std::fmt::Debug,
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

    // fn fsck(&self) -> Result<()> {
    //     unimplemented!()
    // }

    /// Returns a borrowed file descriptor for the repository root.
    ///
    /// This allows low-level operations on the repository directory.
    pub fn repo_fd(&self) -> BorrowedFd<'_> {
        self.repository.as_fd()
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

            if let Ok(target) = readlinkat(&dir_fd, name_bytes, vec![]) {
                if let Ok(target_str) = target.into_string() {
                    refs.push((name, target_str));
                }
            }
        }

        Ok(refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsverity::Sha512HashValue;
    use crate::test::tempdir;
    use rustix::fs::{statat, CWD};
    use tempfile::TempDir;

    /// Create a test repository in insecure mode (no fs-verity required).
    fn create_test_repo(path: &Path) -> Result<Arc<Repository<Sha512HashValue>>> {
        mkdirat(CWD, path, Mode::from_raw_mode(0o755))?;
        let mut repo = Repository::open_path(CWD, path)?;
        repo.set_insecure(true);
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

        let mut writer = repo.create_stream(0);
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

        let mut writer = repo.create_stream(0);
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

        let mut writer = repo.create_stream(0);
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

        let mut writer1 = repo.create_stream(0);
        writer1.write_external(&obj2)?;
        writer1.write_external(&obj3)?;
        let _stream1_id = repo.write_stream(writer1, "test-stream1", None)?;

        let mut writer2 = repo.create_stream(0);
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

        let mut writer1 = repo.create_stream(0);
        writer1.write_external(&obj2)?;
        let stream1_id = repo.write_stream(writer1, "test-stream1", None)?;

        let mut writer2 = repo.create_stream(0);
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

        let mut writer1 = repo.create_stream(0);
        writer1.write_external(&obj2)?;
        let stream1_id = repo.write_stream(writer1, "test-stream1", None)?;

        let mut writer2 = repo.create_stream(0);
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

        let mut writer = repo.create_stream(0);
        writer.write_external(&obj2)?;
        let stream1_id = repo.write_stream(writer, "test-stream1", None)?;

        let mut writer = repo.create_stream(0);
        writer.write_external(&obj3)?;
        let stream2_id = repo.write_stream(writer, "test-stream2", None)?;

        let mut writer = repo.create_stream(0);
        writer.write_external(&obj4)?;
        let stream3_id = repo.write_stream(writer, "test-stream3", None)?;

        let mut writer = repo.create_stream(0);
        writer.add_named_stream_ref("test-stream1", &stream1_id);
        writer.add_named_stream_ref("test-stream2", &stream2_id);
        let _ref_stream1_id = repo.write_stream(writer, "ref-stream1", None)?;

        let mut writer = repo.create_stream(0);
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

    use crate::tree::{FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat};

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
        let inode = Inode::Leaf(std::rc::Rc::new(Leaf {
            stat: Stat {
                st_mode: 0o644,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                xattrs: Default::default(),
            },
            content: LeafContent::Regular(RegularFile::External(obj.clone(), size)),
        }));
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
        let inode = Inode::Leaf(std::rc::Rc::new(Leaf {
            stat: Stat {
                st_mode: 0o644,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                xattrs: Default::default(),
            },
            content: LeafContent::Regular(RegularFile::External(obj2.clone(), size2)),
        }));
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
}
