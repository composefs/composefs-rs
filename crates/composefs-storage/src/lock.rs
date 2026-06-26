//! Layer-store locking for safe concurrent access.
//!
//! containers-storage (podman/buildah) uses an `flock(2)`-based protocol on
//! `<storage_root>/overlay-layers/layers.lock` to coordinate readers and
//! writers.  Taking a shared (read) lock here ensures that a concurrent
//! `podman rmi` cannot delete a layer's diff directory while we are
//! streaming it to the consumer.
//!
//! # Why flock?
//!
//! * **Interoperability**: containers-storage uses `flock(2)` on this exact
//!   path; taking the same lock type gives correct mutual exclusion with all
//!   c/storage users.
//! * **Auto-release on process death**: the kernel closes all fds and
//!   releases any flocks when the process exits, even on SIGKILL.  This is
//!   critical for the userns helper subprocess: if the parent kills it mid-
//!   transfer, the lock is released automatically, unblocking podman.
//! * **RAII**: the guard is just a wrapped `OwnedFd`; the lock releases when
//!   the guard drops (fd close).

use std::os::fd::OwnedFd;

use rustix::fs::{FlockOperation, Mode, OFlags, flock};

use crate::storage::Storage;

/// A shared (read) lock on the containers-storage layer store.
///
/// The lock is held for as long as this guard exists; it releases
/// automatically when the guard is dropped (or when the process exits).
///
/// Acquire via [`Storage::lock_layers_shared`].
///
/// The lock is released by closing the fd, which happens automatically when
/// this guard is dropped (the [`OwnedFd`] closes itself) or when the process
/// exits. No explicit unlock is needed.
#[derive(Debug)]
pub struct LayerStoreLock(#[allow(dead_code)] OwnedFd);

impl Storage {
    /// Acquire a shared (read) flock on `overlay-layers/layers.lock`.
    ///
    /// Blocks until the lock is available.  A concurrent writer (e.g.
    /// `podman rmi`) holds an exclusive lock while removing layers; we block
    /// until it finishes.  Multiple readers may hold shared locks simultaneously.
    ///
    /// The lock is released when the returned [`LayerStoreLock`] is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error if `overlay-layers/layers.lock` cannot be opened
    /// or if the `flock` syscall fails.
    pub fn lock_layers_shared(&self) -> crate::Result<LayerStoreLock> {
        use crate::error::StorageError;

        // Open (or create) the lock file with O_RDWR so that a freshly
        // created file gets the right mode for a later root podman that would
        // open it O_RDWR.  O_RDONLY|O_CREAT would create a 0-byte file with
        // mode 0o644 but the file descriptor would be read-only, which is
        // fine for flock but would break a privileged writer that re-opens it
        // expecting read-write access.  O_RDWR is the safe choice here.
        use std::os::fd::AsFd as _;
        let root_fd = self.root_dir().as_fd();
        let fd = rustix::fs::openat(
            root_fd,
            "overlay-layers/layers.lock",
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::CREATE,
            Mode::from_bits_truncate(0o644),
        )
        .map_err(|e| StorageError::Io(std::io::Error::from(e)))?;

        // Acquire a shared (read) lock; block if an exclusive (write) lock is
        // held by another process.
        flock(&fd, FlockOperation::LockShared)
            .map_err(|e| StorageError::Io(std::io::Error::from(e)))?;

        Ok(LayerStoreLock(fd))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::storage::Storage;

    fn create_test_storage(tmp: &TempDir) -> Storage {
        for d in ["overlay", "overlay-layers", "overlay-images"] {
            std::fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        Storage::open(tmp.path()).unwrap()
    }

    /// Acquiring a shared lock should succeed.
    #[test]
    fn test_shared_lock_succeeds() {
        let tmp = TempDir::new().unwrap();
        let storage = create_test_storage(&tmp);

        let lock = storage.lock_layers_shared().expect("shared lock");
        // Lock file must exist now.
        assert!(tmp.path().join("overlay-layers/layers.lock").exists());
        drop(lock); // releases
    }

    /// Two shared locks from the same process succeed simultaneously (shared
    /// locking is not exclusive against other shared lockers).
    #[test]
    fn test_two_shared_locks() {
        let tmp = TempDir::new().unwrap();
        let storage = create_test_storage(&tmp);

        let lock1 = storage.lock_layers_shared().expect("first shared lock");
        let lock2 = storage.lock_layers_shared().expect("second shared lock");
        drop(lock1);
        drop(lock2);
    }

    /// A non-blocking exclusive lock attempt fails while a shared lock is held.
    ///
    /// This exercises the mutual-exclusion between our shared reader lock and
    /// a concurrent exclusive writer (e.g. podman rmi).  We can't test the
    /// blocking case in a unit test without spawning threads, but we can
    /// assert that the non-blocking attempt fails with EWOULDBLOCK.
    #[test]
    fn test_exclusive_blocked_by_shared() {
        let tmp = TempDir::new().unwrap();
        let storage = create_test_storage(&tmp);

        let _shared = storage.lock_layers_shared().expect("shared lock");

        // Open the lock file and try a non-blocking exclusive lock — must fail.
        use std::os::fd::AsFd as _;
        let root_fd = storage.root_dir().as_fd();
        let fd = rustix::fs::openat(
            root_fd,
            "overlay-layers/layers.lock",
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::CREATE,
            Mode::from_bits_truncate(0o644),
        )
        .expect("open lock file");

        let result = flock(&fd, FlockOperation::NonBlockingLockExclusive);
        assert!(
            result.is_err(),
            "exclusive non-blocking lock must fail while a shared lock is held"
        );
    }
}
