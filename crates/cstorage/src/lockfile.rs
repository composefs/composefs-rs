//! Lock file implementation compatible with containers/storage.
//!
//! This module provides file-based locking that is wire-compatible with
//! the Go implementation in containers/storage. It uses POSIX fcntl locks
//! for cross-process synchronization and in-process RwLock for thread safety.
//!
//! # LastWrite Token
//!
//! The lock file stores a 64-byte "last write" token that allows callers to
//! detect if any writer has modified shared state since they last checked.
//! The format is:
//! - bytes 0-7: Unix timestamp (nanoseconds, little-endian)
//! - bytes 8-15: Counter (little-endian)
//! - bytes 16-19: Process ID (little-endian)
//! - bytes 20-63: Random bytes

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{RwLock, RwLockReadGuard};

use rustix::fs::{fcntl_lock, FlockOperation};

/// Size of the LastWrite token in bytes.
const LAST_WRITE_SIZE: usize = 64;

/// Error types for lock file operations.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// I/O error during lock file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Lock file operation failed.
    #[error("lock operation failed: {0}")]
    LockFailed(#[from] rustix::io::Errno),

    /// Would block on non-blocking lock attempt.
    #[error("lock would block")]
    WouldBlock,

    /// Invalid LastWrite data in lock file.
    #[error("invalid last write data: {0}")]
    InvalidData(String),
}

/// Result type for lock file operations.
pub type Result<T> = std::result::Result<T, LockError>;

/// A 64-byte token representing the last write to the lock file.
///
/// This token can be used to detect if any writer has modified shared state
/// since the token was obtained. The format is compatible with the Go
/// implementation in containers/storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastWrite {
    /// Unix timestamp in nanoseconds.
    timestamp_nanos: u64,
    /// Monotonic counter.
    counter: u64,
    /// Process ID of the writer.
    pid: u32,
    /// Random bytes for uniqueness.
    random: [u8; 44],
}

impl LastWrite {
    /// Deserialize a LastWrite token from a 64-byte array.
    fn from_bytes(buf: &[u8; LAST_WRITE_SIZE]) -> Self {
        let timestamp_nanos = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let counter = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let pid = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let mut random = [0u8; 44];
        random.copy_from_slice(&buf[20..64]);

        Self {
            timestamp_nanos,
            counter,
            pid,
            random,
        }
    }

    /// Check if this token represents an empty/uninitialized state.
    pub fn is_empty(&self) -> bool {
        self.timestamp_nanos == 0 && self.counter == 0 && self.pid == 0
    }
}

impl Default for LastWrite {
    fn default() -> Self {
        Self {
            timestamp_nanos: 0,
            counter: 0,
            pid: 0,
            random: [0u8; 44],
        }
    }
}

/// A file-based lock compatible with containers/storage (read-only).
///
/// This provides cross-process read locking (via fcntl) and in-process
/// thread synchronization (via RwLock). The lock file also stores a
/// LastWrite token that can be used to detect modifications.
#[derive(Debug)]
pub struct LockFile {
    /// Path to the lock file.
    path: PathBuf,
    /// File descriptor for the lock file.
    fd: OwnedFd,
    /// In-process synchronization lock.
    in_process_lock: RwLock<()>,
}

/// RAII guard for a shared (read) lock.
///
/// The lock is released when this guard is dropped.
#[derive(Debug)]
pub struct RLockGuard<'a> {
    lockfile: &'a LockFile,
    /// Hold the in-process read lock guard.
    _guard: RwLockReadGuard<'a, ()>,
}

impl Drop for RLockGuard<'_> {
    fn drop(&mut self) {
        // Release the fcntl lock
        let _ = fcntl_lock(self.lockfile.fd.as_fd(), FlockOperation::Unlock);
    }
}

impl LockFile {
    /// Open a lock file at the specified path in read-only mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        let file = OpenOptions::new().read(true).open(&path)?;

        let fd: OwnedFd = file.into();

        Ok(Self {
            path,
            fd,
            in_process_lock: RwLock::new(()),
        })
    }

    /// Get the path to the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Acquire a shared (read) lock, blocking until available.
    ///
    /// Returns a guard that releases the lock when dropped.
    pub fn rlock(&self) -> RLockGuard<'_> {
        // First acquire the in-process lock
        let guard = self
            .in_process_lock
            .read()
            .expect("in-process lock poisoned");

        // Then acquire the fcntl lock (blocking)
        fcntl_lock(self.fd.as_fd(), FlockOperation::LockShared)
            .expect("fcntl_lock failed unexpectedly");

        RLockGuard {
            lockfile: self,
            _guard: guard,
        }
    }

    /// Try to acquire a shared (read) lock without blocking.
    ///
    /// Returns `Err(LockError::WouldBlock)` if the lock is not available.
    pub fn try_rlock(&self) -> Result<RLockGuard<'_>> {
        // Try to acquire the in-process lock
        let guard = self
            .in_process_lock
            .try_read()
            .map_err(|_| LockError::WouldBlock)?;

        // Try to acquire the fcntl lock (non-blocking)
        match fcntl_lock(self.fd.as_fd(), FlockOperation::NonBlockingLockShared) {
            Ok(()) => Ok(RLockGuard {
                lockfile: self,
                _guard: guard,
            }),
            Err(rustix::io::Errno::AGAIN) => Err(LockError::WouldBlock),
            Err(e) => Err(LockError::LockFailed(e)),
        }
    }

    /// Read the current LastWrite token from the lock file.
    ///
    /// This reads the token directly from the file, not from cache.
    pub fn get_last_write(&self) -> Result<LastWrite> {
        let mut file = self.as_file();
        file.seek(SeekFrom::Start(0))?;

        let mut buf = [0u8; LAST_WRITE_SIZE];
        match file.read_exact(&mut buf) {
            Ok(()) => Ok(LastWrite::from_bytes(&buf)),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // File is empty or too small - return empty token
                Ok(LastWrite::default())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Check if the lock file has been modified since the given token.
    ///
    /// This reads the current token from the file and compares it to
    /// the provided token. Returns `true` if they differ.
    pub fn modified_since(&self, prev: &LastWrite) -> Result<bool> {
        let current = self.get_last_write()?;
        Ok(current != *prev)
    }

    /// Helper to get a File reference for I/O operations.
    ///
    /// This borrows the fd without taking ownership.
    fn as_file(&self) -> File {
        use std::os::fd::BorrowedFd;
        let borrowed: BorrowedFd<'_> = self.fd.as_fd();

        // Use dup to create a new fd that File can own
        let duped = rustix::io::fcntl_dupfd_cloexec(borrowed, 0).expect("fcntl_dupfd failed");
        File::from(duped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lastwrite_default_is_empty() {
        let token = LastWrite::default();
        assert!(token.is_empty());
    }

    #[test]
    fn test_basic_read_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lock");

        // Create the file first
        std::fs::write(&path, &[0u8; 64]).unwrap();

        let lockfile = LockFile::open(&path).unwrap();

        // Acquire and release shared lock
        {
            let _guard = lockfile.rlock();
        }
    }

    #[test]
    fn test_try_rlock_succeeds_when_available() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lock");

        // Create the file first
        std::fs::write(&path, &[0u8; 64]).unwrap();

        let lockfile = LockFile::open(&path).unwrap();

        let guard = lockfile.try_rlock();
        assert!(guard.is_ok());
    }
}
