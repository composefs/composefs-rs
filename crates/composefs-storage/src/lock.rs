//! Layer-store locking for safe concurrent access.
//!
//! containers-storage (podman/buildah) uses POSIX `fcntl(2)` record locks on
//! `<storage_root>/overlay-layers/layers.lock` to coordinate readers and
//! writers.  Taking a shared (read) lock here ensures that a concurrent
//! `podman rmi` cannot delete a layer's diff directory while we are
//! streaming it to the consumer.
//!
//! # Why open-file-description locks?
//!
//! * **Interoperability**: Linux open-file-description (OFD) record locks
//!   conflict with Go's POSIX record locks over the same range (offset zero,
//!   length zero). `flock(2)` does not interoperate with them on local Linux
//!   filesystems.
//! * **Auto-release on process death**: the kernel closes all fds and
//!   releases the locks when the process exits, even on SIGKILL. This is
//!   critical for the userns helper subprocess: if the parent kills it mid-
//!   transfer, the lock is released automatically, unblocking podman.
//! * **RAII**: the guard is just a wrapped `OwnedFd`; the lock releases when
//!   the guard drops (fd close).
//!
//! OFD locks give each independently opened guard its own lifetime. With
//! process-associated POSIX locks, closing *any* descriptor for the lock inode
//! would release all of this process's locks, including other live guards.
//! OFD locks remain held until their own open file description is closed.

use std::os::fd::{AsFd, OwnedFd};

use composefs_ioctls::lock::ofd_lock_shared;
use rustix::fs::{Mode, OFlags};

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
    /// Acquire a shared OFD record lock on `overlay-layers/layers.lock`.
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
    /// or if the record-lock syscall fails. OFD locks require Linux 3.15 or later.
    pub fn lock_layers_shared(&self) -> crate::Result<LayerStoreLock> {
        // Open or create the lock file with the mode Go uses, preserving the
        // existing read-write access. Do not truncate: Go stores its
        // cache-invalidation token in this file.
        let root_fd = self.root_dir().as_fd();
        let fd = rustix::fs::openat(
            root_fd,
            "overlay-layers/layers.lock",
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::CREATE,
            Mode::from_bits_truncate(0o644),
        )
        .map_err(std::io::Error::from)?;

        // Acquire a shared (read) lock; block if an exclusive (write) lock is
        // held by another process.
        ofd_lock_shared(&fd)?;

        Ok(LayerStoreLock(fd))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    use rustix::fs::{FlockOperation, fcntl_lock};
    use rustix::io::Errno;
    use tempfile::TempDir;

    use super::*;

    const LOCK_PATH_ENV: &str = "COMPOSEFS_TEST_POSIX_LOCK_PATH";
    const LOCK_ACTION_ENV: &str = "COMPOSEFS_TEST_POSIX_LOCK_ACTION";
    const LOCK_CONTENDED: i32 = 75;
    const LOCK_READY: &str = "POSIX_LOCK_READY";
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn create_test_storage(tmp: &TempDir) -> Storage {
        for d in ["overlay", "overlay-layers", "overlay-images"] {
            std::fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        Storage::open(tmp.path()).unwrap()
    }

    // Re-executed in a separate process so POSIX locks cannot merge with any
    // locks in the test runner. Use rustix's F_SETLK/F_SETLKW wrapper, not the
    // OFD wrapper under test: this is the protocol Go containers/storage uses.
    #[test]
    fn posix_lock_child() {
        let Some(path) = std::env::var_os(LOCK_PATH_ENV) else {
            return;
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let action = std::env::var(LOCK_ACTION_ENV).unwrap();
        let operation = match action.as_str() {
            "read" => FlockOperation::NonBlockingLockShared,
            "write" => FlockOperation::NonBlockingLockExclusive,
            "hold-write" => FlockOperation::LockExclusive,
            _ => panic!("unknown lock action {action}"),
        };
        match fcntl_lock(&file, operation) {
            Ok(()) => {}
            Err(Errno::AGAIN | Errno::ACCESS) => std::process::exit(LOCK_CONTENDED),
            Err(error) => panic!("POSIX lock failed: {error}"),
        }
        if action == "hold-write" {
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "\n{LOCK_READY}").unwrap();
            stdout.flush().unwrap();
            std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
        }
        std::process::exit(0);
    }

    fn posix_command(path: &Path, action: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "lock::tests::posix_lock_child", "--nocapture"])
            .env(LOCK_PATH_ENV, path)
            .env(LOCK_ACTION_ENV, action);
        command
    }

    fn assert_posix_lock(path: &Path, action: &str, available: bool) {
        let output = posix_command(path, action).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(if available { 0 } else { LOCK_CONTENDED }),
            "POSIX {action} lock, available={available}: {output:?}",
        );
    }

    /// Independent POSIX readers can share the lock, but writers are excluded
    /// until the reader guard is dropped.
    #[test]
    fn test_posix_interop() {
        let tmp = TempDir::new().unwrap();
        let storage = create_test_storage(&tmp);
        let path = tmp.path().join("overlay-layers/layers.lock");
        let lock = storage.lock_layers_shared().unwrap();

        for (action, available) in [("read", true), ("write", false)] {
            assert_posix_lock(&path, action, available);
        }
        drop(lock);
        assert_posix_lock(&path, "write", true);
    }

    /// Multiple reader guards, including aliased paths, retain protection
    /// until the last guard is dropped.
    #[test]
    fn test_independent_guard_lifetimes() {
        for drop_first in [true, false] {
            let tmp = TempDir::new().unwrap();
            let storage = create_test_storage(&tmp);
            let path = tmp.path().join("overlay-layers/layers.lock");
            let token = b"existing Go change token";
            std::fs::write(&path, token).unwrap();
            let alias = tmp.path().join("alias");
            std::os::unix::fs::symlink(tmp.path(), &alias).unwrap();
            let other_storage = Storage::open(alias).unwrap();
            let first = storage.lock_layers_shared().unwrap();
            let second = other_storage.lock_layers_shared().unwrap();

            // Closing an unrelated descriptor for this inode must not release
            // either guard, as it would with process-associated POSIX locks.
            drop(std::fs::File::open(&path).unwrap());
            assert_posix_lock(&path, "write", false);
            let remaining = if drop_first {
                drop(first);
                second
            } else {
                drop(second);
                first
            };
            assert_posix_lock(&path, "write", false);
            drop(remaining);
            assert_posix_lock(&path, "write", true);
            assert_eq!(std::fs::read(path).unwrap(), token);
        }
    }

    /// A shared reader waits for a POSIX writer held in another process.
    #[test]
    fn test_reader_waits_for_posix_writer() {
        let tmp = TempDir::new().unwrap();
        let storage = create_test_storage(&tmp);
        let path = tmp.path().join("overlay-layers/layers.lock");
        std::fs::write(&path, []).unwrap();
        let mut writer = posix_command(&path, "hold-write")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(writer.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(output.read_line(&mut line).unwrap(), 0, "writer exited");
            if line.trim() == LOCK_READY {
                break;
            }
        }

        let (started_tx, started_rx) = mpsc::channel();
        let (locked_tx, locked_rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            locked_tx.send(storage.lock_layers_shared()).unwrap();
        });
        started_rx.recv_timeout(TEST_TIMEOUT).unwrap();
        let early = locked_rx.recv_timeout(Duration::from_millis(100));
        drop(writer.stdin.take());
        assert!(writer.wait().unwrap().success());
        assert!(matches!(early, Err(mpsc::RecvTimeoutError::Timeout)));
        let lock = locked_rx.recv_timeout(TEST_TIMEOUT).unwrap().unwrap();
        reader.join().unwrap();
        drop(lock);
        assert_posix_lock(&path, "write", true);
    }
}
