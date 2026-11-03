//! Linux open-file-description record locks, not yet exposed by rustix.
#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsFd, AsRawFd};

use rustix::fs::FlockOperation;

/// Acquire a shared open-file-description lock over the entire file.
///
/// Blocks until conflicting locks are released, retrying interrupted waits.
/// These locks conflict with POSIX record locks (`F_SETLK`/`F_SETLKW`), but
/// belong to the open file description rather than the process. The lock is
/// released when the last descriptor for that description is closed; closing
/// an independently opened descriptor for the same inode does not release it.
///
/// Requires Linux 3.15 or later. No fallback to another lock type is attempted.
///
/// # Errors
/// Returns the kernel error if the file cannot be locked.
pub fn ofd_lock_shared(fd: impl AsFd) -> io::Result<()> {
    ofd_lock(fd, FlockOperation::LockShared)
}

/// Acquire, convert or release an OFD lock over the entire file.
///
/// Blocking operations retry interrupted waits. Nonblocking acquisition reports
/// contention to the caller, allowing cancellation-aware lock acquisition.
///
/// # Errors
/// Returns the kernel error, including contention or unsupported OFD locking.
pub fn ofd_lock(fd: impl AsFd, operation: FlockOperation) -> io::Result<()> {
    let fd = fd.as_fd();
    let (command, kind) = match operation {
        FlockOperation::LockShared => (libc::F_OFD_SETLKW, libc::F_RDLCK),
        FlockOperation::LockExclusive => (libc::F_OFD_SETLKW, libc::F_WRLCK),
        FlockOperation::NonBlockingLockShared => (libc::F_OFD_SETLK, libc::F_RDLCK),
        FlockOperation::NonBlockingLockExclusive => (libc::F_OFD_SETLK, libc::F_WRLCK),
        FlockOperation::Unlock | FlockOperation::NonBlockingUnlock => {
            (libc::F_OFD_SETLK, libc::F_UNLCK)
        }
    };
    // SAFETY: flock contains only integer fields, including ABI-specific
    // reserved fields, so an all-zero value is valid on every supported ABI.
    // Start/length zero locks the whole file; OFD locks also require pid zero.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = kind as libc::c_short;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    loop {
        // SAFETY: fd is borrowed for the call, and lock is an initialized
        // flock matching libc's fcntl ABI. These SETLK commands only read it.
        let result = unsafe { libc::fcntl(fd.as_raw_fd(), command, &raw const lock) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
