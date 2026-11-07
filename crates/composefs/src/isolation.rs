//! Threads with a private file descriptor table.
//!
//! Linux has no `O_CLOFORK`: when one thread calls `fork()`, the child
//! gets a copy of every file descriptor in the process, including
//! writable ones that another thread opened a moment earlier.  Until
//! the child calls `exec()` (and `O_CLOEXEC` takes effect), those
//! duplicates keep files open for writing, which for example makes
//! `FS_IOC_ENABLE_VERITY` fail with `ETXTBSY`.
//!
//! [`spawn_isolated`] starts a thread that calls `unshare(CLONE_FILES)`
//! and so gets its own copy of the descriptor table.  `fork()` only
//! copies the table of the thread that calls it, so descriptors opened
//! inside the isolated thread (or in threads it spawns, which share its
//! table) can never leak into children forked by other threads.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::thread::JoinHandle;

use rustix::thread::UnshareFlags;

/// Spawn a thread with a private file descriptor table and run `f` in it.
///
/// `fds` are moved into the new thread's table and handed to `f`; their
/// copies in the shared table are closed before this function returns.
/// All other descriptors the new thread inherited are closed, except
/// for standard input, output and error, so that the thread doesn't
/// keep the rest of the process's files, sockets and pipes open.
///
/// Descriptors are opaque numbers that only mean something in the
/// table they came from.  `f` is a plain function pointer and `arg`
/// must be `Copy`, so neither can carry descriptors from the shared
/// table.  Descriptors can still be exchanged safely by passing them
/// over a Unix socket with `SCM_RIGHTS`, where the kernel translates
/// them.
///
/// Inside the isolated thread, `/proc/self/fd` describes the table of
/// the thread group leader; use `/proc/thread-self/fd` instead.
///
/// # Safety
///
/// The compiler can't stop `f` from reaching descriptors through
/// process-wide state.  `f`, and every thread it spawns, must not:
///
/// - use descriptors stored in statics, `&'static` references or
///   library-internal caches, such as a logger's output, the `/proc`
///   handle cached by `rustix::procfs`, or a random number generator's
///   `/dev/urandom` handle.  Those were closed here (the standard streams
///   excepted), so their numbers may now refer to unrelated files.  In
///   particular, don't log;
/// - store descriptors it opens in such state, where other threads
///   would find them.
///
/// Standard input, output and error stay open as copies of the
/// process's own, so writing to them (as the default panic hook does)
/// is fine, but they aren't private to the thread.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by FsVerityHelper in the next commit")
)]
pub(crate) unsafe fn spawn_isolated<A: Copy + Send + 'static>(
    name: String,
    fds: Vec<OwnedFd>,
    arg: A,
    f: fn(Vec<OwnedFd>, A),
) -> io::Result<JoinHandle<()>> {
    let raw: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    let (tx, rx) = std::sync::mpsc::sync_channel::<io::Result<()>>(1);

    let handle = std::thread::Builder::new().name(name).spawn(move || {
        // SAFETY: after this call the thread has a private copy of the
        // descriptor table.  The only descriptors it uses afterwards are
        // the ones it takes ownership of below and the ones it opens
        // itself, which our caller guarantees for `f`.
        if let Err(e) = unsafe { rustix::thread::unshare_unsafe(UnshareFlags::FILES) } {
            let _ = tx.send(Err(e.into()));
            return;
        }

        let closed = close_inherited(&raw);

        // SAFETY: the parent keeps `fds` open until we report back, so
        // these numbers were valid when the table was copied.  In this
        // private table nothing else owns them.
        let owned: Vec<OwnedFd> = raw
            .iter()
            .map(|&fd| unsafe { OwnedFd::from_raw_fd(fd) })
            .collect();

        if let Err(e) = closed {
            let _ = tx.send(Err(e));
            return;
        }
        let _ = tx.send(Ok(()));
        drop(tx);

        f(owned, arg);
    })?;

    let result = rx
        .recv()
        .unwrap_or_else(|_| Err(io::Error::other("isolated thread exited during setup")));
    // These are the copies in the shared table; the thread has its own.
    drop(fds);

    match result {
        Ok(()) => Ok(handle),
        Err(e) => {
            let _ = handle.join();
            Err(e)
        }
    }
}

/// Close every descriptor in the current (private) table except the
/// standard streams and `keep`.
fn close_inherited(keep: &[RawFd]) -> io::Result<()> {
    // Keep 0-2 open: otherwise a later open() could reuse those numbers
    // and stray writes to stderr would land in our files.
    let mut keep: Vec<u32> = [0, 1, 2]
        .into_iter()
        .chain(keep.iter().map(|&fd| fd as u32))
        .collect();
    keep.sort_unstable();
    keep.dedup();

    let mut gaps = Vec::new();
    for pair in keep.windows(2) {
        if pair[1] > pair[0] + 1 {
            gaps.push((pair[0] + 1, pair[1] - 1));
        }
    }
    gaps.push((keep[keep.len() - 1] + 1, u32::MAX));

    for &(first, last) in &gaps {
        match close_range(first, last) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {
                return close_inherited_procfs(&keep);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// rustix doesn't provide close_range() yet.
fn close_range(first: u32, last: u32) -> io::Result<()> {
    // SAFETY: the syscall takes plain integers.  Closing descriptors is
    // fine because this thread's table is private and nothing in it
    // owns them other than the ones we kept.
    let r = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0u32) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Fallback for kernels without `close_range` (before 5.9).
fn close_inherited_procfs(keep: &[u32]) -> io::Result<()> {
    let dir = std::fs::read_dir("/proc/thread-self/fd")?;
    let mut fds = Vec::new();
    for entry in dir {
        if let Some(fd) = entry?
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        {
            fds.push(fd);
        }
    }
    // The ReadDir has been dropped, so its own descriptor is gone and
    // any number left in `fds` that still exists is an inherited one.
    for fd in fds {
        if keep.binary_search(&fd).is_err() {
            // SAFETY: as in close_range(); EBADF (e.g. for the closed
            // directory descriptor) is harmless.
            unsafe { libc::close(fd as RawFd) };
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use rustix::fs::{Mode, OFlags};

    use super::*;

    fn same_file(a: impl AsFd, b: impl AsFd) -> bool {
        let a = rustix::fs::fstat(a).unwrap();
        let b = rustix::fs::fstat(b).unwrap();
        (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)
    }

    #[test]
    fn fds_are_moved_and_private() {
        let file = tempfile::tempfile().unwrap();
        let (tx_sock, rx_sock) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let file_fd = OwnedFd::from(file.try_clone().unwrap());
        let moved_raw = file_fd.as_raw_fd();

        fn body(fds: Vec<OwnedFd>, moved_raw: RawFd) {
            let [file, sock]: [OwnedFd; 2] = fds.try_into().unwrap();
            assert_eq!(file.as_raw_fd(), moved_raw);
            // Something opened here must not show up in the shared table.
            let private =
                rustix::fs::open("/", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
            let n = private.as_raw_fd().to_ne_bytes();
            rustix::net::send(&sock, &n, rustix::net::SendFlags::empty()).unwrap();
            // Keep `private` open until the parent has checked.
            let mut buf = [0u8; 1];
            rustix::net::recv(&sock, &mut buf, rustix::net::RecvFlags::empty()).unwrap();
            drop(file);
        }

        // SAFETY: `body` only uses the descriptors it is given.
        let handle = unsafe {
            spawn_isolated(
                "isolated-test".into(),
                vec![file_fd, tx_sock],
                moved_raw,
                body,
            )
        }
        .unwrap();

        let mut buf = [0u8; 4];
        rustix::net::recv(&rx_sock, &mut buf, rustix::net::RecvFlags::empty()).unwrap();
        let private_raw = RawFd::from_ne_bytes(buf);

        // Either the number is unused in our table, or it is some other
        // file of ours; it is never the directory opened over there.
        match rustix::io::fcntl_getfd(unsafe { std::os::fd::BorrowedFd::borrow_raw(private_raw) }) {
            Err(rustix::io::Errno::BADF) => {}
            Ok(_) => {
                let ours = unsafe { std::os::fd::BorrowedFd::borrow_raw(private_raw) };
                let root =
                    rustix::fs::open("/", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
                assert!(private_raw == root.as_raw_fd() || !same_file(ours, &root));
            }
            Err(e) => panic!("{e}"),
        }

        // The moved descriptor was closed in our table (the number may
        // have been reused by `root` above, but not for `file`).
        if rustix::io::fcntl_getfd(unsafe { std::os::fd::BorrowedFd::borrow_raw(moved_raw) })
            .is_ok()
        {
            let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(moved_raw) };
            assert!(!same_file(fd, &file));
        }

        rustix::net::send(&rx_sock, &[0], rustix::net::SendFlags::empty()).unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn inherited_fds_are_closed() {
        let file = tempfile::tempfile().unwrap();
        let raw = file.as_raw_fd();

        fn body(_fds: Vec<OwnedFd>, raw: RawFd) {
            let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw) };
            assert_eq!(
                rustix::io::fcntl_getfd(fd).unwrap_err(),
                rustix::io::Errno::BADF
            );
            // stderr stays usable
            let stderr = unsafe { std::os::fd::BorrowedFd::borrow_raw(2) };
            rustix::io::fcntl_getfd(stderr).unwrap();
        }

        // SAFETY: `body` only checks that `raw` is closed in its table.
        unsafe { spawn_isolated("isolated-test".into(), vec![], raw, body) }
            .unwrap()
            .join()
            .unwrap();
        // Still open for us.
        rustix::fs::fstat(&file).unwrap();
    }
}
