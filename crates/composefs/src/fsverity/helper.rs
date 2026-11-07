//! Create files with fs-verity enabled, safely in multithreaded programs.
//!
//! fs-verity can only be enabled on a file when nobody holds it open for
//! writing.  In a multithreaded program that is hard to guarantee: if
//! another thread calls `fork()` while we hold the writable descriptor
//! used to fill the file, the child inherits a copy, and until it calls
//! `exec()` enabling verity fails with `ETXTBSY`.  Linux has no
//! `O_CLOFORK` to prevent this.
//!
//! [`FsVerityHelper`] avoids the race entirely.  It runs its work on
//! threads with a private file descriptor table (see
//! [`crate::isolation`]), so writable descriptors to the new
//! files never exist in the table that `fork()` copies.  Callers feed
//! data in through a pipe ([`VerityWriter`]) or by handing over a source
//! descriptor ([`FsVerityHelper::create_from_fd`]) and get back a
//! read-only descriptor with verity already enabled ([`VerityFile`]).
//!
//! Requests and results travel over Unix sockets, with descriptors
//! passed as `SCM_RIGHTS`, so the kernel translates them between tables.
//! The pipes and sockets on our side can still be inherited by forked
//! children, so nothing here waits for them to be closed: end of data
//! and shutdown are signalled explicitly.
//!
//! Code on the helper threads must not touch process-wide state that
//! holds descriptors (loggers, caches), since those refer to the other
//! table.  In particular it does no logging.

use std::{
    collections::HashMap,
    fs::File,
    io::{self, IoSlice, IoSliceMut, PipeWriter, Write},
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    panic::AssertUnwindSafe,
    path::Path,
    pin::Pin,
    sync::{
        Arc, Condvar, Mutex, RwLock,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::{Context, Poll},
    thread::JoinHandle,
};

use rustix::{
    event::{PollFd, PollFlags, poll},
    fs::{AtFlags, CWD, Mode, OFlags, RenameFlags, linkat, openat, renameat_with, unlinkat},
    io::Errno,
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags, Shutdown, SocketFlags, SocketType,
        recvmsg, sendmsg, socketpair,
    },
    pipe::{PipeFlags, SpliceFlags, fcntl_setpipe_size, pipe_with, splice},
};
use thiserror::Error;
use tokio::{io::AsyncWrite, net::unix::pipe::Sender};

use zerocopy::IntoBytes as _;

use super::{
    Algorithm, DEFAULT_LG_BLOCKSIZE, EnableVerityError, FsVerityHashValue, FsVerityHasher,
    Sha256HashValue, Sha512HashValue,
    ioctl::{fs_ioc_enable_verity_with_algorithm, fs_ioc_measure_verity_with_algorithm},
};

/// The default pipe buffer size on Linux.
const DEFAULT_PIPE_SIZE: u64 = 64 * 1024;
/// Largest pipe buffer we ask for; the default `pipe-max-size` limit.
const MAX_PIPE_SIZE: usize = 1 << 20;
/// Prefix for named temporary files on filesystems without `O_TMPFILE`.
const TMPNAME_PREFIX: &str = ".tmp-verity-";

const KIND_PIPE: u8 = 1;
const KIND_FROM_FD: u8 = 2;
const KIND_REFLINK: u8 = 3;
const FLAG_FORCE_NAMED: u8 = 1;
const FLAG_USERSPACE_DIGEST: u8 = 2;
const REQUEST_LEN: usize = 16;

const COMMIT: u8 = 1;

const STATUS_OK: u8 = 0;
const STATUS_NOT_SUPPORTED: u8 = 1;
const STATUS_SIZE_MISMATCH: u8 = 2;
const STATUS_ERROR: u8 = 3;
const STATUS_REFLINK_UNSUPPORTED: u8 = 4;
const REPLY_HEADER_LEN: usize = 10;
const REPLY_MAX_LEN: usize = 4096;

/// Errors from finishing a file in the [`FsVerityHelper`].
#[derive(Debug, Error)]
pub enum FinishError {
    /// The filesystem doesn't support fs-verity.  The file was written,
    /// but it is *not* protected by fs-verity.
    #[error("filesystem does not support fs-verity; the file was written without it")]
    NotSupported(UnverifiedFile),
    /// The amount of data written didn't match the size given up front.
    /// The file was discarded.
    #[error("size mismatch: expected {expected} bytes, got {actual}")]
    SizeMismatch {
        /// The size given when the file was created.
        expected: u64,
        /// The number of bytes actually received.
        actual: u64,
    },
    /// The helper failed while creating the file.  The file was discarded.
    #[error("fs-verity helper: {context}")]
    Helper {
        /// What the helper was doing.
        context: String,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// [`FsVerityHelper::reflink_from_fd`] was asked to reflink between
    /// filesystems (or on a filesystem) that can't.
    #[error("reflinks are not supported here")]
    ReflinkUnsupported,
    /// Communicating with the helper failed.  The file was discarded.
    #[error("fs-verity helper: {0}")]
    Io(#[from] io::Error),
}

/// Builder for [`FsVerityHelper`].
#[derive(Debug, Clone)]
pub struct FsVerityHelperBuilder {
    max_workers: usize,
    userspace_digest: bool,
    force_named_tmpfile: bool,
}

impl Default for FsVerityHelperBuilder {
    fn default() -> Self {
        Self {
            max_workers: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            userspace_digest: false,
            force_named_tmpfile: false,
        }
    }
}

impl FsVerityHelperBuilder {
    /// Set the maximum number of worker threads (at least 1).
    ///
    /// Each file being written occupies one worker from [`create`] until
    /// [`finish`] or drop, and [`create_from_fd`] occupies one until it
    /// returns.  Requests beyond this limit wait for a free worker, and
    /// until then nothing reads from their pipes; so a thread must not
    /// write to (or create from) one file while holding this many
    /// unfinished others, or it deadlocks.
    ///
    /// [`create`]: FsVerityHelper::create
    /// [`create_from_fd`]: FsVerityHelper::create_from_fd
    /// [`finish`]: VerityWriter::finish
    pub fn max_workers(mut self, n: usize) -> Self {
        self.max_workers = n.max(1);
        self
    }

    /// On filesystems without fs-verity support, compute the digest in
    /// userspace instead, while the data is copied, and return it with
    /// the [`UnverifiedFile`] (see [`UnverifiedFile::userspace_digest`]).
    ///
    /// Off by default.  When on, the helper finds out once per filesystem
    /// whether fs-verity works there (by trying it on an empty file), so
    /// files where the kernel computes the digest aren't hashed twice.
    pub fn userspace_digest(mut self, enable: bool) -> Self {
        self.userspace_digest = enable;
        self
    }

    /// Always use a named temporary file, as on filesystems without
    /// `O_TMPFILE`.  For testing.
    #[cfg(any(test, feature = "test"))]
    #[doc(hidden)]
    pub fn force_named_tmpfile(mut self, force: bool) -> Self {
        self.force_named_tmpfile = force;
        self
    }

    /// Start the helper threads.
    pub fn start(self) -> io::Result<FsVerityHelper> {
        let (ours, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        // SAFETY: code on the helper threads follows the rules in the
        // `# Safety` section of `spawn_isolated`: it does no logging, generates names with
        // the getrandom() syscall rather than a library that might cache
        // a descriptor, and only uses descriptors it opens itself or
        // receives over its sockets.
        #[allow(unsafe_code)]
        let control = unsafe {
            crate::isolation::spawn_isolated(
                "fsverity-helper".into(),
                vec![theirs],
                self.max_workers,
                control_main,
            )
        }?;
        Ok(FsVerityHelper(Arc::new(Inner {
            socket: RwLock::new(Some(ours)),
            control: Mutex::new(Some(control)),
            outstanding: Mutex::new(0),
            idle: Condvar::new(),
            userspace_digest: self.userspace_digest,
            force_named_tmpfile: self.force_named_tmpfile,
        })))
    }
}

/// A handle to the fs-verity helper threads.
///
/// Cloning the handle is cheap; all clones share the same threads.  The
/// threads exit when [`shutdown`](Self::shutdown) is called or the last
/// handle (including those held by [`VerityWriter`]s) is dropped.
/// Dropping the last handle waits for the threads to exit, so avoid
/// doing that on an async runtime thread.
#[derive(Debug, Clone)]
pub struct FsVerityHelper(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    /// Our end of the request socket; `None` once shut down.
    socket: RwLock<Option<OwnedFd>>,
    control: Mutex<Option<JoinHandle<()>>>,
    /// Number of requests in progress.
    outstanding: Mutex<usize>,
    idle: Condvar,
    userspace_digest: bool,
    force_named_tmpfile: bool,
}

impl FsVerityHelper {
    /// Return a builder to configure the helper.
    pub fn builder() -> FsVerityHelperBuilder {
        FsVerityHelperBuilder::default()
    }

    /// Start a helper with the default configuration.
    pub fn start() -> io::Result<Self> {
        Self::builder().start()
    }

    /// Start writing a new file of `size` bytes in `dirfd`, to be
    /// protected by fs-verity with hash type `H`.
    pub fn create<H: FsVerityHashValue>(
        &self,
        dirfd: impl AsFd,
        size: u64,
    ) -> io::Result<VerityWriter> {
        self.create_with_algorithm(dirfd, size, H::ALGORITHM)
    }

    /// Like [`create`](Self::create), with the algorithm chosen at runtime.
    pub fn create_with_algorithm(
        &self,
        dirfd: impl AsFd,
        size: u64,
        algorithm: Algorithm,
    ) -> io::Result<VerityWriter> {
        let dir = dirfd.as_fd().try_clone_to_owned()?;
        let (pipe_r, pipe_w) = pipe_with(PipeFlags::CLOEXEC)?;
        if size > DEFAULT_PIPE_SIZE {
            // Best effort: a bigger buffer means fewer context switches.
            let want = usize::try_from(size).map_or(MAX_PIPE_SIZE, |s| s.min(MAX_PIPE_SIZE));
            let _ = fcntl_setpipe_size(&pipe_w, want);
        }

        let (reply, outstanding) =
            self.request(KIND_PIPE, algorithm, size, dir.as_fd(), pipe_r.as_fd())?;
        Ok(VerityWriter {
            pipe: Some(Pipe::Blocking(PipeWriter::from(pipe_w))),
            reply,
            dir: Some(dir),
            size,
            _outstanding: outstanding,
        })
    }

    /// Create a new file in `dirfd` with the entire contents of `src`
    /// (which must be `size` bytes long), protected by fs-verity with
    /// hash type `H`.
    ///
    /// The data is reflinked if the filesystem supports it, and copied
    /// in the kernel otherwise.  `src`'s file offset is not used or
    /// changed.
    pub fn create_from_fd<H: FsVerityHashValue>(
        &self,
        dirfd: impl AsFd,
        src: impl AsFd,
        size: u64,
    ) -> Result<VerityFile, FinishError> {
        let dir = dirfd.as_fd().try_clone_to_owned()?;
        let (reply, _outstanding) =
            self.request(KIND_FROM_FD, H::ALGORITHM, size, dir.as_fd(), src.as_fd())?;
        receive_reply(&reply, dir, size)
    }

    /// Like [`create_from_fd`](Self::create_from_fd), but only by reflink:
    /// fails with [`FinishError::ReflinkUnsupported`] rather than copying.
    pub fn reflink_from_fd<H: FsVerityHashValue>(
        &self,
        dirfd: impl AsFd,
        src: impl AsFd,
        size: u64,
    ) -> Result<VerityFile, FinishError> {
        let dir = dirfd.as_fd().try_clone_to_owned()?;
        let (reply, _outstanding) =
            self.request(KIND_REFLINK, H::ALGORITHM, size, dir.as_fd(), src.as_fd())?;
        receive_reply(&reply, dir, size)
    }

    /// Block until all files being written have been finished or dropped.
    ///
    /// Calling this while holding a [`VerityWriter`] deadlocks.
    pub fn wait(&self) {
        let mut n = self.0.outstanding.lock().unwrap();
        while *n > 0 {
            n = self.0.idle.wait(n).unwrap();
        }
    }

    /// Stop the helper threads and wait for them to exit.
    ///
    /// Fails if files are still being written; use [`wait`](Self::wait)
    /// first.  Afterwards, creating files with any handle fails.
    /// Calling this again does nothing.
    pub fn shutdown(&self) -> io::Result<()> {
        {
            let mut socket = self.0.socket.write().unwrap();
            let outstanding = *self.0.outstanding.lock().unwrap();
            if outstanding > 0 {
                return Err(io::Error::other(format!(
                    "fs-verity helper still has {outstanding} files in progress"
                )));
            }
            close_socket(socket.take());
        }
        self.0.join()
    }

    /// Send a request, returning our end of its reply socket.
    fn request(
        &self,
        kind: u8,
        algorithm: Algorithm,
        size: u64,
        dir: BorrowedFd<'_>,
        data: BorrowedFd<'_>,
    ) -> io::Result<(OwnedFd, Outstanding)> {
        let socket = self.0.socket.read().unwrap();
        let Some(socket) = socket.as_ref() else {
            return Err(io::Error::other("fs-verity helper has been shut down"));
        };
        // Registered before the request goes out (and while `socket` is
        // held) so that shutdown() can't race with it.
        let outstanding = Outstanding::new(&self.0);

        let (ours, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;

        let mut msg = [0u8; REQUEST_LEN];
        msg[0] = kind;
        if self.0.force_named_tmpfile {
            msg[1] |= FLAG_FORCE_NAMED;
        }
        if self.0.userspace_digest {
            msg[1] |= FLAG_USERSPACE_DIGEST;
        }
        msg[2] = algorithm.kernel_id();
        msg[3] = algorithm.lg_blocksize();
        msg[4..12].copy_from_slice(&size.to_le_bytes());
        msg[12..16].copy_from_slice(&0o644u32.to_le_bytes());

        send_with_fds(socket, &msg, &[dir, data, theirs.as_fd()])?;
        Ok((ours, outstanding))
    }
}

/// Signal end-of-stream on a socket even if forked children hold copies
/// of it, then close our copy.
fn close_socket(socket: Option<OwnedFd>) {
    if let Some(socket) = socket {
        let _ = rustix::net::shutdown(&socket, Shutdown::Write);
    }
}

impl Inner {
    fn join(&self) -> io::Result<()> {
        match self.control.lock().unwrap().take() {
            Some(handle) => handle
                .join()
                .map_err(|_| io::Error::other("fs-verity helper thread panicked")),
            None => Ok(()),
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Writers hold a reference, so none can be in progress here.
        close_socket(self.socket.get_mut().unwrap().take());
        if let Err(e) = self.join() {
            log::error!("{e}");
        }
    }
}

/// Counts a request as in progress for as long as it lives.
#[derive(Debug)]
struct Outstanding(Arc<Inner>);

impl Outstanding {
    fn new(inner: &Arc<Inner>) -> Self {
        *inner.outstanding.lock().unwrap() += 1;
        Self(Arc::clone(inner))
    }
}

impl Drop for Outstanding {
    fn drop(&mut self) {
        let mut n = self.0.outstanding.lock().unwrap();
        *n -= 1;
        if *n == 0 {
            self.0.idle.notify_all();
        }
    }
}

#[derive(Debug)]
enum Pipe {
    Blocking(PipeWriter),
    Async(Sender),
}

/// Writes the contents of a new file that will be protected by fs-verity.
///
/// Created by [`FsVerityHelper::create`].  Write exactly the size given
/// there, via [`Write`], [`AsyncWrite`] or [`pipe_mut`](Self::pipe_mut),
/// then call [`finish`](Self::finish).  Dropping the writer without
/// finishing discards the file.
///
/// If the helper fails unexpectedly while data is still being written,
/// writes fail with `EPIPE`; programs that don't ignore `SIGPIPE` (Rust
/// programs do by default) are killed by it instead.
#[derive(Debug)]
pub struct VerityWriter {
    pipe: Option<Pipe>,
    reply: OwnedFd,
    dir: Option<OwnedFd>,
    size: u64,
    _outstanding: Outstanding,
}

impl VerityWriter {
    /// Return the write end of the pipe that feeds the file.
    ///
    /// Writing to it directly lets [`std::io::copy`] move data from a
    /// file or socket with `splice()`, without copying it through
    /// userspace.
    pub fn pipe_mut(&mut self) -> io::Result<&mut PipeWriter> {
        if let Some(Pipe::Async(_)) = &self.pipe {
            let Some(Pipe::Async(sender)) = self.pipe.take() else {
                unreachable!()
            };
            self.pipe = Some(Pipe::Blocking(PipeWriter::from(sender.into_blocking_fd()?)));
        }
        match &mut self.pipe {
            Some(Pipe::Blocking(pipe)) => Ok(pipe),
            _ => unreachable!("pipe is only taken in finish()"),
        }
    }

    fn async_pipe(&mut self) -> io::Result<&mut Sender> {
        if let Some(Pipe::Blocking(_)) = &self.pipe {
            let Some(Pipe::Blocking(pipe)) = self.pipe.take() else {
                unreachable!()
            };
            // Sets O_NONBLOCK and registers with the current runtime.
            self.pipe = Some(Pipe::Async(Sender::from_owned_fd(pipe.into())?));
        }
        match &mut self.pipe {
            Some(Pipe::Async(sender)) => Ok(sender),
            _ => unreachable!("pipe is only taken in finish()"),
        }
    }

    /// Finish writing: enable fs-verity on the file and return it.
    ///
    /// This blocks while the kernel reads the file to build the Merkle
    /// tree; see [`finish_async`](Self::finish_async).
    pub fn finish(mut self) -> Result<VerityFile, FinishError> {
        // All writes have completed, so everything is in the pipe.
        drop(self.pipe.take());
        send_with_fds(&self.reply, &[COMMIT], &[])?;
        let dir = self.dir.take().expect("dir is only taken here");
        receive_reply(&self.reply, dir, self.size)
    }

    /// Like [`finish`](Self::finish), but runs on tokio's blocking pool.
    pub async fn finish_async(self) -> Result<VerityFile, FinishError> {
        tokio::task::spawn_blocking(move || self.finish())
            .await
            .map_err(io::Error::other)?
    }
}

impl Drop for VerityWriter {
    fn drop(&mut self) {
        // Tells the worker to give up (unless we already committed).
        let _ = rustix::net::shutdown(&self.reply, Shutdown::Write);
    }
}

impl Write for VerityWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pipe_mut()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for VerityWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let sender = self.get_mut().async_pipe()?;
        Pin::new(sender).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Where a finished file was put by `publish()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Published {
    /// The file was put in place.
    Created,
    /// Something already existed at the path; our file was discarded.
    AlreadyExists,
}

/// How the data of a file got there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CopyMethod {
    /// Written through a [`VerityWriter`].
    Written = 0,
    /// Reflinked from the source file.
    Reflinked = 1,
    /// Copied from the source file.
    Copied = 2,
}

impl CopyMethod {
    fn decode(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Written),
            1 => Some(Self::Reflinked),
            2 => Some(Self::Copied),
            _ => None,
        }
    }
}

/// A finished, read-only file not yet linked at its final path.
#[derive(Debug)]
struct Staged {
    fd: OwnedFd,
    /// For files created without `O_TMPFILE`: the directory and
    /// temporary name, removed on drop.
    name: Option<(OwnedFd, String)>,
}

impl Staged {
    fn publish(mut self, dir: impl AsFd, path: &Path) -> io::Result<Published> {
        let result = match &self.name {
            None => linkat(
                CWD,
                thread_self_fd(&self.fd),
                &dir,
                path,
                AtFlags::SYMLINK_FOLLOW,
            ),
            Some((tmpdir, name)) => {
                renameat_with(tmpdir, name.as_str(), &dir, path, RenameFlags::NOREPLACE)
            }
        };
        match result {
            Ok(()) => {
                // A renamed file no longer has its temporary name.
                self.name = None;
                Ok(Published::Created)
            }
            Err(Errno::EXIST) => Ok(Published::AlreadyExists),
            Err(e) => Err(e.into()),
        }
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if let Some((dir, name)) = &self.name {
            let _ = unlinkat(dir, name.as_str(), AtFlags::empty());
        }
    }
}

/// A read-only file with fs-verity enabled.
#[derive(Debug)]
pub struct VerityFile {
    staged: Staged,
    algorithm: Algorithm,
    digest: Vec<u8>,
    method: CopyMethod,
}

impl VerityFile {
    /// The algorithm fs-verity was enabled with.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The fs-verity digest as measured by the kernel, or `None` if `H`
    /// doesn't match [`algorithm`](Self::algorithm).
    pub fn digest<H: FsVerityHashValue>(&self) -> Option<H> {
        if self.algorithm != H::ALGORITHM {
            return None;
        }
        H::read_from_bytes(&self.digest).ok()
    }

    /// The raw fs-verity digest as measured by the kernel.
    pub fn digest_bytes(&self) -> &[u8] {
        &self.digest
    }

    /// How the data got into the file.
    pub fn copy_method(&self) -> CopyMethod {
        self.method
    }

    /// Atomically put the file at `path` relative to `dir`, unless
    /// something already exists there.
    pub fn publish(self, dir: impl AsFd, path: impl AsRef<Path>) -> io::Result<Published> {
        self.staged.publish(dir, path.as_ref())
    }
}

impl AsFd for VerityFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.staged.fd.as_fd()
    }
}

/// A read-only file written on a filesystem without fs-verity support.
///
/// It is *not* protected by fs-verity.  See [`FinishError::NotSupported`].
#[derive(Debug)]
pub struct UnverifiedFile {
    staged: Staged,
    algorithm: Algorithm,
    digest: Option<Vec<u8>>,
    method: CopyMethod,
}

impl UnverifiedFile {
    /// The fs-verity digest computed in userspace while the data was
    /// copied, if the helper was configured with
    /// [`userspace_digest`](FsVerityHelperBuilder::userspace_digest) and
    /// `H` matches the requested algorithm.
    ///
    /// This is *not* enforced by the kernel: nothing stops the file from
    /// being changed later.
    pub fn userspace_digest<H: FsVerityHashValue>(&self) -> Option<H> {
        if self.algorithm != H::ALGORITHM {
            return None;
        }
        H::read_from_bytes(self.digest.as_deref()?).ok()
    }

    /// How the data got into the file.
    pub fn copy_method(&self) -> CopyMethod {
        self.method
    }

    /// Atomically put the file at `path` relative to `dir`, unless
    /// something already exists there.
    pub fn publish(self, dir: impl AsFd, path: impl AsRef<Path>) -> io::Result<Published> {
        self.staged.publish(dir, path.as_ref())
    }
}

impl AsFd for UnverifiedFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.staged.fd.as_fd()
    }
}

/// The `/proc` path of a descriptor in the calling thread's table.
///
/// `/proc/self/fd` would be the table of the thread group leader, which
/// is the wrong one on the helper threads.
fn thread_self_fd(fd: impl AsFd) -> String {
    format!("/proc/thread-self/fd/{}", fd.as_fd().as_raw_fd())
}

fn send_with_fds(socket: impl AsFd, data: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(io::Error::other("too many descriptors"));
    }
    // NOSIGNAL: if the other side is gone, report EPIPE instead of
    // killing the process with SIGPIPE.
    sendmsg(
        socket,
        &[IoSlice::new(data)],
        &mut control,
        SendFlags::NOSIGNAL,
    )?;
    Ok(())
}

/// Receive one message; returns the data length (0 means the peer
/// closed the socket) and any descriptors that came with it.
fn recv_with_fds(socket: impl AsFd, buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = loop {
        match recvmsg(
            &socket,
            &mut [IoSliceMut::new(buf)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        ) {
            Err(Errno::INTR) => continue,
            other => break other?,
        }
    };
    let mut fds = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = message {
            fds.extend(received);
        }
    }
    if msg
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(io::Error::other("truncated message"));
    }
    Ok((msg.bytes, fds))
}

fn receive_reply(reply: &OwnedFd, dir: OwnedFd, expected: u64) -> Result<VerityFile, FinishError> {
    let mut buf = vec![0u8; REPLY_MAX_LEN];
    let (len, mut fds) = recv_with_fds(reply, &mut buf)?;
    if len == 0 {
        return Err(io::Error::other("fs-verity helper exited without replying").into());
    }
    let malformed = || io::Error::other("malformed reply from fs-verity helper");
    if len < REPLY_HEADER_LEN {
        return Err(malformed().into());
    }
    let buf = &buf[..len];
    let status = buf[0];
    let aux = u64::from_le_bytes(buf[1..9].try_into().unwrap());
    let digest_len = usize::from(buf[9]);
    let (digest, text) = buf[REPLY_HEADER_LEN..]
        .split_at_checked(digest_len)
        .ok_or_else(malformed)?;
    let text = String::from_utf8_lossy(text).into_owned();

    if let STATUS_OK | STATUS_NOT_SUPPORTED = status {
        // Take charge of the temporary name (if any) before anything
        // else can fail, so it gets cleaned up.
        let fd = fds.pop().ok_or_else(malformed)?;
        let name = (!text.is_empty()).then_some((dir, text));
        let staged = Staged { fd, name };
        let algorithm = decode_algorithm(aux as u8, (aux >> 8) as u8).ok_or_else(malformed)?;
        let method = CopyMethod::decode((aux >> 16) as u8).ok_or_else(malformed)?;
        if status == STATUS_NOT_SUPPORTED {
            return Err(FinishError::NotSupported(UnverifiedFile {
                staged,
                algorithm,
                digest: (!digest.is_empty()).then(|| digest.to_vec()),
                method,
            }));
        }
        return Ok(VerityFile {
            staged,
            algorithm,
            digest: digest.to_vec(),
            method,
        });
    }

    match status {
        STATUS_REFLINK_UNSUPPORTED => Err(FinishError::ReflinkUnsupported),
        STATUS_SIZE_MISMATCH => Err(FinishError::SizeMismatch {
            expected,
            actual: aux,
        }),
        STATUS_ERROR => {
            let errno = aux as i32;
            let source = if errno != 0 {
                io::Error::from_raw_os_error(errno)
            } else {
                io::Error::other(text.clone())
            };
            Err(FinishError::Helper {
                context: text,
                source,
            })
        }
        _ => Err(malformed().into()),
    }
}

fn decode_algorithm(kernel_id: u8, lg_blocksize: u8) -> Option<Algorithm> {
    match kernel_id {
        1 => Some(Algorithm::Sha256 { lg_blocksize }),
        2 => Some(Algorithm::Sha512 { lg_blocksize }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Everything below runs on the isolated helper threads.  No logging here:
// see the module documentation.
// ---------------------------------------------------------------------------

/// A request, as received by the control thread.
struct Job {
    kind: u8,
    force_named: bool,
    userspace_digest: bool,
    algorithm: Algorithm,
    size: u64,
    mode: Mode,
    dir: OwnedFd,
    data: OwnedFd,
    reply: OwnedFd,
}

fn control_main(fds: Vec<OwnedFd>, max_workers: usize) {
    let [socket]: [OwnedFd; 1] = fds.try_into().expect("one control socket");
    let (tx, rx) = mpsc::channel::<Job>();
    let rx = Arc::new(Mutex::new(rx));
    // Jobs handed out and not yet finished.  Counted here rather than by
    // the workers so that a job still sitting in the queue counts too.
    let busy = Arc::new(AtomicUsize::new(0));
    let probes = Arc::new(Probes::default());
    let mut workers: Vec<JoinHandle<()>> = Vec::new();

    loop {
        let mut buf = [0u8; 64];
        let (len, fds) = match recv_with_fds(&socket, &mut buf) {
            Ok((0, _)) | Err(_) => break,
            Ok(msg) => msg,
        };
        let job = match decode_job(&buf[..len], fds) {
            Ok(job) => job,
            Err(Some(reply)) => {
                send_error(&reply, "decoding request", &io::Error::other("malformed"));
                continue;
            }
            Err(None) => continue,
        };

        // Threads spawned here share our private descriptor table.
        if busy.load(Ordering::SeqCst) >= workers.len() && workers.len() < max_workers {
            let rx = Arc::clone(&rx);
            let busy = Arc::clone(&busy);
            let probes = Arc::clone(&probes);
            match std::thread::Builder::new()
                .name("fsverity-worker".into())
                .spawn(move || worker_main(&rx, &busy, &probes))
            {
                Ok(handle) => workers.push(handle),
                Err(e) if workers.is_empty() => {
                    send_error(&job.reply, "starting fs-verity worker", &e);
                    continue;
                }
                // Queue it for the workers we have.
                Err(_) => {}
            }
        }
        busy.fetch_add(1, Ordering::SeqCst);
        if tx.send(job).is_err() {
            break;
        }
    }

    drop(tx);
    for worker in workers {
        // Workers catch panics from jobs, so this can't fail.
        let _ = worker.join();
    }
}

/// Decode a request.  On failure, returns its reply socket if it has one.
fn decode_job(msg: &[u8], fds: Vec<OwnedFd>) -> Result<Job, Option<OwnedFd>> {
    let [dir, data, reply]: [OwnedFd; 3] = fds.try_into().map_err(|_| None)?;
    let decode = || -> Option<_> {
        let msg: &[u8; REQUEST_LEN] = msg.try_into().ok()?;
        Some((
            msg[0],
            msg[1] & FLAG_FORCE_NAMED != 0,
            msg[1] & FLAG_USERSPACE_DIGEST != 0,
            decode_algorithm(msg[2], msg[3])?,
            u64::from_le_bytes(msg[4..12].try_into().ok()?),
            Mode::from_raw_mode(u32::from_le_bytes(msg[12..16].try_into().ok()?)),
        ))
    };
    match decode() {
        Some((
            kind @ (KIND_PIPE | KIND_FROM_FD | KIND_REFLINK),
            force_named,
            userspace_digest,
            algorithm,
            size,
            mode,
        )) => Ok(Job {
            kind,
            force_named,
            userspace_digest,
            algorithm,
            size,
            mode,
            dir,
            data,
            reply,
        }),
        _ => Err(Some(reply)),
    }
}

fn worker_main(rx: &Mutex<mpsc::Receiver<Job>>, busy: &AtomicUsize, probes: &Probes) {
    loop {
        let job = rx.lock().unwrap().recv();
        match job {
            Ok(job) => {
                // A panic drops the job, and with it the reply socket, so
                // the caller gets an error; the worker carries on.
                let _ = std::panic::catch_unwind(AssertUnwindSafe(|| run_job(job, probes)));
                busy.fetch_sub(1, Ordering::SeqCst);
            }
            Err(mpsc::RecvError) => break,
        }
    }
}

/// The file being built, unlinked on drop if it has a name.
struct Tmpfile<'a> {
    file: Option<File>,
    dir: &'a OwnedFd,
    name: Option<String>,
}

impl<'a> Tmpfile<'a> {
    fn create(dir: &'a OwnedFd, mode: Mode, force_named: bool) -> io::Result<Self> {
        if !force_named {
            match openat(
                dir,
                ".",
                OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
                mode,
            ) {
                Ok(fd) => {
                    return Ok(Self {
                        file: Some(fd.into()),
                        dir,
                        name: None,
                    });
                }
                Err(Errno::OPNOTSUPP | Errno::ISDIR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        for _ in 0..16 {
            let name = tmpname()?;
            match openat(
                dir,
                name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                mode,
            ) {
                Ok(fd) => {
                    return Ok(Self {
                        file: Some(fd.into()),
                        dir,
                        name: Some(name),
                    });
                }
                Err(Errno::EXIST) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(Errno::EXIST.into())
    }

    fn file(&self) -> &File {
        self.file.as_ref().expect("file is open")
    }
}

impl Drop for Tmpfile<'_> {
    fn drop(&mut self) {
        if let Some(name) = &self.name {
            let _ = unlinkat(self.dir, name.as_str(), AtFlags::empty());
        }
    }
}

/// A random temporary name.  Uses the getrandom() syscall directly,
/// since random number libraries may keep a descriptor in a static.
fn tmpname() -> io::Result<String> {
    let mut bytes = [0u8; 8];
    let mut filled = 0;
    while filled < bytes.len() {
        match rustix::rand::getrandom(&mut bytes[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(n) => filled += n,
            Err(Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(format!("{TMPNAME_PREFIX}{}", hex::encode(bytes)))
}

/// Whether fs-verity works on each filesystem seen so far, by `st_dev`.
#[derive(Default)]
struct Probes(Mutex<HashMap<u64, bool>>);

impl Probes {
    /// Find out whether fs-verity is supported for files in `dir`, by
    /// trying it on an empty file the first time we see the filesystem.
    /// When unsure, says it is.
    fn verity_supported(&self, dir: &OwnedFd, algorithm: Algorithm, force_named: bool) -> bool {
        let Ok(stat) = rustix::fs::fstat(dir) else {
            return true;
        };
        let mut known = self.0.lock().unwrap();
        *known
            .entry(stat.st_dev)
            .or_insert_with(|| probe_verity(dir, algorithm, force_named))
    }
}

fn probe_verity(dir: &OwnedFd, algorithm: Algorithm, force_named: bool) -> bool {
    let Ok(mut tmp) = Tmpfile::create(dir, Mode::from_raw_mode(0o600), force_named) else {
        return true;
    };
    let Ok(ro) = rustix::fs::open(
        thread_self_fd(tmp.file()),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return true;
    };
    drop(tmp.file.take());
    !matches!(
        fs_ioc_enable_verity_with_algorithm(&ro, algorithm),
        Err(EnableVerityError::FilesystemNotSupported)
    )
}

/// Computes an fs-verity digest in userspace, for a runtime algorithm.
enum Hasher {
    Sha256(FsVerityHasher<Sha256HashValue>),
    Sha512(FsVerityHasher<Sha512HashValue>),
}

impl Hasher {
    fn new(algorithm: Algorithm) -> Option<Self> {
        // FsVerityHasher only does the default block size.
        if algorithm.lg_blocksize() != DEFAULT_LG_BLOCKSIZE {
            return None;
        }
        Some(match algorithm {
            Algorithm::Sha256 { .. } => Self::Sha256(FsVerityHasher::new()),
            Algorithm::Sha512 { .. } => Self::Sha512(FsVerityHasher::new()),
        })
    }

    fn update(&mut self, data: &[u8]) {
        let result = match self {
            Self::Sha256(h) => h.write_all(data),
            Self::Sha512(h) => h.write_all(data),
        };
        result.expect("hashing doesn't fail");
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha256(mut h) => h.digest().as_bytes().to_vec(),
            Self::Sha512(mut h) => h.digest().as_bytes().to_vec(),
        }
    }
}

fn run_job(job: Job, probes: &Probes) {
    let Job {
        kind,
        force_named,
        userspace_digest,
        algorithm,
        size,
        mode,
        dir,
        data,
        reply,
    } = job;

    let tmp = Tmpfile::create(&dir, mode, force_named);
    let file = tmp.as_ref().ok().map(Tmpfile::file);
    // Hash while copying only where the kernel can't do it for us.
    let mut hasher = match file {
        Some(_) if userspace_digest && !probes.verity_supported(&dir, algorithm, force_named) => {
            Hasher::new(algorithm)
        }
        _ => None,
    };

    let copied = match (kind, file) {
        // Even if creating the file failed, the data is consumed so the
        // writer doesn't block, and the error is reported on commit.
        (KIND_PIPE, _) => match receive_pipe(&data, &reply, file, hasher.as_mut()) {
            None => return,
            Some((n, None)) => Ok(Some((n, CopyMethod::Written))),
            Some((_, Some(e))) => Err(e),
        },
        (_, Some(file)) => copy_from_fd(&data, file, kind == KIND_REFLINK, hasher.as_mut()),
        (_, None) => Ok(Some((0, CopyMethod::Copied))),
    };
    drop(data);

    let mut tmp = match tmp {
        Ok(tmp) => tmp,
        Err(e) => return send_error(&reply, "creating file", &e),
    };
    let (copied, method) = match copied {
        Ok(Some(copied)) => copied,
        Ok(None) => {
            let _ = send_reply(&reply, STATUS_REFLINK_UNSUPPORTED, 0, &[], "", None);
            return;
        }
        Err(e) => return send_error(&reply, "writing file", &e),
    };
    if copied != size {
        let _ = send_reply(&reply, STATUS_SIZE_MISMATCH, copied, &[], "", None);
        return;
    }

    let ro = match rustix::fs::open(
        thread_self_fd(tmp.file()),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) => return send_error(&reply, "reopening file read-only", &e.into()),
    };
    drop(tmp.file.take());

    let name = tmp.name.as_deref().unwrap_or("");
    let aux = u64::from(algorithm.kernel_id())
        | (u64::from(algorithm.lg_blocksize()) << 8)
        | (u64::from(method as u8) << 16);
    let sent = match fs_ioc_enable_verity_with_algorithm(&ro, algorithm) {
        Ok(()) => match fs_ioc_measure_verity_with_algorithm(&ro, algorithm) {
            Ok(digest) => send_reply(&reply, STATUS_OK, aux, &digest, name, Some(ro.as_fd())),
            Err(e) => {
                return send_error(&reply, "measuring fs-verity", &io::Error::other(e));
            }
        },
        Err(EnableVerityError::FilesystemNotSupported) => {
            let digest = hasher.map(Hasher::finish).unwrap_or_default();
            send_reply(
                &reply,
                STATUS_NOT_SUPPORTED,
                aux,
                &digest,
                name,
                Some(ro.as_fd()),
            )
        }
        Err(EnableVerityError::Io(e)) => return send_error(&reply, "enabling fs-verity", &e),
        Err(EnableVerityError::FileOpenedForWrite) => {
            return send_error(&reply, "enabling fs-verity", &Errno::TXTBSY.into());
        }
        Err(e) => return send_error(&reply, "enabling fs-verity", &io::Error::other(e)),
    };
    if sent.is_ok() {
        // The name now belongs to the caller.
        tmp.name = None;
    }
}

/// Copy data from the pipe into `file` until the writer commits.
///
/// Returns `None` if the writer gave up, otherwise the number of bytes
/// received and the first error writing them.  After an error (or with
/// no `file`) the data is read and discarded, so the writer doesn't get
/// stuck.
///
/// End of data is signalled by the commit message, not by the pipe
/// closing: a forked child may still hold a copy of the write end.
fn receive_pipe(
    pipe: &OwnedFd,
    reply: &OwnedFd,
    file: Option<&File>,
    hasher: Option<&mut Hasher>,
) -> Option<(u64, Option<io::Error>)> {
    let mut state = PipeState {
        total: 0,
        error: None,
        // splice() keeps the data out of userspace, where we'd hash it.
        use_splice: file.is_some() && hasher.is_none(),
        hasher,
        buf: Vec::new(),
    };
    if let Err(e) = rustix::fs::fcntl_setfl(pipe, OFlags::NONBLOCK) {
        state.error = Some(e.into());
    }
    let mut pipe_open = true;

    loop {
        let mut fds = [
            PollFd::new(reply, PollFlags::IN),
            PollFd::new(pipe, PollFlags::IN),
        ];
        let n = if pipe_open { 2 } else { 1 };
        match poll(&mut fds[..n], None) {
            Ok(_) | Err(Errno::INTR) => {}
            Err(_) => return None,
        }
        let reply_ready = !fds[0].revents().is_empty();
        let pipe_ready = pipe_open && !fds[1].revents().is_empty();

        if pipe_ready && state.pump(pipe, file) {
            pipe_open = false;
        }
        if reply_ready {
            let mut msg = [0u8; 1];
            return match recv_with_fds(reply, &mut msg) {
                Ok((1, _)) if msg[0] == COMMIT => {
                    // All writes finished before the commit was sent.
                    if pipe_open {
                        state.pump(pipe, file);
                    }
                    Some((state.total, state.error))
                }
                _ => None,
            };
        }
    }
}

struct PipeState<'a> {
    total: u64,
    error: Option<io::Error>,
    use_splice: bool,
    hasher: Option<&'a mut Hasher>,
    buf: Vec<u8>,
}

impl PipeState<'_> {
    /// Move whatever is in the (non-blocking) pipe into `file`.
    /// Returns true at end of file.
    fn pump(&mut self, pipe: &OwnedFd, file: Option<&File>) -> bool {
        loop {
            if let (true, None, Some(file)) = (self.use_splice, &self.error, file) {
                match splice(pipe, None, file, None, MAX_PIPE_SIZE, SpliceFlags::MOVE) {
                    Ok(0) => return true,
                    Ok(n) => self.total += n as u64,
                    Err(Errno::AGAIN) => return false,
                    Err(Errno::INTR) => {}
                    // This filesystem can't splice; nothing was consumed.
                    Err(Errno::INVAL) => self.use_splice = false,
                    Err(e) => self.error = Some(e.into()),
                }
                continue;
            }

            if self.buf.is_empty() {
                self.buf.resize(128 * 1024, 0);
            }
            match rustix::io::read(pipe, &mut self.buf) {
                Ok(0) => return true,
                Ok(n) => {
                    self.total += n as u64;
                    if let (Some(mut file), None) = (file, &self.error) {
                        if let Some(hasher) = self.hasher.as_deref_mut() {
                            hasher.update(&self.buf[..n]);
                        }
                        if let Err(e) = file.write_all(&self.buf[..n]) {
                            self.error = Some(e);
                        }
                    }
                }
                Err(Errno::AGAIN) => return false,
                Err(Errno::INTR) => {}
                Err(e) => {
                    self.error.get_or_insert(e.into());
                    return true;
                }
            }
        }
    }
}

/// Copy all of `src` into the (empty) `file`: reflink if possible, then
/// (unless `reflink_only`) `copy_file_range()`, then plain reads and
/// writes.  Feeds the data to `hasher`, if any.
///
/// Returns the size and how it was copied, or `None` if `reflink_only`
/// and the filesystems can't reflink.
fn copy_from_fd(
    src: &OwnedFd,
    file: &File,
    reflink_only: bool,
    mut hasher: Option<&mut Hasher>,
) -> io::Result<Option<(u64, CopyMethod)>> {
    match rustix::fs::ioctl_ficlone(file, src) {
        Ok(()) => {
            if let Some(hasher) = hasher {
                hash_file(file, hasher)?;
            }
            return Ok(Some((file.metadata()?.len(), CopyMethod::Reflinked)));
        }
        Err(Errno::OPNOTSUPP | Errno::XDEV) if reflink_only => return Ok(None),
        Err(e) if reflink_only => return Err(e.into()),
        Err(_) => {}
    }

    let mut offset = 0u64;
    // copy_file_range() keeps the data out of userspace, where we'd hash it.
    while hasher.is_none() {
        match rustix::fs::copy_file_range(src, Some(&mut offset), file, None, 1 << 30) {
            Ok(0) => return Ok(Some((offset, CopyMethod::Copied))),
            Ok(_) => {}
            Err(Errno::INTR) => {}
            Err(Errno::XDEV | Errno::INVAL | Errno::OPNOTSUPP | Errno::NOSYS) if offset == 0 => {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }

    let mut buf = vec![0u8; 128 * 1024];
    let mut writer = file;
    loop {
        match rustix::io::pread(src, &mut buf, offset) {
            Ok(0) => return Ok(Some((offset, CopyMethod::Copied))),
            Ok(n) => {
                if let Some(hasher) = hasher.as_deref_mut() {
                    hasher.update(&buf[..n]);
                }
                writer.write_all(&buf[..n])?;
                offset += n as u64;
            }
            Err(Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

fn hash_file(file: &File, hasher: &mut Hasher) -> io::Result<()> {
    let mut buf = vec![0u8; 128 * 1024];
    let mut offset = 0u64;
    loop {
        match rustix::io::pread(file, &mut buf, offset) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                hasher.update(&buf[..n]);
                offset += n as u64;
            }
            Err(Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

fn send_reply(
    reply: &OwnedFd,
    status: u8,
    aux: u64,
    digest: &[u8],
    text: &str,
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let mut msg = Vec::with_capacity(REPLY_HEADER_LEN + digest.len() + text.len());
    msg.push(status);
    msg.extend_from_slice(&aux.to_le_bytes());
    msg.push(u8::try_from(digest.len()).expect("digest fits"));
    msg.extend_from_slice(digest);
    let mut end = text.len().min(REPLY_MAX_LEN - msg.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    msg.extend_from_slice(&text.as_bytes()[..end]);
    let fds: Vec<BorrowedFd<'_>> = fd.into_iter().collect();
    send_with_fds(reply, &msg, &fds)
}

fn send_error(reply: &OwnedFd, context: &str, error: &io::Error) {
    let (errno, text) = match error.raw_os_error() {
        Some(errno) => (errno, context.to_owned()),
        None => (0, format!("{context}: {error}")),
    };
    // If the caller is gone there is nobody left to tell.
    let _ = send_reply(reply, STATUS_ERROR, errno as u32 as u64, &[], &text, None);
}

#[cfg(test)]
mod tests {
    use std::{os::unix::process::ExitStatusExt as _, time::Duration};

    use composefs_ioctls::test_utils_pub::CommandExt as _;
    use rustix::fs::{Mode, OFlags, open};

    use super::*;
    use crate::{
        fsverity::{Sha256HashValue, Sha512HashValue, compute_verity, measure_verity},
        test::tempdir,
    };

    fn open_dir(path: &Path) -> OwnedFd {
        open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn dir_entries(path: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn roundtrip<H: FsVerityHashValue>(force_named: bool) {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::builder()
            .force_named_tmpfile(force_named)
            .start()
            .unwrap();
        let data = b"hello world".repeat(10000);

        let mut w = helper.create::<H>(&dir, data.len() as u64).unwrap();
        w.write_all(&data).unwrap();
        let file = w.finish().unwrap();

        let expected = compute_verity::<H>(&data);
        assert_eq!(file.algorithm(), H::ALGORITHM);
        assert_eq!(file.digest::<H>().unwrap(), expected);
        assert_eq!(measure_verity::<H>(&file).unwrap(), expected);
        if force_named {
            assert_eq!(dir_entries(tmp.path()).len(), 1);
        } else {
            assert!(dir_entries(tmp.path()).is_empty());
        }

        assert_eq!(file.publish(&dir, "obj").unwrap(), Published::Created);
        assert_eq!(dir_entries(tmp.path()), ["obj"]);
        let published = std::fs::File::open(tmp.path().join("obj")).unwrap();
        assert_eq!(measure_verity::<H>(&published).unwrap(), expected);
        assert_eq!(std::fs::read(tmp.path().join("obj")).unwrap(), data);

        // A second identical file finds the first one in place, and its
        // temporary name (if any) is cleaned up.
        let mut w = helper.create::<H>(&dir, data.len() as u64).unwrap();
        w.write_all(&data).unwrap();
        let file = w.finish().unwrap();
        assert_eq!(file.publish(&dir, "obj").unwrap(), Published::AlreadyExists);
        assert_eq!(dir_entries(tmp.path()), ["obj"]);

        helper.shutdown().unwrap();
    }

    #[test]
    fn test_roundtrip_sha256() {
        roundtrip::<Sha256HashValue>(false);
    }

    #[test]
    fn test_roundtrip_sha512() {
        roundtrip::<Sha512HashValue>(false);
    }

    #[test]
    fn test_roundtrip_named() {
        roundtrip::<Sha256HashValue>(true);
    }

    #[test]
    fn test_digest_wrong_type() {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::start().unwrap();
        let file = helper
            .create::<Sha256HashValue>(&dir, 0)
            .unwrap()
            .finish()
            .unwrap();
        assert!(file.digest::<Sha512HashValue>().is_none());
        assert_eq!(
            file.digest::<Sha256HashValue>().unwrap(),
            compute_verity::<Sha256HashValue>(b"")
        );
    }

    #[test]
    fn test_pipe_mut_copy_from_file() {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::start().unwrap();
        let data: Vec<u8> = (0..3_000_000u32).map(|i| i as u8).collect();
        let src_path = tmp.path().join("src");
        std::fs::write(&src_path, &data).unwrap();

        let mut w = helper
            .create::<Sha256HashValue>(&dir, data.len() as u64)
            .unwrap();
        let mut src = std::fs::File::open(&src_path).unwrap();
        std::io::copy(&mut src, w.pipe_mut().unwrap()).unwrap();
        let file = w.finish().unwrap();
        assert_eq!(
            file.digest::<Sha256HashValue>().unwrap(),
            compute_verity::<Sha256HashValue>(&data)
        );
    }

    #[test]
    fn test_size_mismatch() {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        for force_named in [false, true] {
            let helper = FsVerityHelper::builder()
                .force_named_tmpfile(force_named)
                .start()
                .unwrap();
            for (expected, data) in [(5u64, &b"hello world"[..]), (100, b"short")] {
                let mut w = helper.create::<Sha256HashValue>(&dir, expected).unwrap();
                w.write_all(data).unwrap();
                match w.finish() {
                    Err(FinishError::SizeMismatch {
                        expected: e,
                        actual,
                    }) => {
                        assert_eq!(e, expected);
                        assert_eq!(actual, data.len() as u64);
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
            helper.shutdown().unwrap();
            assert!(dir_entries(tmp.path()).is_empty());
        }
    }

    #[test]
    fn test_abort() {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        for force_named in [false, true] {
            let helper = FsVerityHelper::builder()
                .force_named_tmpfile(force_named)
                .start()
                .unwrap();
            let mut w = helper.create::<Sha256HashValue>(&dir, 100).unwrap();
            w.write_all(b"partial").unwrap();
            drop(w);
            helper.wait();
            // The worker cleans up once it notices; shutdown waits for it.
            helper.shutdown().unwrap();
            assert!(dir_entries(tmp.path()).is_empty());
        }
    }

    #[test]
    fn test_create_from_fd() {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::start().unwrap();
        let data = b"some data for reflinking".repeat(1000);
        let src_path = tmp.path().join("src");
        std::fs::write(&src_path, &data).unwrap();
        let src = std::fs::File::open(&src_path).unwrap();

        let file = helper
            .create_from_fd::<Sha256HashValue>(&dir, &src, data.len() as u64)
            .unwrap();
        assert_eq!(
            file.digest::<Sha256HashValue>().unwrap(),
            compute_verity::<Sha256HashValue>(&data)
        );

        assert!(matches!(
            helper.create_from_fd::<Sha256HashValue>(&dir, &src, 1),
            Err(FinishError::SizeMismatch { expected: 1, .. })
        ));
    }

    #[test_with::path(/dev/shm)]
    #[test]
    fn test_not_supported() {
        let tmp = tempfile::TempDir::new_in("/dev/shm").unwrap();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::start().unwrap();
        let mut w = helper.create::<Sha256HashValue>(&dir, 5).unwrap();
        w.write_all(b"hello").unwrap();
        let Err(FinishError::NotSupported(file)) = w.finish() else {
            panic!("expected NotSupported");
        };
        assert_eq!(file.publish(&dir, "obj").unwrap(), Published::Created);
        assert_eq!(std::fs::read(tmp.path().join("obj")).unwrap(), b"hello");
    }

    #[test_with::path(/dev/shm)]
    #[test]
    fn test_userspace_digest() {
        let tmp = tempfile::TempDir::new_in("/dev/shm").unwrap();
        let dir = open_dir(tmp.path());
        let data = b"hash me in userspace".repeat(5000);
        let src_path = tmp.path().join("src");
        std::fs::write(&src_path, &data).unwrap();
        let src = std::fs::File::open(&src_path).unwrap();

        for enabled in [false, true] {
            let helper = FsVerityHelper::builder()
                .userspace_digest(enabled)
                .start()
                .unwrap();

            let mut w = helper
                .create::<Sha512HashValue>(&dir, data.len() as u64)
                .unwrap();
            w.write_all(&data).unwrap();
            let Err(FinishError::NotSupported(file)) = w.finish() else {
                panic!("expected NotSupported");
            };
            assert_eq!(file.copy_method(), CopyMethod::Written);
            assert!(file.userspace_digest::<Sha256HashValue>().is_none());
            assert_eq!(
                file.userspace_digest::<Sha512HashValue>(),
                enabled.then(|| compute_verity::<Sha512HashValue>(&data))
            );

            let Err(FinishError::NotSupported(file)) =
                helper.create_from_fd::<Sha256HashValue>(&dir, &src, data.len() as u64)
            else {
                panic!("expected NotSupported");
            };
            assert_eq!(
                file.userspace_digest::<Sha256HashValue>(),
                enabled.then(|| compute_verity::<Sha256HashValue>(&data))
            );
        }
    }

    /// With verity available, asking for userspace digests changes nothing.
    #[test]
    fn test_userspace_digest_with_verity() {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::builder()
            .userspace_digest(true)
            .start()
            .unwrap();
        for _ in 0..2 {
            let mut w = helper.create::<Sha256HashValue>(&dir, 5).unwrap();
            w.write_all(b"hello").unwrap();
            let file = w.finish().unwrap();
            assert_eq!(file.copy_method(), CopyMethod::Written);
            assert_eq!(
                file.digest::<Sha256HashValue>().unwrap(),
                compute_verity::<Sha256HashValue>(b"hello")
            );
        }
        // The probe leaves nothing behind.
        assert!(dir_entries(tmp.path()).is_empty());
    }

    #[test]
    fn test_reflink_from_fd() {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::start().unwrap();
        let data = b"reflink me".repeat(1000);
        let src_path = tmp.path().join("src");
        std::fs::write(&src_path, &data).unwrap();
        let src = std::fs::File::open(&src_path).unwrap();

        match helper.reflink_from_fd::<Sha256HashValue>(&dir, &src, data.len() as u64) {
            Ok(file) => {
                assert_eq!(file.copy_method(), CopyMethod::Reflinked);
                assert_eq!(
                    file.digest::<Sha256HashValue>().unwrap(),
                    compute_verity::<Sha256HashValue>(&data)
                );
            }
            Err(FinishError::ReflinkUnsupported) => {
                let file = helper
                    .create_from_fd::<Sha256HashValue>(&dir, &src, data.len() as u64)
                    .unwrap();
                assert_eq!(file.copy_method(), CopyMethod::Copied);
            }
            Err(e) => panic!("{e}"),
        }
        assert_eq!(dir_entries(tmp.path()), ["src"]);
    }

    #[test]
    fn test_shutdown() {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::start().unwrap();
        let other = helper.clone();
        let w = helper.create::<Sha256HashValue>(&dir, 0).unwrap();
        assert!(helper.shutdown().is_err());
        w.finish().unwrap();
        other.wait();
        helper.shutdown().unwrap();
        helper.shutdown().unwrap();
        assert!(other.create::<Sha256HashValue>(&dir, 0).is_err());
    }

    #[test]
    fn test_drop_without_shutdown() {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::start().unwrap();
        let w = helper.create::<Sha256HashValue>(&dir, 0).unwrap();
        drop(helper);
        // The writer keeps the helper alive.
        w.finish().unwrap();
    }

    /// A copy of the pipe's write end held elsewhere (as by a forked
    /// child that hasn't exec'd yet) must not keep finish() waiting.
    #[test]
    fn test_finish_with_pipe_copy() {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::start().unwrap();
        let mut w = helper.create::<Sha256HashValue>(&dir, 5).unwrap();
        let copy = w.pipe_mut().unwrap().try_clone().unwrap();
        w.write_all(b"hello").unwrap();
        let file = w.finish().unwrap();
        assert_eq!(
            file.digest::<Sha256HashValue>().unwrap(),
            compute_verity::<Sha256HashValue>(b"hello")
        );

        // Likewise for aborting.
        let mut w = helper.create::<Sha256HashValue>(&dir, 5).unwrap();
        let copy2 = w.pipe_mut().unwrap().try_clone().unwrap();
        drop(w);
        helper.wait();
        helper.shutdown().unwrap();
        drop((copy, copy2));
        assert!(dir_entries(tmp.path()).is_empty());
    }

    /// More writers in flight at once than there are workers wouldn't
    /// work, but up to the limit they must not block each other.
    #[test]
    fn test_interleaved_writers() {
        const N: usize = 4;
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::builder().max_workers(N).start().unwrap();
        // Several pipe buffers' worth, so each writer blocks if its
        // worker isn't draining.
        let chunk = vec![7u8; 256 * 1024];
        let rounds = 16;
        let size = (chunk.len() * rounds) as u64;
        let mut writers: Vec<_> = (0..N)
            .map(|_| helper.create::<Sha256HashValue>(&dir, size).unwrap())
            .collect();
        for _ in 0..rounds {
            for w in &mut writers {
                w.write_all(&chunk).unwrap();
            }
        }
        let expected = compute_verity::<Sha256HashValue>(&chunk.repeat(rounds));
        for w in writers {
            assert_eq!(
                w.finish().unwrap().digest::<Sha256HashValue>().unwrap(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn test_async_write() {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::start().unwrap();
        let data = b"async data".repeat(100_000);

        let mut w = helper
            .create::<Sha256HashValue>(&dir, data.len() as u64)
            .unwrap();
        tokio::io::copy(&mut &data[..10], &mut w).await.unwrap();
        // Switching back to blocking writes works too.
        w.write_all(&data[10..20]).unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut w, &data[20..])
            .await
            .unwrap();
        let file = w.finish_async().await.unwrap();
        assert_eq!(
            file.digest::<Sha256HashValue>().unwrap(),
            compute_verity::<Sha256HashValue>(&data)
        );
    }

    /// The race this module exists for: other threads forking while we
    /// write.  Every file must get fs-verity on the first try.
    #[test]
    fn test_forking() {
        let tmp = tempdir();
        let dir = open_dir(tmp.path());
        let helper = FsVerityHelper::start().unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let forkers: Vec<_> = (0..4)
            .map(|_| {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let status = std::process::Command::new("true")
                            .pre_exec_sleep(Duration::from_millis(5))
                            .status()
                            .unwrap();
                        assert!(status.success() || status.signal().is_some());
                    }
                })
            })
            .collect();

        let result = std::panic::catch_unwind(|| {
            std::thread::scope(|s| {
                for _ in 0..4 {
                    s.spawn(|| {
                        for i in 0..100u32 {
                            let data = i.to_le_bytes().repeat(1000);
                            let mut w = helper
                                .create::<Sha256HashValue>(&dir, data.len() as u64)
                                .unwrap();
                            w.write_all(&data).unwrap();
                            let file = w.finish().unwrap();
                            assert_eq!(
                                file.digest::<Sha256HashValue>().unwrap(),
                                compute_verity::<Sha256HashValue>(&data)
                            );
                        }
                    });
                }
            });
        });

        stop.store(true, Ordering::Relaxed);
        for f in forkers {
            f.join().unwrap();
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
}
