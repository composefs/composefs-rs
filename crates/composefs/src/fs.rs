//! Reading and writing filesystem trees to/from disk.
//!
//! This module provides functionality to read filesystem structures from
//! disk into composefs tree representations and write them back, including
//! handling of hardlinks, extended attributes, and repository integration.

use std::{
    collections::{BTreeMap, HashMap},
    ffi::{CStr, OsStr},
    fs::File,
    io::{BufRead, Read, Write},
    mem::MaybeUninit,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
    thread::available_parallelism,
};

use anyhow::{Context as _, Result, ensure};
use fn_error_context::context;
use rustix::{
    buffer::spare_capacity,
    fd::{AsFd, OwnedFd},
    fs::{
        AtFlags, CWD, Dir, FileType, Mode, OFlags, fstat, getxattr, linkat, listxattr, mkdirat,
        mknodat, openat, readlinkat, symlinkat,
    },
    io::{Errno, read},
};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use zerocopy::IntoBytes;

use crate::{
    INLINE_CONTENT_MAX_V0,
    fsverity::{FsVerityHashValue, FsVerityHasher},
    generic_tree,
    repository::Repository,
    shared_internals::IO_BUF_CAPACITY,
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
    util::proc_self_fd,
};

/// Attempt to use O_TMPFILE + rename to atomically set file contents.
/// Will fall back to a non-atomic write if the target doesn't support O_TMPFILE.
#[context("Setting file contents for {}", name.to_string_lossy())]
fn set_file_contents(dirfd: &OwnedFd, name: &OsStr, stat: &Stat, data: &[u8]) -> Result<()> {
    match openat(
        dirfd,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
        stat.st_mode.into(),
    ) {
        Ok(tmp) => {
            let mut tmp = File::from(tmp);
            tmp.write_all(data)
                .context("Failed to write data to tmpfile")?;
            tmp.sync_data().context("Failed to sync tmpfile data")?;
            linkat(
                CWD,
                proc_self_fd(&tmp),
                dirfd,
                name,
                AtFlags::SYMLINK_FOLLOW,
            )
            .with_context(|| format!("Failed to link tmpfile to {}", name.to_string_lossy()))?;
        }
        Err(Errno::OPNOTSUPP) => {
            // vfat? yolo...
            let fd = openat(
                dirfd,
                name,
                OFlags::CREATE | OFlags::WRONLY | OFlags::CLOEXEC,
                stat.st_mode.into(),
            )
            .with_context(|| format!("Failed to create file {}", name.to_string_lossy()))?;
            let mut f = File::from(fd);
            f.write_all(data).context("Failed to write file data")?;
            f.sync_data().context("Failed to sync file data")?;
        }
        Err(e) => Err(e)?,
    }
    Ok(())
}

#[context("Writing directory {}", name.to_string_lossy())]
fn write_directory<ObjectID: FsVerityHashValue>(
    dir: &Directory<ObjectID>,
    dirfd: &OwnedFd,
    name: &OsStr,
    fs: &FileSystem<ObjectID>,
    repo: &Repository<ObjectID>,
) -> Result<()> {
    match mkdirat(dirfd, name, dir.stat.st_mode.into()) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(e) => Err(e)?,
    }

    let fd = openat(dirfd, name, OFlags::PATH | OFlags::DIRECTORY, 0.into())?;
    write_directory_contents(dir, &fd, fs, repo)
}

#[context("Writing leaf {}", name.to_string_lossy())]
fn write_leaf<ObjectID: FsVerityHashValue>(
    leaf: &Leaf<ObjectID>,
    dirfd: &OwnedFd,
    name: &OsStr,
    repo: &Repository<ObjectID>,
) -> Result<()> {
    let mode = leaf.stat.st_mode.into();

    match &leaf.content {
        LeafContent::Regular(RegularFile::Inline(data)) => {
            set_file_contents(dirfd, name, &leaf.stat, data)?
        }
        LeafContent::Regular(RegularFile::External(id, size)) => {
            let object = repo.open_object(id)?;
            // TODO: make this better.  At least needs to be EINTR-safe.  Could even do reflink in some cases.
            // Regardless we shouldn't read the whole file into memory.
            let size = (*size).try_into().context("size overflow")?;
            let mut buffer = vec![MaybeUninit::uninit(); size];
            let (data, _) = read(object, &mut buffer)?;
            set_file_contents(dirfd, name, &leaf.stat, data)?;
        }
        LeafContent::BlockDevice(rdev) => mknodat(dirfd, name, FileType::BlockDevice, mode, *rdev)?,
        LeafContent::CharacterDevice(rdev) => {
            mknodat(dirfd, name, FileType::CharacterDevice, mode, *rdev)?
        }
        LeafContent::Socket => mknodat(dirfd, name, FileType::Socket, mode, 0)?,
        LeafContent::Fifo => mknodat(dirfd, name, FileType::Fifo, mode, 0)?,
        LeafContent::Symlink(target) => symlinkat(target.as_ref(), dirfd, name)?,
    }

    Ok(())
}

#[context("Writing directory contents")]
fn write_directory_contents<ObjectID: FsVerityHashValue>(
    dir: &Directory<ObjectID>,
    fd: &OwnedFd,
    fs: &FileSystem<ObjectID>,
    repo: &Repository<ObjectID>,
) -> Result<()> {
    for (name, inode) in dir.entries() {
        match inode {
            Inode::Directory(dir) => write_directory(dir, fd, name, fs, repo),
            Inode::Leaf(id, _) => write_leaf(fs.leaf(*id), fd, name, repo),
        }?;
    }

    Ok(())
}

/// Writes a directory tree from composefs representation to a filesystem path.
///
/// Reconstructs the filesystem structure at the specified output directory,
/// creating directories, files, symlinks, and device nodes as needed. External
/// file content is read from the repository. Note that hardlinks are not supported.
#[context("Writing to path {}", output_dir.display())]
pub fn write_to_path<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    fs: &FileSystem<ObjectID>,
    output_dir: &Path,
) -> Result<()> {
    let fd = openat(CWD, output_dir, OFlags::PATH | OFlags::DIRECTORY, 0.into())?;
    write_directory_contents(&fs.root, &fd, fs, repo)
}

// ---------------------------------------------------------------------------
// Shared helpers for filesystem scanning
// ---------------------------------------------------------------------------

/// Read extended attributes from a file descriptor.
///
/// Uses `/proc/self/fd` to work around `O_PATH` fd limitations with
/// `flistxattr`/`fgetxattr`. The symlink-following version is used,
/// which correctly reads xattrs from symlinks themselves.
///
/// See <https://gist.github.com/allisonkarlitskaya/7a80f2ebb3314d80f45c653a1ba0e398>
#[context("Reading extended attributes")]
fn read_xattrs(fd: &OwnedFd) -> Result<BTreeMap<Box<OsStr>, Box<[u8]>>> {
    let filename = proc_self_fd(fd);

    let mut xattrs = BTreeMap::new();

    let mut names = [MaybeUninit::new(0); 65536];
    let (names, _) = listxattr(&filename, &mut names)?;

    for name in names.split_inclusive(|c| *c == 0) {
        let mut buffer = [MaybeUninit::new(0); 65536];
        let name: &[u8] = name.as_bytes();
        let name = CStr::from_bytes_with_nul(name)?;
        let (value, _) = getxattr(&filename, name, &mut buffer)?;
        let key = Box::from(OsStr::from_bytes(name.to_bytes()));
        xattrs.insert(key, Box::from(value));
    }

    Ok(xattrs)
}

/// Read file metadata and verify the file type matches expectations.
#[context("Getting file stats")]
fn stat_fd(fd: &OwnedFd, ifmt: FileType) -> Result<(rustix::fs::Stat, generic_tree::Stat)> {
    let buf = fstat(fd)?;

    ensure!(
        FileType::from_raw_mode(buf.st_mode) == ifmt,
        "File type changed between readdir() and fstat()"
    );

    Ok((
        buf,
        generic_tree::Stat {
            st_mode: buf.st_mode & 0o7777,
            st_uid: buf.st_uid,
            st_gid: buf.st_gid,
            st_mtim_sec: buf.st_mtime as i64,
            xattrs: read_xattrs(fd)?,
        },
    ))
}

// ---------------------------------------------------------------------------
// Unified filesystem scanner (scan phase)
// ---------------------------------------------------------------------------

/// Device and inode number pair identifying a unique file on a filesystem.
///
/// Used for hardlink deduplication during scanning: files sharing the
/// same `(dev, ino)` are the same underlying inode and only need to
/// be processed once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileDevIno {
    dev: u64,
    ino: u64,
}

/// Represents a regular file during the scan phase, before verity
/// computation and object storage.
#[derive(Debug)]
enum PendingFile {
    /// Small file with inline content (≤ INLINE_CONTENT_MAX_V0 bytes).
    Inline(Box<[u8]>),
    /// Large file pending async processing. Stores the (dev, ino) key
    /// for looking up the result after verity computation.
    External { inode_key: FileDevIno, size: u64 },
}

/// Sends large-file descriptors for concurrent async processing.
///
/// During the synchronous scan phase, large files are sent over a
/// channel as they're discovered, allowing verity computation to
/// begin while the scan is still running.
struct ChannelHandler {
    tx: tokio::sync::mpsc::Sender<(FileDevIno, OwnedFd, u64)>,
}

/// Walks a directory tree synchronously, collecting metadata and recording
/// large files in a [`CollectHandler`] for deferred async processing.
///
/// This is the single scan implementation used by the async filesystem
/// reading path. Small files are read inline during the scan; large files
/// are pushed into the handler's pending list.
struct FilesystemScanner {
    inodes: HashMap<FileDevIno, generic_tree::LeafId>,
    leaves: Vec<generic_tree::Leaf<PendingFile>>,
    handler: ChannelHandler,
}

impl FilesystemScanner {
    fn new(handler: ChannelHandler) -> Self {
        Self {
            inodes: HashMap::new(),
            leaves: Vec::new(),
            handler,
        }
    }

    fn push_leaf(
        &mut self,
        stat: generic_tree::Stat,
        content: generic_tree::LeafContent<PendingFile>,
    ) -> generic_tree::LeafId {
        let id = generic_tree::LeafId(self.leaves.len());
        self.leaves.push(generic_tree::Leaf { stat, content });
        id
    }

    /// Scan the directory tree rooted at `name` (relative to `dirfd`).
    fn scan(
        &mut self,
        dirfd: impl AsFd,
        name: &OsStr,
    ) -> Result<generic_tree::FileSystem<PendingFile>> {
        let root = self.scan_directory(dirfd, name)?;
        Ok(generic_tree::FileSystem {
            root,
            leaves: std::mem::take(&mut self.leaves),
        })
    }

    #[context("Scanning directory {}", name.to_string_lossy())]
    fn scan_directory(
        &mut self,
        dirfd: impl AsFd,
        name: &OsStr,
    ) -> Result<generic_tree::Directory<PendingFile>> {
        let fd = openat(
            dirfd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;

        let (_, stat) = stat_fd(&fd, FileType::Directory)?;
        let mut entries = BTreeMap::new();

        for item in Dir::read_from(&fd)? {
            let entry = item?;
            let child_name = OsStr::from_bytes(entry.file_name().to_bytes());

            if child_name == "." || child_name == ".." {
                continue;
            }

            let inode = self.scan_inode(&fd, child_name, entry.file_type())?;
            entries.insert(Box::from(child_name), inode);
        }

        Ok(generic_tree::Directory { stat, entries })
    }

    #[context("Scanning inode {}", name.to_string_lossy())]
    fn scan_inode(
        &mut self,
        dirfd: &OwnedFd,
        name: &OsStr,
        ifmt: FileType,
    ) -> Result<generic_tree::Inode<PendingFile>> {
        if ifmt == FileType::Directory {
            let dir = self.scan_directory(dirfd, name)?;
            Ok(generic_tree::Inode::Directory(Box::new(dir)))
        } else {
            let id = self.scan_leaf(dirfd, name, ifmt)?;
            Ok(generic_tree::Inode::leaf(id))
        }
    }

    #[context("Scanning leaf {}", name.to_string_lossy())]
    fn scan_leaf(
        &mut self,
        dirfd: &OwnedFd,
        name: &OsStr,
        ifmt: FileType,
    ) -> Result<generic_tree::LeafId> {
        let oflags = match ifmt {
            FileType::RegularFile => OFlags::RDONLY,
            _ => OFlags::PATH,
        };

        let fd = openat(
            dirfd,
            name,
            oflags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;

        let (buf, stat) = stat_fd(&fd, ifmt)?;

        // NB: We could check `st_nlink > 1` to find out if we should track a file as a potential
        // hardlink or not, but some filesystems (like fuse-overlayfs) can report this incorrectly.
        // Track all files.  https://github.com/containers/fuse-overlayfs/issues/435
        let key = FileDevIno {
            dev: buf.st_dev,
            ino: buf.st_ino,
        };
        if let Some(&id) = self.inodes.get(&key) {
            Ok(id)
        } else {
            let content = self.scan_leaf_content(fd, &buf)?;
            let id = self.push_leaf(stat, content);
            self.inodes.insert(key, id);
            Ok(id)
        }
    }

    #[context("Reading leaf content")]
    fn scan_leaf_content(
        &mut self,
        fd: OwnedFd,
        buf: &rustix::fs::Stat,
    ) -> Result<generic_tree::LeafContent<PendingFile>> {
        let content = match FileType::from_raw_mode(buf.st_mode) {
            FileType::Directory | FileType::Unknown => unreachable!(),
            FileType::RegularFile => {
                if buf.st_size > INLINE_CONTENT_MAX_V0 as i64 {
                    // Large file: record for deferred async processing
                    let key = FileDevIno {
                        dev: buf.st_dev,
                        ino: buf.st_ino,
                    };
                    // Ignore send errors — the receiver may have been
                    // dropped if the async side hit an error and cancelled.
                    let _ = self.handler.tx.blocking_send((key, fd, buf.st_size as u64));
                    generic_tree::LeafContent::Regular(PendingFile::External {
                        inode_key: key,
                        size: buf.st_size as u64,
                    })
                } else {
                    // Small file: read inline
                    let size = buf.st_size.try_into().context("size overflow")?;
                    let mut buffer = Vec::with_capacity(size);
                    if buf.st_size > 0 {
                        read(fd, spare_capacity(&mut buffer))?;
                    }
                    generic_tree::LeafContent::Regular(PendingFile::Inline(
                        buffer.into_boxed_slice(),
                    ))
                }
            }
            FileType::Symlink => {
                let target = readlinkat(fd, "", [])?;
                generic_tree::LeafContent::Symlink(OsStr::from_bytes(target.as_bytes()).into())
            }
            FileType::CharacterDevice => generic_tree::LeafContent::CharacterDevice(buf.st_rdev),
            FileType::BlockDevice => generic_tree::LeafContent::BlockDevice(buf.st_rdev),
            FileType::Fifo => generic_tree::LeafContent::Fifo,
            FileType::Socket => generic_tree::LeafContent::Socket,
        };
        Ok(content)
    }
}

// ---------------------------------------------------------------------------
// Resolution: PendingFile -> RegularFile<ObjectID>
// ---------------------------------------------------------------------------

/// Convert a `PendingFile` into a `RegularFile<ObjectID>` using pre-computed
/// verity results for external files.
fn resolve_pending_file<ObjectID: FsVerityHashValue>(
    pf: &PendingFile,
    results: &HashMap<FileDevIno, ObjectID>,
) -> Result<RegularFile<ObjectID>> {
    match pf {
        PendingFile::Inline(data) => Ok(RegularFile::Inline(data.clone())),
        PendingFile::External { inode_key, size } => {
            let id = results
                .get(inode_key)
                .cloned()
                .context("missing result for external file")?;
            Ok(RegularFile::External(id, *size))
        }
    }
}

/// Compute fsverity digest by streaming from a file descriptor.
///
/// Reads data in block-sized chunks, feeding each to the incremental
/// hasher. Never holds more than one block in memory.
fn compute_verity_from_fd<ObjectID: FsVerityHashValue>(source: OwnedFd) -> Result<ObjectID> {
    let mut reader = std::io::BufReader::with_capacity(IO_BUF_CAPACITY, File::from(source));
    let mut hasher = FsVerityHasher::<ObjectID>::new();

    loop {
        let buf = reader
            .fill_buf()
            .context("Reading from fd for verity computation")?;
        if buf.is_empty() {
            break;
        }
        let chunk_size = buf.len().min(FsVerityHasher::<ObjectID>::BLOCK_SIZE);
        hasher.add_block(&buf[..chunk_size]);
        reader.consume(chunk_size);
    }

    Ok(hasher.digest())
}

/// Default xattr allowlist for container filesystems.
///
/// When reading from a mounted container filesystem, host xattrs can leak into
/// the image (e.g., SELinux labels like `container_t` from overlayfs). This
/// allowlist specifies which xattrs are safe to preserve.
///
/// Currently only `security.capability` is allowed, as it represents actual
/// file capabilities that should be preserved. SELinux labels (`security.selinux`)
/// are excluded because they come from the build host and will be regenerated
/// by `transform_for_boot()` based on the target system's policy.
///
/// See: <https://github.com/containers/storage/pull/1608#issuecomment-1600915185>
pub const CONTAINER_XATTR_ALLOWLIST: &[&str] = &["security.capability"];

/// Returns true if the given xattr name is in [`CONTAINER_XATTR_ALLOWLIST`].
pub fn is_allowed_container_xattr(name: &OsStr) -> bool {
    CONTAINER_XATTR_ALLOWLIST
        .iter()
        .any(|allowed| name.as_encoded_bytes() == allowed.as_bytes())
}

/// Read the contents of a file.
pub fn read_file<ObjectID: FsVerityHashValue>(
    file: &RegularFile<ObjectID>,
    repo: &Repository<ObjectID>,
) -> Result<Box<[u8]>> {
    match file {
        RegularFile::Inline(data) => Ok(data.clone()),
        RegularFile::External(id, size) => {
            let capacity: usize = (*size).try_into().context("file too large for memory")?;
            let mut data = Vec::with_capacity(capacity);
            std::fs::File::from(repo.open_object(id)?).read_to_end(&mut data)?;
            ensure!(
                *size == data.len() as u64,
                "File content doesn't have the expected length"
            );
            Ok(data.into_boxed_slice())
        }
    }
}

// ---------------------------------------------------------------------------
// Async filesystem reading
// ---------------------------------------------------------------------------

/// Load a filesystem tree from the given path, parallelizing verity
/// computation and object storage across available cores.
///
/// The directory scan and verity computation run concurrently: as the
/// scan discovers large files, they are immediately dispatched for
/// verity hashing on the async runtime while the scan continues.
///
/// Hardlinks are deduplicated — each unique inode is processed only once.
///
/// If `repo` is `Some`, file objects are stored in the repository.
/// If `None`, fsverity digests are computed without writing to disk.
///
/// An optional `semaphore` can be provided to override the default concurrency
/// control. When `None`, the semaphore is derived from the repository (if any)
/// or from [`available_parallelism`].
pub async fn read_filesystem<ObjectID: FsVerityHashValue>(
    dirfd: OwnedFd,
    path: PathBuf,
    repo: Option<Arc<Repository<ObjectID>>>,
) -> Result<FileSystem<ObjectID>> {
    read_filesystem_impl(dirfd, path, repo, None).await
}

/// Like [`read_filesystem`] but with an explicit concurrency limit.
///
/// The `semaphore`, if provided, overrides the default parallelism derived from
/// the repository or [`available_parallelism`]. This is the recommended way to
/// honour a user-supplied `--threads` argument when no repository is present.
pub async fn read_filesystem_with_semaphore<ObjectID: FsVerityHashValue>(
    dirfd: OwnedFd,
    path: PathBuf,
    repo: Option<Arc<Repository<ObjectID>>>,
    semaphore: Arc<Semaphore>,
) -> Result<FileSystem<ObjectID>> {
    read_filesystem_impl(dirfd, path, repo, Some(semaphore)).await
}

async fn read_filesystem_impl<ObjectID: FsVerityHashValue>(
    dirfd: OwnedFd,
    path: PathBuf,
    repo: Option<Arc<Repository<ObjectID>>>,
    semaphore_override: Option<Arc<Semaphore>>,
) -> Result<FileSystem<ObjectID>> {
    let semaphore = semaphore_override.unwrap_or_else(|| {
        repo.as_ref()
            .map(|r| r.write_semaphore())
            .unwrap_or_else(|| {
                let n = available_parallelism().map(|n| n.get()).unwrap_or(4);
                Arc::new(Semaphore::new(n))
            })
    });

    // Channel for streaming work items from the scan thread to the
    // async runtime. The scan sends (key, fd, size) as files are
    // discovered; the async side spawns verity tasks immediately.
    // The channel bound limits how far the scan can race ahead of
    // verity processing, providing natural backpressure.
    let (tx, rx) =
        tokio::sync::mpsc::channel::<(FileDevIno, OwnedFd, u64)>(semaphore.available_permits());

    /// Result from a task in the join set — either the scan completed
    /// or a verity computation finished.
    enum TaskResult<ObjectID> {
        Scan(generic_tree::FileSystem<PendingFile>),
        Verity(FileDevIno, ObjectID),
    }

    // All work goes into a single JoinSet for structured concurrency.
    let mut tasks: JoinSet<Result<TaskResult<ObjectID>>> = JoinSet::new();

    // Scan the directory tree on a blocking thread, streaming work
    // items over the channel as files are discovered.
    tasks.spawn_blocking(move || {
        let handler = ChannelHandler { tx };
        let mut scanner = FilesystemScanner::new(handler);
        let fs = scanner
            .scan(&dirfd, path.as_os_str())
            .with_context(|| format!("Async reading filesystem from {}", path.display()))?;
        // Drop the sender so the receiver sees the channel close.
        drop(scanner.handler);
        Ok(TaskResult::Scan(fs))
    });

    // Map the channel into a stream that acquires a semaphore permit
    // for each item, gating concurrency before we spawn blocking work.
    let items = ReceiverStream::new(rx).then(|item| {
        let sem = semaphore.clone();
        async move {
            let permit = sem.acquire_owned().await.unwrap();
            (item, permit)
        }
    });
    tokio::pin!(items);

    // Spawn verity tasks as work items arrive from the scan,
    // and collect results from completed tasks — all concurrently.
    let mut results = HashMap::new();
    let mut pending_fs = None;
    let mut items_open = true;
    loop {
        tokio::select! {
            item = items.next(), if items_open => {
                match item {
                    Some(((key, fd, size), permit)) => {
                        let repo = repo.clone();
                        tasks.spawn_blocking(move || {
                            let _permit = permit;
                            let id = if let Some(repo) = repo {
                                repo.ensure_object_from_fd(fd, size)?
                            } else {
                                compute_verity_from_fd::<ObjectID>(fd)?
                            };
                            Ok(TaskResult::Verity(key, id))
                        });
                    }
                    None => items_open = false,
                }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result.expect("JoinSet not empty")?? {
                    TaskResult::Scan(fs) => {
                        assert!(pending_fs.is_none(), "scan task completed twice");
                        pending_fs = Some(fs);
                    }
                    TaskResult::Verity(key, id) => { results.insert(key, id); }
                }
            }
            else => break,
        }
    }

    // Resolve PendingFile -> RegularFile using the computed verity digests.
    let fs = pending_fs
        .expect("scan task completed")
        .try_map_regular(|pf| resolve_pending_file(pf, &results))?;
    debug_assert!(
        fs.fsck().is_ok(),
        "read_filesystem produced invalid filesystem"
    );
    Ok(fs)
}

/// Like [`read_filesystem`] but filters extended attributes using
/// the provided predicate before returning.
pub async fn read_filesystem_filtered<ObjectID, F>(
    dirfd: OwnedFd,
    path: PathBuf,
    repo: Option<Arc<Repository<ObjectID>>>,
    xattr_filter: F,
) -> Result<FileSystem<ObjectID>>
where
    ObjectID: FsVerityHashValue,
    F: Fn(&OsStr) -> bool,
{
    let mut fs = read_filesystem(dirfd, path, repo)
        .await
        .context("Reading filtered filesystem")?;
    fs.filter_xattrs(xattr_filter);
    Ok(fs)
}

/// Load a container root filesystem from the given path.
///
/// Wraps [`read_filesystem_filtered`] with the container xattr allowlist
/// and applies OCI transformations via [`FileSystem::transform_for_oci`].
pub async fn read_container_root<ObjectID: FsVerityHashValue>(
    dirfd: OwnedFd,
    path: PathBuf,
    repo: Option<Arc<Repository<ObjectID>>>,
) -> Result<FileSystem<ObjectID>> {
    let mut fs = read_filesystem_filtered(dirfd, path, repo, is_allowed_container_xattr).await?;
    fs.transform_for_oci()?;
    Ok(fs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{CWD, openat};

    #[test]
    fn test_write_contents() -> Result<()> {
        let td = tempfile::tempdir()?;
        let testpath = &td.path().join("testfile");
        let td = openat(
            CWD,
            td.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0),
        )?;
        let st = Stat {
            st_mode: 0o755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: Default::default(),
            xattrs: Default::default(),
        };
        set_file_contents(&td, OsStr::new("testfile"), &st, b"new contents").unwrap();
        drop(td);
        assert_eq!(std::fs::read(testpath)?, b"new contents");
        Ok(())
    }
}
