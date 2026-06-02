//! FUSE filesystem implementation for composefs trees.
//!
//! This crate provides a userspace filesystem implementation that exposes composefs
//! directory trees through FUSE. It supports read-only access to files, directories,
//! symlinks, and extended attributes, with data served from a composefs repository.

#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    ffi::OsStr,
    num::NonZeroUsize,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use fuser::{
    BackingId, Config, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    InitFlags, KernelConfig, MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEntry, ReplyOpen, Request, Session, SessionACL,
};
use rustix::{buffer::spare_capacity, io::pread};

use composefs::{
    fsverity::FsVerityHashValue,
    generic_tree::LeafId,
    repository::Repository,
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
};

const TTL: Duration = Duration::from_secs(1_000_000);

/// FUSE inode number. Assigned eagerly at mount time.
///
/// Inode 1 is the root directory, then all other nodes get sequential
/// numbers from a depth-first walk. The numbering is an internal FUSE
/// concern and not exposed in the public API.
type Ino = u64;

/// Pre-built static data for one inode, computed at mount time.
///
/// Indexed by `(ino - 1)` for O(1) attribute lookup. Directory inodes
/// store their path from the root so we can resolve them via
/// [`Directory::get_directory`] without raw pointers.
#[derive(Debug, Clone)]
enum InodeData {
    /// A directory inode.
    Dir {
        /// Path from filesystem root (empty bytes for the root itself).
        path: Box<OsStr>,
        /// Inode number of the parent directory.
        parent_ino: Ino,
        /// Pre-computed file attributes.
        attrs: FileAttr,
    },
    /// A leaf (regular file, symlink, device, etc.) inode.
    Leaf {
        /// Index into the filesystem's leaf table.
        leaf_id: LeafId,
        /// Pre-computed file attributes.
        attrs: FileAttr,
    },
}

impl InodeData {
    /// Return the pre-computed [`FileAttr`] for this inode.
    fn attrs(&self) -> &FileAttr {
        match self {
            InodeData::Dir { attrs, .. } | InodeData::Leaf { attrs, .. } => attrs,
        }
    }
}

/// A lookup table mapping directory children to their inode numbers.
///
/// Built once at mount time from the full DFS walk. Directories are keyed by
/// their path (as a `Box<OsStr>`) and leaves by their `LeafId`.
/// This is used during `lookup` and `readdir` to map a child inode found by
/// tree traversal back to its assigned inode number.
#[derive(Debug)]
struct InodeLookup {
    /// Maps a directory's root-relative path to its inode number.
    dir_inos: HashMap<Box<OsStr>, Ino>,
    /// Maps `LeafId.0` to its inode number. Hardlinks share the same ino.
    leaf_inos: Vec<Ino>,
}

impl InodeLookup {
    fn dir_ino(&self, path: &OsStr) -> Option<Ino> {
        self.dir_inos.get(path).copied()
    }

    fn leaf_ino(&self, id: LeafId) -> Ino {
        self.leaf_inos[id.0]
    }
}

/// Helpers to compute attributes from the composefs tree types.
fn leaf_kind(leaf: &Leaf<impl FsVerityHashValue>) -> FileType {
    match leaf.content {
        LeafContent::BlockDevice(..) => FileType::BlockDevice,
        LeafContent::CharacterDevice(..) => FileType::CharDevice,
        LeafContent::Fifo => FileType::NamedPipe,
        LeafContent::Regular(..) => FileType::RegularFile,
        LeafContent::Socket => FileType::Socket,
        LeafContent::Symlink(..) => FileType::Symlink,
    }
}

fn leaf_rdev(leaf: &Leaf<impl FsVerityHashValue>) -> u32 {
    match &leaf.content {
        LeafContent::BlockDevice(rdev) | LeafContent::CharacterDevice(rdev) => *rdev as u32,
        _ => 0,
    }
}

fn leaf_size(leaf: &Leaf<impl FsVerityHashValue>) -> u64 {
    match &leaf.content {
        LeafContent::Regular(RegularFile::Inline(data)) => data.len() as u64,
        LeafContent::Regular(RegularFile::External(.., size)) => *size,
        _ => 0,
    }
}

fn stat_mtime(stat: &Stat) -> SystemTime {
    // Container image timestamps are virtually always post-epoch (positive),
    // so we treat negative values as epoch rather than wrapping to the far future.
    let secs = stat.st_mtim_sec.max(0) as u64;
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn dir_fileattr(dir: &Directory<impl FsVerityHashValue>, ino: Ino, nlinks: u32) -> FileAttr {
    let mtime = stat_mtime(&dir.stat);
    FileAttr {
        ino: INodeNo(ino),
        size: 0,
        blocks: 1,
        atime: mtime,
        mtime,
        ctime: mtime,
        crtime: mtime,
        kind: FileType::Directory,
        perm: dir.stat.st_mode as u16,
        nlink: nlinks,
        uid: dir.stat.st_uid,
        gid: dir.stat.st_gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

fn leaf_fileattr(leaf: &Leaf<impl FsVerityHashValue>, ino: Ino, nlink: u32) -> FileAttr {
    let mtime = stat_mtime(&leaf.stat);
    FileAttr {
        ino: INodeNo(ino),
        size: leaf_size(leaf),
        blocks: 1,
        atime: mtime,
        mtime,
        ctime: mtime,
        crtime: mtime,
        kind: leaf_kind(leaf),
        perm: leaf.stat.st_mode as u16,
        nlink,
        uid: leaf.stat.st_uid,
        gid: leaf.stat.st_gid,
        rdev: leaf_rdev(leaf),
        blksize: 4096,
        flags: 0,
    }
}

/// Result of [`build_inode_table`]: the pre-built table plus the lookup index.
struct InodeTable {
    /// Flat vector indexed by `(ino - 1)`.
    data: Vec<InodeData>,
    /// Lookup index: path → ino for dirs, leaf_id → ino for leaves.
    lookup: InodeLookup,
}

/// Mutable accumulator used during the DFS walk in [`build_inode_table`].
struct InodeWalker<'a, O: FsVerityHashValue> {
    next_ino: Ino,
    dir_inos: HashMap<Box<OsStr>, Ino>,
    leaf_inos: Vec<Ino>,
    entries: Vec<(Ino, InodeData)>,
    nlink_map: &'a [u32],
    leaves: &'a [Leaf<O>],
}

impl<O: FsVerityHashValue> InodeWalker<'_, O> {
    fn walk(&mut self, dir: &Directory<O>, path: &OsStr, parent_ino: Ino, ino: Ino) {
        self.dir_inos.insert(path.into(), ino);
        let nlinks = 2 + dir
            .inodes()
            .filter(|i| matches!(i, Inode::Directory(..)))
            .count() as u32;
        let attrs = dir_fileattr(dir, ino, nlinks);
        self.entries.push((
            ino,
            InodeData::Dir {
                path: path.into(),
                parent_ino,
                attrs,
            },
        ));

        for (name, inode) in dir.entries() {
            match inode {
                Inode::Directory(subdir) => {
                    self.next_ino += 1;
                    let child_ino = self.next_ino;
                    let child_path = child_path_from(path, name);
                    self.walk(subdir, &child_path, ino, child_ino);
                }
                Inode::Leaf(leaf_id, _) => {
                    if self.leaf_inos[leaf_id.0] == 0 {
                        self.next_ino += 1;
                        let leaf_ino = self.next_ino;
                        self.leaf_inos[leaf_id.0] = leaf_ino;
                        let leaf = &self.leaves[leaf_id.0];
                        let nlink = self.nlink_map[leaf_id.0];
                        let attrs = leaf_fileattr(leaf, leaf_ino, nlink);
                        self.entries.push((
                            leaf_ino,
                            InodeData::Leaf {
                                leaf_id: *leaf_id,
                                attrs,
                            },
                        ));
                    }
                    // Hardlinks: same LeafId → same ino, no new entry needed.
                }
            }
        }
    }
}

/// Build the flat inode table and lookup index from the filesystem tree.
///
/// The table is indexed by `(ino - 1)` so index 0 = inode 1 (root).
/// Sequential inode numbers are assigned via DFS, matching what the kernel
/// expects for a stable, mountable filesystem.
fn build_inode_table<ObjectID: FsVerityHashValue>(fs: &FileSystem<ObjectID>) -> InodeTable {
    let nlink_map = fs.nlinks();
    let root_ino: Ino = 1;
    let mut walker = InodeWalker {
        next_ino: root_ino,
        dir_inos: HashMap::new(),
        leaf_inos: vec![0; fs.leaves.len()],
        entries: Vec::new(),
        nlink_map: &nlink_map,
        leaves: &fs.leaves,
    };
    walker.walk(&fs.root, OsStr::new(""), root_ino, root_ino);

    let InodeWalker {
        dir_inos,
        leaf_inos,
        mut entries,
        ..
    } = walker;

    // Sort by ino (ascending) and build the flat Vec indexed by (ino - 1).
    entries.sort_unstable_by_key(|(ino, _)| *ino);
    let max_ino = entries.last().map(|(ino, _)| *ino).unwrap_or(1);
    let mut data: Vec<Option<InodeData>> = vec![None; max_ino as usize];
    for (ino, entry) in entries {
        data[(ino as usize) - 1] = Some(entry);
    }
    let data: Vec<InodeData> = data
        .into_iter()
        .enumerate()
        .map(|(i, opt)| opt.unwrap_or_else(|| panic!("inode table slot {i} was never filled")))
        .collect();

    InodeTable {
        data,
        lookup: InodeLookup {
            dir_inos,
            leaf_inos,
        },
    }
}

/// An open file handle: either a real fd (for external objects) or inline data.
///
/// Both variants are wrapped in `Arc` so that `read()` can clone the handle
/// cheaply and drop the `FuseHandles` lock before issuing the actual I/O.
/// Without this, all `pread` calls would be serialised on the single mutex.
#[derive(Debug, Clone)]
enum OpenHandle {
    /// An `OwnedFd` shared via `Arc` so threads can read concurrently.
    Fd(Arc<OwnedFd>),
    /// Immutable inline bytes, shared via `Arc` for cheap clone-and-read.
    Data(Arc<[u8]>),
    /// A FUSE passthrough backing id. The kernel reads directly from the
    /// backing fd; userspace read() is never called for this handle.
    /// Both fields must be kept alive until release(): the `OwnedFd` is the
    /// file the kernel reads through, and dropping the `BackingId` sends
    /// `FUSE_DEV_IOC_BACKING_CLOSE` to deregister it.
    #[allow(dead_code)]
    Passthrough {
        backing_id: Arc<BackingId>,
        fd: Arc<OwnedFd>,
    },
}

/// Mutable runtime state: only tracks open file handles.
#[derive(Debug, Default)]
struct FuseHandles {
    handles: HashMap<u64, OpenHandle>,
    next_fh: u64,
}

/// The main FUSE filesystem implementation.
///
/// Holds the composefs repository and tree by `Arc`, plus a pre-built inode
/// table (built at mount time). The only mutable state is the open-file-handle
/// map, protected by a `Mutex` to satisfy `Filesystem: Send + Sync + 'static`.
#[derive(Debug)]
struct TreeFuse<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    fs: Arc<FileSystem<ObjectID>>,
    /// Pre-built, static inode data indexed by `(ino - 1)`.
    inode_data: Vec<InodeData>,
    /// Lookup index for resolving child inode numbers.
    lookup: InodeLookup,
    /// Mutable handle state, protected for thread safety.
    handles: Mutex<FuseHandles>,
    /// Whether the caller requested FUSE passthrough.  Only negotiated with the
    /// kernel when this is true; always false until the caller opts in.
    passthrough_requested: bool,
    /// Whether FUSE passthrough was successfully negotiated with the kernel.
    passthrough_enabled: std::sync::atomic::AtomicBool,
}

impl<ObjectID: FsVerityHashValue> TreeFuse<ObjectID> {
    fn get_data(&self, ino: Ino) -> Option<&InodeData> {
        let idx = (ino as usize).checked_sub(1)?;
        self.inode_data.get(idx)
    }

    /// Resolve a directory inode to a `&Directory` by walking the stored path.
    ///
    /// The path walk is O(depth × log(entries_per_dir)) which is acceptable for
    /// typical container image trees (depth < 20). A future optimisation could
    /// store a pre-built `Vec<*const Directory<O>>` indexed by `(ino-1)` for
    /// O(1) resolution, but that would require either `unsafe` raw pointers or
    /// a significant redesign of ownership.
    fn resolve_dir(&self, ino: Ino) -> Option<&Directory<ObjectID>> {
        let InodeData::Dir { path, .. } = self.get_data(ino)? else {
            return None;
        };
        if path.is_empty() {
            Some(&self.fs.root)
        } else {
            self.fs.root.get_directory(path).ok()
        }
    }

    /// Resolve a leaf inode to its `&Leaf`.
    fn resolve_leaf(&self, ino: Ino) -> Option<&Leaf<ObjectID>> {
        let InodeData::Leaf { leaf_id, .. } = self.get_data(ino)? else {
            return None;
        };
        Some(self.fs.leaf(*leaf_id))
    }

    /// Resolve the [`Stat`] for an inode.
    ///
    /// Returns `None` if the inode doesn't exist, `Some(Err(()))` on an internal
    /// path resolution error, and `Some(Ok(&Stat))` on success.
    fn resolve_stat(&self, ino: Ino) -> Option<Result<&Stat, ()>> {
        match self.get_data(ino)? {
            InodeData::Dir { path, .. } => {
                let dir = if path.is_empty() {
                    &self.fs.root
                } else {
                    self.fs.root.get_directory(path).ok()?
                };
                Some(Ok(&dir.stat))
            }
            InodeData::Leaf { leaf_id, .. } => Some(Ok(&self.fs.leaf(*leaf_id).stat)),
        }
    }

    /// Given a child `Inode` (from a directory lookup), return its ino number.
    fn child_ino(&self, inode: &Inode<ObjectID>, child_path: &OsStr) -> Option<Ino> {
        match inode {
            Inode::Directory(_) => self.lookup.dir_ino(child_path),
            Inode::Leaf(id, _) => Some(self.lookup.leaf_ino(*id)),
        }
    }
}

impl<ObjectID: FsVerityHashValue> Filesystem for TreeFuse<ObjectID> {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        if self.passthrough_requested
            && config.capabilities().contains(InitFlags::FUSE_PASSTHROUGH)
            && config.add_capabilities(InitFlags::FUSE_PASSTHROUGH).is_ok()
        {
            match config.set_max_stack_depth(2) {
                Ok(_) => {
                    self.passthrough_enabled
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    log::debug!("FUSE passthrough enabled");
                }
                Err(current) => {
                    log::warn!(
                        "FUSE passthrough: set_max_stack_depth(2) failed \
                         (current={current}), disabling passthrough"
                    );
                }
            }
        }
        Ok(())
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: fuser::ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 4096, 255, 4096);
    }

    /// Forget is a no-op: the inode table is fully pre-built at mount time
    /// and lives for the entire session, so there is nothing to free per-inode.
    fn forget(&self, _req: &Request, _ino: INodeNo, _nlookup: u64) {
        // nothing to do
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let parent = parent.0;
        log::trace!("lookup {parent} {name:?}");

        let Some(InodeData::Dir {
            path: parent_path, ..
        }) = self.get_data(parent)
        else {
            log::error!("lookup({parent}, {name:?}): parent is not a directory");
            return reply.error(fuser::Errno::EBADF);
        };
        let parent_path = parent_path.clone();

        let Some(dir) = self.resolve_dir(parent) else {
            log::error!("lookup({parent}, {name:?}): failed to resolve parent directory");
            return reply.error(fuser::Errno::EIO);
        };

        let child_path: Box<OsStr> = if parent_path.is_empty() {
            name.into()
        } else {
            let mut p = parent_path.as_bytes().to_vec();
            p.push(b'/');
            p.extend_from_slice(name.as_bytes());
            OsStr::from_bytes(&p).into()
        };

        match dir.lookup(name) {
            Some(inode) => match self.child_ino(inode, &child_path) {
                Some(ino) => {
                    let attrs = self.inode_data[(ino as usize) - 1].attrs();
                    reply.entry(&TTL, attrs, Generation(0));
                }
                None => {
                    log::error!("lookup({parent}, {name:?}): child inode not in table");
                    reply.error(fuser::Errno::EIO);
                }
            },
            None => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.get_data(ino.0) {
            Some(data) => reply.attr(&TTL, data.attrs()),
            None => {
                log::error!("getattr({ino}): inode does not exist");
                reply.error(fuser::Errno::EBADF);
            }
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let Some(leaf) = self.resolve_leaf(ino.0) else {
            return reply.error(fuser::Errno::EINVAL);
        };
        let LeafContent::Symlink(target) = &leaf.content else {
            return reply.error(fuser::Errno::EINVAL);
        };
        reply.data(target.as_bytes());
    }

    fn opendir(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let ino = ino.0;
        let Some(InodeData::Dir {
            parent_ino,
            path: dir_path,
            ..
        }) = self.get_data(ino)
        else {
            log::error!("readdir({ino}): inode is not a directory");
            return reply.error(fuser::Errno::EBADF);
        };
        let parent_ino = *parent_ino;
        let dir_path = dir_path.clone();

        let Some(dir) = self.resolve_dir(ino) else {
            log::error!("readdir({ino}): failed to resolve directory");
            return reply.error(fuser::Errno::EIO);
        };

        let mut cur_offset = offset;

        if cur_offset == 0 {
            cur_offset += 1;
            if reply.add(INodeNo(ino), cur_offset, FileType::Directory, ".") {
                return reply.ok();
            }
        }

        if cur_offset == 1 {
            cur_offset += 1;
            if reply.add(INodeNo(parent_ino), cur_offset, FileType::Directory, "..") {
                return reply.ok();
            }
        }

        for (name, inode) in dir.sorted_entries().skip((cur_offset as usize) - 2) {
            let child_path = child_path_from(&dir_path, name);
            let Some(child_ino) = self.child_ino(inode, &child_path) else {
                log::error!("readdir({ino}): child {name:?} not in inode table");
                continue;
            };
            let kind = self.inode_data[(child_ino as usize) - 1].attrs().kind;
            cur_offset += 1;
            if reply.add(INodeNo(child_ino), cur_offset, kind, name) {
                break;
            }
        }

        reply.ok();
    }

    fn readdirplus(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let ino = ino.0;
        let Some(InodeData::Dir {
            parent_ino,
            path: dir_path,
            attrs: dir_attrs,
            ..
        }) = self.get_data(ino)
        else {
            log::error!("readdirplus({ino}): inode is not a directory");
            return reply.error(fuser::Errno::EBADF);
        };
        let parent_ino = *parent_ino;
        let dir_path = dir_path.clone();
        let dir_attrs = *dir_attrs;

        let parent_attrs = self
            .get_data(parent_ino)
            .map(|d| *d.attrs())
            .unwrap_or(dir_attrs);

        let Some(dir) = self.resolve_dir(ino) else {
            log::error!("readdirplus({ino}): failed to resolve directory");
            return reply.error(fuser::Errno::EIO);
        };

        let mut cur_offset = offset;

        if cur_offset == 0 {
            cur_offset += 1;
            if reply.add(
                INodeNo(ino),
                cur_offset,
                ".",
                &TTL,
                &dir_attrs,
                Generation(0),
            ) {
                return reply.ok();
            }
        }

        if cur_offset == 1 {
            cur_offset += 1;
            if reply.add(
                INodeNo(parent_ino),
                cur_offset,
                "..",
                &TTL,
                &parent_attrs,
                Generation(0),
            ) {
                return reply.ok();
            }
        }

        for (name, inode) in dir.sorted_entries().skip((cur_offset as usize) - 2) {
            let child_path = child_path_from(&dir_path, name);
            let Some(child_ino) = self.child_ino(inode, &child_path) else {
                log::error!("readdirplus({ino}): child {name:?} not in inode table");
                continue;
            };
            let child_attrs = self.inode_data[(child_ino as usize) - 1].attrs();
            cur_offset += 1;
            if reply.add(
                INodeNo(child_ino),
                cur_offset,
                name,
                &TTL,
                child_attrs,
                Generation(0),
            ) {
                break;
            }
        }

        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }

    fn getxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let ino = ino.0;
        match self.resolve_stat(ino) {
            None => {
                log::error!("getxattr({ino}, {name:?}, {size}): inode does not exist");
                reply.error(fuser::Errno::EBADF);
            }
            Some(Err(())) => reply.error(fuser::Errno::EIO),
            Some(Ok(stat)) => match stat.xattrs.get(name) {
                None => reply.error(fuser::Errno::ENODATA),
                Some(value) => {
                    if size == 0 {
                        reply.size(value.len() as u32);
                    } else if value.len() > size as usize {
                        reply.error(fuser::Errno::ERANGE);
                    } else {
                        reply.data(value);
                    }
                }
            },
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: fuser::ReplyXattr) {
        let ino = ino.0;
        match self.resolve_stat(ino) {
            None => {
                log::error!("listxattr({ino}, {size}): inode does not exist");
                reply.error(fuser::Errno::EBADF);
            }
            Some(Err(())) => reply.error(fuser::Errno::EIO),
            Some(Ok(stat)) => {
                let mut list = vec![];
                for k in stat.xattrs.keys() {
                    list.extend_from_slice(k.as_bytes());
                    list.push(b'\0');
                }
                if size == 0 {
                    reply.size(list.len() as u32);
                } else if list.len() > size as usize {
                    reply.error(fuser::Errno::ERANGE);
                } else {
                    reply.data(&list);
                }
            }
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let ino = ino.0;
        log::trace!("open({ino})");

        let Some(InodeData::Leaf { leaf_id, .. }) = self.get_data(ino) else {
            log::error!("open({ino}): inode is not a regular file");
            return reply.error(fuser::Errno::EBADF);
        };

        let leaf = self.fs.leaf(*leaf_id);
        let handle = match &leaf.content {
            LeafContent::Regular(RegularFile::External(id, ..)) => {
                let Ok(fd) = self.repo.open_object(id) else {
                    log::error!("open({ino}): failed to open object");
                    return reply.error(fuser::Errno::EIO);
                };
                // If passthrough is enabled, try to register the fd with the
                // kernel so reads bypass the userspace path entirely.
                if self
                    .passthrough_enabled
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    let fd = Arc::new(fd);
                    match reply.open_backing(fd.as_fd()) {
                        Ok(backing_id) => {
                            let mut state =
                                self.handles.lock().expect("fuse handles mutex poisoned");
                            let fh = state.next_fh;
                            state.next_fh += 1;
                            let backing_id = Arc::new(backing_id);
                            log::debug!("open({ino}): inserted passthrough handle {fh}");
                            state.handles.insert(
                                fh,
                                OpenHandle::Passthrough {
                                    backing_id: Arc::clone(&backing_id),
                                    fd: Arc::clone(&fd),
                                },
                            );
                            return reply.opened_passthrough(
                                FileHandle(fh),
                                FopenFlags::FOPEN_KEEP_CACHE,
                                &backing_id,
                            );
                        }
                        Err(err) => {
                            log::warn!(
                                "open({ino}): open_backing failed ({err}), disabling passthrough"
                            );
                            self.passthrough_enabled
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                            // fall through to userspace-read path below
                        }
                    }
                    // Fallback: unwrap Arc (only one reference at this point)
                    let fd = Arc::try_unwrap(fd).expect("no other Arc refs");
                    OpenHandle::Fd(Arc::new(fd))
                } else {
                    OpenHandle::Fd(Arc::new(fd))
                }
            }
            LeafContent::Regular(RegularFile::Inline(data)) => {
                OpenHandle::Data(Arc::from(data.as_ref()))
            }
            _ => {
                log::error!("open({ino}): not a regular file");
                return reply.error(fuser::Errno::EBADF);
            }
        };

        let mut state = self.handles.lock().expect("fuse handles mutex poisoned");
        let fh = state.next_fh;
        state.next_fh += 1;
        log::debug!("open({ino}): inserted handle {fh}");
        state.handles.insert(fh, handle);
        // FOPEN_KEEP_CACHE tells the kernel it may reuse cached pages across
        // open/close cycles. This is always safe for our read-only filesystem.
        reply.opened(FileHandle(fh), FopenFlags::FOPEN_KEEP_CACHE);
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        // Clone the Arc handle so we can release the lock before doing I/O.
        // Holding the mutex across pread() would serialise all concurrent reads
        // onto a single lock, negating the benefit of multithreaded sessions.
        let handle = {
            let state = self.handles.lock().expect("fuse handles mutex poisoned");
            state.handles.get(&fh.0).cloned()
        };
        match handle {
            Some(OpenHandle::Fd(fd)) => {
                let mut data = Vec::with_capacity(size as usize);
                match pread(&*fd, spare_capacity(&mut data), offset) {
                    Ok(_) => reply.data(&data),
                    Err(errno) => {
                        reply.error(errno_to_fuser(errno));
                    }
                }
            }
            Some(OpenHandle::Data(data)) => {
                let start = (offset as usize).min(data.len());
                let end = (start + size as usize).min(data.len());
                reply.data(&data[start..end]);
            }
            Some(OpenHandle::Passthrough { .. }) => {
                // The kernel should never call read() on a passthrough handle;
                // it reads directly from the backing fd. Handle defensively.
                log::error!("read(fh={fh}): unexpected read on passthrough handle");
                reply.error(fuser::Errno::EBADF);
            }
            None => {
                log::error!("read(fh={fh}): handle does not exist");
                reply.error(fuser::Errno::EBADF);
            }
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let mut state = self.handles.lock().expect("fuse handles mutex poisoned");
        match state.handles.remove(&fh.0) {
            Some(_) => reply.ok(),
            None => {
                log::error!("release(fh={fh}): handle does not exist");
                reply.error(fuser::Errno::EBADF);
            }
        }
    }
}

/// Construct the child path given the parent's path and the entry name.
fn child_path_from(parent_path: &OsStr, name: &OsStr) -> Box<OsStr> {
    if parent_path.is_empty() {
        name.into()
    } else {
        let mut p = parent_path.as_bytes().to_vec();
        p.push(b'/');
        p.extend_from_slice(name.as_bytes());
        OsStr::from_bytes(&p).into()
    }
}

/// Convert a `rustix::io::Errno` to the corresponding `fuser::Errno`.
fn errno_to_fuser(errno: rustix::io::Errno) -> fuser::Errno {
    fuser::Errno::from(std::io::Error::from_raw_os_error(errno.raw_os_error()))
}

/// Configuration for [`serve_tree_fuse`].
#[derive(Debug, Default)]
pub struct FuseConfig {
    /// Enable FUSE passthrough for external files (Linux 6.9+, requires root
    /// and a backing filesystem that supports passthrough reads).
    ///
    /// When true and the kernel supports `FUSE_PASSTHROUGH`, external file
    /// reads are routed directly in-kernel to the repository object fds,
    /// eliminating userspace context-switch overhead.
    ///
    /// Defaults to `false`. Set to `true` only when you know the backing
    /// filesystem supports passthrough (e.g. ext4, xfs — not tmpfs).
    pub passthrough: bool,
}

/// Opens `/dev/fuse`, returning the device fd.
///
/// The returned fd should be passed to [`mount_fuse`] (to create a detached mount object
/// via `fsopen`/`fsmount`) and then to [`serve_tree_fuse_fd`] to start serving requests.
/// Splitting open/mount/serve into three steps lets callers attach the mount fd to an
/// arbitrary path — or move it into a container namespace — between `mount_fuse` and
/// `serve_tree_fuse_fd`.
pub fn open_fuse() -> anyhow::Result<OwnedFd> {
    use anyhow::Context as _;
    use rustix::fs::{Mode, OFlags, open};
    open("/dev/fuse", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
        .context("Unable to open fuse device /dev/fuse")
}

/// Creates a detached FUSE mount object for `dev_fuse` via the `fsopen`/`fsmount` API.
///
/// Returns an unattached mount fd. The caller must use [`composefs::mount::mount_at`] (or
/// `move_mount`) to attach it to a path before calling [`serve_tree_fuse_fd`].
///
/// This path requires `CAP_SYS_ADMIN` (Linux kernel ≥ 5.2). For unprivileged mounts,
/// use the high-level [`serve_tree_fuse`] instead, which falls back to the `fusermount3`
/// setuid helper automatically.
pub fn mount_fuse(dev_fuse: impl AsFd) -> anyhow::Result<OwnedFd> {
    use composefs::mount::FsHandle;
    use rustix::mount::{
        FsMountFlags, MountAttrFlags, fsconfig_create, fsconfig_set_flag, fsconfig_set_string,
        fsmount,
    };
    let fusefs = FsHandle::open("fuse")?;
    fsconfig_set_flag(fusefs.as_fd(), "ro")?;
    fsconfig_set_flag(fusefs.as_fd(), "default_permissions")?;
    fsconfig_set_flag(fusefs.as_fd(), "allow_other")?;
    fsconfig_set_string(fusefs.as_fd(), "source", "composefs-fuse")?;
    fsconfig_set_string(fusefs.as_fd(), "rootmode", "040555")?;
    fsconfig_set_string(fusefs.as_fd(), "user_id", "0")?;
    fsconfig_set_string(fusefs.as_fd(), "group_id", "0")?;
    fsconfig_set_string(
        fusefs.as_fd(),
        "fd",
        format!("{}", dev_fuse.as_fd().as_raw_fd()),
    )?;
    fsconfig_create(fusefs.as_fd())?;
    Ok(fsmount(
        fusefs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

/// Build the `TreeFuse` filesystem object and the fuser `Config` from the given inputs.
///
/// This shared helper factors out the construction work that is common to both
/// [`serve_tree_fuse`] (high-level, path-based) and [`serve_tree_fuse_fd`]
/// (low-level, pre-mounted fd).
fn build_fuse_session_parts<ObjectID: FsVerityHashValue>(
    filesystem: Arc<FileSystem<ObjectID>>,
    repo: Arc<Repository<ObjectID>>,
    config: FuseConfig,
) -> (TreeFuse<ObjectID>, Config) {
    let InodeTable {
        data: inode_data,
        lookup,
    } = build_inode_table(&filesystem);

    let tf = TreeFuse::<ObjectID> {
        repo,
        fs: filesystem,
        inode_data,
        lookup,
        handles: Mutex::new(FuseHandles::default()),
        passthrough_requested: config.passthrough,
        passthrough_enabled: std::sync::atomic::AtomicBool::new(false),
    };

    let n_threads: usize = std::thread::available_parallelism()
        .unwrap_or(NonZeroUsize::new(1).unwrap())
        .get();
    let mut session_config = Config::default();
    session_config.n_threads = Some(n_threads);
    // clone_fd gives each worker thread its own /dev/fuse fd via FUSE_DEV_IOC_CLONE,
    // avoiding per-request lock contention on the shared channel (Linux 4.5+).
    session_config.clone_fd = true;

    (tf, session_config)
}

/// Mounts and serves a FUSE filesystem exposing the content of `filesystem`, backed by `repo`.
///
/// Mounts at `mountpoint` and blocks until the session ends (i.e. until the mountpoint is
/// unmounted). Uses `Session::new` which tries the new `fsopen`/`fsmount` kernel API first and
/// automatically falls back to the `fusermount3` setuid helper, so unprivileged callers work
/// without any extra setup.
///
/// FUSE passthrough I/O is opt-in via [`FuseConfig::passthrough`]. When enabled, the
/// kernel reads object data directly from the backing fd, bypassing userspace entirely
/// for external files. This requires root (`CAP_SYS_ADMIN`) **and** a backing filesystem
/// that supports passthrough reads (e.g. ext4, xfs — not tmpfs).
///
/// Uses one worker thread per logical CPU with per-thread fd cloning
/// (`FUSE_DEV_IOC_CLONE`) to avoid kernel channel-lock contention under load.
/// This is safe because [`TreeFuse`] is `Send + Sync` and the filesystem is
/// read-only.
pub fn serve_tree_fuse<ObjectID: FsVerityHashValue>(
    mountpoint: impl AsRef<Path>,
    filesystem: Arc<FileSystem<ObjectID>>,
    repo: Arc<Repository<ObjectID>>,
    config: FuseConfig,
) -> std::io::Result<()> {
    let (tf, mut session_config) = build_fuse_session_parts(filesystem, repo, config);
    session_config.mount_options = vec![MountOption::RO, MountOption::DefaultPermissions];
    Session::new(tf, mountpoint.as_ref(), &session_config)?
        .spawn()?
        .join()
}

/// Serves a FUSE filesystem over a caller-supplied, pre-mounted `/dev/fuse` fd.
///
/// Use this together with [`open_fuse`] and [`mount_fuse`] when you need control over
/// the mount lifecycle — for example, to attach the mount fd to a path inside a container
/// namespace with `move_mount` before handing it to the FUSE server. The caller is
/// responsible for attaching the mount fd (via [`composefs::mount::mount_at`]) before
/// calling this function, and for keeping the mount fd alive for the duration of the
/// session.
///
/// This function blocks until the FUSE session ends.
pub fn serve_tree_fuse_fd<ObjectID: FsVerityHashValue>(
    dev_fuse: OwnedFd,
    filesystem: Arc<FileSystem<ObjectID>>,
    repo: Arc<Repository<ObjectID>>,
    config: FuseConfig,
) -> std::io::Result<()> {
    let (tf, session_config) = build_fuse_session_parts(filesystem, repo, config);
    Session::from_fd(tf, dev_fuse, SessionACL::All, session_config)?
        .spawn()?
        .join()
}
