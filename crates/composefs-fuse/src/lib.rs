//! FUSE filesystem implementation for composefs trees.
//!
//! This crate provides a userspace filesystem implementation that exposes composefs
//! directory trees through FUSE. It supports read-only access to files, directories,
//! symlinks, and extended attributes, with data served from a composefs repository.

#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    ffi::OsStr,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    time::{Duration, SystemTime},
};

use anyhow::Context;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    Request, Session, SessionACL,
};
use rustix::{
    buffer::spare_capacity,
    fs::{Mode, OFlags, open},
    io::{Errno, pread},
    mount::{
        FsMountFlags, MountAttrFlags, fsconfig_create, fsconfig_set_flag, fsconfig_set_string,
        fsmount,
    },
};

use composefs::{
    fsverity::FsVerityHashValue,
    generic_tree::LeafId,
    mount::FsHandle,
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

/// Precomputed inode number assignments for the entire filesystem tree.
///
/// Directories are identified by pointer (stable because the tree is
/// borrowed immutably for the lifetime of the FUSE session). Leaves
/// are identified by `LeafId`.
#[derive(Debug)]
struct InodeMap<ObjectID: FsVerityHashValue> {
    /// Directory pointer → inode number.
    dir_inos: HashMap<*const Directory<ObjectID>, Ino>,
    /// LeafId → inode number. Indexed by `LeafId.0`.
    /// Hardlinked leaves (same `LeafId`) naturally get the same ino.
    leaf_inos: Vec<Ino>,
}

impl<ObjectID: FsVerityHashValue> InodeMap<ObjectID> {
    /// Walk the tree and assign sequential inode numbers.
    fn build(fs: &FileSystem<ObjectID>) -> Self {
        let mut next_ino: Ino = 1; // root = 1
        let mut dir_inos = HashMap::new();
        let mut leaf_inos = vec![0u64; fs.leaves.len()];

        fn walk<O: FsVerityHashValue>(
            dir: &Directory<O>,
            next_ino: &mut Ino,
            dir_inos: &mut HashMap<*const Directory<O>, Ino>,
            leaf_inos: &mut [Ino],
        ) {
            let ino = *next_ino;
            *next_ino += 1;
            dir_inos.insert(dir as *const _, ino);

            for (_, inode) in dir.entries() {
                match inode {
                    Inode::Directory(subdir) => walk(subdir, next_ino, dir_inos, leaf_inos),
                    Inode::Leaf(id, _) => {
                        if leaf_inos[id.0] == 0 {
                            leaf_inos[id.0] = *next_ino;
                            *next_ino += 1;
                        }
                        // Hardlinks: same LeafId keeps the same ino.
                    }
                }
            }
        }

        walk(&fs.root, &mut next_ino, &mut dir_inos, &mut leaf_inos);
        InodeMap {
            dir_inos,
            leaf_inos,
        }
    }

    fn dir_ino(&self, dir: &Directory<ObjectID>) -> Ino {
        self.dir_inos[&(dir as *const _)]
    }

    fn leaf_ino(&self, id: LeafId) -> Ino {
        self.leaf_inos[id.0]
    }

    fn inode_ino(&self, inode: &Inode<ObjectID>) -> Ino {
        match inode {
            Inode::Directory(dir) => self.dir_ino(dir),
            Inode::Leaf(id, _) => self.leaf_ino(*id),
        }
    }
}

/// A reference to a filesystem node, used for FUSE inode lookup.
#[derive(Debug, Clone)]
enum InodeRef<'a, ObjectID: FsVerityHashValue> {
    Directory(&'a Directory<ObjectID>, Ino),
    Leaf(LeafId, &'a Leaf<ObjectID>),
}

impl<'a, ObjectID: FsVerityHashValue> InodeRef<'a, ObjectID> {
    fn nlink(&self, nlink_map: &[u32]) -> u32 {
        (match self {
            InodeRef::Directory(dir, ..) => {
                2 + dir
                    .inodes()
                    .filter(|i| matches!(i, Inode::Directory(..)))
                    .count()
            }
            InodeRef::Leaf(leaf_id, _) => nlink_map[leaf_id.0] as usize,
        }) as u32
    }

    fn rdev(&self) -> u32 {
        (match self {
            InodeRef::Directory(..) => 0,
            InodeRef::Leaf(_, leaf) => match &leaf.content {
                LeafContent::BlockDevice(rdev) | LeafContent::CharacterDevice(rdev) => *rdev,
                _ => 0,
            },
        }) as u32
    }

    fn kind(&self) -> FileType {
        match self {
            InodeRef::Directory(..) => FileType::Directory,
            InodeRef::Leaf(_, leaf) => match leaf.content {
                LeafContent::BlockDevice(..) => FileType::BlockDevice,
                LeafContent::CharacterDevice(..) => FileType::CharDevice,
                LeafContent::Fifo => FileType::NamedPipe,
                LeafContent::Regular(..) => FileType::RegularFile,
                LeafContent::Socket => FileType::Socket,
                LeafContent::Symlink(..) => FileType::Symlink,
            },
        }
    }

    fn stat(&self) -> &'a Stat {
        match self {
            InodeRef::Directory(dir, ..) => &dir.stat,
            InodeRef::Leaf(_, leaf) => &leaf.stat,
        }
    }

    fn size(&self) -> u64 {
        match self {
            InodeRef::Directory(..) => 0,
            InodeRef::Leaf(_, leaf) => match &leaf.content {
                LeafContent::Regular(RegularFile::Inline(data)) => data.len() as u64,
                LeafContent::Regular(RegularFile::External(.., size)) => *size,
                _ => 0,
            },
        }
    }

    fn fileattr(&self, ino: Ino, nlink_map: &[u32]) -> FileAttr {
        let stat = self.stat();
        let mtime =
            SystemTime::UNIX_EPOCH + Duration::new(stat.st_mtim_sec as u64, stat.st_mtim_nsec);

        FileAttr {
            ino,
            size: self.size(),
            blocks: 1,
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind: self.kind(),
            perm: stat.st_mode as u16,
            nlink: self.nlink(nlink_map),
            uid: stat.st_uid,
            gid: stat.st_gid,
            rdev: self.rdev(),
            blksize: 4096,
            flags: 0,
        }
    }
}

#[derive(Debug)]
enum OpenHandle {
    Fd(OwnedFd),
    Data(Box<[u8]>),
}

#[derive(Debug)]
struct TreeFuse<'a, ObjectID: FsVerityHashValue> {
    repo: &'a Repository<ObjectID>,
    fs: &'a FileSystem<ObjectID>,
    inode_map: InodeMap<ObjectID>,
    nlink_map: Vec<u32>,
    inodes: HashMap<Ino, InodeRef<'a, ObjectID>>,
    attrs: HashMap<Ino, FileAttr>,
    handles: HashMap<u64, OpenHandle>,
    next_fh: u64,
}

impl<'a, ObjectID: FsVerityHashValue> TreeFuse<'a, ObjectID> {
    fn register_inode(&mut self, inode: &'a Inode<ObjectID>, parent: Ino) -> (Ino, FileType) {
        let ino = self.inode_map.inode_ino(inode);
        let iref = match inode {
            Inode::Directory(dir) => InodeRef::Directory(dir, parent),
            Inode::Leaf(leaf_id, _) => InodeRef::Leaf(*leaf_id, self.fs.leaf(*leaf_id)),
        };
        let kind = iref.kind();
        self.attrs.insert(ino, iref.fileattr(ino, &self.nlink_map));
        self.inodes.insert(ino, iref);
        (ino, kind)
    }
}

impl<ObjectID: FsVerityHashValue> Filesystem for TreeFuse<'_, ObjectID> {
    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: fuser::ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 4096, 255, 4096);
    }

    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        log::trace!("lookup {parent} {name:?}");
        let Some(InodeRef::Directory(dir, ..)) = self.inodes.get(&parent) else {
            log::error!("lookup({parent}, {name:?}) parent does not exist");
            return reply.error(Errno::BADF.raw_os_error());
        };
        let dir = *dir;

        match dir.lookup(name) {
            Some(inode) => {
                let (ino, _) = self.register_inode(inode, parent);
                reply.entry(&TTL, self.attrs.get(&ino).unwrap(), 0);
            }
            None => reply.error(Errno::NOENT.raw_os_error()),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if let Some(attrs) = self.attrs.get(&ino) {
            return reply.attr(&TTL, attrs);
        }

        let Some(iref) = self.inodes.get(&ino) else {
            log::error!("getattr({ino}) inode does not exist");
            return reply.error(Errno::BADF.raw_os_error());
        };
        let iref = iref.clone();

        let attr = iref.fileattr(ino, &self.nlink_map);
        self.attrs.insert(ino, attr);
        reply.attr(&TTL, self.attrs.get(&ino).unwrap());
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let Some(InodeRef::Leaf(_, leaf)) = self.inodes.get(&ino) else {
            return reply.error(Errno::INVAL.raw_os_error());
        };

        let LeafContent::Symlink(target) = &leaf.content else {
            return reply.error(Errno::INVAL.raw_os_error());
        };

        reply.data(target.as_bytes());
    }

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        mut offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(InodeRef::Directory(dir, parent)) = self.inodes.get(&ino) else {
            log::error!("readdir({ino}) inode is not a directory");
            return reply.error(Errno::BADF.raw_os_error());
        };
        let (dir, parent) = (*dir, *parent);

        if offset == 0 {
            offset += 1;
            if reply.add(ino, offset, FileType::Directory, ".") {
                return reply.ok();
            }
        }

        if offset == 1 {
            offset += 1;
            if reply.add(parent, offset, FileType::Directory, "..") {
                return reply.ok();
            }
        }

        for (name, inode) in dir.sorted_entries().skip(offset as usize - 2) {
            let (child_ino, kind) = self.register_inode(inode, ino);

            offset += 1;
            if reply.add(child_ino, offset, kind, name) {
                break;
            }
        }

        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }

    fn getxattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let Some(iref) = self.inodes.get(&ino) else {
            log::error!("getxattr({ino}, {name:?}, {size}) inode does not exist");
            return reply.error(Errno::BADF.raw_os_error());
        };

        let xattrs = &iref.stat().xattrs;
        let Some(value) = xattrs.get(name) else {
            return reply.error(Errno::NODATA.raw_os_error());
        };

        if size == 0 {
            return reply.size(value.len() as u32);
        } else if value.len() > size as usize {
            return reply.error(Errno::RANGE.raw_os_error());
        }

        reply.data(value);
    }

    fn listxattr(&mut self, _req: &Request<'_>, ino: u64, size: u32, reply: fuser::ReplyXattr) {
        let Some(iref) = self.inodes.get(&ino) else {
            log::error!("listxattr({ino}, {size}) inode does not exist");
            return reply.error(Errno::BADF.raw_os_error());
        };

        let mut list = vec![];
        for name in iref.stat().xattrs.keys() {
            list.extend_from_slice(name.as_bytes());
            list.push(b'\0');
        }

        if size == 0 {
            return reply.size(list.len() as u32);
        } else if list.len() > size as usize {
            return reply.error(Errno::RANGE.raw_os_error());
        }

        reply.data(&list);
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        log::trace!("open({ino})");
        let Some(iref) = self.inodes.get(&ino) else {
            log::error!("open({ino}) inode does not exist");
            return reply.error(Errno::BADF.raw_os_error());
        };

        let InodeRef::Leaf(_, leaf) = iref else {
            log::error!("open({ino}) inode is a directory");
            return reply.error(Errno::BADF.raw_os_error());
        };

        let handle = match &leaf.content {
            LeafContent::Regular(RegularFile::External(id, ..)) => {
                let Ok(fd) = self.repo.open_object(id) else {
                    log::error!("open({ino}) open object failed");
                    return reply.error(Errno::INVAL.raw_os_error());
                };
                OpenHandle::Fd(fd)
            }
            LeafContent::Regular(RegularFile::Inline(data)) => OpenHandle::Data(data.clone()),
            _ => {
                log::error!("open({ino}) non-regular file");
                return reply.error(Errno::BADF.raw_os_error());
            }
        };

        let fh = self.next_fh;
        self.next_fh += 1;
        log::debug!("self.handles.insert({fh}, {handle:?})");
        self.handles.insert(fh, handle);
        reply.opened(fh, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        match self.handles.get(&fh) {
            Some(OpenHandle::Fd(fd)) => {
                let mut data = Vec::with_capacity(size as usize);
                match pread(fd, spare_capacity(&mut data), offset as u64) {
                    Ok(_) => reply.data(&data),
                    Err(errno) => reply.error(errno.raw_os_error()),
                }
            }
            Some(OpenHandle::Data(data)) => {
                if offset as usize > data.len() {
                    reply.data(b"");
                } else {
                    let mut data = &data[offset as usize..];
                    if data.len() > size as usize {
                        data = &data[..size as usize];
                    }
                    reply.data(data);
                }
            }
            None => {
                log::error!("Handle doesn't exist: pread({fh}, {size}, {offset})");
                reply.error(Errno::BADF.raw_os_error());
            }
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        match self.handles.remove(&fh) {
            Some(_) => reply.ok(),
            None => {
                log::error!("Handle doesn't exist: close({fh})");
                reply.error(Errno::BADF.raw_os_error())
            }
        }
    }
}

/// Opens /dev/fuse.
///
/// After you do this, you can mount it using mount_fuse() and then start serving requests using
/// serve_tree_fuse().  You might want to do this in different threads, which is why these
/// operations are defined separately.
pub fn open_fuse() -> anyhow::Result<OwnedFd> {
    open("/dev/fuse", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
        .context("Unable to open fuse device /dev/fuse")
}

/// Mounts a FUSE filesystem with the given /dev/fuse fd.
///
/// This does the necessary dance of creating the mount object, given a /dev/fuse device node.  In
/// order for this to be useful, you'll also need to call serve_tree_fuse() to actually satisfy the
/// requests for data.
pub fn mount_fuse(dev_fuse: impl AsFd) -> anyhow::Result<OwnedFd> {
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

/// Serves a FUSE filesystem exposing the content of `filesystem`, backed by `repo`.
///
/// You should have called mount_fuse() on the dev_fuse fd to establish a mount point.
pub fn serve_tree_fuse<'a, ObjectID: FsVerityHashValue>(
    dev_fuse: OwnedFd,
    filesystem: &'a FileSystem<ObjectID>,
    repo: &'a Repository<ObjectID>,
) -> std::io::Result<()> {
    let inode_map = InodeMap::build(filesystem);
    let nlink_map = filesystem.nlinks();

    let root_ino = inode_map.dir_ino(&filesystem.root);
    let root_ref = InodeRef::Directory(&filesystem.root, root_ino);
    let root_attr = root_ref.fileattr(root_ino, &nlink_map);

    let tf = TreeFuse::<ObjectID> {
        repo,
        fs: filesystem,
        inode_map,
        nlink_map,
        inodes: HashMap::from([(root_ino, root_ref)]),
        attrs: HashMap::from([(root_ino, root_attr)]),
        handles: Default::default(),
        next_fh: 1,
    };
    Session::from_fd(tf, dev_fuse, SessionACL::All).run()
}
