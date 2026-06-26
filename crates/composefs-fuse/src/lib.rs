//! FUSE filesystem implementation for composefs EROFS images.
//!
//! This crate serves a composefs EROFS image directly over FUSE without
//! parsing the entire image into a high-level tree. FUSE inode numbers
//! are EROFS NIDs, and all metadata is resolved on demand from the
//! on-disk structures.

#![deny(unsafe_code)]

use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::OsStr,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::Context;
use fuser::{
    Config, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEntry,
    ReplyOpen, Request, Session, SessionACL,
};
use rustix::{
    buffer::spare_capacity,
    fs::{Mode, OFlags, open, openat},
    io::pread,
    mount::{
        FsMountFlags, MountAttrFlags, fsconfig_create, fsconfig_set_flag, fsconfig_set_string,
        fsmount,
    },
};

use zerocopy::FromBytes as _;

use composefs::{
    erofs::{
        format::{
            self, DataLayout, FileType as ErofsFileType, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO,
            S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, XATTR_PREFIXES,
        },
        reader::{DirectoryBlock, Image, InodeHeader, InodeOps, InodeType},
    },
    mount::FsHandle,
    mountcompat::{overlayfs_set_fd, overlayfs_set_lower_and_data_fds, prepare_mount},
};

const TTL: Duration = Duration::from_secs(1_000_000);

/// Controls the overlay xattr namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OverlayXattrMode {
    /// Synthesize `user.overlay.*` xattrs (for unprivileged `userxattr` mounts).
    #[default]
    User,
    /// Synthesize `trusted.overlay.*` xattrs (requires CAP_SYS_ADMIN).
    Trusted,
}

/// EROFS node ID — byte offset / 32 into the inode region.
///
/// Distinct from fuser's [`INodeNo`] because FUSE requires inode 1 for the
/// root directory, but the EROFS root NID (from `superblock.root_nid`) can
/// be any value — including small values like 0 or 1.
///
/// To avoid collisions, non-root NIDs are mapped to FUSE inodes as
/// `NID + 2` (since FUSE reserves ino 0 as invalid and ino 1 as the root).
/// The root NID is always mapped to FUSE inode 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Nid(u64);

impl std::fmt::Display for Nid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Nid {
    fn to_fuse_ino(self, root_nid: Nid) -> INodeNo {
        if self == root_nid {
            INodeNo(1)
        } else {
            INodeNo(self.0 + 2)
        }
    }

    fn from_fuse_ino(ino: INodeNo, root_nid: Nid) -> Option<Self> {
        match ino.0 {
            0 => None,
            1 => Some(root_nid),
            n => Some(Nid(n - 2)),
        }
    }
}

fn mode_to_filetype(mode: u16) -> FileType {
    match mode & S_IFMT {
        S_IFREG => FileType::RegularFile,
        S_IFDIR => FileType::Directory,
        S_IFCHR => FileType::CharDevice,
        S_IFBLK => FileType::BlockDevice,
        S_IFIFO => FileType::NamedPipe,
        S_IFLNK => FileType::Symlink,
        S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

fn inode_rdev(inode: &InodeType) -> u32 {
    let mode = inode.mode().0.get();
    match mode & S_IFMT {
        S_IFCHR | S_IFBLK => inode.u(),
        _ => 0,
    }
}

fn inode_fileattr(image: &Image, ino: INodeNo, inode: &InodeType) -> FileAttr {
    let mode = inode.mode().0.get();
    let mtime = match inode {
        InodeType::Extended(i) => {
            let secs = (i.header.mtime.get() as i64).max(0) as u64;
            SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
        }
        InodeType::Compact(_) => {
            let secs = (image.sb.build_time.get() as i64).max(0) as u64;
            SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
        }
    };
    let (uid, gid) = match inode {
        InodeType::Extended(i) => (i.header.uid.get(), i.header.gid.get()),
        InodeType::Compact(i) => (i.header.uid.get() as u32, i.header.gid.get() as u32),
    };
    let size = match mode & S_IFMT {
        S_IFDIR => 0,
        _ => inode.size(),
    };

    FileAttr {
        ino,
        size,
        blocks: 1,
        atime: mtime,
        mtime,
        ctime: mtime,
        crtime: mtime,
        kind: mode_to_filetype(mode),
        perm: mode & 0o7777,
        nlink: inode.nlink(),
        uid,
        gid,
        rdev: inode_rdev(inode),
        blksize: 4096,
        flags: 0,
    }
}

fn inode_fileattr_overlay(image: &Image, ino: INodeNo, inode: &InodeType) -> FileAttr {
    let mut attr = inode_fileattr(image, ino, inode);
    if is_whiteout(image, inode) {
        attr.kind = FileType::RegularFile;
        attr.size = 0;
        attr.rdev = 0;
    }
    attr
}

/// Returns true if this inode carries the escaped whiteout xattr that tells
/// overlayfs to treat it as a whiteout.  Used in overlay mode to adjust the
/// file attributes (present as a regular file with size 0 instead of the
/// underlying EROFS type).
fn is_whiteout(image: &Image, inode: &InodeType) -> bool {
    has_xattr(image, inode, b"trusted.overlay.overlay.whiteout")
}

/// Returns true if this inode is any kind of overlayfs whiteout in the raw
/// EROFS lower layer.  This covers both native whiteouts (char device 0,0,
/// including the 256 hex stubs the V1 writer adds to the root directory)
/// and V1-escaped whiteouts (regular files with the escaped whiteout xattr).
/// Used in non-overlay mode to hide these implementation details from the
/// final mount.
fn is_overlayfs_whiteout(image: &Image, inode: &InodeType) -> bool {
    let mode = inode.mode().0.get();
    if mode & S_IFMT == S_IFCHR && inode.u() == 0 {
        return true;
    }
    has_xattr(image, inode, b"trusted.overlay.overlay.whiteout")
}

fn has_xattr(image: &Image, inode: &InodeType, name: &[u8]) -> bool {
    find_raw_xattr(image, inode, name).is_some()
}

fn find_raw_xattr(image: &Image, inode: &InodeType, name: &[u8]) -> Option<Vec<u8>> {
    let xattrs_section = inode.xattrs().ok()??;
    for id in xattrs_section.shared().ok()? {
        let xattr = image.shared_xattr(id.get()).ok()?;
        if xattr_full_name(xattr) == name {
            return Some(xattr.value().ok()?.to_vec());
        }
    }
    for xattr_result in xattrs_section.local().ok()? {
        let xattr = xattr_result.ok()?;
        if xattr_full_name(xattr) == name {
            return Some(xattr.value().ok()?.to_vec());
        }
    }
    None
}

fn xattr_full_name(xattr: &composefs::erofs::reader::XAttr) -> Vec<u8> {
    let idx = xattr.header.name_index as usize;
    let prefix = if idx < XATTR_PREFIXES.len() {
        XATTR_PREFIXES[idx]
    } else {
        b""
    };
    let suffix = xattr.suffix().unwrap_or(b"");
    let mut name = Vec::with_capacity(prefix.len() + suffix.len());
    name.extend_from_slice(prefix);
    name.extend_from_slice(suffix);
    name
}

const TRUSTED_OVERLAY_PREFIX: &[u8] = b"trusted.overlay.";
const USER_OVERLAY_PREFIX: &[u8] = b"user.overlay.";
const ESCAPED_OVERLAY_PREFIX: &[u8] = b"trusted.overlay.overlay.";

fn is_overlayfs_internal_xattr(name: &[u8]) -> bool {
    name.starts_with(TRUSTED_OVERLAY_PREFIX)
}

fn replace_prefix(name: &[u8], from: &[u8], to: &[u8]) -> Option<Vec<u8>> {
    let rest = name.strip_prefix(from)?;
    let mut out = Vec::with_capacity(to.len() + rest.len());
    out.extend_from_slice(to);
    out.extend_from_slice(rest);
    Some(out)
}

fn unescape_xattr_name(name: &[u8]) -> Cow<'_, [u8]> {
    match replace_prefix(name, ESCAPED_OVERLAY_PREFIX, TRUSTED_OVERLAY_PREFIX) {
        Some(unescaped) => Cow::Owned(unescaped),
        None => Cow::Borrowed(name),
    }
}

fn rewrite_xattr_name_for_user(name: &[u8]) -> Option<Vec<u8>> {
    replace_prefix(name, TRUSTED_OVERLAY_PREFIX, USER_OVERLAY_PREFIX)
}

/// Iterate directory entries across inline data and blocks.
fn for_each_dir_entry<F>(image: &Image, inode: &InodeType, mut f: F) -> Result<(), fuser::Errno>
where
    F: FnMut(&composefs::erofs::reader::DirectoryEntry) -> std::ops::ControlFlow<()>,
{
    if let Some(inline) = inode.inline()
        && let Ok(block) = DirectoryBlock::ref_from_bytes(inline)
        && let Ok(entries) = block.entries()
    {
        for entry in entries.flatten() {
            if entry.name == b"." || entry.name == b".." {
                continue;
            }
            if f(&entry).is_break() {
                return Ok(());
            }
        }
    }
    if let Ok(block_range) = image.inode_blocks(inode) {
        for block_id in block_range {
            if let Ok(block) = image.directory_block(block_id)
                && let Ok(entries) = block.entries()
            {
                for entry in entries.flatten() {
                    if entry.name == b"." || entry.name == b".." {
                        continue;
                    }
                    if f(&entry).is_break() {
                        return Ok(());
                    }
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
enum OpenHandle {
    Fd(OwnedFd),
    Data(Box<[u8]>),
}

#[derive(Debug, Default)]
struct FuseHandles {
    handles: HashMap<u64, OpenHandle>,
    next_fh: u64,
}

#[derive(Debug)]
struct ComposefsFuse {
    image: Image<'static>,
    objects_fd: Arc<OwnedFd>,
    overlay_xattr: Option<OverlayXattrMode>,
    handles: Mutex<FuseHandles>,
}

impl ComposefsFuse {
    fn root_nid(&self) -> Nid {
        Nid(self.image.sb.root_nid.get() as u64)
    }

    fn get_inode(&self, nid: Nid) -> Result<InodeType<'_>, fuser::Errno> {
        self.image.inode(nid.0).map_err(|e| {
            log::error!("inode({:?}): {e}", nid);
            fuser::Errno::EIO
        })
    }

    fn is_hidden(&self, nid: Nid) -> bool {
        if self.overlay_xattr.is_some() {
            return false;
        }
        if let Ok(inode) = self.get_inode(nid) {
            is_overlayfs_whiteout(&self.image, &inode)
        } else {
            false
        }
    }

    fn get_fileattr(&self, ino: INodeNo) -> Result<FileAttr, fuser::Errno> {
        let nid = Nid::from_fuse_ino(ino, self.root_nid()).ok_or(fuser::Errno::EINVAL)?;
        let inode = self.get_inode(nid)?;
        if self.overlay_xattr.is_some() {
            Ok(inode_fileattr_overlay(&self.image, ino, &inode))
        } else {
            Ok(inode_fileattr(&self.image, ino, &inode))
        }
    }

    fn open_object_by_redirect(&self, inode: &InodeType) -> Result<OwnedFd, fuser::Errno> {
        let redirect = find_raw_xattr(&self.image, inode, format::XATTR_OVERLAY_REDIRECT)
            .ok_or(fuser::Errno::EIO)?;
        let path = redirect.strip_prefix(b"/").unwrap_or(&redirect);
        openat(
            &*self.objects_fd,
            OsStr::from_bytes(path),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|e| {
            log::error!("open object {}: {e}", String::from_utf8_lossy(path));
            fuser::Errno::EIO
        })
    }

    fn collect_xattr_names(&self, inode: &InodeType) -> Vec<Vec<u8>> {
        let mut names = Vec::new();
        let Some(xattrs_section) = inode.xattrs().ok().flatten() else {
            return names;
        };

        let process_xattr = |names: &mut Vec<Vec<u8>>, raw_name: Vec<u8>| match self.overlay_xattr {
            Some(OverlayXattrMode::User) => {
                if let Some(rewritten) = rewrite_xattr_name_for_user(&raw_name) {
                    names.push(rewritten);
                } else {
                    names.push(raw_name);
                }
            }
            Some(OverlayXattrMode::Trusted) => {
                names.push(raw_name);
            }
            None => {
                if is_overlayfs_internal_xattr(&raw_name) {
                    let unescaped = unescape_xattr_name(&raw_name);
                    if unescaped != raw_name.as_slice() {
                        names.push(unescaped.into_owned());
                    }
                } else {
                    names.push(raw_name);
                }
            }
        };

        if let Ok(shared) = xattrs_section.shared() {
            for id in shared {
                if let Ok(xattr) = self.image.shared_xattr(id.get()) {
                    process_xattr(&mut names, xattr_full_name(xattr));
                }
            }
        }
        if let Ok(local) = xattrs_section.local() {
            for xattr in local.flatten() {
                process_xattr(&mut names, xattr_full_name(xattr));
            }
        }
        names
    }

    fn find_xattr_value(&self, inode: &InodeType, name: &[u8]) -> Option<Vec<u8>> {
        let lookup_name: Cow<'_, [u8]> = match self.overlay_xattr {
            Some(OverlayXattrMode::User) => {
                match replace_prefix(name, USER_OVERLAY_PREFIX, TRUSTED_OVERLAY_PREFIX) {
                    Some(trusted) => Cow::Owned(trusted),
                    None => Cow::Borrowed(name),
                }
            }
            Some(OverlayXattrMode::Trusted) => Cow::Borrowed(name),
            None => {
                if let Some(escaped) =
                    replace_prefix(name, TRUSTED_OVERLAY_PREFIX, ESCAPED_OVERLAY_PREFIX)
                    && let Some(val) = find_raw_xattr(&self.image, inode, &escaped)
                {
                    return Some(val);
                }
                if is_overlayfs_internal_xattr(name) {
                    return None;
                }
                Cow::Borrowed(name)
            }
        };
        find_raw_xattr(&self.image, inode, &lookup_name)
    }
}

impl Filesystem for ComposefsFuse {
    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: fuser::ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 4096, 255, 4096);
    }

    fn forget(&self, _req: &Request, _ino: INodeNo, _nlookup: u64) {}

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_nid) = Nid::from_fuse_ino(parent, self.root_nid()) else {
            return reply.error(fuser::Errno::EINVAL);
        };
        log::trace!("lookup {parent_nid} {name:?}");

        let Ok(parent_inode) = self.get_inode(parent_nid) else {
            return reply.error(fuser::Errno::EBADF);
        };

        let name_bytes = name.as_bytes();
        let mut found = None;
        let _ = for_each_dir_entry(&self.image, &parent_inode, |entry| {
            if entry.name == name_bytes {
                found = Some(Nid(entry.nid()));
                std::ops::ControlFlow::Break(())
            } else {
                std::ops::ControlFlow::Continue(())
            }
        });

        match found {
            Some(child_nid) if !self.is_hidden(child_nid) => {
                let child_fuse_ino = child_nid.to_fuse_ino(self.root_nid());
                match self.get_fileattr(child_fuse_ino) {
                    Ok(attrs) => reply.entry(&TTL, &attrs, Generation(0)),
                    Err(e) => reply.error(e),
                }
            }
            _ => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.get_fileattr(ino) {
            Ok(attrs) => reply.attr(&TTL, &attrs),
            Err(e) => reply.error(e),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let Some(nid) = Nid::from_fuse_ino(ino, self.root_nid()) else {
            return reply.error(fuser::Errno::EINVAL);
        };
        let Ok(inode) = self.get_inode(nid) else {
            return reply.error(fuser::Errno::EINVAL);
        };
        match inode.inline() {
            Some(data) => reply.data(data),
            None => reply.error(fuser::Errno::EINVAL),
        }
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
        let Some(nid) = Nid::from_fuse_ino(ino, self.root_nid()) else {
            return reply.error(fuser::Errno::EINVAL);
        };
        let Ok(inode) = self.get_inode(nid) else {
            return reply.error(fuser::Errno::EBADF);
        };

        let mut cur_offset = offset;

        if cur_offset == 0 {
            cur_offset += 1;
            if reply.add(ino, cur_offset, FileType::Directory, ".") {
                return reply.ok();
            }
        }

        if cur_offset == 1 {
            cur_offset += 1;
            if reply.add(ino, cur_offset, FileType::Directory, "..") {
                return reply.ok();
            }
        }

        let mut entry_idx: u64 = 2;
        let _ = for_each_dir_entry(&self.image, &inode, |entry| {
            let child_nid = Nid(entry.nid());
            if self.is_hidden(child_nid) {
                return std::ops::ControlFlow::Continue(());
            }
            if entry_idx < cur_offset {
                entry_idx += 1;
                return std::ops::ControlFlow::Continue(());
            }
            let child_fuse_ino = child_nid.to_fuse_ino(self.root_nid());
            let kind = match ErofsFileType::from(entry.header.file_type) {
                ErofsFileType::RegularFile => FileType::RegularFile,
                ErofsFileType::Directory => FileType::Directory,
                ErofsFileType::CharacterDevice => FileType::CharDevice,
                ErofsFileType::BlockDevice => FileType::BlockDevice,
                ErofsFileType::Fifo => FileType::NamedPipe,
                ErofsFileType::Socket => FileType::Socket,
                ErofsFileType::Symlink => FileType::Symlink,
                ErofsFileType::Unknown => FileType::RegularFile,
            };
            entry_idx += 1;
            if reply.add(
                child_fuse_ino,
                entry_idx,
                kind,
                OsStr::from_bytes(entry.name),
            ) {
                return std::ops::ControlFlow::Break(());
            }
            std::ops::ControlFlow::Continue(())
        });

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
        let Some(nid) = Nid::from_fuse_ino(ino, self.root_nid()) else {
            return reply.error(fuser::Errno::EINVAL);
        };
        let Ok(inode) = self.get_inode(nid) else {
            return reply.error(fuser::Errno::EBADF);
        };

        let Ok(dir_attrs) = self.get_fileattr(ino) else {
            return reply.error(fuser::Errno::EIO);
        };

        let mut cur_offset = offset;

        if cur_offset == 0 {
            cur_offset += 1;
            if reply.add(ino, cur_offset, ".", &TTL, &dir_attrs, Generation(0)) {
                return reply.ok();
            }
        }

        if cur_offset == 1 {
            cur_offset += 1;
            if reply.add(ino, cur_offset, "..", &TTL, &dir_attrs, Generation(0)) {
                return reply.ok();
            }
        }

        let mut entry_idx: u64 = 2;
        let _ = for_each_dir_entry(&self.image, &inode, |entry| {
            let child_nid = Nid(entry.nid());
            if self.is_hidden(child_nid) {
                return std::ops::ControlFlow::Continue(());
            }
            if entry_idx < cur_offset {
                entry_idx += 1;
                return std::ops::ControlFlow::Continue(());
            }
            let child_ino = child_nid.to_fuse_ino(self.root_nid());
            let child_attrs = match self.get_fileattr(child_ino) {
                Ok(a) => a,
                Err(_) => {
                    entry_idx += 1;
                    return std::ops::ControlFlow::Continue(());
                }
            };
            entry_idx += 1;
            if reply.add(
                child_ino,
                entry_idx,
                OsStr::from_bytes(entry.name),
                &TTL,
                &child_attrs,
                Generation(0),
            ) {
                return std::ops::ControlFlow::Break(());
            }
            std::ops::ControlFlow::Continue(())
        });

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
        let Some(nid) = Nid::from_fuse_ino(ino, self.root_nid()) else {
            return reply.error(fuser::Errno::EINVAL);
        };
        let Ok(inode) = self.get_inode(nid) else {
            return reply.error(fuser::Errno::EBADF);
        };

        match self.find_xattr_value(&inode, name.as_bytes()) {
            Some(value) => {
                if size == 0 {
                    reply.size(value.len() as u32);
                } else if value.len() > size as usize {
                    reply.error(fuser::Errno::ERANGE);
                } else {
                    reply.data(&value);
                }
            }
            None => reply.error(fuser::Errno::ENODATA),
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: fuser::ReplyXattr) {
        let Some(nid) = Nid::from_fuse_ino(ino, self.root_nid()) else {
            return reply.error(fuser::Errno::EINVAL);
        };
        let Ok(inode) = self.get_inode(nid) else {
            return reply.error(fuser::Errno::EBADF);
        };

        let names = self.collect_xattr_names(&inode);
        let mut list = Vec::new();
        for name in &names {
            list.extend_from_slice(name);
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

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let Some(nid) = Nid::from_fuse_ino(ino, self.root_nid()) else {
            return reply.error(fuser::Errno::EINVAL);
        };
        log::trace!("open({nid})");

        let Ok(inode) = self.get_inode(nid) else {
            return reply.error(fuser::Errno::EBADF);
        };

        let Ok(layout) = inode.data_layout() else {
            return reply.error(fuser::Errno::EIO);
        };

        let handle = match layout {
            DataLayout::FlatInline => match inode.inline() {
                Some(data) => OpenHandle::Data(data.into()),
                None => OpenHandle::Data(Box::new([])),
            },
            DataLayout::FlatPlain => {
                if self.overlay_xattr.is_some() {
                    return reply.error(errno_to_fuser(rustix::io::Errno::OPNOTSUPP));
                }
                match self.open_object_by_redirect(&inode) {
                    Ok(fd) => OpenHandle::Fd(fd),
                    Err(e) => return reply.error(e),
                }
            }
            DataLayout::ChunkBased => {
                if self.overlay_xattr.is_some() {
                    return reply.error(errno_to_fuser(rustix::io::Errno::OPNOTSUPP));
                }
                match self.open_object_by_redirect(&inode) {
                    Ok(fd) => OpenHandle::Fd(fd),
                    Err(e) => return reply.error(e),
                }
            }
        };

        let mut state = self.handles.lock().expect("fuse handles mutex poisoned");
        let fh = state.next_fh;
        state.next_fh += 1;
        state.handles.insert(fh, handle);
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
        let state = self.handles.lock().expect("fuse handles mutex poisoned");
        match state.handles.get(&fh.0) {
            Some(OpenHandle::Fd(fd)) => {
                let mut data = Vec::with_capacity(size as usize);
                match pread(fd, spare_capacity(&mut data), offset) {
                    Ok(_) => reply.data(&data),
                    Err(errno) => reply.error(errno_to_fuser(errno)),
                }
            }
            Some(OpenHandle::Data(data)) => {
                let start = (offset as usize).min(data.len());
                let end = (start + size as usize).min(data.len());
                reply.data(&data[start..end]);
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

fn errno_to_fuser(errno: rustix::io::Errno) -> fuser::Errno {
    fuser::Errno::from(std::io::Error::from_raw_os_error(errno.raw_os_error()))
}

/// Check if an fd has fs-verity enabled, meaning its contents cannot change.
fn is_safe_to_mmap(fd: &impl AsFd) -> bool {
    composefs::fsverity::measure_verity_opt::<composefs::fsverity::Sha256HashValue>(fd)
        .ok()
        .flatten()
        .is_some()
}

/// Load an EROFS image from a file descriptor.
///
/// If the image has fs-verity enabled (contents guaranteed immutable),
/// it is memory-mapped for zero-copy access. Otherwise it is read into
/// an owned buffer.
///
/// Returns a `&'static [u8]` via `Box::leak` — the FUSE server process
/// lives until unmount, so the leak is harmless.
#[allow(unsafe_code)]
fn load_image(fd: OwnedFd) -> anyhow::Result<&'static [u8]> {
    if is_safe_to_mmap(&fd) {
        let file = std::fs::File::from(fd);
        let mmap = unsafe { memmap2::Mmap::map(&file) }.context("mmap EROFS image")?;
        let leaked: &'static memmap2::Mmap = Box::leak(Box::new(mmap));
        Ok(leaked.as_ref())
    } else {
        use std::io::Read as _;
        let mut buf = Vec::new();
        std::fs::File::from(fd)
            .read_to_end(&mut buf)
            .context("reading EROFS image")?;
        Ok(Vec::leak(buf))
    }
}

/// Opens /dev/fuse.
pub fn open_fuse() -> anyhow::Result<OwnedFd> {
    open("/dev/fuse", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
        .context("Unable to open fuse device /dev/fuse")
}

/// Options controlling how a FUSE filesystem is mounted.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct FuseMountOptions {
    allow_other: bool,
}

impl FuseMountOptions {
    /// Allow users other than the mounter to access the filesystem.
    pub fn set_allow_other(&mut self, allow_other: bool) -> &mut Self {
        self.allow_other = allow_other;
        self
    }
}

/// Mounts a FUSE filesystem with the given /dev/fuse fd.
///
/// Returns a detached FUSE mount fd. You'll need to call
/// [`serve_fuse`] to actually satisfy the FUSE requests.
///
/// For overlay-lower mode, call [`mount_fuse_overlay`] *after* the FUSE
/// server is running to layer an overlayfs on top.
pub fn mount_fuse(dev_fuse: impl AsFd, options: &FuseMountOptions) -> anyhow::Result<OwnedFd> {
    let fusefs = FsHandle::open("fuse")?;
    fsconfig_set_flag(fusefs.as_fd(), "ro")?;
    fsconfig_set_flag(fusefs.as_fd(), "default_permissions")?;
    if options.allow_other {
        fsconfig_set_flag(fusefs.as_fd(), "allow_other")?;
    }
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

/// Options controlling how an overlayfs is created on top of a FUSE mount.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct OverlayMountOptions {
    overlay_xattr: OverlayXattrMode,
    upperdirs: Option<(OwnedFd, OwnedFd)>,
    read_write: bool,
    enable_verity: bool,
}

impl OverlayMountOptions {
    /// Set the overlay xattr mode. Defaults to [`OverlayXattrMode::User`].
    pub fn set_overlay_xattr(&mut self, mode: OverlayXattrMode) -> &mut Self {
        self.overlay_xattr = mode;
        self
    }

    /// Add an overlayfs upper layer and work directory.
    pub fn set_overlay(&mut self, upperdir: OwnedFd, workdir: OwnedFd) -> &mut Self {
        self.upperdirs = Some((upperdir, workdir));
        self
    }

    /// Make the mount read-write.
    pub fn set_read_write(&mut self, read_write: bool) -> &mut Self {
        self.read_write = read_write;
        self
    }

    /// Require fs-verity for overlay metacopy verification.
    pub fn set_enable_verity(&mut self, enable_verity: bool) -> &mut Self {
        self.enable_verity = enable_verity;
        self
    }
}

/// Probe whether the kernel supports overlayfs with userxattr + data-only
/// layers. Kernels without the `5ef7bcde` backport reject this because
/// data-only layers require metacopy, which conflicts with userxattr.
///
/// The probe creates a temporary directory for the lower/data dirs, sets
/// up a dummy overlay with `userxattr` + data-only layer syntax, and
/// checks whether `fsconfig_create` succeeds.
pub fn user_overlay_supported() -> bool {
    #[cfg(not(feature = "pre-6.16"))]
    return true;

    #[cfg(feature = "pre-6.16")]
    {
        static RESULT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *RESULT.get_or_init(user_overlay_supported_probe)
    }
}

#[cfg(feature = "pre-6.16")]
fn user_overlay_supported_probe() -> bool {
    use std::os::fd::AsRawFd;

    let Ok(tmpdir) = tempfile::tempdir() else {
        return false;
    };
    let lower = tmpdir.path().join("lower");
    let data = tmpdir.path().join("data");
    if std::fs::create_dir(&lower).is_err() || std::fs::create_dir(&data).is_err() {
        return false;
    }
    let Ok(lower_fd) = open(
        &lower,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return false;
    };
    let Ok(data_fd) = open(
        &data,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return false;
    };
    let lowerdir_arg = format!(
        "/proc/self/fd/{}::/proc/self/fd/{}",
        lower_fd.as_raw_fd(),
        data_fd.as_raw_fd()
    );

    let Ok(overlayfs) = FsHandle::open("overlay") else {
        return false;
    };
    fsconfig_set_flag(overlayfs.as_fd(), "userxattr").is_ok()
        && fsconfig_set_string(overlayfs.as_fd(), "lowerdir", &*lowerdir_arg).is_ok()
        && fsconfig_create(overlayfs.as_fd()).is_ok()
}

/// Creates an overlayfs on top of a FUSE mount.
pub fn mount_fuse_overlay(
    fuse_mnt: OwnedFd,
    basedir: impl AsFd,
    options: &OverlayMountOptions,
) -> anyhow::Result<OwnedFd> {
    let prepared = prepare_mount(fuse_mnt)?;

    let overlayfs = FsHandle::open("overlay")?;
    fsconfig_set_string(overlayfs.as_fd(), "source", "composefs-fuse")?;
    if options.overlay_xattr == OverlayXattrMode::User {
        fsconfig_set_flag(overlayfs.as_fd(), "userxattr")?;
    }
    if options.enable_verity {
        fsconfig_set_string(overlayfs.as_fd(), "verity", "require")?;
    }
    if let Some((upperdir, workdir)) = &options.upperdirs {
        overlayfs_set_fd(overlayfs.as_fd(), "upperdir", upperdir.as_fd())?;
        overlayfs_set_fd(overlayfs.as_fd(), "workdir", workdir.as_fd())?;
    }
    overlayfs_set_lower_and_data_fds(&overlayfs, &prepared, &[basedir.as_fd()])?;
    fsconfig_create(overlayfs.as_fd())?;

    let mount_attr = if options.read_write {
        MountAttrFlags::empty()
    } else {
        MountAttrFlags::MOUNT_ATTR_RDONLY
    };
    Ok(fsmount(
        overlayfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        mount_attr,
    )?)
}

/// Options controlling how the FUSE server behaves.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ServeFuseOptions {
    overlay_xattr: Option<OverlayXattrMode>,
}

impl ServeFuseOptions {
    /// Set the overlay xattr mode. When `Some`, the server presents overlay
    /// xattrs and refuses to open external files. When `None` (the default),
    /// the server follows redirects and serves file content from the
    /// repository directly.
    pub fn set_overlay_xattr(&mut self, mode: Option<OverlayXattrMode>) -> &mut Self {
        self.overlay_xattr = mode;
        self
    }
}

fn build_fuse(
    image_fd: OwnedFd,
    objects_fd: Arc<OwnedFd>,
    options: &ServeFuseOptions,
) -> std::io::Result<(ComposefsFuse, Config)> {
    let image_bytes = load_image(image_fd).map_err(|e| std::io::Error::other(format!("{e:#}")))?;
    let image = Image::open(image_bytes).map_err(|e| std::io::Error::other(format!("{e}")))?;

    let tf = ComposefsFuse {
        image,
        objects_fd,
        overlay_xattr: options.overlay_xattr,
        handles: Mutex::new(FuseHandles::default()),
    };

    Ok((tf, Config::default()))
}

/// Mounts and serves a FUSE filesystem at `mountpoint`.
///
/// Uses `Session::new` which handles `fusermount3` fallback for unprivileged
/// callers. Blocks until the session ends.
///
/// If `ready_fd` is provided, a single byte is written after the mount is
/// established but before serving starts.
pub fn serve_fuse(
    mountpoint: impl AsRef<Path>,
    image_fd: OwnedFd,
    objects_fd: Arc<OwnedFd>,
    options: &ServeFuseOptions,
    ready_fd: Option<OwnedFd>,
) -> std::io::Result<()> {
    let (tf, mut config) = build_fuse(image_fd, objects_fd, options)?;
    config.mount_options = vec![MountOption::RO, MountOption::DefaultPermissions];
    let session = Session::new(tf, mountpoint.as_ref(), &config)?;
    if let Some(fd) = ready_fd {
        let _ = rustix::io::write(&fd, b"r");
    }
    session.spawn()?.join()
}

/// Serves a FUSE filesystem over a pre-mounted `/dev/fuse` fd.
///
/// Use together with [`open_fuse`] and [`mount_fuse`] when you need control
/// over the mount lifecycle. Blocks until the session ends.
pub fn serve_fuse_fd(
    dev_fuse: OwnedFd,
    image_fd: OwnedFd,
    objects_fd: Arc<OwnedFd>,
    options: &ServeFuseOptions,
) -> std::io::Result<()> {
    let (tf, config) = build_fuse(image_fd, objects_fd, options)?;
    Session::from_fd(tf, dev_fuse, SessionACL::All, config)?
        .spawn()?
        .join()
}
