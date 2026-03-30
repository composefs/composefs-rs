//! Reading and writing filesystem trees to/from disk.
//!
//! This module provides functionality to read filesystem structures from
//! disk into composefs tree representations and write them back, including
//! handling of hardlinks, extended attributes, and repository integration.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    ffi::{CStr, OsStr},
    fs::File,
    io::{Read, Write},
    mem::MaybeUninit,
    os::unix::ffi::OsStrExt,
    path::Path,
    rc::Rc,
};

use anyhow::{ensure, Context as _, Result};
use fn_error_context::context;
use rustix::{
    buffer::spare_capacity,
    fd::{AsFd, OwnedFd},
    fs::{
        fstat, getxattr, linkat, listxattr, mkdirat, mknodat, openat, readlinkat, symlinkat,
        AtFlags, Dir, FileType, Mode, OFlags, CWD,
    },
    io::{read, Errno},
};
use zerocopy::IntoBytes;

use crate::{
    fsverity::{compute_verity, FsVerityHashValue},
    repository::Repository,
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
    util::proc_self_fd,
    INLINE_CONTENT_MAX_V0,
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
    repo: &Repository<ObjectID>,
) -> Result<()> {
    match mkdirat(dirfd, name, dir.stat.st_mode.into()) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(e) => Err(e)?,
    }

    let fd = openat(dirfd, name, OFlags::PATH | OFlags::DIRECTORY, 0.into())?;
    write_directory_contents(dir, &fd, repo)
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
        LeafContent::Regular(RegularFile::Inline(ref data)) => {
            set_file_contents(dirfd, name, &leaf.stat, data)?
        }
        LeafContent::Regular(RegularFile::External(ref id, size)) => {
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
    repo: &Repository<ObjectID>,
) -> Result<()> {
    for (name, inode) in dir.entries() {
        match inode {
            Inode::Directory(ref dir) => write_directory(dir, fd, name, repo),
            Inode::Leaf(ref leaf) => write_leaf(leaf, fd, name, repo),
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
    dir: &Directory<ObjectID>,
    output_dir: &Path,
) -> Result<()> {
    let fd = openat(CWD, output_dir, OFlags::PATH | OFlags::DIRECTORY, 0.into())?;
    write_directory_contents(dir, &fd, repo)
}

/// Helper for reading filesystem trees from disk into composefs representation.
///
/// Tracks hardlinks via inode numbers and optionally stores large file objects
/// in a repository.
#[derive(Debug)]
pub struct FilesystemReader<'repo, ObjectID: FsVerityHashValue> {
    repo: Option<&'repo Repository<ObjectID>>,
    inodes: HashMap<(u64, u64), Rc<Leaf<ObjectID>>>,
}

impl<ObjectID: FsVerityHashValue> FilesystemReader<'_, ObjectID> {
    #[context("Reading extended attributes")]
    fn read_xattrs(fd: &OwnedFd) -> Result<BTreeMap<Box<OsStr>, Box<[u8]>>> {
        // flistxattr() and fgetxattr() don't work with with O_PATH fds, so go via /proc/self/fd.
        // Note: we want the symlink-following version of this call, which produces the correct
        // behaviour even when trying to read xattrs from symlinks themselves.  See
        // https://gist.github.com/allisonkarlitskaya/7a80f2ebb3314d80f45c653a1ba0e398
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

    #[context("Getting file stats")]
    fn stat(fd: &OwnedFd, ifmt: FileType) -> Result<(rustix::fs::Stat, Stat)> {
        let buf = fstat(fd)?;

        ensure!(
            FileType::from_raw_mode(buf.st_mode) == ifmt,
            "File type changed
            between readdir() and fstat()"
        );

        Ok((
            buf,
            Stat {
                st_mode: buf.st_mode & 0o7777,
                st_uid: buf.st_uid,
                st_gid: buf.st_gid,
                st_mtim_sec: buf.st_mtime as i64,
                xattrs: RefCell::new(Self::read_xattrs(fd)?),
            },
        ))
    }

    #[context("Reading leaf content")]
    fn read_leaf_content(
        &mut self,
        fd: OwnedFd,
        buf: rustix::fs::Stat,
    ) -> Result<LeafContent<ObjectID>> {
        let content = match FileType::from_raw_mode(buf.st_mode) {
            FileType::Directory | FileType::Unknown => unreachable!(),
            FileType::RegularFile => {
                let size = buf.st_size.try_into().context("size overflow")?;
                let mut buffer = Vec::with_capacity(size);
                if buf.st_size > 0 {
                    read(fd, spare_capacity(&mut buffer))?;
                }
                let buffer = Box::from(buffer);

                if buf.st_size > INLINE_CONTENT_MAX_V0 as i64 {
                    let id = if let Some(repo) = self.repo {
                        repo.ensure_object(&buffer)?
                    } else {
                        compute_verity(&buffer)
                    };
                    LeafContent::Regular(RegularFile::External(id, buf.st_size as u64))
                } else {
                    LeafContent::Regular(RegularFile::Inline(buffer))
                }
            }
            FileType::Symlink => {
                let target = readlinkat(fd, "", [])?;
                LeafContent::Symlink(OsStr::from_bytes(target.as_bytes()).into())
            }
            FileType::CharacterDevice => LeafContent::CharacterDevice(buf.st_rdev),
            FileType::BlockDevice => LeafContent::BlockDevice(buf.st_rdev),
            FileType::Fifo => LeafContent::Fifo,
            FileType::Socket => LeafContent::Socket,
        };
        Ok(content)
    }

    #[context("Reading leaf {}", name.to_string_lossy())]
    fn read_leaf(
        &mut self,
        dirfd: &OwnedFd,
        name: &OsStr,
        ifmt: FileType,
    ) -> Result<Rc<Leaf<ObjectID>>> {
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

        let (buf, stat) = Self::stat(&fd, ifmt)?;

        // NB: We could check `st_nlink > 1` to find out if we should track a file as a potential
        // hardlink or not, but some filesystems (like fuse-overlayfs) can report this incorrectly.
        // Track all files.  https://github.com/containers/fuse-overlayfs/issues/435
        let key = (buf.st_dev, buf.st_ino);
        if let Some(leafref) = self.inodes.get(&key) {
            Ok(Rc::clone(leafref))
        } else {
            let content = self.read_leaf_content(fd, buf)?;
            let leaf = Rc::new(Leaf { stat, content });
            self.inodes.insert(key, Rc::clone(&leaf));
            Ok(leaf)
        }
    }

    /// Reads a directory from disk into composefs representation.
    ///
    /// Recursively reads directory contents, tracking hardlinks and optionally
    /// storing large file objects in the repository.
    #[context("Reading directory {}", name.to_string_lossy())]
    fn read_directory(&mut self, dirfd: impl AsFd, name: &OsStr) -> Result<Directory<ObjectID>> {
        let fd = openat(
            dirfd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;

        let (_, stat) = Self::stat(&fd, FileType::Directory)?;
        let mut directory = Directory::new(stat);

        for item in Dir::read_from(&fd)? {
            let entry = item?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes());

            if name == "." || name == ".." {
                continue;
            }

            let inode = self.read_inode(&fd, name, entry.file_type())?;
            directory.insert(name, inode);
        }

        Ok(directory)
    }

    #[context("Reading inode {}", name.to_string_lossy())]
    fn read_inode(
        &mut self,
        dirfd: &OwnedFd,
        name: &OsStr,
        ifmt: FileType,
    ) -> Result<Inode<ObjectID>> {
        if ifmt == FileType::Directory {
            let dir = self.read_directory(dirfd, name)?;
            Ok(Inode::Directory(Box::new(dir)))
        } else {
            let leaf = self.read_leaf(dirfd, name, ifmt)?;
            Ok(Inode::Leaf(leaf))
        }
    }
}

/// Load a filesystem tree from the given path.
///
/// If a repository is provided, all files found in the filesystem are
/// stored in it. If `None`, fsverity digests are computed in memory
/// without writing to disk — suitable for computing image IDs and
/// dumpfiles without requiring O_TMPFILE support.
#[context("Reading filesystem from {}", path.display())]
pub fn read_filesystem<ObjectID: FsVerityHashValue>(
    dirfd: impl AsFd,
    path: &Path,
    repo: Option<&Repository<ObjectID>>,
) -> Result<FileSystem<ObjectID>> {
    let mut reader = FilesystemReader {
        repo,
        inodes: HashMap::new(),
    };

    let root = reader.read_directory(dirfd, path.as_os_str())?;

    Ok(FileSystem { root })
}

/// Load a filesystem tree from the given path, filtering xattrs with a predicate.
///
/// This is a wrapper around [`read_filesystem`] that filters extended attributes
/// using the provided predicate. Only xattrs for which the predicate returns `true`
/// are retained. This is useful when reading from a mounted filesystem where host
/// xattrs may leak into the image.
///
/// # Example
///
/// ```ignore
/// use composefs::fs::{read_filesystem_filtered, CONTAINER_XATTR_ALLOWLIST};
///
/// // Filter to only allow security.capability
/// let fs = read_filesystem_filtered(dirfd, path, None, |name| {
///     name.as_encoded_bytes() == b"security.capability"
/// })?;
/// ```
#[context("Reading filtered filesystem from {}", path.display())]
pub fn read_filesystem_filtered<ObjectID, F>(
    dirfd: impl AsFd,
    path: &Path,
    repo: Option<&Repository<ObjectID>>,
    xattr_filter: F,
) -> Result<FileSystem<ObjectID>>
where
    ObjectID: FsVerityHashValue,
    F: Fn(&OsStr) -> bool,
{
    let fs = read_filesystem(dirfd, path, repo)?;
    fs.filter_xattrs(xattr_filter);
    Ok(fs)
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

/// Load a container root filesystem from the given path.
///
/// This is a convenience wrapper around [`read_filesystem_filtered`] that also
/// applies OCI container transformations via [`FileSystem::transform_for_oci`].
///
/// Equivalent to calling:
/// ```ignore
/// let mut fs = read_filesystem_filtered(dirfd, path, repo, is_allowed_container_xattr)?;
/// fs.transform_for_oci()?;
/// ```
///
/// This is the recommended way to read a container filesystem because:
/// - OCI container runtimes don't preserve root directory metadata from layer tars
/// - Host xattrs (especially `security.selinux`) can leak into mounted filesystems
/// - `/run` should be empty (it's a tmpfs at runtime)
/// - Podman/buildah's `RUN --mount` can leave directory stubs
///
/// By filtering xattrs and applying OCI transformations, we ensure consistent
/// and reproducible composefs digests between build-time and install-time.
pub fn read_container_root<ObjectID: FsVerityHashValue>(
    dirfd: impl AsFd,
    path: &Path,
    repo: Option<&Repository<ObjectID>>,
) -> Result<FileSystem<ObjectID>> {
    let mut fs = read_filesystem_filtered(dirfd, path, repo, is_allowed_container_xattr)?;
    fs.transform_for_oci()?;
    Ok(fs)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{openat, CWD};

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
