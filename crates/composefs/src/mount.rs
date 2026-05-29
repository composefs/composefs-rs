//! Modern Linux mount API support for composefs.
//!
//! This module provides functionality to mount composefs images using the
//! new mount API (fsopen/fsmount) with overlay filesystem support and
//! fs-verity verification.

use std::{
    io::Result,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use rustix::{
    mount::{
        FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags, fsconfig_create,
        fsconfig_set_flag, fsconfig_set_string, fsmount, fsopen, move_mount,
    },
    path,
};

use crate::{
    mountcompat::{make_erofs_mountable, overlayfs_set_lower_and_data_fds, prepare_mount},
    util::proc_self_fd,
};

/// A handle to a filesystem context created via the modern mount API.
///
/// This represents an open filesystem context (created by `fsopen()`) that can be
/// configured and then mounted. The handle automatically reads and prints any
/// error messages from the kernel when dropped.
#[derive(Debug)]
pub struct FsHandle {
    /// The file descriptor for the filesystem context.
    pub fd: OwnedFd,
}

impl FsHandle {
    /// Opens a new filesystem context for the specified filesystem type.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the filesystem type (e.g., "erofs", "overlay")
    ///
    /// # Returns
    ///
    /// Returns a new `FsHandle` that can be configured and mounted.
    pub fn open(name: &str) -> Result<FsHandle> {
        Ok(FsHandle {
            fd: fsopen(name, FsOpenFlags::FSOPEN_CLOEXEC)?,
        })
    }
}

impl AsFd for FsHandle {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Drop for FsHandle {
    fn drop(&mut self) {
        let mut buffer = [0u8; 1024];
        loop {
            match rustix::io::read(&self.fd, &mut buffer) {
                Err(_) => return, // ENODATA, among others?
                Ok(0) => return,
                // Surface the kernel's fsopen/fsconfig diagnostic messages,
                // which are only readable from this fd. We have no error
                // channel from `drop`, so stderr is the only option.
                #[allow(clippy::print_stderr)]
                Ok(size) => eprintln!("{}", String::from_utf8(buffer[0..size].to_vec()).unwrap()),
            }
        }
    }
}

/// Moves a mounted filesystem to a target location.
///
/// # Arguments
///
/// * `fs_fd` - File descriptor for the mounted filesystem (from `fsmount()`)
/// * `dirfd` - Directory file descriptor for the target mount point
/// * `path` - Path relative to `dirfd` where the filesystem should be mounted
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if the mount operation fails.
pub fn mount_at(
    fs_fd: impl AsFd,
    dirfd: impl AsFd,
    path: impl path::Arg,
) -> rustix::io::Result<()> {
    move_mount(
        fs_fd.as_fd(),
        "",
        dirfd.as_fd(),
        path,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
}

/// Mounts an erofs image file.
///
/// Creates a read-only erofs mount from the provided image file descriptor.
/// On older kernels, this may involve creating a loopback device.
///
/// # Arguments
///
/// * `image` - File descriptor for the erofs image file
///
/// # Returns
///
/// Returns a file descriptor for the mounted filesystem, which can be used with
/// `mount_at()` or other mount operations.
pub fn erofs_mount(image: OwnedFd) -> Result<OwnedFd> {
    let image = make_erofs_mountable(image)?;
    let erofs = FsHandle::open("erofs")?;
    fsconfig_set_flag(erofs.as_fd(), "ro")?;
    fsconfig_set_string(erofs.as_fd(), "source", proc_self_fd(&image))?;
    fsconfig_create(erofs.as_fd())?;
    Ok(fsmount(
        erofs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

/// Creates a composefs mount using overlayfs with an erofs image and base directory.
///
/// This mounts a composefs image by creating an overlayfs that layers the erofs image
/// (as the lower layer) over a base directory (as the data layer). The overlayfs is
/// configured with metacopy and redirect_dir enabled for composefs functionality.
///
/// # Arguments
///
/// * `image` - File descriptor for the composefs erofs image
/// * `name` - Name for the mount source (appears as "composefs:{name}")
/// * `basedir` - File descriptor for the base directory containing the actual file data
/// * `enable_verity` - Whether to require fs-verity verification for all files
///
/// # Returns
///
/// Returns a file descriptor for the mounted composefs filesystem, which can be used
/// with `mount_at()` to attach it to a mount point.
pub fn composefs_fsmount(
    image: OwnedFd,
    name: &str,
    basedir: impl AsFd,
    enable_verity: bool,
) -> Result<OwnedFd> {
    let erofs_mnt = prepare_mount(erofs_mount(image)?)?;

    let overlayfs = FsHandle::open("overlay")?;
    fsconfig_set_string(overlayfs.as_fd(), "source", format!("composefs:{name}"))?;
    fsconfig_set_string(overlayfs.as_fd(), "metacopy", "on")?;
    fsconfig_set_string(overlayfs.as_fd(), "redirect_dir", "on")?;
    if enable_verity {
        fsconfig_set_string(overlayfs.as_fd(), "verity", "require")?;
    }
    overlayfs_set_lower_and_data_fds(&overlayfs, &erofs_mnt, Some(&basedir))?;
    fsconfig_create(overlayfs.as_fd())?;

    Ok(fsmount(
        overlayfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}
