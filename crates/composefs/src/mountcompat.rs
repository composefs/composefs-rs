//! Compatibility helpers for older Linux kernel mount APIs.
//!
//! This module provides fallback implementations for mount operations
//! on kernels that don't support the modern mount API, including
//! loopback device setup and temporary mount handling.

use std::{
    io::Result,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

// This file contains a bunch of helpers that deal with the pre-6.15 mount API

// First: the simple pass-through versions of all of our helpers, for 6.15 or later, along with
// documentation about why they're required.

/// Sets one of the "dir" mount options on an overlayfs to the given file descriptor.  This can
/// either be a freshly-created mount or a O_PATH file descriptor.  On 6.15 kernels this can be
/// done by directly calling `fsconfig_set_fd()`.  On pre-6.15 kernels, it needs to be done by
/// reopening the file descriptor `O_RDONLY` and calling `fsconfig_set_fd()` because `O_PATH` fds
/// are rejected.  On very old kernels this needs to be done by way of `fsconfig_set_string()` and
/// `/proc/self/fd/`.
#[cfg(not(feature = "pre-6.15"))]
pub fn overlayfs_set_fd(fs_fd: BorrowedFd, key: &str, fd: BorrowedFd) -> rustix::io::Result<()> {
    rustix::mount::fsconfig_set_fd(fs_fd, key, fd)
}

/// Sets the "lowerdir+" and "datadir+" mount options of an overlayfs mount to the provided file
/// descriptors.  On 6.15 kernels this can be done by directly calling `fsconfig_set_fd()`.  On
/// pre-6.15 kernels, it needs to be done by reopening the file descriptor `O_RDONLY` and calling
/// `fsconfig_set_fd()` because `O_PATH` fds are rejected.  On very old kernels this needs to be
/// done by calculating a `"lowerdir=lower::data"` string using `/proc/self/fd/` filenames and
/// setting it via `fsconfig_set_string()`.
#[cfg(not(feature = "pre-6.15"))]
pub fn overlayfs_set_lower_and_data_fds(
    fs_fd: impl AsFd,
    lower: impl AsFd,
    data_fds: &[BorrowedFd<'_>],
) -> rustix::io::Result<()> {
    overlayfs_set_fd(fs_fd.as_fd(), "lowerdir+", lower.as_fd())?;
    for data_fd in data_fds {
        overlayfs_set_fd(fs_fd.as_fd(), "datadir+", *data_fd)?;
    }
    Ok(())
}

/// Prepares an open erofs image file for mounting.  On kernels versions after 6.12 this is a
/// simple passthrough.  On older kernels (like on RHEL 9) we need to create a loopback device.
#[cfg(not(feature = "rhel9"))]
pub fn make_erofs_mountable(image: OwnedFd) -> Result<OwnedFd> {
    Ok(image)
}

/// Prepares a mounted filesystem for further use.  On 6.15 kernels this is a no-op, due to the
/// expanded number of operations which can be performed on "detached" mounts.  On earlier kernels
/// we need to create a temporary directory and mount the filesystem there to avoid failures,
/// making sure to detach the mount and remove the directory later.  This function returns an `impl
/// AsFd` which also implements the `Drop` trait in order to facilitate this cleanup.
#[cfg(not(feature = "pre-6.15"))]
pub fn prepare_mount(mnt_fd: OwnedFd) -> Result<impl AsFd> {
    Ok(mnt_fd)
}

// Now: support for pre-6.15 kernels

/// Sets one of the "dir" mount options on an overlayfs to the given file descriptor.
///
/// Uses `fsconfig_set_string()` with a `/proc/self/fd/` path.  The previous
/// implementation tried `fsconfig_set_fd()` (with O_PATH fds reopened as O_RDONLY),
/// but `fsconfig_set_fd()` for overlayfs layer options was only added in 6.13 so
/// that broke on 6.12 kernels (e.g. CentOS Stream 10).  The string-based approach
/// works on all kernels with the new mount API.
#[cfg(feature = "pre-6.15")]
pub fn overlayfs_set_fd(fs_fd: BorrowedFd, key: &str, fd: BorrowedFd) -> rustix::io::Result<()> {
    rustix::mount::fsconfig_set_string(fs_fd, key, crate::util::proc_self_fd(fd))
}

/// Sets the "lowerdir+" and "datadir+" mount options of an overlayfs mount to the provided file
/// descriptors.
///
/// Constructs a `lowerdir` string using `/proc/self/fd/` paths, with `::` as the separator
/// for the data layer.
#[cfg(feature = "pre-6.15")]
pub fn overlayfs_set_lower_and_data_fds(
    fs_fd: impl AsFd,
    lower: impl AsFd,
    data_fds: &[BorrowedFd<'_>],
) -> rustix::io::Result<()> {
    use std::os::fd::AsRawFd;

    let lower_fd = lower.as_fd().as_raw_fd().to_string();
    let mut arg = format!("/proc/self/fd/{lower_fd}");
    for data_fd in data_fds {
        let raw = data_fd.as_raw_fd().to_string();
        arg.push_str(&format!("::/proc/self/fd/{raw}"));
    }
    rustix::mount::fsconfig_set_string(fs_fd.as_fd(), "lowerdir", arg)
}

/// Prepares a mounted filesystem for further use.
///
/// On pre-6.15 kernels, this mounts the filesystem to a temporary directory and returns
/// an O_PATH file descriptor to it. The temporary mount is automatically cleaned up when
/// the returned value is dropped.
#[cfg(feature = "pre-6.15")]
pub fn prepare_mount(mnt_fd: OwnedFd) -> Result<impl AsFd> {
    tmpmount::TmpMount::mount(mnt_fd)
}

/// Prepares an open erofs image file for mounting.
///
/// On RHEL9 kernels (before 6.12), this creates a loopback device because erofs
/// cannot directly mount files on these older kernels.
#[cfg(feature = "rhel9")]
pub fn make_erofs_mountable(image: OwnedFd) -> Result<OwnedFd> {
    loopify(image)
}

// Finally, we have two submodules which do the heavy lifting for loopback devices and temporary
// mountpoints.

// Required before Linux 6.15: it's not possible to use detached mounts with OPEN_TREE_CLONE or
// overlayfs.  Convert them into a non-floating form by mounting them on a temporary directory and
// reopening them as an O_PATH fd.
#[cfg(feature = "pre-6.15")]
mod tmpmount {
    use std::{
        io::Result,
        os::fd::{AsFd, BorrowedFd, OwnedFd},
    };

    use rustix::fs::{Mode, OFlags, open};
    use rustix::mount::{MoveMountFlags, UnmountFlags, move_mount, unmount};

    pub(super) struct TmpMount {
        dir: tempfile::TempDir,
        fd: OwnedFd,
    }

    impl TmpMount {
        pub(super) fn mount(mnt_fd: OwnedFd) -> Result<impl AsFd> {
            let tmp = tempfile::TempDir::new()?;
            move_mount(
                mnt_fd.as_fd(),
                "",
                rustix::fs::CWD,
                tmp.path(),
                MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )?;
            let fd = open(
                tmp.path(),
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(TmpMount { dir: tmp, fd })
        }
    }

    impl AsFd for TmpMount {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }
    }

    impl Drop for TmpMount {
        fn drop(&mut self) {
            let _ = unmount(self.dir.path(), UnmountFlags::DETACH);
        }
    }
}

/// Required before 6.12: erofs can't directly mount files.
/// Uses the composefs-ioctls crate for the loop device ioctl.
#[cfg(feature = "rhel9")]
fn loopify(image: OwnedFd) -> Result<OwnedFd> {
    composefs_ioctls::loop_device::loopify(image)
}
