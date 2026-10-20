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
    io::Errno,
    mount::{
        FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags, fsconfig_create,
        fsconfig_set_fd, fsconfig_set_flag, fsconfig_set_string, fsmount, fsopen, move_mount,
    },
    path,
};

use crate::{
    mountcompat::{
        make_erofs_mountable, overlayfs_set_fd, overlayfs_set_lower_and_data_fds, prepare_mount,
    },
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
    errors: Vec<Vec<u8>>,
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
            errors: Vec::new(),
        })
    }

    /// Save currently pending kernel diagnostics for reporting when dropped.
    ///
    /// Call this before probing an optional feature so [`Self::discard_errors`]
    /// can discard the probe's diagnostics while preserving earlier messages.
    pub fn buffer_errors(&mut self) -> Result<()> {
        Self::read_errors(&self.fd, |error| self.errors.push(error))
    }

    /// Discard currently pending kernel diagnostics, logging them at debug level.
    ///
    /// Previously buffered diagnostics are retained. Call [`Self::buffer_errors`]
    /// before an operation whose expected errors should be discarded.
    pub fn discard_errors(&self) -> Result<()> {
        Self::read_errors(&self.fd, |error| {
            log::debug!(
                "Discarding filesystem context diagnostic: {}",
                String::from_utf8_lossy(&error)
            );
        })
    }

    fn read_errors(fd: impl AsFd, consume: impl FnMut(Vec<u8>)) -> Result<()> {
        Self::read_errors_with(|buffer| rustix::io::read(&fd, buffer), consume)
    }

    fn read_errors_with(
        mut read: impl FnMut(&mut [u8]) -> rustix::io::Result<usize>,
        mut consume: impl FnMut(Vec<u8>),
    ) -> Result<()> {
        const INITIAL_BUFFER_SIZE: usize = 1024;
        // An empty fscontext read returns ENODATA if no messages are pending,
        // or EMSGSIZE without consuming the message. Allocate only on demand.
        let mut buffer = Vec::new();
        loop {
            match read(&mut buffer) {
                Ok(0) | Err(Errno::NODATA) => return Ok(()),
                Ok(size) => {
                    buffer.truncate(size);
                    consume(std::mem::take(&mut buffer));
                }
                Err(Errno::INTR) => continue,
                // fscontext reads leave an oversized message queued. Grow the
                // scratch buffer and retry instead of failing the mount.
                Err(Errno::MSGSIZE) => {
                    buffer.resize((buffer.len() * 2).max(INITIAL_BUFFER_SIZE), 0);
                }
                Err(err) => return Err(err.into()),
            }
        }
    }
}

impl AsFd for FsHandle {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Drop for FsHandle {
    #[allow(clippy::print_stderr)]
    fn drop(&mut self) {
        if let Err(err) = self.buffer_errors() {
            log::debug!("Reading filesystem context diagnostics: {err}");
        }
        for error in &self.errors {
            // Surface the kernel's fsopen/fsconfig diagnostics. There is no
            // error channel from Drop, so stderr is the only option.
            // Kernel messages already have a newline.
            eprint!("{}", String::from_utf8_lossy(error));
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
    log::trace!("erofs_mount: flock(LOCK_SH) on {}", proc_self_fd(&image));
    rustix::fs::flock(&image, rustix::fs::FlockOperation::LockShared)?;
    let mut erofs = FsHandle::open("erofs")?;
    fsconfig_set_flag(erofs.as_fd(), "ro")?;
    // Passing the fd keeps the flock held by the kernel for the lifetime of the mount.  Kernels
    // without support reject it, in which case use the /proc/self/fd path instead.
    erofs.buffer_errors()?;
    match fsconfig_set_fd(erofs.as_fd(), "source", image.as_fd()) {
        Ok(()) => {}
        Err(Errno::INVAL | Errno::OPNOTSUPP) => {
            erofs.discard_errors()?;
            fsconfig_set_string(erofs.as_fd(), "source", proc_self_fd(&image))?;
        }
        Err(err) => return Err(err.into()),
    }
    fsconfig_create(erofs.as_fd())?;
    Ok(fsmount(
        erofs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

/// Controls fs-verity enforcement for overlay file data.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum VerityRequirement {
    /// Do not require fs-verity.
    #[default]
    Disabled,
    /// Require fs-verity; fail if the kernel does not support it.
    Required,
    /// Try to enable fs-verity; silently continue if unsupported.
    Try,
}

/// Options controlling how a composefs image is mounted.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct MountOptions {
    /// Overlay upper layer and work directory: (upperdir, workdir).
    upperdirs: Option<(OwnedFd, OwnedFd)>,
    read_write: bool,
    /// User namespace file descriptor for ID-mapped mounts.
    idmap_fd: Option<OwnedFd>,
}

impl MountOptions {
    /// Add an overlayfs upper layer and work directory to the mount.
    pub fn set_overlay(&mut self, upperdir: OwnedFd, workdir: OwnedFd) -> &mut Self {
        self.upperdirs = Some((upperdir, workdir));
        self
    }

    /// Make the mount read-write (only meaningful with an overlay).
    pub fn set_read_write(&mut self, read_write: bool) -> &mut Self {
        self.read_write = read_write;
        self
    }

    /// Set a user namespace file descriptor for ID-mapped mounts.
    pub fn set_idmap(&mut self, fd: OwnedFd) -> &mut Self {
        self.idmap_fd = Some(fd);
        self
    }

    /// Whether an overlay upper layer was configured.
    pub fn has_overlay(&self) -> bool {
        self.upperdirs.is_some()
    }

    /// Whether the mount should be read-write.
    pub fn read_write(&self) -> bool {
        self.read_write
    }

    /// Consume the options, returning the overlay fds if set.
    pub fn into_overlay(self) -> Option<(OwnedFd, OwnedFd)> {
        self.upperdirs
    }
}

/// Creates a composefs mount using overlayfs with an erofs image and base directories.
///
/// This mounts a composefs image by creating an overlayfs that layers the erofs image
/// (as the lower layer) over base directories (as data layers). The overlayfs is
/// configured with metacopy and redirect_dir enabled for composefs functionality.
///
/// # Arguments
///
/// * `image` - File descriptor for the composefs erofs image
/// * `name` - Name for the mount source (appears as "composefs:{name}")
/// * `basedirs` - File descriptors for the base directories containing actual file data
/// * `verity` - Whether and how to enforce fs-verity verification for overlay files
/// * `options` - Mount options controlling overlay and read-write behaviour
///
/// # Returns
///
/// Returns a file descriptor for the mounted composefs filesystem, which can be used
/// with `mount_at()` to attach it to a mount point.
pub fn composefs_fsmount(
    image: OwnedFd,
    name: &str,
    basedirs: &[BorrowedFd<'_>],
    verity: VerityRequirement,
    options: &MountOptions,
) -> Result<OwnedFd> {
    let erofs_mnt = erofs_mount(image)?;
    if let Some(idmap_fd) = &options.idmap_fd {
        composefs_ioctls::mount::mount_setattr_idmap(erofs_mnt.as_fd(), idmap_fd.as_fd())?;
    }
    let erofs_mnt = prepare_mount(erofs_mnt)?;

    let mut overlayfs = FsHandle::open("overlay")?;
    fsconfig_set_string(overlayfs.as_fd(), "source", format!("composefs:{name}"))?;
    fsconfig_set_string(overlayfs.as_fd(), "metacopy", "on")?;
    fsconfig_set_string(overlayfs.as_fd(), "redirect_dir", "on")?;
    match verity {
        VerityRequirement::Disabled => {}
        VerityRequirement::Required => {
            fsconfig_set_string(overlayfs.as_fd(), "verity", "require")?;
        }
        VerityRequirement::Try => {
            overlayfs.buffer_errors()?;
            match fsconfig_set_string(overlayfs.as_fd(), "verity", "require") {
                Ok(()) => {}
                Err(rustix::io::Errno::INVAL) | Err(rustix::io::Errno::NOSYS) => {
                    overlayfs.discard_errors()?;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    if let Some((upperdir, workdir)) = &options.upperdirs {
        overlayfs_set_fd(overlayfs.as_fd(), "upperdir", upperdir.as_fd())?;
        overlayfs_set_fd(overlayfs.as_fd(), "workdir", workdir.as_fd())?;
    }
    overlayfs_set_lower_and_data_fds(&overlayfs, &erofs_mnt, basedirs)?;
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    // Model fscontext records: an undersized read leaves the message queued.
    fn read_message(
        pending: &mut VecDeque<Vec<u8>>,
        buffer: &mut [u8],
    ) -> rustix::io::Result<usize> {
        let Some(message) = pending.front() else {
            return Err(Errno::NODATA);
        };
        if message.len() > buffer.len() {
            return Err(Errno::MSGSIZE);
        }
        let message = pending.pop_front().unwrap();
        buffer[..message.len()].copy_from_slice(&message);
        Ok(message.len())
    }

    #[test]
    fn empty_diagnostics() -> Result<()> {
        for result in [Ok(0), Err(Errno::NODATA)] {
            FsHandle::read_errors_with(
                |buffer| {
                    assert!(buffer.is_empty());
                    result
                },
                |_| panic!("No diagnostic should be consumed"),
            )?;
        }
        Ok(())
    }

    #[test]
    fn oversized_diagnostics() -> Result<()> {
        for size in [1024, 1025, 8193] {
            let expected = [
                b"w before\n".to_vec(),
                vec![b'x'; size],
                b"e after\n".to_vec(),
            ];
            let mut pending = VecDeque::from(expected.clone());
            let mut actual = Vec::new();
            FsHandle::read_errors_with(
                |buffer| read_message(&mut pending, buffer),
                |message| actual.push(message),
            )?;
            assert_eq!(actual, expected);
        }
        Ok(())
    }

    #[test]
    fn preserve_diagnostics_around_probe() -> Result<()> {
        for discard_probe in [false, true] {
            let mut pending = VecDeque::new();
            let mut saved = Vec::new();
            let mut drain = |pending: &mut VecDeque<_>, save: bool| {
                FsHandle::read_errors_with(
                    |buffer| read_message(pending, buffer),
                    |message| {
                        if save {
                            saved.push(message);
                        }
                    },
                )
            };

            pending.push_back(b"w before probe\n".to_vec());
            drain(&mut pending, true)?;
            pending.push_back(b"e probe failure\n".to_vec());
            if discard_probe {
                drain(&mut pending, false)?;
            }
            pending.push_back(b"e fallback failure\n".to_vec());
            drain(&mut pending, true)?;

            let expected = if discard_probe {
                b"w before probe\ne fallback failure\n".as_slice()
            } else {
                b"w before probe\ne probe failure\ne fallback failure\n".as_slice()
            };
            assert_eq!(saved.concat(), expected);
        }
        Ok(())
    }
}
