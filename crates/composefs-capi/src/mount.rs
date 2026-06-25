use std::ffi::{CStr, CString, c_char, c_int};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};

use libc::size_t;
use rustix::fs::{CWD, Mode, OFlags, open};

use crate::errno::set_errno;

#[repr(C)]
pub struct LcfsMountOptions {
    pub objdirs: *const *const c_char,
    pub n_objdirs: size_t,
    pub workdir: *const c_char,
    pub upperdir: *const c_char,
    pub expected_fsverity_digest: *const c_char,
    pub flags: u32,
    pub idmap_fd: c_int,
    pub image_mountdir: *const c_char,
    pub reserved: [u32; 4],
    pub reserved2: [*mut std::ffi::c_void; 4],
}

const LCFS_MOUNT_FLAGS_REQUIRE_VERITY: u32 = 1 << 0;
const LCFS_MOUNT_FLAGS_IDMAP: u32 = 1 << 3;
const LCFS_MOUNT_FLAGS_TRY_VERITY: u32 = 1 << 4;

fn io_error_to_errno(e: &std::io::Error) -> c_int {
    e.raw_os_error().unwrap_or(libc::EINVAL)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_mount_image(
    path: *const c_char,
    mountpoint: *const c_char,
    options: *mut LcfsMountOptions,
) -> c_int {
    if path.is_null() || mountpoint.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }

    unsafe {
        let path_cstr = CStr::from_ptr(path);

        let image_fd = match open(path_cstr, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()) {
            Ok(fd) => fd,
            Err(e) => {
                set_errno(e.raw_os_error());
                return -1;
            }
        };

        let raw_fd = rustix::fd::IntoRawFd::into_raw_fd(image_fd);
        let result = lcfs_mount_fd(raw_fd, mountpoint, options);
        libc::close(raw_fd);
        result
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_mount_fd(
    fd: c_int,
    mountpoint: *const c_char,
    options: *mut LcfsMountOptions,
) -> c_int {
    if fd < 0 || mountpoint.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }

    unsafe {
        let mountpoint_cstr = CStr::from_ptr(mountpoint);

        let dup_fd = libc::dup(fd);
        if dup_fd < 0 {
            return -1;
        }
        let image_fd = OwnedFd::from_raw_fd(dup_fd);

        let erofs_fd = match composefs::mount::erofs_mount(image_fd) {
            Ok(fd) => fd,
            Err(e) => {
                set_errno(io_error_to_errno(&e));
                return -1;
            }
        };

        let mut basedirs: Vec<CString> = Vec::new();
        if !options.is_null() {
            let opts = &*options;
            if !opts.objdirs.is_null() && opts.n_objdirs > 0 {
                for i in 0..opts.n_objdirs {
                    let dir_ptr = *opts.objdirs.add(i);
                    if !dir_ptr.is_null() {
                        basedirs.push(CStr::from_ptr(dir_ptr).to_owned());
                    }
                }
            }
        }

        let verity = if !options.is_null() {
            let opts = &*options;
            if (opts.flags & LCFS_MOUNT_FLAGS_REQUIRE_VERITY) != 0 {
                composefs::mount::VerityRequirement::Required
            } else if (opts.flags & LCFS_MOUNT_FLAGS_TRY_VERITY) != 0 {
                composefs::mount::VerityRequirement::Try
            } else {
                composefs::mount::VerityRequirement::Disabled
            }
        } else {
            composefs::mount::VerityRequirement::Disabled
        };

        if !basedirs.is_empty() {
            let mut basedir_fds: Vec<OwnedFd> = Vec::new();
            for dir in &basedirs {
                match open(
                    dir.as_c_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(fd) => basedir_fds.push(fd),
                    Err(e) => {
                        set_errno(e.raw_os_error());
                        return -1;
                    }
                }
            }

            let borrowed: Vec<_> = basedir_fds.iter().map(|fd| fd.as_fd()).collect();
            let mut mount_options = composefs::mount::MountOptions::default();

            if !options.is_null() {
                let opts = &*options;
                if (opts.flags & LCFS_MOUNT_FLAGS_IDMAP) != 0 && opts.idmap_fd >= 0 {
                    let dup_idmap = libc::dup(opts.idmap_fd);
                    if dup_idmap < 0 {
                        return -1;
                    }
                    mount_options.set_idmap(OwnedFd::from_raw_fd(dup_idmap));
                }
            }

            match composefs::mount::composefs_fsmount(
                erofs_fd,
                "composefs",
                &borrowed,
                verity,
                &mount_options,
            ) {
                Ok(fs_fd) => {
                    if let Err(e) = composefs::mount::mount_at(&fs_fd, CWD, mountpoint_cstr) {
                        set_errno(e.raw_os_error());
                        return -1;
                    }
                }
                Err(e) => {
                    set_errno(io_error_to_errno(&e));
                    return -1;
                }
            }
        } else {
            if let Err(e) = composefs::mount::mount_at(&erofs_fd, CWD, mountpoint_cstr) {
                set_errno(e.raw_os_error());
                return -1;
            }
        }

        0
    }
}
