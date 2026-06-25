//! Low-level mount syscall wrappers not yet exposed by rustix.
#![allow(unsafe_code)]

use std::os::fd::{AsFd, AsRawFd};

const MOUNT_ATTR_IDMAP: u64 = 0x00100000;
const AT_EMPTY_PATH: u32 = 0x1000;

#[cfg(not(any(
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6"
)))]
const SYS_MOUNT_SETATTR: std::ffi::c_long = 442;
#[cfg(any(target_arch = "mips", target_arch = "mips32r6"))]
const SYS_MOUNT_SETATTR: std::ffi::c_long = 4442;
#[cfg(any(target_arch = "mips64", target_arch = "mips64r6"))]
const SYS_MOUNT_SETATTR: std::ffi::c_long = 5442;

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

unsafe extern "C" {
    fn syscall(num: std::ffi::c_long, ...) -> std::ffi::c_long;
}

/// Applies an ID mapping from a user namespace to a mount.
pub fn mount_setattr_idmap(mount_fd: impl AsFd, userns_fd: impl AsFd) -> std::io::Result<()> {
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd: userns_fd.as_fd().as_raw_fd() as u64,
    };
    let ret = unsafe {
        syscall(
            SYS_MOUNT_SETATTR,
            mount_fd.as_fd().as_raw_fd(),
            c"".as_ptr(),
            AT_EMPTY_PATH,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
