use std::ffi::CString;
use std::io::{Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::ptr;

use crate::node;

unsafe extern "C" {
    fn test_basic();
    fn test_xattr_addremove();
    fn test_xattr_doubleadd();
    fn test_add_uninitialized_child();
    fn test_hardlinked_whiteout_load();
    fn test_no_verity();
}

#[test]
fn c_test_basic() {
    unsafe { test_basic() };
}

#[test]
fn c_test_xattr_addremove() {
    unsafe { test_xattr_addremove() };
}

#[test]
fn c_test_xattr_doubleadd() {
    unsafe { test_xattr_doubleadd() };
}

#[test]
fn c_test_add_uninitialized_child() {
    unsafe { test_add_uninitialized_child() };
}

#[test]
fn c_test_hardlinked_whiteout_load() {
    unsafe { test_hardlinked_whiteout_load() };
}

#[test]
fn c_test_no_verity() {
    unsafe { test_no_verity() };
}

// -----------------------------------------------------------------------
// Tests for bugs found in cross-reference review vs C libcomposefs
// -----------------------------------------------------------------------

/// Bug 5: lcfs_node_new must initialize nlink to 1 (not 0).
/// The C library sets st_nlink = 1 in lcfs_node_new().
#[test]
fn test_nlink_default_is_one() {
    unsafe {
        let n = node::lcfs_node_new();
        assert!(!n.is_null());
        assert_eq!(node::lcfs_node_get_nlink(n), 1, "nlink must default to 1");
        node::lcfs_node_unref(n);
    }
}

/// Bug 3: lcfs_node_set_symlink_payload must update node size to payload length.
/// The C library sets node->inode.st_size = strlen(node->payload).
#[test]
fn test_symlink_payload_updates_size() {
    unsafe {
        let n = node::lcfs_node_new();
        node::lcfs_node_set_mode(n, libc::S_IFLNK | 0o777);

        let target = CString::new("/usr/bin/bash").unwrap();
        let ret = node::lcfs_node_set_symlink_payload(n, target.as_ptr());
        assert_eq!(ret, 0);
        assert_eq!(
            node::lcfs_node_get_size(n),
            13,
            "size must equal symlink target length"
        );

        node::lcfs_node_unref(n);
    }
}

/// Bug 3: lcfs_node_set_symlink_payload must reject NULL payload.
#[test]
fn test_symlink_payload_rejects_null() {
    unsafe {
        let n = node::lcfs_node_new();
        node::lcfs_node_set_mode(n, libc::S_IFLNK | 0o777);

        let ret = node::lcfs_node_set_symlink_payload(n, ptr::null());
        assert_eq!(ret, -1, "NULL symlink target must fail");

        node::lcfs_node_unref(n);
    }
}

/// Bug 3: lcfs_node_set_symlink_payload must reject empty string payload.
#[test]
fn test_symlink_payload_rejects_empty() {
    unsafe {
        let n = node::lcfs_node_new();
        node::lcfs_node_set_mode(n, libc::S_IFLNK | 0o777);

        let empty = CString::new("").unwrap();
        let ret = node::lcfs_node_set_symlink_payload(n, empty.as_ptr());
        assert_eq!(ret, -1, "empty symlink target must fail");

        node::lcfs_node_unref(n);
    }
}

/// Bug 7: lcfs_node_set_payload must reject payloads >= PATH_MAX.
/// The C library checks strlen(payload) >= PATH_MAX and returns ENAMETOOLONG.
#[test]
fn test_payload_rejects_too_long() {
    unsafe {
        let n = node::lcfs_node_new();
        node::lcfs_node_set_mode(n, libc::S_IFREG | 0o644);

        // PATH_MAX is typically 4096
        let long_path = "x".repeat(libc::PATH_MAX as usize);
        let payload = CString::new(long_path).unwrap();
        let ret = node::lcfs_node_set_payload(n, payload.as_ptr());
        assert_eq!(ret, -1, "payload >= PATH_MAX must fail");

        let errno_val = *libc::__errno_location();
        assert_eq!(errno_val, libc::ENAMETOOLONG, "errno must be ENAMETOOLONG");

        node::lcfs_node_unref(n);
    }
}

/// Bug 7: Payload just under PATH_MAX should succeed.
#[test]
fn test_payload_under_path_max_succeeds() {
    unsafe {
        let n = node::lcfs_node_new();
        node::lcfs_node_set_mode(n, libc::S_IFREG | 0o644);

        let ok_path = "x".repeat(libc::PATH_MAX as usize - 1);
        let payload = CString::new(ok_path).unwrap();
        let ret = node::lcfs_node_set_payload(n, payload.as_ptr());
        assert_eq!(ret, 0, "payload < PATH_MAX must succeed");

        node::lcfs_node_unref(n);
    }
}

/// Bug 8: lcfs_node_set_xattr must reject empty xattr names.
/// The C library checks namelen == 0 and returns ERANGE.
#[test]
fn test_xattr_rejects_empty_name() {
    unsafe {
        let n = node::lcfs_node_new();
        let empty_name = CString::new("").unwrap();
        let value = CString::new("val").unwrap();
        let ret = node::lcfs_node_set_xattr(n, empty_name.as_ptr(), value.as_ptr(), 3);
        assert_eq!(ret, -1, "empty xattr name must fail");

        let errno_val = *libc::__errno_location();
        assert_eq!(errno_val, libc::ERANGE, "errno must be ERANGE");

        node::lcfs_node_unref(n);
    }
}

/// Bug 8: lcfs_node_set_xattr must reject xattr names > XATTR_NAME_MAX (255).
#[test]
fn test_xattr_rejects_long_name() {
    unsafe {
        let n = node::lcfs_node_new();
        let long_name = "x".repeat(256);
        let name = CString::new(long_name).unwrap();
        let value = CString::new("val").unwrap();
        let ret = node::lcfs_node_set_xattr(n, name.as_ptr(), value.as_ptr(), 3);
        assert_eq!(ret, -1, "xattr name > 255 must fail");

        let errno_val = *libc::__errno_location();
        assert_eq!(errno_val, libc::ERANGE, "errno must be ERANGE");

        node::lcfs_node_unref(n);
    }
}

/// Bug 8: lcfs_node_set_xattr must reject value_len > UINT16_MAX.
#[test]
fn test_xattr_rejects_huge_value() {
    unsafe {
        let n = node::lcfs_node_new();
        let name = CString::new("user.test").unwrap();
        let too_big = u16::MAX as usize + 1;
        let data = vec![0u8; too_big];
        let ret = node::lcfs_node_set_xattr(n, name.as_ptr(), data.as_ptr() as *const _, too_big);
        assert_eq!(ret, -1, "xattr value > u16::MAX must fail");

        let errno_val = *libc::__errno_location();
        assert_eq!(errno_val, libc::EINVAL, "errno must be EINVAL");

        node::lcfs_node_unref(n);
    }
}

/// Bug 8 (continued): replacing an existing xattr with a huge value must also
/// be checked against the cumulative limit, not just new insertions.
#[test]
fn test_xattr_replacement_checks_limit() {
    unsafe {
        let n = node::lcfs_node_new();
        // Insert a small xattr first
        let name = CString::new("user.test").unwrap();
        let small = CString::new("x").unwrap();
        let ret = node::lcfs_node_set_xattr(n, name.as_ptr(), small.as_ptr(), 1);
        assert_eq!(ret, 0, "initial small xattr must succeed");

        // Now try to replace it with a value just under u16::MAX (within the
        // per-value limit but likely exceeding cumulative EROFS limit)
        let big_len: usize = 60000; // > LCFS_INODE_EXTERNAL_XATTR_MAX (32767)
        let big = vec![b'A'; big_len];
        let ret = node::lcfs_node_set_xattr(n, name.as_ptr(), big.as_ptr() as *const _, big_len);
        assert_eq!(ret, -1, "replacing with huge value must fail");

        let errno_val = *libc::__errno_location();
        assert_eq!(errno_val, libc::ERANGE, "errno must be ERANGE");

        node::lcfs_node_unref(n);
    }
}

/// Bug 4: lcfs_compute_fsverity_from_fd must hash from current offset,
/// not seek to the beginning. The C library documents: "the computation
/// starts from the current offset position of the file."
#[test]
fn test_fsverity_from_fd_respects_offset() {
    use crate::fsverity;

    // Create an anonymous temp file via memfd
    let name = CString::new("test-fsverity").unwrap();
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    assert!(fd >= 0, "memfd_create failed");

    // Write known content: "AAABBB"
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(b"AAABBB").unwrap();

    // Compute expected hash of just "BBB" (the tail after seeking past 3 bytes)
    let mut expected_digest = [0u8; 32];
    unsafe {
        fsverity::lcfs_compute_fsverity_from_data(
            expected_digest.as_mut_ptr(),
            b"BBB".as_ptr() as *mut u8,
            3,
        );
    }

    // Seek to offset 3, then compute from fd — must hash only remaining bytes
    file.seek(std::io::SeekFrom::Start(3)).unwrap();
    let mut actual_digest = [0u8; 32];
    let fd = file.as_raw_fd();
    unsafe {
        let ret = fsverity::lcfs_compute_fsverity_from_fd(actual_digest.as_mut_ptr(), fd);
        assert_eq!(ret, 0);
    }
    // Prevent File from closing the fd (we handed raw fd to FFI)
    std::mem::forget(file);

    assert_eq!(
        actual_digest, expected_digest,
        "fsverity from fd at offset 3 must hash only the remaining bytes"
    );

    unsafe { libc::close(fd) };
}

/// Bug 6: lcfs_write_to must reject version > LCFS_VERSION_MAX (1).
#[test]
fn test_write_to_rejects_invalid_version() {
    use crate::image::{LcfsWriteOptions, lcfs_write_to};

    unsafe {
        let root = node::lcfs_node_new();
        node::lcfs_node_set_mode(root, libc::S_IFDIR | 0o755);

        let mut options: LcfsWriteOptions = std::mem::zeroed();
        options.version = 99; // invalid
        options.max_version = 99;

        let ret = lcfs_write_to(root, &mut options);
        assert_eq!(ret, -1, "version > 1 must fail");

        let errno_val = *libc::__errno_location();
        assert_eq!(errno_val, libc::EINVAL, "errno must be EINVAL");

        node::lcfs_node_unref(root);
    }
}

/// Bug 6: lcfs_write_to must clamp max_version up to version.
#[test]
fn test_write_to_clamps_max_version() {
    use crate::image::{LcfsWriteOptions, lcfs_write_to};

    unsafe extern "C" fn null_write(
        _file: *mut std::ffi::c_void,
        _buf: *mut std::ffi::c_void,
        count: usize,
    ) -> isize {
        count as isize
    }

    unsafe {
        let root = node::lcfs_node_new();
        node::lcfs_node_set_mode(root, libc::S_IFDIR | 0o755);

        let mut options: LcfsWriteOptions = std::mem::zeroed();
        options.format = 1; // LCFS_FORMAT_EROFS
        options.version = 1;
        options.max_version = 0; // less than version
        options.file_write_cb = Some(null_write);

        let ret = lcfs_write_to(root, &mut options);
        assert_eq!(ret, 0, "valid write should succeed");
        assert!(
            options.max_version >= options.version,
            "max_version must be clamped up to at least version"
        );

        node::lcfs_node_unref(root);
    }
}

/// Bug 1: lcfs_node_clone_deep must rewrite hardlink targets to point
/// to nodes within the cloned tree, not the original tree.
#[test]
fn test_clone_deep_rewrites_hardlinks() {
    unsafe {
        // Build a small tree:  root/
        //                        ├── file (regular)
        //                        └── link -> file (hardlink)
        let root = node::lcfs_node_new();
        node::lcfs_node_set_mode(root, libc::S_IFDIR | 0o755);

        let file = node::lcfs_node_new();
        node::lcfs_node_set_mode(file, libc::S_IFREG | 0o644);
        let file_name = CString::new("file").unwrap();
        assert_eq!(node::lcfs_node_add_child(root, file, file_name.as_ptr()), 0);

        let link = node::lcfs_node_new();
        node::lcfs_node_make_hardlink(link, file);
        let link_name = CString::new("link").unwrap();
        assert_eq!(node::lcfs_node_add_child(root, link, link_name.as_ptr()), 0);

        // Verify original tree: link's target IS the file node
        let orig_target = node::lcfs_node_get_hardlink_target(link);
        assert_eq!(orig_target, file, "original link must target the file node");

        // Deep-clone the tree
        let cloned_root = node::lcfs_node_clone_deep(root);
        assert!(!cloned_root.is_null(), "clone_deep must succeed");

        // Find the cloned "file" and "link" children
        let cloned_file_name = CString::new("file").unwrap();
        let cloned_file = node::lcfs_node_lookup_child(cloned_root, cloned_file_name.as_ptr());
        assert!(!cloned_file.is_null());

        let cloned_link_name = CString::new("link").unwrap();
        let cloned_link = node::lcfs_node_lookup_child(cloned_root, cloned_link_name.as_ptr());
        assert!(!cloned_link.is_null());

        // The cloned link's hardlink target must point to the CLONED file,
        // not the original file.
        let cloned_target = node::lcfs_node_get_hardlink_target(cloned_link);
        assert!(
            !cloned_target.is_null(),
            "cloned link must still have a hardlink target"
        );
        assert_ne!(
            cloned_target, file,
            "cloned link must NOT point to the original file node"
        );
        assert_eq!(
            cloned_target, cloned_file,
            "cloned link must point to the cloned file node"
        );

        // Verify the cloned nodes are distinct from the originals
        assert_ne!(cloned_root, root);
        assert_ne!(cloned_file, file);
        assert_ne!(cloned_link, link);

        node::lcfs_node_unref(cloned_root);
        node::lcfs_node_unref(root);
    }
}
