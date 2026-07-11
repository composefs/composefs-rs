//! Low-level ioctl interfaces for fs-verity kernel operations.
//!
//! This module provides wrappers around the composefs-ioctls crate,
//! adapting them to work with the FsVerityHashValue trait.

use std::os::fd::AsFd;

// Re-export error types from composefs-ioctls
pub use composefs_ioctls::fsverity::{EnableVerityError, MeasureVerityError};

use super::FsVerityHashValue;

/// Enable fsverity on the target file.
///
/// This is a wrapper for the underlying ioctl that uses the FsVerityHashValue
/// trait to determine the algorithm. The file descriptor must be opened O_RDONLY
/// and there must be no other writable file descriptors.
pub(super) fn fs_ioc_enable_verity<H: FsVerityHashValue>(
    fd: impl AsFd,
) -> Result<(), EnableVerityError> {
    composefs_ioctls::fsverity::fs_ioc_enable_verity(fd.as_fd(), H::ALGORITHM.kernel_id(), 4096)
}

/// Enable fsverity on the target file with an optional PKCS#7 signature.
///
/// Like [`fs_ioc_enable_verity`] but also passes a DER-encoded detached
/// signature to the kernel for validation against the `.fs-verity` keyring.
pub(super) fn fs_ioc_enable_verity_with_sig<H: FsVerityHashValue>(
    fd: impl AsFd,
    signature: Option<&[u8]>,
) -> Result<(), EnableVerityError> {
    composefs_ioctls::fsverity::fs_ioc_enable_verity_with_sig(
        fd.as_fd(),
        H::ALGORITHM.kernel_id(),
        4096,
        signature,
    )
}

/// Check whether a file has a kernel-enrolled fs-verity builtin signature.
///
/// Unlike the other wrappers in this module, this isn't parameterized by
/// [`FsVerityHashValue`]: `FS_IOC_READ_VERITY_METADATA` doesn't depend on
/// the hash algorithm.
pub(super) fn fs_ioc_has_verity_signature(fd: impl AsFd) -> std::io::Result<bool> {
    composefs_ioctls::fsverity::fs_ioc_has_verity_signature(fd)
}

/// Measure the fsverity digest of the provided file descriptor.
///
/// Returns the digest as the appropriate FsVerityHashValue type.
pub(super) fn fs_ioc_measure_verity<H: FsVerityHashValue>(
    fd: impl AsFd,
) -> Result<H, MeasureVerityError> {
    // Dispatch based on algorithm to call the appropriate const-generic version
    let kid = H::ALGORITHM.kernel_id();
    match kid {
        1 => {
            let digest: [u8; 32] =
                composefs_ioctls::fsverity::fs_ioc_measure_verity(fd.as_fd(), kid)?;
            Ok(H::read_from_bytes(&digest).expect("size mismatch"))
        }
        2 => {
            let digest: [u8; 64] =
                composefs_ioctls::fsverity::fs_ioc_measure_verity(fd.as_fd(), kid)?;
            Ok(H::read_from_bytes(&digest).expect("size mismatch"))
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;

    use tempfile::tempfile_in;

    use crate::{fsverity::Sha256HashValue, test::tempfile};

    use super::*;

    #[test]
    fn test_measure_verity_opt() {
        let tf = tempfile();
        assert!(matches!(
            fs_ioc_measure_verity::<Sha256HashValue>(&tf),
            Err(MeasureVerityError::VerityMissing)
        ));
    }

    #[test_with::path(/dev/shm)]
    #[test]
    fn test_measure_verity_not_supported() {
        let tf = tempfile_in("/dev/shm").unwrap();
        assert!(matches!(
            fs_ioc_measure_verity::<Sha256HashValue>(&tf),
            Err(MeasureVerityError::FilesystemNotSupported)
        ));
    }

    #[test_with::path(/dev/shm)]
    #[test]
    fn test_fs_ioc_enable_verity_wrong_fs() {
        let file = tempfile_in("/dev/shm").unwrap();
        let fd = OwnedFd::from(file);
        let err = fs_ioc_enable_verity::<Sha256HashValue>(&fd).unwrap_err();
        assert!(matches!(err, EnableVerityError::FilesystemNotSupported));
        assert_eq!(err.to_string(), "Filesystem does not support fs-verity",);
    }

    // Note: This test uses unsafe code via ManuallyDrop + from_raw_fd.
    // Since we forbid unsafe in this crate, we test bad fd behavior differently.
    // The composefs-ioctls crate has its own tests for error handling.
}
