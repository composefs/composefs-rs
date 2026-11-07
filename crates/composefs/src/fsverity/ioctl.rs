//! Low-level ioctl interfaces for fs-verity kernel operations.
//!
//! This module provides wrappers around the composefs-ioctls crate,
//! adapting them to work with the FsVerityHashValue trait.

use std::os::fd::AsFd;

// Re-export error types from composefs-ioctls
pub use composefs_ioctls::fsverity::{EnableVerityError, MeasureVerityError};

use super::{Algorithm, FsVerityHashValue};

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

/// Enable fsverity on the target file, with the algorithm chosen at runtime.
///
/// Unlike [`fs_ioc_enable_verity`], this honours the block size carried by
/// `algorithm`.
#[cfg_attr(not(test), expect(dead_code, reason = "used by FsVerityHelper"))]
pub(crate) fn fs_ioc_enable_verity_with_algorithm(
    fd: impl AsFd,
    algorithm: Algorithm,
) -> Result<(), EnableVerityError> {
    composefs_ioctls::fsverity::fs_ioc_enable_verity(
        fd.as_fd(),
        algorithm.kernel_id(),
        1u32 << algorithm.lg_blocksize(),
    )
}

/// Measure the fsverity digest of a file, with the algorithm chosen at runtime.
///
/// Returns the raw digest bytes (32 for SHA-256, 64 for SHA-512).
#[cfg_attr(not(test), expect(dead_code, reason = "used by FsVerityHelper"))]
pub(crate) fn fs_ioc_measure_verity_with_algorithm(
    fd: impl AsFd,
    algorithm: Algorithm,
) -> Result<Vec<u8>, MeasureVerityError> {
    let kid = algorithm.kernel_id();
    match algorithm {
        Algorithm::Sha256 { .. } => {
            let digest: [u8; 32] =
                composefs_ioctls::fsverity::fs_ioc_measure_verity(fd.as_fd(), kid)?;
            Ok(digest.to_vec())
        }
        Algorithm::Sha512 { .. } => {
            let digest: [u8; 64] =
                composefs_ioctls::fsverity::fs_ioc_measure_verity(fd.as_fd(), kid)?;
            Ok(digest.to_vec())
        }
    }
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
        assert_eq!(
            err.to_string(),
            "FS_IOC_ENABLE_VERITY: filesystem does not support fs-verity",
        );
    }

    // Note: This test uses unsafe code via ManuallyDrop + from_raw_fd.
    // Since we forbid unsafe in this crate, we test bad fd behavior differently.
    // The composefs-ioctls crate has its own tests for error handling.

    fn rdonly_file_with(data: &[u8]) -> OwnedFd {
        use std::io::Write;

        let mut file = tempfile();
        file.write_all(data).unwrap();
        let fd = rustix::fs::open(
            crate::util::proc_self_fd(&file),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        drop(file);
        fd
    }

    fn check_runtime_algorithm<H: FsVerityHashValue>() {
        let data = b"hello world";
        let fd = rdonly_file_with(data);
        assert!(matches!(
            fs_ioc_measure_verity_with_algorithm(&fd, H::ALGORITHM),
            Err(MeasureVerityError::VerityMissing)
        ));
        fs_ioc_enable_verity_with_algorithm(&fd, H::ALGORITHM).unwrap();
        let digest = fs_ioc_measure_verity_with_algorithm(&fd, H::ALGORITHM).unwrap();
        assert_eq!(
            digest,
            crate::fsverity::compute_verity::<H>(data).as_bytes()
        );
        assert_eq!(fs_ioc_measure_verity::<H>(&fd).unwrap().as_bytes(), digest);
    }

    #[test]
    fn test_runtime_algorithm_sha256() {
        check_runtime_algorithm::<Sha256HashValue>();
    }

    #[test]
    fn test_runtime_algorithm_sha512() {
        check_runtime_algorithm::<crate::fsverity::Sha512HashValue>();
    }
}
