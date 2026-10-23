//! Low-level ioctl interfaces for fs-verity kernel operations.
//!
//! This module provides safe wrappers around the Linux fs-verity ioctls
//! for enabling and measuring fs-verity on files.

#![allow(unsafe_code)]

use std::{io::Error, os::fd::AsFd};

use rustix::{
    io::Errno,
    ioctl::{Opcode, Setter, Updater, ioctl, opcode},
};
use thiserror::Error;

/// Enabling fsverity failed.
#[derive(Error, Debug)]
pub enum EnableVerityError {
    /// I/O operation failed.
    #[error("FS_IOC_ENABLE_VERITY: {0}")]
    Io(#[from] Error),
    /// The filesystem does not support fs-verity.
    #[error("FS_IOC_ENABLE_VERITY: filesystem does not support fs-verity")]
    FilesystemNotSupported,
    /// fs-verity is already enabled on the file.
    #[error("FS_IOC_ENABLE_VERITY: fs-verity is already enabled on file")]
    AlreadyEnabled,
    /// The file has an open writable file descriptor.
    #[error("FS_IOC_ENABLE_VERITY: file is opened for writing")]
    FileOpenedForWrite,
    /// Signature verification failed (when using kernel signatures).
    #[error("FS_IOC_ENABLE_VERITY: signature verification failed")]
    SignatureVerificationFailed,
}

/// Measuring fsverity failed.
#[derive(Error, Debug)]
pub enum MeasureVerityError {
    /// I/O operation failed.
    #[error("FS_IOC_MEASURE_VERITY: {0}")]
    Io(#[from] Error),
    /// fs-verity is not enabled on the file.
    #[error("FS_IOC_MEASURE_VERITY: fs-verity is not enabled on file")]
    VerityMissing,
    /// The filesystem does not support fs-verity.
    #[error("FS_IOC_MEASURE_VERITY: fs-verity is not supported by filesystem")]
    FilesystemNotSupported,
    /// The hash algorithm does not match the expected algorithm.
    #[error("FS_IOC_MEASURE_VERITY: expected algorithm {expected}, found {found}")]
    InvalidDigestAlgorithm {
        /// The expected algorithm identifier.
        expected: u16,
        /// The actual algorithm identifier found.
        found: u16,
    },
    /// The digest size does not match the expected size.
    #[error("FS_IOC_MEASURE_VERITY: expected digest size {expected}")]
    InvalidDigestSize {
        /// The expected digest size in bytes.
        expected: u16,
    },
}

// See /usr/include/linux/fsverity.h
#[repr(C)]
#[derive(Debug)]
struct FsVerityEnableArg {
    version: u32,
    hash_algorithm: u32,
    block_size: u32,
    salt_size: u32,
    salt_ptr: u64,
    sig_size: u32,
    __reserved1: u32,
    sig_ptr: u64,
    __reserved2: [u64; 11],
}

// #define FS_IOC_ENABLE_VERITY    _IOW('f', 133, struct fsverity_enable_arg)
const FS_IOC_ENABLE_VERITY: Opcode = opcode::write::<FsVerityEnableArg>(b'f', 133);

/// Enable fs-verity on the target file without a signature.
///
/// This is a thin safe wrapper for the `FS_IOC_ENABLE_VERITY` ioctl.
/// The file descriptor must be opened `O_RDONLY` and there must be no
/// other writable file descriptors or mappings for the file.
///
/// # Arguments
/// * `fd` - File descriptor opened O_RDONLY
/// * `hash_algorithm` - Algorithm ID (1 = SHA-256, 2 = SHA-512)
/// * `block_size` - Block size (typically 4096)
pub fn fs_ioc_enable_verity(
    fd: impl AsFd,
    hash_algorithm: u8,
    block_size: u32,
) -> Result<(), EnableVerityError> {
    fs_ioc_enable_verity_with_sig(fd, hash_algorithm, block_size, None)
}

/// Enable fs-verity on the target file with an optional PKCS#7 signature.
///
/// When a signature is provided, the kernel will verify it against keys
/// in the `.fs-verity` keyring before enabling verity.
///
/// # Arguments
/// * `fd` - File descriptor opened O_RDONLY
/// * `hash_algorithm` - Algorithm ID (1 = SHA-256, 2 = SHA-512)
/// * `block_size` - Block size (typically 4096)
/// * `signature` - Optional PKCS#7 DER-encoded signature
pub fn fs_ioc_enable_verity_with_sig(
    fd: impl AsFd,
    hash_algorithm: u8,
    block_size: u32,
    signature: Option<&[u8]>,
) -> Result<(), EnableVerityError> {
    let (sig_size, sig_ptr) = match signature {
        Some(sig) => (sig.len() as u32, sig.as_ptr() as u64),
        None => (0, 0),
    };

    unsafe {
        match ioctl(
            fd,
            Setter::<{ FS_IOC_ENABLE_VERITY }, FsVerityEnableArg>::new(FsVerityEnableArg {
                version: 1,
                hash_algorithm: hash_algorithm as u32,
                block_size,
                salt_size: 0,
                salt_ptr: 0,
                sig_size,
                __reserved1: 0,
                sig_ptr,
                __reserved2: [0; 11],
            }),
        ) {
            Err(Errno::NOTTY) | Err(Errno::OPNOTSUPP) => {
                Err(EnableVerityError::FilesystemNotSupported)
            }
            Err(Errno::EXIST) => Err(EnableVerityError::AlreadyEnabled),
            Err(Errno::TXTBSY) => Err(EnableVerityError::FileOpenedForWrite),
            Err(Errno::KEYREJECTED) => Err(EnableVerityError::SignatureVerificationFailed),
            Err(e) => Err(Error::from(e).into()),
            Ok(_) => Ok(()),
        }
    }
}

/// Core definition of a fsverity digest returned by the kernel.
#[repr(C)]
#[derive(Debug)]
struct FsVerityDigest<const N: usize> {
    digest_algorithm: u16,
    digest_size: u16,
    digest: [u8; N],
}

// #define FS_IOC_MEASURE_VERITY   _IORW('f', 134, struct fsverity_digest)
const FS_IOC_MEASURE_VERITY: Opcode = opcode::read_write::<FsVerityDigest<0>>(b'f', 134);

/// Measure the fs-verity digest of a file.
///
/// Returns the raw digest bytes if successful. The generic parameter `N`
/// specifies the expected digest size (32 for SHA-256, 64 for SHA-512).
///
/// # Arguments
/// * `fd` - File descriptor to measure
/// * `expected_algorithm` - Expected algorithm ID (1 = SHA-256, 2 = SHA-512)
///
/// # Returns
/// The digest bytes on success.
pub fn fs_ioc_measure_verity<const N: usize>(
    fd: impl AsFd,
    expected_algorithm: u8,
) -> Result<[u8; N], MeasureVerityError> {
    let digest_size = N as u16;
    let digest_algorithm = expected_algorithm as u16;

    let mut digest = FsVerityDigest::<N> {
        digest_algorithm,
        digest_size,
        digest: [0u8; N],
    };

    let r = unsafe {
        ioctl(
            fd,
            Updater::<{ FS_IOC_MEASURE_VERITY }, FsVerityDigest<N>>::new(&mut digest),
        )
    };

    match r {
        Ok(()) => {
            if digest.digest_algorithm != digest_algorithm {
                return Err(MeasureVerityError::InvalidDigestAlgorithm {
                    expected: digest_algorithm,
                    found: digest.digest_algorithm,
                });
            }
            if digest.digest_size != digest_size {
                return Err(MeasureVerityError::InvalidDigestSize {
                    expected: digest_size,
                });
            }
            Ok(digest.digest)
        }
        Err(Errno::NODATA) => Err(MeasureVerityError::VerityMissing),
        Err(Errno::NOTTY | Errno::OPNOTSUPP) => Err(MeasureVerityError::FilesystemNotSupported),
        Err(Errno::OVERFLOW) => Err(MeasureVerityError::InvalidDigestSize {
            expected: digest.digest_size,
        }),
        Err(e) => Err(Error::from(e).into()),
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write, os::fd::AsRawFd};

    use tempfile::tempfile_in;

    use super::*;

    fn get_test_tmpdir() -> std::ffi::OsString {
        if let Some(path) = std::env::var_os("CFS_TEST_TMPDIR") {
            path
        } else {
            let home = std::env::var("HOME").expect("$HOME must be set when running tests");
            let tmp = std::path::PathBuf::from(home).join(".var/tmp");
            std::fs::create_dir_all(&tmp).expect("can't create ~/.var/tmp");
            tmp.into()
        }
    }

    fn test_tempfile() -> std::fs::File {
        tempfile_in(get_test_tmpdir()).unwrap()
    }

    fn reopen_readonly(file: &std::fs::File) -> rustix::fd::OwnedFd {
        let path = format!("/proc/self/fd/{}", file.as_raw_fd());
        rustix::fs::open(&path, rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty()).unwrap()
    }

    #[test]
    fn test_measure_verity_missing() {
        let mut tf = test_tempfile();
        tf.write_all(b"test").unwrap();
        tf.sync_all().unwrap();

        let ro_fd = reopen_readonly(&tf);
        let err = fs_ioc_measure_verity::<32>(&ro_fd, 1).unwrap_err();
        // The configured test filesystem may not implement fs-verity at all.
        assert!(
            matches!(
                err,
                MeasureVerityError::VerityMissing | MeasureVerityError::FilesystemNotSupported
            ),
            "{err:?}"
        );
    }

    #[test]
    fn test_enable_verity_readonly_and_open_writer() {
        let mut writer = test_tempfile();
        writer.write_all(b"test").unwrap();
        writer.sync_all().unwrap();
        let reader = reopen_readonly(&writer);

        match fs_ioc_enable_verity(&reader, 1, 4096).unwrap_err() {
            EnableVerityError::FilesystemNotSupported => {
                assert!(matches!(
                    fs_ioc_measure_verity::<32>(&reader, 1),
                    Err(MeasureVerityError::FilesystemNotSupported)
                ));
                drop(writer);
                assert!(matches!(
                    fs_ioc_enable_verity(&reader, 1, 4096),
                    Err(EnableVerityError::FilesystemNotSupported)
                ));
            }
            EnableVerityError::FileOpenedForWrite => {
                drop(writer);
                fs_ioc_enable_verity(&reader, 1, 4096).unwrap();
                let digest = fs_ioc_measure_verity::<32>(&reader, 1).unwrap();
                assert!(matches!(
                    fs_ioc_enable_verity(&reader, 1, 4096),
                    Err(EnableVerityError::AlreadyEnabled)
                ));
                assert_eq!(fs_ioc_measure_verity::<32>(&reader, 1).unwrap(), digest);
            }
            err => panic!("unexpected error with an open writer: {err:?}"),
        }
    }

    #[test]
    fn test_verity_io_error_context() {
        // O_PATH descriptors cannot be used for these ioctls, regardless of
        // whether the underlying filesystem supports fs-verity.
        let fd =
            rustix::fs::open("/", rustix::fs::OFlags::PATH, rustix::fs::Mode::empty()).unwrap();
        let enable = fs_ioc_enable_verity(&fd, 1, 4096).unwrap_err();
        let measure = fs_ioc_measure_verity::<32>(&fd, 1).unwrap_err();
        assert!(enable.to_string().starts_with("FS_IOC_ENABLE_VERITY:"));
        assert!(measure.to_string().starts_with("FS_IOC_MEASURE_VERITY:"));
        match enable {
            EnableVerityError::Io(err) => {
                assert_eq!(err.raw_os_error(), Some(Errno::BADF.raw_os_error()))
            }
            err => panic!("unexpected enable error: {err:?}"),
        }
        match measure {
            MeasureVerityError::Io(err) => {
                assert_eq!(err.raw_os_error(), Some(Errno::BADF.raw_os_error()))
            }
            err => panic!("unexpected measure error: {err:?}"),
        }
    }

    #[test_with::path(/dev/shm)]
    #[test]
    fn test_measure_verity_not_supported() {
        let tf = tempfile_in("/dev/shm").unwrap();
        assert!(matches!(
            fs_ioc_measure_verity::<32>(&tf, 1),
            Err(MeasureVerityError::FilesystemNotSupported)
        ));
    }

    #[test_with::path(/dev/shm)]
    #[test]
    fn test_enable_verity_wrong_fs() {
        let file = tempfile_in("/dev/shm").unwrap();
        let reader = reopen_readonly(&file);
        drop(file);
        let err = fs_ioc_enable_verity(&reader, 1, 4096).unwrap_err();
        assert!(
            matches!(err, EnableVerityError::FilesystemNotSupported),
            "{err:?}"
        );
    }
}
