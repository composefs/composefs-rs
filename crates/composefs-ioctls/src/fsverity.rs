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
    #[error("{0}")]
    Io(#[from] Error),
    /// The filesystem does not support fs-verity.
    #[error("Filesystem does not support fs-verity")]
    FilesystemNotSupported,
    /// fs-verity is already enabled on the file.
    #[error("fs-verity is already enabled on file")]
    AlreadyEnabled,
    /// The file has an open writable file descriptor.
    #[error("File is opened for writing")]
    FileOpenedForWrite,
    /// The kernel rejected the signature as invalid (`EKEYREJECTED`) or
    /// malformed (`EBADMSG`). Unlike [`Self::SigningKeyNotFound`], this
    /// means a certificate *is* present in the `.fs-verity` keyring, but
    /// the given signature does not verify against it -- this is a real
    /// tamper-evidence signal and should not be silently ignored.
    #[error(
        "fs-verity signature rejected by kernel: no certificate in the \
         .fs-verity keyring could verify it (see `cfsctl keyring add-cert`), \
         or the file has been tampered with"
    )]
    SignatureVerificationFailed,
    /// The `.fs-verity` keyring has no certificate able to verify this
    /// signature (`ENOKEY`). This commonly just means no certificate has
    /// been loaded yet (see `cfsctl keyring add-cert`), so unlike
    /// [`Self::SignatureVerificationFailed`] this is not evidence of
    /// tampering and callers may reasonably fall back to enabling
    /// verity without a signature.
    #[error("No certificate in the .fs-verity keyring can verify this signature")]
    SigningKeyNotFound,
}

/// Measuring fsverity failed.
#[derive(Error, Debug)]
pub enum MeasureVerityError {
    /// I/O operation failed.
    #[error("{0}")]
    Io(#[from] Error),
    /// fs-verity is not enabled on the file.
    #[error("fs-verity is not enabled on file")]
    VerityMissing,
    /// The filesystem does not support fs-verity.
    #[error("fs-verity is not supported by filesystem")]
    FilesystemNotSupported,
    /// The hash algorithm does not match the expected algorithm.
    #[error("Expected algorithm {expected}, found {found}")]
    InvalidDigestAlgorithm {
        /// The expected algorithm identifier.
        expected: u16,
        /// The actual algorithm identifier found.
        found: u16,
    },
    /// The digest size does not match the expected size.
    #[error("Expected digest size {expected}")]
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

    let r = unsafe {
        ioctl(
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
        )
    };
    r.map_err(enable_verity_errno_to_error)
}

/// Maps the `errno` values documented for `FS_IOC_ENABLE_VERITY` (see
/// `Documentation/filesystems/fsverity.rst`) onto [`EnableVerityError`].
///
/// Split out as a free function so the mapping can be unit tested without
/// needing an fs-verity- or signature-capable kernel/filesystem.
fn enable_verity_errno_to_error(e: Errno) -> EnableVerityError {
    match e {
        Errno::NOTTY | Errno::OPNOTSUPP => EnableVerityError::FilesystemNotSupported,
        Errno::EXIST => EnableVerityError::AlreadyEnabled,
        Errno::TXTBSY => EnableVerityError::FileOpenedForWrite,
        Errno::KEYREJECTED | Errno::BADMSG => EnableVerityError::SignatureVerificationFailed,
        Errno::NOKEY => EnableVerityError::SigningKeyNotFound,
        e => Error::from(e).into(),
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

/// Metadata type identifier for the builtin PKCS#7 signature, as passed to
/// `FS_IOC_READ_VERITY_METADATA` in `fsverity_read_metadata_arg::metadata_type`.
///
/// See `FS_VERITY_METADATA_TYPE_SIGNATURE` in `/usr/include/linux/fsverity.h`.
const FS_VERITY_METADATA_TYPE_SIGNATURE: u64 = 3;

// See /usr/include/linux/fsverity.h
#[repr(C)]
#[derive(Debug)]
struct FsVerityReadMetadataArg {
    metadata_type: u64,
    offset: u64,
    length: u64,
    buf_ptr: u64,
    __reserved: u64,
}

// #define FS_IOC_READ_VERITY_METADATA _IOWR('f', 135, struct fsverity_read_metadata_arg)
const FS_IOC_READ_VERITY_METADATA: Opcode =
    opcode::read_write::<FsVerityReadMetadataArg>(b'f', 135);

/// Check whether a file has a kernel-enrolled fs-verity builtin signature.
///
/// This is a thin safe wrapper around `FS_IOC_READ_VERITY_METADATA` with
/// `FS_VERITY_METADATA_TYPE_SIGNATURE`, used only to answer a yes/no
/// question about signature *presence* -- it does not return the signature
/// bytes themselves. See `fs_ioc_enable_verity_with_sig` for enrolling one.
///
/// # Arguments
/// * `fd` - File descriptor to query (fs-verity must already be enabled on it,
///   though the descriptor doesn't need to be opened `O_RDONLY`).
///
/// # Returns
/// * `Ok(true)` if a signature was enrolled with `FS_IOC_ENABLE_VERITY`.
/// * `Ok(false)` if fs-verity is enabled but no signature was enrolled
///   (kernel reports `ENODATA`).
/// * `Err` for any other ioctl failure, e.g. fs-verity not enabled on the
///   file or not supported by the filesystem.
pub fn fs_ioc_has_verity_signature(fd: impl AsFd) -> std::io::Result<bool> {
    // We only care whether a signature is present, not its contents, so a
    // one-byte buffer is enough: any successful read means a signature is
    // enrolled (a real PKCS#7 signature is never zero-length).
    let mut buf = [0u8; 1];
    let mut arg = FsVerityReadMetadataArg {
        metadata_type: FS_VERITY_METADATA_TYPE_SIGNATURE,
        offset: 0,
        length: buf.len() as u64,
        buf_ptr: buf.as_mut_ptr() as u64,
        __reserved: 0,
    };

    let r = unsafe {
        ioctl(
            fd,
            Updater::<{ FS_IOC_READ_VERITY_METADATA }, FsVerityReadMetadataArg>::new(&mut arg),
        )
    };

    match r {
        Ok(()) => Ok(true),
        Err(Errno::NODATA) => Ok(false),
        Err(e) => Err(Error::from(e)),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

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

    #[test]
    fn test_measure_verity_missing() {
        let mut tf = test_tempfile();
        tf.write_all(b"test").unwrap();
        tf.sync_all().unwrap();

        // Re-open read-only
        let path = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&tf));
        let ro_fd =
            rustix::fs::open(&path, rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty()).unwrap();

        assert!(matches!(
            fs_ioc_measure_verity::<32>(&ro_fd, 1),
            Err(MeasureVerityError::VerityMissing)
        ));
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
        let err = fs_ioc_enable_verity(&file, 1, 4096).unwrap_err();
        assert!(matches!(err, EnableVerityError::FilesystemNotSupported));
    }

    // `FS_IOC_ENABLE_VERITY` signature-related errnos (`ENOKEY`,
    // `EKEYREJECTED`, `EBADMSG`) can't reliably be triggered in a test
    // sandbox: they require a kernel built with
    // `CONFIG_FS_VERITY_BUILTIN_SIGNATURES` and a real PKCS#7 signature.
    // Test the errno mapping directly instead of going through the ioctl.
    #[test]
    fn test_enable_verity_errno_mapping() {
        let cases = [
            (Errno::NOTTY, "FilesystemNotSupported"),
            (Errno::OPNOTSUPP, "FilesystemNotSupported"),
            (Errno::EXIST, "AlreadyEnabled"),
            (Errno::TXTBSY, "FileOpenedForWrite"),
            (Errno::KEYREJECTED, "SignatureVerificationFailed"),
            (Errno::BADMSG, "SignatureVerificationFailed"),
            (Errno::NOKEY, "SigningKeyNotFound"),
        ];
        for (errno, expected) in cases {
            let err = enable_verity_errno_to_error(errno);
            let actual = match err {
                EnableVerityError::FilesystemNotSupported => "FilesystemNotSupported",
                EnableVerityError::AlreadyEnabled => "AlreadyEnabled",
                EnableVerityError::FileOpenedForWrite => "FileOpenedForWrite",
                EnableVerityError::SignatureVerificationFailed => "SignatureVerificationFailed",
                EnableVerityError::SigningKeyNotFound => "SigningKeyNotFound",
                EnableVerityError::Io(_) => "Io",
            };
            assert_eq!(actual, expected, "mapping for {errno:?}");
        }
    }

    // Actually enrolling a kernel signature can't be exercised in this
    // sandbox (see `test_enable_verity_errno_mapping` above), but plain
    // fs-verity enablement can, so we can at least confirm the "no
    // signature enrolled" (`ENODATA`) side of `fs_ioc_has_verity_signature`
    // against a real kernel ioctl.
    #[test]
    fn test_has_verity_signature_no_signature() {
        let mut tf = test_tempfile();
        tf.write_all(b"hello world").unwrap();
        tf.sync_all().unwrap();

        // Re-open read-only: verity can only be enabled on an fd with no
        // other writable descriptors outstanding.
        let path = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&tf));
        let ro_fd =
            rustix::fs::open(&path, rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty()).unwrap();
        drop(tf);

        fs_ioc_enable_verity(&ro_fd, 1, 4096).unwrap();

        assert!(!fs_ioc_has_verity_signature(&ro_fd).unwrap());
    }

    #[test_with::path(/dev/shm)]
    #[test]
    fn test_has_verity_signature_wrong_fs() {
        let file = tempfile_in("/dev/shm").unwrap();
        let err = fs_ioc_has_verity_signature(&file).unwrap_err();
        let raw = err.raw_os_error();
        assert!(
            raw == Some(Errno::NOTTY.raw_os_error())
                || raw == Some(Errno::OPNOTSUPP.raw_os_error()),
            "unexpected error for fs-verity-unsupported filesystem: {err}"
        );
    }
}
