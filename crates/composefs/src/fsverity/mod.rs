//! Linux fs-verity support for integrity verification.
//!
//! This module provides complete fs-verity functionality including userspace
//! digest computation, kernel ioctl interfaces for enabling and measuring
//! verity, and hash value types for SHA-256 and SHA-512.

pub mod algorithm;
mod digest;
pub mod formatted_digest;
mod hashvalue;
mod ioctl;

pub use digest::FsVerityHasher;

use std::{
    fs::File,
    io::Seek,
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::fs::PermissionsExt,
    },
};

use rustix::fs::{Mode, OFlags, open, openat};
use thiserror::Error;

pub use hashvalue::{
    Algorithm, AlgorithmParseError, DEFAULT_LG_BLOCKSIZE, FsVerityHashValue, Sha256HashValue,
    Sha512HashValue,
};

// Re-export error types from composefs-ioctls
pub use ioctl::{EnableVerityError, MeasureVerityError};

use crate::util::proc_self_fd;

/// A verity comparison failed.
#[derive(Error, Debug)]
pub enum CompareVerityError {
    /// Failed to measure the fs-verity digest.
    #[error("failed to read verity")]
    Measure(#[from] MeasureVerityError),
    /// The measured digest does not match the expected digest.
    #[error("Expected digest {expected} but found {found}")]
    DigestMismatch {
        /// The expected digest as a hex string.
        expected: String,
        /// The actual digest found as a hex string.
        found: String,
    },
}

/// Compute the fs-verity digest for a given block of data, in userspace.
///
/// The fs-verity digest is a cryptographic hash over the fs-verity descriptor, which itself
/// contains the root hash of a Merkle tree with an arity determined by the chosen block size and
/// the output size of the chosen hash algorithm.
///
/// It's possible to choose the hash algorithm (via the generic parameter) but the blocksize is
/// currently hardcoded to 4096.  Salt is not supported.
///
/// See <https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#file-digest-computation>
///
/// # Arguments:
///
///  * `data`: the data to hash
pub fn compute_verity<H: FsVerityHashValue>(data: &[u8]) -> H {
    digest::FsVerityHasher::<H, 12>::hash(data)
}

/// Enable fs-verity on the given file.
///
/// This essentially boils down to the FS_IOC_ENABLE_VERITY ioctl.
///
/// The file must be stored on a filesystem which supports fs-verity.  The file descriptor must be
/// opened O_RDONLY and there must be no other writable file descriptors or mappings for the file.
///
/// It's possible to choose the hash algorithm (via the generic parameter) but the blocksize is
/// currently hardcoded to 4096.  Salt is not supported.
pub fn enable_verity_raw<H: FsVerityHashValue>(fd: impl AsFd) -> Result<(), EnableVerityError> {
    ioctl::fs_ioc_enable_verity::<H>(fd)
}

/// Enable fs-verity on the given file, optionally with a PKCS#7 signature.
///
/// Like `enable_verity_raw`, but accepts an optional DER-encoded PKCS#7 detached
/// signature over the [`formatted_digest::format_fsverity_digest`] structure. If
/// provided, the kernel will verify it against the `.fs-verity` keyring before
/// enabling verity.
///
/// # Trust Models
///
/// composefs supports two complementary signature trust models:
///
/// 1. **Application-level (OCI signature artifacts)**: PKCS#7 signatures are stored
///    in OCI artifacts alongside the image. Verification is done in userspace by the
///    composefs tooling. This is the primary model for container image signing.
///
/// 2. **Kernel-level (`.fs-verity` keyring)**: The kernel itself verifies PKCS#7
///    signatures during `FS_IOC_ENABLE_VERITY`. This requires loading a CA certificate
///    into the kernel's `.fs-verity` keyring (typically by root). When enabled, the
///    kernel rejects enabling verity on any file without a valid signature. This
///    function supports this model via the `signature` parameter.
///
/// Most deployments use model 1 (application-level). Model 2 is for high-security
/// environments where kernel-enforced signatures are required.
pub fn enable_verity_raw_with_sig<H: FsVerityHashValue>(
    fd: impl AsFd,
    signature: Option<&[u8]>,
) -> Result<(), EnableVerityError> {
    ioctl::fs_ioc_enable_verity_with_sig::<H>(fd, signature)
}

/// Enable fs-verity on the given file, retrying if file is opened for writing.
///
/// This uses `enable_verity_raw()` and is subject to the same restrictions and features.
///
/// A common pattern with fsverity files is:
///
/// * Open a read-write file descriptor
/// * Write data to the read-write file descriptor
/// * Re-open the file descriptor as a new read-only descriptor
/// * Close the read-write file descriptor
/// * Enable fsverity on the read-only file descriptor
///
/// However, in a multi-threaded program, it is possible that another
/// thread calls `fork()` while the read-write descriptor is valid,
/// thus making a copy of the read-write descriptor.  If the forked
/// process does not close the file descriptor either explicitly or by
/// calling `exec()` via O_CLOEXEC, then attempting to enable fsverity
/// on the read-only file descriptor will fail with ETXTBSY.  It is
/// generally assumed that the file descriptor will be closed rather
/// quickly under these circumstances, so this function will try to
/// enable verity three times, pausing for one millisecond between
/// attempts.
pub fn enable_verity_with_retry<H: FsVerityHashValue>(
    fd: impl AsFd,
) -> Result<(), EnableVerityError> {
    let mut attempt = 1;
    loop {
        match enable_verity_raw::<H>(&fd) {
            Err(EnableVerityError::FileOpenedForWrite) if attempt < 3 => {
                std::thread::sleep(std::time::Duration::from_millis(1));
                attempt += 1;
            }
            other => return other,
        }
    }
}

/// Enable fs-verity on the given file.  If the given file cannot be
/// enabled because it is opened as writable, then a new copy of the
/// file will be returned instead.  No attempt is made to sync the
/// copied file contents to disk, it is up to the caller to do so if
/// desired.
///
/// Take special note that in the case where a copied file descriptor
/// is returned, the returned file is created as a tempfile and is
/// unlinked.  Presumably the caller should take care to make this
/// file permanent, using a combination of `linkat` and `renameat` to
/// replace the original file.
///
/// This uses `enable_verity_raw()` and `enable_verity_with_retry()`
/// and is subject to the same restrictions.
///
/// # Arguments:
/// * `dirfd`: A directory file descriptor, used to determine the placement (via O_TMPFILE) of the new file (if necessary).
/// * `fd`: The file decriptor to enable verity on
/// # Return Value:
/// * `Ok(None)` is returned if verity was enabled on the original file
/// * `Ok(Some(OwnedFd))` is returned if a copy was made
pub fn enable_verity_maybe_copy<H: FsVerityHashValue>(
    dirfd: impl AsFd,
    fd: BorrowedFd,
) -> Result<Option<OwnedFd>, EnableVerityError> {
    match enable_verity_with_retry::<H>(&fd) {
        Ok(()) => Ok(None),
        Err(EnableVerityError::FileOpenedForWrite) => {
            let fd = enable_verity_on_copy::<H>(dirfd, fd)?;
            Ok(Some(fd))
        }
        Err(other) => Err(other),
    }
}

/// Enable fs-verity on a new copy of `fd`, consuming `fd` and
/// returning the new copy.  The copy is created via O_TMPFILE
/// relative to `dirfd`.
fn enable_verity_on_copy<H: FsVerityHashValue>(
    dirfd: impl AsFd,
    fd: BorrowedFd,
) -> Result<OwnedFd, EnableVerityError> {
    let fd = fd.try_clone_to_owned().map_err(EnableVerityError::Io)?;
    let mut fd = File::from(fd);
    let mode = fd.metadata()?.permissions().mode();

    loop {
        fd.rewind().map_err(EnableVerityError::Io)?;

        let mut new_rw_fd = File::from(
            openat(
                &dirfd,
                ".",
                OFlags::CLOEXEC | OFlags::RDWR | OFlags::TMPFILE,
                mode.into(),
            )
            .map_err(|e| EnableVerityError::Io(e.into()))?,
        );

        std::io::copy(&mut fd, &mut new_rw_fd)?;
        let new_ro_fd = open(
            proc_self_fd(&new_rw_fd),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| EnableVerityError::Io(e.into()))?;
        drop(new_rw_fd);
        if enable_verity_with_retry::<H>(&new_ro_fd).is_ok() {
            return Ok(new_ro_fd);
        }
    }
}

/// Measures fs-verity on the given file.
///
/// This essentially boils down to the FS_IOC_MEASURE_VERITY ioctl.
///
/// If the file has fs-verity enabled then the hash of the fs-verity descriptor is reported as the
/// successful return value.  In this case, the kernel guarantees that the file content cannot
/// possibly change for as long as the file descriptor exists.
///
/// If the file doesn't have fs-verity enabled then an error will be returned.
///
/// This function is generic over the hash algorithm, which means that you need to choose the
/// expected hash algorithm in advance.  If the file has fs-verity enabled, but with a different
/// hash algorithm, then this is also considered an error.
///
/// For a version of this function which returns an Option<> depending on if fs-verity is enabled
/// or not, see `measure_verity_opt()`.
///
/// Simply measuring the fs-verity value of a file is not a common operation: you usually want to
/// compare it to a value that you already know.  In that case, it's better to use the
/// `compare_verity()` function in this module.
pub fn measure_verity<H: FsVerityHashValue>(fd: impl AsFd) -> Result<H, MeasureVerityError> {
    ioctl::fs_ioc_measure_verity(fd)
}

/// Measures fs-verity on the given file.
///
/// This essentially boils down to the FS_IOC_MEASURE_VERITY ioctl.
///
/// This is the `_opt()` variant of `measure_verity()`.  If the file doesn't have fs-verity
/// enabled, or resides on a filesystem where fs-verity is unsupported, this function returns None.
/// Other errors are still passed through.
pub fn measure_verity_opt<H: FsVerityHashValue>(
    fd: impl AsFd,
) -> Result<Option<H>, MeasureVerityError> {
    match ioctl::fs_ioc_measure_verity(fd) {
        Ok(result) => Ok(Some(result)),
        Err(MeasureVerityError::VerityMissing | MeasureVerityError::FilesystemNotSupported) => {
            Ok(None)
        }
        Err(other) => Err(other),
    }
}

/// Compare the fs-verity digest of the file versus the expected digest.
///
/// This calls `measure_verity()` and verifies that the result is equal to the expected value.
///
/// If this function returns successfully then the values match.  In this case, the kernel
/// guarantees that the file content cannot possibly change for as long as the file descriptor
/// exists.
///
/// If the file doesn't have fs-verity enabled, the hash value doesn't match, or if a different
/// hash algorithm is in use, the comparison will fail.
pub fn ensure_verity_equal(
    fd: impl AsFd,
    expected: &impl FsVerityHashValue,
) -> Result<(), CompareVerityError> {
    let found = measure_verity(fd)?;
    if expected == &found {
        Ok(())
    } else {
        Err(CompareVerityError::DigestMismatch {
            expected: expected.to_hex(),
            found: found.to_hex(),
        })
    }
}

// Re-export keyring from composefs-ioctls where the unsafe code lives
pub use composefs_ioctls::keyring::{KeyringError, inject_fsverity_cert};

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, io::Write, time::Duration};

    use composefs_ioctls::test_utils_pub::CommandExt;

    use once_cell::sync::Lazy;
    use rand::RngExt;
    use rustix::{
        fd::OwnedFd,
        fs::{Mode, OFlags, open},
    };
    use tempfile::{TempDir, tempfile_in};
    use tokio::{task::JoinSet, time::Instant};

    use crate::{test::tempdir, util::proc_self_fd};

    use super::*;

    static TEMPDIR: Lazy<TempDir> = Lazy::new(tempdir);
    static TD_FD: Lazy<File> = Lazy::new(|| File::open(TEMPDIR.path()).unwrap());

    fn tempfile() -> File {
        tempfile_in(TEMPDIR.path()).unwrap()
    }

    fn rdonly_file_with(data: &[u8]) -> OwnedFd {
        let mut file = tempfile();
        file.write_all(data).unwrap();
        file.sync_data().unwrap();
        let fd = open(
            proc_self_fd(&file),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        drop(file); // can't enable verity with outstanding writable fds
        fd
    }

    fn empty_file_in_tmpdir(flags: OFlags, mode: Mode) -> (tempfile::TempDir, OwnedFd) {
        let tmpdir = tempdir();
        let path = tmpdir.path().join("empty");
        let fd = open(path, OFlags::CLOEXEC | OFlags::CREATE | flags, mode).unwrap();
        (tmpdir, fd)
    }

    #[test]
    fn test_verity_missing() {
        let tf = rdonly_file_with(b"");

        assert!(matches!(
            measure_verity::<Sha256HashValue>(&tf).unwrap_err(),
            MeasureVerityError::VerityMissing
        ));

        assert!(
            measure_verity_opt::<Sha256HashValue>(&tf)
                .unwrap()
                .is_none()
        );

        assert!(matches!(
            ensure_verity_equal(&tf, &Sha256HashValue::EMPTY).unwrap_err(),
            CompareVerityError::Measure(MeasureVerityError::VerityMissing)
        ));
    }

    #[test]
    fn test_verity_simple() {
        let tf = rdonly_file_with(b"hello world");

        // first time: success
        let tf = enable_verity_maybe_copy::<Sha256HashValue>(&*TD_FD, tf.as_fd())
            .unwrap()
            .unwrap_or(tf);

        // second time: fail with "already enabled"
        assert!(matches!(
            enable_verity_maybe_copy::<Sha256HashValue>(&*TD_FD, tf.as_fd()).unwrap_err(),
            EnableVerityError::AlreadyEnabled
        ));

        assert_eq!(
            measure_verity::<Sha256HashValue>(&tf).unwrap().to_hex(),
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64"
        );

        assert_eq!(
            measure_verity_opt::<Sha256HashValue>(&tf)
                .unwrap()
                .unwrap()
                .to_hex(),
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64"
        );

        ensure_verity_equal(
            &tf,
            &Sha256HashValue::from_hex(
                "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64",
            )
            .unwrap(),
        )
        .unwrap();

        let Err(CompareVerityError::DigestMismatch { expected, found }) = ensure_verity_equal(
            &tf,
            &Sha256HashValue::from_hex(
                "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7000000000000",
            )
            .unwrap(),
        ) else {
            panic!("Didn't fail with expected error");
        };
        assert_eq!(
            expected,
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7000000000000"
        );
        assert_eq!(
            found,
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64"
        );
    }

    #[tokio::test]
    async fn test_verity_forking() {
        const DELAY_MIN: u64 = 0;
        const DELAY_MAX: u64 = 10;
        // Break if we get 100 successes
        const SUCCESS_LIMIT: u32 = 100;
        // Don't run more than 10s by default
        const TIMEOUT: Duration = Duration::from_secs(10);
        let start = Instant::now();

        let cpus = std::thread::available_parallelism().unwrap();
        // use half of capacity for forking
        let threads = cpus.get() >> 1;
        assert!(threads >= 1);
        eprintln!("using {threads} threads");
        let mut txs = vec![];
        let mut jhs = vec![];

        for _ in 0..threads {
            let (tx, rx) = std::sync::mpsc::channel();
            let jh = std::thread::spawn(move || {
                let mut rng = rand::rng();

                loop {
                    if rx.try_recv().is_ok() {
                        break;
                    }

                    let delay = rng.random_range(DELAY_MIN..=DELAY_MAX);
                    let delay = Duration::from_millis(delay);
                    // Use the test helper from composefs-ioctls which wraps the
                    // unsafe pre_exec call
                    std::process::Command::new("true")
                        .pre_exec_sleep(delay)
                        .status()
                        .unwrap();
                }
            });

            txs.push(tx);
            jhs.push(jh);
        }

        let raw_verity_enabler = async move {
            let mut successes = 0;
            let mut failures = 0;

            loop {
                if tokio::time::Instant::now().duration_since(start) > TIMEOUT {
                    break;
                }
                if successes == SUCCESS_LIMIT {
                    break;
                }

                let r = tokio::task::spawn_blocking(move || {
                    let ro_fd = rdonly_file_with(b"hello world");
                    enable_verity_raw::<Sha256HashValue>(&ro_fd)
                })
                .await
                .unwrap();
                if r.is_ok() {
                    successes += 1;
                } else {
                    failures += 1;
                }
            }

            (successes, failures)
        };

        let retry_verity_enabler = async move {
            let mut successes = 0;
            let mut failures = 0;

            loop {
                if tokio::time::Instant::now().duration_since(start) > TIMEOUT {
                    break;
                }
                if successes == SUCCESS_LIMIT {
                    break;
                }

                let r = tokio::task::spawn_blocking(move || {
                    let ro_fd = rdonly_file_with(b"hello world");
                    enable_verity_with_retry::<Sha256HashValue>(&ro_fd)
                })
                .await
                .unwrap();
                if r.is_ok() {
                    successes += 1;
                } else {
                    failures += 1;
                }
            }

            (successes, failures)
        };

        let copy_verity_enabler = async move {
            let mut orig = 0;
            let mut copy = 0;

            loop {
                if tokio::time::Instant::now().duration_since(start) > TIMEOUT {
                    break;
                }
                if orig + copy == SUCCESS_LIMIT {
                    break;
                }

                let is_copy = tokio::task::spawn_blocking(|| {
                    let ro_fd = rdonly_file_with(b"Hello world");
                    enable_verity_maybe_copy::<Sha256HashValue>(&*TD_FD, ro_fd.as_fd())
                        .unwrap()
                        .is_some()
                })
                .await
                .unwrap();

                if is_copy {
                    copy += 1;
                } else {
                    orig += 1;
                }
            }

            (orig, copy)
        };

        let ts = tokio::time::Instant::now();

        let mut set = JoinSet::new();
        set.spawn(async move {
            let (successes, failures) = raw_verity_enabler.await;
            let elapsed = ts.elapsed().as_millis();
            eprintln!("raw verity enabled ({successes} attempts succeeded, {failures} attempts failed) in {elapsed}ms");
        });
        set.spawn(async move {
            let (successes, failures) = retry_verity_enabler.await;
            let elapsed = ts.elapsed().as_millis();
            eprintln!("retry verity enabled ({successes} attempts succeeded, {failures} attempts failed) in {elapsed}ms");
        });
        set.spawn(async move {
            let (orig, copy) = copy_verity_enabler.await;
            assert!(orig > 0 || copy > 0);
            let elapsed = ts.elapsed().as_millis();
            eprintln!("copy verity enabled ({orig} original, {copy} copies) in {elapsed}ms");
        });

        while let Some(res) = set.join_next().await {
            res.unwrap();
        }

        txs.into_iter().for_each(|tx| tx.send(()).unwrap());
        jhs.into_iter().for_each(|jh| jh.join().unwrap());
    }

    #[test_with::path(/dev/shm)]
    #[test]
    fn test_verity_error_noverity() {
        let tf = tempfile_in("/dev/shm").unwrap();

        assert!(matches!(
            enable_verity_with_retry::<Sha256HashValue>(&tf).unwrap_err(),
            EnableVerityError::FilesystemNotSupported
        ));

        assert!(matches!(
            measure_verity::<Sha256HashValue>(&tf).unwrap_err(),
            MeasureVerityError::FilesystemNotSupported
        ));

        assert!(
            measure_verity_opt::<Sha256HashValue>(&tf)
                .unwrap()
                .is_none()
        );

        assert!(matches!(
            ensure_verity_equal(&tf, &Sha256HashValue::EMPTY).unwrap_err(),
            CompareVerityError::Measure(MeasureVerityError::FilesystemNotSupported)
        ));
    }

    #[test]
    fn test_verity_wrongdigest_sha512_sha256() {
        let tf = rdonly_file_with(b"hello world");

        // Enable with SHA-512 but then try to read with SHA-256
        let tf = enable_verity_maybe_copy::<Sha512HashValue>(&*TD_FD, tf.as_fd())
            .unwrap()
            .unwrap_or(tf);

        assert!(matches!(
            measure_verity::<Sha256HashValue>(&tf).unwrap_err(),
            MeasureVerityError::InvalidDigestSize { .. }
        ));

        assert!(matches!(
            measure_verity_opt::<Sha256HashValue>(&tf).unwrap_err(),
            MeasureVerityError::InvalidDigestSize { .. }
        ));

        assert!(matches!(
            ensure_verity_equal(&tf, &Sha256HashValue::EMPTY).unwrap_err(),
            CompareVerityError::Measure(MeasureVerityError::InvalidDigestSize { .. })
        ));
    }

    #[test]
    fn test_verity_wrongdigest_sha256_sha512() {
        let tf = rdonly_file_with(b"hello world");

        // Enable with SHA-256 but then try to read with SHA-512
        let tf = enable_verity_maybe_copy::<Sha256HashValue>(&*TD_FD, tf.as_fd())
            .unwrap()
            .unwrap_or(tf);

        assert!(matches!(
            measure_verity::<Sha512HashValue>(&tf).unwrap_err(),
            MeasureVerityError::InvalidDigestAlgorithm { .. }
        ));

        assert!(matches!(
            measure_verity_opt::<Sha512HashValue>(&tf).unwrap_err(),
            MeasureVerityError::InvalidDigestAlgorithm { .. }
        ));

        assert!(matches!(
            ensure_verity_equal(&tf, &Sha512HashValue::EMPTY).unwrap_err(),
            CompareVerityError::Measure(MeasureVerityError::InvalidDigestAlgorithm { .. })
        ));
    }

    #[test]
    fn crosscheck_interesting_cases() {
        // Test the kernel against our userspace calculations.
        //
        // We try to pick some "interesting" sizes to test the edge cases.  The arity of a
        // SHA-256/4096 Merkle tree is 128 = 4096 / 32.  With SHA-512 it's 64 = 4096 / 64.
        // So we try to chose values around the page size times powers of 32 and 64.
        let mut cases = BTreeSet::new();
        for arity in [32, 64] {
            for layer4 in [/* -1, */ 0 /*, 1 */] {
                /* otherwise it's too slow */
                for layer3 in [-1, 0, 1] {
                    for layer2 in [-1, 0, 1] {
                        for layer1 in [-1, 0, 1] {
                            for layer0 in [-1, 0, 1] {
                                let candidate = layer4 * (arity * arity * arity * arity)
                                    + layer3 * (arity * arity * arity)
                                    + layer2 * (arity * arity)
                                    + layer1 * arity
                                    + layer0;
                                if let Ok(size) = usize::try_from(candidate) {
                                    cases.insert(size);
                                }
                            }
                        }
                    }
                }
            }
        }

        fn assert_kernel_equal<H: FsVerityHashValue>(data: &[u8], expected: H) {
            let fd = rdonly_file_with(data);
            let fd = enable_verity_maybe_copy::<H>(&*TD_FD, fd.as_fd())
                .unwrap()
                .unwrap_or(fd);
            ensure_verity_equal(&fd, &expected).unwrap();
        }

        for size in cases {
            // the actual data is uninteresting
            let data = vec![0x5a; size];
            assert_kernel_equal(&data, compute_verity::<Sha256HashValue>(&data));
            assert_kernel_equal(&data, compute_verity::<Sha512HashValue>(&data));
        }
    }

    #[test]
    fn test_enable_verity_maybe_copy_without_copy() {
        // Enabling verity on an empty file created without a
        // read-write file descriptor ever existing should always
        // succeed and hand us back the original file descriptor.
        let (tempdir, fd) = empty_file_in_tmpdir(OFlags::RDONLY, 0o644.into());
        let tempdir_fd = File::open(tempdir.path()).unwrap();
        let fd = enable_verity_maybe_copy::<Sha256HashValue>(&tempdir_fd, fd.as_fd()).unwrap();
        assert!(fd.is_none());
    }

    #[test]
    fn test_enable_verity_maybe_copy_with_copy() {
        // Here we intentionally try to enable verity on a read-write
        // file descriptor, which will never work directly, so we
        // expect to always get back a new copy of the requested file.
        let (tempdir, fd) = empty_file_in_tmpdir(OFlags::RDWR, 0o644.into());
        let tempdir_fd = File::open(tempdir.path()).unwrap();
        let mut fd = File::from(fd);
        let _ = fd.write(b"hello world").unwrap();
        let fd = enable_verity_maybe_copy::<Sha256HashValue>(&tempdir_fd, fd.as_fd())
            .unwrap()
            .unwrap();

        // The new fd has the correct data
        assert!(
            ensure_verity_equal(
                fd,
                &Sha256HashValue::from_hex(
                    "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64",
                )
                .unwrap(),
            )
            .is_ok()
        );
    }
}
