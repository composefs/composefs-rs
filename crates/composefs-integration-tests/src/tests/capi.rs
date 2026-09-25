//! Privileged tests of our libcomposefs through its C API.
//!
//! They run `lcfs-mount-test` (crates/composefs-capi/tests/lcfs-mount-test.c),
//! which the test image builds against our libcomposefs, and mounts images
//! the way ostree-prepare-root does: `lcfs_mount_image()` with an object
//! directory and optionally an expected fs-verity digest.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use rustix::io::Errno;
use xshell::{Shell, cmd};

use crate::tests::privileged::{VerityTempDir, require_privileged};
use crate::{cfsctl, integration_test};

/// The C test program; overridable for running outside the test image.
fn lcfs_mount_test() -> String {
    std::env::var("LCFS_MOUNT_TEST_PATH").unwrap_or_else(|_| "lcfs-mount-test".into())
}

/// lcfs-mount.h's `EWRONGVERITY`: the image digest doesn't match.
const EWRONGVERITY: Errno = Errno::ILSEQ;
/// lcfs-mount.h's `ENOVERITY`: the image has no fs-verity digest.
const ENOVERITY: Errno = Errno::NOTTY;

/// Larger than the inline threshold, so it's stored as an external object.
const LARGE_FILE_SIZE: usize = 64 * 1024;

/// A composefs image in a verity-enabled repository, with its source tree.
struct TestImage {
    dir: VerityTempDir,
    image: PathBuf,
    digest: String,
}

impl TestImage {
    fn new(sh: &Shell) -> Result<Self> {
        let cfsctl = cfsctl()?;
        let dir = VerityTempDir::new()?;
        let repo = dir.path().join("repo");
        let rootfs = dir.path().join("rootfs");
        // create-image needs a /usr
        std::fs::create_dir_all(rootfs.join("usr/sub"))?;
        std::fs::write(rootfs.join("usr/sub/small"), "hello\n")?;
        std::fs::write(rootfs.join("usr/large"), large_content())?;

        // The C API measures images with sha256 fs-verity.
        cmd!(
            sh,
            "{cfsctl} --repo {repo} init --algorithm fsverity-sha256-12"
        )
        .run()?;
        let output = cmd!(sh, "{cfsctl} --repo {repo} create-image {rootfs}").read()?;
        let digest = output
            .trim()
            .strip_prefix("sha256:")
            .with_context(|| format!("unexpected image ID: {output}"))?
            .to_string();
        let image = repo.join("images").join(&digest);
        ensure!(image.exists(), "no image at {}", image.display());
        Ok(Self { dir, image, digest })
    }

    fn objects(&self) -> PathBuf {
        self.dir.path().join("repo/objects")
    }

    fn scratch(&self, name: &str) -> Result<PathBuf> {
        let path = self.dir.path().join(name);
        std::fs::create_dir_all(&path)?;
        Ok(path)
    }
}

fn large_content() -> Vec<u8> {
    (0..LARGE_FILE_SIZE).map(|i| (i % 251) as u8).collect()
}

/// Unmounts its mountpoint when dropped, if it's mounted, so a failed
/// assertion doesn't leave a mount behind.
struct Unmount(PathBuf);

impl Drop for Unmount {
    fn drop(&mut self) {
        let path = &self.0;
        if let Ok(sh) = Shell::new()
            && is_mounted(&sh, path)
        {
            let _ = cmd!(sh, "umount {path}").quiet().run();
        }
    }
}

/// Runs lcfs-mount-test, returning its exit status (the errno on failure)
/// and a guard that unmounts the mountpoint again.
fn mount(image: &TestImage, mountpoint: &Path, args: &[&str]) -> Result<(i32, Unmount)> {
    let guard = Unmount(mountpoint.to_path_buf());
    let status = std::process::Command::new(lcfs_mount_test())
        .args(args)
        .arg(&image.image)
        .arg(mountpoint)
        .arg(image.objects())
        .status()
        .context("running lcfs-mount-test")?;
    let code = status
        .code()
        .with_context(|| format!("lcfs-mount-test killed: {status}"))?;
    Ok((code, guard))
}

fn assert_content(mountpoint: &Path) -> Result<()> {
    assert_eq!(
        std::fs::read_to_string(mountpoint.join("usr/sub/small"))?,
        "hello\n"
    );
    assert!(std::fs::read(mountpoint.join("usr/large"))? == large_content());
    Ok(())
}

fn is_mounted(sh: &Shell, mountpoint: &Path) -> bool {
    cmd!(sh, "mountpoint -q {mountpoint}").quiet().run().is_ok()
}

fn privileged_capi_mount_image() -> Result<()> {
    if require_privileged("privileged_capi_mount_image")?.is_some() {
        return Ok(());
    }
    let sh = Shell::new()?;
    let image = TestImage::new(&sh)?;
    let mnt = image.scratch("mnt")?;

    // Without and with the image's own digest
    let digest_args = ["-d", image.digest.as_str()];
    for args in [&[][..], &digest_args] {
        let (status, mounted) = mount(&image, &mnt, args)?;
        assert_eq!(status, 0, "mount with {args:?}");
        assert_content(&mnt)?;
        drop(mounted);
        assert!(!is_mounted(&sh, &mnt));
    }
    Ok(())
}
integration_test!(privileged_capi_mount_image);

/// `expected_fsverity_digest` must be enforced: ostree-prepare-root
/// relies on it to only mount the image it expects.
fn privileged_capi_mount_wrong_digest() -> Result<()> {
    if require_privileged("privileged_capi_mount_wrong_digest")?.is_some() {
        return Ok(());
    }
    let sh = Shell::new()?;
    let image = TestImage::new(&sh)?;
    let mnt = image.scratch("mnt")?;

    // Flip the last hex digit.
    let mut wrong = image.digest.clone();
    let last = wrong.pop().context("empty digest")?;
    wrong.push(if last == '0' { '1' } else { '0' });

    let plus_digest = format!("+{}", &image.digest[1..]);

    // (digest, errno), as the C library reports them
    let cases = [
        (wrong.as_str(), EWRONGVERITY),
        ("not-hex", Errno::INVAL),
        (&image.digest[..10], EWRONGVERITY),
        // Rejected like any other non-hex digit, as in C
        (&plus_digest, Errno::INVAL),
    ];
    for (digest, errno) in cases {
        // Keep the guard until after the check, so it can't hide a mount.
        let (status, _mounted) = mount(&image, &mnt, &["-d", digest])?;
        assert_eq!(status, errno.raw_os_error(), "digest {digest}");
        assert!(
            !is_mounted(&sh, &mnt),
            "{} mounted with digest {digest}",
            mnt.display()
        );
    }
    Ok(())
}
integration_test!(privileged_capi_mount_wrong_digest);

/// An image without fs-verity can't match an expected digest.
fn privileged_capi_mount_digest_without_verity() -> Result<()> {
    if require_privileged("privileged_capi_mount_digest_without_verity")?.is_some() {
        return Ok(());
    }
    let sh = Shell::new()?;
    let mut image = TestImage::new(&sh)?;
    let mnt = image.scratch("mnt")?;
    let copy = image.dir.path().join("image-copy");
    std::fs::copy(&image.image, &copy)?;
    image.image = copy;

    let digest = image.digest.clone();
    let (status, _mounted) = mount(&image, &mnt, &["-d", &digest])?;
    assert_eq!(status, ENOVERITY.raw_os_error());
    assert!(!is_mounted(&sh, &mnt));
    Ok(())
}
integration_test!(privileged_capi_mount_digest_without_verity);

/// upperdir/workdir give a writable mount unless READONLY is set, as in C.
fn privileged_capi_mount_upperdir() -> Result<()> {
    if require_privileged("privileged_capi_mount_upperdir")?.is_some() {
        return Ok(());
    }
    let sh = Shell::new()?;
    let image = TestImage::new(&sh)?;
    let mnt = image.scratch("mnt")?;
    let upper = image.scratch("upper")?;
    let work = image.scratch("work")?;
    let (upper_arg, work_arg) = (
        upper.to_str().context("non-UTF-8 path")?,
        work.to_str().context("non-UTF-8 path")?,
    );
    let overlay_args = ["-u", upper_arg, "-w", work_arg];

    let (status, mounted) = mount(&image, &mnt, &overlay_args)?;
    assert_eq!(status, 0);
    assert_content(&mnt)?;
    std::fs::write(mnt.join("new"), "written\n")?;
    drop(mounted);
    assert_eq!(std::fs::read_to_string(upper.join("new"))?, "written\n");

    let (status, mounted) = mount(&image, &mnt, &[&overlay_args[..], &["-r"]].concat())?;
    assert_eq!(status, 0);
    assert_content(&mnt)?;
    let err = std::fs::write(mnt.join("readonly"), "x").expect_err("READONLY mount is writable");
    assert_eq!(err.raw_os_error(), Some(Errno::ROFS.raw_os_error()));
    drop(mounted);

    // Only one of them is invalid.
    let (status, _mounted) = mount(&image, &mnt, &["-u", upper_arg])?;
    assert_eq!(status, Errno::INVAL.raw_os_error());
    assert!(!is_mounted(&sh, &mnt));
    Ok(())
}
integration_test!(privileged_capi_mount_upperdir);
