//! Privileged integration tests requiring root and fs-verity support.
//!
//! These tests run `cfsctl` without `--insecure` on a real ext4 filesystem
//! with the verity feature enabled. They need root to create loop mounts.
//!
//! When run on the host (not as root), each test automatically re-executes
//! itself inside a bcvk ephemeral VM where it has real root and kernel
//! fs-verity support. The `COMPOSEFS_IN_VM` env var prevents infinite
//! recursion — see [`require_privileged`].

use std::path::{Path, PathBuf};

use anyhow::{Result, bail, ensure};
use xshell::{Shell, cmd};

use crate::{cfsctl, integration_test};

/// Ensure we're running as root, or re-exec this test inside a VM.
///
/// If already root (e.g. inside a bcvk VM), returns `Ok(None)` and the
/// test proceeds normally.
///
/// If not root and `COMPOSEFS_TEST_IMAGE` is set, spawns
/// `bcvk ephemeral run-ssh <image> -- cfsctl-integration-tests --exact <test>`
/// and returns `Ok(Some(()))` — the caller should return immediately since
/// the test already ran in the VM.
///
/// If not root and no test image is configured, returns an error.
fn require_privileged(test_name: &str) -> Result<Option<()>> {
    if rustix::process::getuid().is_root() {
        return Ok(None);
    }

    // We're on the host without root — delegate to a VM.
    if std::env::var_os("COMPOSEFS_IN_VM").is_some() {
        bail!("COMPOSEFS_IN_VM is set but we're not root — VM setup is broken");
    }

    let image = std::env::var("COMPOSEFS_TEST_IMAGE").map_err(|_| {
        anyhow::anyhow!(
            "not root and COMPOSEFS_TEST_IMAGE not set; \
             run `just test-integration-vm` to build the image and run all tests"
        )
    })?;

    let sh = Shell::new()?;
    let bcvk = std::env::var("BCVK_PATH").unwrap_or_else(|_| "bcvk".into());
    cmd!(
        sh,
        "{bcvk} ephemeral run-ssh {image} -- cfsctl-integration-tests --exact {test_name}"
    )
    .run()?;
    Ok(Some(()))
}

/// A temporary directory backed by a loopback ext4 filesystem with verity support.
///
/// tmpfs doesn't support fs-verity, so privileged tests that need verity
/// (i.e. running cfsctl without `--insecure`) must use a real filesystem.
/// This creates a sparse file, formats it as ext4 with the verity feature,
/// and loop-mounts it to a temp directory.
struct VerityTempDir {
    mountpoint: PathBuf,
    _backing: tempfile::TempDir,
}

impl VerityTempDir {
    fn new() -> Result<Self> {
        let backing = tempfile::tempdir()?;
        let img = backing.path().join("fs.img");
        let mountpoint = backing.path().join("mnt");
        std::fs::create_dir(&mountpoint)?;

        let sh = Shell::new()?;
        cmd!(sh, "truncate -s 256M {img}").run()?;
        cmd!(sh, "mkfs.ext4 -q -O verity -b 4096 {img}").run()?;
        cmd!(sh, "mount -o loop {img} {mountpoint}").run()?;

        // Create a repo subdirectory (cfsctl needs it to exist)
        std::fs::create_dir(mountpoint.join("repo"))?;

        Ok(Self {
            mountpoint,
            _backing: backing,
        })
    }

    fn path(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for VerityTempDir {
    fn drop(&mut self) {
        let _ = std::process::Command::new("umount")
            .arg(&self.mountpoint)
            .status();
    }
}

fn privileged_check_root() -> Result<()> {
    if require_privileged("privileged_check_root")?.is_some() {
        return Ok(());
    }
    Ok(())
}
integration_test!(privileged_check_root);

fn privileged_repo_without_insecure() -> Result<()> {
    if require_privileged("privileged_repo_without_insecure")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");

    // Init on ext4+verity: meta.json gets verity enabled → secure repo
    cmd!(sh, "{cfsctl} --repo {repo} init").run()?;

    let output = cmd!(sh, "{cfsctl} --repo {repo} gc").read()?;
    ensure!(
        output.contains("Objects: 0 removed"),
        "gc on fresh repo failed: {output}"
    );
    Ok(())
}
integration_test!(privileged_repo_without_insecure);

/// Build a bootable test OCI image, mount it via `cfsctl oci mount` (plain
/// and `--bootable`), and verify the filesystem content differs correctly.
/// The plain mount should contain /boot/EFI/Linux/test-6.1.0.efi (the UKI),
/// while the bootable mount should have an empty /boot (transform_for_boot
/// clears it) but still have /usr content intact.
fn privileged_oci_bootable_mount() -> Result<()> {
    if require_privileged("privileged_oci_bootable_mount")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo_path = verity_dir.path().join("repo");
    let repo_arg = repo_path.to_str().unwrap();
    let hash = "sha256";

    composefs_oci::test_util::create_test_bootable_oci_image(&repo_path, "boot-test:v1")?;

    let inspect_output = cmd!(
        sh,
        "{cfsctl} --insecure --hash {hash} --repo {repo_arg} oci inspect boot-test:v1"
    )
    .read()?;
    let inspect: serde_json::Value = serde_json::from_str(&inspect_output)?;
    ensure!(
        inspect.get("composefs_erofs").is_some(),
        "inspect should show composefs_erofs field"
    );
    ensure!(
        inspect.get("composefs_boot_erofs").is_some(),
        "inspect should show composefs_boot_erofs field"
    );

    // Plain mount: full filesystem including /boot
    let mountpoint1 = tempfile::tempdir()?;
    let mp1 = mountpoint1.path().to_str().unwrap();
    cmd!(
        sh,
        "{cfsctl} --insecure --hash {hash} --repo {repo_arg} oci mount boot-test:v1 {mp1}"
    )
    .run()?;

    ensure!(
        mountpoint1
            .path()
            .join("boot/EFI/Linux/test-6.1.0.efi")
            .exists(),
        "plain mount should contain UKI at /boot/EFI/Linux/test-6.1.0.efi"
    );

    cmd!(sh, "umount {mp1}").run()?;

    // Bootable mount: /boot empty, /usr intact
    let mountpoint2 = tempfile::tempdir()?;
    let mp2 = mountpoint2.path().to_str().unwrap();
    cmd!(
        sh,
        "{cfsctl} --insecure --hash {hash} --repo {repo_arg} oci mount --bootable boot-test:v1 {mp2}"
    )
    .run()?;

    let boot_dir = mountpoint2.path().join("boot");
    ensure!(
        boot_dir.is_dir(),
        "bootable mount should have /boot directory"
    );
    let boot_entries: Vec<_> = std::fs::read_dir(&boot_dir)?.collect();
    ensure!(
        boot_entries.is_empty(),
        "bootable mount /boot should be empty, found {} entries",
        boot_entries.len()
    );

    ensure!(
        !mountpoint2
            .path()
            .join("boot/EFI/Linux/test-6.1.0.efi")
            .exists(),
        "bootable mount should NOT contain UKI"
    );

    ensure!(
        mountpoint2
            .path()
            .join("usr/lib/modules/6.1.0/vmlinuz")
            .exists(),
        "bootable mount should still have kernel at /usr/lib/modules/6.1.0/vmlinuz"
    );

    let os_release = std::fs::read_to_string(mountpoint2.path().join("etc/os-release"))?;
    ensure!(
        os_release.contains("ID=test"),
        "bootable mount os-release missing ID=test: {os_release:?}"
    );

    cmd!(sh, "umount {mp2}").run()?;

    Ok(())
}
integration_test!(privileged_oci_bootable_mount);

/// Build a test OCI image, mount it via `cfsctl oci mount`, and verify
/// the filesystem content. Uses the library only for image creation (test
/// setup); all verification goes through the CLI.
fn privileged_oci_pull_mount() -> Result<()> {
    if require_privileged("privileged_oci_pull_mount")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo_path = verity_dir.path().join("repo");
    let repo_arg = repo_path.to_str().unwrap();

    // Create a test OCI image with EROFS linked (library used only for setup)
    composefs_oci::test_util::create_test_oci_image(&repo_path, "mount-test:v1")?;

    // test_util creates SHA-256 repos; tell cfsctl to match
    let hash = "sha256";

    // Verify inspect shows the EROFS ref
    let inspect_output = cmd!(
        sh,
        "{cfsctl} --insecure --hash {hash} --repo {repo_arg} oci inspect mount-test:v1"
    )
    .read()?;
    let inspect: serde_json::Value = serde_json::from_str(&inspect_output)?;
    ensure!(
        inspect.get("composefs_erofs").is_some(),
        "inspect should show composefs_erofs field"
    );

    // Mount via cfsctl oci mount
    let mountpoint = tempfile::tempdir()?;
    let mp = mountpoint.path().to_str().unwrap();
    cmd!(
        sh,
        "{cfsctl} --insecure --hash {hash} --repo {repo_arg} oci mount mount-test:v1 {mp}"
    )
    .run()?;

    // Verify file content at the mountpoint
    let hostname = std::fs::read_to_string(mountpoint.path().join("etc/hostname"))?;
    ensure!(hostname == "testhost\n", "hostname mismatch: {hostname:?}");

    let os_release = std::fs::read_to_string(mountpoint.path().join("etc/os-release"))?;
    ensure!(
        os_release.contains("ID=test"),
        "os-release missing ID: {os_release:?}"
    );

    let busybox = std::fs::read(mountpoint.path().join("usr/bin/busybox"))?;
    ensure!(
        busybox == b"busybox-binary-content",
        "busybox content mismatch"
    );

    let sh_target = std::fs::read_link(mountpoint.path().join("usr/bin/sh"))?;
    ensure!(
        sh_target.to_str() == Some("busybox"),
        "sh symlink target mismatch: {sh_target:?}"
    );

    let app_data = std::fs::read_to_string(mountpoint.path().join("usr/share/myapp/data.txt"))?;
    ensure!(
        app_data == "application-data",
        "app data mismatch: {app_data:?}"
    );

    ensure!(mountpoint.path().join("tmp").is_dir(), "/tmp missing");
    ensure!(mountpoint.path().join("var").is_dir(), "/var missing");
    ensure!(
        mountpoint.path().join("usr/lib").is_dir(),
        "/usr/lib missing"
    );

    Ok(())
}
integration_test!(privileged_oci_pull_mount);

/// Verify that `init` on a verity-capable filesystem enables verity on
/// meta.json, and that `--require-verity` succeeds on such a repo.
fn privileged_init_enables_verity() -> Result<()> {
    if require_privileged("privileged_init_enables_verity")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");

    let output = cmd!(sh, "{cfsctl} --repo {repo} init").read()?;
    ensure!(
        output.contains("verity") && output.contains("required"),
        "init should report verity as required, got: {output}"
    );

    // --require-verity should succeed on this repo
    let output = cmd!(sh, "{cfsctl} --require-verity --repo {repo} gc").read()?;
    ensure!(
        output.contains("Objects: 0 removed"),
        "--require-verity gc should work on secure repo, got: {output}"
    );

    Ok(())
}
integration_test!(privileged_init_enables_verity);

/// Verify that `init --insecure` on a verity-capable filesystem does NOT
/// enable verity on meta.json, and `--require-verity` fails.
fn privileged_init_insecure_skips_verity() -> Result<()> {
    if require_privileged("privileged_init_insecure_skips_verity")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");

    let output = cmd!(sh, "{cfsctl} --repo {repo} init --insecure").read()?;
    ensure!(
        output.contains("insecure"),
        "init --insecure should say insecure, got: {output}"
    );

    // --require-verity should fail even though the filesystem supports verity,
    // because init --insecure skipped enabling it on meta.json
    let result = cmd!(sh, "{cfsctl} --require-verity --repo {repo} gc").read();
    ensure!(
        result.is_err(),
        "--require-verity should fail on insecure-initialized repo"
    );

    // But operations without --require-verity should work fine
    let output = cmd!(sh, "{cfsctl} --repo {repo} gc").read()?;
    ensure!(
        output.contains("Objects: 0 removed"),
        "gc should work on insecure repo, got: {output}"
    );

    Ok(())
}
integration_test!(privileged_init_insecure_skips_verity);

/// Verify that `oci pull` into a read-only bind-mounted repository fails
/// immediately with a clear "not writable" error instead of a confusing
/// tar header error.
fn privileged_pull_readonly_repo() -> Result<()> {
    if require_privileged("privileged_pull_readonly_repo")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");

    cmd!(sh, "{cfsctl} --repo {repo} init").run()?;

    // Bind-mount the repo read-only over itself
    cmd!(sh, "mount --bind {repo} {repo}").run()?;
    cmd!(sh, "mount -o remount,ro,bind {repo}").run()?;

    // Use a bogus oci: reference — the writable check fires before any
    // image processing so the source doesn't matter.
    let output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci pull oci:/nonexistent ignored"
    )
    .ignore_status()
    .output()?;

    // Clean up the bind mount before asserting
    cmd!(sh, "umount {repo}").run()?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");

    ensure!(
        !output.status.success(),
        "pull into read-only repo should fail"
    );
    ensure!(
        combined.contains("not writable") || combined.contains("Read-only file system"),
        "expected writable or EROFS error, got: {combined}"
    );
    ensure!(
        !combined.contains("header error") && !combined.contains("invalid octal"),
        "should NOT produce misleading tar header errors, got: {combined}"
    );

    Ok(())
}
integration_test!(privileged_pull_readonly_repo);
