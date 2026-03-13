//! Privileged integration tests requiring root and fs-verity support.
//!
//! These tests run `cfsctl` without `--insecure` on a real ext4 filesystem
//! with the verity feature enabled. They need root to create loop mounts.
//!
//! When run on the host (not as root), each test automatically re-executes
//! itself inside a bcvk ephemeral VM where it has real root and kernel
//! fs-verity support. The `COMPOSEFS_IN_VM` env var prevents infinite
//! recursion — see [`require_privileged`].
//!
//! Some tests additionally require `CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y`,
//! which is available on Debian/Ubuntu kernels but not on CentOS/Fedora.
//! These are gated with [`require_fsverity_builtin_signatures`] — a kernel
//! capability check that legitimately skips on unsupported kernels.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail, ensure};
use xshell::{Shell, cmd};

use crate::{cfsctl, create_oci_layout, integration_test};

/// Ensure we're running in a privileged environment, or re-exec this test inside a VM.
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
///
/// This is also used by cstor tests which need user namespace support
/// (via `podman unshare`) that may not be available on GHA runners.
pub fn require_privileged(test_name: &str) -> Result<Option<()>> {
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

/// Check if user namespaces work (needed for podman unshare).
fn userns_works() -> bool {
    std::process::Command::new("podman")
        .args(["unshare", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Ensure user namespace support is available, or re-exec this test inside a VM.
///
/// Unlike `require_privileged`, this doesn't require root — it just needs
/// working user namespaces (for `podman unshare`). If user namespaces work,
/// the test proceeds normally. Otherwise, it dispatches to a VM.
///
/// Returns `Ok(None)` if the test should proceed, `Ok(Some(()))` if it was
/// dispatched to a VM and the caller should return immediately.
pub fn require_userns(test_name: &str) -> Result<Option<()>> {
    // If we're root (e.g. in VM), userns works
    if rustix::process::getuid().is_root() {
        return Ok(None);
    }

    // Check if userns works on this host
    if userns_works() {
        return Ok(None);
    }

    // userns doesn't work — delegate to a VM
    if std::env::var_os("COMPOSEFS_IN_VM").is_some() {
        bail!("COMPOSEFS_IN_VM is set but userns doesn't work — VM setup is broken");
    }

    let image = std::env::var("COMPOSEFS_TEST_IMAGE").map_err(|_| {
        anyhow::anyhow!(
            "user namespaces not available and COMPOSEFS_TEST_IMAGE not set; \
             run `just build-test-image` or use `just test-integration-vm`"
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

/// Check whether the kernel supports `CONFIG_FS_VERITY_BUILTIN_SIGNATURES`.
///
/// Returns `true` if the feature is available and the test should proceed.
/// Returns `false` and prints a skip message if the kernel doesn't support it.
///
/// This is a legitimate kernel capability check — CentOS/Fedora kernels don't
/// enable this feature, so tests gated on it can only run on Debian/Ubuntu.
fn require_fsverity_builtin_signatures() -> bool {
    if crate::has_fsverity_builtin_signatures() {
        return true;
    }
    // This is a kernel capability, not a missing dependency.
    // CentOS/Fedora kernels don't enable CONFIG_FS_VERITY_BUILTIN_SIGNATURES.
    // These tests only run on Debian/Ubuntu where it's enabled.
    eprintln!("SKIP (kernel capability): CONFIG_FS_VERITY_BUILTIN_SIGNATURES not enabled");
    false
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

// ---------------------------------------------------------------------------
// OCI signing tests with real fs-verity enforcement
// ---------------------------------------------------------------------------

/// Generate a self-signed X.509 certificate and private key for testing.
fn generate_test_cert(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let sh = Shell::new()?;
    let key_path = dir.join("test-key.pem");
    let cert_path = dir.join("test-cert.pem");
    cmd!(
        sh,
        "openssl req -x509 -newkey rsa:2048 -keyout {key_path} -out {cert_path} -days 1 -nodes -subj /CN=test-ca"
    )
    .run()?;
    Ok((cert_path, key_path))
}

/// Pull a local OCI layout into a verity-enabled repo (no `--insecure`).
fn pull_oci_image_verity(
    sh: &Shell,
    cfsctl: &Path,
    repo: &Path,
    oci_layout: &Path,
    tag_name: &str,
) -> Result<String> {
    let output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci pull oci:{oci_layout} {tag_name}"
    )
    .read()?;
    Ok(output)
}

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

/// Sign, then verify an OCI image on a verity-enabled filesystem.
///
/// This exercises the full signing pipeline with real fs-verity enforcement:
/// pull into a verity repo, generate a cert, sign, and verify.
fn privileged_sign_and_verify_with_verity() -> Result<()> {
    if require_privileged("privileged_sign_and_verify_with_verity")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");

    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    pull_oci_image_verity(&sh, &cfsctl, &repo, &oci_layout, "test-image")?;

    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    let sign_output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;
    ensure!(
        sign_output.contains("sha256:"),
        "expected artifact digest in sign output, got: {sign_output}"
    );

    let verify_output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci verify test-image --cert {cert}"
    )
    .read()?;
    ensure!(
        verify_output.contains("verified"),
        "expected verification success, got: {verify_output}"
    );

    Ok(())
}
integration_test!(privileged_sign_and_verify_with_verity);

/// Seal an OCI image, then sign and verify it on a verity-enabled filesystem.
///
/// Sealing embeds the composefs verity digest into the manifest. This test
/// confirms that signing still works correctly on a sealed image.
fn privileged_seal_then_sign() -> Result<()> {
    if require_privileged("privileged_seal_then_sign")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");

    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    pull_oci_image_verity(&sh, &cfsctl, &repo, &oci_layout, "test-image")?;

    // Seal the image first
    let seal_output = cmd!(sh, "{cfsctl} --repo {repo} oci seal test-image").read()?;
    ensure!(
        !seal_output.trim().is_empty(),
        "expected seal output with config/verity digests, got nothing"
    );

    // Then sign the sealed image
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    let sign_output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;
    ensure!(
        sign_output.contains("sha256:"),
        "expected artifact digest in sign output, got: {sign_output}"
    );

    // Verify the sealed+signed image
    let verify_output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci verify test-image --cert {cert}"
    )
    .read()?;
    ensure!(
        verify_output.contains("verified"),
        "expected verification success on sealed image, got: {verify_output}"
    );

    Ok(())
}
integration_test!(privileged_seal_then_sign);

/// Inject a test certificate into the kernel's `.fs-verity` keyring.
///
/// This modifies kernel state and must run in an ephemeral VM to avoid
/// polluting the host keyring. Requires `CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y`.
fn privileged_keyring_add_cert() -> Result<()> {
    if require_privileged("privileged_keyring_add_cert")?.is_some() {
        return Ok(());
    }

    if !require_fsverity_builtin_signatures() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;

    let cert_dir = tempfile::tempdir()?;
    let (cert, _key) = generate_test_cert(cert_dir.path())?;

    let output = cmd!(sh, "{cfsctl} keyring add-cert {cert}").read()?;
    ensure!(
        output.contains("Certificate added"),
        "expected 'Certificate added' confirmation, got: {output}"
    );

    Ok(())
}
integration_test!(privileged_keyring_add_cert);

/// Inject a cert into the kernel keyring, then sign and verify an OCI image
/// on a verity-enabled filesystem.
///
/// This exercises the full kernel-level signature enforcement pipeline:
/// cert injection into `.fs-verity` keyring, pull with real verity, sign,
/// and verify. Requires `CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y`.
fn privileged_keyring_and_verify_with_verity() -> Result<()> {
    if require_privileged("privileged_keyring_and_verify_with_verity")?.is_some() {
        return Ok(());
    }

    if !require_fsverity_builtin_signatures() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");
    let fixture_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(fixture_dir.path())?;

    // Inject cert into kernel's .fs-verity keyring
    let add_output = cmd!(sh, "{cfsctl} keyring add-cert {cert}").read()?;
    ensure!(
        add_output.contains("Certificate added"),
        "keyring add-cert failed: {add_output}"
    );

    // Pull an image with real verity (no --insecure)
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    pull_oci_image_verity(&sh, &cfsctl, &repo, &oci_layout, "test-image")?;

    // Sign the image
    let sign_output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;
    ensure!(
        sign_output.contains("sha256:"),
        "expected artifact digest in sign output, got: {sign_output}"
    );

    // Verify the image with the cert
    let verify_output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci verify test-image --cert {cert}"
    )
    .read()?;
    ensure!(
        verify_output.contains("verified"),
        "expected verification success, got: {verify_output}"
    );

    Ok(())
}
integration_test!(privileged_keyring_and_verify_with_verity);

// ---------------------------------------------------------------------------
// Kernel-level fsverity signature enforcement tests
//
// These tests exercise the kernel's require_signatures sysctl, which forces
// all FS_IOC_ENABLE_VERITY calls to include a valid PKCS#7 signature whose
// cert is in the `.fs-verity` keyring. They only work on kernels with
// CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y (Debian/Ubuntu).
// ---------------------------------------------------------------------------

const REQUIRE_SIGNATURES_PATH: &str = "/proc/sys/fs/verity/require_signatures";

/// RAII guard that restores `require_signatures` to 0 on drop.
///
/// Kernel-level signature enforcement affects ALL verity operations system-wide,
/// so we must restore it even if a test panics — otherwise subsequent tests in
/// the same VM would be broken.
struct RequireSignaturesGuard;

impl RequireSignaturesGuard {
    fn enable() -> Result<Self> {
        std::fs::write(REQUIRE_SIGNATURES_PATH, "1")?;
        Ok(Self)
    }
}

impl Drop for RequireSignaturesGuard {
    fn drop(&mut self) {
        let _ = std::fs::write(REQUIRE_SIGNATURES_PATH, "0");
    }
}

/// Test that the kernel rejects enabling fsverity without a signature when
/// `require_signatures` is enabled.
fn privileged_kernel_rejects_unsigned_verity() -> Result<()> {
    if require_privileged("privileged_kernel_rejects_unsigned_verity")?.is_some() {
        return Ok(());
    }
    if !require_fsverity_builtin_signatures() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;

    // Generate and inject a cert so the keyring is populated
    let cert_dir = tempfile::tempdir()?;
    let (cert, _key) = generate_test_cert(cert_dir.path())?;
    cmd!(sh, "{cfsctl} keyring add-cert {cert}").run()?;

    // Enable require_signatures — guard restores to 0 on drop
    let _guard = RequireSignaturesGuard::enable()?;

    // Write a test file on the verity-capable filesystem
    let test_file = verity_dir.path().join("testfile");
    std::fs::write(&test_file, "test content for unsigned verity\n")?;

    // Try to enable fsverity without a signature using the fsverity CLI
    let result = cmd!(sh, "fsverity enable {test_file}").run();

    ensure!(
        result.is_err(),
        "expected fsverity enable WITHOUT signature to fail when require_signatures=1, \
         but it succeeded"
    );

    Ok(())
}
integration_test!(privileged_kernel_rejects_unsigned_verity);

/// Test that the kernel rejects a fsverity signature made with a key whose
/// certificate is NOT in the kernel's `.fs-verity` keyring.
fn privileged_kernel_rejects_wrong_signature() -> Result<()> {
    if require_privileged("privileged_kernel_rejects_wrong_signature")?.is_some() {
        return Ok(());
    }
    if !require_fsverity_builtin_signatures() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;

    // Generate two certs — only inject cert_a into the kernel keyring
    let cert_dir_a = tempfile::tempdir()?;
    let (cert_a, _key_a) = generate_test_cert(cert_dir_a.path())?;

    let cert_dir_b = tempfile::tempdir()?;
    let (cert_b, key_b) = generate_test_cert(cert_dir_b.path())?;

    cmd!(sh, "{cfsctl} keyring add-cert {cert_a}").run()?;

    let _guard = RequireSignaturesGuard::enable()?;

    // Write a test file
    let test_file = verity_dir.path().join("testfile");
    std::fs::write(&test_file, "test content for wrong signature\n")?;

    // Sign the file's verity digest with key_b (whose cert is NOT in the keyring)
    let sig_file = verity_dir.path().join("wrong.sig");
    cmd!(
        sh,
        "fsverity sign {test_file} {sig_file} --key {key_b} --cert {cert_b}"
    )
    .run()?;

    // Try to enable verity with the wrong signature — kernel should reject
    let result = cmd!(sh, "fsverity enable {test_file} --signature {sig_file}").run();

    ensure!(
        result.is_err(),
        "expected fsverity enable with WRONG cert's signature to fail, but it succeeded"
    );

    Ok(())
}
integration_test!(privileged_kernel_rejects_wrong_signature);

/// Test the positive case: kernel accepts a fsverity signature made with a
/// key whose certificate IS in the `.fs-verity` keyring.
fn privileged_kernel_accepts_valid_signature() -> Result<()> {
    if require_privileged("privileged_kernel_accepts_valid_signature")?.is_some() {
        return Ok(());
    }
    if !require_fsverity_builtin_signatures() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;

    // Generate cert and inject into kernel keyring
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;
    cmd!(sh, "{cfsctl} keyring add-cert {cert}").run()?;

    let _guard = RequireSignaturesGuard::enable()?;

    // Write a test file
    let test_file = verity_dir.path().join("testfile");
    std::fs::write(&test_file, "test content for valid signature\n")?;

    // Sign the file with the trusted key
    let sig_file = verity_dir.path().join("valid.sig");
    cmd!(
        sh,
        "fsverity sign {test_file} {sig_file} --key {key} --cert {cert}"
    )
    .run()?;

    // Enable verity with the valid signature — should succeed
    cmd!(sh, "fsverity enable {test_file} --signature {sig_file}").run()?;

    // Verify the file now has a measurable verity digest
    let digest_output = cmd!(sh, "fsverity measure {test_file}").read()?;
    ensure!(
        !digest_output.trim().is_empty(),
        "expected fsverity measure to return a digest after enabling verity"
    );
    ensure!(
        digest_output.contains("sha256:"),
        "expected sha256 digest in fsverity measure output, got: {digest_output}"
    );

    Ok(())
}
integration_test!(privileged_kernel_accepts_valid_signature);
