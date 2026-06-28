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
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use xshell::{Shell, cmd};

use composefs_oci::composefs::fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue};
use composefs_oci::composefs::repository::{Repository, RepositoryConfig};

use crate::{cfsctl, create_test_rootfs, integration_test};

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
    require_privileged_with_memory(test_name, "4G")
}

/// Like [`require_privileged`], but allows specifying VM memory size.
///
/// Tests that pull large container images inside the VM may need more
/// memory since `/var` is backed by tmpfs.
pub fn require_privileged_with_memory(test_name: &str, memory: &str) -> Result<Option<()>> {
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
        "{bcvk} ephemeral run-ssh --memory {memory} {image} -- cfsctl-integration-tests --exact {test_name}"
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
    ensure!(hostname == "test-host", "hostname mismatch: {hostname:?}");

    let os_release = std::fs::read_to_string(mountpoint.path().join("etc/os-release"))?;
    ensure!(
        os_release.contains("ID=test"),
        "os-release missing ID: {os_release:?}"
    );

    // busybox is a 4096-byte external file (random data seeded from size)
    let busybox = std::fs::read(mountpoint.path().join("usr/bin/busybox"))?;
    ensure!(
        busybox.len() == 4096,
        "busybox size mismatch: expected 4096, got {}",
        busybox.len()
    );

    let sh_target = std::fs::read_link(mountpoint.path().join("usr/bin/sh"))?;
    ensure!(
        sh_target.to_str() == Some("busybox"),
        "sh symlink target mismatch: {sh_target:?}"
    );

    // App layer has a 512-byte README (external, random data)
    let readme = std::fs::read(mountpoint.path().join("usr/share/doc/README"))?;
    ensure!(
        readme.len() == 512,
        "README size mismatch: expected 512, got {}",
        readme.len()
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

/// Test `cfsctl mount` with `--upperdir`/`--workdir`/`--read-write` flags.
///
/// Exercises three scenarios:
/// 1. Upperdir present but no `--read-write` → mount stays read-only.
/// 2. Upperdir + `--read-write` → writes land in the upper directory.
/// 3. Plain mount (no upperdir) → baseline sanity check.
fn privileged_mount_upper_layer() -> Result<()> {
    if require_privileged("privileged_mount_upper_layer")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo_path = verity_dir.path().join("repo");
    let repo_arg = repo_path.to_str().unwrap();

    cmd!(sh, "{cfsctl} --insecure --repo {repo_arg} init").run()?;

    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;
    let rootfs = rootfs.to_str().unwrap();

    // Use a named ref so we can mount via "refs/upper-test" — the bare output
    // of create-image is "algo:hex" but mount expects just the hex or a ref path.
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo_arg} create-image {rootfs} upper-test"
    )
    .run()?;
    let image_name = "refs/upper-test";

    // --- Scenario 1: upperdir without --read-write keeps the mount read-only ---
    {
        let upper1 = tempfile::tempdir()?;
        let work1 = tempfile::tempdir()?;
        let mp1 = tempfile::tempdir()?;
        let upper1_path = upper1.path().to_str().unwrap();
        let work1_path = work1.path().to_str().unwrap();
        let mp1_path = mp1.path().to_str().unwrap();

        cmd!(
            sh,
            "{cfsctl} --insecure --repo {repo_arg} mount {image_name} {mp1_path}
             --upperdir {upper1_path} --workdir {work1_path}"
        )
        .run()?;

        // The rootfs fixture has etc/hostname — verify the mount is populated.
        let hostname = std::fs::read_to_string(mp1.path().join("etc/hostname"))?;
        ensure!(
            hostname == "integration-test\n",
            "hostname mismatch in scenario 1: {hostname:?}"
        );

        // Without --read-write the mount must be read-only.
        let write_result = std::fs::write(mp1.path().join("should_fail"), b"data");
        ensure!(
            write_result.is_err(),
            "write to read-only overlayfs mount should fail"
        );

        cmd!(sh, "umount {mp1_path}").run()?;
    }

    // --- Scenario 2: upperdir + --read-write allows writes that persist in upperdir ---
    {
        let upper2 = tempfile::tempdir()?;
        let work2 = tempfile::tempdir()?;
        let mp2 = tempfile::tempdir()?;
        let upper2_path = upper2.path().to_str().unwrap();
        let work2_path = work2.path().to_str().unwrap();
        let mp2_path = mp2.path().to_str().unwrap();

        cmd!(
            sh,
            "{cfsctl} --insecure --repo {repo_arg} mount {image_name} {mp2_path}
             --upperdir {upper2_path} --workdir {work2_path} --read-write"
        )
        .run()?;

        // Write a new file through the mount.
        let new_file = mp2.path().join("upper_test_file");
        std::fs::write(&new_file, b"hello from upper")?;

        // Read it back through the mount.
        let content = std::fs::read(&new_file)?;
        ensure!(
            content == b"hello from upper",
            "newly written file content mismatch"
        );

        cmd!(sh, "umount {mp2_path}").run()?;

        // After unmount the file must be visible in the upperdir itself.
        let upper_file = upper2.path().join("upper_test_file");
        ensure!(
            upper_file.exists(),
            "written file should persist in upperdir after unmount"
        );
        let upper_content = std::fs::read(&upper_file)?;
        ensure!(
            upper_content == b"hello from upper",
            "upperdir file content mismatch after unmount"
        );
    }

    // --- Scenario 3: plain mount (no upperdir) still works as a baseline ---
    {
        let mp3 = tempfile::tempdir()?;
        let mp3_path = mp3.path().to_str().unwrap();

        cmd!(
            sh,
            "{cfsctl} --insecure --repo {repo_arg} mount {image_name} {mp3_path}"
        )
        .run()?;

        // Check a known file rather than read_dir to avoid keeping a dirfd open.
        ensure!(
            mp3.path().join("etc/hostname").exists(),
            "plain mount should expose etc/hostname from rootfs"
        );

        cmd!(sh, "umount {mp3_path}").run()?;
    }

    Ok(())
}
integration_test!(privileged_mount_upper_layer);

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

// ============================================================================
// Filesystem-specific reflink / hardlink tests
// ============================================================================

/// A temporary directory backed by a loop-mounted filesystem.
///
/// Supports ext4 (with verity) and XFS (with reflinks).  The backing sparse
/// file is 512 MB — large enough for a synthetic OCI image in
/// containers-storage plus a composefs repo.
struct LoopTempDir {
    mountpoint: PathBuf,
    _backing: tempfile::TempDir,
}

impl LoopTempDir {
    /// Create a loop-mounted ext4 filesystem with verity support.
    fn ext4_verity() -> Result<Self> {
        Self::create("mkfs.ext4", &["-q", "-O", "verity", "-b", "4096"])
    }

    /// Create a loop-mounted XFS filesystem with reflink support.
    fn xfs_reflink() -> Result<Self> {
        Self::create("mkfs.xfs", &["-q", "-m", "reflink=1"])
    }

    fn create(mkfs: &str, args: &[&str]) -> Result<Self> {
        let backing = tempfile::tempdir()?;
        let img = backing.path().join("fs.img");
        let mountpoint = backing.path().join("mnt");
        std::fs::create_dir(&mountpoint)?;

        let sh = Shell::new()?;
        cmd!(sh, "truncate -s 512M {img}").run()?;
        cmd!(sh, "{mkfs} {args...} {img}").run()?;
        cmd!(sh, "mount -o loop {img} {mountpoint}").run()?;

        Ok(Self {
            mountpoint,
            _backing: backing,
        })
    }

    fn path(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for LoopTempDir {
    fn drop(&mut self) {
        let _ = std::process::Command::new("umount")
            .arg(&self.mountpoint)
            .status();
    }
}

/// Create a minimal OCI directory image with files large enough to exercise
/// the `ensure_object_from_file` path (> 64 bytes, the inline threshold).
///
/// Returns the path to the OCI directory.
pub(super) fn create_oci_layout_with_large_files(parent: &Path) -> Result<PathBuf> {
    use cap_std_ext::cap_std;
    use ocidir::oci_spec::image::{
        ConfigBuilder, ImageConfigurationBuilder, Platform, PlatformBuilder, RootFsBuilder,
    };

    let oci_dir = parent.join("oci-image");
    std::fs::create_dir_all(&oci_dir)?;

    let dir = cap_std::fs::Dir::open_ambient_dir(&oci_dir, cap_std::ambient_authority())?;
    let ocidir = ocidir::OciDir::ensure(dir)?;

    let mut manifest = ocidir.new_empty_manifest()?.build()?;

    let runtime_config = ConfigBuilder::default().build()?;
    let rootfs = RootFsBuilder::default()
        .typ("layers")
        .diff_ids(Vec::<String>::new())
        .build()?;
    let mut config = ImageConfigurationBuilder::default()
        .architecture("amd64")
        .os("linux")
        .rootfs(rootfs)
        .config(runtime_config)
        .build()?;

    // Create a layer with several files > INLINE_CONTENT_MAX_V0 (64 bytes)
    // so they go through the ensure_object_from_file path during cstor import.
    // The image must have /usr (required by transform_for_oci).
    let mut layer_builder = ocidir.create_layer(None)?;

    // Add /usr directory (required by composefs OCI transformations)
    let mut usr_hdr = tar::Header::new_gnu();
    usr_hdr.set_entry_type(tar::EntryType::Directory);
    usr_hdr.set_size(0);
    usr_hdr.set_mode(0o755);
    usr_hdr.set_uid(0);
    usr_hdr.set_gid(0);
    usr_hdr.set_mtime(1234567890);
    usr_hdr.set_cksum();
    layer_builder.append_data(&mut usr_hdr, "usr/", &[] as &[u8])?;

    for i in 0..5u8 {
        let data = vec![i.wrapping_mul(0x37); 4096];
        let name = format!("usr/file_{i}.bin");
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1234567890);
        header.set_cksum();
        layer_builder.append_data(&mut header, &name, &data[..])?;
    }
    let layer = layer_builder.into_inner()?.complete()?;

    ocidir.push_layer(&mut manifest, &mut config, layer, "test layer", None);

    let platform: Platform = PlatformBuilder::default()
        .architecture("amd64")
        .os("linux")
        .build()?;
    ocidir.insert_manifest_and_config(manifest, config, None, platform)?;

    Ok(oci_dir)
}

/// Copy an OCI directory image into containers-storage on a specific filesystem.
///
/// Uses `skopeo copy` with the `[overlay@root+runroot]` syntax to target
/// a containers-storage instance at the given mount point.
///
/// Returns the storage root path.
pub(super) fn copy_oci_to_cstor(sh: &Shell, oci_dir: &Path, mount: &Path) -> Result<PathBuf> {
    let storage_root = mount.join("storage");
    let run_root = mount.join("run");
    std::fs::create_dir_all(&storage_root)?;
    std::fs::create_dir_all(&run_root)?;

    let oci_ref = format!("oci:{}", oci_dir.display());
    let cstor_ref = format!(
        "containers-storage:[overlay@{}+{}]test:latest",
        storage_root.display(),
        run_root.display()
    );

    // Run in a private mount namespace so that any bind mounts the overlay
    // driver creates (e.g. on storage/overlay) don't leak into our namespace.
    // This ensures the diff files we later open are on the raw filesystem,
    // not behind a bind mount that would cause EXDEV on hardlinks.
    cmd!(sh, "unshare -m skopeo copy {oci_ref} {cstor_ref}").run()?;

    Ok(storage_root)
}

/// Open a repository at `path`, initializing it first.  Uses insecure mode
/// so the tests work on filesystems without verity (XFS).
fn init_insecure_repo_at<ObjectID: FsVerityHashValue>(
    path: &Path,
    algorithm: composefs_oci::composefs::fsverity::Algorithm,
) -> Result<Arc<Repository<ObjectID>>> {
    std::fs::create_dir_all(path)?;
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::RDONLY,
        0.into(),
    )?;
    let (repo, _created) = Repository::<ObjectID>::init_path(
        &fd,
        ".",
        RepositoryConfig::new(algorithm).set_insecure(),
    )?;
    Ok(Arc::new(repo))
}

/// Pull a containers-storage image into a composefs repo with an explicit
/// storage root and local-fetch mode, and return the import stats.
fn cstor_pull<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    storage_root: &Path,
    local_fetch: composefs_oci::LocalFetchOpt,
) -> Result<composefs_oci::ImportStats> {
    let opts = composefs_oci::PullOptions {
        local_fetch,
        storage_root: Some(storage_root),
        ..Default::default()
    };

    let rt = tokio::runtime::Runtime::new()?;
    let pull_result = rt
        .block_on(async {
            composefs_oci::pull(repo, "containers-storage:test:latest", None, opts).await
        })
        .context("containers-storage pull failed")?;
    Ok(pull_result.stats)
}

/// Dispatch a cstor pull with the given algorithm and local-fetch mode.
///
/// This creates a fresh repo at `repo_path` with the appropriate hash type
/// and pulls the `test:latest` image from containers-storage.
fn cstor_pull_with_algorithm(
    storage_root: &Path,
    repo_path: &Path,
    algorithm: composefs_oci::composefs::fsverity::Algorithm,
    local_fetch: composefs_oci::LocalFetchOpt,
) -> Result<composefs_oci::ImportStats> {
    match algorithm {
        composefs_oci::composefs::fsverity::Algorithm::Sha256 { .. } => {
            let repo = init_insecure_repo_at::<Sha256HashValue>(repo_path, algorithm)?;
            cstor_pull(&repo, storage_root, local_fetch)
        }
        composefs_oci::composefs::fsverity::Algorithm::Sha512 { .. } => {
            let repo = init_insecure_repo_at::<Sha512HashValue>(repo_path, algorithm)?;
            cstor_pull(&repo, storage_root, local_fetch)
        }
    }
}

/// On ext4 (no reflink support), the import should skip FICLONE after the
/// first probe fails and use hardlinks instead (zero-copy).  The `skopeo
/// copy` step runs in `unshare -m` to prevent the overlay driver's bind
/// mount from interfering with hardlinks.
///
/// Covers all combinations of `{sha256, sha512} × {auto, zerocopy}`.
fn privileged_cstor_import_ext4_hardlink() -> Result<()> {
    use composefs_oci::LocalFetchOpt;
    use composefs_oci::composefs::fsverity::Algorithm;

    if require_privileged("privileged_cstor_import_ext4_hardlink")?.is_some() {
        return Ok(());
    }

    let algorithms = [(Algorithm::SHA256, "sha256"), (Algorithm::SHA512, "sha512")];
    let modes = [
        (LocalFetchOpt::IfPossible, "auto"),
        (LocalFetchOpt::ZeroCopy, "zerocopy"),
    ];

    let sh = Shell::new()?;

    for (algorithm, alg_name) in &algorithms {
        // One LoopTempDir per algorithm: enabling verity is irreversible and
        // algorithm-specific, so we cannot reuse across algorithms.
        let fs = LoopTempDir::ext4_verity()?;

        let oci_dir = create_oci_layout_with_large_files(fs.path())?;
        let storage_root = copy_oci_to_cstor(&sh, &oci_dir, fs.path())?;

        for (mode, mode_name) in &modes {
            let repo_dir = fs.path().join(format!("repo-{alg_name}-{mode_name}"));
            let stats = cstor_pull_with_algorithm(&storage_root, &repo_dir, *algorithm, *mode)?;

            println!("ext4 [{alg_name}/{mode_name}] import stats: {stats:?}");
            ensure!(
                stats.objects_reflinked == 0,
                "ext4 [{alg_name}/{mode_name}] should not reflink any objects, got {} reflinked",
                stats.objects_reflinked,
            );
            ensure!(
                stats.objects_hardlinked > 0,
                "ext4 [{alg_name}/{mode_name}] should hardlink objects, got 0 hardlinked (copied={})",
                stats.objects_copied,
            );
            ensure!(
                stats.objects_copied == 0,
                "ext4 [{alg_name}/{mode_name}] should not need copies, got {} copied",
                stats.objects_copied,
            );
            println!(
                "ext4 [{alg_name}/{mode_name}]: {} hardlinked, {} already present",
                stats.objects_hardlinked, stats.objects_already_present,
            );
        }
    }

    Ok(())
}
integration_test!(privileged_cstor_import_ext4_hardlink);

/// On XFS with reflink support, importing from containers-storage on the same
/// filesystem should use reflinks (zero-copy), and the import stats should
/// show `objects_reflinked > 0`.
///
/// Covers all combinations of `{sha256, sha512} × {auto, zerocopy}`.
fn privileged_cstor_import_xfs_reflink() -> Result<()> {
    use composefs_oci::LocalFetchOpt;
    use composefs_oci::composefs::fsverity::Algorithm;

    if require_privileged("privileged_cstor_import_xfs_reflink")?.is_some() {
        return Ok(());
    }

    // Skip if mkfs.xfs is not available (e.g. Debian bootc images).
    if !Path::new("/usr/sbin/mkfs.xfs").exists() && !Path::new("/sbin/mkfs.xfs").exists() {
        println!("SKIP: mkfs.xfs not available");
        return Ok(());
    }

    let algorithms = [(Algorithm::SHA256, "sha256"), (Algorithm::SHA512, "sha512")];
    let modes = [
        (LocalFetchOpt::IfPossible, "auto"),
        (LocalFetchOpt::ZeroCopy, "zerocopy"),
    ];

    let sh = Shell::new()?;

    for (algorithm, alg_name) in &algorithms {
        let fs = LoopTempDir::xfs_reflink()?;

        let oci_dir = create_oci_layout_with_large_files(fs.path())?;
        let storage_root = copy_oci_to_cstor(&sh, &oci_dir, fs.path())?;

        for (mode, mode_name) in &modes {
            let repo_dir = fs.path().join(format!("repo-{alg_name}-{mode_name}"));
            let stats = cstor_pull_with_algorithm(&storage_root, &repo_dir, *algorithm, *mode)?;

            println!("XFS [{alg_name}/{mode_name}] import stats: {stats:?}");
            ensure!(
                stats.objects_reflinked > 0,
                "XFS [{alg_name}/{mode_name}] should reflink objects, got 0 reflinked (hardlinked={}, copied={})",
                stats.objects_hardlinked,
                stats.objects_copied,
            );
            ensure!(
                stats.objects_copied == 0,
                "XFS [{alg_name}/{mode_name}] should not need copies, got {} copied",
                stats.objects_copied,
            );
            println!(
                "XFS [{alg_name}/{mode_name}]: {} reflinked, {} already present",
                stats.objects_reflinked, stats.objects_already_present,
            );
        }
    }

    Ok(())
}
integration_test!(privileged_cstor_import_xfs_reflink);

// ============================================================================
// FUSE integration test
// ============================================================================

/// RAII guard that tears down a `cfsctl fuse-serve` subprocess and its FUSE
/// mount, even if the test panics.
///
/// The subprocess owns the `/dev/fuse` fd and the `fsmount()` fd that pin the
/// FUSE superblock. Killing it closes those fds, the kernel aborts the
/// connection, then a lazy (`DETACH`) unmount removes the dead mount from
/// the directory tree.
struct MountGuard {
    mountpoint: PathBuf,
    child: Option<std::process::Child>,
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = rustix::mount::unmount(&self.mountpoint, rustix::mount::UnmountFlags::DETACH);
    }
}

/// Content for the external files used by [`build_test_filesystem`].
///
/// These are defined at module level so the FUSE content-read verification
/// in [`privileged_fuse_dumpfile_roundtrip`] can reconstruct the same bytes
/// without having to pass them out of `build_test_filesystem`.
fn bigfile_content() -> Vec<u8> {
    // 600 bytes of 'A' — well above MAX_INLINE_CONTENT (512)
    vec![b'A'; 600]
}

fn biglib_content() -> Vec<u8> {
    // 800 bytes cycling 0..=255 — different pattern, different hash
    (0u8..=255).cycle().take(800).collect()
}

/// Build a synthetic [`FileSystem<Sha256HashValue>`] with diverse content:
/// directories, inline regular files (≤64 bytes), external regular files
/// (>512 bytes), symlinks, xattrs, hardlinks, a FIFO, and a character device.
///
/// The `repo` argument is used to store the external file objects and obtain
/// their fsverity hashes; it must already be initialised and set insecure.
fn build_test_filesystem(
    repo: &Repository<Sha256HashValue>,
) -> Result<composefs_oci::composefs::tree::FileSystem<Sha256HashValue>> {
    use std::collections::BTreeMap;
    use std::ffi::OsStr;

    use composefs_oci::composefs::generic_tree::{LeafId, Stat};
    use composefs_oci::composefs::tree::{
        Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile,
    };

    fn dir_stat(mode: u32, uid: u32, gid: u32, mtime: i64) -> Stat {
        Stat {
            st_mode: mode,
            st_uid: uid,
            st_gid: gid,
            st_mtim_sec: mtime,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        }
    }

    fn leaf_stat(mode: u32, uid: u32, gid: u32, mtime: i64) -> Stat {
        Stat {
            st_mode: mode,
            st_uid: uid,
            st_gid: gid,
            st_mtim_sec: mtime,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        }
    }

    fn leaf_stat_xattr(
        mode: u32,
        uid: u32,
        gid: u32,
        mtime: i64,
        xattrs: &[(&str, &[u8])],
    ) -> Stat {
        let mut map = BTreeMap::new();
        for (k, v) in xattrs {
            map.insert(OsStr::new(k).into(), Box::from(*v));
        }
        Stat {
            st_mode: mode,
            st_uid: uid,
            st_gid: gid,
            st_mtim_sec: mtime,
            st_mtim_nsec: 0,
            xattrs: map,
        }
    }

    // Root directory stat (with an xattr)
    let mut root_xattrs = BTreeMap::new();
    root_xattrs.insert(
        OsStr::new("security.selinux").into(),
        Box::from(b"system_u:object_r:root_t:s0".as_ref()),
    );
    let root_stat = Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 1_700_000_000,
        st_mtim_nsec: 0,
        xattrs: root_xattrs,
    };

    let mut fs = FileSystem::<Sha256HashValue>::new(root_stat);

    // Insert leaves in a deterministic order so indices are predictable.

    // leaf 0: /usr/bin/hello  (inline file with xattr)
    let hello_id = LeafId(fs.leaves.len());
    fs.leaves.push(Leaf {
        stat: leaf_stat_xattr(0o755, 0, 0, 1_700_000_001, &[("user.test", b"hello-value")]),
        content: LeafContent::Regular(RegularFile::Inline(
            b"hello world binary stub".as_ref().into(),
        )),
    });

    // leaf 1: /usr/lib/readme.txt  (inline file)
    let readme_id = LeafId(fs.leaves.len());
    fs.leaves.push(Leaf {
        stat: leaf_stat(0o644, 0, 0, 1_700_000_002),
        content: LeafContent::Regular(RegularFile::Inline(
            b"readme text content\n".as_ref().into(),
        )),
    });

    // leaf 2: /etc/hostname  (inline file)
    let hostname_id = LeafId(fs.leaves.len());
    fs.leaves.push(Leaf {
        stat: leaf_stat(0o644, 0, 0, 1_700_000_003),
        content: LeafContent::Regular(RegularFile::Inline(b"integration-test\n".as_ref().into())),
    });

    // leaf 3: /usr/lib/os-release  (inline file, also target of symlink)
    let os_release_id = LeafId(fs.leaves.len());
    fs.leaves.push(Leaf {
        stat: leaf_stat(0o644, 0, 0, 1_700_000_004),
        content: LeafContent::Regular(RegularFile::Inline(b"ID=test\nNAME=Test\n".as_ref().into())),
    });

    // leaf 4: /etc/os-release  (symlink → ../usr/lib/os-release)
    let symlink_id = LeafId(fs.leaves.len());
    fs.leaves.push(Leaf {
        stat: leaf_stat(0o777, 0, 0, 1_700_000_005),
        content: LeafContent::Symlink(OsStr::new("../usr/lib/os-release").into()),
    });

    // leaf 5: /dev/null  (char device, major=1 minor=3 → rdev = makedev(1,3) = 259)
    let devnull_id = LeafId(fs.leaves.len());
    fs.leaves.push(Leaf {
        stat: leaf_stat(0o666, 0, 0, 0),
        // rdev = major * 256 + minor for the erofs encoding used here
        // Linux makedev(1,3) = (1 << 8) | 3 = 259
        content: LeafContent::CharacterDevice(rustix::fs::makedev(1, 3)),
    });

    // leaf 6: /tmp/fifo  (named pipe)
    let fifo_id = LeafId(fs.leaves.len());
    fs.leaves.push(Leaf {
        stat: leaf_stat(0o644, 0, 0, 1_700_000_006),
        content: LeafContent::Fifo,
    });

    // leaf 7: /usr/bin/bigfile  (external file, 600 bytes — above MAX_INLINE_CONTENT)
    // Exercises the FUSE open()+read() path through Repository::open_object().
    let bigfile_data = bigfile_content();
    let bigfile_hash = repo.ensure_object(&bigfile_data)?;
    let bigfile_id = LeafId(fs.leaves.len());
    fs.leaves.push(Leaf {
        stat: leaf_stat(0o755, 0, 0, 1_700_000_007),
        content: LeafContent::Regular(RegularFile::External(
            bigfile_hash,
            bigfile_data.len() as u64,
        )),
    });

    // leaf 8: /usr/lib/biglib.so  (external file, 800 bytes — different pattern)
    let biglib_data = biglib_content();
    let biglib_hash = repo.ensure_object(&biglib_data)?;
    let biglib_id = LeafId(fs.leaves.len());
    fs.leaves.push(Leaf {
        stat: leaf_stat(0o755, 0, 0, 1_700_000_008),
        content: LeafContent::Regular(RegularFile::External(biglib_hash, biglib_data.len() as u64)),
    });

    // Now build the directory tree.

    // /usr/bin/
    let mut usr_bin = Directory::<Sha256HashValue>::new(dir_stat(0o755, 0, 0, 1_700_000_010));
    usr_bin.insert(OsStr::new("hello"), Inode::leaf(hello_id));
    // hardlink: /usr/bin/hello2 → same leaf as /usr/bin/hello
    usr_bin.insert(OsStr::new("hello2"), Inode::leaf(hello_id));
    usr_bin.insert(OsStr::new("bigfile"), Inode::leaf(bigfile_id));

    // /usr/lib/
    let mut usr_lib = Directory::<Sha256HashValue>::new(dir_stat(0o755, 0, 0, 1_700_000_011));
    usr_lib.insert(OsStr::new("readme.txt"), Inode::leaf(readme_id));
    usr_lib.insert(OsStr::new("os-release"), Inode::leaf(os_release_id));
    usr_lib.insert(OsStr::new("biglib.so"), Inode::leaf(biglib_id));

    // /usr/
    let mut usr = Directory::<Sha256HashValue>::new(dir_stat(0o755, 0, 0, 1_700_000_012));
    usr.insert(OsStr::new("bin"), Inode::Directory(Box::new(usr_bin)));
    usr.insert(OsStr::new("lib"), Inode::Directory(Box::new(usr_lib)));

    // /etc/
    let mut etc = Directory::<Sha256HashValue>::new(dir_stat(0o755, 0, 0, 1_700_000_013));
    etc.insert(OsStr::new("hostname"), Inode::leaf(hostname_id));
    etc.insert(OsStr::new("os-release"), Inode::leaf(symlink_id));

    // /dev/
    let mut dev = Directory::<Sha256HashValue>::new(dir_stat(0o755, 0, 0, 1_700_000_014));
    dev.insert(OsStr::new("null"), Inode::leaf(devnull_id));

    // /tmp/
    let mut tmp_dir = Directory::<Sha256HashValue>::new(dir_stat(0o1777, 0, 0, 1_700_000_015));
    tmp_dir.insert(OsStr::new("fifo"), Inode::leaf(fifo_id));

    // Root
    fs.root
        .insert(OsStr::new("usr"), Inode::Directory(Box::new(usr)));
    fs.root
        .insert(OsStr::new("etc"), Inode::Directory(Box::new(etc)));
    fs.root
        .insert(OsStr::new("dev"), Inode::Directory(Box::new(dev)));
    fs.root
        .insert(OsStr::new("tmp"), Inode::Directory(Box::new(tmp_dir)));

    Ok(fs)
}

/// Mount a composefs [`FileSystem`] via FUSE, generate a dumpfile from the
/// FUSE mount using `cfsctl create-dumpfile`, and assert that it is
/// byte-for-byte identical to the dumpfile produced directly by
/// [`write_dumpfile`] on the same in-memory tree.
///
/// This validates that the FUSE implementation correctly reports every piece
/// of metadata that the dumpfile format captures: modes, uid/gid, mtimes,
/// xattrs, symlink targets, hardlink structure, and device numbers.
fn privileged_fuse_dumpfile_roundtrip() -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    use std::time::{Duration, Instant};

    use composefs_oci::composefs::{
        dumpfile::write_dumpfile,
        erofs::{
            reader::erofs_to_filesystem,
            writer::{ValidatedFileSystem, mkfs_erofs},
        },
        repository::{Repository, RepositoryConfig},
    };

    if require_privileged("privileged_fuse_dumpfile_roundtrip")?.is_some() {
        return Ok(());
    }

    // 1. Temp dir: mountpoint, insecure SHA-256 repo, and EROFS image file.
    let work_dir = tempfile::tempdir()?;
    let mountpoint = work_dir.path().join("mnt");
    let repo_path = work_dir.path().join("repo");
    let image_path = work_dir.path().join("image.erofs");
    std::fs::create_dir(&mountpoint)?;
    std::fs::create_dir(&repo_path)?;

    let repo_fd = rustix::fs::open(
        &repo_path,
        rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::RDONLY,
        rustix::fs::Mode::empty(),
    )?;
    let (mut repo, _created) = Repository::<Sha256HashValue>::init_path(
        &repo_fd,
        ".",
        RepositoryConfig::default().set_insecure(),
    )?;
    repo.set_insecure();

    // 2. Build the synthetic tree, write external objects to the repo, and
    //    round-trip through EROFS for canonical form.
    let synthetic = build_test_filesystem(&repo)?;
    let erofs_bytes = mkfs_erofs(&ValidatedFileSystem::new(synthetic)?);
    std::fs::write(&image_path, &*erofs_bytes)?;
    let canonical_fs = erofs_to_filesystem::<Sha256HashValue>(&erofs_bytes)?;

    // 3. Expected dumpfile from the in-memory canonical tree.
    let mut expected_buf = Vec::new();
    write_dumpfile(&mut expected_buf, &canonical_fs)?;
    let expected_dump = String::from_utf8(expected_buf)?;

    // 4. Record the mountpoint's device number so we can detect when the
    //    FUSE mount becomes visible (st_dev changes).
    let pre_mount_dev = std::fs::metadata(&mountpoint)?.dev();

    // 5. Spawn `cfsctl fuse-serve` in the background. It opens /dev/fuse,
    //    mounts, attaches at <mountpoint>, and serves until killed.
    let cfsctl_bin = cfsctl()?;
    let child = std::process::Command::new(&cfsctl_bin)
        .arg("--repo")
        .arg(&repo_path)
        .arg("fuse-serve")
        .arg(&image_path)
        .arg(&mountpoint)
        .spawn()
        .context("spawning cfsctl fuse-serve")?;

    let mut guard = MountGuard {
        mountpoint: mountpoint.clone(),
        child: Some(child),
    };

    // 6. Poll until the mount is ready: st_dev of mountpoint changes once
    //    the FUSE filesystem is attached. Bail if the child exits early.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(child) = guard.child.as_mut()
            && let Some(status) = child.try_wait()?
        {
            bail!("cfsctl fuse-serve exited before mount was ready: {status}");
        }
        if std::fs::metadata(&mountpoint)
            .map(|m| m.dev())
            .unwrap_or(pre_mount_dev)
            != pre_mount_dev
        {
            break;
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for FUSE mount");
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // 7. Verify external file content is served correctly.
    let bigfile_actual = std::fs::read(mountpoint.join("usr/bin/bigfile"))
        .context("reading bigfile from FUSE mount")?;
    ensure!(
        bigfile_actual == bigfile_content(),
        "bigfile content mismatch: got {} bytes, expected {}",
        bigfile_actual.len(),
        bigfile_content().len(),
    );
    let biglib_actual = std::fs::read(mountpoint.join("usr/lib/biglib.so"))
        .context("reading biglib.so from FUSE mount")?;
    ensure!(
        biglib_actual == biglib_content(),
        "biglib.so content mismatch: got {} bytes, expected {}",
        biglib_actual.len(),
        biglib_content().len(),
    );

    // 8. Generate the actual dumpfile by walking the FUSE mount via cfsctl.
    //    --no-propagate-usr-to-root preserves raw metadata; --repo points at
    //    the SHA-256 repo so external-file digests match expected_dump.
    let sh = Shell::new()?;
    let mp = mountpoint.to_str().context("non-UTF-8 mountpoint")?;
    let repo_arg = repo_path.to_str().context("non-UTF-8 repo path")?;
    let actual_dump = cmd!(
        sh,
        "{cfsctl_bin} --repo {repo_arg} create-dumpfile --no-propagate-usr-to-root {mp}"
    )
    .read()?;

    // 9. Tear down before asserting so a mismatch doesn't leak the mount.
    drop(guard);

    // 10. Compare with a readable diff on mismatch.
    similar_asserts::assert_eq!(
        expected_dump.trim_end_matches('\n'),
        actual_dump.trim_end_matches('\n')
    );

    Ok(())
}
integration_test!(privileged_fuse_dumpfile_roundtrip);
