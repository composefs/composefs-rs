//! Integration test runner for composefs-rs.
//!
//! This binary uses [`libtest_mimic`] as a custom test harness (no `#[test]`).
//! Tests are registered via the [`integration_test!`] macro in submodules
//! and collected from the [`INTEGRATION_TESTS`] distributed slice at startup.
//!
//! IMPORTANT: This binary may be re-executed via `podman unshare` to act as a
//! userns helper for rootless containers-storage access. The init_if_helper()
//! call at the start of main() handles this.

// linkme requires unsafe for distributed slices
#![allow(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use libtest_mimic::{Arguments, Trial};

pub(crate) use integration_tests::{INTEGRATION_TESTS, integration_test};

mod tests;

/// Return the path to the cfsctl binary.
///
/// Resolution order:
/// 1. `CFSCTL_PATH` environment variable
/// 2. `target/{release,debug}/cfsctl` relative to the workspace root
/// 3. `/usr/bin/cfsctl` (for VM-based integration tests)
pub(crate) fn cfsctl() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("CFSCTL_PATH") {
        return Ok(PathBuf::from(p));
    }

    // Walk up from the crate's manifest dir to find the workspace target/
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(Path::new("."));

    for profile in ["release", "debug"] {
        let candidate = workspace.join("target").join(profile).join("cfsctl");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // In VM-based tests the binary is baked into the container image
    let system = Path::new("/usr/bin/cfsctl");
    if system.exists() {
        return Ok(system.to_path_buf());
    }

    bail!(
        "cfsctl binary not found; build it with `cargo build -p cfsctl` \
         or set CFSCTL_PATH"
    )
}

/// Create a test rootfs fixture inside `parent` and return its path.
///
/// Includes a file large enough (128 KiB) to avoid erofs inlining so that
/// `image-objects` will report at least one external object.
pub(crate) fn create_test_rootfs(parent: &Path) -> Result<PathBuf> {
    let root = parent.join("rootfs");
    fs::create_dir_all(root.join("usr/bin"))?;
    fs::create_dir_all(root.join("usr/lib"))?;
    fs::create_dir_all(root.join("etc"))?;

    // A large-ish file that won't be inlined into the erofs image
    fs::write(root.join("usr/bin/hello"), "x".repeat(128 * 1024))?;
    fs::write(root.join("usr/lib/readme.txt"), "test fixture\n")?;
    fs::write(root.join("etc/hostname"), "integration-test\n")?;
    Ok(root)
}

/// Creates a minimal OCI image layout directory for testing using the ocidir crate.
///
/// Returns the path to the OCI layout directory.
pub(crate) fn create_oci_layout(parent: &Path) -> Result<PathBuf> {
    use cap_std_ext::cap_std;
    use ocidir::oci_spec::image::{
        ConfigBuilder, ImageConfigurationBuilder, Platform, PlatformBuilder, RootFsBuilder,
    };

    let oci_dir = parent.join("oci-image");
    fs::create_dir_all(&oci_dir)?;

    let dir = cap_std::fs::Dir::open_ambient_dir(&oci_dir, cap_std::ambient_authority())?;
    let ocidir = ocidir::OciDir::ensure(dir)?;

    // Create a new empty manifest
    let mut manifest = ocidir.new_empty_manifest()?.build()?;

    // Create config with architecture and OS
    let rootfs = RootFsBuilder::default()
        .typ("layers")
        .diff_ids(Vec::<String>::new())
        .build()?;
    let runtime_config = ConfigBuilder::default().build()?;
    let mut config = ImageConfigurationBuilder::default()
        .architecture("amd64")
        .os("linux")
        .rootfs(rootfs)
        .config(runtime_config)
        .build()?;

    // Create a layer with a minimal container rootfs (signing needs /usr to exist)
    let mut layer_builder = ocidir.create_layer(None)?;
    {
        // Directory entries that form a plausible container rootfs
        for dir in ["usr/", "usr/bin/", "etc/"] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(1234567890);
            header.set_cksum();
            layer_builder.append_data(&mut header, dir, &[] as &[u8])?;
        }

        let data = b"hello from test layer\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1234567890);
        header.set_cksum();
        layer_builder.append_data(&mut header, "usr/bin/hello.txt", &data[..])?;
    }
    let layer = layer_builder.into_inner()?.complete()?;

    // Push the layer to manifest and config
    ocidir.push_layer(&mut manifest, &mut config, layer, "test layer", None);

    // Create platform for the manifest
    let platform: Platform = PlatformBuilder::default()
        .architecture("amd64")
        .os("linux")
        .build()?;

    // Insert manifest and config into the OCI directory
    ocidir.insert_manifest_and_config(manifest, config, None, platform)?;

    Ok(oci_dir)
}

/// Check if the running kernel supports fs-verity builtin signatures.
///
/// Detection strategy (first match wins):
/// 1. `/proc/sys/fs/verity/require_signatures` — only exists when the
///    kernel was built with `CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y`
/// 2. Kernel config files at standard locations for the running kernel
///    (`/usr/lib/modules`, `/lib/modules`, `/boot`)
/// 3. Kernel config files for any installed kernel (catches the case
///    where `uname -r` returns the host kernel inside a container but
///    the image ships a different kernel's modules)
pub(crate) fn has_fsverity_builtin_signatures() -> bool {
    // Fast path: the sysctl only exists when CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y
    if Path::new("/proc/sys/fs/verity/require_signatures").exists() {
        return true;
    }

    let release = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    // Check config for the running kernel
    if let Some(ref release) = release {
        for path in [
            format!("/usr/lib/modules/{release}/config"),
            format!("/lib/modules/{release}/config"),
            format!("/boot/config-{release}"),
        ] {
            if let Ok(config) = fs::read_to_string(&path) {
                return config.contains("CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y");
            }
        }
    }

    // Inside a bcvk VM, uname -r matches the booted kernel whose modules
    // are under /usr/lib/modules.  But also check any installed kernel in
    // case we're in a container where uname -r is the host kernel.
    if let Ok(entries) = fs::read_dir("/usr/lib/modules") {
        for entry in entries.flatten() {
            let config_path = entry.path().join("config");
            if let Ok(config) = fs::read_to_string(&config_path)
                && config.contains("CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y")
            {
                return true;
            }
        }
    }

    false
}

fn main() {
    // CRITICAL: Handle userns helper re-execution.
    // When running rootless, this binary may be re-executed via `podman unshare`
    // to act as a helper process for containers-storage access.
    composefs_oci::cstor::init_if_helper();

    let args = Arguments::from_args();

    let tests: Vec<Trial> = INTEGRATION_TESTS
        .iter()
        .map(|t| {
            let f = t.f;
            Trial::test(t.name, move || f().map_err(|e| format!("{e:?}").into()))
        })
        .collect();

    libtest_mimic::run(&args, tests).exit();
}
