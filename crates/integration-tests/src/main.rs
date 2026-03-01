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

use anyhow::{bail, Result};
use libtest_mimic::{Arguments, Trial};

pub(crate) use integration_tests::{integration_test, INTEGRATION_TESTS};

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
