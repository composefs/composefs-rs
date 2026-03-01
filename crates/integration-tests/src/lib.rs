//! Integration test infrastructure for composefs-rs.
//!
//! Provides test registration via [`linkme`] distributed slices and the
//! [`integration_test!`] macro, collected and executed by a custom
//! [`libtest_mimic`] harness in `main.rs`.

// linkme requires unsafe for distributed slices
#![allow(unsafe_code)]

use std::process::Command;
use std::sync::Arc;

use anyhow::Result;
use composefs_oci::composefs::fsverity::Sha256HashValue;
use composefs_oci::composefs::repository::Repository;
use tempfile::TempDir;

/// A test function that returns a Result.
pub type TestFn = fn() -> anyhow::Result<()>;

/// Metadata for a registered integration test.
#[derive(Debug)]
pub struct IntegrationTest {
    /// Name of the integration test.
    pub name: &'static str,
    /// Test function to execute.
    pub f: TestFn,
}

impl IntegrationTest {
    /// Create a new integration test with the given name and function.
    pub const fn new(name: &'static str, f: TestFn) -> Self {
        Self { name, f }
    }
}

/// Distributed slice holding all registered integration tests.
#[linkme::distributed_slice]
pub static INTEGRATION_TESTS: [IntegrationTest];

/// Register an integration test function with less boilerplate.
///
/// # Examples
///
/// ```ignore
/// fn test_something() -> anyhow::Result<()> {
///     Ok(())
/// }
/// integration_test!(test_something);
/// ```
#[macro_export]
macro_rules! integration_test {
    ($fn_name:ident) => {
        ::paste::paste! {
            #[::linkme::distributed_slice($crate::INTEGRATION_TESTS)]
            static [<$fn_name:upper>]: $crate::IntegrationTest =
                $crate::IntegrationTest::new(stringify!($fn_name), $fn_name);
        }
    };
}

// ============================================================================
// Utilities for containers-storage tests
// ============================================================================

/// Test label for cleanup
pub const INTEGRATION_TEST_LABEL: &str = "composefs-rs.integration-test=1";

/// Get the path to cfsctl binary
pub fn get_cfsctl_path() -> Result<String> {
    // Check environment first
    if let Ok(path) = std::env::var("CFSCTL_PATH") {
        return Ok(path);
    }
    // Look in common locations
    for path in [
        "./target/release/cfsctl",
        "./target/debug/cfsctl",
        "/usr/bin/cfsctl",
    ] {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    anyhow::bail!("cfsctl not found; set CFSCTL_PATH or build with `cargo build --release`")
}

/// Get the primary test image
pub fn get_primary_image() -> String {
    std::env::var("COMPOSEFS_RS_PRIMARY_IMAGE")
        .unwrap_or_else(|_| "quay.io/centos-bootc/centos-bootc:stream10".to_string())
}

/// Get all test images
pub fn get_all_images() -> Vec<String> {
    std::env::var("COMPOSEFS_RS_ALL_IMAGES")
        .unwrap_or_else(|_| get_primary_image())
        .split_whitespace()
        .map(String::from)
        .collect()
}

/// Create a test repository in a temporary directory.
///
/// The TempDir is returned alongside the repo to keep it alive.
pub fn create_test_repository(tempdir: &TempDir) -> Result<Arc<Repository<Sha256HashValue>>> {
    let fd = rustix::fs::open(
        tempdir.path(),
        rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::PATH,
        0.into(),
    )?;

    let mut repo = Repository::open_path(&fd, ".")?;
    repo.set_insecure(true);
    Ok(Arc::new(repo))
}

fn podman_command() -> Command {
    Command::new("podman")
}

/// Build a minimal test image using podman and return its ID
pub fn build_test_image() -> Result<String> {
    let temp_dir = TempDir::new()?;
    let containerfile = temp_dir.path().join("Containerfile");

    // Create a simple Containerfile with various file sizes to test
    // both inline and external storage paths.
    // Use Fedora instead of busybox because busybox has UID 65534 which
    // breaks in nested container environments due to user namespace issues.
    std::fs::write(
        &containerfile,
        r#"FROM quay.io/centos/centos:stream10
# Small file (should be inlined)
RUN echo "small content" > /small.txt
# Larger file (should be external)
RUN dd if=/dev/zero of=/large.bin bs=1024 count=100 2>/dev/null
# Directory with files
RUN mkdir -p /testdir && echo "file1" > /testdir/a.txt && echo "file2" > /testdir/b.txt
# Symlink
RUN ln -s /small.txt /link.txt
"#,
    )?;

    let iid_file = temp_dir.path().join("image.iid");

    let output = podman_command()
        .args([
            "build",
            "--pull=newer",
            &format!("--iidfile={}", iid_file.display()),
            "-f",
            &containerfile.to_string_lossy(),
            &temp_dir.path().to_string_lossy(),
        ])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "podman build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let image_id = std::fs::read_to_string(&iid_file)?.trim().to_string();
    Ok(image_id)
}

/// Remove a test image
pub fn cleanup_test_image(image_id: &str) {
    let _ = podman_command().args(["rmi", "-f", image_id]).output();
}
