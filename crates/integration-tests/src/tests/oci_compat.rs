//! Real filesystem compatibility tests.
//!
//! These tests create realistic filesystem structures (similar to what you'd find
//! in container images) and verify bit-for-bit compatibility between the Rust
//! mkfs_erofs and C mkcomposefs implementations.
//!
//! Requirements:
//! - C mkcomposefs binary (/usr/bin/mkcomposefs or set C_MKCOMPOSEFS_PATH)
//! - Rust mkcomposefs binary (built from this project)
//! - cfsctl binary (built from this project)
//!
//! Install the C mkcomposefs with: `sudo apt install composefs`

use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};
use xshell::{cmd, Shell};

use crate::{cfsctl, integration_test};

/// Cached path to C mkcomposefs binary, computed once.
static C_MKCOMPOSEFS_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Get the path to C mkcomposefs binary.
///
/// Priority:
/// 1. C_MKCOMPOSEFS_PATH environment variable (if set)
/// 2. /usr/bin/mkcomposefs (system installation)
///
/// Panics if no C mkcomposefs binary is found, with a helpful error message.
fn c_mkcomposefs_path() -> &'static PathBuf {
    C_MKCOMPOSEFS_PATH.get_or_init(|| {
        // Check env var first
        if let Ok(path) = std::env::var("C_MKCOMPOSEFS_PATH") {
            let path = PathBuf::from(path);
            if path.exists() {
                return path;
            }
            panic!(
                "C_MKCOMPOSEFS_PATH is set to '{}' but the file does not exist",
                path.display()
            );
        }

        // Check system location
        let system_path = PathBuf::from("/usr/bin/mkcomposefs");
        if system_path.exists() {
            return system_path;
        }

        panic!(
            "C mkcomposefs binary not found.\n\n\
             These tests require the C mkcomposefs binary to compare against.\n\
             Please install it:\n\n\
             \x20   sudo apt install composefs\n\n\
             Or set C_MKCOMPOSEFS_PATH to point to an existing binary."
        );
    })
}

/// Get the path to the Rust mkcomposefs binary.
fn rust_mkcomposefs_path() -> Result<PathBuf> {
    // Walk up from the crate's manifest dir to find the workspace target/
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(std::path::Path::new("."));

    for profile in ["release", "debug"] {
        let candidate = workspace.join("target").join(profile).join("mkcomposefs");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!(
        "mkcomposefs binary not found; build it with `cargo build -p mkcomposefs` \
         or `cargo build --release -p mkcomposefs`"
    )
}

/// Compare Rust and C mkcomposefs output for a given dumpfile.
///
/// Returns Ok(()) if the outputs are bit-for-bit identical.
fn compare_mkcomposefs_output(dumpfile: &str) -> Result<()> {
    let rust_mkcomposefs = rust_mkcomposefs_path()?;
    let c_mkcomposefs = c_mkcomposefs_path();

    // Run Rust mkcomposefs
    let mut rust_cmd = Command::new(&rust_mkcomposefs)
        .args(["--from-file", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn Rust mkcomposefs")?;

    {
        let stdin = rust_cmd.stdin.as_mut().unwrap();
        stdin
            .write_all(dumpfile.as_bytes())
            .context("Failed to write to Rust mkcomposefs stdin")?;
    }

    let rust_output = rust_cmd
        .wait_with_output()
        .context("Failed to wait for Rust mkcomposefs")?;

    if !rust_output.status.success() {
        bail!(
            "Rust mkcomposefs failed: {}",
            String::from_utf8_lossy(&rust_output.stderr)
        );
    }

    // Run C mkcomposefs
    let mut c_cmd = Command::new(c_mkcomposefs)
        .args(["--min-version=0", "--from-file", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn C mkcomposefs")?;

    {
        let stdin = c_cmd.stdin.as_mut().unwrap();
        stdin
            .write_all(dumpfile.as_bytes())
            .context("Failed to write to C mkcomposefs stdin")?;
    }

    let c_output = c_cmd
        .wait_with_output()
        .context("Failed to wait for C mkcomposefs")?;

    if !c_output.status.success() {
        bail!(
            "C mkcomposefs failed: {}",
            String::from_utf8_lossy(&c_output.stderr)
        );
    }

    // Compare outputs
    let rust_image = rust_output.stdout;
    let c_image = c_output.stdout;

    if rust_image != c_image {
        // Find first difference for debugging
        let first_diff = rust_image
            .iter()
            .zip(c_image.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(std::cmp::min(rust_image.len(), c_image.len()));

        bail!(
            "Images differ! Rust: {} bytes, C: {} bytes. First difference at byte {}.\n\
             Dumpfile has {} lines.",
            rust_image.len(),
            c_image.len(),
            first_diff,
            dumpfile.lines().count()
        );
    }

    Ok(())
}

/// Create a realistic test filesystem with container-like structure.
///
/// This creates a directory structure similar to what you'd find in a container:
/// - Nested directories (/usr/bin, /usr/lib, /etc, /var/log)
/// - Symlinks (absolute and relative)
/// - Large files (for external content)
/// - Various file permissions
fn create_container_like_rootfs(root: &std::path::Path) -> Result<()> {
    // Create directory structure
    fs::create_dir_all(root.join("usr/bin"))?;
    fs::create_dir_all(root.join("usr/lib/x86_64-linux-gnu"))?;
    fs::create_dir_all(root.join("usr/share/doc/test"))?;
    fs::create_dir_all(root.join("etc/default"))?;
    fs::create_dir_all(root.join("var/log"))?;
    fs::create_dir_all(root.join("var/cache"))?;
    fs::create_dir_all(root.join("tmp"))?;
    fs::create_dir_all(root.join("home/user"))?;

    // Create various files
    fs::write(root.join("usr/bin/hello"), "#!/bin/sh\necho Hello\n")?;
    fs::write(root.join("usr/bin/world"), "#!/bin/sh\necho World\n")?;

    // Create a large file (128KB) that won't be inlined
    let large_content = "x".repeat(128 * 1024);
    fs::write(root.join("usr/lib/libtest.so"), &large_content)?;

    // Create files in nested directories
    fs::write(
        root.join("usr/lib/x86_64-linux-gnu/libc.so.6"),
        &large_content,
    )?;
    fs::write(
        root.join("usr/share/doc/test/README"),
        "Test documentation\n",
    )?;
    fs::write(
        root.join("usr/share/doc/test/LICENSE"),
        "MIT License\n...\n",
    )?;

    // Create config files
    fs::write(root.join("etc/hostname"), "container\n")?;
    fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\n")?;
    fs::write(root.join("etc/default/locale"), "LANG=en_US.UTF-8\n")?;

    // Create log files
    fs::write(root.join("var/log/messages"), "")?;
    fs::write(root.join("var/log/auth.log"), "")?;

    // Create symlinks
    symlink("/usr/bin/hello", root.join("usr/bin/hi"))?;
    symlink("../lib/libtest.so", root.join("usr/bin/libtest-link"))?;
    symlink("/etc/hostname", root.join("etc/HOSTNAME"))?;

    // Create home directory files
    fs::write(root.join("home/user/.bashrc"), "# Bash config\n")?;
    fs::write(root.join("home/user/.profile"), "# Profile\n")?;

    Ok(())
}

/// Create a dumpfile from a directory using cfsctl.
fn create_dumpfile_from_dir(sh: &Shell, root: &std::path::Path) -> Result<String> {
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Use cfsctl to create a dumpfile from the directory.
    // Use --no-propagate-usr-to-root because test directories may not have /usr.
    let dumpfile = cmd!(
        sh,
        "{cfsctl} --insecure --hash sha256 --repo {repo} create-dumpfile --no-propagate-usr-to-root {root}"
    )
    .read()
    .with_context(|| format!("Failed to create dumpfile from {:?}", root))?;

    Ok(dumpfile)
}

/// Test bit-for-bit compatibility with a container-like filesystem.
///
/// Creates a realistic filesystem structure and verifies that both
/// Rust and C mkcomposefs produce identical output.
fn test_container_rootfs_compat() -> Result<()> {
    let sh = Shell::new()?;
    let rootfs_dir = tempfile::tempdir()?;
    let rootfs = rootfs_dir.path().join("rootfs");
    fs::create_dir_all(&rootfs)?;

    // Create the test filesystem
    create_container_like_rootfs(&rootfs)?;

    // Generate dumpfile
    let dumpfile = create_dumpfile_from_dir(&sh, &rootfs)?;

    eprintln!(
        "Container rootfs dumpfile: {} lines, {} bytes",
        dumpfile.lines().count(),
        dumpfile.len()
    );

    compare_mkcomposefs_output(&dumpfile)?;
    eprintln!("Container rootfs: bit-for-bit match!");
    Ok(())
}
integration_test!(test_container_rootfs_compat);

/// Test with deeply nested directory structure.
///
/// This exercises the BFS inode ordering with many levels of nesting.
fn test_deep_nesting_compat() -> Result<()> {
    let sh = Shell::new()?;
    let rootfs_dir = tempfile::tempdir()?;
    let rootfs = rootfs_dir.path().join("rootfs");

    // Create deeply nested structure: /a/b/c/d/e/f/g/h/file
    let deep_path = rootfs.join("a/b/c/d/e/f/g/h");
    fs::create_dir_all(&deep_path)?;
    fs::write(deep_path.join("file"), "deep content")?;

    // Add files at various levels
    fs::write(rootfs.join("a/file1"), "level 1")?;
    fs::write(rootfs.join("a/b/file2"), "level 2")?;
    fs::write(rootfs.join("a/b/c/file3"), "level 3")?;
    fs::write(rootfs.join("a/b/c/d/file4"), "level 4")?;

    // Add parallel directory trees
    fs::create_dir_all(rootfs.join("x/y/z"))?;
    fs::write(rootfs.join("x/file"), "x tree")?;
    fs::write(rootfs.join("x/y/file"), "y tree")?;
    fs::write(rootfs.join("x/y/z/file"), "z tree")?;

    let dumpfile = create_dumpfile_from_dir(&sh, &rootfs)?;

    eprintln!(
        "Deep nesting dumpfile: {} lines, {} bytes",
        dumpfile.lines().count(),
        dumpfile.len()
    );

    compare_mkcomposefs_output(&dumpfile)?;
    eprintln!("Deep nesting: bit-for-bit match!");
    Ok(())
}
integration_test!(test_deep_nesting_compat);

/// Test with many files in a single directory.
///
/// This exercises the directory entry handling with many entries.
fn test_wide_directory_compat() -> Result<()> {
    let sh = Shell::new()?;
    let rootfs_dir = tempfile::tempdir()?;
    let rootfs = rootfs_dir.path().join("rootfs");
    fs::create_dir_all(&rootfs)?;

    // Create many files in a single directory
    for i in 0..100 {
        fs::write(rootfs.join(format!("file{i:03}")), format!("content {i}"))?;
    }

    // Add some subdirectories with files too
    for i in 0..10 {
        let subdir = rootfs.join(format!("dir{i:02}"));
        fs::create_dir_all(&subdir)?;
        for j in 0..5 {
            fs::write(subdir.join(format!("file{j}")), format!("content {i}.{j}"))?;
        }
    }

    let dumpfile = create_dumpfile_from_dir(&sh, &rootfs)?;

    eprintln!(
        "Wide directory dumpfile: {} lines, {} bytes",
        dumpfile.lines().count(),
        dumpfile.len()
    );

    compare_mkcomposefs_output(&dumpfile)?;
    eprintln!("Wide directory: bit-for-bit match!");
    Ok(())
}
integration_test!(test_wide_directory_compat);

/// Test with symlinks (both absolute and relative).
fn test_symlinks_compat() -> Result<()> {
    let sh = Shell::new()?;
    let rootfs_dir = tempfile::tempdir()?;
    let rootfs = rootfs_dir.path().join("rootfs");

    fs::create_dir_all(rootfs.join("usr/bin"))?;
    fs::create_dir_all(rootfs.join("usr/lib"))?;
    fs::create_dir_all(rootfs.join("bin"))?;
    fs::create_dir_all(rootfs.join("lib"))?;

    // Create target files
    fs::write(rootfs.join("usr/bin/real"), "real binary")?;
    fs::write(rootfs.join("usr/lib/libreal.so"), "real library")?;

    // Absolute symlinks
    symlink("/usr/bin/real", rootfs.join("bin/link1"))?;
    symlink("/usr/lib/libreal.so", rootfs.join("lib/liblink.so"))?;

    // Relative symlinks
    symlink("../usr/bin/real", rootfs.join("bin/link2"))?;
    symlink("../lib/libreal.so", rootfs.join("usr/bin/liblink"))?;

    // Symlink to symlink
    symlink("link1", rootfs.join("bin/link3"))?;

    // Long symlink target
    let long_target = "/very/long/path/that/goes/deep/into/the/filesystem/structure";
    symlink(long_target, rootfs.join("bin/longlink"))?;

    let dumpfile = create_dumpfile_from_dir(&sh, &rootfs)?;

    eprintln!(
        "Symlinks dumpfile: {} lines, {} bytes",
        dumpfile.lines().count(),
        dumpfile.len()
    );

    compare_mkcomposefs_output(&dumpfile)?;
    eprintln!("Symlinks: bit-for-bit match!");
    Ok(())
}
integration_test!(test_symlinks_compat);
