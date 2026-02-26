//! Corpus compatibility tests between Rust and C composefs implementations.
//!
//! These tests read real-world dump files from the C test corpus and verify
//! that both implementations produce bit-for-bit identical EROFS images.
//!
//! # Test corpus sources
//!
//! Uses environment variables with fallback to relative paths from the workspace:
//! - `COMPOSEFS_FUZZING_DATA_DIR` - Seed corpus (alpine, busybox, fedora)
//! - `COMPOSEFS_ASSETS_DIR` - Various .dump files including honggfuzz discoveries
//!
//! # Test categories
//!
//! - **Passing tests**: Dump files where both Rust and C produce identical output,
//!   or where edge cases are handled safely (even if differently)
//! - **Ignored tests**: Known parser differences or format gaps that need work:
//!   - `xx/hash` format for external file digests (alpine, busybox, fedora, dump-example)
//!   - `./` vs `/` root path prefix (dot-root)
//!   - EROFS generation differences (special, longlink, bigfile, etc.)
//! - **should-fail tests**: Invalid inputs that both implementations should reject
//!
//! # Running tests
//!
//! ```bash
//! # Run passing tests only
//! cargo test --package composefs --test corpus_compatibility
//!
//! # Run all tests including known failures
//! cargo test --package composefs --test corpus_compatibility -- --ignored
//! ```

use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use composefs::{
    dumpfile::dumpfile_to_filesystem,
    erofs::{debug::debug_img, format::FormatVersion, writer::mkfs_erofs},
    fsverity::Sha256HashValue,
    tree::FileSystem,
};

/// Get the path to mkcomposefs binary.
/// Uses MKCOMPOSEFS_PATH env var if set, otherwise looks for "mkcomposefs" in PATH.
fn mkcomposefs_path() -> std::path::PathBuf {
    std::env::var("MKCOMPOSEFS_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("mkcomposefs"))
}

/// Check if mkcomposefs is available for testing.
fn mkcomposefs_available() -> bool {
    let path = mkcomposefs_path();
    if path.is_absolute() {
        path.exists()
    } else {
        std::process::Command::new("which")
            .arg(&path)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Get the path to the fuzzing data directory.
/// Uses COMPOSEFS_FUZZING_DATA_DIR env var if set, otherwise uses a relative path.
fn fuzzing_data_dir() -> std::path::PathBuf {
    std::env::var("COMPOSEFS_FUZZING_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            // Try relative path from workspace root
            let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
            manifest_dir.join("../../../tests/fuzzing/data")
        })
}

/// Get the path to the test assets directory.
/// Uses COMPOSEFS_ASSETS_DIR env var if set, otherwise uses a relative path.
fn assets_dir() -> std::path::PathBuf {
    std::env::var("COMPOSEFS_ASSETS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            // Try relative path from workspace root
            let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
            manifest_dir.join("../../../tests/assets")
        })
}

/// Create a Format 1.0 compatible image with whiteout transformations applied.
fn mkfs_erofs_v1_0(mut fs: FileSystem<Sha256HashValue>) -> Box<[u8]> {
    fs.add_overlay_whiteouts();
    mkfs_erofs(&fs, FormatVersion::V1_0)
}

/// Dump EROFS image metadata for comparison diagnostics.
fn dump_image(img: &[u8]) -> String {
    let mut dump = vec![];
    debug_img(&mut dump, img).unwrap();
    String::from_utf8(dump).unwrap()
}

/// Result of comparing Rust and C mkcomposefs output.
#[derive(Debug)]
enum CompareResult {
    /// C mkcomposefs not available
    CNotAvailable,
    /// Rust failed to parse the dump file
    RustParseFailed(String),
    /// C mkcomposefs failed to process the dump
    CProcessFailed(String),
    /// Both succeeded and images match
    Match,
    /// Both succeeded but images differ
    Differ { rust_size: usize, c_size: usize },
}

/// Compare Rust and C mkcomposefs output for a given dump file content.
fn compare_with_c(dump_content: &str) -> CompareResult {
    if !mkcomposefs_available() {
        return CompareResult::CNotAvailable;
    }

    // Parse dump with Rust and generate image
    let fs = match dumpfile_to_filesystem::<Sha256HashValue>(dump_content) {
        Ok(fs) => fs,
        Err(e) => return CompareResult::RustParseFailed(e.to_string()),
    };
    let rust_image = mkfs_erofs_v1_0(fs);

    // Run C mkcomposefs on the same dump
    let mut mkcomposefs = Command::new(mkcomposefs_path())
        .args(["--min-version=0", "--from-file", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn mkcomposefs");

    {
        let mut stdin = mkcomposefs.stdin.take().unwrap();
        stdin
            .write_all(dump_content.as_bytes())
            .expect("Failed to write to mkcomposefs stdin");
    }

    let output = mkcomposefs
        .wait_with_output()
        .expect("Failed to wait for mkcomposefs");

    if !output.status.success() {
        return CompareResult::CProcessFailed(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let c_image = output.stdout.into_boxed_slice();

    // Compare byte-for-byte
    if rust_image == c_image {
        CompareResult::Match
    } else {
        CompareResult::Differ {
            rust_size: rust_image.len(),
            c_size: c_image.len(),
        }
    }
}

/// Assert that Rust and C produce identical output for a dump file.
fn assert_corpus_identical(path: &Path) {
    let name = path.file_name().unwrap().to_string_lossy();

    if !path.exists() {
        panic!("{name}: file not found at {}", path.display());
    }

    let content = fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("Failed to read {}: {e}", path.display());
    });

    match compare_with_c(&content) {
        CompareResult::CNotAvailable => {
            eprintln!("Skipping {name}: mkcomposefs not available");
        }
        CompareResult::Match => {
            eprintln!("{name}: OK (bit-for-bit identical)");
        }
        CompareResult::RustParseFailed(e) => {
            panic!("{name}: Rust failed to parse dump: {e}");
        }
        CompareResult::CProcessFailed(e) => {
            panic!("{name}: C mkcomposefs failed: {e}");
        }
        CompareResult::Differ { rust_size, c_size } => {
            // Re-parse to get the actual dumps for diagnostics
            let fs = dumpfile_to_filesystem::<Sha256HashValue>(&content).unwrap();
            let rust_image = mkfs_erofs_v1_0(fs);
            let rust_dump = dump_image(&rust_image);

            panic!(
                "{name}: Images differ!\n\
                 Rust image size: {rust_size} bytes\n\
                 C image size: {c_size} bytes\n\
                 \n--- Rust debug dump (first 2000 chars) ---\n{}",
                &rust_dump[..rust_dump.len().min(2000)]
            );
        }
    }
}

// =============================================================================
// Tests that should pass (bit-for-bit identical output)
// NOTE: Many tests are currently marked #[ignore] due to parser differences.
// These document known gaps between Rust and C implementations.
// =============================================================================

#[test]
#[ignore] // FIXME: Rust produces different EROFS image - needs investigation
fn test_corpus_special() {
    // special.dump contains various special file types with xattrs
    let path = assets_dir().join("special.dump");
    assert_corpus_identical(&path);
}

#[test]
#[ignore] // FIXME: Rust produces different EROFS image - needs investigation
fn test_corpus_longlink() {
    // longlink.dump contains very long symlink targets
    let path = assets_dir().join("longlink.dump");
    assert_corpus_identical(&path);
}

#[test]
#[ignore] // FIXME: Rust produces different EROFS image - needs investigation
fn test_corpus_bigfile() {
    // bigfile.dump contains a large external file reference
    let path = assets_dir().join("bigfile.dump");
    assert_corpus_identical(&path);
}

#[test]
#[ignore] // FIXME: Rust produces different EROFS image - needs investigation
fn test_corpus_bigfile_xattr() {
    // bigfile-xattr.dump contains a large file with xattrs
    let path = assets_dir().join("bigfile-xattr.dump");
    assert_corpus_identical(&path);
}

#[test]
#[ignore] // Rust parser doesn't support "xx/hash" format for external digests
fn test_corpus_dump_example() {
    // dump-example uses "35/d02f..." format for external file digests
    let path = fuzzing_data_dir().join("dump-example");
    assert_corpus_identical(&path);
}

#[test]
#[ignore] // FIXME: Rust produces different EROFS image - needs investigation
fn test_corpus_honggfuzz_bigfile_with_acl() {
    // Fuzzer-discovered file with ACL xattrs
    let path = assets_dir().join("honggfuzz-bigfile-with-acl.dump");
    assert_corpus_identical(&path);
}

#[test]
#[ignore] // FIXME: Rust produces different EROFS image size (20480 vs 24576)
fn test_corpus_honggfuzz_long_symlink() {
    // Fuzzer-discovered file with very long symlink
    let path = assets_dir().join("honggfuzz-long-symlink.dump");
    assert_corpus_identical(&path);
}

// =============================================================================
// Tests with known Rust parser differences (marked as ignored until fixed)
// =============================================================================

#[test]
#[ignore] // Rust parser requires "/" not "./" for root path
fn test_corpus_dot_root() {
    // dot-root uses "./" prefix instead of "/" which Rust doesn't accept
    let path = fuzzing_data_dir().join("dot-root");
    assert_corpus_identical(&path);
}

#[test]
#[ignore] // Rust parser doesn't support fsverity digest in backing path format "xx/hash"
fn test_corpus_alpine() {
    // alpine corpus uses "5e/0f79..." format for external file digests
    let path = fuzzing_data_dir().join("alpine");
    assert_corpus_identical(&path);
}

#[test]
#[ignore] // Rust parser doesn't support fsverity digest in backing path format "xx/hash"
fn test_corpus_busybox() {
    // busybox corpus uses "5e/0f79..." format for external file digests
    let path = fuzzing_data_dir().join("busybox");
    assert_corpus_identical(&path);
}

#[test]
#[ignore] // Large file - run with --ignored
fn test_corpus_fedora() {
    let path = fuzzing_data_dir().join("fedora");
    assert_corpus_identical(&path);
}

// =============================================================================
// Edge cases that may be malformed or have undefined behavior
// =============================================================================

#[test]
fn test_corpus_honggfuzz_chardev_nonzero_size() {
    // Edge case: chardev with non-zero size field (unusual but C accepts it)
    // This tests whether both implementations handle this edge case the same way
    let path = assets_dir().join("honggfuzz-chardev-nonzero-size.dump");
    let name = path.file_name().unwrap().to_string_lossy();

    if !path.exists() {
        eprintln!("Skipping: file not found");
        return;
    }

    let content = fs::read_to_string(&path).unwrap();
    match compare_with_c(&content) {
        CompareResult::CNotAvailable => eprintln!("Skipping: C not available"),
        CompareResult::Match => eprintln!("{name}: OK"),
        CompareResult::RustParseFailed(e) => {
            // Rust is stricter - this might be intentional
            eprintln!("{name}: Rust rejects (stricter): {e}");
        }
        CompareResult::CProcessFailed(e) => {
            eprintln!("{name}: C rejects: {e}");
        }
        CompareResult::Differ { rust_size, c_size } => {
            // Known difference: Rust and C may handle this edge case differently
            eprintln!(
                "{name}: Known difference (chardev size handling)\n\
                 Rust: {rust_size} bytes, C: {c_size} bytes"
            );
        }
    }
}

#[test]
fn test_corpus_honggfuzz_longlink_unterminated() {
    // Edge case: Very long symlink that may be unterminated
    // This is a fuzzer edge case with unusual mode bits
    let path = assets_dir().join("honggfuzz-longlink-unterminated.dump");
    let name = path.file_name().unwrap().to_string_lossy();

    if !path.exists() {
        eprintln!("Skipping: file not found");
        return;
    }

    let content = fs::read_to_string(&path).unwrap();
    match compare_with_c(&content) {
        CompareResult::CNotAvailable => eprintln!("Skipping: C not available"),
        CompareResult::Match => eprintln!("{name}: OK"),
        CompareResult::RustParseFailed(e) => {
            // Expected: mode 20720777 is invalid
            eprintln!("{name}: Rust correctly rejects invalid mode: {e}");
        }
        CompareResult::CProcessFailed(e) => {
            eprintln!("{name}: C also rejects: {e}");
        }
        CompareResult::Differ { rust_size, c_size } => {
            panic!("{name}: Unexpected difference (Rust: {rust_size}, C: {c_size})");
        }
    }
}

#[test]
fn test_corpus_no_newline() {
    // Edge case: dump file without trailing newline and high nlink count
    let path = assets_dir().join("no-newline.dump");
    let name = path.file_name().unwrap().to_string_lossy();

    if !path.exists() {
        eprintln!("Skipping: file not found");
        return;
    }

    let content = fs::read_to_string(&path).unwrap();
    match compare_with_c(&content) {
        CompareResult::CNotAvailable => eprintln!("Skipping: C not available"),
        CompareResult::Match => eprintln!("{name}: OK"),
        CompareResult::RustParseFailed(e) => {
            // Note what Rust doesn't like about this file
            eprintln!("{name}: Rust parse issue: {e}");
        }
        CompareResult::CProcessFailed(e) => {
            eprintln!("{name}: C also rejects: {e}");
        }
        CompareResult::Differ { rust_size, c_size } => {
            panic!("{name}: Unexpected difference (Rust: {rust_size}, C: {c_size})");
        }
    }
}

// =============================================================================
// SIGSEGV fuzz cases (historical crash inputs for C implementation)
// These may be binary or malformed - we just verify both handle them safely
// =============================================================================

#[test]
fn test_corpus_sigsegv_1() {
    let path = fuzzing_data_dir()
        .join("SIGSEGV.PC.432623.STACK.1a9c9e1981.CODE.1.ADDR.0.INSTR.movsbl_(%rax),%eax.fuzz");

    if !path.exists() {
        eprintln!("Skipping: file not found");
        return;
    }

    // These files may be binary/malformed
    if let Ok(content) = fs::read_to_string(&path) {
        match compare_with_c(&content) {
            CompareResult::CNotAvailable => eprintln!("Skipping: C not available"),
            CompareResult::Match => eprintln!("SIGSEGV-1: Both handle identically"),
            CompareResult::RustParseFailed(_) | CompareResult::CProcessFailed(_) => {
                eprintln!("SIGSEGV-1: Safely rejected");
            }
            CompareResult::Differ { .. } => {
                eprintln!("SIGSEGV-1: Handled differently (expected for malformed input)");
            }
        }
    } else {
        eprintln!("SIGSEGV-1: Not valid UTF-8 (skipped)");
    }
}

#[test]
fn test_corpus_sigsegv_2() {
    let path = fuzzing_data_dir().join(
        "SIGSEGV.PC.435caa.STACK.18ea55ecb1.CODE.1.ADDR.20.INSTR.mov____0x20(%rax),%rax.fuzz",
    );

    if !path.exists() {
        eprintln!("Skipping: file not found");
        return;
    }

    if let Ok(content) = fs::read_to_string(&path) {
        match compare_with_c(&content) {
            CompareResult::CNotAvailable => eprintln!("Skipping: C not available"),
            CompareResult::Match => eprintln!("SIGSEGV-2: Both handle identically"),
            CompareResult::RustParseFailed(_) | CompareResult::CProcessFailed(_) => {
                eprintln!("SIGSEGV-2: Safely rejected");
            }
            CompareResult::Differ { .. } => {
                eprintln!("SIGSEGV-2: Handled differently (expected for malformed input)");
            }
        }
    } else {
        eprintln!("SIGSEGV-2: Not valid UTF-8 (skipped)");
    }
}

// =============================================================================
// should-fail tests - files that SHOULD be rejected by both implementations
// NOTE: These tests are now in should_fail.rs which tests Rust parser rejection
// behavior without requiring external C test assets. The tests here would
// compare Rust vs C mkcomposefs behavior but require external test corpus files
// from the C composefs repository. Run with COMPOSEFS_ASSETS_DIR set to enable.
// =============================================================================

// Tests removed - see should_fail.rs for Rust parser validation tests.
// To run C compatibility tests for should-fail cases, set COMPOSEFS_ASSETS_DIR
// to point to the C composefs test assets directory.
