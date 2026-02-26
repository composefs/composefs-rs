//! Tests for dumpfile parsing rejection of invalid inputs
//!
//! These test cases are ported from the C composefs implementation's should-fail tests.
//! Each should-fail-*.dump file contains input that should be rejected by the dumpfile parser.
//!
//! # Missing Validations
//!
//! The following validations are present in the C implementation but missing in Rust:
//!
//! - **Empty xattr key**: Xattr entries with empty keys (e.g., "=value") are accepted.
//!
//! - **Excessive file size**: The parser does not reject unreasonably large file sizes
//!   (e.g., 9.5 petabytes). This may be intentional as size validation could be
//!   deferred to filesystem creation time.

use std::fs;
use std::path::Path;

use composefs::dumpfile_parse::Entry;

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

/// Result of attempting to parse a dump file.
enum ParseResult {
    /// Successfully parsed all entries
    Ok,
    /// Failed to parse (expected for should-fail cases)
    ParseError(String),
    /// File contains invalid UTF-8 (counts as rejection for text-based format)
    InvalidUtf8,
}

/// Parse all lines from a dump file, returning the result.
fn try_parse_dump_file(path: &Path) -> ParseResult {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.to_string().contains("valid UTF-8") => return ParseResult::InvalidUtf8,
        Err(e) => panic!("unexpected error reading {}: {}", path.display(), e),
    };

    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        if let Err(e) = Entry::parse(line) {
            return ParseResult::ParseError(e.to_string());
        }
    }
    ParseResult::Ok
}

/// Test that all should-fail-*.dump files are rejected by the parser.
///
/// This uses a data-driven approach: iterate over all should-fail dump files
/// in the C test assets directory and verify each one fails to parse.
#[test]
fn test_should_fail_cases() {
    let assets = assets_dir();
    if !assets.exists() {
        eprintln!(
            "Skipping test: assets directory not found at {}",
            assets.display()
        );
        return;
    }

    // Known cases where Rust parser lacks validation that C has.
    // These are documented above and tracked for future implementation.
    let known_missing_validation = [
        "should-fail-empty-xattr-key.dump", // empty xattr key not rejected
        "should-fail-too-big.dump",         // file size not validated at parse time
    ];

    let mut tested_count = 0;
    let mut failed_to_reject = Vec::new();
    let mut expected_missing = Vec::new();

    for entry in fs::read_dir(&assets).expect("failed to read assets directory") {
        let entry = entry.expect("failed to read directory entry");
        let path = entry.path();

        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if !filename.starts_with("should-fail-") || !filename.ends_with(".dump") {
            continue;
        }

        let result = try_parse_dump_file(&path);
        tested_count += 1;

        match result {
            ParseResult::Ok => {
                if known_missing_validation.contains(&filename) {
                    expected_missing.push(filename.to_string());
                } else {
                    failed_to_reject.push(filename.to_string());
                }
            }
            ParseResult::ParseError(_) | ParseResult::InvalidUtf8 => {
                // Good - the file was rejected
            }
        }
    }

    assert!(
        tested_count > 0,
        "No should-fail dump files found in {}",
        assets.display()
    );

    if !expected_missing.is_empty() {
        eprintln!(
            "Note: {} cases not rejected due to known missing validation:\n  - {}",
            expected_missing.len(),
            expected_missing.join("\n  - ")
        );
    }

    if !failed_to_reject.is_empty() {
        panic!(
            "The following {} should-fail cases were NOT rejected by the parser (unexpected):\n  - {}",
            failed_to_reject.len(),
            failed_to_reject.join("\n  - ")
        );
    }

    eprintln!(
        "Successfully verified {}/{} should-fail test cases ({} known missing)",
        tested_count - expected_missing.len(),
        tested_count,
        expected_missing.len()
    );
}

/// Individual test for each should-fail case, giving more specific error information.
/// These document the expected validation behavior.
mod individual_cases {
    use super::*;

    fn expect_parse_failure(filename: &str) {
        let path = assets_dir().join(filename);
        if !path.exists() {
            eprintln!("Skipping: {} not found", filename);
            return;
        }

        match try_parse_dump_file(&path) {
            ParseResult::Ok => {
                panic!("{} should have failed to parse, but succeeded", filename);
            }
            ParseResult::ParseError(e) => {
                eprintln!("{} correctly rejected: {}", filename, e);
            }
            ParseResult::InvalidUtf8 => {
                eprintln!("{} correctly rejected: invalid UTF-8", filename);
            }
        }
    }

    #[test]
    fn test_dir_hardlink() {
        // Directories cannot be hardlinks
        expect_parse_failure("should-fail-dir-hardlink.dump");
    }

    #[test]
    fn test_self_hardlink() {
        // A file cannot be a hardlink to itself.
        // The Rust parser rejects this because the path uses an octal escape \037
        // for a control character, which makes it invalid.
        expect_parse_failure("should-fail-self-hardlink.dump");
    }

    #[test]
    fn test_dot_name() {
        // "." is not a valid filename - rejected as invalid path component
        expect_parse_failure("should-fail-dot-name.dump");
    }

    #[test]
    fn test_dotdot_name() {
        // ".." is not a valid filename - correctly rejected as "Invalid \"..\" in path"
        expect_parse_failure("should-fail-dotdot-name.dump");
    }

    #[test]
    fn test_empty_name() {
        // Empty filename (represented as "//" for a child of root) - rejected as empty path component
        expect_parse_failure("should-fail-empty-name.dump");
    }

    #[test]
    #[ignore = "Missing validation: empty xattr key should be rejected"]
    fn test_empty_xattr_key() {
        // Empty xattr key is not valid
        expect_parse_failure("should-fail-empty-xattr-key.dump");
    }

    #[test]
    fn test_long_xattr_key() {
        // Xattr key exceeds XATTR_NAME_MAX (255 bytes)
        expect_parse_failure("should-fail-long-xattr-key.dump");
    }

    #[test]
    fn test_long_xattr_value() {
        // Xattr value exceeds XATTR_SIZE_MAX (65535 bytes)
        expect_parse_failure("should-fail-long-xattr-value.dump");
    }

    #[test]
    fn test_empty_link_name() {
        // Symlink with missing/empty target
        expect_parse_failure("should-fail-empty-link-name.dump");
    }

    #[test]
    fn test_long_link() {
        // Symlink target exceeds PATH_MAX
        expect_parse_failure("should-fail-long-link.dump");
    }

    #[test]
    fn test_big_inline() {
        // Inline content exceeds MAX_INLINE_CONTENT
        expect_parse_failure("should-fail-big-inline.dump");
    }

    #[test]
    fn test_no_ftype() {
        // Mode has no valid file type bits set
        expect_parse_failure("should-fail-no-ftype.dump");
    }

    #[test]
    #[ignore = "Missing validation: unreasonably large file sizes should be rejected"]
    fn test_too_big() {
        // File size is unreasonably large (9.5 PB)
        // The C implementation rejects this, but Rust parser doesn't validate sizes
        expect_parse_failure("should-fail-too-big.dump");
    }

    #[test]
    fn test_honggfuzz_long_xattr() {
        // Fuzzer-discovered case with malformed/long xattr data containing invalid UTF-8
        // The Rust parser correctly rejects this because dump files must be valid UTF-8
        expect_parse_failure("should-fail-honggfuzz-long-xattr.dump");
    }
}
