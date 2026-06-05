//! Kernel command line parsing and manipulation.
//!
//! This module provides utilities for parsing and generating kernel command line arguments,
//! with specific support for composefs parameters. It handles the kernel's simple quoting
//! mechanism and provides functions to extract and create composefs= arguments with optional
//! insecure mode indicators.

use anyhow::{Context, Result};
use composefs::fsverity::{Algorithm, FsVerityHashValue};

/// Legacy kernel argument for V2 EROFS: `composefs=<hex_digest>`.
///
/// Shorthand for `composefs.digest=v2-<hash>-12:<hex>`.  Used in existing
/// sealed UKIs.  The initramfs checks for [`KARG_COMPOSEFS_DIGEST`] first,
/// then falls back to this.
pub const KARG_V2: &str = "composefs";

/// Self-describing kernel argument: `composefs.digest=<version>-<hash>-<lg>:<hex>`.
///
/// The value encodes the EROFS format version, hash algorithm, and block size,
/// e.g. `composefs.digest=v1-sha256-12:<hex>` or `composefs.digest=v2-sha512-12:<hex>`.
/// Both `v1` and `v2` are accepted; `composefs=<hex>` is a legacy alias for
/// the `v2` form.
///
/// Multiple entries may appear on the cmdline with different format/algorithm
/// combinations; the initramfs tries each in order, mounting the first image
/// that exists in the repository.
pub const KARG_COMPOSEFS_DIGEST: &str = "composefs.digest";

/// A composefs kernel argument identifying which EROFS image to mount at boot.
///
/// Two variants exist to distinguish EROFS format versions:
/// - [`ComposefsCmdline::V2`]: V2 EROFS — either `composefs=<digest>` (legacy shorthand)
///   or `composefs.digest=v2-<hash>-<lg>:<digest>` (explicit form)
/// - [`ComposefsCmdline::V1`]: V1 EROFS — `composefs.digest=v1-<hash>-<lg>:<digest>`
///
/// The initramfs checks for `composefs.digest=` first (accepting both `v1` and `v2`
/// descriptors), then falls back to the legacy `composefs=` shorthand.
/// Multiple `composefs.digest=` entries may appear on the cmdline (different
/// format/algorithm combinations); the initramfs tries each in order, mounting
/// the first image that exists.
///
/// NOTE: The equivalent parsing logic in bootc's `crates/initramfs/src/lib.rs` must be
/// kept in sync with this file manually, since bootc does not yet depend on composefs-boot
/// directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposefsCmdline<ObjectID: FsVerityHashValue> {
    /// V2 EROFS image: embedded as `composefs=<hex-digest>` in the UKI cmdline.
    ///
    /// The `insecure` flag, when `true`, means the digest is prefixed with `?`
    /// (e.g. `composefs=?<hex>`), making fs-verity verification optional.
    V2 {
        /// The fs-verity hash of the EROFS image.
        digest: ObjectID,
        /// If `true`, a `?` prefix is added to the digest, making fs-verity
        /// verification optional at boot.
        insecure: bool,
    },
    /// V1 EROFS image: embedded as `composefs.digest=v1-<hash>-<lg>:<hex-digest>` in the UKI cmdline.
    ///
    /// The value encodes the algorithm, e.g. `composefs.digest=v1-sha256-12:<hex>`
    /// or `composefs.digest=v1-sha512-12:<hex>`.
    ///
    /// The `insecure` flag, when `true`, means the value is prefixed with `?`
    /// (e.g. `composefs.digest=?v1-sha512-12:<hex>`), making fs-verity verification optional.
    V1 {
        /// The fs-verity hash of the EROFS image.
        digest: ObjectID,
        /// If `true`, a `?` prefix is added before the format descriptor in the value,
        /// making fs-verity verification optional at boot.
        insecure: bool,
    },
}

impl<ObjectID: FsVerityHashValue> ComposefsCmdline<ObjectID> {
    /// Returns a reference to the hex digest, regardless of variant.
    ///
    /// Useful for looking up the image in `composefs/images/<digest>`.
    pub fn digest(&self) -> &ObjectID {
        match self {
            ComposefsCmdline::V2 { digest, .. } | ComposefsCmdline::V1 { digest, .. } => digest,
        }
    }

    /// Validates that this UKI cmdline's digest matches one of the acceptable
    /// boot image digests.
    ///
    /// With dual V1+V2 EROFS, a single composefs image is stored as two boot
    /// EROFS serializations with distinct digests; a UKI is sealed carrying
    /// exactly one of them. This accepts the UKI if its digest matches ANY of
    /// `acceptable`. Returns the matched (UKI's own) digest on success.
    pub fn validate_digest<'a>(
        &self,
        acceptable: impl IntoIterator<Item = &'a ObjectID>,
    ) -> Result<&ObjectID>
    where
        ObjectID: 'a,
    {
        let acceptable: Vec<&ObjectID> = acceptable.into_iter().collect();
        let uki_digest = self.digest();
        if acceptable.contains(&uki_digest) {
            return Ok(uki_digest);
        }
        let expected = acceptable
            .iter()
            .map(|id| format!("{id:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "The UKI has the wrong composefs digest (is '{uki_digest:?}', should be one of [{expected}])"
        )
    }

    /// Returns whether this karg is in insecure mode (fs-verity verification skipped).
    pub fn is_insecure(&self) -> bool {
        match self {
            ComposefsCmdline::V1 { insecure, .. } | ComposefsCmdline::V2 { insecure, .. } => {
                *insecure
            }
        }
    }

    /// Constructs a V2 cmdline value (`composefs=<hex>`).
    pub fn new_v2(digest: ObjectID, insecure: bool) -> Self {
        ComposefsCmdline::V2 { digest, insecure }
    }

    /// Constructs a V1 cmdline value (`composefs.digest=v1-<hash>-<lg>:<hex>`).
    pub fn new_v1(digest: ObjectID, insecure: bool) -> Self {
        ComposefsCmdline::V1 { digest, insecure }
    }

    /// Parses a [`ComposefsCmdline`] from a kernel command line string.
    ///
    /// Scans for `composefs.digest=` tokens first (→ [`ComposefsCmdline::V1`]).  Multiple
    /// such tokens may appear on the cmdline (different algorithms); the first one whose
    /// format descriptor matches the `ObjectID` algorithm is returned.  Then falls back to
    /// `composefs=` (→ [`ComposefsCmdline::V2`]).  Returns `None` if no matching token is
    /// present.
    ///
    /// # Errors
    ///
    /// Returns an error if a matching karg is found but the hex digest cannot be parsed
    /// for the given `ObjectID` type.
    pub fn from_cmdline(cmdline: &str) -> Result<Option<Self>> {
        let expected_hex_len = size_of::<ObjectID>() * 2;

        // V1: composefs.digest=v1-<hash>-<lg>:<hex>
        // Optional '?' insecure marker directly after '=': composefs.digest=?v1-sha256-12:<hex>
        // There may be multiple composefs.digest= tokens with different algorithms; find the
        // first one whose format descriptor matches this ObjectID type.
        let v1_key_prefix = format!("{KARG_COMPOSEFS_DIGEST}=");
        for token in split_cmdline(cmdline) {
            let Some(val) = token.strip_prefix(&v1_key_prefix) else {
                continue;
            };
            let (val_no_q, insecure) = if let Some(s) = val.strip_prefix('?') {
                (s, true)
            } else {
                (val, false)
            };
            let (desc, hex) = parse_digest_value(val_no_q)
                .with_context(|| format!("parsing {KARG_COMPOSEFS_DIGEST}= value: {val}"))?;
            if !desc.algorithm.is_compatible::<ObjectID>() {
                // Different algorithm (e.g. sha512 when we're sha256) — skip.
                continue;
            }
            let digest = ObjectID::from_hex(hex).with_context(|| {
                format!(
                    "parsing {KARG_COMPOSEFS_DIGEST}= hash: got {} hex chars, expected {} for {}",
                    hex.len(),
                    expected_hex_len,
                    ObjectID::ALGORITHM,
                )
            })?;
            return Ok(Some(match desc.version {
                1 => ComposefsCmdline::V1 { digest, insecure },
                _ => ComposefsCmdline::V2 { digest, insecure },
            }));
        }

        // V2: composefs=<hex>  (optional '?' prefix for insecure mode)
        if let Some(val) = get_cmdline_value(cmdline, &format!("{KARG_V2}=")) {
            let (hex, insecure) = if let Some(stripped) = val.strip_prefix('?') {
                (stripped, true)
            } else {
                (val, false)
            };
            let digest = ObjectID::from_hex(hex).with_context(|| {
                format!(
                    "parsing {KARG_V2}= hash: got {} hex chars, expected {} for {}",
                    hex.len(),
                    expected_hex_len,
                    ObjectID::ALGORITHM,
                )
            })?;
            return Ok(Some(ComposefsCmdline::V2 { digest, insecure }));
        }

        Ok(None)
    }

    /// Renders this value as a kernel command line fragment.
    ///
    /// - [`ComposefsCmdline::V1`] (secure)   → `"composefs.digest=v1-<hash>-<lg>:<hex>"`
    /// - [`ComposefsCmdline::V1`] (insecure) → `"composefs.digest=?v1-<hash>-<lg>:<hex>"`
    /// - [`ComposefsCmdline::V2`] (secure)   → `"composefs=<hex>"`
    /// - [`ComposefsCmdline::V2`] (insecure) → `"composefs=?<hex>"`
    pub fn to_cmdline_arg(&self) -> String {
        let verity_suffix = ObjectID::ALGORITHM.verity_suffix();
        match self {
            ComposefsCmdline::V1 {
                digest,
                insecure: false,
            } => format!(
                "{KARG_COMPOSEFS_DIGEST}=v1-{verity_suffix}:{}",
                digest.to_hex()
            ),
            ComposefsCmdline::V1 {
                digest,
                insecure: true,
            } => format!(
                "{KARG_COMPOSEFS_DIGEST}=?v1-{verity_suffix}:{}",
                digest.to_hex()
            ),
            ComposefsCmdline::V2 {
                digest,
                insecure: false,
            } => {
                format!("{KARG_V2}={}", digest.to_hex())
            }
            ComposefsCmdline::V2 {
                digest,
                insecure: true,
            } => {
                format!("{KARG_V2}=?{}", digest.to_hex())
            }
        }
    }
}

/// Perform kernel command line splitting.
///
/// The way this works in the kernel is to split on whitespace with an extremely simple quoting
/// mechanism: whitespace inside of double quotes is literal, but there is no escaping mechanism.
/// That means that having a literal double quote in the cmdline is effectively impossible.
pub fn split_cmdline(cmdline: &str) -> impl Iterator<Item = &str> {
    let mut in_quotes = false;

    cmdline.split(move |c: char| {
        if c == '"' {
            in_quotes = !in_quotes;
        }
        !in_quotes && c.is_ascii_whitespace()
    })
}

/// Gets the value of an entry from the kernel cmdline.
///
/// The prefix should be something like "composefs=".
///
/// This iterates the entries in the provided cmdline string searching for an entry that starts
/// with the provided prefix.  This will successfully handle quoting of other items in the cmdline,
/// but the value of the searched entry is returned verbatim (ie: not dequoted).
pub fn get_cmdline_value<'a>(cmdline: &'a str, prefix: &str) -> Option<&'a str> {
    split_cmdline(cmdline).find_map(|item| item.strip_prefix(prefix))
}

/// Parsed format descriptor from a `composefs.digest=` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestDescriptor {
    /// The EROFS format version (`v1` or `v2`).
    pub version: u32,
    /// The fs-verity algorithm (hash + blocksize).
    pub algorithm: Algorithm,
}

/// Parse a `composefs.digest=` value like `v1-sha256-12:<hex>` or `v2-sha512-12:<hex>`.
///
/// Returns `(descriptor, hex_digest)`.  Errors on malformed or unsupported
/// format descriptors (unknown version, bad hash name, unsupported blocksize).
pub fn parse_digest_value(s: &str) -> Result<(DigestDescriptor, &str)> {
    // Split "v1-sha256-12:<hex>" into descriptor "v1-sha256-12" and hex.
    let (descriptor, hex) = s
        .split_once(':')
        .with_context(|| format!("expected '<version>-<hash>-<blocksize>:<hex>', got: {s}"))?;

    // Split "v1-sha256-12" → version "v1", remainder "sha256-12".
    let (version_str, hash_and_bs) = descriptor
        .split_once('-')
        .with_context(|| format!("expected 'v<N>-<hash>-<blocksize>', got: {descriptor}"))?;

    let version = match version_str {
        "v1" => 1,
        "v2" => 2,
        _ => anyhow::bail!("unsupported format version '{version_str}'"),
    };

    // Reuse Algorithm's parser by prepending the expected "fsverity-" prefix.
    let algorithm: Algorithm = format!("fsverity-{hash_and_bs}")
        .parse()
        .with_context(|| format!("parsing algorithm from '{hash_and_bs}'"))?;

    Ok((DigestDescriptor { version, algorithm }, hex))
}

/// Creates a composefs kernel command line argument string.
///
/// # Arguments
///
/// * `id` - The composefs object ID as a hex string
/// * `insecure` - If true, prepends '?' to make fs-verity verification optional
/// * `version` - Which EROFS format version karg to emit
/// * `algorithm` - The fs-verity algorithm (used to build the V1 value prefix)
///
/// # Returns
///
/// A string like `"composefs.digest=v1-sha512-12:abc123"` (V1) or `"composefs=abc123"` (V2),
/// with optional `?` insecure marker for V1 (`composefs.digest=?v1-sha512-12:abc123`).
pub fn make_cmdline_composefs(
    id: &str,
    insecure: bool,
    version: composefs::erofs::format::FormatVersion,
    algorithm: composefs::fsverity::Algorithm,
) -> String {
    use composefs::erofs::format::FormatVersion;
    match version {
        // V0 and V1 both use the C-compatible compact-inode layout; same karg key.
        FormatVersion::V0 | FormatVersion::V1 => {
            let fmt_desc = format!("v1-{}", algorithm.verity_suffix());
            if insecure {
                format!("{KARG_COMPOSEFS_DIGEST}=?{fmt_desc}:{id}")
            } else {
                format!("{KARG_COMPOSEFS_DIGEST}={fmt_desc}:{id}")
            }
        }
        FormatVersion::V2 => {
            if insecure {
                format!("{KARG_V2}=?{id}")
            } else {
                format!("{KARG_V2}={id}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use composefs::fsverity::{Algorithm, Sha256HashValue, Sha512HashValue};

    use super::*;

    const SHA256_HEX: &str = "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52";
    const SHA512_HEX: &str = "6f06b5e82420abec546d6e6d3ddd612c50cfa9b707c129345b7ec16f456b92fe\
        35df68999b042e1a6a70dfe75f2fed8cf9f67afd0bf08d2374678d75e2f65a02";

    #[test]
    fn test_composefs_cmdline_v2_round_trip() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let karg = ComposefsCmdline::new_v2(digest.clone(), false);
        assert_eq!(karg.to_cmdline_arg(), format!("composefs={SHA256_HEX}"));

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V2 {
                digest,
                insecure: false
            }
        );
    }

    #[test]
    fn test_composefs_cmdline_v2_insecure_round_trip() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let karg = ComposefsCmdline::new_v2(digest.clone(), true);
        assert_eq!(karg.to_cmdline_arg(), format!("composefs=?{SHA256_HEX}"));

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V2 {
                digest,
                insecure: true
            }
        );
    }

    #[test]
    fn test_composefs_cmdline_v1_round_trip_sha256() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let karg = ComposefsCmdline::new_v1(digest.clone(), false);
        assert_eq!(
            karg.to_cmdline_arg(),
            format!("composefs.digest=v1-sha256-12:{SHA256_HEX}")
        );

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V1 {
                digest,
                insecure: false
            }
        );
    }

    #[test]
    fn test_composefs_cmdline_v1_round_trip_sha512() {
        let digest = Sha512HashValue::from_hex(SHA512_HEX).unwrap();
        let karg = ComposefsCmdline::new_v1(digest.clone(), false);
        assert_eq!(
            karg.to_cmdline_arg(),
            format!("composefs.digest=v1-sha512-12:{SHA512_HEX}")
        );

        let parsed = ComposefsCmdline::<Sha512HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V1 {
                digest,
                insecure: false
            }
        );
    }

    #[test]
    fn test_composefs_cmdline_v1_insecure_round_trip() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let karg = ComposefsCmdline::new_v1(digest.clone(), true);
        assert_eq!(
            karg.to_cmdline_arg(),
            format!("composefs.digest=?v1-sha256-12:{SHA256_HEX}")
        );

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V1 {
                digest,
                insecure: true
            }
        );
        assert!(parsed.is_insecure());
    }

    #[test]
    fn test_composefs_cmdline_v1_takes_priority_over_v2() {
        // When both kargs are present, V1 (composefs.digest=) should win.
        let hex_v1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hex_v2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let cmdline = format!("composefs={hex_v2} composefs.digest=v1-sha256-12:{hex_v1}");

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&cmdline)
            .unwrap()
            .unwrap();
        assert!(
            matches!(&parsed, ComposefsCmdline::V1 { digest, .. } if digest.to_hex() == hex_v1),
            "expected V1 variant with hex_v1, got {parsed:?}"
        );
    }

    #[test]
    fn test_composefs_cmdline_v1_cross_type_rejection() {
        // A sha512 V1 karg should NOT be parsed by the sha256 variant (returns None).
        let cmdline = format!("composefs.digest=v1-sha512-12:{SHA512_HEX}");
        let result = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&cmdline).unwrap();
        assert!(
            result.is_none(),
            "sha256 parser should not match sha512 karg, got {result:?}"
        );

        // And vice versa: sha256 V1 karg should not be parsed by the sha512 variant.
        let cmdline256 = format!("composefs.digest=v1-sha256-12:{SHA256_HEX}");
        let result512 = ComposefsCmdline::<Sha512HashValue>::from_cmdline(&cmdline256).unwrap();
        assert!(
            result512.is_none(),
            "sha512 parser should not match sha256 karg, got {result512:?}"
        );
    }

    #[test]
    fn test_composefs_cmdline_absent_returns_none() {
        assert!(
            ComposefsCmdline::<Sha256HashValue>::from_cmdline("quiet splash rw")
                .unwrap()
                .is_none()
        );
        assert!(
            ComposefsCmdline::<Sha256HashValue>::from_cmdline("")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_composefs_cmdline_invalid_hex_errors() {
        // Valid key present but digest is garbage.
        let err = ComposefsCmdline::<Sha256HashValue>::from_cmdline(
            "composefs.digest=v1-sha256-12:notahex",
        )
        .unwrap_err();
        assert!(err.to_string().contains("composefs.digest="));

        let err =
            ComposefsCmdline::<Sha256HashValue>::from_cmdline("composefs=notahex").unwrap_err();
        assert!(err.to_string().contains("composefs="));
    }

    #[test]
    fn test_composefs_cmdline_unsupported_blocksize_errors() {
        // Right hash, wrong blocksize → error (not silently skipped)
        let err = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&format!(
            "composefs.digest=v1-sha256-8:{SHA256_HEX}"
        ))
        .unwrap_err();
        // The root cause is AlgorithmParseError::UnsupportedBlockSize, wrapped by anyhow context.
        let chain = format!("{err:#}");
        assert!(
            chain.contains("unsupported"),
            "expected 'unsupported' in error chain, got: {chain}"
        );

        // Right hash (sha512), wrong blocksize
        let err = ComposefsCmdline::<Sha512HashValue>::from_cmdline(&format!(
            "composefs.digest=v1-sha512-99:{SHA512_HEX}"
        ))
        .unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("unsupported"),
            "expected 'unsupported' in error chain, got: {chain}"
        );

        // Unknown version → error
        let err = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&format!(
            "composefs.digest=v3-sha256-12:{SHA256_HEX}"
        ))
        .unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("unsupported format version"),
            "expected version error, got: {chain}"
        );
    }

    #[test]
    fn test_composefs_digest_v2_parsed_as_v2() {
        // composefs.digest=v2-sha256-12:<hex> should parse as V2, same as composefs=<hex>
        let cmdline = format!("composefs.digest=v2-sha256-12:{SHA256_HEX}");
        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&cmdline)
            .unwrap()
            .unwrap();
        assert!(
            matches!(parsed, ComposefsCmdline::V2 { .. }),
            "expected V2 variant, got {parsed:?}"
        );
        assert_eq!(parsed.digest().to_hex(), SHA256_HEX);
        assert!(!parsed.is_insecure());

        // Insecure variant
        let cmdline = format!("composefs.digest=?v2-sha512-12:{SHA512_HEX}");
        let parsed = ComposefsCmdline::<Sha512HashValue>::from_cmdline(&cmdline)
            .unwrap()
            .unwrap();
        assert!(matches!(
            parsed,
            ComposefsCmdline::V2 { insecure: true, .. }
        ));
    }

    #[test]
    fn test_digest_accessor() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let v1 = ComposefsCmdline::new_v1(digest.clone(), false);
        let v2 = ComposefsCmdline::new_v2(digest.clone(), false);
        assert_eq!(v1.digest(), &digest);
        assert_eq!(v2.digest(), &digest);
    }

    #[test]
    fn test_from_cmdline_v1() {
        let cmdline = format!("root=UUID=abc composefs.digest=v1-sha256-12:{SHA256_HEX} rw");
        let result = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&cmdline)
            .unwrap()
            .unwrap();
        assert!(matches!(result, ComposefsCmdline::V1 { .. }));
        assert_eq!(result.digest().to_hex(), SHA256_HEX);
        assert!(!result.is_insecure());
    }

    #[test]
    fn test_from_cmdline_v2_fallback() {
        let cmdline = format!("root=UUID=abc composefs={SHA256_HEX} rw");
        let result = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&cmdline)
            .unwrap()
            .unwrap();
        assert!(matches!(result, ComposefsCmdline::V2 { .. }));
        assert_eq!(result.digest().to_hex(), SHA256_HEX);
        assert!(!result.is_insecure());
    }

    #[test]
    fn test_from_cmdline_missing_returns_none() {
        let result = ComposefsCmdline::<Sha256HashValue>::from_cmdline("root=UUID=abc rw").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_from_cmdline_insecure_prefix() {
        let cmdline = format!("composefs=?{SHA256_HEX}");
        let result = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&cmdline)
            .unwrap()
            .unwrap();
        assert!(result.is_insecure());
        assert_eq!(result.digest().to_hex(), SHA256_HEX);
    }

    #[test]
    fn test_make_cmdline_composefs_v1() {
        use composefs::erofs::format::FormatVersion;
        let result =
            make_cmdline_composefs(SHA256_HEX, false, FormatVersion::V1, Algorithm::SHA256);
        assert_eq!(
            result,
            format!("composefs.digest=v1-sha256-12:{SHA256_HEX}")
        );
    }

    #[test]
    fn test_make_cmdline_composefs_v1_sha512() {
        use composefs::erofs::format::FormatVersion;
        let result =
            make_cmdline_composefs(SHA512_HEX, false, FormatVersion::V1, Algorithm::SHA512);
        assert_eq!(
            result,
            format!("composefs.digest=v1-sha512-12:{SHA512_HEX}")
        );
    }

    #[test]
    fn test_validate_digest() {
        let v1_digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let other = Sha256HashValue::from_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        let karg = ComposefsCmdline::new_v2(v1_digest.clone(), false);

        // Digest present in a multi-element acceptable set → Ok with the match.
        let acceptable = [&other, &v1_digest];
        let matched = karg.validate_digest(acceptable.iter().copied()).unwrap();
        assert_eq!(matched, &v1_digest);

        // Digest absent → Err mentioning "should be one of".
        let err = karg.validate_digest(std::iter::once(&other)).unwrap_err();
        assert!(
            err.to_string().contains("should be one of"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn test_make_cmdline_composefs_v2_insecure() {
        use composefs::erofs::format::FormatVersion;
        let result = make_cmdline_composefs(SHA256_HEX, true, FormatVersion::V2, Algorithm::SHA256);
        assert_eq!(result, format!("composefs=?{SHA256_HEX}"));
    }
}
