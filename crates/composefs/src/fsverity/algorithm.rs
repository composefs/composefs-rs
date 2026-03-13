//! Composefs algorithm identifiers for OCI sealing.
//!
//! Composefs uses a string format `fsverity-{hash}-{blocksizebits}` (e.g. `fsverity-sha512-12`)
//! to identify the combination of hash algorithm and block size used for
//! fsverity computation. The `fsverity-` prefix makes clear this is an fsverity
//! Merkle tree digest, not a simple hash. This module provides parsing and
//! mapping to kernel constants.

use std::fmt;

/// A composefs fsverity algorithm identifier.
///
/// Combines a hash algorithm with a block size, encoded as `fsverity-{hash}-{blocksizebits}`.
/// For example, `fsverity-sha512-12` means SHA-512 with 4096-byte blocks (2^12).
/// The `fsverity-` prefix distinguishes these from simple hash digests.
///
/// The kernel uses no salt with composefs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ComposeFsAlgorithm {
    /// Kernel algorithm identifier (FS_VERITY_HASH_ALG_SHA256=1, FS_VERITY_HASH_ALG_SHA512=2)
    algorithm: u8,
    /// Log2 of the block size (e.g. 12 for 4096-byte blocks)
    log_block_size: u8,
}

/// SHA-256, 4096-byte blocks
pub const SHA256_12: ComposeFsAlgorithm = ComposeFsAlgorithm {
    algorithm: 1,
    log_block_size: 12,
};

/// SHA-512, 4096-byte blocks (recommended default)
pub const SHA512_12: ComposeFsAlgorithm = ComposeFsAlgorithm {
    algorithm: 2,
    log_block_size: 12,
};

/// SHA-256, 65536-byte blocks
pub const SHA256_16: ComposeFsAlgorithm = ComposeFsAlgorithm {
    algorithm: 1,
    log_block_size: 16,
};

impl ComposeFsAlgorithm {
    /// Kernel algorithm identifier (e.g. 1 for SHA-256, 2 for SHA-512).
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Log2 of the block size (e.g. 12 for 4096-byte blocks).
    pub const fn log_block_size(&self) -> u8 {
        self.log_block_size
    }

    /// Block size in bytes.
    pub const fn block_size(&self) -> u32 {
        1u32 << self.log_block_size
    }

    /// The hash algorithm name component (e.g. "sha256" or "sha512").
    pub const fn hash_name(&self) -> &'static str {
        match self.algorithm {
            1 => "sha256",
            2 => "sha512",
            _ => "unknown",
        }
    }

    /// The digest size in bytes for this algorithm.
    pub const fn digest_size(&self) -> usize {
        match self.algorithm {
            1 => 32,
            2 => 64,
            _ => 0,
        }
    }

    /// Parse from the composefs string format `fsverity-{hash}-{blocksizebits}`.
    ///
    /// Also accepts the legacy format without the `fsverity-` prefix for compatibility.
    ///
    /// # Examples
    /// ```
    /// use composefs::fsverity::algorithm::ComposeFsAlgorithm;
    /// let alg = ComposeFsAlgorithm::parse("fsverity-sha512-12").unwrap();
    /// assert_eq!(alg.algorithm(), 2);
    /// assert_eq!(alg.block_size(), 4096);
    /// ```
    pub fn parse(s: &str) -> Result<Self, ParseAlgorithmError> {
        // Strip optional fsverity- prefix for compatibility
        let s = s.strip_prefix("fsverity-").unwrap_or(s);

        let (hash, bits) = s
            .split_once('-')
            .ok_or_else(|| ParseAlgorithmError::Format(s.to_string()))?;

        let algorithm = match hash {
            "sha256" => 1u8,
            "sha512" => 2u8,
            _ => return Err(ParseAlgorithmError::UnknownHash(hash.to_string())),
        };

        let log_block_size: u8 = bits
            .parse()
            .map_err(|_| ParseAlgorithmError::InvalidBlockSize(bits.to_string()))?;

        // Sanity check: block size must be at least 1024 (10) and at most 65536 (16)
        if !(10..=16).contains(&log_block_size) {
            return Err(ParseAlgorithmError::InvalidBlockSize(bits.to_string()));
        }

        Ok(ComposeFsAlgorithm {
            algorithm,
            log_block_size,
        })
    }
}

impl fmt::Display for ComposeFsAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fsverity-{}-{}", self.hash_name(), self.log_block_size)
    }
}

/// Errors from parsing a composefs algorithm string.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ParseAlgorithmError {
    /// String does not contain a `-` separator.
    #[error("invalid algorithm format (expected 'hash-blocksizebits'): {0}")]
    Format(String),
    /// Unknown hash algorithm name.
    #[error("unknown hash algorithm: {0}")]
    UnknownHash(String),
    /// Block size bits value is not a valid number or out of range.
    #[error("invalid block size bits: {0}")]
    InvalidBlockSize(String),
}

impl std::str::FromStr for ComposeFsAlgorithm {
    type Err = ParseAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sha512_12() {
        let alg: ComposeFsAlgorithm = "fsverity-sha512-12".parse().unwrap();
        assert_eq!(alg.algorithm(), 2);
        assert_eq!(alg.log_block_size(), 12);
        assert_eq!(alg.block_size(), 4096);
        assert_eq!(alg.digest_size(), 64);
        assert_eq!(alg.hash_name(), "sha512");
        assert_eq!(alg.to_string(), "fsverity-sha512-12");
    }

    #[test]
    fn parse_sha256_12() {
        let alg: ComposeFsAlgorithm = "fsverity-sha256-12".parse().unwrap();
        assert_eq!(alg.algorithm(), 1);
        assert_eq!(alg.log_block_size(), 12);
        assert_eq!(alg.block_size(), 4096);
        assert_eq!(alg.digest_size(), 32);
        assert_eq!(alg.hash_name(), "sha256");
        assert_eq!(alg.to_string(), "fsverity-sha256-12");
    }

    #[test]
    fn parse_sha256_16() {
        let alg: ComposeFsAlgorithm = "fsverity-sha256-16".parse().unwrap();
        assert_eq!(alg.algorithm(), 1);
        assert_eq!(alg.log_block_size(), 16);
        assert_eq!(alg.block_size(), 65536);
    }

    #[test]
    fn parse_legacy_format() {
        // Legacy format without fsverity- prefix should still work
        let alg: ComposeFsAlgorithm = "sha512-12".parse().unwrap();
        assert_eq!(alg.algorithm(), 2);
        assert_eq!(alg.log_block_size(), 12);
        // But Display always uses the new format
        assert_eq!(alg.to_string(), "fsverity-sha512-12");
    }

    #[test]
    fn constants_match_parse() {
        assert_eq!(SHA512_12, "fsverity-sha512-12".parse().unwrap());
        assert_eq!(SHA256_12, "fsverity-sha256-12".parse().unwrap());
        assert_eq!(SHA256_16, "fsverity-sha256-16".parse().unwrap());
        // Also match legacy format
        assert_eq!(SHA512_12, "sha512-12".parse().unwrap());
        assert_eq!(SHA256_12, "sha256-12".parse().unwrap());
    }

    #[test]
    fn reject_invalid() {
        assert!(ComposeFsAlgorithm::parse("sha512").is_err());
        assert!(ComposeFsAlgorithm::parse("sha384-12").is_err());
        assert!(ComposeFsAlgorithm::parse("sha256-99").is_err());
        assert!(ComposeFsAlgorithm::parse("sha256-9").is_err());
        assert!(ComposeFsAlgorithm::parse("").is_err());
        assert!(ComposeFsAlgorithm::parse("-12").is_err());
        assert!(ComposeFsAlgorithm::parse("fsverity-sha384-12").is_err());
    }

    #[test]
    fn roundtrip() {
        for s in [
            "fsverity-sha256-12",
            "fsverity-sha512-12",
            "fsverity-sha256-16",
        ] {
            let alg: ComposeFsAlgorithm = s.parse().unwrap();
            assert_eq!(alg.to_string(), s);
        }
    }
}
