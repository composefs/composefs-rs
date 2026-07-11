//! Construction of the `fsverity_formatted_digest` byte buffer.
//!
//! The kernel verifies PKCS#7 signatures over a specific byte structure called
//! `fsverity_formatted_digest`. This module provides functions to construct that
//! structure from either typed hash values or raw algorithm + digest bytes.
//!
//! See <https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#built-in-signature-verification>

use super::FsVerityHashValue;

/// The ASCII magic bytes at the start of a `fsverity_formatted_digest`.
const FSVERITY_MAGIC: &[u8; 8] = b"FSVerity";

/// Constructs the `fsverity_formatted_digest` byte buffer.
///
/// This is the data that must be signed with PKCS#7 to create a kernel-compatible
/// fsverity signature. The kernel reconstructs this structure from the measured
/// digest and verifies the signature against it.
///
/// Layout:
/// - `[0..8]`: `"FSVerity"` ASCII magic
/// - `[8..10]`: hash algorithm (u16 LE, 1=SHA-256, 2=SHA-512)
/// - `[10..12]`: digest size in bytes (u16 LE)
/// - `[12..]`: raw digest bytes
pub fn format_fsverity_digest<H: FsVerityHashValue>(digest: &H) -> Vec<u8> {
    let digest_bytes = digest.as_bytes();
    format_fsverity_digest_raw(H::ALGORITHM.kernel_id(), digest_bytes)
}

/// Constructs the `fsverity_formatted_digest` from a raw algorithm identifier and digest bytes.
///
/// This is useful when the algorithm/digest are known dynamically rather than
/// via a typed `FsVerityHashValue`.
///
/// # Arguments
/// * `algorithm` - Kernel hash algorithm identifier (1=SHA-256, 2=SHA-512)
/// * `digest` - Raw digest bytes
pub fn format_fsverity_digest_raw(algorithm: u8, digest: &[u8]) -> Vec<u8> {
    let digest_size = digest.len() as u16;

    let mut buf = Vec::with_capacity(12 + digest.len());
    buf.extend_from_slice(FSVERITY_MAGIC);
    buf.extend_from_slice(&(algorithm as u16).to_le_bytes());
    buf.extend_from_slice(&digest_size.to_le_bytes());
    buf.extend_from_slice(digest);
    buf
}

#[cfg(test)]
mod tests {
    use zerocopy::IntoBytes;

    use super::*;
    use crate::fsverity::{Sha256HashValue, Sha512HashValue};

    #[test]
    fn test_format_sha256() {
        let digest = Sha256HashValue::from_hex(
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64",
        )
        .unwrap();
        let buf = format_fsverity_digest(&digest);

        // Total length: 8 (magic) + 2 (alg) + 2 (size) + 32 (digest) = 44
        assert_eq!(buf.len(), 44);
        assert_eq!(&buf[0..8], b"FSVerity");
        assert_eq!(u16::from_le_bytes([buf[8], buf[9]]), 1); // SHA-256
        assert_eq!(u16::from_le_bytes([buf[10], buf[11]]), 32);
        assert_eq!(&buf[12..], digest.as_bytes());
    }

    #[test]
    fn test_format_sha512() {
        let hex_str = "a".repeat(128); // 64 bytes
        let digest = Sha512HashValue::from_hex(&hex_str).unwrap();
        let buf = format_fsverity_digest(&digest);

        // Total length: 8 + 2 + 2 + 64 = 76
        assert_eq!(buf.len(), 76);
        assert_eq!(&buf[0..8], b"FSVerity");
        assert_eq!(u16::from_le_bytes([buf[8], buf[9]]), 2); // SHA-512
        assert_eq!(u16::from_le_bytes([buf[10], buf[11]]), 64);
        assert_eq!(&buf[12..], digest.as_bytes());
    }

    #[test]
    fn test_format_roundtrip() {
        let digest = Sha256HashValue::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let buf = format_fsverity_digest(&digest);

        // Parse the fields back out
        let magic = &buf[0..8];
        let alg = u16::from_le_bytes([buf[8], buf[9]]);
        let size = u16::from_le_bytes([buf[10], buf[11]]);
        let raw_digest = &buf[12..];

        assert_eq!(magic, b"FSVerity");
        assert_eq!(alg, 1);
        assert_eq!(size, 32);
        assert_eq!(raw_digest, digest.as_bytes());
    }

    #[test]
    fn test_format_raw_matches_typed() {
        let digest = Sha256HashValue::from_hex(
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64",
        )
        .unwrap();

        let typed = format_fsverity_digest(&digest);
        let raw = format_fsverity_digest_raw(1, digest.as_bytes());
        assert_eq!(typed, raw);
    }
}
