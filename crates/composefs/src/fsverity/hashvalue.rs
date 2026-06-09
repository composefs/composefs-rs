//! Hash value types and trait definitions for fs-verity.
//!
//! This module defines the [`FsVerityHashValue`] trait, concrete implementations
//! for SHA-256 and SHA-512 hash values, and the [`Algorithm`] type that
//! identifies an fs-verity algorithm configuration (hash + block size).

use core::{fmt, hash::Hash, str::FromStr};

use hex::FromHexError;
use sha2::{Digest, Sha256, Sha512, digest::FixedOutputReset, digest::Output};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Trait for fs-verity hash value types supporting SHA-256 and SHA-512.
///
/// This trait defines the interface for hash values used in fs-verity operations,
/// including serialization to/from hex strings and object store pathnames.
pub trait FsVerityHashValue
where
    Self: Clone,
    Self: From<Output<Self::Digest>>,
    Self: FromBytes + Immutable + IntoBytes + KnownLayout + Unaligned,
    Self: Hash + Eq,
    Self: fmt::Debug,
    Self: Send + Sync + Unpin + 'static,
{
    /// The underlying hash digest algorithm type.
    type Digest: Digest + FixedOutputReset + fmt::Debug;
    /// The fs-verity algorithm for this hash type.
    const ALGORITHM: Algorithm;
    /// An empty hash value with all bytes set to zero.
    const EMPTY: Self;

    /// Parse a hash value from a hexadecimal string.
    ///
    /// # Arguments
    /// * `hex` - A hexadecimal string representation of the hash
    ///
    /// # Returns
    /// The parsed hash value, or an error if the input is invalid.
    fn from_hex(hex: impl AsRef<[u8]>) -> Result<Self, FromHexError> {
        let mut value = Self::EMPTY;
        hex::decode_to_slice(hex.as_ref(), value.as_mut_bytes())?;
        Ok(value)
    }

    /// Parse a hash value from an object store directory number and basename.
    ///
    /// Object stores typically use a two-level hierarchy where the first byte
    /// of the hash determines the directory name and the remaining bytes form
    /// the basename.
    ///
    /// # Arguments
    /// * `dirnum` - The directory number (first byte of the hash)
    /// * `basename` - The hexadecimal basename (remaining bytes)
    ///
    /// # Returns
    /// The parsed hash value, or an error if the input is invalid.
    fn from_object_dir_and_basename(
        dirnum: u8,
        basename: impl AsRef<[u8]>,
    ) -> Result<Self, FromHexError> {
        let expected_size = 2 * (size_of::<Self>() - 1);
        let bytes = basename.as_ref();
        if bytes.len() != expected_size {
            return Err(FromHexError::InvalidStringLength);
        }
        let mut result = Self::EMPTY;
        result.as_mut_bytes()[0] = dirnum;
        hex::decode_to_slice(bytes, &mut result.as_mut_bytes()[1..])?;
        Ok(result)
    }

    /// Parse a hash value from a full object pathname.
    ///
    /// Parses a pathname in the format "xx/yyyyyy" where "xxyyyyyy" is the
    /// full hexadecimal hash. The prefix before the two-level hierarchy is ignored.
    ///
    /// # Arguments
    /// * `pathname` - The object pathname (e.g., "ab/cdef1234...")
    ///
    /// # Returns
    /// The parsed hash value, or an error if the input is invalid.
    fn from_object_pathname(pathname: impl AsRef<[u8]>) -> Result<Self, FromHexError> {
        // We want to the trailing part of "....../xx/yyyyyy" where xxyyyyyy is our hex length
        let min_size = 2 * size_of::<Self>() + 1;
        let bytes = pathname.as_ref();
        if bytes.len() < min_size {
            return Err(FromHexError::InvalidStringLength);
        }

        let trailing = &bytes[bytes.len() - min_size..];
        let mut result = Self::EMPTY;
        hex::decode_to_slice(&trailing[0..2], &mut result.as_mut_bytes()[0..1])?;
        if trailing[2] != b'/' {
            return Err(FromHexError::InvalidHexCharacter {
                c: trailing[2] as char,
                index: 2,
            });
        }
        hex::decode_to_slice(&trailing[3..], &mut result.as_mut_bytes()[1..])?;
        Ok(result)
    }

    /// Convert the hash value to an object pathname.
    ///
    /// Formats the hash as "xx/yyyyyy" where xx is the first byte in hex
    /// and yyyyyy is the remaining bytes in hex.
    ///
    /// # Returns
    /// A string in object pathname format.
    fn to_object_pathname(&self) -> String {
        format!(
            "{:02x}/{}",
            self.as_bytes()[0],
            hex::encode(&self.as_bytes()[1..])
        )
    }

    /// Convert the hash value to an object directory name.
    ///
    /// Returns just the first byte of the hash as a two-character hex string.
    ///
    /// # Returns
    /// A string representing the directory name.
    fn to_object_dir(&self) -> String {
        format!("{:02x}", self.as_bytes()[0])
    }

    /// Convert the hash value to a hexadecimal string.
    ///
    /// # Returns
    /// The full hash as a hex string.
    fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Convert the hash value to an identifier string with algorithm prefix.
    ///
    /// # Returns
    /// A string in the format "algorithm:hexhash" (e.g., "sha256:abc123...").
    fn to_id(&self) -> String {
        format!("{}:{}", Self::ALGORITHM.hash_name(), self.to_hex())
    }
}

impl fmt::Debug for Sha256HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::ALGORITHM.hash_name(), self.to_hex())
    }
}

impl fmt::Debug for Sha512HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::ALGORITHM.hash_name(), self.to_hex())
    }
}

/// A SHA-256 hash value for fs-verity operations.
///
/// This is a 32-byte hash value using the SHA-256 algorithm.
#[derive(Clone, Eq, FromBytes, Hash, Immutable, IntoBytes, KnownLayout, PartialEq, Unaligned)]
#[repr(C)]
pub struct Sha256HashValue([u8; 32]);

impl From<Output<Sha256>> for Sha256HashValue {
    fn from(value: Output<Sha256>) -> Self {
        Self(value.into())
    }
}

impl FsVerityHashValue for Sha256HashValue {
    type Digest = Sha256;
    const ALGORITHM: Algorithm = Algorithm::SHA256;
    const EMPTY: Self = Self([0; 32]);
}

/// A SHA-512 hash value for fs-verity operations.
///
/// This is a 64-byte hash value using the SHA-512 algorithm.
#[derive(Clone, Eq, FromBytes, Hash, Immutable, IntoBytes, KnownLayout, PartialEq, Unaligned)]
#[repr(C)]
pub struct Sha512HashValue([u8; 64]);

impl From<Output<Sha512>> for Sha512HashValue {
    fn from(value: Output<Sha512>) -> Self {
        Self(value.into())
    }
}

impl FsVerityHashValue for Sha512HashValue {
    type Digest = Sha512;
    const ALGORITHM: Algorithm = Algorithm::SHA512;
    const EMPTY: Self = Self([0; 64]);
}

/// Default log2 block size for fs-verity (4096 bytes).
pub const DEFAULT_LG_BLOCKSIZE: u8 = 12;

/// An fs-verity algorithm identifier.
///
/// Each variant corresponds to a hash function supported by the Linux
/// kernel's fs-verity subsystem.  The `lg_blocksize` field is the log2
/// of the Merkle tree block size (always 12, i.e. 4096 bytes, today).
///
/// The string representation is `fsverity-<hash>-<lg_blocksize>`,
/// e.g. `fsverity-sha256-12` or `fsverity-sha512-12`.
///
/// # Examples
///
/// ```
/// use composefs::fsverity::Algorithm;
///
/// let alg: Algorithm = "fsverity-sha512-12".parse().unwrap();
/// assert_eq!(alg.hash_name(), "sha512");
/// assert_eq!(alg.lg_blocksize(), 12);
/// assert_eq!(alg.kernel_id(), 2);
/// assert_eq!(alg.to_string(), "fsverity-sha512-12");
///
/// // Construct from a hash type at compile time
/// use composefs::fsverity::Sha256HashValue;
/// let alg = Algorithm::for_hash::<Sha256HashValue>();
/// assert_eq!(alg.to_string(), "fsverity-sha256-12");
/// assert_eq!(alg.kernel_id(), 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// SHA-256 with the given log2 block size.
    Sha256 {
        /// Log2 of the Merkle tree block size (e.g. 12 for 4096 bytes).
        lg_blocksize: u8,
    },
    /// SHA-512 with the given log2 block size.
    Sha512 {
        /// Log2 of the Merkle tree block size (e.g. 12 for 4096 bytes).
        lg_blocksize: u8,
    },
}

/// Errors from parsing an [`Algorithm`] string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmParseError {
    /// The string does not start with `fsverity-`.
    MissingPrefix,
    /// The hash-blocksize separator is missing.
    MissingSeparator,
    /// The hash name is not recognised.
    UnknownHash(String),
    /// The log2 block size is not a valid number.
    InvalidBlockSize(String),
    /// The log2 block size value is not currently supported.
    UnsupportedBlockSize(u8),
}

impl fmt::Display for AlgorithmParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => write!(f, "algorithm must start with 'fsverity-'"),
            Self::MissingSeparator => {
                write!(f, "algorithm must be 'fsverity-<hash>-<lg_blocksize>'")
            }
            Self::UnknownHash(h) => {
                write!(
                    f,
                    "unsupported hash algorithm '{h}' (expected sha256 or sha512)"
                )
            }
            Self::InvalidBlockSize(s) => write!(f, "invalid lg_blocksize '{s}'"),
            Self::UnsupportedBlockSize(n) => write!(
                f,
                "unsupported lg_blocksize {n} (only {DEFAULT_LG_BLOCKSIZE} is currently supported)"
            ),
        }
    }
}

impl std::error::Error for AlgorithmParseError {}

impl Algorithm {
    /// SHA-256 with the default block size (convenience constant).
    pub const SHA256: Self = Self::Sha256 {
        lg_blocksize: DEFAULT_LG_BLOCKSIZE,
    };

    /// SHA-512 with the default block size (convenience constant).
    pub const SHA512: Self = Self::Sha512 {
        lg_blocksize: DEFAULT_LG_BLOCKSIZE,
    };

    /// Build the algorithm identifier for a given [`FsVerityHashValue`] type.
    pub fn for_hash<H: FsVerityHashValue>() -> Self {
        H::ALGORITHM
    }

    /// The hash algorithm name (e.g. `"sha256"` or `"sha512"`).
    pub const fn hash_name(&self) -> &'static str {
        match self {
            Self::Sha256 { .. } => "sha256",
            Self::Sha512 { .. } => "sha512",
        }
    }

    /// The Linux kernel `FS_VERITY_HASH_ALGORITHM_*` identifier.
    ///
    /// Returns 1 for SHA-256, 2 for SHA-512.
    pub const fn kernel_id(&self) -> u8 {
        match self {
            Self::Sha256 { .. } => 1,
            Self::Sha512 { .. } => 2,
        }
    }

    /// The log2 block size (e.g. `12` for 4096-byte blocks).
    pub const fn lg_blocksize(&self) -> u8 {
        match self {
            Self::Sha256 { lg_blocksize } | Self::Sha512 { lg_blocksize } => *lg_blocksize,
        }
    }

    /// The Merkle-tree block size in bytes (e.g. 4096 for lg_blocksize 12).
    pub const fn block_size(&self) -> u32 {
        1u32 << self.lg_blocksize()
    }

    /// The digest size in bytes for this algorithm's hash
    /// (32 for SHA-256, 64 for SHA-512).
    pub const fn digest_size(&self) -> usize {
        match self {
            Self::Sha256 { .. } => 32,
            Self::Sha512 { .. } => 64,
        }
    }

    /// Check whether this algorithm is compatible with the given hash type.
    pub fn is_compatible<H: FsVerityHashValue>(&self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(&H::ALGORITHM)
    }

    /// The suffix used in V1 kernel cmdline karg values.
    ///
    /// Returns `"<hash>-<lg_blocksize>"`, e.g. `"sha256-12"` or `"sha512-12"`.
    /// This is the part after `v1-` in the format descriptor (e.g. `v1-sha256-12` in
    /// `composefs.digest=v1-sha256-12:<hex>`).
    pub fn verity_suffix(&self) -> String {
        format!("{}-{}", self.hash_name(), self.lg_blocksize())
    }
}

impl FromStr for Algorithm {
    type Err = AlgorithmParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("fsverity-")
            .ok_or(AlgorithmParseError::MissingPrefix)?;
        let (hash, lg_bs) = rest
            .rsplit_once('-')
            .ok_or(AlgorithmParseError::MissingSeparator)?;

        let lg_blocksize: u8 = lg_bs
            .parse()
            .map_err(|_| AlgorithmParseError::InvalidBlockSize(lg_bs.to_owned()))?;
        if lg_blocksize != DEFAULT_LG_BLOCKSIZE {
            return Err(AlgorithmParseError::UnsupportedBlockSize(lg_blocksize));
        }

        match hash {
            "sha256" => Ok(Self::Sha256 { lg_blocksize }),
            "sha512" => Ok(Self::Sha512 { lg_blocksize }),
            other => Err(AlgorithmParseError::UnknownHash(other.to_owned())),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fsverity-{}-{}", self.hash_name(), self.lg_blocksize())
    }
}

impl serde::Serialize for Algorithm {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Algorithm {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
#[cfg(test)]
mod test {
    use super::*;

    fn test_fsverity_hash<H: FsVerityHashValue>() {
        let len = size_of::<H>();
        let hexlen = len * 2;

        let hex = H::EMPTY.to_hex();
        assert_eq!(hex.as_bytes(), [b'0'].repeat(hexlen));

        assert_eq!(
            H::EMPTY.to_id(),
            format!("{}:{}", H::ALGORITHM.hash_name(), hex)
        );
        assert_eq!(
            format!("{:?}", H::EMPTY),
            format!("{}:{}", H::ALGORITHM.hash_name(), hex)
        );

        assert_eq!(H::from_hex(&hex), Ok(H::EMPTY));

        assert_eq!(H::from_hex("lol"), Err(FromHexError::OddLength));
        assert_eq!(H::from_hex("lolo"), Err(FromHexError::InvalidStringLength));
        assert_eq!(
            H::from_hex([b'l'].repeat(hexlen)),
            Err(FromHexError::InvalidHexCharacter { c: 'l', index: 0 })
        );

        assert_eq!(H::from_object_dir_and_basename(0, &hex[2..]), Ok(H::EMPTY));

        assert_eq!(H::from_object_dir_and_basename(0, &hex[2..]), Ok(H::EMPTY));

        assert_eq!(
            H::from_object_dir_and_basename(0, "lol"),
            Err(FromHexError::InvalidStringLength)
        );

        assert_eq!(
            H::from_object_dir_and_basename(0, [b'l'].repeat(hexlen - 2)),
            Err(FromHexError::InvalidHexCharacter { c: 'l', index: 0 })
        );

        assert_eq!(
            H::from_object_pathname(format!("{}/{}", &hex[0..2], &hex[2..])),
            Ok(H::EMPTY)
        );

        assert_eq!(
            H::from_object_pathname(format!("../this/is/ignored/{}/{}", &hex[0..2], &hex[2..])),
            Ok(H::EMPTY)
        );

        assert_eq!(
            H::from_object_pathname(&hex),
            Err(FromHexError::InvalidStringLength)
        );

        assert_eq!(
            H::from_object_pathname("lol"),
            Err(FromHexError::InvalidStringLength)
        );

        assert_eq!(
            H::from_object_pathname([b'l'].repeat(hexlen + 1)),
            Err(FromHexError::InvalidHexCharacter { c: 'l', index: 0 })
        );

        assert_eq!(
            H::from_object_pathname(format!("{}0{}", &hex[0..2], &hex[2..])),
            Err(FromHexError::InvalidHexCharacter { c: '0', index: 2 })
        );
    }

    #[test]
    fn test_sha256hashvalue() {
        test_fsverity_hash::<Sha256HashValue>();
    }

    #[test]
    fn test_sha512hashvalue() {
        test_fsverity_hash::<Sha512HashValue>();
    }

    #[test]
    fn test_algorithm_for_hash() {
        let a256 = Algorithm::for_hash::<Sha256HashValue>();
        assert_eq!(a256.hash_name(), "sha256");
        assert_eq!(a256.kernel_id(), 1);
        assert_eq!(a256.lg_blocksize(), 12);
        assert_eq!(a256.to_string(), "fsverity-sha256-12");
        assert!(a256.is_compatible::<Sha256HashValue>());
        assert!(!a256.is_compatible::<Sha512HashValue>());

        let a512 = Algorithm::for_hash::<Sha512HashValue>();
        assert_eq!(a512.hash_name(), "sha512");
        assert_eq!(a512.kernel_id(), 2);
        assert_eq!(a512.to_string(), "fsverity-sha512-12");
        assert!(a512.is_compatible::<Sha512HashValue>());
        assert!(!a512.is_compatible::<Sha256HashValue>());
    }

    #[test]
    fn test_algorithm_parse_roundtrip() {
        for s in ["fsverity-sha256-12", "fsverity-sha512-12"] {
            let alg: Algorithm = s.parse().unwrap();
            assert_eq!(alg.to_string(), s);
        }
    }

    #[test]
    fn test_algorithm_parse_errors() {
        let cases = [
            ("sha256-12", AlgorithmParseError::MissingPrefix),
            ("garbage", AlgorithmParseError::MissingPrefix),
            ("fsverity-sha256", AlgorithmParseError::MissingSeparator),
            (
                "fsverity-sha1-12",
                AlgorithmParseError::UnknownHash("sha1".to_owned()),
            ),
            (
                "fsverity-sha256-abc",
                AlgorithmParseError::InvalidBlockSize("abc".to_owned()),
            ),
            (
                "fsverity-sha256-16",
                AlgorithmParseError::UnsupportedBlockSize(16),
            ),
        ];
        for (input, expected) in cases {
            let err = input.parse::<Algorithm>().unwrap_err();
            assert_eq!(err, expected, "input: {input}");
        }
    }

    #[test]
    fn test_algorithm_equality() {
        let a: Algorithm = "fsverity-sha512-12".parse().unwrap();
        let b = Algorithm::for_hash::<Sha512HashValue>();
        assert_eq!(a, b);
    }
}
