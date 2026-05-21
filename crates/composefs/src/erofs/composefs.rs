//! Composefs-specific EROFS structures and overlay metadata.
//!
//! This module defines EROFS structures specific to composefs usage,
//! particularly overlay metadata for fs-verity integration.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::fsverity::FsVerityHashValue;

/// Overlay metacopy xattr structure for fs-verity digest storage.
///
/// From linux/fs/overlayfs/overlayfs.h struct ovl_metacopy
#[derive(Debug, FromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C)]
pub struct OverlayMetacopy<H: FsVerityHashValue> {
    version: u8,
    len: u8,
    flags: u8,
    digest_algo: u8,
    /// The fs-verity digest value.
    pub digest: H,
}

impl<H: FsVerityHashValue> OverlayMetacopy<H> {
    /// Creates a new overlay metacopy entry with the given digest.
    pub fn new(digest: &H) -> Self {
        Self {
            version: 0,
            len: size_of::<Self>() as u8,
            flags: 0,
            digest_algo: H::ALGORITHM.kernel_id(),
            digest: digest.clone(),
        }
    }

    /// Checks whether this metacopy entry is valid.
    pub fn valid(&self) -> bool {
        self.version == 0
            && self.len == size_of::<Self>() as u8
            && self.flags == 0
            && self.digest_algo == H::ALGORITHM.kernel_id()
    }

    pub(super) fn version(&self) -> u8 {
        self.version
    }

    pub(super) fn len(&self) -> u8 {
        self.len
    }

    pub(super) fn flags(&self) -> u8 {
        self.flags
    }

    pub(super) fn digest_algo(&self) -> u8 {
        self.digest_algo
    }
}
