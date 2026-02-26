//! Composefs-specific EROFS structures and overlay metadata.
//!
//! This module defines EROFS structures specific to composefs usage,
//! particularly overlay metadata for fs-verity integration.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::fsverity::FsVerityHashValue;

/* From linux/fs/overlayfs/overlayfs.h struct ovl_metacopy */
/// Overlay metacopy xattr structure containing fs-verity digest.
///
/// This structure is stored as the value of the `trusted.overlay.metacopy`
/// extended attribute on composefs files that reference external backing storage.
#[derive(Debug, FromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C)]
pub struct OverlayMetacopy<H: FsVerityHashValue> {
    version: u8,
    len: u8,
    flags: u8,
    digest_algo: u8,
    /// The fs-verity digest of the backing file.
    pub digest: H,
}

impl<H: FsVerityHashValue> OverlayMetacopy<H> {
    pub(super) fn new(digest: &H) -> Self {
        Self {
            version: 0,
            len: size_of::<Self>() as u8,
            flags: 0,
            digest_algo: H::ALGORITHM,
            digest: digest.clone(),
        }
    }

    /// Returns true if this metacopy structure has valid header fields.
    pub fn valid(&self) -> bool {
        self.version == 0
            && self.len == size_of::<Self>() as u8
            && self.flags == 0
            && self.digest_algo == H::ALGORITHM
    }
}
