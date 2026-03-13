//! High-level filesystem operations for composefs trees.
//!
//! This module provides convenience methods for common operations on
//! FileSystem objects, including computing image IDs, committing to
//! repositories, and generating dumpfiles.

use anyhow::Result;
use fn_error_context::context;

use crate::{
    dumpfile::write_dumpfile,
    erofs::writer::mkfs_erofs,
    fsverity::{FsVerityHashValue, compute_verity},
    repository::Repository,
    tree::FileSystem,
};

impl<ObjectID: FsVerityHashValue> FileSystem<ObjectID> {
    /// Commits this filesystem as an EROFS image to the repository.
    ///
    /// Generates an EROFS filesystem image and writes it to the repository
    /// with the optional name. Returns the fsverity digest of the committed image.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    #[context("Committing filesystem as EROFS image")]
    pub fn commit_image(
        &self,
        repository: &Repository<ObjectID>,
        image_name: Option<&str>,
    ) -> Result<ObjectID> {
        repository.write_image(image_name, &mkfs_erofs(self))
    }

    /// Computes the fsverity digest for this filesystem as an EROFS image.
    ///
    /// Generates the EROFS image and returns its fsverity digest without
    /// writing to a repository.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    pub fn compute_image_id(&self) -> ObjectID {
        compute_verity(&mkfs_erofs(self))
    }

    /// Generate the EROFS image and compute its fs-verity digest.
    ///
    /// Returns the raw EROFS image bytes alongside the fs-verity digest.
    /// Unlike `compute_image_id()` which discards the bytes, this preserves
    /// them for inclusion in composefs artifacts.
    pub fn generate_erofs_image(&self) -> (Box<[u8]>, ObjectID) {
        let erofs_bytes = mkfs_erofs(self);
        let digest = compute_verity(&erofs_bytes);
        (erofs_bytes, digest)
    }

    /// Prints this filesystem in dumpfile format to stdout.
    ///
    /// Serializes the entire filesystem tree to stdout in composefs dumpfile
    /// text format.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    #[context("Printing filesystem as dumpfile")]
    pub fn print_dumpfile(&self) -> Result<()> {
        write_dumpfile(&mut std::io::stdout(), self)
    }
}
