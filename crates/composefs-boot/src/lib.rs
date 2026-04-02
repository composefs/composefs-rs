//! Boot integration for composefs filesystem images.
//!
//! This crate provides functionality to transform composefs filesystem images for boot
//! scenarios by extracting boot resources, applying SELinux labels, and preparing
//! bootloader entries. It supports both Boot Loader Specification (Type 1) entries
//! and Unified Kernel Images (Type 2) for UEFI boot.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod bootloader;
pub mod cmdline;
pub mod os_release;
pub mod selabel;
pub mod uki;
pub mod write_boot;

use std::ffi::OsStr;

use anyhow::Result;

use composefs::{fsverity::FsVerityHashValue, repository::Repository, tree::FileSystem};

use crate::bootloader::{get_boot_resources, BootEntry};

/// These directories are required to exist in images.
/// They may have content in the container, but we don't
/// want to expose them in the final merged root.
///
/// # /boot
///
/// This is how sealed UKIs are handled; the UKI in /boot has the composefs
/// digest, so we can't include it in the rendered image.
///
/// # /sysroot
///
/// See https://github.com/containers/composefs-rs/issues/164
/// Basically there is only content here in ostree-container cases,
/// and us traversing there for SELinux labeling will cause problems.
/// The ostree-container code special cases it in a different way, but
/// here we can just ignore it.
const REQUIRED_TOPLEVEL_TO_EMPTY_DIRS: &[&str] = &["boot", "sysroot"];

/// Trait for transforming filesystem images for boot scenarios.
///
/// This trait provides functionality to prepare composefs filesystem images for booting by
/// extracting boot resources and applying necessary transformations like SELinux labeling.
pub trait BootOps<ObjectID: FsVerityHashValue> {
    /// Transforms a filesystem image for boot by extracting boot entries and applying SELinux labels.
    ///
    /// This method extracts boot resources from the filesystem, empties required top-level
    /// directories (/boot, /sysroot), and applies SELinux security contexts.
    ///
    /// # Arguments
    ///
    /// * `repo` - The composefs repository containing filesystem objects
    ///
    /// # Returns
    ///
    /// A vector of boot entries extracted from the filesystem (Type 1 BLS entries, Type 2 UKIs, etc.)
    fn transform_for_boot(
        &mut self,
        repo: &Repository<ObjectID>,
    ) -> Result<Vec<BootEntry<ObjectID>>>;
}

impl<ObjectID: FsVerityHashValue> BootOps<ObjectID> for FileSystem<ObjectID> {
    fn transform_for_boot(
        &mut self,
        repo: &Repository<ObjectID>,
    ) -> Result<Vec<BootEntry<ObjectID>>> {
        let boot_entries = get_boot_resources(self)?;

        // Get /usr's mtime to use as the canonical mtime for emptied directories.
        // This matches how we handle the root directory in copy_root_metadata_from_usr().
        let usr_mtime = self.root.get_directory(OsStr::new("usr"))?.stat.st_mtim_sec;

        for d in REQUIRED_TOPLEVEL_TO_EMPTY_DIRS {
            let d = self.root.get_directory_mut(d.as_ref())?;
            d.stat.st_mtim_sec = usr_mtime;
            d.clear();
        }

        selabel::selabel(self, repo)?;

        Ok(boot_entries)
    }
}
