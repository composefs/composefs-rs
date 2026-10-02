//! Boot integration for composefs filesystem images.
//!
//! This crate provides functionality to transform composefs filesystem images for boot
//! scenarios by extracting boot resources, applying SELinux labels, and preparing
//! bootloader entries. It supports both Boot Loader Specification (Type 1) entries
//! and Unified Kernel Images (Type 2) for UEFI boot.
//!
//! The `composefs-integration` feature is enabled by default. Disable default features
//! to use the Android boot image and UKI parsers without the composefs integration dependencies.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod android_boot;
#[cfg(feature = "composefs-integration")]
pub mod bootloader;
#[cfg(feature = "composefs-integration")]
pub mod cmdline;
pub mod os_release;
#[cfg(feature = "composefs-integration")]
pub mod selabel;
pub mod uki;
#[cfg(feature = "composefs-integration")]
pub mod write_boot;

#[cfg(doc)]
pub mod design;

#[cfg(feature = "composefs-integration")]
mod integration;

#[cfg(feature = "composefs-integration")]
pub use integration::BootOps;
