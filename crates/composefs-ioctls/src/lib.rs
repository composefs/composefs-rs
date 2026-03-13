//! Low-level ioctl wrappers for composefs operations.
//!
//! This crate provides safe Rust wrappers around Linux ioctls used by composefs:
//!
//! - **fs-verity ioctls**: Enable and measure fs-verity on files
//! - **Loop device ioctls**: Create loop devices (behind `loop-device` feature)
//!
//! # Safety
//!
//! All unsafe ioctl code is contained within this crate, allowing dependent
//! crates to use `#![forbid(unsafe_code)]`.
//!
//! # Example
//!
//! ```ignore
//! use composefs_ioctls::fsverity::{fs_ioc_enable_verity, fs_ioc_measure_verity};
//!
//! // Enable verity on a file
//! fs_ioc_enable_verity(&file, 1, 4096)?; // SHA-256, 4K blocks
//!
//! // Measure the verity digest
//! let digest: [u8; 32] = fs_ioc_measure_verity(&file, 1)?;
//! ```

#![deny(unsafe_code)]

pub mod fsverity;
pub mod keyring;

#[cfg(feature = "loop-device")]
pub mod loop_device;

#[cfg(test)]
mod test_utils;

// Re-export test utilities for use in other crates' tests
#[doc(hidden)]
pub mod test_utils_pub;
