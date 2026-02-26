//! EROFS (Enhanced Read-Only File System) format support for composefs.
//!
//! This module provides functionality to read and write EROFS filesystem images,
//! which are used as the underlying storage format for composefs images.

pub mod composefs;
pub mod debug;
pub mod dump;
pub mod format;
pub mod reader;
pub mod writer;
