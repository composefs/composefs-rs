//! Streaming tar parser with transparent GNU and PAX extension handling.
//!
//! This module provides a high-level streaming parser for tar archives that
//! automatically handles GNU long name/link extensions and PAX extended headers,
//! yielding only "actual" entries with fully resolved metadata.
//!
//! # Overview
//!
//! Tar archives can use several mechanisms for extended metadata:
//!
//! - **GNU long name (type 'L')**: Stores paths longer than 100 bytes
//! - **GNU long link (type 'K')**: Stores link targets longer than 100 bytes
//! - **PAX extended headers (type 'x')**: Key-value pairs for path, size, uid, gid, xattrs, etc.
//! - **PAX global headers (type 'g')**: Global defaults for all subsequent entries
//!
//! The [`TarStreamParser`] handles all of these transparently, accumulating
//! metadata entries and applying them to the next actual entry.
//!
//! # Security
//!
//! The parser applies configurable [`Limits`] to prevent resource exhaustion
//! from malicious or malformed archives:
//!
//! - Maximum path length
//! - Maximum PAX extension size
//! - Maximum GNU long name/link size
//! - Maximum consecutive metadata entries
//!
//! # Example
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::{BufReader, Read};
//! use tar_header::stream::{TarStreamParser, Limits};
//!
//! let file = File::open("archive.tar").unwrap();
//! let reader = BufReader::new(file);
//! let mut parser = TarStreamParser::new(reader, Limits::default());
//!
//! while let Some(entry) = parser.next_entry().unwrap() {
//!     println!("{} ({} bytes)", entry.path_lossy(), entry.size);
//!
//!     // Save size before dropping entry borrow
//!     let size = entry.size;
//!     drop(entry);
//!
//!     // Must skip or read content before next entry
//!     if size > 0 {
//!         parser.skip_content(size).unwrap();
//!     }
//! }
//! ```
//!
//! # Comparison with tar-rs
//!
//! This parser is designed to be a potential replacement for the parsing layer
//! of the [`tar`](https://crates.io/crates/tar) crate, with:
//!
//! - Explicit security limits
//! - zerocopy-based header parsing
//! - Cleaner separation of parsing from I/O
//!
//! The goal is to eventually upstream this as a shared core for tar-rs.

mod entry;
mod error;
mod limits;
mod parser;

pub use entry::ParsedEntry;
pub use error::{Result, StreamError};
pub use limits::Limits;
pub use parser::TarStreamParser;

#[cfg(test)]
mod tests;
