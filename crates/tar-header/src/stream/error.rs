//! Error types for tar stream parsing.

use std::str::Utf8Error;

use thiserror::Error;

use crate::{HeaderError, PaxError};

/// Errors that can occur during tar stream parsing.
#[derive(Debug, Error)]
pub enum StreamError {
    /// I/O error from the underlying reader.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Header parsing error (checksum, invalid octal, etc.).
    #[error("header error: {0}")]
    Header(#[from] HeaderError),

    /// PAX extension parsing error.
    #[error("PAX error: {0}")]
    Pax(#[from] PaxError),

    /// Invalid UTF-8 in PAX key.
    #[error("invalid UTF-8 in PAX key: {0}")]
    InvalidUtf8(#[from] Utf8Error),

    /// Path exceeds configured maximum length.
    #[error("path exceeds limit: {len} bytes > {limit} bytes")]
    PathTooLong {
        /// Actual path length.
        len: usize,
        /// Configured limit.
        limit: usize,
    },

    /// PAX extended header exceeds configured maximum size.
    #[error("PAX header exceeds limit: {size} bytes > {limit} bytes")]
    PaxTooLarge {
        /// Actual PAX header size.
        size: u64,
        /// Configured limit.
        limit: u64,
    },

    /// GNU long name/link exceeds configured maximum size.
    #[error("GNU long name/link exceeds limit: {size} bytes > {limit} bytes")]
    GnuLongTooLarge {
        /// Actual GNU long name/link size.
        size: u64,
        /// Configured limit.
        limit: u64,
    },

    /// Duplicate GNU long name entry without an intervening actual entry.
    #[error("duplicate GNU long name entry")]
    DuplicateGnuLongName,

    /// Duplicate GNU long link entry without an intervening actual entry.
    #[error("duplicate GNU long link entry")]
    DuplicateGnuLongLink,

    /// Duplicate PAX extended header without an intervening actual entry.
    #[error("duplicate PAX extended header")]
    DuplicatePaxHeader,

    /// Metadata entries (GNU long name, PAX, etc.) found but no actual entry followed.
    #[error("metadata entries without a following actual entry")]
    OrphanedMetadata,

    /// Too many consecutive metadata entries (possible infinite loop or malicious archive).
    #[error("too many pending metadata entries: {count} > {limit}")]
    TooManyPendingEntries {
        /// Number of pending metadata entries.
        count: usize,
        /// Configured limit.
        limit: usize,
    },

    /// Entry size in header is invalid (e.g., overflow when computing padded size).
    #[error("invalid entry size: {0}")]
    InvalidSize(u64),

    /// Unexpected EOF while reading entry content or padding.
    #[error("unexpected EOF at position {pos}")]
    UnexpectedEof {
        /// Position in the stream where EOF occurred.
        pos: u64,
    },
}

/// Result type for stream parsing operations.
pub type Result<T> = std::result::Result<T, StreamError>;
