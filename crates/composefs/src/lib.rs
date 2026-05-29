//! Rust bindings and utilities for working with composefs images and repositories.
//!
//! Composefs is a read-only FUSE filesystem that enables efficient sharing
//! of container filesystem layers by using content-addressable storage
//! and fs-verity for integrity verification.

#![forbid(unsafe_code)]
// This is a library: emit diagnostics via the `log` crate (or return them),
// never by writing to the process's stdout/stderr. Genuinely-intentional
// exceptions carry a local `#[allow]` with justification. Test code is exempt.
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod dumpfile;
pub mod dumpfile_parse;
pub mod erofs;
pub mod filesystem_ops;
pub mod fs;
pub mod fsverity;
pub mod mount;
pub mod mountcompat;
pub mod progress;
pub mod repository;
pub use repository::ImageNotFound;
pub mod splitstream;
pub mod tree;
pub mod util;

pub mod generic_tree;
#[cfg(any(test, feature = "test"))]
pub mod test;

/// Files with this many bytes or fewer are stored inline in the erofs image
/// (and in splitstreams).  Files above this threshold are written to object
/// storage and referenced via overlay metacopy xattrs.
///
/// Changing this value is effectively a format break: it affects which files
/// get fs-verity checksums (external) vs. which are stored directly (inline),
/// so images produced with different thresholds are not interchangeable.
/// A future composefs format version may change this size
/// (see <https://github.com/composefs/composefs-rs/issues/107>).
///
/// For the *parsing* safety bound enforced when reading untrusted input, see
/// [`MAX_INLINE_CONTENT`].
pub const INLINE_CONTENT_MAX_V0: usize = 64;

/// Maximum inline content size accepted when parsing untrusted input (dumpfiles,
/// EROFS images in composefs-restricted mode).
///
/// This is intentionally higher than [`INLINE_CONTENT_MAX_V0`] to allow for future
/// increases to the inline threshold (see
/// <https://github.com/composefs/composefs-rs/issues/107>).
pub const MAX_INLINE_CONTENT: usize = 512;

/// Maximum symlink target length in bytes.
///
/// XFS limits symlink targets to 1024 bytes (`XFS_SYMLINK_MAXLEN`). Since
/// generic Linux containers are commonly backed by XFS, we enforce that
/// limit rather than the Linux VFS `PATH_MAX` of 4096.
pub const SYMLINK_MAX: usize = 1024;

/// Internal constants shared across workspace crates.
///
/// Not part of the public API — may change without notice.
#[doc(hidden)]
pub mod shared_internals {
    /// Default I/O buffer capacity for BufWriter/BufReader in streaming paths.
    ///
    /// The stdlib default of 8 KiB is suboptimal for large file I/O.
    /// 64 KiB provides significantly better throughput.
    /// See <https://github.com/bootc-dev/ocidir-rs/pull/63>.
    pub const IO_BUF_CAPACITY: usize = 64 * 1024;
}
