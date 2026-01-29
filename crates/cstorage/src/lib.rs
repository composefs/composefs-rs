//! Read-only access to containers-storage overlay driver.
//!
//! This library provides efficient, capability-based access to container image
//! storage using the overlay driver. All file operations are performed using
//! file descriptor-relative operations via cap-std, providing security against
//! path traversal attacks and TOCTOU race conditions.
//!
//! # Overview
//!
//! The library is designed to access containers-storage (overlay driver) without
//! requiring tar serialization. Instead, it provides direct file descriptor access
//! to layer content, enabling zero-copy operations.
//!
//! # Key Features
//!
//! - **Capability-based security**: All file access via `cap_std::fs::Dir` handles
//! - **Zero-copy access**: File descriptors instead of data copies
//! - **Safe by design**: No path traversal vulnerabilities
//! - **Tar-split integration**: Bit-for-bit identical TAR reconstruction
//! - **OCI compatibility**: Uses oci-spec for standard image formats
//!
//! # Example
//!
//! ```no_run
//! use cstorage::Storage;
//!
//! // Discover storage from default locations
//! let storage = Storage::discover()?;
//!
//! // Or open storage at a specific path
//! let storage = Storage::open("/var/lib/containers/storage")?;
//!
//! // List images
//! for image in storage.list_images()? {
//!     println!("Image: {}", image.id());
//! }
//! # Ok::<(), cstorage::StorageError>(())
//! ```
//!
//! # Architecture
//!
//! The library uses cap-std for all file operations:
//! - `Storage` holds a `Dir` handle to the storage root
//! - All file access is relative to `Dir` handles
//! - No absolute paths are constructed during operations
//! - SQLite database accessed via fd-relative path

// Core storage access
pub mod config;
pub mod error;
pub mod image;
pub mod layer;
pub mod lockfile;
pub mod storage;
pub mod tar_split;

// Re-export commonly used types
pub use config::{AdditionalLayerStore, StorageConfig};
pub use error::{Result, StorageError};
pub use image::Image;
pub use layer::Layer;
pub use lockfile::LastWrite;
pub use storage::{ImageRLockGuard, LayerMetadata, LayerRLockGuard, Storage};
pub use tar_split::{TarHeader, TarSplitFdStream, TarSplitItem};

// Re-export OCI spec types for convenience
pub use oci_spec::image::{Descriptor, ImageConfiguration, ImageManifest};
