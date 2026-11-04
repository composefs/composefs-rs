//! Importing OCI images into a containers/storage overlay store.
//!
//! Use [`StorageWriter`] to begin an [`ImageImport`], supply its layers through
//! [`LayerSource`], and publish the image with its names. Imports preserve OCI
//! metadata and layer content for use by containers/storage consumers. Compatible
//! destination layers can be reused.
//!
//! Reflinks avoid copying file-backed payloads where supported. Callers can also
//! enable hardlinking through [`SharingOptions`] when source metadata is
//! compatible with the destination. Payloads are copied when sharing is
//! unavailable.
//!
//! Sessions own their storage locks. Async methods perform normally quick local
//! I/O, such as opening files and reading metadata, directly on the calling thread.
//! Lock waits are asynchronous; lengthy filesystem operations, including layer
//! installation, recovery cleanup and durability syncs, run on blocking workers.

mod extract;
mod initialize;
mod locking;
mod names;
mod overlay;
mod records;
mod transaction;

use std::fs::File;
use std::path::PathBuf;

use cap_std::fs::Dir;
pub use oci_spec::image::Digest as OciDigest;
pub use transaction::{ImageImport, ImagePublication, StorageWriter};

/// Result of an image import operation.
pub type Result<T> = std::result::Result<T, ImportError>;

/// Failure to validate, materialize or publish an image.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// Unsupported destination layout or driver setting.
    #[error("unsupported store configuration: {0}")]
    UnsupportedStore(String),
    /// Invalid OCI metadata, tar representation or source chunk.
    #[error("malformed image or layer: {0}")]
    Malformed(String),
    /// A supplied identity did not match the logical bytes.
    #[error("{kind} mismatch: expected {expected}, found {actual}")]
    DigestMismatch {
        /// Identity being checked.
        kind: &'static str,
        /// Expected digest.
        expected: String,
        /// Computed digest.
        actual: String,
    },
    /// A filesystem worker failed to complete.
    #[error("image import worker failed: {0}")]
    Worker(#[from] tokio::task::JoinError),
    /// The previous layer has not been installed.
    #[error("layer {0} needs its parent")]
    NeedsParent(u32),
    /// Finalization was attempted with missing layers.
    #[error("image has missing layer {0}")]
    MissingLayer(u32),
    /// Existing image metadata or its applied chain differs.
    #[error("image metadata conflict: {0}")]
    MetadataConflict(String),
    /// The same config already has another default manifest.
    #[error("manifest variant conflict for image {0}")]
    ManifestVariantConflict(String),
    /// A requested name belongs to another image.
    #[error("image name already assigned: {0}")]
    NameConflict(String),
    /// State cannot be safely recovered by this writer.
    #[error("store recovery required: {0}")]
    RecoveryRequired(String),
    /// An error while importing a layer.
    #[error("layer {index} ({id}): {source}")]
    Layer {
        /// Config layer index.
        index: u32,
        /// Destination-local storage ID.
        id: String,
        /// Underlying failure.
        source: Box<ImportError>,
    },
    /// Filesystem failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Invalid storage record JSON.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl From<rustix::io::Errno> for ImportError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}

/// Locations of a containers/storage destination.
///
/// Each optional path is relative to its directory handle. Without a path,
/// the directory handle itself is the root.
#[derive(Debug)]
pub struct StoreLocation {
    /// Graphroot directory, or the parent of `graphroot_path`.
    pub graphroot: Dir,
    /// Relative graphroot path, if the handle names a parent directory.
    pub graphroot_path: Option<PathBuf>,
    /// Runroot directory, or the parent of `runroot_path`.
    /// Without a runroot, recovery treats the mount records as empty.
    pub runroot: Option<Dir>,
    /// Relative runroot path, used only when `runroot` is supplied.
    pub runroot_path: Option<PathBuf>,
}

impl StoreLocation {
    /// Use an already-open graphroot and an optional runroot.
    pub fn new(graphroot: Dir, runroot: Option<Dir>) -> Self {
        Self {
            graphroot,
            graphroot_path: None,
            runroot,
            runroot_path: None,
        }
    }

    fn open(self) -> Result<OpenedStoreLocation> {
        let graphroot = match self.graphroot_path {
            Some(path) => self.graphroot.open_dir(path)?,
            None => self.graphroot,
        };
        let runroot = self
            .runroot
            .map(|dir| match self.runroot_path {
                Some(path) => dir.open_dir(path),
                None => Ok(dir),
            })
            .transpose()?;
        Ok(OpenedStoreLocation { graphroot, runroot })
    }
}

#[derive(Debug)]
struct OpenedStoreLocation {
    graphroot: Dir,
    runroot: Option<Dir>,
}

/// Original OCI manifest and configuration for the image to import.
///
/// Callers supply trusted original layer descriptors for the uncompressed
/// streams. The writer checks each stream's diff ID and retains the descriptor's
/// blob digest and size for containers/storage reuse.
#[derive(Debug)]
pub struct RawImage {
    /// Digest of the selected single-platform OCI manifest.
    pub expected_manifest: OciDigest,
    /// Original manifest bytes, without JSON normalization.
    pub manifest_json: Vec<u8>,
    /// Original config bytes referenced by that manifest.
    pub config_json: Vec<u8>,
}

/// File-sharing policy for new regular files.
#[derive(Debug, Default, Clone, Copy)]
pub struct SharingOptions {
    /// Permit hardlinks to source files with compatible metadata.
    ///
    /// The caller must ensure source labels permit access by destination consumers.
    pub allow_compatible_hardlinks: bool,
}

/// Resolution of requested names already assigned to another image.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum NamePolicy {
    /// Fail without changing name associations.
    #[default]
    FailOnConflict,
    /// Move the requested names to the published image.
    Reassign,
}

/// Policy for an image import.
#[derive(Debug, Default, Clone, Copy)]
pub struct ImportOptions {
    /// Sharing of file-backed regular payloads.
    pub sharing: SharingOptions,
    /// Name conflict resolution at publication.
    pub names: NamePolicy,
}

/// Cumulative logical payload statistics, independent of tar metadata bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MaterializationStats {
    /// Reflinked regular files.
    pub reflinked_files: u64,
    /// Reflinked bytes.
    pub reflinked_bytes: u64,
    /// Canonical-object hardlinks.
    pub hardlinked_files: u64,
    /// Hardlinked bytes.
    pub hardlinked_bytes: u64,
    /// Copied file-backed payloads.
    pub copied_files: u64,
    /// Copied bytes.
    pub copied_bytes: u64,
    /// Literal regular file payloads.
    pub inline_files: u64,
    /// Literal payload bytes.
    pub inline_bytes: u64,
    /// Existing layers reused without reading their tar streams.
    pub reused_layers: u64,
    /// Recorded uncompressed bytes in reused layers.
    pub reused_bytes: u64,
}

impl MaterializationStats {
    pub(crate) fn add(&mut self, other: Self) {
        self.reflinked_files += other.reflinked_files;
        self.reflinked_bytes += other.reflinked_bytes;
        self.hardlinked_files += other.hardlinked_files;
        self.hardlinked_bytes += other.hardlinked_bytes;
        self.copied_files += other.copied_files;
        self.copied_bytes += other.copied_bytes;
        self.inline_files += other.inline_files;
        self.inline_bytes += other.inline_bytes;
        self.reused_layers += other.reused_layers;
        self.reused_bytes += other.reused_bytes;
    }
}

/// A source fragment with inline bytes in the caller's buffer or a whole-file reference.
#[derive(Debug)]
pub enum LayerChunk {
    /// Number of literal bytes placed at the start of the supplied buffer.
    Inline(usize),
    /// An immutable whole-file payload, read starting at offset zero.
    File {
        /// Open readable regular file; contents must remain immutable throughout import.
        file: File,
        /// Expected complete file length.
        length: u64,
    },
}

/// A synchronous source of literal bytes and immutable file-backed payloads.
pub trait LayerSource {
    /// Yield another chunk, or clean EOF. Literal chunks must be nonempty and
    /// fit in `buffer`; file references must occupy a complete tar file body.
    fn next_chunk(&mut self, buffer: &mut [u8]) -> Result<Option<LayerChunk>>;
}

impl<S: LayerSource + ?Sized> LayerSource for &mut S {
    fn next_chunk(&mut self, buffer: &mut [u8]) -> Result<Option<LayerChunk>> {
        (**self).next_chunk(buffer)
    }
}

/// A [`LayerSource`] adapter for an uncompressed tar reader.
#[derive(Debug)]
pub struct TarSource<R>(pub R);
impl<R: std::io::Read> LayerSource for TarSource<R> {
    fn next_chunk(&mut self, buffer: &mut [u8]) -> Result<Option<LayerChunk>> {
        loop {
            match self.0.read(buffer) {
                Ok(0) => return Ok(None),
                Ok(n) => return Ok(Some(LayerChunk::Inline(n))),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
}

/// Availability of a config layer in the selected applied chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerStatus {
    /// Its preceding config layer has not been selected yet.
    NeedsParent,
    /// No compatible complete destination layer exists.
    Missing,
    /// Reusable destination-local storage layer ID.
    Reusable(String),
}

/// Completed layer publication or reuse.
#[derive(Debug, Clone)]
pub struct LayerResult {
    /// Destination-local layer ID.
    pub storage_layer_id: String,
    /// Exact uncompressed tar digest.
    pub diff_id: OciDigest,
    /// Whether an existing layer was selected.
    pub reused: bool,
    /// Materialization performed for this layer.
    pub stats: MaterializationStats,
}

/// A durably published image.
#[derive(Debug)]
pub struct PublishedImage {
    /// Bare config hex digest, as used by containers/storage.
    pub image_id: String,
    /// Exact retained manifest digest.
    pub manifest_digest: OciDigest,
    /// Exact retained config digest.
    pub config_digest: OciDigest,
    /// Destination layers in config order.
    pub layer_ids: Vec<String>,
    /// Whether this image record already existed.
    pub already_present: bool,
    /// Total materialization/reuse statistics.
    pub stats: MaterializationStats,
}

/// Result of aborting an image import.
#[derive(Debug, Default)]
pub struct AbortReport {
    /// Completed layers retained by this session.
    pub retained_layers: Vec<String>,
}

#[cfg(test)]
mod tests;

async fn worker<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    struct Job<T>(tokio::task::JoinHandle<T>);
    impl<T> Drop for Job<T> {
        fn drop(&mut self) {
            // Cancels queued work where possible. A running blocking job keeps
            // its owned state and finishes normally, including error cleanup.
            self.0.abort();
        }
    }
    let mut job = Job(tokio::task::spawn_blocking(operation));
    (&mut job.0).await?
}
