//! Tar-split integration for reading container layers without full tar serialization.
//!
//! This module provides the `TarSplitFdStream` which reads tar-split metadata files
//! and returns file descriptors for the actual file content, enabling zero-copy
//! access to layer data.
//!
//! # Overview
//!
//! The tar-split format stores tar header metadata separately from file content,
//! allowing reconstruction of tar archives without duplicating the actual file data.
//! This implementation uses that metadata to provide file descriptors directly to
//! the files in the overlay diff directory.
//!
//! # Architecture
//!
//! The tar-split format is NDJSON (newline-delimited JSON), gzip-compressed:
//! - Type 1 (FileType): File/directory references with name, optional size, optional CRC64
//! - Type 2 (SegmentType): Raw TAR header bytes and padding (base64-encoded)
//! - CRC64-ISO algorithm for checksums

use std::io::{BufRead, BufReader, Read, Seek};
use std::os::fd::{AsFd as _, OwnedFd};

use base64::prelude::*;
use cap_std::fs::{Dir, File};
use crc::{CRC_64_GO_ISO, Crc};
use flate2::read::GzDecoder;
use serde::Deserialize;

use crate::error::{Result, StorageError};
use crate::layer::Layer;
use crate::storage::Storage;

/// CRC64-ISO implementation for verifying file checksums.
const CRC64_ISO: Crc<u64> = Crc::<u64>::new(&CRC_64_GO_ISO);

/// Overlay metacopy xattr names — checked in priority order.
///
/// Root mode uses `trusted.overlay.metacopy`; rootless mode (with the
/// `userxattr` overlay mount option) uses `user.overlay.metacopy`.
const OVERLAY_METACOPY_XATTRS: &[&str] = &["trusted.overlay.metacopy", "user.overlay.metacopy"];

/// Returns `true` if `file` is an overlay metacopy stub.
///
/// A metacopy file is a zero-byte upper-layer stub whose content lives in a
/// lower layer.  The kernel signals this by attaching a
/// `trusted.overlay.metacopy` (or `user.overlay.metacopy` in rootless mode)
/// extended attribute to the file.  Reading data from the stub via a plain
/// file descriptor returns EOF immediately, so the producer must detect and
/// skip it, falling back to the lower layer that holds the real data.
///
/// Returns `Err` only for unexpected I/O errors; `ENODATA` / `ENOATTR`
/// (xattr not present) is treated as `Ok(false)`.
fn is_overlay_metacopy(file: &File) -> Result<bool> {
    let fd = file.as_fd();
    for name in OVERLAY_METACOPY_XATTRS {
        // Pass a 1-byte buffer: we only care whether the xattr exists, not
        // its value.  The kernel returns Ok(n) when the value fits and ERANGE
        // when the buffer is too small — both mean the xattr is present.
        match rustix::fs::fgetxattr(fd, *name, &mut [0u8; 1]) {
            Ok(_) => return Ok(true),
            // ERANGE: buffer too small, but the xattr is present.
            Err(rustix::io::Errno::RANGE) => return Ok(true),
            // ENODATA / ENOATTR: xattr not present on this file.
            Err(rustix::io::Errno::NODATA) => continue,
            // ENOATTR is the BSD spelling; some libc glue maps it the same way.
            #[cfg(not(target_os = "linux"))]
            Err(rustix::io::Errno::NOATTR) => continue,
            Err(e) => {
                return Err(StorageError::Io(std::io::Error::from_raw_os_error(
                    e.raw_os_error(),
                )));
            }
        }
    }
    Ok(false)
}

/// Item returned from tar-split stream iteration.
#[derive(Debug)]
pub enum TarSplitItem {
    /// Raw segment bytes (TAR header + padding) to write directly.
    Segment(Vec<u8>),

    /// File content to write.
    FileContent {
        /// File descriptor for reading the content.
        ///
        /// The caller takes ownership of this file descriptor and is responsible
        /// for reading the content and closing it when done.
        fd: OwnedFd,
        /// Expected file size in bytes.
        ///
        /// Used for tar padding calculation: TAR files are padded to 512-byte
        /// boundaries, so the consumer needs to know the size to write the
        /// correct amount of padding after the file content.
        size: u64,
        /// File path from the tar-split entry.
        ///
        /// This is the path as recorded in the original tar archive
        /// (e.g., "./etc/hosts").
        name: String,
        /// Short link ID of the layer in whose diff directory this file was found.
        ///
        /// This is the value of `overlay/l/<link_id>` — the short symlink name
        /// created by containers/storage that points at `../<layer-id>/diff`.
        /// The consumer uses it to build filenames of the form
        /// `l/<link_id>/<relpath>` relative to the `overlay/` directory.
        link_id: String,
    },
}

/// Raw tar-split entry from NDJSON format before validation.
#[derive(Debug, Deserialize)]
struct TarSplitEntryRaw {
    /// Entry type discriminant: 1 for File, 2 for Segment.
    #[serde(rename = "type")]
    type_id: u8,
    /// File name from TAR header (type 1 only).
    #[serde(default)]
    name: Option<String>,
    /// File size in bytes (type 1 only).
    #[serde(default)]
    size: Option<u64>,
    /// CRC64-ISO checksum, base64-encoded (type 1 only).
    #[serde(default)]
    crc64: Option<String>,
    /// Base64-encoded TAR header bytes or padding (type 2 only).
    #[serde(default)]
    payload: Option<String>,
}

/// Tar-split entry from NDJSON format.
#[derive(Debug)]
enum TarSplitEntry {
    /// File type entry: references a file/directory with metadata.
    File {
        /// File name from TAR header.
        name: Option<String>,
        /// File size in bytes.
        size: Option<u64>,
        /// CRC64-ISO checksum (base64-encoded).
        crc64: Option<String>,
    },
    /// Segment type entry: raw TAR header bytes and padding.
    Segment {
        /// Base64-encoded TAR header bytes (512 bytes) or padding.
        payload: Option<String>,
    },
}

impl TarSplitEntry {
    /// Parse a tar-split entry from raw format with validation.
    fn from_raw(raw: TarSplitEntryRaw) -> Result<Self> {
        match raw.type_id {
            1 => Ok(TarSplitEntry::File {
                name: raw.name,
                size: raw.size,
                crc64: raw.crc64,
            }),
            2 => Ok(TarSplitEntry::Segment {
                payload: raw.payload,
            }),
            _ => Err(StorageError::TarSplitError(format!(
                "Invalid tar-split entry type: {}",
                raw.type_id
            ))),
        }
    }
}

/// Tar header information extracted from tar-split metadata.
#[derive(Debug, Clone)]
pub struct TarHeader {
    /// File path in the tar archive (e.g., "./etc/hosts")
    pub name: String,

    /// File mode (permissions and type information)
    pub mode: u32,

    /// User ID of the file owner
    pub uid: u32,

    /// Group ID of the file owner
    pub gid: u32,

    /// File size in bytes
    pub size: u64,

    /// Modification time (Unix timestamp)
    pub mtime: i64,

    /// Tar entry type flag
    pub typeflag: u8,

    /// Link target for symbolic links and hard links
    pub linkname: String,

    /// User name of the file owner
    pub uname: String,

    /// Group name of the file owner
    pub gname: String,

    /// Major device number (for device files)
    pub devmajor: u32,

    /// Minor device number (for device files)
    pub devminor: u32,
}

impl TarHeader {
    /// Parse a TarHeader from a 512-byte TAR header block.
    ///
    /// # Errors
    ///
    /// Returns an error if the header is too short or has an invalid checksum.
    pub fn from_bytes(header_bytes: &[u8]) -> Result<Self> {
        let header_array: &[u8; tar_core::HEADER_SIZE] = header_bytes.try_into().map_err(|_| {
            StorageError::TarSplitError(format!(
                "TAR header wrong size: {} bytes (expected {})",
                header_bytes.len(),
                tar_core::HEADER_SIZE
            ))
        })?;
        let header = tar_core::Header::from_bytes(header_array);

        let name = String::from_utf8(header.path_bytes().to_vec()).map_err(|e| {
            StorageError::TarSplitError(format!("Non-UTF-8 path in TAR header: {}", e))
        })?;
        let mode = header
            .mode()
            .map_err(|e| StorageError::TarSplitError(format!("Invalid mode: {}", e)))?;
        let uid = header
            .uid()
            .map_err(|e| StorageError::TarSplitError(format!("Invalid uid: {}", e)))?
            as u32;
        let gid = header
            .gid()
            .map_err(|e| StorageError::TarSplitError(format!("Invalid gid: {}", e)))?
            as u32;
        let size = header
            .entry_size()
            .map_err(|e| StorageError::TarSplitError(format!("Invalid size: {}", e)))?;
        let mtime = header
            .mtime()
            .map_err(|e| StorageError::TarSplitError(format!("Invalid mtime: {}", e)))?
            as i64;
        let typeflag = header.entry_type().as_byte();
        let link_bytes = header.link_name_bytes();
        let linkname = if link_bytes.is_empty() {
            String::new()
        } else {
            String::from_utf8(link_bytes.to_vec()).map_err(|e| {
                StorageError::TarSplitError(format!("Non-UTF-8 link name in TAR header: {}", e))
            })?
        };
        let uname = header
            .username()
            .map(|b| {
                String::from_utf8(b.to_vec()).map_err(|e| {
                    StorageError::TarSplitError(format!("Non-UTF-8 username in TAR header: {}", e))
                })
            })
            .transpose()?
            .unwrap_or_default();
        let gname = header
            .groupname()
            .map(|b| {
                String::from_utf8(b.to_vec()).map_err(|e| {
                    StorageError::TarSplitError(format!(
                        "Non-UTF-8 group name in TAR header: {}",
                        e
                    ))
                })
            })
            .transpose()?
            .unwrap_or_default();
        let devmajor = header
            .device_major()
            .map_err(|e| StorageError::TarSplitError(format!("Invalid devmajor: {}", e)))?
            .unwrap_or(0);
        let devminor = header
            .device_minor()
            .map_err(|e| StorageError::TarSplitError(format!("Invalid devminor: {}", e)))?
            .unwrap_or(0);

        Ok(TarHeader {
            name,
            mode,
            uid,
            gid,
            size,
            mtime,
            typeflag,
            linkname,
            uname,
            gname,
            devmajor,
            devminor,
        })
    }

    /// Check if this header represents a regular file.
    pub fn is_regular_file(&self) -> bool {
        self.typeflag == b'0' || self.typeflag == b'\0'
    }

    /// Check if this header represents a directory.
    pub fn is_directory(&self) -> bool {
        self.typeflag == b'5'
    }

    /// Check if this header represents a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.typeflag == b'2'
    }

    /// Check if this header represents a hard link.
    pub fn is_hardlink(&self) -> bool {
        self.typeflag == b'1'
    }

    /// Normalize the path by stripping leading "./"
    pub fn normalized_name(&self) -> &str {
        self.name.strip_prefix("./").unwrap_or(&self.name)
    }
}

/// Stream that reads tar-split metadata and provides file descriptors for file content.
#[derive(Debug)]
pub struct TarSplitFdStream {
    /// The current layer for file lookups.
    layer: Layer,

    /// Storage root directory for accessing parent layers on-demand.
    storage_root: Dir,

    /// Gzip decompressor reading from the tar-split file.
    reader: BufReader<GzDecoder<File>>,

    /// Entry counter for debugging and error messages.
    entry_count: usize,

    /// Short link IDs for each layer in the chain.
    ///
    /// Index 0 is the target layer's own link ID; subsequent entries are the
    /// ancestor layers in the same depth-first order produced by
    /// [`Layer::layer_chain`].  Each link ID corresponds to a symlink under
    /// `overlay/l/<link_id>` that points to the layer's diff directory.
    chain_link_ids: Vec<String>,

    /// Layer IDs parallel to `chain_link_ids`.
    ///
    /// `chain_ids[i]` is the layer ID whose link ID is `chain_link_ids[i]`.
    chain_ids: Vec<String>,
}

impl TarSplitFdStream {
    /// Create a new tar-split stream for a layer.
    ///
    /// # Errors
    ///
    /// Returns an error if the tar-split file doesn't exist or cannot be opened.
    pub fn new(storage: &Storage, layer: &Layer) -> Result<Self> {
        // Open overlay-layers directory via Dir handle
        let layers_dir = storage.root_dir().open_dir("overlay-layers").map_err(|e| {
            StorageError::TarSplitError(format!("Failed to open overlay-layers directory: {}", e))
        })?;

        // Open tar-split file relative to layers directory
        let filename = format!("{}.tar-split.gz", layer.id());
        let file = layers_dir.open(&filename).map_err(|e| {
            StorageError::TarSplitError(format!(
                "Failed to open tar-split file {}: {}",
                filename, e
            ))
        })?;

        // Wrap in gzip decompressor
        let gz_decoder = GzDecoder::new(file);
        let reader = BufReader::new(gz_decoder);

        // Build the ordered chain up front.
        // layer_chain() consumes a Layer, so open a fresh one for that purpose;
        // then open another fresh copy for the on-demand lookups below.
        let chain_layer = Layer::open(storage, layer.id())?;
        let chain = chain_layer.layer_chain(storage)?;

        let mut chain_link_ids = Vec::with_capacity(chain.len());
        let mut chain_ids = Vec::with_capacity(chain.len());
        for l in &chain {
            chain_link_ids.push(l.link_id().to_string());
            chain_ids.push(l.id().to_string());
        }

        // Open the layer for on-demand file lookups (kept for the existing
        // parent-search helpers that still operate on Layer objects).
        let layer = Layer::open(storage, layer.id())?;

        // Clone storage root dir for on-demand parent layer access
        let storage_root = storage.root_dir().try_clone()?;

        // `chain` is no longer needed.
        drop(chain);

        Ok(Self {
            layer,
            storage_root,
            reader,
            entry_count: 0,
            chain_link_ids,
            chain_ids,
        })
    }

    /// Open a file in the layer chain, trying current layer first then parents.
    ///
    /// Returns the opened file together with the link ID of the layer in whose
    /// diff directory the file was found (i.e. `overlay/l/<link_id>` points
    /// to that layer's diff dir).
    ///
    /// Overlay metacopy stubs (files whose content lives in a lower layer,
    /// signalled by a `trusted.overlay.metacopy` or `user.overlay.metacopy`
    /// xattr) are transparently skipped: finding one in a layer is treated as
    /// "not found here" and the search continues down the parent chain until
    /// the layer that contains the real file data is found.
    fn open_file_in_chain(&self, path: &str) -> Result<(cap_std::fs::File, String)> {
        // Normalize path (remove leading ./)
        let normalized_path = path.strip_prefix("./").unwrap_or(path);

        // Try to open in current layer first (chain index 0 = own diff dir).
        // Skip overlay metacopy stubs — they are zero-byte upper-layer files
        // whose actual content lives in a lower layer.
        match self.layer.diff_dir().open(normalized_path) {
            Ok(file) if !is_overlay_metacopy(&file)? => {
                let link_id = self.chain_link_ids[0].clone();
                return Ok((file, link_id));
            }
            Ok(_) => {
                // File exists but is a metacopy stub; fall through to parents.
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Continue to search parent layers
            }
            Err(e) => return Err(StorageError::Io(e)),
        }

        // Search parent layers on-demand
        self.search_parent_layers(&self.layer, normalized_path, 0)
    }

    /// Recursively search parent layers for a file.
    ///
    /// Returns the opened file together with the link ID of the layer in whose
    /// diff directory the file was found.
    fn search_parent_layers(
        &self,
        current_layer: &Layer,
        path: &str,
        depth: usize,
    ) -> Result<(cap_std::fs::File, String)> {
        const MAX_DEPTH: usize = 500;

        if depth >= MAX_DEPTH {
            return Err(StorageError::TarSplitError(format!(
                "Layer chain exceeds maximum depth of {} while searching for file: {}",
                MAX_DEPTH, path
            )));
        }

        // Get parent link IDs
        let parent_links = current_layer.parent_links();

        // Try each parent
        for link_id in parent_links {
            // Resolve link ID to layer ID by reading the symlink directly
            let parent_id = self.resolve_link_direct(link_id)?;

            // Try to open file directly in parent's diff directory
            match self.open_file_in_layer(&parent_id, path) {
                Ok(file) => {
                    let found_link_id = self.link_id_for(&parent_id)?;
                    return Ok((file, found_link_id));
                }
                Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    // File not in this parent, recursively search its parents
                    match self.search_by_layer_id(&parent_id, path, depth + 1) {
                        Ok(result) => return Ok(result),
                        Err(StorageError::TarSplitError(_)) => continue, // File not found in this branch, try next parent
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }

        Err(StorageError::TarSplitError(format!(
            "File not found in layer chain: {}",
            path
        )))
    }

    /// Search for a file starting from a layer ID.
    ///
    /// Returns the opened file together with the link ID of the layer in whose
    /// diff directory the file was found.
    fn search_by_layer_id(
        &self,
        layer_id: &str,
        path: &str,
        depth: usize,
    ) -> Result<(cap_std::fs::File, String)> {
        const MAX_DEPTH: usize = 500;

        if depth >= MAX_DEPTH {
            return Err(StorageError::TarSplitError(format!(
                "Layer chain exceeds maximum depth of {} while searching for file: {}",
                MAX_DEPTH, path
            )));
        }

        // Try to open file in this layer
        match self.open_file_in_layer(layer_id, path) {
            Ok(file) => {
                let found_link_id = self.link_id_for(layer_id)?;
                return Ok((file, found_link_id));
            }
            Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                // File not found, check parents
            }
            Err(e) => return Err(e),
        }

        // Read parent links for this layer
        let parent_links = self.read_layer_parent_links(layer_id)?;

        // Try each parent
        for link_id in parent_links {
            let parent_id = self.resolve_link_direct(&link_id)?;
            match self.search_by_layer_id(&parent_id, path, depth + 1) {
                Ok(result) => return Ok(result),
                Err(StorageError::TarSplitError(_)) => continue, // File not found in this branch, try next parent
                Err(e) => return Err(e),
            }
        }

        Err(StorageError::TarSplitError(format!(
            "File not found in layer chain: {}",
            path
        )))
    }

    /// Resolve a link ID to layer ID by directly reading the symlink.
    fn resolve_link_direct(&self, link_id: &str) -> Result<String> {
        let overlay_dir = self.storage_root.open_dir("overlay")?;
        let link_dir = overlay_dir.open_dir("l")?;
        let target = link_dir.read_link(link_id).map_err(|e| {
            StorageError::LinkReadError(format!("Failed to read link {}: {}", link_id, e))
        })?;

        // Extract layer ID from symlink target (format: ../<layer-id>/diff)
        let target_str = target.to_str().ok_or_else(|| {
            StorageError::LinkReadError("Invalid UTF-8 in link target".to_string())
        })?;
        let components: Vec<&str> = target_str.split('/').collect();
        if components.len() >= 2 {
            let layer_id = components[components.len() - 2];
            if !layer_id.is_empty() && layer_id != ".." {
                return Ok(layer_id.to_string());
            }
        }
        Err(StorageError::LinkReadError(format!(
            "Invalid link target format: {}",
            target_str
        )))
    }

    /// Open a file in a specific layer's diff directory.
    ///
    /// Returns `Err(StorageError::Io(NotFound))` both when the file is absent
    /// and when it is present but is an overlay metacopy stub, so that callers
    /// uniformly fall back to the next lower layer in either case.
    fn open_file_in_layer(&self, layer_id: &str, path: &str) -> Result<cap_std::fs::File> {
        let overlay_dir = self.storage_root.open_dir("overlay")?;
        let layer_dir = overlay_dir.open_dir(layer_id)?;
        let diff_dir = layer_dir.open_dir("diff")?;
        let file = diff_dir.open(path).map_err(StorageError::Io)?;
        if is_overlay_metacopy(&file)? {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "overlay metacopy stub — real data is in a lower layer",
            )));
        }
        Ok(file)
    }

    /// Read parent link IDs from a layer's lower file.
    fn read_layer_parent_links(&self, layer_id: &str) -> Result<Vec<String>> {
        let overlay_dir = self.storage_root.open_dir("overlay")?;
        let layer_dir = overlay_dir.open_dir(layer_id)?;

        match layer_dir.read_to_string("lower") {
            Ok(content) => Ok(content
                .trim()
                .split(':')
                .filter_map(|s| s.strip_prefix("l/"))
                .map(|s| s.to_string())
                .collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()), // Base layer has no lower file
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// Look up the link ID for a layer by its layer ID.
    ///
    /// Returns the link ID (i.e. the short name under `overlay/l/`) for the
    /// layer identified by `layer_id`.  This should always succeed because the
    /// on-demand search and the precomputed chain are built from the same
    /// storage; a miss means the store mutated under us or the image is
    /// malformed, so we fail closed.
    fn link_id_for(&self, layer_id: &str) -> Result<String> {
        self.chain_ids
            .iter()
            .position(|id| id == layer_id)
            .map(|idx| self.chain_link_ids[idx].clone())
            .ok_or_else(|| {
                StorageError::TarSplitError(format!(
                    "resolved layer {} is not in the precomputed chain",
                    layer_id
                ))
            })
    }

    /// Return the ordered link-ID chain for this stream.
    ///
    /// Index 0 is the target layer's own link ID; subsequent entries are
    /// ancestor layers in the same depth-first order produced by
    /// [`Layer::layer_chain`].  The `link_id` field on every
    /// [`TarSplitItem::FileContent`] yielded by [`Self::next`] is one of the
    /// values in this slice.
    pub fn chain_link_ids(&self) -> &[String] {
        &self.chain_link_ids
    }

    /// Verify CRC64-ISO checksum of a file.
    fn verify_crc64(
        &self,
        file: &mut cap_std::fs::File,
        expected_b64: &str,
        size: u64,
    ) -> Result<()> {
        // Decode base64 checksum
        let expected_bytes = BASE64_STANDARD.decode(expected_b64).map_err(|e| {
            StorageError::TarSplitError(format!("Failed to decode base64 CRC64: {}", e))
        })?;

        if expected_bytes.len() != 8 {
            return Err(StorageError::TarSplitError(format!(
                "Invalid CRC64 length: {} bytes",
                expected_bytes.len()
            )));
        }

        // Convert to u64 (big-endian)
        let expected = u64::from_be_bytes(expected_bytes.try_into().unwrap());

        // Compute CRC64 of file content
        let mut digest = CRC64_ISO.digest();
        let mut buffer = vec![0u8; 8192];
        let mut bytes_read = 0u64;

        loop {
            let n = file.read(&mut buffer).map_err(|e| {
                StorageError::TarSplitError(format!(
                    "Failed to read file for CRC64 verification: {}",
                    e
                ))
            })?;
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
            bytes_read += n as u64;
        }

        // Verify size matches
        if bytes_read != size {
            return Err(StorageError::TarSplitError(format!(
                "File size mismatch: expected {}, got {}",
                size, bytes_read
            )));
        }

        let computed = digest.finalize();
        if computed != expected {
            return Err(StorageError::TarSplitError(format!(
                "CRC64 mismatch: expected {:016x}, got {:016x}",
                expected, computed
            )));
        }

        Ok(())
    }

    /// Read the next item from the tar-split stream.
    ///
    /// Returns:
    /// - `Ok(Some(item))` - Next item was read successfully
    /// - `Ok(None)` - End of stream reached
    /// - `Err(...)` - Error occurred during reading
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<TarSplitItem>> {
        loop {
            // Read next line from NDJSON stream
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => {
                    return Ok(None);
                }
                Ok(_) => {
                    // Parse NDJSON entry
                    let raw: TarSplitEntryRaw = serde_json::from_str(&line).map_err(|e| {
                        StorageError::TarSplitError(format!(
                            "Failed to parse tar-split entry: {}",
                            e
                        ))
                    })?;
                    let entry = TarSplitEntry::from_raw(raw)?;

                    match entry {
                        TarSplitEntry::Segment { payload } => {
                            if let Some(payload_b64) = payload {
                                let payload_bytes =
                                    BASE64_STANDARD.decode(&payload_b64).map_err(|e| {
                                        StorageError::TarSplitError(format!(
                                            "Failed to decode base64 payload: {}",
                                            e
                                        ))
                                    })?;

                                return Ok(Some(TarSplitItem::Segment(payload_bytes)));
                            }
                            // Empty segment, continue
                        }

                        TarSplitEntry::File { name, size, crc64 } => {
                            self.entry_count += 1;

                            // Check if this file has content to write
                            let file_size = size.unwrap_or(0);
                            if file_size > 0 {
                                // Regular file with content - open it
                                let path = name.as_ref().ok_or_else(|| {
                                    StorageError::TarSplitError(
                                        "FileType entry missing name".to_string(),
                                    )
                                })?;

                                let (mut file, link_id) = self.open_file_in_chain(path)?;

                                // Verify CRC64 if provided
                                if let Some(ref crc64_b64) = crc64 {
                                    self.verify_crc64(&mut file, crc64_b64, file_size)?;

                                    // Seek back to start after CRC verification consumed the file
                                    file.rewind().map_err(StorageError::Io)?;
                                }

                                // Convert to OwnedFd and return
                                let std_file = file.into_std();
                                let owned_fd: OwnedFd = std_file.into();
                                return Ok(Some(TarSplitItem::FileContent {
                                    fd: owned_fd,
                                    size: file_size,
                                    name: path.clone(),
                                    link_id,
                                }));
                            }
                            // Empty file or directory - header already in preceding Segment
                        }
                    }
                }
                Err(e) => {
                    return Err(StorageError::TarSplitError(format!(
                        "Failed to read tar-split line: {}",
                        e
                    )));
                }
            }
        }
    }

    /// Get the number of entries processed so far.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;
    use crate::storage::Storage;

    // ---------------------------------------------------------------------------
    // Helper: build a minimal two-layer mock storage on disk.
    //
    // Layout created:
    //   <root>/
    //     overlay/
    //       l/
    //         CHILDLINKID000000000000000  ->  ../../overlay/child-layer-001/diff
    //         PARENTLINKID0000000000000  ->  ../../overlay/parent-layer-001/diff
    //       child-layer-001/
    //         diff/
    //           etc/
    //             child.txt          ("child content")
    //         link                   ("CHILDLINKID000000000000000")
    //         lower                  ("l/PARENTLINKID0000000000000")
    //       parent-layer-001/
    //         diff/
    //           etc/
    //             parent.txt         ("parent content")
    //         link                   ("PARENTLINKID0000000000000")
    //     overlay-layers/
    //       child-layer-001.tar-split.gz   (two File entries, no CRC)
    //     overlay-images/   (empty, required by Storage::open)
    //
    // The tar-split for child-layer-001 references:
    //   - "./etc/child.txt"  (size 14, found in child diff → dirfd_index 0)
    //   - "./etc/parent.txt" (size 15, found in parent diff → dirfd_index 1)
    // ---------------------------------------------------------------------------
    fn create_two_layer_mock(root: &std::path::Path) -> Storage {
        // Required top-level dirs
        for d in ["overlay", "overlay-layers", "overlay-images"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }

        // --- child layer ---
        let child_id = "child-layer-001";
        let child_link = "CHILDLINKID000000000000000";
        let child_diff = root.join("overlay").join(child_id).join("diff");
        std::fs::create_dir_all(child_diff.join("etc")).unwrap();
        std::fs::write(child_diff.join("etc/child.txt"), b"child content!").unwrap(); // 14 bytes
        std::fs::write(root.join("overlay").join(child_id).join("link"), child_link).unwrap();

        // --- parent layer ---
        let parent_id = "parent-layer-001";
        let parent_link = "PARENTLINKID000000000000000";
        let parent_diff = root.join("overlay").join(parent_id).join("diff");
        std::fs::create_dir_all(parent_diff.join("etc")).unwrap();
        std::fs::write(parent_diff.join("etc/parent.txt"), b"parent content!").unwrap(); // 15 bytes
        std::fs::write(
            root.join("overlay").join(parent_id).join("link"),
            parent_link,
        )
        .unwrap();

        // child's lower file: references parent via its link
        std::fs::write(
            root.join("overlay").join(child_id).join("lower"),
            format!("l/{}", parent_link),
        )
        .unwrap();

        // overlay/l/ symlinks: target is relative from overlay/l/ to overlay/<id>/diff
        // i.e. "../../overlay/<id>/diff" won't work since overlay/l is already inside overlay/
        // The actual format used by containers/storage is: "../<layer-id>/diff"
        let l_dir = root.join("overlay").join("l");
        std::fs::create_dir_all(&l_dir).unwrap();
        std::os::unix::fs::symlink(format!("../{}/diff", child_id), l_dir.join(child_link))
            .unwrap();
        std::os::unix::fs::symlink(format!("../{}/diff", parent_id), l_dir.join(parent_link))
            .unwrap();

        // --- tar-split for child layer ---
        // Two File entries (no CRC, so no checksum is verified).
        // We also need at least one Segment entry so the reader has something
        // to return for the Segment path; we emit a minimal one.
        let ndjson = concat!(
            r#"{"type":1,"name":"./etc/child.txt","size":14}"#,
            "\n",
            r#"{"type":1,"name":"./etc/parent.txt","size":15}"#,
            "\n",
        );

        let gz_path = root
            .join("overlay-layers")
            .join(format!("{}.tar-split.gz", child_id));
        let gz_file = std::fs::File::create(&gz_path).unwrap();
        let mut encoder = GzEncoder::new(gz_file, Compression::default());
        encoder.write_all(ndjson.as_bytes()).unwrap();
        encoder.finish().unwrap();

        Storage::open(root).unwrap()
    }

    #[test]
    fn test_link_id_two_layer_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = create_two_layer_mock(tmp.path());
        let layer = Layer::open(&storage, "child-layer-001").unwrap();
        let mut stream = TarSplitFdStream::new(&storage, &layer).unwrap();

        // chain_link_ids should have exactly 2 entries (child + parent)
        assert_eq!(
            stream.chain_link_ids().len(),
            2,
            "expected chain length 2 (child + parent)"
        );

        let child_link = "CHILDLINKID000000000000000";
        let parent_link = "PARENTLINKID000000000000000";

        // First item: ./etc/child.txt — present only in child diff
        match stream.next().unwrap().expect("expected FileContent item") {
            TarSplitItem::FileContent { name, link_id, .. } => {
                assert_eq!(name, "./etc/child.txt");
                assert_eq!(
                    link_id, child_link,
                    "./etc/child.txt should be found in the child layer"
                );
            }
            TarSplitItem::Segment(_) => panic!("expected FileContent, got Segment"),
        }

        // Second item: ./etc/parent.txt — present only in parent diff
        match stream.next().unwrap().expect("expected FileContent item") {
            TarSplitItem::FileContent { name, link_id, .. } => {
                assert_eq!(name, "./etc/parent.txt");
                assert_eq!(
                    link_id, parent_link,
                    "./etc/parent.txt should be found in the parent layer"
                );
            }
            TarSplitItem::Segment(_) => panic!("expected FileContent, got Segment"),
        }

        // Stream should be exhausted
        assert!(stream.next().unwrap().is_none());
    }

    #[test]
    fn test_link_id_single_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // Minimal single-layer storage (no lower file → no parents)
        for d in ["overlay", "overlay-layers", "overlay-images"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }

        let layer_id = "base-layer-001";
        let link_id = "BASELINKID0000000000000000";
        let diff = root.join("overlay").join(layer_id).join("diff");
        std::fs::create_dir_all(&diff).unwrap();
        std::fs::write(diff.join("hello.txt"), b"hello").unwrap(); // 5 bytes
        std::fs::write(root.join("overlay").join(layer_id).join("link"), link_id).unwrap();

        // overlay/l/ symlink (not strictly needed for single layer, but good hygiene)
        let l_dir = root.join("overlay").join("l");
        std::fs::create_dir_all(&l_dir).unwrap();
        std::os::unix::fs::symlink(format!("../{}/diff", layer_id), l_dir.join(link_id)).unwrap();

        // tar-split with one file entry
        let ndjson = concat!(r#"{"type":1,"name":"./hello.txt","size":5}"#, "\n");
        let gz_path = root
            .join("overlay-layers")
            .join(format!("{}.tar-split.gz", layer_id));
        let gz_file = std::fs::File::create(&gz_path).unwrap();
        let mut encoder = GzEncoder::new(gz_file, Compression::default());
        encoder.write_all(ndjson.as_bytes()).unwrap();
        encoder.finish().unwrap();

        let storage = Storage::open(root).unwrap();
        let layer = Layer::open(&storage, layer_id).unwrap();
        let mut stream = TarSplitFdStream::new(&storage, &layer).unwrap();

        assert_eq!(
            stream.chain_link_ids().len(),
            1,
            "single layer → chain len 1"
        );

        match stream.next().unwrap().expect("expected item") {
            TarSplitItem::FileContent {
                name,
                link_id: found_link_id,
                ..
            } => {
                assert_eq!(name, "./hello.txt");
                assert_eq!(
                    found_link_id, link_id,
                    "base layer file must have its own link_id"
                );
            }
            TarSplitItem::Segment(_) => panic!("expected FileContent"),
        }

        assert!(stream.next().unwrap().is_none());
    }

    #[test]
    fn test_tar_header_type_checks() {
        let mut header = TarHeader {
            name: "test.txt".to_string(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            size: 100,
            mtime: 0,
            typeflag: b'0',
            linkname: String::new(),
            uname: "user".to_string(),
            gname: "group".to_string(),
            devmajor: 0,
            devminor: 0,
        };

        assert!(header.is_regular_file());
        assert!(!header.is_directory());
        assert!(!header.is_symlink());

        header.typeflag = b'5';
        assert!(!header.is_regular_file());
        assert!(header.is_directory());

        header.typeflag = b'2';
        assert!(header.is_symlink());
    }

    #[test]
    fn test_tar_split_entry_deserialization() {
        // Test type 2 (Segment) with integer discriminant
        let json_segment = r#"{"type":2,"payload":"dXN0YXIAMDA="}"#;
        let raw: TarSplitEntryRaw = serde_json::from_str(json_segment).unwrap();
        let entry = TarSplitEntry::from_raw(raw).unwrap();
        match entry {
            TarSplitEntry::Segment { payload } => {
                assert_eq!(payload, Some("dXN0YXIAMDA=".to_string()));
            }
            _ => panic!("Expected Segment variant"),
        }

        // Test type 1 (File) with integer discriminant
        let json_file = r#"{"type":1,"name":"./etc/hosts","size":123,"crc64":"AAAAAAAAAA=="}"#;
        let raw: TarSplitEntryRaw = serde_json::from_str(json_file).unwrap();
        let entry = TarSplitEntry::from_raw(raw).unwrap();
        match entry {
            TarSplitEntry::File { name, size, crc64 } => {
                assert_eq!(name, Some("./etc/hosts".to_string()));
                assert_eq!(size, Some(123));
                assert_eq!(crc64, Some("AAAAAAAAAA==".to_string()));
            }
            _ => panic!("Expected File variant"),
        }

        // Test invalid type
        let json_invalid = r#"{"type":99}"#;
        let raw: TarSplitEntryRaw = serde_json::from_str(json_invalid).unwrap();
        let result = TarSplitEntry::from_raw(raw);
        assert!(result.is_err());
    }

    /// Build a two-layer mock where the child layer holds a metacopy stub for
    /// `shared.txt` and the real content lives only in the parent layer.
    ///
    /// Uses `/var/tmp` as the temp-dir root because `user.*` extended
    /// attributes are supported there (tmpfs, no `nosuid`/`nouser_xattr`
    /// mount restrictions).  If `/var/tmp` is unavailable or the filesystem
    /// does not support `user.*` xattrs, the test is skipped.
    ///
    /// Layout:
    /// ```text
    /// <root>/overlay/
    ///   child-layer-001/diff/shared.txt   — 0-byte metacopy stub
    ///                                       (user.overlay.metacopy xattr set)
    ///   parent-layer-001/diff/shared.txt  — "real content" (12 bytes)
    /// ```
    #[test]
    fn test_metacopy_stub_falls_back_to_parent() {
        // Use /var/tmp so user.* xattrs are available on tmpfs.
        let tmp = match tempfile::Builder::new().tempdir_in("/var/tmp") {
            Ok(d) => d,
            Err(_) => {
                // /var/tmp unavailable — skip rather than fail.
                return;
            }
        };
        let root =
            cap_std::fs::Dir::open_ambient_dir(tmp.path(), cap_std::ambient_authority()).unwrap();

        // Required top-level dirs.
        for d in ["overlay", "overlay-layers", "overlay-images"] {
            root.create_dir_all(d).unwrap();
        }

        let child_id = "child-layer-001";
        let child_link = "CHILDLINKID000000000000000";
        let parent_id = "parent-layer-001";
        let parent_link = "PARENTLINKID000000000000000";

        // Parent layer: real file content.
        root.create_dir_all(format!("overlay/{parent_id}/diff"))
            .unwrap();
        root.write(
            format!("overlay/{parent_id}/diff/shared.txt"),
            b"real content", // 12 bytes
        )
        .unwrap();
        root.write(format!("overlay/{parent_id}/link"), parent_link)
            .unwrap();

        // Child layer: zero-byte metacopy stub with user.overlay.metacopy xattr.
        root.create_dir_all(format!("overlay/{child_id}/diff"))
            .unwrap();
        root.write(format!("overlay/{child_id}/diff/shared.txt"), b"")
            .unwrap(); // 0 bytes — the stub

        // Set the metacopy xattr.  If the filesystem refuses user.* xattrs,
        // bail out with a skip rather than a spurious failure.
        let stub_file = root
            .open(format!("overlay/{child_id}/diff/shared.txt"))
            .unwrap();
        match rustix::fs::fsetxattr(
            stub_file.as_fd(),
            "user.overlay.metacopy",
            b"",
            rustix::fs::XattrFlags::CREATE,
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::OPNOTSUPP) => {
                // Filesystem does not support xattrs — skip.
                return;
            }
            Err(e) => panic!("unexpected fsetxattr error: {e}"),
        }

        root.write(format!("overlay/{child_id}/link"), child_link)
            .unwrap();
        root.write(
            format!("overlay/{child_id}/lower"),
            format!("l/{parent_link}"),
        )
        .unwrap();

        // overlay/l/ symlinks.
        root.create_dir_all("overlay/l").unwrap();
        root.symlink(
            format!("../{child_id}/diff"),
            format!("overlay/l/{child_link}"),
        )
        .unwrap();
        root.symlink(
            format!("../{parent_id}/diff"),
            format!("overlay/l/{parent_link}"),
        )
        .unwrap();

        // tar-split: one file entry referencing shared.txt (size 12).
        let ndjson = concat!(r#"{"type":1,"name":"./shared.txt","size":12}"#, "\n");
        let gz_file = root
            .open_with(
                format!("overlay-layers/{child_id}.tar-split.gz"),
                cap_std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true),
            )
            .unwrap();
        let mut encoder = GzEncoder::new(gz_file.into_std(), Compression::default());
        encoder.write_all(ndjson.as_bytes()).unwrap();
        encoder.finish().unwrap();

        let storage = Storage::open(tmp.path()).unwrap();
        let layer = Layer::open(&storage, child_id).unwrap();
        let mut stream = TarSplitFdStream::new(&storage, &layer).unwrap();

        assert_eq!(
            stream.chain_link_ids().len(),
            2,
            "expected chain length 2 (child + parent)"
        );

        match stream.next().unwrap().expect("expected FileContent item") {
            TarSplitItem::FileContent { name, link_id, .. } => {
                assert_eq!(name, "./shared.txt");
                assert_eq!(
                    link_id, parent_link,
                    "./shared.txt metacopy stub in child must be skipped; \
                     real data is at parent (link_id={parent_link})"
                );
            }
            TarSplitItem::Segment(_) => panic!("expected FileContent, got Segment"),
        }

        assert!(stream.next().unwrap().is_none());
    }
}
