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

use std::io::{BufRead, BufReader, Read};
use std::os::fd::OwnedFd;

use base64::prelude::*;
use cap_std::fs::{Dir, File};
use crc::{Crc, CRC_64_GO_ISO};
use flate2::read::GzDecoder;
use serde::Deserialize;

use crate::error::{Result, StorageError};
use crate::layer::Layer;
use crate::storage::Storage;

/// CRC64-ISO implementation for verifying file checksums.
const CRC64_ISO: Crc<u64> = Crc::<u64>::new(&CRC_64_GO_ISO);

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
        let header = tar_header::Header::from_bytes(header_bytes).map_err(|e| {
            StorageError::TarSplitError(format!("Failed to parse TAR header: {}", e))
        })?;

        header.verify_checksum().map_err(|e| {
            StorageError::TarSplitError(format!("TAR header checksum error: {}", e))
        })?;

        let name = String::from_utf8_lossy(header.path_bytes()).to_string();
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
        let typeflag = header.entry_type().to_byte();
        let linkname = String::from_utf8_lossy(header.link_name_bytes()).to_string();
        let uname = header
            .username()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .unwrap_or_default();
        let gname = header
            .groupname()
            .map(|b| String::from_utf8_lossy(b).to_string())
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

        // Open the layer for on-demand file lookups
        let layer = Layer::open(storage, layer.id())?;

        // Clone storage root dir for on-demand parent layer access
        let storage_root = storage.root_dir().try_clone()?;

        Ok(Self {
            layer,
            storage_root,
            reader,
            entry_count: 0,
        })
    }

    /// Open a file in the layer chain, trying current layer first then parents.
    fn open_file_in_chain(&self, path: &str) -> Result<cap_std::fs::File> {
        // Normalize path (remove leading ./)
        let normalized_path = path.strip_prefix("./").unwrap_or(path);

        // Try to open in current layer first
        match self.layer.diff_dir().open(normalized_path) {
            Ok(file) => return Ok(file),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Continue to search parent layers
            }
            Err(e) => return Err(StorageError::Io(e)),
        }

        // Search parent layers on-demand
        self.search_parent_layers(&self.layer, normalized_path, 0)
    }

    /// Recursively search parent layers for a file.
    fn search_parent_layers(
        &self,
        current_layer: &Layer,
        path: &str,
        depth: usize,
    ) -> Result<cap_std::fs::File> {
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
                Ok(file) => return Ok(file),
                Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    // File not in this parent, recursively search its parents
                    match self.search_by_layer_id(&parent_id, path, depth + 1) {
                        Ok(file) => return Ok(file),
                        Err(_) => continue, // Try next parent at this level
                    }
                }
                Err(_) => continue, // Try next parent
            }
        }

        Err(StorageError::TarSplitError(format!(
            "File not found in layer chain: {}",
            path
        )))
    }

    /// Search for a file starting from a layer ID.
    fn search_by_layer_id(
        &self,
        layer_id: &str,
        path: &str,
        depth: usize,
    ) -> Result<cap_std::fs::File> {
        const MAX_DEPTH: usize = 500;

        if depth >= MAX_DEPTH {
            return Err(StorageError::TarSplitError(format!(
                "Layer chain exceeds maximum depth of {} while searching for file: {}",
                MAX_DEPTH, path
            )));
        }

        // Try to open file in this layer
        match self.open_file_in_layer(layer_id, path) {
            Ok(file) => return Ok(file),
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
                Ok(file) => return Ok(file),
                Err(_) => continue,
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
    fn open_file_in_layer(&self, layer_id: &str, path: &str) -> Result<cap_std::fs::File> {
        let overlay_dir = self.storage_root.open_dir("overlay")?;
        let layer_dir = overlay_dir.open_dir(layer_id)?;
        let diff_dir = layer_dir.open_dir("diff")?;
        diff_dir.open(path).map_err(StorageError::Io)
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
            Err(_) => Ok(Vec::new()), // Base layer has no lower file
        }
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

                                let mut file = self.open_file_in_chain(path)?;

                                // Verify CRC64 if provided
                                if let Some(ref crc64_b64) = crc64 {
                                    self.verify_crc64(&mut file, crc64_b64, file_size)?;

                                    // Reopen file since we consumed it for CRC check
                                    file = self.open_file_in_chain(path)?;
                                }

                                // Convert to OwnedFd and return
                                let std_file = file.into_std();
                                let owned_fd: OwnedFd = std_file.into();
                                return Ok(Some(TarSplitItem::FileContent {
                                    fd: owned_fd,
                                    size: file_size,
                                    name: path.clone(),
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
    use super::*;

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
}
