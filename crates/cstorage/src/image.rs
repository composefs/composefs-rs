//! Image reading and manifest parsing.
//!
//! This module provides access to OCI image manifests and metadata stored in
//! the `overlay-images/` directory. All operations use fd-relative access via
//! cap-std Dir handles.
//!
//! # Overview
//!
//! The [`Image`] struct represents a container image stored in the overlay driver.
//! It provides access to:
//! - OCI image manifests ([`oci_spec::image::ImageManifest`])
//! - OCI image configurations ([`oci_spec::image::ImageConfiguration`])
//! - Layer information (diff_ids that map to storage layer IDs)
//! - Additional metadata stored in base64-encoded files
//!
//! # Image Directory Structure
//!
//! Each image is stored in `overlay-images/<image-id>/`:
//! ```text
//! overlay-images/<image-id>/
//! +-- manifest              # OCI image manifest (JSON)
//! +-- =<base64-key>         # Additional metadata files
//! ```

use base64::{engine::general_purpose::STANDARD, Engine};
use cap_std::fs::Dir;
use oci_spec::image::{ImageConfiguration, ImageManifest};
use std::io::Read;

use crate::error::{Result, StorageError};
use crate::storage::Storage;

/// Filename for OCI image manifest in the image directory.
const MANIFEST_FILENAME: &str = "manifest";

/// Represents an OCI image with its metadata and manifest.
#[derive(Debug)]
pub struct Image {
    /// Image ID (typically a 64-character hex digest).
    id: String,

    /// Directory handle for overlay-images/\<image-id\>/.
    image_dir: Dir,
}

impl Image {
    /// Open an image by ID using fd-relative operations.
    ///
    /// The ID can be provided with or without a `sha256:` prefix - the prefix
    /// will be stripped if present, since containers-storage directories use
    /// just the hex digest.
    ///
    /// # Errors
    ///
    /// Returns an error if the image directory doesn't exist or cannot be opened.
    pub fn open(storage: &Storage, id: &str) -> Result<Self> {
        // Strip the sha256: prefix if present - containers-storage directories
        // use just the hex digest, but image IDs from podman (e.g. via --iidfile)
        // include the prefix. See https://github.com/containers/skopeo/issues/2750
        let id = id.strip_prefix("sha256:").unwrap_or(id);

        // Open overlay-images directory from storage root
        let images_dir = storage.root_dir().open_dir("overlay-images")?;

        // Open specific image directory
        let image_dir = images_dir
            .open_dir(id)
            .map_err(|_| StorageError::ImageNotFound(id.to_string()))?;

        Ok(Self {
            id: id.to_string(),
            image_dir,
        })
    }

    /// Get the image ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Read and parse the image manifest.
    ///
    /// The manifest is stored as a JSON file named "manifest" in the image directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest file cannot be read or parsed.
    pub fn manifest(&self) -> Result<ImageManifest> {
        let file = self.image_dir.open(MANIFEST_FILENAME)?;
        serde_json::from_reader(file)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid manifest JSON: {}", e)))
    }

    /// Read and parse the image configuration.
    ///
    /// The image config is stored with a base64-encoded key based on the image digest.
    ///
    /// # Errors
    ///
    /// Returns an error if the config file cannot be read or parsed.
    pub fn config(&self) -> Result<ImageConfiguration> {
        // The config is stored with key: sha256:<image-id>
        // Base64 encode: "sha256:<id>"
        let key = format!("sha256:{}", self.id);
        let encoded_key = STANDARD.encode(key.as_bytes());

        let config_data = self.read_metadata(&encoded_key)?;
        serde_json::from_slice(&config_data)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid config JSON: {}", e)))
    }

    /// Get the OCI diff_ids for this image in order (base to top).
    ///
    /// This returns the diff_ids from the image config, which are the uncompressed
    /// tar digests. Note that these are **not** the same as the storage layer IDs!
    /// To get the actual storage layer IDs, use [`storage_layer_ids()`](Self::storage_layer_ids).
    ///
    /// # Errors
    ///
    /// Returns an error if the config cannot be read or parsed.
    pub fn layers(&self) -> Result<Vec<String>> {
        let config = self.config()?;

        // Extract diff_ids from config - these are NOT the storage layer IDs
        let diff_ids: Vec<String> = config
            .rootfs()
            .diff_ids()
            .iter()
            .map(|digest| {
                // Remove the "sha256:" prefix if present
                let diff_id = digest.to_string();
                diff_id
                    .strip_prefix("sha256:")
                    .unwrap_or(&diff_id)
                    .to_string()
            })
            .collect();

        Ok(diff_ids)
    }

    /// Get the storage layer IDs for this image in order (base to top).
    ///
    /// Unlike [`layers()`](Self::layers) which returns OCI diff_ids, this method
    /// returns the actual storage layer directory names by resolving diff_ids
    /// through the `layers.json` mapping file.
    ///
    /// # Errors
    ///
    /// Returns an error if the config cannot be read, parsed, or if any layer
    /// cannot be resolved.
    pub fn storage_layer_ids(&self, storage: &Storage) -> Result<Vec<String>> {
        let diff_ids = self.layers()?;
        diff_ids
            .iter()
            .map(|diff_id| storage.resolve_diff_id(diff_id))
            .collect()
    }

    /// Read additional metadata files.
    ///
    /// Metadata files are stored with base64-encoded keys as filenames,
    /// prefixed with '='.
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata file doesn't exist or cannot be read.
    pub fn read_metadata(&self, key: &str) -> Result<Vec<u8>> {
        let filename = format!("={}", key);
        let mut file = self.image_dir.open(&filename)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }

    /// Get a reference to the image directory handle.
    pub fn image_dir(&self) -> &Dir {
        &self.image_dir
    }

    /// Get the repository names/tags for this image.
    ///
    /// Reads from the `overlay-images/images.json` index file to find the
    /// names associated with this image.
    ///
    /// # Errors
    ///
    /// Returns an error if the images.json file cannot be read or parsed.
    pub fn names(&self, storage: &Storage) -> Result<Vec<String>> {
        let images_dir = storage.root_dir().open_dir("overlay-images")?;
        let mut file = images_dir.open("images.json")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let entries: Vec<ImageJsonEntry> = serde_json::from_str(&contents)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid images.json: {}", e)))?;

        for entry in entries {
            if entry.id == self.id {
                return Ok(entry.names.unwrap_or_default());
            }
        }

        // Image not found in images.json - return empty names
        Ok(Vec::new())
    }
}

/// Entry in images.json for image name lookups.
#[derive(Debug, serde::Deserialize)]
struct ImageJsonEntry {
    id: String,
    names: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_parsing() {
        let manifest_json = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "size": 1234
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "size": 5678
                },
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "size": 9012
                }
            ]
        }"#;

        let manifest: ImageManifest = serde_json::from_str(manifest_json).unwrap();
        assert_eq!(manifest.schema_version(), 2);
        assert_eq!(manifest.layers().len(), 2);
    }
}
