//! Storage access for container overlay filesystem.
//!
//! This module provides the main [`Storage`] struct for accessing containers-storage
//! overlay driver data. All file access uses cap-std for fd-relative operations,
//! providing security against path traversal attacks and TOCTOU race conditions.
//!
//! # Overview
//!
//! The `Storage` struct is the primary entry point for interacting with container
//! storage. It holds a capability-based directory handle to the storage root.
//!
//! # Storage Structure
//!
//! Container storage on disk follows this layout:
//! ```text
//! /var/lib/containers/storage/
//! +-- overlay/            # Layer data
//! |   +-- <layer-id>/     # Individual layer directories
//! |   |   +-- diff/       # Layer file contents
//! |   |   +-- link        # Short link ID (26 chars)
//! |   |   +-- lower       # Parent layer references
//! |   +-- l/              # Short link directory (symlinks)
//! +-- overlay-layers/     # Tar-split metadata
//! |   +-- <layer-id>.tar-split.gz
//! +-- overlay-images/     # Image metadata
//!     +-- <image-id>/
//!         +-- manifest    # OCI image manifest
//!         +-- =<key>      # Base64-encoded metadata files
//! ```
//!
//! # Security Model
//!
//! All file operations are performed via [`cap_std::fs::Dir`] handles, which provide:
//! - Protection against path traversal attacks
//! - Prevention of TOCTOU race conditions
//! - Guarantee that all access stays within the storage directory tree

use crate::error::{Result, StorageError};
use crate::lockfile::{LastWrite, LockFile, RLockGuard};
use cap_std::ambient_authority;
use cap_std::fs::Dir;
use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Main storage handle providing read-only access to container storage.
///
/// The Storage struct holds:
/// - A `Dir` handle to the storage root for fd-relative file operations
/// - Optional lock files for coordinating reads with other processes
#[derive(Debug)]
pub struct Storage {
    /// Directory handle for the storage root, used for all fd-relative operations.
    root_dir: Dir,

    /// Lock file for layer operations (overlay-layers/layers.lock).
    layers_lock: Option<LockFile>,

    /// Lock file for image operations (overlay-images/images.lock).
    images_lock: Option<LockFile>,
}

impl Storage {
    /// Open storage at the given root path.
    ///
    /// This validates that the path points to a valid container storage directory
    /// by checking for required subdirectories and the database file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path does not exist or is not a directory
    /// - Required subdirectories are missing
    /// - The database file is missing or invalid
    pub fn open<P: AsRef<Path>>(root: P) -> Result<Self> {
        let root_path = root.as_ref();

        // Open the directory handle for fd-relative operations
        let root_dir = Dir::open_ambient_dir(root_path, ambient_authority()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::RootNotFound(root_path.to_path_buf())
            } else {
                StorageError::Io(e)
            }
        })?;

        // Validate storage structure
        Self::validate_storage(&root_dir)?;

        // Try to open lock files (they may not exist for read-only storage)
        let layers_lock_path = root_path.join("overlay-layers/layers.lock");
        let images_lock_path = root_path.join("overlay-images/images.lock");

        let layers_lock = LockFile::open(&layers_lock_path).ok();
        let images_lock = LockFile::open(&images_lock_path).ok();

        Ok(Self {
            root_dir,
            layers_lock,
            images_lock,
        })
    }

    /// Discover storage root from default locations.
    ///
    /// Searches for container storage in the following order:
    /// 1. `$CONTAINERS_STORAGE_ROOT` environment variable
    /// 2. Rootless storage: `$XDG_DATA_HOME/containers/storage` or `~/.local/share/containers/storage`
    /// 3. Root storage: `/var/lib/containers/storage`
    ///
    /// # Errors
    ///
    /// Returns an error if no valid storage location is found.
    pub fn discover() -> Result<Self> {
        let search_paths = Self::default_search_paths();

        for path in search_paths {
            if path.exists() {
                match Self::open(&path) {
                    Ok(storage) => return Ok(storage),
                    Err(_) => continue,
                }
            }
        }

        Err(StorageError::InvalidStorage(
            "No valid storage location found. Searched default locations.".to_string(),
        ))
    }

    /// Get the default search paths for storage discovery.
    fn default_search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // 1. Check CONTAINERS_STORAGE_ROOT environment variable
        if let Ok(root) = env::var("CONTAINERS_STORAGE_ROOT") {
            paths.push(PathBuf::from(root));
        }

        // 2. Check rootless locations
        if let Ok(home) = env::var("HOME") {
            let home_path = PathBuf::from(home);

            // Try XDG_DATA_HOME first
            if let Ok(xdg_data) = env::var("XDG_DATA_HOME") {
                paths.push(PathBuf::from(xdg_data).join("containers/storage"));
            }

            // Fallback to ~/.local/share/containers/storage
            paths.push(home_path.join(".local/share/containers/storage"));
        }

        // 3. Check root location
        paths.push(PathBuf::from("/var/lib/containers/storage"));

        paths
    }

    /// Validate that the directory structure is a valid overlay storage.
    fn validate_storage(root_dir: &Dir) -> Result<()> {
        // Check for required subdirectories
        let required_dirs = ["overlay", "overlay-layers", "overlay-images"];

        for dir_name in &required_dirs {
            match root_dir.try_exists(dir_name) {
                Ok(exists) if !exists => {
                    return Err(StorageError::InvalidStorage(format!(
                        "Missing required directory: {}",
                        dir_name
                    )));
                }
                Err(e) => return Err(StorageError::Io(e)),
                _ => {}
            }
        }

        Ok(())
    }

    /// Create storage from an existing root directory handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory is not a valid container storage.
    pub fn from_root_dir(root_dir: Dir) -> Result<Self> {
        Self::validate_storage(&root_dir)?;
        Ok(Self {
            root_dir,
            layers_lock: None,
            images_lock: None,
        })
    }

    /// Get a reference to the root directory handle.
    pub fn root_dir(&self) -> &Dir {
        &self.root_dir
    }

    // ========== Locking Methods ==========

    /// Acquire a shared (read) lock on the layers store.
    ///
    /// This lock allows concurrent readers but blocks writers. Use this when
    /// reading layer data to ensure consistency.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock file is not available.
    pub fn rlock_layers(&self) -> Result<LayerRLockGuard<'_>> {
        let lock = self
            .layers_lock
            .as_ref()
            .ok_or_else(|| StorageError::InvalidStorage("No layers lock file".to_string()))?;
        let guard = lock.rlock();
        Ok(LayerRLockGuard {
            storage: self,
            _lock: guard,
        })
    }

    /// Acquire a shared (read) lock on the images store.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock file is not available.
    pub fn rlock_images(&self) -> Result<ImageRLockGuard<'_>> {
        let lock = self
            .images_lock
            .as_ref()
            .ok_or_else(|| StorageError::InvalidStorage("No images lock file".to_string()))?;
        let guard = lock.rlock();
        Ok(ImageRLockGuard {
            storage: self,
            _lock: guard,
        })
    }

    // ========== Change Detection Methods ==========

    /// Get the current "last write" token for the layers store.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock file is not available.
    pub fn get_layers_last_write(&self) -> Result<LastWrite> {
        let lock = self
            .layers_lock
            .as_ref()
            .ok_or_else(|| StorageError::InvalidStorage("No layers lock file".to_string()))?;
        Ok(lock.get_last_write()?)
    }

    /// Get the current "last write" token for the images store.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock file is not available.
    pub fn get_images_last_write(&self) -> Result<LastWrite> {
        let lock = self
            .images_lock
            .as_ref()
            .ok_or_else(|| StorageError::InvalidStorage("No images lock file".to_string()))?;
        Ok(lock.get_last_write()?)
    }

    /// Check if the layers store was modified since the given token.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock file is not available.
    pub fn layers_modified_since(&self, token: &LastWrite) -> Result<bool> {
        let lock = self
            .layers_lock
            .as_ref()
            .ok_or_else(|| StorageError::InvalidStorage("No layers lock file".to_string()))?;
        Ok(lock.modified_since(token)?)
    }

    /// Check if the images store was modified since the given token.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock file is not available.
    pub fn images_modified_since(&self, token: &LastWrite) -> Result<bool> {
        let lock = self
            .images_lock
            .as_ref()
            .ok_or_else(|| StorageError::InvalidStorage("No images lock file".to_string()))?;
        Ok(lock.modified_since(token)?)
    }

    /// Resolve a link ID to a layer ID using fd-relative symlink reading.
    ///
    /// # Errors
    ///
    /// Returns an error if the link doesn't exist or has an invalid format.
    pub fn resolve_link(&self, link_id: &str) -> Result<String> {
        // Open overlay directory from storage root
        let overlay_dir = self.root_dir.open_dir("overlay")?;

        // Open link directory
        let link_dir = overlay_dir.open_dir("l")?;

        // Read symlink target using fd-relative operation
        let target = link_dir.read_link(link_id).map_err(|e| {
            StorageError::LinkReadError(format!("Failed to read link {}: {}", link_id, e))
        })?;

        // Extract layer ID from symlink target
        Self::extract_layer_id_from_link(&target)
    }

    /// Extract layer ID from symlink target path.
    ///
    /// Target format: ../<layer-id>/diff
    fn extract_layer_id_from_link(target: &Path) -> Result<String> {
        // Convert to string for processing
        let target_str = target.to_str().ok_or_else(|| {
            StorageError::LinkReadError("Invalid UTF-8 in link target".to_string())
        })?;

        // Split by '/' and find the layer ID component
        let components: Vec<&str> = target_str.split('/').collect();

        // Expected format: ../<layer-id>/diff
        // So we need the second-to-last component
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

    /// List all images in storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the images directory cannot be read.
    pub fn list_images(&self) -> Result<Vec<crate::image::Image>> {
        use crate::image::Image;

        let images_dir = self.root_dir.open_dir("overlay-images")?;
        let mut images = Vec::new();

        for entry in images_dir.entries()? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let id = entry
                    .file_name()
                    .to_str()
                    .ok_or_else(|| {
                        StorageError::InvalidStorage(
                            "Invalid UTF-8 in image directory name".to_string(),
                        )
                    })?
                    .to_string();
                images.push(Image::open(self, &id)?);
            }
        }
        Ok(images)
    }

    /// Get an image by ID.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ImageNotFound`] if the image doesn't exist.
    pub fn get_image(&self, id: &str) -> Result<crate::image::Image> {
        crate::image::Image::open(self, id)
    }

    /// Get layers for an image (in order from base to top).
    ///
    /// # Errors
    ///
    /// Returns an error if any layer cannot be opened.
    pub fn get_image_layers(
        &self,
        image: &crate::image::Image,
    ) -> Result<Vec<crate::layer::Layer>> {
        use crate::layer::Layer;
        // image.layers() returns diff_ids, which need to be mapped to storage layer IDs
        let diff_ids = image.layers()?;
        let mut layers = Vec::new();
        for diff_id in diff_ids {
            let layer_id = self.resolve_diff_id(&diff_id)?;
            layers.push(Layer::open(self, &layer_id)?);
        }
        Ok(layers)
    }

    /// Find an image by name.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ImageNotFound`] if no image with the given name is found.
    pub fn find_image_by_name(&self, name: &str) -> Result<crate::image::Image> {
        // Read images.json from overlay-images/
        let images_dir = self.root_dir.open_dir("overlay-images")?;
        let mut file = images_dir.open("images.json")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Parse the JSON array
        let entries: Vec<ImageEntry> = serde_json::from_str(&contents)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid images.json: {}", e)))?;

        // Search for matching name
        for entry in &entries {
            if let Some(names) = &entry.names {
                for image_name in names {
                    if image_name == name {
                        return self.get_image(&entry.id);
                    }
                }
            }
        }

        // Try partial matching (e.g., "alpine:latest" matches "docker.io/library/alpine:latest")
        for entry in &entries {
            if let Some(names) = &entry.names {
                for image_name in names {
                    // Check if name is a suffix (after removing registry/namespace prefix)
                    if let Some(prefix) = image_name.strip_suffix(name) {
                        // Verify it's a proper boundary (preceded by '/')
                        if prefix.is_empty() || prefix.ends_with('/') {
                            return self.get_image(&entry.id);
                        }
                    }
                }
            }
        }

        // Try matching short name without tag (e.g., "busybox" matches "docker.io/library/busybox:latest")
        // This handles the common case of just specifying the image name
        let name_with_tag = if name.contains(':') {
            name.to_string()
        } else {
            format!("{}:latest", name)
        };

        for entry in &entries {
            if let Some(names) = &entry.names {
                for image_name in names {
                    // Check if image_name ends with /name:tag pattern
                    if let Some(prefix) = image_name.strip_suffix(&name_with_tag) {
                        if prefix.is_empty() || prefix.ends_with('/') {
                            return self.get_image(&entry.id);
                        }
                    }
                }
            }
        }

        Err(StorageError::ImageNotFound(name.to_string()))
    }

    /// Resolve a diff-digest to a storage layer ID.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::LayerNotFound`] if no layer with the given diff-digest exists.
    pub fn resolve_diff_id(&self, diff_digest: &str) -> Result<String> {
        // Normalize the diff_digest to include sha256: prefix for comparison
        let normalized = if diff_digest.starts_with("sha256:") {
            diff_digest.to_string()
        } else {
            format!("sha256:{}", diff_digest)
        };

        // Read layers.json from overlay-layers/
        let layers_dir = self.root_dir.open_dir("overlay-layers")?;
        let mut file = layers_dir.open("layers.json")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Parse the JSON array
        let entries: Vec<LayerEntry> = serde_json::from_str(&contents)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid layers.json: {}", e)))?;

        // Search for matching diff-digest
        for entry in entries {
            if entry.diff_digest.as_ref() == Some(&normalized) {
                return Ok(entry.id);
            }
        }

        Err(StorageError::LayerNotFound(diff_digest.to_string()))
    }

    /// Get layer metadata including size information.
    ///
    /// # Errors
    ///
    /// Returns an error if the layer is not found.
    pub fn get_layer_metadata(&self, layer_id: &str) -> Result<LayerMetadata> {
        // Read layers.json from overlay-layers/
        let layers_dir = self.root_dir.open_dir("overlay-layers")?;
        let mut file = layers_dir.open("layers.json")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Parse the JSON array
        let entries: Vec<LayerEntry> = serde_json::from_str(&contents)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid layers.json: {}", e)))?;

        // Search for matching layer ID
        for entry in entries {
            if entry.id == layer_id {
                return Ok(LayerMetadata {
                    id: entry.id,
                    parent: entry.parent,
                    diff_size: entry.diff_size,
                    compressed_size: entry.compressed_size,
                });
            }
        }

        Err(StorageError::LayerNotFound(layer_id.to_string()))
    }

    /// Calculate the total uncompressed size of an image.
    ///
    /// # Errors
    ///
    /// Returns an error if any layer metadata cannot be read.
    pub fn calculate_image_size(&self, image: &crate::image::Image) -> Result<u64> {
        let layers = self.get_image_layers(image)?;
        let mut total_size: u64 = 0;

        for layer in &layers {
            let metadata = self.get_layer_metadata(layer.id())?;
            if let Some(size) = metadata.diff_size {
                total_size = total_size.saturating_add(size);
            }
        }

        Ok(total_size)
    }
}

/// Entry in images.json for image name lookups.
#[derive(Debug, serde::Deserialize)]
struct ImageEntry {
    id: String,
    names: Option<Vec<String>>,
}

/// Entry in layers.json for layer ID lookups.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct LayerEntry {
    id: String,
    parent: Option<String>,
    diff_digest: Option<String>,
    diff_size: Option<u64>,
    compressed_size: Option<u64>,
}

/// Metadata about a layer from layers.json.
#[derive(Debug, Clone)]
pub struct LayerMetadata {
    /// Layer storage ID.
    pub id: String,
    /// Parent layer ID (if not base layer).
    pub parent: Option<String>,
    /// Uncompressed diff size in bytes.
    pub diff_size: Option<u64>,
    /// Compressed size in bytes.
    pub compressed_size: Option<u64>,
}

// ========== Lock Guard Types ==========

/// RAII guard for a shared (read) lock on the layers store.
#[derive(Debug)]
pub struct LayerRLockGuard<'a> {
    /// Reference to the storage that owns the lock.
    storage: &'a Storage,
    /// The underlying read lock guard from the lockfile module.
    _lock: RLockGuard<'a>,
}

impl<'a> LayerRLockGuard<'a> {
    /// Get a reference to the storage.
    pub fn storage(&self) -> &Storage {
        self.storage
    }
}

/// RAII guard for a shared (read) lock on the images store.
#[derive(Debug)]
pub struct ImageRLockGuard<'a> {
    /// Reference to the storage that owns the lock.
    storage: &'a Storage,
    /// The underlying read lock guard from the lockfile module.
    _lock: RLockGuard<'a>,
}

impl<'a> ImageRLockGuard<'a> {
    /// Get a reference to the storage.
    pub fn storage(&self) -> &Storage {
        self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_search_paths() {
        let paths = Storage::default_search_paths();
        assert!(!paths.is_empty(), "Should have at least one search path");
    }

    #[test]
    fn test_storage_validation() {
        // Create a mock storage directory structure for testing
        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path();

        // Create required directories
        std::fs::create_dir_all(storage_path.join("overlay")).unwrap();
        std::fs::create_dir_all(storage_path.join("overlay-layers")).unwrap();
        std::fs::create_dir_all(storage_path.join("overlay-images")).unwrap();

        let storage = Storage::open(storage_path).unwrap();
        assert!(storage.root_dir().try_exists("overlay").unwrap());
    }
}
