//! Layer reading and metadata handling.
//!
//! This module provides access to individual overlay layers and their metadata.
//! Layers are the fundamental storage units in the overlay driver, representing
//! filesystem changes that are stacked to form complete container images.
//!
//! # Overview
//!
//! The [`Layer`] struct represents a single layer in the overlay filesystem.
//! Each layer contains:
//! - A `diff/` directory with the actual file contents
//! - A `link` file containing a short 26-character identifier
//! - A `lower` file listing parent layers (if not a base layer)
//! - Metadata for whiteouts and opaque directories
//!
//! # Layer Structure
//!
//! Each layer is stored in `overlay/<layer-id>/`:
//! ```text
//! overlay/<layer-id>/
//! +-- diff/                 # Layer file contents
//! |   +-- etc/
//! |   |   +-- hosts
//! |   +-- usr/
//! |       +-- bin/
//! +-- link                  # Short link ID (26 chars)
//! +-- lower                 # Parent references: "l/<link-id>:l/<link-id>:..."
//! ```
//!
//! # Whiteouts and Opaque Directories
//!
//! The overlay driver uses special markers to indicate file deletions:
//! - `.wh.<filename>` - Whiteout file (marks `<filename>` as deleted)
//! - `.wh..wh..opq` - Opaque directory marker (hides lower layer contents)

use crate::error::{Result, StorageError};
use crate::storage::Storage;
use cap_std::fs::Dir;

/// Represents an overlay layer with its metadata and content.
#[derive(Debug)]
pub struct Layer {
    /// Layer ID (typically a 64-character hex digest).
    id: String,

    /// Directory handle for the layer directory (overlay/\<layer-id\>/).
    layer_dir: Dir,

    /// Directory handle for the diff/ subdirectory containing layer content.
    diff_dir: Dir,

    /// Short link identifier from the link file (26 characters).
    link_id: String,

    /// Parent layer link IDs from the lower file.
    parent_links: Vec<String>,
}

impl Layer {
    /// Open a layer by ID using fd-relative operations.
    ///
    /// # Errors
    ///
    /// Returns an error if the layer directory doesn't exist or cannot be opened.
    pub fn open(storage: &Storage, id: &str) -> Result<Self> {
        // Open overlay directory from storage root
        let overlay_dir = storage.root_dir().open_dir("overlay")?;

        // Open layer directory relative to overlay
        let layer_dir = overlay_dir
            .open_dir(id)
            .map_err(|_| StorageError::LayerNotFound(id.to_string()))?;

        // Open diff directory for content access
        let diff_dir = layer_dir.open_dir("diff")?;

        // Read metadata files using fd-relative operations
        let link_id = Self::read_link(&layer_dir)?;
        let parent_links = Self::read_lower(&layer_dir)?;

        Ok(Self {
            id: id.to_string(),
            layer_dir,
            diff_dir,
            link_id,
            parent_links,
        })
    }

    /// Get the layer ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Read the link file (26-char identifier) via Dir handle.
    fn read_link(layer_dir: &Dir) -> Result<String> {
        let content = layer_dir.read_to_string("link")?;
        Ok(content.trim().to_string())
    }

    /// Read the lower file (colon-separated parent links) via Dir handle.
    fn read_lower(layer_dir: &Dir) -> Result<Vec<String>> {
        match layer_dir.read_to_string("lower") {
            Ok(content) => {
                // Format is "l/<link-id>:l/<link-id>:..."
                let links: Vec<String> = content
                    .trim()
                    .split(':')
                    .filter_map(|s| s.strip_prefix("l/"))
                    .map(|s| s.to_string())
                    .collect();
                Ok(links)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()), // Base layer has no lower file
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// Get the short link ID for this layer.
    pub fn link_id(&self) -> &str {
        &self.link_id
    }

    /// Get the parent link IDs for this layer.
    pub fn parent_links(&self) -> &[String] {
        &self.parent_links
    }

    /// Get parent layer IDs (resolved from link IDs).
    ///
    /// This resolves the short link IDs from the `lower` file to full layer IDs
    /// by reading the symlinks in the `overlay/l/` directory.
    ///
    /// # Errors
    ///
    /// Returns an error if any link cannot be resolved.
    pub fn parents(&self, storage: &Storage) -> Result<Vec<String>> {
        self.parent_links
            .iter()
            .map(|link_id| storage.resolve_link(link_id))
            .collect()
    }

    /// Get a reference to the layer directory handle.
    pub fn layer_dir(&self) -> &Dir {
        &self.layer_dir
    }

    /// Get a reference to the diff directory handle.
    pub fn diff_dir(&self) -> &Dir {
        &self.diff_dir
    }

    /// Get the complete chain of layers from this layer to the base.
    ///
    /// Returns layers in order: [self, parent, grandparent, ..., base]
    ///
    /// # Errors
    ///
    /// Returns an error if the layer chain exceeds the maximum depth of 500 layers.
    pub fn layer_chain(self, storage: &Storage) -> Result<Vec<Layer>> {
        let mut chain = vec![self];
        let mut current_idx = 0;

        // Maximum depth to prevent infinite loops
        const MAX_DEPTH: usize = 500;

        while current_idx < chain.len() && chain.len() < MAX_DEPTH {
            let parent_ids = chain[current_idx].parents(storage)?;

            // Add all parents to the chain
            for parent_id in parent_ids {
                chain.push(Layer::open(storage, &parent_id)?);
            }

            current_idx += 1;
        }

        if chain.len() >= MAX_DEPTH {
            return Err(StorageError::InvalidStorage(
                "Layer chain exceeds maximum depth of 500".to_string(),
            ));
        }

        Ok(chain)
    }

    /// Open a file in the layer's diff directory using fd-relative operations.
    ///
    /// # Errors
    ///
    /// Returns an error if the file doesn't exist or cannot be opened.
    pub fn open_file(&self, path: impl AsRef<std::path::Path>) -> Result<cap_std::fs::File> {
        self.diff_dir.open(path).map_err(StorageError::Io)
    }

    /// Open a file and return a standard library File.
    ///
    /// # Errors
    ///
    /// Returns an error if the file doesn't exist or cannot be opened.
    pub fn open_file_std(&self, path: impl AsRef<std::path::Path>) -> Result<std::fs::File> {
        let file = self.diff_dir.open(path).map_err(StorageError::Io)?;
        Ok(file.into_std())
    }

    /// Get metadata for a file in the layer's diff directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the file doesn't exist.
    pub fn metadata(&self, path: impl AsRef<std::path::Path>) -> Result<cap_std::fs::Metadata> {
        self.diff_dir.metadata(path).map_err(StorageError::Io)
    }

    /// Read directory entries using Dir handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory doesn't exist.
    pub fn read_dir(&self, path: impl AsRef<std::path::Path>) -> Result<cap_std::fs::ReadDir> {
        self.diff_dir.read_dir(path).map_err(StorageError::Io)
    }

    /// Check if a whiteout file exists for the given filename.
    ///
    /// Whiteout format: `.wh.<filename>`
    ///
    /// # Arguments
    ///
    /// * `parent_path` - The directory path containing the file (empty string or "." for root)
    /// * `filename` - The name of the file to check for whiteout
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be accessed.
    pub fn has_whiteout(&self, parent_path: &str, filename: &str) -> Result<bool> {
        let whiteout_name = format!(".wh.{}", filename);

        // Handle root directory case
        if parent_path.is_empty() || parent_path == "." {
            Ok(self.diff_dir.try_exists(&whiteout_name)?)
        } else {
            match self.diff_dir.open_dir(parent_path) {
                Ok(parent_dir) => Ok(parent_dir.try_exists(&whiteout_name)?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(StorageError::Io(e)),
            }
        }
    }

    /// Check if a directory is marked as opaque (hides lower layers).
    ///
    /// Opaque marker: `.wh..wh..opq`
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be accessed.
    pub fn is_opaque_dir(&self, path: &str) -> Result<bool> {
        const OPAQUE_MARKER: &str = ".wh..wh..opq";

        if path.is_empty() || path == "." {
            Ok(self.diff_dir.try_exists(OPAQUE_MARKER)?)
        } else {
            match self.diff_dir.open_dir(path) {
                Ok(dir) => Ok(dir.try_exists(OPAQUE_MARKER)?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(StorageError::Io(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_parse_lower_format() {
        // Test that we correctly parse the lower file format
        let content = "l/ABCDEFGHIJKLMNOPQRSTUVWXY:l/BCDEFGHIJKLMNOPQRSTUVWXYZ";
        let links: Vec<String> = content
            .trim()
            .split(':')
            .filter_map(|s| s.strip_prefix("l/"))
            .map(|s| s.to_string())
            .collect();

        assert_eq!(links.len(), 2);
        assert_eq!(links[0], "ABCDEFGHIJKLMNOPQRSTUVWXY");
        assert_eq!(links[1], "BCDEFGHIJKLMNOPQRSTUVWXYZ");
    }

    /// Create a minimal mock storage + layer on disk so that `Layer::open()` succeeds.
    /// Returns the opened `Layer`.
    fn create_mock_layer(root: &Path) -> Layer {
        // Storage validation requires these three directories
        for d in ["overlay", "overlay-layers", "overlay-images"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }

        let layer_id = "test-layer-001";
        let layer_dir = root.join("overlay").join(layer_id);
        std::fs::create_dir_all(layer_dir.join("diff")).unwrap();
        std::fs::write(layer_dir.join("link"), "ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();

        let storage = Storage::open(root).unwrap();
        Layer::open(&storage, layer_id).unwrap()
    }

    // --- has_whiteout tests ---

    #[test]
    fn test_has_whiteout_in_root() {
        let dir = tempfile::tempdir().unwrap();
        let layer = create_mock_layer(dir.path());

        // No whiteout yet
        assert!(!layer.has_whiteout("", "somefile").unwrap());
        assert!(!layer.has_whiteout(".", "somefile").unwrap());

        // Create whiteout marker (regular file — has_whiteout uses try_exists)
        std::fs::write(
            dir.path().join("overlay/test-layer-001/diff/.wh.somefile"),
            "",
        )
        .unwrap();

        assert!(layer.has_whiteout("", "somefile").unwrap());
        assert!(layer.has_whiteout(".", "somefile").unwrap());
        // Different name still returns false
        assert!(!layer.has_whiteout("", "otherfile").unwrap());
    }

    #[test]
    fn test_has_whiteout_in_subdirectory() {
        let dir = tempfile::tempdir().unwrap();
        let layer = create_mock_layer(dir.path());
        let diff = dir.path().join("overlay/test-layer-001/diff");

        std::fs::create_dir_all(diff.join("etc")).unwrap();
        std::fs::write(diff.join("etc/.wh.hosts"), "").unwrap();

        assert!(layer.has_whiteout("etc", "hosts").unwrap());
        // Root doesn't have this whiteout
        assert!(!layer.has_whiteout("", "hosts").unwrap());
    }

    #[test]
    fn test_has_whiteout_in_nested_subdirectory() {
        let dir = tempfile::tempdir().unwrap();
        let layer = create_mock_layer(dir.path());
        let diff = dir.path().join("overlay/test-layer-001/diff");

        std::fs::create_dir_all(diff.join("usr/local/bin")).unwrap();
        std::fs::write(diff.join("usr/local/bin/.wh.myapp"), "").unwrap();

        assert!(layer.has_whiteout("usr/local/bin", "myapp").unwrap());
        assert!(!layer.has_whiteout("usr/local", "myapp").unwrap());
        assert!(!layer.has_whiteout("usr", "myapp").unwrap());
    }

    #[test]
    fn test_has_whiteout_nonexistent_parent() {
        let dir = tempfile::tempdir().unwrap();
        let layer = create_mock_layer(dir.path());

        // Parent directory doesn't exist — should return false, not error
        assert!(!layer.has_whiteout("no/such/dir", "file").unwrap());
    }

    #[test]
    fn test_has_whiteout_multiple() {
        let dir = tempfile::tempdir().unwrap();
        let layer = create_mock_layer(dir.path());
        let diff = dir.path().join("overlay/test-layer-001/diff");

        std::fs::write(diff.join(".wh.file_a"), "").unwrap();
        std::fs::write(diff.join(".wh.file_b"), "").unwrap();

        assert!(layer.has_whiteout("", "file_a").unwrap());
        assert!(layer.has_whiteout("", "file_b").unwrap());
        assert!(!layer.has_whiteout("", "file_c").unwrap());
    }

    // --- is_opaque_dir tests ---

    #[test]
    fn test_is_opaque_dir_in_root() {
        let dir = tempfile::tempdir().unwrap();
        let layer = create_mock_layer(dir.path());
        let diff = dir.path().join("overlay/test-layer-001/diff");

        assert!(!layer.is_opaque_dir("").unwrap());
        assert!(!layer.is_opaque_dir(".").unwrap());

        std::fs::write(diff.join(".wh..wh..opq"), "").unwrap();

        assert!(layer.is_opaque_dir("").unwrap());
        assert!(layer.is_opaque_dir(".").unwrap());
    }

    #[test]
    fn test_is_opaque_dir_in_subdirectory() {
        let dir = tempfile::tempdir().unwrap();
        let layer = create_mock_layer(dir.path());
        let diff = dir.path().join("overlay/test-layer-001/diff");

        std::fs::create_dir_all(diff.join("etc")).unwrap();
        std::fs::write(diff.join("etc/.wh..wh..opq"), "").unwrap();

        assert!(layer.is_opaque_dir("etc").unwrap());
        // Root is not opaque
        assert!(!layer.is_opaque_dir("").unwrap());
    }

    #[test]
    fn test_is_opaque_dir_false_for_normal_dir() {
        let dir = tempfile::tempdir().unwrap();
        let layer = create_mock_layer(dir.path());
        let diff = dir.path().join("overlay/test-layer-001/diff");

        // Create a subdirectory with a regular file, but no opaque marker
        std::fs::create_dir_all(diff.join("var/log")).unwrap();
        std::fs::write(diff.join("var/log/syslog"), "log data").unwrap();

        assert!(!layer.is_opaque_dir("var").unwrap());
        assert!(!layer.is_opaque_dir("var/log").unwrap());
    }

    #[test]
    fn test_is_opaque_dir_nonexistent_path() {
        let dir = tempfile::tempdir().unwrap();
        let layer = create_mock_layer(dir.path());

        // Non-existent directory should return false, not error
        assert!(!layer.is_opaque_dir("no/such/path").unwrap());
    }

    #[test]
    fn test_is_opaque_dir_nested() {
        let dir = tempfile::tempdir().unwrap();
        let layer = create_mock_layer(dir.path());
        let diff = dir.path().join("overlay/test-layer-001/diff");

        // Only the nested dir is opaque, not its parents
        std::fs::create_dir_all(diff.join("a/b/c")).unwrap();
        std::fs::write(diff.join("a/b/c/.wh..wh..opq"), "").unwrap();

        assert!(!layer.is_opaque_dir("a").unwrap());
        assert!(!layer.is_opaque_dir("a/b").unwrap());
        assert!(layer.is_opaque_dir("a/b/c").unwrap());
    }

    // --- Interaction between whiteout and opaque ---

    #[test]
    fn test_whiteout_and_opaque_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let layer = create_mock_layer(dir.path());
        let diff = dir.path().join("overlay/test-layer-001/diff");

        std::fs::create_dir_all(diff.join("mydir")).unwrap();
        // Opaque marker in mydir
        std::fs::write(diff.join("mydir/.wh..wh..opq"), "").unwrap();
        // Also a file whiteout in mydir
        std::fs::write(diff.join("mydir/.wh.oldfile"), "").unwrap();

        assert!(layer.is_opaque_dir("mydir").unwrap());
        assert!(layer.has_whiteout("mydir", "oldfile").unwrap());
    }

    #[test]
    fn test_whiteout_of_dotdot_prefix_name() {
        // .wh..wh. is NOT an opaque whiteout — it's a whiteout for a file
        // literally named ".wh." (the has_whiteout logic just prepends ".wh.")
        let dir = tempfile::tempdir().unwrap();
        let layer = create_mock_layer(dir.path());
        let diff = dir.path().join("overlay/test-layer-001/diff");

        // Create .wh..wh. (whiteout for file named ".wh.")
        std::fs::write(diff.join(".wh..wh."), "").unwrap();

        assert!(layer.has_whiteout("", ".wh.").unwrap());
        // This is NOT an opaque marker — the opaque marker is ".wh..wh..opq"
        assert!(!layer.is_opaque_dir("").unwrap());
    }
}
