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
            Err(_) => Ok(Vec::new()), // Base layer has no lower file
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
}
