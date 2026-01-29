//! containers-storage integration for zero-copy layer import.
//!
//! This module provides functionality to import container images directly from
//! containers-storage (as used by podman/buildah) into composefs repositories.
//! It uses the cstorage crate to access the storage and leverages reflinks when
//! available to avoid copying file data, enabling efficient zero-copy extraction.
//!
//! This module requires the `containers-storage` feature to be enabled.
//!
//! The main entry point is [`import_from_containers_storage`], which takes an
//! image ID and imports all layers into the repository.
//!
//! # Overview
//!
//! When importing from containers-storage, we:
//! 1. Open the storage and locate the image
//! 2. For each layer, iterate through the tar-split metadata
//! 3. For large files (> INLINE_CONTENT_MAX), reflink directly to objects/
//! 4. For small files, embed inline in the splitstream
//! 5. Handle overlay whiteouts properly
//!
//! # Example
//!
//! ```ignore
//! use composefs_oci::cstor::import_from_containers_storage;
//!
//! let repo = Arc::new(Repository::open_user()?);
//! let result = import_from_containers_storage(&repo, "sha256:abc123...", None).await?;
//! println!("Imported config: {}", result.0);
//! ```

use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::Digest;
use tokio::task::spawn_blocking;

use composefs::{fsverity::FsVerityHashValue, repository::Repository, INLINE_CONTENT_MAX};

use cstorage::{Image, Layer, Storage, TarSplitFdStream, TarSplitItem};

use crate::skopeo::{OCI_CONFIG_CONTENT_TYPE, TAR_LAYER_CONTENT_TYPE};
use crate::{config_identifier, layer_identifier, ContentAndVerity};

/// Import a container image from containers-storage into the composefs repository.
///
/// This function reads an image from the local containers-storage (podman/buildah)
/// and imports all layers using reflinks when possible, avoiding data duplication.
///
/// # Arguments
/// * `repo` - The composefs repository to import into
/// * `image_id` - The image ID (sha256 digest or name) to import
/// * `reference` - Optional reference name to assign to the imported config
///
/// # Returns
/// A tuple of (config_digest, config_verity_id) for the imported image.
pub async fn import_from_containers_storage<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    image_id: &str,
    reference: Option<&str>,
) -> Result<ContentAndVerity<ObjectID>> {
    let repo = Arc::clone(repo);
    let image_id = image_id.to_owned();
    let reference = reference.map(|s| s.to_owned());

    spawn_blocking(move || {
        import_from_containers_storage_blocking(&repo, &image_id, reference.as_deref())
    })
    .await
    .context("spawn_blocking failed")?
}

/// Synchronous implementation of containers-storage import.
///
/// All file I/O operations in this function are blocking, so it must be called
/// from a blocking context (e.g., via `spawn_blocking`).
fn import_from_containers_storage_blocking<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    image_id: &str,
    reference: Option<&str>,
) -> Result<ContentAndVerity<ObjectID>> {
    // Open containers-storage
    let storage = Storage::discover().context("Failed to discover containers-storage")?;

    // Open the image - first try by ID, then fall back to name lookup
    let image = Image::open(&storage, image_id)
        .or_else(|_| storage.find_image_by_name(image_id))
        .with_context(|| format!("Failed to open image {}", image_id))?;

    // Get the storage layer IDs
    let storage_layer_ids = image
        .storage_layer_ids(&storage)
        .context("Failed to get storage layer IDs from image")?;

    // Get the config to access diff_ids
    let config = image.config().context("Failed to read image config")?;
    let diff_ids: Vec<String> = config
        .rootfs()
        .diff_ids()
        .iter()
        .map(|s| s.to_string())
        .collect();

    // Ensure layer count matches
    anyhow::ensure!(
        storage_layer_ids.len() == diff_ids.len(),
        "Layer count mismatch: {} layers in storage, {} diff_ids in config",
        storage_layer_ids.len(),
        diff_ids.len()
    );

    // Import each layer with progress bar
    let progress = ProgressBar::new(storage_layer_ids.len() as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .expect("valid template")
            .progress_chars("=>-"),
    );

    let mut layer_refs = Vec::with_capacity(storage_layer_ids.len());
    for (storage_layer_id, diff_id) in storage_layer_ids.iter().zip(diff_ids.iter()) {
        let content_id = layer_identifier(diff_id);
        let short_id = &diff_id[..std::cmp::min(19, diff_id.len())];

        let layer_verity = if let Some(existing) = repo.has_stream(&content_id)? {
            progress.set_message(format!("Already have {short_id}..."));
            existing
        } else {
            progress.set_message(format!("Importing {short_id}..."));
            let layer = Layer::open(&storage, storage_layer_id)
                .with_context(|| format!("Failed to open layer {}", storage_layer_id))?;
            import_layer_with_writer(repo, &storage, &layer, diff_id)?
        };

        layer_refs.push((diff_id.clone(), layer_verity));
        progress.inc(1);
    }
    progress.finish_with_message("Layers imported");

    // Create the config splitstream with layer references
    // Read the raw config JSON bytes from metadata
    let config_key = format!("sha256:{}", image.id());
    let encoded_key = base64::engine::general_purpose::STANDARD.encode(config_key.as_bytes());
    let config_json = image
        .read_metadata(&encoded_key)
        .context("Failed to read config bytes")?;
    let config_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&config_json)));
    let content_id = config_identifier(&config_digest);

    let config_verity = if let Some(existing) = repo.has_stream(&content_id)? {
        progress.println(format!("Already have config {}", config_digest));
        existing
    } else {
        progress.println(format!("Creating config splitstream {}", config_digest));
        let mut writer = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);

        // Add layer references
        for (diff_id, verity) in &layer_refs {
            writer.add_named_stream_ref(diff_id, verity);
        }

        // Store config as external object for independent fsverity
        // (must match skopeo path which uses write_external)
        writer.write_external(&config_json)?;

        repo.write_stream(writer, &content_id, reference)?
    };

    Ok((config_digest, config_verity))
}

/// Import a single layer from containers-storage using the writer pattern.
///
/// This function reads tar-split metadata and:
/// - For large files: reflinks the file content to the objects directory
/// - For small files: embeds content inline in the splitstream
/// - Writes tar headers and padding as inline data
fn import_layer_with_writer<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    storage: &Storage,
    layer: &Layer,
    diff_id: &str,
) -> Result<ObjectID> {
    let mut stream = TarSplitFdStream::new(storage, layer)
        .with_context(|| format!("Failed to create tar-split stream for layer {}", layer.id()))?;

    let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);
    let content_id = layer_identifier(diff_id);

    while let Some(item) = stream.next()? {
        match item {
            TarSplitItem::Segment(bytes) => {
                // Write raw segment bytes (tar headers, padding) as inline data
                writer.write_inline(&bytes);
            }
            TarSplitItem::FileContent { fd, size, name } => {
                // Convert fd to File for operations
                let file = std::fs::File::from(fd);

                if size as usize > INLINE_CONTENT_MAX {
                    // Large file: use reflink to store as external object
                    let (object_id, _method) = repo
                        .ensure_object_from_file(&file, size)
                        .with_context(|| format!("Failed to store object for {}", name))?;

                    writer.add_external_size(size);
                    writer.write_reference(object_id)?;
                } else {
                    // Small file: read and embed inline
                    let mut content = vec![0u8; size as usize];
                    let mut file = file;
                    file.seek(SeekFrom::Start(0))?;
                    file.read_exact(&mut content)?;
                    writer.write_inline(&content);
                }
            }
        }
    }

    // Write the stream with the content identifier
    repo.write_stream(writer, &content_id, None)
}

/// Check if an image reference uses the containers-storage transport.
///
/// Returns the image ID portion if the reference starts with "containers-storage:",
/// otherwise returns None.
pub fn parse_containers_storage_ref(imgref: &str) -> Option<&str> {
    imgref.strip_prefix("containers-storage:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_containers_storage_ref() {
        assert_eq!(
            parse_containers_storage_ref("containers-storage:sha256:abc123"),
            Some("sha256:abc123")
        );
        assert_eq!(
            parse_containers_storage_ref("containers-storage:quay.io/fedora:latest"),
            Some("quay.io/fedora:latest")
        );
        assert_eq!(
            parse_containers_storage_ref("docker://quay.io/fedora:latest"),
            None
        );
        assert_eq!(parse_containers_storage_ref("sha256:abc123"), None);
    }
}
