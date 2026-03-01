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
//! # Rootless Support
//!
//! When running as an unprivileged user, files in containers-storage may have
//! restrictive permissions (e.g., `/etc/shadow` with mode 0600 owned by remapped
//! UIDs). In this case, we spawn a helper process via `podman unshare` that can
//! read all files, and it streams the content back to us via a Unix socket with
//! file descriptor passing.
//!
//! # Example
//!
//! ```ignore
//! use composefs_oci::cstor::import_from_containers_storage;
//!
//! let repo = Arc::new(Repository::open_user()?);
//! let (result, stats) = import_from_containers_storage(&repo, "sha256:abc123...", None).await?;
//! println!("Imported config: {}", result.0);
//! println!("Stats: {:?}", stats);
//! ```

use std::os::unix::fs::FileExt;
use std::os::unix::io::OwnedFd;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::Digest;

use composefs::{
    fsverity::FsVerityHashValue,
    repository::{ObjectStoreMethod, Repository},
    INLINE_CONTENT_MAX,
};

use cstorage::{
    can_bypass_file_permissions, Image, Layer, ProxiedTarSplitItem, Storage, StorageProxy,
    TarSplitFdStream, TarSplitItem,
};

// Re-export init_if_helper for consumers that need userns helper support
pub use cstorage::init_if_helper;

use crate::skopeo::{OCI_CONFIG_CONTENT_TYPE, TAR_LAYER_CONTENT_TYPE};
use crate::{config_identifier, layer_identifier, ContentAndVerity};

/// Zero padding buffer for tar block alignment (512 bytes max needed).
const ZERO_PADDING: [u8; 512] = [0u8; 512];

/// Statistics from a containers-storage import operation.
#[derive(Debug, Clone, Default)]
pub struct ImportStats {
    /// Number of layers in the image.
    pub layers: u64,
    /// Number of layers that were already present (skipped).
    pub layers_already_present: u64,
    /// Number of objects stored via reflink (zero-copy).
    pub objects_reflinked: u64,
    /// Number of objects stored via regular copy (reflink not supported).
    pub objects_copied: u64,
    /// Number of objects that were already present (deduplicated).
    pub objects_already_present: u64,
    /// Total bytes stored via reflink.
    pub bytes_reflinked: u64,
    /// Total bytes stored via regular copy.
    pub bytes_copied: u64,
    /// Total bytes inlined in splitstreams (small files + headers).
    pub bytes_inlined: u64,
}

impl ImportStats {
    /// Merge stats from another ImportStats into this one.
    pub fn merge(&mut self, other: &ImportStats) {
        self.layers += other.layers;
        self.layers_already_present += other.layers_already_present;
        self.objects_reflinked += other.objects_reflinked;
        self.objects_copied += other.objects_copied;
        self.objects_already_present += other.objects_already_present;
        self.bytes_reflinked += other.bytes_reflinked;
        self.bytes_copied += other.bytes_copied;
        self.bytes_inlined += other.bytes_inlined;
    }

    /// Returns true if any objects were stored via reflink.
    pub fn used_reflinks(&self) -> bool {
        self.objects_reflinked > 0
    }

    /// Total number of objects processed.
    pub fn total_objects(&self) -> u64 {
        self.objects_reflinked + self.objects_copied + self.objects_already_present
    }

    /// Total bytes processed (external objects only, not inline).
    pub fn total_external_bytes(&self) -> u64 {
        self.bytes_reflinked + self.bytes_copied
    }
}

/// Import a container image from containers-storage into the composefs repository.
///
/// This function reads an image from the local containers-storage (podman/buildah)
/// and imports all layers using reflinks when possible, avoiding data duplication.
///
/// For rootless access, this function will automatically spawn a userns helper
/// process via `podman unshare` to read files with restrictive permissions.
///
/// # Arguments
/// * `repo` - The composefs repository to import into
/// * `image_id` - The image ID (sha256 digest or name) to import
/// * `reference` - Optional reference name to assign to the imported config
///
/// # Returns
/// A tuple of ((config_digest, config_verity_id), import_stats).
pub async fn import_from_containers_storage<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    image_id: &str,
    reference: Option<&str>,
) -> Result<(ContentAndVerity<ObjectID>, ImportStats)> {
    // Check if we can access files directly or need a proxy
    if can_bypass_file_permissions() {
        // Direct access - use blocking implementation
        let repo = Arc::clone(repo);
        let image_id = image_id.to_owned();
        let reference = reference.map(|s| s.to_owned());

        tokio::task::spawn_blocking(move || {
            import_from_containers_storage_direct(&repo, &image_id, reference.as_deref())
        })
        .await
        .context("spawn_blocking failed")?
    } else {
        // Need proxy for rootless access
        import_from_containers_storage_proxied(repo, image_id, reference).await
    }
}

/// Direct (privileged) implementation of containers-storage import.
///
/// All file I/O operations in this function are blocking, so it must be called
/// from a blocking context (e.g., via `spawn_blocking`).
fn import_from_containers_storage_direct<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    image_id: &str,
    reference: Option<&str>,
) -> Result<(ContentAndVerity<ObjectID>, ImportStats)> {
    let mut stats = ImportStats::default();

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

    stats.layers = storage_layer_ids.len() as u64;

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
        let short_id = diff_id.get(..19).unwrap_or(diff_id);

        let layer_verity = if let Some(existing) = repo.has_stream(&content_id)? {
            progress.set_message(format!("Already have {short_id}..."));
            stats.layers_already_present += 1;
            existing
        } else {
            progress.set_message(format!("Importing {short_id}..."));
            let layer = Layer::open(&storage, storage_layer_id)
                .with_context(|| format!("Failed to open layer {}", storage_layer_id))?;
            let (verity, layer_stats) = import_layer_direct(repo, &storage, &layer, diff_id)?;
            stats.merge(&layer_stats);
            verity
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

    Ok(((config_digest, config_verity), stats))
}

/// Proxied (rootless) implementation of containers-storage import.
///
/// This spawns a helper process via `podman unshare` that can read all files
/// in containers-storage, and communicates with it via Unix socket + fd passing.
async fn import_from_containers_storage_proxied<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    image_id: &str,
    reference: Option<&str>,
) -> Result<(ContentAndVerity<ObjectID>, ImportStats)> {
    let mut stats = ImportStats::default();

    // Spawn the proxy helper
    let mut proxy = StorageProxy::spawn()
        .await
        .context("Failed to spawn userns helper")?
        .context("Expected proxy but got None")?;

    // Discover storage path for the proxy
    let storage_path = discover_storage_path()?;

    // Get image info via the proxy
    let image_info = proxy
        .get_image(&storage_path, image_id)
        .await
        .context("Failed to get image info via proxy")?;

    // Ensure layer count matches
    anyhow::ensure!(
        image_info.storage_layer_ids.len() == image_info.layer_diff_ids.len(),
        "Layer count mismatch: {} layers in storage, {} diff_ids in config",
        image_info.storage_layer_ids.len(),
        image_info.layer_diff_ids.len()
    );

    stats.layers = image_info.storage_layer_ids.len() as u64;

    // Import each layer with progress bar
    let progress = ProgressBar::new(image_info.storage_layer_ids.len() as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .expect("valid template")
            .progress_chars("=>-"),
    );

    let mut layer_refs = Vec::with_capacity(image_info.storage_layer_ids.len());

    for (storage_layer_id, diff_id) in image_info
        .storage_layer_ids
        .iter()
        .zip(image_info.layer_diff_ids.iter())
    {
        let content_id = layer_identifier(diff_id);
        let short_id = diff_id.get(..19).unwrap_or(diff_id);

        let layer_verity = if let Some(existing) = repo.has_stream(&content_id)? {
            progress.set_message(format!("Already have {short_id}..."));
            stats.layers_already_present += 1;
            existing
        } else {
            progress.set_message(format!("Importing {short_id}..."));
            let (verity, layer_stats) =
                import_layer_proxied(repo, &mut proxy, &storage_path, storage_layer_id, diff_id)
                    .await?;
            stats.merge(&layer_stats);
            verity
        };

        layer_refs.push((diff_id.clone(), layer_verity));
        progress.inc(1);
    }
    progress.finish_with_message("Layers imported");

    // For the config, we need to read it from storage.
    // The config is stored as metadata in containers-storage.
    // Note: We can read the metadata directly (it doesn't have restrictive permissions).
    let direct_storage = Storage::discover().context("Failed to discover containers-storage")?;
    let image = Image::open(&direct_storage, &image_info.id)
        .with_context(|| format!("Failed to open image {}", image_info.id))?;

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

        // Write config as external object
        // (must match skopeo path which uses write_external)
        writer.write_external(&config_json)?;

        repo.write_stream(writer, &content_id, reference)?
    };

    // Shutdown the proxy
    proxy.shutdown().await.context("Failed to shutdown proxy")?;

    Ok(((config_digest, config_verity), stats))
}

/// Import a single layer directly (privileged mode).
fn import_layer_direct<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    storage: &Storage,
    layer: &Layer,
    diff_id: &str,
) -> Result<(ObjectID, ImportStats)> {
    let mut stats = ImportStats::default();

    let mut stream = TarSplitFdStream::new(storage, layer)
        .with_context(|| format!("Failed to create tar-split stream for layer {}", layer.id()))?;

    let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);
    let content_id = layer_identifier(diff_id);

    // Track padding from previous file - tar-split bundles padding with the NEXT
    // file's header in Segment entries, but we need to write padding immediately
    // after file content (like tar.rs does) for consistent splitstream output.
    let mut prev_file_padding: usize = 0;

    while let Some(item) = stream.next()? {
        match item {
            TarSplitItem::Segment(bytes) => {
                // Skip the leading padding bytes (we already wrote them after prev file)
                let header_bytes = &bytes[prev_file_padding..];
                stats.bytes_inlined += header_bytes.len() as u64;
                writer.write_inline(header_bytes);
                prev_file_padding = 0;
            }
            TarSplitItem::FileContent { fd, size, name } => {
                process_file_content(repo, &mut writer, &mut stats, fd, size, &name)?;

                // Write padding inline immediately after file content
                let padding_size = (size as usize).next_multiple_of(512) - size as usize;
                if padding_size > 0 {
                    stats.bytes_inlined += padding_size as u64;
                    writer.write_inline(&ZERO_PADDING[..padding_size]);
                }
                prev_file_padding = padding_size;
            }
        }
    }

    // Write the stream with the content identifier
    let verity = repo.write_stream(writer, &content_id, None)?;
    Ok((verity, stats))
}

/// Import a single layer via the proxy (rootless mode).
async fn import_layer_proxied<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    proxy: &mut StorageProxy,
    storage_path: &str,
    layer_id: &str,
    diff_id: &str,
) -> Result<(ObjectID, ImportStats)> {
    let mut stats = ImportStats::default();

    let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);
    let content_id = layer_identifier(diff_id);

    // Track padding from previous file - tar-split bundles padding with the NEXT
    // file's header in Segment entries, but we need to write padding immediately
    // after file content (like tar.rs does) for consistent splitstream output.
    let mut prev_file_padding: usize = 0;

    // Stream the layer via the proxy
    let mut stream = proxy
        .stream_layer(storage_path, layer_id)
        .await
        .with_context(|| format!("Failed to start streaming layer {}", layer_id))?;

    while let Some(item) = stream
        .next()
        .await
        .with_context(|| format!("Failed to receive stream item for layer {}", layer_id))?
    {
        match item {
            ProxiedTarSplitItem::Segment(bytes) => {
                // Skip the leading padding bytes (we already wrote them after prev file)
                let header_bytes = &bytes[prev_file_padding..];
                stats.bytes_inlined += header_bytes.len() as u64;
                writer.write_inline(header_bytes);
                prev_file_padding = 0;
            }
            ProxiedTarSplitItem::FileContent { fd, size, name } => {
                process_file_content(repo, &mut writer, &mut stats, fd, size, &name)?;

                // Write padding inline immediately after file content
                let padding_size = (size as usize).next_multiple_of(512) - size as usize;
                if padding_size > 0 {
                    stats.bytes_inlined += padding_size as u64;
                    writer.write_inline(&ZERO_PADDING[..padding_size]);
                }
                prev_file_padding = padding_size;
            }
        }
    }

    // Write the stream with the content identifier
    let verity = repo.write_stream(writer, &content_id, None)?;
    Ok((verity, stats))
}

/// Process file content (shared between direct and proxied modes).
fn process_file_content<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    writer: &mut composefs::splitstream::SplitStreamWriter<ObjectID>,
    stats: &mut ImportStats,
    fd: OwnedFd,
    size: u64,
    name: &str,
) -> Result<()> {
    // Convert fd to File for operations
    let file = std::fs::File::from(fd);

    if size as usize > INLINE_CONTENT_MAX {
        // Large file: use reflink to store as external object
        let (object_id, method) = repo
            .ensure_object_from_file(&file, size)
            .with_context(|| format!("Failed to store object for {}", name))?;

        match method {
            ObjectStoreMethod::Reflinked => {
                stats.objects_reflinked += 1;
                stats.bytes_reflinked += size;
            }
            ObjectStoreMethod::Copied => {
                stats.objects_copied += 1;
                stats.bytes_copied += size;
            }
            ObjectStoreMethod::AlreadyPresent => {
                stats.objects_already_present += 1;
            }
        }

        writer.add_external_size(size);
        writer.write_reference(object_id)?;
    } else {
        // Small file: read and embed inline
        let mut content = vec![0u8; size as usize];
        file.read_exact_at(&mut content, 0)?;
        stats.bytes_inlined += size;
        writer.write_inline(&content);
    }

    Ok(())
}

/// Discover the storage path by trying standard locations.
fn discover_storage_path() -> Result<String> {
    // Try user storage first (rootless podman)
    if let Ok(home) = std::env::var("HOME") {
        let user_path = format!("{}/.local/share/containers/storage", home);
        if std::path::Path::new(&user_path).exists() {
            return Ok(user_path);
        }
    }

    // Fall back to system storage
    let system_path = "/var/lib/containers/storage";
    if std::path::Path::new(system_path).exists() {
        return Ok(system_path.to_string());
    }

    anyhow::bail!("Could not find containers-storage at standard locations")
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
