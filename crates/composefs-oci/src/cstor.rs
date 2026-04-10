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
//! 3. For large files (> INLINE_CONTENT_MAX_V0), reflink directly to objects/
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
//! let (result, stats) = import_from_containers_storage(&repo, "sha256:abc123...", None, false).await?;
//! println!("Imported config: {}", result.0);
//! println!("Stats: {:?}", stats);
//! ```

use std::os::unix::fs::FileExt;
use std::os::unix::io::OwnedFd;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use indicatif::{ProgressBar, ProgressStyle};

use composefs::{
    INLINE_CONTENT_MAX_V0,
    fsverity::FsVerityHashValue,
    repository::{ImportContext, ObjectStoreMethod, Repository},
};

use cstorage::{
    Image, Layer, ProxiedTarSplitItem, Storage, StorageProxy, TarSplitFdStream, TarSplitItem,
    can_bypass_file_permissions,
};

// Re-export init_if_helper for consumers that need userns helper support
pub use cstorage::init_if_helper;

use crate::oci_image::manifest_identifier;
use crate::skopeo::{OCI_CONFIG_CONTENT_TYPE, OCI_MANIFEST_CONTENT_TYPE, TAR_LAYER_CONTENT_TYPE};
use crate::{ContentAndVerity, ImportStats, OciDigest, config_identifier, layer_identifier};

/// Full result of a cstor import: manifest and config digests + verities.
type CstorImportResult<ObjectID> = (ContentAndVerity<ObjectID>, ContentAndVerity<ObjectID>);

/// Zero padding buffer for tar block alignment (512 bytes max needed).
const ZERO_PADDING: [u8; 512] = [0u8; 512];

/// Import a container image from containers-storage into the composefs repository.
///
/// This function reads an image from the local containers-storage (podman/buildah)
/// and imports all layers using reflinks when possible, avoiding data duplication.
/// It creates full OCI structure (manifest + config + layers) matching the skopeo
/// import path.
///
/// For rootless access, this function will automatically spawn a userns helper
/// process via `podman unshare` to read files with restrictive permissions.
///
/// # Arguments
/// * `repo` - The composefs repository to import into
/// * `image_id` - The image ID (sha256 digest or name) to import
/// * `reference` - Optional reference name to assign to the imported image
/// * `zerocopy` - If true, error instead of falling back to copy (reflink or hardlink required)
/// * `storage_root` - Explicit storage root; skips auto-discovery when set
/// * `additional_image_stores` - Additional read-only image stores (appended after the primary store)
///
/// # Returns
/// A tuple of ((manifest_digest, manifest_verity), (config_digest, config_verity))
/// plus import stats.
pub async fn import_from_containers_storage<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    image_id: &str,
    reference: Option<&str>,
    zerocopy: bool,
    storage_root: Option<&std::path::Path>,
    additional_image_stores: &[&std::path::Path],
) -> Result<(CstorImportResult<ObjectID>, ImportStats)> {
    // Check if we can access files directly or need a proxy
    if can_bypass_file_permissions() {
        // Direct access - use blocking implementation
        let repo = Arc::clone(repo);
        let image_id = image_id.to_owned();
        let reference = reference.map(|s| s.to_owned());
        let storage_root = storage_root.map(|p| p.to_path_buf());
        let additional_image_stores: Vec<std::path::PathBuf> = additional_image_stores
            .iter()
            .map(|p| p.to_path_buf())
            .collect();

        tokio::task::spawn_blocking(move || {
            import_from_containers_storage_direct(
                &repo,
                &image_id,
                reference.as_deref(),
                zerocopy,
                storage_root.as_deref(),
                &additional_image_stores,
            )
        })
        .await
        .context("spawn_blocking failed")?
    } else {
        // The proxied (rootless) path uses a userns helper process that does
        // its own storage discovery.  Explicit storage paths are not yet
        // plumbed through the proxy protocol.
        if storage_root.is_some() || !additional_image_stores.is_empty() {
            anyhow::bail!(
                "storage_root and additional_image_stores are not supported in rootless mode"
            );
        }
        import_from_containers_storage_proxied(repo, image_id, reference, zerocopy).await
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
    zerocopy: bool,
    storage_root: Option<&std::path::Path>,
    additional_image_stores: &[std::path::PathBuf],
) -> Result<(CstorImportResult<ObjectID>, ImportStats)> {
    let mut stats = ImportStats::default();
    let mut ctx = ImportContext::default();

    // Build the list of stores to search.  When an explicit root is given,
    // skip auto-discovery entirely; otherwise discover from the standard
    // locations and $STORAGE_OPTS.
    let mut stores = if let Some(root) = storage_root {
        vec![
            Storage::open(root)
                .with_context(|| format!("Failed to open storage root at {}", root.display()))?,
        ]
    } else {
        // Auto-discover; tolerate failure only if extra stores are provided.
        match Storage::discover_all() {
            Ok(s) => s,
            Err(e) if !additional_image_stores.is_empty() => {
                tracing::warn!(
                    "containers-storage auto-discovery failed ({e:#}), \
                     using additional image stores only"
                );
                Vec::new()
            }
            Err(e) => return Err(e).context("Failed to discover containers-storage"),
        }
    };
    for path in additional_image_stores {
        stores.push(Storage::open(path).with_context(|| {
            format!(
                "Failed to open additional image store at {}",
                path.display()
            )
        })?);
    }

    // Search all stores for the image (primary first, then additional image stores)
    let (_image_store, image) = stores
        .iter()
        .find_map(|s| {
            Image::open(s, image_id)
                .or_else(|_| s.find_image_by_name(image_id))
                .ok()
                .map(|img| (s, img))
        })
        .with_context(|| format!("Failed to find image {image_id} in any storage"))?;

    // Get the storage layer IDs — layers may span stores (e.g. base layers
    // in an additional image store, new layers in the primary)
    let storage_layer_ids = image
        .storage_layer_ids(&stores)
        .context("Failed to get storage layer IDs from image")?;

    // Get the config to access diff_ids
    let config = image.config().context("Failed to read image config")?;
    let diff_ids: Vec<OciDigest> = config
        .rootfs()
        .diff_ids()
        .iter()
        .map(|s| s.parse::<OciDigest>().context("parsing diff_id"))
        .collect::<Result<_>>()?;

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
        let diff_id_str: &str = diff_id.as_ref();
        let short_id = diff_id_str.get(..19).unwrap_or(diff_id_str);

        let layer_verity = if let Some(existing) = repo.has_stream(&content_id)? {
            progress.set_message(format!("Already have {short_id}..."));
            stats.layers_already_present += 1;
            existing
        } else {
            progress.set_message(format!("Importing {short_id}..."));
            let (layer_store, layer) = stores
                .iter()
                .find_map(|s| Layer::open(s, storage_layer_id).ok().map(|l| (s, l)))
                .with_context(|| format!("Failed to open layer {}", storage_layer_id))?;
            let (verity, layer_stats) =
                import_layer_direct(repo, layer_store, &layer, diff_id, zerocopy, &mut ctx)?;
            stats.merge(&layer_stats);
            verity
        };

        layer_refs.push((diff_id.clone(), layer_verity));
        progress.inc(1);
    }
    progress.finish_with_message("Layers imported");

    finalize_import(repo, &image, &layer_refs, reference, &progress, stats)
}

/// Proxied (rootless) implementation of containers-storage import.
///
/// This spawns a helper process via `podman unshare` that can read all files
/// in containers-storage, and communicates with it via Unix socket + fd passing.
async fn import_from_containers_storage_proxied<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    image_id: &str,
    reference: Option<&str>,
    zerocopy: bool,
) -> Result<(CstorImportResult<ObjectID>, ImportStats)> {
    let mut stats = ImportStats::default();
    let mut ctx = ImportContext::default();

    // Spawn the proxy helper
    let mut proxy = StorageProxy::spawn()
        .await
        .context("Failed to spawn userns helper")?
        .context("Expected proxy but got None")?;

    // Discover storage paths (primary + additional from $STORAGE_OPTS)
    let storage_paths = discover_storage_paths()?;

    // Search all storage paths for the image
    let mut image_info = None;
    let mut found_storage_path = String::new();
    for path in &storage_paths {
        match proxy.get_image(path, image_id).await {
            Ok(info) => {
                found_storage_path = path.clone();
                image_info = Some(info);
                break;
            }
            Err(_) => continue,
        }
    }
    let image_info =
        image_info.with_context(|| format!("Failed to find image {} in any storage", image_id))?;
    let storage_path = found_storage_path;

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

    for (storage_layer_id, diff_id_str) in image_info
        .storage_layer_ids
        .iter()
        .zip(image_info.layer_diff_ids.iter())
    {
        let diff_id: OciDigest = diff_id_str.parse().context("parsing diff_id")?;
        let content_id = layer_identifier(&diff_id);
        let short_id = diff_id_str.get(..19).unwrap_or(diff_id_str);

        let layer_verity = if let Some(existing) = repo.has_stream(&content_id)? {
            progress.set_message(format!("Already have {short_id}..."));
            stats.layers_already_present += 1;
            existing
        } else {
            progress.set_message(format!("Importing {short_id}..."));
            let (verity, layer_stats) = import_layer_proxied(
                repo,
                &mut proxy,
                &storage_path,
                storage_layer_id,
                diff_id_str,
                zerocopy,
                &mut ctx,
            )
            .await?;
            stats.merge(&layer_stats);
            verity
        };

        layer_refs.push((diff_id, layer_verity));
        progress.inc(1);
    }
    progress.finish_with_message("Layers imported");

    // Config and manifest metadata don't have restrictive file permissions,
    // so we can read them directly without the proxy.
    let stores = Storage::discover_all().context("Failed to discover containers-storage")?;
    let (_, image) = stores
        .iter()
        .find_map(|s| Image::open(s, &image_info.id).ok().map(|img| (s, img)))
        .with_context(|| format!("Failed to open image {}", image_info.id))?;

    // Shutdown the proxy before the blocking finalization
    proxy.shutdown().await.context("Failed to shutdown proxy")?;

    finalize_import(repo, &image, &layer_refs, reference, &progress, stats)
}

/// Create config + manifest splitstreams, generate the EROFS image, and tag.
///
/// This is the shared finalization step for both direct and proxied import
/// paths. By this point all layers are already imported; this function:
/// 1. Creates the config splitstream with layer references
/// 2. Creates the manifest splitstream
/// 3. Generates the composefs EROFS image and links it to the config
/// 4. Tags the manifest if a reference was provided
fn finalize_import<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    image: &Image,
    layer_refs: &[(OciDigest, ObjectID)],
    reference: Option<&str>,
    progress: &ProgressBar,
    stats: ImportStats,
) -> Result<(CstorImportResult<ObjectID>, ImportStats)> {
    // Read the raw config JSON bytes from metadata
    let config_key = format!("sha256:{}", image.id());
    let encoded_key = base64::engine::general_purpose::STANDARD.encode(config_key.as_bytes());
    let config_json = image
        .read_metadata(&encoded_key)
        .context("Failed to read config bytes")?;
    let config_digest = crate::sha256_content_digest(&config_json);
    let content_id = config_identifier(&config_digest);

    let config_verity = if let Some(existing) = repo.has_stream(&content_id)? {
        progress.println(format!("Already have config {config_digest}"));
        existing
    } else {
        progress.println(format!("Creating config splitstream {config_digest}"));
        let mut writer = repo.create_stream(OCI_CONFIG_CONTENT_TYPE)?;

        for (diff_id, verity) in layer_refs {
            let key: &str = diff_id.as_ref();
            writer.add_named_stream_ref(key, verity);
        }

        writer.write_external(&config_json)?;
        repo.write_stream(writer, &content_id, None)?
    };

    // Create the manifest splitstream (matching the skopeo path)
    let manifest_json = image
        .read_manifest_raw()
        .context("Failed to read manifest bytes")?;
    let manifest_digest = crate::sha256_content_digest(&manifest_json);

    let manifest_content_id = manifest_identifier(&manifest_digest);
    let manifest_verity = if let Some(existing) = repo.has_stream(&manifest_content_id)? {
        progress.println(format!("Already have manifest {manifest_digest}"));
        existing
    } else {
        progress.println(format!("Creating manifest splitstream {manifest_digest}"));
        let mut writer = repo.create_stream(OCI_MANIFEST_CONTENT_TYPE)?;

        let config_ref_key = format!("config:{config_digest}");
        writer.add_named_stream_ref(&config_ref_key, &config_verity);

        for (diff_id, verity) in layer_refs {
            let key: &str = diff_id.as_ref();
            writer.add_named_stream_ref(key, verity);
        }

        writer.write_external(&manifest_json)?;
        repo.write_stream(writer, &manifest_content_id, None)?
    };

    // Generate the composefs EROFS image and tag the manifest.
    // Skip if the image already has an EROFS ref (idempotent re-import).
    let existing_erofs =
        crate::composefs_erofs_for_manifest(repo, &manifest_digest, Some(&manifest_verity))?;
    if existing_erofs.is_none() {
        let erofs = crate::ensure_oci_composefs_erofs(
            repo,
            &manifest_digest,
            Some(&manifest_verity),
            reference,
        )?;
        if erofs.is_none() {
            // Not a container image (unlikely for cstor, but handle consistently)
            if let Some(name) = reference {
                crate::oci_image::tag_image(repo, &manifest_digest, name)?;
            }
        }
    } else if let Some(name) = reference {
        crate::oci_image::tag_image(repo, &manifest_digest, name)?;
    }

    // Re-read verities: ensure_oci_composefs_erofs rewrites config and
    // manifest splitstreams (adding the EROFS ref), so the verities captured
    // above may be stale.
    let config_verity = repo
        .has_stream(&content_id)?
        .context("config splitstream missing after finalization")?;
    let manifest_verity = repo
        .has_stream(&manifest_content_id)?
        .context("manifest splitstream missing after finalization")?;

    Ok((
        (
            (manifest_digest, manifest_verity),
            (config_digest, config_verity),
        ),
        stats,
    ))
}

/// Import a single layer directly (privileged mode).
fn import_layer_direct<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    storage: &Storage,
    layer: &Layer,
    diff_id: &OciDigest,
    zerocopy: bool,
    ctx: &mut ImportContext,
) -> Result<(ObjectID, ImportStats)> {
    let mut stats = ImportStats::default();

    let mut stream = TarSplitFdStream::new(storage, layer)
        .with_context(|| format!("Failed to create tar-split stream for layer {}", layer.id()))?;

    let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE)?;
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
                process_file_content(
                    repo,
                    &mut writer,
                    &mut stats,
                    ctx,
                    fd,
                    size,
                    &name,
                    zerocopy,
                )?;

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
    zerocopy: bool,
    ctx: &mut ImportContext,
) -> Result<(ObjectID, ImportStats)> {
    let mut stats = ImportStats::default();

    let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE)?;
    let diff_id_digest: OciDigest = diff_id.parse().context("parsing diff_id")?;
    let content_id = layer_identifier(&diff_id_digest);

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
                process_file_content(
                    repo,
                    &mut writer,
                    &mut stats,
                    ctx,
                    fd,
                    size,
                    &name,
                    zerocopy,
                )?;

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
#[allow(clippy::too_many_arguments)]
fn process_file_content<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    writer: &mut composefs::splitstream::SplitStreamWriter<ObjectID>,
    stats: &mut ImportStats,
    ctx: &mut ImportContext,
    fd: OwnedFd,
    size: u64,
    name: &str,
    zerocopy: bool,
) -> Result<()> {
    // Convert fd to File for operations
    let file = std::fs::File::from(fd);

    if size as usize > INLINE_CONTENT_MAX_V0 {
        // Large file: store as external object
        let (object_id, method) = if zerocopy {
            repo.ensure_object_from_file_zerocopy(&file, size, ctx)
        } else {
            repo.ensure_object_from_file(&file, size, ctx)
        }
        .with_context(|| format!("Failed to store object for {}", name))?;

        match method {
            ObjectStoreMethod::Reflinked => {
                stats.objects_reflinked += 1;
                stats.bytes_reflinked += size;
            }
            ObjectStoreMethod::Hardlinked => {
                stats.objects_hardlinked += 1;
                stats.bytes_hardlinked += size;
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

/// Discover storage paths: the primary store plus any additional image stores
/// from `$STORAGE_OPTS`.
fn discover_storage_paths() -> Result<Vec<String>> {
    let mut paths = Vec::new();

    // Try user storage first (rootless podman)
    if let Ok(home) = std::env::var("HOME") {
        let user_path = format!("{}/.local/share/containers/storage", home);
        if std::path::Path::new(&user_path).exists() {
            paths.push(user_path);
        }
    }

    // Fall back to system storage
    let system_path = "/var/lib/containers/storage";
    if std::path::Path::new(system_path).exists() {
        paths.push(system_path.to_string());
    }

    // Also check $STORAGE_OPTS for additional image stores
    if let Ok(opts) = std::env::var("STORAGE_OPTS") {
        for item in opts.split(',') {
            let item = item.trim();
            if let Some(path) = item.strip_prefix("additionalimagestore=")
                && std::path::Path::new(path).exists()
            {
                paths.push(path.to_string());
            }
        }
    }

    anyhow::ensure!(
        !paths.is_empty(),
        "Could not find containers-storage at standard locations"
    );
    Ok(paths)
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
