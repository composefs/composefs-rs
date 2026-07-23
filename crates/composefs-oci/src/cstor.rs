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
//! 2. For each layer, stream it via the `org.composefs.Oci` zlink service
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

use std::os::unix::io::OwnedFd;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;

use composefs::{
    fsverity::FsVerityHashValue,
    repository::{ImportContext, Repository},
};

use cstorage::{
    CstorLayerService, Image, Layer, Storage, StorageProxy, can_bypass_file_permissions,
    spawn_cstor_in_process,
};

use crate::varlink_types::{GetLayerParams, OciProxy as _, StorageLocator};

// Re-export init_if_helper for consumers that need userns helper support
pub use cstorage::init_if_helper;

use crate::progress::{ComponentId, ProgressEvent, ProgressUnit, SharedReporter};
use crate::{ContentAndVerity, ImportStats, OciDigest, layer_identifier};

/// Full result of a cstor import: manifest and config digests + verities.
type CstorImportResult<ObjectID> = (ContentAndVerity<ObjectID>, ContentAndVerity<ObjectID>);

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
    reporter: SharedReporter,
) -> Result<(CstorImportResult<ObjectID>, ImportStats)> {
    // Check if we can access files directly or need a proxy
    if can_bypass_file_permissions() {
        // Direct access via in-process CstorLayerService.
        let storage_root = storage_root.map(|p| p.to_path_buf());
        let additional_image_stores: Vec<std::path::PathBuf> = additional_image_stores
            .iter()
            .map(|p| p.to_path_buf())
            .collect();

        import_from_containers_storage_direct(
            repo,
            image_id,
            reference,
            zerocopy,
            storage_root.as_deref(),
            &additional_image_stores,
            reporter,
        )
        .await
    } else {
        // The proxied (rootless) path uses a userns helper process that does
        // its own storage discovery.  Explicit storage paths are not yet
        // plumbed through the proxy protocol.
        if storage_root.is_some() || !additional_image_stores.is_empty() {
            anyhow::bail!(
                "storage_root and additional_image_stores are not supported in rootless mode"
            );
        }
        import_from_containers_storage_proxied(repo, image_id, reference, zerocopy, reporter).await
    }
}

/// Resolved image metadata needed by the async layer-import loop.
struct ResolvedImageLayers {
    /// The `Image` handle (for finalize_import).
    image: Image,
    /// Per-layer: (storage_root_path_string, storage_layer_id, diff_id).
    layers: Vec<(String, String, OciDigest)>,
}

/// Synchronous helper: open stores, find image, resolve layer IDs + diff_ids.
///
/// Runs entirely in blocking context.  We open the stores with explicit paths
/// so that we can pass the path string to the `CstorLayerService` per layer.
fn resolve_image_layers(
    image_id: &str,
    storage_root: Option<std::path::PathBuf>,
    additional_image_stores: Vec<std::path::PathBuf>,
) -> Result<ResolvedImageLayers> {
    // Build an ordered list of store root paths to search. An explicit
    // `storage_root` skips auto-discovery; the additional image stores are
    // appended after the primary store(s) in either case.
    let mut store_paths: Vec<String> = match &storage_root {
        Some(root) => vec![root.to_string_lossy().into_owned()],
        None => storage_search_paths(),
    };
    for p in &additional_image_stores {
        store_paths.push(p.to_string_lossy().into_owned());
    }

    // Open all stores.
    let mut stores: Vec<(String, Storage)> = Vec::with_capacity(store_paths.len());
    let mut open_errors: Vec<String> = Vec::new();
    for path in &store_paths {
        match Storage::open(path) {
            Ok(s) => stores.push((path.clone(), s)),
            Err(e) => open_errors.push(format!("{path}: {e:#}")),
        }
    }
    if stores.is_empty() {
        anyhow::bail!(
            "Could not open any containers-storage root: {}",
            open_errors.join("; ")
        );
    }

    // Search all stores for the image.
    let image = stores
        .iter()
        .find_map(|(_path, s)| {
            Image::open(s, image_id)
                .or_else(|_| s.find_image_by_name(image_id))
                .ok()
        })
        .with_context(|| format!("Failed to find image {image_id} in any storage"))?;

    // storage_layer_ids() takes &[Storage]; collect owned Storage values by
    // re-opening the already-open stores (cheap: just another fd dup via cap-std).
    // We re-open so that storage_layer_ids can have an owned &[Storage] slice.
    let storage_vec: Vec<Storage> = stores
        .iter()
        .map(|(path, _s)| Storage::open(path))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to re-open stores for storage_layer_ids")?;
    let storage_layer_ids = image
        .storage_layer_ids(&storage_vec)
        .context("Failed to get storage layer IDs from image")?;

    // Get the config to access diff_ids.
    let config = image.config().context("Failed to read image config")?;
    let diff_ids: Vec<OciDigest> = config
        .rootfs()
        .diff_ids()
        .iter()
        .map(|s| s.parse::<OciDigest>().context("parsing diff_id"))
        .collect::<Result<_>>()?;

    anyhow::ensure!(
        storage_layer_ids.len() == diff_ids.len(),
        "Layer count mismatch: {} layers in storage, {} diff_ids in config",
        storage_layer_ids.len(),
        diff_ids.len()
    );

    // For each layer, find which store path it lives in.
    let mut layers = Vec::with_capacity(storage_layer_ids.len());
    for (storage_layer_id, diff_id) in storage_layer_ids.into_iter().zip(diff_ids) {
        let store_path = stores
            .iter()
            .find_map(|(path, s)| Layer::open(s, &storage_layer_id).ok().map(|_| path.clone()))
            .with_context(|| format!("Could not find store containing layer {storage_layer_id}"))?;
        layers.push((store_path, storage_layer_id, diff_id));
    }

    Ok(ResolvedImageLayers { image, layers })
}

/// Return the ordered list of storage root path strings to search, mirroring
/// `Storage::discover_all()` internals so we can pair each store with a path.
fn storage_search_paths() -> Vec<String> {
    // TODO: Read graphroot and additional image dirs from storage.conf,
    // and respect the CONTAINERS_STORAGE_CONF environment variable.
    let mut paths = Vec::new();

    if let Ok(root) = std::env::var("CONTAINERS_STORAGE_ROOT") {
        paths.push(root);
    }

    if let Ok(home) = std::env::var("HOME") {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            paths.push(format!("{xdg}/containers/storage"));
        }
        paths.push(format!("{home}/.local/share/containers/storage"));
    }

    paths.push("/var/lib/containers/storage".to_string());

    if let Ok(opts) = std::env::var("STORAGE_OPTS") {
        for item in opts.split(',') {
            let item = item.trim();
            if let Some(p) = item.strip_prefix("additionalimagestore=") {
                paths.push(p.to_string());
            }
        }
    }

    paths
}

/// Direct (privileged) async implementation of containers-storage import.
///
/// Layer discovery is done synchronously via `spawn_blocking`, then each
/// layer is imported asynchronously through the in-process `CstorLayerService`
/// (`org.composefs.Oci` zlink interface).
async fn import_from_containers_storage_direct<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    image_id: &str,
    reference: Option<&str>,
    zerocopy: bool,
    storage_root: Option<&std::path::Path>,
    additional_image_stores: &[std::path::PathBuf],
    reporter: SharedReporter,
) -> Result<(CstorImportResult<ObjectID>, ImportStats)> {
    let mut stats = ImportStats::default();
    let mut ctx = ImportContext::default();

    // Resolve image layers synchronously (filesystem + JSON work).
    let image_id_owned = image_id.to_owned();
    let storage_root_owned = storage_root.map(|p| p.to_path_buf());
    let additional_owned: Vec<std::path::PathBuf> = additional_image_stores.to_vec();
    let resolved = tokio::task::spawn_blocking(move || {
        resolve_image_layers(&image_id_owned, storage_root_owned, additional_owned)
    })
    .await
    .context("spawn_blocking(resolve_image_layers) failed")??;

    stats.layers = resolved.layers.len() as u64;

    // Spawn the in-process CstorLayerService server (synchronous call, no .await).
    // `server` keeps the server's dedicated thread alive for the whole layer loop;
    // it is shut down explicitly after the layer loop.
    let (mut client, server) =
        spawn_cstor_in_process(CstorLayerService).context("Failed to spawn CstorLayerService")?;

    let mut layer_refs = Vec::with_capacity(resolved.layers.len());
    for (store_path, storage_layer_id, diff_id) in &resolved.layers {
        let content_id = layer_identifier(diff_id);
        let id = ComponentId::from(diff_id.to_string());

        let layer_verity = if let Some(existing) = repo.has_stream(&content_id)? {
            reporter.report(ProgressEvent::Skipped { id });
            stats.layers_already_present += 1;
            existing
        } else {
            reporter.report(ProgressEvent::Started {
                id: id.clone(),
                total: None,
                unit: ProgressUnit::Bytes,
            });
            let (verity, layer_stats) = import_layer_via_transfer(
                repo,
                &mut client,
                store_path,
                storage_layer_id,
                diff_id,
                zerocopy,
                true, // direct path: only entered when can_bypass_file_permissions()
                &mut ctx,
            )
            .await?;
            let bytes = layer_stats.new_bytes();
            stats.merge(&layer_stats);
            reporter.report(ProgressEvent::Done {
                id,
                transferred: bytes,
            });
            verity
        };

        layer_refs.push((diff_id.clone(), layer_verity));
    }

    // Drop the client so the server connection closes, then shut the server
    // down.  The server's `run()` never returns on its own (the in-process
    // listener pends forever after the first connection), so `shutdown` sends an
    // explicit stop signal and reaps the thread on a blocking task — the latter
    // is important so we don't park the caller's reactor, which must stay live
    // to deliver that very stop signal to the server thread.
    drop(client);
    server.shutdown().await;

    reporter.report(ProgressEvent::Message("Layers imported".to_string()));

    // finalize_import does blocking repo work; run it on spawn_blocking.
    let repo2 = Arc::clone(repo);
    let image = resolved.image;
    let reference_owned = reference.map(|s| s.to_owned());
    let reporter2 = reporter.clone();
    tokio::task::spawn_blocking(move || {
        finalize_import(
            &repo2,
            &image,
            &layer_refs,
            reference_owned.as_deref(),
            &reporter2,
            stats,
        )
    })
    .await
    .context("spawn_blocking(finalize_import) failed")?
}

/// Import a single layer via the in-process `org.composefs.Oci` zlink service.
///
/// Calls `get_layer(0, GetLayerParams{storage:Some(StorageLocator{...})})`,
/// collects all frames, then drains the `splitdirfdstream` pipe in a
/// `spawn_blocking` closure while the server-side producer fills the pipe
/// concurrently on its own thread.
#[allow(clippy::too_many_arguments)]
async fn import_layer_via_transfer<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    client: &mut zlink::tokio::unix::Connection,
    storage_path: &str,
    storage_layer_id: &str,
    diff_id: &OciDigest,
    zerocopy: bool,
    consumer_has_cap_dac_override: bool,
    ctx: &mut ImportContext,
) -> Result<(ObjectID, ImportStats)> {
    // Call get_layer with the storage locator (handle=0; cstor service ignores it).
    let params = GetLayerParams {
        diff_id: None,
        storage: Some(StorageLocator {
            storage_path: storage_path.to_owned(),
            layer_id: storage_layer_id.to_owned(),
        }),
        consumer_has_cap_dac_override,
    };
    let stream = client
        .get_layer(0, params)
        .await
        .with_context(|| format!("Oci.GetLayer RPC failed for {storage_layer_id}"))?;

    // Collect all frames.  Each frame carries a batch of FDs; concatenate them
    // in arrival order to reconstruct the full logical FD array:
    //   index 0             : pipe read end
    //   index 1..=dir_count : dirfds region (sparse — may include dummy slots)
    //   index dir_count+1.. : opaque lifetime FDs (keepalive + optional extras)
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut reply_opt: Option<crate::varlink_types::GetLayerReply> = None;
    {
        use zlink::futures_util::StreamExt as _;
        let mut stream = std::pin::pin!(stream);
        while let Some(item) = stream.next().await {
            let (result, frame_fds) =
                item.with_context(|| format!("Oci.GetLayer stream error for {storage_layer_id}"))?;
            let frame_reply = result.map_err(|e| anyhow::anyhow!("Oci.GetLayer error: {e:?}"))?;
            reply_opt = Some(frame_reply);
            fds.extend(frame_fds);
        }
    }
    let reply = reply_opt.ok_or_else(|| anyhow::anyhow!("Oci.GetLayer yielded no frames"))?;

    // At minimum: 1 pipe fd + dir_count slots + 1 keepalive fd.
    anyhow::ensure!(
        fds.len() >= reply.dir_count as usize + 2,
        "Oci.GetLayer: expected at least {} fds (1 pipe + {} dirfd slots + 1 keepalive), got {}",
        2 + reply.dir_count,
        reply.dir_count,
        fds.len()
    );

    // Split into: pipe_read | dir_fds[dir_count] | lifetime_fds...
    let mut it = fds.into_iter();
    let pipe_read: OwnedFd = it.next().expect("checked above: fds.len() >= 1");
    let dir_fds: Vec<OwnedFd> = it.by_ref().take(reply.dir_count as usize).collect();
    // Opaque lifetime tokens — hold open until drain completes, then drop to
    // signal the server's producer that we are done consuming the layer.
    let lifetime_fds: Vec<OwnedFd> = it.collect();

    // Drain the pipe in a blocking task (producer runs concurrently on the
    // server's spawn_blocking thread).  ImportContext is threaded through.
    let repo_clone = Arc::clone(repo);
    let diff_id_owned = diff_id.clone();
    let ctx_moved = std::mem::take(ctx);

    let (verity, layer_stats, ctx_returned) = tokio::task::spawn_blocking(move || {
        // Hold all lifetime FDs for the full duration of the drain.
        let _lifetime_fds = lifetime_fds;
        crate::layer_sync::drain_splitdirfdstream(
            repo_clone,
            pipe_read,
            dir_fds,
            &diff_id_owned,
            zerocopy,
            ctx_moved,
        )
    })
    .await
    .context("spawn_blocking(drain_splitdirfdstream) failed")??;

    *ctx = ctx_returned;

    Ok((verity, layer_stats))
}

/// Proxied (rootless) implementation of containers-storage import.
///
/// Mirrors `import_from_containers_storage_direct` exactly, but acquires the
/// `org.composefs.Oci` zlink client from the userns helper subprocess instead
/// of an in-process server.  Metadata resolution (layer IDs, diff_ids, config)
/// runs in `spawn_blocking` using the same `resolve_image_layers` path as the
/// direct path, so the two paths remain behaviorally identical.
///
/// Note: explicit `storage_root` / `additional_image_stores` are not supported
/// here; the caller (`import_from_containers_storage`) already guards against
/// that and bails before reaching this function.
async fn import_from_containers_storage_proxied<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    image_id: &str,
    reference: Option<&str>,
    zerocopy: bool,
    reporter: SharedReporter,
) -> Result<(CstorImportResult<ObjectID>, ImportStats)> {
    let mut stats = ImportStats::default();
    let mut ctx = ImportContext::default();

    // Resolve image layers synchronously (filesystem + JSON work).
    // Pass None / empty for storage_root / additional: the caller already
    // rejected those for rootless mode, so this is always auto-discovery.
    let image_id_owned = image_id.to_owned();
    let resolved =
        tokio::task::spawn_blocking(move || resolve_image_layers(&image_id_owned, None, vec![]))
            .await
            .context("spawn_blocking(resolve_image_layers) failed")??;

    stats.layers = resolved.layers.len() as u64;

    // Spawn the userns helper; it serves the org.composefs.Oci zlink service
    // (CstorLayerService) over a Unix socket.  We drive it through
    // `proxy.connection()` exactly as the direct path drives the in-process client.
    let mut proxy = StorageProxy::spawn()
        .await
        .context("spawn userns helper")?
        .context("expected helper but got None (can_bypass_file_permissions returned true?)")?;

    let mut layer_refs = Vec::with_capacity(resolved.layers.len());
    for (store_path, storage_layer_id, diff_id) in &resolved.layers {
        let content_id = layer_identifier(diff_id);
        let id = ComponentId::from(diff_id.to_string());

        let layer_verity = if let Some(existing) = repo.has_stream(&content_id)? {
            reporter.report(ProgressEvent::Skipped { id });
            stats.layers_already_present += 1;
            existing
        } else {
            reporter.report(ProgressEvent::Started {
                id: id.clone(),
                total: None,
                unit: ProgressUnit::Bytes,
            });
            let (verity, layer_stats) = import_layer_via_transfer(
                repo,
                proxy.connection(),
                store_path,
                storage_layer_id,
                diff_id,
                zerocopy,
                false, // proxied path: consumer cannot bypass file permissions
                &mut ctx,
            )
            .await?;
            let bytes = layer_stats.new_bytes();
            stats.merge(&layer_stats);
            reporter.report(ProgressEvent::Done {
                id,
                transferred: bytes,
            });
            verity
        };

        layer_refs.push((diff_id.clone(), layer_verity));
    }

    // Shut down the helper before finalize_import: finalize reads config and
    // manifest JSON directly (no restrictive permissions), so the helper is
    // no longer needed.
    proxy.shutdown().await.context("shutdown userns helper")?;

    reporter.report(ProgressEvent::Message("Layers imported".to_string()));

    // finalize_import does blocking repo work; run it on spawn_blocking,
    // mirroring _direct exactly.
    let repo2 = Arc::clone(repo);
    let image = resolved.image;
    let reference_owned = reference.map(|s| s.to_owned());
    let reporter2 = reporter.clone();
    tokio::task::spawn_blocking(move || {
        finalize_import(
            &repo2,
            &image,
            &layer_refs,
            reference_owned.as_deref(),
            &reporter2,
            stats,
        )
    })
    .await
    .context("spawn_blocking(finalize_import) failed")?
}

/// Create config + manifest splitstreams, generate the EROFS image, and tag.
///
/// This is the shared finalization step for both direct and proxied import
/// paths. By this point all layers are already imported; this function:
/// 1. Reads config JSON and manifest JSON from the containers-storage `Image`
/// 2. Delegates to [`crate::layer_sync::finalize_oci_image`] for the repo work
/// 3. Re-attaches the `ImportStats` for the caller
fn finalize_import<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    image: &Image,
    layer_refs: &[(OciDigest, ObjectID)],
    reference: Option<&str>,
    reporter: &SharedReporter,
    stats: ImportStats,
) -> Result<(CstorImportResult<ObjectID>, ImportStats)> {
    // Read the raw config JSON bytes from metadata
    let config_key = format!("sha256:{}", image.id());
    let encoded_key = base64::engine::general_purpose::STANDARD.encode(config_key.as_bytes());
    let config_json = image
        .read_metadata(&encoded_key)
        .context("Failed to read config bytes")?;

    reporter.report(ProgressEvent::Message(format!(
        "Read config ({} bytes)",
        config_json.len()
    )));

    // Read the raw manifest JSON bytes
    let manifest_json = image
        .read_manifest_raw()
        .context("Failed to read manifest bytes")?;

    reporter.report(ProgressEvent::Message(format!(
        "Read manifest ({} bytes)",
        manifest_json.len()
    )));

    let result = crate::layer_sync::finalize_oci_image(
        repo,
        &manifest_json,
        &config_json,
        layer_refs,
        reference,
    )
    .context("finalize_oci_image")?;

    Ok((result, stats))
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
