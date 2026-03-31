//! Direct OCI layout directory import without the skopeo proxy.
//!
//! This module provides a fast path for importing images from local OCI layout
//! directories (the `oci:` transport). Instead of going through the
//! containers-image-proxy (which spawns skopeo as a subprocess), we read the
//! OCI layout directly using the `ocidir` crate.
//!
//! This is significantly faster for local imports since:
//! - No subprocess overhead from skopeo
//! - No IPC/pipe overhead for blob streaming
//! - Direct file I/O instead of proxy protocol parsing
//!
//! The import produces identical results to the proxy path: the same
//! splitstream format with the same content identifiers.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::thread::available_parallelism;

use anyhow::{Context, Result};
use cap_std_ext::cap_std;
use fn_error_context::context;
use oci_spec::image::{Descriptor, MediaType};
use ocidir::OciDir;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::debug;

use composefs::fsverity::FsVerityHashValue;
use composefs::repository::{ObjectStoreMethod, Repository};

use crate::layer::{decompress_async, import_tar_async, is_tar_media_type, store_blob_async};
use crate::oci_image::manifest_identifier;
use crate::skopeo::OCI_BLOB_CONTENT_TYPE;
use crate::skopeo::{OCI_CONFIG_CONTENT_TYPE, OCI_MANIFEST_CONTENT_TYPE};
use crate::{config_identifier, layer_identifier, oci_image::tag_image, ImportStats};

use crate::skopeo::PullResult;

/// Parse an OCI layout reference like "/path/to/dir:tag" or "/path/to/dir".
///
/// Returns (path, optional_tag).
pub(crate) fn parse_oci_layout_ref(imgref: &str) -> (&str, Option<&str>) {
    // The format is: path[:tag]
    // We need to be careful: paths can contain colons (on Windows, or weird Unix paths).
    // The convention is that if the last colon is after the last slash, it's a tag separator.

    let Some((before_colon, tag)) = imgref.rsplit_once(':') else {
        return (imgref, None);
    };

    if tag.contains('/') {
        // Slash after the colon means colon is part of the path
        (imgref, None)
    } else {
        // No slash after the colon - it's a tag separator
        (before_colon, Some(tag))
    }
}

/// Read a blob from an OCI layout as bytes.
fn read_blob_bytes(ocidir: &OciDir, desc: &Descriptor) -> Result<Vec<u8>> {
    let mut file = ocidir.read_blob(desc)?;
    let mut bytes = Vec::with_capacity(desc.size() as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Import an image from a local OCI layout directory.
///
/// This is the fast path for `oci:` transport references. It reads the OCI
/// layout directly without going through skopeo.
#[context("Importing OCI layout from {}", layout_path.display())]
pub async fn import_oci_layout<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    layout_path: &Path,
    layout_tag: Option<&str>,
    reference: Option<&str>,
) -> Result<(PullResult<ObjectID>, ImportStats)> {
    // Open the OCI layout directory
    let dir = cap_std::fs::Dir::open_ambient_dir(layout_path, cap_std::ambient_authority())
        .with_context(|| format!("Opening OCI layout directory {}", layout_path.display()))?;
    let ocidir = OciDir::open(dir).context("Opening OCI directory")?;

    // Resolve the manifest for this platform, peeling through manifest lists if needed
    let resolved = ocidir
        .open_image_this_platform(layout_tag)
        .context("Resolving manifest for platform")?;

    let manifest = resolved.manifest;
    let manifest_descriptor = &resolved.manifest_descriptor;
    let manifest_digest = manifest_descriptor.digest().to_string();

    // Import config and layers
    let config_descriptor = manifest.config();
    let layers = manifest.layers();
    let (config_digest, config_verity, layer_refs, stats) =
        import_config_and_layers(repo, &ocidir, layers, config_descriptor)
            .await
            .with_context(|| format!("Failed to import config {}", config_descriptor.digest()))?;

    // Store the manifest
    let manifest_content_id = manifest_identifier(&manifest_digest);
    let manifest_verity = if let Some(verity) = repo.has_stream(&manifest_content_id)? {
        debug!("Already have manifest {manifest_digest}");
        verity
    } else {
        debug!("Storing manifest {manifest_digest}");

        let mut splitstream = repo.create_stream(OCI_MANIFEST_CONTENT_TYPE);

        let config_key = format!("config:{}", config_descriptor.digest());
        splitstream.add_named_stream_ref(&config_key, &config_verity);

        // Add layer refs in config-defined diff_id order
        for (diff_id, verity) in &layer_refs {
            splitstream.add_named_stream_ref(diff_id, verity);
        }

        let raw_manifest =
            read_blob_bytes(&ocidir, manifest_descriptor).context("Reading raw manifest bytes")?;
        splitstream.write_external(&raw_manifest)?;
        repo.write_stream(splitstream, &manifest_content_id, None)?
    };

    // Tag if requested
    if let Some(name) = reference {
        tag_image(repo, &manifest_digest, name)?;
    }

    Ok((
        PullResult {
            manifest_digest,
            manifest_verity,
            config_digest,
            config_verity,
        },
        stats,
    ))
}

/// Import config and all layers from an OCI layout.
///
/// Returns (config_digest, config_verity, layer_refs, stats).
/// `layer_refs` is an ordered Vec of (diff_id, verity) pairs preserving the
/// order from the config (or manifest for artifacts).
async fn import_config_and_layers<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    ocidir: &OciDir,
    manifest_layers: &[Descriptor],
    config_descriptor: &Descriptor,
) -> Result<(String, ObjectID, Vec<(String, ObjectID)>, ImportStats)> {
    let config_digest: &str = config_descriptor.digest().as_ref();
    let content_id = config_identifier(config_digest);

    if let Some(config_id) = repo.has_stream(&content_id)? {
        debug!("Already have container config {config_digest}");

        let (data, named_refs) = crate::oci_image::read_external_splitstream(
            repo,
            &content_id,
            Some(&config_id),
            Some(OCI_CONFIG_CONTENT_TYPE),
        )?;
        let named_refs_map: HashMap<&str, ObjectID> = named_refs
            .iter()
            .map(|(k, v)| (k.as_ref(), v.clone()))
            .collect();

        let diff_ids =
            crate::extract_diff_ids(config_descriptor.media_type(), &data, manifest_layers)?;

        let layer_refs: Vec<(String, ObjectID)> = diff_ids
            .into_iter()
            .map(|diff_id| {
                let verity = named_refs_map
                    .get(diff_id.as_str())
                    .with_context(|| format!("missing layer verity for diff_id {diff_id}"))?;
                Ok((diff_id, verity.clone()))
            })
            .collect::<Result<_>>()?;

        anyhow::ensure!(
            layer_refs.len() == manifest_layers.len(),
            "expected {} layer refs but got {}",
            manifest_layers.len(),
            layer_refs.len()
        );

        return Ok((
            config_digest.to_string(),
            config_id,
            layer_refs,
            ImportStats::default(),
        ));
    }

    // Fetch config
    debug!("Reading config {config_digest}");
    let raw_config = read_blob_bytes(ocidir, config_descriptor).context("Reading config blob")?;

    // Parse config to get diff_ids (if this is a container image).
    // For artifacts with non-standard config types, falls back to layer digests.
    let diff_ids =
        crate::extract_diff_ids(config_descriptor.media_type(), &raw_config, manifest_layers)?;

    // Sort layers by size for parallel fetching (largest first)
    let mut layers: Vec<_> = manifest_layers.iter().zip(&diff_ids).collect();
    layers.sort_by_key(|(desc, _)| Reverse(desc.size()));

    let threads = available_parallelism()?;
    let sem = Arc::new(Semaphore::new(threads.into()));
    let mut layer_tasks = JoinSet::new();

    for (idx, (descriptor, diff_id)) in layers.iter().enumerate() {
        let diff_id = diff_id.to_string();
        let repo = Arc::clone(repo);
        let permit = Arc::clone(&sem).acquire_owned().await?;

        let layer_file = ocidir
            .read_blob(descriptor)
            .with_context(|| format!("Opening layer blob {}", descriptor.digest()))?;

        let media_type = descriptor.media_type().clone();

        layer_tasks.spawn(async move {
            let _permit = permit;
            let (verity, layer_stats) =
                import_layer_from_file(&repo, &diff_id, layer_file, &media_type).await?;
            anyhow::Ok((idx, diff_id, verity, layer_stats))
        });
    }

    // Collect results into a map keyed by diff_id for ordered lookup
    let mut verity_map = HashMap::new();
    let mut stats = ImportStats::default();
    for result in layer_tasks.join_all().await {
        let (_, diff_id, verity, layer_stats) = result?;
        verity_map.insert(diff_id, verity);
        stats.merge(&layer_stats);
    }

    // Build ordered layer_refs from config-defined diff_id order
    let layer_refs: Vec<(String, ObjectID)> = diff_ids
        .into_iter()
        .map(|diff_id| {
            let verity = verity_map
                .get(diff_id.as_str())
                .with_context(|| format!("missing layer verity for diff_id {diff_id}"))?;
            Ok((diff_id, verity.clone()))
        })
        .collect::<Result<_>>()?;

    anyhow::ensure!(
        layer_refs.len() == manifest_layers.len(),
        "expected {} layer refs but got {}",
        manifest_layers.len(),
        layer_refs.len()
    );

    let mut splitstream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
    for (diff_id, verity) in &layer_refs {
        splitstream.add_named_stream_ref(diff_id, verity);
    }

    splitstream.write_external(&raw_config)?;
    let config_id = repo.write_stream(splitstream, &content_id, None)?;

    Ok((config_digest.to_string(), config_id, layer_refs, stats))
}

/// Import a single layer by streaming from a file handle.
async fn import_layer_from_file<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    diff_id: &str,
    layer_file: std::fs::File,
    media_type: &MediaType,
) -> Result<(ObjectID, ImportStats)> {
    let content_id = layer_identifier(diff_id);

    if let Some(layer_id) = repo.has_stream(&content_id)? {
        debug!("Already have layer {diff_id}");
        return Ok((layer_id, ImportStats::default()));
    }

    debug!("Importing layer {diff_id}");

    // Convert std::fs::File to tokio::fs::File for async I/O
    let async_file = tokio::fs::File::from_std(layer_file);

    let (object_id, layer_stats) = if is_tar_media_type(media_type) {
        let reader = decompress_async(async_file, media_type)?;
        import_tar_async(repo.clone(), reader).await?
    } else {
        // Non-tar blob: store as object and create splitstream wrapper
        let (object_id, size, method) = store_blob_async(repo, async_file).await?;

        let mut stats = ImportStats::default();
        match method {
            ObjectStoreMethod::Copied => {
                stats.objects_copied += 1;
                stats.bytes_copied += size;
            }
            ObjectStoreMethod::AlreadyPresent => {
                stats.objects_already_present += 1;
            }
        }

        let mut stream = repo.create_stream(OCI_BLOB_CONTENT_TYPE);
        stream.add_external_size(size);
        stream.write_reference(object_id)?;
        let stream_id = repo.write_stream(stream, &content_id, None)?;
        return Ok((stream_id, stats));
    };

    // Register the stream with its content identifier
    repo.register_stream(&object_id, &content_id, None).await?;

    Ok((object_id, layer_stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_oci_layout_ref() {
        let cases: &[(&str, (&str, Option<&str>))] = &[
            ("/path/to/oci", ("/path/to/oci", None)),
            ("./local/oci", ("./local/oci", None)),
            ("ocidir", ("ocidir", None)),
            ("/path/to/oci:latest", ("/path/to/oci", Some("latest"))),
            ("/path/to/oci:v1.0.0", ("/path/to/oci", Some("v1.0.0"))),
            ("./local/oci:mytag", ("./local/oci", Some("mytag"))),
            ("ocidir:latest", ("ocidir", Some("latest"))),
            ("C:/path/to/oci", ("C:/path/to/oci", None)),
            ("C:/path/to/oci:latest", ("C:/path/to/oci", Some("latest"))),
            (
                "/path/to/oci:tag:with:colons",
                ("/path/to/oci:tag:with", Some("colons")),
            ),
            ("/path/to/oci:", ("/path/to/oci", Some(""))),
            ("ocidir:", ("ocidir", Some(""))),
            ("/path:middle/to/oci", ("/path:middle/to/oci", None)),
            (
                "/path:middle/to/oci:tag",
                ("/path:middle/to/oci", Some("tag")),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(parse_oci_layout_ref(input), *expected, "input: {input}");
        }
    }

    #[tokio::test]
    async fn test_empty_manifest_list_rejected() {
        use composefs::fsverity::Sha256HashValue;
        use oci_spec::image::{DescriptorBuilder, ImageIndexBuilder, OciLayoutBuilder};
        use sha2::Digest;

        let tempdir = tempfile::tempdir().unwrap();
        let layout_path = tempdir.path();

        let oci_layout = OciLayoutBuilder::default()
            .image_layout_version("1.0.0".to_string())
            .build()
            .unwrap();
        let oci_layout_path = layout_path.join("oci-layout");
        std::fs::write(&oci_layout_path, oci_layout.to_string().unwrap()).unwrap();

        let blobs_dir = layout_path.join("blobs/sha256");
        std::fs::create_dir_all(&blobs_dir).unwrap();

        let manifest_list = ImageIndexBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageIndex)
            .manifests(vec![])
            .build()
            .unwrap();
        let manifest_list_json = manifest_list.to_string().unwrap();
        let manifest_list_digest = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(manifest_list_json.as_bytes()))
        );
        let blob_path = blobs_dir.join(&manifest_list_digest[7..]);
        std::fs::write(&blob_path, &manifest_list_json).unwrap();

        let manifest_list_desc = DescriptorBuilder::default()
            .media_type(MediaType::ImageIndex)
            .digest(
                manifest_list_digest
                    .parse::<oci_spec::image::Digest>()
                    .unwrap(),
            )
            .size(manifest_list_json.len() as u64)
            .build()
            .unwrap();

        let top_index = ImageIndexBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageIndex)
            .manifests(vec![manifest_list_desc])
            .build()
            .unwrap();
        let index_path = layout_path.join("index.json");
        std::fs::write(&index_path, top_index.to_string().unwrap()).unwrap();

        let repo_dir = tempfile::tempdir().unwrap();
        let repo = std::sync::Arc::new(
            composefs::repository::Repository::<Sha256HashValue>::open_path(
                rustix::fs::CWD,
                repo_dir.path(),
            )
            .unwrap(),
        );

        let result = import_oci_layout(&repo, layout_path, None, None).await;
        let err = result.expect_err("should fail with no matching platform");
        let err_msg = format!("{err:#}");
        assert!(
            err_msg.contains("No manifest found for platform")
                || err_msg.contains("no platform info"),
            "unexpected error: {err_msg}"
        );
    }
}
