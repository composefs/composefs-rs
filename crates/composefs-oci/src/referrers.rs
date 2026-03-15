//! Fetch OCI referrer artifacts from a remote registry.
//!
//! This module supplements the skopeo-based pull (which doesn't support the
//! OCI Referrers API) by querying the registry directly via `oci-client` for
//! artifacts that reference the pulled image's manifest digest.
//!
//! The primary use case is fetching composefs signature artifacts so that
//! `--require-signature` works after pulling a sealed+signed image.

use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};

use composefs::fsverity::FsVerityHashValue;
use composefs::repository::Repository;
use oci_client::Client;
use oci_client::Reference;
use oci_client::client::ClientConfig;
use oci_client::secrets::RegistryAuth;

use crate::oci_image;
use crate::signature::EROFS_ALONGSIDE_ARTIFACT_TYPE;

/// Fetch OCI referrer artifacts from a remote registry and import them
/// into the local composefs repository.
///
/// This supplements the skopeo-based pull (which doesn't support the
/// OCI Referrers API) by querying the registry directly for artifacts
/// that reference the pulled image's manifest digest.
///
/// `registry_ref` is the image reference as used for pulling, e.g.
/// `"docker://docker.io/myorg/myimage:latest"` or `"docker.io/myorg/myimage:latest"`.
/// Transport prefixes like `docker://` are stripped automatically.
///
/// `manifest_digest` is the sha256 digest of the pulled image's manifest,
/// e.g. `"sha256:abc123..."`.
///
/// Returns the number of referrer artifacts imported.
pub async fn fetch_and_import_referrers<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    registry_ref: &str,
    manifest_digest: &str,
) -> Result<usize> {
    // Strip transport prefixes that skopeo uses but oci-client doesn't understand
    let clean_ref = strip_transport_prefix(registry_ref);

    // Parse into an oci-client Reference
    let reference = Reference::from_str(clean_ref)
        .with_context(|| format!("parsing image reference '{clean_ref}' for referrer lookup"))?;

    // Create a reference with the manifest digest for the referrers API.
    // The referrers API needs the digest, not the tag.
    let digest_ref = reference.clone_with_digest(manifest_digest.to_string());

    let client = Client::new(ClientConfig::default());

    // Fetch the referrers index, filtering by our artifact type.
    // Try the OCI Referrers API first, then fall back to the tag scheme.
    // Some registries (e.g. GHCR) don't properly support the referrers API
    // but store referrers under a tag named "sha256-<hex>" per the OCI 1.1
    // referrers tag scheme fallback.
    let index = match client
        .pull_referrers(&digest_ref, Some(EROFS_ALONGSIDE_ARTIFACT_TYPE))
        .await
    {
        Ok(idx) => idx,
        Err(api_err) => {
            log::debug!("Referrers API failed ({api_err:#}), trying tag scheme fallback");
            fetch_referrers_by_tag(&client, &reference, manifest_digest).await?
        }
    };

    if index.manifests.is_empty() {
        return Ok(0);
    }

    let mut imported = 0;

    for entry in &index.manifests {
        let artifact_digest = &entry.digest;

        // Check if we already have this artifact
        let manifest_content_id = oci_image::manifest_identifier(artifact_digest);
        if repo.has_stream(&manifest_content_id)?.is_some() {
            log::debug!("Already have referrer artifact {artifact_digest}");
            imported += 1;
            continue;
        }

        // Fetch the artifact manifest
        let artifact_ref = reference.clone_with_digest(artifact_digest.clone());
        let (raw_manifest_bytes, _manifest_content_digest) = client
            .pull_manifest_raw(
                &artifact_ref,
                &RegistryAuth::Anonymous,
                &["application/vnd.oci.image.manifest.v1+json"],
            )
            .await
            .with_context(|| format!("fetching artifact manifest {artifact_digest}"))?;

        // Parse manifest through JSON to bridge oci-spec 0.9 (oci-client) to 0.8 (composefs).
        // Both versions use the same JSON schema, so serde round-tripping works.
        let manifest: oci_spec::image::ImageManifest = serde_json::from_slice(&raw_manifest_bytes)
            .with_context(|| {
                format!("parsing artifact manifest {artifact_digest} (oci-spec version bridge)")
            })?;

        // Import the config blob
        let config_digest = manifest.config().digest().to_string();
        let config_content_id = crate::config_identifier(&config_digest);
        let config_verity = if let Some(v) = repo.has_stream(&config_content_id)? {
            v
        } else {
            // Fetch config blob from registry
            let config_data = fetch_blob(&client, &reference, &config_digest)
                .await
                .with_context(|| format!("fetching config blob {config_digest}"))?;
            let mut config_stream = repo.create_stream(crate::skopeo::OCI_CONFIG_CONTENT_TYPE);
            config_stream.write_external(&config_data)?;
            repo.write_stream(config_stream, &config_content_id, None)?
        };

        // Import each layer blob
        let mut layer_verities = Vec::new();
        for layer_desc in manifest.layers() {
            let layer_digest = layer_desc.digest().to_string();
            let layer_content_id = oci_image::blob_identifier(&layer_digest);
            let layer_verity = if let Some(v) = repo.has_stream(&layer_content_id)? {
                v
            } else {
                let layer_data = fetch_blob(&client, &reference, &layer_digest)
                    .await
                    .with_context(|| format!("fetching layer blob {layer_digest}"))?;
                let mut layer_stream = repo.create_stream(crate::skopeo::OCI_BLOB_CONTENT_TYPE);
                layer_stream.write_external(&layer_data)?;
                repo.write_stream(layer_stream, &layer_content_id, None)?
            };
            layer_verities.push((layer_digest, layer_verity));
        }

        // Store the manifest splitstream
        let mut manifest_stream = repo.create_stream(crate::skopeo::OCI_MANIFEST_CONTENT_TYPE);

        let config_key = format!("config:{config_digest}");
        manifest_stream.add_named_stream_ref(&config_key, &config_verity);

        for (layer_digest, layer_verity) in &layer_verities {
            manifest_stream.add_named_stream_ref(layer_digest, layer_verity);
        }

        // Store the raw manifest bytes (from the registry) as-is to preserve
        // the exact digest
        manifest_stream.write_external(&raw_manifest_bytes)?;
        repo.write_stream(manifest_stream, &manifest_content_id, None)?;

        // Register in the referrer index
        oci_image::add_referrer(repo, manifest_digest, artifact_digest)?;

        log::info!("Imported referrer artifact {artifact_digest}");
        imported += 1;
    }

    Ok(imported)
}

/// Fetch referrers using the OCI 1.1 tag scheme fallback.
///
/// When a registry doesn't support the Referrers API (e.g. GHCR returns 303/404),
/// referrer artifacts are stored under a tag named `sha256-<hex>` in the same
/// repository. The tagged manifest is an OCI Image Index listing all referrers.
async fn fetch_referrers_by_tag(
    client: &Client,
    reference: &Reference,
    manifest_digest: &str,
) -> Result<oci_client::manifest::OciImageIndex> {
    // Convert "sha256:abcdef..." to tag "sha256-abcdef..."
    let tag = manifest_digest.replace(':', "-");
    let tag_ref = Reference::with_tag(
        reference.registry().to_string(),
        reference.repository().to_string(),
        tag.clone(),
    );

    let (raw_bytes, _digest) = client
        .pull_manifest_raw(
            &tag_ref,
            &RegistryAuth::Anonymous,
            &["application/vnd.oci.image.index.v1+json"],
        )
        .await
        .with_context(|| format!("fetching referrers via tag scheme (tag '{tag}')"))?;

    let index: oci_client::manifest::OciImageIndex =
        serde_json::from_slice(&raw_bytes).context("parsing referrers tag index")?;

    log::info!(
        "Found {} referrer(s) via tag scheme fallback",
        index.manifests.len()
    );
    Ok(index)
}

/// Fetch a blob by digest from the registry.
///
/// Uses the oci-client `pull_blob` method which writes to an async writer.
async fn fetch_blob(client: &Client, reference: &Reference, digest: &str) -> Result<Vec<u8>> {
    // Create a descriptor for pull_blob — it just needs the digest field
    let desc = oci_client::manifest::OciDescriptor {
        digest: digest.to_string(),
        ..Default::default()
    };

    let mut buf = Vec::new();
    client
        .pull_blob(reference, &desc, &mut buf)
        .await
        .with_context(|| format!("pulling blob {digest}"))?;
    Ok(buf)
}

/// Strip common transport prefixes from image references.
///
/// Skopeo-style references include transport prefixes like `docker://`,
/// `containers-storage:`, etc. The `oci-client` `Reference` parser expects
/// bare registry references like `docker.io/library/nginx:latest`.
fn strip_transport_prefix(imgref: &str) -> &str {
    // Common transport prefixes used by skopeo/containers-image
    for prefix in &[
        "docker://",
        "docker:",
        "containers-storage:",
        "oci:",
        "dir:",
    ] {
        if let Some(rest) = imgref.strip_prefix(prefix) {
            return rest;
        }
    }
    imgref
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_transport_prefix() {
        assert_eq!(
            strip_transport_prefix("docker://docker.io/library/nginx:latest"),
            "docker.io/library/nginx:latest"
        );
        assert_eq!(
            strip_transport_prefix("docker:docker.io/myorg/myimage:v1"),
            "docker.io/myorg/myimage:v1"
        );
        assert_eq!(
            strip_transport_prefix("containers-storage:sha256:abc123"),
            "sha256:abc123"
        );
        assert_eq!(
            strip_transport_prefix("oci:/path/to/layout"),
            "/path/to/layout"
        );
        assert_eq!(
            strip_transport_prefix("quay.io/fedora/fedora:latest"),
            "quay.io/fedora/fedora:latest"
        );
    }

    #[test]
    fn test_reference_parsing() {
        // Verify that common image references parse correctly after stripping
        let cases = [
            "docker.io/library/nginx:latest",
            "quay.io/fedora/fedora:40",
            "ghcr.io/myorg/myimage:v1.0",
            "registry.example.com/repo:tag",
        ];

        for case in cases {
            let reference = Reference::from_str(case);
            assert!(
                reference.is_ok(),
                "Failed to parse reference '{case}': {:?}",
                reference.err()
            );
        }
    }

    #[test]
    fn test_reference_clone_with_digest() {
        let reference = Reference::from_str("docker.io/library/nginx:latest").unwrap();
        let digest = "sha256:abc123def456";
        let digest_ref = reference.clone_with_digest(digest.to_string());

        assert_eq!(digest_ref.registry(), "docker.io");
        assert_eq!(digest_ref.repository(), "library/nginx");
        assert_eq!(digest_ref.digest(), Some(digest));
    }

    #[test]
    fn test_strip_and_parse_docker_prefix() {
        let imgref = "docker://quay.io/fedora/fedora:40";
        let clean = strip_transport_prefix(imgref);
        let reference = Reference::from_str(clean).unwrap();
        assert_eq!(reference.registry(), "quay.io");
        assert_eq!(reference.repository(), "fedora/fedora");
        assert_eq!(reference.tag(), Some("40"));
    }
}
