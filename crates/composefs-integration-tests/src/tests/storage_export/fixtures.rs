//! OCI metadata fixtures shared by storage-export integration tests.

use anyhow::Result;
use composefs_storage::writer::RawImage;
use serde_json::{Value, json};

pub(super) fn raw_image(layers: &[&[u8]]) -> Result<RawImage> {
    raw_image_with_config(layers, json!({"architecture": "amd64", "os": "linux"}))
}

/// Add layer identities to the supplied config and build its matching manifest.
pub(super) fn raw_image_with_config(layers: &[&[u8]], mut config: Value) -> Result<RawImage> {
    let diffs: Vec<_> = layers
        .iter()
        .map(|bytes| composefs_oci::sha256_content_digest(bytes))
        .collect();
    config["rootfs"] = json!({"type": "layers", "diff_ids": diffs});
    let config_json = serde_json::to_vec_pretty(&config)?;
    let manifest_json = serde_json::to_vec_pretty(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": composefs_oci::sha256_content_digest(&config_json),
            "size": config_json.len(),
        },
        "layers": layers.iter().zip(&diffs).map(|(bytes, diff)| json!({
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": diff,
            "size": bytes.len(),
        })).collect::<Vec<_>>(),
    }))?;
    Ok(RawImage {
        expected_manifest: composefs_oci::sha256_content_digest(&manifest_json),
        manifest_json,
        config_json,
    })
}
