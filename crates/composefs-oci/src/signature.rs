//! Composefs artifact construction and verification.
//!
//! Builds OCI artifact manifests containing composefs fsverity digests
//! and PKCS#7 signatures per the OCI sealing specification.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use base64::Engine;
use composefs::fsverity::Algorithm;

/// Error when an image has no signature artifacts.
#[derive(Debug, thiserror::Error)]
#[error("No signature artifacts found for {name}")]
pub struct NoSignatureArtifacts {
    /// Name of the image missing artifacts.
    pub name: String,
}

/// Error when an image's signature artifact fails verification.
#[derive(Debug, thiserror::Error)]
#[error("Signature verification failed: {reason}")]
pub struct SignatureVerificationFailed {
    /// Reason for the verification failure.
    pub reason: String,
}
use composefs::fsverity::FsVerityHashValue;
use composefs::repository::Repository;
use containers_image_proxy::oci_spec::image::{
    Descriptor, DescriptorBuilder, Digest as OciDigest, ImageManifest, ImageManifestBuilder,
    MediaType,
};

/// Artifact type for composefs metadata manifests.
pub const METADATA_ARTIFACT_TYPE: &str = "application/vnd.composefs.metadata.v1";

/// Backward-compatible alias for the artifact type constant.
pub const ARTIFACT_TYPE: &str = METADATA_ARTIFACT_TYPE;

/// Media type for PKCS#7 DER signature layers.
pub const SIGNATURE_MEDIA_TYPE: &str = "application/vnd.composefs.signature.v1+pkcs7";

/// The type of object a signature layer refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureType {
    /// Signature for the OCI manifest JSON.
    Manifest,
    /// Signature for the OCI config JSON.
    Config,
    /// Signature for an individual composefs layer EROFS (inline mode only).
    Layer,
    /// Signature for a merged (rolling) composefs filesystem.
    Merged,
    /// Signature for a bootable merged composefs filesystem.
    MergedBootable,
}

impl SignatureType {
    /// The annotation value string for this type.
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureType::Manifest => "manifest",
            SignatureType::Config => "config",
            SignatureType::Layer => "layer",
            SignatureType::Merged => "merged",
            SignatureType::MergedBootable => "merged.bootable",
        }
    }

    /// Return the annotation key for this role.
    pub fn annotation_key(&self, algorithm: Algorithm) -> String {
        let suffix = match algorithm {
            Algorithm::Sha256 { lg_blocksize } => format!("sha256-{lg_blocksize}"),
            Algorithm::Sha512 { lg_blocksize } => format!("sha512-{lg_blocksize}"),
        };
        match self {
            SignatureType::Manifest | SignatureType::Config => {
                format!("composefs.{}.fsverity-{}", self.as_str(), suffix)
            }
            _ => {
                format!("composefs.{}.erofs.v1.fsverity-{}", self.as_str(), suffix)
            }
        }
    }
}

/// A single signature entry in a composefs artifact.
#[derive(Debug, Clone)]
pub struct SignatureEntry {
    /// What this entry signs.
    pub sig_type: SignatureType,
    /// The composefs fsverity digest as a hex string.
    pub digest: String,
    /// Raw PKCS#7 DER signature blob, if available (always available if parsed from artifact).
    pub signature: Option<Vec<u8>>,
}

/// The result of parsing a composefs artifact manifest.
#[derive(Debug)]
pub struct ParsedComposeFsArtifact {
    /// The composefs algorithm used for fsverity digests.
    pub algorithm: Algorithm,
    /// The subject descriptor (the image this artifact refers to).
    pub subject: Descriptor,
    /// Signature entries.
    pub signature_entries: Vec<SignatureEntry>,
}

/// Backward-compatible alias for ParsedComposeFsArtifact.
pub type ParsedSignatureArtifact = ParsedComposeFsArtifact;

/// Extracts (Algorithm, SignatureType, digest_hex) from annotation key/value pair
#[allow(clippy::manual_map)]
pub fn parse_annotation_key_value(
    key: &str,
    value: &str,
) -> Option<(Algorithm, SignatureType, String)> {
    let suffix = if let Some(s) = key.strip_prefix("composefs.manifest.fsverity-") {
        Some((SignatureType::Manifest, s))
    } else if let Some(s) = key.strip_prefix("composefs.config.fsverity-") {
        Some((SignatureType::Config, s))
    } else if let Some(s) = key.strip_prefix("composefs.merged.erofs.v1.fsverity-") {
        Some((SignatureType::Merged, s))
    } else if let Some(s) = key.strip_prefix("composefs.merged.bootable.erofs.v1.fsverity-") {
        Some((SignatureType::MergedBootable, s))
    } else if let Some(s) = key.strip_prefix("composefs.layer.erofs.v1.fsverity-") {
        Some((SignatureType::Layer, s))
    } else {
        None
    };

    let (sig_type, alg_str) = suffix?;

    // Check for .sig suffix (used in inline mode) and strip it
    let alg_str = alg_str.strip_suffix(".sig").unwrap_or(alg_str);

    let algorithm = match alg_str {
        "sha256-12" => Algorithm::Sha256 { lg_blocksize: 12 },
        "sha512-12" => Algorithm::Sha512 { lg_blocksize: 12 },
        "sha256-16" => Algorithm::Sha256 { lg_blocksize: 16 },
        "sha512-16" => Algorithm::Sha512 { lg_blocksize: 16 },
        _ => return None,
    };

    Some((algorithm, sig_type, value.to_string()))
}

/// Parses an OCI image manifest into a ParsedComposeFsArtifact.
pub fn parse_signature_artifact(manifest: &ImageManifest) -> Result<ParsedComposeFsArtifact> {
    match manifest.artifact_type() {
        Some(MediaType::Other(s)) if s == METADATA_ARTIFACT_TYPE => {}
        other => bail!("wrong artifact type: {:?}", other),
    }

    let subject = manifest
        .subject()
        .as_ref()
        .context("composefs artifact missing subject descriptor")?
        .clone();

    let mut signature_entries = Vec::new();
    let mut detected_algorithm = None;

    for layer in manifest.layers() {
        let annotations = layer
            .annotations()
            .as_ref()
            .context("layer missing annotations")?;

        let mut found = None;
        for (k, v) in annotations {
            if let Some((alg, sig_type, digest)) = parse_annotation_key_value(k, v) {
                found = Some((alg, sig_type, digest));
                break;
            }
        }

        let (algorithm, sig_type, digest) =
            found.context("layer missing valid composefs digest annotation")?;

        if let Some(existing) = detected_algorithm {
            if existing != algorithm {
                bail!("mixed algorithms in artifact");
            }
        } else {
            detected_algorithm = Some(algorithm);
        }

        signature_entries.push(SignatureEntry {
            sig_type,
            digest,
            signature: None, // Will be populated by caller if downloading the blob
        });
    }

    let algorithm = detected_algorithm.context("no composefs layers found")?;

    Ok(ParsedComposeFsArtifact {
        algorithm,
        subject,
        signature_entries,
    })
}

fn sha256_digest(data: &[u8]) -> OciDigest {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let hex = hex::encode(result);
    format!("sha256:{hex}").parse().unwrap()
}

/// Signs a container image and stores the resulting composefs signature artifact in the repository.
pub fn sign_image<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    name: &str,
    signing_key: &crate::signing::FsVeritySigningKey,
) -> Result<(OciDigest, ObjectID)> {
    let img = crate::oci_image::OciImage::open_ref(repo, name)?;

    anyhow::ensure!(
        img.is_container_image(),
        "can only sign container images, not artifacts"
    );

    let config_digest = img.config_digest();
    let algorithm = ObjectID::ALGORITHM;

    let (_merged_erofs, merged_digest) = crate::generate_merged_image(repo, config_digest, None)?;

    let subject = crate::OciDescriptorBuilder::default()
        .media_type(crate::OciMediaType::ImageManifest)
        .digest(img.manifest_digest().clone())
        .size(img.manifest().to_string()?.len() as u64)
        .build()
        .context("building subject descriptor")?;

    let merged_sig = signing_key.sign(&merged_digest)?;

    // Construct layers
    let mut layers = Vec::new();
    let mut blobs = Vec::new();

    // 1. Manifest signature (optional, we'll skip for now since we don't have manifest bytes readily available in standard fsverity format)
    // 2. Config signature (optional, we'll skip for now)

    // 3. Merged EROFS signature
    let mut merged_annotations = std::collections::HashMap::new();
    merged_annotations.insert(
        SignatureType::Merged.annotation_key(algorithm),
        merged_digest.to_hex(),
    );

    let merged_desc = DescriptorBuilder::default()
        .media_type(MediaType::Other(SIGNATURE_MEDIA_TYPE.to_string()))
        .digest(sha256_digest(&merged_sig))
        .size(merged_sig.len() as u64)
        .annotations(merged_annotations)
        .build()
        .context("building merged signature descriptor")?;

    layers.push(merged_desc);
    blobs.push(merged_sig);

    let empty_config = b"{}";
    let config_digest = sha256_digest(empty_config);
    let config_id = crate::config_identifier(&config_digest);

    let config_verity = if let Some(v) = repo.has_stream(&config_id)? {
        v
    } else {
        let mut config_stream = repo.create_stream(crate::skopeo::OCI_CONFIG_CONTENT_TYPE)?;
        config_stream.write_external(empty_config)?;
        repo.write_stream(config_stream, &config_id, None)?
    };

    let mut artifact_builder = ImageManifestBuilder::default()
        .schema_version(2u32)
        .media_type(crate::OciMediaType::ImageManifest)
        .artifact_type(MediaType::Other(METADATA_ARTIFACT_TYPE.to_string()))
        .subject(subject)
        .config(
            DescriptorBuilder::default()
                .media_type(MediaType::Other(
                    "application/vnd.oci.empty.v1+json".to_string(),
                ))
                .digest(config_digest)
                .size(empty_config.len() as u64)
                .build()?,
        );

    artifact_builder = artifact_builder.layers(layers);
    let artifact_manifest = artifact_builder.build()?;

    // Write signature blobs and collect their verities
    let mut layer_verities = Vec::new();
    for blob in blobs {
        let (digest, verity) = crate::oci_image::write_blob(repo, &blob)?;
        layer_verities.push((digest.to_string(), verity));
    }

    let manifest_bytes = artifact_manifest.to_string()?.into_bytes();
    let manifest_digest = sha256_digest(&manifest_bytes);

    let (manifest_digest, artifact_id) = crate::oci_image::write_manifest(
        repo,
        &artifact_manifest,
        &manifest_digest,
        &config_verity,
        &layer_verities,
        None,
    )?;

    crate::oci_image::add_referrer(repo, img.manifest_digest(), &manifest_digest)?;

    Ok((manifest_digest, artifact_id))
}

/// Verifies the composefs signatures associated with a container image.
pub fn verify_image_signatures<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
    verifier: Option<&crate::signing::FsVeritySignatureVerifier>,
) -> Result<usize> {
    Ok(verify_image_report(repo, name, verifier)?.verified_count)
}

/// Signs an inline-sealed container image by adding signature annotations directly in the image manifest.
pub fn sign_image_inline<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    name: &str,
    signing_key: &crate::signing::FsVeritySigningKey,
) -> Result<OciDigest> {
    let img = crate::oci_image::OciImage::open_ref(repo, name)?;
    anyhow::ensure!(
        img.is_container_image(),
        "can only sign container images, not artifacts"
    );

    // Sign config annotations
    let mut config_annotations = img
        .manifest()
        .config()
        .annotations()
        .as_ref()
        .cloned()
        .unwrap_or_default();
    let mut config_sigs_to_add = Vec::new();
    for (key, value) in &config_annotations {
        if key.ends_with(".sig") {
            continue;
        }
        if let Some((_, sig_type, digest_hex)) = parse_annotation_key_value(key, value) {
            if sig_type == SignatureType::Manifest {
                continue;
            }
            let objid = ObjectID::from_hex(&digest_hex)
                .map_err(|e| anyhow::anyhow!("invalid digest hex in config annotation: {e}"))?;
            let sig_bytes = signing_key.sign(&objid)?;
            let base64_sig = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
            config_sigs_to_add.push((format!("{key}.sig"), base64_sig));
        }
    }
    for (k, v) in config_sigs_to_add {
        config_annotations.insert(k, v);
    }

    // Sign layer annotations
    let mut new_layers = Vec::new();
    for layer in img.manifest().layers() {
        let mut layer_annotations = layer.annotations().as_ref().cloned().unwrap_or_default();
        let mut layer_sigs_to_add = Vec::new();
        for (key, value) in &layer_annotations {
            if key.ends_with(".sig") {
                continue;
            }
            if let Some((_, sig_type, digest_hex)) = parse_annotation_key_value(key, value) {
                if sig_type == SignatureType::Manifest {
                    continue;
                }
                let objid = ObjectID::from_hex(&digest_hex)
                    .map_err(|e| anyhow::anyhow!("invalid digest hex in layer annotation: {e}"))?;
                let sig_bytes = signing_key.sign(&objid)?;
                let base64_sig = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
                layer_sigs_to_add.push((format!("{key}.sig"), base64_sig));
            }
        }
        for (k, v) in layer_sigs_to_add {
            layer_annotations.insert(k, v);
        }
        let new_layer = DescriptorBuilder::default()
            .media_type(layer.media_type().clone())
            .digest(layer.digest().clone())
            .size(layer.size())
            .annotations(layer_annotations)
            .build()
            .context("building layer descriptor")?;
        new_layers.push(new_layer);
    }

    // Sign top-level manifest annotations
    let mut manifest_annotations = img
        .manifest()
        .annotations()
        .as_ref()
        .cloned()
        .unwrap_or_default();
    let mut manifest_sigs_to_add = Vec::new();
    for (key, value) in &manifest_annotations {
        if key.ends_with(".sig") {
            continue;
        }
        if let Some((_, sig_type, digest_hex)) = parse_annotation_key_value(key, value) {
            if sig_type == SignatureType::Manifest {
                continue;
            }
            let objid = ObjectID::from_hex(&digest_hex)
                .map_err(|e| anyhow::anyhow!("invalid digest hex in manifest annotation: {e}"))?;
            let sig_bytes = signing_key.sign(&objid)?;
            let base64_sig = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
            manifest_sigs_to_add.push((format!("{key}.sig"), base64_sig));
        }
    }
    for (k, v) in manifest_sigs_to_add {
        manifest_annotations.insert(k, v);
    }

    let new_config_descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageConfig)
        .digest(img.config_digest().clone())
        .size(img.manifest().config().size())
        .annotations(config_annotations)
        .build()
        .context("building config descriptor")?;

    let new_manifest = ImageManifestBuilder::default()
        .schema_version(img.manifest().schema_version())
        .media_type(MediaType::ImageManifest)
        .config(new_config_descriptor)
        .layers(new_layers)
        .annotations(manifest_annotations)
        .build()
        .context("building signed manifest")?;

    let new_manifest_json = new_manifest.to_string()?;
    let new_manifest_digest = crate::sha256_content_digest(new_manifest_json.as_bytes());

    let layer_refs_vec: Vec<(Box<str>, ObjectID)> = img
        .layer_refs()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    crate::oci_image::write_manifest(
        repo,
        &new_manifest,
        &new_manifest_digest,
        img.config_verity(),
        &layer_refs_vec,
        Some(name),
    )?;

    Ok(new_manifest_digest)
}

/// Verifies the inline composefs signatures and digests embedded in a container image manifest.
pub fn verify_image_signatures_inline<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
    verifier: Option<&crate::signing::FsVeritySignatureVerifier>,
) -> Result<usize> {
    Ok(verify_image_report(repo, name, verifier)?.verified_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use composefs::fsverity::Sha256HashValue;
    use composefs::test::TestRepo;

    #[test]
    fn test_inline_annotation_keys_roundtrip() {
        let algs = vec![
            Algorithm::Sha256 { lg_blocksize: 12 },
            Algorithm::Sha512 { lg_blocksize: 12 },
            Algorithm::Sha256 { lg_blocksize: 16 },
            Algorithm::Sha512 { lg_blocksize: 16 },
        ];
        let types = vec![
            SignatureType::Config,
            SignatureType::Layer,
            SignatureType::Merged,
        ];
        for alg in algs {
            for t in &types {
                let key = t.annotation_key(alg);
                let value = "abcd1234abcd1234";
                let res = parse_annotation_key_value(&key, value);
                assert!(res.is_some());
                let (parsed_alg, parsed_t, parsed_val) = res.unwrap();
                assert_eq!(parsed_alg, alg);
                assert_eq!(parsed_t, *t);
                assert_eq!(parsed_val, value);

                // With .sig suffix
                let sig_key = format!("{key}.sig");
                let res_sig = parse_annotation_key_value(&sig_key, value);
                assert!(res_sig.is_some());
                let (parsed_alg_sig, parsed_t_sig, parsed_val_sig) = res_sig.unwrap();
                assert_eq!(parsed_alg_sig, alg);
                assert_eq!(parsed_t_sig, *t);
                assert_eq!(parsed_val_sig, value);
            }
        }
    }

    #[tokio::test]
    async fn test_inline_sign_verify_end_to_end() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = Arc::new(test_repo.repo);

        // 1. Create a base image
        let _img = crate::test_util::create_base_image(&repo, Some("base:v1")).await;

        // 2. Seal inline
        let sealed_digest = crate::oci_image::seal_image_inline(&repo, "base:v1").unwrap();

        // Check that annotations are present on the new image
        let sealed_img = crate::oci_image::OciImage::open_ref(&repo, "base:v1").unwrap();
        assert_eq!(sealed_img.manifest_digest(), &sealed_digest);

        let alg = Sha256HashValue::ALGORITHM;
        let config_anno_key = SignatureType::Config.annotation_key(alg);
        let merged_anno_key = SignatureType::Merged.annotation_key(alg);
        let layer_anno_key = SignatureType::Layer.annotation_key(alg);

        assert!(
            sealed_img
                .manifest()
                .config()
                .annotations()
                .as_ref()
                .unwrap()
                .contains_key(&config_anno_key)
        );
        assert!(
            sealed_img
                .manifest()
                .annotations()
                .as_ref()
                .unwrap()
                .contains_key(&merged_anno_key)
        );
        for layer in sealed_img.manifest().layers() {
            assert!(
                layer
                    .annotations()
                    .as_ref()
                    .unwrap()
                    .contains_key(&layer_anno_key)
            );
        }

        // Verify digest-only (verifier is None)
        let verified_digests = verify_image_signatures_inline(&repo, "base:v1", None).unwrap();
        assert!(verified_digests >= 2); // merged + config + layers

        // 3. Sign inline
        let (cert_pem, key_pem) = crate::signing::generate_test_keypair();
        let signer = crate::signing::FsVeritySigningKey::from_pem(&cert_pem, &key_pem).unwrap();
        let verifier = crate::signing::FsVeritySignatureVerifier::from_pem(&cert_pem).unwrap();

        let _signed_digest = sign_image_inline(&repo, "base:v1", &signer).unwrap();

        // Verify with verifier
        let verified_sigs =
            verify_image_signatures_inline(&repo, "base:v1", Some(&verifier)).unwrap();
        assert!(verified_sigs >= 2); // config + merged + layers should have signatures

        // Verify that trying to verify with a different cert fails
        let (wrong_cert_pem, _wrong_key_pem) = crate::signing::generate_test_keypair();
        let wrong_verifier =
            crate::signing::FsVeritySignatureVerifier::from_pem(&wrong_cert_pem).unwrap();
        let wrong_verify_res =
            verify_image_signatures_inline(&repo, "base:v1", Some(&wrong_verifier));
        assert!(wrong_verify_res.is_err());
    }

    fn mutate_and_restore_manifest<ObjectID: FsVerityHashValue>(
        repo: &Arc<Repository<ObjectID>>,
        name: &str,
        mutator: impl FnOnce(&mut std::collections::HashMap<String, String>),
    ) -> Result<()> {
        let img = crate::oci_image::OciImage::open_ref(repo, name)?;
        let mut manifest_annotations = img
            .manifest()
            .annotations()
            .as_ref()
            .cloned()
            .unwrap_or_default();

        mutator(&mut manifest_annotations);

        let config_annotations = img
            .manifest()
            .config()
            .annotations()
            .as_ref()
            .cloned()
            .unwrap_or_default();

        let new_config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageConfig)
            .digest(img.config_digest().clone())
            .size(img.manifest().config().size())
            .annotations(config_annotations)
            .build()
            .context("building config descriptor")?;

        let new_manifest = ImageManifestBuilder::default()
            .schema_version(img.manifest().schema_version())
            .media_type(MediaType::ImageManifest)
            .config(new_config_descriptor)
            .layers(img.manifest().layers().to_vec())
            .annotations(manifest_annotations)
            .build()
            .context("building signed manifest")?;

        let new_manifest_json = new_manifest.to_string()?;
        let new_manifest_digest = crate::sha256_content_digest(new_manifest_json.as_bytes());

        let layer_refs_vec: Vec<(Box<str>, ObjectID)> = img
            .layer_refs()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        crate::oci_image::write_manifest(
            repo,
            &new_manifest,
            &new_manifest_digest,
            img.config_verity(),
            &layer_refs_vec,
            Some(name),
        )?;

        Ok(())
    }

    #[tokio::test]
    async fn test_inline_verify_rejects_stripped_merged_signature() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = Arc::new(test_repo.repo);

        let _img = crate::test_util::create_base_image(&repo, Some("base:v1")).await;
        let _sealed_digest = crate::oci_image::seal_image_inline(&repo, "base:v1").unwrap();

        let (cert_pem, key_pem) = crate::signing::generate_test_keypair();
        let signer = crate::signing::FsVeritySigningKey::from_pem(&cert_pem, &key_pem).unwrap();
        let verifier = crate::signing::FsVeritySignatureVerifier::from_pem(&cert_pem).unwrap();

        let _signed_digest = sign_image_inline(&repo, "base:v1", &signer).unwrap();

        let verified_sigs =
            verify_image_signatures_inline(&repo, "base:v1", Some(&verifier)).unwrap();
        assert!(verified_sigs >= 1);

        let alg = Sha256HashValue::ALGORITHM;
        let merged_sig_key = format!("{}.sig", SignatureType::Merged.annotation_key(alg));

        mutate_and_restore_manifest(&repo, "base:v1", |annotations| {
            assert!(annotations.remove(&merged_sig_key).is_some());
        })
        .unwrap();

        let verify_res = verify_image_signatures_inline(&repo, "base:v1", Some(&verifier));
        assert!(verify_res.is_err());
        let err = verify_res.err().unwrap();
        let err_msg = format!("{:#}", err);
        assert!(
            err_msg.contains("merged filesystem digest is not signed"),
            "Expected 'merged filesystem digest is not signed' error, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_inline_verify_rejects_tampered_merged_digest() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = Arc::new(test_repo.repo);

        let _img = crate::test_util::create_base_image(&repo, Some("base:v1")).await;
        let _sealed_digest = crate::oci_image::seal_image_inline(&repo, "base:v1").unwrap();

        let (cert_pem, key_pem) = crate::signing::generate_test_keypair();
        let signer = crate::signing::FsVeritySigningKey::from_pem(&cert_pem, &key_pem).unwrap();
        let verifier = crate::signing::FsVeritySignatureVerifier::from_pem(&cert_pem).unwrap();

        let _signed_digest = sign_image_inline(&repo, "base:v1", &signer).unwrap();

        let alg = Sha256HashValue::ALGORITHM;
        let merged_digest_key = SignatureType::Merged.annotation_key(alg);

        mutate_and_restore_manifest(&repo, "base:v1", |annotations| {
            let old_value = annotations.get(&merged_digest_key).unwrap().clone();
            let tampered_value = "0".repeat(old_value.len());
            annotations.insert(merged_digest_key, tampered_value);
        })
        .unwrap();

        let verify_res = verify_image_signatures_inline(&repo, "base:v1", Some(&verifier));
        assert!(verify_res.is_err());
        let err_msg = format!("{:#}", verify_res.err().unwrap());
        assert!(
            err_msg.contains("Merged digest mismatch")
                || err_msg.to_lowercase().contains("merged")
                || err_msg.to_lowercase().contains("signature"),
            "Expected digest or signature error, got: {}",
            err_msg
        );

        let verify_none_res = verify_image_signatures_inline(&repo, "base:v1", None);
        assert!(verify_none_res.is_err());
        let err_none_msg = format!("{:#}", verify_none_res.err().unwrap());
        assert!(
            err_none_msg.contains("Merged digest mismatch")
                || err_none_msg.to_lowercase().contains("merged"),
            "Expected merged digest mismatch error for None verifier, got: {}",
            err_none_msg
        );
    }

    #[tokio::test]
    async fn test_inline_verify_digest_only_no_error_when_unsigned() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = Arc::new(test_repo.repo);

        let _img = crate::test_util::create_base_image(&repo, Some("base:v1")).await;
        let _sealed_digest = crate::oci_image::seal_image_inline(&repo, "base:v1").unwrap();

        let verified_digests = verify_image_signatures_inline(&repo, "base:v1", None);
        assert!(verified_digests.is_ok());
        let count = verified_digests.unwrap();
        assert!(count >= 1);
    }
}

/// Individual verification entry of an OCI image's component.
#[derive(Debug, Clone)]
pub struct VerificationEntry {
    /// The role of this entry (e.g. layer[0], merged, config, manifest).
    pub role: String,
    /// The expected digest for this role.
    pub expected_digest: Option<String>,
    /// Whether the expected digest matches the actual digest.
    pub digest_ok: bool,
    /// Whether the cryptographic signature verified successfully.
    pub signature_verified: bool,
    /// Detailed error message if verification failed.
    pub detail: Option<String>,
}

/// Verification report summarizing the full signature/digest checks.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// The number of signatures cryptographically verified.
    pub verified_count: usize,
    /// Whether a certificate was supplied for verification.
    pub cert_supplied: bool,
    /// The mode of verification: inline or artifact.
    pub mode: &'static str,
    /// The algorithm used (e.g. sha256-12).
    pub algorithm: Option<String>,
    /// Component-by-component verification results.
    pub entries: Vec<VerificationEntry>,
}

/// Verification report for OCI image, single source of truth.
pub fn verify_image_report<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
    verifier: Option<&crate::signing::FsVeritySignatureVerifier>,
) -> Result<VerificationReport> {
    let img = crate::oci_image::OciImage::open_ref(repo, name)?;

    // Check inline vs artifact
    let mut is_inline = false;
    if let Some(annotations) = img.manifest().annotations() {
        for key in annotations.keys() {
            if key.starts_with("composefs.") && key.contains(".fsverity-") {
                is_inline = true;
            }
        }
    }
    if let Some(annotations) = img.manifest().config().annotations() {
        for key in annotations.keys() {
            if key.starts_with("composefs.") && key.contains(".fsverity-") {
                is_inline = true;
            }
        }
    }
    for layer in img.manifest().layers() {
        if let Some(annotations) = layer.annotations() {
            for key in annotations.keys() {
                if key.starts_with("composefs.") && key.contains(".fsverity-") {
                    is_inline = true;
                }
            }
        }
    }

    if is_inline {
        verify_image_report_inline(repo, &img, name, verifier)
    } else {
        verify_image_report_artifact(repo, &img, name, verifier)
    }
}

fn verify_image_report_inline<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    img: &crate::oci_image::OciImage<ObjectID>,
    name: &str,
    verifier: Option<&crate::signing::FsVeritySignatureVerifier>,
) -> Result<VerificationReport> {
    // 1. Collect annotations
    let mut config_digests = Vec::new();
    let mut config_sigs = std::collections::HashMap::new();
    if let Some(annotations) = img.manifest().config().annotations() {
        for (key, value) in annotations {
            if key.ends_with(".sig") {
                config_sigs.insert(key.clone(), value.clone());
            } else if let Some((alg, sig_type, digest)) = parse_annotation_key_value(key, value) {
                config_digests.push((key.clone(), alg, sig_type, digest));
            }
        }
    }

    let mut layer_digests = Vec::new();
    for layer in img.manifest().layers() {
        let mut layer_info = Vec::new();
        if let Some(annotations) = layer.annotations() {
            for (key, value) in annotations {
                if key.ends_with(".sig") {
                    continue;
                }
                if let Some((alg, sig_type, digest)) = parse_annotation_key_value(key, value) {
                    let sig_key = format!("{key}.sig");
                    let sig_base64 = annotations.get(&sig_key).cloned();
                    layer_info.push((key.clone(), alg, sig_type, digest, sig_base64));
                }
            }
        }
        layer_digests.push(layer_info);
    }

    let mut manifest_digests = Vec::new();
    let mut manifest_sigs = std::collections::HashMap::new();
    if let Some(annotations) = img.manifest().annotations() {
        for (key, value) in annotations {
            if key.ends_with(".sig") {
                manifest_sigs.insert(key.clone(), value.clone());
            } else if let Some((alg, sig_type, digest)) = parse_annotation_key_value(key, value) {
                manifest_digests.push((key.clone(), alg, sig_type, digest));
            }
        }
    }

    // 2. DIGEST-CHECK & verify
    let local_merged_digest =
        crate::image::compute_merged_digest(repo, img.config_digest(), Some(img.config_verity()))?;
    let local_merged_hex = local_merged_digest.to_hex();

    let local_layer_digests = crate::image::compute_per_layer_digests(
        repo,
        img.config_digest(),
        Some(img.config_verity()),
    )?;

    let mut entries = Vec::new();
    let mut verified_count = 0;
    let mut detected_algorithm = None;

    // Config entries
    for (key, alg, _sig_type, digest) in &config_digests {
        if detected_algorithm.is_none() {
            detected_algorithm = Some(alg.to_string());
        }
        let role = "config".to_string();
        let expected_digest = Some(img.config_verity().to_hex());
        let digest_ok = Some(digest) == expected_digest.as_ref();

        if !digest_ok {
            return Err(anyhow::Error::new(SignatureVerificationFailed {
                reason: format!(
                    "Config verity mismatch for key {key}: expected {}, got {digest}",
                    expected_digest.as_ref().unwrap()
                ),
            }));
        }

        let mut signature_verified = false;
        if let Some(verifier) = verifier {
            let sig_key = format!("{key}.sig");
            if let Some(sig_base64) = config_sigs.get(&sig_key) {
                let sig_bytes = base64::engine::general_purpose::STANDARD
                    .decode(sig_base64)
                    .map_err(|e| {
                        anyhow::Error::new(SignatureVerificationFailed {
                            reason: format!("failed to base64-decode config signature: {e}"),
                        })
                    })?;
                let digest_bytes = hex::decode(digest).map_err(|e| {
                    anyhow::Error::new(SignatureVerificationFailed {
                        reason: format!("invalid digest hex: {e}"),
                    })
                })?;
                verifier
                    .verify_raw(&sig_bytes, alg.kernel_id(), &digest_bytes)
                    .map_err(|e| {
                        anyhow::Error::new(SignatureVerificationFailed {
                            reason: format!("signature verification failed for {key}: {e}"),
                        })
                    })?;
                signature_verified = true;
                verified_count += 1;
            }
        }

        entries.push(VerificationEntry {
            role,
            expected_digest,
            digest_ok,
            signature_verified,
            detail: None,
        });
    }

    // Merged/manifest entries
    let mut merged_sig_verified = false;
    let mut has_merged_digest = false;

    for (key, alg, sig_type, digest) in &manifest_digests {
        if detected_algorithm.is_none() {
            detected_algorithm = Some(alg.to_string());
        }
        if *sig_type == SignatureType::Merged {
            has_merged_digest = true;
            let role = "merged".to_string();
            let expected_digest = Some(local_merged_hex.clone());
            let digest_ok = Some(digest) == expected_digest.as_ref();

            if !digest_ok {
                return Err(anyhow::Error::new(SignatureVerificationFailed {
                    reason: format!(
                        "Merged digest mismatch for key {key}: expected {}, got {digest}",
                        expected_digest.as_ref().unwrap()
                    ),
                }));
            }

            let mut signature_verified = false;
            if let Some(verifier) = verifier {
                let sig_key = format!("{key}.sig");
                if let Some(sig_base64) = manifest_sigs.get(&sig_key) {
                    let sig_bytes = base64::engine::general_purpose::STANDARD
                        .decode(sig_base64)
                        .map_err(|e| {
                            anyhow::Error::new(SignatureVerificationFailed {
                                reason: format!("failed to base64-decode manifest signature: {e}"),
                            })
                        })?;
                    let digest_bytes = hex::decode(digest).map_err(|e| {
                        anyhow::Error::new(SignatureVerificationFailed {
                            reason: format!("invalid digest hex: {e}"),
                        })
                    })?;
                    verifier
                        .verify_raw(&sig_bytes, alg.kernel_id(), &digest_bytes)
                        .map_err(|e| {
                            anyhow::Error::new(SignatureVerificationFailed {
                                reason: format!("signature verification failed for {key}: {e}"),
                            })
                        })?;
                    signature_verified = true;
                    merged_sig_verified = true;
                    verified_count += 1;
                }
            }

            entries.push(VerificationEntry {
                role,
                expected_digest,
                digest_ok,
                signature_verified,
                detail: None,
            });
        }
    }

    // Layer entries
    let has_layer_digests = layer_digests.iter().any(|infos| !infos.is_empty());
    if has_layer_digests {
        for (i, infos) in layer_digests.iter().enumerate() {
            let expected_hex = local_layer_digests
                .get(i)
                .ok_or_else(|| {
                    anyhow::Error::new(SignatureVerificationFailed {
                        reason: "manifest layer count exceeds config diff_ids".into(),
                    })
                })?
                .to_hex();

            for (key, alg, _sig_type, digest, sig_base64_opt) in infos {
                if detected_algorithm.is_none() {
                    detected_algorithm = Some(alg.to_string());
                }
                let role = format!("layer[{i}]");
                let expected_digest = Some(expected_hex.clone());
                let digest_ok = Some(digest) == expected_digest.as_ref();

                if !digest_ok {
                    return Err(anyhow::Error::new(SignatureVerificationFailed {
                        reason: format!(
                            "Layer {i} digest mismatch for key {key}: expected {expected_hex}, got {digest}"
                        ),
                    }));
                }

                let mut signature_verified = false;
                if let (Some(verifier), Some(sig_base64)) = (verifier, sig_base64_opt) {
                    let sig_bytes = base64::engine::general_purpose::STANDARD
                        .decode(sig_base64)
                        .map_err(|e| {
                            anyhow::Error::new(SignatureVerificationFailed {
                                reason: format!("failed to base64-decode layer signature: {e}"),
                            })
                        })?;
                    let digest_bytes = hex::decode(digest).map_err(|e| {
                        anyhow::Error::new(SignatureVerificationFailed {
                            reason: format!("invalid digest hex: {e}"),
                        })
                    })?;
                    verifier
                        .verify_raw(&sig_bytes, alg.kernel_id(), &digest_bytes)
                        .map_err(|e| {
                            anyhow::Error::new(SignatureVerificationFailed {
                                reason: format!("signature verification failed for {key}: {e}"),
                            })
                        })?;
                    signature_verified = true;
                    verified_count += 1;
                }

                entries.push(VerificationEntry {
                    role,
                    expected_digest,
                    digest_ok,
                    signature_verified,
                    detail: None,
                });
            }
        }
    }

    if verifier.is_some() {
        if !has_merged_digest || !merged_sig_verified {
            return Err(anyhow::Error::new(SignatureVerificationFailed {
                reason: "merged filesystem digest is not signed".into(),
            }));
        }

        let total_sigs_found = config_digests
            .iter()
            .filter(|(k, _, _, _)| config_sigs.contains_key(&format!("{k}.sig")))
            .count()
            + manifest_digests
                .iter()
                .filter(|(k, _, _, _)| manifest_sigs.contains_key(&format!("{k}.sig")))
                .count()
            + layer_digests
                .iter()
                .flatten()
                .filter(|(_, _, _, _, sig_opt)| sig_opt.is_some())
                .count();

        if total_sigs_found == 0 {
            return Err(anyhow::Error::new(NoSignatureArtifacts {
                name: name.to_string(),
            }));
        }
    }

    let verified_count = if verifier.is_some() {
        verified_count
    } else {
        entries.len()
    };

    Ok(VerificationReport {
        verified_count,
        cert_supplied: verifier.is_some(),
        mode: "inline",
        algorithm: detected_algorithm,
        entries,
    })
}

fn verify_image_report_artifact<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    img: &crate::oci_image::OciImage<ObjectID>,
    name: &str,
    verifier: Option<&crate::signing::FsVeritySignatureVerifier>,
) -> Result<VerificationReport> {
    let manifest_digest = img.manifest_digest();
    let referrers = crate::oci_image::list_referrers(repo, manifest_digest)?;

    let mut metadata_artifacts = Vec::new();
    for (artifact_digest, verity) in &referrers {
        let artifact_image = crate::oci_image::OciImage::open(repo, artifact_digest, Some(verity))?;
        if artifact_image.manifest().artifact_type()
            == &Some(MediaType::Other(METADATA_ARTIFACT_TYPE.to_string()))
        {
            metadata_artifacts.push(artifact_image);
        }
    }

    if metadata_artifacts.is_empty() {
        return Err(anyhow::Error::new(NoSignatureArtifacts {
            name: name.to_string(),
        }));
    }

    let config_digest = img.config_digest();
    let algorithm = ObjectID::ALGORITHM;

    let per_layer_digests = crate::image::compute_per_layer_digests(repo, config_digest, None)?;
    let merged_digest: ObjectID = crate::image::compute_merged_digest(repo, config_digest, None)?;
    let merged_hex = merged_digest.to_hex();

    let mut entries = Vec::new();
    let mut verified_count = 0usize;
    let mut detected_algorithm = None;

    for artifact in &metadata_artifacts {
        let parsed = parse_signature_artifact(artifact.manifest())?;
        detected_algorithm = Some(parsed.algorithm.to_string());

        let layer_descriptors = artifact.layer_descriptors();
        let mut layer_idx = 0usize;
        let sig_layer_offset = 0;

        for (entry_idx, entry) in parsed.signature_entries.iter().enumerate() {
            let (role, expected_digest) = match entry.sig_type {
                SignatureType::Layer => {
                    let r = format!("layer[{layer_idx}]");
                    let expected = per_layer_digests.get(layer_idx).map(|d| d.to_hex());
                    layer_idx += 1;
                    (r, expected)
                }
                SignatureType::Merged => ("merged".to_string(), Some(merged_hex.clone())),
                SignatureType::Config => ("config".to_string(), None),
                SignatureType::Manifest => ("manifest".to_string(), None),
                SignatureType::MergedBootable => ("merged.bootable".to_string(), None),
            };

            let digest_ok = match &expected_digest {
                Some(expected) => *expected == entry.digest,
                None => false,
            };

            if expected_digest.is_some() && !digest_ok {
                let expected = expected_digest.as_deref().unwrap_or("");
                return Err(anyhow::Error::new(SignatureVerificationFailed {
                    reason: format!(
                        "digest mismatch for entry {role}: expected {expected}, got {}",
                        entry.digest
                    ),
                }));
            }

            let mut signature_verified = false;

            if let Some(verifier) = verifier {
                let layer_desc = layer_descriptors
                    .get(sig_layer_offset + entry_idx)
                    .ok_or_else(|| {
                        anyhow::Error::new(SignatureVerificationFailed {
                            reason: "layer descriptor out of bounds".to_string(),
                        })
                    })?;
                let blob_digest = layer_desc.digest();

                if layer_desc.size() == 0u64 {
                    return Err(anyhow::Error::new(SignatureVerificationFailed {
                        reason: format!("signature blob size is 0 for {role}"),
                    }));
                }

                let blob_verity = artifact.layer_verity(blob_digest.as_ref()).ok_or_else(|| {
                    anyhow::Error::new(SignatureVerificationFailed {
                        reason: format!("verity not found for {blob_digest}"),
                    })
                })?;
                let signature_blob =
                    crate::oci_image::open_blob(repo, blob_digest, Some(blob_verity))?;

                let digest_bytes = hex::decode(&entry.digest).map_err(|e| {
                    anyhow::Error::new(SignatureVerificationFailed {
                        reason: format!("invalid hex digest {}: {e}", entry.digest),
                    })
                })?;

                verifier
                    .verify_raw(&signature_blob, algorithm.kernel_id(), &digest_bytes)
                    .map_err(|e| {
                        anyhow::Error::new(SignatureVerificationFailed {
                            reason: format!("signature verification failed for {role}: {e:#}"),
                        })
                    })?;
                signature_verified = true;
                verified_count += 1;
            }

            entries.push(VerificationEntry {
                role,
                expected_digest,
                digest_ok,
                signature_verified,
                detail: None,
            });
        }
    }

    if verifier.is_some() && verified_count == 0 {
        return Err(anyhow::Error::new(SignatureVerificationFailed {
            reason: "no signature artifacts verified with the given certificate".to_string(),
        }));
    }

    let verified_count = if verifier.is_some() {
        verified_count
    } else {
        metadata_artifacts.len()
    };

    Ok(VerificationReport {
        verified_count,
        cert_supplied: verifier.is_some(),
        mode: "artifact",
        algorithm: detected_algorithm,
        entries,
    })
}
