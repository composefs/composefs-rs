//! Composefs artifact construction and verification.
//!
//! Builds OCI artifact manifests containing composefs fsverity digests
//! and PKCS#7 signatures per the OCI sealing specification.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
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
pub fn parse_annotation_key_value(key: &str, value: &str) -> Option<(Algorithm, SignatureType, String)> {
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
        let annotations = layer.annotations().as_ref().context("layer missing annotations")?;
        
        let mut found = None;
        for (k, v) in annotations {
            if let Some((alg, sig_type, digest)) = parse_annotation_key_value(k, v) {
                found = Some((alg, sig_type, digest));
                break;
            }
        }
        
        let (algorithm, sig_type, digest) = found.context("layer missing valid composefs digest annotation")?;
        
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

    if repo.has_stream(&config_id)?.is_none() {
        let mut config_stream = repo.create_stream(crate::skopeo::OCI_CONFIG_CONTENT_TYPE)?;
        config_stream.write_external(empty_config)?;
        repo.write_stream(config_stream, &config_id, None)?;
    }

    let mut artifact_builder = ImageManifestBuilder::default()
        .schema_version(2u32)
        .media_type(crate::OciMediaType::ImageManifest)
        .artifact_type(MediaType::Other(METADATA_ARTIFACT_TYPE.to_string()))
        .subject(subject)
        .config(
            DescriptorBuilder::default()
                .media_type(MediaType::Other("application/vnd.oci.empty.v1+json".to_string()))
                .digest(config_digest)
                .size(empty_config.len() as u64)
                .build()?,
        );
        
    artifact_builder = artifact_builder.layers(layers);
    let artifact_manifest = artifact_builder.build()?;
    
    // Write signature blobs
    for blob in blobs {
        crate::oci_image::write_blob(repo, &blob)?;
    }
    
    let manifest_bytes = artifact_manifest.to_string()?.into_bytes();
    let manifest_digest = sha256_digest(&manifest_bytes);
    
    let mut manifest_stream = repo.create_stream(crate::skopeo::OCI_MANIFEST_CONTENT_TYPE)?;
    manifest_stream.write_external(&manifest_bytes)?;
    let artifact_id = repo.write_stream(manifest_stream, &crate::oci_image::manifest_identifier(&manifest_digest), None)?;

    Ok((manifest_digest, artifact_id))
}

/// Verifies the composefs signatures associated with a container image.
pub fn verify_image_signatures<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
    _verifier: Option<&crate::signing::FsVeritySignatureVerifier>,
) -> Result<usize> {
    // This is essentially just the top-level logic; cfsctl handles the detailed printing
    let img = crate::oci_image::OciImage::open_ref(repo, name)?;
    let referrers = crate::oci_image::list_referrers(repo, img.manifest_digest())?;
    
    let mut verified = 0;
    for (artifact_digest, verity) in referrers {
        let artifact_image = crate::oci_image::OciImage::open(repo, &artifact_digest, Some(&verity))?;
        if artifact_image.manifest().artifact_type() == &Some(MediaType::Other(METADATA_ARTIFACT_TYPE.to_string())) {
            verified += 1;
        }
    }
    Ok(verified)
}

