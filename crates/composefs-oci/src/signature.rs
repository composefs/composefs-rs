//! Composefs artifact construction and verification.
//!
//! Builds OCI artifact manifests containing composefs EROFS metadata layers
//! and/or fsverity digests (with optional PKCS#7 signatures) per the OCI
//! sealing specification. The primary mode is "erofs-alongside" where the
//! artifact carries EROFS metadata layers alongside optional signatures.
//! Composefs artifacts reference the source image via the OCI referrer
//! pattern (`subject` field) and are discoverable via the `/referrers` API.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use composefs::fsverity::FsVerityHashValue;
use composefs::fsverity::algorithm::ComposeFsAlgorithm;
use composefs::repository::Repository;
use containers_image_proxy::oci_spec::image::{
    Descriptor, DescriptorBuilder, Digest as OciDigest, ImageManifest, ImageManifestBuilder,
    MediaType,
};

/// Artifact type for composefs erofs-alongside manifests.
pub const EROFS_ALONGSIDE_ARTIFACT_TYPE: &str = "application/vnd.composefs.erofs-alongside.v1";

/// Backward-compatible alias for the old artifact type constant.
pub const ARTIFACT_TYPE: &str = EROFS_ALONGSIDE_ARTIFACT_TYPE;

/// Media type for PKCS#7 DER signature layers.
pub const SIGNATURE_MEDIA_TYPE: &str = "application/vnd.composefs.signature.v1+pkcs7";

/// Media type for EROFS metadata layers.
pub const EROFS_MEDIA_TYPE: &str = "application/vnd.composefs.v1.erofs";

/// Annotation key for the composefs signature type on each signature layer.
pub const ANN_SIGNATURE_TYPE: &str = "composefs.signature.type";

/// Annotation key for the composefs EROFS type on each EROFS layer.
pub const ANN_EROFS_TYPE: &str = "composefs.erofs.type";

/// Annotation key for the composefs fsverity digest on each layer.
pub const ANN_DIGEST: &str = "composefs.digest";

/// Annotation key for the composefs algorithm on the artifact manifest.
pub const ANN_ALGORITHM: &str = "composefs.algorithm";

/// The type of object a signature layer refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureType {
    /// Signature for the OCI manifest JSON.
    Manifest,
    /// Signature for the OCI config JSON.
    Config,
    /// Signature for an individual composefs layer EROFS.
    Layer,
    /// Signature for a merged (rolling) composefs filesystem.
    Merged,
}

impl SignatureType {
    /// The annotation value string for this type.
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureType::Manifest => "manifest",
            SignatureType::Config => "config",
            SignatureType::Layer => "layer",
            SignatureType::Merged => "merged",
        }
    }

    /// Parse from an annotation value string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "manifest" => Some(SignatureType::Manifest),
            "config" => Some(SignatureType::Config),
            "layer" => Some(SignatureType::Layer),
            "merged" => Some(SignatureType::Merged),
            _ => None,
        }
    }

    /// Ordering rank for enforcing canonical entry order.
    fn rank(self) -> u8 {
        match self {
            SignatureType::Manifest => 0,
            SignatureType::Config => 1,
            SignatureType::Layer => 2,
            SignatureType::Merged => 3,
        }
    }
}

impl std::fmt::Display for SignatureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SignatureType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| anyhow::anyhow!("unknown signature type: {s}"))
    }
}

/// The type of object an EROFS metadata layer refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErofsEntryType {
    /// EROFS metadata for an individual composefs layer.
    Layer,
    /// EROFS metadata for a merged (rolling) composefs filesystem.
    Merged,
}

impl ErofsEntryType {
    /// The annotation value string for this type.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErofsEntryType::Layer => "layer",
            ErofsEntryType::Merged => "merged",
        }
    }

    /// Parse from an annotation value string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "layer" => Some(ErofsEntryType::Layer),
            "merged" => Some(ErofsEntryType::Merged),
            _ => None,
        }
    }

    /// Ordering rank for enforcing canonical entry order.
    fn rank(self) -> u8 {
        match self {
            ErofsEntryType::Layer => 0,
            ErofsEntryType::Merged => 1,
        }
    }
}

impl std::fmt::Display for ErofsEntryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ErofsEntryType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| anyhow::anyhow!("unknown erofs type: {s}"))
    }
}

/// A single EROFS metadata entry in a composefs artifact.
///
/// Contains the composefs fsverity digest and the raw EROFS image bytes.
#[derive(Debug)]
pub struct ErofsEntry {
    /// What this entry represents (layer or merged).
    pub erofs_type: ErofsEntryType,
    /// The composefs fsverity digest as a hex string.
    pub digest: String,
    /// Raw EROFS image bytes, if available.
    pub data: Option<Vec<u8>>,
}

/// A single signature entry in a composefs artifact.
///
/// Contains the composefs fsverity digest and optionally a PKCS#7 signature blob.
/// When no signature is present, the entry is "digest-only" — the digest can be
/// verified against the EROFS blob but without kernel signature enforcement.
#[derive(Debug)]
pub struct SignatureEntry {
    /// What this entry signs (manifest, config, layer, or merged).
    pub sig_type: SignatureType,
    /// The composefs fsverity digest as a hex string.
    pub digest: String,
    /// Raw PKCS#7 DER signature blob, if available.
    pub signature: Option<Vec<u8>>,
}

/// The result of parsing a composefs artifact manifest.
#[derive(Debug)]
pub struct ParsedComposeFsArtifact {
    /// The composefs algorithm used for fsverity digests.
    pub algorithm: ComposeFsAlgorithm,
    /// The subject descriptor (the image this artifact refers to).
    pub subject: Descriptor,
    /// EROFS metadata entries in artifact layer order.
    pub erofs_entries: Vec<ErofsEntry>,
    /// Signature entries in artifact layer order.
    pub signature_entries: Vec<SignatureEntry>,
}

/// Backward-compatible alias.
pub type ParsedSignatureArtifact = ParsedComposeFsArtifact;

/// Builder for composefs artifacts.
///
/// Collects EROFS metadata and signature entries and produces an OCI image
/// manifest following the OCI artifacts guidance pattern. EROFS entries must
/// be added before signature entries.
#[derive(Debug)]
pub struct ComposeFsArtifactBuilder {
    /// Algorithm identifier (e.g. SHA512_12).
    algorithm: ComposeFsAlgorithm,
    /// The subject descriptor (the source image manifest).
    subject: Descriptor,
    /// EROFS metadata entries.
    erofs_entries: Vec<ErofsEntry>,
    /// Signature entries in order: manifest, config, layers, merged.
    signature_entries: Vec<SignatureEntry>,
    /// Rank of the last EROFS entry added, for ordering enforcement.
    last_erofs_rank: Option<u8>,
    /// Rank of the last signature entry added, for ordering enforcement.
    last_sig_rank: Option<u8>,
    /// Whether we've started adding signature entries (no more EROFS after).
    signatures_started: bool,
}

/// Backward-compatible alias.
pub type SignatureArtifactBuilder = ComposeFsArtifactBuilder;

/// The result of building a composefs artifact.
#[derive(Debug)]
pub struct ComposeFsArtifact {
    /// The OCI image manifest for the artifact.
    pub manifest: ImageManifest,
    /// The raw layer blobs (EROFS images, PKCS#7 signatures, or empty placeholders).
    /// One per entry, in the same order as the manifest layers.
    pub blobs: Vec<Vec<u8>>,
}

/// Backward-compatible alias.
pub type SignatureArtifact = ComposeFsArtifact;

/// The sha256 digest of `{}` (empty JSON object), per OCI artifacts guidance.
const EMPTY_CONFIG_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

impl ComposeFsArtifactBuilder {
    /// Create a new builder for a composefs artifact.
    ///
    /// `algorithm` is the composefs algorithm identifier (e.g. `ComposeFsAlgorithm::SHA512_12`).
    /// `subject` is the descriptor of the source image manifest.
    pub fn new(algorithm: ComposeFsAlgorithm, subject: Descriptor) -> Self {
        ComposeFsArtifactBuilder {
            algorithm,
            subject,
            erofs_entries: Vec::new(),
            signature_entries: Vec::new(),
            last_erofs_rank: None,
            last_sig_rank: None,
            signatures_started: false,
        }
    }

    /// Add an EROFS metadata entry.
    ///
    /// EROFS entries MUST be added before any signature entries, and in order:
    /// layer entries (in manifest order), then optionally one merged entry.
    pub fn add_erofs_entry(&mut self, entry: ErofsEntry) -> Result<()> {
        if self.signatures_started {
            bail!("cannot add EROFS entry after signature entries have been added");
        }
        let rank = entry.erofs_type.rank();
        if let Some(last) = self.last_erofs_rank
            && rank < last
        {
            bail!(
                "out-of-order EROFS entry: {} after {}",
                entry.erofs_type,
                erofs_rank_to_name(last)
            );
        }
        self.last_erofs_rank = Some(rank);
        self.erofs_entries.push(entry);
        Ok(())
    }

    /// Add EROFS metadata entries for per-layer composefs images.
    ///
    /// Convenience method that adds one `Layer` EROFS entry per (data, digest) pair.
    pub fn add_erofs_layers(&mut self, data_and_digests: &[(Vec<u8>, String)]) -> Result<()> {
        for (data, digest) in data_and_digests {
            self.add_erofs_entry(ErofsEntry {
                erofs_type: ErofsEntryType::Layer,
                digest: digest.clone(),
                data: Some(data.clone()),
            })?;
        }
        Ok(())
    }

    /// Add a signature entry.
    ///
    /// Signature entries MUST be added after all EROFS entries, and in the
    /// spec-defined order: manifest, config, layers (in manifest order), merged.
    /// Returns an error if the entry would violate this ordering, or if a
    /// `Manifest` or `Config` entry is duplicated.
    pub fn add_entry(&mut self, entry: SignatureEntry) -> Result<()> {
        self.add_signature_entry(entry)
    }

    /// Add a signature entry (preferred name).
    ///
    /// Signature entries MUST be added after all EROFS entries, and in the
    /// spec-defined order: manifest, config, layers (in manifest order), merged.
    pub fn add_signature_entry(&mut self, entry: SignatureEntry) -> Result<()> {
        self.signatures_started = true;
        let rank = entry.sig_type.rank();

        if let Some(last) = self.last_sig_rank {
            if rank < last {
                bail!(
                    "out-of-order entry: {} after {}",
                    entry.sig_type,
                    rank_to_name(last)
                );
            }
            // Reject duplicate Manifest or Config (at most one each)
            if rank == last && rank <= 1 {
                bail!("duplicate {} entry", entry.sig_type);
            }
        }

        self.last_sig_rank = Some(rank);
        self.signature_entries.push(entry);
        Ok(())
    }

    /// Add digest-only signature entries for per-layer composefs digests.
    ///
    /// Convenience method that adds one `Layer` signature entry per digest.
    pub fn add_layer_digests<ObjectID: FsVerityHashValue>(
        &mut self,
        digests: &[ObjectID],
    ) -> Result<()> {
        for digest in digests {
            self.add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: digest.to_hex(),
                signature: None,
            })?;
        }
        Ok(())
    }

    /// Add a digest-only signature entry for a merged composefs digest.
    pub fn add_merged_digest<ObjectID: FsVerityHashValue>(
        &mut self,
        digest: &ObjectID,
    ) -> Result<()> {
        self.add_signature_entry(SignatureEntry {
            sig_type: SignatureType::Merged,
            digest: digest.to_hex(),
            signature: None,
        })
    }

    /// Build the composefs artifact.
    ///
    /// Produces an OCI image manifest and the associated layer blobs.
    /// Layer order: EROFS entries first, then signature entries.
    pub fn build(self) -> Result<ComposeFsArtifact> {
        let total = self.erofs_entries.len() + self.signature_entries.len();
        let mut layers = Vec::with_capacity(total);
        let mut blobs = Vec::with_capacity(total);

        // EROFS metadata layers first
        for entry in &self.erofs_entries {
            let blob = entry.data.clone().unwrap_or_default();
            let blob_digest = sha256_digest(&blob);

            let mut annotations = HashMap::new();
            annotations.insert(
                ANN_EROFS_TYPE.to_string(),
                entry.erofs_type.as_str().to_string(),
            );
            annotations.insert(ANN_DIGEST.to_string(), entry.digest.clone());

            let descriptor = DescriptorBuilder::default()
                .media_type(MediaType::Other(EROFS_MEDIA_TYPE.to_string()))
                .digest(blob_digest)
                .size(blob.len() as u64)
                .annotations(annotations)
                .build()
                .context("building EROFS layer descriptor")?;

            layers.push(descriptor);
            blobs.push(blob);
        }

        // Signature layers second
        for entry in &self.signature_entries {
            let blob = entry.signature.clone().unwrap_or_default();
            let blob_digest = sha256_digest(&blob);

            let mut annotations = HashMap::new();
            annotations.insert(
                ANN_SIGNATURE_TYPE.to_string(),
                entry.sig_type.as_str().to_string(),
            );
            annotations.insert(ANN_DIGEST.to_string(), entry.digest.clone());

            let descriptor = DescriptorBuilder::default()
                .media_type(MediaType::Other(SIGNATURE_MEDIA_TYPE.to_string()))
                .digest(blob_digest)
                .size(blob.len() as u64)
                .annotations(annotations)
                .build()
                .context("building signature layer descriptor")?;

            layers.push(descriptor);
            blobs.push(blob);
        }

        // Empty config per OCI artifacts guidance
        let config = DescriptorBuilder::default()
            .media_type(MediaType::Other(
                "application/vnd.oci.empty.v1+json".to_string(),
            ))
            .digest(
                EMPTY_CONFIG_DIGEST
                    .parse::<OciDigest>()
                    .context("parsing empty config digest")?,
            )
            .size(2u64)
            .build()
            .context("building config descriptor")?;

        let mut annotations = HashMap::new();
        annotations.insert(ANN_ALGORITHM.to_string(), self.algorithm.to_string());

        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .artifact_type(MediaType::Other(EROFS_ALONGSIDE_ARTIFACT_TYPE.to_string()))
            .config(config)
            .layers(layers)
            .subject(self.subject)
            .annotations(annotations)
            .build()
            .context("building composefs artifact manifest")?;

        Ok(ComposeFsArtifact { manifest, blobs })
    }
}

/// Parse a composefs artifact manifest and extract EROFS and signature entries.
///
/// Validates artifact type, layer media types, digest format/length, entry
/// ordering (all EROFS before all signatures), and the presence of a subject
/// descriptor.
pub fn parse_composefs_artifact(manifest: &ImageManifest) -> Result<ParsedComposeFsArtifact> {
    // Validate artifact type
    match manifest.artifact_type() {
        Some(MediaType::Other(s)) if s == EROFS_ALONGSIDE_ARTIFACT_TYPE => {}
        other => bail!(
            "wrong artifact type: expected {EROFS_ALONGSIDE_ARTIFACT_TYPE}, got {}",
            match other {
                Some(t) => format!("{t:?}"),
                None => "none".to_string(),
            }
        ),
    }

    // A referrer artifact MUST have a subject
    let subject = manifest
        .subject()
        .as_ref()
        .context("composefs artifact missing subject descriptor")?
        .clone();

    let annotations = manifest
        .annotations()
        .as_ref()
        .context("composefs artifact missing annotations")?;

    let algorithm: ComposeFsAlgorithm = annotations
        .get(ANN_ALGORITHM)
        .context("composefs artifact missing composefs.algorithm annotation")?
        .parse()
        .context("parsing composefs.algorithm annotation")?;

    let expected_digest_bytes = algorithm.digest_size();

    let mut erofs_entries = Vec::new();
    let mut signature_entries = Vec::new();
    let mut seen_signature = false;

    for layer in manifest.layers() {
        let media_type = layer.media_type();

        let layer_annotations = layer
            .annotations()
            .as_ref()
            .context("layer missing annotations")?;

        let digest = layer_annotations
            .get(ANN_DIGEST)
            .context("layer missing composefs.digest")?
            .clone();

        // Validate digest: must be valid hex with correct length for the algorithm
        let decoded = hex::decode(&digest)
            .context(format!("invalid composefs.digest: not valid hex: {digest}"))?;
        if decoded.len() != expected_digest_bytes {
            bail!(
                "invalid composefs.digest: expected {} bytes for {}, got {}",
                expected_digest_bytes,
                algorithm,
                decoded.len()
            );
        }

        if *media_type == MediaType::Other(EROFS_MEDIA_TYPE.to_string()) {
            // EROFS metadata layer
            if seen_signature {
                bail!(
                    "EROFS layer found after signature layer — all EROFS entries must come first"
                );
            }

            let erofs_type_str = layer_annotations
                .get(ANN_EROFS_TYPE)
                .context("EROFS layer missing composefs.erofs.type")?;

            let erofs_type = ErofsEntryType::parse(erofs_type_str)
                .context(format!("unknown erofs type: {erofs_type_str}"))?;

            erofs_entries.push(ErofsEntry {
                erofs_type,
                digest,
                // EROFS blob must be fetched separately by the caller
                data: None,
            });
        } else if *media_type == MediaType::Other(SIGNATURE_MEDIA_TYPE.to_string()) {
            // Signature layer
            seen_signature = true;

            let sig_type_str = layer_annotations
                .get(ANN_SIGNATURE_TYPE)
                .context("signature layer missing composefs.signature.type")?;

            let sig_type = SignatureType::parse(sig_type_str)
                .context(format!("unknown signature type: {sig_type_str}"))?;

            signature_entries.push(SignatureEntry {
                sig_type,
                digest,
                // Signature blob must be fetched separately by the caller
                signature: None,
            });
        } else {
            bail!(
                "wrong layer media type: expected {EROFS_MEDIA_TYPE} or {SIGNATURE_MEDIA_TYPE}, got {:?}",
                media_type
            );
        }
    }

    // Validate ordering within each section
    validate_erofs_ordering(&erofs_entries)?;
    validate_signature_ordering(&signature_entries)?;

    Ok(ParsedComposeFsArtifact {
        algorithm,
        subject,
        erofs_entries,
        signature_entries,
    })
}

/// Backward-compatible alias for `parse_composefs_artifact`.
pub fn parse_signature_artifact(manifest: &ImageManifest) -> Result<ParsedComposeFsArtifact> {
    parse_composefs_artifact(manifest)
}

/// Validate that EROFS entries follow the required ordering.
///
/// Required order: Layer (0..), Merged (0..=1).
fn validate_erofs_ordering(entries: &[ErofsEntry]) -> Result<()> {
    let mut prev_rank: Option<u8> = None;
    let mut merged_count = 0u32;

    for entry in entries {
        let rank = entry.erofs_type.rank();
        if let Some(prev) = prev_rank
            && rank < prev
        {
            bail!(
                "out-of-order EROFS entry: {} after {}",
                entry.erofs_type,
                erofs_rank_to_name(prev)
            );
        }
        if entry.erofs_type == ErofsEntryType::Merged {
            merged_count += 1;
            if merged_count > 1 {
                bail!("duplicate merged EROFS entry");
            }
        }
        prev_rank = Some(rank);
    }
    Ok(())
}

/// Validate that signature entries follow the required ordering and uniqueness.
///
/// Required order: Manifest (0..=1), Config (0..=1), Layer (0..), Merged (0..).
fn validate_signature_ordering(entries: &[SignatureEntry]) -> Result<()> {
    let mut prev_rank: Option<u8> = None;
    let mut manifest_count = 0u32;
    let mut config_count = 0u32;

    for entry in entries {
        let rank = entry.sig_type.rank();
        if let Some(prev) = prev_rank
            && rank < prev
        {
            bail!(
                "out-of-order entry: {} after {}",
                entry.sig_type,
                rank_to_name(prev)
            );
        }

        match entry.sig_type {
            SignatureType::Manifest => {
                manifest_count += 1;
                if manifest_count > 1 {
                    bail!("duplicate manifest entry");
                }
            }
            SignatureType::Config => {
                config_count += 1;
                if config_count > 1 {
                    bail!("duplicate config entry");
                }
            }
            _ => {}
        }

        prev_rank = Some(rank);
    }
    Ok(())
}

/// Map a signature rank value back to a type name for error messages.
fn rank_to_name(rank: u8) -> &'static str {
    match rank {
        0 => "manifest",
        1 => "config",
        2 => "layer",
        3 => "merged",
        _ => "unknown",
    }
}

/// Map an EROFS rank value back to a type name for error messages.
fn erofs_rank_to_name(rank: u8) -> &'static str {
    match rank {
        0 => "layer",
        1 => "merged",
        _ => "unknown",
    }
}

// =============================================================================
// Repository Storage and Discovery
// =============================================================================

/// Stores a composefs artifact in the repository and indexes it as a referrer.
///
/// Writes the artifact's layer blobs and manifest, then creates a referrer
/// index entry linking it to its subject image. The subject is extracted from
/// the manifest's `subject` field.
///
/// Returns `(manifest_digest, manifest_verity)` for the stored artifact.
pub fn store_composefs_artifact<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    artifact: ComposeFsArtifact,
) -> Result<(OciDigest, ObjectID)> {
    // Write the empty config "{}"
    let empty_config = b"{}";
    let config_digest = sha256_digest(empty_config);
    let config_id = crate::config_identifier(&config_digest);

    let config_verity = match repo.has_stream(&config_id)? {
        Some(v) => v,
        None => {
            let mut config_stream = repo.create_stream(crate::skopeo::OCI_CONFIG_CONTENT_TYPE)?;
            config_stream.write_external(empty_config)?;
            repo.write_stream(config_stream, &config_id, None)?
        }
    };

    // Write each layer blob and collect verity mappings
    let mut layer_verities = HashMap::new();
    for (descriptor, blob) in artifact.manifest.layers().iter().zip(&artifact.blobs) {
        let (blob_digest, blob_verity) = crate::oci_image::write_blob(repo, blob)?;
        // For artifacts, the layer descriptor's digest is the key
        let desc_digest = descriptor.digest();

        // Sanity check: the blob digest we computed should match the descriptor
        if &blob_digest != desc_digest {
            anyhow::bail!(
                "Layer blob digest mismatch: descriptor says {desc_digest}, \
                 computed {blob_digest}"
            );
        }

        layer_verities.insert(desc_digest.as_ref().into(), blob_verity);
    }

    // Compute the manifest digest
    let manifest_json = artifact.manifest.to_string()?;
    let manifest_digest = sha256_digest(manifest_json.as_bytes());

    // Write the manifest (no tag — referrer artifacts aren't typically tagged)
    let (digest, verity) = crate::oci_image::write_manifest(
        repo,
        &artifact.manifest,
        &manifest_digest,
        &config_verity,
        &layer_verities,
        None,
    )?;

    // Extract the subject digest and create the referrer index entry
    let subject = artifact
        .manifest
        .subject()
        .as_ref()
        .context("composefs artifact has no subject")?;
    let subject_digest = subject.digest();

    crate::oci_image::add_referrer(repo, subject_digest, &digest)?;

    Ok((digest, verity))
}

/// Backward-compatible alias for `store_composefs_artifact`.
pub fn store_signature_artifact<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    artifact: ComposeFsArtifact,
) -> Result<(OciDigest, ObjectID)> {
    store_composefs_artifact(repo, artifact)
}

/// Finds and parses composefs artifacts referencing the given image.
///
/// Searches the local referrer index for artifacts with the composefs
/// artifact type, then parses each one. Non-composefs referrers are silently
/// skipped.
pub fn find_composefs_artifacts<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    subject_digest: &OciDigest,
) -> Result<Vec<ParsedComposeFsArtifact>> {
    use crate::oci_image::{OciImage, list_referrers};

    let referrers = list_referrers(repo, subject_digest)?;
    let mut results = Vec::new();

    for (artifact_digest, artifact_verity) in &referrers {
        // Open the artifact manifest — failure here means the referrer index
        // points to a corrupt or missing manifest, which is an error.
        let image = OciImage::open(repo, artifact_digest, Some(artifact_verity))
            .with_context(|| format!("opening referrer artifact {artifact_digest}"))?;

        // Check if this is a composefs artifact.
        // Non-composefs artifact types are expected (other tools may store
        // their own referrer artifacts) and are silently skipped.
        let manifest = image.manifest();
        match manifest.artifact_type() {
            Some(MediaType::Other(t)) if t == EROFS_ALONGSIDE_ARTIFACT_TYPE => {}
            _ => continue,
        }

        // Parse the composefs artifact — failure here means the artifact
        // claims to be a composefs artifact but is malformed.
        let parsed = parse_composefs_artifact(manifest)
            .with_context(|| format!("parsing composefs artifact {artifact_digest}"))?;
        results.push(parsed);
    }

    Ok(results)
}

/// Backward-compatible alias for `find_composefs_artifacts`.
pub fn find_signature_artifacts<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    subject_digest: &OciDigest,
) -> Result<Vec<ParsedComposeFsArtifact>> {
    find_composefs_artifacts(repo, subject_digest)
}

fn sha256_digest(data: &[u8]) -> OciDigest {
    crate::sha256_content_digest(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a realistic-length fake SHA-512 hex digest (128 hex chars = 64 bytes).
    fn fake_sha512_digest(seed: u8) -> String {
        format!("{seed:02x}").repeat(64)
    }

    /// Generate a realistic-length fake SHA-256 hex digest (64 hex chars = 32 bytes).
    fn fake_sha256_digest(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    fn sample_subject() -> Descriptor {
        DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(
                "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270"
                    .parse::<OciDigest>()
                    .unwrap(),
            )
            .size(7682u64)
            .build()
            .unwrap()
    }

    #[test]
    fn build_signature_only_artifact() {
        let subject = sample_subject();
        let mut builder =
            ComposeFsArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        let layer_digest = fake_sha512_digest(0xab);
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: layer_digest.clone(),
                signature: None,
            })
            .unwrap();

        let artifact = builder.build().unwrap();

        assert_eq!(artifact.manifest.schema_version(), 2);
        assert_eq!(
            artifact.manifest.artifact_type().as_ref().unwrap(),
            &MediaType::Other(EROFS_ALONGSIDE_ARTIFACT_TYPE.to_string())
        );
        assert_eq!(artifact.manifest.layers().len(), 1);
        assert_eq!(artifact.blobs.len(), 1);

        let subject = artifact.manifest.subject().as_ref().unwrap();
        assert_eq!(subject.media_type(), &MediaType::ImageManifest);

        let layer = &artifact.manifest.layers()[0];
        let ann = layer.annotations().as_ref().unwrap();
        assert_eq!(ann.get(ANN_SIGNATURE_TYPE).unwrap(), "layer");
        assert_eq!(ann.get(ANN_DIGEST).unwrap(), &layer_digest);

        let manifest_ann = artifact.manifest.annotations().as_ref().unwrap();
        assert_eq!(
            manifest_ann.get(ANN_ALGORITHM).unwrap(),
            "fsverity-sha512-12"
        );
    }

    #[test]
    fn build_erofs_only_artifact() {
        let subject = sample_subject();
        let mut builder =
            ComposeFsArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        let layer_digest = fake_sha512_digest(0xab);
        let erofs_data = vec![0xE0, 0xF5, 0x01, 0x02];
        builder
            .add_erofs_entry(ErofsEntry {
                erofs_type: ErofsEntryType::Layer,
                digest: layer_digest.clone(),
                data: Some(erofs_data.clone()),
            })
            .unwrap();

        let artifact = builder.build().unwrap();

        assert_eq!(artifact.manifest.schema_version(), 2);
        assert_eq!(artifact.manifest.layers().len(), 1);
        assert_eq!(artifact.blobs.len(), 1);
        assert_eq!(artifact.blobs[0], erofs_data);

        let layer = &artifact.manifest.layers()[0];
        assert_eq!(
            layer.media_type(),
            &MediaType::Other(EROFS_MEDIA_TYPE.to_string())
        );
        let ann = layer.annotations().as_ref().unwrap();
        assert_eq!(ann.get(ANN_EROFS_TYPE).unwrap(), "layer");
        assert_eq!(ann.get(ANN_DIGEST).unwrap(), &layer_digest);

        // Parse round-trip
        let parsed = parse_composefs_artifact(&artifact.manifest).unwrap();
        assert_eq!(parsed.erofs_entries.len(), 1);
        assert!(parsed.signature_entries.is_empty());
        assert_eq!(parsed.erofs_entries[0].erofs_type, ErofsEntryType::Layer);
        assert_eq!(parsed.erofs_entries[0].digest, layer_digest);
    }

    #[test]
    fn build_and_parse_roundtrip_signatures_only() {
        let subject = sample_subject();
        let mut builder =
            ComposeFsArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        let d_manifest = fake_sha512_digest(0xaa);
        let d_config = fake_sha512_digest(0xbb);
        let d_layer0 = fake_sha512_digest(0xcc);
        let d_layer1 = fake_sha512_digest(0xdd);
        let d_merged = fake_sha512_digest(0xee);

        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Manifest,
                digest: d_manifest.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Config,
                digest: d_config.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: d_layer0.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: d_layer1.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Merged,
                digest: d_merged.clone(),
                signature: None,
            })
            .unwrap();

        let artifact = builder.build().unwrap();
        let parsed = parse_composefs_artifact(&artifact.manifest).unwrap();

        assert_eq!(parsed.algorithm, composefs::fsverity::algorithm::SHA512_12);
        assert!(parsed.erofs_entries.is_empty());
        assert_eq!(parsed.signature_entries.len(), 5);
        assert_eq!(
            parsed.signature_entries[0].sig_type,
            SignatureType::Manifest
        );
        assert_eq!(parsed.signature_entries[0].digest, d_manifest);
        assert_eq!(parsed.signature_entries[1].sig_type, SignatureType::Config);
        assert_eq!(parsed.signature_entries[1].digest, d_config);
        assert_eq!(parsed.signature_entries[2].sig_type, SignatureType::Layer);
        assert_eq!(parsed.signature_entries[2].digest, d_layer0);
        assert_eq!(parsed.signature_entries[3].sig_type, SignatureType::Layer);
        assert_eq!(parsed.signature_entries[3].digest, d_layer1);
        assert_eq!(parsed.signature_entries[4].sig_type, SignatureType::Merged);
        assert_eq!(parsed.signature_entries[4].digest, d_merged);

        // Subject should be preserved
        assert_eq!(parsed.subject.media_type(), &MediaType::ImageManifest);
    }

    #[test]
    fn build_and_parse_roundtrip_erofs_plus_signatures() {
        let subject = sample_subject();
        let mut builder =
            ComposeFsArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        let erofs_layer = fake_sha512_digest(0xa1);
        let erofs_merged = fake_sha512_digest(0xa2);
        let sig_layer = fake_sha512_digest(0xb1);
        let sig_merged = fake_sha512_digest(0xb2);

        builder
            .add_erofs_entry(ErofsEntry {
                erofs_type: ErofsEntryType::Layer,
                digest: erofs_layer.clone(),
                data: Some(vec![1, 2, 3]),
            })
            .unwrap();
        builder
            .add_erofs_entry(ErofsEntry {
                erofs_type: ErofsEntryType::Merged,
                digest: erofs_merged.clone(),
                data: Some(vec![4, 5, 6]),
            })
            .unwrap();
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: sig_layer.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Merged,
                digest: sig_merged.clone(),
                signature: None,
            })
            .unwrap();

        let artifact = builder.build().unwrap();

        // 2 EROFS + 2 signature = 4 layers
        assert_eq!(artifact.manifest.layers().len(), 4);
        assert_eq!(artifact.blobs.len(), 4);

        // First two are EROFS
        assert_eq!(
            artifact.manifest.layers()[0].media_type(),
            &MediaType::Other(EROFS_MEDIA_TYPE.to_string())
        );
        assert_eq!(
            artifact.manifest.layers()[1].media_type(),
            &MediaType::Other(EROFS_MEDIA_TYPE.to_string())
        );
        // Last two are signatures
        assert_eq!(
            artifact.manifest.layers()[2].media_type(),
            &MediaType::Other(SIGNATURE_MEDIA_TYPE.to_string())
        );
        assert_eq!(
            artifact.manifest.layers()[3].media_type(),
            &MediaType::Other(SIGNATURE_MEDIA_TYPE.to_string())
        );

        let parsed = parse_composefs_artifact(&artifact.manifest).unwrap();

        assert_eq!(parsed.erofs_entries.len(), 2);
        assert_eq!(parsed.erofs_entries[0].erofs_type, ErofsEntryType::Layer);
        assert_eq!(parsed.erofs_entries[0].digest, erofs_layer);
        assert_eq!(parsed.erofs_entries[1].erofs_type, ErofsEntryType::Merged);
        assert_eq!(parsed.erofs_entries[1].digest, erofs_merged);

        assert_eq!(parsed.signature_entries.len(), 2);
        assert_eq!(parsed.signature_entries[0].sig_type, SignatureType::Layer);
        assert_eq!(parsed.signature_entries[0].digest, sig_layer);
        assert_eq!(parsed.signature_entries[1].sig_type, SignatureType::Merged);
        assert_eq!(parsed.signature_entries[1].digest, sig_merged);
    }

    #[test]
    fn test_build_with_signature_blobs() {
        let subject = sample_subject();
        let mut builder =
            ComposeFsArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        let d_manifest = fake_sha512_digest(0x11);
        let d_layer = fake_sha512_digest(0x22);
        let d_merged = fake_sha512_digest(0x33);

        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Manifest,
                digest: d_manifest.clone(),
                signature: None,
            })
            .unwrap();

        let fake_sig = vec![0x30, 0x82, 0x01, 0x00, 0xAB, 0xCD, 0xEF];
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: d_layer.clone(),
                signature: Some(fake_sig.clone()),
            })
            .unwrap();

        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Merged,
                digest: d_merged.clone(),
                signature: None,
            })
            .unwrap();

        let artifact = builder.build().unwrap();

        assert_eq!(artifact.blobs.len(), 3);
        assert!(artifact.blobs[0].is_empty());
        assert_eq!(artifact.blobs[1], fake_sig);
        assert!(artifact.blobs[2].is_empty());

        let layers = artifact.manifest.layers();
        assert_eq!(layers[0].size(), 0);
        assert_eq!(layers[1].size(), fake_sig.len() as u64);
        assert_eq!(layers[2].size(), 0);

        for layer in layers {
            assert_eq!(
                layer.media_type(),
                &MediaType::Other(SIGNATURE_MEDIA_TYPE.to_string())
            );
        }

        let parsed = parse_composefs_artifact(&artifact.manifest).unwrap();
        assert_eq!(parsed.signature_entries[0].digest, d_manifest);
        assert_eq!(parsed.signature_entries[1].digest, d_layer);
        assert_eq!(parsed.signature_entries[2].digest, d_merged);
    }

    #[test]
    fn test_json_serialization_roundtrip() {
        let subject = sample_subject();
        let mut builder =
            ComposeFsArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        let d_manifest = fake_sha512_digest(0x66);
        let d_layer = fake_sha512_digest(0x77);

        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Manifest,
                digest: d_manifest.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: d_layer.clone(),
                signature: Some(vec![1, 2, 3]),
            })
            .unwrap();

        let artifact = builder.build().unwrap();

        let json = artifact
            .manifest
            .to_string()
            .expect("manifest serialization");

        let parsed_manifest =
            ImageManifest::from_reader(json.as_bytes()).expect("manifest deserialization");

        let parsed = parse_composefs_artifact(&parsed_manifest).unwrap();
        assert_eq!(parsed.algorithm, composefs::fsverity::algorithm::SHA512_12);
        assert_eq!(parsed.signature_entries.len(), 2);
        assert_eq!(
            parsed.signature_entries[0].sig_type,
            SignatureType::Manifest
        );
        assert_eq!(parsed.signature_entries[0].digest, d_manifest);
        assert_eq!(parsed.signature_entries[1].sig_type, SignatureType::Layer);
        assert_eq!(parsed.signature_entries[1].digest, d_layer);
    }

    #[test]
    fn test_empty_config_digest_correctness() {
        let computed = sha256_digest(b"{}");
        assert_eq!(
            computed.as_ref(),
            EMPTY_CONFIG_DIGEST,
            "EMPTY_CONFIG_DIGEST doesn't match sha256 of '{{}}'"
        );
    }

    #[test]
    fn test_subject_preserved() {
        let subject = sample_subject();
        let expected_digest = subject.digest().clone();
        let expected_media_type = subject.media_type().clone();

        let mut builder =
            ComposeFsArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0x88),
                signature: None,
            })
            .unwrap();

        let artifact = builder.build().unwrap();

        let json = artifact
            .manifest
            .to_string()
            .expect("manifest serialization");
        let parsed_manifest =
            ImageManifest::from_reader(json.as_bytes()).expect("manifest deserialization");

        let parsed = parse_composefs_artifact(&parsed_manifest).unwrap();
        assert_eq!(parsed.subject.digest(), &expected_digest);
        assert_eq!(parsed.subject.media_type(), &expected_media_type);
    }

    // ==================== Parse Validation (data-driven) ====================

    /// Build a valid single-layer (signature) artifact manifest for tampering in tests.
    fn build_test_manifest() -> ImageManifest {
        let mut builder = ComposeFsArtifactBuilder::new(
            composefs::fsverity::algorithm::SHA512_12,
            sample_subject(),
        );
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0xaa),
                signature: None,
            })
            .unwrap();
        builder.build().unwrap().manifest
    }

    /// Each case tampers with a valid manifest and expects parse to fail
    /// with an error message containing `expected_err`.
    #[test]
    #[allow(clippy::type_complexity)]
    fn test_parse_rejects_malformed_manifests() {
        let cases: Vec<(&str, Box<dyn Fn(ImageManifest) -> ImageManifest>)> = vec![
            // Manifest-level problems
            (
                "wrong artifact type",
                Box::new(|mut m| {
                    m.set_artifact_type(Some(MediaType::Other("wrong/type".to_string())));
                    m
                }),
            ),
            (
                "none",
                Box::new(|mut m| {
                    m.set_artifact_type(None);
                    m
                }),
            ),
            (
                "missing composefs.algorithm",
                Box::new(|mut m| {
                    let mut ann = m.annotations().clone().unwrap();
                    ann.remove(ANN_ALGORITHM);
                    m.set_annotations(Some(ann));
                    m
                }),
            ),
            (
                "composefs.algorithm",
                Box::new(|mut m| {
                    let mut ann = m.annotations().clone().unwrap();
                    ann.insert(ANN_ALGORITHM.to_string(), "bogus-algo".to_string());
                    m.set_annotations(Some(ann));
                    m
                }),
            ),
            (
                "missing annotations",
                Box::new(|mut m| {
                    m.set_annotations(None);
                    m
                }),
            ),
            (
                "missing subject",
                Box::new(|mut m| {
                    m.set_subject(None);
                    m
                }),
            ),
            // Layer-level problems
            (
                "missing annotations",
                Box::new(|mut m| {
                    m.layers_mut()[0].set_annotations(None);
                    m
                }),
            ),
            (
                "missing composefs.signature.type",
                Box::new(|mut m| {
                    let layer = &mut m.layers_mut()[0];
                    let mut ann = layer.annotations().clone().unwrap();
                    ann.remove(ANN_SIGNATURE_TYPE);
                    layer.set_annotations(Some(ann));
                    m
                }),
            ),
            (
                "missing composefs.digest",
                Box::new(|mut m| {
                    let layer = &mut m.layers_mut()[0];
                    let mut ann = layer.annotations().clone().unwrap();
                    ann.remove(ANN_DIGEST);
                    layer.set_annotations(Some(ann));
                    m
                }),
            ),
            (
                "unknown signature type",
                Box::new(|mut m| {
                    let layer = &mut m.layers_mut()[0];
                    let mut ann = layer.annotations().clone().unwrap();
                    ann.insert(ANN_SIGNATURE_TYPE.to_string(), "bogus_type".to_string());
                    layer.set_annotations(Some(ann));
                    m
                }),
            ),
            (
                "not valid hex",
                Box::new(|mut m| {
                    let layer = &mut m.layers_mut()[0];
                    let mut ann = layer.annotations().clone().unwrap();
                    ann.insert(ANN_DIGEST.to_string(), "not-valid-hex!@#$".to_string());
                    layer.set_annotations(Some(ann));
                    m
                }),
            ),
            (
                "expected 64 bytes",
                Box::new(|mut m| {
                    let layer = &mut m.layers_mut()[0];
                    let mut ann = layer.annotations().clone().unwrap();
                    ann.insert(ANN_DIGEST.to_string(), fake_sha256_digest(0xcd));
                    layer.set_annotations(Some(ann));
                    m
                }),
            ),
            (
                "wrong layer media type",
                Box::new(|m| {
                    let json = m.to_string().unwrap();
                    let tampered = json.replace(SIGNATURE_MEDIA_TYPE, "application/octet-stream");
                    ImageManifest::from_reader(tampered.as_bytes()).unwrap()
                }),
            ),
            (
                "duplicate config",
                Box::new(|mut m| {
                    let layer = &mut m.layers_mut()[0];
                    let mut ann = layer.annotations().clone().unwrap();
                    ann.insert(ANN_SIGNATURE_TYPE.to_string(), "config".to_string());
                    layer.set_annotations(Some(ann));
                    let dup = m.layers()[0].clone();
                    m.layers_mut().push(dup);
                    m
                }),
            ),
            (
                "out-of-order",
                Box::new(|_| {
                    let mut b = ComposeFsArtifactBuilder::new(
                        composefs::fsverity::algorithm::SHA512_12,
                        sample_subject(),
                    );
                    b.add_signature_entry(SignatureEntry {
                        sig_type: SignatureType::Layer,
                        digest: fake_sha512_digest(0x01),
                        signature: None,
                    })
                    .unwrap();
                    b.add_signature_entry(SignatureEntry {
                        sig_type: SignatureType::Merged,
                        digest: fake_sha512_digest(0x02),
                        signature: None,
                    })
                    .unwrap();
                    let mut m = b.build().unwrap().manifest;
                    let layers = m.layers_mut();
                    let ann0 = layers[0].annotations().clone().unwrap();
                    let ann1 = layers[1].annotations().clone().unwrap();
                    layers[0].set_annotations(Some(ann1));
                    layers[1].set_annotations(Some(ann0));
                    m
                }),
            ),
            // EROFS after signature (ordering violation)
            (
                "EROFS layer found after signature",
                Box::new(|_| {
                    // Build an artifact with both EROFS and sig, then swap them
                    let mut b = ComposeFsArtifactBuilder::new(
                        composefs::fsverity::algorithm::SHA512_12,
                        sample_subject(),
                    );
                    b.add_erofs_entry(ErofsEntry {
                        erofs_type: ErofsEntryType::Layer,
                        digest: fake_sha512_digest(0x01),
                        data: Some(vec![1]),
                    })
                    .unwrap();
                    b.add_signature_entry(SignatureEntry {
                        sig_type: SignatureType::Layer,
                        digest: fake_sha512_digest(0x02),
                        signature: None,
                    })
                    .unwrap();
                    let mut m = b.build().unwrap().manifest;
                    // Swap layers so EROFS comes after signature
                    let layers = m.layers_mut();
                    layers.swap(0, 1);
                    m
                }),
            ),
        ];

        for (expected_err, tamper) in &cases {
            let manifest = tamper(build_test_manifest());
            let err = parse_composefs_artifact(&manifest).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains(expected_err),
                "case {expected_err:?}: unexpected error: {msg}"
            );
        }
    }

    /// Zero-layer artifact is valid (boundary case).
    #[test]
    fn test_parse_zero_layers() {
        let builder = ComposeFsArtifactBuilder::new(
            composefs::fsverity::algorithm::SHA512_12,
            sample_subject(),
        );
        let parsed = parse_composefs_artifact(&builder.build().unwrap().manifest).unwrap();
        assert!(parsed.erofs_entries.is_empty());
        assert!(parsed.signature_entries.is_empty());
    }

    // ==================== Builder Validation (data-driven) ====================

    #[test]
    fn test_builder_rejects_invalid_signature_sequences() {
        let reject_cases: &[(SignatureType, SignatureType, &str)] = &[
            (
                SignatureType::Layer,
                SignatureType::Manifest,
                "out-of-order",
            ),
            (SignatureType::Layer, SignatureType::Config, "out-of-order"),
            (SignatureType::Merged, SignatureType::Layer, "out-of-order"),
            (
                SignatureType::Manifest,
                SignatureType::Manifest,
                "duplicate",
            ),
            (SignatureType::Config, SignatureType::Config, "duplicate"),
        ];

        for (first, second, expected_err) in reject_cases {
            let mut builder = ComposeFsArtifactBuilder::new(
                composefs::fsverity::algorithm::SHA512_12,
                sample_subject(),
            );
            builder
                .add_signature_entry(SignatureEntry {
                    sig_type: *first,
                    digest: fake_sha512_digest(0x01),
                    signature: None,
                })
                .unwrap();
            let err = builder
                .add_signature_entry(SignatureEntry {
                    sig_type: *second,
                    digest: fake_sha512_digest(0x02),
                    signature: None,
                })
                .unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains(expected_err),
                "case ({first} then {second}): unexpected error: {msg}"
            );
        }
    }

    #[test]
    fn test_builder_rejects_erofs_after_signature() {
        let mut builder = ComposeFsArtifactBuilder::new(
            composefs::fsverity::algorithm::SHA512_12,
            sample_subject(),
        );
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0x01),
                signature: None,
            })
            .unwrap();
        let err = builder
            .add_erofs_entry(ErofsEntry {
                erofs_type: ErofsEntryType::Layer,
                digest: fake_sha512_digest(0x02),
                data: None,
            })
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("cannot add EROFS entry after signature"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_builder_accepts_valid_sequences() {
        let accept_cases: &[(&[SignatureType], usize)] = &[
            (&[], 0),
            (
                &[
                    SignatureType::Layer,
                    SignatureType::Layer,
                    SignatureType::Layer,
                ],
                3,
            ),
            (&[SignatureType::Merged, SignatureType::Merged], 2),
            (
                &[
                    SignatureType::Manifest,
                    SignatureType::Config,
                    SignatureType::Layer,
                    SignatureType::Merged,
                ],
                4,
            ),
        ];

        for (types, expected) in accept_cases {
            let mut builder = ComposeFsArtifactBuilder::new(
                composefs::fsverity::algorithm::SHA512_12,
                sample_subject(),
            );
            for (i, sig_type) in types.iter().enumerate() {
                builder
                    .add_signature_entry(SignatureEntry {
                        sig_type: *sig_type,
                        digest: fake_sha512_digest(i as u8),
                        signature: None,
                    })
                    .unwrap();
            }
            let artifact = builder.build().unwrap();
            assert_eq!(
                artifact.manifest.layers().len(),
                *expected,
                "case {types:?}: wrong layer count"
            );
        }
    }

    // ==================== Repository Integration Tests ====================

    use composefs::fsverity::Sha256HashValue;
    use composefs::test::TestRepo;

    /// Helper to create a minimal subject image in a test repository.
    /// Returns (manifest_digest, manifest_verity).
    fn create_subject_image(
        repo: &std::sync::Arc<Repository<Sha256HashValue>>,
    ) -> (OciDigest, Sha256HashValue) {
        use containers_image_proxy::oci_spec::image::{
            ConfigBuilder, ImageConfigurationBuilder, ImageManifestBuilder, RootFsBuilder,
        };

        let layer_data = b"fake-subject-layer";
        let layer_digest = sha256_digest(layer_data);

        let mut layer_stream = repo
            .create_stream(crate::skopeo::TAR_LAYER_CONTENT_TYPE)
            .unwrap();
        layer_stream.write_external(layer_data).unwrap();
        let layer_verity = repo
            .write_stream(layer_stream, &crate::layer_identifier(&layer_digest), None)
            .unwrap();

        let rootfs = RootFsBuilder::default()
            .typ("layers")
            .diff_ids(vec![layer_digest.to_string()])
            .build()
            .unwrap();
        let cfg = ConfigBuilder::default().build().unwrap();
        let config = ImageConfigurationBuilder::default()
            .architecture("amd64")
            .os("linux")
            .rootfs(rootfs)
            .config(cfg)
            .build()
            .unwrap();

        let config_json = config.to_string().unwrap();
        let config_digest = sha256_digest(config_json.as_bytes());

        let mut config_stream = repo
            .create_stream(crate::skopeo::OCI_CONFIG_CONTENT_TYPE)
            .unwrap();
        config_stream.add_named_stream_ref(layer_digest.as_ref(), &layer_verity);
        config_stream
            .write_external(config_json.as_bytes())
            .unwrap();
        let config_verity = repo
            .write_stream(
                config_stream,
                &crate::config_identifier(&config_digest),
                None,
            )
            .unwrap();

        let config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageConfig)
            .digest(config_digest.clone())
            .size(config_json.len() as u64)
            .build()
            .unwrap();
        let layer_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayerGzip)
            .digest(layer_digest.clone())
            .size(layer_data.len() as u64)
            .build()
            .unwrap();

        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(config_descriptor)
            .layers(vec![layer_descriptor])
            .build()
            .unwrap();

        let mut layer_verities = std::collections::HashMap::new();
        layer_verities.insert(layer_digest.as_ref().into(), layer_verity);

        let manifest_json = manifest.to_string().unwrap();
        let manifest_digest = sha256_digest(manifest_json.as_bytes());

        let (digest, verity) = crate::oci_image::write_manifest(
            repo,
            &manifest,
            &manifest_digest,
            &config_verity,
            &layer_verities,
            Some("subject:v1"),
        )
        .unwrap();

        (digest, verity)
    }

    #[test]
    fn test_store_and_find_composefs_artifact() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create a subject image
        let (subject_digest, _subject_verity) = create_subject_image(repo);

        // Build a composefs artifact referencing the subject
        let subject_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(subject_digest.clone())
            .size(100u64)
            .build()
            .unwrap();

        let layer_digest = fake_sha512_digest(0xab);
        let merged_digest = fake_sha512_digest(0xcd);

        let mut builder = ComposeFsArtifactBuilder::new(
            composefs::fsverity::algorithm::SHA512_12,
            subject_descriptor,
        );
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: layer_digest.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Merged,
                digest: merged_digest.clone(),
                signature: None,
            })
            .unwrap();

        let artifact = builder.build().unwrap();

        // Store it
        let (artifact_digest, _artifact_verity) = store_composefs_artifact(repo, artifact).unwrap();

        // Verify the manifest was stored
        assert!(
            crate::oci_image::has_manifest(repo, &artifact_digest)
                .unwrap()
                .is_some()
        );

        // Find it by subject
        let found = find_composefs_artifacts(repo, &subject_digest).unwrap();
        assert_eq!(found.len(), 1);

        let parsed = &found[0];
        assert_eq!(parsed.algorithm, composefs::fsverity::algorithm::SHA512_12);
        assert_eq!(parsed.signature_entries.len(), 2);
        assert_eq!(parsed.signature_entries[0].sig_type, SignatureType::Layer);
        assert_eq!(parsed.signature_entries[0].digest, layer_digest);
        assert_eq!(parsed.signature_entries[1].sig_type, SignatureType::Merged);
        assert_eq!(parsed.signature_entries[1].digest, merged_digest);

        // Subject descriptor should be preserved
        assert_eq!(parsed.subject.digest(), &subject_digest);

        // Querying a different subject should return empty
        let other = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let found = find_composefs_artifacts(repo, &other.parse::<OciDigest>().unwrap()).unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn test_store_multiple_composefs_artifacts() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let (subject_digest, _) = create_subject_image(repo);

        let subject_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(subject_digest.clone())
            .size(100u64)
            .build()
            .unwrap();

        // Store two composefs artifacts for the same subject
        for seed in [0xaau8, 0xbbu8] {
            let mut builder = ComposeFsArtifactBuilder::new(
                composefs::fsverity::algorithm::SHA512_12,
                subject_descriptor.clone(),
            );
            builder
                .add_signature_entry(SignatureEntry {
                    sig_type: SignatureType::Layer,
                    digest: fake_sha512_digest(seed),
                    signature: None,
                })
                .unwrap();
            let artifact = builder.build().unwrap();
            store_composefs_artifact(repo, artifact).unwrap();
        }

        let found = find_composefs_artifacts(repo, &subject_digest).unwrap();
        assert_eq!(found.len(), 2);

        let digests: Vec<&str> = found
            .iter()
            .map(|p| p.signature_entries[0].digest.as_str())
            .collect();
        assert!(digests.contains(&fake_sha512_digest(0xaa).as_str()));
        assert!(digests.contains(&fake_sha512_digest(0xbb).as_str()));
    }

    #[test]
    fn test_store_signature_with_blobs() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let (subject_digest, _) = create_subject_image(repo);

        let subject_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(subject_digest.clone())
            .size(100u64)
            .build()
            .unwrap();

        let fake_sig = vec![0x30, 0x82, 0x01, 0x00, 0xAB, 0xCD, 0xEF];
        let mut builder = ComposeFsArtifactBuilder::new(
            composefs::fsverity::algorithm::SHA512_12,
            subject_descriptor,
        );
        builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0x11),
                signature: Some(fake_sig.clone()),
            })
            .unwrap();

        let artifact = builder.build().unwrap();
        let (artifact_digest, _) = store_composefs_artifact(repo, artifact).unwrap();

        // Find it and verify the parsed result
        let found = find_composefs_artifacts(repo, &subject_digest).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].signature_entries[0].sig_type, SignatureType::Layer);
        assert_eq!(
            found[0].signature_entries[0].digest,
            fake_sha512_digest(0x11)
        );

        // Verify we can open the artifact as an OciImage and read the blob
        let image = crate::oci_image::OciImage::open(repo, &artifact_digest, None).unwrap();
        assert!(!image.is_container_image());

        // The layer blob should be retrievable
        let layer_desc = &image.layer_descriptors()[0];
        let blob_digest = layer_desc.digest().to_string();
        let blob_verity = image.layer_verity(&blob_digest).unwrap();
        let blob_data = crate::oci_image::open_blob(
            repo,
            &blob_digest.parse::<OciDigest>().unwrap(),
            Some(blob_verity),
        )
        .unwrap();
        assert_eq!(blob_data, fake_sig);
    }

    // ==================== Repository Integration Edge Cases ====================

    #[test]
    fn test_find_returns_empty_for_unknown_subject() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let found = find_composefs_artifacts(
            &test_repo.repo,
            &"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse::<OciDigest>()
                .unwrap(),
        )
        .unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn test_store_idempotent() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;
        let (subject_digest, _) = create_subject_image(repo);

        let subject_desc = DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(subject_digest.clone())
            .size(100u64)
            .build()
            .unwrap();

        let build_artifact = || {
            let mut b = ComposeFsArtifactBuilder::new(
                composefs::fsverity::algorithm::SHA512_12,
                subject_desc.clone(),
            );
            b.add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0xe1),
                signature: None,
            })
            .unwrap();
            b.build().unwrap()
        };

        // Store twice — both succeed (content-addressed, idempotent)
        store_composefs_artifact(repo, build_artifact()).unwrap();
        store_composefs_artifact(repo, build_artifact()).unwrap();

        let found = find_composefs_artifacts(repo, &subject_digest).unwrap();
        assert!(!found.is_empty());
        for a in &found {
            assert_eq!(a.signature_entries[0].digest, fake_sha512_digest(0xe1));
        }
    }

    /// Non-composefs referrer artifacts are silently skipped by find_composefs_artifacts.
    #[test]
    fn test_find_skips_non_composefs_referrers() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;
        let (subject_digest, _) = create_subject_image(repo);

        let empty_config = b"{}";
        let config_id =
            crate::config_identifier(&EMPTY_CONFIG_DIGEST.parse::<OciDigest>().unwrap());
        let config_verity = match repo.has_stream(&config_id).unwrap() {
            Some(v) => v,
            None => {
                let mut s = repo
                    .create_stream(crate::skopeo::OCI_CONFIG_CONTENT_TYPE)
                    .unwrap();
                s.write_external(empty_config).unwrap();
                repo.write_stream(s, &config_id, None).unwrap()
            }
        };

        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .artifact_type(MediaType::Other("application/vnd.other.v1".to_string()))
            .config(
                DescriptorBuilder::default()
                    .media_type(MediaType::Other(
                        "application/vnd.oci.empty.v1+json".to_string(),
                    ))
                    .digest(EMPTY_CONFIG_DIGEST.parse::<OciDigest>().unwrap())
                    .size(2u64)
                    .build()
                    .unwrap(),
            )
            .layers(vec![])
            .subject(
                DescriptorBuilder::default()
                    .media_type(MediaType::ImageManifest)
                    .digest(subject_digest.clone())
                    .size(100u64)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let manifest_json = manifest.to_string().unwrap();
        let manifest_digest = sha256_digest(manifest_json.as_bytes());
        let (stored_digest, _) = crate::oci_image::write_manifest(
            repo,
            &manifest,
            &manifest_digest,
            &config_verity,
            &std::collections::HashMap::new(),
            None,
        )
        .unwrap();
        crate::oci_image::add_referrer(repo, &subject_digest, &stored_digest).unwrap();

        let found = find_composefs_artifacts(repo, &subject_digest).unwrap();
        assert!(found.is_empty(), "should skip non-composefs referrers");
    }

    // ==================== End-to-End Integration Test ====================

    /// Full seal → sign → discover → verify workflow using real tar layers
    /// and the actual composefs pipeline (import_layer, write_config, seal,
    /// compute_per_layer_digests, store_composefs_artifact, find_composefs_artifacts).
    #[test]
    fn test_end_to_end_seal_sign_verify() {
        use composefs::fsverity::FsVerityHashValue;
        use containers_image_proxy::oci_spec::image::{
            ConfigBuilder, ImageConfigurationBuilder, ImageManifestBuilder, RootFsBuilder,
        };

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // --- 1. Build a tar layer with /usr (required by transform_for_oci in seal) ---
        let mut builder = ::tar::Builder::new(vec![]);
        {
            let mut header = ::tar::Header::new_ustar();
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o755);
            header.set_entry_type(::tar::EntryType::Directory);
            header.set_size(0);
            builder
                .append_data(&mut header, "usr", std::io::empty())
                .unwrap();
        }
        {
            let data = b"hello composefs";
            let mut header = ::tar::Header::new_ustar();
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o644);
            header.set_entry_type(::tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            builder
                .append_data(&mut header, "usr/hello.txt", &data[..])
                .unwrap();
        }
        let tar_data = builder.into_inner().unwrap();

        let diff_id = {
            use sha2::{Digest, Sha256};
            let mut ctx = Sha256::new();
            ctx.update(&tar_data);
            format!("sha256:{}", hex::encode(ctx.finalize()))
        };

        // --- 2. Import the layer ---
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (layer_verity, _stats) = rt
            .block_on(crate::import_layer(
                repo,
                &diff_id.parse::<OciDigest>().unwrap(),
                None,
                &mut tar_data.as_slice(),
            ))
            .unwrap();

        // --- 3. Create an OCI config referencing this layer ---
        let rootfs = RootFsBuilder::default()
            .typ("layers")
            .diff_ids(vec![diff_id.clone()])
            .build()
            .unwrap();
        let cfg = ConfigBuilder::default().build().unwrap();
        let config = ImageConfigurationBuilder::default()
            .architecture("amd64")
            .os("linux")
            .rootfs(rootfs)
            .config(cfg)
            .build()
            .unwrap();

        let mut refs = std::collections::HashMap::<Box<str>, Sha256HashValue>::new();
        refs.insert(Box::from(diff_id.as_str()), layer_verity.clone());

        let (config_digest, config_verity) =
            crate::write_config(repo, &config, refs, None, None).unwrap();

        // --- 4. Compute merged digest directly (no sealing required) ---
        let expected_merged: Sha256HashValue =
            crate::image::compute_merged_digest(repo, &config_digest, Some(&config_verity))
                .unwrap();

        // --- 5. Compute per-layer digests ---
        let per_layer_digests =
            crate::image::compute_per_layer_digests(repo, &config_digest, Some(&config_verity))
                .unwrap();
        assert_eq!(
            per_layer_digests.len(),
            1,
            "expected exactly 1 layer digest"
        );

        // --- 6. Build a source image manifest so we have a subject descriptor ---
        let config_json = config.to_string().unwrap();

        let config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageConfig)
            .digest(config_digest.clone())
            .size(config_json.len() as u64)
            .build()
            .unwrap();

        let layer_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayerGzip)
            .digest(diff_id.parse::<OciDigest>().unwrap())
            .size(tar_data.len() as u64)
            .build()
            .unwrap();

        let source_manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(config_descriptor)
            .layers(vec![layer_descriptor])
            .build()
            .unwrap();

        // Build layer verities map for writing the manifest
        let mut layer_verities_map = std::collections::HashMap::new();
        layer_verities_map.insert(diff_id.clone().into_boxed_str(), layer_verity.clone());

        let source_manifest_json = source_manifest.to_string().unwrap();
        let source_manifest_digest = sha256_digest(source_manifest_json.as_bytes());

        let (stored_manifest_digest, _manifest_verity) = crate::oci_image::write_manifest(
            repo,
            &source_manifest,
            &source_manifest_digest,
            &config_verity,
            &layer_verities_map,
            Some("e2e-test:v1"),
        )
        .unwrap();

        // --- 8. Build and store a signature artifact ---
        let subject_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(stored_manifest_digest.clone())
            .size(source_manifest_json.len() as u64)
            .build()
            .unwrap();

        let mut sig_builder = ComposeFsArtifactBuilder::new(
            composefs::fsverity::algorithm::SHA256_12,
            subject_descriptor,
        );
        sig_builder.add_layer_digests(&per_layer_digests).unwrap();
        sig_builder.add_merged_digest(&expected_merged).unwrap();

        let artifact = sig_builder.build().unwrap();
        let (_artifact_digest, _artifact_verity) =
            store_composefs_artifact(repo, artifact).unwrap();

        // --- 9. Discover the artifact via find_composefs_artifacts ---
        let found = find_composefs_artifacts(repo, &stored_manifest_digest).unwrap();
        assert_eq!(found.len(), 1, "expected exactly 1 composefs artifact");

        let parsed = &found[0];

        // Verify algorithm
        assert_eq!(
            parsed.algorithm,
            composefs::fsverity::algorithm::SHA256_12,
            "algorithm should be SHA256_12"
        );

        // Verify signature entries: 1 layer + 1 merged = 2
        assert_eq!(
            parsed.signature_entries.len(),
            2,
            "expected 2 signature entries (layer + merged)"
        );

        // Verify layer digest matches compute_per_layer_digests output
        assert_eq!(parsed.signature_entries[0].sig_type, SignatureType::Layer);
        assert_eq!(
            parsed.signature_entries[0].digest,
            per_layer_digests[0].to_hex(),
            "layer digest must match compute_per_layer_digests output"
        );

        // Verify merged digest matches the computed value
        assert_eq!(parsed.signature_entries[1].sig_type, SignatureType::Merged);
        assert_eq!(
            parsed.signature_entries[1].digest,
            expected_merged.to_hex(),
            "merged digest must match computed value"
        );

        // Verify subject descriptor is preserved
        assert_eq!(
            parsed.subject.digest(),
            &stored_manifest_digest,
            "subject descriptor must reference the source image manifest"
        );
    }

    /// Full seal → sign → discover → verify workflow with actual PKCS#7
    /// signature blobs attached to each entry, exercising the complete
    /// signing round-trip through the repository.
    #[test]
    fn test_end_to_end_with_pkcs7_signatures() {
        use composefs::fsverity::FsVerityHashValue;
        use containers_image_proxy::oci_spec::image::{
            ConfigBuilder, ImageConfigurationBuilder, ImageManifestBuilder, RootFsBuilder,
        };

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // --- 1. Build a tar layer with /usr ---
        let mut builder = ::tar::Builder::new(vec![]);
        {
            let mut header = ::tar::Header::new_ustar();
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o755);
            header.set_entry_type(::tar::EntryType::Directory);
            header.set_size(0);
            builder
                .append_data(&mut header, "usr", std::io::empty())
                .unwrap();
        }
        {
            let data = b"hello composefs pkcs7";
            let mut header = ::tar::Header::new_ustar();
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o644);
            header.set_entry_type(::tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            builder
                .append_data(&mut header, "usr/hello.txt", &data[..])
                .unwrap();
        }
        let tar_data = builder.into_inner().unwrap();

        let diff_id = {
            use sha2::{Digest, Sha256};
            let mut ctx = Sha256::new();
            ctx.update(&tar_data);
            format!("sha256:{}", hex::encode(ctx.finalize()))
        };

        // --- 2. Import the layer ---
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (layer_verity, _stats) = rt
            .block_on(crate::import_layer(
                repo,
                &diff_id.parse::<OciDigest>().unwrap(),
                None,
                &mut tar_data.as_slice(),
            ))
            .unwrap();

        // --- 3. Create an OCI config referencing this layer ---
        let rootfs = RootFsBuilder::default()
            .typ("layers")
            .diff_ids(vec![diff_id.clone()])
            .build()
            .unwrap();
        let cfg = ConfigBuilder::default().build().unwrap();
        let config = ImageConfigurationBuilder::default()
            .architecture("amd64")
            .os("linux")
            .rootfs(rootfs)
            .config(cfg)
            .build()
            .unwrap();

        let mut refs = std::collections::HashMap::<Box<str>, Sha256HashValue>::new();
        refs.insert(Box::from(diff_id.as_str()), layer_verity.clone());

        let (config_digest, config_verity) =
            crate::write_config(repo, &config, refs, None, None).unwrap();

        // --- 4. Compute merged digest directly (no sealing required) ---
        let expected_merged: Sha256HashValue =
            crate::image::compute_merged_digest(repo, &config_digest, Some(&config_verity))
                .unwrap();

        // --- 5. Compute per-layer digests ---
        let per_layer_digests =
            crate::image::compute_per_layer_digests(repo, &config_digest, Some(&config_verity))
                .unwrap();
        assert_eq!(per_layer_digests.len(), 1);

        // --- 6. Generate test keypair and create signer/verifier ---
        let (cert_pem, key_pem) = {
            use openssl::asn1::Asn1Time;
            use openssl::hash::MessageDigest;
            use openssl::pkey::PKey;
            use openssl::rsa::Rsa;
            use openssl::x509::{X509Builder, X509NameBuilder};

            let rsa = Rsa::generate(2048).unwrap();
            let key = PKey::from_rsa(rsa).unwrap();

            let mut name_builder = X509NameBuilder::new().unwrap();
            name_builder
                .append_entry_by_text("CN", "composefs-test")
                .unwrap();
            let name = name_builder.build();

            let mut x509_builder = X509Builder::new().unwrap();
            x509_builder.set_version(2).unwrap();
            x509_builder.set_subject_name(&name).unwrap();
            x509_builder.set_issuer_name(&name).unwrap();
            x509_builder.set_pubkey(&key).unwrap();

            let not_before = Asn1Time::days_from_now(0).unwrap();
            let not_after = Asn1Time::days_from_now(365).unwrap();
            x509_builder.set_not_before(&not_before).unwrap();
            x509_builder.set_not_after(&not_after).unwrap();

            x509_builder.sign(&key, MessageDigest::sha256()).unwrap();
            let cert = x509_builder.build();

            (
                cert.to_pem().unwrap(),
                key.private_key_to_pem_pkcs8().unwrap(),
            )
        };

        let signer = crate::signing::FsVeritySigningKey::from_pem(&cert_pem, &key_pem).unwrap();
        let verifier = crate::signing::FsVeritySignatureVerifier::from_pem(&cert_pem).unwrap();

        // --- 7. Build a source image manifest (subject for the artifact) ---
        let config_json = config.to_string().unwrap();

        let config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageConfig)
            .digest(config_digest.clone())
            .size(config_json.len() as u64)
            .build()
            .unwrap();

        let layer_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayerGzip)
            .digest(diff_id.parse::<OciDigest>().unwrap())
            .size(tar_data.len() as u64)
            .build()
            .unwrap();

        let source_manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(config_descriptor)
            .layers(vec![layer_descriptor])
            .build()
            .unwrap();

        let mut layer_verities_map = std::collections::HashMap::new();
        layer_verities_map.insert(diff_id.clone().into_boxed_str(), layer_verity.clone());

        let source_manifest_json = source_manifest.to_string().unwrap();
        let source_manifest_digest = sha256_digest(source_manifest_json.as_bytes());

        let (stored_manifest_digest, _) = crate::oci_image::write_manifest(
            repo,
            &source_manifest,
            &source_manifest_digest,
            &config_verity,
            &layer_verities_map,
            Some("e2e-pkcs7:v1"),
        )
        .unwrap();

        // --- 9. Build composefs artifact WITH actual PKCS#7 signatures ---
        let subject_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(stored_manifest_digest.clone())
            .size(source_manifest_json.len() as u64)
            .build()
            .unwrap();

        let mut sig_builder = ComposeFsArtifactBuilder::new(
            composefs::fsverity::algorithm::SHA256_12,
            subject_descriptor,
        );

        // Sign each per-layer digest
        for layer_digest in &per_layer_digests {
            let sig = signer.sign(layer_digest).unwrap();
            sig_builder
                .add_signature_entry(SignatureEntry {
                    sig_type: SignatureType::Layer,
                    digest: layer_digest.to_hex(),
                    signature: Some(sig),
                })
                .unwrap();
        }

        // Sign the merged digest
        let merged_sig = signer.sign(&expected_merged).unwrap();
        sig_builder
            .add_signature_entry(SignatureEntry {
                sig_type: SignatureType::Merged,
                digest: expected_merged.to_hex(),
                signature: Some(merged_sig),
            })
            .unwrap();

        let artifact = sig_builder.build().unwrap();

        // Verify blobs are non-empty before storing
        for blob in &artifact.blobs {
            assert!(!blob.is_empty(), "signature blob should not be empty");
        }

        let (artifact_digest, _) = store_composefs_artifact(repo, artifact).unwrap();

        // --- 10. Discover the artifact ---
        let found = find_composefs_artifacts(repo, &stored_manifest_digest).unwrap();
        assert_eq!(found.len(), 1, "expected exactly 1 composefs artifact");

        let parsed = &found[0];
        assert_eq!(parsed.algorithm, composefs::fsverity::algorithm::SHA256_12);
        assert_eq!(
            parsed.signature_entries.len(),
            2,
            "expected layer + merged entries"
        );

        // Verify digest values match
        assert_eq!(parsed.signature_entries[0].sig_type, SignatureType::Layer);
        assert_eq!(
            parsed.signature_entries[0].digest,
            per_layer_digests[0].to_hex()
        );
        assert_eq!(parsed.signature_entries[1].sig_type, SignatureType::Merged);
        assert_eq!(parsed.signature_entries[1].digest, expected_merged.to_hex());

        // parse_composefs_artifact doesn't populate the signature field —
        // the blobs are stored separately and must be read from the repo.
        assert!(
            parsed.signature_entries[0].signature.is_none(),
            "parsed entries should not have signature blobs inline"
        );

        // --- 11. Read blobs from the repository and verify signatures ---
        let image = crate::oci_image::OciImage::open(repo, &artifact_digest, None).unwrap();
        let layer_descs = image.layer_descriptors();
        assert_eq!(layer_descs.len(), 2);

        // Verify each signature blob
        for (i, entry) in parsed.signature_entries.iter().enumerate() {
            let desc = &layer_descs[i];
            let blob_digest = desc.digest().to_string();
            let blob_verity = image.layer_verity(&blob_digest).unwrap();
            let blob_data = crate::oci_image::open_blob(
                repo,
                &blob_digest.parse::<OciDigest>().unwrap(),
                Some(blob_verity),
            )
            .unwrap();
            assert!(
                !blob_data.is_empty(),
                "stored signature blob must not be empty"
            );

            // Verify the signature against the digest
            let raw_digest = hex::decode(&entry.digest).unwrap();
            verifier
                .verify_raw(
                    &blob_data,
                    Sha256HashValue::ALGORITHM.kernel_id(),
                    &raw_digest,
                )
                .expect("signature verification should succeed");
        }

        // --- 12. Verify that a different cert rejects the signatures ---
        let (wrong_cert_pem, _) = {
            use openssl::asn1::Asn1Time;
            use openssl::hash::MessageDigest;
            use openssl::pkey::PKey;
            use openssl::rsa::Rsa;
            use openssl::x509::{X509Builder, X509NameBuilder};

            let rsa = Rsa::generate(2048).unwrap();
            let key = PKey::from_rsa(rsa).unwrap();

            let mut name_builder = X509NameBuilder::new().unwrap();
            name_builder
                .append_entry_by_text("CN", "wrong-signer")
                .unwrap();
            let name = name_builder.build();

            let mut x509_builder = X509Builder::new().unwrap();
            x509_builder.set_version(2).unwrap();
            x509_builder.set_subject_name(&name).unwrap();
            x509_builder.set_issuer_name(&name).unwrap();
            x509_builder.set_pubkey(&key).unwrap();

            let not_before = Asn1Time::days_from_now(0).unwrap();
            let not_after = Asn1Time::days_from_now(365).unwrap();
            x509_builder.set_not_before(&not_before).unwrap();
            x509_builder.set_not_after(&not_after).unwrap();

            x509_builder.sign(&key, MessageDigest::sha256()).unwrap();
            let cert = x509_builder.build();

            (
                cert.to_pem().unwrap(),
                key.private_key_to_pem_pkcs8().unwrap(),
            )
        };

        let wrong_verifier =
            crate::signing::FsVeritySignatureVerifier::from_pem(&wrong_cert_pem).unwrap();

        // Read any blob and check it fails with the wrong cert
        let desc = &layer_descs[0];
        let blob_digest = desc.digest().to_string();
        let blob_verity = image.layer_verity(&blob_digest).unwrap();
        let blob_data = crate::oci_image::open_blob(
            repo,
            &blob_digest.parse::<OciDigest>().unwrap(),
            Some(blob_verity),
        )
        .unwrap();
        let raw_digest = hex::decode(&parsed.signature_entries[0].digest).unwrap();

        let result = wrong_verifier.verify_raw(
            &blob_data,
            Sha256HashValue::ALGORITHM.kernel_id(),
            &raw_digest,
        );
        assert!(
            result.is_err(),
            "verification with wrong certificate must fail"
        );
    }
}
