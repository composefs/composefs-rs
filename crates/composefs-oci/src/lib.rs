//! OCI container image support for composefs.
//!
//! This crate provides functionality for working with OCI (Open Container Initiative) container images
//! in the context of composefs. It enables importing, extracting, and mounting container images as
//! composefs filesystems with fs-verity integrity protection.
//!
//! Key functionality includes:
//! - Pulling container images from registries using skopeo
//! - Converting OCI image layers from tar format to composefs split streams
//! - Creating mountable filesystems from OCI image configurations
//! - Importing from containers-storage with zero-copy reflinks (optional feature)

#![forbid(unsafe_code)]

pub mod boot;
#[cfg(feature = "containers-storage")]
pub mod cstor;
pub mod image;
pub mod oci_image;
pub mod skopeo;
pub mod tar;

/// Test utilities for building OCI images from dumpfile strings.
#[cfg(any(test, feature = "test"))]
#[allow(missing_docs, missing_debug_implementations)]
#[doc(hidden)]
pub mod test_util;

// Re-export the composefs crate for consumers who only need composefs-oci
pub use composefs;

use std::{collections::HashMap, sync::Arc};

use anyhow::{Result, ensure};
/// OCI content-addressable digest type (e.g. `sha256:abcd...`).
///
/// Re-exported from `oci-spec` for convenience.
pub use containers_image_proxy::oci_spec::image::Digest as OciDigest;

use containers_image_proxy::ImageProxyConfig;
use containers_image_proxy::oci_spec::image::ImageConfiguration;
use sha2::{Digest, Sha256};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::{ObjectStoreMethod, Repository},
    splitstream::SplitStreamStats,
};

use crate::skopeo::{OCI_CONFIG_CONTENT_TYPE, TAR_LAYER_CONTENT_TYPE};
use crate::tar::get_entry;

/// Named ref key for the EROFS image derived from this OCI config.
pub const IMAGE_REF_KEY: &str = "composefs.image";

/// Named ref key for the boot EROFS image derived from this OCI config.
pub const BOOT_IMAGE_REF_KEY: &str = "composefs.image.boot";

// Re-export key types for convenience
#[cfg(feature = "boot")]
pub use boot::generate_boot_image;
pub use boot::{boot_image, remove_boot_image};
pub use oci_image::{
    ImageInfo, LayerInfo, OCI_REF_PREFIX, OciFsckError, OciFsckResult, OciImage, SplitstreamInfo,
    add_referrer, layer_dumpfile, layer_info, layer_tar, list_images, list_referrers, list_refs,
    oci_fsck, oci_fsck_image, remove_referrer, remove_referrers_for_subject, resolve_ref,
    tag_image, untag_image,
};
pub use skopeo::pull_image;

/// Statistics from an image import operation.
#[derive(Debug, Clone, Default)]
pub struct ImportStats {
    /// Number of layers in the image.
    pub layers: u64,
    /// Number of layers that were already present (skipped).
    pub layers_already_present: u64,
    /// Number of objects stored via regular copy.
    pub objects_copied: u64,
    /// Number of objects stored via reflink (zero-copy).
    pub objects_reflinked: u64,
    /// Number of objects stored via hardlink (zero-copy).
    pub objects_hardlinked: u64,
    /// Number of objects that already existed (deduplicated).
    pub objects_already_present: u64,
    /// Total bytes stored via regular copy.
    pub bytes_copied: u64,
    /// Total bytes stored via reflink.
    pub bytes_reflinked: u64,
    /// Total bytes stored via hardlink.
    pub bytes_hardlinked: u64,
    /// Total bytes inlined in splitstreams (small files + headers).
    pub bytes_inlined: u64,
}

impl ImportStats {
    /// Total number of new objects stored (copied + reflinked + hardlinked).
    pub fn new_objects(&self) -> u64 {
        self.objects_copied + self.objects_reflinked + self.objects_hardlinked
    }

    /// Total number of objects processed (new + already present).
    pub fn total_objects(&self) -> u64 {
        self.new_objects() + self.objects_already_present
    }

    /// Total bytes stored as new objects (copied + reflinked + hardlinked).
    pub fn new_bytes(&self) -> u64 {
        self.bytes_copied + self.bytes_reflinked + self.bytes_hardlinked
    }

    /// Merge another `ImportStats` into this one.
    pub fn merge(&mut self, other: &ImportStats) {
        self.layers += other.layers;
        self.layers_already_present += other.layers_already_present;
        self.objects_copied += other.objects_copied;
        self.objects_reflinked += other.objects_reflinked;
        self.objects_hardlinked += other.objects_hardlinked;
        self.objects_already_present += other.objects_already_present;
        self.bytes_copied += other.bytes_copied;
        self.bytes_reflinked += other.bytes_reflinked;
        self.bytes_hardlinked += other.bytes_hardlinked;
        self.bytes_inlined += other.bytes_inlined;
    }

    /// Build import stats from [`SplitStreamStats`].
    pub(crate) fn from_split_stream_stats(ss: &SplitStreamStats) -> Self {
        let mut stats = ImportStats {
            bytes_inlined: ss.inline_bytes,
            ..Default::default()
        };
        for &(size, method) in &ss.external_objects {
            match method {
                ObjectStoreMethod::Copied => {
                    stats.objects_copied += 1;
                    stats.bytes_copied += size;
                }
                ObjectStoreMethod::Reflinked => {
                    stats.objects_reflinked += 1;
                    stats.bytes_reflinked += size;
                }
                ObjectStoreMethod::Hardlinked => {
                    stats.objects_hardlinked += 1;
                    stats.bytes_hardlinked += size;
                }
                ObjectStoreMethod::AlreadyPresent => {
                    stats.objects_already_present += 1;
                }
            }
        }
        stats
    }
}

impl std::fmt::Display for ImportStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let has_zerocopy = self.objects_reflinked > 0 || self.objects_hardlinked > 0;
        if has_zerocopy {
            // Show detailed breakdown when zero-copy methods were used
            let mut parts = Vec::new();
            if self.objects_reflinked > 0 {
                parts.push(format!("{} reflinked", self.objects_reflinked));
            }
            if self.objects_hardlinked > 0 {
                parts.push(format!("{} hardlinked", self.objects_hardlinked));
            }
            parts.push(format!("{} copied", self.objects_copied));
            parts.push(format!("{} already present", self.objects_already_present));
            write!(f, "{} objects; ", parts.join(" + "))?;

            let mut byte_parts = Vec::new();
            if self.objects_reflinked > 0 {
                byte_parts.push(format!(
                    "{} reflinked",
                    indicatif::HumanBytes(self.bytes_reflinked)
                ));
            }
            if self.objects_hardlinked > 0 {
                byte_parts.push(format!(
                    "{} hardlinked",
                    indicatif::HumanBytes(self.bytes_hardlinked)
                ));
            }
            byte_parts.push(format!(
                "{} copied",
                indicatif::HumanBytes(self.bytes_copied)
            ));
            byte_parts.push(format!(
                "{} inlined",
                indicatif::HumanBytes(self.bytes_inlined)
            ));
            write!(f, "{}", byte_parts.join(", "))
        } else {
            write!(
                f,
                "{} new + {} already present objects; {} stored, {} inlined",
                self.objects_copied,
                self.objects_already_present,
                indicatif::HumanBytes(self.bytes_copied),
                indicatif::HumanBytes(self.bytes_inlined),
            )
        }
    }
}

/// Options for a [`pull`] operation.
///
/// Use `Default::default()` for the common case (skopeo transport, no
/// zero-copy requirement).
#[derive(Debug, Default)]
pub struct PullOptions<'a> {
    /// Image proxy configuration passed to skopeo (ignored for
    /// `containers-storage:` references).
    pub img_proxy_config: Option<ImageProxyConfig>,

    /// If `true`, the containers-storage import path will error instead of
    /// falling back to a data copy when neither reflink nor hardlink succeeds.
    /// Intended for bootc's unified storage layout where the composefs repo
    /// and containers-storage are always on the same filesystem.
    pub zerocopy: bool,

    /// Explicit containers-storage root.  When set, auto-discovery is skipped
    /// and only this path (plus any `additional_image_stores`) is searched.
    /// Only relevant for `containers-storage:` references.
    pub storage_root: Option<&'a std::path::Path>,

    /// Additional read-only image stores to search beyond the primary
    /// (auto-discovered or explicit) store.  Equivalent to the
    /// `additionalimagestore=` option in containers/storage.
    /// Only relevant for `containers-storage:` references.
    pub additional_image_stores: &'a [&'a std::path::Path],
}

/// Result of a pull operation.
#[derive(Debug)]
pub struct PullResult<ObjectID> {
    /// The manifest digest (sha256:...).
    pub manifest_digest: OciDigest,
    /// The fs-verity hash of the manifest splitstream.
    pub manifest_verity: ObjectID,
    /// The config digest (sha256:...).
    pub config_digest: OciDigest,
    /// The fs-verity hash of the config splitstream.
    pub config_verity: ObjectID,
    /// Import statistics.
    pub stats: ImportStats,
}

/// A tuple of (content digest, fs-verity ObjectID).
pub type ContentAndVerity<ObjectID> = (OciDigest, ObjectID);

/// Parsed OCI config and its associated references.
pub struct OpenConfig<ObjectID> {
    /// The parsed OCI image configuration.
    pub config: ImageConfiguration,
    /// Map from layer diff_id to its fs-verity object ID.
    pub layer_refs: HashMap<Box<str>, ObjectID>,
    /// The EROFS image ObjectID linked to this config, if any.
    pub image_ref: Option<ObjectID>,
    /// The boot EROFS image ObjectID linked to this config, if any.
    pub boot_image_ref: Option<ObjectID>,
}

impl<ObjectID: std::fmt::Debug> std::fmt::Debug for OpenConfig<ObjectID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenConfig")
            .field("layer_refs", &self.layer_refs)
            .field("image_ref", &self.image_ref)
            .field("boot_image_ref", &self.boot_image_ref)
            .finish_non_exhaustive()
    }
}

pub(crate) fn layer_identifier(diff_id: &OciDigest) -> String {
    format!("oci-layer-{diff_id}")
}

pub(crate) fn config_identifier(config: &OciDigest) -> String {
    format!("oci-config-{config}")
}

/// Imports a container layer from a tar stream into the repository.
///
/// Converts the tar stream into a composefs split stream format and stores it in the repository.
/// If a name is provided, creates a reference to the imported layer for easier access.
///
/// Returns the fs-verity hash value and import statistics for the stored split stream.
pub async fn import_layer<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    diff_id: &OciDigest,
    name: Option<&str>,
    tar_stream: impl tokio::io::AsyncRead + Unpin,
) -> Result<(ObjectID, ImportStats)> {
    let content_identifier = layer_identifier(diff_id);

    // Idempotency: if the stream already exists, just ensure the reference symlink
    if let Some(id) = repo.has_stream(&content_identifier)? {
        if let Some(name) = name {
            repo.name_stream(&content_identifier, name)?;
        }
        return Ok((id, ImportStats::default()));
    }

    let (object_id, stats) =
        tar::split_async(tar_stream, repo.clone(), TAR_LAYER_CONTENT_TYPE).await?;

    // Sync and register the stream with its content identifier
    repo.register_stream(&object_id, &content_identifier, name)
        .await?;

    Ok((object_id, stats))
}

/// Lists the contents of a container layer stored in the repository.
///
/// Reads the split stream for the named layer and prints each tar entry to stdout
/// in composefs dumpfile format.
pub fn ls_layer<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    diff_id: &OciDigest,
) -> Result<()> {
    let mut split_stream = repo.open_stream(
        &layer_identifier(diff_id),
        None,
        Some(TAR_LAYER_CONTENT_TYPE),
    )?;

    while let Some(entry) = get_entry(&mut split_stream)? {
        println!("{entry}");
    }

    Ok(())
}

/// Pull the target image, and add the provided tag. If this is a mountable
/// image (i.e. not an artifact), it is *not* unpacked by default.
///
/// When the `containers-storage` feature is enabled and the image reference
/// starts with `containers-storage:`, this uses the native cstor import path
/// which supports zero-copy reflinks/hardlinks. Otherwise, it uses skopeo.
///
/// See [`PullOptions`] for tunable knobs (zero-copy mode, extra storage
/// roots, image proxy configuration).
pub async fn pull<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
    opts: PullOptions<'_>,
) -> Result<PullResult<ObjectID>> {
    #[cfg(feature = "containers-storage")]
    if let Some(image_id) = cstor::parse_containers_storage_ref(imgref) {
        let (((manifest_digest, manifest_verity), (config_digest, config_verity)), stats) =
            cstor::import_from_containers_storage(
                repo,
                image_id,
                reference,
                opts.zerocopy,
                opts.storage_root,
                opts.additional_image_stores,
            )
            .await?;
        return Ok(PullResult {
            manifest_digest,
            manifest_verity,
            config_digest,
            config_verity,
            stats,
        });
    }

    let (result, stats) =
        skopeo::pull_image(repo, imgref, reference, opts.img_proxy_config).await?;
    Ok(crate::PullResult {
        manifest_digest: result.manifest_digest,
        manifest_verity: result.manifest_verity,
        config_digest: result.config_digest,
        config_verity: result.config_verity,
        stats,
    })
}

/// Convert a SHA-256 hash output to an OCI content digest.
pub(crate) fn sha256_output_to_digest(output: sha2::digest::Output<Sha256>) -> OciDigest {
    let hex = hex::encode(output);
    format!("sha256:{hex}")
        .try_into()
        .expect("sha256 hex should always produce a valid OCI digest")
}

/// Compute the SHA-256 content digest of `bytes`, returning an OCI digest
/// (e.g. `sha256:abcd...`).
pub(crate) fn sha256_content_digest(bytes: &[u8]) -> OciDigest {
    let mut context = Sha256::new();
    context.update(bytes);
    sha256_output_to_digest(context.finalize())
}

fn hash_sha256(bytes: &[u8]) -> OciDigest {
    sha256_content_digest(bytes)
}

/// Opens and parses a container configuration.
///
/// Reads the OCI image configuration from the repository and returns an [`OpenConfig`]
/// containing the parsed configuration, a digest map of layer fs-verity hashes, and an
/// optional EROFS image ObjectID if one has been linked to this config.
///
/// If verity is provided, it's used directly. Otherwise, the name must be a sha256 digest
/// and the corresponding verity hash will be looked up (which is more expensive) and the content
/// will be hashed and compared to the provided digest.
///
/// The returned layer refs map does not contain the [`IMAGE_REF_KEY`] — that is
/// returned separately in [`OpenConfig::image_ref`].
///
/// Note: if the verity value is known and trusted then the layer fs-verity values can also be
/// trusted.  If not, then you can use the layer map to find objects that are ostensibly the layers
/// in question, but you'll have to verity their content hashes yourself.
pub fn open_config<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    config_digest: &OciDigest,
    verity: Option<&ObjectID>,
) -> Result<OpenConfig<ObjectID>> {
    let (data, mut named_refs) = oci_image::read_external_splitstream(
        repo,
        &config_identifier(config_digest),
        verity,
        Some(OCI_CONFIG_CONTENT_TYPE),
    )?;

    if verity.is_none() {
        let computed = hash_sha256(&data);
        ensure!(
            *config_digest == computed,
            "Config integrity check failed: expected {config_digest}, got {computed}"
        );
    }

    let image_ref = named_refs.remove(IMAGE_REF_KEY);
    let boot_image_ref = named_refs.remove(BOOT_IMAGE_REF_KEY);
    let config = ImageConfiguration::from_reader(&data[..])?;
    Ok(OpenConfig {
        config,
        layer_refs: named_refs,
        image_ref,
        boot_image_ref,
    })
}

/// Returns the composefs EROFS ObjectID referenced by the given OCI config, if any.
pub fn composefs_erofs_for_config<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    config_digest: &OciDigest,
    verity: Option<&ObjectID>,
) -> Result<Option<ObjectID>> {
    let oc = open_config(repo, config_digest, verity)?;
    Ok(oc.image_ref)
}

/// Returns the composefs EROFS ObjectID for an OCI image identified by manifest, if any.
///
/// This opens the manifest to find the config, then reads the config's
/// [`IMAGE_REF_KEY`] named ref.
pub fn composefs_erofs_for_manifest<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    manifest_digest: &OciDigest,
    manifest_verity: Option<&ObjectID>,
) -> Result<Option<ObjectID>> {
    let img = oci_image::OciImage::open(repo, manifest_digest, manifest_verity)?;
    Ok(img.image_ref().cloned())
}

/// Returns the boot EROFS ObjectID from the given OCI config, if any.
pub fn composefs_boot_erofs_for_config<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    config_digest: &OciDigest,
    verity: Option<&ObjectID>,
) -> Result<Option<ObjectID>> {
    let oc = open_config(repo, config_digest, verity)?;
    Ok(oc.boot_image_ref)
}

/// Returns the boot EROFS ObjectID for an OCI image identified by manifest, if any.
pub fn composefs_boot_erofs_for_manifest<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    manifest_digest: &OciDigest,
    manifest_verity: Option<&ObjectID>,
) -> Result<Option<ObjectID>> {
    let img = oci_image::OciImage::open(repo, manifest_digest, manifest_verity)?;
    Ok(img.boot_image_ref().cloned())
}

/// Writes a container configuration to the repository.
///
/// Serializes the image configuration to JSON and stores it as a split stream with the
/// provided layer reference map. The configuration is stored as an external object so
/// fsverity can be independently enabled on it.
///
/// If `image` is provided, a named ref with key [`IMAGE_REF_KEY`] is added to the
/// splitstream pointing to the EROFS image's ObjectID. This ensures the GC walk keeps
/// the EROFS image alive as long as the config is reachable.
///
/// If `boot_image` is provided, a named ref with key [`BOOT_IMAGE_REF_KEY`] is added
/// pointing to the boot EROFS image's ObjectID.
///
/// Returns a tuple of (sha256 content hash, fs-verity hash value).
pub fn write_config<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    config: &ImageConfiguration,
    refs: HashMap<Box<str>, ObjectID>,
    image: Option<&ObjectID>,
    boot_image: Option<&ObjectID>,
) -> Result<ContentAndVerity<ObjectID>> {
    let json = config.to_string()?;
    write_config_raw(repo, json.as_bytes(), refs, image, boot_image)
}

/// Rewrites a container configuration in the repository from raw JSON bytes.
///
/// Like [`write_config`], but takes pre-serialized JSON bytes instead of an
/// `ImageConfiguration`. This must be used when rewriting an existing config
/// (e.g. to add EROFS image refs) to preserve the original JSON bytes and
/// avoid changing the sha256 content digest.
pub fn write_config_raw<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    config_json: &[u8],
    refs: HashMap<Box<str>, ObjectID>,
    image: Option<&ObjectID>,
    boot_image: Option<&ObjectID>,
) -> Result<ContentAndVerity<ObjectID>> {
    let config_digest = hash_sha256(config_json);
    let mut stream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE)?;
    for (name, value) in &refs {
        stream.add_named_stream_ref(name, value)
    }
    if let Some(image_id) = image {
        stream.add_named_stream_ref(IMAGE_REF_KEY, image_id);
    }
    if let Some(boot_id) = boot_image {
        stream.add_named_stream_ref(BOOT_IMAGE_REF_KEY, boot_id);
    }
    stream.write_external(config_json)?;
    let id = repo.write_stream(stream, &config_identifier(&config_digest), None)?;
    Ok((config_digest, id))
}

/// Ensures a composefs EROFS image exists for the given OCI container image,
/// linking it to the config splitstream so GC keeps it alive through the tag chain.
///
/// This performs the following steps:
/// 1. Opens the manifest and config to get the image configuration
/// 2. Creates a composefs `FileSystem` from the OCI layers
/// 3. Commits the filesystem as an EROFS image to the repository
/// 4. Rewrites the config splitstream with an [`IMAGE_REF_KEY`] named ref
///    pointing to the EROFS image's ObjectID
/// 5. Rewrites the manifest splitstream with the updated config verity
/// 6. If `tag` is provided, updates the tag to point to the new manifest
///
/// Calling this multiple times is safe — a new EROFS image is generated each
/// time (though usually identical via object dedup) and the config+manifest
/// splitstreams are rewritten. The old splitstream objects become unreferenced
/// and are collected by the next GC.
///
/// Returns the EROFS image's ObjectID (fs-verity digest).
fn ensure_oci_composefs_erofs<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    manifest_digest: &OciDigest,
    manifest_verity: Option<&ObjectID>,
    tag: Option<&str>,
) -> Result<Option<ObjectID>> {
    let img = oci_image::OciImage::open(repo, manifest_digest, manifest_verity)?;
    if !img.is_container_image() {
        return Ok(None);
    }

    // Build the composefs filesystem from all layers
    let fs = image::create_filesystem(repo, img.config_digest(), Some(img.config_verity()))?;

    // Commit as EROFS image (no name — the GC link comes from the config ref)
    let erofs_id = fs.commit_image(repo, None)?;

    // Read original config JSON to preserve its exact bytes (and thus its
    // sha256 digest) when rewriting the splitstream with the new EROFS ref.
    let config_json = img.read_config_json(repo)?;

    // Rewrite config with the EROFS image ref, using layer refs from the
    // OciImage (which already stripped the old image ref if any).
    // Preserve any existing boot image ref.
    let (_config_digest, new_config_verity) = write_config_raw(
        repo,
        &config_json,
        img.layer_refs().clone(),
        Some(&erofs_id),
        img.boot_image_ref(),
    )?;

    // Read original manifest JSON for rewriting
    let manifest_json = img.read_manifest_json(repo)?;

    // Rewrite manifest with updated config verity, preserving layer verities.
    // The layer_refs from OciImage are the same as the manifest's layer refs
    // (both ultimately come from the config's diff_id → verity map).
    let layer_verities = img.layer_refs().clone();

    let (_new_manifest_digest, _new_manifest_verity) = oci_image::rewrite_manifest(
        repo,
        &manifest_json,
        manifest_digest,
        &new_config_verity,
        &layer_verities,
        tag,
    )?;

    Ok(Some(erofs_id))
}

/// Boot-variant counterpart to [`ensure_oci_composefs_erofs`]; applies
/// `transform_for_boot` before committing.
#[cfg(feature = "boot")]
fn ensure_oci_composefs_erofs_boot<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    manifest_digest: &OciDigest,
    manifest_verity: Option<&ObjectID>,
    tag: Option<&str>,
) -> Result<Option<ObjectID>> {
    use composefs_boot::BootOps;

    let img = oci_image::OciImage::open(repo, manifest_digest, manifest_verity)?;
    if !img.is_container_image() {
        return Ok(None);
    }

    // Build the composefs filesystem from all layers, then transform for boot
    let mut fs = image::create_filesystem(repo, img.config_digest(), Some(img.config_verity()))?;
    fs.transform_for_boot(repo)?;

    // Commit as EROFS image
    let boot_erofs_id = fs.commit_image(repo, None)?;

    // Read original config JSON to preserve its exact bytes
    let config_json = img.read_config_json(repo)?;

    // Rewrite config with the boot EROFS image ref, preserving the existing image ref
    let (_config_digest, new_config_verity) = write_config_raw(
        repo,
        &config_json,
        img.layer_refs().clone(),
        img.image_ref(),
        Some(&boot_erofs_id),
    )?;

    // Read original manifest JSON for rewriting
    let manifest_json = img.read_manifest_json(repo)?;

    let layer_verities = img.layer_refs().clone();

    let (_new_manifest_digest, _new_manifest_verity) = oci_image::rewrite_manifest(
        repo,
        &manifest_json,
        manifest_digest,
        &new_config_verity,
        &layer_verities,
        tag,
    )?;

    Ok(Some(boot_erofs_id))
}

#[cfg(test)]
mod test {
    use std::{fmt::Write, io::Read};

    use rustix::fs::CWD;

    use composefs::{fsverity::Sha256HashValue, repository::Repository, test::tempdir};

    use super::*;

    /// Create a test repository with meta.json in insecure mode.
    fn create_test_repo() -> (tempfile::TempDir, Arc<Repository<Sha256HashValue>>) {
        let dir = tempdir();
        let repo_path = dir.path().join("repo");
        let (repo, _) = Repository::init_path(
            CWD,
            &repo_path,
            composefs::fsverity::Algorithm::SHA256,
            false,
        )
        .expect("initializing test repo");
        (dir, Arc::new(repo))
    }

    fn append_data(builder: &mut ::tar::Builder<Vec<u8>>, name: &str, size: usize) {
        let mut header = ::tar::Header::new_ustar();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o700);
        header.set_entry_type(::tar::EntryType::Regular);
        header.set_size(size as u64);
        builder
            .append_data(&mut header, name, std::io::repeat(0u8).take(size as u64))
            .unwrap();
    }

    fn example_layer() -> Vec<u8> {
        let mut builder = ::tar::Builder::new(vec![]);
        append_data(&mut builder, "file0", 0);
        append_data(&mut builder, "file4095", 4095);
        append_data(&mut builder, "file4096", 4096);
        append_data(&mut builder, "file4097", 4097);
        builder.into_inner().unwrap()
    }

    #[tokio::test]
    async fn test_layer() {
        let layer = example_layer();
        let layer_id = hash_sha256(&layer);

        let (_repo_dir, repo) = create_test_repo();
        let (id, _stats) = import_layer(&repo, &layer_id, Some("name"), &layer[..])
            .await
            .unwrap();

        let mut dump = String::new();
        let mut split_stream = repo.open_stream("refs/name", Some(&id), None).unwrap();
        while let Some(entry) = tar::get_entry(&mut split_stream).unwrap() {
            writeln!(dump, "{entry}").unwrap();
        }
        similar_asserts::assert_eq!(dump, "\
/file0 0 100700 1 0 0 0 0.0 - - -
/file4095 4095 100700 1 0 0 0 0.0 53/72beb83c78537c8970c8361e3254119fafdf1763854ecd57d3f0fe2da7c719 - 5372beb83c78537c8970c8361e3254119fafdf1763854ecd57d3f0fe2da7c719
/file4096 4096 100700 1 0 0 0 0.0 ba/bc284ee4ffe7f449377fbf6692715b43aec7bc39c094a95878904d34bac97e - babc284ee4ffe7f449377fbf6692715b43aec7bc39c094a95878904d34bac97e
/file4097 4097 100700 1 0 0 0 0.0 09/3756e4ea9683329106d4a16982682ed182c14bf076463a9e7f97305cbac743 - 093756e4ea9683329106d4a16982682ed182c14bf076463a9e7f97305cbac743
");
    }

    #[test]
    fn test_write_and_open_config() {
        use containers_image_proxy::oci_spec::image::{ImageConfigurationBuilder, RootFsBuilder};

        let (_repo_dir, repo) = create_test_repo();

        let rootfs = RootFsBuilder::default()
            .typ("layers")
            .diff_ids(vec!["sha256:abc123def456".to_string()])
            .build()
            .unwrap();

        let config = ImageConfigurationBuilder::default()
            .architecture("amd64")
            .os("linux")
            .rootfs(rootfs)
            .build()
            .unwrap();

        let mut refs = HashMap::new();
        refs.insert("sha256:abc123def456".into(), Sha256HashValue::EMPTY);

        let (config_digest, config_verity) =
            write_config(&repo, &config, refs.clone(), None, None).unwrap();

        assert!(config_digest.as_ref().starts_with("sha256:"));

        let oc = open_config(&repo, &config_digest, Some(&config_verity)).unwrap();
        assert_eq!(oc.config.architecture().to_string(), "amd64");
        assert_eq!(oc.config.os().to_string(), "linux");
        assert_eq!(oc.layer_refs.len(), 1);
        assert!(oc.layer_refs.contains_key("sha256:abc123def456"));
        assert!(oc.image_ref.is_none());
        assert!(oc.boot_image_ref.is_none());

        let oc2 = open_config(&repo, &config_digest, None).unwrap();
        assert_eq!(oc2.config.architecture().to_string(), "amd64");
    }

    #[test]
    fn test_config_stored_as_external_object() {
        use containers_image_proxy::oci_spec::image::{ImageConfigurationBuilder, RootFsBuilder};

        let (_repo_dir, repo) = create_test_repo();

        let rootfs = RootFsBuilder::default()
            .typ("layers")
            .diff_ids(vec![])
            .build()
            .unwrap();

        let config = ImageConfigurationBuilder::default()
            .architecture("amd64")
            .os("linux")
            .rootfs(rootfs)
            .build()
            .unwrap();

        let (config_digest, config_verity) =
            write_config(&repo, &config, HashMap::new(), None, None).unwrap();

        // Re-open the splitstream and check that the config JSON is stored
        // as an external object reference (not inline). This is important
        // because external objects get their own file in objects/, which
        // allows fsverity to be independently enabled on the raw content —
        // a prerequisite for signing the config by its fsverity digest.
        let mut stream = repo
            .open_stream(
                &config_identifier(&config_digest),
                Some(&config_verity),
                Some(crate::skopeo::OCI_CONFIG_CONTENT_TYPE),
            )
            .unwrap();

        let mut object_refs = Vec::new();
        stream
            .get_object_refs(|id| object_refs.push(id.clone()))
            .unwrap();

        // The config JSON should appear as exactly one external object
        assert_eq!(
            object_refs.len(),
            1,
            "Config should be stored as one external object, got {} refs",
            object_refs.len()
        );

        // The external object's fsverity digest should match what we'd
        // compute independently from the raw JSON bytes
        let json_bytes = config.to_string().unwrap();
        let expected_verity: Sha256HashValue =
            composefs::fsverity::compute_verity(json_bytes.as_bytes());
        assert_eq!(
            object_refs[0], expected_verity,
            "External object verity should match independently computed verity of config JSON"
        );
    }

    #[test]
    fn test_open_config_bad_hash() {
        use containers_image_proxy::oci_spec::image::{ImageConfigurationBuilder, RootFsBuilder};

        let (_repo_dir, repo) = create_test_repo();

        let rootfs = RootFsBuilder::default()
            .typ("layers")
            .diff_ids(vec![])
            .build()
            .unwrap();

        let config = ImageConfigurationBuilder::default()
            .architecture("amd64")
            .os("linux")
            .rootfs(rootfs)
            .build()
            .unwrap();

        let (config_digest, _config_verity) =
            write_config(&repo, &config, HashMap::new(), None, None).unwrap();

        let bad_digest: OciDigest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap();
        let result = open_config::<Sha256HashValue>(&repo, &bad_digest, None);
        assert!(result.is_err());

        let result = open_config::<Sha256HashValue>(&repo, &config_digest, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_with_image_ref() {
        use containers_image_proxy::oci_spec::image::{ImageConfigurationBuilder, RootFsBuilder};

        let (_repo_dir, repo) = create_test_repo();

        let rootfs = RootFsBuilder::default()
            .typ("layers")
            .diff_ids(vec!["sha256:abc123def456".to_string()])
            .build()
            .unwrap();

        let config = ImageConfigurationBuilder::default()
            .architecture("amd64")
            .os("linux")
            .rootfs(rootfs)
            .build()
            .unwrap();

        let mut refs = HashMap::new();
        let layer_id = Sha256HashValue::EMPTY;
        refs.insert("sha256:abc123def456".into(), layer_id);

        // Use a fake EROFS image ID
        let fake_erofs_id: Sha256HashValue =
            composefs::fsverity::compute_verity(b"fake-erofs-image");

        let (config_digest, config_verity) =
            write_config(&repo, &config, refs.clone(), Some(&fake_erofs_id), None).unwrap();

        // Reopen and verify
        let oc = open_config(&repo, &config_digest, Some(&config_verity)).unwrap();
        assert_eq!(
            oc.layer_refs.len(),
            1,
            "layer refs should not include image ref"
        );
        assert!(oc.layer_refs.contains_key("sha256:abc123def456"));
        assert_eq!(
            oc.image_ref,
            Some(fake_erofs_id.clone()),
            "image ref should be returned"
        );

        // Also verify via the convenience function
        let img_ref =
            composefs_erofs_for_config(&repo, &config_digest, Some(&config_verity)).unwrap();
        assert_eq!(img_ref, Some(fake_erofs_id));
    }

    #[test]
    fn test_config_without_image_ref() {
        use containers_image_proxy::oci_spec::image::{ImageConfigurationBuilder, RootFsBuilder};

        let (_repo_dir, repo) = create_test_repo();

        let rootfs = RootFsBuilder::default()
            .typ("layers")
            .diff_ids(vec!["sha256:abc123def456".to_string()])
            .build()
            .unwrap();

        let config = ImageConfigurationBuilder::default()
            .architecture("amd64")
            .os("linux")
            .rootfs(rootfs)
            .build()
            .unwrap();

        let mut refs = HashMap::new();
        refs.insert("sha256:abc123def456".into(), Sha256HashValue::EMPTY);

        let (config_digest, config_verity) =
            write_config(&repo, &config, refs.clone(), None, None).unwrap();

        let oc = open_config(&repo, &config_digest, Some(&config_verity)).unwrap();
        assert_eq!(oc.layer_refs.len(), 1);
        assert!(oc.layer_refs.contains_key("sha256:abc123def456"));
        assert!(oc.image_ref.is_none(), "no image ref should be present");

        let img_ref =
            composefs_erofs_for_config(&repo, &config_digest, Some(&config_verity)).unwrap();
        assert!(img_ref.is_none());
    }

    #[tokio::test]
    async fn test_ensure_oci_composefs_erofs() {
        use composefs::test::TestRepo;

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = test_util::create_base_image(repo, Some("test:v1")).await;

        // Create the EROFS image and link it to the config
        let erofs_id = ensure_oci_composefs_erofs(
            repo,
            &img.manifest_digest,
            Some(&img.manifest_verity),
            Some("test:v1"),
        )
        .unwrap()
        .expect("container image should produce EROFS");

        // The EROFS image should exist in the repository
        assert!(
            repo.open_image(&erofs_id.to_hex()).is_ok(),
            "EROFS image should be accessible"
        );

        // The manifest+config were rewritten with the EROFS ref
        let oci = oci_image::OciImage::open_ref(repo, "test:v1").unwrap();
        assert_ne!(
            oci.manifest_verity(),
            &img.manifest_verity,
            "manifest should have been rewritten with new config verity"
        );
        assert_eq!(
            oci.image_ref(),
            Some(&erofs_id),
            "config should reference the EROFS image"
        );
        // Also verify via the convenience functions
        let erofs_ref =
            composefs_erofs_for_config(repo, oci.config_digest(), Some(oci.config_verity()))
                .unwrap();
        assert_eq!(erofs_ref, Some(erofs_id.clone()));

        let erofs_ref2 =
            composefs_erofs_for_manifest(repo, &img.manifest_digest, Some(oci.manifest_verity()))
                .unwrap();
        assert_eq!(erofs_ref2, Some(erofs_id.clone()));

        // Verify the EROFS content by round-tripping through erofs_to_filesystem
        let erofs_data = repo.read_object(&erofs_id).unwrap();
        let fs =
            composefs::erofs::reader::erofs_to_filesystem::<Sha256HashValue>(&erofs_data).unwrap();
        let mut dump = Vec::new();
        composefs::dumpfile::write_dumpfile(&mut dump, &fs).unwrap();
        let dump = String::from_utf8(dump).unwrap();
        similar_asserts::assert_eq!(
            dump,
            "\
/ 0 40755 6 0 0 0 0.0 - - -
/etc 0 40755 2 0 0 0 0.0 - - -
/etc/hostname 9 100644 1 0 0 0 0.0 - test-host -
/etc/os-release 23 100644 1 0 0 0 0.0 - ID=test\\nVERSION_ID=1.0\\n -
/etc/passwd 100 100644 1 0 0 0 0.0 f2/c4fd5735bd46db3b18d402ae87c5086c97c0e1321901cfd30f320b73ef25aa - f2c4fd5735bd46db3b18d402ae87c5086c97c0e1321901cfd30f320b73ef25aa
/tmp 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 5 0 0 0 0.0 - - -
/usr/bin 0 40755 2 0 0 0 0.0 - - -
/usr/bin/busybox 4096 100755 1 0 0 0 0.0 f0/f7e1e58fdd31f5792222087377a4a976760c416ecdf5f426193e608681b7a1 - f0f7e1e58fdd31f5792222087377a4a976760c416ecdf5f426193e608681b7a1
/usr/bin/cat 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/cp 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/ls 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/mv 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/ping 7 120777 1 0 0 0 0.0 busybox - - security.capability=\\x02\\x00\\x00\\x02\\x00\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00
/usr/bin/rm 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/sh 7 120777 1 0 0 0 0.0 busybox - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/share 0 40755 3 0 0 0 0.0 - - -
/usr/share/doc 0 40755 2 0 0 0 0.0 - - -
/usr/share/doc/README 512 100644 1 0 0 0 0.0 51/44b8f80be57c3518f410d930e18c4e405387c82e4993c18265a1ba4a80263b - 5144b8f80be57c3518f410d930e18c4e405387c82e4993c18265a1ba4a80263b
/var 0 40755 3 0 0 0 0.0 - - -
/var/data 0 40755 2 0 0 0 0.0 - - -
/var/data/app.json 256 100644 1 0 0 0 0.0 c9/21965b74ac1780bc437cec640b27186d85317b9afdb3dbb68626aed5ecd2b6 - c921965b74ac1780bc437cec640b27186d85317b9afdb3dbb68626aed5ecd2b6
"
        );
    }

    #[tokio::test]
    async fn test_ensure_oci_composefs_erofs_gc() {
        use composefs::test::TestRepo;

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = test_util::create_base_image(repo, Some("gctest:v1")).await;

        // After pull, nothing is garbage
        let dry = repo.gc_dry_run(&[]).unwrap();
        assert_eq!(dry.objects_removed, 0);
        assert_eq!(dry.streams_pruned, 0);
        assert_eq!(dry.images_pruned, 0);

        let erofs_id = ensure_oci_composefs_erofs(
            repo,
            &img.manifest_digest,
            Some(&img.manifest_verity),
            Some("gctest:v1"),
        )
        .unwrap()
        .expect("container image should produce EROFS");

        // ensure_oci_composefs_erofs rewrites config+manifest, leaving 2 old splitstream
        // objects unreferenced (the original config and manifest splitstreams)
        let gc1 = repo.gc(&[]).unwrap();
        assert_eq!(
            gc1.objects_removed, 2,
            "old config+manifest splitstream objects"
        );
        assert_eq!(gc1.streams_pruned, 0);
        assert_eq!(gc1.images_pruned, 0);

        // After GC, everything is clean — EROFS survives via config ref
        let dry = repo.gc_dry_run(&[]).unwrap();
        assert_eq!(dry.objects_removed, 0);
        assert!(
            repo.open_image(&erofs_id.to_hex()).is_ok(),
            "EROFS image should survive GC while tagged"
        );

        // Untag and GC — everything gets collected
        oci_image::untag_image(repo, "gctest:v1").unwrap();
        let gc2 = repo.gc(&[]).unwrap();
        // 14 objects: 5 layer splitstreams + 4 external file objects
        //   + config JSON + manifest JSON + EROFS image
        //   + new config splitstream + new manifest splitstream
        assert_eq!(gc2.objects_removed, 14, "all objects collected after untag");
        // 7 streams: 5 layers + 1 config + 1 manifest (tag ref removed by untag)
        assert_eq!(gc2.streams_pruned, 7, "all stream symlinks pruned");
        // 1 image: the EROFS symlink under images/
        assert_eq!(gc2.images_pruned, 1, "EROFS image symlink pruned");

        assert!(
            repo.open_image(&erofs_id.to_hex()).is_err(),
            "EROFS image should be collected after untag + GC"
        );

        // Repo is completely empty now
        let dry = repo.gc_dry_run(&[]).unwrap();
        assert_eq!(dry.objects_removed, 0);
        assert_eq!(dry.streams_pruned, 0);
        assert_eq!(dry.images_pruned, 0);
    }

    /// Verify that rewriting a config splitstream (to add an EROFS image ref)
    /// preserves the original config JSON bytes — even when those bytes use
    /// non-canonical formatting that differs from `ImageConfiguration::to_string()`.
    ///
    /// Regression test: `ensure_oci_composefs_erofs` previously re-serialized
    /// the config through `config.to_string()`, producing different bytes (and
    /// a different sha256 digest), which caused `oci fsck` to report a
    /// `config-digest-mismatch`.
    #[tokio::test]
    async fn test_config_rewrite_preserves_noncanonical_json() {
        use composefs::test::TestRepo;
        use serde_json::ser::{PrettyFormatter, Serializer};

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create a normal image with well-formed layers
        let _img = test_util::create_base_image(repo, Some("nc:v1")).await;

        // Read back the original config JSON
        let oci_before = oci_image::OciImage::open_ref(repo, "nc:v1").unwrap();
        let canonical_json = oci_before.read_config_json(repo).unwrap();

        // Re-serialize through serde_json::Value with PrettyFormatter to
        // get different bytes (tab indentation) while remaining
        // semantically identical JSON.
        let value: serde_json::Value = serde_json::from_slice(&canonical_json).unwrap();
        let mut buf = Vec::new();
        let formatter = PrettyFormatter::with_indent(b"\t");
        let mut ser = Serializer::with_formatter(&mut buf, formatter);
        serde::Serialize::serialize(&value, &mut ser).unwrap();
        let noncanonical_json = buf;

        // Sanity: the two serializations must differ in bytes but parse
        // identically.
        assert_ne!(
            canonical_json.as_slice(),
            noncanonical_json.as_slice(),
            "pretty-printed JSON should differ from canonical"
        );
        let reparsed: serde_json::Value = serde_json::from_slice(&noncanonical_json).unwrap();
        assert_eq!(value, reparsed, "non-canonical JSON must parse identically");

        // Now overwrite the config splitstream with the non-canonical bytes.
        let (_new_config_digest, new_config_verity) = write_config_raw(
            repo,
            &noncanonical_json,
            oci_before.layer_refs().clone(),
            None,
            None,
        )
        .unwrap();
        let new_config_digest = hash_sha256(&noncanonical_json);

        // Rewrite the manifest to reference the non-canonical config.
        use containers_image_proxy::oci_spec::image::{
            DescriptorBuilder, ImageManifestBuilder, MediaType,
        };

        let old_manifest = oci_before.manifest();
        let config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageConfig)
            .digest(new_config_digest.clone())
            .size(noncanonical_json.len() as u64)
            .build()
            .unwrap();
        let new_manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(config_descriptor)
            .layers(old_manifest.layers().clone())
            .build()
            .unwrap();

        let new_manifest_json = new_manifest.to_string().unwrap();
        let new_manifest_digest = hash_sha256(new_manifest_json.as_bytes());

        oci_image::untag_image(repo, "nc:v1").unwrap();
        let (_md, new_manifest_verity) = oci_image::write_manifest(
            repo,
            &new_manifest,
            &new_manifest_digest,
            &new_config_verity,
            oci_before.layer_refs(),
            Some("nc:v1"),
        )
        .unwrap();

        // Now the real test: ensure_oci_composefs_erofs rewrites the config
        // to add an EROFS image ref.  The config digest MUST be preserved.
        let erofs_id = ensure_oci_composefs_erofs(
            repo,
            &new_manifest_digest,
            Some(&new_manifest_verity),
            Some("nc:v1"),
        )
        .unwrap()
        .expect("should produce EROFS");

        let oci_after = oci_image::OciImage::open_ref(repo, "nc:v1").unwrap();
        assert_eq!(
            oci_after.config_digest(),
            &new_config_digest,
            "config digest must be preserved after EROFS rewrite"
        );
        assert_eq!(oci_after.image_ref(), Some(&erofs_id));

        let stored_json = oci_after.read_config_json(repo).unwrap();
        assert_eq!(
            stored_json, noncanonical_json,
            "raw config JSON bytes must survive round-trip through EROFS rewrite"
        );
    }

    #[test]
    fn test_import_stats_display() {
        // Copy-only stats (no reflinks)
        let stats = ImportStats {
            objects_copied: 42,
            objects_already_present: 100,
            bytes_copied: 1_500_000,
            bytes_inlined: 800,
            ..Default::default()
        };
        assert_eq!(
            stats.to_string(),
            "42 new + 100 already present objects; 1.43 MiB stored, 800 B inlined"
        );
        assert_eq!(stats.total_objects(), 142);
        assert_eq!(stats.new_objects(), 42);
        assert_eq!(stats.new_bytes(), 1_500_000);

        // Stats with reflinks
        let reflink_stats = ImportStats {
            objects_reflinked: 30,
            objects_copied: 12,
            objects_already_present: 100,
            bytes_reflinked: 1_000_000,
            bytes_copied: 500_000,
            bytes_inlined: 800,
            ..Default::default()
        };
        assert_eq!(
            reflink_stats.to_string(),
            "30 reflinked + 12 copied + 100 already present objects; 976.56 KiB reflinked, 488.28 KiB copied, 800 B inlined"
        );
        assert_eq!(reflink_stats.total_objects(), 142);
        assert_eq!(reflink_stats.new_objects(), 42);
        assert_eq!(reflink_stats.new_bytes(), 1_500_000);

        // Stats with hardlinks only
        let hardlink_stats = ImportStats {
            objects_hardlinked: 20,
            objects_copied: 5,
            objects_already_present: 50,
            bytes_hardlinked: 800_000,
            bytes_copied: 200_000,
            bytes_inlined: 400,
            ..Default::default()
        };
        assert_eq!(
            hardlink_stats.to_string(),
            "20 hardlinked + 5 copied + 50 already present objects; 781.25 KiB hardlinked, 195.31 KiB copied, 400 B inlined"
        );
        assert_eq!(hardlink_stats.total_objects(), 75);
        assert_eq!(hardlink_stats.new_objects(), 25);
        assert_eq!(hardlink_stats.new_bytes(), 1_000_000);

        // Stats with both reflinks and hardlinks
        let mixed_stats = ImportStats {
            objects_reflinked: 10,
            objects_hardlinked: 15,
            objects_copied: 5,
            objects_already_present: 70,
            bytes_reflinked: 500_000,
            bytes_hardlinked: 750_000,
            bytes_copied: 250_000,
            bytes_inlined: 600,
            ..Default::default()
        };
        assert_eq!(
            mixed_stats.to_string(),
            "10 reflinked + 15 hardlinked + 5 copied + 70 already present objects; 488.28 KiB reflinked, 732.42 KiB hardlinked, 244.14 KiB copied, 600 B inlined"
        );
        assert_eq!(mixed_stats.total_objects(), 100);
        assert_eq!(mixed_stats.new_objects(), 30);
        assert_eq!(mixed_stats.new_bytes(), 1_500_000);

        let empty = ImportStats::default();
        assert_eq!(
            empty.to_string(),
            "0 new + 0 already present objects; 0 B stored, 0 B inlined"
        );
        assert_eq!(empty.total_objects(), 0);
    }

    /// End-to-end test: multi-layer OCI image with nontrivial whiteout usage.
    ///
    /// Builds three tar layers exercising individual file whiteouts (`.wh.<name>`)
    /// and opaque directory whiteouts (`.wh..wh..opq`), imports them through the
    /// full OCI pipeline (tar → splitstream → OCI config/manifest → EROFS), and
    /// verifies the resulting filesystem contains exactly the expected files.
    #[tokio::test]
    async fn test_whiteout_multi_layer_import() {
        use composefs::test::TestRepo;
        use containers_image_proxy::oci_spec::image::{
            ConfigBuilder, DescriptorBuilder, ImageConfigurationBuilder, ImageManifestBuilder,
            MediaType, RootFsBuilder,
        };

        // --- Tar builder helpers (local to this test) ---

        fn tar_dir(builder: &mut ::tar::Builder<Vec<u8>>, name: &str) {
            let mut header = ::tar::Header::new_ustar();
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o755);
            header.set_entry_type(::tar::EntryType::Directory);
            header.set_size(0);
            builder
                .append_data(&mut header, name, std::io::empty())
                .unwrap();
        }

        fn tar_file(builder: &mut ::tar::Builder<Vec<u8>>, name: &str, content: &[u8]) {
            let mut header = ::tar::Header::new_ustar();
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o644);
            header.set_entry_type(::tar::EntryType::Regular);
            header.set_size(content.len() as u64);
            builder.append_data(&mut header, name, content).unwrap();
        }

        /// Zero-length regular file — used for `.wh.<name>` and `.wh..wh..opq` entries.
        fn tar_whiteout(builder: &mut ::tar::Builder<Vec<u8>>, name: &str) {
            tar_file(builder, name, &[]);
        }

        // --- Build the three layers ---

        // Layer 1 (base): create initial filesystem
        let layer1 = {
            let mut b = ::tar::Builder::new(vec![]);
            tar_dir(&mut b, "etc");
            tar_file(&mut b, "etc/config.toml", b"[server]\nport = 8080\n");
            tar_file(&mut b, "etc/hosts", b"127.0.0.1 localhost\n");
            tar_dir(&mut b, "usr");
            tar_dir(&mut b, "usr/bin");
            tar_file(&mut b, "usr/bin/app", b"#!/bin/sh\necho hello\n");
            tar_dir(&mut b, "usr/lib");
            tar_file(&mut b, "usr/lib/old-lib.so", b"fake-old-lib-content");
            tar_file(&mut b, "usr/lib/shared.so", b"fake-shared-lib-content");
            tar_dir(&mut b, "tmp");
            tar_dir(&mut b, "tmp/cache");
            tar_file(&mut b, "tmp/cache/data.bin", b"cached-data-payload");
            tar_file(&mut b, "tmp/cache/index.db", b"cached-index-payload");
            b.into_inner().unwrap()
        };

        // Layer 2 (whiteout + modify):
        //  - delete /etc/hosts (file whiteout)
        //  - delete /usr/lib/old-lib.so (file whiteout)
        //  - add /etc/hosts.new (replacement)
        //  - opaque whiteout on /tmp/cache (clears data.bin + index.db)
        //  - add /tmp/cache/fresh.bin (re-populate after opaque)
        let layer2 = {
            let mut b = ::tar::Builder::new(vec![]);
            tar_dir(&mut b, "etc");
            tar_whiteout(&mut b, "etc/.wh.hosts");
            tar_file(&mut b, "etc/hosts.new", b"127.0.0.1 localhost.new\n");
            tar_dir(&mut b, "usr");
            tar_dir(&mut b, "usr/lib");
            tar_whiteout(&mut b, "usr/lib/.wh.old-lib.so");
            tar_dir(&mut b, "tmp");
            tar_dir(&mut b, "tmp/cache");
            tar_whiteout(&mut b, "tmp/cache/.wh..wh..opq");
            tar_file(&mut b, "tmp/cache/fresh.bin", b"fresh-cache-content");
            b.into_inner().unwrap()
        };

        // Layer 3 (more whiteouts):
        //  - delete /usr/bin/app (file whiteout)
        //  - add /usr/bin/app-v2 (replacement)
        let layer3 = {
            let mut b = ::tar::Builder::new(vec![]);
            tar_dir(&mut b, "usr");
            tar_dir(&mut b, "usr/bin");
            tar_whiteout(&mut b, "usr/bin/.wh.app");
            tar_file(&mut b, "usr/bin/app-v2", b"#!/bin/sh\necho hello v2\n");
            b.into_inner().unwrap()
        };

        // --- Import layers and build OCI image ---

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let layers_data = [&layer1[..], &layer2[..], &layer3[..]];
        let mut layer_digests = Vec::new();
        let mut layer_verities_map: HashMap<Box<str>, composefs::fsverity::Sha256HashValue> =
            HashMap::new();
        let mut layer_descriptors = Vec::new();

        for tar_data in &layers_data {
            let digest = hash_sha256(tar_data);
            let (verity, _stats) = import_layer(repo, &digest, None, *tar_data).await.unwrap();

            let descriptor = DescriptorBuilder::default()
                .media_type(MediaType::ImageLayerGzip)
                .digest(digest.clone())
                .size(tar_data.len() as u64)
                .build()
                .unwrap();

            layer_verities_map.insert(digest.to_string().into_boxed_str(), verity);
            layer_digests.push(digest.to_string());
            layer_descriptors.push(descriptor);
        }

        // Build OCI config
        let rootfs = RootFsBuilder::default()
            .typ("layers")
            .diff_ids(layer_digests.clone())
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
        let config_digest = hash_sha256(config_json.as_bytes());

        let mut config_stream = repo.create_stream(skopeo::OCI_CONFIG_CONTENT_TYPE).unwrap();
        for (digest, verity) in &layer_verities_map {
            config_stream.add_named_stream_ref(digest, verity);
        }
        config_stream
            .write_external(config_json.as_bytes())
            .unwrap();
        let config_verity = repo
            .write_stream(config_stream, &config_identifier(&config_digest), None)
            .unwrap();

        // Build OCI manifest
        let config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageConfig)
            .digest(config_digest.clone())
            .size(config_json.len() as u64)
            .build()
            .unwrap();

        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(config_descriptor)
            .layers(layer_descriptors)
            .build()
            .unwrap();

        let manifest_json = manifest.to_string().unwrap();
        let manifest_digest = hash_sha256(manifest_json.as_bytes());

        let (_stored_digest, manifest_verity) = oci_image::write_manifest(
            repo,
            &manifest,
            &manifest_digest,
            &config_verity,
            &layer_verities_map,
            Some("whiteout-test:v1"),
        )
        .unwrap();

        // --- Create the EROFS image ---

        let erofs_id = ensure_oci_composefs_erofs(
            repo,
            &manifest_digest,
            Some(&manifest_verity),
            Some("whiteout-test:v1"),
        )
        .unwrap()
        .expect("container image should produce EROFS");

        // --- Verify the flattened filesystem ---

        let erofs_data = repo.read_object(&erofs_id).unwrap();
        let fs =
            composefs::erofs::reader::erofs_to_filesystem::<Sha256HashValue>(&erofs_data).unwrap();
        let mut dump = Vec::new();
        composefs::dumpfile::write_dumpfile(&mut dump, &fs).unwrap();
        let dump = String::from_utf8(dump).unwrap();

        // Extract just the paths from the dumpfile for structural verification
        let paths: Vec<&str> = dump.lines().map(|l| l.split_once(' ').unwrap().0).collect();

        // Files that SHOULD exist after all three layers
        let expected_present = [
            "/",
            "/etc",
            "/etc/config.toml", // layer 1, survived
            "/etc/hosts.new",   // layer 2 addition
            "/tmp",
            "/tmp/cache",
            "/tmp/cache/fresh.bin", // layer 2, after opaque whiteout
            "/usr",
            "/usr/bin",
            "/usr/bin/app-v2", // layer 3 replacement
            "/usr/lib",
            "/usr/lib/shared.so", // layer 1, survived
        ];

        // Files that MUST NOT exist (removed by whiteouts)
        let must_not_exist = [
            "/etc/hosts",          // deleted by layer 2 file whiteout
            "/usr/lib/old-lib.so", // deleted by layer 2 file whiteout
            "/usr/bin/app",        // deleted by layer 3 file whiteout
            "/tmp/cache/data.bin", // cleared by layer 2 opaque whiteout
            "/tmp/cache/index.db", // cleared by layer 2 opaque whiteout
        ];

        similar_asserts::assert_eq!(paths, expected_present);

        for path in &must_not_exist {
            assert!(
                !paths.contains(path),
                "{path} should have been removed by whiteout but is still present"
            );
        }
    }
}
