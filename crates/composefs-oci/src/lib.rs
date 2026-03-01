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
//! - Sealing containers with fs-verity hashes for integrity verification
//! - Importing from containers-storage with zero-copy reflinks (optional feature)

#![forbid(unsafe_code)]

#[cfg(feature = "containers-storage")]
pub mod cstor;
pub mod image;
pub mod oci_image;
pub mod skopeo;
pub mod tar;

use std::{collections::HashMap, io::Read, sync::Arc};

use anyhow::{bail, ensure, Context, Result};
use containers_image_proxy::ImageProxyConfig;
use oci_spec::image::ImageConfiguration;
use sha2::{Digest, Sha256};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::{ObjectStoreMethod, Repository},
    splitstream::SplitStreamStats,
};

use crate::skopeo::{OCI_CONFIG_CONTENT_TYPE, TAR_LAYER_CONTENT_TYPE};
use crate::tar::get_entry;

// Re-export key types for convenience
pub use oci_image::{
    add_referrer, layer_dumpfile, layer_info, layer_tar, list_images, list_referrers, list_refs,
    remove_referrer, remove_referrers_for_subject, resolve_ref, tag_image, untag_image, ImageInfo,
    LayerInfo, OciImage, SplitstreamInfo, OCI_REF_PREFIX,
};
pub use skopeo::pull_image;

/// Statistics from an image import operation.
#[derive(Debug, Clone, Default)]
pub struct ImportStats {
    /// Number of objects stored via copy.
    pub objects_copied: u64,
    /// Number of objects that already existed (deduplicated).
    pub objects_already_present: u64,
    /// Total bytes stored as new objects.
    pub bytes_copied: u64,
    /// Total bytes inlined in splitstreams (small files + headers).
    pub bytes_inlined: u64,
}

impl ImportStats {
    /// Merge another `ImportStats` into this one.
    pub fn merge(&mut self, other: &ImportStats) {
        self.objects_copied += other.objects_copied;
        self.objects_already_present += other.objects_already_present;
        self.bytes_copied += other.bytes_copied;
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
                ObjectStoreMethod::Copied | ObjectStoreMethod::Reflinked => {
                    stats.objects_copied += 1;
                    stats.bytes_copied += size;
                }
                ObjectStoreMethod::AlreadyPresent => {
                    stats.objects_already_present += 1;
                }
            }
        }
        stats
    }
}

// Re-export the composefs crate for consumers who only need composefs-oci
pub use composefs;

/// A tuple of (content digest, fs-verity ObjectID).
pub type ContentAndVerity<ObjectID> = (String, ObjectID);

pub(crate) fn layer_identifier(diff_id: &str) -> String {
    format!("oci-layer-{diff_id}")
}

pub(crate) fn config_identifier(config: &str) -> String {
    format!("oci-config-{config}")
}

/// Imports a container layer from a tar stream into the repository.
///
/// Converts the tar stream into a composefs split stream format and stores it in the repository.
/// If a name is provided, creates a reference to the imported layer for easier access.
///
/// Returns the fs-verity hash value and import statistics for the stored split stream.
pub fn import_layer<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    diff_id: &str,
    name: Option<&str>,
    tar_stream: &mut impl Read,
) -> Result<(ObjectID, ImportStats)> {
    repo.ensure_stream(
        &layer_identifier(diff_id),
        TAR_LAYER_CONTENT_TYPE,
        |writer| tar::split(tar_stream, writer),
        name,
    )
}

/// Lists the contents of a container layer stored in the repository.
///
/// Reads the split stream for the named layer and prints each tar entry to stdout
/// in composefs dumpfile format.
pub fn ls_layer<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    diff_id: &str,
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

/// Result of a pull operation.
#[derive(Debug)]
pub struct PullResult<ObjectID> {
    /// The config digest (sha256:...).
    pub config_digest: String,
    /// The fs-verity hash of the config splitstream.
    pub config_verity: ObjectID,
    /// Import statistics.
    pub stats: ImportStats,
}

/// Pull the target image, and add the provided tag. If this is a mountable
/// image (i.e. not an artifact), it is *not* unpacked by default.
///
/// When the `containers-storage` feature is enabled and the image reference
/// starts with `containers-storage:`, this uses the native cstor import path
/// which supports zero-copy reflinks. Otherwise, it uses skopeo.
pub async fn pull<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
    img_proxy_config: Option<ImageProxyConfig>,
) -> Result<PullResult<ObjectID>> {
    #[cfg(feature = "containers-storage")]
    if let Some(image_id) = cstor::parse_containers_storage_ref(imgref) {
        let ((config_digest, config_verity), cstor_stats) =
            cstor::import_from_containers_storage(repo, image_id, reference).await?;
        // Convert cstor::ImportStats to our ImportStats
        let stats = ImportStats {
            objects_copied: cstor_stats.objects_reflinked + cstor_stats.objects_copied,
            objects_already_present: cstor_stats.objects_already_present,
            bytes_copied: cstor_stats.bytes_reflinked + cstor_stats.bytes_copied,
            bytes_inlined: cstor_stats.bytes_inlined,
        };
        return Ok(PullResult {
            config_digest,
            config_verity,
            stats,
        });
    }

    let (config_digest, config_verity, stats) =
        skopeo::pull(repo, imgref, reference, img_proxy_config).await?;
    Ok(PullResult {
        config_digest,
        config_verity,
        stats,
    })
}

fn hash(bytes: &[u8]) -> String {
    let mut context = Sha256::new();
    context.update(bytes);
    format!("sha256:{}", hex::encode(context.finalize()))
}

/// Opens and parses a container configuration.
///
/// Reads the OCI image configuration from the repository and returns both the parsed
/// configuration and a digest map containing fs-verity hashes for all referenced layers.
///
/// If verity is provided, it's used directly. Otherwise, the name must be a sha256 digest
/// and the corresponding verity hash will be looked up (which is more expensive) and the content
/// will be hashed and compared to the provided digest.
///
/// Returns the parsed image configuration and the map of layer references.
///
/// Note: if the verity value is known and trusted then the layer fs-verity values can also be
/// trusted.  If not, then you can use the layer map to find objects that are ostensibly the layers
/// in question, but you'll have to verity their content hashes yourself.
pub fn open_config<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    config_digest: &str,
    verity: Option<&ObjectID>,
) -> Result<(ImageConfiguration, HashMap<Box<str>, ObjectID>)> {
    let (data, named_refs) = oci_image::read_external_splitstream(
        repo,
        &config_identifier(config_digest),
        verity,
        Some(OCI_CONFIG_CONTENT_TYPE),
    )?;

    if verity.is_none() {
        let computed = hash(&data);
        ensure!(
            config_digest == computed,
            "Config integrity check failed: expected {config_digest}, got {computed}"
        );
    }

    let config = ImageConfiguration::from_reader(&data[..])?;
    Ok((config, named_refs))
}

/// Writes a container configuration to the repository.
///
/// Serializes the image configuration to JSON and stores it as a split stream with the
/// provided layer reference map. The configuration is stored as an external object so
/// fsverity can be independently enabled on it.
///
/// Returns a tuple of (sha256 content hash, fs-verity hash value).
pub fn write_config<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    config: &ImageConfiguration,
    refs: HashMap<Box<str>, ObjectID>,
) -> Result<ContentAndVerity<ObjectID>> {
    let json = config.to_string()?;
    let json_bytes = json.as_bytes();
    let config_digest = hash(json_bytes);
    let mut stream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
    for (name, value) in &refs {
        stream.add_named_stream_ref(name, value)
    }
    stream.write_external(json_bytes)?;
    let id = repo.write_stream(stream, &config_identifier(&config_digest), None)?;
    Ok((config_digest, id))
}

/// Seals a container by computing its filesystem fs-verity hash and adding it to the config.
///
/// Creates the complete filesystem from all layers, computes its fs-verity hash, and stores
/// this hash in the container config labels under "containers.composefs.fsverity". This allows
/// the container to be mounted with integrity protection.
///
/// Returns a tuple of (sha256 content hash, fs-verity hash value) for the updated configuration.
pub fn seal<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    config_name: &str,
    config_verity: Option<&ObjectID>,
) -> Result<ContentAndVerity<ObjectID>> {
    let (mut config, refs) = open_config(repo, config_name, config_verity)?;
    let mut myconfig = config.config().clone().context("no config!")?;
    let labels = myconfig.labels_mut().get_or_insert_with(HashMap::new);
    let fs = crate::image::create_filesystem(repo, config_name, config_verity)?;
    let id = fs.compute_image_id();
    labels.insert("containers.composefs.fsverity".to_string(), id.to_hex());
    config.set_config(Some(myconfig));
    write_config(repo, &config, refs)
}

/// Mounts a sealed container filesystem at the specified mountpoint.
///
/// Reads the container configuration to extract the fs-verity hash from the
/// "containers.composefs.fsverity" label, then mounts the corresponding filesystem.
/// The container must have been previously sealed using `seal()`.
///
/// Returns an error if the container is not sealed or if mounting fails.
pub fn mount<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
    mountpoint: &str,
    verity: Option<&ObjectID>,
) -> Result<()> {
    let (config, _map) = open_config(repo, name, verity)?;
    let Some(id) = config.get_config_annotation("containers.composefs.fsverity") else {
        bail!("Can only mount sealed containers");
    };
    repo.mount_at(id, mountpoint)
}

#[cfg(test)]
mod test {
    use std::{fmt::Write, io::Read};

    use rustix::fs::CWD;
    use sha2::{Digest, Sha256};

    use composefs::{fsverity::Sha256HashValue, repository::Repository, test::tempdir};

    use super::*;

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

    #[test]
    fn test_layer() {
        let layer = example_layer();
        let mut context = Sha256::new();
        context.update(&layer);
        let layer_id = format!("sha256:{}", hex::encode(context.finalize()));

        let repo_dir = tempdir();
        let repo = Arc::new(Repository::<Sha256HashValue>::open_path(CWD, &repo_dir).unwrap());
        let (id, _stats) = import_layer(&repo, &layer_id, Some("name"), &mut layer.as_slice()).unwrap();

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
        use oci_spec::image::{ImageConfigurationBuilder, RootFsBuilder};

        let repo_dir = tempdir();
        let repo = Arc::new(Repository::<Sha256HashValue>::open_path(CWD, &repo_dir).unwrap());

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

        let (config_digest, config_verity) = write_config(&repo, &config, refs.clone()).unwrap();

        assert!(config_digest.starts_with("sha256:"));

        let (opened_config, opened_refs) =
            open_config(&repo, &config_digest, Some(&config_verity)).unwrap();
        assert_eq!(opened_config.architecture().to_string(), "amd64");
        assert_eq!(opened_config.os().to_string(), "linux");
        assert_eq!(opened_refs.len(), 1);
        assert!(opened_refs.contains_key("sha256:abc123def456"));

        let (opened_config2, _) = open_config(&repo, &config_digest, None).unwrap();
        assert_eq!(opened_config2.architecture().to_string(), "amd64");
    }

    #[test]
    fn test_config_stored_as_external_object() {
        use oci_spec::image::{ImageConfigurationBuilder, RootFsBuilder};

        let repo_dir = tempdir();
        let repo = Arc::new(Repository::<Sha256HashValue>::open_path(CWD, &repo_dir).unwrap());

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

        let (config_digest, config_verity) = write_config(&repo, &config, HashMap::new()).unwrap();

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
        use oci_spec::image::{ImageConfigurationBuilder, RootFsBuilder};

        let repo_dir = tempdir();
        let repo = Arc::new(Repository::<Sha256HashValue>::open_path(CWD, &repo_dir).unwrap());

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

        let (config_digest, _config_verity) = write_config(&repo, &config, HashMap::new()).unwrap();

        let bad_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let result = open_config::<Sha256HashValue>(&repo, bad_digest, None);
        assert!(result.is_err());

        let result = open_config::<Sha256HashValue>(&repo, &config_digest, None);
        assert!(result.is_ok());
    }
}
