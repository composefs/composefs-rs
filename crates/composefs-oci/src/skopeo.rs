//! Container image pulling and registry interaction via skopeo/containers-image-proxy.
//!
//! This module provides functionality to pull container images from various registries and import them
//! into composefs repositories. It uses the containers-image-proxy library to interface with skopeo
//! for image operations, handling authentication, transport protocols, and image manifest processing.
//!
//! The main entry point is the `pull()` function which downloads an image, processes its layers
//! asynchronously with parallelism control, and stores them in the composefs repository with proper
//! fs-verity integration. It supports various image formats and compression types.

use std::{cmp::Reverse, process::Command, thread::available_parallelism};

use std::{iter::zip, sync::Arc};

use anyhow::{Context, Result};
use containers_image_proxy::{
    ConvertedLayerInfo, ImageProxy, ImageProxyConfig, OpenedImage, Transport,
};
use fn_error_context::context;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use oci_spec::image::{Descriptor, ImageConfiguration, MediaType};
use rustix::process::geteuid;
use tokio::{io::AsyncReadExt, sync::Semaphore, task::JoinSet};

use composefs::{fsverity::FsVerityHashValue, repository::Repository};

use crate::{
    config_identifier,
    layer::{decompress_async, import_tar_async, is_tar_media_type, store_blob_async},
    layer_identifier,
    oci_image::{manifest_identifier, tag_image},
    ContentAndVerity,
};

/// Result of pulling an OCI image.
///
/// Contains digests and fs-verity IDs for both the manifest and config,
/// allowing callers to access either level of the image structure.
#[derive(Debug, Clone)]
pub struct PullResult<ObjectID: FsVerityHashValue> {
    /// The sha256 content digest of the manifest.
    pub manifest_digest: String,
    /// The fs-verity ID of the manifest splitstream.
    pub manifest_verity: ObjectID,
    /// The sha256 content digest of the config.
    pub config_digest: String,
    /// The fs-verity ID of the config splitstream.
    pub config_verity: ObjectID,
}

impl<ObjectID: FsVerityHashValue> PullResult<ObjectID> {
    /// Returns (config_digest, config_verity) for backward compatibility.
    pub fn into_config(self) -> ContentAndVerity<ObjectID> {
        (self.config_digest, self.config_verity)
    }

    /// Returns (manifest_digest, manifest_verity).
    pub fn into_manifest(self) -> ContentAndVerity<ObjectID> {
        (self.manifest_digest, self.manifest_verity)
    }
}

// Content type identifiers stored as ASCII in the splitstream file.
// These are arbitrary 8-byte ASCII strings for identification.
pub(crate) const TAR_LAYER_CONTENT_TYPE: u64 = u64::from_le_bytes(*b"ocilayer");
pub(crate) const OCI_CONFIG_CONTENT_TYPE: u64 = u64::from_le_bytes(*b"ociconfg");
pub(crate) const OCI_MANIFEST_CONTENT_TYPE: u64 = u64::from_le_bytes(*b"ocimanif");
/// Content type for arbitrary blobs (OCI artifacts with non-tar media types).
pub(crate) const OCI_BLOB_CONTENT_TYPE: u64 = u64::from_le_bytes(*b"oci_blob");

struct ImageOp<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    proxy: ImageProxy,
    img: OpenedImage,
    progress: MultiProgress,
    transport: Transport,
}

impl<ObjectID: FsVerityHashValue> ImageOp<ObjectID> {
    async fn new(
        repo: &Arc<Repository<ObjectID>>,
        imgref: &str,
        img_proxy_config: Option<ImageProxyConfig>,
    ) -> Result<Self> {
        // Detect transport from image reference
        let transport = Transport::try_from(imgref).context("Failed to get image transport")?;

        // See https://github.com/containers/skopeo/issues/2563
        let skopeo_cmd = if transport == Transport::ContainerStorage && !geteuid().is_root() {
            let mut cmd = Command::new("podman");
            cmd.args(["unshare", "skopeo"]);
            Some(cmd)
        } else {
            None
        };

        // See https://github.com/containers/skopeo/issues/2750
        let imgref = if let Some(hash) = imgref.strip_prefix("containers-storage:sha256:") {
            &format!("containers-storage:{hash}") // yay temporary lifetime extension!
        } else {
            imgref
        };

        let config = match img_proxy_config {
            Some(mut conf) => {
                if conf.skopeo_cmd.is_none() {
                    conf.skopeo_cmd = skopeo_cmd;
                }

                conf
            }

            None => {
                ImageProxyConfig {
                    skopeo_cmd,
                    // auth_anonymous: true, debug: true, insecure_skip_tls_verification: None,
                    ..ImageProxyConfig::default()
                }
            }
        };

        let proxy = containers_image_proxy::ImageProxy::new_with_config(config)
            .await
            .context("Creating ImageProxy")?;
        let img = proxy.open_image(imgref).await.context("Opening image")?;
        let progress = MultiProgress::new();
        Ok(ImageOp {
            repo: Arc::clone(repo),
            proxy,
            img,
            progress,
            transport,
        })
    }

    pub async fn ensure_layer(
        &self,
        diff_id: &str,
        descriptor: &Descriptor,
        uncompressed_layer_info: Option<Arc<Vec<ConvertedLayerInfo>>>,
        layer_idx: usize,
    ) -> Result<ObjectID> {
        // We need to use the per_manifest descriptor to download the compressed layer but it gets
        // stored in the repository via the per_config descriptor.  Our return value is the
        // fsverity digest for the corresponding splitstream.
        let content_id = layer_identifier(diff_id);

        if let Some(layer_id) = self.repo.has_stream(&content_id)? {
            self.progress
                .println(format!("Already have layer {diff_id}"))?;
            Ok(layer_id)
        } else {
            // Otherwise, we need to fetch it...
            let descriptor = match self.transport {
                Transport::ContainerStorage => {
                    let layers = uncompressed_layer_info
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Failed to get uncompressed layer info"))?;

                    let layer = layers.get(layer_idx).ok_or_else(|| {
                        anyhow::anyhow!(
                            "Failed to get uncompressed layer info for layer index {layer_idx}. Total layers: {}",
                            layers.len()
                        )
                    })?;

                    &Descriptor::new(layer.media_type.clone(), layer.size, layer.digest.clone())
                }

                _ => descriptor,
            };

            let (blob_reader, driver) = self
                .proxy
                .get_blob(&self.img, descriptor.digest(), descriptor.size())
                .await?;

            // See https://github.com/containers/containers-image-proxy-rs/issues/71
            let blob_reader = blob_reader.take(descriptor.size());

            let bar = self.progress.add(ProgressBar::new(descriptor.size()));
            bar.set_style(ProgressStyle::with_template("[eta {eta}] {bar:40.cyan/blue} {decimal_bytes:>7}/{decimal_total_bytes:7} {msg}")
                .unwrap()
                .progress_chars("##-"));
            let progress = bar.wrap_async_read(blob_reader);
            self.progress.println(format!("Fetching layer {diff_id}"))?;

            let media_type = descriptor.media_type();
            let object_id = if is_tar_media_type(media_type) {
                // Tar layers: decompress and split into a splitstream
                let reader = decompress_async(progress, media_type)?;
                import_tar_async(self.repo.clone(), reader).await?
            } else {
                // Non-tar layers (OCI artifacts): stream raw bytes to object store
                let (object_id, size) = store_blob_async(&self.repo, progress).await?;
                driver.await?;
                // Create splitstream with external reference and register it
                let mut stream = self.repo.create_stream(OCI_BLOB_CONTENT_TYPE);
                stream.add_external_size(size);
                stream.write_reference(object_id)?;
                return self.repo.write_stream(stream, &content_id, None);
            };

            // skopeo is doing data checksums for us to make sure the content we received is equal
            // to the claimed diff_id. We trust it, but we need to check it by awaiting the driver.
            driver.await?;

            // Sync and register the stream with its content identifier
            self.repo
                .register_stream(&object_id, &content_id, None)
                .await?;

            Ok(object_id)
        }
    }

    /// Ensure config is present and return layer verities along with config info.
    async fn ensure_config_with_layers(
        self: &Arc<Self>,
        manifest_layers: &[Descriptor],
        descriptor: &Descriptor,
    ) -> Result<(
        String,
        ObjectID,
        // FIXME change this string to be Digest - actually we may want to go stronger and have a
        // struct DiffID(Digest) newtype
        std::collections::HashMap<String, ObjectID>,
    )> {
        let config_digest: &str = descriptor.digest().as_ref();
        let content_id = config_identifier(config_digest);

        if let Some(config_id) = self.repo.has_stream(&content_id)? {
            // We already got this config - need to read the layer refs from it
            self.progress
                .println(format!("Already have container config {config_digest}"))?;

            let stream = self.repo.open_stream(
                &content_id,
                Some(&config_id),
                Some(OCI_CONFIG_CONTENT_TYPE),
            )?;
            let layer_refs: std::collections::HashMap<String, ObjectID> = stream
                .into_named_refs()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect();

            Ok((config_digest.to_string(), config_id, layer_refs))
        } else {
            // We need to add the config to the repo
            self.progress
                .println(format!("Fetching config {config_digest}"))?;

            let (mut config, driver) = self.proxy.get_descriptor(&self.img, descriptor).await?;
            let config = async move {
                let mut s = Vec::new();
                config.read_to_end(&mut s).await?;
                anyhow::Ok(s)
            };
            let (config, driver) = tokio::join!(config, driver);
            let _: () = driver?;
            let raw_config = config?;

            // Per the OCI artifacts guidance [1], artifact configs use the
            // empty descriptor (`application/vnd.oci.empty.v1+json`) or a
            // custom media type — not a standard image config. In that case
            // there are no diff_ids, so we use the manifest layer digests.
            // [1]: https://github.com/opencontainers/image-spec/blob/main/artifacts-guidance.md
            let is_image_config = *descriptor.media_type() == MediaType::ImageConfig;
            let diff_ids: Vec<String> = if is_image_config {
                let config = ImageConfiguration::from_reader(&raw_config[..])?;
                config.rootfs().diff_ids().to_vec()
            } else {
                manifest_layers
                    .iter()
                    .map(|d| d.digest().to_string())
                    .collect()
            };

            // Sort layers by size for parallel fetching
            let mut layers: Vec<_> = zip(manifest_layers, &diff_ids).collect();
            layers.sort_by_key(|(mld, ..)| Reverse(mld.size()));

            let threads = available_parallelism()?;
            let sem = Arc::new(Semaphore::new(threads.into()));
            let mut layer_tasks = JoinSet::new();

            let uncompressed_layer_info = match self.transport {
                Transport::ContainerStorage => {
                    self.proxy.get_layer_info(&self.img).await?.map(Arc::new)
                }
                _ => None,
            };

            for (idx, (mld, diff_id)) in layers.into_iter().enumerate() {
                let diff_id_ = diff_id.clone();
                let self_ = Arc::clone(self);
                let permit = Arc::clone(&sem).acquire_owned().await?;
                let descriptor = mld.clone();

                let layer_idx = manifest_layers
                    .iter()
                    .position(|d| *d == descriptor)
                    .ok_or_else(|| anyhow::anyhow!("Layer descriptor not found in manifest"))?;

                let uncompressed_layer_info = uncompressed_layer_info.clone();

                layer_tasks.spawn(async move {
                    let _permit = permit;
                    let verity = self_
                        .ensure_layer(&diff_id_, &descriptor, uncompressed_layer_info, layer_idx)
                        .await?;
                    anyhow::Ok((idx, diff_id_, verity))
                });
            }

            // Collect results and sort by index for deterministic ordering
            let mut results: Vec<_> = layer_tasks
                .join_all()
                .await
                .into_iter()
                .collect::<Result<_, _>>()?;
            results.sort_by_key(|(idx, _, _)| *idx);

            let mut splitstream = self.repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
            let mut layer_refs = std::collections::HashMap::new();
            for (_, diff_id, verity) in results {
                splitstream.add_named_stream_ref(&diff_id, &verity);
                layer_refs.insert(diff_id, verity);
            }

            // Store config as external object for independent fsverity
            splitstream.write_external(&raw_config)?;
            let config_id = self.repo.write_stream(splitstream, &content_id, None)?;
            Ok((config_digest.to_string(), config_id, layer_refs))
        }
    }

    /// Pull the image, storing manifest, config, and all layers.
    pub async fn pull(self: &Arc<Self>) -> Result<PullResult<ObjectID>> {
        let (manifest_digest, raw_manifest) = self
            .proxy
            .fetch_manifest_raw_oci(&self.img)
            .await
            .context("Fetching manifest")?;

        let manifest = oci_spec::image::ImageManifest::from_reader(raw_manifest.as_slice())?;
        let config_descriptor = manifest.config();
        let layers = manifest.layers();
        let (config_digest, config_verity, layer_verities) = self
            .ensure_config_with_layers(layers, config_descriptor)
            .await
            .with_context(|| format!("Failed to pull config {config_descriptor:?}"))?;

        let manifest_content_id = manifest_identifier(&manifest_digest);
        let manifest_verity = if let Some(verity) = self.repo.has_stream(&manifest_content_id)? {
            self.progress
                .println(format!("Already have manifest {manifest_digest}"))?;
            verity
        } else {
            self.progress
                .println(format!("Storing manifest {manifest_digest}"))?;

            let mut splitstream = self.repo.create_stream(OCI_MANIFEST_CONTENT_TYPE);

            let config_key = format!("config:{}", config_descriptor.digest());
            splitstream.add_named_stream_ref(&config_key, &config_verity);

            for (diff_id, verity) in &layer_verities {
                splitstream.add_named_stream_ref(diff_id, verity);
            }

            // Store the raw manifest bytes as an external object for fsverity
            splitstream.write_external(&raw_manifest)?;
            self.repo
                .write_stream(splitstream, &manifest_content_id, None)?
        };

        Ok(PullResult {
            manifest_digest,
            manifest_verity,
            config_digest,
            config_verity,
        })
    }
}

/// Pull the target image, storing manifest, config, and layers.
///
/// Returns `PullResult` containing both manifest and config digests/verities.
/// If `reference` is provided, the manifest is also stored under that name.
///
/// Note: For backward compatibility, use `.into_config()` on the result to get
/// the (config_digest, config_verity) tuple that was previously returned.
///
/// For `oci:` transport (local OCI layout directories), this uses a fast path
/// that reads the layout directly without going through the skopeo proxy.
pub async fn pull_image<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
    img_proxy_config: Option<ImageProxyConfig>,
) -> Result<PullResult<ObjectID>> {
    // Fast path: local OCI layout directories
    if let Some(result) = crate::oci_layout::try_pull_oci_layout(repo, imgref, reference).await? {
        return Ok(result);
    }

    // Standard path: use skopeo proxy for other transports
    let op = Arc::new(ImageOp::new(repo, imgref, img_proxy_config).await?);
    let result = op
        .pull()
        .await
        .with_context(|| format!("Unable to pull container image {imgref}"))?;

    if let Some(name) = reference {
        tag_image(repo, &result.manifest_digest, name)?;
    }
    Ok(result)
}

/// Pull the target image, and add the provided tag. If this is a mountable
/// image (i.e. not an artifact), it is *not* unpacked by default.
///
/// Returns (config_digest, config_verity) for backward compatibility.
/// Consider using `pull_image` for access to manifest information.
#[context("Pulling image {imgref}")]
pub async fn pull<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
    img_proxy_config: Option<ImageProxyConfig>,
) -> Result<(String, ObjectID)> {
    let result = pull_image(repo, imgref, reference, img_proxy_config).await?;
    Ok(result.into_config())
}
