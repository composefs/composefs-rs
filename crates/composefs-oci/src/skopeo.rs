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
use containers_image_proxy::oci_spec::image::{Descriptor, Digest as OciDigest};
use containers_image_proxy::{
    ConvertedLayerInfo, ImageProxy, ImageProxyConfig, ImageReference, OpenedImage, Transport,
};
use fn_error_context::context;

use rustix::process::geteuid;
use tokio::{io::AsyncReadExt, sync::Semaphore, task::JoinSet};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::{ObjectStoreMethod, Repository},
};

use crate::{
    ContentAndVerity, ImportStats, config_identifier,
    layer::{decompress_async, import_tar_async, is_tar_media_type, store_blob_async},
    layer_identifier,
    oci_image::{manifest_identifier, tag_image},
    progress::{ComponentId, ProgressEvent, ProgressRead, ProgressUnit, SharedReporter},
};

/// Result of pulling an OCI image.
///
/// Contains digests and fs-verity IDs for both the manifest and config,
/// allowing callers to access either level of the image structure.
#[derive(Debug, Clone)]
pub struct PullResult<ObjectID: FsVerityHashValue> {
    /// The sha256 content digest of the manifest.
    pub manifest_digest: OciDigest,
    /// The fs-verity ID of the manifest splitstream.
    pub manifest_verity: ObjectID,
    /// The sha256 content digest of the config.
    pub config_digest: OciDigest,
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
    reporter: SharedReporter,
    transport: Transport,
}

impl<ObjectID: FsVerityHashValue> ImageOp<ObjectID> {
    async fn new(
        repo: &Arc<Repository<ObjectID>>,
        image_ref: &ImageReference,
        img_proxy_config: Option<ImageProxyConfig>,
        reporter: SharedReporter,
    ) -> Result<Self> {
        // Fail fast if the repository is not writable, before starting
        // the image proxy or doing any network I/O.
        repo.ensure_writable()?;

        let transport = image_ref.transport;

        // See https://github.com/containers/skopeo/issues/2563
        let skopeo_cmd = if transport == Transport::ContainerStorage && !geteuid().is_root() {
            let mut cmd = Command::new("podman");
            cmd.args(["unshare", "skopeo"]);
            Some(cmd)
        } else {
            None
        };

        // See https://github.com/containers/skopeo/issues/2750
        // ImageReference.name for containers-storage: is already without the
        // transport prefix (e.g. "sha256:abc" not "containers-storage:sha256:abc").
        // Skopeo expects "abc" without the "sha256:" prefix for digest references.
        let fixup_ref;
        let image_ref = if transport == Transport::ContainerStorage {
            if let Some(hash) = image_ref.name.strip_prefix("sha256:") {
                fixup_ref = ImageReference {
                    transport,
                    name: hash.to_string(),
                };
                &fixup_ref
            } else {
                image_ref
            }
        } else {
            image_ref
        };

        let config = match img_proxy_config {
            Some(mut conf) => {
                if conf.skopeo_cmd.is_none() {
                    conf.skopeo_cmd = skopeo_cmd;
                }

                conf
            }

            None => {
                let mut conf = ImageProxyConfig::default();
                conf.skopeo_cmd = skopeo_cmd;
                conf
            }
        };

        let proxy = containers_image_proxy::ImageProxy::new_with_config(config)
            .await
            .context("Creating ImageProxy")?;
        let img = proxy
            .open_image_ref(image_ref)
            .await
            .context("Opening image")?;
        Ok(ImageOp {
            repo: Arc::clone(repo),
            proxy,
            img,
            reporter,
            transport,
        })
    }

    pub async fn ensure_layer(
        &self,
        diff_id: &OciDigest,
        descriptor: &Descriptor,
        uncompressed_layer_info: Option<Arc<Vec<ConvertedLayerInfo>>>,
        layer_idx: usize,
    ) -> Result<(ObjectID, ImportStats)> {
        // We need to use the per_manifest descriptor to download the compressed layer but it gets
        // stored in the repository via the per_config descriptor.  Our return value is the
        // fsverity digest for the corresponding splitstream.
        let content_id = layer_identifier(diff_id);

        if let Some(layer_id) = self.repo.has_stream(&content_id)? {
            self.reporter.report(ProgressEvent::Skipped {
                id: ComponentId::from(diff_id.to_string()),
            });
            Ok((layer_id, ImportStats::default()))
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

            let id = ComponentId::from(diff_id.to_string());
            self.reporter.report(ProgressEvent::Started {
                id: id.clone(),
                total: Some(descriptor.size()),
                unit: ProgressUnit::Bytes,
            });

            // Wrap the blob reader to emit Progress events as compressed bytes are read.
            // This sits before decompression so `fetched` tracks bytes-over-the-wire,
            // matching the `total` from the descriptor size above.
            //
            // The watch channel provides backpressure: if the renderer is slow, intermediate
            // byte counts are coalesced rather than queued, keeping the I/O path non-blocking.
            let (blob_reader, progress_driver) = ProgressRead::new(
                blob_reader,
                Arc::clone(&self.reporter),
                id.clone(),
                Some(descriptor.size()),
            );

            let media_type = descriptor.media_type();
            let (object_id, layer_stats) = if is_tar_media_type(media_type) {
                // Tar layers: decompress and split into a splitstream.
                // Run the progress driver concurrently with the import.
                let reader = decompress_async(blob_reader, media_type)?;
                let (result, ()) =
                    tokio::join!(import_tar_async(self.repo.clone(), reader), progress_driver);
                result?
            } else {
                // Non-tar layers (OCI artifacts): stream raw bytes to object store.
                // Run the progress driver concurrently with the blob store.
                let (store_result, ()) =
                    tokio::join!(store_blob_async(&self.repo, blob_reader), progress_driver);
                let (object_id, size, method) = store_result?;
                driver.await?;

                let mut stats = ImportStats::default();
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

                let mut stream = self.repo.create_stream(OCI_BLOB_CONTENT_TYPE)?;
                stream.add_external_size(size);
                stream.write_reference(object_id)?;
                let stream_id = self.repo.write_stream(stream, &content_id, None)?;
                self.reporter.report(ProgressEvent::Done {
                    id,
                    transferred: size,
                });
                return Ok((stream_id, stats));
            };

            // skopeo is doing data checksums for us to make sure the content we received is equal
            // to the claimed diff_id. We trust it, but we need to check it by awaiting the driver.
            driver.await?;

            // Sync and register the stream with its content identifier
            self.repo
                .register_stream(&object_id, &content_id, None)
                .await?;

            self.reporter.report(ProgressEvent::Done {
                id,
                transferred: descriptor.size(),
            });

            Ok((object_id, layer_stats))
        }
    }

    /// Ensure config is present and return layer verities along with config info.
    ///
    /// Returns (config_digest, config_verity, layer_refs, stats).
    /// `layer_refs` is an ordered Vec of (diff_id, verity) pairs preserving the
    /// order from the config (or manifest for artifacts).
    async fn ensure_config_with_layers(
        self: &Arc<Self>,
        manifest_layers: &[Descriptor],
        descriptor: &Descriptor,
    ) -> Result<(OciDigest, ObjectID, Vec<(OciDigest, ObjectID)>, ImportStats)> {
        let config_digest = descriptor.digest();
        let content_id = config_identifier(config_digest);

        if let Some(config_id) = self.repo.has_stream(&content_id)? {
            // We already got this config - need to read the layer refs and diff_ids from it
            self.reporter.report(ProgressEvent::Message(format!(
                "Already have container config {config_digest}"
            )));

            let (data, named_refs) = crate::oci_image::read_external_splitstream(
                &self.repo,
                &content_id,
                Some(&config_id),
                Some(OCI_CONFIG_CONTENT_TYPE),
            )?;
            let named_refs_map: std::collections::HashMap<&str, ObjectID> = named_refs
                .iter()
                .map(|(k, v)| (k.as_ref(), v.clone()))
                .collect();

            let diff_ids =
                crate::extract_diff_ids(descriptor.media_type(), data.as_slice(), manifest_layers)?;

            let layer_refs: Vec<(OciDigest, ObjectID)> = diff_ids
                .into_iter()
                .map(|diff_id| {
                    let verity = named_refs_map
                        .get(diff_id.as_ref())
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

            Ok((
                descriptor.digest().clone(),
                config_id,
                layer_refs,
                ImportStats::default(),
            ))
        } else {
            // We need to add the config to the repo
            self.reporter.report(ProgressEvent::Message(format!(
                "Fetching config {config_digest}"
            )));

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
            let diff_ids = crate::extract_diff_ids(
                descriptor.media_type(),
                raw_config.as_slice(),
                manifest_layers,
            )?;

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
                let diff_id = diff_id.clone();
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
                    let (verity, layer_stats) = self_
                        .ensure_layer(&diff_id, &descriptor, uncompressed_layer_info, layer_idx)
                        .await?;
                    anyhow::Ok((idx, diff_id, verity, layer_stats))
                });
            }

            // Collect results into a map keyed by diff_id for ordered lookup
            let mut verity_map = std::collections::HashMap::new();
            let mut stats = ImportStats::default();
            for result in layer_tasks.join_all().await {
                let (_, diff_id, verity, layer_stats) = result?;
                verity_map.insert(diff_id, verity);
                stats.merge(&layer_stats);
            }

            // Build ordered layer_refs from config-defined diff_id order
            let layer_refs: Vec<(OciDigest, ObjectID)> = diff_ids
                .into_iter()
                .map(|diff_id| {
                    let verity = verity_map
                        .get(&diff_id)
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

            let mut splitstream = self.repo.create_stream(OCI_CONFIG_CONTENT_TYPE)?;
            for (diff_id, verity) in &layer_refs {
                splitstream.add_named_stream_ref(diff_id.as_ref(), verity);
            }

            // Store config as external object for independent fsverity
            splitstream.write_external(&raw_config)?;
            let config_id = self.repo.write_stream(splitstream, &content_id, None)?;
            Ok((descriptor.digest().clone(), config_id, layer_refs, stats))
        }
    }

    /// Pull the image, storing manifest, config, and all layers.
    pub async fn pull(self: &Arc<Self>) -> Result<(PullResult<ObjectID>, ImportStats)> {
        let (manifest_digest_str, raw_manifest) = self
            .proxy
            .fetch_manifest_raw_oci(&self.img)
            .await
            .context("Fetching manifest")?;
        let manifest_digest: OciDigest = manifest_digest_str
            .try_into()
            .context("Invalid manifest digest from image proxy")?;

        let manifest = containers_image_proxy::oci_spec::image::ImageManifest::from_reader(
            raw_manifest.as_slice(),
        )?;

        // Delta artifact detection
        if crate::delta::is_delta_artifact(&manifest) {
            return self.pull_delta(&manifest).await;
        }

        let config_descriptor = manifest.config();
        let layers = manifest.layers();
        let (config_digest, config_verity, layer_refs, stats) = self
            .ensure_config_with_layers(layers, config_descriptor)
            .await
            .with_context(|| format!("Failed to pull config {config_descriptor:?}"))?;

        let manifest_content_id = manifest_identifier(&manifest_digest);
        let manifest_verity = if let Some(verity) = self.repo.has_stream(&manifest_content_id)? {
            self.reporter.report(ProgressEvent::Message(format!(
                "Already have manifest {manifest_digest}"
            )));
            verity
        } else {
            self.reporter.report(ProgressEvent::Message(format!(
                "Storing manifest {manifest_digest}"
            )));

            let mut splitstream = self.repo.create_stream(OCI_MANIFEST_CONTENT_TYPE)?;

            let config_key = format!("config:{}", config_descriptor.digest());
            splitstream.add_named_stream_ref(&config_key, &config_verity);

            // Add layer refs in config-defined diff_id order
            for (diff_id, verity) in &layer_refs {
                splitstream.add_named_stream_ref(diff_id.as_ref(), verity);
            }

            // Store the raw manifest bytes as an external object for fsverity
            splitstream.write_external(&raw_manifest)?;
            self.repo
                .write_stream(splitstream, &manifest_content_id, None)?
        };

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

    /// Pull a delta artifact: blobs are fetched on demand during apply.
    async fn pull_delta(
        self: &Arc<Self>,
        manifest: &containers_image_proxy::oci_spec::image::ImageManifest,
    ) -> Result<(PullResult<ObjectID>, ImportStats)> {
        self.reporter
            .report(ProgressEvent::Message("Detected delta artifact...".into()));

        let blob_reader = Arc::new(ProxyBlobReader {
            image_op: Arc::clone(self),
        });

        // Limit to 2 concurrent layers: download the next while applying the previous,
        // but avoid fetching further ahead to keep local disk usage bounded.
        crate::delta::import_delta(&self.repo, manifest, blob_reader, &self.reporter, Some(2)).await
    }
}

/// Blob reader that fetches from a skopeo image proxy on demand.
struct ProxyBlobReader<ObjectID: FsVerityHashValue> {
    image_op: Arc<ImageOp<ObjectID>>,
}

impl<ObjectID: FsVerityHashValue> crate::delta::DeltaBlobReader for ProxyBlobReader<ObjectID> {
    fn open_blob(
        &self,
        desc: &Descriptor,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Box<dyn std::io::Read + Send>>> + Send + '_>,
    > {
        let desc = desc.clone();
        Box::pin(async move {
            let (reader, driver) = self
                .image_op
                .proxy
                .get_blob(&self.image_op.img, desc.digest(), desc.size())
                .await?;

            let tmpfile = self
                .image_op
                .repo
                .create_object_tmpfile()
                .context("Creating temp file for delta blob")?;
            let copy_fut = async {
                let mut async_dst = tokio::fs::File::from(std::fs::File::from(tmpfile));
                tokio::io::copy(&mut reader.take(desc.size()), &mut async_dst).await?;
                tokio::io::AsyncWriteExt::flush(&mut async_dst).await?;
                let mut std_file = async_dst.into_std().await;
                use std::io::Seek;
                std_file.seek(std::io::SeekFrom::Start(0))?;
                anyhow::Ok(Box::new(std_file) as Box<dyn std::io::Read + Send>)
            };
            let (file_result, driver_result) = tokio::join!(copy_fut, driver);
            let _: () = driver_result?;
            file_result
        })
    }
}

/// Pull the target image, storing manifest, config, and layers.
///
/// Returns `PullResult` containing both manifest and config digests/verities.
/// If `reference` is provided, the manifest is also stored under that name.
///
/// For `oci:` transport (local OCI layout directories), this uses a fast path
/// that reads the layout directly without going through the skopeo proxy.
///
/// Note: For backward compatibility, use `.into_config()` on the result to get
/// the (config_digest, config_verity) tuple that was previously returned.
pub async fn pull_image<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
    img_proxy_config: Option<ImageProxyConfig>,
    reporter: SharedReporter,
) -> Result<(PullResult<ObjectID>, ImportStats)> {
    // Fail fast if the repository is not writable, before doing any I/O.
    repo.ensure_writable()?;

    let image_ref =
        ImageReference::try_from(imgref).context("Parsing image reference transport")?;

    // Fast path: read local OCI layout directories and archives directly without skopeo
    let (result, stats) = if image_ref.transport == Transport::OciDir
        || image_ref.transport == Transport::OciArchive
    {
        let (path_str, layout_tag) = crate::oci_layout::parse_oci_layout_ref(&image_ref.name);
        let layout_path = std::path::Path::new(path_str);
        crate::oci_layout::import_oci_layout(repo, layout_path, layout_tag, reporter).await?
    } else {
        // Standard path: use skopeo proxy for other transports
        let op = Arc::new(ImageOp::new(repo, &image_ref, img_proxy_config, reporter).await?);
        op.pull()
            .await
            .with_context(|| format!("Unable to pull container image {imgref}"))?
    };

    // Generate the composefs EROFS image and link it to the config splitstream.
    // For container images this rewrites the config+manifest with the EROFS ref
    // and tags the final manifest. Artifacts are skipped and tagged as-is.
    let erofs = crate::ensure_oci_composefs_erofs(
        repo,
        &result.manifest_digest,
        Some(&result.manifest_verity),
        reference,
    )?;
    if erofs.is_none() {
        // Not a container image (artifact) — tag the manifest directly
        if let Some(name) = reference {
            tag_image(repo, &result.manifest_digest, name)?;
        }
    }

    Ok((result, stats))
}

/// Pull the target image, and add the provided tag. If this is a mountable
/// image (i.e. not an artifact), it is *not* unpacked by default.
///
/// Returns (config_digest, config_verity, stats).
/// Consider using `pull_image` for access to manifest information.
#[context("Pulling image {imgref}")]
pub async fn pull<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
    img_proxy_config: Option<ImageProxyConfig>,
) -> Result<(OciDigest, ObjectID, ImportStats)> {
    let reporter = Arc::new(crate::progress::NullReporter);
    let (result, stats) = pull_image(repo, imgref, reference, img_proxy_config, reporter).await?;
    let (config_digest, config_verity) = result.into_config();
    Ok((config_digest, config_verity, stats))
}
