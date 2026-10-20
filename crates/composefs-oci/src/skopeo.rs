//! Container image pulling and registry interaction via skopeo/containers-image-proxy.
//!
//! This module provides functionality to pull container images from various registries and import them
//! into composefs repositories. It uses the containers-image-proxy library to interface with skopeo
//! for image operations, handling authentication, transport protocols, and image manifest processing.
//!
//! The main entry point is the `pull()` function which downloads an image, processes its layers
//! asynchronously with parallelism control, and stores them in the composefs repository with proper
//! fs-verity integration. It supports various image formats and compression types.

use std::{cmp::Reverse, future::Future, process::Command, thread::available_parallelism};

use std::{iter::zip, sync::Arc};

use anyhow::{Context, Result};
use containers_image_proxy::oci_spec::image::{Descriptor, Digest as OciDigest};
use containers_image_proxy::{
    ConvertedLayerInfo, ImageProxy, ImageProxyConfig, ImageReference, OpenedImage, Transport,
};
use fn_error_context::context;

use crate::oci_layout::OciLayoutKind;

use rustix::process::geteuid;
use tokio::{
    io::{AsyncBufRead, AsyncReadExt},
    sync::Semaphore,
    task::JoinSet,
};

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
    retry::{RetryPolicy, with_retry},
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
    retry: RetryPolicy,
}

impl<ObjectID: FsVerityHashValue> ImageOp<ObjectID> {
    async fn new(
        repo: &Arc<Repository<ObjectID>>,
        image_ref: &ImageReference,
        img_proxy_config: Option<ImageProxyConfig>,
        reporter: SharedReporter,
        retry: RetryPolicy,
    ) -> Result<Self> {
        // Fail fast if the repository is not writable, before starting
        // the image proxy or doing any network I/O.
        repo.ensure_writable()?;

        let transport = image_ref.transport;
        // Only a registry fails transiently; for local transports such as
        // containers-storage: a failure would just repeat.
        let retry = if transport == Transport::Registry {
            retry
        } else {
            RetryPolicy::none()
        };

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
        // Opening the image fetches its manifest from the registry.
        let img = with_retry(&retry, "Opening image", &*reporter, || async {
            Ok(proxy.open_image_ref(image_ref).await?)
        })
        .await
        .context("Opening image")?;
        Ok(ImageOp {
            repo: Arc::clone(repo),
            proxy,
            img,
            reporter,
            transport,
            retry,
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

            fetch_layer(
                &self.repo,
                &self.reporter,
                &self.retry,
                diff_id,
                descriptor,
                || {
                    self.proxy
                        .get_blob(&self.img, descriptor.digest(), descriptor.size())
                },
            )
            .await
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
            )
            .with_context(|| format!("Failed to read cached config {config_digest}"))?;
            let named_refs_map: std::collections::HashMap<&str, ObjectID> = named_refs
                .iter()
                .map(|(k, v)| (k.as_ref(), v.clone()))
                .collect();

            let diff_ids =
                crate::extract_diff_ids(descriptor.media_type(), data.as_slice(), manifest_layers)
                    .with_context(|| format!("Failed to parse config {config_digest}"))?;

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
            let what = format!("Fetching config {config_digest}");
            self.reporter.report(ProgressEvent::Message(what.clone()));

            let raw_config = with_retry(&self.retry, &what, &*self.reporter, || async {
                let (mut config, driver) = self.proxy.get_descriptor(&self.img, descriptor).await?;
                let config = async move {
                    let mut s = Vec::new();
                    config.read_to_end(&mut s).await?;
                    anyhow::Ok(s)
                };
                let (config, driver) = tokio::join!(config, driver);
                let _: () = driver?;
                config
            })
            .await
            .with_context(|| format!("Failed to fetch config {config_digest}"))?;

            // Per the OCI artifacts guidance [1], artifact configs use the
            // empty descriptor (`application/vnd.oci.empty.v1+json`) or a
            // custom media type — not a standard image config. In that case
            // there are no diff_ids, so we use the manifest layer digests.
            // [1]: https://github.com/opencontainers/image-spec/blob/main/artifacts-guidance.md
            let diff_ids = crate::extract_diff_ids(
                descriptor.media_type(),
                raw_config.as_slice(),
                manifest_layers,
            )
            .with_context(|| format!("Failed to parse config {config_digest}"))?;

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
                        .await
                        .with_context(|| {
                            format!("Failed to import layer {}", descriptor.digest())
                        })?;
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
        let (manifest_digest_str, raw_manifest) = with_retry(
            &self.retry,
            "Fetching manifest",
            &*self.reporter,
            || async { Ok(self.proxy.fetch_manifest_raw_oci(&self.img).await?) },
        )
        .await
        .context("Fetching manifest")?;
        let manifest_digest: OciDigest = manifest_digest_str
            .try_into()
            .context("Invalid manifest digest from image proxy")?;

        let manifest = containers_image_proxy::oci_spec::image::ImageManifest::from_reader(
            raw_manifest.as_slice(),
        )?;

        // Delta artifact detection
        if oci_delta::is_delta_artifact(&manifest) {
            return self.pull_delta(&manifest).await;
        }

        let config_descriptor = manifest.config();
        let layers = manifest.layers();
        let (config_digest, config_verity, layer_refs, stats) = self
            .ensure_config_with_layers(layers, config_descriptor)
            .await
            .with_context(|| {
                format!("Failed to pull image content for manifest {manifest_digest}")
            })?;

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

impl<ObjectID: FsVerityHashValue> oci_delta::DeltaBlobReader for ProxyBlobReader<ObjectID> {
    fn open_blob(&self, desc: &Descriptor) -> oci_delta::BlobStreamFuture<'_> {
        let desc = desc.clone();
        Box::pin(async move {
            let op = &self.image_op;
            let desc = &desc;
            let what = format!("Fetching blob {}", desc.digest());
            // Each attempt downloads into a fresh anonymous tmpfile, so a
            // failed attempt leaves nothing behind.
            with_retry(&op.retry, &what, &*op.reporter, || async move {
                let (reader, driver) = op
                    .proxy
                    .get_blob(&op.img, desc.digest(), desc.size())
                    .await?;

                let tmpfile = op
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
                    anyhow::Ok(Box::new(std_file) as Box<dyn oci_delta::BlobStream>)
                };
                let (file_result, driver_result) = tokio::join!(copy_fut, driver);
                let _: () = driver_result?;
                file_result
            })
            .await
        })
    }
}

/// Fetch a layer blob and import it into the repository, retrying transient
/// failures according to `policy`.
///
/// `fetch` starts a new download of the blob, returning the data stream and
/// the proxy's "driver" future which reports whether the proxy verified the
/// size and digest of what it sent.  It is called once per attempt.
async fn fetch_layer<ObjectID, F, Fut, R, D>(
    repo: &Arc<Repository<ObjectID>>,
    reporter: &SharedReporter,
    policy: &RetryPolicy,
    diff_id: &OciDigest,
    descriptor: &Descriptor,
    mut fetch: F,
) -> Result<(ObjectID, ImportStats)>
where
    ObjectID: FsVerityHashValue,
    F: FnMut() -> Fut,
    Fut: Future<Output = containers_image_proxy::Result<(R, D)>>,
    R: AsyncBufRead + Send + Unpin,
    D: Future<Output = containers_image_proxy::Result<()>>,
{
    let id = ComponentId::from(diff_id.to_string());
    let content_id = layer_identifier(diff_id);
    let what = format!("Fetching layer {}", descriptor.digest());
    let (object_id, stats, transferred) = with_retry(policy, &what, &**reporter, || {
        // Reported for every attempt: each one refetches the blob from the
        // start, so its progress restarts from zero.
        reporter.report(ProgressEvent::Started {
            id: id.clone(),
            total: Some(descriptor.size()),
            unit: ProgressUnit::Bytes,
        });
        let fetched = fetch();
        let (id, content_id) = (&id, content_id.as_str());
        async move {
            let (reader, driver) = fetched.await?;
            import_layer_blob(repo, reporter, id, content_id, descriptor, reader, driver).await
        }
    })
    .await?;

    reporter.report(ProgressEvent::Done { id, transferred });
    Ok((object_id, stats))
}

/// A single attempt at importing a layer blob streamed from the image proxy.
///
/// The layer is only registered under `content_id` once the proxy has
/// confirmed (via `driver`) that the complete blob with the expected size
/// and digest was sent.  If the transfer fails part way, anything already
/// written to the repository is either a content-addressed object (correct
/// by construction, and reused by the next attempt) or unreferenced (and
/// removed by garbage collection).
///
/// Returns the stream ID, import statistics and the number of bytes
/// transferred.
async fn import_layer_blob<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    reporter: &SharedReporter,
    id: &ComponentId,
    content_id: &str,
    descriptor: &Descriptor,
    reader: impl AsyncBufRead + Send + Unpin,
    driver: impl Future<Output = containers_image_proxy::Result<()>>,
) -> Result<(ObjectID, ImportStats, u64)> {
    enum Imported<ObjectID> {
        Tar(ObjectID, ImportStats),
        Blob(ObjectID, u64, ObjectStoreMethod),
    }

    // See https://github.com/containers/containers-image-proxy-rs/issues/71
    let reader = reader.take(descriptor.size());

    // Wrap the blob reader to emit Progress events as compressed bytes are read.
    // This sits before decompression so `fetched` tracks bytes-over-the-wire,
    // matching the `total` from the descriptor size.
    //
    // The watch channel provides backpressure: if the renderer is slow, intermediate
    // byte counts are coalesced rather than queued, keeping the I/O path non-blocking.
    let (reader, progress_driver) = ProgressRead::new(
        reader,
        Arc::clone(reporter),
        id.clone(),
        Some(descriptor.size()),
    );

    let media_type = descriptor.media_type();
    let import = async {
        if is_tar_media_type(media_type) {
            // Tar layers: decompress and split into a splitstream.
            let reader = decompress_async(reader, media_type)?;
            let (object_id, stats) = import_tar_async(repo.clone(), reader).await?;
            anyhow::Ok(Imported::Tar(object_id, stats))
        } else {
            // Non-tar layers (OCI artifacts): stream raw bytes to object store.
            let (object_id, size, method) = store_blob_async(repo, reader).await?;
            Ok(Imported::Blob(object_id, size, method))
        }
    };
    let (imported, ()) = tokio::join!(import, progress_driver);

    // The reader has been dropped, so the proxy is done writing.  It checks
    // the size and digest of the blob for us, and reports the outcome via the
    // driver.  Check that even if the import failed: a failed transfer is
    // then usually the root cause, and it decides whether to retry.
    let imported = match (imported, driver.await) {
        (Ok(imported), Ok(())) => imported,
        (Err(import_err), Ok(())) => return Err(import_err),
        (Ok(_), Err(proxy_err)) => return Err(proxy_err.into()),
        // Keep the proxy's error as the source, so that retrying looks at it.
        (Err(import_err), Err(proxy_err)) => {
            return Err(
                anyhow::Error::from(proxy_err).context(format!("Import failed: {import_err:#}"))
            );
        }
    };

    match imported {
        Imported::Tar(object_id, stats) => {
            // Sync and register the stream with its content identifier
            repo.register_stream(&object_id, content_id, None).await?;
            Ok((object_id, stats, descriptor.size()))
        }
        Imported::Blob(object_id, size, method) => {
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

            let mut stream = repo.create_stream(OCI_BLOB_CONTENT_TYPE)?;
            stream.add_external_size(size);
            stream.write_reference(object_id)?;
            let stream_id = repo.write_stream(stream, content_id, None)?;
            Ok((stream_id, stats, size))
        }
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
///
/// If `boot_options` is `Some`, the boot-transformed EROFS variant is also
/// generated and linked in the same pass over the OCI layers, avoiding the
/// extra tar walk a separate `boot::generate_boot_image()` call would
/// otherwise require.
///
/// Transient registry failures are retried with the default [`RetryPolicy`];
/// use [`crate::pull`] with [`crate::PullOptions::retry`] to change that.
pub async fn pull_image<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
    img_proxy_config: Option<ImageProxyConfig>,
    reporter: SharedReporter,
    boot_options: Option<&composefs::generic_tree::OciTransformOptions>,
) -> Result<(PullResult<ObjectID>, ImportStats)> {
    pull_image_with_retry(
        repo,
        imgref,
        reference,
        img_proxy_config,
        reporter,
        boot_options,
        &RetryPolicy::default(),
    )
    .await
}

/// Like [`pull_image`], but retrying transient failures according to `retry`.
pub(crate) async fn pull_image_with_retry<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
    img_proxy_config: Option<ImageProxyConfig>,
    reporter: SharedReporter,
    boot_options: Option<&composefs::generic_tree::OciTransformOptions>,
    retry: &RetryPolicy,
) -> Result<(PullResult<ObjectID>, ImportStats)> {
    // Fail fast if the repository is not writable, before doing any I/O.
    repo.ensure_writable()?;

    let image_ref =
        ImageReference::try_from(imgref).context("Parsing image reference transport")?;

    // Fast path: read local OCI layout directories and archives directly without skopeo
    let kind = match image_ref.transport {
        Transport::OciDir => Some(OciLayoutKind::Directory),
        Transport::OciArchive => Some(OciLayoutKind::Archive),
        _ => None,
    };
    let oci_layout = kind.and_then(|kind| {
        let (path_str, layout_tag) = crate::oci_layout::parse_oci_layout_ref(&image_ref.name);
        let layout_path = std::path::Path::new(path_str);
        // A compressed oci-archive is only readable via the proxy, which
        // decompresses it for us.  A path that doesn't exist stays on the
        // direct path so the error names the file, rather than surfacing as a
        // skopeo failure.
        let needs_proxy = kind == OciLayoutKind::Archive
            && layout_path.exists()
            && !crate::oci_layout::is_uncompressed_tar(layout_path);
        (!needs_proxy).then_some((kind, layout_path, layout_tag))
    });

    let (result, stats) = if let Some((kind, layout_path, layout_tag)) = oci_layout {
        crate::oci_layout::import_oci_layout(repo, kind, layout_path, layout_tag, reporter).await?
    } else {
        // Standard path: use skopeo proxy for other transports
        let op = Arc::new(
            ImageOp::new(repo, &image_ref, img_proxy_config, reporter, retry.clone()).await?,
        );
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
        boot_options,
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
    let (result, stats) =
        pull_image(repo, imgref, reference, img_proxy_config, reporter, None).await?;
    let (config_digest, config_verity) = result.into_config();
    Ok((config_digest, config_verity, stats))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Mutex;
    use std::time::Duration;

    use composefs::fsverity::Sha256HashValue;
    use composefs::test::TestRepo;
    use containers_image_proxy::Error as ProxyError;
    use containers_image_proxy::oci_spec::image::MediaType;

    use super::*;
    use crate::progress::ProgressReporter;

    const FAST_RETRIES: RetryPolicy = RetryPolicy {
        max_retries: 2,
        delay: Some(Duration::ZERO),
    };

    /// Size of a tar header block, which precedes each file's content.
    const TAR_BLOCK_SIZE: usize = 512;

    /// What one call of the injected fetcher does.
    #[derive(Debug, Clone, Copy)]
    enum Attempt {
        /// The request itself fails with this message, which the proxy
        /// classifies as retryable or not.
        RequestFails(&'static str, bool),
        /// The stream ends half way and the proxy reports the (retryable)
        /// network error that interrupted it.
        Interrupted,
        /// Full-length data with a flipped byte; the proxy reports the
        /// digest mismatch, which is not retryable, only after it has all
        /// been read.
        Corrupted,
        /// The stream ends half way, but the proxy claims success, so the
        /// failure is local (as for a malformed layer) and must not be retried.
        TruncatedUnnoticed,
        /// The complete, correct blob.
        Good,
    }

    const HTTP_503: &str = "reading blob: received unexpected HTTP status: 503 Service Unavailable";
    const UNAUTHORIZED: &str = "reading blob: unauthorized: authentication required";
    const CONNECTION_RESET: &str =
        "read tcp 10.0.0.1:1234->10.0.0.2:443: read: connection reset by peer";
    const ARTIFACT_MEDIA_TYPE: &str = "application/vnd.example.artifact";

    /// An uncompressed tar layer with a single file.
    fn test_layer() -> Vec<u8> {
        let mut builder = ::tar::Builder::new(Vec::new());
        let data = b"hello from a flaky registry\n".repeat(100);
        let mut header = ::tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(1234567890);
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/hello.txt", data.as_slice())
            .unwrap();
        builder.into_inner().unwrap()
    }

    /// The proxy reports failures, including the verdict of `FinishPipe`,
    /// like this.
    fn proxy_failure(method: &str, msg: String, retryable: bool) -> ProxyError {
        let (method, error) = (method.into(), msg.into());
        if retryable {
            ProxyError::RetryableRequestFailure { method, error }
        } else {
            ProxyError::RequestInitiationFailure { method, error }
        }
    }

    type FakeDriver = std::future::Ready<containers_image_proxy::Result<()>>;
    type FakeFetch = containers_image_proxy::Result<(Cursor<Vec<u8>>, FakeDriver)>;

    fn run_attempt(attempt: Attempt, blob: &[u8], digest: &OciDigest) -> FakeFetch {
        let size = blob.len();
        let half = blob[..size / 2].to_vec();
        let (data, verdict) = match attempt {
            Attempt::RequestFails(msg, retryable) => {
                return Err(proxy_failure("GetBlob", msg.into(), retryable));
            }
            Attempt::Interrupted => (half, Err((CONNECTION_RESET.to_string(), true))),
            Attempt::Corrupted => {
                let mut data = blob.to_vec();
                // Inside the file content, so the tar still parses
                data[TAR_BLOCK_SIZE + 10] ^= 0xff;
                (
                    data,
                    Err((format!("corrupted blob, expecting {digest}"), false)),
                )
            }
            Attempt::TruncatedUnnoticed => (half, Ok(())),
            Attempt::Good => (blob.to_vec(), Ok(())),
        };
        let driver = std::future::ready(
            verdict.map_err(|(msg, retryable)| proxy_failure("FinishPipe", msg, retryable)),
        );
        Ok((Cursor::new(data), driver))
    }

    /// Records `Started` and `Done` events.
    #[derive(Debug, Default)]
    struct EventLog(Mutex<Vec<&'static str>>);

    impl ProgressReporter for EventLog {
        fn report(&self, event: ProgressEvent) {
            let name = match event {
                ProgressEvent::Started { .. } => "started",
                ProgressEvent::Done { .. } => "done",
                _ => return,
            };
            self.0.lock().unwrap().push(name);
        }
    }

    /// Run [`fetch_layer`] with a fetcher following `script`, returning
    /// the result, the number of fetches and the progress events.
    async fn fetch_scripted(
        repo: &Arc<Repository<Sha256HashValue>>,
        policy: &RetryPolicy,
        descriptor: &Descriptor,
        blob: &[u8],
        script: &[Attempt],
    ) -> (Result<Sha256HashValue>, usize, Vec<&'static str>) {
        let events = Arc::new(EventLog::default());
        let reporter: SharedReporter = events.clone();
        let digest = descriptor.digest();
        let mut calls = 0;
        let result = fetch_layer(repo, &reporter, policy, digest, descriptor, || {
            let attempt = script[calls];
            calls += 1;
            std::future::ready(run_attempt(attempt, blob, digest))
        })
        .await
        .map(|(id, _stats)| id);
        let events = events.0.lock().unwrap().clone();
        (result, calls, events)
    }

    /// Drive [`fetch_layer`] with an injected fetcher that fails according
    /// to a script, and check that only verified data is ever registered.
    #[tokio::test]
    async fn test_fetch_layer_retries() {
        use Attempt::*;

        let layer = test_layer();
        let artifact = b"some artifact blob contents\n".repeat(50);

        // (media type, blob, policy, script, expected success)
        type Case<'a> = (MediaType, &'a [u8], RetryPolicy, &'a [Attempt], bool);
        let cases: &[Case] = &[
            (MediaType::ImageLayer, &layer, FAST_RETRIES, &[Good], true),
            (
                MediaType::ImageLayer,
                &layer,
                FAST_RETRIES,
                &[RequestFails(HTTP_503, true), Good],
                true,
            ),
            (
                MediaType::ImageLayer,
                &layer,
                FAST_RETRIES,
                &[Interrupted, Good],
                true,
            ),
            (
                MediaType::ImageLayer,
                &layer,
                FAST_RETRIES,
                &[Interrupted, RequestFails(HTTP_503, true), Good],
                true,
            ),
            // Out of retries
            (
                MediaType::ImageLayer,
                &layer,
                FAST_RETRIES,
                &[Interrupted; 3],
                false,
            ),
            // Errors the proxy doesn't consider transient are not retried
            (
                MediaType::ImageLayer,
                &layer,
                FAST_RETRIES,
                &[RequestFails(UNAUTHORIZED, false)],
                false,
            ),
            (
                MediaType::ImageLayer,
                &layer,
                FAST_RETRIES,
                &[Corrupted],
                false,
            ),
            // Nor are local failures to import verified data
            (
                MediaType::ImageLayer,
                &layer,
                FAST_RETRIES,
                &[TruncatedUnnoticed],
                false,
            ),
            // Retrying disabled
            (
                MediaType::ImageLayer,
                &layer,
                RetryPolicy::none(),
                &[Interrupted],
                false,
            ),
            // Non-tar blobs take a different import path
            (
                MediaType::Other(ARTIFACT_MEDIA_TYPE.into()),
                &artifact,
                FAST_RETRIES,
                &[Interrupted, RequestFails(HTTP_503, true), Good],
                true,
            ),
            (
                MediaType::Other(ARTIFACT_MEDIA_TYPE.into()),
                &artifact,
                FAST_RETRIES,
                &[Corrupted],
                false,
            ),
        ];

        for (media_type, blob, policy, script, expected_ok) in cases {
            let ctx = format!("media_type={media_type} policy={policy:?} script={script:?}");
            let digest = crate::sha256_content_digest(blob);
            let descriptor = Descriptor::new(media_type.clone(), blob.len() as u64, digest);
            let content_id = layer_identifier(descriptor.digest());

            // The stream ID that a single clean fetch produces
            let expected_id = {
                let reference = TestRepo::<Sha256HashValue>::new();
                let (r, ..) =
                    fetch_scripted(&reference.repo, policy, &descriptor, blob, &[Good]).await;
                r.unwrap()
            };

            let test_repo = TestRepo::<Sha256HashValue>::new();
            let (result, calls, events) =
                fetch_scripted(&test_repo.repo, policy, &descriptor, blob, script).await;

            assert_eq!(calls, script.len(), "{ctx}");
            let registered = test_repo.repo.has_stream(&content_id).unwrap();
            if *expected_ok {
                let id = result.unwrap_or_else(|e| panic!("{ctx}: {e:#}"));
                assert_eq!(id, expected_id, "{ctx}");
                assert_eq!(registered, Some(expected_id), "{ctx}");
                let mut expected_events = vec!["started"; script.len()];
                expected_events.push("done");
                assert_eq!(events, expected_events, "{ctx}");
            } else {
                assert!(result.is_err(), "{ctx}");
                // Data from failed attempts must never be registered
                assert_eq!(registered, None, "{ctx}");
                // One `Started` per attempt, and no `Done`
                assert_eq!(events, vec!["started"; script.len()], "{ctx}");
            }
        }
    }

    /// For a tar layer, the stream ID matches a direct import of the layer.
    #[tokio::test]
    async fn test_fetch_layer_matches_import() {
        let layer = test_layer();
        let diff_id = crate::sha256_content_digest(&layer);
        let descriptor =
            Descriptor::new(MediaType::ImageLayer, layer.len() as u64, diff_id.clone());
        let reference = TestRepo::<Sha256HashValue>::new();
        let (imported, _) =
            crate::import_layer(&reference.repo, &diff_id, None, Cursor::new(layer.clone()))
                .await
                .unwrap();
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let (fetched, ..) = fetch_scripted(
            &test_repo.repo,
            &FAST_RETRIES,
            &descriptor,
            &layer,
            &[Attempt::Interrupted, Attempt::Good],
        )
        .await;
        assert_eq!(fetched.unwrap(), imported);
    }
}
