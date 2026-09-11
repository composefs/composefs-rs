//! Direct OCI layout directory import without the skopeo proxy.
//!
//! This module provides a fast path for importing images from local OCI layout
//! directories (the `oci:` transport). Instead of going through the
//! containers-image-proxy (which spawns skopeo as a subprocess), we read the
//! OCI layout directly using the `ocidir` crate.
//!
//! This is significantly faster for local imports since:
//! - No subprocess overhead from skopeo
//! - No IPC/pipe overhead for blob streaming
//! - Direct file I/O instead of proxy protocol parsing
//!
//! The import produces identical results to the proxy path: the same
//! splitstream format with the same content identifiers.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, ready};
use std::thread::available_parallelism;

use anyhow::{Context, Result};
use cap_std_ext::cap_std;
use containers_image_proxy::oci_spec::image::{
    Descriptor, Digest as OciDigest, ImageManifest, MediaType,
};
use fn_error_context::context;
use ocidir::prelude::*;
use ocidir::{OciArchive, OciDir, ResolvedManifest};
use tokio::io::{AsyncRead, DuplexStream, ReadBuf};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio_util::io::SyncIoBridge;
use tracing::debug;

use composefs::fsverity::FsVerityHashValue;
use composefs::repository::{ObjectStoreMethod, Repository};

use crate::layer::{decompress_async, import_tar_async, is_tar_media_type, store_blob_async};
use crate::oci_image::manifest_identifier;
use crate::progress::{ComponentId, ProgressEvent, ProgressRead, ProgressUnit, SharedReporter};
use crate::skopeo::OCI_BLOB_CONTENT_TYPE;
use crate::skopeo::{OCI_CONFIG_CONTENT_TYPE, OCI_MANIFEST_CONTENT_TYPE};
use crate::{ImportStats, config_identifier, layer_identifier};
use oci_delta::BlobStream;

use crate::skopeo::PullResult;

const READ_BUF_SIZE: usize = 128 * 1024;

/// Adapts a synchronous `Read` into a [`tokio::io::AsyncRead`] by copying data
/// through a [`tokio::io::duplex`] channel from a single blocking thread.
///
/// A failure in the blocking copy closes the duplex channel, which is
/// indistinguishable from a clean end of stream, so the error is passed
/// out-of-band and re-raised in place of that end of stream.
struct BlockingReader {
    stream: DuplexStream,
    err: oneshot::Receiver<std::io::Error>,
}

impl BlockingReader {
    fn new(mut reader: impl Read + Send + 'static) -> Self {
        let (async_read, async_write) = tokio::io::duplex(READ_BUF_SIZE);
        let (err_tx, err_rx) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let mut writer = SyncIoBridge::new(async_write);
            if let Err(err) = std::io::copy(&mut reader, &mut writer) {
                // Send before dropping the bridge: the consumer only sees the
                // end of the stream once the write half is closed, so by then
                // the error is guaranteed to be available.
                let _ = err_tx.send(err);
            }
        });
        Self {
            stream: async_read,
            err: err_rx,
        }
    }
}

impl AsyncRead for BlockingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled = buf.filled().len();
        ready!(Pin::new(&mut self.stream).poll_read(cx, buf))?;
        if buf.filled().len() == filled
            && let Ok(err) = self.err.try_recv()
        {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(()))
    }
}

/// Check if an OCI layout contains a single delta artifact manifest.
///
/// Anything that isn't a parseable image manifest is simply not a delta and
/// will be handled by the regular codepath.
fn detect_delta_manifest(oci: &impl OciRead) -> Result<Option<ImageManifest>> {
    let index = oci.read_index()?;
    let [desc] = index.manifests().as_slice() else {
        return Ok(None);
    };
    if desc.media_type() != &MediaType::ImageManifest {
        return Ok(None);
    }

    let mut manifest_data = Vec::new();
    oci.read_blob(desc)?.read_to_end(&mut manifest_data)?;
    match ImageManifest::from_reader(&manifest_data[..]) {
        Ok(manifest) if oci_delta::is_delta_artifact(&manifest) => Ok(Some(manifest)),
        Ok(_) => Ok(None),
        Err(err) => {
            debug!("Ignoring unparseable manifest {}: {err}", desc.digest());
            Ok(None)
        }
    }
}

/// Parse an OCI layout reference like "/path/to/dir:tag" or "/path/to/dir".
///
/// Returns (path, optional_tag).
pub(crate) fn parse_oci_layout_ref(imgref: &str) -> (&str, Option<&str>) {
    // The format is: path[:tag]
    // We need to be careful: paths can contain colons (on Windows, or weird Unix paths).
    // The convention is that if the last colon is after the last slash, it's a tag separator.

    let Some((before_colon, tag)) = imgref.rsplit_once(':') else {
        return (imgref, None);
    };

    if tag.contains('/') {
        // Slash after the colon means colon is part of the path
        (imgref, None)
    } else {
        // No slash after the colon - it's a tag separator
        (before_colon, Some(tag))
    }
}

/// The `ustar` magic of a POSIX or GNU tar header, and its offset in the header.
const TAR_MAGIC: &[u8; 5] = b"ustar";
const TAR_MAGIC_OFFSET: u64 = 257;

/// Is `path` an uncompressed tar archive?
pub(crate) fn is_uncompressed_tar(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; TAR_MAGIC.len()];
    std::os::unix::fs::FileExt::read_exact_at(&file, &mut buf, TAR_MAGIC_OFFSET).is_ok()
        && &buf == TAR_MAGIC
}

/// Resolve a manifest from an OCI layout directory for the current platform.
fn resolve_manifest<T: OciRead + Send + Sync>(
    oci: &T,
    tag: Option<&str>,
) -> Result<ResolvedManifest> {
    oci.open_image_this_platform(tag)
        .context("Resolving manifest for platform")
}

/// Whether a layout path is an `oci:` directory or an `oci-archive:` tarball.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OciLayoutKind {
    /// An `oci:` layout directory.
    Directory,
    /// An `oci-archive:` tarball.
    Archive,
}

/// Import an image from a local OCI layout directory or archive.
///
/// This is the fast path for `oci:` and uncompressed `oci-archive:` transport
/// references. It reads the layout directly without going through skopeo.
/// Progress events are emitted
/// via `reporter` using the same `Started`/`Done`/`Skipped` lifecycle as the
/// skopeo path.
#[context("Importing OCI layout from {}", layout_path.display())]
pub async fn import_oci_layout<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    kind: OciLayoutKind,
    layout_path: &Path,
    layout_tag: Option<&str>,
    reporter: SharedReporter,
) -> Result<(PullResult<ObjectID>, ImportStats)> {
    // Check writability before touching the source, so a read-only repo gives
    // a clear "not writable" error rather than a misleading source-open error.
    repo.ensure_writable()?;

    match kind {
        OciLayoutKind::Archive => {
            let oci = OciArchive::open(layout_path)
                .with_context(|| format!("Opening OCI archive {}", layout_path.display()))?;
            import_opened_layout(repo, oci, layout_tag, reporter).await
        }
        OciLayoutKind::Directory => {
            let dir = cap_std::fs::Dir::open_ambient_dir(layout_path, cap_std::ambient_authority())
                .with_context(|| {
                    format!("Opening OCI layout directory {}", layout_path.display())
                })?;
            let oci = OciDir::open(dir).context("Opening OCI directory")?;
            import_opened_layout(repo, oci, layout_tag, reporter).await
        }
    }
}

/// Import from any opened [`OciRead`] backend, as either a delta artifact or a
/// plain image.
async fn import_opened_layout<ObjectID: FsVerityHashValue, T: OciRead + Send + Sync + 'static>(
    repo: &Arc<Repository<ObjectID>>,
    oci: T,
    tag: Option<&str>,
    reporter: SharedReporter,
) -> Result<(PullResult<ObjectID>, ImportStats)> {
    if let Some(manifest) = detect_delta_manifest(&oci)? {
        let blob_reader = Arc::new(OciBlobReader(oci));
        return crate::delta::import_delta(repo, &manifest, blob_reader, &reporter, None).await;
    }

    // Resolve the manifest, with fallback for images lacking platform annotations
    let resolved = resolve_manifest(&oci, tag)?;

    let manifest = resolved.manifest;
    let manifest_descriptor = &resolved.manifest_descriptor;
    let manifest_digest = manifest_descriptor.digest().clone();

    // Import config and layers
    let config_descriptor = manifest.config();
    let layers = manifest.layers();
    reporter.report(ProgressEvent::Message(format!(
        "Importing {} layers from OCI layout",
        layers.len()
    )));
    let (config_digest, config_verity, layer_refs, stats) =
        import_config_and_layers(repo, &oci, layers, config_descriptor, &reporter)
            .await
            .with_context(|| {
                format!("Failed to import image content for manifest {manifest_digest}")
            })?;

    reporter.report(ProgressEvent::Message("Storing manifest".to_string()));

    // Store the manifest
    let manifest_content_id = manifest_identifier(&manifest_digest);
    let manifest_verity = if let Some(verity) = repo.has_stream(&manifest_content_id)? {
        debug!("Already have manifest {manifest_digest}");
        verity
    } else {
        debug!("Storing manifest {manifest_digest}");

        let mut splitstream = repo.create_stream(OCI_MANIFEST_CONTENT_TYPE)?;

        let config_key = format!("config:{}", config_descriptor.digest());
        splitstream.add_named_stream_ref(&config_key, &config_verity);

        // Add layer refs in config-defined diff_id order
        for (diff_id, verity) in &layer_refs {
            splitstream.add_named_stream_ref(diff_id.as_ref(), verity);
        }

        let mut raw_manifest = Vec::with_capacity(manifest_descriptor.size() as usize);
        oci.read_blob(manifest_descriptor)
            .context("Reading raw manifest bytes")?
            .read_to_end(&mut raw_manifest)?;
        splitstream.write_external(&raw_manifest)?;
        repo.write_stream(splitstream, &manifest_content_id, None)?
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

/// Import config and all layers from an OCI layout.
///
/// Returns (config_digest, config_verity, layer_refs, stats).
/// `layer_refs` is an ordered Vec of (diff_id, verity) pairs preserving the
/// order from the config (or manifest for artifacts).
async fn import_config_and_layers<ObjectID: FsVerityHashValue, T: OciRead + Send + Sync>(
    repo: &Arc<Repository<ObjectID>>,
    oci: &T,
    manifest_layers: &[Descriptor],
    config_descriptor: &Descriptor,
    reporter: &SharedReporter,
) -> Result<(OciDigest, ObjectID, Vec<(OciDigest, ObjectID)>, ImportStats)> {
    let config_digest = config_descriptor.digest().clone();
    let content_id = config_identifier(&config_digest);

    if let Some(config_id) = repo.has_stream(&content_id)? {
        debug!("Already have container config {config_digest}");

        let (data, named_refs) = crate::oci_image::read_external_splitstream(
            repo,
            &content_id,
            Some(&config_id),
            Some(OCI_CONFIG_CONTENT_TYPE),
        )
        .with_context(|| format!("Failed to read cached config {config_digest}"))?;
        let named_refs_map: HashMap<&str, ObjectID> = named_refs
            .iter()
            .map(|(k, v)| (k.as_ref(), v.clone()))
            .collect();

        let diff_ids = crate::extract_diff_ids(
            config_descriptor.media_type(),
            data.as_slice(),
            manifest_layers,
        )
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

        // Emit Skipped for each cached layer so callers can close any open progress bars
        for (diff_id, _) in &layer_refs {
            reporter.report(ProgressEvent::Skipped {
                id: ComponentId::from(diff_id.to_string()),
            });
        }

        return Ok((config_digest, config_id, layer_refs, ImportStats::default()));
    }

    // Read config blob — we need the raw bytes for splitstream storage below,
    // and parse diff_ids from the same buffer via as_slice().
    debug!("Reading config {config_digest}");
    let mut raw_config = Vec::with_capacity(config_descriptor.size() as usize);
    oci.read_blob(config_descriptor)
        .with_context(|| format!("Failed to read config {config_digest}"))?
        .read_to_end(&mut raw_config)
        .with_context(|| format!("Failed to read config {config_digest}"))?;
    let diff_ids = crate::extract_diff_ids(
        config_descriptor.media_type(),
        raw_config.as_slice(),
        manifest_layers,
    )
    .with_context(|| format!("Failed to parse config {config_digest}"))?;

    // Sort layers by size for parallel fetching (largest first)
    let mut layers: Vec<_> = manifest_layers.iter().zip(&diff_ids).collect();
    layers.sort_by_key(|(desc, _)| Reverse(desc.size()));

    let threads = available_parallelism()?;
    let sem = Arc::new(Semaphore::new(threads.into()));
    let mut layer_tasks = JoinSet::new();

    for (idx, (descriptor, diff_id)) in layers.iter().enumerate() {
        let diff_id = (*diff_id).clone();
        let repo = Arc::clone(repo);
        let permit = Arc::clone(&sem).acquire_owned().await?;
        let reporter = Arc::clone(reporter);

        let layer_reader = oci
            .read_blob(descriptor)
            .with_context(|| format!("Opening layer blob {}", descriptor.digest()))?;

        let media_type = descriptor.media_type().clone();
        let layer_size = descriptor.size();
        let layer_digest = descriptor.digest().clone();

        layer_tasks.spawn(async move {
            let _permit = permit;
            let (verity, layer_stats) = import_layer_from_blob(
                &repo,
                &diff_id,
                layer_reader,
                &media_type,
                layer_size,
                &reporter,
            )
            .await
            .with_context(|| format!("Failed to import layer {layer_digest}"))?;
            anyhow::Ok((idx, diff_id, verity, layer_stats))
        });
    }

    // Collect results into a map keyed by diff_id for ordered lookup
    let mut verity_map: HashMap<OciDigest, ObjectID> = HashMap::new();
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

    let mut splitstream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE)?;
    for (diff_id, verity) in &layer_refs {
        splitstream.add_named_stream_ref(diff_id.as_ref(), verity);
    }

    splitstream.write_external(&raw_config)?;
    let config_id = repo.write_stream(splitstream, &content_id, None)?;

    Ok((config_digest, config_id, layer_refs, stats))
}

/// Import a single layer by streaming from a blob reader.
///
/// Emits `Started`/`Done` (or `Skipped`) progress events via `reporter`.
async fn import_layer_from_blob<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    diff_id: &OciDigest,
    layer_reader: impl BlobStream + 'static,
    media_type: &MediaType,
    layer_size: u64,
    reporter: &SharedReporter,
) -> Result<(ObjectID, ImportStats)> {
    let content_id = layer_identifier(diff_id);
    let id = ComponentId::from(diff_id.to_string());

    if let Some(layer_id) = repo.has_stream(&content_id)? {
        debug!("Already have layer {diff_id}");
        reporter.report(ProgressEvent::Skipped { id });
        return Ok((layer_id, ImportStats::default()));
    }

    debug!("Importing layer {diff_id}");
    reporter.report(ProgressEvent::Started {
        id: id.clone(),
        total: Some(layer_size),
        unit: ProgressUnit::Bytes,
    });

    // Wrap the file reader to emit Progress events as compressed bytes are read.
    // This sits before decompression so `fetched` tracks bytes-on-disk,
    // matching the `total` from the descriptor size above.
    //
    // The watch channel provides backpressure: if the renderer is slow, intermediate
    // byte counts are coalesced rather than queued, keeping the I/O path non-blocking.
    let (async_file, progress_driver) = ProgressRead::new(
        BlockingReader::new(layer_reader),
        Arc::clone(reporter),
        id.clone(),
        Some(layer_size),
    );

    let (object_id, layer_stats) = if is_tar_media_type(media_type) {
        // Run the progress driver concurrently with the import.
        let reader = decompress_async(async_file, media_type)?;
        let (result, ()) = tokio::join!(import_tar_async(repo.clone(), reader), progress_driver);
        result?
    } else {
        // Non-tar blob: store as object and create splitstream wrapper.
        // Run the progress driver concurrently with the blob store.
        let (store_result, ()) = tokio::join!(store_blob_async(repo, async_file), progress_driver);
        let (object_id, size, method) = store_result?;

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
        let stream_id = repo.write_stream(stream, &content_id, None)?;
        reporter.report(ProgressEvent::Done {
            id,
            transferred: size,
        });
        return Ok((stream_id, stats));
    };

    // Register the stream with its content identifier
    repo.register_stream(&object_id, &content_id, None).await?;

    reporter.report(ProgressEvent::Done {
        id,
        transferred: layer_size,
    });
    Ok((object_id, layer_stats))
}

/// Blob reader that owns an [`OciRead`] backend, for use with delta imports.
struct OciBlobReader<T: OciRead + Send + Sync>(T);

impl<T: OciRead + Send + Sync> oci_delta::DeltaBlobReader for OciBlobReader<T> {
    fn open_blob(&self, desc: &Descriptor) -> oci_delta::BlobStreamFuture<'_> {
        let result = self
            .0
            .read_blob(desc)
            .map(|r| Box::new(r) as Box<dyn BlobStream>)
            .with_context(|| format!("Reading blob {}", desc.digest()));
        Box::pin(std::future::ready(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::NullReporter;

    /// A reader that yields `head`, then fails.
    struct FailingReader {
        head: std::io::Cursor<Vec<u8>>,
    }

    impl Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.head.read(buf)? {
                0 => Err(std::io::Error::other("blob read failed")),
                n => Ok(n),
            }
        }
    }

    #[tokio::test]
    async fn test_blocking_reader_propagates_error() {
        use tokio::io::AsyncReadExt;

        let head = vec![b'x'; 4096];
        let mut reader = BlockingReader::new(Box::new(FailingReader {
            head: std::io::Cursor::new(head.clone()),
        }));

        let mut buf = Vec::new();
        let err = reader.read_to_end(&mut buf).await.unwrap_err();

        assert_eq!(err.to_string(), "blob read failed");
        assert_eq!(buf, head);
    }

    #[tokio::test]
    async fn test_blocking_reader_clean_eof() {
        use tokio::io::AsyncReadExt;

        // Larger than the duplex buffer, so the copy blocks and completes only
        // as the consumer drains it.
        let data = vec![b'y'; READ_BUF_SIZE * 3 + 17];
        let mut reader = BlockingReader::new(Box::new(std::io::Cursor::new(data.clone())));

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf, data);
    }

    #[test]
    fn test_is_uncompressed_tar() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let tar = crate::test_util::dumpfile_to_tar(
            "/ 0 40755 2 0 0 0 0.0 - - -\n\
             /foo 0 100644 1 0 0 0 0.0 - - -\n",
        );

        let plain = dir.path().join("plain.tar");
        std::fs::write(&plain, &tar).unwrap();
        assert!(is_uncompressed_tar(&plain));

        let gzipped = dir.path().join("compressed.tar.gz");
        let mut encoder = flate2::write::GzEncoder::new(
            std::fs::File::create(&gzipped).unwrap(),
            flate2::Compression::default(),
        );
        encoder.write_all(&tar).unwrap();
        encoder.finish().unwrap();
        assert!(!is_uncompressed_tar(&gzipped));

        assert!(!is_uncompressed_tar(&dir.path().join("does-not-exist.tar")));
        assert!(!is_uncompressed_tar(dir.path()));
    }

    #[test]
    fn test_parse_oci_layout_ref() {
        let cases: &[(&str, (&str, Option<&str>))] = &[
            ("/path/to/oci", ("/path/to/oci", None)),
            ("./local/oci", ("./local/oci", None)),
            ("ocidir", ("ocidir", None)),
            ("/path/to/oci:latest", ("/path/to/oci", Some("latest"))),
            ("/path/to/oci:v1.0.0", ("/path/to/oci", Some("v1.0.0"))),
            ("./local/oci:mytag", ("./local/oci", Some("mytag"))),
            ("ocidir:latest", ("ocidir", Some("latest"))),
            ("C:/path/to/oci", ("C:/path/to/oci", None)),
            ("C:/path/to/oci:latest", ("C:/path/to/oci", Some("latest"))),
            (
                "/path/to/oci:tag:with:colons",
                ("/path/to/oci:tag:with", Some("colons")),
            ),
            ("/path/to/oci:", ("/path/to/oci", Some(""))),
            ("ocidir:", ("ocidir", Some(""))),
            ("/path:middle/to/oci", ("/path:middle/to/oci", None)),
            (
                "/path:middle/to/oci:tag",
                ("/path:middle/to/oci", Some("tag")),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(parse_oci_layout_ref(input), *expected, "input: {input}");
        }
    }

    /// A missing path must be reported as the kind the caller asked for,
    /// rather than being silently treated as the other kind.
    #[tokio::test]
    async fn test_missing_path_reports_requested_kind() {
        use composefs::fsverity::Sha256HashValue;
        use composefs::test::TestRepo;

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let missing = std::path::Path::new("/does/not/exist");

        let cases = [
            (OciLayoutKind::Archive, "Opening OCI archive"),
            (OciLayoutKind::Directory, "Opening OCI layout directory"),
        ];
        for (kind, expected) in cases {
            let err = import_oci_layout(
                &test_repo.repo,
                kind,
                missing,
                None,
                std::sync::Arc::new(NullReporter),
            )
            .await
            .expect_err("should fail on a missing path");
            let err = format!("{err:#}");
            assert!(err.contains(expected), "{kind:?}: unexpected error: {err}");
        }
    }

    #[tokio::test]
    async fn test_wrong_platform_rejected() {
        use cap_std_ext::cap_std;
        use composefs::fsverity::Sha256HashValue;
        use containers_image_proxy::oci_spec::image::{
            Arch, ConfigBuilder, ImageConfigurationBuilder, Os, PlatformBuilder, RootFsBuilder,
        };

        let tempdir = tempfile::tempdir().unwrap();
        let layout_path = tempdir.path();

        let dir =
            cap_std::fs::Dir::open_ambient_dir(layout_path, cap_std::ambient_authority()).unwrap();
        let ocidir = OciDir::ensure(dir).unwrap();

        // Pick an architecture that differs from the host
        let foreign_arch = if Arch::default() == Arch::Amd64 {
            "s390x"
        } else {
            "amd64"
        };

        // Build a minimal image for the foreign platform
        let manifest = ocidir.new_empty_manifest().unwrap().build().unwrap();
        let config = ImageConfigurationBuilder::default()
            .architecture(foreign_arch)
            .os("linux")
            .rootfs(
                RootFsBuilder::default()
                    .typ("layers")
                    .diff_ids(Vec::<String>::new())
                    .build()
                    .unwrap(),
            )
            .config(ConfigBuilder::default().build().unwrap())
            .build()
            .unwrap();
        let platform = PlatformBuilder::default()
            .architecture(foreign_arch)
            .os(Os::default())
            .build()
            .unwrap();
        ocidir
            .insert_manifest_and_config(manifest, config, None, platform)
            .unwrap();

        let repo_dir = tempfile::tempdir().unwrap();
        let repo_path = repo_dir.path().join("repo");
        let (repo, _) = composefs::repository::Repository::<Sha256HashValue>::init_path(
            rustix::fs::CWD,
            &repo_path,
            composefs::repository::RepositoryConfig::default().set_insecure(),
        )
        .unwrap();
        let repo = std::sync::Arc::new(repo);

        let reporter = std::sync::Arc::new(NullReporter);
        let result =
            import_oci_layout(&repo, OciLayoutKind::Directory, layout_path, None, reporter).await;
        let err = result.expect_err("should fail with no matching platform");
        let err_msg = format!("{err:#}");
        assert!(
            err_msg.contains("No manifest found for platform"),
            "unexpected error: {err_msg}"
        );
    }
}
