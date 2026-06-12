//! OCI delta support: detect and apply oci-delta artifacts during pull.
//!
//! An oci-delta artifact has `artifactType` set to the delta media type.
//! Its layers contain the target image manifest, config, and changed layer
//! blobs (as tar-diff patches or original gzip layers). Layers identical
//! between source and target (by diff_id) are omitted from the delta.
//! For more information, see https://github.com/containers/oci-delta

use std::collections::HashMap;
use std::fs::File;
use std::future::Future;
use std::io::{self, BufRead, BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::available_parallelism;

use anyhow::{Context, Result, bail, ensure};
use composefs::erofs::reader::erofs_to_filesystem;
use composefs::fsverity::FsVerityHashValue;
use composefs::repository::Repository;
use composefs::tree::RegularFile;
use containers_image_proxy::oci_spec::image::{
    Digest as OciDigest, DigestAlgorithm, ImageConfiguration, ImageManifest, MediaType,
};

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::oci_image;
use crate::progress::{ComponentId, ProgressEvent, ProgressUnit, SharedReporter};
use crate::skopeo::PullResult;
use crate::{ImportStats, layer_identifier};

pub(crate) const MEDIA_TYPE_DELTA: &str = "application/vnd.io.github.containers.oci-delta.v1";
fn media_type_tar_diff() -> MediaType {
    MediaType::Other("application/vnd.tar-diff".to_string())
}
const ANNOTATION_DELTA_SOURCE_CONFIG: &str = "io.github.containers.delta.source-config";
const ANNOTATION_DELTA_TO: &str = "io.github.containers.delta.to";
const ANNOTATION_DELTA_CONTENT: &str = "io.github.containers.delta.content";

const TAR_DIFF_HEADER: &[u8; 8] = b"tardf1\n\0";

// tar-diff opcodes
const OP_DATA: u8 = 0;
const OP_OPEN: u8 = 1;
const OP_COPY: u8 = 2;
const OP_ADD_DATA: u8 = 3;
const OP_SEEK: u8 = 4;

// DoS protection limits from the Go tar-patch reference implementation
const MAX_FILENAME_SIZE: u64 = 4 * 1024;
const MAX_ADD_DATA_SIZE: u64 = 100 * 1024 * 1024;

// ─── Blob reader trait ──────────────────────────────────────────────────────

/// Read blobs from a delta artifact by digest.
///
/// Implemented for OCI layout directories and pre-fetched blob maps
/// (used by the skopeo proxy path which fetches blobs asynchronously).
pub(crate) trait DeltaBlobReader: Send + Sync {
    /// Open a blob for reading by digest.
    /// For local storage this opens the file directly. For remote transports
    /// this fetches the blob to a local temp file first.
    fn open_blob(
        &self,
        digest: &OciDigest,
    ) -> Pin<Box<dyn Future<Output = Result<File>> + Send + '_>>;
}

/// Check whether an OCI manifest is a delta artifact.
pub(crate) fn is_delta_artifact(manifest: &ImageManifest) -> bool {
    manifest
        .artifact_type()
        .as_ref()
        .is_some_and(|t| t.to_string() == MEDIA_TYPE_DELTA)
}

// ─── Composefs-backed data source for tar-patch ─────────────────────────────

/// Shared source image state: the parsed EROFS filesystem and the repository.
struct SourceImage<ObjectID: FsVerityHashValue> {
    fs: composefs::tree::FileSystem<ObjectID>,
    repo: Arc<Repository<ObjectID>>,
}

enum CurrentFile {
    Inline(Cursor<Vec<u8>>),
    External(File),
}

impl Read for CurrentFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            CurrentFile::Inline(c) => c.read(buf),
            CurrentFile::External(f) => f.read(buf),
        }
    }
}

impl Seek for CurrentFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            CurrentFile::Inline(c) => c.seek(pos),
            CurrentFile::External(f) => f.seek(pos),
        }
    }
}

/// Per-task mutable cursor into the shared source image filesystem.
struct ComposeFsDataSource<ObjectID: FsVerityHashValue> {
    source: Arc<SourceImage<ObjectID>>,
    current: Option<CurrentFile>,
}

impl<ObjectID: FsVerityHashValue> ComposeFsDataSource<ObjectID> {
    fn set_current_file(&mut self, path: &str) -> Result<()> {
        let path = Path::new(path);
        let (dir, filename) = self
            .source
            .fs
            .root
            .split(path.as_os_str())
            .with_context(|| format!("Source file not found: {}", path.display()))?;
        let file = dir
            .get_file(filename, &self.source.fs.leaves)
            .with_context(|| format!("Source file not found: {}", path.display()))?;

        self.current = Some(match file {
            RegularFile::Inline(data) => CurrentFile::Inline(Cursor::new(data.to_vec())),
            RegularFile::External(id, _size) => {
                let fd = self
                    .source
                    .repo
                    .open_object(id)
                    .with_context(|| format!("Opening source object for {}", path.display()))?;
                CurrentFile::External(File::from(fd))
            }
        });
        Ok(())
    }

    fn read_exact_current(&mut self, buf: &mut [u8]) -> Result<()> {
        let current = self
            .current
            .as_mut()
            .context("No current file set in data source")?;
        current.read_exact(buf)?;
        Ok(())
    }

    fn seek_current(&mut self, offset: u64) -> Result<u64> {
        let current = self
            .current
            .as_mut()
            .context("No current file set in data source")?;
        Ok(current.seek(SeekFrom::Start(offset))?)
    }

    fn copy_to(&mut self, dst: &mut impl Write, n: u64) -> Result<()> {
        let current = self
            .current
            .as_mut()
            .context("No current file set in data source")?;
        let copied = io::copy(&mut Read::by_ref(current).take(n), dst)?;
        ensure!(
            copied == n,
            "Short read from data source: expected {n}, got {copied}"
        );
        Ok(())
    }
}

// ─── Tar-patch apply ────────────────────────────────────────────────────────

fn read_uvarint(r: &mut impl io::BufRead) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift: u8 = 0;
    loop {
        let mut byte = [0u8; 1];
        r.read_exact(&mut byte)?;
        let bits = (byte[0] & 0x7f) as u64;
        ensure!(
            shift < 64 && bits <= (u64::MAX >> shift),
            "uvarint overflow"
        );
        result |= bits << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(result);
        }
        shift = shift.checked_add(7).context("uvarint overflow")?;
    }
}

enum OciHasher {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl OciHasher {
    fn new(algorithm: &DigestAlgorithm) -> Result<Self> {
        use sha2::Digest;
        match algorithm {
            &DigestAlgorithm::Sha256 => Ok(Self::Sha256(sha2::Sha256::new())),
            &DigestAlgorithm::Sha384 => Ok(Self::Sha384(sha2::Sha384::new())),
            &DigestAlgorithm::Sha512 => Ok(Self::Sha512(sha2::Sha512::new())),
            other => bail!("Unsupported digest algorithm: {other}"),
        }
    }

    fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
        }
    }

    fn finalize(self) -> Result<OciDigest> {
        use sha2::Digest;
        let (algorithm, hex) = match self {
            Self::Sha256(h) => ("sha256", hex::encode(h.finalize())),
            Self::Sha384(h) => ("sha384", hex::encode(h.finalize())),
            Self::Sha512(h) => ("sha512", hex::encode(h.finalize())),
        };
        format!("{algorithm}:{hex}")
            .parse()
            .context("Constructed digest")
    }
}

struct HashingWriter<'a, W: Write> {
    inner: &'a mut W,
    hasher: &'a mut OciHasher,
}

impl<W: Write> Write for HashingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn tar_patch_apply<ObjectID: FsVerityHashValue>(
    delta: impl Read,
    data_source: &mut ComposeFsDataSource<ObjectID>,
    mut dst: impl Write,
) -> Result<()> {
    let mut header_buf = [0u8; 8];
    let mut reader = io::BufReader::new(delta);
    reader.read_exact(&mut header_buf)?;
    ensure!(header_buf == *TAR_DIFF_HEADER, "Invalid tar-diff header");

    let decoder =
        zstd::stream::read::Decoder::new(reader).context("Creating zstd decoder for tar-diff")?;
    let mut r = io::BufReader::new(decoder);

    loop {
        let buf = r.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        let op = buf[0];
        r.consume(1);
        let size = read_uvarint(&mut r)?;

        match op {
            OP_DATA => {
                let copied = io::copy(&mut (&mut r).take(size), &mut dst)?;
                ensure!(
                    copied == size,
                    "Short OP_DATA: expected {size}, got {copied}"
                );
            }
            OP_OPEN => {
                ensure!(
                    size <= MAX_FILENAME_SIZE,
                    "Filename size {size} exceeds limit"
                );
                let mut name_buf = vec![0u8; size as usize];
                r.read_exact(&mut name_buf)?;
                let name =
                    String::from_utf8(name_buf).context("Invalid UTF-8 in tar-diff filename")?;
                data_source.set_current_file(&name)?;
            }
            OP_COPY => {
                data_source.copy_to(&mut dst, size)?;
            }
            OP_ADD_DATA => {
                ensure!(
                    size <= MAX_ADD_DATA_SIZE,
                    "AddData size {size} exceeds limit"
                );
                let mut delta_bytes = vec![0u8; size as usize];
                r.read_exact(&mut delta_bytes)?;
                let mut source_bytes = vec![0u8; size as usize];
                data_source
                    .read_exact_current(&mut source_bytes)
                    .context("Reading source data for AddData")?;
                let n = source_bytes.len();
                for i in 0..n {
                    delta_bytes[i] = delta_bytes[i].wrapping_add(source_bytes[i]);
                }
                dst.write_all(&delta_bytes)?;
            }
            OP_SEEK => {
                data_source.seek_current(size)?;
            }
            _ => bail!("Unexpected tar-diff op {op}"),
        }
    }

    Ok(())
}

// ─── Delta layer reconstruction ─────────────────────────────────────────────

/// Reconstruct a single layer's uncompressed tar from a delta blob.
/// Returns a seeked-to-start temp file with diff_id already verified.
fn decompress_layer(reader: File, media_type: &MediaType) -> Result<Box<dyn Read + Send>> {
    let buf = BufReader::new(reader);
    match media_type {
        MediaType::ImageLayer | MediaType::ImageLayerNonDistributable => Ok(Box::new(buf)),
        MediaType::ImageLayerGzip | MediaType::ImageLayerNonDistributableGzip => {
            Ok(Box::new(BufReader::new(flate2::read::GzDecoder::new(buf))))
        }
        MediaType::ImageLayerZstd | MediaType::ImageLayerNonDistributableZstd => Ok(Box::new(
            BufReader::new(zstd::stream::read::Decoder::new(buf)?),
        )),
        _ => bail!("Unsupported layer media type: {media_type}"),
    }
}

fn reconstruct_layer<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    source_image: &Arc<SourceImage<ObjectID>>,
    blob_file: File,
    media_type: &MediaType,
    expected_diff_id: &OciDigest,
) -> Result<File> {
    let tmpfile_fd = repo
        .create_object_tmpfile()
        .context("Creating temp file for layer reconstruction")?;
    let mut tmpfile = File::from(tmpfile_fd);
    let mut hasher = OciHasher::new(expected_diff_id.algorithm())?;

    if *media_type == media_type_tar_diff() {
        let mut data_source = ComposeFsDataSource {
            source: Arc::clone(source_image),
            current: None,
        };
        let mut hashing_writer = HashingWriter {
            inner: &mut tmpfile,
            hasher: &mut hasher,
        };
        tar_patch_apply(blob_file, &mut data_source, &mut hashing_writer)?;
    } else {
        let mut decoder = decompress_layer(blob_file, media_type)?;
        let mut hashing_writer = HashingWriter {
            inner: &mut tmpfile,
            hasher: &mut hasher,
        };
        io::copy(&mut decoder, &mut hashing_writer)?;
    }

    let computed_diff_id = hasher.finalize()?;
    ensure!(
        computed_diff_id == *expected_diff_id,
        "Layer diff_id mismatch: expected {expected_diff_id}, got {computed_diff_id}",
    );

    tmpfile.seek(SeekFrom::Start(0))?;
    Ok(tmpfile)
}

// ─── Delta manifest parsing ─────────────────────────────────────────────────

struct DeltaLayer {
    blob_digest: OciDigest,
    media_type: MediaType,
}

struct ParsedDelta {
    target_manifest: ImageManifest,
    target_manifest_digest: OciDigest,
    target_manifest_raw: Vec<u8>,
    target_config_digest: OciDigest,
    target_config_raw: Vec<u8>,
    source_config_digest: OciDigest,
    delta_layer_by_to: HashMap<OciDigest, DeltaLayer>,
}

/// Parse a delta artifact's manifest and extract the embedded target image
/// manifest, config, and layer mapping. Blobs are fetched via `blob_reader`.
async fn parse_delta_manifest(
    delta_manifest: &ImageManifest,
    blob_reader: &dyn DeltaBlobReader,
) -> Result<ParsedDelta> {
    let annotations = delta_manifest
        .annotations()
        .as_ref()
        .context("Delta manifest has no annotations")?;

    let source_config_digest: OciDigest = annotations
        .get(ANNOTATION_DELTA_SOURCE_CONFIG)
        .context("Delta missing source config digest annotation")?
        .parse()
        .context("Invalid source config digest")?;

    let mut target_manifest_digest = None;
    let mut target_config_digest = None;
    let mut delta_layer_by_to = HashMap::new();

    for layer in delta_manifest.layers() {
        let layer_annotations = layer.annotations();
        let content = layer_annotations
            .as_ref()
            .and_then(|a| a.get(ANNOTATION_DELTA_CONTENT))
            .map(|s| s.as_str())
            .unwrap_or("");

        match content {
            "image-manifest" => {
                target_manifest_digest = Some(layer.digest().clone());
            }
            "image-config" => {
                target_config_digest = Some(layer.digest().clone());
            }
            "image-layer" => {
                if let Some(to_str) = layer_annotations
                    .as_ref()
                    .and_then(|a| a.get(ANNOTATION_DELTA_TO))
                    .filter(|s| !s.is_empty())
                {
                    let to_digest: OciDigest = to_str.parse().context("Invalid delta.to digest")?;
                    delta_layer_by_to.insert(
                        to_digest,
                        DeltaLayer {
                            blob_digest: layer.digest().clone(),
                            media_type: layer.media_type().clone(),
                        },
                    );
                }
            }
            _ => {}
        }
    }

    let target_manifest_digest =
        target_manifest_digest.context("Delta manifest has no embedded image manifest")?;
    let target_config_digest =
        target_config_digest.context("Delta manifest has no embedded image config")?;

    let mut target_manifest_raw = Vec::new();
    blob_reader
        .open_blob(&target_manifest_digest)
        .await
        .context("Fetching embedded image manifest")?
        .read_to_end(&mut target_manifest_raw)?;
    let target_manifest = ImageManifest::from_reader(&target_manifest_raw[..])
        .context("Parsing embedded image manifest")?;

    let mut target_config_raw = Vec::new();
    blob_reader
        .open_blob(&target_config_digest)
        .await
        .context("Fetching embedded image config")?
        .read_to_end(&mut target_config_raw)?;
    // Validate it parses
    ImageConfiguration::from_reader(&target_config_raw[..])
        .context("Parsing embedded image config")?;

    Ok(ParsedDelta {
        target_manifest,
        target_manifest_digest,
        target_manifest_raw,
        target_config_digest,
        target_config_raw,
        source_config_digest,
        delta_layer_by_to,
    })
}

// ─── Import delta ───────────────────────────────────────────────────────────

/// Import a delta artifact into the repository, reconstructing the target image.
///
/// The delta manifest has already been fetched and parsed by the pull path.
/// Blobs are accessed via `blob_reader` (backed by OCI layout or pre-fetched map).
///
/// Returns the same `PullResult` and `ImportStats` as a normal pull.
pub(crate) async fn import_delta<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    delta_manifest: &ImageManifest,
    blob_reader: Arc<dyn DeltaBlobReader>,
    reporter: &SharedReporter,
    max_concurrency: Option<usize>,
) -> Result<(PullResult<ObjectID>, ImportStats)> {
    let parsed = parse_delta_manifest(delta_manifest, &*blob_reader).await?;

    let manifest_digest = &parsed.target_manifest_digest;
    let config_digest = &parsed.target_config_digest;

    // Check if the target image already exists
    if let Some(manifest_verity) = oci_image::has_manifest(repo, manifest_digest)? {
        reporter.report(ProgressEvent::Message(
            "Target image already present.".into(),
        ));
        let config_verity = repo
            .has_stream(&crate::config_identifier(config_digest))?
            .context("Manifest exists but config is missing")?;
        return Ok((
            PullResult {
                manifest_digest: manifest_digest.clone(),
                manifest_verity,
                config_digest: config_digest.clone(),
                config_verity,
            },
            ImportStats::default(),
        ));
    }

    // Extract diff_ids from target config
    let target_config = ImageConfiguration::from_reader(&parsed.target_config_raw[..])?;
    let diff_ids: Vec<OciDigest> = target_config
        .rootfs()
        .diff_ids()
        .iter()
        .map(|s| s.parse().context("parsing diff_id"))
        .collect::<Result<_>>()?;
    ensure!(
        diff_ids.len() == parsed.target_manifest.layers().len(),
        "diff_id count ({}) doesn't match layer count ({})",
        diff_ids.len(),
        parsed.target_manifest.layers().len(),
    );

    // Verify the source image exists in the repository before doing any work
    reporter.report(ProgressEvent::Message("Looking up source image...".into()));
    let source_config_id = crate::config_identifier(&parsed.source_config_digest);
    if repo.has_stream(&source_config_id)?.is_none() {
        bail!(
            "The delta is based on an image with config {}, \
             but it is not present in the repository. \
             The delta cannot be applied.",
            parsed.source_config_digest,
        );
    }

    let source_config = crate::open_config(repo, &parsed.source_config_digest, None)?;
    let erofs_id = source_config.image_ref.with_context(|| {
        format!(
            "Source image (config {}) exists but has no EROFS image. \
             Try re-pulling the base image with a current version of cfsctl.",
            parsed.source_config_digest,
        )
    })?;

    // Build the shared file index from the source image's EROFS
    reporter.report(ProgressEvent::Message(
        "Building data source from base image...".into(),
    ));
    let erofs_data = repo
        .read_object(&erofs_id)
        .context("Reading base EROFS image")?;
    let fs = erofs_to_filesystem::<ObjectID>(&erofs_data).context("Parsing base EROFS image")?;
    let source_image = Arc::new(SourceImage {
        fs,
        repo: Arc::clone(repo),
    });

    // Process layers in parallel
    let n_layers = diff_ids.len() as u64;
    let progress_id = ComponentId::from("apply-delta".to_string());
    reporter.report(ProgressEvent::Started {
        id: progress_id.clone(),
        total: Some(n_layers),
        unit: ProgressUnit::Items,
    });

    let mut layer_tasks = JoinSet::new();
    let mut immediate_results: HashMap<usize, (OciDigest, ObjectID)> = HashMap::new();
    let mut stats = ImportStats::default();

    let concurrency = max_concurrency.unwrap_or(available_parallelism()?.into());
    let sem = Arc::new(Semaphore::new(concurrency));
    let completed = Arc::new(AtomicU64::new(0));

    for (i, (layer_desc, diff_id)) in parsed
        .target_manifest
        .layers()
        .iter()
        .zip(&diff_ids)
        .enumerate()
    {
        let delta_layer = parsed.delta_layer_by_to.get(layer_desc.digest());

        if let Some(dl) = delta_layer {
            let content_id = layer_identifier(diff_id);
            if let Some(verity) = repo.has_stream(&content_id)? {
                stats.layers += 1;
                stats.layers_already_present += 1;
                completed.fetch_add(1, Ordering::Relaxed);
                immediate_results.insert(i, (diff_id.clone(), verity));
                continue;
            }

            let diff_id = diff_id.clone();
            let blob_digest = dl.blob_digest.clone();
            let media_type = dl.media_type.clone();
            let repo = Arc::clone(repo);
            let source_image = Arc::clone(&source_image);
            let blob_reader = Arc::clone(&blob_reader);
            let reporter = Arc::clone(reporter);
            let progress_id = progress_id.clone();
            let completed = Arc::clone(&completed);
            let permit = Arc::clone(&sem).acquire_owned().await?;

            layer_tasks.spawn(async move {
                let _permit = permit;

                let blob_file = blob_reader
                    .open_blob(&blob_digest)
                    .await
                    .with_context(|| format!("Fetching delta blob for layer {diff_id}"))?;

                let reconstructed = tokio::task::spawn_blocking({
                    let diff_id = diff_id.clone();
                    let repo = Arc::clone(&repo);
                    move || -> Result<File> {
                        reconstruct_layer(&repo, &source_image, blob_file, &media_type, &diff_id)
                            .with_context(|| format!("Reconstructing layer {diff_id}"))
                    }
                })
                .await??;

                let tar_file = tokio::fs::File::from_std(reconstructed);
                let (verity, layer_stats) =
                    crate::import_layer(&repo, &diff_id, None, tar_file).await?;

                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                reporter.report(ProgressEvent::Progress {
                    id: progress_id,
                    fetched: done,
                    total: Some(n_layers),
                });

                anyhow::Ok((i, diff_id, verity, layer_stats))
            });
        } else {
            // Reused layer — must already exist in repo
            let layer_id = layer_identifier(diff_id);
            let verity = repo
                .has_stream(&layer_id)?
                .with_context(|| format!("Reused layer {diff_id} not found"))?;
            stats.layers += 1;
            stats.layers_already_present += 1;
            completed.fetch_add(1, Ordering::Relaxed);
            immediate_results.insert(i, (diff_id.clone(), verity));
        }
    }

    // Collect parallel results
    for result in layer_tasks.join_all().await {
        let (_, _, _, layer_stats) = result?;
        stats.merge(&layer_stats);
        stats.layers += 1;
    }

    reporter.report(ProgressEvent::Done {
        id: progress_id,
        transferred: n_layers,
    });

    // Assemble layer_refs in manifest order
    let mut layer_refs: Vec<(OciDigest, ObjectID)> = Vec::with_capacity(diff_ids.len());
    for (i, diff_id) in diff_ids.iter().enumerate() {
        if let Some((d, v)) = immediate_results.remove(&i) {
            layer_refs.push((d, v));
        } else {
            let content_id = layer_identifier(diff_id);
            let verity = repo
                .has_stream(&content_id)?
                .with_context(|| format!("Layer {diff_id} missing after import"))?;
            layer_refs.push((diff_id.clone(), verity));
        }
    }

    // Write config splitstream
    reporter.report(ProgressEvent::Message(
        "Storing config and manifest...".into(),
    ));
    let refs_map: HashMap<Box<str>, ObjectID> = layer_refs
        .iter()
        .map(|(diff_id, verity)| (diff_id.to_string().into_boxed_str(), verity.clone()))
        .collect();

    let (_, config_verity) = crate::write_config_raw(
        repo,
        &parsed.target_config_raw,
        refs_map,
        None,
        None,
        None,
        None,
    )?;

    // Write manifest splitstream (using raw bytes to preserve original JSON)
    let layer_verities: Vec<_> = layer_refs
        .iter()
        .map(|(d, v)| (d.to_string(), v.clone()))
        .collect();

    let (_, manifest_verity) = oci_image::rewrite_manifest(
        repo,
        &parsed.target_manifest_raw,
        manifest_digest,
        &config_verity,
        &layer_verities,
        None,
    )?;

    Ok((
        PullResult {
            manifest_digest: manifest_digest.clone(),
            manifest_verity,
            config_digest: config_digest.clone(),
            config_verity,
        },
        stats,
    ))
}

/// Return references to all layer descriptors in a delta manifest.
pub(crate) fn delta_layer_descriptors(
    manifest: &ImageManifest,
) -> &[containers_image_proxy::oci_spec::image::Descriptor] {
    manifest.layers()
}

#[cfg(test)]
mod tests {
    use super::*;
    use composefs::fsverity::Sha256HashValue;
    use composefs::test::TestRepo;
    use std::path::PathBuf;

    fn uvarint(bytes: &[u8]) -> Result<u64> {
        read_uvarint(&mut io::BufReader::new(bytes))
    }

    #[test]
    fn test_read_uvarint() {
        assert_eq!(uvarint(&[0]).unwrap(), 0);
        assert_eq!(uvarint(&[1]).unwrap(), 1);
        assert_eq!(uvarint(&[0x7f]).unwrap(), 127);
        assert_eq!(uvarint(&[0x80, 0x01]).unwrap(), 128);
        assert_eq!(uvarint(&[0xac, 0x02]).unwrap(), 300);
        assert_eq!(uvarint(&[0xff, 0x7f]).unwrap(), 16383);
        assert_eq!(uvarint(&[0x80, 0x80, 0x01]).unwrap(), 16384);
        // u64::MAX = 0xffff_ffff_ffff_ffff
        assert_eq!(
            uvarint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]).unwrap(),
            u64::MAX,
        );
    }

    #[test]
    fn test_read_uvarint_overflow() {
        // 10 bytes with all continuation bits set overflows shift
        assert!(uvarint(&[0x80; 10]).is_err());
        // 11 continuation bytes
        assert!(uvarint(&[0x80; 11]).is_err());
        // 10th byte value > 1 overflows u64 (2 << 63 > u64::MAX)
        assert!(uvarint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]).is_err());
        // 10th byte value == 1 is the last valid encoding (1 << 63 fits)
        assert_eq!(
            uvarint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]).unwrap(),
            u64::MAX,
        );
    }

    #[test]
    fn test_read_uvarint_truncated() {
        // Continuation bit set but no more bytes
        assert!(uvarint(&[0x80]).is_err());
        assert!(uvarint(&[]).is_err());
    }

    fn have_oci_delta() -> Option<PathBuf> {
        std::process::Command::new("oci-delta")
            .arg("--help")
            .output()
            .ok()
            .map(|_| PathBuf::from("oci-delta"))
    }

    fn create_delta(oci_delta_bin: &Path, source: &Path, target: &Path) -> tempfile::TempDir {
        let delta_dir = tempfile::tempdir().expect("creating delta tempdir");
        let status = std::process::Command::new(oci_delta_bin)
            .arg("create")
            .arg(format!("oci:{}", source.display()))
            .arg(format!("oci:{}", target.display()))
            .arg(format!("oci:{}", delta_dir.path().display()))
            .status()
            .expect("running oci-delta");
        assert!(status.success(), "oci-delta create failed: {status}");
        delta_dir
    }

    async fn pull_from_layout(
        repo: &Arc<Repository<Sha256HashValue>>,
        layout_dir: &Path,
    ) -> (OciDigest, OciDigest) {
        let reporter: SharedReporter = Arc::new(crate::NullReporter);
        let (pull_result, _stats) =
            crate::oci_layout::import_oci_layout(repo, layout_dir, None, reporter)
                .await
                .expect("importing OCI layout");

        crate::ensure_oci_composefs_erofs(
            repo,
            &pull_result.manifest_digest,
            Some(&pull_result.manifest_verity),
            None,
        )
        .expect("generating EROFS");

        (pull_result.manifest_digest, pull_result.config_digest)
    }

    // Shared layer (reused in delta)
    const LAYER_SHARED: &str = "\
        /etc 0 40755 2 0 0 0 0.0 - - -\n\
        /etc/hostname 9 100644 1 0 0 0 0.0 - testhost\\n -\n\
        /usr 0 40755 2 0 0 0 0.0 - - -\n\
        /usr/bin 0 40755 2 0 0 0 0.0 - - -\n\
        /usr/bin/hello 21 100755 1 0 0 0 0.0 - #!/bin/sh\\necho\\x20hello\\n -\n";

    // Layer with a 4KB file (source version)
    const LAYER_BLOB_V1: &str = "\
        /data 0 40755 2 0 0 0 0.0 - - -\n\
        /data/blob.bin 4096 100644 1 0 0 0 0.0 / - -\n";

    // Layer with same structure but different size (target — triggers tar-diff)
    const LAYER_BLOB_V2: &str = "\
        /data 0 40755 2 0 0 0 0.0 - - -\n\
        /data/blob.bin 4000 100644 1 0 0 0 0.0 / - -\n";

    // Completely new layer (target only)
    const LAYER_NEW: &str = "\
        /opt 0 40755 2 0 0 0 0.0 - - -\n\
        /opt/newfile.bin 2048 100644 1 0 0 0 0.0 / - -\n";

    fn build_test_fixtures(
        oci_delta_bin: &Path,
    ) -> (tempfile::TempDir, tempfile::TempDir, tempfile::TempDir) {
        let source = crate::test_util::build_oci_layout(&[LAYER_SHARED, LAYER_BLOB_V1]);
        let target = crate::test_util::build_oci_layout(&[LAYER_SHARED, LAYER_BLOB_V2, LAYER_NEW]);
        let delta = create_delta(oci_delta_bin, source.path(), target.path());
        (source, target, delta)
    }

    #[tokio::test]
    async fn test_pull_delta_end_to_end() {
        let Some(oci_delta_bin) = have_oci_delta() else {
            eprintln!("skipping: oci-delta not found in PATH");
            return;
        };
        let (source, target, delta) = build_test_fixtures(&oci_delta_bin);

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Import source image
        pull_from_layout(repo, source.path()).await;

        // Pull the delta (goes through import_oci_layout → delta detection)
        let (delta_manifest, delta_config) = pull_from_layout(repo, delta.path()).await;

        // Import target image directly for comparison
        let (target_manifest, target_config) = pull_from_layout(repo, target.path()).await;

        // Manifest and config digests must match
        assert_eq!(delta_manifest, target_manifest, "manifest digest mismatch");
        assert_eq!(delta_config, target_config, "config digest mismatch");
    }

    fn have_skopeo() -> bool {
        std::process::Command::new("skopeo")
            .arg("--version")
            .output()
            .is_ok()
    }

    fn tar_oci_layout(layout_dir: &Path) -> tempfile::NamedTempFile {
        let archive = tempfile::NamedTempFile::new().expect("creating archive tempfile");
        let status = std::process::Command::new("tar")
            .arg("-cf")
            .arg(archive.path())
            .arg("-C")
            .arg(layout_dir)
            .arg(".")
            .status()
            .expect("running tar");
        assert!(status.success(), "tar failed: {status}");
        archive
    }

    #[tokio::test]
    async fn test_pull_delta_oci_archive() {
        let Some(oci_delta_bin) = have_oci_delta() else {
            eprintln!("skipping: oci-delta not found in PATH");
            return;
        };
        if !have_skopeo() {
            eprintln!("skipping: skopeo not found in PATH");
            return;
        }
        let (source, target, delta) = build_test_fixtures(&oci_delta_bin);

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;
        let reporter: SharedReporter = Arc::new(crate::NullReporter);

        // Pull source via oci-archive: (through skopeo)
        let source_archive = tar_oci_layout(source.path());
        let source_ref = format!("oci-archive:{}", source_archive.path().display());
        crate::pull(
            repo,
            &source_ref,
            None,
            crate::PullOptions {
                progress: Some(Arc::clone(&reporter)),
                ..Default::default()
            },
        )
        .await
        .expect("pulling source");

        // Pull delta via oci-archive: (should detect delta and apply)
        let delta_archive = tar_oci_layout(delta.path());
        let delta_ref = format!("oci-archive:{}", delta_archive.path().display());
        let delta_result = crate::pull(
            repo,
            &delta_ref,
            None,
            crate::PullOptions {
                progress: Some(Arc::clone(&reporter)),
                ..Default::default()
            },
        )
        .await
        .expect("pulling delta");

        // Pull target directly for comparison
        let (target_manifest, target_config) = pull_from_layout(repo, target.path()).await;

        assert_eq!(
            delta_result.manifest_digest, target_manifest,
            "manifest digest mismatch"
        );
        assert_eq!(
            delta_result.config_digest, target_config,
            "config digest mismatch"
        );
    }

    #[tokio::test]
    async fn test_pull_delta_idempotent() {
        let Some(oci_delta_bin) = have_oci_delta() else {
            eprintln!("skipping: oci-delta not found in PATH");
            return;
        };
        let (source, _target, delta) = build_test_fixtures(&oci_delta_bin);

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        pull_from_layout(repo, source.path()).await;

        // Pull delta twice — second should be a no-op
        let (digest1, _) = pull_from_layout(repo, delta.path()).await;
        let (digest2, _) = pull_from_layout(repo, delta.path()).await;
        assert_eq!(digest1, digest2);
    }
}
