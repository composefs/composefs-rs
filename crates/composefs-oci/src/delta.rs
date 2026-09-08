//! OCI delta support: detect and apply oci-delta artifacts during pull.
//!
//! An oci-delta artifact has `artifactType` set to the delta media type.
//! Its layers contain the target image manifest, config, and changed layer
//! blobs (as tar-diff patches or original gzip layers). Layers identical
//! between source and target (by diff_id) are omitted from the delta.
//! For more information, see <https://github.com/containers/oci-delta>

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::available_parallelism;

use anyhow::{Context, Result, bail, ensure};
use composefs::erofs::reader::erofs_to_filesystem;
use composefs::fsverity::FsVerityHashValue;
use composefs::repository::Repository;
use composefs::tree::RegularFile;
use containers_image_proxy::oci_spec::image::{
    Digest as OciDigest, ImageConfiguration, ImageManifest, MediaType,
};

use oci_delta::{
    BlobStream, DeltaBlobReader, DeltaDataSource, parse_delta_manifest, reconstruct_layer_to,
};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::oci_image;
use crate::progress::{ComponentId, ProgressEvent, ProgressUnit, SharedReporter};
use crate::skopeo::PullResult;
use crate::{ImportStats, layer_identifier};

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

impl<ObjectID: FsVerityHashValue> DeltaDataSource for ComposeFsDataSource<ObjectID> {
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
            RegularFile::External(id, _size) | RegularFile::ExternalNoVerity(id, _size) => {
                let fd = self
                    .source
                    .repo
                    .open_object(id)
                    .with_context(|| format!("Opening source object for {}", path.display()))?;
                CurrentFile::External(File::from(fd))
            }
            RegularFile::Sparse(_) => {
                anyhow::bail!(
                    "Sparse file not supported as delta source: {}",
                    path.display()
                );
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

    /// Read the whole current file, leaving the cursor at end of file.
    fn read_current_to_end(&mut self, max_size: u64) -> Result<Vec<u8>> {
        let current = self
            .current
            .as_mut()
            .context("No current file set in data source")?;
        let size = current.seek(SeekFrom::End(0))?;
        ensure!(
            size <= max_size,
            "Source file too large: {size} > {max_size}"
        );
        current.seek(SeekFrom::Start(0))?;
        let mut data = Vec::with_capacity(size as usize);
        current.read_to_end(&mut data)?;
        Ok(data)
    }

    fn copy_to(&mut self, dst: &mut dyn Write, n: u64) -> Result<()> {
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

/// Reconstruct a single layer's uncompressed tar from a delta blob.
/// Returns a seeked-to-start temp file with diff_id already verified.
fn reconstruct_layer<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    source_image: &Arc<SourceImage<ObjectID>>,
    blob_reader: impl BlobStream + 'static,
    media_type: &MediaType,
    expected_diff_id: &OciDigest,
) -> Result<File> {
    let tmpfile_fd = repo
        .create_object_tmpfile()
        .context("Creating temp file for layer reconstruction")?;
    let mut tmpfile = File::from(tmpfile_fd);
    let mut data_source = ComposeFsDataSource {
        source: Arc::clone(source_image),
        current: None,
    };

    reconstruct_layer_to(
        blob_reader,
        media_type,
        &mut data_source,
        expected_diff_id,
        &mut tmpfile,
    )?;

    tmpfile.seek(SeekFrom::Start(0))?;
    Ok(tmpfile)
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

    let manifest_digest = parsed.target_manifest_descriptor.digest();
    let config_digest = parsed.target_config_descriptor.digest();

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

    let erofs_version = repo.erofs_version();
    let erofs_id =
        crate::composefs_erofs_for_config(repo, &parsed.source_config_digest, None, erofs_version)?
            .with_context(|| {
                format!(
                    "Source image (config {}) exists but has no {erofs_version:?} EROFS image. \
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

        if let Some(delta_descriptor) = delta_layer {
            let content_id = layer_identifier(diff_id);
            if let Some(verity) = repo.has_stream(&content_id)? {
                stats.layers += 1;
                stats.layers_already_present += 1;
                completed.fetch_add(1, Ordering::Relaxed);
                immediate_results.insert(i, (diff_id.clone(), verity));
                continue;
            }

            let diff_id = diff_id.clone();
            let descriptor = delta_descriptor.clone();
            let repo = Arc::clone(repo);
            let source_image = Arc::clone(&source_image);
            let blob_reader = Arc::clone(&blob_reader);
            let reporter = Arc::clone(reporter);
            let progress_id = progress_id.clone();
            let completed = Arc::clone(&completed);
            let permit = Arc::clone(&sem).acquire_owned().await?;

            layer_tasks.spawn(async move {
                let _permit = permit;

                let blob = blob_reader
                    .open_blob(&descriptor)
                    .await
                    .with_context(|| format!("Fetching delta blob for layer {diff_id}"))?;

                let media_type = descriptor.media_type().clone();
                let reconstructed = tokio::task::spawn_blocking({
                    let diff_id = diff_id.clone();
                    let repo = Arc::clone(&repo);
                    move || -> Result<File> {
                        reconstruct_layer(&repo, &source_image, blob, &media_type, &diff_id)
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
        &HashMap::new(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci_layout::OciLayoutKind;
    use composefs::fsverity::Sha256HashValue;
    use composefs::test::TestRepo;
    use std::path::PathBuf;

    const TAR_DIFF_HEADER_V1: &[u8; 8] = b"tardf1\n\0";
    const TAR_DIFF_HEADER_V2: &[u8; 8] = b"tardf2\n\0";
    const OP_COPY: u8 = 2;
    const OP_ADD_DATA: u8 = 3;
    const OP_SEEK: u8 = 4;
    const OP_ZSTD_DICT: u8 = 5;
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

    const SOURCE_NAME: &str = "data/blob.bin";
    /// A composefs data source with content from a tar file
    async fn tar_to_compose(
        repo: &Arc<Repository<Sha256HashValue>>,
        tar: &[u8],
    ) -> ComposeFsDataSource<Sha256HashValue> {
        let (layer_id, _stats) = crate::layer::import_tar_async(Arc::clone(repo), tar)
            .await
            .expect("importing source layer");

        let mut fs = composefs::tree::FileSystem::new(composefs::tree::Stat::uninitialized());
        let mut stream = repo
            .open_stream(
                "",
                Some(&layer_id),
                Some(crate::skopeo::TAR_LAYER_CONTENT_TYPE),
            )
            .expect("opening source layer stream");
        while let Some(entry) = crate::tar::get_entry(&mut stream).expect("reading tar entry") {
            crate::image::process_entry(&mut fs, entry).expect("processing tar entry");
        }

        ComposeFsDataSource {
            source: Arc::new(SourceImage {
                fs,
                repo: Arc::clone(repo),
            }),
            current: None,
        }
    }

    #[tokio::test]
    async fn test_read_current_to_end_size_limit() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let mut data_source = tar_to_compose(&test_repo.repo, &blob_layer_tar(b"0123456789")).await;
        data_source.set_current_file(SOURCE_NAME).unwrap();

        let err = data_source
            .read_current_to_end(9)
            .expect_err("a source over the limit must be refused");
        assert!(
            format!("{err:#}").contains("Source file too large"),
            "unexpected error: {err:#}"
        );
        assert_eq!(data_source.read_current_to_end(10).unwrap(), b"0123456789");
    }

    bitflags::bitflags! {
        /// A set of oci-delta capabilities that only newer builds have.
        #[derive(Clone, Copy)]
        struct OciDeltaFeatures: u32 {
            /// `--binary-diff` (and with it the tardf2 zstd-dict op) was added
            /// in oci-delta 0.6; older builds only ever emit tardf1.
            const BINARY_DIFF = 1 << 0;
        }
    }

    /// The oci-delta binary, if it is installed and has all of `required`.
    /// Reports why it is unavailable, for tests that then skip themselves.
    fn have_oci_delta(required: OciDeltaFeatures) -> Option<PathBuf> {
        let bin = PathBuf::from("oci-delta");
        if std::process::Command::new(&bin)
            .arg("--help")
            .output()
            .is_err()
        {
            eprintln!("skipping: oci-delta not found in PATH");
            return None;
        }
        if required.contains(OciDeltaFeatures::BINARY_DIFF)
            && !delta_create_help(&bin).contains("--binary-diff")
        {
            eprintln!("skipping: oci-delta has no --binary-diff support");
            return None;
        }
        Some(bin)
    }

    fn create_delta(oci_delta_bin: &Path, source: &Path, target: &Path) -> tempfile::TempDir {
        create_delta_with(oci_delta_bin, source, target, &[])
    }

    fn create_delta_with(
        oci_delta_bin: &Path,
        source: &Path,
        target: &Path,
        extra_args: &[&str],
    ) -> tempfile::TempDir {
        let delta_dir = tempfile::tempdir().expect("creating delta tempdir");
        let status = std::process::Command::new(oci_delta_bin)
            .arg("create")
            .args(extra_args)
            .arg(format!("oci:{}", source.display()))
            .arg(format!("oci:{}", target.display()))
            .arg(format!("oci:{}", delta_dir.path().display()))
            .status()
            .expect("running oci-delta");
        assert!(status.success(), "oci-delta create failed: {status}");
        delta_dir
    }

    fn delta_create_help(oci_delta_bin: &Path) -> String {
        let out = std::process::Command::new(oci_delta_bin)
            .args(["create", "--help"])
            .output()
            .expect("running oci-delta create --help");
        assert!(
            out.status.success(),
            "oci-delta create --help failed: {}",
            out.status
        );
        let help = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            help.contains("--signature"),
            "unrecognised oci-delta create --help output, the probes against it are stale:\n{help}"
        );
        help
    }

    async fn pull_from_layout(
        repo: &Arc<Repository<Sha256HashValue>>,
        layout_dir: &Path,
    ) -> (OciDigest, OciDigest) {
        let reporter: SharedReporter = Arc::new(crate::NullReporter);
        let (pull_result, _stats) = crate::oci_layout::import_oci_layout(
            repo,
            OciLayoutKind::Directory,
            layout_dir,
            None,
            reporter,
        )
        .await
        .expect("importing OCI layout");

        crate::ensure_oci_composefs_erofs(
            repo,
            &pull_result.manifest_digest,
            Some(&pull_result.manifest_verity),
            None,
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

    /// A layer tar holding a single file with exactly `content`. Built directly
    /// rather than via a dumpfile because dumpfile lines are capped at 512
    /// bytes and `Item::Regular` derives its content from the size alone, which
    /// would leave the source and target blobs unrelated.
    fn blob_layer_tar(content: &[u8]) -> Vec<u8> {
        let mut builder = ::tar::Builder::new(Vec::new());

        let mut header = ::tar::Header::new_ustar();
        header.set_entry_type(::tar::EntryType::Directory);
        header.set_mode(0o755);
        header.set_size(0);
        builder
            .append_data(&mut header, "data/", std::io::empty())
            .unwrap();

        let mut header = ::tar::Header::new_ustar();
        header.set_entry_type(::tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(content.len() as u64);
        builder
            .append_data(&mut header, "data/blob.bin", content)
            .unwrap();

        builder.into_inner().unwrap()
    }

    /// Incompressible source and target contents that differ only in the
    /// middle, so tar-diff has something worth encoding as a binary diff and a
    /// zstd-dict patch comes out much smaller than the target itself.
    fn similar_blobs() -> (Vec<u8>, Vec<u8>) {
        let source: Vec<u8> = (0..32768u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let mut target = source.clone();
        target[10000..10256].fill(0x5a);
        target.extend_from_slice(b"appended target-only bytes");
        (source, target)
    }

    // Completely new layer (target only)
    const LAYER_NEW: &str = "\
        /opt 0 40755 2 0 0 0 0.0 - - -\n\
        /opt/newfile.bin 2048 100644 1 0 0 0 0.0 / - -\n";

    /// Source and target layouts sharing one layer, differing in a second one,
    /// with a third present only in the target.  The differing layer holds
    /// similar (not unrelated) blobs, so tar-diff encodes it with real
    /// Copy/AddData or ZstdDict ops rather than emitting it verbatim as Data.
    fn build_test_layouts() -> (tempfile::TempDir, tempfile::TempDir) {
        let (source_blob, target_blob) = similar_blobs();
        let source = crate::test_util::build_oci_layout_from_tars(&[
            crate::test_util::dumpfile_to_tar(LAYER_SHARED),
            blob_layer_tar(&source_blob),
        ]);
        let target = crate::test_util::build_oci_layout_from_tars(&[
            crate::test_util::dumpfile_to_tar(LAYER_SHARED),
            blob_layer_tar(&target_blob),
            crate::test_util::dumpfile_to_tar(LAYER_NEW),
        ]);
        (source, target)
    }

    fn build_test_fixtures(
        oci_delta_bin: &Path,
    ) -> (tempfile::TempDir, tempfile::TempDir, tempfile::TempDir) {
        let (source, target) = build_test_layouts();
        let delta = create_delta(oci_delta_bin, source.path(), target.path());
        (source, target, delta)
    }

    /// The set of opcodes used across all tar-diff blobs in a delta layout, so
    /// tests can fail loudly if oci-delta stops emitting the op they cover.
    fn delta_ops(layout_dir: &Path) -> std::collections::HashSet<u8> {
        let blobs = layout_dir.join("blobs/sha256");
        let mut seen = std::collections::HashSet::new();
        for entry in std::fs::read_dir(blobs).expect("reading delta blobs") {
            let blob =
                std::fs::read(entry.expect("delta blob entry").path()).expect("reading delta blob");
            if !blob.starts_with(TAR_DIFF_HEADER_V1) && !blob.starts_with(TAR_DIFF_HEADER_V2) {
                continue;
            }
            let ops = zstd::stream::decode_all(&blob[8..]).expect("decompressing tar-diff");
            let mut r = io::BufReader::new(&ops[..]);
            let mut op = [0u8; 1];
            while r.read_exact(&mut op).is_ok() {
                let size = read_uvarint(&mut r).expect("tar-diff op size");
                seen.insert(op[0]);
                if !matches!(op[0], OP_COPY | OP_SEEK) {
                    io::copy(&mut Read::by_ref(&mut r).take(size), &mut io::sink())
                        .expect("skipping tar-diff op data");
                }
            }
        }
        seen
    }

    #[tokio::test]
    async fn test_pull_delta_end_to_end() {
        let Some(oci_delta_bin) = have_oci_delta(OciDeltaFeatures::empty()) else {
            return;
        };
        let (source, target, delta) = build_test_fixtures(&oci_delta_bin);
        let ops = delta_ops(delta.path());
        assert!(
            ops.iter()
                .any(|op| matches!(*op, OP_COPY | OP_ADD_DATA | OP_SEEK | OP_ZSTD_DICT)),
            "delta only replays whole files ({ops:?}), so it exercises no diff op"
        );

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

    /// `--binary-diff zstd` makes oci-delta emit tardf2 deltas whose changed
    /// layers use the ZstdDict op instead of bsdiff.
    #[tokio::test]
    async fn test_pull_delta_zstd_binary_diff() {
        let Some(oci_delta_bin) = have_oci_delta(OciDeltaFeatures::BINARY_DIFF) else {
            return;
        };
        let (source, target) = build_test_layouts();
        let delta = create_delta_with(
            &oci_delta_bin,
            source.path(),
            target.path(),
            &["--binary-diff", "zstd"],
        );
        assert!(
            delta_ops(delta.path()).contains(&OP_ZSTD_DICT),
            "delta has no ZstdDict op, so it would not exercise the v2 path"
        );

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        pull_from_layout(repo, source.path()).await;
        let (delta_manifest, delta_config) = pull_from_layout(repo, delta.path()).await;
        let (target_manifest, target_config) = pull_from_layout(repo, target.path()).await;

        assert_eq!(delta_manifest, target_manifest, "manifest digest mismatch");
        assert_eq!(delta_config, target_config, "config digest mismatch");
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
        let Some(oci_delta_bin) = have_oci_delta(OciDeltaFeatures::empty()) else {
            return;
        };
        let (source, target, delta) = build_test_fixtures(&oci_delta_bin);

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;
        let reporter: SharedReporter = Arc::new(crate::NullReporter);

        // Pull source via oci-archive:
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
        let Some(oci_delta_bin) = have_oci_delta(OciDeltaFeatures::empty()) else {
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
