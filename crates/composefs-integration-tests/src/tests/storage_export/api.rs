//! Native importer exercised through the shared image source interface.

use std::sync::Arc;

use crate::integration_test;
use cap_std_ext::cap_std::{self, ambient_authority};
use composefs::fsverity::{Sha256HashValue, Sha512HashValue};
use composefs::progress::{
    ProgressEvent, ProgressReporter, ProgressUnit, test_support::RecordingReporter,
};
use composefs::repository::RepositoryConfig;
use composefs::{fsverity::FsVerityHashValue, repository::Repository};
use composefs_oci::{ImageSource, OciDigest};
use composefs_storage as cstorage;
use cstorage::writer::StoreLocation;
use cstorage::writer::{ImportOptions, import_image};
use std::time::Duration;

use crate::tests::privileged::{LoopTempDir, require_privileged};

struct RecordingSource<H: FsVerityHashValue> {
    inner: ImageSource<H>,
    requested: Vec<usize>,
}

impl<H: FsVerityHashValue> cstorage::writer::ImageSource for RecordingSource<H> {
    type Error = anyhow::Error;

    fn manifest_digest(&self) -> &str {
        self.inner.image().manifest_digest().as_ref()
    }

    fn manifest_json(&self) -> &[u8] {
        self.inner.manifest_json()
    }

    fn config_json(&self) -> &[u8] {
        self.inner.config_json()
    }

    async fn get_layer(
        &mut self,
        index: usize,
    ) -> anyhow::Result<composefs_splitdirfdstream::SplitDirFdStream> {
        self.requested.push(index);
        cstorage::writer::ImageSource::get_layer(&mut self.inner, index).await
    }
}

struct ExportFixture<H: FsVerityHashValue> {
    repo: Arc<Repository<H>>,
    digest: OciDigest,
    manifest: Vec<u8>,
    diffs: Vec<OciDigest>,
    size: u64,
}

fn fixture<H: FsVerityHashValue>(
    root: &std::path::Path,
    count: usize,
) -> anyhow::Result<ExportFixture<H>> {
    let (repo, _) = Repository::<H>::init_path(
        rustix::fs::CWD,
        root.join("repo"),
        RepositoryConfig::new(H::ALGORITHM).set_insecure(),
    )?;
    let repo = Arc::new(repo);
    let payload = vec![91u8; 128 * 1024 + 1];
    let mut refs = Vec::new();
    let mut sizes = Vec::new();
    for index in 0..count {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_uid(rustix::process::geteuid().as_raw() as u64);
        header.set_gid(rustix::process::getegid().as_raw() as u64);
        header.set_mode(0o755);
        header.set_size(0);
        header.set_mtime(123 + index as u64);
        header.set_cksum();
        tar.append_data(&mut header, ".", std::io::empty())?;
        tar.append_data(&mut header, "usr", std::io::empty())?;
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(payload.len() as u64);
        header.set_cksum();
        tar.append_data(&mut header, "payload", payload.as_slice())?;
        let tar = tar.into_inner()?;
        let diff = composefs_oci::sha256_content_digest(&tar);
        let mut writer = repo.create_stream(composefs_oci::LAYER_CONTENT_TYPE)?;
        writer.write_inline(&tar[..1536]);
        writer.write_external(&payload)?;
        writer.write_inline(&tar[1536 + payload.len()..]);
        let layer = repo.write_stream(writer, &composefs_oci::layer_content_id(&diff), None)?;
        refs.push((diff, layer));
        sizes.push(tar.len());
    }
    let diff_ids = refs.iter().map(|r| r.0.to_string()).collect::<Vec<_>>();
    let config = composefs_oci::test_util::make_config_json(&diff_ids);
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": composefs_oci::sha256_content_digest(&config),
            "size": config.len(),
        },
        "layers": refs.iter().zip(sizes).map(|((diff, _), size)| {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": diff,
                "size": size,
            })
        }).collect::<Vec<_>>(),
    }))?;
    let ((digest, _), _) = composefs_oci::layer_sync::finalize_oci_image(
        &repo, &manifest, &config, &refs, None, None,
    )?;
    Ok(ExportFixture {
        repo,
        digest,
        manifest,
        diffs: refs.into_iter().map(|r| r.0).collect(),
        size: payload.len() as u64 * count as u64,
    })
}

fn destination(root: &std::path::Path) -> anyhow::Result<StoreLocation> {
    let root = cap_std::fs::Dir::open_ambient_dir(root, ambient_authority())?;
    Ok(StoreLocation {
        graphroot: root,
        graphroot_path: Some("graph".into()),
        runroot: None,
        runroot_path: None,
    })
}

async fn round_trip<H: FsVerityHashValue>() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let ExportFixture {
        repo,
        digest,
        manifest,
        diffs,
        size,
    } = fixture::<H>(temp.path(), 2)?;
    let reporter = Arc::new(RecordingReporter::new());
    let mut source = RecordingSource {
        inner: ImageSource::open(&repo, &digest).await?,
        requested: Vec::new(),
    };
    let result = import_image(
        &mut source,
        destination(temp.path())?,
        &["localhost/test:export".into()],
        ImportOptions::default(),
        Some(reporter.clone()),
    )
    .await?;
    assert_eq!(result.manifest_digest, digest);
    assert_eq!(
        result.stats.reflinked_bytes + result.stats.copied_bytes,
        size
    );
    let path = temp
        .path()
        .join("graph/overlay-images")
        .join(&result.image_id)
        .join("manifest");
    assert_eq!(std::fs::read(path)?, manifest);
    let storage = cstorage::Storage::open(temp.path().join("graph"))?;
    let image = cstorage::Image::open(&storage, &result.image_id)?;
    assert_eq!(image.read_manifest_raw()?, manifest);
    assert_eq!(
        image.layers()?,
        diffs
            .iter()
            .map(|d| d.digest().to_string())
            .collect::<Vec<_>>()
    );
    let events = reporter.events();
    assert!(matches!(
        events.first(),
        Some(ProgressEvent::Started {
            unit: ProgressUnit::Items,
            total: Some(2),
            ..
        })
    ));
    assert_eq!(
        events
            .iter()
            .filter_map(|e| match e {
                ProgressEvent::Progress { fetched, .. } => Some(*fetched),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(matches!(
        events.last(),
        Some(ProgressEvent::Done { transferred: 2, .. })
    ));
    assert_eq!(source.requested, vec![0, 1]);
    source.requested.clear();
    let retry = import_image(
        &mut source,
        destination(temp.path())?,
        &[],
        Default::default(),
        None,
    )
    .await?;
    assert!(retry.already_present);
    assert_eq!(retry.stats.reused_layers, 2);
    assert!(source.requested.is_empty());
    Ok(())
}

fn test_storage_import_with_one_blocking_worker() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()?
        .block_on(async {
            round_trip::<Sha256HashValue>().await?;
            round_trip::<Sha512HashValue>().await
        })
}

async fn export_reflinks<H: FsVerityHashValue>(root: &std::path::Path) -> anyhow::Result<()> {
    let ExportFixture {
        repo, digest, size, ..
    } = fixture::<H>(root, 2)?;
    let mut source = ImageSource::open(&repo, &digest).await?;
    let result = import_image(
        &mut source,
        destination(root)?,
        &[],
        ImportOptions::default(),
        None,
    )
    .await?;

    println!("XFS [{:?}] export stats: {:?}", H::ALGORITHM, result.stats);
    assert_eq!(result.stats.reflinked_files, 2);
    assert_eq!(result.stats.reflinked_bytes, size);
    assert_eq!(result.stats.copied_files, 0);
    assert_eq!(result.stats.copied_bytes, 0);
    Ok(())
}

fn privileged_storage_export_xfs_reflink() -> anyhow::Result<()> {
    if require_privileged("privileged_storage_export_xfs_reflink")?.is_some() {
        return Ok(());
    }
    // Match the XFS import test's optional xfsprogs dependency.
    if !std::path::Path::new("/usr/sbin/mkfs.xfs").exists()
        && !std::path::Path::new("/sbin/mkfs.xfs").exists()
    {
        println!("SKIP: mkfs.xfs not available");
        return Ok(());
    }

    // Keep each source repository and its graphroot on the same reflink-capable
    // filesystem. Separate directories prevent reuse between algorithm cases.
    let fs = LoopTempDir::xfs_reflink()?;
    tokio::runtime::Runtime::new()?.block_on(async {
        let sha256 = tempfile::tempdir_in(fs.path())?;
        export_reflinks::<Sha256HashValue>(sha256.path()).await?;
        let sha512 = tempfile::tempdir_in(fs.path())?;
        export_reflinks::<Sha512HashValue>(sha512.path()).await
    })
}

async fn dropping_export_cancels_a_repository_lease_wait() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let ExportFixture { repo, digest, .. } = fixture::<Sha256HashValue>(temp.path(), 1)?;
    rustix::fs::flock(
        repo.repo_fd(),
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )?;
    let mut pending = Box::pin(ImageSource::open(&repo, &digest));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut pending)
            .await
            .is_err()
    );
    drop(pending);
    assert!(
        !temp
            .path()
            .join("graph/overlay-layers/layers.json")
            .exists()
    );
    rustix::fs::flock(repo.repo_fd(), rustix::fs::FlockOperation::LockShared)?;
    tokio::time::timeout(Duration::from_secs(5), repo.lease_async()).await??;
    Ok(())
}

struct CancelAfterLayer(std::sync::Mutex<Option<tokio::task::AbortHandle>>);
impl ProgressReporter for CancelAfterLayer {
    fn report(&self, event: ProgressEvent) {
        if matches!(event, ProgressEvent::Progress { fetched: 1, .. }) {
            self.0.lock().unwrap().as_ref().unwrap().abort();
        }
    }
}

async fn cancellation_between_layers_leaves_a_reusable_layer_and_no_image() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let ExportFixture { repo, digest, .. } = fixture::<Sha256HashValue>(temp.path(), 2)?;
    let destination = destination(temp.path())?;
    let reporter = Arc::new(CancelAfterLayer(std::sync::Mutex::new(None)));
    let progress = reporter.clone();
    let task = tokio::spawn(async move {
        let mut source = ImageSource::open(&repo, &digest).await?;
        import_image(
            &mut source,
            destination,
            &[],
            Default::default(),
            Some(progress),
        )
        .await
        .map_err(anyhow::Error::from)
    });
    *reporter.0.lock().unwrap() = Some(task.abort_handle());
    assert!(task.await.unwrap_err().is_cancelled());
    let layers: Vec<serde_json::Value> = serde_json::from_slice(&std::fs::read(
        temp.path().join("graph/overlay-layers/layers.json"),
    )?)?;
    assert_eq!(layers.len(), 1);
    assert!(layers[0].get("flags").is_none());
    assert!(
        !temp
            .path()
            .join("graph/overlay-images/images.json")
            .exists()
    );
    Ok(())
}

fn test_storage_import_source_lease_wait() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(dropping_export_cancels_a_repository_lease_wait())
}

fn test_storage_import_cancellation_between_layers() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(cancellation_between_layers_leaves_a_reusable_layer_and_no_image())
}

integration_test!(test_storage_import_with_one_blocking_worker);
integration_test!(privileged_storage_export_xfs_reflink);
integration_test!(test_storage_import_source_lease_wait);
integration_test!(test_storage_import_cancellation_between_layers);
