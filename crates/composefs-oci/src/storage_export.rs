//! Exporting images from a composefs repository to containers/storage.
//!
//! Exports preserve OCI metadata and layer content for use by containers/storage
//! consumers such as Podman and Skopeo.

use std::sync::Arc;

use composefs::{
    fsverity::FsVerityHashValue,
    progress::{ComponentId, ProgressEvent, ProgressUnit, SharedReporter},
    repository::{Repository, RepositoryLease},
    splitstream::{SplitStreamChunk, SplitStreamReader},
};
use cstorage::writer::{
    ImportError, ImportOptions, LayerChunk, LayerSource, LayerStatus, PublishedImage, RawImage,
    Result, StorageWriter,
};

use crate::{OciDigest, oci_image::OciImage};

/// Export an image selected by manifest digest and assign the requested names.
///
/// Progress counts completed or reused layers. Dropping the future stops further
/// layers; a layer or final publication already running on a worker finishes.
pub async fn export_to_containers_storage<H: FsVerityHashValue>(
    repo: &Arc<Repository<H>>,
    manifest: &OciDigest,
    destination: StorageWriter,
    names: &[String],
    options: ImportOptions,
    progress: Option<SharedReporter>,
) -> Result<PublishedImage> {
    // An Arc keeps the repository handle alive, but GC through that same handle
    // can upgrade its shared lock. A separate lease prevents that upgrade while
    // export still needs source objects. Layer workers retain their own lease
    // reference so cancellation cannot release it while they are running.
    let lease = Arc::new(repo.lease_async().await.map_err(source_error)?);

    let (image, manifest_json, config_json) =
        OciImage::open_with_raw_metadata(repo, manifest, None).map_err(source_error)?;
    let raw = RawImage {
        expected_manifest: image.manifest_digest().clone(),
        manifest_json,
        config_json,
    };

    let mut import = destination.begin_image(raw, options).await?;
    let diff_ids = image.layer_diff_ids();
    let total = diff_ids.len() as u64;

    let id = ComponentId::from(format!("storage-export:{}", image.manifest_digest()));
    let report = |event| {
        if let Some(reporter) = &progress {
            reporter.report(event);
        }
    };
    report(ProgressEvent::Started {
        id: id.clone(),
        total: Some(total),
        unit: ProgressUnit::Items,
    });

    for (i, diff) in diff_ids.into_iter().enumerate() {
        // Give cancellation a boundary even when every layer is already present.
        tokio::task::yield_now().await;

        match import.layer_status(i as u32)? {
            LayerStatus::Reusable(_) => {
                report(ProgressEvent::Message(format!(
                    "Reusing layer {}/{total}",
                    i + 1
                )));
            }
            LayerStatus::NeedsParent => return Err(ImportError::NeedsParent(i as u32)),
            LayerStatus::Missing => {
                let verity = image
                    .layer_verity(diff)
                    .ok_or_else(|| {
                        ImportError::Malformed(format!("missing splitstream reference for {diff}"))
                    })?
                    .clone();
                report(ProgressEvent::Message(format!(
                    "Importing layer {}/{total}",
                    i + 1
                )));
                import
                    .put_layer(
                        i as u32,
                        RepositoryLayerSource {
                            repo: Arc::clone(repo),
                            _lease: Arc::clone(&lease),
                            diff: diff.parse().map_err(source_error)?,
                            verity,
                            stream: None,
                        },
                    )
                    .await?;
            }
        }
        report(ProgressEvent::Progress {
            id: id.clone(),
            fetched: (i + 1) as u64,
            total: Some(total),
        });
    }
    report(ProgressEvent::Message(
        "Publishing image to containers/storage".into(),
    ));
    let publication = import.prepare_publication().await?;
    let published = publication.finish(names).await?;
    report(ProgressEvent::Done {
        id,
        transferred: total,
    });
    Ok(published)
}

fn source_error(error: impl Into<anyhow::Error>) -> ImportError {
    ImportError::Io(std::io::Error::other(error.into()))
}

#[derive(Debug)]
struct RepositoryLayerSource<H: FsVerityHashValue> {
    repo: Arc<Repository<H>>,
    _lease: Arc<RepositoryLease>,
    diff: OciDigest,
    verity: H,
    stream: Option<SplitStreamReader<H>>,
}
impl<H: FsVerityHashValue> LayerSource for RepositoryLayerSource<H> {
    fn next_chunk(&mut self, buffer: &mut [u8]) -> Result<Option<LayerChunk>> {
        let stream = match &mut self.stream {
            Some(stream) => stream,
            empty @ None => empty.insert(
                self.repo
                    .open_stream(
                        &crate::layer_identifier(&self.diff),
                        Some(&self.verity),
                        Some(crate::LAYER_CONTENT_TYPE),
                    )
                    .map_err(source_error)?,
            ),
        };
        match stream.next_chunk(buffer).map_err(source_error)? {
            None => Ok(None),
            Some(SplitStreamChunk::Inline(bytes)) => Ok(Some(LayerChunk::Inline(bytes.len()))),
            Some(SplitStreamChunk::External(id)) => {
                let file = std::fs::File::from(self.repo.open_object(&id).map_err(source_error)?);
                let length = file.metadata()?.len();
                Ok(Some(LayerChunk::File { file, length }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::ambient_authority;
    use composefs::fsverity::{Sha256HashValue, Sha512HashValue};
    use composefs::progress::{ProgressReporter, test_support::RecordingReporter};
    use composefs::repository::RepositoryConfig;
    use containers_image_proxy::oci_spec::image::{DescriptorBuilder, MediaType};
    use cstorage::writer::StoreLocation;
    use std::time::Duration;

    fn fixture<H: FsVerityHashValue>(
        root: &std::path::Path,
        count: usize,
    ) -> anyhow::Result<(Arc<Repository<H>>, OciDigest, Vec<u8>, Vec<OciDigest>, u64)> {
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
            let diff = crate::sha256_content_digest(&tar);
            let mut writer = repo.create_stream(crate::LAYER_CONTENT_TYPE)?;
            writer.write_inline(&tar[..1536]);
            writer.write_external(&payload)?;
            writer.write_inline(&tar[1536 + payload.len()..]);
            let layer = repo.write_stream(writer, &crate::layer_identifier(&diff), None)?;
            refs.push((diff, layer));
            sizes.push(tar.len());
        }
        let diff_ids = refs.iter().map(|r| r.0.to_string()).collect::<Vec<_>>();
        let config = crate::test_util::make_config_json(&diff_ids);
        let descriptors = refs
            .iter()
            .zip(sizes)
            .map(|((diff, _), size)| {
                DescriptorBuilder::default()
                    .media_type(MediaType::ImageLayer)
                    .digest(diff.clone())
                    .size(size as u64)
                    .build()
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let manifest = crate::test_util::make_manifest_json_with_layers(
            &config,
            crate::sha256_content_digest(&config).as_ref(),
            descriptors,
        );
        let ((digest, _), _) =
            crate::layer_sync::finalize_oci_image(&repo, &manifest, &config, &refs, None, None)?;
        Ok((
            repo,
            digest,
            manifest,
            refs.into_iter().map(|r| r.0).collect(),
            payload.len() as u64 * count as u64,
        ))
    }

    async fn destination(root: &std::path::Path) -> anyhow::Result<StorageWriter> {
        let root = cap_std::fs::Dir::open_ambient_dir(root, ambient_authority())?;
        Ok(StorageWriter::ensure(StoreLocation {
            graphroot: root,
            graphroot_path: Some("graph".into()),
            runroot: None,
            runroot_path: None,
        })
        .await?)
    }

    async fn round_trip<H: FsVerityHashValue>() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let (repo, digest, manifest, diffs, size) = fixture::<H>(temp.path(), 2)?;
        let reporter = Arc::new(RecordingReporter::new());
        let result = export_to_containers_storage(
            &repo,
            &digest,
            destination(temp.path()).await?,
            &["test:export".into()],
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
        let retry = export_to_containers_storage(
            &repo,
            &digest,
            destination(temp.path()).await?,
            &[],
            Default::default(),
            None,
        )
        .await?;
        assert!(retry.already_present);
        assert_eq!(retry.stats.reused_layers, 2);
        Ok(())
    }

    #[tokio::test]
    async fn export_preserves_sha256_and_sha512_repository_identities() -> anyhow::Result<()> {
        round_trip::<Sha256HashValue>().await?;
        round_trip::<Sha512HashValue>().await
    }

    #[tokio::test]
    async fn dropping_export_cancels_a_repository_lease_wait() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let (repo, digest, _, _, _) = fixture::<Sha256HashValue>(temp.path(), 1)?;
        let destination = destination(temp.path()).await?;
        rustix::fs::flock(
            repo.repo_fd(),
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )?;
        let mut pending = Box::pin(export_to_containers_storage(
            &repo,
            &digest,
            destination,
            &[],
            Default::default(),
            None,
        ));
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

    #[tokio::test]
    async fn cancellation_between_layers_leaves_a_reusable_layer_and_no_image() -> anyhow::Result<()>
    {
        let temp = tempfile::tempdir()?;
        let (repo, digest, _, _, _) = fixture::<Sha256HashValue>(temp.path(), 2)?;
        let destination = destination(temp.path()).await?;
        let reporter = Arc::new(CancelAfterLayer(std::sync::Mutex::new(None)));
        let progress = reporter.clone();
        let task = tokio::spawn(async move {
            export_to_containers_storage(
                &repo,
                &digest,
                destination,
                &[],
                Default::default(),
                Some(progress),
            )
            .await
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
}
