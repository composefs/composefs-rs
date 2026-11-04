//! Read OCI image metadata and produce splitdirfd layer streams.
//!
//! This is the basis for exporting an OCI either to an out-of-process Varlink consumer
//! or and internal rust consumer like composefs-storage.


use std::future::Future;
use std::os::fd::AsFd;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, Result};
use composefs::{
    fsverity::FsVerityHashValue,
    repository::{Repository, RepositoryLease},
};
use composefs_splitdirfdstream::{SplitDirFdStream, build_layer_fd_layout, seed_from_id};
use tokio::sync::oneshot;

use crate::{OciDigest, layer_sync::produce_layer_splitdirfdstream, oci_image::OciImage};

/// An immutable image source, protected from repository garbage collection.
///
/// Raw metadata retains its original bytes. Layers are produced on demand;
/// neither layer ordering nor destination reuse is decided by this source.
#[derive(Debug)]
pub struct ImageSource<H: FsVerityHashValue> {
    repo: Arc<Repository<H>>,
    lease: Arc<RepositoryLease>,
    image: OciImage<H>,
    manifest_json: Vec<u8>,
    config_json: Vec<u8>,
}

impl<H: FsVerityHashValue> ImageSource<H> {
    /// Open an image selected by manifest digest and acquire a source
    /// lease protecting the image from GC, independent from repo.
    /// Dropping this future cancels a pending lease wait.
    pub async fn open(repo: &Arc<Repository<H>>, manifest: &OciDigest) -> Result<Self> {
        let lease = Arc::new(repo.lease_async().await?);
        let (image, manifest_json, config_json) =
            OciImage::open_with_raw_metadata(repo, manifest, None)?;
        Ok(Self {
            repo: Arc::clone(repo),
            lease,
            image,
            manifest_json,
            config_json,
        })
    }

    /// Image metadata and ordered layer descriptors.
    pub fn image(&self) -> &OciImage<H> {
        &self.image
    }

    /// Original manifest bytes, without JSON normalization.
    pub fn manifest_json(&self) -> &[u8] {
        &self.manifest_json
    }

    /// Original configuration bytes referenced by the manifest.
    pub fn config_json(&self) -> &[u8] {
        &self.config_json
    }

    /// Start producing a layer by its index in the manifest.
    ///
    /// Container layers reconstruct the uncompressed tar; artifact layers
    /// reconstruct their original blob. Production starts before this returns
    /// and may block on pipe backpressure until a consumer reads the stream.
    /// Each worker retains its own lease reference until the consumer closes
    /// the stream's lifetime descriptors, independently of this source's lifetime.
    pub async fn layer_stream(
        &self,
        index: usize,
    ) -> Result<(SplitDirFdStream, ProducerCompletion)> {
        let descriptor = self
            .image
            .layer_descriptors()
            .get(index)
            .with_context(|| format!("layer index {index} out of range"))?;
        let identity = match self.image.config() {
            Some(config) => config
                .rootfs()
                .diff_ids()
                .get(index)
                .context("missing layer diff ID")?
                .as_str(),
            None => descriptor.digest().as_ref(),
        };
        let verity = self
            .image
            .layer_verity(identity)
            .with_context(|| format!("missing splitstream reference for {identity}"))?;
        start_layer_stream(&self.repo, verity, Arc::clone(&self.lease))
    }
}

impl<H: FsVerityHashValue> composefs_splitdirfdstream::ImageSource for ImageSource<H> {
    type Error = anyhow::Error;

    fn manifest_digest(&self) -> &str {
        self.image.manifest_digest().as_ref()
    }

    fn manifest_json(&self) -> &[u8] {
        self.manifest_json()
    }

    fn config_json(&self) -> &[u8] {
        self.config_json()
    }

    async fn get_layer(&mut self, index: usize) -> Result<SplitDirFdStream> {
        // The generic interface carries descriptors, just like GetLayer over
        // Varlink. The worker logs production errors; the consumer verifies the
        // logical content. Direct layer_stream callers may also observe errors
        // through the optional completion handle.
        let (stream, _completion) = self.layer_stream(index).await?;
        Ok(stream)
    }
}

/// Observe the result of encoding a layer stream.
///
/// Production already runs on its own worker; polling this future only observes
/// its result. Dropping it does not cancel production or release the source
/// lease. Producer failures are also logged, even if this handle is dropped.
///
/// Completion means the data writer has closed. The worker can still retain
/// source resources until the consumer closes all lifetime descriptors. A
/// consumer must process or drop the stream concurrently with production;
/// awaiting completion first can block on a full pipe.
#[derive(Debug)]
#[must_use = "await this handle to observe layer production errors"]
pub struct ProducerCompletion {
    receiver: oneshot::Receiver<Result<()>>,
}

impl Future for ProducerCompletion {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        Poll::Ready(
            match std::task::ready!(Pin::new(&mut self.receiver).poll(cx)) {
                Ok(result) => result,
                Err(error) => Err(error).context("layer producer exited without a result"),
            },
        )
    }
}

/// Produce any repository layer splitstream, identified by its fs-verity hash.
///
/// The returned stream contains only descriptors and can be consumed locally
/// or forwarded to an external process. The producer owns an independent
/// repository lease until the consumer closes the lifetime descriptors.
pub async fn layer_stream<H: FsVerityHashValue>(
    repo: &Arc<Repository<H>>,
    layer: &H,
) -> Result<(SplitDirFdStream, ProducerCompletion)> {
    let lease = Arc::new(repo.lease_async().await?);
    start_layer_stream(repo, layer, lease)
}

fn start_layer_stream<H: FsVerityHashValue>(
    repo: &Arc<Repository<H>>,
    layer: &H,
    lease: Arc<RepositoryLease>,
) -> Result<(SplitDirFdStream, ProducerCompletion)> {
    let objects = rustix::io::dup(repo.objects_dir()?.as_fd())?;
    let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    let layout = build_layer_fd_layout(read, vec![objects], seed_from_id(&layer.to_hex()))?;
    let stream = SplitDirFdStream::from_fds(layout.dir_count, layout.fds_all)?;
    let (sender, receiver) = oneshot::channel();
    let repo = Arc::clone(repo);
    let layer = layer.clone();

    // We use a dedicated thread here not not occupy the blocking-pool, as this can
    // block for quite some time depending on the consumer behaviour.
    std::thread::Builder::new()
        .name("composefs-layer-producer".into())
        .spawn(move || {
            let result = produce_layer_splitdirfdstream(
                &repo,
                &layer,
                layout.real_indices[0],
                std::fs::File::from(write),
            );
            // The writer has closed before notifying completion or waiting on
            // keepalive, so consumers can reach EOF without a lifetime cycle.
            if let Err(error) = &result {
                tracing::warn!(%error, "layer producer failed");
            }
            // A dropped observer abandons the result, not the transfer.
            let _ = sender.send(result);
            if let Err(error) = std::io::copy(
                &mut std::fs::File::from(layout.keepalive_read),
                &mut std::io::sink(),
            ) {
                tracing::warn!(%error, "waiting for layer consumer completion");
            }
            drop(lease);
        })
        .context("starting layer producer")?;
    Ok((stream, ProducerCompletion { receiver }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use composefs::{fsverity::Sha256HashValue, repository::RepositoryConfig};
    use rustix::fs::FlockOperation;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(5);

    struct LayerFixture {
        _temp: tempfile::TempDir,
        repo: Arc<Repository<Sha256HashValue>>,
        id: Sha256HashValue,
        expected: Vec<u8>,
    }

    fn fixture() -> Result<LayerFixture> {
        let temp = tempfile::tempdir()?;
        let (repo, _) = Repository::init_path(
            rustix::fs::CWD,
            temp.path().join("repo"),
            RepositoryConfig::new(Sha256HashValue::ALGORITHM).set_insecure(),
        )?;
        let repo = Arc::new(repo);
        // More than a pipe's capacity so consumption must run concurrently.
        let inline = vec![39; 2 * 1024 * 1024];
        let external = vec![71; 128 * 1024];
        let mut writer = repo.create_stream(crate::LAYER_CONTENT_TYPE)?;
        writer.write_inline(&inline);
        writer.write_external(&external)?;
        writer.write_inline(b"tail");
        let id = writer.done()?;
        let expected = [inline.as_slice(), external.as_slice(), b"tail"].concat();
        Ok(LayerFixture {
            _temp: temp,
            repo,
            id,
            expected,
        })
    }

    #[tokio::test]
    async fn completion_is_optional_and_lifetime_fds_retain_the_lease() -> Result<()> {
        for observe in [true, false] {
            let LayerFixture {
                _temp,
                repo,
                id,
                expected,
            } = fixture()?;
            let (stream, completion) = layer_stream(&repo, &id).await?;
            let completion = if observe {
                Some(completion)
            } else {
                drop(completion);
                None
            };
            // Exercise the public ownership handoff used by external transports.
            let (dir_count, fds) = stream.into_fds();
            let (data, dirs, lifetime) = SplitDirFdStream::from_fds(dir_count, fds)?.into_parts();
            let bytes = tokio::task::spawn_blocking(move || {
                let borrowed = dirs.iter().map(AsFd::as_fd).collect::<Vec<_>>();
                let mut bytes = Vec::new();
                composefs_splitdirfdstream::reconstruct(
                    std::fs::File::from(data),
                    &borrowed,
                    &mut bytes,
                )?;
                anyhow::Ok(bytes)
            });
            assert_eq!(tokio::time::timeout(TIMEOUT, bytes).await???, expected);
            if let Some(completion) = completion {
                // Production result arrives even while lifetime FDs remain open.
                tokio::time::timeout(TIMEOUT, completion).await??;
            }
            assert_eq!(
                rustix::fs::flock(repo.repo_fd(), FlockOperation::NonBlockingLockExclusive),
                Err(rustix::io::Errno::WOULDBLOCK),
                "source lease must prevent GC after data EOF",
            );
            drop(lifetime);
            tokio::time::timeout(TIMEOUT, async {
                loop {
                    match rustix::fs::flock(
                        repo.repo_fd(),
                        FlockOperation::NonBlockingLockExclusive,
                    ) {
                        Ok(()) => break,
                        Err(rustix::io::Errno::WOULDBLOCK) => {
                            tokio::time::sleep(Duration::from_millis(1)).await
                        }
                        Err(error) => panic!("probing source lease: {error}"),
                    }
                }
            })
            .await?;
            rustix::fs::flock(repo.repo_fd(), FlockOperation::LockShared)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn image_sources_preserve_raw_metadata_and_support_artifacts() -> Result<()> {
        for container in [true, false] {
            let LayerFixture {
                _temp,
                repo,
                id,
                expected,
            } = fixture()?;
            let identity = crate::sha256_content_digest(&expected);
            let config = if container {
                crate::test_util::make_config_json(&[identity.to_string()])
            } else {
                b"{ \"artifact\": true }\n".to_vec()
            };
            let config_digest = crate::sha256_content_digest(&config);
            let mut writer = repo.create_stream(crate::skopeo::OCI_CONFIG_CONTENT_TYPE)?;
            writer.add_named_stream_ref(identity.as_ref(), &id);
            writer.write_external(&config)?;
            let config_verity =
                repo.write_stream(writer, &crate::config_identifier(&config_digest), None)?;
            let manifest = serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": if container { "application/vnd.oci.image.config.v1+json" } else { "application/vnd.example.artifact.config.v1+json" },
                    "digest": config_digest,
                    "size": config.len(),
                },
                "layers": [{
                    "mediaType": if container { "application/vnd.oci.image.layer.v1.tar" } else { "application/octet-stream" },
                    "digest": identity,
                    "size": expected.len(),
                }],
            }))?;
            let digest = crate::sha256_content_digest(&manifest);
            let mut writer = repo.create_stream(crate::skopeo::OCI_MANIFEST_CONTENT_TYPE)?;
            writer.add_named_stream_ref(&format!("config:{config_digest}"), &config_verity);
            writer.add_named_stream_ref(identity.as_ref(), &id);
            writer.write_external(&manifest)?;
            repo.write_stream(
                writer,
                &crate::oci_image::manifest_identifier(&digest),
                None,
            )?;

            let source = ImageSource::open(&repo, &digest).await?;
            assert_eq!(source.manifest_json(), manifest);
            assert_eq!(source.config_json(), config);
            assert_eq!(source.image().is_container_image(), container);
            assert!(source.layer_stream(1).await.is_err());
            let (stream, completion) = source.layer_stream(0).await?;
            drop(source);
            let consume = tokio::task::spawn_blocking(move || {
                let (data, dirs, _lifetime) = stream.into_parts();
                let dirs = dirs.iter().map(AsFd::as_fd).collect::<Vec<_>>();
                let mut bytes = Vec::new();
                composefs_splitdirfdstream::reconstruct(
                    std::fs::File::from(data),
                    &dirs,
                    &mut bytes,
                )?;
                anyhow::Ok(bytes)
            });
            let (consumed, produced) =
                tokio::time::timeout(TIMEOUT, async { tokio::join!(consume, completion) }).await?;
            assert_eq!(consumed??, expected);
            produced?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn dropping_an_unread_stream_unblocks_the_producer() -> Result<()> {
        let LayerFixture {
            _temp, repo, id, ..
        } = fixture()?;
        let (stream, mut completion) = layer_stream(&repo, &id).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut completion)
                .await
                .is_err()
        );
        drop(stream);
        let error = tokio::time::timeout(TIMEOUT, completion)
            .await?
            .unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<composefs_splitdirfdstream::Error>(),
                Some(composefs_splitdirfdstream::Error::Io(error))
                    if error.kind() == std::io::ErrorKind::BrokenPipe
            ),
            "{error:#}",
        );
        Ok(())
    }
}
