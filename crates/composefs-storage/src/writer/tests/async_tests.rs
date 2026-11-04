use std::time::Duration;

use composefs_ioctls::lock::ofd_lock;
use rustix::fs::FlockOperation;
use tokio::time::timeout;

use super::*;
use crate::writer::locking::LockFile;

const DEADLINE: Duration = Duration::from_secs(5);
const WAIT: Duration = Duration::from_millis(50);

fn probe(path: impl AsRef<std::path::Path>) -> std::fs::File {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

fn available(file: &std::fs::File) -> bool {
    match ofd_lock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {
            ofd_lock(file, FlockOperation::Unlock).unwrap();
            true
        }
        Err(e) if matches!(e.raw_os_error(), Some(n) if n == rustix::io::Errno::AGAIN.raw_os_error() || n == rustix::io::Errno::ACCESS.raw_os_error()) => {
            false
        }
        Err(e) => panic!("lock probe: {e}"),
    }
}

async fn wait_available(file: &std::fs::File) {
    timeout(DEADLINE, async {
        while !available(file) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

async fn occupy_worker() -> (std::sync::mpsc::Sender<()>, tokio::task::JoinHandle<()>) {
    let (started, ready) = tokio::sync::oneshot::channel();
    let (resume, receiver) = std::sync::mpsc::channel();
    let blocker = tokio::task::spawn_blocking(move || {
        started.send(()).unwrap();
        receiver.recv().unwrap();
    });
    ready.await.unwrap();
    (resume, blocker)
}

#[test]
fn import_preparation_only_needs_a_worker_for_recovery_cleanup() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        for recovery in [false, true] {
            let (temp, writer) = store().await;
            let graph = temp.path().join("graph");
            let interrupted = graph.join("overlay/interrupted");
            if recovery {
                std::fs::create_dir_all(interrupted.join("diff")).unwrap();
                std::fs::write(interrupted.join("diff/payload"), b"unfinished").unwrap();
                std::fs::write(
                    graph.join("overlay-layers/layers.json"),
                    br#"[{"id":"interrupted","flags":{"incomplete":true}}]"#,
                )
                .unwrap();
            }
            // Occupy the only worker so import and publication preparation must
            // finish on the coordinator, while recovery deletion has to wait.
            let (resume, blocker) = occupy_worker().await;
            let mut pending = Box::pin(writer.begin_image(image(&[]), Default::default()));
            if recovery {
                assert!(timeout(WAIT, &mut pending).await.is_err());
                assert!(available(&probe(graph.join("storage.lock"))));
                for path in ["overlay-layers/layers.lock", "overlay-images/images.lock"] {
                    assert!(!available(&probe(graph.join(path))), "{path}");
                }
                assert!(interrupted.is_dir());
                drop(pending);
            } else {
                let import = timeout(DEADLINE, &mut pending).await.unwrap().unwrap();
                let publication = timeout(DEADLINE, import.prepare_publication())
                    .await
                    .unwrap()
                    .unwrap();
                drop(publication);
            }
            resume.send(()).unwrap();
            blocker.await.unwrap();
            if recovery {
                wait_available(&probe(graph.join("overlay-layers/layers.lock"))).await;
                // Cancelling queued cleanup leaves recovery for the next import.
                assert!(interrupted.is_dir());
                timeout(DEADLINE, writer.begin_image(image(&[]), Default::default()))
                    .await
                    .unwrap()
                    .unwrap()
                    .abort()
                    .await
                    .unwrap();
                assert!(!interrupted.exists());
                let layers: Value = serde_json::from_slice(
                    &std::fs::read(graph.join("overlay-layers/layers.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(layers, json!([]));
            }
        }
    });
}

#[test]
fn publication_validates_without_a_worker_and_finishes_after_cancellation() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (temp, writer) = store().await;
        let graph = temp.path().join("graph");
        let (resume, blocker) = occupy_worker().await;
        let invalid = timeout(DEADLINE, async {
            writer
                .begin_image(image(&[]), Default::default())
                .await?
                .prepare_publication()
                .await?
                .finish(&["invalid name".into()])
                .await
        })
        .await
        .unwrap();
        assert!(matches!(invalid, Err(ImportError::Malformed(_))));
        assert!(!graph.join("overlay-images/images.json").exists());

        let raw = image(&[]);
        let manifest = raw.manifest_json.clone();
        let publication = timeout(DEADLINE, async {
            writer
                .begin_image(raw, Default::default())
                .await?
                .prepare_publication()
                .await
        })
        .await
        .unwrap()
        .unwrap();
        let names = ["example:async".into()];
        let mut pending = Box::pin(publication.finish(&names));
        assert!(timeout(WAIT, &mut pending).await.is_err());
        drop(pending);
        assert!(available(&probe(graph.join("storage.lock"))));
        for path in ["overlay-layers/layers.lock", "overlay-images/images.lock"] {
            assert!(!available(&probe(graph.join(path))), "{path}");
        }
        assert!(!graph.join("overlay-images/images.json").exists());
        resume.send(()).unwrap();
        blocker.await.unwrap();
        wait_available(&probe(graph.join("overlay-layers/layers.lock"))).await;
        let images: Vec<Value> = serde_json::from_slice(
            &std::fs::read(graph.join("overlay-images/images.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0]["names"], json!(["example:async"]));
        let storage = crate::Storage::open(&graph).unwrap();
        let image = crate::Image::open(&storage, images[0]["id"].as_str().unwrap()).unwrap();
        assert_eq!(image.read_manifest_raw().unwrap(), manifest);
    });
}

#[tokio::test]
async fn cancelling_acquisition_releases_every_acquired_prefix() {
    let paths = [
        "graph/overlay-layers/layers.lock",
        "graph/overlay-images/images.lock",
    ];
    for (blocked, path) in paths.iter().enumerate() {
        let (temp, writer) = store().await;
        std::fs::create_dir_all(temp.path().join("graph/overlay/interrupted/diff")).unwrap();
        std::fs::write(
            temp.path().join("graph/overlay-layers/layers.json"),
            br#"[{"id":"interrupted","flags":{"incomplete":true}}]"#,
        )
        .unwrap();
        let path = temp.path().join(path);
        let dir = Dir::open_ambient_dir(path.parent().unwrap(), ambient_authority()).unwrap();
        let held = LockFile::open(&dir, path.file_name().unwrap().to_str().unwrap())
            .unwrap()
            .write()
            .await
            .unwrap();
        let mut pending = Box::pin(writer.begin_image(image(&[]), Default::default()));
        assert!(timeout(WAIT, &mut pending).await.is_err(), "{path:?}");
        assert!(available(&probe(temp.path().join("graph/storage.lock"))));
        drop(pending);
        for earlier in &paths[..blocked] {
            wait_available(&probe(temp.path().join(earlier))).await;
        }
        drop(held);
        timeout(DEADLINE, writer.begin_image(image(&[]), Default::default()))
            .await
            .unwrap()
            .unwrap()
            .abort()
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn independent_imports_wait_and_reload_after_the_previous_import() {
    let (temp, writer) = store().await;
    let tar = tar_bytes(b"contents", false);
    let mut first = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    let alias = open_store(temp.path());
    let mut second = Box::pin(alias.begin_image(image(&[&tar]), Default::default()));
    assert!(timeout(WAIT, &mut second).await.is_err());
    assert!(available(&probe(temp.path().join("graph/storage.lock"))));
    assert!(!available(&probe(
        temp.path().join("graph/overlay-layers/layers.lock")
    )));
    let layer = first
        .put_layer(0, TarSource(Cursor::new(tar)))
        .await
        .unwrap();
    first.abort().await.unwrap();
    let mut second = timeout(DEADLINE, second).await.unwrap().unwrap();
    assert_eq!(
        second.layer_status(0).unwrap(),
        LayerStatus::Reusable(layer.storage_layer_id)
    );
}

#[tokio::test]
async fn import_checks_share_image_read_locks_and_ignore_unrelated_locks() {
    for recovery in [false, true] {
        let (temp, writer) = store().await;
        let graph = temp.path().join("graph");
        std::fs::create_dir(graph.join("overlay-containers")).unwrap();
        if recovery {
            std::fs::create_dir_all(graph.join("overlay/interrupted/diff")).unwrap();
            std::fs::write(
                graph.join("overlay-layers/layers.json"),
                br#"[{"id":"interrupted","flags":{"incomplete":true}}]"#,
            )
            .unwrap();
        }
        let image_dir =
            Dir::open_ambient_dir(graph.join("overlay-images"), ambient_authority()).unwrap();
        let images = LockFile::open(&image_dir, "images.lock")
            .unwrap()
            .read()
            .await
            .unwrap();
        let mut held = Vec::new();
        for (directory, name) in [
            (graph.clone(), "storage.lock"),
            (graph.join("overlay-containers"), "containers.lock"),
            (temp.path().join("run/overlay-layers"), "mountpoints.lock"),
        ] {
            let dir = Dir::open_ambient_dir(directory, ambient_authority()).unwrap();
            held.push(LockFile::open(&dir, name).unwrap().write().await.unwrap());
        }
        timeout(DEADLINE, writer.begin_image(image(&[]), Default::default()))
            .await
            .unwrap()
            .unwrap()
            .abort()
            .await
            .unwrap();
        assert!(!recovery || !graph.join("overlay/interrupted").exists());
        drop(held);
        drop(images);
    }
}

#[tokio::test]
async fn cancelling_publication_wait_releases_the_import() {
    let (temp, writer) = store().await;
    let import = writer
        .begin_image(image(&[]), Default::default())
        .await
        .unwrap();
    let layers = probe(temp.path().join("graph/overlay-layers/layers.lock"));
    let dir = Dir::open_ambient_dir(
        temp.path().join("graph/overlay-images"),
        ambient_authority(),
    )
    .unwrap();
    let held = LockFile::open(&dir, "images.lock")
        .unwrap()
        .read()
        .await
        .unwrap();
    let mut pending = Box::pin(import.prepare_publication());
    assert!(timeout(WAIT, &mut pending).await.is_err());
    assert!(available(&probe(temp.path().join("graph/storage.lock"))));
    assert!(!available(&layers));
    drop(pending);
    wait_available(&layers).await;
    drop(held);
    writer
        .begin_image(image(&[]), Default::default())
        .await
        .unwrap()
        .prepare_publication()
        .await
        .unwrap()
        .finish(&[])
        .await
        .unwrap();
}

struct PausedSource {
    started: Option<tokio::sync::oneshot::Sender<()>>,
    resume: std::sync::mpsc::Receiver<()>,
    tar: TarSource<Cursor<Vec<u8>>>,
}

impl LayerSource for PausedSource {
    fn next_chunk(&mut self, buffer: &mut [u8]) -> Result<Option<LayerChunk>> {
        if let Some(started) = self.started.take() {
            started.send(()).unwrap();
            self.resume.recv().unwrap();
        }
        self.tar.next_chunk(buffer)
    }
}

#[tokio::test]
async fn dropping_a_layer_future_keeps_locks_until_the_layer_is_registered() {
    let (temp, writer) = store().await;
    let tar = tar_bytes(b"contents", false);
    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (resume, receiver) = std::sync::mpsc::channel();
    let source = PausedSource {
        started: Some(started),
        resume: receiver,
        tar: TarSource(Cursor::new(tar.clone())),
    };
    let mut pending = Box::pin(import.put_layer(0, source));
    timeout(DEADLINE, async {
        tokio::select! {
            result = &mut pending => panic!("layer finished before resume: {result:?}"),
            result = ready => result.unwrap(),
        }
    })
    .await
    .unwrap();
    drop(pending);
    assert!(matches!(
        import.abort().await,
        Err(ImportError::MetadataConflict(_))
    ));
    assert!(available(&probe(temp.path().join("graph/storage.lock"))));
    let layers = probe(temp.path().join("graph/overlay-layers/layers.lock"));
    assert!(!available(&layers));
    resume.send(()).unwrap();
    wait_available(&layers).await;
    let mut retry = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    let LayerStatus::Reusable(id) = retry.layer_status(0).unwrap() else {
        panic!("layer was not completed")
    };
    assert_eq!(reconstruct(&temp.path().join("graph"), &id), tar);
    assert!(
        !temp
            .path()
            .join("graph/overlay-images/images.json")
            .exists()
    );
}

struct CleanupFailureSource {
    graph: std::path::PathBuf,
    coordinator: std::thread::ThreadId,
}

impl LayerSource for CleanupFailureSource {
    fn next_chunk(&mut self, _buffer: &mut [u8]) -> Result<Option<LayerChunk>> {
        // Prevent both the immediate cleanup and Drop's retry from opening l/.
        std::fs::rename(self.graph.join("overlay/l"), self.graph.join("saved-links")).unwrap();
        Err(ImportError::Malformed("test source failure".into()))
    }
}

impl Drop for CleanupFailureSource {
    fn drop(&mut self) {
        assert_ne!(std::thread::current().id(), self.coordinator);
        // Restoring this before the session's Drop would let its retry succeed,
        // so the incomplete layer below also checks the source's lifetime.
        std::fs::rename(self.graph.join("saved-links"), self.graph.join("overlay/l")).unwrap();
    }
}

#[tokio::test]
async fn failed_cleanup_drops_the_session_on_the_worker_before_the_source() {
    let (temp, writer) = store().await;
    let tar = tar_bytes(b"contents", false);
    let graph = temp.path().join("graph");
    let id = records::digest(&tar)
        .strip_prefix("sha256:")
        .unwrap()
        .to_owned();
    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    let result = import
        .put_layer(
            0,
            CleanupFailureSource {
                graph: graph.clone(),
                coordinator: std::thread::current().id(),
            },
        )
        .await;
    assert!(
        matches!(result, Err(ImportError::Layer { index: 0, id: layer_id, source })
        if layer_id == id && matches!(*source, ImportError::Malformed(ref message) if message == "test source failure"))
    );
    assert!(matches!(
        import.abort().await,
        Err(ImportError::MetadataConflict(_))
    ));
    assert!(available(&probe(graph.join("overlay-layers/layers.lock"))));
    assert!(graph.join(format!("overlay/{id}/diff")).is_dir());
    let layers: Value =
        serde_json::from_slice(&std::fs::read(graph.join("overlay-layers/layers.json")).unwrap())
            .unwrap();
    assert_eq!(layers.as_array().unwrap().len(), 1);
    assert_eq!(layers[0]["id"], id);
    assert_eq!(layers[0]["flags"]["incomplete"], true);

    let mut retry = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    assert_eq!(retry.layer_status(0).unwrap(), LayerStatus::Missing);
    assert!(!graph.join(format!("overlay/{id}")).exists());
    assert!(retry.abort().await.unwrap().retained_layers.is_empty());
}
