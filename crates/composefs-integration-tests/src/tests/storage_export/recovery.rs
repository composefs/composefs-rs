//! Kill a real importer during extraction, without running its Drop cleanup.

use std::{io::Cursor, os::unix::process::ExitStatusExt, path::Path, time::Duration};

use anyhow::{Context, Result};
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use composefs_storage::writer::{
    LayerChunk, LayerSource, LayerStatus, StorageWriter, StoreLocation, TarSource,
};
use serde_json::Value;
use tokio::io::AsyncReadExt;
use xshell::{Shell, cmd};

use super::{
    OverlayMountCleanup, VerityTempDir, append, integration_test, raw_image, require_privileged,
};

const TEST_NAME: &str = "privileged_storage_export_kill_recovery";
const CHILD_GRAPH: &str = "COMPOSEFS_TEST_INTERRUPTED_GRAPH";
const CHILD_SOCKET: &str = "COMPOSEFS_TEST_INTERRUPTED_SOCKET";
const PAYLOAD_SIZE: usize = 128 * 1024 + 1;
const READY_TIMEOUT: Duration = Duration::from_secs(30);
// The first bounded payload read spans two source chunks because the initial
// chunk also contains tar headers. Allow that write to finish before pausing.
const CHUNKS_BEFORE_PAUSE: usize = 2;

fn layer(name: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let mut tar = tar::Builder::new(Vec::new());
    append(&mut tar, ".", &[], true)?;
    append(&mut tar, name, payload, false)?;
    Ok(tar.into_inner()?)
}

fn interrupted_layers() -> Result<[Vec<u8>; 2]> {
    Ok([
        layer("orphan", b"completed orphan")?,
        layer("partial", &vec![73; PAYLOAD_SIZE])?,
    ])
}

fn writer(graph: &Path) -> Result<StorageWriter> {
    Ok(StorageWriter::open(StoreLocation::new(
        Dir::open_ambient_dir(graph, ambient_authority())?,
        None,
    ))?)
}

struct PausedSource {
    tar: TarSource<Cursor<Vec<u8>>>,
    ready: std::os::unix::net::UnixStream,
    chunks_read: usize,
}

impl LayerSource for PausedSource {
    fn next_chunk(
        &mut self,
        buffer: &mut [u8],
    ) -> composefs_storage::writer::Result<Option<LayerChunk>> {
        if self.chunks_read == CHUNKS_BEFORE_PAUSE {
            // Handshake instead of racing a timer against extraction.
            use std::io::{Read, Write};
            self.ready.write_all(&[1])?;
            self.ready.read_exact(&mut [0])?;
            return Err(std::io::Error::other("parent unexpectedly resumed importer").into());
        }
        self.chunks_read += 1;
        self.tar.next_chunk(buffer)
    }
}

async fn interrupted_child(graph: &Path, socket: &Path) -> Result<()> {
    let [complete, partial] = interrupted_layers()?;
    let mut import = writer(graph)?
        .begin_image(raw_image(&[&complete, &partial])?, Default::default())
        .await?;
    import
        .put_layer(0, TarSource(Cursor::new(complete)))
        .await?;
    import
        .put_layer(
            1,
            PausedSource {
                tar: TarSource(Cursor::new(partial)),
                ready: std::os::unix::net::UnixStream::connect(socket)?,
                chunks_read: 0,
            },
        )
        .await?;
    anyhow::bail!("importer continued beyond its interruption point")
}

fn layer_records(graph: &Path) -> Result<Vec<Value>> {
    Ok(serde_json::from_slice(&std::fs::read(
        graph.join("overlay-layers/layers.json"),
    )?)?)
}

fn privileged_storage_export_kill_recovery() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    if let Some(graph) = std::env::var_os(CHILD_GRAPH) {
        let socket = std::env::var_os(CHILD_SOCKET).context("missing interruption socket")?;
        return runtime.block_on(interrupted_child(Path::new(&graph), Path::new(&socket)));
    }
    if require_privileged(TEST_NAME)?.is_some() {
        return Ok(());
    }
    let backing = VerityTempDir::new()?;
    let temp = tempfile::tempdir()?;
    let sh = Shell::new()?;
    runtime.block_on(async {
        for recoverer in ["rust", "go"] {
            let graph = backing.path().join(recoverer);
            let _mount = OverlayMountCleanup(&graph);
            std::fs::create_dir(&graph)?;
            StorageWriter::ensure(StoreLocation::new(
                Dir::open_ambient_dir(&graph, ambient_authority())?,
                None,
            ))
            .await?;
            let original = layer("existing", b"preserve existing image")?;
            let mut existing = writer(&graph)?
                .begin_image(raw_image(&[&original])?, Default::default())
                .await?;
            existing
                .put_layer(0, TarSource(Cursor::new(original.clone())))
                .await?;
            let existing = existing
                .prepare_publication()
                .await?
                .finish(&["localhost/existing:latest".into()])
                .await?;
            let images_path = graph.join("overlay-images/images.json");
            let images_before = std::fs::read(&images_path)?;

            let socket = temp.path().join(format!("{recoverer}.sock"));
            let listener = tokio::net::UnixListener::bind(&socket)?;
            let mut child = tokio::process::Command::new(std::env::current_exe()?)
                .args(["--exact", TEST_NAME])
                .env(CHILD_GRAPH, &graph)
                .env(CHILD_SOCKET, &socket)
                .kill_on_drop(true)
                .spawn()?;
            let ready = tokio::time::timeout(READY_TIMEOUT, async {
                let (mut stream, _) = listener.accept().await?;
                let mut message = [0];
                stream.read_exact(&mut message).await?;
                anyhow::ensure!(message == [1], "unexpected interruption handshake");
                Ok::<_, anyhow::Error>(stream)
            })
            .await
            .context("importer did not reach partial extraction")??;

            let before = layer_records(&graph)?;
            assert_eq!(before.len(), 3);
            let incomplete = before
                .iter()
                .find(|l| l["flags"]["incomplete"] == true)
                .context("missing incomplete layer")?;
            let id = incomplete["id"].as_str().unwrap();
            let orphan_id = incomplete["parent"].as_str().unwrap();
            assert!(
                before
                    .iter()
                    .any(|l| l["id"] == orphan_id && l["flags"]["incomplete"] != true)
            );
            let partial_size =
                std::fs::metadata(graph.join(format!("overlay/{id}/diff/partial")))?.len();
            assert!(partial_size > 0 && partial_size < PAYLOAD_SIZE as u64);
            let short = std::fs::read_to_string(graph.join(format!("overlay/{id}/link")))?;
            let short_path = graph.join("overlay/l").join(short);
            assert_eq!(
                std::fs::read_link(&short_path)?,
                Path::new(&format!("../{id}/diff"))
            );
            child.kill().await?;
            assert_eq!(child.wait().await?.signal(), Some(9));
            // The killed worker cannot run Drop and clean up on our behalf.
            drop(ready);
            assert_eq!(std::fs::read(&images_path)?, images_before);
            assert_eq!(layer_records(&graph)?, before);

            let [complete, partial] = interrupted_layers()?;
            if recoverer == "rust" {
                writer(&graph)?
                    .begin_image(raw_image(&[&complete, &partial])?, Default::default())
                    .await?
                    .abort()
                    .await?;
            }
            // In the Go case, reading a blob opens the writable Go layer store
            // and triggers its own incomplete-layer cleanup before Rust opens it.
            let run = temp.path().join(format!("{recoverer}-run"));
            let source = format!(
                "containers-storage:[overlay@{}+{}]@{}",
                graph.display(),
                run.display(),
                existing.image_id
            );
            let output = temp.path().join(format!("{recoverer}-oci"));
            let destination = format!("oci:{}:existing", output.display());
            cmd!(sh, "skopeo copy --preserve-digests {source} {destination}").run()?;
            let diff = composefs_oci::sha256_content_digest(&original);
            assert_eq!(
                std::fs::read(output.join("blobs/sha256").join(diff.digest()))?,
                original
            );
            for removed in [
                graph.join(format!("overlay/{id}")),
                graph.join(format!("overlay-layers/{id}.tar-split.gz")),
                short_path,
            ] {
                assert_eq!(
                    removed.symlink_metadata().unwrap_err().kind(),
                    std::io::ErrorKind::NotFound,
                    "{}",
                    removed.display()
                );
            }
            let recovered = layer_records(&graph)?;
            assert_eq!(recovered.len(), 2);
            assert!(
                recovered
                    .iter()
                    .all(|l| l["id"] != id && l["flags"]["incomplete"] != true)
            );
            assert_eq!(std::fs::read(&images_path)?, images_before);
            let mut retry = writer(&graph)?
                .begin_image(raw_image(&[&complete, &partial])?, Default::default())
                .await?;
            assert_eq!(
                retry.layer_status(0)?,
                LayerStatus::Reusable(orphan_id.to_owned())
            );
            assert_eq!(retry.layer_status(1)?, LayerStatus::Missing);
            retry.abort().await?;
        }
        Ok(())
    })
}
integration_test!(privileged_storage_export_kill_recovery);
