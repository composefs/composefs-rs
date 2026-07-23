//! Stateless `org.composefs.Oci` service backed by containers-storage.
//!
//! Exposes `GetInfo` and `GetLayer` from the `org.composefs.Oci` varlink
//! interface, using the `containers-storage` layer store as the source.
#![allow(missing_docs)]
//!
//! # Design
//!
//! The service is **stateless**: there is no handle map and no `Open`/`Close`
//! lifecycle.  `GetLayer` receives all necessary parameters inline via
//! [`GetLayerParams`]:
//!
//! ```text
//! GetLayer(handle, params: GetLayerParams) → streaming frames
//! ```
//!
//! Where `params.storage` carries both the `storage_path` and `layer_id`.
//!
//! # Lock safety
//!
//! The service acquires a **shared flock** on `overlay-layers/layers.lock`
//! before opening any diff-directory file descriptors.  This prevents a
//! concurrent `podman rmi` (which holds an exclusive lock) from deleting a
//! layer's diff directory while we are streaming it.
//!
//! The lock is held by a **self-reaping producer task** (a `spawn_blocking`
//! closure) across three phases:
//!
//! 1. **Phase 1**: Produce the `splitdirfdstream` bytes into the data pipe
//!    write end; drop the write end (data-pipe EOF to consumer).
//! 2. **Phase 2**: Read the keepalive-pipe read end to EOF, blocking until
//!    the consumer drops its keepalive write end (signalling it is finished).
//! 3. **Phase 3**: Drop the lock guard (releases the flock) and all other
//!    resources.
//!
//! **Critical ordering**: Phase 2 comes AFTER the write end drops (Phase 1
//! end), otherwise the data pipe never EOF and the consumer deadlocks.
//!
//! On process death (SIGKILL, etc.) the kernel closes all fds, automatically
//! releasing the flock — so the userns-helper subprocess can be killed
//! safely without leaving containers-storage in a locked state.

use std::collections::HashMap;
use std::io::Write;
use std::os::fd::OwnedFd;

use composefs_splitdirfdstream::{
    MAX_FDS_PER_FRAME, SplitdirfdstreamWriter, build_layer_fd_layout, seed_from_id,
    spawn_self_reaping_producer, split_fds_into_frames,
};
use serde::{Deserialize, Serialize};

use crate::layer::Layer;
use crate::lock::LayerStoreLock;
use crate::storage::Storage;
use crate::tar_split::{TarSplitFdStream, TarSplitItem as TarItem};

// ── Wire types (compatible with composefs-oci::varlink_types) ────────────────
//
// These definitions are independent of composefs-oci to avoid a dependency
// cycle. They are wire-format-compatible (same field names, same JSON
// encoding) with the types in composefs-oci::varlink_types.

/// Locator for a layer inside a containers-storage store.
///
/// This is the wire-format counterpart of `composefs_oci::varlink_types::StorageLocator`.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct StorageLocator {
    /// Absolute path to the containers-storage root directory.
    pub storage_path: String,
    /// The layer ID within that storage root.
    pub layer_id: String,
}

/// Parameters for the `GetLayer` method.
///
/// This is the wire-format counterpart of `composefs_oci::varlink_types::GetLayerParams`.
/// The `diff_id` field is ignored by this service; only `storage` is used.
#[derive(Debug, Clone, Default, Serialize, Deserialize, zlink::introspect::Type)]
pub struct GetLayerParams {
    /// Ignored by the cstor service (used by the repo service).
    pub diff_id: Option<String>,
    /// Location of the layer in containers-storage (required).
    pub storage: Option<StorageLocator>,
    /// Whether the consumer can bypass file DAC permissions.
    /// See `composefs_oci::varlink_types::GetLayerParams` for details.
    #[serde(default)]
    pub consumer_has_cap_dac_override: bool,
}

/// Reply from `GetInfo`.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct GetInfoReply {
    /// Capability tokens supported by this service.
    pub features: Vec<String>,
}

/// Reply from `GetLayer`.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct GetLayerReply {
    /// Number of diff-directory fd slots in the logical FD array.
    pub dir_count: u32,
}

/// Errors from the `org.composefs.Oci` interface (cstor service subset).
#[derive(Debug, zlink::ReplyError, zlink::introspect::ReplyError)]
#[zlink(interface = "org.composefs.Oci")]
pub enum CstorOciError {
    /// The repository could not be found or opened.
    RepoNotFound { message: String },
    /// The given handle is ignored (stateless service).
    InvalidHandle { handle: u64 },
    /// The named OCI image/reference does not exist.
    NoSuchImage { image: String },
    /// Internal error.
    InternalError { message: String },
    /// Layer not found.
    NoSuchLayer { diff_id: String },
    /// Malformed digest/diff-id.
    InvalidDigest { message: String },
    /// Diff-id mismatch (unused in this service, kept for interface compat).
    DiffIdMismatch { expected: String, actual: String },
    /// Malformed request.
    InvalidRequest { message: String },
    /// Too many fds for a single non-streaming reply.
    FdLimitExceeded { fd_count: u64, max_per_frame: u64 },
}

// ── CstorLayerService ─────────────────────────────────────────────────────────

/// Stateless service implementing the `org.composefs.Oci` interface, backed
/// by a containers-storage layer store.
///
/// Only `GetInfo` and `GetLayer` are implemented; all other methods return
/// a `MethodNotFound` error from zlink.
#[derive(Debug, Default)]
pub struct CstorLayerService;

// ── Producer helpers ──────────────────────────────────────────────────────────

/// Produce a `splitdirfdstream`-encoded byte sequence for `layer` in
/// `storage` into `out`.
///
/// `link_id_to_dirfd` maps each layer's link ID to the *sparse* dirfd slot
/// index where its pre-opened diff-directory fd was placed.
///
/// `consumer_has_cap_dac_override` controls how non-world-readable files
/// are transported: when `true`, every file is emitted as `FileBackedData`
/// (dirfd + filename reference) regardless of its permission bits, since the
/// consumer is trusted to open it directly; when `false`, non-world-readable
/// files are still read into memory and sent as `InlineData`, as before.
pub(crate) fn produce_splitdirfdstream<W: Write>(
    storage: &Storage,
    layer: &Layer,
    link_id_to_dirfd: &HashMap<String, u32>,
    real_indices: &std::collections::HashSet<u32>,
    consumer_has_cap_dac_override: bool,
    out: W,
) -> crate::Result<()> {
    let mut stream = TarSplitFdStream::new(storage, layer)?;
    let mut writer = SplitdirfdstreamWriter::new(out);
    const ZERO_PADDING: [u8; 512] = [0u8; 512];
    let mut prev_pad: usize = 0;

    while let Some(item) = stream.next()? {
        match item {
            TarItem::Segment(bytes) => {
                let stripped = if prev_pad <= bytes.len() {
                    &bytes[prev_pad..]
                } else {
                    &[][..]
                };
                if !stripped.is_empty() {
                    writer.write_metadata(stripped).map_err(|e| {
                        crate::error::StorageError::TarSplitError(format!(
                            "splitdirfdstream write_inline: {e}"
                        ))
                    })?;
                }
                prev_pad = 0;
            }
            TarItem::FileContent {
                fd,
                size,
                name,
                link_id,
            } => {
                let relpath = name.strip_prefix("./").unwrap_or(&name);
                let dirfd_index = *link_id_to_dirfd.get(link_id.as_str()).ok_or_else(|| {
                    crate::error::StorageError::TarSplitError(format!(
                        "link_id {link_id} not found in dirfd map"
                    ))
                })?;
                assert!(
                    real_indices.contains(&dirfd_index),
                    "BUG: producer emitting dirfd_index={dirfd_index} for {relpath:?} \
                     (link_id={link_id:?}) but that slot is NOT a real diff-dir slot; \
                     real_indices={real_indices:?} link_id_to_dirfd={link_id_to_dirfd:?}"
                );
                let stat = rustix::fs::fstat(&fd).map_err(|e| {
                    crate::error::StorageError::TarSplitError(format!(
                        "fstat failed for {relpath}: {e}"
                    ))
                })?;
                let world_readable = stat.st_mode & 0o004 != 0;
                if world_readable || consumer_has_cap_dac_override {
                    writer
                        .write_file_backed_data(dirfd_index, size, relpath.as_bytes())
                        .map_err(|e| {
                            crate::error::StorageError::TarSplitError(format!(
                                "splitdirfdstream write_external {relpath}: {e}"
                            ))
                        })?;
                } else {
                    let mut buf = vec![0u8; size as usize];
                    let mut off = 0u64;
                    while (off as usize) < buf.len() {
                        let n =
                            rustix::io::pread(&fd, &mut buf[off as usize..], off).map_err(|e| {
                                crate::error::StorageError::TarSplitError(format!(
                                    "pread failed for {relpath}: {e}"
                                ))
                            })?;
                        if n == 0 {
                            return Err(crate::error::StorageError::TarSplitError(format!(
                                "unexpected EOF reading {relpath}"
                            )));
                        }
                        off += n as u64;
                    }
                    writer.write_inline_data(&buf).map_err(|e| {
                        crate::error::StorageError::TarSplitError(format!(
                            "write_file_content {relpath}: {e}"
                        ))
                    })?;
                }
                let pad = (size.next_multiple_of(512) - size) as usize;
                if pad > 0 {
                    writer.write_metadata(&ZERO_PADDING[..pad]).map_err(|e| {
                        crate::error::StorageError::TarSplitError(format!(
                            "splitdirfdstream write_inline padding: {e}"
                        ))
                    })?;
                }
                prev_pad = pad;
            }
        }
    }

    writer.finish().map_err(|e| {
        crate::error::StorageError::TarSplitError(format!("splitdirfdstream finish: {e}"))
    })?;
    Ok(())
}

/// Open one diff-directory fd per layer in the chain, in chain order.
///
/// Returns `(real_fds, link_ids)` where `real_fds[i]` is the diff-dir fd for
/// `link_ids[i]`.  The sparse-slot placement is **not** done here; callers
/// should pass `real_fds` to [`composefs_splitdirfdstream::build_layer_fd_layout`]
/// which fills dummy slots using the canonical ordinal-parity rule.  The
/// returned `link_ids` can then be zipped with `layout.real_indices` to build
/// the `link_id → dirfd_slot_index` map required by [`produce_splitdirfdstream`].
pub(crate) fn open_layer_diff_fds(
    storage: &Storage,
    layer: &Layer,
) -> crate::Result<(Vec<OwnedFd>, Vec<String>)> {
    use std::os::fd::AsFd as _;
    let chain = crate::layer::Layer::open(storage, layer.id())?
        .layer_chain(storage)
        .map_err(|e| crate::error::StorageError::Io(std::io::Error::other(format!("{e:#}"))))?;

    let mut real_fds = Vec::with_capacity(chain.len());
    let mut link_ids = Vec::with_capacity(chain.len());

    for l in &chain {
        let fd = rustix::io::dup(l.diff_dir().as_fd())
            .map_err(|e| crate::error::StorageError::Io(std::io::Error::from(e)))?;
        real_fds.push(fd);
        link_ids.push(l.link_id().to_string());
    }

    Ok((real_fds, link_ids))
}

// ── zlink service impl ────────────────────────────────────────────────────────

mod service_impl {
    #![allow(missing_docs)]

    use super::{
        CstorLayerService, CstorOciError, GetInfoReply, GetLayerParams, GetLayerReply, Layer,
        LayerStoreLock, MAX_FDS_PER_FRAME, Storage, build_layer_fd_layout, open_layer_diff_fds,
        produce_splitdirfdstream, seed_from_id, spawn_self_reaping_producer, split_fds_into_frames,
    };

    #[zlink::service(
        interface = "org.composefs.Oci",
        vendor = "org.composefs",
        product = "composefs-storage",
        version = env!("CARGO_PKG_VERSION"),
        url = "https://github.com/composefs/composefs-rs"
    )]
    impl<Sock> CstorLayerService {
        /// Advertise the capabilities of this service.
        async fn get_info(&self) -> std::result::Result<GetInfoReply, CstorOciError> {
            Ok(GetInfoReply {
                features: vec![
                    "splitdirfdstream-v0".into(),
                    "source-containers-storage".into(),
                    "read-only".into(),
                ],
            })
        }

        /// Stream a layer from containers-storage as a `splitdirfdstream`.
        ///
        /// `params.storage` must be set; `params.diff_id` is ignored.
        ///
        /// The self-reaping producer task:
        ///   Phase 1 — produce stream into data pipe; drop write end (data EOF).
        ///   Phase 2 — wait for keepalive-pipe EOF (consumer finished).
        ///   Phase 3 — drop lock guard + all resources.
        #[zlink(more, return_fds)]
        async fn get_layer(
            &self,
            more: bool,
            handle: u64,
            params: GetLayerParams,
            #[zlink(fds)] _fds: Vec<std::os::fd::OwnedFd>,
        ) -> impl zlink::futures_util::Stream<
            Item = (
                std::result::Result<zlink::Reply<GetLayerReply>, CstorOciError>,
                Vec<std::os::fd::OwnedFd>,
            ),
        > + Unpin {
            use zlink::futures_util::stream::{self, StreamExt as _};

            let _ = handle; // stateless — handle is ignored

            type StreamItem = (
                std::result::Result<zlink::Reply<GetLayerReply>, CstorOciError>,
                Vec<std::os::fd::OwnedFd>,
            );

            macro_rules! err_stream {
                ($e:expr) => {
                    return stream::iter(std::iter::once::<StreamItem>((Err($e), vec![])))
                        .left_stream()
                };
            }

            let consumer_has_cap_dac_override = params.consumer_has_cap_dac_override;

            // Extract storage locator (required).
            let locator = match params.storage {
                Some(l) => l,
                None => err_stream!(CstorOciError::InvalidRequest {
                    message: "GetLayer: params.storage is required for the cstor service".into(),
                }),
            };
            let storage_path = locator.storage_path;
            let layer_id = locator.layer_id;

            // Open storage and locate the layer.
            let storage = match Storage::open(&storage_path) {
                Ok(s) => s,
                Err(e) => err_stream!(CstorOciError::RepoNotFound {
                    message: format!("{e:#}"),
                }),
            };
            let layer = match Layer::open(&storage, &layer_id) {
                Ok(l) => l,
                Err(_) => err_stream!(CstorOciError::NoSuchLayer {
                    diff_id: layer_id.clone(),
                }),
            };

            // Seed for sparse layout (derived from layer_id).
            let seed = seed_from_id(&layer_id);

            // Acquire shared lock FIRST (before opening diff-dir fds).
            // Lock → open ordering is atomic w.r.t. concurrent `podman rmi`.
            let lock: LayerStoreLock = match storage.lock_layers_shared() {
                Ok(l) => l,
                Err(e) => err_stream!(CstorOciError::InternalError {
                    message: format!("lock_layers_shared: {e:#}"),
                }),
            };

            // Open one real diff-dir fd per chain layer (in chain order).
            // Sparse placement and dummy-fd insertion are delegated to
            // build_layer_fd_layout so that both paths share one implementation.
            let (real_fds, link_ids) = match open_layer_diff_fds(&storage, &layer) {
                Ok(pair) => pair,
                Err(e) => err_stream!(CstorOciError::InternalError {
                    message: format!("open diff dirs: {e:#}"),
                }),
            };

            // Create the data pipe.
            let (read_fd, write_fd) =
                match rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC) {
                    Ok(p) => p,
                    Err(e) => err_stream!(CstorOciError::InternalError {
                        message: format!("pipe: {e}"),
                    }),
                };

            // Build the full sparse fd layout (dirfds region + keepalive + extras).
            // This is the same call the repo path makes, ensuring one canonical
            // dummy-fd parity rule (ordinal-based, not slot-value-based).
            let layout = match build_layer_fd_layout(read_fd, real_fds, seed) {
                Ok(l) => l,
                Err(e) => err_stream!(CstorOciError::InternalError {
                    message: format!("build_layer_fd_layout: {e}"),
                }),
            };
            let dir_count = layout.dir_count;
            // Build the link_id → sparse-slot-index map from the layout's real_indices.
            // layout.real_indices[i] is the slot where chain layer i's real fd was placed.
            let link_id_to_dirfd: std::collections::HashMap<String, u32> = link_ids
                .into_iter()
                .zip(layout.real_indices.iter().copied())
                .collect();
            let real_indices: std::collections::HashSet<u32> =
                layout.real_indices.iter().copied().collect();

            // Split into transport frames (with more=false guard).
            let (batches, n_frames) = match split_fds_into_frames(layout.fds_all, seed, more) {
                Ok(b) => {
                    let n = b.len();
                    (b, n)
                }
                Err((_fds, e)) => {
                    err_stream!(CstorOciError::FdLimitExceeded {
                        fd_count: e.fd_count as u64,
                        max_per_frame: MAX_FDS_PER_FRAME as u64,
                    })
                }
            };

            // Spawn the 3-phase self-reaping producer task via the shared helper.
            // Phase 1: produce; drop write_fd (data-pipe EOF).
            // Phase 2: keepalive-pipe EOF wait (consumer finished).
            // Phase 3: drop lock (releases shared flock).
            let keepalive_read = layout.keepalive_read;
            spawn_self_reaping_producer(write_fd, keepalive_read, lock, move |wf| {
                if let Err(e) = produce_splitdirfdstream(
                    &storage,
                    &layer,
                    &link_id_to_dirfd,
                    &real_indices,
                    consumer_has_cap_dac_override,
                    wf,
                ) {
                    tracing::warn!("cstor producer error: {e:#}");
                }
            });

            stream::iter(batches.into_iter().enumerate().map(move |(i, batch)| {
                let is_last = i == n_frames - 1;
                (
                    Ok(zlink::Reply::new(Some(GetLayerReply { dir_count }))
                        .set_continues(Some(!is_last))),
                    batch,
                )
            }))
            .right_stream()
        }
    }
}

// ── In-process transport ──────────────────────────────────────────────────────

/// Handle to an in-process [`CstorLayerService`] server.
///
/// Drop or call [`InProcessServer::shutdown`] when done.
#[derive(Debug)]
pub struct InProcessServer {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl InProcessServer {
    /// Signal the server to stop and reap its thread.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
        }
    }
}

impl Drop for InProcessServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Spawn a [`CstorLayerService`] in-process over a Unix socket pair.
///
/// Returns a connected `zlink::tokio::unix::Connection` and an [`InProcessServer`]
/// handle for shutdown.
pub fn spawn_in_process(
    service: CstorLayerService,
) -> std::io::Result<(zlink::tokio::unix::Connection, InProcessServer)> {
    let (client_std, server_std) = std::os::unix::net::UnixStream::pair()?;
    client_std.set_nonblocking(true)?;
    server_std.set_nonblocking(true)?;

    let client_stream = tokio::net::UnixStream::from_std(client_std)?;
    let client_zlink =
        zlink::tokio::unix::Stream::try_from(client_stream).map_err(std::io::Error::other)?;
    let client_conn = zlink::Connection::new(client_zlink);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let handle = std::thread::Builder::new()
        .name("cstor-oci-server".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("CstorLayerService server runtime build failed: {e:#?}");
                    return;
                }
            };
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, async move {
                let server_stream = match tokio::net::UnixStream::from_std(server_std) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(
                            "CstorLayerService server stream conversion failed: {e:#?}"
                        );
                        return;
                    }
                };
                let server_zlink = match zlink::tokio::unix::Stream::try_from(server_stream) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(
                            "CstorLayerService server zlink stream conversion failed: {e:#?}"
                        );
                        return;
                    }
                };
                let listener = zlink::ReadyListener::new(server_zlink);
                let server = zlink::Server::new(listener, service);

                tokio::select! {
                    res = server.run() => {
                        if let Err(e) = res {
                            tracing::warn!("CstorLayerService in-process server error: {e:#?}");
                        }
                    }
                    _ = shutdown_rx => {
                        tracing::trace!("CstorLayerService in-process server received stop signal");
                    }
                }
            });
        })?;

    Ok((
        client_conn,
        InProcessServer {
            shutdown: Some(shutdown_tx),
            thread: Some(handle),
        },
    ))
}

/// Serve the `CstorLayerService` on `socket` until the peer disconnects.
///
/// Intended for the userns helper subprocess: the helper is shut down by the
/// parent (`cfsctl`) `kill()`ing it once the import is done (see
/// [`crate::userns_helper::StorageProxy`]). Abnormal parent death is covered by
/// the helper's `PR_SET_PDEATHSIG` net (see `init_if_helper`), so there is no
/// need to detect peer close here.
pub fn serve_on_socket_blocking(socket: std::os::unix::net::UnixStream) -> std::io::Result<()> {
    socket.set_nonblocking(true)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move {
        // `from_std` must be called inside the runtime context.
        let stream = tokio::net::UnixStream::from_std(socket)?;
        let zs = zlink::tokio::unix::Stream::try_from(stream).map_err(std::io::Error::other)?;
        let listener = zlink::ReadyListener::new(zs);
        let server = zlink::Server::new(listener, CstorLayerService);
        server
            .run()
            .await
            .map_err(|e| std::io::Error::other(format!("{e:#?}")))?;
        Ok(())
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Read as _;
    use std::os::fd::{AsFd as _, BorrowedFd};

    use composefs_splitdirfdstream::{SplitdirfdstreamReader, build_layer_fd_layout, seed_from_id};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tempfile::TempDir;

    use super::*;
    use crate::layer::Layer;
    use crate::storage::Storage;

    // ── Shared test fixture ──────────────────────────────────────────────────

    fn create_two_layer_mock(root: &std::path::Path) -> Storage {
        for d in ["overlay", "overlay-layers", "overlay-images"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }

        let child_id = "child-layer-001";
        let child_link = "CHILDLINKID000000000000000";
        let child_diff = root.join("overlay").join(child_id).join("diff");
        std::fs::create_dir_all(child_diff.join("etc")).unwrap();
        std::fs::write(child_diff.join("etc/child.txt"), b"child content!").unwrap();
        std::fs::write(root.join("overlay").join(child_id).join("link"), child_link).unwrap();

        let parent_id = "parent-layer-001";
        let parent_link = "PARENTLINKID000000000000000";
        let parent_diff = root.join("overlay").join(parent_id).join("diff");
        std::fs::create_dir_all(parent_diff.join("etc")).unwrap();
        std::fs::write(parent_diff.join("etc/parent.txt"), b"parent content!").unwrap();
        std::fs::write(
            root.join("overlay").join(parent_id).join("link"),
            parent_link,
        )
        .unwrap();

        std::fs::write(
            root.join("overlay").join(child_id).join("lower"),
            format!("l/{}", parent_link),
        )
        .unwrap();

        let l_dir = root.join("overlay").join("l");
        std::fs::create_dir_all(&l_dir).unwrap();
        std::os::unix::fs::symlink(format!("../{}/diff", child_id), l_dir.join(child_link))
            .unwrap();
        std::os::unix::fs::symlink(format!("../{}/diff", parent_id), l_dir.join(parent_link))
            .unwrap();

        let ndjson = concat!(
            r#"{"type":1,"name":"./etc/child.txt","size":14}"#,
            "\n",
            r#"{"type":1,"name":"./etc/parent.txt","size":15}"#,
            "\n",
        );
        let gz_path = root
            .join("overlay-layers")
            .join(format!("{}.tar-split.gz", child_id));
        let gz_file = std::fs::File::create(&gz_path).unwrap();
        let mut encoder = GzEncoder::new(gz_file, Compression::default());
        encoder.write_all(ndjson.as_bytes()).unwrap();
        encoder.finish().unwrap();

        Storage::open(root).unwrap()
    }

    // Deterministic constants for "child-layer-001".
    //
    // These derive from the layer-id seed independently of the sparse-slot
    // *placement* (which comes from a seeded shuffle): the number of dummy slots,
    // extra lifetime fds, and transport frames are all fixed for this seed. The
    // real-layer slot indices themselves are read from the layout at runtime.
    const LAYER_SEED: u64 = 9_551_015_030_439_334_514;
    const EXPECTED_DIR_COUNT: u32 = 5;
    const EXPECTED_N_EXTRA_LIFETIME: usize = 2;
    const EXPECTED_N_FRAMES: usize = 4;

    /// Build the fd layout for a layer under test and return the full layout
    /// plus the `link_id → sparse-slot-index` map.
    ///
    /// Uses a `/dev/null` fd as a throwaway pipe_read (tests don't drain the
    /// data pipe; they call `produce_splitdirfdstream` separately into a vec).
    fn build_test_layout(
        storage: &Storage,
        layer: &Layer,
        seed: u64,
    ) -> (
        composefs_splitdirfdstream::LayerFdLayout,
        HashMap<String, u32>,
        std::collections::HashSet<u32>,
    ) {
        let (real_fds, link_ids) = open_layer_diff_fds(storage, layer).unwrap();
        let dummy_pipe_read = composefs_splitdirfdstream::open_devnull().unwrap();
        let layout = build_layer_fd_layout(dummy_pipe_read, real_fds, seed).unwrap();
        let real_indices: std::collections::HashSet<u32> =
            layout.real_indices.iter().copied().collect();
        let map: HashMap<String, u32> = link_ids
            .into_iter()
            .zip(layout.real_indices.iter().copied())
            .collect();
        (layout, map, real_indices)
    }

    // ── C1: sparse layout + producer ────────────────────────────────────────

    #[test]
    fn test_produce_splitdirfdstream_chunk_sequence() {
        let tmp = TempDir::new().unwrap();
        let storage = create_two_layer_mock(tmp.path());
        let layer = Layer::open(&storage, "child-layer-001").unwrap();

        let seed = seed_from_id("child-layer-001");
        assert_eq!(seed, LAYER_SEED, "seed must match precomputed value");

        let (layout, link_id_to_dirfd, real_indices) = build_test_layout(&storage, &layer, seed);

        let child_link = "CHILDLINKID000000000000000";
        let parent_link = "PARENTLINKID000000000000000";

        // The real-layer slot positions come from the seeded shuffle; rather
        // than pin them to specific values, take them from the layout map and
        // assert the produced chunks reference those same slots.
        let child_idx = link_id_to_dirfd[child_link];
        let parent_idx = link_id_to_dirfd[parent_link];

        // dir_count = total slot count including dummies.
        assert_eq!(layout.dir_count, EXPECTED_DIR_COUNT);
        assert!(child_idx < EXPECTED_DIR_COUNT && parent_idx < EXPECTED_DIR_COUNT);
        assert_ne!(child_idx, parent_idx, "real layers occupy distinct slots");

        let mut buf = Vec::<u8>::new();
        produce_splitdirfdstream(
            &storage,
            &layer,
            &link_id_to_dirfd,
            &real_indices,
            false,
            &mut buf,
        )
        .unwrap();

        let mut reader = SplitdirfdstreamReader::new(buf.as_slice());

        // child.txt → FileBackedData at child's sparse slot.
        match reader.next_chunk().unwrap().expect("chunk 1") {
            composefs_splitdirfdstream::Chunk::FileBackedData {
                dirfd_index,
                length,
                filename,
            } => {
                assert_eq!(dirfd_index, child_idx);
                assert_eq!(length, 14);
                assert_eq!(filename, b"etc/child.txt");
            }
            other => panic!("expected FileBackedData, got {other:?}"),
        }

        // 498 bytes padding.
        match reader.next_chunk().unwrap().expect("chunk 2") {
            composefs_splitdirfdstream::Chunk::Metadata(data) => {
                assert_eq!(data.len(), 498);
                assert!(data.iter().all(|&b| b == 0));
            }
            other => panic!("expected Metadata (padding), got {other:?}"),
        }

        // parent.txt → FileBackedData at parent's sparse slot.
        match reader.next_chunk().unwrap().expect("chunk 3") {
            composefs_splitdirfdstream::Chunk::FileBackedData {
                dirfd_index,
                length,
                filename,
            } => {
                assert_eq!(dirfd_index, parent_idx);
                assert_eq!(length, 15);
                assert_eq!(filename, b"etc/parent.txt");
            }
            other => panic!("expected FileBackedData, got {other:?}"),
        }

        // 497 bytes padding.
        match reader.next_chunk().unwrap().expect("chunk 4") {
            composefs_splitdirfdstream::Chunk::Metadata(data) => {
                assert_eq!(data.len(), 497);
                assert!(data.iter().all(|&b| b == 0));
            }
            other => panic!("expected Metadata (padding), got {other:?}"),
        }

        assert!(reader.next_chunk().unwrap().is_none(), "expected EOF");
    }

    #[test]
    fn test_non_world_readable_file_uses_file_content() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = TempDir::new().unwrap();
        let storage = create_two_layer_mock(tmp.path());

        let child_txt = tmp
            .path()
            .join("overlay/child-layer-001/diff/etc/child.txt");
        std::fs::set_permissions(&child_txt, std::fs::Permissions::from_mode(0o640)).unwrap();

        let layer = Layer::open(&storage, "child-layer-001").unwrap();
        let seed = seed_from_id("child-layer-001");
        let (_, link_id_to_dirfd, real_indices) = build_test_layout(&storage, &layer, seed);
        let mut buf = Vec::<u8>::new();
        produce_splitdirfdstream(
            &storage,
            &layer,
            &link_id_to_dirfd,
            &real_indices,
            false,
            &mut buf,
        )
        .unwrap();

        let mut reader = SplitdirfdstreamReader::new(buf.as_slice());
        let mut saw_file_content = false;
        while let Some(chunk) = reader.next_chunk().unwrap() {
            match chunk {
                composefs_splitdirfdstream::Chunk::Metadata(_) => {}
                composefs_splitdirfdstream::Chunk::InlineData(data) => {
                    assert_eq!(data, b"child content!");
                    saw_file_content = true;
                    break;
                }
                composefs_splitdirfdstream::Chunk::FileBackedData { filename, .. } => {
                    panic!(
                        "non-world-readable must produce InlineData, got FileBackedData({:?})",
                        std::str::from_utf8(filename).unwrap_or("<invalid utf8>")
                    );
                }
            }
        }
        assert!(saw_file_content, "expected InlineData chunk for child.txt");
    }

    /// When the consumer can bypass file permissions, even non-world-readable
    /// files should be emitted as `FileBackedData` (dirfd + filename reference)
    /// rather than `InlineData`, enabling zero-copy transport.
    #[test]
    fn test_non_world_readable_file_with_bypass_uses_file_backed_data() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = TempDir::new().unwrap();
        let storage = create_two_layer_mock(tmp.path());

        let child_txt = tmp
            .path()
            .join("overlay/child-layer-001/diff/etc/child.txt");
        std::fs::set_permissions(&child_txt, std::fs::Permissions::from_mode(0o640)).unwrap();

        let layer = Layer::open(&storage, "child-layer-001").unwrap();
        let seed = seed_from_id("child-layer-001");
        let (_, link_id_to_dirfd, real_indices) = build_test_layout(&storage, &layer, seed);
        let mut buf = Vec::<u8>::new();
        produce_splitdirfdstream(
            &storage,
            &layer,
            &link_id_to_dirfd,
            &real_indices,
            true,
            &mut buf,
        )
        .unwrap();

        let mut reader = SplitdirfdstreamReader::new(buf.as_slice());
        let mut saw_file_backed = false;
        while let Some(chunk) = reader.next_chunk().unwrap() {
            match chunk {
                composefs_splitdirfdstream::Chunk::Metadata(_) => {}
                composefs_splitdirfdstream::Chunk::FileBackedData { filename, .. } => {
                    if filename == b"etc/child.txt" {
                        saw_file_backed = true;
                        break;
                    }
                }
                composefs_splitdirfdstream::Chunk::InlineData(_) => {
                    panic!(
                        "with consumer_has_cap_dac_override=true, non-world-readable \
                         files must produce FileBackedData, got InlineData"
                    );
                }
            }
        }
        assert!(
            saw_file_backed,
            "expected FileBackedData chunk for child.txt"
        );
    }

    #[test]
    fn test_per_layer_diff_fds() {
        let tmp = TempDir::new().unwrap();
        let storage = create_two_layer_mock(tmp.path());
        let layer = Layer::open(&storage, "child-layer-001").unwrap();

        let seed = seed_from_id("child-layer-001");
        let (layout, link_id_to_dirfd, _real_indices) = build_test_layout(&storage, &layer, seed);

        // dir_count counts the full sparse region (real + dummy slots).
        assert_eq!(layout.dir_count, EXPECTED_DIR_COUNT);

        // Real-layer slots come from the seeded shuffle; read them from the map.
        let child_idx = link_id_to_dirfd["CHILDLINKID000000000000000"];
        let parent_idx = link_id_to_dirfd["PARENTLINKID000000000000000"];
        assert_ne!(child_idx, parent_idx, "real layers occupy distinct slots");

        // fds_all layout: [dummy_pipe, dirfds region (dir_count), keepalive_write, extras]
        // dirfds region starts at index 1.
        let child_fd = layout.fds_all[1 + child_idx as usize].as_fd();
        assert!(
            composefs_splitdirfdstream::open_beneath(child_fd, b"etc/child.txt").is_ok(),
            "child diff-dir must allow opening etc/child.txt"
        );

        let parent_fd = layout.fds_all[1 + parent_idx as usize].as_fd();
        assert!(
            composefs_splitdirfdstream::open_beneath(parent_fd, b"etc/parent.txt").is_ok(),
            "parent diff-dir must allow opening etc/parent.txt"
        );

        // Every other slot in the dirfds region is a dummy and must not open
        // any real file.
        for dummy_slot in (0..EXPECTED_DIR_COUNT).filter(|s| *s != child_idx && *s != parent_idx) {
            assert!(
                composefs_splitdirfdstream::open_beneath(
                    layout.fds_all[1 + dummy_slot as usize].as_fd(),
                    b"etc/child.txt"
                )
                .is_err(),
                "dummy slot {dummy_slot} must not open real files"
            );
        }
    }

    #[test]
    fn test_reconstruct_produces_file_content() {
        let tmp = TempDir::new().unwrap();
        let storage = create_two_layer_mock(tmp.path());
        let layer = Layer::open(&storage, "child-layer-001").unwrap();

        let seed = seed_from_id("child-layer-001");
        let (layout, link_id_to_dirfd, real_indices) = build_test_layout(&storage, &layer, seed);
        assert_eq!(layout.dir_count, EXPECTED_DIR_COUNT);

        let mut buf = Vec::<u8>::new();
        produce_splitdirfdstream(
            &storage,
            &layer,
            &link_id_to_dirfd,
            &real_indices,
            false,
            &mut buf,
        )
        .unwrap();

        // The dirfds region in fds_all starts at index 1.
        let dir_count = layout.dir_count as usize;
        let borrowed_fds: Vec<BorrowedFd<'_>> = layout.fds_all[1..=dir_count]
            .iter()
            .map(|f| f.as_fd())
            .collect();
        let mut out = Vec::<u8>::new();
        let bytes_written =
            composefs_splitdirfdstream::reconstruct(buf.as_slice(), &borrowed_fds, &mut out)
                .unwrap();

        assert!(bytes_written > 0);
        assert!(
            out.windows(b"child content!".len())
                .any(|w| w == b"child content!")
        );
        assert!(
            out.windows(b"parent content!".len())
                .any(|w| w == b"parent content!")
        );
        assert_eq!(bytes_written, 1024);
    }

    // ── C2/C3: CstorLayerService in-process GetLayer round-trip ─────────────

    /// Proxy trait for the org.composefs.Oci interface (cstor client side).
    #[zlink::proxy(interface = "org.composefs.Oci")]
    trait CstorOciProxy {
        async fn get_info(
            &mut self,
        ) -> zlink::Result<std::result::Result<GetInfoReply, CstorOciError>>;

        #[zlink(more, return_fds)]
        async fn get_layer(
            &mut self,
            handle: u64,
            params: GetLayerParams,
        ) -> zlink::Result<
            impl zlink::futures_util::Stream<
                Item = zlink::Result<(
                    std::result::Result<GetLayerReply, CstorOciError>,
                    Vec<std::os::fd::OwnedFd>,
                )>,
            >,
        >;
    }

    /// Collect all frames from a streaming get_layer call.
    async fn collect_get_layer(
        client: &mut zlink::tokio::unix::Connection,
        storage_path: &str,
        layer_id: &str,
    ) -> (GetLayerReply, Vec<OwnedFd>, usize) {
        use zlink::futures_util::StreamExt as _;

        let params = GetLayerParams {
            diff_id: None,
            storage: Some(StorageLocator {
                storage_path: storage_path.to_owned(),
                layer_id: layer_id.to_owned(),
            }),
            ..Default::default()
        };

        let mut stream = std::pin::pin!(client.get_layer(0, params).await.unwrap());
        let mut all_fds: Vec<OwnedFd> = Vec::new();
        let mut last_reply: Option<GetLayerReply> = None;
        let mut frame_count = 0usize;

        while let Some(item) = stream.next().await {
            let (result, fds) = item.unwrap();
            last_reply = Some(result.unwrap());
            all_fds.extend(fds);
            frame_count += 1;
        }

        (last_reply.expect("no frames"), all_fds, frame_count)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_cstor_oci_get_layer_in_process() {
        let tmp = TempDir::new().unwrap();
        let _ = create_two_layer_mock(tmp.path());
        let storage_path = tmp.path().to_str().unwrap().to_string();

        let (mut client, server) = spawn_in_process(CstorLayerService).unwrap();

        // GetInfo.
        let info = client.get_info().await.unwrap().unwrap();
        assert!(info.features.contains(&"splitdirfdstream-v0".to_string()));
        assert!(
            info.features
                .contains(&"source-containers-storage".to_string())
        );

        // GetLayer — full round-trip.
        let (reply, all_fds, frame_count) =
            collect_get_layer(&mut client, &storage_path, "child-layer-001").await;

        assert_eq!(frame_count, EXPECTED_N_FRAMES);
        assert_eq!(reply.dir_count, EXPECTED_DIR_COUNT);

        let expected_total = 1 + EXPECTED_DIR_COUNT as usize + 1 + EXPECTED_N_EXTRA_LIFETIME;
        assert_eq!(all_fds.len(), expected_total);

        let mut it = all_fds.into_iter();
        let pipe_fd = it.next().unwrap();
        let dir_fds: Vec<OwnedFd> = it.by_ref().take(reply.dir_count as usize).collect();
        let lifetime_fds: Vec<OwnedFd> = it.collect();

        // Verify the real diff-dirs are present somewhere in the sparse region.
        // The exact slots come from the seeded shuffle and are not known to the
        // client; the stream reconstruction below proves the producer used the
        // right indices.
        assert!(
            dir_fds
                .iter()
                .any(
                    |fd| composefs_splitdirfdstream::open_beneath(fd.as_fd(), b"etc/child.txt")
                        .is_ok()
                ),
            "some dir slot must open etc/child.txt"
        );
        assert!(
            dir_fds
                .iter()
                .any(
                    |fd| composefs_splitdirfdstream::open_beneath(fd.as_fd(), b"etc/parent.txt")
                        .is_ok()
                ),
            "some dir slot must open etc/parent.txt"
        );

        // Read and reconstruct the stream.
        let pipe_dup = rustix::io::dup(pipe_fd.as_fd()).unwrap();
        drop(pipe_fd);
        let borrowed: Vec<BorrowedFd<'_>> = dir_fds.iter().map(|f| f.as_fd()).collect();

        let mut stream_bytes = Vec::new();
        std::fs::File::from(pipe_dup)
            .read_to_end(&mut stream_bytes)
            .unwrap();

        let mut reconstructed = Vec::new();
        let n = composefs_splitdirfdstream::reconstruct(
            stream_bytes.as_slice(),
            &borrowed,
            &mut reconstructed,
        )
        .unwrap();
        assert_eq!(n, 1024);
        assert!(
            reconstructed
                .windows(b"child content!".len())
                .any(|w| w == b"child content!")
        );
        assert!(
            reconstructed
                .windows(b"parent content!".len())
                .any(|w| w == b"parent content!")
        );

        // Drop lifetime fds → signals producer (keepalive EOF).
        drop(lifetime_fds);

        drop(client);
        server.shutdown().await;
    }

    /// Regression test: the self-reaping producer must not deadlock.
    #[test]
    fn test_in_process_teardown_does_not_deadlock() {
        let tmp = TempDir::new().unwrap();
        let _ = create_two_layer_mock(tmp.path());
        let storage_path = tmp.path().to_str().unwrap().to_string();

        let worker = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async move {
                let (mut client, server) = spawn_in_process(CstorLayerService).unwrap();

                let (reply, all_fds, frame_count) =
                    collect_get_layer(&mut client, &storage_path, "child-layer-001").await;

                assert_eq!(frame_count, EXPECTED_N_FRAMES);
                assert_eq!(reply.dir_count, EXPECTED_DIR_COUNT);

                let mut it = all_fds.into_iter();
                let pipe_fd = it.next().unwrap();
                let _dir_fds: Vec<OwnedFd> = it.by_ref().take(reply.dir_count as usize).collect();
                let lifetime_fds: Vec<OwnedFd> = it.collect();

                let pipe_dup = rustix::io::dup(pipe_fd.as_fd()).unwrap();
                drop(pipe_fd);

                tokio::task::spawn_blocking(move || {
                    let _lifetime_fds = lifetime_fds;
                    let mut f = std::fs::File::from(pipe_dup);
                    let mut buf = Vec::new();
                    f.read_to_end(&mut buf).unwrap();
                    assert!(!buf.is_empty());
                })
                .await
                .unwrap();

                drop(client);
                server.shutdown().await;
            });
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !worker.is_finished() {
            if std::time::Instant::now() >= deadline {
                panic!("producer deadlocked: worker did not finish within 5s");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        worker.join().expect("worker thread panicked");
    }
}
