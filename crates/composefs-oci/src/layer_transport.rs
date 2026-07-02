//! Abstraction layer for the OCI `GetLayer` producer side.
//!
//! Defines the [`LayerSource`] trait that decouples the fd-assembly and
//! framing mechanics from the specific backing store (composefs repo today,
//! containers-storage in a later step).  Both the in-process `copy` path and
//! the varlink `GetLayer` handler use this trait.
//!
//! The shared entry point is [`serve_get_layer`], which:
//! 1. Calls [`LayerSource::open`] to get real dirfds and a lifetime guard.
//! 2. Calls [`composefs_splitdirfdstream::build_layer_fd_layout`] to place them
//!    in the sparse layout, add dummies, keepalive pipe and extra lifetime fds.
//! 3. Spawns the 3-phase self-reaping producer via
//!    [`composefs_splitdirfdstream::spawn_self_reaping_producer`].
//! 4. Splits the fd array into transport frames via
//!    [`composefs_splitdirfdstream::split_fds_into_frames`].
//! 5. Returns the ready frame batches + `dir_count` for the caller to wrap in
//!    zlink `Reply` frames (interface-specific error types stay in the callers).
//!
//! # Dependency note
//!
//! This module lives in `composefs-oci` rather than `composefs-splitdirfdstream`
//! because the trait references `anyhow::Result` and repository types, while
//! `composefs-splitdirfdstream` must stay dependency-free of those crates.
//! The cstor service (`composefs-storage`) CANNOT call `serve_get_layer`
//! (it would create a dep cycle), so it calls `build_layer_fd_layout` +
//! `spawn_self_reaping_producer` directly.

use std::io::Write;
use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::Arc;

use anyhow::{Context as _, Result};

use composefs::fsverity::FsVerityHashValue;
use composefs::repository::Repository;
use composefs_splitdirfdstream::{
    FdLimitError, build_layer_fd_layout, spawn_self_reaping_producer, split_fds_into_frames,
};

use crate::layer_sync::produce_layer_splitdirfdstream;

// ── LayerSource trait ─────────────────────────────────────────────────────────

/// A producer that can open the real diff-directory file descriptors for one
/// layer and stream the layer content as a `splitdirfdstream`.
///
/// Implementors supply two things:
/// 1. The set of real diff-directory fds (in chain order) **plus an opaque
///    lifetime guard** that must be held open until the consumer signals
///    completion (keepalive-pipe EOF).  For the repo case the guard is `()`;
///    for containers-storage the guard is the shared `LayerStoreLock`.
/// 2. A function that, given the slot-index assignments from the sparse layout,
///    produces the `splitdirfdstream` bytes into a writer.
///
/// The trait is object-safe so it can be stored in `Box<dyn LayerSource>`.
pub trait LayerSource: Send + 'static {
    /// Open the real diff-directory file descriptors for this layer, in chain order,
    /// AND acquire any lifetime-bound resources (e.g. a shared layer-store lock).
    ///
    /// Returns `(dirfds, guard)` where:
    /// - `dirfds` — the real diff-dir fds, one per chain layer, in chain order.
    /// - `guard` — an opaque object that **must be held open** until the
    ///   consumer finishes processing (keepalive-pipe EOF). Dropping the guard
    ///   signals that the layer's storage may be released.  For the repo source
    ///   this is `Box::new(())` (no-op).
    ///
    /// The lock is acquired BEFORE the fds are opened so that the lock →
    /// open sequence is atomic (avoids a TOCTOU race where a concurrent
    /// `podman rmi` could unlink a diff directory between lock and open).
    ///
    /// Called once per `GetLayer` request, before the sparse layout is built.
    fn open(&self) -> Result<(Vec<OwnedFd>, Box<dyn Send + 'static>)>;

    /// Write the layer content as a `splitdirfdstream` to `out`.
    ///
    /// `dirfd_index_map[i]` is the slot index within the sparse dirfds region
    /// where the `i`-th real diff-dir fd was placed.  The producer must use
    /// `write_file_backed_data(dirfd_index_map[i], ...)` for every file that
    /// belongs to chain layer `i`.
    ///
    /// This method is called from a `spawn_blocking` context so it MAY block.
    fn produce(&self, dirfd_index_map: &[u32], out: Box<dyn Write + Send>) -> Result<()>;
}

// ── RepoLayerSource ───────────────────────────────────────────────────────────

/// [`LayerSource`] implementation backed by a composefs [`Repository`].
///
/// The objects directory is the single real diff-dir (chain index 0).
pub struct RepoLayerSource<ObjectID: FsVerityHashValue> {
    /// The repository from which to serve the layer.
    pub repo: Arc<Repository<ObjectID>>,
    /// fs-verity hash of the layer splitstream to serve.
    pub layer_verity: ObjectID,
}

impl<ObjectID> std::fmt::Debug for RepoLayerSource<ObjectID>
where
    ObjectID: FsVerityHashValue + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepoLayerSource")
            .field("layer_verity", &self.layer_verity)
            .finish_non_exhaustive()
    }
}

impl<ObjectID> LayerSource for RepoLayerSource<ObjectID>
where
    ObjectID: FsVerityHashValue,
{
    fn open(&self) -> Result<(Vec<OwnedFd>, Box<dyn Send + 'static>)> {
        let objects_dir = self
            .repo
            .objects_dir()
            .context("opening repository objects dir")?;
        let dup = rustix::io::dup(objects_dir.as_fd())
            .map_err(std::io::Error::from)
            .context("dup objects_dir fd")?;
        // No external lock needed for the repo source; the guard is a no-op.
        Ok((vec![dup], Box::new(())))
    }

    fn produce(&self, dirfd_index_map: &[u32], out: Box<dyn Write + Send>) -> Result<()> {
        // The objects dir is at chain layer index 0 → dirfd_index_map[0].
        let objects_dirfd_index = dirfd_index_map
            .first()
            .copied()
            .context("dirfd_index_map is empty: expected at least one real dir")?;
        produce_layer_splitdirfdstream(&self.repo, &self.layer_verity, objects_dirfd_index, out)
    }
}

// ── serve_get_layer ───────────────────────────────────────────────────────────

/// Ready frame batches returned by [`serve_get_layer`].
///
/// The caller wraps these in interface-specific zlink `Reply` frames and
/// yields them from the streaming `GetLayer` method.
#[derive(Debug)]
pub struct GetLayerFrames {
    /// Number of dirfd slots in the sparse layout (`fds[1..=dir_count]`).
    pub dir_count: u32,
    /// FD batches in frame order; one inner `Vec<OwnedFd>` per transport frame.
    pub batches: Vec<Vec<OwnedFd>>,
}

/// Error from [`serve_get_layer`].
#[derive(Debug)]
pub enum ServeGetLayerError {
    /// `more=false` but total fd count exceeds `MAX_FDS_PER_FRAME`.
    FdLimitExceeded(FdLimitError),
    /// Any other I/O or source error.
    Other(anyhow::Error),
}

impl From<anyhow::Error> for ServeGetLayerError {
    fn from(e: anyhow::Error) -> Self {
        ServeGetLayerError::Other(e)
    }
}

/// Drive the full `GetLayer` flow for a [`LayerSource`] and return ready frame
/// batches.
///
/// This is the single canonical implementation of the fd-layout + producer +
/// framing logic for the repo `GetLayer` path.  The cstor `GetLayer` path in
/// `composefs-storage` cannot call this function (dep cycle), so it calls
/// `build_layer_fd_layout` and `spawn_self_reaping_producer` directly.
/// Both paths share the same primitives from `composefs-splitdirfdstream`.
///
/// # Arguments
/// * `source` — The layer source.  `source.open()` is called once; the returned
///   guard is moved into the self-reaping producer task.
/// * `seed` — Deterministic seed for sparse layout and frame count.
/// * `more` — Whether the client requested multi-frame streaming (`more=true`)
///   or a single-frame reply (`more=false`).
///
/// # Returns
/// `Ok(GetLayerFrames)` — ready to wrap in zlink replies.
/// `Err(ServeGetLayerError::FdLimitExceeded)` — total fd count exceeds
///   `MAX_FDS_PER_FRAME`; retry with `more=true`.
/// `Err(ServeGetLayerError::Other)` — source or I/O error.
pub fn serve_get_layer(
    source: impl LayerSource,
    seed: u64,
    more: bool,
) -> std::result::Result<GetLayerFrames, ServeGetLayerError> {
    // Open real dirfds + acquire lifetime guard.
    let (real_fds, guard) = source.open()?;

    // Create the data pipe.
    let (pipe_read, pipe_write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
        .map_err(|e| anyhow::anyhow!("pipe: {e}"))?;

    // Build the sparse fd layout (dirfds region + keepalive + extra lifetime fds).
    let layout = build_layer_fd_layout(pipe_read, real_fds, seed)
        .map_err(|e| anyhow::anyhow!("build_layer_fd_layout: {e}"))?;

    let dir_count = layout.dir_count;
    let real_indices = layout.real_indices.clone();
    let keepalive_read = layout.keepalive_read;

    // Split into transport frames (enforces more=false single-frame cap).
    let batches = split_fds_into_frames(layout.fds_all, seed, more)
        .map_err(|(_fds, e)| ServeGetLayerError::FdLimitExceeded(e))?;

    // Spawn the 3-phase self-reaping producer.
    // `source` and `guard` are both moved into the closure.
    // `guard` drops last (Phase 3), releasing any held lock.
    spawn_self_reaping_producer(pipe_write, keepalive_read, guard, move |wf| {
        if let Err(e) = source.produce(&real_indices, Box::new(wf)) {
            tracing::warn!("GetLayer producer error: {e:#}");
        }
    });

    Ok(GetLayerFrames { dir_count, batches })
}
