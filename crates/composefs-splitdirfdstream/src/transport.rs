//! Source-agnostic FD-transport mechanics for the splitdirfdstream wire protocol.
//!
//! This module contains the pure, Storage/Layer-independent helpers that govern
//! *how* a set of file descriptors is partitioned into transport frames and how
//! the sparse dirfd-slot layout is computed.  Both the `composefs-storage`
//! layer-transfer producer and future producers (e.g. a composefs-repo producer)
//! can share these primitives without pulling in any higher-level dependencies.
//!
//! # Public API
//!
//! | Item | Role |
//! |------|------|
//! | [`MAX_FDS_PER_FRAME`] | Enforced per-frame fd cap (240, safely below 253). |
//! | [`seed_from_id`] | Derive a deterministic `u64` seed from an opaque string id. |
//! | [`open_devnull`] | Open `/dev/null` for use as a dummy fd. |
//! | [`FdLimitError`] | Error from [`split_fds_into_frames`] when `more=false` overflows. |
//! | [`LayerFdLayout`] | Complete assembled wire layout from [`build_layer_fd_layout`]. |
//! | [`build_layer_fd_layout`] | Assemble the full sparse dirfd+keepalive+lifetime fd array. |
//! | [`split_fds_into_frames`] | Partition fds into frames, enforcing `more=false` cap. |
//! | [`spawn_self_reaping_producer`] | Spawn the 3-phase keepalive-lock producer task (requires `tokio` feature). |
//!
//! The producer-side seed jitter (sparse-slot placement, frame count, extra
//! lifetime fds) is computed by crate-internal helpers (`sparse_dir_slots`,
//! `compute_n_frames`, `n_extra_lifetime_fds`); the consumer never recomputes
//! it, since every `FileBackedData` chunk carries an explicit `dirfd_index`.

use std::os::fd::OwnedFd;

use rand::seq::SliceRandom as _;
use rand_pcg::Pcg64;
use rand_pcg::rand_core::SeedableRng as _;

// ── Constants ────────────────────────────────────────────────────────────────

/// Our enforced per-frame fd cap.
///
/// Kept safely below the hard kernel limit of 253 fds per `sendmsg(SCM_RIGHTS)`
/// call.  Every transport frame carries at most this many fds.
pub const MAX_FDS_PER_FRAME: usize = 240;

// ── Frame splitting ───────────────────────────────────────────────────────────

/// Partition `fds` into `n_frames` contiguous batches as evenly as possible.
///
/// The first `fds.len() % n_frames` batches receive one extra fd (so all
/// batches are non-empty when `n_frames <= fds.len()`).  Ordering is preserved:
/// concatenating the returned batches in order reconstructs the original vec.
///
/// # Panics
/// Panics if `n_frames == 0` or `n_frames > fds.len()`.
pub(crate) fn split_into_frames(fds: Vec<OwnedFd>, n_frames: usize) -> Vec<Vec<OwnedFd>> {
    assert!(n_frames > 0 && n_frames <= fds.len());
    let fd_count = fds.len();
    let base = fd_count / n_frames;
    let remainder = fd_count % n_frames;
    let mut result = Vec::with_capacity(n_frames);
    let mut it = fds.into_iter();
    for i in 0..n_frames {
        let batch_size = base + if i < remainder { 1 } else { 0 };
        result.push(it.by_ref().take(batch_size).collect());
    }
    result
}

// ── Seed derivation ───────────────────────────────────────────────────────────

/// Derive a deterministic `u64` seed from an opaque string identifier.
///
/// Uses the first 8 bytes of SHA-256(id) interpreted as little-endian u64.
/// The result is stable across runs for the same id string.
pub fn seed_from_id(id: &str) -> u64 {
    use sha2::Digest as _;
    let hash = sha2::Sha256::digest(id.as_bytes());
    u64::from_le_bytes(hash[..8].try_into().expect("sha256 is at least 8 bytes"))
}

// ── Frame-count helpers ───────────────────────────────────────────────────────

/// Compute the *hash-derived* minimum frame count for `fd_count` FDs keyed by `seed`.
///
/// - If `fd_count < 3`: returns `max(fd_count, 1)` (never more frames than FDs,
///   but always at least one so `split_into_frames` has a valid divisor).  This
///   branch is effectively dead: a real transport array is always ≥4 FDs
///   (pipe + ≥2 dirfd slots + keepalive).
/// - Otherwise: `max(3, seed % (fd_count + 1))` clamped to `fd_count`.
///
/// This guarantees ≥3 frames whenever there are ≥3 FDs, which exercises the
/// multi-frame path in tests while keeping the arithmetic deterministic.
///
/// **This is the hash-min component only.**  The call site additionally enforces
/// a per-frame cap ([`MAX_FDS_PER_FRAME`]) by taking `hash_min.max(cap_min)` where
/// `cap_min = ceil(fd_count / MAX_FDS_PER_FRAME)`.  For small layers
/// (≤`MAX_FDS_PER_FRAME` fds) `cap_min = 1` so the hash-min always wins,
/// preserving test-hardening behaviour.
pub(crate) fn n_frames_for(seed: u64, fd_count: usize) -> usize {
    if fd_count < 3 {
        return fd_count.max(1);
    }
    let raw = (seed % (fd_count as u64 + 1)) as usize;
    raw.max(3).min(fd_count)
}

/// Compute the actual number of transport frames for a `more=true` call.
///
/// Returns the larger of:
/// - the hash-derived minimum ([`n_frames_for`]`(seed, fd_count)`, ≥3 for real
///   layers), which exercises multi-frame paths in tests; and
/// - `ceil(fd_count / MAX_FDS_PER_FRAME)`, the minimum needed so every frame
///   carries at most [`MAX_FDS_PER_FRAME`] fds (kernel SCM_RIGHTS cap).
///
/// The result is additionally clamped to `[1, fd_count]` so `split_into_frames`
/// never receives an out-of-range value.
///
/// Proved invariant: `fd_count.div_ceil(n) <= MAX_FDS_PER_FRAME` for the
/// returned `n`, because `n >= ceil(fd_count / MAX_FDS_PER_FRAME)`.
pub(crate) fn compute_n_frames(seed: u64, fd_count: usize) -> usize {
    let hash_min = n_frames_for(seed, fd_count);
    let cap_min = fd_count.div_ceil(MAX_FDS_PER_FRAME);
    hash_min.max(cap_min).min(fd_count).max(1)
}

// ── Dummy-fd helpers ──────────────────────────────────────────────────────────

/// Open `/dev/null` as an opaque dummy fd.
///
/// Returns a plain [`std::io::Result`] so callers can map it to their own error type.
pub fn open_devnull() -> std::io::Result<OwnedFd> {
    rustix::fs::open(
        c"/dev/null",
        rustix::fs::OFlags::RDONLY,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)
}

/// Open an anonymous `memfd` as an opaque dummy fd.
///
/// Returns a plain [`std::io::Result`] so callers can map it to their own error type.
pub(crate) fn open_memfd() -> std::io::Result<OwnedFd> {
    rustix::fs::memfd_create(
        c"composefs-layer-transfer-dummy",
        rustix::fs::MemfdFlags::CLOEXEC,
    )
    .map_err(std::io::Error::from)
}

// ── Sparse-slot layout ────────────────────────────────────────────────────────

/// Describes the sparse dirfd-slot layout produced by [`sparse_dir_slots`].
///
/// The `dirfds` array passed to the consumer has length `total_slots` and contains
/// real diff-dir fds at `real_slot_indices[i]` (for chain layer `i`) and dummy fds
/// at all other positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SparseLayout {
    /// Total number of slots in the dirfds array (real + dummy).
    pub(crate) total_slots: usize,
    /// Ascending slot indices assigned to real layers.
    ///
    /// `real_slot_indices[i]` is the slot index for chain layer `i`.
    pub(crate) real_slot_indices: Vec<u32>,
    /// Slot indices that are dummy (complement of `real_slot_indices` in `0..total_slots`).
    pub(crate) dummy_slot_indices: Vec<u32>,
}

/// Compute the sparse slot assignment for `n_real` real layers using `seed`.
///
/// This is a pure function (no I/O) that encodes the deterministic slot-placement
/// algorithm:
///
/// 1. `n_dummy = (seed >> 8) % (n_real + 1) + 1`  (at least 1 dummy).
/// 2. `total_slots = n_real + n_dummy`.
/// 3. Deterministically shuffle `0..total_slots` with a `seed`-seeded PCG RNG,
///    take the first `n_real` as real-layer slot indices, sort them ascending.
/// 4. Dummy slots are `0..total_slots` minus the real indices.
///
/// The shuffle uses [`Pcg64`], whose algorithm is stable across `rand_pcg`
/// releases, so the placement is reproducible from the seed (useful for tests).
/// Reproducibility is *not* a correctness requirement: the consumer is driven
/// entirely by the explicit `dirfd_index` in each `FileBackedData` chunk and
/// never recomputes this layout.
///
/// The returned [`SparseLayout`] records `total_slots`, `real_slot_indices`
/// (ascending, length `n_real`), and `dummy_slot_indices` (ascending).
pub(crate) fn sparse_dir_slots(n_real: usize, seed: u64) -> SparseLayout {
    // ── 1/2: total slot count (at least 1 dummy) ─────────────────────────────
    let n_dummy: usize = ((seed >> 8) % (n_real as u64 + 1) + 1) as usize;
    let total_slots = n_real + n_dummy;

    // ── 3: select real-layer slot positions ──────────────────────────────────
    // Deterministically shuffle all slot indices from the seed, take the first
    // n_real as the real-layer positions, then sort them ascending.
    let mut rng = Pcg64::seed_from_u64(seed);
    let mut shuffled_slots: Vec<u32> = (0..total_slots as u32).collect();
    shuffled_slots.shuffle(&mut rng);
    let mut real_indices: Vec<u32> = shuffled_slots[..n_real].to_vec();
    real_indices.sort_unstable();

    // ── 4: compute dummy indices (complement) ─────────────────────────────────
    let real_set: std::collections::HashSet<u32> = real_indices.iter().copied().collect();
    let dummy_indices: Vec<u32> = (0..total_slots as u32)
        .filter(|i| !real_set.contains(i))
        .collect();

    SparseLayout {
        total_slots,
        real_slot_indices: real_indices,
        dummy_slot_indices: dummy_indices,
    }
}

// ── Lifetime dummy count ──────────────────────────────────────────────────────

/// Compute the number of extra opaque lifetime dummy fds for a given seed.
///
/// Returns 0, 1, or 2 — derived as `(seed >> 16) % 3`.  These are additional
/// dummy fds (beyond the keepalive pipe write-end) that the client must hold open
/// until it has finished reading the splitdirfdstream, then close.  Alternating
/// `/dev/null` and `memfd` fd kinds exercise transparent client pass-through.
pub(crate) fn n_extra_lifetime_fds(seed: u64) -> usize {
    ((seed >> 16) % 3) as usize
}

// ── High-level fd-layout helpers ─────────────────────────────────────────────

/// Error returned by [`split_fds_into_frames`] when `more=false` and the fd
/// count exceeds [`MAX_FDS_PER_FRAME`].
///
/// The caller must map this to their interface error and instruct the client to
/// retry with `more=true`.
#[derive(Debug, thiserror::Error)]
#[error("fd count {fd_count} exceeds per-frame limit {max_per_frame}; retry with more=true")]
pub struct FdLimitError {
    /// Total number of fds that would be sent.
    pub fd_count: usize,
    /// The per-frame cap that was exceeded.
    pub max_per_frame: usize,
}

/// Assembled FD layout ready to wire to the client in one or more transport frames.
///
/// This is the output of [`build_layer_fd_layout`]: a complete description of
/// every fd that will be sent across the socket, split into two groups:
///
/// * The **wire region** — everything that travels to the client:
///   - `fds_all[0]` — pipe read end (carries the `splitdirfdstream` bytes).
///   - `fds_all[1..=dir_count]` — dirfds region (sparse: real dirs + dummies).
///   - `fds_all[dir_count+1..]` — lifetime region (keepalive write + extras).
/// * The **keepalive read end** — retained on the server; when the client drops
///   the keepalive write end the server sees EOF and may release resources.
///
/// The `real_indices` slice maps chain layer `i` → slot index within the
/// *dirfds region* where that layer's real diff-dir fd sits.  Pass this to the
/// producer (via [`build_layer_fd_layout`]'s return value) so it can write the
/// correct `dirfd_index` into each `FileBackedData` chunk.
#[derive(Debug)]
pub struct LayerFdLayout {
    /// All fds to send to the client, ordered as described above.
    pub fds_all: Vec<OwnedFd>,
    /// Number of slots in the dirfds region (`dir_count` in reply and in the
    /// wire layout: `fds_all[1..=dir_count]`).
    pub dir_count: u32,
    /// Slot index within the dirfds region for each real layer (ascending).
    ///
    /// `real_indices[i]` is the `dirfd_index` the producer must use for chain
    /// layer `i`.
    pub real_indices: Vec<u32>,
    /// Server-side read end of the keepalive pipe.
    ///
    /// Hold this `OwnedFd` until the client has finished consuming the layer
    /// (or until the request is complete if keepalive is not needed for resource
    /// management).  When it drops, the client's matching write end sees EOF.
    pub keepalive_read: OwnedFd,
}

/// Build the complete wire fd layout for a producer serving `n_real` real diff
/// directories.
///
/// This pure-ish (only I/O: `pipe`, `/dev/null`, `memfd`) function:
///
/// 1. Calls [`sparse_dir_slots`] to compute the sparse placement.
/// 2. Opens dummy fds (`/dev/null` alternating with `memfd`) for gap slots.
/// 3. Builds the dirfds region by interleaving real and dummy fds in slot order.
/// 4. Creates a keepalive pipe; the write end goes into `fds_all`, the read end
///    is returned in [`LayerFdLayout::keepalive_read`].
/// 5. Adds `n_extra_lifetime_fds(seed)` extra dummy lifetime fds.
/// 6. Prepends the `pipe_read` fd so `fds_all[0]` is always the data pipe.
///
/// The caller is responsible for:
/// * Passing the correct `real_fds` (in chain order) — the first real_fd gets
///   slot `real_indices[0]`, the second gets `real_indices[1]`, etc.
/// * Spawning the producer with `write_fd` (not returned here; the caller opens
///   the pipe and passes `write_fd` to the producer separately).
///
/// # Arguments
/// * `pipe_read` — Read end of the data pipe (will become `fds_all[0]`).
/// * `real_fds` — Pre-opened real diff-directory file descriptors, one per
///   chain layer, in chain order.
/// * `seed` — Deterministic seed (see [`seed_from_id`]).
///
/// # Errors
/// Returns `io::Error` if any dummy-fd or keepalive-pipe creation fails.
pub fn build_layer_fd_layout(
    pipe_read: OwnedFd,
    real_fds: Vec<OwnedFd>,
    seed: u64,
) -> std::io::Result<LayerFdLayout> {
    let n_real = real_fds.len();
    let layout = sparse_dir_slots(n_real, seed);
    let total_slots = layout.total_slots;

    // ── Build dirfds region: slot i = real fd or dummy fd ────────────────────
    let mut dirfd_region: Vec<Option<OwnedFd>> = (0..total_slots).map(|_| None).collect();

    // Place real fds at their assigned slots.
    for (chain_idx, real_fd) in real_fds.into_iter().enumerate() {
        let slot = layout.real_slot_indices[chain_idx] as usize;
        dirfd_region[slot] = Some(real_fd);
    }

    // Fill dummy slots, alternating /dev/null and memfd.
    for (dummy_ordinal, &dummy_slot) in layout.dummy_slot_indices.iter().enumerate() {
        let dummy_fd = if dummy_ordinal % 2 == 0 {
            open_devnull()?
        } else {
            open_memfd()?
        };
        dirfd_region[dummy_slot as usize] = Some(dummy_fd);
    }

    // Unwrap: every slot was filled above.
    let dirfd_region: Vec<OwnedFd> = dirfd_region.into_iter().map(|o| o.unwrap()).collect();

    // ── Keepalive pipe ────────────────────────────────────────────────────────
    let (keepalive_read, keepalive_write) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(std::io::Error::from)?;

    // ── Extra lifetime dummy fds ──────────────────────────────────────────────
    let n_extra = n_extra_lifetime_fds(seed);
    let mut extra_lifetime: Vec<OwnedFd> = Vec::with_capacity(n_extra);
    for i in 0..n_extra {
        let fd = if i % 2 == 0 {
            open_devnull()?
        } else {
            open_memfd()?
        };
        extra_lifetime.push(fd);
    }

    // ── Assemble fds_all ──────────────────────────────────────────────────────
    //   index 0              : pipe read
    //   index 1..=dir_count  : dirfds region
    //   index dir_count+1    : keepalive write end
    //   remaining            : extra lifetime dummies
    let dir_count = total_slots as u32;
    let mut fds_all: Vec<OwnedFd> = Vec::with_capacity(1 + total_slots + 1 + n_extra);
    fds_all.push(pipe_read);
    fds_all.extend(dirfd_region);
    fds_all.push(keepalive_write);
    fds_all.extend(extra_lifetime);

    Ok(LayerFdLayout {
        fds_all,
        dir_count,
        real_indices: layout.real_slot_indices,
        keepalive_read,
    })
}

/// Partition a complete fd array into transport frames.
///
/// When `more` is `true` the fds are split across `compute_n_frames(seed, n)`
/// batches (≥3 for test hardening, cap-limited to ≤[`MAX_FDS_PER_FRAME`] per
/// frame).
///
/// When `more` is `false` all fds must fit in a single frame.  If the total
/// count exceeds [`MAX_FDS_PER_FRAME`] the fds are returned intact inside an
/// [`Err(FdLimitError)`] so they can be dropped cleanly by the caller before
/// returning an error reply.
///
/// # Returns
/// `Ok(Vec<Vec<OwnedFd>>)` — one inner vec per transport frame (1…N frames).
/// `Err(FdLimitError { fds, .. })` — the original fds are returned so the
/// caller can drop them; the error contains the count and cap for a diagnostic.
pub fn split_fds_into_frames(
    fds: Vec<OwnedFd>,
    seed: u64,
    more: bool,
) -> Result<Vec<Vec<OwnedFd>>, (Vec<OwnedFd>, FdLimitError)> {
    let fd_count = fds.len();
    if !more && fd_count > MAX_FDS_PER_FRAME {
        return Err((
            fds,
            FdLimitError {
                fd_count,
                max_per_frame: MAX_FDS_PER_FRAME,
            },
        ));
    }
    let n = if more {
        compute_n_frames(seed, fd_count)
    } else {
        1
    };
    Ok(split_into_frames(fds, n))
}

// ─────────────────────────────────────────────────────────────────────────────
// Self-reaping producer task (optional: requires `tokio` feature)
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn a self-reaping blocking producer task that implements the 3-phase
/// keepalive-lock protocol used by both the repo and cstor `GetLayer`
/// implementations.
///
/// # Phases
///
/// 1. **Produce**: call `produce(write_fd_as_File)`.  When `produce` returns the
///    write end of the data pipe drops, signalling data-EOF to the consumer.
/// 2. **Keepalive wait**: read from `keepalive_read` until EOF.  The consumer
///    drops its keepalive write end after it finishes draining the data pipe,
///    so this phase acts as a rendezvous before releasing any held resources.
/// 3. **Release**: drop `guard`.  For the repo path `guard` is `()` (no-op);
///    for the cstor path `guard` is a `LayerStoreLock` whose drop releases the
///    shared flock.
///
/// # Ordering guarantee
///
/// Phase 2 begins **after** `write_fd` is dropped (end of Phase 1), so the
/// data pipe is always at EOF before we start waiting on the keepalive.  The
/// reverse would cause a deadlock: if the consumer must drain to EOF to drop
/// the keepalive but the producer never finishes, the pipe never EOF.
///
/// # Arguments
///
/// * `write_fd` — Write end of the data pipe; moved into the closure and
///   dropped at the end of Phase 1.
/// * `keepalive_read` — Read end of the keepalive pipe; retained until Phase 2
///   EOF, then dropped.
/// * `guard` — Opaque lifetime guard released in Phase 3 (e.g. a lock).
/// * `produce` — Called with a `std::fs::File` wrapping `write_fd`.  Should
///   write the complete `splitdirfdstream` into the file and return.  Errors
///   are logged as warnings; a short/corrupt stream will be detected later by
///   the consumer's integrity check.
#[cfg(feature = "tokio")]
pub fn spawn_self_reaping_producer(
    write_fd: OwnedFd,
    keepalive_read: OwnedFd,
    guard: impl Send + 'static,
    produce: impl FnOnce(std::fs::File) + Send + 'static,
) {
    tokio::task::spawn_blocking(move || {
        // Phase 1: produce into write_fd; drop write_fd (data-pipe EOF).
        {
            let wf = std::fs::File::from(write_fd);
            produce(wf);
            // write_fd drops here → data-pipe EOF visible to consumer.
        }

        // Phase 2: wait for consumer to signal completion via keepalive EOF.
        let mut buf = [0u8; 64];
        loop {
            match rustix::io::read(&keepalive_read, &mut buf) {
                Ok(0) => break,                    // EOF — consumer dropped its write end
                Ok(_) => {}                        // unexpected bytes — drain and continue
                Err(rustix::io::Errno::INTR) => {} // EINTR — retry
                Err(_) => break,                   // other error — bail
            }
        }

        // Phase 3: release guard (e.g. drop the shared flock).
        drop(guard);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Seed for "child-layer-001" (SHA-256("child-layer-001")[0..8] as LE-u64).
    ///
    /// Verified: `seed_from_id("child-layer-001") == LAYER_SEED`.
    const LAYER_SEED: u64 = 9_551_015_030_439_334_514;

    /// `compute_n_frames` must ensure every frame holds ≤ MAX_FDS_PER_FRAME fds
    /// for a large synthetic fd count where the hash-min alone would be too small.
    #[test]
    fn test_compute_n_frames_caps_large_fd_count() {
        // Use a seed whose hash-min is small (e.g. seed=0 → raw=0 → max(3,0)=3).
        let seed: u64 = 0;
        // Choose fd_count large enough that 3 frames would exceed 240 each.
        // ceil(1000 / 3) = 334 > 240, so cap_min must win.
        let fd_count: usize = 1000;

        let n = compute_n_frames(seed, fd_count);

        // Invariant: every frame carries at most MAX_FDS_PER_FRAME fds.
        let max_frame_size = fd_count.div_ceil(n);
        assert!(
            max_frame_size <= MAX_FDS_PER_FRAME,
            "frame size {max_frame_size} exceeds cap {MAX_FDS_PER_FRAME} (n={n}, fd_count={fd_count})",
        );

        // Also verify n is large enough: ceil(1000/240) = 5.
        let cap_min = fd_count.div_ceil(MAX_FDS_PER_FRAME);
        assert!(n >= cap_min, "n={n} < cap_min={cap_min}",);
    }

    /// For small fd counts (≤ MAX_FDS_PER_FRAME) the hash-min should still
    /// dominate so test-hardening (≥3 frames for real layers) is preserved.
    #[test]
    fn test_compute_n_frames_small_fd_count_preserves_hash_min() {
        // The existing test layer has 9 fds → cap_min=1, hash_min=4.
        let n = compute_n_frames(LAYER_SEED, 9);
        // EXPECTED_N_FRAMES = 4 for "child-layer-001"
        assert_eq!(n, 4, "hash_min should win for small fd counts");

        // Any fd count ≤ MAX_FDS_PER_FRAME has cap_min=1; hash_min (≥3) always wins.
        for fd_count in 3..=MAX_FDS_PER_FRAME {
            let n = compute_n_frames(LAYER_SEED, fd_count);
            let max_frame_size = fd_count.div_ceil(n);
            assert!(
                max_frame_size <= MAX_FDS_PER_FRAME,
                "frame size {max_frame_size} > cap for fd_count={fd_count}",
            );
        }
    }

    /// `compute_n_frames` invariant holds across a sweep of large fd counts.
    #[test]
    fn test_compute_n_frames_cap_invariant_sweep() {
        let seeds: &[u64] = &[0, 1, 42, LAYER_SEED, u64::MAX];
        let fd_counts: &[usize] = &[
            MAX_FDS_PER_FRAME,
            MAX_FDS_PER_FRAME + 1,
            MAX_FDS_PER_FRAME * 2,
            MAX_FDS_PER_FRAME * 5,
            1000,
            5000,
        ];
        for &seed in seeds {
            for &fd_count in fd_counts {
                let n = compute_n_frames(seed, fd_count);
                let max_frame_size = fd_count.div_ceil(n);
                assert!(
                    max_frame_size <= MAX_FDS_PER_FRAME,
                    "invariant violated: seed={seed} fd_count={fd_count} n={n} \
                     max_frame_size={max_frame_size} cap={MAX_FDS_PER_FRAME}",
                );
            }
        }
    }

    /// A non-streaming (`more=false`) call that would exceed MAX_FDS_PER_FRAME
    /// must be detected by the over-cap check before the producer is spawned.
    ///
    /// We test the pure decision logic (`!more && fd_count > MAX_FDS_PER_FRAME`)
    /// without opening real fds, keeping the test deterministic and cheap.
    #[test]
    fn test_more_false_over_cap_decision() {
        // Verify the threshold is exactly MAX_FDS_PER_FRAME.
        assert!(
            !(!false && MAX_FDS_PER_FRAME > MAX_FDS_PER_FRAME),
            "fd_count == cap should NOT trigger error",
        );
        assert!(
            !false && (MAX_FDS_PER_FRAME + 1) > MAX_FDS_PER_FRAME,
            "fd_count == cap+1 MUST trigger error",
        );

        // Simulate: if !more and fd_count > MAX_FDS_PER_FRAME → error.
        let should_error =
            |more: bool, fd_count: usize| -> bool { !more && fd_count > MAX_FDS_PER_FRAME };

        assert!(
            !should_error(true, MAX_FDS_PER_FRAME + 1),
            "more=true should never error on fd count"
        );
        assert!(
            !should_error(false, MAX_FDS_PER_FRAME),
            "more=false at exactly cap should not error"
        );
        assert!(
            should_error(false, MAX_FDS_PER_FRAME + 1),
            "more=false over cap must error"
        );
        assert!(
            should_error(false, 1000),
            "more=false with 1000 fds must error"
        );
    }

    /// `seed_from_id` must match the precomputed value for "child-layer-001".
    #[test]
    fn test_seed_from_id_child_layer() {
        assert_eq!(
            seed_from_id("child-layer-001"),
            LAYER_SEED,
            "seed_from_id must match precomputed SHA-256-derived value"
        );
    }

    /// `sparse_dir_slots` must produce a valid, seed-reproducible layout.
    ///
    /// The dummy count derives from the seed independently of placement, so for
    /// "child-layer-001" (seed = 9551015030439334514): `n_dummy = (seed >> 8) %
    /// (2+1) + 1 = 3`, hence `total_slots = 5`.  Real-slot *placement* comes from
    /// a `Pcg64` shuffle: we assert the structural invariants plus determinism
    /// (same seed → same layout) rather than pinning the exact slot indices.
    #[test]
    fn test_sparse_dir_slots_known_layout() {
        let layout = sparse_dir_slots(2, LAYER_SEED);

        // Seed-derived counts (independent of the shuffle).
        assert_eq!(layout.total_slots, 5, "total_slots must be 5");
        assert_eq!(layout.real_slot_indices.len(), 2, "two real layers");
        assert_eq!(layout.dummy_slot_indices.len(), 3, "three dummy slots");

        // Structural invariants: both lists ascending, disjoint, and together
        // covering exactly 0..total_slots.
        assert!(
            layout.real_slot_indices.windows(2).all(|w| w[0] < w[1]),
            "real_slot_indices ascending"
        );
        assert!(
            layout.dummy_slot_indices.windows(2).all(|w| w[0] < w[1]),
            "dummy_slot_indices ascending"
        );
        let mut all: Vec<u32> = layout
            .real_slot_indices
            .iter()
            .chain(&layout.dummy_slot_indices)
            .copied()
            .collect();
        all.sort_unstable();
        assert_eq!(
            all,
            (0..layout.total_slots as u32).collect::<Vec<_>>(),
            "real and dummy slots must partition 0..total_slots"
        );

        // Determinism: the Pcg64 shuffle is reproducible from the seed.
        assert_eq!(
            sparse_dir_slots(2, LAYER_SEED),
            layout,
            "same seed must yield the same layout"
        );
    }

    /// `n_extra_lifetime_fds` must return 2 for "child-layer-001"'s seed.
    #[test]
    fn test_n_extra_lifetime_fds_child_layer() {
        assert_eq!(
            n_extra_lifetime_fds(LAYER_SEED),
            2,
            "n_extra_lifetime_fds must be 2 for child-layer-001 seed"
        );
    }
}
