//! Shared, content-agnostic splitdirfdstream producer and consumer for layer
//! synchronisation.
//!
//! This module holds the blocking logic for producing a `splitdirfdstream` from a
//! stored layer and for draining one back into a repository.  It depends only on
//! the (tiny) `composefs-splitdirfdstream` crate, not the containers-storage /
//! podman stack, so it is always compiled — including in builds that do not
//! enable the `containers-storage` feature.
//!
//! Callers:
//! * `crates/composefs-oci/src/cstor.rs` — the containers-storage import path
//!   (only built with the `containers-storage` feature).
//! * `composefs-ctl` varlink server — repo-to-repo layer synchronisation via
//!   `GetLayer`/`PutLayer`, and the `oci copy` command.

use std::os::unix::fs::FileExt;
use std::os::unix::io::OwnedFd;
use std::sync::Arc;

use anyhow::{Context, Result};
use cap_std_ext::cap_std;
use composefs_splitdirfdstream::{Chunk, SplitdirfdstreamReader, SplitdirfdstreamWriter};
use rustix::fs::{MemfdFlags, fstat, memfd_create};
use sha2::{Digest as _, Sha256};

use composefs::{
    INLINE_CONTENT_MAX_V0,
    fsverity::FsVerityHashValue,
    repository::{ImportContext, ObjectStoreMethod, Repository},
    splitstream::{SplitStreamData, SplitStreamWriter},
};

use crate::skopeo::TAR_LAYER_CONTENT_TYPE;
use crate::{ImportStats, OciDigest, layer_identifier, sha256_output_to_digest};

/// Errors returned by the diff-id-verifying drain path.
///
/// Separates the integrity-check failure (wrong content) from I/O or
/// repository errors so that callers can surface a clear diagnostic.
#[derive(Debug, thiserror::Error)]
pub enum VerifiedDrainError {
    /// The reconstructed layer content does not match the declared `diff_id`.
    #[error("layer content does not match declared diff_id: expected {expected}, got {actual}")]
    DiffIdMismatch {
        /// The diff_id that was declared by the sender.
        expected: String,
        /// The sha256 of the data that was actually received.
        actual: String,
    },
    /// Any other I/O or repository error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Verify that `fd` is a directory before using it as a base for `openat`.
///
/// If it is not a directory, returns a detailed error showing the fd index,
/// file type bits, and size — making it easy to distinguish real diff-dirs
/// from dummy `/dev/null` or `memfd` fds that ended up at the wrong slot.
fn assert_is_dir(fd: &impl rustix::fd::AsFd, slot: u32, name: &str) -> anyhow::Result<()> {
    use rustix::fs::FileType;
    let st = fstat(fd).with_context(|| format!("fstat overlay_dir[{slot}]"))?;
    let ft = FileType::from_raw_mode(st.st_mode);
    if ft != FileType::Directory {
        anyhow::bail!(
            "overlay_dir[{slot}] is not a directory (file type: {ft:?}, \
             mode={:#o}, size={}) — cannot open {name:?}; \
             this is likely a bug where a dummy fd (e.g. /dev/null or memfd) \
             was stored at a slot that should hold a real diff-dir fd",
            st.st_mode,
            st.st_size
        );
    }
    Ok(())
}

/// Drain the `splitdirfdstream` pipe and write the resulting layer splitstream.
///
/// This is the blocking half of a layer-import operation — it should be run on a
/// `spawn_blocking` thread so the pipe can fill concurrently with the producer.
///
/// # Arguments
/// * `repo` — Repository to import into.
/// * `pipe_read` — Read end of the splitdirfdstream pipe.
/// * `dir_fds` — Sparse dirfds region passed wholesale by the transport layer.
///   `dir_fds[dirfd_index]` resolves the real diff-directory fd for each
///   [`Chunk::FileBackedData`] chunk.  Dummy fds at gap slots are never opened.
/// * `diff_id` — OCI diff-id of the layer (used as the stream content identifier).
/// * `zerocopy` — If `true`, use reflink/zerocopy when storing large objects.
/// * `ctx` — Import context (passed back to the caller on success).
///
/// # Returns
/// A tuple of `(verity_hash, import_stats, import_context)` on success.
pub fn drain_splitdirfdstream<ObjectID: FsVerityHashValue>(
    repo: Arc<Repository<ObjectID>>,
    pipe_read: OwnedFd,
    dir_fds: Vec<OwnedFd>,
    diff_id: &OciDigest,
    zerocopy: bool,
    mut ctx: ImportContext,
) -> Result<(ObjectID, ImportStats, ImportContext)> {
    // Wrap each fd as a cap_std Dir. Dummy fds (at sparse gap slots) are never
    // opened by the logic below; only the slot named by dirfd_index is accessed.
    let overlay_dirs: Vec<cap_std::fs::Dir> =
        dir_fds.into_iter().map(cap_std::fs::Dir::from).collect();

    let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE)?;
    let content_id = layer_identifier(diff_id);
    let mut reader = SplitdirfdstreamReader::new(std::fs::File::from(pipe_read));
    let mut inline_buf = Vec::new();
    let mut stats = ImportStats::default();

    drain_splitdirfdstream_inner(
        &repo,
        &mut writer,
        &mut reader,
        &overlay_dirs,
        zerocopy,
        &mut stats,
        &mut ctx,
        &mut inline_buf,
        None,
    )?;

    let verity = repo.write_stream(writer, &content_id, None)?;
    Ok((verity, stats, ctx))
}

#[allow(clippy::too_many_arguments)]
fn drain_splitdirfdstream_inner<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    writer: &mut SplitStreamWriter<ObjectID>,
    reader: &mut SplitdirfdstreamReader<std::fs::File>,
    overlay_dirs: &[cap_std::fs::Dir],
    zerocopy: bool,
    stats: &mut ImportStats,
    ctx: &mut ImportContext,
    inline_buf: &mut Vec<u8>,
    mut hasher: Option<&mut Sha256>,
) -> Result<()> {
    while let Some(chunk) = reader.next_chunk().context("splitdirfdstream read error")? {
        match chunk {
            Chunk::Metadata(data) => {
                if let Some(ref mut h) = hasher {
                    h.update(data);
                }
                stats.bytes_inlined += data.len() as u64;
                writer.write_inline(data);
            }
            Chunk::InlineData(data) => {
                // Non-world-readable file transported inline by the producer.
                // We already have the bytes — no fd needed for the small case.
                if let Some(ref mut h) = hasher {
                    h.update(data);
                }
                let length = data.len() as u64;
                if should_inline(length) {
                    stats.bytes_inlined += length;
                    writer.write_inline(data);
                } else {
                    // Large payload received as Chunk::InlineData (producer
                    // determined the consumer can't safely open this file by
                    // name — see consumer_has_cap_dac_override in
                    // GetLayerParams), so unlike Chunk::FileBackedData below,
                    // there's no real on-disk file backing this data. We
                    // materialise it into a memfd purely to hand
                    // process_file_content an fd; that memfd can never be
                    // zero-copyable (reflink/hardlink), regardless of the
                    // caller's `zerocopy` flag, so always pass `false` here.
                    process_file_content(
                        repo,
                        writer,
                        stats,
                        ctx,
                        file_content_to_memfd(data)?,
                        length,
                        "<file-content>",
                        false,
                        inline_buf,
                    )?;
                }
            }
            Chunk::FileBackedData {
                dirfd_index,
                length,
                filename,
            } => {
                let name = std::str::from_utf8(filename).with_context(|| {
                    format!("non-utf8 filename in splitdirfdstream: {filename:?}")
                })?;
                let dir = overlay_dirs.get(dirfd_index as usize).with_context(|| {
                    format!(
                        "dirfd_index {dirfd_index} out of range (dir_fds.len={})",
                        overlay_dirs.len()
                    )
                })?;
                assert_is_dir(dir, dirfd_index, name)?;
                let fd = dir
                    .open(name)
                    .map(OwnedFd::from)
                    .with_context(|| format!("open {name:?} in overlay dir[{dirfd_index}]"))?;

                use rustix::fs::FileType;
                let st = fstat(&fd).with_context(|| format!("fstat {name:?}"))?;
                let ft = FileType::from_raw_mode(st.st_mode);
                if ft != FileType::RegularFile {
                    anyhow::bail!(
                        "object {name:?} in overlay dir[{dirfd_index}] is not a regular file (file type: {ft:?}, mode={:#o})",
                        st.st_mode
                    );
                }

                let fd_to_process = if let Some(ref mut h) = hasher {
                    // Defend against a producer that declares a `length` that
                    // disagrees with the actual object size.  The reflink store
                    // path already rejects a mismatch, but the copy fallback would
                    // store the whole file while we only hashed `length` bytes,
                    // so the committed object could differ from the verified
                    // bytes.  Pin the two together by requiring length == size.
                    let obj_file = std::fs::File::from(fd);
                    let actual_size = st.st_size as u64;
                    if actual_size != length {
                        anyhow::bail!(
                            "object {name}: declared length {length} != actual size {actual_size}"
                        );
                    }

                    // Hash the object file content using positioned reads.  This
                    // does not disturb the fd cursor, so process_file_content can
                    // independently read/reflink the same fd afterwards.
                    hash_fd_contents(&obj_file, length, h)
                        .with_context(|| format!("hashing object {name}"))?;

                    obj_file.into()
                } else {
                    fd
                };

                process_file_content(
                    repo,
                    writer,
                    stats,
                    ctx,
                    fd_to_process,
                    length,
                    name,
                    zerocopy,
                    inline_buf,
                )?;
                // NOTE: padding after the file content is already emitted by the
                // producer as a following Inline chunk; do NOT add extra padding here.
            }
        }
    }
    Ok(())
}

/// Materialise `data` into an anonymous `memfd` for use with
/// [`process_file_content`].
///
/// The memfd is created `CLOEXEC` and the data written at offset 0.
/// `process_file_content` uses positioned reads (`pread`/`read_at`) so the
/// write cursor position does not matter.
fn file_content_to_memfd(data: &[u8]) -> Result<OwnedFd> {
    let memfd = memfd_create(c"composefs-filecontent", MemfdFlags::CLOEXEC)
        .context("memfd_create for FileContent chunk")?;
    rustix::io::write(&memfd, data).context("writing FileContent to memfd")?;
    Ok(memfd)
}

/// Hash `len` bytes of `fd` starting at offset 0 into `hasher`, using
/// positioned reads so the fd cursor is not disturbed.
///
/// Uses [`FileExt::read_at`] in a loop with a 64 KiB stack buffer to
/// avoid allocating for large objects.
fn hash_fd_contents(fd: &std::fs::File, len: u64, hasher: &mut Sha256) -> Result<()> {
    const BUF_SIZE: usize = 65536;
    let mut buf = [0u8; BUF_SIZE];
    let mut remaining = len;
    let mut offset = 0u64;

    while remaining > 0 {
        let to_read = remaining.min(BUF_SIZE as u64) as usize;
        let n = fd
            .read_at(&mut buf[..to_read], offset)
            .context("read_at while hashing fd contents")?;
        if n == 0 {
            anyhow::bail!(
                "unexpected EOF at offset {offset} hashing fd (expected {len} bytes total)"
            );
        }
        hasher.update(&buf[..n]);
        offset += n as u64;
        remaining -= n as u64;
    }
    Ok(())
}

/// Like [`drain_splitdirfdstream`], but additionally verifies that the
/// reconstructed (uncompressed tar) content hashes to `diff_id`, and only
/// commits the layer splitstream to the repository if it matches.
///
/// On mismatch the partially-written stream is discarded and
/// [`VerifiedDrainError::DiffIdMismatch`] is returned.
///
/// # Integrity model
///
/// The diff_id is the sha256 of the uncompressed tar bytes — the same byte
/// stream that `cat` on the splitstream produces.  As chunks are processed,
/// every logical byte is fed into a running SHA-256 hasher:
/// * **Inline** chunks: hash the raw bytes verbatim.
/// * **External** chunks: hash the full object file (all `length` bytes) via
///   positioned reads, then pass the same fd to [`process_file_content`].
///   Using positioned reads (`read_at`) means the fd cursor is not consumed,
///   so `process_file_content` can read the file independently.
///
/// # Note on partial objects
///
/// If verification fails, large external objects that were already written to
/// the `objects/` directory of the destination repo are left in place.  They
/// are orphaned (not referenced by any committed splitstream) and will be
/// reclaimed by the next GC run.  We do NOT attempt to clean them up here
/// because doing so correctly (without racing with concurrent imports) would
/// be complex and the GC already handles this case.
pub fn drain_splitdirfdstream_verified<ObjectID: FsVerityHashValue>(
    repo: Arc<Repository<ObjectID>>,
    pipe_read: OwnedFd,
    dir_fds: Vec<OwnedFd>,
    diff_id: &OciDigest,
    zerocopy: bool,
    mut ctx: ImportContext,
) -> Result<(ObjectID, ImportStats, ImportContext), VerifiedDrainError> {
    // We hash with SHA-256, which is the only algorithm OCI diff-ids use in
    // practice (and the only one the rest of this crate assumes). Reject other
    // algorithms up front with a clear error rather than producing a confusing
    // "mismatch" between a sha256 hash and e.g. a sha512 diff-id string.
    let algorithm = diff_id.algorithm().as_ref();
    if algorithm != "sha256" {
        return Err(VerifiedDrainError::Other(anyhow::anyhow!(
            "unsupported diff_id algorithm {algorithm:?}: only sha256 is supported"
        )));
    }

    // Wrap each fd as a cap_std Dir. Dummy fds at sparse gap slots are never
    // opened by the logic below; only the slot named by dirfd_index is accessed.
    let overlay_dirs: Vec<cap_std::fs::Dir> =
        dir_fds.into_iter().map(cap_std::fs::Dir::from).collect();

    let mut writer = repo
        .create_stream(TAR_LAYER_CONTENT_TYPE)
        .context("create_stream")?;
    let content_id = layer_identifier(diff_id);
    let mut reader = SplitdirfdstreamReader::new(std::fs::File::from(pipe_read));
    let mut inline_buf = Vec::new();
    let mut stats = ImportStats::default();
    let mut hasher = Sha256::new();

    drain_splitdirfdstream_inner(
        &repo,
        &mut writer,
        &mut reader,
        &overlay_dirs,
        zerocopy,
        &mut stats,
        &mut ctx,
        &mut inline_buf,
        Some(&mut hasher),
    )?;

    // Verify the accumulated hash against the declared diff_id.
    let actual_digest = sha256_output_to_digest(hasher.finalize());
    let actual_str = actual_digest.to_string();
    let expected_str = diff_id.to_string();
    if actual_str != expected_str {
        // Drop `writer` without calling write_stream: the stream is not
        // committed.  Large objects already written to objects/ are orphaned
        // but GC will reclaim them.
        return Err(VerifiedDrainError::DiffIdMismatch {
            expected: expected_str,
            actual: actual_str,
        });
    }

    let verity = repo
        .write_stream(writer, &content_id, None)
        .context("write_stream")?;
    Ok((verity, stats, ctx))
}

/// Decide whether a file of the given `size` should be stored inline in the
/// splitstream rather than as a separate object in the object store.
///
/// Files with `size <= INLINE_CONTENT_MAX_V0` are embedded directly in the
/// splitstream; larger files become external objects.
pub(crate) fn should_inline(size: u64) -> bool {
    (size as usize) <= INLINE_CONTENT_MAX_V0
}

/// Store the content of one file fd into the splitstream, choosing inline vs
/// external storage based on the file size.
///
/// For files at or below [`composefs::INLINE_CONTENT_MAX_V0`] bytes the
/// content is read into `inline_buf` and embedded directly in `writer`.
/// Larger files are stored as external objects in `repo` and referenced
/// by hash.
#[allow(clippy::too_many_arguments)]
pub fn process_file_content<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    writer: &mut SplitStreamWriter<ObjectID>,
    stats: &mut ImportStats,
    ctx: &mut ImportContext,
    fd: OwnedFd,
    size: u64,
    name: &str,
    zerocopy: bool,
    inline_buf: &mut Vec<u8>,
) -> Result<()> {
    // Convert fd to File for operations
    let file = std::fs::File::from(fd);

    if !should_inline(size) {
        // Large file: store as external object
        let (object_id, method) = if zerocopy {
            repo.ensure_object_from_file_zerocopy(&file, size, ctx)
        } else {
            repo.ensure_object_from_file(&file, size, ctx)
        }
        .with_context(|| format!("Failed to store object for {}", name))?;

        match method {
            ObjectStoreMethod::Reflinked => {
                stats.objects_reflinked += 1;
                stats.bytes_reflinked += size;
            }
            ObjectStoreMethod::Hardlinked => {
                stats.objects_hardlinked += 1;
                stats.bytes_hardlinked += size;
            }
            ObjectStoreMethod::Copied => {
                stats.objects_copied += 1;
                stats.bytes_copied += size;
            }
            ObjectStoreMethod::AlreadyPresent => {
                stats.objects_already_present += 1;
            }
        }

        writer.add_external_size(size);
        writer.write_reference(object_id)?;
    } else {
        // Small file: read and embed inline (reuse buffer across calls)
        inline_buf.resize(size as usize, 0);
        file.read_exact_at(inline_buf, 0)?;
        stats.bytes_inlined += size;
        writer.write_inline(inline_buf);
    }

    Ok(())
}

/// Return the on-disk size of the object identified by `id` in `repo`.
///
/// Opens the object file and `fstat`s it to obtain the size without reading
/// the full content.  This is used by [`produce_layer_splitdirfdstream`] to
/// populate the `length` field of external chunks in the output stream.
fn object_size<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    id: &ObjectID,
) -> Result<u64> {
    let fd = repo
        .open_object(id)
        .context("Opening object for size query")?;
    let stat = fstat(&fd).context("fstat on object fd")?;
    Ok(stat.st_size as u64)
}

/// Produce a `splitdirfdstream` for the layer splitstream identified by
/// `layer_verity`, writing it to `out`.
///
/// External objects are emitted as references of the form `"xx/yyyy"` beneath
/// the repository's `objects/` directory.  The consumer must supply the objects
/// directory at `dirfd_index` within the sparse dirfds region (obtained from
/// [`composefs_splitdirfdstream::build_layer_fd_layout`]'s `real_indices[0]`).
///
/// This is the read/serve side that mirrors [`drain_splitdirfdstream`]: given
/// the same repo, a stream produced here and then passed through
/// [`composefs_splitdirfdstream::reconstruct`] with the repo's objects dir will
/// yield byte-identical output to calling
/// [`composefs::splitstream::SplitStreamReader::cat`] on the same layer.
///
/// # Arguments
/// * `repo`              — Repository that holds the layer and its objects.
/// * `layer_verity`      — fs-verity hash of the layer splitstream to serve.
/// * `objects_dirfd_index` — Slot index within the sparse dirfds region where
///   the repository objects directory fd is placed (from `real_indices[0]`).
/// * `out`               — Destination writer for the produced `splitdirfdstream`.
pub fn produce_layer_splitdirfdstream<ObjectID: FsVerityHashValue, W: std::io::Write>(
    repo: &Repository<ObjectID>,
    layer_verity: &ObjectID,
    objects_dirfd_index: u32,
    out: W,
) -> Result<()> {
    // No `expected_content_type` filter here: layer streams may be tarballs
    // (`TAR_LAYER_CONTENT_TYPE`) or, for OCI artifacts, arbitrary blobs
    // (`OCI_BLOB_CONTENT_TYPE`/`BLOB_CONTENT_TYPE`). This function walks
    // chunks generically and does not care which; enforcing one type here
    // would silently produce an empty stream for the other (the caller only
    // logs a warning, since by the time `produce` runs the fds have already
    // been handed to the client).
    let mut reader = repo
        .open_stream("", Some(layer_verity), None)
        .context("Opening layer splitstream")?;
    let mut writer = SplitdirfdstreamWriter::new(out);

    reader
        .for_each_chunk(|chunk| {
            match chunk {
                SplitStreamData::Inline(data) => {
                    writer.write_metadata(&data).map_err(anyhow::Error::from)?;
                }
                SplitStreamData::External(id) => {
                    let size = object_size(repo, &id)?;
                    let pathname = id.to_object_pathname();
                    writer
                        .write_file_backed_data(objects_dirfd_index, size, pathname.as_bytes())
                        .map_err(anyhow::Error::from)?;
                }
            }
            Ok(())
        })
        .context("Walking layer splitstream chunks")?;

    writer.finish().map_err(anyhow::Error::from)?;
    Ok(())
}

/// A type alias for the (manifest, config) digest-and-verity pair returned by
/// [`finalize_oci_image`].
///
/// The first element is `(manifest_digest, manifest_verity)`;
/// the second is `(config_digest, config_verity)`.
pub type FinalizeResult<ObjectID> = (
    crate::ContentAndVerity<ObjectID>,
    crate::ContentAndVerity<ObjectID>,
);

/// Finalize an OCI image whose layers are already imported into `repo`.
///
/// Given the raw manifest and config JSON (exact bytes, so their sha256
/// digests are preserved) and the ordered (diff_id, layer_verity) pairs,
/// this writes the config and manifest splitstreams, generates the composefs
/// EROFS image, and optionally tags the manifest under `name`. Idempotent.
///
/// Returns `((manifest_digest, manifest_verity), (config_digest, config_verity))`.
pub fn finalize_oci_image<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    manifest_json: &[u8],
    config_json: &[u8],
    layer_refs: &[(OciDigest, ObjectID)],
    name: Option<&str>,
) -> anyhow::Result<FinalizeResult<ObjectID>> {
    use crate::oci_image::manifest_identifier;
    use crate::skopeo::{OCI_CONFIG_CONTENT_TYPE, OCI_MANIFEST_CONTENT_TYPE};
    use crate::{config_identifier, sha256_content_digest};

    let config_digest = sha256_content_digest(config_json);
    let content_id = config_identifier(&config_digest);

    let config_verity = if let Some(existing) = repo.has_stream(&content_id)? {
        existing
    } else {
        let mut writer = repo.create_stream(OCI_CONFIG_CONTENT_TYPE)?;

        for (diff_id, verity) in layer_refs {
            let key: &str = diff_id.as_ref();
            writer.add_named_stream_ref(key, verity);
        }

        writer.write_external(config_json)?;
        repo.write_stream(writer, &content_id, None)?
    };

    let manifest_digest = sha256_content_digest(manifest_json);

    let manifest_content_id = manifest_identifier(&manifest_digest);
    let manifest_verity = if let Some(existing) = repo.has_stream(&manifest_content_id)? {
        existing
    } else {
        let mut writer = repo.create_stream(OCI_MANIFEST_CONTENT_TYPE)?;

        let config_ref_key = format!("config:{config_digest}");
        writer.add_named_stream_ref(&config_ref_key, &config_verity);

        for (diff_id, verity) in layer_refs {
            let key: &str = diff_id.as_ref();
            writer.add_named_stream_ref(key, verity);
        }

        writer.write_external(manifest_json)?;
        repo.write_stream(writer, &manifest_content_id, None)?
    };

    // Generate the composefs EROFS image and tag the manifest.
    // Skip if the image already has an EROFS ref (idempotent re-finalize).
    let existing_erofs = crate::composefs_erofs_for_manifest(
        repo,
        &manifest_digest,
        Some(&manifest_verity),
        repo.erofs_version(),
    )?;
    if existing_erofs.is_none() {
        let erofs = crate::ensure_oci_composefs_erofs(
            repo,
            &manifest_digest,
            Some(&manifest_verity),
            name,
        )?;
        if erofs.is_none() {
            // Not a container image (e.g. an artifact) — tag directly.
            if let Some(n) = name {
                crate::oci_image::tag_image(repo, &manifest_digest, n)?;
            }
        }
    } else if let Some(n) = name {
        crate::oci_image::tag_image(repo, &manifest_digest, n)?;
    }

    // Re-read verities: ensure_oci_composefs_erofs rewrites config and
    // manifest splitstreams (adding the EROFS ref), so the verities captured
    // above may be stale.
    let config_verity = repo
        .has_stream(&content_id)?
        .context("config splitstream missing after finalization")?;
    let manifest_verity = repo
        .has_stream(&manifest_content_id)?
        .context("manifest splitstream missing after finalization")?;

    Ok((
        (manifest_digest, manifest_verity),
        (config_digest, config_verity),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write as _;

    use composefs::fsverity::Sha256HashValue;
    use composefs::repository::RepositoryConfig;
    use composefs_splitdirfdstream::reconstruct;

    /// The pure inline-vs-external predicate, tested exhaustively around the
    /// boundary.  This is the exact expression branched on inside
    /// [`process_file_content`], so locking it down here guards the decision
    /// independently of the (heavier) end-to-end test below.
    #[test]
    fn test_should_inline_boundary() {
        assert!(should_inline(0), "size 0 should be inlined");
        assert!(should_inline(1), "size 1 should be inlined");
        assert!(
            should_inline(INLINE_CONTENT_MAX_V0 as u64),
            "size == INLINE_CONTENT_MAX_V0 ({INLINE_CONTENT_MAX_V0}) should be inlined"
        );
        assert!(
            !should_inline(INLINE_CONTENT_MAX_V0 as u64 + 1),
            "size INLINE_CONTENT_MAX_V0+1 ({}) should NOT be inlined",
            INLINE_CONTENT_MAX_V0 + 1
        );
        for size in [128u64, 4096, 65536, 1024 * 1024] {
            assert!(
                !should_inline(size),
                "size {size} should NOT be inlined (well above threshold)"
            );
        }
    }

    /// Create an insecure (no fs-verity) repository in a fresh tempdir.
    ///
    /// Returns the repo alongside the `TempDir`, which the caller must keep
    /// alive for the duration of the test.
    fn create_test_repo() -> (Arc<Repository<Sha256HashValue>>, tempfile::TempDir) {
        let tempdir = tempfile::TempDir::new().unwrap();
        let (repo, _) = Repository::init_path(
            rustix::fs::CWD,
            &tempdir.path().join("repo"),
            RepositoryConfig::default().set_insecure(),
        )
        .unwrap();
        (Arc::new(repo), tempdir)
    }

    /// A file fd backed by `len` bytes of deterministic content.
    fn tmpfile_of(len: usize) -> OwnedFd {
        let mut f = tempfile::tempfile().unwrap();
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        f.write_all(&data).unwrap();
        f.into()
    }

    /// Data-driven end-to-end check of `process_file_content`'s storage
    /// decision: small files land inline (no object written, `bytes_inlined`
    /// grows), large files become external objects (`objects_*` grows,
    /// `bytes_inlined` unchanged).
    #[test]
    fn test_process_file_content_inline_vs_external() {
        let (repo, _tempdir) = create_test_repo();

        let cases = [
            (0usize, false),
            (1, false),
            (INLINE_CONTENT_MAX_V0, false),
            (INLINE_CONTENT_MAX_V0 + 1, true),
            (4096, true),
            (256 * 1024, true),
        ];

        for (size, expect_external) in cases {
            let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE).unwrap();
            let mut stats = ImportStats::default();
            let mut ctx = ImportContext::default();
            let mut inline_buf = Vec::new();

            let before_inlined = stats.bytes_inlined;
            process_file_content(
                &repo,
                &mut writer,
                &mut stats,
                &mut ctx,
                tmpfile_of(size),
                size as u64,
                "test-file",
                false,
                &mut inline_buf,
            )
            .unwrap();

            let objects_written = stats.objects_reflinked
                + stats.objects_hardlinked
                + stats.objects_copied
                + stats.objects_already_present;

            if expect_external {
                assert_eq!(
                    stats.bytes_inlined, before_inlined,
                    "size {size}: external file must not change bytes_inlined"
                );
                assert_eq!(
                    objects_written, 1,
                    "size {size}: exactly one external object expected"
                );
            } else {
                assert_eq!(
                    stats.bytes_inlined,
                    before_inlined + size as u64,
                    "size {size}: inline file must add its bytes to bytes_inlined"
                );
                assert_eq!(
                    objects_written, 0,
                    "size {size}: inline file must not write an object"
                );
            }
        }
    }

    /// Regression test: a memfd-backed fd must not error under the copy
    /// fallback path when the caller correctly identifies it as
    /// non-zerocopy-able (`zerocopy=false`), since memfds live on tmpfs
    /// where reflink/hardlink are structurally impossible.
    #[test]
    fn test_memfd_file_content_uses_copy_fallback() {
        let (repo, _tempdir) = create_test_repo();
        let size: usize = INLINE_CONTENT_MAX_V0 + 1; // just above inline threshold
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

        let memfd = file_content_to_memfd(&data).unwrap();

        let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE).unwrap();
        let mut stats = ImportStats::default();
        let mut ctx = ImportContext::default();
        let mut inline_buf = Vec::new();

        process_file_content(
            &repo,
            &mut writer,
            &mut stats,
            &mut ctx,
            memfd,
            size as u64,
            "memfd-test",
            false,
            &mut inline_buf,
        )
        .unwrap();

        assert_eq!(stats.objects_copied, 1, "memfd content should be copied");
        assert_eq!(stats.bytes_copied, size as u64);
    }

    // -------------------------------------------------------------------------
    // Helpers for the produce->reconstruct==cat round-trip tests
    // -------------------------------------------------------------------------

    /// Build a tar layer where each file has the specified size (bytes).
    ///
    /// File names are derived from the size so each case is identifiable
    /// in assertion output.  Content is deterministic: repeating bytes
    /// `i % 251`.
    fn build_tar_layer(file_sizes: &[usize]) -> Vec<u8> {
        let mut builder = ::tar::Builder::new(vec![]);
        for &size in file_sizes {
            let content: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut header = ::tar::Header::new_ustar();
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o644);
            header.set_entry_type(::tar::EntryType::Regular);
            header.set_size(size as u64);
            builder
                .append_data(
                    &mut header,
                    format!("file_{size}_{:08x}", size),
                    &content[..],
                )
                .unwrap();
        }
        builder.into_inner().unwrap()
    }

    /// Assert that produce -> reconstruct yields the same bytes as `cat`.
    ///
    /// This is the determinism contract: given a layer already imported into
    /// `repo` with verity hash `verity`, the two paths must be identical.
    async fn assert_produce_eq_cat(
        repo: &Arc<Repository<Sha256HashValue>>,
        verity: &Sha256HashValue,
    ) {
        use std::os::fd::AsFd as _;
        // --- expected: what cat() produces ---
        let mut expected = Vec::<u8>::new();
        let mut reader = repo
            .open_stream("", Some(verity), Some(TAR_LAYER_CONTENT_TYPE))
            .expect("open_stream for cat");
        reader
            .cat(repo, &mut expected)
            .expect("cat on layer splitstream");

        // --- actual: produce -> reconstruct ---
        // For the single-repo test path the objects dir is always at index 0
        // (one real dir, seed-determined slot may vary, but for this helper we
        // just use dirfd_index=0 directly to keep the test simple).
        let mut stream_buf = Vec::<u8>::new();
        produce_layer_splitdirfdstream(repo, verity, 0, &mut stream_buf)
            .expect("produce_layer_splitdirfdstream");

        let objects_dir_fd = repo.objects_dir().expect("objects_dir");
        let dirfds = [objects_dir_fd.as_fd()];
        let mut actual = Vec::<u8>::new();
        reconstruct(stream_buf.as_slice(), &dirfds, &mut actual)
            .expect("reconstruct splitdirfdstream");

        similar_asserts::assert_eq!(
            actual,
            expected,
            "produce->reconstruct must equal cat for verity={verity:?}"
        );
    }

    /// Data-driven round-trip test: produce -> reconstruct == cat for each
    /// layer shape.
    ///
    /// The test cases cover:
    /// - all-inline (only files <= INLINE_CONTENT_MAX_V0)
    /// - only-external (one file larger than INLINE_CONTENT_MAX_V0)
    /// - mixed (various sizes including crossing the threshold)
    #[tokio::test]
    async fn test_produce_reconstruct_eq_cat() {
        let (repo, _tempdir) = create_test_repo();

        // (label, file sizes in bytes)
        let cases: &[(&str, &[usize])] = &[
            // All inline: empty layer (no files)
            ("empty", &[]),
            // All inline: only small files (all <= INLINE_CONTENT_MAX_V0 = 64)
            ("all_inline", &[0, 1, 10, 64]),
            // Single external object (> 64 bytes)
            ("single_external", &[65]),
            // Larger external objects
            ("large_external", &[4096, 200_000]),
            // Mixed: small + large + various sizes
            ("mixed", &[0, 10, 64, 65, 4096, 200_000]),
        ];

        for (label, sizes) in cases {
            let tar_bytes = build_tar_layer(sizes);
            let diff_id = crate::sha256_content_digest(&tar_bytes);
            let (verity, _stats) = crate::import_layer(&repo, &diff_id, None, tar_bytes.as_slice())
                .await
                .unwrap_or_else(|e| panic!("import_layer failed for {label}: {e}"));

            // Run the determinism check for this layer shape.
            assert_produce_eq_cat(&repo, &verity).await;
        }
    }

    // -------------------------------------------------------------------------
    // Tests for drain_splitdirfdstream_verified
    // -------------------------------------------------------------------------

    /// Produce a splitdirfdstream from `repo_a` for `verity` into a pipe,
    /// returning the pipe read end, repo_a's objects dir fd, and a join handle
    /// for the producer task.
    ///
    /// The producer runs on a `spawn_blocking` task so the pipe can fill
    /// concurrently with the consumer. The caller MUST await the returned
    /// handle (after draining the pipe, to avoid a full-pipe deadlock) and
    /// assert the producer succeeded — the task is tracked, not detached, so
    /// producer errors are surfaced rather than swallowed.
    fn produce_to_pipe(
        repo_a: Arc<Repository<Sha256HashValue>>,
        verity: Sha256HashValue,
    ) -> (
        OwnedFd,
        Vec<OwnedFd>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        use std::os::fd::AsFd as _;

        let (pipe_read, pipe_write) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).expect("pipe");

        let objects_dir = repo_a.objects_dir().expect("objects_dir");
        let objects_owned = rustix::io::dup(objects_dir.as_fd()).expect("dup objects_dir");

        let handle = tokio::task::spawn_blocking(move || {
            let wf = std::fs::File::from(pipe_write);
            // dirfd_index=0 for single-repo tests (objects dir at slot 0).
            produce_layer_splitdirfdstream(&repo_a, &verity, 0, wf)
        });

        (pipe_read, vec![objects_owned], handle)
    }

    /// Await a producer handle from [`produce_to_pipe`] and assert success.
    async fn join_producer(handle: tokio::task::JoinHandle<anyhow::Result<()>>) {
        handle
            .await
            .expect("producer task panicked")
            .expect("producer must succeed");
    }

    /// Await a producer handle without asserting its outcome.
    ///
    /// Used when the consumer rejects the stream early (before reading it):
    /// the producer then sees a broken pipe and errors, which is expected. We
    /// still join it so no task is left untracked.
    async fn drain_producer(handle: tokio::task::JoinHandle<anyhow::Result<()>>) {
        let _ = handle.await.expect("producer task panicked");
    }

    /// Positive test: produce → verified drain with the CORRECT diff_id.
    ///
    /// repo_a imports a layer (with a large external object), then produces
    /// it as a splitdirfdstream into repo_b via `drain_splitdirfdstream_verified`.
    /// Asserts:
    /// - the call succeeds,
    /// - repo_b now has the layer stream committed.
    #[tokio::test]
    async fn test_verified_drain_correct_diff_id() {
        let (repo_a, _td_a) = create_test_repo();
        let (repo_b, _td_b) = create_test_repo();

        // Build a layer with both inline and external content.
        let tar_bytes = build_tar_layer(&[10, 128 * 1024]); // 10 B inline + 128 KiB external
        let diff_id = crate::sha256_content_digest(&tar_bytes);

        let (verity_a, _) = crate::import_layer(&repo_a, &diff_id, None, tar_bytes.as_slice())
            .await
            .expect("import_layer into repo_a");

        let (pipe_read, dir_fds, producer) = produce_to_pipe(repo_a, verity_a.clone());

        let repo_b_clone = repo_b.clone();
        let diff_id_clone = diff_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            drain_splitdirfdstream_verified(
                repo_b_clone,
                pipe_read,
                dir_fds,
                &diff_id_clone,
                false,
                composefs::repository::ImportContext::default(),
            )
        })
        .await
        .expect("spawn_blocking");

        let (verity_b, _stats, _ctx) = result.expect("verified drain must succeed");

        // Producer must have completed cleanly (drain succeeded, so it did).
        join_producer(producer).await;

        // The layer must now be committed in repo_b.
        let content_id = crate::layer_content_id(&diff_id);
        assert!(
            repo_b
                .has_stream(&content_id)
                .expect("has_stream")
                .is_some(),
            "repo_b must have the layer stream after verified drain"
        );

        // Both repos resolved to the same verity hash.
        assert_eq!(
            verity_a, verity_b,
            "verity hash must be identical across repos"
        );
    }

    /// Negative test: produce → verified drain with a WRONG diff_id.
    ///
    /// The drain must return `DiffIdMismatch` and repo_b must NOT have the
    /// stream committed.
    #[tokio::test]
    async fn test_verified_drain_wrong_diff_id() {
        let (repo_a, _td_a) = create_test_repo();
        let (repo_b, _td_b) = create_test_repo();

        let tar_bytes = build_tar_layer(&[10, 128 * 1024]);
        let correct_diff_id = crate::sha256_content_digest(&tar_bytes);

        let (verity_a, _) =
            crate::import_layer(&repo_a, &correct_diff_id, None, tar_bytes.as_slice())
                .await
                .expect("import_layer into repo_a");

        // Construct a diff_id that is a valid sha256 digest but definitely wrong.
        let wrong_diff_id: crate::OciDigest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap();

        let (pipe_read, dir_fds, producer) = produce_to_pipe(repo_a, verity_a);

        let repo_b_clone = repo_b.clone();
        let wrong_diff_id_clone = wrong_diff_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            drain_splitdirfdstream_verified(
                repo_b_clone,
                pipe_read,
                dir_fds,
                &wrong_diff_id_clone,
                false,
                composefs::repository::ImportContext::default(),
            )
        })
        .await
        .expect("spawn_blocking");

        // The drain hashes the whole stream before rejecting, so it consumes
        // the entire pipe and the producer completes cleanly.
        join_producer(producer).await;

        // Must fail with DiffIdMismatch.
        match result {
            Err(VerifiedDrainError::DiffIdMismatch { expected, actual }) => {
                assert_eq!(
                    expected,
                    wrong_diff_id.to_string(),
                    "expected field must be the wrong diff_id"
                );
                assert_eq!(
                    actual,
                    correct_diff_id.to_string(),
                    "actual field must be the real content hash"
                );
            }
            other => panic!("expected DiffIdMismatch, got {other:?}"),
        }

        // The stream must NOT be committed in repo_b.
        let wrong_content_id = crate::layer_content_id(&wrong_diff_id);
        assert!(
            repo_b
                .has_stream(&wrong_content_id)
                .expect("has_stream")
                .is_none(),
            "repo_b must NOT have a committed stream for the wrong diff_id"
        );
    }

    /// A non-sha256 diff_id must be rejected up front with a clear error
    /// rather than producing a confusing hash "mismatch".
    #[tokio::test]
    async fn test_verified_drain_rejects_non_sha256() {
        let (repo_a, _td_a) = create_test_repo();
        let (repo_b, _td_b) = create_test_repo();

        let tar_bytes = build_tar_layer(&[10, 128 * 1024]);
        let diff_id = crate::sha256_content_digest(&tar_bytes);
        let (verity_a, _) = crate::import_layer(&repo_a, &diff_id, None, tar_bytes.as_slice())
            .await
            .expect("import_layer into repo_a");

        // A valid sha512 digest (64 bytes hex) — well-formed but unsupported.
        let sha512_diff_id: crate::OciDigest = format!("sha512:{}", "0".repeat(128))
            .parse()
            .expect("valid sha512 digest");

        let (pipe_read, dir_fds, producer) = produce_to_pipe(repo_a, verity_a);

        let repo_b_clone = repo_b.clone();
        let result = tokio::task::spawn_blocking(move || {
            drain_splitdirfdstream_verified(
                repo_b_clone,
                pipe_read,
                dir_fds,
                &sha512_diff_id,
                false,
                composefs::repository::ImportContext::default(),
            )
        })
        .await
        .expect("spawn_blocking");

        // The drain rejects before reading the pipe, so the producer may error
        // with a broken pipe; join it regardless so it isn't left untracked.
        drain_producer(producer).await;

        match result {
            Err(VerifiedDrainError::Other(e)) => {
                let msg = format!("{e:#}");
                assert!(
                    msg.contains("sha256") && msg.contains("sha512"),
                    "error should explain the algorithm restriction, got: {msg}"
                );
            }
            other => panic!("expected Other(unsupported algorithm) error, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Tests for finalize_oci_image
    // -------------------------------------------------------------------------

    /// End-to-end test for `finalize_oci_image`:
    ///
    /// 1. Import 2 synthetic tar layers with valid OCI structure.
    /// 2. Build matching config + manifest JSON.
    /// 3. Call `finalize_oci_image`.
    /// 4. Assert config/manifest splitstreams exist and EROFS was produced.
    #[tokio::test]
    async fn test_finalize_oci_image() {
        let (repo, _tempdir) = create_test_repo();

        // Import two layers: one all-inline (10 B), one external (128 KiB).
        let tar1 = crate::test_util::build_oci_tar_layer(10);
        let tar2 = crate::test_util::build_oci_tar_layer(128 * 1024);

        let diff_id1 = crate::sha256_content_digest(&tar1);
        let diff_id2 = crate::sha256_content_digest(&tar2);

        let (verity1, _) = crate::import_layer(&repo, &diff_id1, None, tar1.as_slice())
            .await
            .expect("import layer 1");
        let (verity2, _) = crate::import_layer(&repo, &diff_id2, None, tar2.as_slice())
            .await
            .expect("import layer 2");

        let diff_ids = vec![diff_id1.to_string(), diff_id2.to_string()];
        let config_json = crate::test_util::make_config_json(&diff_ids);
        let config_digest = crate::sha256_content_digest(&config_json);
        let manifest_json =
            crate::test_util::make_manifest_json(&config_json, config_digest.as_ref(), &diff_ids);

        let layer_refs = vec![(diff_id1.clone(), verity1), (diff_id2.clone(), verity2)];

        let ((manifest_digest, manifest_verity), (out_config_digest, config_verity)) =
            finalize_oci_image(
                &repo,
                &manifest_json,
                &config_json,
                &layer_refs,
                Some("test:v1"),
            )
            .expect("finalize_oci_image");

        // Digests must be non-empty.
        assert!(!manifest_digest.to_string().is_empty());
        assert!(!out_config_digest.to_string().is_empty());

        // Splitstreams must exist.
        use crate::oci_image::manifest_identifier;
        let manifest_id = manifest_identifier(&manifest_digest);
        let config_id = crate::config_identifier(&out_config_digest);

        assert!(
            repo.has_stream(&manifest_id)
                .expect("has_stream manifest")
                .is_some(),
            "manifest splitstream must exist"
        );
        assert!(
            repo.has_stream(&config_id)
                .expect("has_stream config")
                .is_some(),
            "config splitstream must exist"
        );

        // Verify the returned verities match what's stored.
        let stored_manifest_verity = repo
            .has_stream(&manifest_id)
            .unwrap()
            .expect("manifest verity must be stored");
        assert_eq!(
            manifest_verity, stored_manifest_verity,
            "returned manifest_verity must match stored"
        );
        let stored_config_verity = repo
            .has_stream(&config_id)
            .unwrap()
            .expect("config verity must be stored");
        assert_eq!(
            config_verity, stored_config_verity,
            "returned config_verity must match stored"
        );

        // EROFS must have been generated for this container image.
        let erofs = crate::composefs_erofs_for_manifest(
            &repo,
            &manifest_digest,
            Some(&manifest_verity),
            repo.erofs_version(),
        )
        .expect("composefs_erofs_for_manifest");
        assert!(
            erofs.is_some(),
            "EROFS image must exist after finalize_oci_image for a container image"
        );

        // Idempotency: calling again must succeed and return the same digests.
        let ((md2, _mv2), (cd2, _cv2)) = finalize_oci_image(
            &repo,
            &manifest_json,
            &config_json,
            &layer_refs,
            Some("test:v1"),
        )
        .expect("finalize_oci_image idempotent");
        assert_eq!(manifest_digest, md2, "idempotent call: manifest_digest");
        assert_eq!(out_config_digest, cd2, "idempotent call: config_digest");
    }
}
