//! Integration tests for the `oci copy` CLI command.
//!
//! Test A (`test_copy_image_correctness`) runs unprivileged on any filesystem;
//! it verifies that all data is faithfully reproduced in the destination
//! repository.
//!
//! Test B (`privileged_copy_image_reflink`) runs on a loop-mounted XFS
//! filesystem and asserts that `objects_reflinked > 0`, proving that the
//! zero-copy path actually triggers between two composefs repositories on
//! the same XFS volume.
//!
//! Test C (`test_copy_image_via_varlink`) replicates `cfsctl oci copy` entirely
//! over the varlink wire interface, across two real `cfsctl varlink` subprocess
//! servers. This proves that SCM_RIGHTS fd passing works cross-process, which
//! the existing in-process varlink tests cannot exercise.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use xshell::{Shell, cmd};

use composefs_oci::OciDigest;
use composefs_oci::composefs::fsverity::{Sha256HashValue, Sha512HashValue};
use composefs_oci::composefs::repository::{Repository, RepositoryConfig};
use composefs_oci::layer_sync::finalize_oci_image;
use composefs_oci::test_util::{build_oci_tar_layer, make_config_json, make_manifest_json};
use composefs_oci::{import_layer, layer_content_id, sha256_content_digest};

use composefs_ctl::varlink::RepositoryError;
use composefs_ctl::varlink::layer_sync::LayerRef;
use composefs_ctl::varlink::oci::OciError;
use composefs_ctl::varlink::proxy::{GetLayerParams, OciProxy, RepositoryProxy};

use crate::{cfsctl, integration_test};

// ── Shared helpers ─────────────────────────────────────────────────────────

/// Initialise an insecure SHA-256 repository at `path`.
fn init_sha256_repo(path: &std::path::Path) -> Result<Arc<Repository<Sha256HashValue>>> {
    std::fs::create_dir_all(path)?;
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::RDONLY,
        0.into(),
    )?;
    let (repo, _) = Repository::<Sha256HashValue>::init_path(
        &fd,
        ".",
        RepositoryConfig::default().set_insecure(),
    )?;
    Ok(Arc::new(repo))
}

/// Build a two-layer synthetic image in `repo` and tag it `name`.
///
/// Layer 1: 10 bytes — small enough to be fully inlined.
/// Layer 2: 256 KiB — large enough to produce an external object that
///          exercises the reflink / hardlink path.
///
/// Returns `(manifest_json_bytes, config_json_bytes, diff_id_layer2_string)`.
fn build_and_import_test_image(
    repo: &Arc<Repository<Sha256HashValue>>,
    name: &str,
) -> Result<(Vec<u8>, Vec<u8>, String)> {
    let rt = tokio::runtime::Runtime::new()?;

    let tar1 = build_oci_tar_layer(10);
    let tar2 = build_oci_tar_layer(256 * 1024);

    let diff_id1 = sha256_content_digest(&tar1);
    let diff_id2 = sha256_content_digest(&tar2);
    let diff_id2_str = diff_id2.to_string();

    let (verity1, verity2) = rt.block_on(async {
        let (v1, _) = import_layer(repo, &diff_id1, None, tar1.as_slice())
            .await
            .context("import layer 1")?;
        let (v2, _) = import_layer(repo, &diff_id2, None, tar2.as_slice())
            .await
            .context("import layer 2")?;
        Ok::<_, anyhow::Error>((v1, v2))
    })?;

    let diff_ids = vec![diff_id1.to_string(), diff_id2_str.clone()];
    let config_json = make_config_json(&diff_ids);
    let config_digest = sha256_content_digest(&config_json);
    let manifest_json = make_manifest_json(&config_json, config_digest.as_ref(), &diff_ids);

    let layer_refs = vec![(diff_id1, verity1), (diff_id2, verity2)];
    finalize_oci_image(repo, &manifest_json, &config_json, &layer_refs, Some(name))
        .context("finalize_oci_image")?;

    Ok((manifest_json, config_json, diff_id2_str))
}

// ── Test A: correctness (unprivileged) ─────────────────────────────────────

fn test_copy_image_correctness() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;

    // Both repos under the same parent tempdir (same filesystem).
    let parent = tempfile::tempdir()?;
    let repo_a_path = parent.path().join("repo-a");
    let repo_b_path = parent.path().join("repo-b");

    // Initialise repo A and synthesise a two-layer image.
    let repo_a = init_sha256_repo(&repo_a_path)?;
    let (manifest_json_a, config_json_a, diff_id2_str) =
        build_and_import_test_image(&repo_a, "copyme:v1")?;

    // Compute digests for repo A for later comparison.
    let manifest_digest_a = sha256_content_digest(&manifest_json_a);
    let config_digest_a = sha256_content_digest(&config_json_a);

    // Initialise repo B (empty).
    let _repo_b_init = init_sha256_repo(&repo_b_path)?;
    drop(_repo_b_init); // close — cfsctl will open it

    // Run `cfsctl oci copy` as a subprocess. This is a sanity check of the
    // CLI: it must succeed and land the image in the destination. Structured
    // transfer stats are intentionally not exposed by the CLI (use varlink for
    // that); we verify the outcome by inspecting the destination repo below.
    let repo_a_str = repo_a_path.to_str().unwrap();
    let repo_b_str = repo_b_path.to_str().unwrap();
    let tag = "copyme:v1";
    cmd!(
        sh,
        "{cfsctl} --repo {repo_a_str} --insecure oci copy {tag} --to {repo_b_str} --name {tag}"
    )
    .run()
    .context("cfsctl oci copy failed")?;

    // ── Assert: manifest and config digests are identical in repo B ───────
    // Open repo B in-process and compare.
    let repo_b = Repository::<Sha256HashValue>::open_path(rustix::fs::CWD, &repo_b_path)?;
    let img_b = composefs_oci::oci_image::OciImage::open_ref(&repo_b, "copyme:v1")
        .context("opening copyme:v1 in repo B")?;

    ensure!(
        img_b.manifest_digest() == &manifest_digest_a,
        "manifest digest mismatch: src={manifest_digest_a}, dest={}",
        img_b.manifest_digest()
    );
    ensure!(
        img_b.config_digest() == &config_digest_a,
        "config digest mismatch: src={config_digest_a}, dest={}",
        img_b.config_digest()
    );

    // ── Assert: the 256 KiB external object exists in B and is byte-identical ──
    // Find the object path using the diff_id of layer 2.
    let diff_id2: composefs_oci::OciDigest = diff_id2_str
        .parse()
        .context("parsing diff_id2 as OciDigest")?;
    let content_id = composefs_oci::layer_content_id(&diff_id2);

    let verity_a = repo_a
        .has_stream(&content_id)?
        .context("repo_a missing layer 2 stream")?;
    let verity_b = repo_b
        .has_stream(&content_id)?
        .context("repo_b missing layer 2 stream after copy")?;

    // Both repos should have resolved to the same verity hash (same content).
    ensure!(
        verity_a == verity_b,
        "verity hashes differ: src={verity_a:?}, dest={verity_b:?}"
    );

    // Read the external object from both repos and compare bytes.
    let obj_bytes_a = repo_a
        .read_object(&verity_a)
        .context("read_object from repo_a")?;
    let obj_bytes_b = repo_b
        .read_object(&verity_b)
        .context("read_object from repo_b")?;
    ensure!(
        obj_bytes_a == obj_bytes_b,
        "external object content differs between repos"
    );

    Ok(())
}
integration_test!(test_copy_image_correctness);

// ── Test B: deterministic reflink on XFS (privileged) ──────────────────────

fn privileged_copy_image_reflink() -> Result<()> {
    use crate::tests::privileged::{LoopTempDir, require_privileged};

    if require_privileged("privileged_copy_image_reflink")?.is_some() {
        return Ok(());
    }

    // Skip if mkfs.xfs is not available.
    if !std::path::Path::new("/usr/sbin/mkfs.xfs").exists()
        && !std::path::Path::new("/sbin/mkfs.xfs").exists()
    {
        println!("SKIP: mkfs.xfs not available");
        return Ok(());
    }

    // Both repos on the same XFS reflink-capable loop mount.
    let fs = LoopTempDir::xfs_reflink()?;
    let repo_a_path = fs.path().join("repo-a");
    let repo_b_path = fs.path().join("repo-b");

    let repo_a = init_sha256_repo(&repo_a_path)?;
    build_and_import_test_image(&repo_a, "copyme:v1")?;

    let repo_b = init_sha256_repo(&repo_b_path)?;

    // The reflink count is a structured detail the CLI deliberately does not
    // expose, so drive the copy through the in-process library API (which
    // returns ImportStats) rather than the `oci copy` subprocess. This keeps
    // the deterministic reflink assertion while leaving structured output to
    // the varlink interface.
    let image: composefs_ctl::OciReference = "copyme:v1".parse()?;
    let rt = tokio::runtime::Runtime::new()?;
    let stats = rt.block_on(composefs_ctl::copy_image(
        &repo_a,
        &repo_b,
        &image,
        Some("copyme:v1"),
        true, // zerocopy: attempt reflink
    ))?;

    // On XFS with reflinks enabled, at least one object must be reflinked.
    ensure!(
        stats.objects_reflinked > 0,
        "expected objects_reflinked > 0 on XFS, got: {stats}"
    );

    // Also verify correctness: manifest + config digests match.
    let img_a = composefs_oci::oci_image::OciImage::open_ref(&repo_a, "copyme:v1")
        .context("open copyme:v1 in repo_a")?;
    let img_b = composefs_oci::oci_image::OciImage::open_ref(&repo_b, "copyme:v1")
        .context("open copyme:v1 in repo_b")?;

    ensure!(
        img_a.manifest_digest() == img_b.manifest_digest(),
        "manifest digest mismatch after reflink copy"
    );
    ensure!(
        img_a.config_digest() == img_b.config_digest(),
        "config digest mismatch after reflink copy"
    );

    Ok(())
}
integration_test!(privileged_copy_image_reflink);

// ── Test C: varlink cross-process fd-passing copy ───────────────────────────

/// A running `cfsctl varlink` subprocess bound to a Unix socket.
///
/// Kills the child process on drop so a test panic does not leak it.
struct VarlinkProc {
    child: std::process::Child,
    socket: std::path::PathBuf,
    /// Keep the tempdir holding the socket alive for the process's lifetime.
    _socket_dir: tempfile::TempDir,
}

impl Drop for VarlinkProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl VarlinkProc {
    /// Spawn `cfsctl` via systemd socket-activation with a pre-bound listening
    /// socket. The socket is already listening before the child starts, so
    /// callers may connect immediately — no polling needed.
    fn spawn() -> Result<Self> {
        let (child, socket_dir, socket) = crate::spawn_activated_cfsctl()?;
        Ok(VarlinkProc {
            child,
            socket,
            _socket_dir: socket_dir,
        })
    }

    fn socket(&self) -> &Path {
        &self.socket
    }
}

/// Open a repository on a varlink server and return its handle, via the typed
/// zlink proxy. Connects a fresh client for this single call.
/// Open `repo_path` over an existing connection and return the handle.
///
/// The handle is reused for all subsequent calls on the same connection.
async fn open_repo(conn: &mut zlink::unix::Connection, repo_path: &Path) -> Result<u64> {
    let path_str = repo_path.to_str().context("repo path is not valid UTF-8")?;
    let reply = conn
        .open_repository(Some(path_str), None, None)
        .await
        .context("zlink transport error calling OpenRepository")?;
    match reply {
        Ok(r) => Ok(r.handle),
        Err(RepositoryError::InvalidSpec { message }) => {
            bail!("OpenRepository: InvalidSpec: {message}")
        }
        Err(e) => bail!("OpenRepository failed: {e:?}"),
    }
}

/// Replicate `cfsctl oci copy` entirely over two varlink subprocess servers,
/// exercising cross-process SCM_RIGHTS fd passing.
///
/// Two separate `cfsctl varlink` processes are spawned (one per repository).
/// The test drives the copy protocol through the typed zlink proxy:
/// `Inspect` → `HasLayer` / `GetLayer` / `PutLayer` per diff_id →
/// `FinalizeImage`. The pipe and objects-dir file descriptors returned by
/// `GetLayer` on server A are passed directly (via the kernel's SCM_RIGHTS
/// mechanism) into `PutLayer` on server B, which is the cross-process path
/// that the existing in-process tests cannot cover.
fn test_copy_image_via_varlink() -> Result<()> {
    // ── Set up two repos ──────────────────────────────────────────────────
    let parent = tempfile::tempdir()?;
    let repo_a_path = parent.path().join("repo-a");
    let repo_b_path = parent.path().join("repo-b");

    let repo_a = init_sha256_repo(&repo_a_path)?;
    let (manifest_json_a, config_json_a, _diff_id2_str) =
        build_and_import_test_image(&repo_a, "copyme:v1")?;

    // Pre-compute expected digests from source.
    let manifest_digest_a = sha256_content_digest(&manifest_json_a);
    let config_digest_a = sha256_content_digest(&config_json_a);

    // Init repo B (empty) then drop the in-process handle so the subprocess
    // can open it exclusively.
    {
        let _repo_b_init = init_sha256_repo(&repo_b_path)?;
    }
    // Drop repo_a Arc so the subprocess can open it too (shared lock is fine
    // but let's be tidy; the subprocess opens it read-write, Arc hold is
    // read-write as well — both succeed).
    drop(repo_a);

    // ── Spawn two varlink server subprocesses ─────────────────────────────
    let svc_a = VarlinkProc::spawn().context("spawning varlink server A")?;
    let svc_b = VarlinkProc::spawn().context("spawning varlink server B")?;

    // ── Drive the copy over the wire ──────────────────────────────────────
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    // Parse the ordered diff_ids from the config JSON we built (the same JSON
    // that `Inspect` will return). We use serde_json to extract
    // `rootfs.diff_ids` — no need to import containers_image_proxy here.
    let diff_ids_ordered: Vec<String> = {
        let config_val: serde_json::Value =
            serde_json::from_slice(&config_json_a).context("parsing config_json as JSON")?;
        config_val["rootfs"]["diff_ids"]
            .as_array()
            .context("config rootfs.diff_ids is not an array")?
            .iter()
            .map(|v| {
                v.as_str()
                    .context("diff_id is not a string")
                    .map(str::to_owned)
            })
            .collect::<Result<Vec<_>>>()?
    };

    let finalize_reply = rt.block_on(async {
        // One connection per server, held for the whole session — exactly as a
        // real client (and the in-process `copy_image`) would. Each repo handle
        // is opened on its own connection and reused for every subsequent call.
        let mut conn_a = zlink::unix::connect(svc_a.socket())
            .await
            .context("connecting to server A")?;
        let mut conn_b = zlink::unix::connect(svc_b.socket())
            .await
            .context("connecting to server B")?;

        let handle_a = open_repo(&mut conn_a, &repo_a_path).await?;
        let handle_b = open_repo(&mut conn_b, &repo_b_path).await?;

        // Inspect the source image to get manifest + config JSON strings.
        let inspect = conn_a
            .inspect(handle_a, "copyme:v1")
            .await
            .context("zlink transport error calling Inspect")?
            .map_err(|e: OciError| anyhow::anyhow!("Inspect failed: {e:?}"))?;

        ensure!(
            !inspect.manifest.is_empty(),
            "inspect returned empty manifest"
        );
        ensure!(!inspect.config.is_empty(), "inspect returned empty config");

        // Copy each layer from A to B over the two persistent connections.
        let mut layer_refs: Vec<LayerRef> = Vec::with_capacity(diff_ids_ordered.len());

        for diff_id in &diff_ids_ordered {
            let has = conn_b
                .has_layer(handle_b, diff_id)
                .await
                .context("zlink transport error calling HasLayer")?
                .map_err(|e: OciError| anyhow::anyhow!("HasLayer failed: {e:?}"))?;

            let layer_verity = if has.present {
                has.layer_verity
                    .context("HasLayer returned present=true but no layer_verity")?
            } else {
                // GetLayer on A is now a streaming method: collect all frames,
                // concatenate fds, then split into [pipe+dirfds] and [lifetime_fds].
                // The kernel SCM_RIGHTS mechanism dups them cross-process — this is
                // the cross-process path the in-process tests cannot cover.
                use zlink::futures_util::StreamExt as _;
                let get_params = GetLayerParams {
                    diff_id: Some(diff_id.to_string()),
                    storage: None,
                };
                let mut get_stream = std::pin::pin!(
                    conn_a
                        .get_layer(handle_a, get_params)
                        .await
                        .context("zlink transport error calling GetLayer")?
                );
                let mut all_fds: Vec<std::os::fd::OwnedFd> = Vec::new();
                let mut get_reply = None;
                while let Some(item) = get_stream.next().await {
                    let (result, fds) = item.context("GetLayer stream frame error")?;
                    let reply =
                        result.map_err(|e: OciError| anyhow::anyhow!("GetLayer failed: {e:?}"))?;
                    get_reply = Some(reply);
                    all_fds.extend(fds);
                }
                let get_reply = get_reply.context("GetLayer returned empty stream")?;
                let dir_count = get_reply.dir_count as usize;

                // Split: pipe+dirfds for PutLayer; lifetime_fds held until after PutLayer.
                let pipe_and_dirfds_len = 1 + dir_count;
                let lifetime_fds = all_fds.split_off(pipe_and_dirfds_len);

                let put_reply = conn_b
                    .put_layer(handle_b, diff_id, false, all_fds)
                    .await
                    .context("zlink transport error calling PutLayer")?
                    .map_err(|e: OciError| anyhow::anyhow!("PutLayer failed: {e:?}"))?;
                // Drop lifetime fds after PutLayer completes.
                drop(lifetime_fds);

                put_reply.layer_verity
            };

            layer_refs.push(LayerRef {
                diff_id: diff_id.clone(),
                layer_verity,
            });
        }

        // Finalize the image in repo B over the same connection.
        let manifest_str = String::from_utf8(manifest_json_a.clone())
            .context("manifest_json is not valid UTF-8")?;
        let config_str =
            String::from_utf8(config_json_a.clone()).context("config_json is not valid UTF-8")?;

        let finalize = conn_b
            .finalize_image(
                handle_b,
                &manifest_str,
                &config_str,
                layer_refs,
                Some("copyme:v1"),
            )
            .await
            .context("zlink transport error calling FinalizeImage")?
            .map_err(|e: OciError| anyhow::anyhow!("FinalizeImage failed: {e:?}"))?;

        // Fsck the destination over the wire: the freshly-copied image must be
        // structurally sound (every referenced stream and object present).
        let fsck = conn_b
            .fsck(handle_b, None)
            .await
            .context("zlink transport error calling Fsck")?
            .map_err(|e: RepositoryError| anyhow::anyhow!("Fsck failed: {e:?}"))?;
        ensure!(
            fsck.ok,
            "fsck of destination repo reported problems after copy: {fsck:?}"
        );

        // The copied image must be discoverable by its tag in the destination.
        let listed = conn_b
            .list_images(handle_b, None)
            .await
            .context("zlink transport error calling ListImages")?
            .map_err(|e: OciError| anyhow::anyhow!("ListImages failed: {e:?}"))?;
        ensure!(
            listed.images.iter().any(|img| img.name == "copyme:v1"),
            "copied image 'copyme:v1' not found in destination ListImages: {:?}",
            listed.images.iter().map(|i| &i.name).collect::<Vec<_>>()
        );

        Ok::<_, anyhow::Error>(finalize)
    })?;

    // ── Assertions ────────────────────────────────────────────────────────

    // FinalizeImage must return non-empty digest/verity strings.
    ensure!(
        !finalize_reply.manifest_digest.is_empty(),
        "FinalizeImage returned empty manifest_digest"
    );
    ensure!(
        !finalize_reply.config_digest.is_empty(),
        "FinalizeImage returned empty config_digest"
    );
    ensure!(
        !finalize_reply.manifest_verity.is_empty(),
        "FinalizeImage returned empty manifest_verity"
    );

    // The digests must match those we computed from the source.
    let expected_manifest_digest = manifest_digest_a.to_string();
    let expected_config_digest = config_digest_a.to_string();
    ensure!(
        finalize_reply.manifest_digest == expected_manifest_digest,
        "manifest_digest mismatch: wire={}, expected={expected_manifest_digest}",
        finalize_reply.manifest_digest
    );
    ensure!(
        finalize_reply.config_digest == expected_config_digest,
        "config_digest mismatch: wire={}, expected={expected_config_digest}",
        finalize_reply.config_digest
    );

    // Open repo B in-process and verify the image landed correctly.
    let repo_b = Repository::<Sha256HashValue>::open_path(rustix::fs::CWD, &repo_b_path)
        .context("opening repo B in-process after copy")?;
    let img_b = composefs_oci::oci_image::OciImage::open_ref(&repo_b, "copyme:v1")
        .context("opening copyme:v1 in repo B")?;

    ensure!(
        img_b.manifest_digest() == &manifest_digest_a,
        "in-process manifest digest mismatch: src={manifest_digest_a}, dest={}",
        img_b.manifest_digest()
    );
    ensure!(
        img_b.config_digest() == &config_digest_a,
        "in-process config digest mismatch: src={config_digest_a}, dest={}",
        img_b.config_digest()
    );

    // Verify the external (256 KiB) object in repo B matches repo A.
    let diff_id2: OciDigest = _diff_id2_str
        .parse()
        .context("parsing diff_id2 as OciDigest")?;
    let content_id = layer_content_id(&diff_id2);

    let repo_a_check = Repository::<Sha256HashValue>::open_path(rustix::fs::CWD, &repo_a_path)
        .context("re-opening repo A in-process")?;

    let verity_a = repo_a_check
        .has_stream(&content_id)?
        .context("repo A missing layer-2 stream")?;
    let verity_b = repo_b
        .has_stream(&content_id)?
        .context("repo B missing layer-2 stream after varlink copy")?;

    ensure!(
        verity_a == verity_b,
        "layer-2 verity mismatch after varlink copy: src={verity_a:?}, dest={verity_b:?}"
    );

    let obj_bytes_a = repo_a_check
        .read_object(&verity_a)
        .context("read_object from repo A")?;
    let obj_bytes_b = repo_b
        .read_object(&verity_b)
        .context("read_object from repo B")?;
    ensure!(
        obj_bytes_a == obj_bytes_b,
        "external object content differs after varlink copy"
    );

    // Subprocesses are killed by the VarlinkProc Drop impls.
    Ok(())
}
integration_test!(test_copy_image_via_varlink);

// ── Test D: cross-algorithm copy via varlink (sha256 → sha512) ────────────

/// Initialise an insecure SHA-512 repository at `path`.
fn init_sha512_repo(path: &std::path::Path) -> Result<()> {
    use composefs_oci::composefs::fsverity::Algorithm;
    std::fs::create_dir_all(path)?;
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::RDONLY,
        0.into(),
    )?;
    let config = RepositoryConfig::new(Algorithm::SHA512).set_insecure();
    Repository::<Sha512HashValue>::init_path(&fd, ".", config)?;
    Ok(())
}

/// Copy an image from a sha256 repository to a sha512 repository over varlink.
///
/// This proves that cross-algorithm copy works end-to-end: the
/// splitdirfdstream carries only algorithm-independent data (inline bytes +
/// transient source-object locators) and the destination re-computes every
/// object's fs-verity digest under its own (sha512) algorithm on import.
///
/// The test also validates the new `OpenRepositoryReply` metadata fields
/// (`hash_algorithm`, `objects_device_id`) introduced for explicit zerocopy
/// negotiation between client and servers.
fn test_copy_image_cross_algorithm() -> Result<()> {
    // ── Set up repos ──────────────────────────────────────────────────────
    let parent = tempfile::tempdir()?;
    let repo_a_path = parent.path().join("repo-sha256");
    let repo_b_path = parent.path().join("repo-sha512");

    // Source: sha256 with an image.
    let repo_a = init_sha256_repo(&repo_a_path)?;
    let (manifest_json_a, config_json_a, _) = build_and_import_test_image(&repo_a, "copyme:v1")?;
    let manifest_digest_a = sha256_content_digest(&manifest_json_a);
    let config_digest_a = sha256_content_digest(&config_json_a);
    drop(repo_a);

    // Destination: sha512, empty.
    init_sha512_repo(&repo_b_path)?;

    // ── Spawn two varlink servers ─────────────────────────────────────────
    let svc_a = VarlinkProc::spawn().context("spawning server A (sha256)")?;
    let svc_b = VarlinkProc::spawn().context("spawning server B (sha512)")?;

    // ── Drive the cross-algorithm copy ────────────────────────────────────
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let diff_ids_ordered: Vec<String> = {
        let v: serde_json::Value = serde_json::from_slice(&config_json_a)?;
        v["rootfs"]["diff_ids"]
            .as_array()
            .context("config rootfs.diff_ids is not an array")?
            .iter()
            .map(|v| {
                v.as_str()
                    .context("diff_id not a string")
                    .map(str::to_owned)
            })
            .collect::<Result<Vec<_>>>()?
    };

    let finalize_reply = rt.block_on(async {
        let mut conn_a = zlink::unix::connect(svc_a.socket()).await?;
        let mut conn_b = zlink::unix::connect(svc_b.socket()).await?;

        // Open both repos and check the metadata.
        let reply_a = conn_a
            .open_repository(Some(repo_a_path.to_str().unwrap()), None, None)
            .await
            .context("transport error opening repo A")?
            .map_err(|e| anyhow::anyhow!("OpenRepository A failed: {e:?}"))?;
        let reply_b = conn_b
            .open_repository(Some(repo_b_path.to_str().unwrap()), None, None)
            .await
            .context("transport error opening repo B")?
            .map_err(|e| anyhow::anyhow!("OpenRepository B failed: {e:?}"))?;

        // Validate the new hash_algorithm fields.
        ensure!(
            reply_a.hash_algorithm.as_deref() == Some("sha256"),
            "expected hash_algorithm='sha256' for repo A, got {:?}",
            reply_a.hash_algorithm,
        );
        ensure!(
            reply_b.hash_algorithm.as_deref() == Some("sha512"),
            "expected hash_algorithm='sha512' for repo B, got {:?}",
            reply_b.hash_algorithm,
        );

        // Validate objects_device_id is present.
        ensure!(
            reply_a.objects_device_id.is_some(),
            "repo A should report objects_device_id"
        );
        ensure!(
            reply_b.objects_device_id.is_some(),
            "repo B should report objects_device_id"
        );

        let handle_a = reply_a.handle;
        let handle_b = reply_b.handle;

        // Inspect the source image.
        let inspect = conn_a
            .inspect(handle_a, "copyme:v1")
            .await
            .context("Inspect transport error")?
            .map_err(|e: OciError| anyhow::anyhow!("Inspect failed: {e:?}"))?;

        ensure!(!inspect.manifest.is_empty(), "empty manifest");
        ensure!(!inspect.config.is_empty(), "empty config");

        // Copy each layer.
        let mut layer_refs: Vec<LayerRef> = Vec::with_capacity(diff_ids_ordered.len());
        for diff_id in &diff_ids_ordered {
            let has = conn_b
                .has_layer(handle_b, diff_id)
                .await
                .context("HasLayer transport error")?
                .map_err(|e: OciError| anyhow::anyhow!("HasLayer failed: {e:?}"))?;

            let layer_verity = if has.present {
                has.layer_verity.context("present but no layer_verity")?
            } else {
                use zlink::futures_util::StreamExt as _;
                let get_params = GetLayerParams {
                    diff_id: Some(diff_id.to_string()),
                    storage: None,
                };
                let mut get_stream = std::pin::pin!(
                    conn_a
                        .get_layer(handle_a, get_params)
                        .await
                        .context("GetLayer transport error")?
                );
                let mut all_fds: Vec<std::os::fd::OwnedFd> = Vec::new();
                let mut get_reply = None;
                while let Some(item) = get_stream.next().await {
                    let (result, fds) = item.context("GetLayer stream frame error")?;
                    let reply =
                        result.map_err(|e: OciError| anyhow::anyhow!("GetLayer failed: {e:?}"))?;
                    get_reply = Some(reply);
                    all_fds.extend(fds);
                }
                let get_reply = get_reply.context("GetLayer returned empty stream")?;
                let dir_count = get_reply.dir_count as usize;
                let pipe_and_dirfds_len = 1 + dir_count;
                let lifetime_fds = all_fds.split_off(pipe_and_dirfds_len);

                let put_reply = conn_b
                    .put_layer(handle_b, diff_id, false, all_fds)
                    .await
                    .context("PutLayer transport error")?
                    .map_err(|e: OciError| anyhow::anyhow!("PutLayer failed: {e:?}"))?;
                drop(lifetime_fds);

                put_reply.layer_verity
            };

            layer_refs.push(LayerRef {
                diff_id: diff_id.clone(),
                layer_verity,
            });
        }

        // Finalize.
        let manifest_str = String::from_utf8(manifest_json_a.clone())?;
        let config_str = String::from_utf8(config_json_a.clone())?;

        let finalize = conn_b
            .finalize_image(
                handle_b,
                &manifest_str,
                &config_str,
                layer_refs,
                Some("copyme:v1"),
            )
            .await
            .context("FinalizeImage transport error")?
            .map_err(|e: OciError| anyhow::anyhow!("FinalizeImage failed: {e:?}"))?;

        // Fsck the sha512 destination.
        let fsck = conn_b
            .fsck(handle_b, None)
            .await
            .context("Fsck transport error")?
            .map_err(|e: RepositoryError| anyhow::anyhow!("Fsck failed: {e:?}"))?;
        ensure!(fsck.ok, "fsck failed on sha512 dest: {fsck:?}");

        // The image must be discoverable.
        let listed = conn_b
            .list_images(handle_b, None)
            .await
            .context("ListImages transport error")?
            .map_err(|e: OciError| anyhow::anyhow!("ListImages failed: {e:?}"))?;
        ensure!(
            listed.images.iter().any(|img| img.name == "copyme:v1"),
            "copied image not found in sha512 dest: {:?}",
            listed.images.iter().map(|i| &i.name).collect::<Vec<_>>()
        );

        Ok::<_, anyhow::Error>(finalize)
    })?;

    // ── Post-copy assertions ──────────────────────────────────────────────

    // OCI content digests (sha256 of the raw JSON) must match regardless of
    // fs-verity algorithm — they are algorithm-independent.
    ensure!(
        finalize_reply.manifest_digest == manifest_digest_a.to_string(),
        "manifest_digest mismatch: wire={}, expected={}",
        finalize_reply.manifest_digest,
        manifest_digest_a,
    );
    ensure!(
        finalize_reply.config_digest == config_digest_a.to_string(),
        "config_digest mismatch: wire={}, expected={}",
        finalize_reply.config_digest,
        config_digest_a,
    );

    // The verity strings WILL differ (sha512 vs sha256) — just verify
    // they are non-empty and look like sha512 (128 hex chars).
    ensure!(
        finalize_reply.manifest_verity.len() == 128,
        "sha512 manifest_verity should be 128 hex chars, got {} chars",
        finalize_reply.manifest_verity.len(),
    );
    ensure!(
        finalize_reply.config_verity.len() == 128,
        "sha512 config_verity should be 128 hex chars, got {} chars",
        finalize_reply.config_verity.len(),
    );

    // Open the sha512 repo in-process to verify the image exists.
    let repo_b = Repository::<Sha512HashValue>::open_path(rustix::fs::CWD, &repo_b_path)
        .context("opening sha512 repo B in-process")?;
    let img_b = composefs_oci::oci_image::OciImage::open_ref(&repo_b, "copyme:v1")
        .context("opening copyme:v1 in sha512 repo B")?;
    ensure!(
        img_b.manifest_digest() == &manifest_digest_a,
        "in-process manifest digest mismatch: expected={manifest_digest_a}, got={}",
        img_b.manifest_digest(),
    );

    Ok(())
}
integration_test!(test_copy_image_cross_algorithm);

// ── Test E: CLI cross-algorithm copy (sha256 → sha512) ────────────────────

/// Run `cfsctl oci copy` from a sha256 repo to a sha512 repo via the CLI.
///
/// Proves that the CLI dispatch correctly opens the destination with its own
/// algorithm (2×2 monomorphisation) and that non-zerocopy cross-algorithm
/// copy succeeds end-to-end.
fn test_copy_image_cross_algorithm_cli() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;

    let parent = tempfile::tempdir()?;
    let repo_a_path = parent.path().join("repo-sha256");
    let repo_b_path = parent.path().join("repo-sha512");

    let repo_a = init_sha256_repo(&repo_a_path)?;
    let (manifest_json_a, _config_json_a, _) = build_and_import_test_image(&repo_a, "copyme:v1")?;
    let manifest_digest_a = sha256_content_digest(&manifest_json_a);
    drop(repo_a);

    init_sha512_repo(&repo_b_path)?;

    let repo_a_str = repo_a_path.to_str().unwrap();
    let repo_b_str = repo_b_path.to_str().unwrap();
    let tag = "copyme:v1";
    cmd!(
        sh,
        "{cfsctl} --repo {repo_a_str} --insecure oci copy {tag} --to {repo_b_str} --name {tag}"
    )
    .run()
    .context("cfsctl oci copy (sha256→sha512) should succeed without --zerocopy")?;

    // Verify the image landed in the sha512 repo.
    let repo_b = Repository::<Sha512HashValue>::open_path(rustix::fs::CWD, &repo_b_path)?;
    let img_b = composefs_oci::oci_image::OciImage::open_ref(&repo_b, "copyme:v1")
        .context("opening copyme:v1 in sha512 repo B")?;
    ensure!(
        img_b.manifest_digest() == &manifest_digest_a,
        "manifest_digest mismatch: expected={manifest_digest_a}, got={}",
        img_b.manifest_digest(),
    );

    Ok(())
}
integration_test!(test_copy_image_cross_algorithm_cli);

// ── Test F: zerocopy + algorithm mismatch → error ─────────────────────────

/// `cfsctl oci copy --zerocopy` from sha256 to sha512 must fail with a clear
/// error rather than silently degrading.
fn test_copy_image_zerocopy_algo_mismatch() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;

    let parent = tempfile::tempdir()?;
    let repo_a_path = parent.path().join("repo-sha256");
    let repo_b_path = parent.path().join("repo-sha512");

    let repo_a = init_sha256_repo(&repo_a_path)?;
    let _ = build_and_import_test_image(&repo_a, "copyme:v1")?;
    drop(repo_a);

    init_sha512_repo(&repo_b_path)?;

    let repo_a_str = repo_a_path.to_str().unwrap();
    let repo_b_str = repo_b_path.to_str().unwrap();
    let tag = "copyme:v1";
    let result = cmd!(
        sh,
        "{cfsctl} --repo {repo_a_str} --insecure oci copy {tag} --to {repo_b_str} --name {tag} --zerocopy"
    )
    .ignore_status()
    .read_stderr()
    .context("running cfsctl oci copy --zerocopy")?;

    ensure!(
        result.contains("zerocopy") && result.contains("hash algorithm"),
        "expected error about zerocopy + hash algorithm mismatch, got: {result}"
    );

    Ok(())
}
integration_test!(test_copy_image_zerocopy_algo_mismatch);
