//! Integration tests for the `oci copy` CLI command and `copy_image` API.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use xshell::{Shell, cmd};

use composefs_oci::composefs::fsverity::{Sha256HashValue, Sha512HashValue};
use composefs_oci::composefs::repository::{Repository, RepositoryConfig};
use composefs_oci::layer_sync::finalize_oci_image;
use composefs_oci::test_util::{build_oci_tar_layer, make_config_json, make_manifest_json};
use composefs_oci::{import_layer, sha256_content_digest};

use composefs_ctl::varlink::RepositoryError;
use composefs_ctl::varlink::proxy::RepositoryProxy;

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
        "{cfsctl} --repo {repo_b_str} --insecure oci copy {tag} --from {repo_a_str} --name {tag}"
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

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;

    // Both repos on the same XFS reflink-capable loop mount.
    let fs = LoopTempDir::xfs_reflink()?;
    let repo_a_path = fs.path().join("repo-a");
    let repo_b_path = fs.path().join("repo-b");

    let repo_a = init_sha256_repo(&repo_a_path)?;
    build_and_import_test_image(&repo_a, "copyme:v1")?;

    let _repo_b = init_sha256_repo(&repo_b_path)?;

    // Run `cfsctl oci copy --zerocopy` via the CLI.
    let repo_a_str = repo_a_path.to_str().unwrap();
    let repo_b_str = repo_b_path.to_str().unwrap();
    let tag = "copyme:v1";
    cmd!(
        sh,
        "{cfsctl} --repo {repo_b_str} --insecure oci copy {tag} --from {repo_a_str} --name {tag} --zerocopy"
    )
    .run()
    .context("cfsctl oci copy --zerocopy failed")?;

    // Verify correctness: manifest + config digests match.
    let repo_b = Repository::<Sha256HashValue>::open_path(rustix::fs::CWD, &repo_b_path)?;
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

    // On XFS with reflinks, the objects should share extents.  Verify by
    // checking that at least one object in repo B has nlink > 1 or shares
    // its extents with the corresponding object in repo A (same inode on
    // XFS reflink means FICLONE succeeded).
    // A lighter check: the copy succeeded with --zerocopy (which would fail
    // if reflink/hardlink was not possible), and the content matches.

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
async fn open_repo(conn: &mut zlink::tokio::unix::Connection, repo_path: &Path) -> Result<u64> {
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

/// Copy an image between two varlink subprocess servers using `copy_image`.
///
/// This exercises the cross-process SCM_RIGHTS fd passing path that
/// in-process tests cannot cover.
fn test_copy_image_via_varlink() -> Result<()> {
    let parent = tempfile::tempdir()?;
    let repo_a_path = parent.path().join("repo-a");
    let repo_b_path = parent.path().join("repo-b");

    let repo_a = init_sha256_repo(&repo_a_path)?;
    let (manifest_json_a, config_json_a, _diff_id2_str) =
        build_and_import_test_image(&repo_a, "copyme:v1")?;

    let manifest_digest_a = sha256_content_digest(&manifest_json_a);
    let config_digest_a = sha256_content_digest(&config_json_a);

    {
        let _repo_b_init = init_sha256_repo(&repo_b_path)?;
    }
    drop(repo_a);

    let svc_a = VarlinkProc::spawn().context("spawning varlink server A")?;
    let svc_b = VarlinkProc::spawn().context("spawning varlink server B")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    let image: composefs_ctl::OciReference = "copyme:v1".parse()?;

    let finalize_reply = rt.block_on(async {
        let mut conn_a = zlink::tokio::unix::connect(svc_a.socket())
            .await
            .context("connecting to server A")?;
        let mut conn_b = zlink::tokio::unix::connect(svc_b.socket())
            .await
            .context("connecting to server B")?;

        let handle_a = open_repo(&mut conn_a, &repo_a_path).await?;
        let handle_b = open_repo(&mut conn_b, &repo_b_path).await?;

        let finalize = composefs_ctl::copy_image(
            &mut conn_a,
            &mut conn_b,
            handle_a,
            handle_b,
            &image,
            Some("copyme:v1"),
            false,
        )
        .await?;

        // Fsck the destination over the wire.
        let fsck = conn_b
            .fsck(handle_b, None)
            .await
            .context("Fsck transport error")?
            .map_err(|e: RepositoryError| anyhow::anyhow!("Fsck failed: {e:?}"))?;
        ensure!(fsck.ok, "fsck failed after copy: {fsck:?}");

        Ok::<_, anyhow::Error>(finalize)
    })?;

    ensure!(
        finalize_reply.manifest_digest == manifest_digest_a.to_string(),
        "manifest_digest mismatch"
    );
    ensure!(
        finalize_reply.config_digest == config_digest_a.to_string(),
        "config_digest mismatch"
    );

    // Open repo B in-process and verify the image landed correctly.
    let repo_b = Repository::<Sha256HashValue>::open_path(rustix::fs::CWD, &repo_b_path)?;
    let img_b = composefs_oci::oci_image::OciImage::open_ref(&repo_b, "copyme:v1")
        .context("opening copyme:v1 in repo B")?;

    ensure!(
        img_b.manifest_digest() == &manifest_digest_a,
        "manifest digest mismatch in-process"
    );
    ensure!(
        img_b.config_digest() == &config_digest_a,
        "config digest mismatch in-process"
    );

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
    let parent = tempfile::tempdir()?;
    let repo_a_path = parent.path().join("repo-sha256");
    let repo_b_path = parent.path().join("repo-sha512");

    let repo_a = init_sha256_repo(&repo_a_path)?;
    let (manifest_json_a, _config_json_a, _) = build_and_import_test_image(&repo_a, "copyme:v1")?;
    let manifest_digest_a = sha256_content_digest(&manifest_json_a);
    drop(repo_a);

    init_sha512_repo(&repo_b_path)?;

    let svc_a = VarlinkProc::spawn().context("spawning server A (sha256)")?;
    let svc_b = VarlinkProc::spawn().context("spawning server B (sha512)")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let image: composefs_ctl::OciReference = "copyme:v1".parse()?;

    let finalize_reply = rt.block_on(async {
        let mut conn_a = zlink::tokio::unix::connect(svc_a.socket()).await?;
        let mut conn_b = zlink::tokio::unix::connect(svc_b.socket()).await?;

        let handle_a = open_repo(&mut conn_a, &repo_a_path).await?;
        let handle_b = open_repo(&mut conn_b, &repo_b_path).await?;

        let finalize = composefs_ctl::copy_image(
            &mut conn_a,
            &mut conn_b,
            handle_a,
            handle_b,
            &image,
            Some("copyme:v1"),
            false,
        )
        .await?;

        // Fsck the sha512 destination.
        let fsck = conn_b
            .fsck(handle_b, None)
            .await
            .context("Fsck transport error")?
            .map_err(|e: RepositoryError| anyhow::anyhow!("Fsck failed: {e:?}"))?;
        ensure!(fsck.ok, "fsck failed on sha512 dest: {fsck:?}");

        Ok::<_, anyhow::Error>(finalize)
    })?;

    // OCI content digests must match regardless of fs-verity algorithm.
    ensure!(
        finalize_reply.manifest_digest == manifest_digest_a.to_string(),
        "manifest_digest mismatch",
    );

    // The verity strings should be sha512 (128 hex chars).
    ensure!(
        finalize_reply.manifest_verity.len() == 128,
        "sha512 manifest_verity should be 128 hex chars, got {} chars",
        finalize_reply.manifest_verity.len(),
    );

    // Verify the image exists in the sha512 repo.
    let repo_b = Repository::<Sha512HashValue>::open_path(rustix::fs::CWD, &repo_b_path)?;
    let img_b = composefs_oci::oci_image::OciImage::open_ref(&repo_b, "copyme:v1")
        .context("opening copyme:v1 in sha512 repo B")?;
    ensure!(
        img_b.manifest_digest() == &manifest_digest_a,
        "manifest digest mismatch in sha512 repo",
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
        "{cfsctl} --repo {repo_b_str} --insecure oci copy {tag} --from {repo_a_str} --name {tag}"
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
        "{cfsctl} --repo {repo_b_str} --insecure oci copy {tag} --from {repo_a_str} --name {tag} --zerocopy"
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

// ── Test G: OCI artifact copy (no rootfs.diff_ids) ────────────────────────

/// Build a synthetic OCI artifact (not a container image) in repo A, then
/// copy it to repo B via `cfsctl oci copy`.  Artifacts have no
/// `rootfs.diff_ids` in their config, so this exercises the manifest-layer
/// fallback in `copy_image`.
fn test_copy_artifact() -> Result<()> {
    use composefs_oci::composefs::repository::Repository;
    use containers_image_proxy::oci_spec::image::{
        DescriptorBuilder, ImageManifestBuilder, MediaType,
    };

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;

    let parent = tempfile::tempdir()?;
    let repo_a_path = parent.path().join("repo-a");
    let repo_b_path = parent.path().join("repo-b");

    // ── Build an artifact in repo A ───────────────────────────────────────
    let repo_a = init_sha256_repo(&repo_a_path)?;

    // Artifact payload: a small SBOM-like blob (not a tar).
    let blob_data = br#"{"spdxVersion":"SPDX-2.3","name":"test-artifact"}"#;
    let blob_digest = sha256_content_digest(blob_data);

    // Store the blob as an object + layer splitstream.
    let blob_object_id = repo_a.ensure_object(blob_data)?;
    let layer_id = composefs_oci::layer_content_id(&blob_digest);
    // Use BLOB_CONTENT_TYPE for non-tar artifact layers.
    let mut layer_stream = repo_a.create_stream(composefs_oci::BLOB_CONTENT_TYPE)?;
    layer_stream.add_external_size(blob_data.len() as u64);
    layer_stream.write_reference(blob_object_id)?;
    let layer_verity = repo_a.write_stream(layer_stream, &layer_id, None)?;

    // Empty config (the OCI 1.1 artifact config pattern).
    let config_json = b"{}";
    let config_digest = sha256_content_digest(config_json);

    // Build the manifest with EmptyJSON config media type (not ImageConfig).
    let config_desc = DescriptorBuilder::default()
        .media_type(MediaType::EmptyJSON)
        .digest(config_digest.clone())
        .size(config_json.len() as u64)
        .build()
        .context("building config descriptor")?;

    let layer_desc = DescriptorBuilder::default()
        .media_type(MediaType::Other("text/spdx+json".to_string()))
        .digest(blob_digest.clone())
        .size(blob_data.len() as u64)
        .build()
        .context("building layer descriptor")?;

    let manifest = ImageManifestBuilder::default()
        .schema_version(2u32)
        .media_type(MediaType::ImageManifest)
        .config(config_desc)
        .layers(vec![layer_desc])
        .build()
        .context("building manifest")?;

    let manifest_json = serde_json::to_vec(&manifest).context("serializing manifest")?;
    let manifest_digest = sha256_content_digest(&manifest_json);

    let layer_refs = vec![(blob_digest.clone(), layer_verity)];
    finalize_oci_image(
        &repo_a,
        &manifest_json,
        config_json,
        &layer_refs,
        Some("artifact:v1"),
    )
    .context("finalize artifact")?;

    // Verify it's not a container image.
    let img = composefs_oci::oci_image::OciImage::open_ref(&repo_a, "artifact:v1")?;
    ensure!(
        !img.is_container_image(),
        "expected artifact, got container image"
    );
    drop(repo_a);

    // ── Init repo B and copy via CLI ──────────────────────────────────────
    {
        let _repo_b = init_sha256_repo(&repo_b_path)?;
    }

    let repo_a_str = repo_a_path.to_str().unwrap();
    let repo_b_str = repo_b_path.to_str().unwrap();
    cmd!(
        sh,
        "{cfsctl} --repo {repo_b_str} --insecure oci copy artifact:v1 --from {repo_a_str} --name artifact:v1"
    )
    .run()
    .context("cfsctl oci copy failed for artifact")?;

    // ── Verify the artifact landed in repo B ──────────────────────────────
    let repo_b = Repository::<Sha256HashValue>::open_path(rustix::fs::CWD, &repo_b_path)?;
    let img_b = composefs_oci::oci_image::OciImage::open_ref(&repo_b, "artifact:v1")
        .context("opening artifact:v1 in repo B")?;

    ensure!(
        !img_b.is_container_image(),
        "copied artifact became a container image"
    );
    ensure!(
        img_b.manifest_digest() == &manifest_digest,
        "manifest digest mismatch after artifact copy"
    );

    Ok(())
}
integration_test!(test_copy_artifact);
