//! Integration tests for the `cfsctl` varlink RPC API.
//!
//! These drive the service the same way an external consumer would: they spawn
//! `cfsctl varlink --address <socket>` (or `cfsctl oci varlink ...`) as a
//! separate process and talk to it over the Unix socket.
//!
//! ## Two clients, on purpose
//!
//! The suite deliberately uses *both* of the ways a consumer can talk to the
//! service, because they prove different things:
//!
//! * **`varlinkctl`** (systemd's CLI) exercises the real on-the-wire varlink
//!   protocol against the *canonical* implementation. This is the interop
//!   guarantee — it proves the bytes we put on the socket are what the
//!   ecosystem expects. Most tests use this path (the `call`/`call_more`/
//!   `call_expect_err` helpers).
//! * **zlink's typed Rust proxy** (the `#[zlink::proxy]` bindings exposed by
//!   `composefs_ctl::varlink::proxy`) exercises the generated, type-checked
//!   client bindings — the same path a future cfsctl-as-client would use. This
//!   catches type-level regressions `varlinkctl` cannot see (a renamed field or
//!   changed shape still serialises to *some* JSON, but fails to deserialise
//!   into the typed reply). A small, high-value subset uses this path (the
//!   `proxy_*` helpers), notably the negative tests, which assert the *exact*
//!   typed error variant rather than merely "something failed".
//!
//! When adding a test, prefer `varlinkctl` for wire/interop coverage; reach for
//! the typed proxy when you specifically want to pin down a typed reply or a
//! typed error variant. Avoid converting the whole suite to either side.
//!
//! A single service answers both the `org.composefs.Repository` and
//! `org.composefs.Oci` interfaces on one socket, so the `repository()` and
//! `oci()` spawn helpers below differ only in which CLI subcommand starts the
//! (identical) combined service.
//!
//! ## Handle-based API
//!
//! The service now requires an explicit repository handle on every method call.
//! On startup, the service pre-opens the repo passed via `--repo` and assigns
//! it handle `1`. `VarlinkService::spawn` fetches this default handle and
//! stores it; `call` and `call_more` automatically inject `"handle":N` into
//! the params object. Use `call_raw` / `call_more_raw` to skip injection (e.g.
//! for negative tests).

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use composefs_ctl::varlink::oci::{OciError, OciInspectReply, PullProgress};
use composefs_ctl::varlink::proxy::{OciProxy, RepositoryProxy};
use composefs_ctl::varlink::{ImageObjectsReply, InitRepositoryReply, RepositoryError};
use serde_json::{Value, json};
use xshell::{Shell, cmd};
use zlink::futures_util::TryStreamExt;

use crate::tests::cli::{corrupt_one_object, create_oci_layout, init_insecure_repo};
use crate::{cfsctl, create_test_rootfs, integration_test};

/// A `cfsctl` varlink service spawned on a Unix socket for the duration of a
/// test. Killed on drop.
struct VarlinkService {
    child: std::process::Child,
    socket: std::path::PathBuf,
    /// Handle for the test repository, opened via `OpenRepository` at spawn and
    /// auto-injected into subsequent calls.
    handle: u64,
    /// Current-thread runtime used to drive the async zlink proxy client from
    /// the synchronous test functions.
    rt: tokio::runtime::Runtime,
    // Keep the tempdir holding the socket alive for the service's lifetime.
    _socket_dir: tempfile::TempDir,
}

impl Drop for VarlinkService {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl VarlinkService {
    /// Spawn `cfsctl <service_args...> --address <sock>`, wait for the socket to
    /// appear, then open `repo` via `OpenRepository` and cache its handle.
    ///
    /// The varlink service opens no repository at startup, so the test repo is
    /// opened explicitly here; the returned handle is auto-injected into
    /// subsequent calls. The repository's insecure mode is auto-detected from
    /// its metadata, so no open flags are needed.
    fn spawn(repo: &Path, service_args: &[&str]) -> Result<Self> {
        let cfsctl = cfsctl()?;
        let socket_dir = tempfile::tempdir()?;
        let socket = socket_dir.path().join("varlink.sock");

        let mut cmd = Command::new(&cfsctl);
        cmd.args(service_args);
        cmd.arg("--address").arg(&socket);
        let child = cmd.spawn().context("spawning cfsctl varlink server")?;

        // Wait (briefly) for the service to bind the socket.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            if Instant::now() > deadline {
                bail!("timed out waiting for varlink socket {}", socket.display());
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let handle = Self::open_repository(&socket, repo)?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building tokio runtime for zlink client")?;

        Ok(VarlinkService {
            child,
            socket,
            handle,
            rt,
            _socket_dir: socket_dir,
        })
    }

    /// Open a repository via `OpenRepository` and return its handle value.
    fn open_repository(socket: &Path, repo: &Path) -> Result<u64> {
        let sock_str = socket.to_string_lossy();
        let params = json!({"path": repo.to_str().context("repo path not UTF-8")?}).to_string();
        let output = Command::new("varlinkctl")
            .args([
                "--json=short",
                "call",
                &sock_str,
                "org.composefs.Repository.OpenRepository",
                &params,
            ])
            .output()
            .context("running varlinkctl for OpenRepository")?;
        if !output.status.success() {
            bail!(
                "OpenRepository failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let stdout = String::from_utf8(output.stdout).context("varlinkctl output not UTF-8")?;
        let line = stdout
            .lines()
            .map(|l| l.trim_start_matches('\u{1e}').trim())
            .find(|l| !l.is_empty())
            .context("no reply from OpenRepository")?;
        let reply: Value = serde_json::from_str(line)
            .with_context(|| format!("parsing OpenRepository reply: {line}"))?;
        reply["handle"]
            .as_u64()
            .context("OpenRepository reply missing numeric 'handle'")
    }

    /// Spawn the combined service via the top-level `varlink` subcommand.
    fn repository(repo: &Path) -> Result<Self> {
        Self::spawn(repo, &["varlink"])
    }

    /// Spawn the combined service via the `oci varlink` subcommand. Serves the
    /// same interfaces as [`Self::repository`]; kept to exercise both CLI entry
    /// points.
    fn oci(repo: &Path) -> Result<Self> {
        Self::spawn(repo, &["oci", "varlink"])
    }

    fn socket_str(&self) -> String {
        self.socket.to_string_lossy().into_owned()
    }

    /// Inject `"handle": self.handle` into a JSON object params value if the
    /// caller did not already set it. Non-object params are returned unchanged.
    fn inject_handle(&self, mut params: Value) -> Value {
        if let Value::Object(ref mut map) = params {
            map.entry("handle").or_insert_with(|| json!(self.handle));
        }
        params
    }

    /// Invoke `varlinkctl call <socket> <method> <params>` and return the
    /// parsed JSON reply. Automatically injects `"handle"` into object params.
    /// Returns an error if the call fails (non-zero exit).
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let params = self.inject_handle(params);
        self.run(&["call", &self.socket_str(), method, &params.to_string()])
            .map(|frames| frames.into_iter().next().unwrap_or(Value::Null))
    }

    /// Like [`call`] but does NOT inject the handle. Use for negative tests
    /// that need precise control over the params (e.g. testing `InvalidHandle`
    /// or `InvalidSpec`).
    fn call_raw(&self, method: &str, params: Value) -> Result<Value> {
        self.run(&["call", &self.socket_str(), method, &params.to_string()])
            .map(|frames| frames.into_iter().next().unwrap_or(Value::Null))
    }

    /// Like [`call_raw`] but expects the call to **fail**. Returns the
    /// stderr string (containing the varlink error name) on non-zero exit,
    /// or bails if the call unexpectedly succeeds.
    fn call_expect_err(&self, method: &str, params: Value) -> Result<String> {
        let output = Command::new("varlinkctl")
            .arg("--json=short")
            .args(["call", &self.socket_str(), method, &params.to_string()])
            .output()
            .context("running varlinkctl (is systemd's varlinkctl installed?)")?;
        if output.status.success() {
            bail!("expected {method} to fail, but it succeeded");
        }
        Ok(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }

    // ── zlink typed proxy client ─────────────────────────────────────────
    //
    // These drive the *same* spawned `cfsctl varlink` process, but via zlink's
    // generated Rust bindings instead of the `varlinkctl` CLI. The outer
    // `zlink::Result` is a transport/protocol error (wrong method, connection
    // dropped, malformed reply); the inner `Result<_, E>` is the typed varlink
    // error reply. Negative tests assert the inner typed error variant, which a
    // bare `is_err()` (that also catches transport failures) could not.

    /// Connect a fresh zlink client to the service socket.
    async fn connect(&self) -> zlink::Result<zlink::unix::Connection> {
        zlink::unix::connect(&self.socket).await
    }

    /// `org.composefs.Oci.Inspect` via the typed proxy, using the cached handle.
    fn proxy_inspect(&self, image: &str) -> zlink::Result<Result<OciInspectReply, OciError>> {
        self.rt.block_on(async {
            let mut conn = self.connect().await?;
            conn.inspect(self.handle, image).await
        })
    }

    /// `org.composefs.Repository.ImageObjects` via the typed proxy.
    fn proxy_image_objects(
        &self,
        name: &str,
    ) -> zlink::Result<Result<ImageObjectsReply, RepositoryError>> {
        self.rt.block_on(async {
            let mut conn = self.connect().await?;
            conn.image_objects(self.handle, name).await
        })
    }

    /// `org.composefs.Repository.InitRepository` via the typed proxy.
    fn proxy_init_repository(
        &self,
        path: &str,
        algorithm: Option<&str>,
        insecure: Option<bool>,
    ) -> zlink::Result<Result<InitRepositoryReply, RepositoryError>> {
        self.rt.block_on(async {
            let mut conn = self.connect().await?;
            conn.init_repository(path, algorithm, insecure).await
        })
    }

    /// `org.composefs.Oci.Pull` via the typed streaming proxy. Collects all
    /// `PullProgress` frames into a `Vec`, surfacing the first error (transport
    /// or typed) encountered.
    fn proxy_pull(
        &self,
        image: &str,
        name: Option<&str>,
        bootable: bool,
    ) -> zlink::Result<Result<Vec<PullProgress>, OciError>> {
        self.rt.block_on(async {
            let mut conn = self.connect().await?;
            let stream = conn
                .pull(self.handle, image, name, "disabled", None, bootable)
                .await?;
            zlink::futures_util::pin_mut!(stream);
            let mut frames = Vec::new();
            while let Some(item) = stream.try_next().await? {
                match item {
                    Ok(frame) => frames.push(frame),
                    Err(e) => return Ok(Err(e)),
                }
            }
            Ok(Ok(frames))
        })
    }

    /// Run a streaming (`--more`) call and return all reply frames.
    /// Automatically injects `"handle"` into object params.
    fn call_more(&self, method: &str, params: Value) -> Result<Vec<Value>> {
        let params = self.inject_handle(params);
        self.run(&[
            "--more",
            "call",
            &self.socket_str(),
            method,
            &params.to_string(),
        ])
    }

    /// Invoke `varlinkctl` and parse its stdout (one JSON object per line) into
    /// reply frames. `--json=short` forces single-line JSON regardless of
    /// whether stdout is a tty.
    fn run(&self, args: &[&str]) -> Result<Vec<Value>> {
        let output = Command::new("varlinkctl")
            .arg("--json=short")
            .args(args)
            .output()
            .context("running varlinkctl (is systemd's varlinkctl installed?)")?;
        if !output.status.success() {
            bail!(
                "varlinkctl {:?} failed: {}",
                args,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let stdout = String::from_utf8(output.stdout).context("varlinkctl output not UTF-8")?;
        let mut frames = Vec::new();
        for line in stdout.lines() {
            // `varlinkctl --more` emits JSON-SEQ (RFC 7464): each record is
            // prefixed with an ASCII record-separator (0x1e). Strip it.
            let line = line.trim_start_matches('\u{1e}').trim();
            if line.is_empty() {
                continue;
            }
            frames.push(
                serde_json::from_str(line).with_context(|| format!("parsing reply: {line}"))?,
            );
        }
        Ok(frames)
    }
}

fn test_varlink_fsck_empty_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let svc = VarlinkService::repository(repo)?;
    let reply = svc.call("org.composefs.Repository.Fsck", json!({}))?;
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["objects_checked"], 0);
    assert!(reply["errors"].as_array().unwrap().is_empty());

    Ok(())
}
integration_test!(test_varlink_fsck_empty_repo);

fn test_varlink_fsck_healthy_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    let svc = VarlinkService::repository(repo)?;
    let reply = svc.call("org.composefs.Repository.Fsck", json!({}))?;
    assert_eq!(reply["ok"], true);
    assert!(reply["objects_checked"].as_u64().unwrap() > 0);
    assert_eq!(reply["objects_corrupted"], 0);
    assert!(reply["errors"].as_array().unwrap().is_empty());

    Ok(())
}
integration_test!(test_varlink_fsck_healthy_repo);

fn test_varlink_fsck_metadata_only() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    let svc = VarlinkService::repository(repo)?;
    // metadata_only skips per-object verification, so objects_checked stays 0.
    let reply = svc.call(
        "org.composefs.Repository.Fsck",
        json!({"metadata_only": true}),
    )?;
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["objects_checked"], 0);
    assert!(reply["errors"].as_array().unwrap().is_empty());

    Ok(())
}
integration_test!(test_varlink_fsck_metadata_only);

fn test_varlink_fsck_detects_corruption() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    corrupt_one_object(repo)?;

    let svc = VarlinkService::repository(repo)?;
    let reply = svc.call("org.composefs.Repository.Fsck", json!({}))?;
    assert_eq!(reply["ok"], false);
    assert!(reply["objects_corrupted"].as_u64().unwrap() > 0);
    assert!(!reply["errors"].as_array().unwrap().is_empty());

    Ok(())
}
integration_test!(test_varlink_fsck_detects_corruption);

fn test_varlink_oci_list_images_empty_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let svc = VarlinkService::oci(repo)?;
    let reply = svc.call("org.composefs.Oci.ListImages", json!({}))?;
    assert!(reply["images"].as_array().unwrap().is_empty());

    Ok(())
}
integration_test!(test_varlink_oci_list_images_empty_repo);

fn test_varlink_oci_list_images_after_pull() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{layout} test-image"
    )
    .run()?;

    let svc = VarlinkService::oci(repo)?;
    let reply = svc.call("org.composefs.Oci.ListImages", json!({}))?;
    let images = reply["images"].as_array().unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0]["name"], "test-image");
    assert!(
        images[0]["manifest_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    Ok(())
}
integration_test!(test_varlink_oci_list_images_after_pull);

fn test_varlink_oci_list_images_filter() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let layout = create_oci_layout(fixture_dir.path())?;
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{layout} keep-me"
    )
    .run()?;

    let svc = VarlinkService::oci(repo)?;
    // A non-matching filter yields nothing; a matching one yields the image.
    let none = svc.call("org.composefs.Oci.ListImages", json!({"filter": "nope"}))?;
    assert!(none["images"].as_array().unwrap().is_empty());

    let some = svc.call("org.composefs.Oci.ListImages", json!({"filter": "keep"}))?;
    assert_eq!(some["images"].as_array().unwrap().len(), 1);

    Ok(())
}
integration_test!(test_varlink_oci_list_images_filter);

fn test_varlink_gc_empty_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let svc = VarlinkService::repository(repo)?;
    let reply = svc.call(
        "org.composefs.Repository.Gc",
        json!({"dry_run": false, "roots": []}),
    )?;
    assert_eq!(reply["result"]["objects_removed"], 0);
    assert_eq!(reply["result"]["objects_bytes"], 0);
    assert_eq!(reply["dry_run"], false);

    Ok(())
}
integration_test!(test_varlink_gc_empty_repo);

fn test_varlink_gc_dry_run() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    let svc = VarlinkService::repository(repo)?;
    let reply = svc.call(
        "org.composefs.Repository.Gc",
        json!({"dry_run": true, "roots": []}),
    )?;
    assert_eq!(reply["dry_run"], true);

    let objects = svc.call(
        "org.composefs.Repository.ImageObjects",
        json!({"name": "refs/my-image"}),
    )?;
    assert!(!objects["object_ids"].as_array().unwrap().is_empty());

    Ok(())
}
integration_test!(test_varlink_gc_dry_run);

fn test_varlink_image_objects() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    let svc = VarlinkService::repository(repo)?;
    let reply = svc.call(
        "org.composefs.Repository.ImageObjects",
        json!({"name": "refs/my-image"}),
    )?;
    let ids: Vec<&str> = reply["object_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(!ids.is_empty());
    for id in &ids {
        assert!(id.contains(':'), "id '{id}' should contain a colon");
    }
    assert!(ids.windows(2).all(|w| w[0] <= w[1]));

    Ok(())
}
integration_test!(test_varlink_image_objects);

fn test_varlink_image_objects_missing() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let svc = VarlinkService::repository(repo)?;
    // Typed-proxy path: assert the exact `NoSuchRef` variant rather than a bare
    // `is_err()` that could also fire on a transport error or wrong method.
    let inner = svc
        .proxy_image_objects("refs/does-not-exist")
        .context("transport/protocol error calling ImageObjects")?;
    match inner {
        Err(RepositoryError::NoSuchRef { reference }) => {
            assert_eq!(reference, "refs/does-not-exist")
        }
        other => bail!("expected NoSuchRef error, got: {other:?}"),
    }

    Ok(())
}
integration_test!(test_varlink_image_objects_missing);

fn test_varlink_oci_fsck_healthy() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{layout} test-image"
    )
    .run()?;

    let svc = VarlinkService::oci(repo)?;
    let reply = svc.call("org.composefs.Oci.Check", json!({}))?;
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["images_checked"], 1);
    assert_eq!(reply["images_corrupted"], 0);
    assert!(reply["errors"].as_array().unwrap().is_empty());
    assert_eq!(reply["repo"]["ok"], true);

    Ok(())
}
integration_test!(test_varlink_oci_fsck_healthy);

fn test_varlink_oci_fsck_single_image() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{layout} test-image"
    )
    .run()?;

    let svc = VarlinkService::oci(repo)?;
    let reply = svc.call("org.composefs.Oci.Check", json!({"image": "test-image"}))?;
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["images_checked"], 1);
    assert_eq!(reply["images_corrupted"], 0);
    assert!(reply["errors"].as_array().unwrap().is_empty());
    assert_eq!(reply["repo"]["ok"], true);

    Ok(())
}
integration_test!(test_varlink_oci_fsck_single_image);

fn test_varlink_oci_inspect() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{layout} test-image"
    )
    .run()?;

    let svc = VarlinkService::oci(repo)?;
    // Positive round-trip through the typed proxy: this proves the non-trivial
    // `OciInspectReply` struct (incl. its optional/vec fields) deserialises
    // correctly through the generated bindings — something `varlinkctl` can't
    // check, since it only ever sees raw JSON.
    let reply = svc
        .proxy_inspect("test-image")
        .context("transport/protocol error calling Inspect")?
        .map_err(|e| anyhow::anyhow!("Inspect returned a varlink error: {e:?}"))?;
    assert!(!reply.manifest.is_empty());
    assert!(!reply.config.is_empty());

    let m: Value = serde_json::from_str(&reply.manifest)?;
    assert!(
        m.get("schemaVersion").is_some() || m.get("layers").is_some() || m.get("config").is_some()
    );

    let c: Value = serde_json::from_str(&reply.config)?;
    assert!(c.get("architecture").is_some() || c.get("rootfs").is_some());

    // `referrers` is a typed Vec<String>; just touch it to prove it deserialised.
    let _: &Vec<String> = &reply.referrers;

    Ok(())
}
integration_test!(test_varlink_oci_inspect);

fn test_varlink_oci_tag_and_untag() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{layout} myimage:v1"
    )
    .run()?;

    let svc = VarlinkService::oci(repo)?;
    let list = svc.call("org.composefs.Oci.ListImages", json!({}))?;
    let images = list["images"].as_array().unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0]["name"], "myimage:v1");
    let manifest_digest = images[0]["manifest_digest"].as_str().unwrap().to_string();

    svc.call(
        "org.composefs.Oci.Tag",
        json!({"manifest_digest": manifest_digest, "name": "myimage:latest"}),
    )?;

    let list2 = svc.call("org.composefs.Oci.ListImages", json!({}))?;
    let mut names: Vec<String> = list2["images"]
        .as_array()
        .unwrap()
        .iter()
        .map(|img| img["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["myimage:latest".to_string(), "myimage:v1".to_string()]
    );

    svc.call("org.composefs.Oci.Untag", json!({"name": "myimage:v1"}))?;

    let list3 = svc.call("org.composefs.Oci.ListImages", json!({}))?;
    let images3 = list3["images"].as_array().unwrap();
    assert_eq!(images3.len(), 1);
    assert_eq!(images3[0]["name"], "myimage:latest");

    Ok(())
}
integration_test!(test_varlink_oci_tag_and_untag);

fn test_varlink_oci_compute_id() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{layout} test-ref-image"
    )
    .run()?;

    let svc = VarlinkService::oci(repo)?;
    let reply = svc.call(
        "org.composefs.Oci.ComputeId",
        json!({"image": "test-ref-image", "verity": null, "bootable": false}),
    )?;
    let image_id = reply["image_id"].as_str().unwrap();
    assert!(!image_id.is_empty());
    assert!(image_id.chars().all(|c| c.is_ascii_hexdigit()));

    let cli_id = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci compute-id test-ref-image"
    )
    .read()?;
    assert_eq!(image_id, cli_id.trim());

    Ok(())
}
integration_test!(test_varlink_oci_compute_id);

fn test_varlink_oci_inspect_missing() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let svc = VarlinkService::oci(repo)?;
    // Driven through zlink's typed proxy so we can assert the *exact* varlink
    // error variant. A bare `is_err()` would also pass for a wrong method name
    // or a transport failure; here the outer Result must be Ok (the call
    // reached the service and got a proper reply) and the inner Result must be
    // the typed `NoSuchImage` error.
    let inner = svc
        .proxy_inspect("does-not-exist")
        .context("transport/protocol error calling Inspect")?;
    match inner {
        Err(OciError::NoSuchImage { image }) => assert_eq!(image, "does-not-exist"),
        other => bail!("expected NoSuchImage error, got: {other:?}"),
    }

    Ok(())
}
integration_test!(test_varlink_oci_inspect_missing);

fn test_varlink_oci_pull_streaming() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let layout = create_oci_layout(fixture_dir.path())?;

    let svc = VarlinkService::oci(repo)?;
    let frames = svc.call_more(
        "org.composefs.Oci.Pull",
        json!({
            "image": format!("oci:{}", layout.display()),
            "name": "streamed-image",
            "local_fetch": "disabled",
            "storage_root": null,
            "bootable": false,
        }),
    )?;

    assert!(!frames.is_empty(), "stream should emit at least one frame");
    let last = frames.last().unwrap();
    let completed = &last["completed"];
    assert!(completed.is_object(), "last frame should be `completed`");
    let manifest_digest = completed["manifest_digest"].as_str().unwrap();
    assert!(manifest_digest.starts_with("sha256:"));
    assert!(!completed["config_digest"].as_str().unwrap().is_empty());
    assert!(!completed["manifest_verity"].as_str().unwrap().is_empty());
    assert!(!completed["stats"].as_str().unwrap().is_empty());

    let completed_count = frames.iter().filter(|f| f["completed"].is_object()).count();
    assert_eq!(completed_count, 1);
    // Every non-terminal frame sets exactly one event variant.
    for frame in &frames {
        if frame["completed"].is_object() {
            continue;
        }
        let variants = ["started", "progress", "skipped", "done", "message"];
        let set = variants.iter().filter(|k| !frame[**k].is_null()).count();
        assert_eq!(set, 1, "exactly one event variant must be set: {frame}");
    }

    let list = svc.call("org.composefs.Oci.ListImages", json!({}))?;
    let images = list["images"].as_array().unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0]["name"], "streamed-image");
    assert_eq!(images[0]["manifest_digest"], manifest_digest);

    Ok(())
}
integration_test!(test_varlink_oci_pull_streaming);

/// Streaming pull driven through zlink's typed `more` proxy. Mirrors
/// `test_varlink_oci_pull_streaming` (which uses `varlinkctl`) but proves the
/// generated streaming bindings deserialise each `PullProgress` frame into the
/// typed sum-of-options shape, including the terminal `completed` frame.
fn test_varlink_oci_pull_streaming_proxy() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let layout = create_oci_layout(fixture_dir.path())?;
    let image = format!("oci:{}", layout.display());

    let svc = VarlinkService::oci(repo)?;
    let frames = svc
        .proxy_pull(&image, Some("streamed-proxy"), false)
        .context("transport/protocol error calling Pull")?
        .map_err(|e| anyhow::anyhow!("Pull returned a varlink error: {e:?}"))?;

    assert!(!frames.is_empty(), "stream should emit at least one frame");

    // Exactly one terminal `completed` frame, and it is the last one.
    let completed_count = frames.iter().filter(|f| f.completed.is_some()).count();
    assert_eq!(completed_count, 1, "expected exactly one completed frame");
    let last = frames.last().unwrap();
    let completed = last
        .completed
        .as_ref()
        .context("last frame should be the completed frame")?;
    assert!(completed.manifest_digest.starts_with("sha256:"));
    assert!(!completed.config_digest.is_empty());
    assert!(!completed.manifest_verity.is_empty());
    assert!(!completed.stats.is_empty());

    // Every non-terminal frame sets exactly one event variant.
    for frame in &frames {
        if frame.completed.is_some() {
            continue;
        }
        let set = [
            frame.started.is_some(),
            frame.progress.is_some(),
            frame.skipped.is_some(),
            frame.done.is_some(),
            frame.message.is_some(),
        ]
        .into_iter()
        .filter(|x| *x)
        .count();
        assert_eq!(set, 1, "exactly one event variant must be set: {frame:?}");
    }

    // The image landed in the repo under the requested tag.
    let list = svc.call("org.composefs.Oci.ListImages", json!({}))?;
    let images = list["images"].as_array().unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0]["name"], "streamed-proxy");
    assert_eq!(images[0]["manifest_digest"], completed.manifest_digest);

    Ok(())
}
integration_test!(test_varlink_oci_pull_streaming_proxy);

fn test_varlink_oci_pull_then_inspect() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let layout = create_oci_layout(fixture_dir.path())?;

    let svc = VarlinkService::oci(repo)?;
    let frames = svc.call_more(
        "org.composefs.Oci.Pull",
        json!({
            "image": format!("oci:{}", layout.display()),
            "name": "inspectme",
            "local_fetch": "disabled",
            "storage_root": null,
            "bootable": false,
        }),
    )?;
    assert!(frames.last().unwrap()["completed"].is_object());

    let reply = svc.call("org.composefs.Oci.Inspect", json!({"image": "inspectme"}))?;
    assert!(!reply["manifest"].as_str().unwrap().is_empty());
    assert!(!reply["config"].as_str().unwrap().is_empty());
    assert!(reply["composefs_boot_erofs"].is_null());

    let m: Value = serde_json::from_str(reply["manifest"].as_str().unwrap())?;
    assert!(
        m.get("schemaVersion").is_some() || m.get("layers").is_some() || m.get("config").is_some()
    );

    Ok(())
}
integration_test!(test_varlink_oci_pull_then_inspect);

fn test_varlink_oci_pull_bad_image() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let svc = VarlinkService::oci(repo)?;
    let result = svc.call_more(
        "org.composefs.Oci.Pull",
        json!({
            "image": "oci:/nonexistent/path/nope",
            "name": "x",
            "local_fetch": "disabled",
            "storage_root": null,
            "bootable": false,
        }),
    );

    // The pull must fail; either the call errors outright, or no `completed`
    // frame is produced before the error.
    match result {
        Err(_) => {}
        Ok(frames) => {
            assert!(
                !frames.iter().any(|f| f["completed"].is_object()),
                "no completed frame should be emitted for a bad image pull"
            );
        }
    }

    Ok(())
}
integration_test!(test_varlink_oci_pull_bad_image);

fn test_varlink_oci_pull_bootable() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let fixture_dir = tempfile::tempdir()?;
    let layout = create_oci_layout(fixture_dir.path())?;

    let svc = VarlinkService::oci(repo)?;
    let result = svc.call_more(
        "org.composefs.Oci.Pull",
        json!({
            "image": format!("oci:{}", layout.display()),
            "name": "bootme",
            "local_fetch": "disabled",
            "storage_root": null,
            "bootable": true,
        }),
    );

    // A synthetic layer lacks boot resources, so the bootable pull either
    // completes (possibly with no boot image) or fails cleanly.
    match result {
        Ok(frames) => {
            if let Some(frame) = frames.iter().find(|f| f["completed"].is_object())
                && let Some(boot) = frame["completed"]["boot_image"].as_str()
            {
                assert!(
                    !boot.is_empty(),
                    "boot image should not be empty if present"
                );
            }
        }
        Err(_) => {
            // Clean failure due to missing boot resources is acceptable.
        }
    }

    Ok(())
}
integration_test!(test_varlink_oci_pull_bootable);

/// Both the `org.composefs.Repository` and `org.composefs.Oci` interfaces are
/// served on the same socket by a single service process.
fn test_varlink_both_interfaces_one_socket() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let svc = VarlinkService::repository(repo)?;

    // A Repository-interface method...
    let fsck = svc.call(
        "org.composefs.Repository.Fsck",
        json!({"metadata_only": true}),
    )?;
    assert_eq!(fsck["ok"], true);

    // ...and an Oci-interface method, on the very same socket.
    let images = svc.call("org.composefs.Oci.ListImages", json!({}))?;
    assert!(images["images"].as_array().unwrap().is_empty());

    Ok(())
}
integration_test!(test_varlink_both_interfaces_one_socket);

/// The service is reachable via systemd socket activation, the way
/// `varlinkctl exec:<binary>` launches it: the connected socket is passed on fd
/// 3 with `LISTEN_FDS`/`LISTEN_PID` set, and the process serves varlink without
/// any subcommand on its command line.
///
/// An activated launch must be argument-less, so the client selects a
/// repository at runtime with `OpenRepository`. (The repository's insecure mode
/// is auto-detected from its `meta.json`, so no open flags are needed.)
///
/// Each `varlinkctl exec:` invocation spawns a *fresh* process, so a handle
/// obtained from one call cannot be used in a later call — there is no shared,
/// long-lived service. We therefore assert only that a single activated call
/// works end to end: `OpenRepository` over `exec:` returns a valid handle,
/// which proves the socket-activation wiring (the connected socket on fd 3 with
/// `LISTEN_FDS`/`LISTEN_PID`) and that the service can open a real repository.
///
/// `varlinkctl`'s `exec:` reference is a single binary path with no argument
/// splitting; the binary path is kept space-free so `exec:` can resolve it.
fn test_varlink_socket_activation() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let reference = format!("exec:{}", cfsctl.display());
    let params = json!({"path": repo.to_str().unwrap()}).to_string();
    let output = Command::new("varlinkctl")
        .args([
            "--json=short",
            "call",
            &reference,
            "org.composefs.Repository.OpenRepository",
            &params,
        ])
        .output()
        .context("running varlinkctl (is systemd's varlinkctl installed?)")?;
    if !output.status.success() {
        bail!(
            "varlinkctl exec: OpenRepository failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8(output.stdout)?;
    let line = stdout
        .lines()
        .map(|l| l.trim_start_matches('\u{1e}').trim())
        .find(|l| !l.is_empty())
        .context("no reply from socket-activated OpenRepository")?;
    let reply: Value = serde_json::from_str(line).with_context(|| format!("parsing: {line}"))?;
    let handle = reply["handle"]
        .as_u64()
        .context("OpenRepository reply missing numeric 'handle'")?;
    assert!(handle >= 1, "handle should be >= 1, got {handle}");

    Ok(())
}
integration_test!(test_varlink_socket_activation);

// ============================================================================
// New handle-API tests
// ============================================================================

/// Opening a repository by path yields a new handle; using that handle works;
/// closing it makes subsequent calls fail with InvalidHandle.
fn test_varlink_open_and_close_repository() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let svc = VarlinkService::repository(repo)?;

    // Open a second handle to the same repo.
    let open_reply = svc.call_raw(
        "org.composefs.Repository.OpenRepository",
        json!({"path": repo.to_str().unwrap()}),
    )?;
    let new_handle = open_reply["handle"]
        .as_u64()
        .context("OpenRepository reply missing numeric 'handle'")?;
    assert!(new_handle >= 1, "handle should be >= 1, got {new_handle}");

    // The new handle works.
    let fsck = svc.call_raw(
        "org.composefs.Repository.Fsck",
        json!({"handle": new_handle}),
    )?;
    assert_eq!(fsck["ok"], true);

    // Close the handle.
    svc.call_raw(
        "org.composefs.Repository.CloseRepository",
        json!({"handle": new_handle}),
    )?;

    // After closing, the handle is no longer valid.
    let err = svc.call_expect_err(
        "org.composefs.Repository.Fsck",
        json!({"handle": new_handle}),
    )?;
    assert!(
        err.contains("InvalidHandle"),
        "expected InvalidHandle error, got: {err}"
    );

    Ok(())
}
integration_test!(test_varlink_open_and_close_repository);

/// `OpenRepository` with zero or multiple selector fields returns `InvalidSpec`.
fn test_varlink_open_repository_invalid_spec() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let svc = VarlinkService::repository(repo)?;

    // No selector field at all.
    let err = svc.call_expect_err("org.composefs.Repository.OpenRepository", json!({}))?;
    assert!(
        err.contains("InvalidSpec"),
        "expected InvalidSpec for empty params, got: {err}"
    );

    // Two selector fields simultaneously.
    let err2 = svc.call_expect_err(
        "org.composefs.Repository.OpenRepository",
        json!({"path": repo.to_str().unwrap(), "user": true}),
    )?;
    assert!(
        err2.contains("InvalidSpec"),
        "expected InvalidSpec for conflicting selectors, got: {err2}"
    );

    Ok(())
}
integration_test!(test_varlink_open_repository_invalid_spec);

/// Methods called with an unknown handle return the appropriate `InvalidHandle`
/// error for both the Repository and Oci interfaces.
fn test_varlink_invalid_handle() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let svc = VarlinkService::repository(repo)?;

    // Repository method with bogus handle.
    let err = svc.call_expect_err("org.composefs.Repository.Fsck", json!({"handle": 999}))?;
    assert!(
        err.contains("InvalidHandle"),
        "expected InvalidHandle from Fsck, got: {err}"
    );

    // OCI method with bogus handle (org.composefs.Oci.InvalidHandle).
    let err2 = svc.call_expect_err("org.composefs.Oci.ListImages", json!({"handle": 999}))?;
    assert!(
        err2.contains("InvalidHandle"),
        "expected InvalidHandle from Oci.ListImages, got: {err2}"
    );

    Ok(())
}
integration_test!(test_varlink_invalid_handle);

/// `CloseRepository` with an unknown handle returns `InvalidHandle`.
fn test_varlink_close_unknown_handle() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let svc = VarlinkService::repository(repo)?;
    let err = svc.call_expect_err(
        "org.composefs.Repository.CloseRepository",
        json!({"handle": 424242}),
    )?;
    assert!(
        err.contains("InvalidHandle"),
        "expected InvalidHandle for unknown handle, got: {err}"
    );

    Ok(())
}
integration_test!(test_varlink_close_unknown_handle);

// ============================================================================
// InitRepository tests
// ============================================================================

/// `InitRepository` creates a new repository and returns `created: true`; the
/// freshly-created repo can immediately be opened with `OpenRepository`.
fn test_varlink_init_repository_creates_new() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    // We need a running service — use an existing insecure repo for that.
    let existing_dir = init_insecure_repo(&sh, &cfsctl)?;
    let svc = VarlinkService::repository(existing_dir.path())?;

    // Point InitRepository at a brand-new (non-existent) path.
    let new_repo_dir = tempfile::tempdir()?;
    let new_repo_path = new_repo_dir.path().join("new-repo");
    let path_str = new_repo_path.to_str().context("repo path not UTF-8")?;

    let reply = svc.call_raw(
        "org.composefs.Repository.InitRepository",
        json!({"path": path_str, "insecure": true}),
    )?;
    assert_eq!(
        reply["created"], true,
        "expected created=true for a fresh repo, got: {reply}"
    );

    // The new repo should be openable.
    let open_reply = svc.call_raw(
        "org.composefs.Repository.OpenRepository",
        json!({"path": path_str}),
    )?;
    assert!(
        open_reply["handle"].as_u64().is_some(),
        "expected a numeric handle after init, got: {open_reply}"
    );

    Ok(())
}
integration_test!(test_varlink_init_repository_creates_new);

/// Calling `InitRepository` twice on the same path with the same algorithm is
/// idempotent: the second call returns `created: false`.
fn test_varlink_init_repository_idempotent() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let existing_dir = init_insecure_repo(&sh, &cfsctl)?;
    let svc = VarlinkService::repository(existing_dir.path())?;

    let new_repo_dir = tempfile::tempdir()?;
    let new_repo_path = new_repo_dir.path().join("idempotent-repo");
    let path_str = new_repo_path.to_str().context("repo path not UTF-8")?;

    // First call: creates the repo.
    let first = svc.call_raw(
        "org.composefs.Repository.InitRepository",
        json!({"path": path_str, "insecure": true}),
    )?;
    assert_eq!(first["created"], true, "first call should create the repo");

    // Second call with the same algorithm: idempotent.
    let second = svc.call_raw(
        "org.composefs.Repository.InitRepository",
        json!({"path": path_str, "insecure": true}),
    )?;
    assert_eq!(
        second["created"], false,
        "second call should be idempotent (created=false)"
    );

    Ok(())
}
integration_test!(test_varlink_init_repository_idempotent);

/// `InitRepository` with an unrecognised algorithm string returns `InvalidSpec`.
fn test_varlink_init_repository_invalid_algorithm() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let existing_dir = init_insecure_repo(&sh, &cfsctl)?;
    let svc = VarlinkService::repository(existing_dir.path())?;

    let new_repo_dir = tempfile::tempdir()?;
    let path_str = new_repo_dir
        .path()
        .join("bad-algo")
        .to_str()
        .context("path not UTF-8")?
        .to_owned();

    let err = svc.call_expect_err(
        "org.composefs.Repository.InitRepository",
        json!({"path": path_str, "algorithm": "not-an-algorithm"}),
    )?;
    assert!(
        err.contains("InvalidSpec"),
        "expected InvalidSpec for bad algorithm, got: {err}"
    );

    Ok(())
}
integration_test!(test_varlink_init_repository_invalid_algorithm);

/// `InitRepository` via the typed zlink proxy — proves the generated client
/// bindings round-trip the reply and error types correctly.
fn test_varlink_init_repository_proxy() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let existing_dir = init_insecure_repo(&sh, &cfsctl)?;
    let svc = VarlinkService::repository(existing_dir.path())?;

    let new_repo_dir = tempfile::tempdir()?;
    let new_repo_path = new_repo_dir.path().join("proxy-repo");
    let path_str = new_repo_path.to_str().context("repo path not UTF-8")?;

    // Fresh init via typed proxy.
    let reply = svc
        .proxy_init_repository(path_str, None, Some(true))?
        .expect("InitRepository should succeed");
    assert!(reply.created, "expected created=true for a fresh repo");

    // Idempotent second call.
    let reply2 = svc
        .proxy_init_repository(path_str, None, Some(true))?
        .expect("second InitRepository should succeed");
    assert!(!reply2.created, "expected created=false on second call");

    // Bad algorithm returns the typed InvalidSpec error.
    let err = svc
        .proxy_init_repository(path_str, Some("bad-algo"), None)?
        .expect_err("bad algorithm should return an error");
    assert!(
        matches!(err, RepositoryError::InvalidSpec { .. }),
        "expected InvalidSpec, got: {err:?}"
    );

    Ok(())
}
integration_test!(test_varlink_init_repository_proxy);
