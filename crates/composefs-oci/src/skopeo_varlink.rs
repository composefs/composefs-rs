//! Import container images via skopeo's JSON proxy + varlink socket.
//!
//! This module spawns a `skopeo experimental-image-proxy` subprocess,
//! opens a `containers-storage:` image through it, then calls
//! `OpenVarlinkSocket` to obtain a Unix socket speaking the
//! `org.composefs.Oci` varlink protocol.  Layers are transferred via
//! `GetLayer` over that socket, reusing the same `import_layer_via_transfer`
//! path as the in-process cstor import.

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use anyhow::{Context, Result};
use containers_image_proxy::oci_spec::image::ImageManifest;

use composefs::{
    fsverity::FsVerityHashValue,
    repository::{ImportContext, Repository},
};

use crate::progress::{ComponentId, ProgressEvent, ProgressUnit, SharedReporter};
use crate::varlink_types::GetLayerParams;
use crate::{ContentAndVerity, ImportStats, OciDigest, layer_identifier};

const MAX_MSG_SIZE: usize = 32 * 1024;

#[derive(serde::Serialize)]
struct Request {
    method: String,
    args: Vec<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct Reply {
    success: bool,
    error: String,
    pipeid: u32,
    value: serde_json::Value,
}

/// Guard that keeps the skopeo child process alive.  Kills the child on drop.
pub(crate) struct SkopeoGuard {
    child: std::process::Child,
    _sock: OwnedFd,
    /// Run root handed to skopeo for an explicit storage root; removed on
    /// drop, after the child has been reaped.
    _runroot: Option<tempfile::TempDir>,
}

impl Drop for SkopeoGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Send a JSON request over a `SOCK_SEQPACKET` socket and receive the reply,
/// optionally receiving a single file descriptor via `SCM_RIGHTS`.
///
/// Returns the reply value, the pipe id (meaningful only for methods that
/// deliver their payload over a pipe) and the received fd, if any.
fn proxy_call(
    sock: &OwnedFd,
    method: &str,
    args: Vec<serde_json::Value>,
) -> Result<(serde_json::Value, u32, Option<OwnedFd>)> {
    tracing::debug!("skopeo proxy -> {method}{args:?}");
    let req = Request {
        method: method.to_string(),
        args,
    };
    let sendbuf = serde_json::to_vec(&req)?;
    rustix::net::send(sock, &sendbuf, rustix::net::SendFlags::empty())?;

    let mut buf = [0u8; MAX_MSG_SIZE];
    let mut cmsg_space: Vec<std::mem::MaybeUninit<u8>> =
        vec![std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut cmsg_buffer = rustix::net::RecvAncillaryBuffer::new(cmsg_space.as_mut_slice());
    let iov = std::io::IoSliceMut::new(&mut buf);
    let mut iov = [iov];
    let nread = rustix::net::recvmsg(
        sock,
        &mut iov,
        &mut cmsg_buffer,
        rustix::net::RecvFlags::CMSG_CLOEXEC,
    )?
    .bytes;

    let received_fd: Option<OwnedFd> = cmsg_buffer
        .drain()
        .filter_map(|m| match m {
            rustix::net::RecvAncillaryMessage::ScmRights(fds) => Some(fds),
            _ => None,
        })
        .flatten()
        .next();

    let reply: Reply = serde_json::from_slice(&buf[..nread])
        .with_context(|| format!("parsing reply for {method}"))?;
    if !reply.success {
        tracing::debug!("skopeo proxy <- {method} failed: {}", reply.error);
        anyhow::bail!("skopeo proxy {method} failed: {}", reply.error);
    }
    tracing::debug!(
        "skopeo proxy <- {method} ok ({nread} bytes, fd: {})",
        if received_fd.is_some() { "yes" } else { "no" }
    );

    Ok((reply.value, reply.pipeid, received_fd))
}

/// Perform a proxy call whose payload is delivered over a pipe, and return
/// that payload.
///
/// The proxy only closes the write end of the pipe when `FinishPipe` is
/// called, so a payload larger than the pipe buffer would deadlock if we read
/// it to EOF first; the read therefore runs on its own thread, concurrently
/// with `FinishPipe`.
fn proxy_call_bytes(sock: &OwnedFd, method: &str, args: Vec<serde_json::Value>) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let (_value, pipeid, fd) = proxy_call(sock, method, args)?;
    let fd = fd.with_context(|| format!("{method} did not return a pipe fd"))?;

    let reader = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut payload = Vec::new();
        std::fs::File::from(fd).read_to_end(&mut payload)?;
        Ok(payload)
    });

    let finished = proxy_call(sock, "FinishPipe", vec![pipeid.into()]);

    let payload = reader
        .join()
        .map_err(|_| anyhow::anyhow!("{method} pipe reader thread panicked"))?
        .with_context(|| format!("reading {method} payload"))?;
    finished.with_context(|| format!("FinishPipe after {method}"))?;

    tracing::debug!("skopeo proxy <- {method} payload: {} bytes", payload.len());
    Ok(payload)
}

/// An open skopeo image proxy session: the image's manifest and config as
/// served by the proxy, plus a varlink connection for transferring layers.
pub(crate) struct SkopeoSession {
    /// `org.composefs.Oci` varlink connection, for `GetLayer`.
    pub conn: zlink::tokio::unix::Connection,
    /// Raw OCI manifest JSON, converted to OCI format by the proxy.
    pub manifest: String,
    /// Raw OCI config JSON, converted to OCI format by the proxy.
    pub config: String,
    /// Keeps the skopeo child process alive for the lifetime of the session.
    pub guard: SkopeoGuard,
}

/// Spawn skopeo's image proxy, open the given image, read its manifest and
/// config, and call `OpenVarlinkSocket` to get a varlink connection.
///
/// The manifest and config come from the proxy rather than over varlink: the
/// proxy sits on top of containers/image, so it knows which instance of a
/// manifest list applies and converts docker schema2 to OCI for us.
///
/// `imgref` is passed to the proxy verbatim, so it has to be a reference the
/// `containers-storage` transport accepts: a name, or an image ID written as
/// `@<id>`.  Note that podman's display form for an ID, `sha256:<hex>`, is
/// *not* one of those - the transport reads it as the name `sha256` with the
/// tag `<hex>`.
///
/// `storage_root` and `additional_image_stores` select a store other than the
/// default one.  An explicit root is spelled into the reference as
/// `[overlay@root+runroot:options]`; additional stores alone are passed through
/// `STORAGE_OPTS`, so that the default root is kept.
pub(crate) fn open_skopeo_varlink(
    imgref: &str,
    storage_root: Option<&std::path::Path>,
    additional_image_stores: &[&std::path::Path],
) -> Result<SkopeoSession> {
    use std::process::{Command, Stdio};

    let mut options = Vec::new();
    for store in additional_image_stores {
        let store = store
            .to_str()
            .filter(|s| !s.contains([',', ':', ']']))
            .with_context(|| format!("unsupported additional image store {store:?}"))?;
        options.push(format!("additionalimagestore={store}"));
    }
    let mut runroot = None;
    let mut storage_opts = None;
    let imgref = match (storage_root, imgref.strip_prefix("containers-storage:")) {
        (Some(root), Some(rest)) => {
            anyhow::ensure!(
                !rest.starts_with('['),
                "storage_root given together with a storage location in {imgref}"
            );
            let root = root
                .to_str()
                .filter(|s| !s.contains(['+', ':', ']']))
                .with_context(|| format!("unsupported storage root {root:?}"))?;
            let run = tempfile::tempdir().context("creating run root for skopeo")?;
            // An empty option after the colon is rejected, so leave the colon
            // out when there are no options.
            let options = match options.is_empty() {
                true => String::new(),
                false => format!(":{}", options.join(",")),
            };
            let spec = format!(
                "containers-storage:[overlay@{root}+{}{options}]{rest}",
                run.path().display(),
            );
            runroot = Some(run);
            spec
        }
        _ => {
            if !options.is_empty() {
                storage_opts = Some(options.join(","));
            }
            imgref.to_owned()
        }
    };
    let imgref = imgref.as_str();

    let (my_sock, their_sock) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;

    // Rootless, the store can only be read from inside podman's user
    // namespace; see https://github.com/containers/skopeo/issues/2563
    let mut cmd = if rustix::process::geteuid().is_root() {
        Command::new("skopeo")
    } else {
        let mut cmd = Command::new("podman");
        cmd.args(["unshare", "skopeo"]);
        cmd
    };
    cmd.arg("experimental-image-proxy");
    if let Some(opts) = storage_opts {
        cmd.env("STORAGE_OPTS", opts);
    }
    cmd.stdin(Stdio::from(their_sock));
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().context("failed to spawn skopeo")?;
    // `cmd` still owns a copy of the proxy's end of the socket; drop it so
    // that we see a disconnect if skopeo exits before replying.
    drop(cmd);
    let sock: OwnedFd = my_sock;
    // Reap the child on every error path from here on.
    let mut guard = SkopeoGuard {
        child,
        _sock: sock,
        _runroot: runroot,
    };
    tracing::debug!(
        "spawned `skopeo experimental-image-proxy` as pid {}",
        guard.child.id()
    );

    // Drain the child's stderr on a thread and forward it to the log.  Nothing
    // else reads this pipe, so without a drainer skopeo would block once it
    // filled the pipe buffer — and its diagnostics would be lost either way.
    if let Some(stderr) = guard.child.stderr.take() {
        std::thread::spawn(move || {
            use std::io::BufRead as _;
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                tracing::debug!("skopeo stderr: {line}");
            }
        });
    }

    let sock = &guard._sock;

    // Initialize — verify protocol version ≥ 0.2.9
    let (version_val, _, _) = proxy_call(sock, "Initialize", vec![])?;
    let version_str: String = serde_json::from_value(version_val)?;
    let version = semver::Version::parse(&version_str)?;
    let required = semver::VersionReq::parse(">=0.2.9")?;
    anyhow::ensure!(
        required.matches(&version),
        "skopeo proxy version {version} too old, need >=0.2.9 for OpenVarlinkSocket"
    );
    tracing::debug!("skopeo proxy protocol version {version}");

    // OpenImage
    let (img_val, _, _) = proxy_call(sock, "OpenImage", vec![imgref.into()])?;
    let img_id: u64 = serde_json::from_value(img_val).context("parsing OpenImage reply")?;

    // The manifest is normalised to OCI by the proxy, which also rejects
    // schema1 and picks the right instance of a manifest list.
    let manifest = proxy_call_bytes(sock, "GetManifest", vec![img_id.into()])?;
    let manifest = String::from_utf8(manifest).context("manifest is not valid UTF-8")?;

    // The config has to be the blob the manifest points at, byte for byte:
    // it is stored under its own digest and looked up again by the digest in
    // the manifest.  GetFullConfig would re-serialize it, so fetch the blob.
    let config_descriptor = ImageManifest::from_reader(manifest.as_bytes())
        .context("parsing manifest")?
        .config()
        .clone();
    let config = proxy_call_bytes(
        sock,
        "GetBlob",
        vec![
            img_id.into(),
            config_descriptor.digest().to_string().into(),
            config_descriptor.size().into(),
        ],
    )?;
    // The proxy converts docker schema2 manifests to OCI, which can change
    // the config bytes (and so its digest), while GetBlob serves the original
    // blob.  Refuse a mismatch rather than store a config its manifest does
    // not describe.
    let actual = crate::sha256_content_digest(&config);
    anyhow::ensure!(
        &actual == config_descriptor.digest(),
        "config blob digest {actual} does not match the manifest's {}; \
         the image's config was probably altered by the proxy's manifest conversion",
        config_descriptor.digest()
    );
    let config = String::from_utf8(config).context("config is not valid UTF-8")?;

    // OpenVarlinkSocket — returns a socket fd via SCM_RIGHTS, serving the
    // store the image reference names.
    let store_spec = store_spec(imgref);
    let (_, _, varlink_fd) = proxy_call(sock, "OpenVarlinkSocket", vec![store_spec.into()])?;
    let varlink_fd = varlink_fd.context("OpenVarlinkSocket did not return an fd")?;
    tracing::debug!("got org.composefs.Oci varlink socket from skopeo for {imgref}");

    // Wrap as a zlink Connection
    let std_stream = UnixStream::from(varlink_fd);
    std_stream.set_nonblocking(true)?;
    let tokio_stream = tokio::net::UnixStream::from_std(std_stream)?;
    let zlink_stream =
        zlink::tokio::unix::Stream::try_from(tokio_stream).map_err(std::io::Error::other)?;
    let conn = zlink::Connection::new(zlink_stream);

    Ok(SkopeoSession {
        conn,
        manifest,
        config,
        guard,
    })
}

/// Return the `[driver@graphroot+runroot:options]` store specifier at the
/// start of a `containers-storage:` reference, or `""` (the default store)
/// if there is none.
fn store_spec(imgref: &str) -> &str {
    let rest = crate::cstor::parse_containers_storage_ref(imgref).unwrap_or(imgref);
    if rest.starts_with('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..=end];
        }
    }
    ""
}

/// Full result of a skopeo varlink import: manifest and config digests + verities.
type SkopeoImportResult<ObjectID> = (ContentAndVerity<ObjectID>, ContentAndVerity<ObjectID>);

/// Import a container image from containers-storage via skopeo's varlink socket.
///
/// This spawns a `skopeo experimental-image-proxy`, opens the image, obtains a
/// varlink socket via `OpenVarlinkSocket`, then transfers each layer via
/// `GetLayer` and finalizes the OCI image in the repository.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn import_via_skopeo_proxy<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    storage_root: Option<&std::path::Path>,
    additional_image_stores: &[&std::path::Path],
    reference: Option<&str>,
    zerocopy: bool,
    boot_options: Option<&composefs::generic_tree::OciTransformOptions>,
    reporter: SharedReporter,
) -> Result<(SkopeoImportResult<ObjectID>, ImportStats)> {
    let mut stats = ImportStats::default();
    let mut ctx = ImportContext::default();

    // Spawn skopeo, open the image and get its manifest, config and the
    // varlink connection (blocking I/O).
    let imgref_owned = imgref.to_owned();
    let storage_root = storage_root.map(|p| p.to_path_buf());
    let stores: Vec<std::path::PathBuf> = additional_image_stores
        .iter()
        .map(|p| p.to_path_buf())
        .collect();
    let SkopeoSession {
        mut conn,
        manifest,
        config,
        guard: _guard,
    } = tokio::task::spawn_blocking(move || {
        let stores: Vec<&std::path::Path> = stores.iter().map(|p| p.as_path()).collect();
        open_skopeo_varlink(&imgref_owned, storage_root.as_deref(), &stores)
    })
    .await
    .context("spawn_blocking(open_skopeo_varlink) failed")??;

    // The OCI diff-ids from the config are what identifies a layer, both to
    // the server (Oci.GetLayer resolves them against containers-storage) and
    // to us in the composefs repo.
    let diff_ids =
        crate::extract_layer_ids(&manifest, &config).context("extracting layer IDs from config")?;
    let diff_ids: Vec<OciDigest> = diff_ids
        .iter()
        .map(|s| s.parse::<OciDigest>().context("parsing diff_id"))
        .collect::<Result<_>>()?;

    stats.layers = diff_ids.len() as u64;

    // Import each layer via the varlink connection.
    let mut layer_refs = Vec::with_capacity(diff_ids.len());
    for diff_id in diff_ids.iter() {
        let content_id = layer_identifier(diff_id);
        let id = ComponentId::from(diff_id.to_string());

        let layer_verity = if let Some(existing) = repo.has_stream(&content_id)? {
            tracing::debug!("layer {diff_id} already present, skipping Oci.GetLayer");
            reporter.report(ProgressEvent::Skipped { id });
            stats.layers_already_present += 1;
            existing
        } else {
            reporter.report(ProgressEvent::Started {
                id: id.clone(),
                total: None,
                unit: ProgressUnit::Bytes,
            });
            let params = GetLayerParams {
                diff_id: Some(diff_id.to_string()),
                storage: None,
                // Conservative: let the skopeo-side producer inline
                // non-world-readable files rather than hand us dirfd
                // references we may not be able to open.
                consumer_has_cap_dac_override: false,
            };
            let (verity, layer_stats) = crate::cstor::import_layer_via_transfer(
                repo, &mut conn, params, diff_id, zerocopy, &mut ctx,
            )
            .await?;
            let bytes = layer_stats.new_bytes();
            stats.merge(&layer_stats);
            reporter.report(ProgressEvent::Done {
                id,
                transferred: bytes,
            });
            verity
        };

        layer_refs.push((diff_id.clone(), layer_verity));
    }

    reporter.report(ProgressEvent::Message("Layers imported".to_string()));

    // Finalize the OCI image
    let repo2 = Arc::clone(repo);
    let manifest_json = manifest.into_bytes();
    let config_json = config.into_bytes();
    let reference_owned = reference.map(|s| s.to_owned());
    let reporter2 = reporter.clone();
    let boot_options_owned = boot_options.cloned();

    let (result, final_stats) = tokio::task::spawn_blocking(move || {
        reporter2.report(ProgressEvent::Message("Finalizing image".to_string()));
        let result = crate::layer_sync::finalize_oci_image(
            &repo2,
            &manifest_json,
            &config_json,
            &layer_refs,
            reference_owned.as_deref(),
            boot_options_owned.as_ref(),
        )
        .context("finalize_oci_image")?;
        Ok::<_, anyhow::Error>((result, stats))
    })
    .await
    .context("spawn_blocking(finalize_oci_image) failed")??;

    Ok((result, final_stats))
}

#[cfg(test)]
mod tests {
    use super::store_spec;

    #[test]
    fn test_store_spec() {
        assert_eq!(store_spec("containers-storage:busybox"), "");
        assert_eq!(store_spec("containers-storage:@abc123"), "");
        assert_eq!(
            store_spec("containers-storage:[overlay@/var/lib/containers/storage]busybox"),
            "[overlay@/var/lib/containers/storage]"
        );
        assert_eq!(
            store_spec("containers-storage:[/srv/storage+/run/storage:opt=1]@abc123"),
            "[/srv/storage+/run/storage:opt=1]"
        );
        // Malformed specifier: leave it for the proxy to reject.
        assert_eq!(store_spec("containers-storage:[/srv/storage"), "");
    }
}
