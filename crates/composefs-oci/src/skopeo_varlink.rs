//! Import container images via skopeo's image proxy + varlink socket.
//!
//! This module starts a `skopeo experimental-image-proxy` through
//! [`containers_image_proxy`], opens a `containers-storage:` image through it,
//! then asks for a socket speaking the `org.composefs.Oci` varlink protocol.
//! Layers are transferred via `GetLayer` over that socket, reusing the same
//! `import_layer_via_transfer` path as the in-process cstor import.

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use anyhow::{Context, Result};
use containers_image_proxy::oci_spec::image::ImageManifest;
use containers_image_proxy::{ImageProxy, ImageProxyConfig};
use tokio::io::AsyncReadExt as _;

use composefs::{
    fsverity::FsVerityHashValue,
    repository::{ImportContext, Repository},
};

use crate::progress::{ComponentId, ProgressEvent, ProgressUnit, SharedReporter};
use crate::varlink_types::GetLayerParams;
use crate::{ContentAndVerity, ImportStats, OciDigest, layer_identifier};

/// The installed skopeo does not implement `OpenVarlinkSocket`.  Callers can
/// detect it with `downcast_ref` and fall back to another import path.
#[derive(Debug)]
pub(crate) struct SkopeoTooOld(String);

impl std::fmt::Display for SkopeoTooOld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "skopeo proxy version {} too old, need >=0.2.9 for OpenVarlinkSocket",
            self.0
        )
    }
}

impl std::error::Error for SkopeoTooOld {}

/// An open skopeo image proxy session: the image's manifest and config as
/// served by the proxy, plus a varlink connection for transferring layers.
pub(crate) struct SkopeoSession {
    /// `org.composefs.Oci` varlink connection, for `GetLayer`.
    pub conn: zlink::tokio::unix::Connection,
    /// Raw OCI manifest JSON, converted to OCI format by the proxy.
    pub manifest: String,
    /// Raw OCI config JSON, converted to OCI format by the proxy.
    pub config: String,
    /// The proxy; dropping it closes the socket, which makes skopeo exit.
    pub proxy: ImageProxy,
    /// Run root handed to skopeo for an explicit storage root.  Declared
    /// after `proxy` so that it is removed only once the proxy is gone.
    _runroot: Option<tempfile::TempDir>,
}

/// Start skopeo's image proxy, open the given image, read its manifest and
/// config, and get a varlink connection to it.
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
pub(crate) async fn open_skopeo_varlink(
    imgref: &str,
    storage_root: Option<&std::path::Path>,
    additional_image_stores: &[&std::path::Path],
) -> Result<SkopeoSession> {
    use std::process::Command;

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

    // Rootless, the store can only be read from inside podman's user
    // namespace; see https://github.com/containers/skopeo/issues/2563
    let mut cmd = if rustix::process::geteuid().is_root() {
        Command::new("skopeo")
    } else {
        let mut cmd = Command::new("podman");
        cmd.args(["unshare", "skopeo"]);
        cmd
    };
    if let Some(opts) = storage_opts {
        // Setting the variable replaces the inherited one; keep its options.
        let inherited = std::env::var("STORAGE_OPTS").ok();
        cmd.env(
            "STORAGE_OPTS",
            append_storage_opts(inherited.as_deref(), &opts),
        );
    }
    let mut config = ImageProxyConfig::default();
    config.skopeo_cmd = Some(cmd);

    let proxy = ImageProxy::new_with_config(config)
        .await
        .context("starting skopeo image proxy")?;
    if !proxy.supports_open_varlink_socket() {
        return Err(SkopeoTooOld(proxy.protocol_version().to_string()).into());
    }

    let img = proxy
        .open_image(&imgref)
        .await
        .with_context(|| format!("opening {imgref}"))?;

    // The manifest is normalised to OCI by the proxy, which also rejects
    // schema1 and picks the right instance of a manifest list.
    let (_, manifest) = proxy
        .fetch_manifest_raw_oci(&img)
        .await
        .context("fetching manifest")?;
    let config_descriptor = ImageManifest::from_reader(manifest.as_slice())
        .context("parsing manifest")?
        .config()
        .clone();
    let manifest = String::from_utf8(manifest).context("manifest is not valid UTF-8")?;

    // The config has to be the blob the manifest points at, byte for byte:
    // it is stored under its own digest and looked up again by the digest in
    // the manifest.  For an OCI image that is the blob itself.
    let digest = config_descriptor.digest();
    let blob = async {
        let (mut reader, driver) = proxy
            .get_blob(&img, digest, config_descriptor.size())
            .await?;
        let mut config = Vec::new();
        let (read, finished) = tokio::join!(reader.read_to_end(&mut config), driver);
        read?;
        finished?;
        anyhow::Ok(config)
    }
    .await;
    let config = match blob {
        Ok(config) if &crate::sha256_content_digest(&config) == digest => config,
        blob => {
            // The proxy converts a docker schema2 image to OCI, and the config
            // the converted manifest points at is a re-serialization of the
            // original, which is not a blob of the image and so can only be had
            // from the proxy.
            match &blob {
                Ok(_) => tracing::debug!("config blob does not match {digest}"),
                Err(e) => tracing::debug!("fetching config blob {digest}: {e:#}"),
            }
            let config = proxy
                .fetch_config_raw(&img)
                .await
                .context("fetching config")?;
            let actual = crate::sha256_content_digest(&config);
            anyhow::ensure!(
                &actual == digest,
                "the image's config has digest {actual}, not the manifest's {digest}"
            );
            config
        }
    };
    let config = String::from_utf8(config).context("config is not valid UTF-8")?;

    // Serves the layers of the image we opened, by position.
    let varlink_fd = proxy
        .open_varlink_socket(&img)
        .await
        .context("OpenVarlinkSocket")?;
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
        proxy,
        _runroot: runroot,
    })
}

/// `inherited` `STORAGE_OPTS`, if any, followed by `opts`.
fn append_storage_opts(inherited: Option<&str>, opts: &str) -> String {
    match inherited.filter(|i| !i.is_empty()) {
        Some(inherited) => format!("{inherited},{opts}"),
        None => opts.to_owned(),
    }
}

/// Check that the config lists a diff ID for each layer of the manifest.
///
/// Layers are fetched by position and verified against the diff ID at that
/// position, so a config that lists only some of the layers would otherwise
/// import just those, and leave an image with layers missing.
fn ensure_same_layer_count(manifest: &str, diff_ids: &[OciDigest]) -> Result<()> {
    let layers = ImageManifest::from_reader(manifest.as_bytes())
        .context("parsing manifest")?
        .layers()
        .len();
    anyhow::ensure!(
        layers == diff_ids.len(),
        "the manifest has {layers} layers but the config lists {} diff IDs",
        diff_ids.len()
    );
    Ok(())
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
    // The files belong to containers-storage, which is not ours to hardlink.
    let mut ctx = ImportContext::default().forbid_hardlinks();

    // Start skopeo, open the image and get its manifest, config and the
    // varlink connection.
    let SkopeoSession {
        mut conn,
        manifest,
        config,
        proxy,
        _runroot,
    } = open_skopeo_varlink(imgref, storage_root, additional_image_stores).await?;

    // The OCI diff-ids from the config are what identifies a layer in the
    // composefs repo.  The server is asked for layers by position instead:
    // only containers-storage knows which of its layers make up the image,
    // and each one is verified against its diff-id as it is drained.
    let diff_ids =
        crate::extract_layer_ids(&manifest, &config).context("extracting layer IDs from config")?;
    let diff_ids: Vec<OciDigest> = diff_ids
        .iter()
        .map(|s| s.parse::<OciDigest>().context("parsing diff_id"))
        .collect::<Result<_>>()?;

    ensure_same_layer_count(&manifest, &diff_ids)?;

    stats.layers = diff_ids.len() as u64;

    // Import each layer via the varlink connection.
    let mut layer_refs = Vec::with_capacity(diff_ids.len());
    for (layer_index, diff_id) in diff_ids.iter().enumerate() {
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
                diff_id: None,
                storage: None,
                // Without it, the producer inlines files we could not open.
                consumer_has_cap_dac_override: cstorage::can_bypass_file_permissions(),
                layer_index: Some(layer_index as u64),
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

    // Done with skopeo: shut it down and reap it before the run root goes away.
    drop(conn);
    proxy.finalize().await.context("shutting down skopeo")?;

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
mod layer_count_tests {
    use super::ensure_same_layer_count;
    use crate::OciDigest;

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn manifest(layers: usize) -> String {
        let layer = format!(
            r#"{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{DIGEST}","size":1}}"#
        );
        let layers = vec![layer; layers].join(",");
        format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{DIGEST}","size":1}},"layers":[{layers}]}}"#
        )
    }

    #[test]
    fn test_ensure_same_layer_count() {
        let ids = |n: usize| -> Vec<OciDigest> { vec![DIGEST.parse().unwrap(); n] };
        assert!(ensure_same_layer_count(&manifest(2), &ids(2)).is_ok());
        assert!(ensure_same_layer_count(&manifest(0), &ids(0)).is_ok());
        // a prefix of the layers
        let e = ensure_same_layer_count(&manifest(3), &ids(2)).unwrap_err();
        assert!(e.to_string().contains("3 layers"), "{e}");
        // more diff IDs than layers
        assert!(ensure_same_layer_count(&manifest(1), &ids(2)).is_err());
    }
}

#[cfg(test)]
mod storage_opts_tests {
    use super::append_storage_opts;

    #[test]
    fn test_append_storage_opts() {
        let ours = "additionalimagestore=/extra";
        assert_eq!(append_storage_opts(None, ours), ours);
        assert_eq!(append_storage_opts(Some(""), ours), ours);
        assert_eq!(
            append_storage_opts(Some("additionalimagestore=/host"), ours),
            "additionalimagestore=/host,additionalimagestore=/extra"
        );
    }
}
