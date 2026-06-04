//! Client for importing container images and layers from a splitfdstream server.
//!
//! Uses the `jsonrpc-fdpass` crate for the JSON-RPC 2.0 + SCM_RIGHTS protocol.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use containers_image_proxy::oci_spec::image::{ImageConfiguration, ImageManifest};
use jsonrpc_fdpass::{JsonRpcMessage, JsonRpcRequest, MessageWithFds, UnixSocketTransport};
use tokio::net::UnixStream;

use composefs::fsverity::FsVerityHashValue;
use composefs::repository::Repository;
use splitfdstream::{Chunk, SplitfdstreamReader};

use crate::skopeo::TAR_LAYER_CONTENT_TYPE;

/// Send a JSON-RPC request and receive the response with file descriptors.
async fn rpc_call(
    socket_path: &Path,
    method: &str,
    params: serde_json::Value,
) -> Result<(serde_json::Value, Vec<OwnedFd>)> {
    let stream = UnixStream::connect(socket_path)
        .await
        .context("connecting to splitfdstream server")?;

    let transport = UnixSocketTransport::new(stream);
    let (mut sender, mut receiver) = transport.split();

    let request = JsonRpcRequest::new(method.to_string(), Some(params), serde_json::json!(1));
    let message = MessageWithFds::new(JsonRpcMessage::Request(request), Vec::new());
    sender.send(message).await.context("sending request")?;

    let response = receiver.receive().await.context("receiving response")?;

    let resp_value = response
        .message
        .to_json_value()
        .context("converting response to value")?;

    if let Some(err) = resp_value.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        bail!("splitfdstream server error: {msg}");
    }

    Ok((resp_value, response.file_descriptors))
}

/// Import a container layer from a splitfdstream server into the repository.
///
/// Receives file descriptors from the server and stores each one to the
/// repository immediately (then closes it) to avoid hitting the per-process
/// file descriptor limit.
pub fn import_from_splitfdstream<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    socket_path: impl AsRef<Path>,
    diff_id: &str,
    layer_id: Option<&str>,
    parent_id: Option<&str>,
    reference: Option<&str>,
) -> Result<ObjectID> {
    let effective_layer_id = layer_id.unwrap_or(diff_id);
    let mut params = serde_json::json!({ "layerId": effective_layer_id });
    if let Some(pid) = parent_id {
        params["parentId"] = serde_json::json!(pid);
    }

    let rt = tokio::runtime::Handle::try_current()
        .map(|h| {
            // We're inside an async runtime but called synchronously;
            // spawn a blocking task context so we can block_on.
            h
        })
        .ok();

    let (resp_value, mut fds) = if let Some(handle) = rt {
        tokio::task::block_in_place(|| {
            handle.block_on(rpc_call(socket_path.as_ref(), "GetSplitFDStream", params))
        })?
    } else {
        let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
        rt.block_on(rpc_call(socket_path.as_ref(), "GetSplitFDStream", params))?
    };

    let _ = resp_value; // error checking done inside rpc_call

    // allFDs[0] is a memfd with the stream data; allFDs[1:] are content FDs.
    if fds.is_empty() {
        bail!("no file descriptors received in response");
    }

    // Read the stream data from the first FD (memfd).
    let stream_fd = fds.remove(0);
    let mut stream_file = File::from(stream_fd);
    let mut stream_data = Vec::new();
    stream_file
        .read_to_end(&mut stream_data)
        .context("reading stream data from memfd")?;

    // Store content FDs to the repository immediately.
    let mut stored_objects: Vec<(ObjectID, u64)> = Vec::new();
    let mut copy_buf = vec![0u8; 1024 * 1024];
    for fd in fds {
        let stat = rustix::fs::fstat(&fd).context("fstat on received fd")?;
        let size = stat.st_size as u64;
        let (object_id, _method) = repo
            .ensure_object_from_fd_reflink(fd, size, &mut copy_buf)
            .context("storing fd to repository")?;
        stored_objects.push((object_id, size));
    }

    // Parse the splitfdstream and build a composefs splitstream.
    let diff_digest: crate::OciDigest = diff_id.parse().context("parsing diff_id as digest")?;
    let content_identifier = crate::layer_identifier(&diff_digest);
    let (object_id, _) = repo.ensure_stream(
        &content_identifier,
        TAR_LAYER_CONTENT_TYPE,
        |writer| {
            let mut reader = SplitfdstreamReader::new(Cursor::new(&stream_data));
            while let Some(chunk) = reader.next_chunk().context("reading splitfdstream chunk")? {
                match chunk {
                    Chunk::Inline(data) => {
                        writer.write_inline(data);
                    }
                    Chunk::External(fd_index) => {
                        let idx = fd_index as usize;
                        if idx >= stored_objects.len() {
                            bail!(
                                "splitfdstream references fd index {idx} \
                                 but only {} content fds received",
                                stored_objects.len()
                            );
                        }
                        let (ref object_id, size) = stored_objects[idx];
                        writer.add_external_size(size);
                        writer.write_reference(object_id.clone())?;
                    }
                }
            }
            Ok(())
        },
        reference,
    )?;
    Ok(object_id)
}

/// Result of importing a complete image via splitfdstream.
#[derive(Debug)]
pub struct CompleteImageImportResult<ObjectID> {
    /// SHA-256 digest of the manifest.
    pub manifest_digest: String,
    /// fs-verity hash of the stored manifest.
    pub manifest_verity: ObjectID,
    /// SHA-256 digest of the config.
    pub config_digest: String,
    /// fs-verity hash of the stored config.
    pub config_verity: ObjectID,
    /// Per-layer (diff_id, fs-verity hash) pairs.
    pub layer_verities: Vec<(String, ObjectID)>,
    /// Number of layers imported.
    pub layers_imported: usize,
    /// Total compressed size in bytes across all layers.
    pub total_size_bytes: u64,
}

/// Import a complete OCI image from a splitfdstream server into the repository.
///
/// Fetches image metadata (manifest, config, layer IDs) via the `GetImage` RPC,
/// then imports each layer individually via `GetSplitFDStream` calls.
pub fn import_complete_image_from_splitfdstream<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    socket_path: impl AsRef<Path>,
    image_id: &str,
    reference: Option<&str>,
) -> Result<CompleteImageImportResult<ObjectID>> {
    let params = serde_json::json!({ "imageId": image_id });

    let rt = tokio::runtime::Handle::try_current().ok();
    let (resp_value, _fds) = if let Some(handle) = rt {
        tokio::task::block_in_place(|| {
            handle.block_on(rpc_call(socket_path.as_ref(), "GetImage", params))
        })?
    } else {
        let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
        rt.block_on(rpc_call(socket_path.as_ref(), "GetImage", params))?
    };

    let result = resp_value
        .get("result")
        .context("missing 'result' in response")?;

    let manifest_json = result
        .get("manifest")
        .and_then(|v| v.as_str())
        .context("missing 'manifest' in response")?;
    let config_json = result
        .get("config")
        .and_then(|v| v.as_str())
        .context("missing 'config' in response")?;
    let storage_layer_ids: Vec<String> = result
        .get("layerDigests")
        .and_then(|v| v.as_array())
        .context("missing 'layerDigests' in response")?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();

    let manifest: ImageManifest =
        serde_json::from_str(manifest_json).context("parsing image manifest")?;
    let config: ImageConfiguration =
        serde_json::from_str(config_json).context("parsing image configuration")?;

    let manifest_digest = crate::sha256_content_digest(manifest_json.as_bytes());
    let config_digest = crate::sha256_content_digest(config_json.as_bytes());

    let layers = manifest.layers();
    let diff_ids = config.rootfs().diff_ids();

    if storage_layer_ids.len() != layers.len() {
        bail!(
            "server returned {} storage layer IDs but manifest has {} layers",
            storage_layer_ids.len(),
            layers.len()
        );
    }
    if storage_layer_ids.len() != diff_ids.len() {
        bail!(
            "server returned {} storage layer IDs but config has {} diff IDs",
            storage_layer_ids.len(),
            diff_ids.len()
        );
    }

    let mut imported_layers = Vec::new();
    let mut total_size_bytes = 0u64;

    for (i, (layer_desc, diff_id)) in layers.iter().zip(diff_ids.iter()).enumerate() {
        let layer_verity = import_from_splitfdstream(
            repo,
            &socket_path,
            diff_id,
            Some(&storage_layer_ids[i]),
            None,
            None,
        )?;

        imported_layers.push((diff_id.to_string(), layer_verity));
        total_size_bytes += layer_desc.size();
    }

    let mut layer_refs = HashMap::new();
    for (diff_id, (_, layer_verity)) in diff_ids.iter().zip(&imported_layers) {
        layer_refs.insert(diff_id.clone().into_boxed_str(), layer_verity.clone());
    }

    let (_, config_verity) = crate::write_config(repo, &config, layer_refs, None, None)
        .context("storing image configuration")?;

    let mut layer_digest_to_verity = HashMap::new();
    for (layer_desc, (_, layer_verity)) in layers.iter().zip(&imported_layers) {
        layer_digest_to_verity.insert(
            layer_desc.digest().to_string().into_boxed_str(),
            layer_verity.clone(),
        );
    }

    let manifest_digest_str = manifest_digest.to_string();
    let (_, manifest_verity) = crate::oci_image::write_manifest_raw(
        repo,
        manifest_json.as_bytes(),
        &manifest_digest_str,
        &config_verity,
        &layer_digest_to_verity,
        reference,
    )
    .context("storing image manifest")?;

    let layers_imported = imported_layers.len();
    Ok(CompleteImageImportResult {
        manifest_digest: manifest_digest_str,
        manifest_verity,
        config_digest: config_digest.to_string(),
        config_verity,
        layer_verities: imported_layers,
        layers_imported,
        total_size_bytes,
    })
}
