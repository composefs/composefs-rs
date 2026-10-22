//! containers-storage import support.
//!
//! Images in containers-storage are imported through skopeo's image proxy and
//! its `OpenVarlinkSocket` method (see `skopeo_varlink`).  This module holds
//! the pieces that import path shares: recognising a `containers-storage:`
//! reference and draining a layer received over the `org.composefs.Oci`
//! varlink socket into the repository.
//!
//! This module requires the `containers-storage` feature to be enabled.

use std::os::unix::io::OwnedFd;
use std::sync::Arc;

use anyhow::{Context, Result};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::{ImportContext, Repository},
};

use crate::varlink_types::{GetLayerParams, OciProxy as _};
use crate::{ImportStats, OciDigest};

/// Import a single layer from an `org.composefs.Oci` zlink service.
///
/// Calls `get_layer(0, params)`,
/// collects all frames, then drains the `splitdirfdstream` pipe in a
/// `spawn_blocking` closure while the server-side producer fills the pipe
/// concurrently on its own thread.
pub(crate) async fn import_layer_via_transfer<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    client: &mut zlink::tokio::unix::Connection,
    params: GetLayerParams,
    diff_id: &OciDigest,
    zerocopy: bool,
    ctx: &mut ImportContext,
) -> Result<(ObjectID, ImportStats)> {
    let label = diff_id.to_string();
    let stream = client
        .get_layer(0, params)
        .await
        .with_context(|| format!("Oci.GetLayer RPC failed for {label}"))?;

    // Collect all frames.  Each frame carries a batch of FDs; concatenate them
    // in arrival order to reconstruct the full logical FD array:
    //   index 0             : pipe read end
    //   index 1..=dir_count : dirfds region (sparse — may include dummy slots)
    //   index dir_count+1.. : opaque lifetime FDs (keepalive + optional extras)
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut reply_opt: Option<crate::varlink_types::GetLayerReply> = None;
    {
        use zlink::futures_util::StreamExt as _;
        let mut stream = std::pin::pin!(stream);
        while let Some(item) = stream.next().await {
            let (result, frame_fds) =
                item.with_context(|| format!("Oci.GetLayer stream error for {label}"))?;
            let frame_reply = result.map_err(|e| anyhow::anyhow!("Oci.GetLayer error: {e:?}"))?;
            reply_opt = Some(frame_reply);
            fds.extend(frame_fds);
        }
    }
    let reply = reply_opt.ok_or_else(|| anyhow::anyhow!("Oci.GetLayer yielded no frames"))?;

    // At minimum: 1 pipe fd + dir_count slots + 1 keepalive fd.
    anyhow::ensure!(
        fds.len() >= reply.dir_count as usize + 2,
        "Oci.GetLayer: expected at least {} fds (1 pipe + {} dirfd slots + 1 keepalive), got {}",
        2 + reply.dir_count,
        reply.dir_count,
        fds.len()
    );

    // Split into: pipe_read | dir_fds[dir_count] | lifetime_fds...
    let mut it = fds.into_iter();
    let pipe_read: OwnedFd = it.next().expect("checked above: fds.len() >= 1");
    let dir_fds: Vec<OwnedFd> = it.by_ref().take(reply.dir_count as usize).collect();
    // Opaque lifetime tokens — hold open until drain completes, then drop to
    // signal the server's producer that we are done consuming the layer.
    let lifetime_fds: Vec<OwnedFd> = it.collect();

    // Drain the pipe in a blocking task (producer runs concurrently on the
    // server's spawn_blocking thread).  ImportContext is threaded through.
    let repo_clone = Arc::clone(repo);
    let diff_id_owned = diff_id.clone();
    let ctx_moved = std::mem::take(ctx);

    let (verity, layer_stats, ctx_returned) = tokio::task::spawn_blocking(move || {
        // Hold all lifetime FDs for the full duration of the drain.
        let _lifetime_fds = lifetime_fds;
        // The producer is another program reading another store: what it
        // sends is only trusted once it hashes to the diff ID we asked for.
        crate::layer_sync::drain_splitdirfdstream_verified(
            repo_clone,
            pipe_read,
            dir_fds,
            &diff_id_owned,
            zerocopy,
            ctx_moved,
        )
    })
    .await
    .context("spawn_blocking(drain_splitdirfdstream_verified) failed")?
    .with_context(|| format!("importing layer {label}"))?;

    *ctx = ctx_returned;

    Ok((verity, layer_stats))
}

/// Check if an image reference uses the containers-storage transport.
///
/// Returns the image ID portion if the reference starts with "containers-storage:",
/// otherwise returns None.
pub fn parse_containers_storage_ref(imgref: &str) -> Option<&str> {
    imgref.strip_prefix("containers-storage:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_containers_storage_ref() {
        assert_eq!(
            parse_containers_storage_ref("containers-storage:sha256:abc123"),
            Some("sha256:abc123")
        );
        assert_eq!(
            parse_containers_storage_ref("containers-storage:quay.io/fedora:latest"),
            Some("quay.io/fedora:latest")
        );
        assert_eq!(
            parse_containers_storage_ref("docker://quay.io/fedora:latest"),
            None
        );
        assert_eq!(parse_containers_storage_ref("sha256:abc123"), None);
    }
}
