//! Shared wire types and the `OciProxy` client trait for the
//! `org.composefs.Oci` varlink interface.
//!
//! These types are defined here (in `composefs-oci`) rather than
//! `composefs-ctl` so that both the repo-side service (`CfsctlService` in
//! composefs-ctl) and the containers-storage service (`CstorLayerService` in
//! composefs-storage) can share the same proxy trait without creating a
//! dependency cycle.
//!
//! `composefs-ctl` re-exports everything from this module; callers should
//! prefer `composefs_oci::varlink_types` or the re-exports in
//! `composefs_ctl::varlink::{layer_sync,oci::OciError,proxy::OciProxy}`.
//!
//! # Feature gate
//!
//! This module is compiled only when the `varlink` feature is enabled on
//! `composefs-oci` (which pulls in `zlink`).

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

// ── Locator for a layer inside containers-storage ────────────────────────────

/// Locator for a layer that lives inside a containers-storage store.
///
/// Both fields are required when routing a `GetLayer` call to the
/// `CstorLayerService`; the repo-side service ignores this field entirely.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct StorageLocator {
    /// Absolute path to the containers-storage root directory
    /// (e.g. `/var/lib/containers/storage`).
    pub storage_path: String,
    /// The layer ID within that storage root, as returned by
    /// `storage_layer_ids()`.
    pub layer_id: String,
}

/// Parameters for the `GetLayer` method of the `org.composefs.Oci` interface.
///
/// Exactly one of `diff_id` or `storage` must be set:
/// - **Repo service** (`CfsctlService`): reads `diff_id`, errors if `None`.
/// - **Cstor service** (`CstorLayerService`): reads `storage`, errors if `None`.
///
/// Both fields are `Option` for forward-compatibility: new locator kinds can
/// be added in future without breaking old clients.
#[derive(Debug, Clone, Default, Serialize, Deserialize, zlink::introspect::Type)]
pub struct GetLayerParams {
    /// OCI diff-id (`sha256:…`) identifying the layer in a composefs repo.
    pub diff_id: Option<String>,
    /// Location of a specific layer inside a containers-storage store.
    pub storage: Option<StorageLocator>,
    /// Whether the consumer of this layer's bytes can bypass file DAC
    /// permissions (real root or `CAP_DAC_OVERRIDE`).  When `true`, the cstor
    /// service may emit `FileBackedData` chunks even for non-world-readable
    /// files, since the consumer can open them directly.  Defaults to `false`
    /// for backward compatibility.
    #[serde(default)]
    pub consumer_has_cap_dac_override: bool,
}

// ── Reply types ───────────────────────────────────────────────────────────────

/// Reply from `GetInfo`: capability tokens supported by this service.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct GetInfoReply {
    /// Capability tokens advertised by this service instance.
    ///
    /// Currently only `"splitdirfdstream-v0"` is defined.  The cstor service
    /// additionally reports `"source-containers-storage"` and `"read-only"`.
    pub features: Vec<String>,
}

/// Reply from `HasLayer`: whether the layer is present in the repository.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct HasLayerReply {
    /// Whether the layer splitstream for the given diff-id is present.
    pub present: bool,
    /// Hex-encoded fs-verity hash of the layer splitstream, if present.
    pub layer_verity: Option<String>,
}

/// Reply from `GetLayer`: the number of diff-directory slots in the logical FD
/// array.
///
/// `GetLayer` is a **streaming** method (`more`): it yields multiple frames,
/// each carrying a batch of FDs.  The client MUST concatenate the FD batches
/// from all frames (in arrival order) to reconstruct the full logical FD array:
///
/// - `fds[0]` — data pipe read end (carries the `splitdirfdstream` bytes).
/// - `fds[1..=dir_count]` — the dirfds region (`dir_count` slots total).  The
///   real objects-directory fd sits at a sparse, hash-determined index within
///   this region; the remaining (gap) slots hold inert dummy fds that
///   `reconstruct` never dereferences.
/// - `fds[dir_count+1..]` — opaque lifetime FDs.  The client MUST hold every
///   one of these open until it has finished reading and processing all dir
///   fds, then close them all to signal completion to the server.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct GetLayerReply {
    /// Number of diff-directory file descriptors in the full logical FD array
    /// (i.e. `fds[1..=dir_count]` after concatenating all frames' batches).
    pub dir_count: u32,
}

/// Reply from `PutLayer`: the verity hash of the imported layer, whether
/// it was already present, and per-object transfer statistics.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct PutLayerReply {
    /// Hex-encoded fs-verity hash of the committed layer splitstream.
    pub layer_verity: String,
    /// `true` if the layer was already present before this call.
    pub already_present: bool,

    /// Number of objects that were reflinked (FICLONE) into the destination.
    #[serde(default)]
    pub objects_reflinked: u64,
    /// Number of objects hardlinked into the destination.
    #[serde(default)]
    pub objects_hardlinked: u64,
    /// Number of objects byte-copied into the destination.
    #[serde(default)]
    pub objects_copied: u64,
    /// Number of objects already present in the destination (skipped).
    #[serde(default)]
    pub objects_already_present: u64,
}

/// A single (diff_id, layer_verity) pair passed to `FinalizeImage`.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct LayerRef {
    /// OCI diff-id of the layer (e.g. `"sha256:abcd..."`).
    pub diff_id: String,
    /// Hex-encoded fs-verity hash of the layer splitstream in the destination
    /// repository, as returned by `PutLayer`.
    pub layer_verity: String,
}

/// Reply from `FinalizeImage`.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct FinalizeImageReply {
    /// OCI digest of the manifest.
    pub manifest_digest: String,
    /// Hex-encoded fs-verity hash of the manifest splitstream.
    pub manifest_verity: String,
    /// OCI digest of the config.
    pub config_digest: String,
    /// Hex-encoded fs-verity hash of the config splitstream.
    pub config_verity: String,
}

// ── OciError ──────────────────────────────────────────────────────────────────

/// Errors returned by the `org.composefs.Oci` interface.
#[derive(Debug, zlink::ReplyError, zlink::introspect::ReplyError)]
#[zlink(interface = "org.composefs.Oci")]
pub enum OciError {
    /// The repository could not be found or opened at the configured path.
    RepoNotFound {
        /// Description of the failure.
        message: String,
    },
    /// The given handle does not refer to an open repository.
    InvalidHandle {
        /// The handle that was not found.
        handle: u64,
    },
    /// The named OCI image/reference does not exist.
    NoSuchImage {
        /// The image reference that was not found.
        image: String,
    },
    /// An unexpected internal error occurred while servicing the request.
    InternalError {
        /// Description of the failure.
        message: String,
    },
    /// The requested layer (by diff-id) is not present in the repository.
    NoSuchLayer {
        /// The diff-id that was not found.
        diff_id: String,
    },
    /// A supplied digest/diff-id string was malformed.
    InvalidDigest {
        /// Human-readable description of the parse failure.
        message: String,
    },
    /// Received layer content did not hash to the declared diff-id.
    DiffIdMismatch {
        /// The diff_id that was declared by the client.
        expected: String,
        /// The sha256 digest of the data that was actually received.
        actual: String,
    },
    /// The request was malformed (e.g. wrong fd count).
    InvalidRequest {
        /// Human-readable description of what was wrong.
        message: String,
    },
    /// The total fd count exceeds the per-frame cap for a `more=false` call.
    FdLimitExceeded {
        /// Total number of fds that would be sent.
        fd_count: u64,
        /// The per-frame cap that was exceeded.
        max_per_frame: u64,
    },
}

// ── OciProxy trait ────────────────────────────────────────────────────────────

/// Typed client proxy for the `org.composefs.Oci` varlink interface.
///
/// Both the composefs repo service and the containers-storage service expose
/// this interface; this proxy trait can be used against either.
#[zlink::proxy(interface = "org.composefs.Oci")]
pub trait OciProxy {
    /// Query capability tokens supported by the service.
    async fn get_info(&mut self) -> zlink::Result<Result<GetInfoReply, OciError>>;

    /// Check whether a layer is present in the repository.
    async fn has_layer(
        &mut self,
        handle: u64,
        diff_id: &str,
    ) -> zlink::Result<Result<HasLayerReply, OciError>>;

    /// Stream the layer as a `splitdirfdstream` with full hardened fd-transport
    /// contract (sparse dirfds, keepalive, lifetime fds, multi-frame).
    ///
    /// `params.diff_id` is used by the repo service; `params.storage` is used
    /// by the cstor service.
    #[zlink(more, return_fds)]
    async fn get_layer(
        &mut self,
        handle: u64,
        params: GetLayerParams,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<
            Item = zlink::Result<(Result<GetLayerReply, OciError>, Vec<std::os::fd::OwnedFd>)>,
        >,
    >;

    /// Receive a layer as a `splitdirfdstream` from the client and import it.
    async fn put_layer(
        &mut self,
        handle: u64,
        diff_id: &str,
        zerocopy: bool,
        #[zlink(fds)] fds: Vec<std::os::fd::OwnedFd>,
    ) -> zlink::Result<Result<PutLayerReply, OciError>>;

    /// Finalize an OCI image after all layers have been imported.
    async fn finalize_image(
        &mut self,
        handle: u64,
        manifest_json: &str,
        config_json: &str,
        layers: Vec<LayerRef>,
        name: Option<&str>,
    ) -> zlink::Result<Result<FinalizeImageReply, OciError>>;
}
