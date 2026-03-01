//! User namespace helper process for privileged storage access.
//!
//! This module provides a mechanism for unprivileged processes to access
//! containers-storage content that has restrictive permissions. It works by
//! spawning a helper process inside a user namespace (via `podman unshare`)
//! that can read any file, and communicating with it via JSON-RPC over a
//! Unix socket with fd-passing.
//!
//! # Why This Is Needed
//!
//! Container images contain files with various permission bits (e.g., `/etc/shadow`
//! with mode 0600). When stored in rootless containers-storage, these files are
//! owned by remapped UIDs that the unprivileged user cannot access. Even though
//! we have tar-split metadata telling us the file structure, we still need to
//! read the actual file content.
//!
//! # Architecture
//!
//! The helper uses stdin (fd 0) for IPC, avoiding the need for unsafe code:
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │         Parent Process              │
//! │   (unprivileged, library user)      │
//! │                                     │
//! │  StorageProxy::spawn()              │
//! │       │                             │
//! │       ├─► Create socketpair         │
//! │       ├─► Spawn: podman unshare     │
//! │       │      /proc/self/exe         │
//! │       │      (child's stdin=socket) │
//! │       │                             │
//! │  proxy.stream_layer() ───────────►  │
//! │       │                             │
//! │  ◄─── receives OwnedFd via SCM_RIGHTS│
//! └─────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! Library users must call [`init_if_helper`] early in their `main()` function:
//!
//! ```no_run
//! // This must be called before any other cstorage operations.
//! // If this process was spawned as a userns helper, it will
//! // serve requests and exit, never returning.
//! cstorage::userns_helper::init_if_helper();
//!
//! // Normal application code continues here...
//! ```

use std::os::fd::AsFd;
use std::os::unix::io::OwnedFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use base64::prelude::*;
use jsonrpc_fdpass::transport::UnixSocketTransport;
use jsonrpc_fdpass::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, MessageWithFds};
use rustix::io::dup;
use rustix::process::{set_parent_process_death_signal, Signal};
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream as TokioUnixStream;

use crate::layer::Layer;
use crate::storage::Storage;
use crate::tar_split::{TarSplitFdStream, TarSplitItem};
use crate::userns::can_bypass_file_permissions;

/// Environment variable that indicates this process is a userns helper.
const HELPER_ENV: &str = "__CSTORAGE_USERNS_HELPER";

/// JSON-RPC 2.0 error codes.
///
/// These codes follow the JSON-RPC 2.0 specification:
/// - Standard errors: -32700 to -32600
/// - Server errors: -32099 to -32000 (implementation-defined)
mod error_codes {
    /// Invalid params - the params passed to a method are invalid.
    pub const INVALID_PARAMS: i32 = -32602;

    /// Method not found - the requested method does not exist.
    pub const METHOD_NOT_FOUND: i32 = -32601;

    /// Resource not found - the requested resource (image, layer, etc.) was not found.
    pub const RESOURCE_NOT_FOUND: i32 = -32000;

    /// Internal error - a server-side error occurred (I/O, storage access, etc.).
    pub const INTERNAL_ERROR: i32 = -32003;
}

/// JSON-RPC method names.
mod methods {
    /// Open a file and return its fd.
    pub const OPEN_FILE: &str = "userns.openFile";
    /// Shutdown the helper process.
    pub const SHUTDOWN: &str = "userns.shutdown";
    /// List images in storage.
    pub const LIST_IMAGES: &str = "userns.listImages";
    /// Get image metadata.
    pub const GET_IMAGE: &str = "userns.getImage";
    /// Stream layer as tar-split entries with fds.
    pub const STREAM_LAYER: &str = "userns.streamLayer";
}

/// Parameters for the open_file method.
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenFileParams {
    /// Path to open.
    pub path: String,
}

/// Result for the open_file method.
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenFileResult {
    /// True if successful (fd is passed out-of-band).
    pub success: bool,
}

/// Parameters for list_images method.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListImagesParams {
    /// Storage root path.
    pub storage_path: String,
}

/// Image info returned by list_images.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    /// Image ID.
    pub id: String,
    /// Image names/tags.
    pub names: Vec<String>,
}

/// Result for list_images method.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListImagesResult {
    /// List of images.
    pub images: Vec<ImageInfo>,
}

/// Parameters for get_image method.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetImageParams {
    /// Storage root path.
    pub storage_path: String,
    /// Image ID or name.
    pub image_ref: String,
}

/// Result for get_image method.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetImageResult {
    /// Image ID.
    pub id: String,
    /// Image names.
    pub names: Vec<String>,
    /// Layer diff IDs (sha256:...).
    pub layer_diff_ids: Vec<String>,
    /// Storage layer IDs (internal IDs used by containers-storage).
    pub storage_layer_ids: Vec<String>,
}

/// Parameters for stream_layer method.
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamLayerParams {
    /// Storage root path.
    pub storage_path: String,
    /// Layer ID (storage layer ID, not diff ID).
    pub layer_id: String,
}

/// Streaming notification for a segment.
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamSegmentNotification {
    /// Base64-encoded segment data.
    pub data: String,
}

/// Streaming notification for a file (fd is passed out-of-band).
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamFileNotification {
    /// File path in the tar.
    pub name: String,
    /// File size.
    pub size: u64,
}

/// Result for stream_layer method (sent after all notifications).
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamLayerResult {
    /// Number of items streamed.
    pub items_sent: usize,
}

/// Error type for userns helper operations.
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// Failed to create socket.
    #[error("failed to create socket: {0}")]
    Socket(#[source] std::io::Error),

    /// Failed to spawn helper process.
    #[error("failed to spawn helper process: {0}")]
    Spawn(#[source] std::io::Error),

    /// IPC error.
    #[error("IPC error: {0}")]
    Ipc(String),

    /// Helper returned an error.
    #[error("helper error: {0}")]
    HelperError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON-RPC error from the helper.
    #[error("RPC error: code={code}, message={message}")]
    RpcError {
        /// JSON-RPC error code.
        code: i32,
        /// Error message.
        message: String,
    },
}

/// Check if this process was spawned as a userns helper and run the helper loop if so.
///
/// This function **must** be called early in `main()`, before any other cstorage
/// operations. If this process was spawned as a helper, this function will:
///
/// 1. Read from stdin (which is a Unix socket from the parent)
/// 2. Serve JSON-RPC requests for file operations  
/// 3. Exit when the parent closes the connection
///
/// If this is not a helper process, this function returns immediately.
pub fn init_if_helper() {
    // Check if we're a helper via environment variable
    if std::env::var(HELPER_ENV).is_err() {
        return; // Not a helper, continue normal execution
    }

    // Ensure we exit if parent dies (avoids orphan helper processes)
    if let Err(e) = set_parent_process_death_signal(Some(Signal::TERM)) {
        eprintln!("cstorage helper: failed to set parent death signal: {}", e);
        // Continue anyway - this is a nice-to-have, not critical
    }

    // We're a helper - stdin is our IPC socket.
    // Use dup() to get a new owned fd from stdin (fd 0).
    // This is safe because:
    // 1. We were spawned with stdin set to a socket
    // 2. dup() gives us a new fd that we own
    // 3. We use std::io::stdin().as_fd() which is the safe way to get the fd
    let stdin_fd = match dup(std::io::stdin().as_fd()) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("cstorage helper: failed to dup stdin: {}", e);
            std::process::exit(1);
        }
    };
    let std_socket = StdUnixStream::from(stdin_fd);

    // Run the helper loop (never returns on success)
    if let Err(e) = run_helper_loop_blocking(std_socket) {
        eprintln!("cstorage helper: error in helper loop: {}", e);
        std::process::exit(1);
    }
    std::process::exit(0);
}

/// Run the helper loop synchronously by creating a tokio runtime.
fn run_helper_loop_blocking(std_socket: StdUnixStream) -> std::result::Result<(), HelperError> {
    // Set non-blocking for tokio
    std_socket.set_nonblocking(true)?;

    // Create a tokio runtime for the helper
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| HelperError::Ipc(format!("failed to create tokio runtime: {}", e)))?;

    rt.block_on(run_helper_loop_async(std_socket))
}

/// Run the helper loop, serving requests from the parent.
async fn run_helper_loop_async(std_socket: StdUnixStream) -> std::result::Result<(), HelperError> {
    // Convert std socket to tokio socket
    let tokio_socket = TokioUnixStream::from_std(std_socket)
        .map_err(|e| HelperError::Ipc(format!("failed to convert socket: {}", e)))?;

    let transport = UnixSocketTransport::new(tokio_socket);
    let (mut sender, mut receiver) = transport.split();

    tracing::debug!("userns helper: starting request loop");

    loop {
        let msg_with_fds = match receiver.receive().await {
            Ok(m) => m,
            Err(jsonrpc_fdpass::Error::ConnectionClosed) => {
                tracing::debug!("userns helper: connection closed");
                return Ok(());
            }
            Err(e) => {
                return Err(HelperError::Ipc(format!(
                    "failed to receive message: {}",
                    e
                )));
            }
        };

        match msg_with_fds.message {
            JsonRpcMessage::Request(request) => {
                let id = request.id.clone();

                // Handle stream_layer specially since it needs to send multiple messages
                if request.method == methods::STREAM_LAYER {
                    if let Err((code, msg)) = handle_stream_layer(&request, &mut sender).await {
                        let error = jsonrpc_fdpass::JsonRpcError::owned(code, msg, None::<()>);
                        let response = JsonRpcResponse::error(error, id);
                        let message =
                            MessageWithFds::new(JsonRpcMessage::Response(response), vec![]);
                        sender.send(message).await.map_err(|e| {
                            HelperError::Ipc(format!("failed to send error response: {}", e))
                        })?;
                    }
                    // Success response is sent by handle_stream_layer
                    continue;
                }

                let (result, fds) = handle_request(&request);

                match result {
                    Ok(response_value) => {
                        let response = JsonRpcResponse::success(response_value, id);
                        let message = MessageWithFds::new(JsonRpcMessage::Response(response), fds);
                        sender.send(message).await.map_err(|e| {
                            HelperError::Ipc(format!("failed to send response: {}", e))
                        })?;
                    }
                    Err((code, message_str)) => {
                        let error =
                            jsonrpc_fdpass::JsonRpcError::owned(code, message_str, None::<()>);
                        let response = JsonRpcResponse::error(error, id);
                        let message =
                            MessageWithFds::new(JsonRpcMessage::Response(response), vec![]);
                        sender.send(message).await.map_err(|e| {
                            HelperError::Ipc(format!("failed to send error response: {}", e))
                        })?;
                    }
                }

                // Check for shutdown request (handle after sending response)
                if request.method == methods::SHUTDOWN {
                    tracing::debug!("userns helper: received shutdown request");
                    return Ok(());
                }
            }
            JsonRpcMessage::Notification(notif) => {
                if notif.method == methods::SHUTDOWN {
                    tracing::debug!("userns helper: received shutdown notification");
                    return Ok(());
                }
                // Ignore other notifications
            }
            JsonRpcMessage::Response(_) => {
                // Unexpected response - ignore
            }
        }
    }
}

/// Handle stream_layer request - sends multiple notifications with fds.
async fn handle_stream_layer(
    request: &JsonRpcRequest,
    sender: &mut jsonrpc_fdpass::transport::Sender,
) -> std::result::Result<(), (i32, String)> {
    let params: StreamLayerParams = request
        .params
        .as_ref()
        .and_then(|p| serde_json::from_value(p.clone()).ok())
        .ok_or((
            error_codes::INVALID_PARAMS,
            "invalid params for streamLayer".to_string(),
        ))?;

    let storage = Storage::open(&params.storage_path).map_err(|e| {
        (
            error_codes::INTERNAL_ERROR,
            format!("failed to open storage: {}", e),
        )
    })?;

    let layer = Layer::open(&storage, &params.layer_id).map_err(|e| {
        (
            error_codes::RESOURCE_NOT_FOUND,
            format!("layer not found: {}", e),
        )
    })?;

    let mut stream = TarSplitFdStream::new(&storage, &layer).map_err(|e| {
        (
            error_codes::INTERNAL_ERROR,
            format!("failed to create tar-split stream: {}", e),
        )
    })?;

    let mut items_sent = 0usize;

    // Stream all items as notifications
    while let Some(item) = stream
        .next()
        .map_err(|e| (error_codes::INTERNAL_ERROR, format!("stream error: {}", e)))?
    {
        match item {
            TarSplitItem::Segment(bytes) => {
                // Send segment as base64-encoded notification
                let params = StreamSegmentNotification {
                    data: BASE64_STANDARD.encode(&bytes),
                };
                let notif = jsonrpc_fdpass::JsonRpcNotification::new(
                    "stream.segment".to_string(),
                    Some(serde_json::to_value(&params).unwrap()),
                );
                let message = MessageWithFds::new(JsonRpcMessage::Notification(notif), vec![]);
                sender.send(message).await.map_err(|e| {
                    (
                        error_codes::INTERNAL_ERROR,
                        format!("failed to send segment: {}", e),
                    )
                })?;
                items_sent += 1;
            }
            TarSplitItem::FileContent { fd, size, name } => {
                // Send file notification with fd
                let params = StreamFileNotification { name, size };
                let notif = jsonrpc_fdpass::JsonRpcNotification::new(
                    "stream.file".to_string(),
                    Some(serde_json::to_value(&params).unwrap()),
                );
                let message = MessageWithFds::new(JsonRpcMessage::Notification(notif), vec![fd]);
                sender.send(message).await.map_err(|e| {
                    (
                        error_codes::INTERNAL_ERROR,
                        format!("failed to send file: {}", e),
                    )
                })?;
                items_sent += 1;
            }
        }
    }

    // Send success response
    let result = StreamLayerResult { items_sent };
    let response =
        JsonRpcResponse::success(serde_json::to_value(result).unwrap(), request.id.clone());
    let message = MessageWithFds::new(JsonRpcMessage::Response(response), vec![]);
    sender.send(message).await.map_err(|e| {
        (
            error_codes::INTERNAL_ERROR,
            format!("failed to send response: {}", e),
        )
    })?;

    Ok(())
}

/// Handle a JSON-RPC request.
fn handle_request(
    request: &JsonRpcRequest,
) -> (
    std::result::Result<serde_json::Value, (i32, String)>,
    Vec<OwnedFd>,
) {
    match request.method.as_str() {
        methods::OPEN_FILE => {
            let params: OpenFileParams = match request
                .params
                .as_ref()
                .and_then(|p| serde_json::from_value(p.clone()).ok())
            {
                Some(p) => p,
                None => {
                    return (
                        Err((
                            error_codes::INVALID_PARAMS,
                            "invalid params: missing 'path' field".to_string(),
                        )),
                        vec![],
                    );
                }
            };

            match std::fs::File::open(&params.path) {
                Ok(file) => {
                    let fd: OwnedFd = file.into();
                    let result = OpenFileResult { success: true };
                    (Ok(serde_json::to_value(result).unwrap()), vec![fd])
                }
                Err(e) => (
                    Err((
                        error_codes::INTERNAL_ERROR,
                        format!("failed to open file: {}", e),
                    )),
                    vec![],
                ),
            }
        }
        methods::LIST_IMAGES => handle_list_images(request),
        methods::GET_IMAGE => handle_get_image(request),
        methods::SHUTDOWN => {
            // Just return success - the loop will exit after sending the response
            (Ok(serde_json::json!({"success": true})), vec![])
        }
        _ => (
            Err((
                error_codes::METHOD_NOT_FOUND,
                format!("method not found: {}", request.method),
            )),
            vec![],
        ),
    }
}

/// Handle list_images request.
fn handle_list_images(
    request: &JsonRpcRequest,
) -> (
    std::result::Result<serde_json::Value, (i32, String)>,
    Vec<OwnedFd>,
) {
    let params: ListImagesParams = match request
        .params
        .as_ref()
        .and_then(|p| serde_json::from_value(p.clone()).ok())
    {
        Some(p) => p,
        None => {
            return (
                Err((
                    error_codes::INVALID_PARAMS,
                    "invalid params for listImages".to_string(),
                )),
                vec![],
            );
        }
    };

    let storage = match Storage::open(&params.storage_path) {
        Ok(s) => s,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to open storage: {}", e),
                )),
                vec![],
            );
        }
    };

    let images = match storage.list_images() {
        Ok(imgs) => imgs,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to list images: {}", e),
                )),
                vec![],
            );
        }
    };

    let image_infos: Vec<ImageInfo> = images
        .iter()
        .map(|img| ImageInfo {
            id: img.id().to_string(),
            names: img.names(&storage).unwrap_or_default(),
        })
        .collect();

    let result = ListImagesResult {
        images: image_infos,
    };
    (Ok(serde_json::to_value(result).unwrap()), vec![])
}

/// Handle get_image request.
fn handle_get_image(
    request: &JsonRpcRequest,
) -> (
    std::result::Result<serde_json::Value, (i32, String)>,
    Vec<OwnedFd>,
) {
    let params: GetImageParams = match request
        .params
        .as_ref()
        .and_then(|p| serde_json::from_value(p.clone()).ok())
    {
        Some(p) => p,
        None => {
            return (
                Err((
                    error_codes::INVALID_PARAMS,
                    "invalid params for getImage".to_string(),
                )),
                vec![],
            );
        }
    };

    let storage = match Storage::open(&params.storage_path) {
        Ok(s) => s,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to open storage: {}", e),
                )),
                vec![],
            );
        }
    };

    // Try by ID first, then by name
    let image = match crate::image::Image::open(&storage, &params.image_ref) {
        Ok(img) => img,
        Err(_) => match storage.find_image_by_name(&params.image_ref) {
            Ok(img) => img,
            Err(e) => {
                return (
                    Err((
                        error_codes::RESOURCE_NOT_FOUND,
                        format!("image not found: {}", e),
                    )),
                    vec![],
                );
            }
        },
    };

    let config = match image.config() {
        Ok(cfg) => cfg,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to read config: {}", e),
                )),
                vec![],
            );
        }
    };

    let diff_ids: Vec<String> = config
        .rootfs()
        .diff_ids()
        .iter()
        .map(|s| s.to_string())
        .collect();

    let storage_layer_ids = match image.storage_layer_ids(&storage) {
        Ok(ids) => ids,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to get storage layer IDs: {}", e),
                )),
                vec![],
            );
        }
    };

    let result = GetImageResult {
        id: image.id().to_string(),
        names: image.names(&storage).unwrap_or_default(),
        layer_diff_ids: diff_ids,
        storage_layer_ids,
    };
    (Ok(serde_json::to_value(result).unwrap()), vec![])
}

/// Proxy for accessing files via the userns helper process.
///
/// This spawns a helper process (via `podman unshare`) that runs inside a
/// user namespace and can read files with restrictive permissions. File
/// descriptors are passed back via SCM_RIGHTS.
pub struct StorageProxy {
    child: Child,
    sender: jsonrpc_fdpass::transport::Sender,
    receiver: jsonrpc_fdpass::transport::Receiver,
    next_id: u64,
}

impl std::fmt::Debug for StorageProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageProxy")
            .field("child_pid", &self.child.id())
            .finish_non_exhaustive()
    }
}

impl StorageProxy {
    /// Spawn a userns helper process.
    ///
    /// If the current process can already bypass file permissions (running as
    /// root or has CAP_DAC_OVERRIDE), this returns `Ok(None)` since no helper
    /// is needed.
    pub async fn spawn() -> std::result::Result<Option<Self>, HelperError> {
        // Check if we even need a helper
        if can_bypass_file_permissions() {
            return Ok(None);
        }

        Self::spawn_helper().await.map(Some)
    }

    /// Spawn the helper unconditionally.
    async fn spawn_helper() -> std::result::Result<Self, HelperError> {
        let exe = std::fs::read_link("/proc/self/exe").map_err(HelperError::Io)?;
        Self::spawn_helper_with_binary(exe).await
    }

    /// Spawn the helper with a specific binary path.
    ///
    /// This is used when the default /proc/self/exe is not suitable,
    /// such as when running from a test harness.
    async fn spawn_helper_with_binary(
        exe: std::path::PathBuf,
    ) -> std::result::Result<Self, HelperError> {
        // Create a socket pair - one end for us, one for the child's stdin
        let (parent_sock, child_sock) = StdUnixStream::pair().map_err(HelperError::Socket)?;

        // Spawn via podman unshare, with child_sock as the child's stdin.
        // We use `env` to set the HELPER_ENV because podman unshare doesn't
        // propagate the parent's environment to the inner command.
        let child = Command::new("podman")
            .arg("unshare")
            .arg("env")
            .arg(format!("{}=1", HELPER_ENV))
            .arg(&exe)
            .stdin(Stdio::from(OwnedFd::from(child_sock)))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(HelperError::Spawn)?;

        // Convert our socket to async
        parent_sock.set_nonblocking(true)?;
        let tokio_socket = TokioUnixStream::from_std(parent_sock)
            .map_err(|e| HelperError::Ipc(format!("failed to convert socket: {}", e)))?;

        let transport = UnixSocketTransport::new(tokio_socket);
        let (sender, receiver) = transport.split();

        Ok(Self {
            child,
            sender,
            receiver,
            next_id: 1,
        })
    }

    /// Open a file via the helper, returning its fd.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to open (should be absolute)
    ///
    /// # Returns
    ///
    /// The opened file descriptor, which can be used for reading.
    pub async fn open_file(
        &mut self,
        path: impl AsRef<Path>,
    ) -> std::result::Result<OwnedFd, HelperError> {
        let params = OpenFileParams {
            path: path.as_ref().to_string_lossy().to_string(),
        };

        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest::new(
            methods::OPEN_FILE.to_string(),
            Some(serde_json::to_value(&params).unwrap()),
            serde_json::Value::Number(id.into()),
        );

        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);
        self.sender
            .send(message)
            .await
            .map_err(|e| HelperError::Ipc(format!("failed to send request: {}", e)))?;

        // Receive response
        let response = self
            .receiver
            .receive()
            .await
            .map_err(|e| HelperError::Ipc(format!("failed to receive response: {}", e)))?;

        match response.message {
            JsonRpcMessage::Response(resp) => {
                if let Some(error) = resp.error {
                    return Err(HelperError::RpcError {
                        code: error.code(),
                        message: error.message().to_string(),
                    });
                }

                // The fd should be in the response
                if response.file_descriptors.is_empty() {
                    return Err(HelperError::Ipc(
                        "response missing file descriptor".to_string(),
                    ));
                }

                Ok(response.file_descriptors.into_iter().next().unwrap())
            }
            other => Err(HelperError::Ipc(format!(
                "unexpected message type: {:?}",
                other
            ))),
        }
    }

    /// Shutdown the helper process gracefully.
    pub async fn shutdown(mut self) -> std::result::Result<(), HelperError> {
        let id = self.next_id;

        let request = JsonRpcRequest::new(
            methods::SHUTDOWN.to_string(),
            None,
            serde_json::Value::Number(id.into()),
        );

        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);
        // Ignore send errors - the child may have already exited
        let _ = self.sender.send(message).await;

        // Wait for the child to exit
        let _ = self.child.wait();

        Ok(())
    }

    /// List images in storage via the helper.
    pub async fn list_images(
        &mut self,
        storage_path: &str,
    ) -> std::result::Result<Vec<ImageInfo>, HelperError> {
        let params = ListImagesParams {
            storage_path: storage_path.to_string(),
        };
        let result: ListImagesResult = self.call(methods::LIST_IMAGES, &params).await?;
        Ok(result.images)
    }

    /// Get image information via the helper.
    pub async fn get_image(
        &mut self,
        storage_path: &str,
        image_ref: &str,
    ) -> std::result::Result<GetImageResult, HelperError> {
        let params = GetImageParams {
            storage_path: storage_path.to_string(),
            image_ref: image_ref.to_string(),
        };
        self.call(methods::GET_IMAGE, &params).await
    }

    /// Start streaming a layer's tar-split content.
    ///
    /// Returns a stream that yields `ProxiedTarSplitItem`s. The helper sends
    /// notifications with file descriptors for each file in the layer.
    pub async fn stream_layer(
        &mut self,
        storage_path: &str,
        layer_id: &str,
    ) -> std::result::Result<ProxiedLayerStream<'_>, HelperError> {
        let params = StreamLayerParams {
            storage_path: storage_path.to_string(),
            layer_id: layer_id.to_string(),
        };

        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest::new(
            methods::STREAM_LAYER.to_string(),
            Some(serde_json::to_value(&params).unwrap()),
            serde_json::Value::Number(id.into()),
        );

        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);
        self.sender
            .send(message)
            .await
            .map_err(|e| HelperError::Ipc(format!("failed to send stream_layer request: {}", e)))?;

        Ok(ProxiedLayerStream {
            receiver: &mut self.receiver,
            request_id: id,
            finished: false,
        })
    }

    /// Make an RPC call and parse the response.
    async fn call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &mut self,
        method: &str,
        params: &P,
    ) -> std::result::Result<R, HelperError> {
        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest::new(
            method.to_string(),
            Some(serde_json::to_value(params).unwrap()),
            serde_json::Value::Number(id.into()),
        );

        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);
        self.sender
            .send(message)
            .await
            .map_err(|e| HelperError::Ipc(format!("failed to send request: {}", e)))?;

        // Receive response
        let response = self
            .receiver
            .receive()
            .await
            .map_err(|e| HelperError::Ipc(format!("failed to receive response: {}", e)))?;

        match response.message {
            JsonRpcMessage::Response(resp) => {
                if let Some(error) = resp.error {
                    return Err(HelperError::RpcError {
                        code: error.code(),
                        message: error.message().to_string(),
                    });
                }

                let result = resp
                    .result
                    .ok_or_else(|| HelperError::Ipc("response missing result".to_string()))?;

                serde_json::from_value(result)
                    .map_err(|e| HelperError::Ipc(format!("failed to parse result: {}", e)))
            }
            other => Err(HelperError::Ipc(format!(
                "unexpected message type: {:?}",
                other
            ))),
        }
    }
}

/// Item received from a proxied layer stream.
#[derive(Debug)]
pub enum ProxiedTarSplitItem {
    /// Raw segment bytes (tar header/padding).
    Segment(Vec<u8>),
    /// File content with metadata and fd.
    FileContent {
        /// File descriptor for the content.
        fd: OwnedFd,
        /// File size.
        size: u64,
        /// File name/path.
        name: String,
    },
}

/// Stream of tar-split items received via the helper proxy.
pub struct ProxiedLayerStream<'a> {
    receiver: &'a mut jsonrpc_fdpass::transport::Receiver,
    request_id: u64,
    finished: bool,
}

impl std::fmt::Debug for ProxiedLayerStream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxiedLayerStream")
            .field("request_id", &self.request_id)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<'a> ProxiedLayerStream<'a> {
    /// Get the next item from the stream.
    ///
    /// Returns `None` when the stream is complete.
    pub async fn next(&mut self) -> std::result::Result<Option<ProxiedTarSplitItem>, HelperError> {
        if self.finished {
            return Ok(None);
        }

        let msg_with_fds = match self.receiver.receive().await {
            Ok(m) => m,
            Err(jsonrpc_fdpass::Error::ConnectionClosed) => {
                self.finished = true;
                return Ok(None);
            }
            Err(e) => {
                return Err(HelperError::Ipc(format!("failed to receive: {}", e)));
            }
        };

        let mut fds = msg_with_fds.file_descriptors;

        match msg_with_fds.message {
            JsonRpcMessage::Notification(notif) => {
                let params = notif.params.unwrap_or(serde_json::Value::Null);

                match notif.method.as_str() {
                    "stream.segment" => {
                        let seg: StreamSegmentNotification = serde_json::from_value(params)
                            .map_err(|e| {
                                HelperError::Ipc(format!("invalid segment params: {}", e))
                            })?;

                        let bytes = BASE64_STANDARD.decode(&seg.data).map_err(|e| {
                            HelperError::Ipc(format!("failed to decode segment: {}", e))
                        })?;

                        Ok(Some(ProxiedTarSplitItem::Segment(bytes)))
                    }
                    "stream.file" => {
                        let file: StreamFileNotification = serde_json::from_value(params)
                            .map_err(|e| HelperError::Ipc(format!("invalid file params: {}", e)))?;

                        if fds.is_empty() {
                            return Err(HelperError::Ipc(
                                "file notification missing fd".to_string(),
                            ));
                        }

                        let fd = fds.remove(0);
                        Ok(Some(ProxiedTarSplitItem::FileContent {
                            fd,
                            size: file.size,
                            name: file.name,
                        }))
                    }
                    other => Err(HelperError::Ipc(format!(
                        "unknown notification method: {}",
                        other
                    ))),
                }
            }
            JsonRpcMessage::Response(resp) => {
                // Final response - stream is complete
                self.finished = true;

                if let Some(error) = resp.error {
                    return Err(HelperError::RpcError {
                        code: error.code(),
                        message: error.message().to_string(),
                    });
                }

                Ok(None)
            }
            JsonRpcMessage::Request(_) => Err(HelperError::Ipc(
                "unexpected request from helper".to_string(),
            )),
        }
    }
}

impl Drop for StorageProxy {
    fn drop(&mut self) {
        // Try to kill the child if it's still running
        let _ = self.child.kill();
    }
}
