//! User namespace helper process for privileged storage access.
//!
//! This module provides a mechanism for unprivileged processes to access
//! containers-storage content that has restrictive permissions. It works by
//! spawning a helper process inside a user namespace (via `podman unshare`)
//! that can read any file, and communicating with it via the zlink
//! `org.composefs.Oci` service (`CstorLayerService`) over a Unix socket.
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
//! │  proxy.connection()  ──────────────►│
//! │       │   (OciProxy/CstorLayerSvc)  │
//! └─────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! Library users must call [`init_if_helper`] early in their `main()` function:
//!
//! ```no_run
//! // This must be called before any other composefs_storage operations.
//! // If this process was spawned as a userns helper, it will
//! // serve requests and exit, never returning.
//! composefs_storage::userns_helper::init_if_helper();
//!
//! // Normal application code continues here...
//! ```

use std::os::fd::AsFd as _;
use std::os::unix::io::OwnedFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::process::{Child, Command, Stdio};

use rustix::io::dup;
use rustix::process::{Signal, set_parent_process_death_signal};

use crate::userns::can_bypass_file_permissions;

/// Environment variable that indicates this process is a userns helper.
const HELPER_ENV: &str = "__CSTORAGE_USERNS_HELPER";

/// Error type for userns helper operations.
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// Failed to create socket.
    #[error("failed to create socket: {0}")]
    Socket(#[source] std::io::Error),

    /// `podman` binary was not found on `PATH`.
    ///
    /// The userns helper requires `podman unshare` to set up a user
    /// namespace.  Install `podman` and ensure it is on `PATH`.
    #[error("podman not found on PATH (required for user-namespace helper): {0}")]
    PodmanNotFound(#[source] std::io::Error),

    /// Failed to spawn helper process.
    #[error("failed to spawn helper process: {0}")]
    Spawn(#[source] std::io::Error),

    /// IPC / transport error.
    #[error("IPC error: {0}")]
    Ipc(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Check if this process was spawned as a userns helper and serve the
/// `org.composefs.Oci` (`CstorLayerService`) zlink service if so.
///
/// This function **must** be called early in `main()`, before any other
/// `composefs_storage` operations.  If the `__CSTORAGE_USERNS_HELPER`
/// environment variable is set this function will:
///
/// 1. Set a parent-death signal so the helper exits when the parent dies.
/// 2. Duplicate `stdin` into an owned [`StdUnixStream`].
/// 3. Call [`crate::cstor_service::serve_on_socket_blocking`] to serve the
///    `org.composefs.Oci` zlink service until the parent closes the connection.
/// 4. Exit the process (0 on success, 1 on error).
///
/// If the environment variable is **not** set, this function returns
/// immediately and the caller continues normal execution.
//
// Runs in a forked helper subprocess whose stdin is the IPC socket; there is
// no logging facility or error channel back to the parent, so fatal
// diagnostics are written to stderr before exiting.
#[allow(clippy::print_stderr)]
pub fn init_if_helper() {
    if std::env::var(HELPER_ENV).is_err() {
        return; // Not a helper — continue normal execution.
    }

    // Set a death signal on our immediate parent's exit, as a best-effort net
    // against orphaned helpers.
    //
    // The PRIMARY shutdown mechanism is explicit: `StorageProxy` (in the parent
    // cfsctl process) `kill()`s this helper when the import finishes or when the
    // proxy is dropped.  PDEATHSIG is only a fallback for abnormal parent death.
    //
    // CAVEAT: when spawned via `podman unshare <exe>`, the helper's PPID is the
    // intermediate `podman` process, NOT cfsctl.  So PDEATHSIG actually fires on
    // *podman's* death, not cfsctl's; it does not track cfsctl through the
    // podman intermediary.  In the normal flow `podman unshare` waits on this
    // helper, so cfsctl killing the helper (or podman) tears the whole chain
    // down.  This signal is purely a backstop.
    if let Err(e) = set_parent_process_death_signal(Some(Signal::TERM)) {
        eprintln!("cstorage helper: failed to set parent death signal: {e}");
        // Continue anyway — explicit kill() from the parent is the real guard.
    }

    // stdin is our IPC socket.  dup() it so we hold an owned fd.
    let stdin_fd: OwnedFd = match dup(std::io::stdin().as_fd()) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("cstorage helper: failed to dup stdin: {e}");
            std::process::exit(1);
        }
    };
    let std_socket = StdUnixStream::from(stdin_fd);

    if let Err(e) = crate::cstor_service::serve_on_socket_blocking(std_socket) {
        eprintln!("cstorage helper: server error: {e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

/// Proxy for accessing storage content via the userns helper process.
///
/// When the caller cannot bypass file permissions, `StorageProxy::spawn()`
/// starts a helper process inside a user namespace using `podman unshare` and
/// returns a connected [`zlink::tokio::unix::Connection`] the caller can use with the
/// [`composefs_oci::varlink_types::OciProxy`] trait to stream layers.
///
/// # Dependency on `podman`
///
/// This type requires the `podman` binary to be present on `PATH`.  If
/// `podman` is not found, [`StorageProxy::spawn`] returns
/// [`HelperError::PodmanNotFound`].
///
/// # Liveness
///
/// The helper subprocess is shut down explicitly: [`StorageProxy::shutdown`]
/// (and the `Drop` impl) `kill()` the child once the caller is done.  A
/// best-effort `PR_SET_PDEATHSIG` in the helper is a fallback for abnormal
/// parent death (see `init_if_helper`).
///
/// Dropping this struct kills the child process.
pub struct StorageProxy {
    /// The spawned helper child process.  Wrapped in `Option` so that
    /// `shutdown` can take ownership and call `wait()` without fighting the
    /// `Drop` impl.
    child: Option<Child>,
    conn: zlink::tokio::unix::Connection,
}

impl std::fmt::Debug for StorageProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageProxy")
            .field("child_pid", &self.child.as_ref().map(|c| c.id()))
            .finish_non_exhaustive()
    }
}

impl StorageProxy {
    /// Spawn a userns helper process if required.
    ///
    /// Returns `Ok(None)` when the current process can already bypass file
    /// permissions (running as root, or has `CAP_DAC_OVERRIDE`), since no
    /// helper is needed in that case.
    pub async fn spawn() -> Result<Option<Self>, HelperError> {
        if can_bypass_file_permissions() {
            return Ok(None);
        }
        Self::spawn_helper().await.map(Some)
    }

    /// Spawn the helper unconditionally using `/proc/self/exe`.
    async fn spawn_helper() -> Result<Self, HelperError> {
        let exe = std::fs::read_link("/proc/self/exe").map_err(HelperError::Io)?;
        Self::spawn_helper_with_binary(exe).await
    }

    /// Spawn the helper with an explicit binary path.
    ///
    /// Useful when `/proc/self/exe` is not the right choice (e.g. test
    /// harnesses that run under a wrapper binary).
    async fn spawn_helper_with_binary(exe: std::path::PathBuf) -> Result<Self, HelperError> {
        // Create a socket pair — one end becomes the child's stdin, the other
        // stays in the parent for the zlink connection.
        let (parent_sock, child_sock) = StdUnixStream::pair().map_err(HelperError::Socket)?;

        // Spawn via `podman unshare`; set HELPER_ENV because podman unshare
        // does not automatically forward the parent's environment.
        //
        // `podman` must be on PATH — see [`HelperError::PodmanNotFound`].
        let child = Command::new("podman")
            .arg("unshare")
            .arg("env")
            .arg(format!("{HELPER_ENV}=1"))
            .arg(&exe)
            .stdin(Stdio::from(OwnedFd::from(child_sock)))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    HelperError::PodmanNotFound(e)
                } else {
                    HelperError::Spawn(e)
                }
            })?;

        // Wrap the parent socket end as a zlink Connection.
        parent_sock.set_nonblocking(true)?;
        let tok = tokio::net::UnixStream::from_std(parent_sock)
            .map_err(|e| HelperError::Ipc(format!("failed to convert socket: {e}")))?;
        let zs = zlink::tokio::unix::Stream::try_from(tok).map_err(std::io::Error::other)?;
        let conn = zlink::Connection::new(zs);

        Ok(Self {
            child: Some(child),
            conn,
        })
    }

    /// Return a mutable reference to the underlying zlink connection.
    ///
    /// Callers use this with the `OciProxy` trait (from
    /// `composefs_oci::varlink_types`) to drive `GetLayer` calls over the
    /// helper connection.
    pub fn connection(&mut self) -> &mut zlink::tokio::unix::Connection {
        &mut self.conn
    }

    /// Shut down the helper.
    ///
    /// Kills the child process and waits for it to exit.  Dropping this
    /// struct also kills the child (via `Drop`), but `shutdown` additionally
    /// waits for the process to be reaped so no zombie is left behind.  This
    /// explicit `kill()` is the helper's primary shutdown mechanism.
    pub async fn shutdown(mut self) -> Result<(), HelperError> {
        // Take the child out so Drop sees None and skips the redundant kill().
        if let Some(mut child) = self.child.take() {
            drop(self); // drop conn first
            let _ = tokio::task::spawn_blocking(move || {
                let _ = child.kill();
                child.wait()
            })
            .await;
        }
        Ok(())
    }
}

impl Drop for StorageProxy {
    fn drop(&mut self) {
        // Best-effort: kill the child if it is still running.
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
        }
    }
}
