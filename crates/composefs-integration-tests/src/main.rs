//! Integration test runner for composefs-rs.
//!
//! This binary uses [`libtest_mimic`] as a custom test harness (no `#[test]`).
//! Tests are registered via the [`integration_test!`] macro in submodules
//! and collected from the [`INTEGRATION_TESTS`] distributed slice at startup.
//!
//! IMPORTANT: This binary may be re-executed via `podman unshare` to act as a
//! userns helper for rootless containers-storage access. The init_if_helper()
//! call at the start of main() handles this.

// linkme requires unsafe for distributed slices
#![allow(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use libtest_mimic::{Arguments, Trial};

pub(crate) use composefs_integration_tests::{INTEGRATION_TESTS, integration_test};

mod tests;

/// Return the path to the cfsctl binary.
///
/// Resolution order:
/// 1. `CFSCTL_PATH` environment variable
/// 2. `target/{release,debug}/cfsctl` relative to the workspace root
/// 3. `/usr/bin/cfsctl` (for VM-based integration tests)
pub(crate) fn cfsctl() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("CFSCTL_PATH") {
        return Ok(PathBuf::from(p));
    }

    // Walk up from the crate's manifest dir to find the workspace target/
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(Path::new("."));

    for profile in ["release", "debug"] {
        let candidate = workspace.join("target").join(profile).join("cfsctl");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // In VM-based tests the binary is baked into the container image
    let system = Path::new("/usr/bin/cfsctl");
    if system.exists() {
        return Ok(system.to_path_buf());
    }

    bail!(
        "cfsctl binary not found; build it with `cargo build -p cfsctl` \
         or set CFSCTL_PATH"
    )
}

/// Bind a listening Unix socket at a fresh tempdir path and spawn `cfsctl`
/// against it via the systemd socket-activation protocol (`LISTEN_FDS=1`, the
/// listening socket on fd 3, `LISTEN_PID` set in the child). The socket is
/// already listening before the child starts, so callers may connect
/// immediately — no polling needed. The path exists on disk, so `varlinkctl`
/// (which connects by path) works unchanged.
///
/// Returns the spawned child, the tempdir (keep alive for the socket's
/// lifetime), and the socket path.
pub(crate) fn spawn_activated_cfsctl() -> Result<(std::process::Child, tempfile::TempDir, PathBuf)>
{
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;

    use cap_std_ext::cmdext::{CapStdExtCommandExt, CmdFds, SystemdFdName};

    let cfsctl = cfsctl()?;
    let socket_dir = tempfile::tempdir()?;
    let socket = socket_dir.path().join("varlink.sock");

    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("binding varlink listener at {}", socket.display()))?;
    let listener_fd: Arc<OwnedFd> = Arc::new(listener.into());

    let mut cmd = std::process::Command::new(&cfsctl);
    // Bare invocation — no subcommand, no --address.  cfsctl serves on the
    // inherited listening fd via run_if_socket_activated().
    //
    // IMPORTANT: do NOT call cmd.env()/.envs() here — take_fds() sets the
    // LISTEN_* vars via setenv in pre_exec, and Command::env would clobber
    // them by building a separate envp array.
    let fds = CmdFds::new_systemd_fds([(listener_fd, SystemdFdName::new("varlink"))]);
    cmd.take_fds(fds);
    let child = cmd.spawn().context("spawning socket-activated cfsctl")?;

    Ok((child, socket_dir, socket))
}

/// Create a test rootfs fixture inside `parent` and return its path.
///
/// Includes a file large enough (128 KiB) to avoid erofs inlining so that
/// `image-objects` will report at least one external object.
pub(crate) fn create_test_rootfs(parent: &Path) -> Result<PathBuf> {
    let root = parent.join("rootfs");
    fs::create_dir_all(root.join("usr/bin"))?;
    fs::create_dir_all(root.join("usr/lib"))?;
    fs::create_dir_all(root.join("etc"))?;

    // A large-ish file that won't be inlined into the erofs image
    fs::write(root.join("usr/bin/hello"), "x".repeat(128 * 1024))?;
    fs::write(root.join("usr/lib/readme.txt"), "test fixture\n")?;
    fs::write(root.join("etc/hostname"), "integration-test\n")?;
    Ok(root)
}

fn main() {
    // CRITICAL: Handle userns helper re-execution.
    // When running rootless, this binary may be re-executed via `podman unshare`
    // to act as a helper process for containers-storage access.
    composefs_oci::cstor::init_if_helper();

    let args = Arguments::from_args();

    let tests: Vec<Trial> = INTEGRATION_TESTS
        .iter()
        .map(|t| {
            let f = t.f;
            Trial::test(t.name, move || f().map_err(|e| format!("{e:?}").into()))
        })
        .collect();

    libtest_mimic::run(&args, tests).exit();
}
