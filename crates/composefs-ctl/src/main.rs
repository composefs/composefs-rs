//! Command-line control utility for composefs repositories and images.
//!
//! `cfsctl` is a multi-call binary: when invoked as `mkcomposefs`,
//! `composefs-info`, or `mount.composefs` (via symlink or hardlink),
//! it dispatches to the corresponding tool. Otherwise it runs the normal
//! `cfsctl` interface.
//!
//! ## C composefs compatibility roadmap
//!
//! This work aims to provide a Rust implementation that is a drop-in for the
//! C composefs tools and library.  See:
//! <https://github.com/composefs/composefs/discussions/423>
//!
//! Status:
//! 1. **CLI interfaces** (`mkcomposefs`, `composefs-info`): Substantially
//!    implemented. V1 EROFS output is byte-for-byte identical to C mkcomposefs.
//!    See individual module docs for remaining gaps.
//! 2. **EROFS output format**: V1 (C-compatible) writer with compact inodes,
//!    BFS ordering, whiteout table, and overlay xattr escaping is complete and
//!    tested.  V2 (Rust-native) is the default for the composefs-rs repository.
//! 3. **C shared library (`libcomposefs`)**: TODO(compat): Not yet started.
//!    This is the next major milestone — providing a C-ABI compatible shared
//!    library so that existing C consumers (e.g. ostree, bootc) can link
//!    against the Rust implementation.  Will require `#[no_mangle]` exports,
//!    a `cdylib` crate, and C header generation (e.g. via cbindgen).

use std::ffi::OsStr;
use std::path::Path;

use anyhow::Result;

/// Extract the binary name from argv[0], stripping any directory prefix.
fn binary_name() -> Option<String> {
    std::env::args_os().next().and_then(|arg0| {
        Path::new(&arg0)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
    })
}

/// Collect all arguments after the first (i.e. argv[2..]) as OsStrings.
fn rest_of_args() -> Vec<std::ffi::OsString> {
    std::env::args_os().skip(2).collect()
}

fn main() -> Result<()> {
    match binary_name().as_deref() {
        Some("mkcomposefs") => composefs_ctl::mkcomposefs::run(),
        Some("composefs-info") => composefs_ctl::composefs_info::run(),
        Some("mount.composefs") => composefs_ctl::mountcomposefs::run(),
        // When called as `cfsctl mkcomposefs ...` or `cfsctl composefs-info ...`,
        // intercept before clap so that --help and all flags go to the real tool.
        _ if std::env::args_os().nth(1).as_deref() == Some(OsStr::new("mkcomposefs")) => {
            composefs_ctl::mkcomposefs::run_from_args(rest_of_args())
        }
        _ if std::env::args_os().nth(1).as_deref() == Some(OsStr::new("composefs-info")) => {
            composefs_ctl::composefs_info::run_from_args(rest_of_args())
        }
        _ if std::env::args_os().nth(1).as_deref() == Some(OsStr::new("mount.composefs")) => {
            composefs_ctl::mountcomposefs::run_from_args(rest_of_args())
        }
        _ => {
            // If we were spawned as a userns helper process, handle that and exit.
            // This MUST be called before the tokio runtime is created.
            #[cfg(feature = "containers-storage")]
            cstorage::init_if_helper();

            // Now we can create the tokio runtime for the main application
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(async_main())
        }
    }
}

async fn async_main() -> Result<()> {
    use clap::Parser;
    use composefs_ctl::App;

    env_logger::init();

    // If we were launched via systemd socket activation (e.g. `varlinkctl
    // exec:cfsctl`, which passes the connected socket on fd 3 but no
    // arguments), serve the varlink API directly. This must run before clap,
    // since a bare activated invocation has no subcommand to parse.
    if composefs_ctl::run_if_socket_activated().await? {
        return Ok(());
    }

    let args = App::parse();
    composefs_ctl::run_app(args).await
}
