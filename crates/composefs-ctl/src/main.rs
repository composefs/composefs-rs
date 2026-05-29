//! Command-line control utility for composefs repositories and images.
//!
//! `cfsctl` provides a comprehensive interface for managing composefs repositories,
//! creating and mounting filesystem images, handling OCI containers, and performing
//! repository maintenance operations like garbage collection.

use composefs_ctl::App;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
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

async fn async_main() -> Result<()> {
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
