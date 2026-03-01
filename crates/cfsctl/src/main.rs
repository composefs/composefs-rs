//! Command-line control utility for composefs repositories and images.
//!
//! `cfsctl` provides a comprehensive interface for managing composefs repositories,
//! creating and mounting filesystem images, handling OCI containers, and performing
//! repository maintenance operations like garbage collection.

use cfsctl::{open_repo, run_cmd_with_repo, App, HashType};

use anyhow::Result;
use clap::Parser;
use composefs::fsverity::{Sha256HashValue, Sha512HashValue};

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

    let args = App::parse();

    match args.hash {
        HashType::Sha256 => run_cmd_with_repo(open_repo::<Sha256HashValue>(&args)?, args).await,
        HashType::Sha512 => run_cmd_with_repo(open_repo::<Sha512HashValue>(&args)?, args).await,
    }
}
