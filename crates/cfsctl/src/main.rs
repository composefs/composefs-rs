//! Command-line control utility for composefs repositories and images.
//!
//! `cfsctl` provides a comprehensive interface for managing composefs repositories,
//! creating and mounting filesystem images, handling OCI containers, and performing
//! repository maintenance operations like garbage collection.

use cfsctl::{open_repo, run_cmd_with_repo, run_cmd_without_repo, App, HashType};

use anyhow::Result;
use clap::Parser;
use composefs::fsverity::{Sha256HashValue, Sha512HashValue};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = App::parse();

    if args.no_repo {
        return match args.hash {
            HashType::Sha256 => run_cmd_without_repo::<Sha256HashValue>(args),
            HashType::Sha512 => run_cmd_without_repo::<Sha512HashValue>(args),
        };
    }

    match args.hash {
        HashType::Sha256 => run_cmd_with_repo(open_repo::<Sha256HashValue>(&args)?, args).await,
        HashType::Sha512 => run_cmd_with_repo(open_repo::<Sha512HashValue>(&args)?, args).await,
    }
}
