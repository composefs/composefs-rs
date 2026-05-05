//! Rust bindings and utilities for working with composefs repositorie and ostree
//!

use anyhow::Result;
use rustix::fs::CWD;
use std::{path::Path, sync::Arc};

use composefs::{fsverity::FsVerityHashValue, repository::Repository, tree::FileSystem};

pub mod commit;
pub mod pull;
pub mod repo;

use crate::commit::CommitReader;
use crate::pull::PullOperation;
use crate::repo::{LocalRepo, RemoteRepo};

/// Pull from a local ostree repo into the repository
pub async fn pull_local<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    ostree_repo_path: &Path,
    ostree_ref: &str,
    base_reference: Option<&str>,
) -> Result<ObjectID> {
    let ostree_repo = LocalRepo::open_path(repo, CWD, ostree_repo_path)?;

    let commit_checksum = ostree_repo.read_ref(ostree_ref)?;

    let mut op = PullOperation::<ObjectID, LocalRepo<ObjectID>>::new(repo, ostree_repo);
    if let Some(base_name) = base_reference {
        op.add_base(base_name)?;
    }

    op.pull_commit(&commit_checksum).await
}

/// Pull from a remote ostree repo into the repository
pub async fn pull<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    ostree_repo_url: &str,
    ostree_ref: &str,
    base_reference: Option<&str>,
) -> Result<ObjectID> {
    let ostree_repo = RemoteRepo::new(repo, ostree_repo_url)?;

    let commit_checksum = ostree_repo.resolve_ref(ostree_ref).await?;

    let mut op = PullOperation::<ObjectID, RemoteRepo<ObjectID>>::new(repo, ostree_repo);
    if let Some(base_name) = base_reference {
        op.add_base(base_name)?;
    }

    op.pull_commit(&commit_checksum).await
}

/// Creates a filesystem from the given OSTree commit.
pub fn create_filesystem<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    commit_name: &str,
) -> Result<FileSystem<ObjectID>> {
    let commit = CommitReader::<ObjectID>::load(repo, commit_name)?;
    let fs = commit.create_filesystem()?;

    Ok(fs)
}

/// Inspects commit
pub fn inspect<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    commit_name: &str,
) -> Result<()> {
    let objmap = CommitReader::<ObjectID>::load(repo, commit_name)?;

    for (ostree_digest, maybe_obj_id, _data) in objmap.iter() {
        if let Some(obj_id) = maybe_obj_id {
            println!("Ostree {} => {:?}", hex::encode(ostree_digest), obj_id);
        }
    }

    Ok(())
}
