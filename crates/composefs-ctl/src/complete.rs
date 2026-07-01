use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use clap_complete::engine::CompletionCandidate;
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue};
use composefs::repository::Repository;
use rustix::fs::CWD;

use crate::HashType;

fn resolve_repo_for_completion() -> Option<(PathBuf, HashType)> {
    let args: Vec<String> = std::env::args().collect();
    let mut repo_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" => {
                repo_path = args.get(i + 1).map(PathBuf::from);
                i += 2;
            }
            _ if args[i].starts_with("--repo=") => {
                repo_path = args[i].strip_prefix("--repo=").map(PathBuf::from);
                i += 1;
            }
            "--user" => {
                repo_path = composefs::repository::user_path().ok();
                i += 1;
            }
            "--system" => {
                repo_path = Some(composefs::repository::system_path());
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    let repo_path = repo_path.or_else(|| crate::default_repo_path().ok())?;
    let hash_type = crate::resolve_hash_type(&repo_path, None, false).ok()?;
    Some((repo_path, hash_type))
}

/// Complete OCI image tag names from the active repository.
#[cfg(feature = "oci")]
pub fn complete_oci_tags(current: &OsStr) -> Vec<CompletionCandidate> {
    let Some((repo_path, hash_type)) = resolve_repo_for_completion() else {
        return vec![];
    };
    match hash_type {
        HashType::Sha256 => collect_oci::<Sha256HashValue>(&repo_path, current, true, false),
        HashType::Sha512 => collect_oci::<Sha512HashValue>(&repo_path, current, true, false),
    }
}

/// Complete OCI manifest digests from the active repository.
#[cfg(feature = "oci")]
pub fn complete_oci_digests(current: &OsStr) -> Vec<CompletionCandidate> {
    let Some((repo_path, hash_type)) = resolve_repo_for_completion() else {
        return vec![];
    };
    match hash_type {
        HashType::Sha256 => collect_oci::<Sha256HashValue>(&repo_path, current, false, true),
        HashType::Sha512 => collect_oci::<Sha512HashValue>(&repo_path, current, false, true),
    }
}

/// Complete OCI image tags and manifest digests from the active repository.
#[cfg(feature = "oci")]
pub fn complete_oci_tags_and_digests(current: &OsStr) -> Vec<CompletionCandidate> {
    let Some((repo_path, hash_type)) = resolve_repo_for_completion() else {
        return vec![];
    };
    match hash_type {
        HashType::Sha256 => collect_oci::<Sha256HashValue>(&repo_path, current, true, true),
        HashType::Sha512 => collect_oci::<Sha512HashValue>(&repo_path, current, true, true),
    }
}

#[cfg(feature = "oci")]
fn collect_oci<ObjectID: FsVerityHashValue>(
    repo_path: &Path,
    prefix: &OsStr,
    tags: bool,
    digests: bool,
) -> Vec<CompletionCandidate> {
    let Some(repo) = Repository::<ObjectID>::open_path(CWD, repo_path).ok() else {
        return vec![];
    };
    let Ok(images) = composefs_oci::oci_image::list_images(&repo) else {
        return vec![];
    };
    let prefix = prefix.as_encoded_bytes();
    let mut out = Vec::new();
    for img in &images {
        if tags && img.name.as_bytes().starts_with(prefix) {
            out.push(CompletionCandidate::new(&img.name));
        }
        if digests {
            let d: &str = img.manifest_digest.as_ref();
            if d.as_bytes().starts_with(prefix) {
                out.push(CompletionCandidate::new(d));
            }
        }
    }
    out
}

/// Complete ostree commit references from the active repository.
#[cfg(feature = "ostree")]
pub fn complete_ostree_refs(current: &OsStr) -> Vec<CompletionCandidate> {
    let Some((repo_path, hash_type)) = resolve_repo_for_completion() else {
        return vec![];
    };
    match hash_type {
        HashType::Sha256 => collect_ostree_refs::<Sha256HashValue>(&repo_path, current),
        HashType::Sha512 => collect_ostree_refs::<Sha512HashValue>(&repo_path, current),
    }
}

#[cfg(feature = "ostree")]
fn collect_ostree_refs<ObjectID: FsVerityHashValue>(
    repo_path: &Path,
    prefix: &OsStr,
) -> Vec<CompletionCandidate> {
    let Some(repo) = Repository::<ObjectID>::open_path(CWD, repo_path).ok() else {
        return vec![];
    };
    let Ok(commits) = composefs_ostree::list_commits(&repo) else {
        return vec![];
    };
    let prefix = prefix.as_encoded_bytes();
    commits
        .into_iter()
        .filter(|c| c.name.as_bytes().starts_with(prefix))
        .map(|c| CompletionCandidate::new(c.name))
        .collect()
}

#[derive(Clone, Copy)]
enum RefKind {
    Image,
    Stream,
}

/// Complete image names (`refs/…`) from the active repository.
pub fn complete_image_refs(current: &OsStr) -> Vec<CompletionCandidate> {
    complete_refs(current, RefKind::Image)
}

/// Complete stream names (`refs/…`) from the active repository.
pub fn complete_stream_refs(current: &OsStr) -> Vec<CompletionCandidate> {
    complete_refs(current, RefKind::Stream)
}

fn complete_refs(current: &OsStr, kind: RefKind) -> Vec<CompletionCandidate> {
    let Some((repo_path, hash_type)) = resolve_repo_for_completion() else {
        return vec![];
    };
    match hash_type {
        HashType::Sha256 => collect_refs::<Sha256HashValue>(&repo_path, current, kind),
        HashType::Sha512 => collect_refs::<Sha512HashValue>(&repo_path, current, kind),
    }
}

fn collect_refs<ObjectID: FsVerityHashValue>(
    repo_path: &Path,
    prefix: &OsStr,
    kind: RefKind,
) -> Vec<CompletionCandidate> {
    let Some(repo) = Repository::<ObjectID>::open_path(CWD, repo_path).ok() else {
        return vec![];
    };
    let refs = match kind {
        RefKind::Image => repo.list_image_refs(""),
        RefKind::Stream => repo.list_stream_refs(""),
    };
    let Ok(refs) = refs else {
        return vec![];
    };
    let prefix = prefix.as_encoded_bytes();
    refs.into_iter()
        .filter_map(|(name, _)| {
            let candidate = format!("refs/{name}");
            candidate
                .as_bytes()
                .starts_with(prefix)
                .then(|| CompletionCandidate::new(candidate))
        })
        .collect()
}
