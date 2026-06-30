//! OSTree support for composefs repositories.
//!
//! This crate enables importing images from OSTree repositories into a composefs
//! repository, where they can be mounted as composefs images and share storage
//! (deduplication) with OCI or other image types.
//!
//! The main entry point is [`pull()`], which fetches an ostree commit from an
//! [`OstreeRepo`] implementation (either [`LocalRepo`] for on-disk repositories
//! or [`RemoteRepo`] for HTTP), stores it as a splitstream, and produces an
//! EROFS image that can be mounted.  Additional functions provide reference
//! management ([`tag`]/[`untag`]), listing ([`list_commits`]), and inspection
//! ([`inspect`]).
//!

use anyhow::{Context, Result, bail};
use rustix::fs::{AtFlags, Dir, OFlags, readlinkat, unlinkat};
use std::collections::HashSet;
use std::sync::Arc;

use composefs::{
    fsverity::FsVerityHashValue,
    progress::{NullReporter, ProgressEvent, SharedReporter},
    repository::Repository,
    tree::FileSystem,
    util::{Sha256Digest, parse_sha256},
};

/// Information about a stored ostree commit.
#[derive(Debug, Clone)]
pub struct CommitInfo {
    /// The decoded ref name (e.g. "fedora/40/x86_64")
    pub name: String,
    /// The ostree commit ID (hex)
    pub commit_id: String,
}

mod commit;
pub mod delta;
#[cfg(doc)]
pub mod design;
pub mod ostree;
mod pull;
pub mod repo;

use crate::commit::{CommitReader, CommitWriter};
pub use crate::delta::apply_delta_offline;
use crate::pull::PullOperation;
pub use crate::pull::PullStats;
pub use crate::repo::{LocalRepo, OstreeRepo, RemoteRepo};

/// Options for a [`pull`] operation.
#[derive(Default)]
pub struct PullOptions<'a> {
    /// An existing ostree ref whose objects should be used as a base to avoid
    /// re-fetching shared content.
    pub base_reference: Option<&'a str>,

    /// Progress reporter for this pull operation.
    ///
    /// When `None`, all progress events are silently discarded.
    pub progress: Option<SharedReporter>,
}

impl std::fmt::Debug for PullOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PullOptions")
            .field("base_reference", &self.base_reference)
            .field(
                "progress",
                if self.progress.is_some() {
                    &"Some(<ProgressReporter>)"
                } else {
                    &"None"
                },
            )
            .finish()
    }
}

const OSTREE_REF_PREFIX: &str = "ostree/";
const IMAGE_REF_KEY: &str = "composefs.image";

fn ostree_ref_path(name: &str) -> String {
    format!(
        "{OSTREE_REF_PREFIX}{}",
        name.replace('%', "%25").replace('/', "%2F")
    )
}

/// Pull an ostree commit into the composefs repository.
///
/// The `ostree_repo` can be any [`OstreeRepo`] implementation — typically a
/// [`LocalRepo`] for on-disk repositories or a [`RemoteRepo`] for HTTP.
/// Automatically creates the EROFS image and links it from the commit splitstream.
/// `ostree_ref` can be either a ref name or a 64-character hex commit ID.
///
/// See [`PullOptions`] for tunable knobs (base commit, progress reporting).
pub async fn pull<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    ostree_repo: impl OstreeRepo<ObjectID> + 'static,
    ostree_ref: &str,
    opts: PullOptions<'_>,
) -> Result<(ObjectID, PullStats)> {
    let reporter: SharedReporter = opts.progress.unwrap_or_else(|| Arc::new(NullReporter));

    reporter.report(ProgressEvent::Message(format!("Fetching {ostree_ref}")));

    let (commit_checksum, reference) = if is_commit_id(ostree_ref) {
        (parse_sha256(ostree_ref)?, None)
    } else {
        let checksum = ostree_repo.resolve_ref(ostree_ref).await?;
        (checksum, Some(ostree_ref_path(ostree_ref)))
    };

    // Try delta pull first
    if let Some((verity, stats)) = ostree_repo.try_pull_delta(repo, &commit_checksum).await? {
        reporter.report(ProgressEvent::Message("Using static delta".into()));
        if let Some(ref_name) = reference {
            repo.name_stream(&format!("ostree-commit-{}", stats.commit_id), &ref_name)?;
        }
        return Ok((verity, stats));
    }

    let mut op = PullOperation::new(repo, ostree_repo, reporter);
    if let Some(base_name) = opts.base_reference {
        let base_ref = format!("refs/{}", ostree_ref_path(base_name));
        op.add_base(&base_ref)?;
    }

    let (verity, stats) = op
        .pull_commit(&commit_checksum, reference.as_deref())
        .await?;
    ensure_ostree_erofs(repo, &stats.commit_id)?;
    Ok((verity, stats))
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Returns `true` if the string is a full 64-character hex commit ID.
pub fn is_commit_id(s: &str) -> bool {
    s.len() == 64 && is_hex(s)
}

/// Finds the unique ostree commit stream whose commit ID starts with `prefix`.
fn resolve_commit_prefix<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    prefix: &str,
) -> Result<String> {
    let stream_prefix = format!("ostree-commit-{prefix}");

    if prefix.len() == 64 {
        if repo.has_stream(&stream_prefix)?.is_some() {
            return Ok(stream_prefix);
        }
        bail!("ostree commit {prefix} not found in repository");
    }

    let dir_fd = rustix::fs::openat(
        repo.repo_fd(),
        "streams",
        OFlags::RDONLY | OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )?;
    let mut match_name: Option<String> = None;
    for item in Dir::read_from(&dir_fd)? {
        let entry = item?;
        let name = entry.file_name().to_bytes();
        if let Ok(s) = std::str::from_utf8(name)
            && s.starts_with(&stream_prefix)
        {
            if match_name.is_some() {
                bail!("ambiguous commit ID prefix '{prefix}'");
            }
            match_name = Some(s.to_string());
        }
    }

    match_name
        .ok_or_else(|| anyhow::anyhow!("ostree commit prefix '{prefix}' not found in repository"))
}

/// Resolves a source (either an ostree ref name or a commit ID / prefix) to a stream content_id.
///
/// Validates that the resolved stream exists in the repository.
fn resolve_source<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    source: &str,
) -> Result<String> {
    // Try as an ostree ref first
    let ref_path = format!("streams/refs/{}", ostree_ref_path(source));
    if let Ok(target) = readlinkat(repo.repo_fd(), ref_path.as_str(), vec![])
        && let Ok(target_str) = target.into_string()
    {
        let content_id = target_str
            .rsplit('/')
            .next()
            .unwrap_or(&target_str)
            .to_string();
        if repo.has_stream(&content_id)?.is_none() {
            bail!("ref '{source}' points to missing stream '{content_id}'");
        }
        return Ok(content_id);
    }

    // Try as a commit ID or prefix
    if !is_hex(source) || source.len() > 64 {
        bail!("'{source}' is not a known ostree ref or valid commit ID");
    }

    resolve_commit_prefix(repo, source)
}

/// Tags an ostree commit with a named reference.
///
/// The `source` can be either an existing ostree ref name or a hex-encoded
/// ostree commit checksum. Creates a ref at `refs/ostree/{name}` pointing
/// to the commit's stream.
pub fn tag<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    source: &str,
    name: &str,
) -> Result<()> {
    let content_id = resolve_source(repo, source)?;
    let ref_name = ostree_ref_path(name);
    repo.name_stream(&content_id, &ref_name)
}

/// Removes a named ostree reference.
///
/// The commit data is not deleted; it becomes eligible for garbage collection
/// if no other references point to it.
pub fn untag<ObjectID: FsVerityHashValue>(repo: &Repository<ObjectID>, name: &str) -> Result<()> {
    let ref_path = format!("streams/refs/{}", ostree_ref_path(name));
    unlinkat(repo.repo_fd(), &ref_path, AtFlags::empty())
        .with_context(|| format!("Failed to remove tag {name}"))?;
    Ok(())
}

fn decode_ref(encoded: &str) -> String {
    encoded.replace("%2F", "/").replace("%25", "%")
}

/// Lists all ostree commits stored in the repository.
pub fn list_commits<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
) -> Result<Vec<CommitInfo>> {
    let commits = repo
        .list_stream_refs(OSTREE_REF_PREFIX)?
        .into_iter()
        .filter_map(|(encoded_name, target)| {
            let target_name = target.rsplit('/').next().unwrap_or(&target);
            target_name
                .strip_prefix("ostree-commit-")
                .map(|commit_id| CommitInfo {
                    name: decode_ref(&encoded_name),
                    commit_id: commit_id.to_string(),
                })
        })
        .collect();

    Ok(commits)
}

/// Returns the set of ostree commit checksums stored in the repository.
fn list_local_commit_ids<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
) -> Result<HashSet<Sha256Digest>> {
    let dir_fd = rustix::fs::openat(
        repo.repo_fd(),
        "streams",
        OFlags::RDONLY | OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )?;
    let mut ids = HashSet::new();
    for item in Dir::read_from(&dir_fd)? {
        let entry = item?;
        let name = entry.file_name().to_bytes();
        if let Ok(s) = std::str::from_utf8(name)
            && let Some(hex) = s.strip_prefix("ostree-commit-")
            && hex.len() == 64
            && let Ok(checksum) = parse_sha256(hex)
        {
            ids.insert(checksum);
        }
    }
    Ok(ids)
}

/// Ensures the EROFS image exists for a commit and stores a named ref to it
/// in the commit splitstream.
///
/// `source` can be an ostree ref name or a commit ID / prefix.
pub fn ensure_ostree_erofs<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    source: &str,
) -> Result<ObjectID> {
    let content_id = resolve_source(repo, source)?;

    let ss = repo.open_stream(&content_id, None, None)?;
    if let Some(id) = ss.lookup_named_ref(IMAGE_REF_KEY) {
        return Ok(id.clone());
    }

    let commit = CommitReader::<ObjectID>::load(repo, &content_id)?;
    let fs = commit.create_filesystem()?;
    let image_id = fs.commit_image(repo, None)?;

    let writer = CommitWriter::from_reader(&commit)?;
    writer.serialize(repo, &content_id, None, Some(&image_id))?;

    Ok(image_id)
}

/// Returns the EROFS image ObjectID stored in a commit's splitstream.
///
/// The `source` can be an ostree ref name or a commit ID / prefix.
pub fn get_image_ref<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    source: &str,
) -> Result<ObjectID> {
    let content_id = resolve_source(repo, source)?;
    let ss = repo.open_stream(&content_id, None, None)?;
    ss.lookup_named_ref(IMAGE_REF_KEY)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no composefs image linked to '{source}' — try re-pulling"))
}

/// Creates a filesystem from the given OSTree commit.
///
/// The `commit_name` is looked up as a ref under `refs/ostree/`.
pub fn create_filesystem<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    commit_name: &str,
) -> Result<FileSystem<ObjectID>> {
    let ref_path = format!("refs/{}", ostree_ref_path(commit_name));
    let commit = CommitReader::<ObjectID>::load(repo, &ref_path)?;
    let fs = commit.create_filesystem()?;

    Ok(fs)
}

/// Prints the contents of an ostree commit object.
///
/// `source` can be an ostree ref name or a commit ID / prefix.
/// If `metadata_only` is true, only the commit metadata key-value pairs are printed.
pub fn inspect<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    source: &str,
    metadata_only: bool,
) -> Result<()> {
    let content_id = resolve_source(repo, source)?;
    let reader = CommitReader::<ObjectID>::load(repo, &content_id)?;
    let commit_id = reader.commit_id();

    let commit_data = reader
        .lookup_data(&commit_id)?
        .ok_or_else(|| anyhow::anyhow!("commit object not found in stream"))?;
    let commit = crate::ostree::OstreeCommit::from_data(commit_data)?;

    if metadata_only {
        for (key, value) in &commit.metadata {
            println!("{key}={value}");
        }
        return Ok(());
    }

    println!("commit  {}", hex::encode(commit_id));
    if let Some(parent) = &commit.parent_commit {
        println!("parent  {}", hex::encode(parent));
    }
    if let Some(dt) = chrono::DateTime::from_timestamp(commit.timestamp as i64, 0) {
        println!("date    {}", dt.format("%Y-%m-%d %H:%M:%S UTC"));
    } else {
        println!("date    {}", commit.timestamp);
    }
    println!("tree    {}", hex::encode(commit.root_tree));
    println!("dirmeta {}", hex::encode(commit.root_metadata));
    if !commit.subject.is_empty() {
        println!("\n{}", commit.subject);
    }
    if !commit.body.is_empty() {
        println!("\n{}", commit.body);
    }

    Ok(())
}
