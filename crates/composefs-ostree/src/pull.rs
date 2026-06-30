//! Orchestrates pulling ostree commits into a composefs repository.
//!
//! A pull proceeds in two phases: first all metadata objects (commits, dirtrees,
//! dirmetas) are fetched with high concurrency, then file content objects are
//! fetched.  Previously-pulled commits can serve as a base to avoid re-fetching
//! shared objects.

use anyhow::{Result, bail};
use composefs::{
    fsverity::FsVerityHashValue,
    progress::{ComponentId, ProgressEvent, ProgressUnit, SharedReporter},
    repository::Repository,
    util::Sha256Digest,
};
use gvariant::aligned_bytes::AlignedBuf;
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::{fmt, sync::Arc};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::commit::{CommitReader, CommitWriter};
use crate::ostree::{ObjectType, OstreeCommit, OstreeDirTree};
use crate::repo::OstreeRepo;

/// Statistics from a pull operation.
#[derive(Debug, Default)]
pub struct PullStats {
    /// The ostree commit ID (hex).
    pub commit_id: String,
    /// Number of metadata objects (commits, dirtrees, dirmetas) fetched.
    pub metadata_fetched: usize,
    /// Number of file objects fetched.
    pub files_fetched: usize,
}

const MAX_CONCURRENT_METADATA_FETCHES: usize = 32;
const MAX_CONCURRENT_CONTENT_FETCHES: usize = 8;

struct Outstanding {
    id: Sha256Digest,
    obj_type: ObjectType,
}

impl fmt::Debug for Outstanding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outstanding")
            .field("id", &hex::encode(self.id))
            .field("obj_type", &self.obj_type)
            .finish()
    }
}

enum FetchResult<ObjectID: FsVerityHashValue> {
    Metadata {
        id: Sha256Digest,
        obj_type: ObjectType,
        data: AlignedBuf,
    },
    File {
        id: Sha256Digest,
        file_header: AlignedBuf,
        obj_id: Option<ObjectID>,
    },
}

/// Drives a two-phase pull of an ostree commit into a composefs repository.
pub(crate) struct PullOperation<ObjectID: FsVerityHashValue, RepoType: OstreeRepo<ObjectID>> {
    repo: Arc<Repository<ObjectID>>,
    writer: CommitWriter<ObjectID>,
    ostree_repo: Arc<RepoType>,
    reporter: SharedReporter,
    base_commits: Vec<CommitReader<ObjectID>>,
    outstanding: VecDeque<Outstanding>,
    // All ids that were ever enqueued (including already fetched and currently being fetched)
    fetched: HashSet<Sha256Digest>,
    stats: PullStats,
}

impl<ObjectID: FsVerityHashValue, RepoType: OstreeRepo<ObjectID> + 'static>
    PullOperation<ObjectID, RepoType>
{
    pub fn new(
        repo: &Arc<Repository<ObjectID>>,
        ostree_repo: RepoType,
        reporter: SharedReporter,
    ) -> Self {
        PullOperation {
            repo: repo.clone(),
            writer: CommitWriter::<ObjectID>::new(),
            ostree_repo: Arc::new(ostree_repo),
            reporter,
            outstanding: VecDeque::new(),
            base_commits: vec![],
            fetched: HashSet::new(),
            stats: PullStats::default(),
        }
    }

    pub fn add_base(&mut self, base_name: &str) -> Result<()> {
        let base = CommitReader::<ObjectID>::load(&self.repo, base_name)?;
        self.base_commits.push(base);
        Ok(())
    }

    fn enqueue_fetch(&mut self, id: &Sha256Digest, obj_type: ObjectType) {
        // To avoid fetching twice, even if the id is not in the outstanding list
        // (for example we may be currenly downloading it) we keep all ids we ever
        // fetch in a map
        if self.fetched.contains(id) {
            return;
        }
        self.fetched.insert(*id);
        // We request metadata objects first
        if obj_type == ObjectType::File {
            self.outstanding
                .push_back(Outstanding { id: *id, obj_type });
        } else {
            self.outstanding
                .push_front(Outstanding { id: *id, obj_type });
        }
    }

    fn insert_commit(&mut self, id: &Sha256Digest, data: &[u8]) {
        self.writer.insert(id, None, data);
        self.writer.set_commit_id(id);
    }

    fn insert_dirmeta(&mut self, id: &Sha256Digest, data: &[u8]) {
        self.writer.insert(id, None, data);
    }

    fn insert_dirtree(&mut self, id: &Sha256Digest, data: &[u8]) {
        self.writer.insert(id, None, data);
    }

    fn insert_file(
        &mut self,
        id: &Sha256Digest,
        obj_id: Option<&ObjectID>,
        file_header: AlignedBuf,
    ) {
        self.writer.insert(id, obj_id, &file_header);
    }

    fn maybe_fetch_file(&mut self, id: &Sha256Digest) -> Result<()> {
        if self.writer.contains(id) {
            return Ok(());
        }

        for base in self.base_commits.iter() {
            if let Some((obj_id, file_header)) = base.lookup(id)? {
                self.add_file(id, obj_id.cloned().as_ref(), file_header.to_owned());
                return Ok(());
            }
        }

        self.enqueue_fetch(id, ObjectType::File);
        Ok(())
    }

    fn add_file(&mut self, id: &Sha256Digest, obj_id: Option<&ObjectID>, file_header: AlignedBuf) {
        self.insert_file(id, obj_id, file_header);
    }

    fn maybe_fetch_dirmeta(&mut self, id: &Sha256Digest) -> Result<()> {
        if self.writer.contains(id) {
            return Ok(());
        }

        for base in self.base_commits.iter() {
            if let Some(dirmeta) = base.lookup_data(id)? {
                self.add_dirmeta(id, dirmeta.to_owned());
                return Ok(());
            }
        }

        self.enqueue_fetch(id, ObjectType::DirMeta);
        Ok(())
    }

    fn add_dirmeta(&mut self, id: &Sha256Digest, data: AlignedBuf) {
        self.insert_dirmeta(id, &data);
    }

    fn maybe_fetch_dirtree(&mut self, id: &Sha256Digest) -> Result<()> {
        if self.writer.contains(id) {
            return Ok(());
        }

        for base in self.base_commits.iter() {
            if let Some(dirtree) = base.lookup_data(id)? {
                return self.add_dirtree(id, dirtree.to_owned());
            }
        }

        self.enqueue_fetch(id, ObjectType::DirTree);

        Ok(())
    }

    fn add_dirtree(&mut self, id: &Sha256Digest, buf: AlignedBuf) -> Result<()> {
        let dirtree = OstreeDirTree::from_data(&buf)?;

        for (_name, checksum) in &dirtree.files {
            self.maybe_fetch_file(checksum)?;
        }

        for (_name, tree_checksum, meta_checksum) in &dirtree.dirs {
            self.maybe_fetch_dirmeta(meta_checksum)?;
            self.maybe_fetch_dirtree(tree_checksum)?;
        }

        self.insert_dirtree(id, &buf);
        Ok(())
    }

    fn add_commit(&mut self, id: &Sha256Digest, buf: AlignedBuf) -> Result<()> {
        let commit = OstreeCommit::from_data(&buf)?;

        if let Some(parent_id) = &commit.parent_commit {
            let parent_stream = format!("ostree-commit-{}", hex::encode(parent_id));
            if self.repo.has_stream(&parent_stream)?.is_some()
                && !self
                    .base_commits
                    .iter()
                    .any(|b| b.commit_id() == *parent_id)
            {
                let base = CommitReader::<ObjectID>::load(&self.repo, &parent_stream)?;
                self.base_commits.push(base);
            }
        }

        self.maybe_fetch_dirmeta(&commit.root_metadata)?;
        self.maybe_fetch_dirtree(&commit.root_tree)?;

        self.insert_commit(id, &buf);

        Ok(())
    }

    fn process_metadata(
        &mut self,
        id: &Sha256Digest,
        obj_type: ObjectType,
        data: AlignedBuf,
    ) -> Result<()> {
        let data_sha = Sha256::digest(&*data);
        if *data_sha != *id {
            bail!(
                "Invalid {:?} checksum {:?}, expected {:?}",
                obj_type,
                data_sha,
                id
            );
        }
        match obj_type {
            ObjectType::Commit => self.add_commit(id, data),
            ObjectType::DirTree => self.add_dirtree(id, data),
            ObjectType::DirMeta => {
                self.add_dirmeta(id, data);
                Ok(())
            }
            _ => bail!("Unexpected metadata object type {:?}", obj_type),
        }
    }

    fn pop_metadata(&mut self) -> Option<Outstanding> {
        match self.outstanding.front() {
            Some(front) if front.obj_type != ObjectType::File => self.outstanding.pop_front(),
            _ => None,
        }
    }

    fn drain_files(&mut self) -> Vec<Outstanding> {
        let files: Vec<_> = self.outstanding.drain(..).collect();
        debug_assert!(files.iter().all(|f| f.obj_type == ObjectType::File));
        files
    }

    pub async fn pull_commit(
        &mut self,
        commit_id: &Sha256Digest,
        reference: Option<&str>,
    ) -> Result<(ObjectID, PullStats)> {
        let commit_hex = hex::encode(commit_id);
        let content_id = format!("ostree-commit-{commit_hex}");
        if let Some(objid) = self.repo.has_stream(&content_id)? {
            return Ok((
                objid,
                PullStats {
                    commit_id: commit_hex,
                    ..Default::default()
                },
            ));
        }
        self.stats.commit_id = commit_hex;

        self.enqueue_fetch(commit_id, ObjectType::Commit);

        // TODO: Support deltas

        let metadata_id: ComponentId = "metadata".into();
        self.reporter.report(ProgressEvent::Started {
            id: metadata_id.clone(),
            total: None,
            unit: ProgressUnit::Items,
        });
        let metadata_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_METADATA_FETCHES));

        // Phase 1: Fetch all metadata (commits, dirtrees, dirmetas) in parallel.
        // Processing results may discover new metadata to fetch, so we loop
        // until the queue is drained and all in-flight fetches have completed.
        let mut join_set: JoinSet<Result<FetchResult<ObjectID>>> = JoinSet::new();

        loop {
            while let Some(item) = self.pop_metadata() {
                let permit = match metadata_semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        self.outstanding.push_front(item);
                        break;
                    }
                };
                let ostree_repo = self.ostree_repo.clone();
                join_set.spawn(async move {
                    let data = ostree_repo.fetch_object(&item.id, item.obj_type).await?;
                    drop(permit);
                    Ok(FetchResult::Metadata {
                        id: item.id,
                        obj_type: item.obj_type,
                        data,
                    })
                });
            }

            match join_set.join_next().await {
                Some(result) => {
                    let fetch = result??;
                    match fetch {
                        FetchResult::Metadata { id, obj_type, data } => {
                            self.stats.metadata_fetched += 1;
                            self.reporter.report(ProgressEvent::Progress {
                                id: metadata_id.clone(),
                                fetched: self.stats.metadata_fetched as u64,
                                total: None,
                            });
                            self.process_metadata(&id, obj_type, data)?;
                        }
                        _ => unreachable!(),
                    }
                }
                None => break,
            }
        }

        self.reporter.report(ProgressEvent::Done {
            id: metadata_id,
            transferred: self.stats.metadata_fetched as u64,
        });

        // Phase 2: Fetch all files in parallel. Files are leaf objects with
        // no dependencies on each other.
        let files = self.drain_files();
        if files.is_empty() {
            let commit_id = self
                .writer
                .serialize(&self.repo, &content_id, reference, None)?;
            let stats = std::mem::take(&mut self.stats);
            return Ok((commit_id, stats));
        }

        let files_total = files.len() as u64;
        let files_id: ComponentId = "files".into();
        self.reporter.report(ProgressEvent::Started {
            id: files_id.clone(),
            total: Some(files_total),
            unit: ProgressUnit::Items,
        });
        let content_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONTENT_FETCHES));
        let mut join_set: JoinSet<Result<FetchResult<ObjectID>>> = JoinSet::new();

        for item in files {
            let ostree_repo = self.ostree_repo.clone();
            let permit = content_semaphore.clone().acquire_owned().await?;
            join_set.spawn(async move {
                let (file_header, obj_id) = ostree_repo.fetch_file(&item.id).await?;
                drop(permit);
                Ok(FetchResult::File {
                    id: item.id,
                    file_header,
                    obj_id,
                })
            });
        }

        while let Some(result) = join_set.join_next().await {
            let fetch = result??;
            match fetch {
                FetchResult::File {
                    id,
                    file_header,
                    obj_id,
                } => {
                    self.stats.files_fetched += 1;
                    self.add_file(&id, obj_id.as_ref(), file_header);
                    self.reporter.report(ProgressEvent::Progress {
                        id: files_id.clone(),
                        fetched: self.stats.files_fetched as u64,
                        total: Some(files_total),
                    });
                }
                _ => unreachable!(),
            }
        }

        self.reporter.report(ProgressEvent::Done {
            id: files_id,
            transferred: self.stats.files_fetched as u64,
        });

        let commit_id = self
            .writer
            .serialize(&self.repo, &content_id, reference, None)?;
        let stats = std::mem::take(&mut self.stats);

        Ok((commit_id, stats))
    }
}
