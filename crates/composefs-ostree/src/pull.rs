//! Ostree pull support

use anyhow::{Result, bail};
use composefs::{fsverity::FsVerityHashValue, repository::Repository, util::Sha256Digest};
use gvariant::aligned_bytes::{AlignedBuf, AsAligned};
use gvariant::{Marker, Structure, gv};
use indicatif::ProgressBar;
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::time::Instant;
use std::{fmt, sync::Arc};

use crate::commit::{CommitReader, CommitWriter};
use crate::repo::{ObjectType, OstreeRepo};

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

#[derive(Debug)]
pub(crate) struct PullOperation<ObjectID: FsVerityHashValue, RepoType: OstreeRepo<ObjectID>> {
    repo: Arc<Repository<ObjectID>>,
    writer: CommitWriter<ObjectID>,
    commit_id: Option<Sha256Digest>,
    ostree_repo: RepoType,
    base_commits: Vec<CommitReader<ObjectID>>,
    outstanding: VecDeque<Outstanding>,
    // All ids that were ever enqueued (including already fetched and currently being fetched)
    fetched: HashSet<Sha256Digest>,
}

impl<ObjectID: FsVerityHashValue, RepoType: OstreeRepo<ObjectID>>
    PullOperation<ObjectID, RepoType>
{
    pub fn new(repo: &Arc<Repository<ObjectID>>, ostree_repo: RepoType) -> Self {
        PullOperation {
            repo: repo.clone(),
            commit_id: None,
            writer: CommitWriter::<ObjectID>::new(),
            ostree_repo,
            outstanding: VecDeque::new(),
            base_commits: vec![],
            fetched: HashSet::new(),
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
        self.commit_id = Some(*id);
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

    fn maybe_fetch_file(&mut self, id: &Sha256Digest) {
        if self.writer.contains(id) {
            return;
        }

        for base in self.base_commits.iter() {
            if let Some((obj_id, file_header)) = base.lookup(id) {
                self.add_file(id, obj_id.cloned().as_ref(), file_header.to_owned());
                return;
            }
        }

        self.enqueue_fetch(id, ObjectType::File);
    }

    fn add_file(&mut self, id: &Sha256Digest, obj_id: Option<&ObjectID>, file_header: AlignedBuf) {
        self.insert_file(id, obj_id, file_header);
    }

    fn maybe_fetch_dirmeta(&mut self, id: &Sha256Digest) {
        if self.writer.contains(id) {
            return;
        }

        for base in self.base_commits.iter() {
            if let Some(dirmeta) = base.lookup_data(id) {
                self.add_dirmeta(id, dirmeta.to_owned());
                return;
            }
        }

        self.enqueue_fetch(id, ObjectType::DirMeta);
    }

    fn add_dirmeta(&mut self, id: &Sha256Digest, data: AlignedBuf) {
        self.insert_dirmeta(id, &data);
    }

    fn maybe_fetch_dirtree(&mut self, id: &Sha256Digest) -> Result<()> {
        if self.writer.contains(id) {
            return Ok(());
        }

        for base in self.base_commits.iter() {
            if let Some(dirtree) = base.lookup_data(id) {
                return self.add_dirtree(id, dirtree.to_owned());
            }
        }

        self.enqueue_fetch(id, ObjectType::DirTree);

        Ok(())
    }

    fn add_dirtree(&mut self, id: &Sha256Digest, buf: AlignedBuf) -> Result<()> {
        let data = gv!("(a(say)a(sayay))").cast(buf.as_aligned());
        let (files_data, dirs_data) = data.to_tuple();

        for f in files_data.iter() {
            let (_name, checksum) = f.to_tuple();

            self.maybe_fetch_file(checksum.try_into()?);
        }

        for d in dirs_data.iter() {
            let (_name, tree_checksum, meta_checksum) = d.to_tuple();

            self.maybe_fetch_dirmeta(meta_checksum.try_into()?);
            self.maybe_fetch_dirtree(tree_checksum.try_into()?)?;
        }

        self.insert_dirtree(id, &buf);
        Ok(())
    }

    fn add_commit(&mut self, id: &Sha256Digest, buf: AlignedBuf) -> Result<()> {
        let data = gv!("(a{sv}aya(say)sstayay)").cast(&buf);
        let (
            _metadata_data,
            _parent_checksum,
            _related_objects,
            _subject,
            _body,
            _timestamp,
            root_tree,
            root_metadata,
        ) = data.to_tuple();

        self.maybe_fetch_dirmeta(root_metadata.try_into()?);
        self.maybe_fetch_dirtree(root_tree.try_into()?)?;

        self.insert_commit(id, &buf);

        Ok(())
    }

    pub async fn pull_commit(&mut self, commit_id: &Sha256Digest) -> Result<ObjectID> {
        let content_id = format!("ostree-commit-{}", hex::encode(commit_id));
        if let Some(objid) = self.repo.has_stream(&content_id)? {
            return Ok(objid);
        }

        self.enqueue_fetch(commit_id, ObjectType::Commit);

        // TODO: Support deltas

        let metadata_bar = ProgressBar::new_spinner().with_message("Fetching metadata");
        let files_bar = ProgressBar::new(0);
        let mut finished_metadata = false;

        // TODO: At least for http we should make parallel fetches
        let mut last_tick = Instant::now();
        while !self.outstanding.is_empty() {
            if last_tick.elapsed().as_millis() >= 200 {
                metadata_bar.tick();
                last_tick = Instant::now();
            }

            let fetch = self.outstanding.pop_front().unwrap();
            match fetch.obj_type {
                ObjectType::Commit => {
                    let data = self
                        .ostree_repo
                        .fetch_object(&fetch.id, fetch.obj_type)
                        .await?;
                    let data_sha = Sha256::digest(&*data);
                    if *data_sha != fetch.id {
                        bail!(
                            "Invalid commit checksum {:?}, expected {:?}",
                            data_sha,
                            fetch.id
                        );
                    }
                    self.add_commit(&fetch.id, data)?;
                }
                ObjectType::DirMeta => {
                    let data = self
                        .ostree_repo
                        .fetch_object(&fetch.id, fetch.obj_type)
                        .await?;
                    let data_sha = Sha256::digest(&*data);
                    if *data_sha != fetch.id {
                        bail!(
                            "Invalid dirmeta checksum {:?}, expected {:?}",
                            data_sha,
                            fetch.id
                        );
                    }
                    self.add_dirmeta(&fetch.id, data);
                }
                ObjectType::DirTree => {
                    let data = self
                        .ostree_repo
                        .fetch_object(&fetch.id, fetch.obj_type)
                        .await?;
                    let data_sha = Sha256::digest(&*data);
                    if *data_sha != fetch.id {
                        bail!(
                            "Invalid dirtree checksum {:?}, expected {:?}",
                            data_sha,
                            fetch.id
                        );
                    }
                    self.add_dirtree(&fetch.id, data)?;
                }
                ObjectType::File => {
                    if !finished_metadata {
                        finished_metadata = true;
                        metadata_bar.finish_and_clear();
                        files_bar.set_length(self.outstanding.len() as u64 + 1);
                        files_bar.tick();
                    }
                    let (file_header, obj_id) = self.ostree_repo.fetch_file(&fetch.id).await?;

                    self.add_file(&fetch.id, obj_id.as_ref(), file_header);
                    files_bar.inc(1);
                }
                _ => {}
            }
        }
        if !finished_metadata {
            metadata_bar.finish_and_clear();
        } else {
            files_bar.finish();
        }

        let commit_id = self.writer.serialize(&self.repo, &content_id)?;

        Ok(commit_id)
    }
}
