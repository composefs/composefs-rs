//! Ostree commit splitstream serialization and deserialization.
//!
//! Implements the binary format described in `doc/ostree.md`: a sorted array
//! of ostree object IDs with bucket-indexed lookup, per-object data refs
//! (with optional external content references), and an 8-byte-aligned content
//! region.
use anyhow::{Result, anyhow, bail, ensure};
use gvariant::aligned_bytes::{A8, AlignedBuf, AlignedSlice, TryAsAligned};
use std::{fmt, io::Read, mem::size_of, sync::Arc};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
};

use composefs::{
    fsverity::FsVerityHashValue,
    generic_tree::LeafId,
    repository::Repository,
    tree::{Directory, FileSystem, Inode, LeafContent, RegularFile, Stat},
    util::Sha256Digest,
};

use crate::ostree::{
    CommitMetadata, OstreeCommit, OstreeDirMeta, OstreeDirTree, OstreeFileHeader,
    should_inline_file, split_sized_variant,
};

const OSTREE_COMMIT_CONTENT_TYPE: u64 = 0xAFE138C18C463EF1;

fn stat_xattrs_to_vec(stat: &Stat) -> Vec<(Vec<u8>, Vec<u8>)> {
    stat.xattrs
        .iter()
        .map(|(k, v)| {
            let mut val = v.to_vec();
            // The kernel stores security.selinux with a NUL terminator,
            // but programmatic labeling (e.g. bootc's selabel()) may omit
            // it.  Canonicalize to always include the NUL so that ostree
            // checksums match what ostree fsck expects.
            if k.as_bytes() == b"security.selinux" && !val.ends_with(&[0]) {
                val.push(0);
            }
            (k.as_bytes().to_vec(), val)
        })
        .collect()
}

const S_IFMT: u32 = composefs::erofs::format::S_IFMT as u32;
const S_IFDIR: u32 = composefs::erofs::format::S_IFDIR as u32;
const S_IFLNK: u32 = composefs::erofs::format::S_IFLNK as u32;

fn xattrs_to_btreemap(xattrs: &[(Vec<u8>, Vec<u8>)]) -> BTreeMap<Box<OsStr>, Box<[u8]>> {
    xattrs
        .iter()
        .map(|(k, v)| (OsStr::from_bytes(k).into(), Box::from(v.as_slice())))
        .collect()
}

#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
struct CommitHeader {
    commit_id: u32,
    flags: u32,
    bucket_ends: [u32; 256],
}

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
struct Sha256DigestArray {
    ids: [Sha256Digest],
}

const NO_EXTERNAL_INDEX: u32 = u32::MAX;

#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout, Clone)]
#[repr(C)]
struct DataRef {
    /// Byte offset into the content region, divided by 8 (the alignment).
    data_block: u32,
    size: u32,
    external_index: u32,
}

impl DataRef {
    pub fn new(offset: usize, size: usize, external_index: Option<usize>) -> Result<Self> {
        ensure!(
            offset.is_multiple_of(8),
            "data offset {offset} is not 8-byte aligned"
        );
        let block = u32::try_from(offset / 8)
            .map_err(|_| anyhow!("data offset {offset} exceeds 32 GB limit"))?;
        let size = u32::try_from(size).map_err(|_| anyhow!("data size {size} exceeds u32::MAX"))?;
        Ok(DataRef {
            data_block: u32::to_le(block),
            size: u32::to_le(size),
            external_index: u32::to_le(match external_index {
                Some(idx) => idx as u32,
                None => NO_EXTERNAL_INDEX,
            }),
        })
    }
    pub fn get_offset(&self) -> usize {
        u32::from_le(self.data_block) as usize * 8
    }
    pub fn get_size(&self) -> usize {
        u32::from_le(self.size) as usize
    }
    pub fn get_external_index(&self) -> Option<usize> {
        match u32::from_le(self.external_index) {
            NO_EXTERNAL_INDEX => None,
            idx => Some(idx as usize),
        }
    }
}

#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
struct DataRefs {
    datas: [DataRef],
}

#[derive(Debug)]
struct WriterEntry<ObjectID: FsVerityHashValue> {
    ostree_id: Sha256Digest,
    external_object: Option<ObjectID>,
    data: AlignedBuf,
}

/// Accumulates ostree objects and serializes them into a commit splitstream.
#[derive(Debug)]
pub(crate) struct CommitWriter<ObjectID: FsVerityHashValue> {
    commit_id: Option<Sha256Digest>,
    map: Vec<WriterEntry<ObjectID>>,
}

impl<ObjectID: FsVerityHashValue> CommitWriter<ObjectID> {
    pub fn new() -> Self {
        CommitWriter {
            commit_id: None,
            map: vec![],
        }
    }

    fn lookup_idx(&self, ostree_id: &Sha256Digest) -> Option<usize> {
        self.map
            .binary_search_by_key(ostree_id, |e| e.ostree_id)
            .ok()
    }

    pub fn contains(&self, ostree_id: &Sha256Digest) -> bool {
        self.lookup_idx(ostree_id).is_some()
    }

    pub fn lookup_data(&self, ostree_id: &Sha256Digest) -> Option<&AlignedBuf> {
        self.lookup_idx(ostree_id).map(|i| &self.map[i].data)
    }

    pub fn set_commit_id(&mut self, id: &Sha256Digest) {
        self.commit_id = Some(*id);
    }

    pub fn insert(
        &mut self,
        ostree_id: &Sha256Digest,
        external_object: Option<&ObjectID>,
        data: &[u8],
    ) {
        if let Err(idx) = self.map.binary_search_by_key(ostree_id, |e| e.ostree_id) {
            let mut aligned_data = AlignedBuf::new();
            aligned_data.with_vec(|v| v.extend_from_slice(data));
            self.map.insert(
                idx,
                WriterEntry {
                    ostree_id: *ostree_id,
                    external_object: external_object.cloned(),
                    data: aligned_data,
                },
            );
        }
    }

    pub fn from_reader(reader: &CommitReader<ObjectID>) -> Result<Self> {
        let mut writer = CommitWriter::new();
        for (ostree_id, external_object, data) in reader.iter() {
            let data = data?;
            writer.insert(ostree_id, external_object, data);
        }
        writer.set_commit_id(&reader.commit_id());
        Ok(writer)
    }

    /// Build a commit from an in-memory filesystem tree.
    ///
    /// Walks the tree bottom-up, producing ostree dirtree/dirmeta/file
    /// objects with correct checksums, then creates the commit object.
    /// Returns the writer and the commit's ostree checksum.
    pub fn from_filesystem(
        repo: &Arc<Repository<ObjectID>>,
        fs: &FileSystem<ObjectID>,
        metadata: CommitMetadata,
    ) -> Result<(Self, Sha256Digest)> {
        let mut writer = CommitWriter::new();
        let mut leaf_cache: HashMap<LeafId, Sha256Digest> = HashMap::new();

        let (root_tree_id, root_meta_id) =
            Self::write_dir(repo, &mut writer, fs, &fs.root, &mut leaf_cache)?;

        let commit = metadata.into_commit(root_tree_id, root_meta_id);
        let commit_data = commit.serialize();
        let commit_id: Sha256Digest = Sha256::digest(&commit_data).into();
        writer.insert(&commit_id, None, &commit_data);
        writer.set_commit_id(&commit_id);

        Ok((writer, commit_id))
    }

    fn write_dir(
        repo: &Arc<Repository<ObjectID>>,
        writer: &mut CommitWriter<ObjectID>,
        fs: &FileSystem<ObjectID>,
        dir: &Directory<ObjectID>,
        leaf_cache: &mut HashMap<LeafId, Sha256Digest>,
    ) -> Result<(Sha256Digest, Sha256Digest)> {
        let mut file_entries = Vec::new();
        let mut dir_entries = Vec::new();

        for (name, inode) in dir.entries() {
            let name_str = name
                .to_str()
                .ok_or_else(|| anyhow!("non-UTF8 filename: {:?}", name))?;
            match inode {
                Inode::Leaf(leaf_id, _) => {
                    let checksum = if let Some(cached) = leaf_cache.get(leaf_id) {
                        *cached
                    } else {
                        let checksum = Self::write_leaf(repo, writer, fs, *leaf_id)?;
                        leaf_cache.insert(*leaf_id, checksum);
                        checksum
                    };
                    file_entries.push((name_str.to_string(), checksum));
                }
                Inode::Directory(subdir) => {
                    let (tree_id, meta_id) = Self::write_dir(repo, writer, fs, subdir, leaf_cache)?;
                    dir_entries.push((name_str.to_string(), tree_id, meta_id));
                }
            }
        }

        let dirmeta = OstreeDirMeta {
            uid: dir.stat.st_uid,
            gid: dir.stat.st_gid,
            mode: (dir.stat.st_mode & !S_IFMT) | S_IFDIR,
            xattrs: stat_xattrs_to_vec(&dir.stat),
        };
        let dirmeta_data = dirmeta.serialize();
        let dirmeta_id: Sha256Digest = Sha256::digest(&dirmeta_data).into();
        writer.insert(&dirmeta_id, None, &dirmeta_data);

        let dirtree = OstreeDirTree {
            files: file_entries,
            dirs: dir_entries,
        };
        let dirtree_data = dirtree.serialize();
        let dirtree_id: Sha256Digest = Sha256::digest(&dirtree_data).into();
        writer.insert(&dirtree_id, None, &dirtree_data);

        Ok((dirtree_id, dirmeta_id))
    }

    fn write_leaf(
        repo: &Arc<Repository<ObjectID>>,
        writer: &mut CommitWriter<ObjectID>,
        fs: &FileSystem<ObjectID>,
        leaf_id: LeafId,
    ) -> Result<Sha256Digest> {
        let leaf = fs.leaf(leaf_id);

        let symlink_target = match &leaf.content {
            LeafContent::Symlink(target) => target
                .to_str()
                .ok_or_else(|| anyhow!("non-UTF8 symlink target: {:?}", target))?
                .to_string(),
            _ => String::new(),
        };

        let file_size = match &leaf.content {
            LeafContent::Regular(reg) => reg.file_size(),
            _ => 0,
        };

        let header = OstreeFileHeader {
            size: file_size,
            uid: leaf.stat.st_uid,
            gid: leaf.stat.st_gid,
            mode: (leaf.stat.st_mode & !S_IFMT) | leaf.content.file_type_bits(),
            symlink_target,
            xattrs: stat_xattrs_to_vec(&leaf.stat),
        };

        let regular_header = header.serialize_regular_sized();
        let zlib_header = header.serialize_zlib_sized();

        match &leaf.content {
            LeafContent::Regular(
                RegularFile::External(obj_id, size) | RegularFile::ExternalNoVerity(obj_id, size),
            ) if !should_inline_file::<ObjectID>(*size as usize) => {
                // Stream through the hasher without buffering the entire file.
                let mut hasher = Sha256::new();
                hasher.update(&*regular_header);
                let fd = repo.open_object(obj_id)?;
                let mut file = std::io::BufReader::new(std::fs::File::from(fd));
                let mut buf = [0u8; 8192];
                loop {
                    let n = std::io::Read::read(&mut file, &mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                let checksum: Sha256Digest = hasher.finalize().into();
                writer.insert(&checksum, Some(obj_id), &zlib_header);
                Ok(checksum)
            }
            _ => {
                // Inline content: symlinks, small files, devices, etc.
                let content: Option<Vec<u8>> = match &leaf.content {
                    LeafContent::Regular(RegularFile::Inline(data)) => Some(data.to_vec()),
                    LeafContent::Regular(
                        RegularFile::External(obj_id, _) | RegularFile::ExternalNoVerity(obj_id, _),
                    ) => Some(repo.read_object(obj_id)?),
                    LeafContent::Regular(RegularFile::Sparse(size)) => {
                        Some(vec![0u8; *size as usize])
                    }
                    _ => None,
                };

                let mut hasher = Sha256::new();
                hasher.update(&*regular_header);
                if let Some(ref bytes) = content {
                    hasher.update(bytes);
                }
                let checksum: Sha256Digest = hasher.finalize().into();

                if let Some(bytes) = content {
                    let mut data = zlib_header;
                    data.with_vec(|v| v.extend_from_slice(&bytes));
                    writer.insert(&checksum, None, &data);
                } else {
                    writer.insert(&checksum, None, &zlib_header);
                }
                Ok(checksum)
            }
        }
    }

    pub fn serialize(
        &self,
        repo: &Arc<Repository<ObjectID>>,
        content_id: &str,
        reference: Option<&str>,
        image_ref: Option<&ObjectID>,
    ) -> Result<ObjectID> {
        let mut ss = repo.create_stream(OSTREE_COMMIT_CONTENT_TYPE)?;

        if let Some(image_id) = image_ref {
            ss.add_named_stream_ref(crate::IMAGE_REF_KEY, image_id);
        }

        /* Ensure we can index and count items using u32 (leaving one for NO_EXTERNAL_INDEX) */
        let item_count = self.map.len();
        ensure!(
            item_count <= (NO_EXTERNAL_INDEX - 1) as usize,
            "Too many items in object map"
        );

        let objid = self
            .commit_id
            .as_ref()
            .ok_or_else(|| anyhow!("No commit id set"))?;
        let main_idx = self
            .lookup_idx(objid)
            .ok_or_else(|| anyhow!("commit object not in commit"))?;

        let mut header = CommitHeader {
            commit_id: u32::to_le(main_idx as u32),
            flags: 0,
            bucket_ends: [0; 256],
        };

        // Compute data offsets (running sum of aligned sizes)
        let mut data_size = 0usize;
        let data_offsets: Vec<usize> = self
            .map
            .iter()
            .map(|e| {
                let offset = data_size;
                data_size += e.data.len().next_multiple_of(8);
                offset
            })
            .collect();

        // DataRef::new() validates that offsets fit in u32 (as offset/8)

        // Compute bucket ends
        for e in self.map.iter() {
            // Initially end is just the count
            header.bucket_ends[e.ostree_id[0] as usize] += 1;
        }
        for i in 1..256 {
            // Then we sum them up to the end
            header.bucket_ends[i] += header.bucket_ends[i - 1];
        }
        // Convert buckets to little endian
        header
            .bucket_ends
            .iter_mut()
            .for_each(|b| *b = u32::to_le(*b));

        // Add header
        ss.write_inline(header.as_bytes());
        // Add mapped ids
        for e in self.map.iter() {
            ss.write_inline(&e.ostree_id);
        }
        // Add data refs
        for (e, &offset) in self.map.iter().zip(&data_offsets) {
            let idx = e
                .external_object
                .as_ref()
                .map(|external_object| ss.add_object_ref(external_object));
            let d = DataRef::new(offset, e.data.len(), idx)?;
            ss.write_inline(d.as_bytes());
        }

        // Add 8-aligned data chunks
        const ZERO_PAD: [u8; 7] = [0; 7];
        for e in self.map.iter() {
            ss.write_inline(&e.data);
            let padding = e.data.len().next_multiple_of(8) - e.data.len();
            if padding > 0 {
                ss.write_inline(&ZERO_PAD[..padding]);
            }
        }

        repo.write_stream(ss, content_id, reference)
    }
}

#[derive(Debug)]
struct ReaderEntry<ObjectID: FsVerityHashValue> {
    ostree_id: Sha256Digest,
    data_offset: usize,
    data_size: usize,
    external_object: Option<ObjectID>,
}

/// Reads and queries an ostree commit splitstream.
///
/// Provides lookup by ostree object ID (using bucket-accelerated binary search)
/// and can reconstruct a [`FileSystem`] tree from the stored commit DAG.
pub(crate) struct CommitReader<ObjectID: FsVerityHashValue> {
    map: Vec<ReaderEntry<ObjectID>>,
    commit_id: Sha256Digest,
    bucket_ends: [u32; 256],
    data: AlignedBuf,
}

impl<ObjectID: FsVerityHashValue> fmt::Debug for CommitReader<ObjectID> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut m = f.debug_map();
        for e in self.map.iter() {
            m.entry(
                &hex::encode(e.ostree_id),
                &format!("{:?}", self.lookup(&e.ostree_id)),
            );
        }
        m.finish()
    }
}

fn validate_buckets(buckets: &[u32; 256]) -> Result<()> {
    ensure!(
        buckets.windows(2).all(|w| w[0] <= w[1]),
        "Invalid commit bucket data"
    );
    Ok(())
}

impl<ObjectID: FsVerityHashValue> CommitReader<ObjectID> {
    pub fn load(repo: &Repository<ObjectID>, content_id: &str) -> Result<Self> {
        let mut ss = repo.open_stream(content_id, None, Some(OSTREE_COMMIT_CONTENT_TYPE))?;

        let mut buf = AlignedBuf::new();

        // Read and parse header
        buf.with_vec(|v| v.resize(size_of::<CommitHeader>(), 0u8));
        Read::read_exact(&mut ss, &mut buf)?;

        let h = CommitHeader::ref_from_bytes(&buf).map_err(|_| anyhow!("Invalid commit header"))?;

        let commit_id_idx = u32::from_le(h.commit_id) as usize;
        let buckets = h.bucket_ends.map(u32::from_le);
        validate_buckets(&buckets)?;
        let item_count = buckets[255] as usize;

        ensure!(commit_id_idx < item_count, "commit id out of bounds");

        // Read object IDs
        buf.with_vec(|v| v.resize(item_count * size_of::<Sha256Digest>(), 0u8));
        Read::read_exact(&mut ss, &mut buf)?;

        let ostree_ids = Sha256DigestArray::ref_from_bytes(&buf)
            .map_err(|_| anyhow!("Invalid object ID array"))?;
        ensure!(
            ostree_ids.ids.len() == item_count,
            "Invalid object ID array"
        );

        let commit_id = ostree_ids.ids[commit_id_idx];

        // Read data refs
        let mut data_buf = AlignedBuf::new();
        data_buf.with_vec(|v| v.resize(item_count * size_of::<DataRef>(), 0u8));
        Read::read_exact(&mut ss, &mut data_buf)?;

        let data_refs =
            DataRefs::ref_from_bytes(&data_buf).map_err(|_| anyhow!("Invalid data refs array"))?;
        ensure!(
            data_refs.datas.len() == item_count,
            "Invalid data refs array"
        );

        // Combine object ids and data into ReaderEntry map
        let map = ostree_ids
            .ids
            .iter()
            .zip(data_refs.datas.iter())
            .map(|(id, dref)| {
                let external_object = dref
                    .get_external_index()
                    .map(|idx| {
                        ss.lookup_external_ref(idx)
                            .ok_or_else(|| anyhow!("External ref index {idx} out of range"))
                            .cloned()
                    })
                    .transpose()?;
                Ok(ReaderEntry {
                    ostree_id: *id,
                    data_offset: dref.get_offset(),
                    data_size: dref.get_size(),
                    external_object,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Read remaining content data
        buf.with_vec(|v| {
            v.clear();
            ss.read_to_end(v)
        })?;

        Ok(CommitReader {
            map,
            commit_id,
            data: buf,
            bucket_ends: buckets,
        })
    }

    fn get_data(&self, entry: &ReaderEntry<ObjectID>) -> Result<&AlignedSlice<A8>> {
        let start = entry.data_offset;
        let end = start
            .checked_add(entry.data_size)
            .ok_or_else(|| anyhow!("Object data offset/size overflow"))?;
        self.data
            .get(start..end)
            .ok_or_else(|| anyhow!("Object data offset/size out of bounds"))?
            .try_as_aligned()
            .map_err(|_| anyhow!("Object data not 8-byte aligned"))
    }

    fn get_bucket(&self, ostree_id: &Sha256Digest) -> (usize, usize) {
        let first = ostree_id[0] as usize;
        let start = if first == 0 {
            0
        } else {
            self.bucket_ends[first - 1]
        };
        let end = self.bucket_ends[first];
        (start as usize, end as usize)
    }

    pub fn commit_id(&self) -> Sha256Digest {
        self.commit_id
    }

    pub fn lookup(
        &self,
        ostree_id: &Sha256Digest,
    ) -> Result<Option<(Option<&ObjectID>, &AlignedSlice<A8>)>> {
        let (start, end) = self.get_bucket(ostree_id);
        let in_bucket = self
            .map
            .get(start..end)
            .ok_or_else(|| anyhow!("Bucket range out of bounds"))?;
        let index = match in_bucket.binary_search_by_key(ostree_id, |e| e.ostree_id) {
            Ok(i) => i,
            Err(..) => return Ok(None),
        };
        let entry = &in_bucket[index];
        Ok(Some((
            entry.external_object.as_ref(),
            self.get_data(entry)?,
        )))
    }

    pub fn lookup_data(&self, ostree_id: &Sha256Digest) -> Result<Option<&AlignedSlice<A8>>> {
        match self.lookup(ostree_id)? {
            Some((None, data)) => Ok(Some(data)),
            _ => Ok(None),
        }
    }

    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&Sha256Digest, Option<&ObjectID>, Result<&AlignedSlice<A8>>)> {
        self.map
            .iter()
            .map(|e| (&e.ostree_id, e.external_object.as_ref(), self.get_data(e)))
    }

    fn create_filesystem_file(
        &self,
        fs: &mut FileSystem<ObjectID>,
        file_cache: &mut HashMap<Sha256Digest, LeafId>,
        id: &Sha256Digest,
    ) -> Result<LeafId> {
        // Make hardlinks for files that are already used
        if let Some(&leaf_id) = file_cache.get(id) {
            return Ok(leaf_id);
        }

        let (maybe_obj_id, file_header) = self.lookup(id)?.ok_or_else(|| {
            anyhow!(
                "Unexpectedly missing ostree file object {}",
                hex::encode(id)
            )
        })?;

        let (sized_data, remaining_data) = split_sized_variant(file_header)?;

        let file_header = OstreeFileHeader::from_zlib_sized(sized_data)?;
        let xattrs = xattrs_to_btreemap(&file_header.xattrs);

        let stat = Stat {
            st_mode: file_header.mode,
            st_uid: file_header.uid,
            st_gid: file_header.gid,
            st_mtim_sec: 0,
            st_mtim_nsec: 0,
            xattrs,
        };

        let content = if (stat.st_mode & S_IFMT) == S_IFLNK {
            LeafContent::Symlink(OsStr::new(&file_header.symlink_target).into())
        } else {
            let file = if let Some(obj_id) = maybe_obj_id {
                if !remaining_data.is_empty() {
                    bail!("Unexpected trailing file data");
                }
                RegularFile::External(obj_id.clone(), file_header.size)
            } else {
                RegularFile::Inline(remaining_data.into())
            };
            LeafContent::Regular(file)
        };

        let leaf_id = fs.push_leaf(stat, content);
        file_cache.insert(*id, leaf_id);
        Ok(leaf_id)
    }

    fn parse_dirmeta(&self, dirmeta_id: &Sha256Digest) -> Result<Stat> {
        let (_obj_id, dirmeta) = self.lookup(dirmeta_id)?.ok_or_else(|| {
            anyhow!(
                "Unexpectedly missing ostree dirmeta object {}",
                hex::encode(dirmeta_id)
            )
        })?;

        let dirmeta_sha = Sha256::digest(dirmeta);
        if *dirmeta_sha != *dirmeta_id {
            bail!(
                "Invalid dirmeta checksum {:?}, expected {:?}",
                dirmeta_sha,
                dirmeta_id
            );
        }

        let dm = OstreeDirMeta::from_data(dirmeta)?;
        let xattrs = xattrs_to_btreemap(&dm.xattrs);

        Ok(Stat {
            st_mode: dm.mode,
            st_uid: dm.uid,
            st_gid: dm.gid,
            st_mtim_sec: 0,
            st_mtim_nsec: 0,
            xattrs,
        })
    }

    fn create_filesystem_dir(
        &self,
        fs: &mut FileSystem<ObjectID>,
        file_cache: &mut HashMap<Sha256Digest, LeafId>,
        dirtree_id: &Sha256Digest,
    ) -> Result<Vec<(Box<OsStr>, Inode<ObjectID>)>> {
        let (_obj_id, dirtree) = self.lookup(dirtree_id)?.ok_or_else(|| {
            anyhow!(
                "Unexpectedly missing ostree dirtree object {}",
                hex::encode(dirtree_id)
            )
        })?;

        let tree = OstreeDirTree::from_data(dirtree)?;

        let mut entries = Vec::<(Box<OsStr>, Inode<ObjectID>)>::new();

        for (name, checksum) in &tree.files {
            let leaf_id = self.create_filesystem_file(fs, file_cache, checksum)?;
            entries.push((OsStr::new(name).into(), Inode::leaf(leaf_id)));
        }

        for (name, tree_checksum, meta_checksum) in &tree.dirs {
            let stat = self.parse_dirmeta(meta_checksum)?;
            let mut subdir = Directory::new(stat);
            for (name, inode) in self.create_filesystem_dir(fs, file_cache, tree_checksum)? {
                subdir.insert(&name, inode);
            }

            entries.push((
                OsStr::new(name.as_str()).into(),
                Inode::Directory(Box::new(subdir)),
            ));
        }

        Ok(entries)
    }

    /// Create a tree::Filesystem for the commit
    pub fn create_filesystem(&self) -> Result<FileSystem<ObjectID>> {
        let commit = self
            .lookup_data(&self.commit_id)?
            .ok_or_else(|| anyhow!("Unexpectedly missing commit object"))?;

        let commit = OstreeCommit::from_data(commit)?;

        let stat = self.parse_dirmeta(&commit.root_metadata)?;

        let mut fs = FileSystem::<ObjectID>::new(stat);

        let mut file_cache = HashMap::new();
        for (name, inode) in
            self.create_filesystem_dir(&mut fs, &mut file_cache, &commit.root_tree)?
        {
            fs.root.insert(&name, inode);
        }

        Ok(fs)
    }
}
