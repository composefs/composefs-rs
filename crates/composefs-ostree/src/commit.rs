//! Ostree commit splitstream implementation

/* Implementation of the ostree commit splitstream format
 *
 * Commit splitstreams are mappings from a set of ostree sha256
 * digests into the content for that ostree object. The content is
 * defined as some data, and an optional ObjectID referencing an
 * external object.  In the case there is an external reference, the
 * data is the header of the ostree object.
 *
 * The file format is intended to be stored in a splitstream and
 * uses the splitstream header to reference the external object ids.
 *
 * An object file has this format:
 *  (All ints are in little endian)
 *
 * header:
 * +-----------------------------------+
 * | u32: index of commit object       |
 * | u32: flags                        |
 * +-----------------------------------+
 *
 * buckets;
 *  256 x (indexes are into ostree_ids)
 * +-----------------------------------+
 * | u32: end index of bucket          |
 * +-----------------------------------+
 *
 * ostree_ids:
 *  n_objects x (sorted)
 * +-----------------------------------+
 * |  [u8; 32] ostree object id        |
 * +-----------------------------------+
 *
 * object_data:
 *  n_objects x (same order as ostree_ids)
 * +-----------------------------------+
 * | u32: offset to per-object data    |
 * | u32: length of per-object data    |
 * | u32: Index of external object ref |
 * |      or MAXUINT32 if none.        |
 * +-----------------------------------+
 *
 * Offset are 8 byte aligned offsets from after the end of the
 * object_data array.
 *
 */
use anyhow::{Error, Result, bail};
use gvariant::aligned_bytes::{A8, AlignedBuf, AlignedSlice, AsAligned, TryAsAligned};
use std::{fmt, io::Read, mem::size_of, sync::Arc};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use gvariant::{Marker, Structure, gv};
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

use crate::repo::split_sized_variant;

const OSTREE_COMMIT_CONTENT_TYPE: u64 = 0xAFE138C18C463EF1;

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;

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
    offset: u32,
    size: u32,
    external_index: u32,
}

impl DataRef {
    pub fn new(offset: usize, size: usize, external_index: Option<usize>) -> Self {
        DataRef {
            offset: u32::to_le(offset as u32),
            size: u32::to_le(size as u32),
            external_index: u32::to_le(match external_index {
                Some(idx) => idx as u32,
                None => NO_EXTERNAL_INDEX,
            }),
        }
    }
    pub fn get_offset(&self) -> usize {
        u32::from_le(self.offset) as usize
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

#[derive(Debug)]
pub(crate) struct CommitWriter<ObjectID: FsVerityHashValue> {
    commit_id: Option<Sha256Digest>,
    map: Vec<WriterEntry<ObjectID>>,
}

fn align8(x: usize) -> usize {
    (x + 7) & !7
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

    pub fn set_commit_id(&mut self, id: &Sha256Digest) {
        self.commit_id = Some(*id);
    }

    pub fn insert(
        &mut self,
        ostree_id: &Sha256Digest,
        external_object: Option<&ObjectID>,
        data: &[u8],
    ) {
        match self.map.binary_search_by_key(ostree_id, |e| e.ostree_id) {
            Ok(_idx) => {}
            Err(idx) => {
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
    }

    pub fn serialize(
        &self,
        repo: &Arc<Repository<ObjectID>>,
        content_id: &str,
    ) -> Result<ObjectID> {
        let mut ss = repo.create_stream(OSTREE_COMMIT_CONTENT_TYPE)?;

        /* Ensure we can index and count items using u32 (leaving one for NO_EXTERNAL_INDEX) */
        let item_count = self.map.len();
        if item_count > (NO_EXTERNAL_INDEX - 1) as usize {
            return Err(Error::msg("Too many items in object map"));
        }

        let main_idx = if let Some(objid) = &self.commit_id {
            if let Some(idx) = self.lookup_idx(objid) {
                idx
            } else {
                return Err(Error::msg("commit object not in commit"));
            }
        } else {
            return Err(Error::msg("No commit id set"));
        };

        let mut header = CommitHeader {
            commit_id: u32::to_le(main_idx as u32),
            flags: 0,
            bucket_ends: [0; 256],
        };

        // Compute data offsets and add external object references
        let mut data_size = 0usize;
        let mut data_offsets = vec![0usize; item_count];
        for (i, e) in self.map.iter().enumerate() {
            data_offsets[i] = data_size;
            data_size += align8(e.data.len());
        }

        // Ensure all data can be indexed by u32
        if data_size > u32::MAX as usize {
            return Err(Error::msg("Too large data in object map"));
        }

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
        for i in 0..256 {
            header.bucket_ends[i] = u32::to_le(header.bucket_ends[i]);
        }

        // Add header
        ss.write_inline(header.as_bytes());
        // Add mapped ids
        for e in self.map.iter() {
            ss.write_inline(&e.ostree_id);
        }
        // Add data refs
        for (i, e) in self.map.iter().enumerate() {
            let idx = e
                .external_object
                .as_ref()
                .map(|external_object| ss.add_object_ref(external_object));
            let d = DataRef::new(data_offsets[i], e.data.len(), idx);
            ss.write_inline(d.as_bytes());
        }

        // Add 8-aligned data chunks
        for e in self.map.iter() {
            ss.write_inline(&e.data);
            // Pad to 8
            let padding = align8(e.data.len()) - e.data.len();
            if padding > 0 {
                ss.write_inline(&vec![0u8; padding]);
            }
        }

        repo.write_stream(ss, content_id, None)
    }
}

#[derive(Debug)]
struct ReaderEntry<ObjectID: FsVerityHashValue> {
    ostree_id: Sha256Digest,
    data_offset: usize,
    data_size: usize,
    external_object: Option<ObjectID>,
}

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
                &format!("{:?}", self.lookup(&e.ostree_id).unwrap()),
            );
        }
        m.finish()
    }
}

fn validate_buckets(buckets: &[u32; 256]) -> Result<()> {
    for i in 1..256 {
        // Bucket ends are (non-strictly) increasing
        if buckets[i] < buckets[i - 1] {
            return Err(Error::msg("Invalid commit bucket data"));
        }
    }
    Ok(())
}

impl<ObjectID: FsVerityHashValue> CommitReader<ObjectID> {
    pub fn load(repo: &Repository<ObjectID>, content_id: &str) -> Result<Self> {
        let mut ss = repo.open_stream(content_id, None, Some(OSTREE_COMMIT_CONTENT_TYPE))?;

        let mut buf = AlignedBuf::new();

        buf.with_vec(|v| v.resize(size_of::<CommitHeader>(), 0u8));
        let n_read = ss.read(&mut buf)?;
        if n_read != buf.len() {
            return Err(Error::msg("Not enough data"));
        }

        let h =
            CommitHeader::ref_from_bytes(&buf).map_err(|_e| Error::msg("Invalid commit header"))?;

        let commit_id_idx = u32::from_le(h.commit_id) as usize;

        let mut buckets: [u32; 256] = h.bucket_ends;
        for b in buckets.iter_mut() {
            *b = u32::from_le(*b);
        }
        validate_buckets(&buckets)?;
        let item_count = buckets[255] as usize;

        if commit_id_idx >= item_count {
            return Err(Error::msg("commit id out of bounds"));
        }

        buf.with_vec(|v| v.resize(item_count * size_of::<Sha256Digest>(), 0u8));
        let n_read = ss.read(&mut buf)?;
        if n_read != buf.len() {
            return Err(Error::msg("Not enough data"));
        };
        let ostree_ids = Sha256DigestArray::ref_from_bytes(&buf)
            .map_err(|_e| Error::msg("Invalid commit array"))?;

        if ostree_ids.ids.len() != item_count {
            return Err(Error::msg("Invalid commit array"));
        }

        let commit_id = ostree_ids.ids[commit_id_idx];

        let mut map = Vec::<ReaderEntry<ObjectID>>::with_capacity(item_count);
        for i in 0..item_count {
            map.push(ReaderEntry {
                ostree_id: ostree_ids.ids[i],
                data_offset: 0,
                data_size: 0,
                external_object: None,
            })
        }

        buf.with_vec(|v| v.resize(item_count * size_of::<DataRef>(), 0u8));
        let n_read = ss.read(&mut buf)?;
        if n_read != buf.len() {
            return Err(Error::msg("Not enough data"));
        };

        let data_refs =
            DataRefs::ref_from_bytes(&buf).map_err(|_e| Error::msg("Invalid commit array"))?;

        if data_refs.datas.len() != item_count {
            return Err(Error::msg("Invalid commit array"));
        }

        for (i, item) in map.iter_mut().enumerate() {
            let data = &data_refs.datas[i];

            item.data_offset = data.get_offset();
            item.data_size = data.get_size();
            item.external_object = if let Some(idx) = data.get_external_index() {
                ss.lookup_external_ref(idx).cloned()
            } else {
                None
            };
        }

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

    fn get_data(&self, entry: &ReaderEntry<ObjectID>) -> &AlignedSlice<A8> {
        let start = entry.data_offset;
        let end = start + entry.data_size;
        // The unwrap here is safe, because data is always 8 aligned
        self.data[start..end].try_as_aligned().unwrap()
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

    pub fn lookup(
        &self,
        ostree_id: &Sha256Digest,
    ) -> Option<(Option<&ObjectID>, &AlignedSlice<A8>)> {
        let (start, end) = self.get_bucket(ostree_id);
        let in_bucket = &self.map[start..end];
        let index = match in_bucket.binary_search_by_key(ostree_id, |e| e.ostree_id) {
            Ok(i) => i,
            Err(..) => return None,
        };
        let entry = &in_bucket[index];
        Some((entry.external_object.as_ref(), self.get_data(entry)))
    }

    pub fn lookup_data(&self, ostree_id: &Sha256Digest) -> Option<&AlignedSlice<A8>> {
        if let Some((None, data)) = self.lookup(ostree_id) {
            Some(data)
        } else {
            None
        }
    }

    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&Sha256Digest, Option<&ObjectID>, &AlignedSlice<A8>)> {
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

        let (maybe_obj_id, file_header) = self.lookup(id).ok_or(Error::msg(format!(
            "Unexpectedly missing ostree file object {}",
            hex::encode(id)
        )))?;

        let (_sized_data, variant_data, remaining_data) = split_sized_variant(file_header)?;

        let data = gv!("(tuuuusa(ayay))").cast(variant_data.try_as_aligned()?);
        let (size, uid, gid, mode, _zero, symlink_target, xattrs_data) = data.to_tuple();
        let mut xattrs = BTreeMap::<Box<OsStr>, Box<[u8]>>::new();
        for x in xattrs_data.iter() {
            let (key, value) = x.to_tuple();
            xattrs.insert(OsStr::from_bytes(key).into(), Box::from(value));
        }

        let stat = Stat {
            st_mode: u32::from_be(*mode),
            st_uid: u32::from_be(*uid),
            st_gid: u32::from_be(*gid),
            st_mtim_sec: 0,
            xattrs: xattrs.into(),
        };

        let content = if (stat.st_mode & S_IFMT) == S_IFLNK {
            LeafContent::Symlink(OsStr::new(symlink_target.to_str()).into())
        } else {
            let file = if let Some(obj_id) = maybe_obj_id {
                if !remaining_data.is_empty() {
                    bail!("Unexpected trailing file data");
                }
                RegularFile::External(obj_id.clone(), u64::from_be(*size))
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
        let (_obj_id, dirmeta) = self.lookup(dirmeta_id).ok_or(Error::msg(format!(
            "Unexpectedly missing ostree dirmeta object {}",
            hex::encode(dirmeta_id)
        )))?;

        let dirmeta_sha = Sha256::digest(dirmeta);
        if *dirmeta_sha != *dirmeta_id {
            bail!(
                "Invalid dirmeta checksum {:?}, expected {:?}",
                dirmeta_sha,
                dirmeta_id
            );
        }

        let data = gv!("(uuua(ayay))").cast(dirmeta.as_aligned());
        let (uid, gid, mode, xattrs_data) = data.to_tuple();
        let mut xattrs = BTreeMap::<Box<OsStr>, Box<[u8]>>::new();
        for x in xattrs_data.iter() {
            let (key, value) = x.to_tuple();
            xattrs.insert(OsStr::from_bytes(key).into(), Box::from(value));
        }

        Ok(Stat {
            st_mode: u32::from_be(*mode),
            st_uid: u32::from_be(*uid),
            st_gid: u32::from_be(*gid),
            st_mtim_sec: 0,
            xattrs: xattrs.into(),
        })
    }

    fn create_filesystem_dir(
        &self,
        fs: &mut FileSystem<ObjectID>,
        file_cache: &mut HashMap<Sha256Digest, LeafId>,
        dirtree_id: &Sha256Digest,
    ) -> Result<Vec<(Box<OsStr>, Inode<ObjectID>)>> {
        let (_obj_id, dirtree) = self.lookup(dirtree_id).ok_or(Error::msg(format!(
            "Unexpectedly missing ostree dirtree object {}",
            hex::encode(dirtree_id)
        )))?;

        let tree_data = gv!("(a(say)a(sayay))").cast(dirtree.as_aligned());
        let (files_data, dirs_data) = tree_data.to_tuple();

        let mut entries = Vec::<(Box<OsStr>, Inode<ObjectID>)>::new();

        for f in files_data.iter() {
            let (name, checksum) = f.to_tuple();

            let leaf_id = self.create_filesystem_file(fs, file_cache, checksum.try_into()?)?;
            entries.push((OsStr::new(name.to_str()).into(), Inode::leaf(leaf_id)));
        }

        for d in dirs_data.iter() {
            let (name, tree_checksum, meta_checksum) = d.to_tuple();

            let stat = self.parse_dirmeta(meta_checksum.try_into()?)?;
            let mut subdir = Directory::new(stat);
            for (name, inode) in
                self.create_filesystem_dir(fs, file_cache, tree_checksum.try_into()?)?
            {
                subdir.insert(&name, inode);
            }

            entries.push((
                OsStr::new(name.to_str()).into(),
                Inode::Directory(Box::new(subdir)),
            ));
        }

        Ok(entries)
    }

    /// Create a tree::Filesystem for the commit
    pub fn create_filesystem(&self) -> Result<FileSystem<ObjectID>> {
        let commit = self
            .lookup_data(&self.commit_id)
            .ok_or(Error::msg("Unexpectedly missing commit object"))?;

        let data = gv!("(a{sv}aya(say)sstayay)").cast(commit);
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

        let stat = self.parse_dirmeta(root_metadata.try_into()?)?;

        let mut fs = FileSystem::<ObjectID>::new(stat);

        let mut file_cache = HashMap::new();
        for (name, inode) in
            self.create_filesystem_dir(&mut fs, &mut file_cache, root_tree.try_into()?)?
        {
            fs.root.insert(&name, inode);
        }

        Ok(fs)
    }
}
