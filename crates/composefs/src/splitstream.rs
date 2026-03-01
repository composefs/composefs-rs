//! Split Stream file format implementation.
//!
//! This module implements the Split Stream format for efficiently storing
//! and transferring data with inline content and external object references,
//! supporting compression and content deduplication.

/* Implementation of the Split Stream file format
 *
 * NB: This format is documented in `doc/splitstream.md`.  Please keep the docs up to date!!
 */

use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    hash::Hash,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Take, Write},
    mem::size_of,
    mem::MaybeUninit,
    ops::Range,
    sync::Arc,
};

use anyhow::{bail, ensure, Context, Error, Result};
use fn_error_context::context;
use rustix::{
    buffer::spare_capacity,
    io::{pread, read},
};
use tokio::task::JoinHandle;

use crate::repository::ObjectStoreMethod;
use zerocopy::{
    little_endian::{I64, U16, U64},
    FromBytes, Immutable, IntoBytes, KnownLayout,
};
use zstd::stream::{read::Decoder, write::Encoder};

use crate::{fsverity::FsVerityHashValue, repository::Repository, util::read_exactish};

const SPLITSTREAM_MAGIC: [u8; 11] = *b"SplitStream";
const LG_BLOCKSIZE: u8 = 12; // TODO: hard-coded 4k.  make this generic later...

// Nearly everything in the file is located at an offset indicated by a FileRange.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct FileRange {
    start: U64,
    end: U64,
}

// The only exception is the header: it is a fixed sized and comes at the start (offset 0).
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct SplitstreamHeader {
    pub magic: [u8; 11],  // Contains SPLITSTREAM_MAGIC
    pub version: u8,      // must always be 0
    pub _flags: U16,      // is currently always 0 (but ignored)
    pub algorithm: u8,    // kernel fs-verity algorithm identifier (1 = sha256, 2 = sha512)
    pub lg_blocksize: u8, // log2 of the fs-verity block size (12 = 4k, 16 = 64k)
    pub info: FileRange,  // can be used to expand/move the info section in the future
}

// The info block can be located anywhere, indicated by the "info" FileRange in the header.
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct SplitstreamInfo {
    pub stream_refs: FileRange, // location of the stream references array
    pub object_refs: FileRange, // location of the object references array
    pub stream: FileRange,      // location of the zstd-compressed stream within the file
    pub named_refs: FileRange,  // location of the compressed named references
    pub content_type: U64,      // user can put whatever magic identifier they want there
    pub stream_size: U64,       // total uncompressed size of inline chunks and external chunks
}

impl FileRange {
    fn len(&self) -> Result<u64> {
        self.end
            .get()
            .checked_sub(self.start.get())
            .context("Negative-sized range in splitstream")
    }
}

impl From<Range<u64>> for FileRange {
    fn from(value: Range<u64>) -> Self {
        Self {
            start: U64::from(value.start),
            end: U64::from(value.end),
        }
    }
}

#[context("Reading range from splitstream file")]
fn read_range(file: &mut File, range: FileRange) -> Result<Vec<u8>> {
    let size: usize = (range.len()?.try_into())
        .context("Unable to allocate buffer for implausibly large splitstream section")?;
    let mut buffer = Vec::with_capacity(size);
    if size > 0 {
        pread(file, spare_capacity(&mut buffer), range.start.get())
            .context("Unable to read section from splitstream file")?;
    }
    ensure!(
        buffer.len() == size,
        "Incomplete read from splitstream file"
    );
    Ok(buffer)
}

/// An array of objects with the following properties:
///   - each item appears only once
///   - efficient insertion and lookup of indexes of existing items
///   - insertion order is maintained, indexes are stable across modification
///   - can do .as_bytes() for items that are IntoBytes + Immutable
struct UniqueVec<T: Clone + Hash + Eq> {
    items: Vec<T>,
    index: HashMap<T, usize>,
}

impl<T: Clone + Hash + Eq + std::fmt::Debug> std::fmt::Debug for UniqueVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UniqueVec")
            .field("items", &self.items)
            .field("index", &self.index)
            .finish()
    }
}

impl<T: Clone + Hash + Eq + IntoBytes + Immutable> UniqueVec<T> {
    fn as_bytes(&self) -> &[u8] {
        self.items.as_bytes()
    }
}

impl<T: Clone + Hash + Eq> UniqueVec<T> {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            index: HashMap::new(),
        }
    }

    fn get(&self, item: &T) -> Option<usize> {
        self.index.get(item).copied()
    }

    fn ensure(&mut self, item: &T) -> usize {
        self.get(item).unwrap_or_else(|| {
            let idx = self.items.len();
            self.index.insert(item.clone(), idx);
            self.items.push(item.clone());
            idx
        })
    }

    /// Get an item by its index.
    fn get_by_index(&self, idx: usize) -> Option<&T> {
        self.items.get(idx)
    }
}

/// Statistics from finalizing a [`SplitStreamBuilder`].
#[derive(Debug, Clone, Default)]
pub struct SplitStreamStats {
    /// Total bytes of inline data written to the stream.
    pub inline_bytes: u64,
    /// Per-external-object (size, method) pairs describing how each was stored.
    pub external_objects: Vec<(u64, ObjectStoreMethod)>,
}

/// An entry in the split stream being built.
///
/// Used by `SplitStreamBuilder` to collect entries before serialization.
pub enum SplitStreamEntry<ObjectID: FsVerityHashValue> {
    /// Inline data (headers, small files, padding)
    Inline(Vec<u8>),
    /// External reference - will be resolved to ObjectID when the handle completes
    External {
        /// Background task that will return the ObjectID and how it was stored
        handle: JoinHandle<Result<(ObjectID, ObjectStoreMethod)>>,
        /// Size of the external object in bytes
        size: u64,
    },
}

impl<ObjectID: FsVerityHashValue> std::fmt::Debug for SplitStreamEntry<ObjectID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SplitStreamEntry::Inline(data) => {
                f.debug_struct("Inline").field("len", &data.len()).finish()
            }
            SplitStreamEntry::External { size, .. } => f
                .debug_struct("External")
                .field("size", size)
                .finish_non_exhaustive(),
        }
    }
}

/// Builder for constructing a split stream with parallel object storage.
///
/// This builder collects entries (inline data and pending external object handles),
/// then serializes them all at once when `finish()` is called. This approach:
/// - Allows all external handles to be awaited in parallel
/// - Enables proper deduplication of ObjectIDs
/// - Writes the stream in one clean pass after all IDs are known
///
/// # Example
/// ```ignore
/// let mut builder = SplitStreamBuilder::new(repo.clone(), content_type);
/// builder.push_inline(header_bytes);
/// builder.push_external(storage_handle, file_size);
/// builder.push_inline(padding);
/// let object_id = builder.finish().await?;
/// ```
pub struct SplitStreamBuilder<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    entries: Vec<SplitStreamEntry<ObjectID>>,
    total_external_size: u64,
    total_inline_bytes: u64,
    content_type: u64,
    stream_refs: UniqueVec<ObjectID>,
    named_refs: BTreeMap<Box<str>, usize>,
}

impl<ObjectID: FsVerityHashValue> std::fmt::Debug for SplitStreamBuilder<ObjectID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplitStreamBuilder")
            .field("repo", &self.repo)
            .field("entries", &self.entries)
            .field("total_external_size", &self.total_external_size)
            .field("content_type", &self.content_type)
            .finish_non_exhaustive()
    }
}

impl<ObjectID: FsVerityHashValue> SplitStreamBuilder<ObjectID> {
    /// Create a new split stream builder.
    pub fn new(repo: Arc<Repository<ObjectID>>, content_type: u64) -> Self {
        Self {
            repo,
            entries: Vec::new(),
            total_external_size: 0,
            total_inline_bytes: 0,
            content_type,
            stream_refs: UniqueVec::new(),
            named_refs: Default::default(),
        }
    }

    /// Append inline data to the stream.
    ///
    /// Adjacent inline data will be coalesced to avoid fragmentation.
    pub fn push_inline(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        self.total_inline_bytes += data.len() as u64;
        // Coalesce with the previous inline entry if possible
        if let Some(SplitStreamEntry::Inline(ref mut existing)) = self.entries.last_mut() {
            existing.extend_from_slice(data);
        } else {
            self.entries.push(SplitStreamEntry::Inline(data.to_vec()));
        }
    }

    /// Append an external object being stored in background.
    ///
    /// The handle should resolve to the (ObjectID, ObjectStoreMethod) when the storage completes.
    pub fn push_external(
        &mut self,
        handle: JoinHandle<Result<(ObjectID, ObjectStoreMethod)>>,
        size: u64,
    ) {
        self.total_external_size += size;
        self.entries
            .push(SplitStreamEntry::External { handle, size });
    }

    /// Add an externally-referenced stream with the given name.
    ///
    /// The name has no meaning beyond the scope of this file: it is meant to be used to link to
    /// associated data when reading the file back again. For example, for OCI config files, this
    /// might refer to a layer splitstream via its DiffId.
    pub fn add_named_stream_ref(&mut self, name: &str, verity: &ObjectID) {
        let idx = self.stream_refs.ensure(verity);
        self.named_refs.insert(Box::from(name), idx);
    }

    /// Finalize: await all handles, build the splitstream, store it.
    ///
    /// This method:
    /// 1. Awaits all external handles to get ObjectIDs
    /// 2. Builds a UniqueVec<ObjectID> for deduplication
    /// 3. Creates a SplitStreamWriter and replays all entries
    /// 4. Stores the final splitstream in the repository
    ///
    /// Returns the fs-verity object ID of the stored splitstream and
    /// [`SplitStreamStats`] with inline byte counts and per-object storage methods.
    pub async fn finish(self) -> Result<(ObjectID, SplitStreamStats)> {
        let mut stats = SplitStreamStats {
            inline_bytes: self.total_inline_bytes,
            external_objects: Vec::new(),
        };

        // First pass: await all handles to collect ObjectIDs
        // We need to preserve the order of entries, so we process them in sequence
        let mut resolved_entries: Vec<ResolvedEntry<ObjectID>> =
            Vec::with_capacity(self.entries.len());

        for entry in self.entries {
            match entry {
                SplitStreamEntry::Inline(data) => {
                    resolved_entries.push(ResolvedEntry::Inline(data));
                }
                SplitStreamEntry::External { handle, size } => {
                    let (id, method) = handle.await??;
                    stats.external_objects.push((size, method));
                    resolved_entries.push(ResolvedEntry::External { id, size });
                }
            }
        }

        // Second pass: build the splitstream using SplitStreamWriter
        // This gives us proper deduplication through UniqueVec
        let mut writer = SplitStreamWriter::new(&self.repo, self.content_type);

        // Copy over stream refs and named refs
        for (name, idx) in &self.named_refs {
            let verity = self
                .stream_refs
                .get_by_index(*idx)
                .expect("named ref index out of bounds");
            writer.add_named_stream_ref(name, verity);
        }

        // Replay all entries
        // Note: write_inline tracks total_size internally, but write_reference doesn't,
        // so we manually add the external size to the writer's total_size.
        for entry in resolved_entries {
            match entry {
                ResolvedEntry::Inline(data) => {
                    writer.write_inline(&data);
                }
                ResolvedEntry::External { id, size } => {
                    // Add size before writing reference (write_reference doesn't track size)
                    writer.add_external_size(size);
                    writer.write_reference(id)?;
                }
            }
        }

        // Finalize and store
        let id = tokio::task::spawn_blocking(move || writer.done()).await??;
        Ok((id, stats))
    }
}

/// Internal type for resolved entries after awaiting handles.
#[derive(Debug)]
enum ResolvedEntry<ObjectID: FsVerityHashValue> {
    Inline(Vec<u8>),
    External { id: ObjectID, size: u64 },
}

/// Writer for creating split stream format files with inline content and external object references.
pub struct SplitStreamWriter<ObjectId: FsVerityHashValue> {
    repo: Arc<Repository<ObjectId>>,
    stream_refs: UniqueVec<ObjectId>,
    object_refs: UniqueVec<ObjectId>,
    named_refs: BTreeMap<Box<str>, usize>, // index into stream_refs
    inline_buffer: Vec<u8>,
    total_size: u64,
    writer: Encoder<'static, Vec<u8>>,
    content_type: u64,
}

impl<ObjectID: FsVerityHashValue> std::fmt::Debug for SplitStreamWriter<ObjectID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // writer doesn't impl Debug
        f.debug_struct("SplitStreamWriter")
            .field("repo", &self.repo)
            .field("inline_content", &self.inline_buffer)
            .finish()
    }
}

impl<ObjectID: FsVerityHashValue> SplitStreamWriter<ObjectID> {
    /// Get a reference to the repository.
    pub fn repo(&self) -> &Repository<ObjectID> {
        &self.repo
    }

    /// Create a new split stream writer.
    pub fn new(repo: &Arc<Repository<ObjectID>>, content_type: u64) -> Self {
        // SAFETY: we surely can't get an error writing the header to a Vec<u8>
        let writer = Encoder::new(vec![], 0).unwrap();

        Self {
            repo: Arc::clone(repo),
            content_type,
            inline_buffer: vec![],
            stream_refs: UniqueVec::new(),
            object_refs: UniqueVec::new(),
            named_refs: Default::default(),
            total_size: 0,
            writer,
        }
    }

    /// Add an externally-referenced object.
    ///
    /// This establishes a link to an object (ie: raw data file) from this stream.  The link is
    /// given a unique index number, which is returned.  Once assigned, this index won't change.
    /// The same index can be used to find the linked object when reading the file back.
    ///
    /// This is the primary mechanism by which splitstreams reference split external content.
    ///
    /// You usually won't need to call this yourself: if you want to add split external content to
    /// the stream, call `.write_external()` or `._write_external_async()`.
    pub fn add_object_ref(&mut self, verity: &ObjectID) -> usize {
        self.object_refs.ensure(verity)
    }

    /// Find the index of a previously referenced object.
    ///
    /// Finds the previously-assigned index for a linked object, or None if the object wasn't
    /// previously linked.
    pub fn lookup_object_ref(&self, verity: &ObjectID) -> Option<usize> {
        self.object_refs.get(verity)
    }

    /// Add an externally-referenced stream with the given name.
    ///
    /// The name has no meaning beyond the scope of this file: it is meant to be used to link to
    /// associated data when reading the file back again.  For example, for OCI config files, this
    /// might refer to a layer splitstream via its DiffId.
    ///
    /// This establishes a link between the two splitstreams and is considered when performing
    /// garbage collection: the named stream will be kept alive by this stream.
    pub fn add_named_stream_ref(&mut self, name: &str, verity: &ObjectID) {
        let idx = self.stream_refs.ensure(verity);
        self.named_refs.insert(Box::from(name), idx);
    }

    // flush any buffered inline data
    fn flush_inline(&mut self) -> Result<()> {
        let size = self.inline_buffer.len();
        if size > 0 {
            // Inline chunk: stored as negative LE i64 number of bytes (non-zero!)
            // SAFETY: naive - fails on -i64::MIN but we know size was unsigned
            let instruction = -i64::try_from(size).expect("implausibly large inline chunk");
            self.writer.write_all(I64::new(instruction).as_bytes())?;
            self.writer.write_all(&self.inline_buffer)?;
            self.inline_buffer.clear();
        }
        Ok(())
    }

    /// Write inline data to the stream.
    pub fn write_inline(&mut self, data: &[u8]) {
        // SAFETY: We'd have to write a lot of data to get here...
        self.total_size += data.len() as u64;
        self.inline_buffer.extend(data);
    }

    /// Add to the total external size tracked by this writer.
    ///
    /// This is used by `SplitStreamBuilder` when replaying external entries,
    /// since `write_reference` doesn't track size on its own.
    pub fn add_external_size(&mut self, size: u64) {
        self.total_size += size;
    }

    /// Write a reference to an external object that has already been stored.
    ///
    /// This is the common implementation for `.write_external()` and `.write_external_async()`,
    /// and is also used by `SplitStreamBuilder` when replaying resolved entries.
    ///
    /// Note: This does NOT add to total_size - the caller must do that if needed.
    pub fn write_reference(&mut self, id: ObjectID) -> Result<()> {
        // Flush any buffered inline data before we store the external reference.
        self.flush_inline()?;

        // External chunk: non-negative LE i64 index into object_refs array
        let index = self.add_object_ref(&id);
        let instruction = i64::try_from(index).expect("implausibly large external index");
        self.writer.write_all(I64::from(instruction).as_bytes())?;
        Ok(())
    }

    /// Write externally-split data to the stream.
    ///
    /// The data is stored in the repository and a reference is written to the stream.
    pub fn write_external(&mut self, data: &[u8]) -> Result<()> {
        self.total_size += data.len() as u64;
        let id = self.repo.ensure_object(data)?;
        self.write_reference(id)
    }

    /// Asynchronously write externally-split data to the stream.
    ///
    /// The data is stored in the repository asynchronously and a reference is written to the stream.
    /// This method awaits the storage operation before returning.
    pub async fn write_external_async(&mut self, data: Vec<u8>) -> Result<()> {
        self.total_size += data.len() as u64;
        let id = self.repo.ensure_object_async(data).await?;
        self.write_reference(id)
    }

    fn write_named_refs(named_refs: BTreeMap<Box<str>, usize>) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new(vec![], 0)?;

        for (name, idx) in &named_refs {
            write!(&mut encoder, "{idx}:{name}\0")?;
        }

        Ok(encoder.finish()?)
    }

    /// Finalizes the split stream and returns its object ID.
    ///
    /// Flushes any remaining inline content, validates the SHA256 hash if provided,
    /// and stores the compressed stream in the repository.
    pub fn done(mut self) -> Result<ObjectID> {
        self.flush_inline()?;
        let stream = self.writer.finish()?;

        // Pre-compute the file layout
        let header_start = 0u64;
        let header_end = header_start + size_of::<SplitstreamHeader>() as u64;

        let info_start = header_end;
        let info_end = info_start + size_of::<SplitstreamInfo>() as u64;
        assert_eq!(info_start % 8, 0);

        let stream_refs_size = self.stream_refs.as_bytes().len();
        let stream_refs_start = info_end;
        let stream_refs_end = stream_refs_start + stream_refs_size as u64;
        assert_eq!(stream_refs_start % 8, 0);

        let object_refs_size = self.object_refs.as_bytes().len();
        let object_refs_start = stream_refs_end;
        let object_refs_end = object_refs_start + object_refs_size as u64;
        assert_eq!(object_refs_start % 8, 0);

        let named_refs =
            Self::write_named_refs(self.named_refs).context("Formatting named references")?;
        let named_refs_start = object_refs_end;
        let named_refs_end = named_refs_start + named_refs.len() as u64;
        assert_eq!(named_refs_start % 8, 0);

        let stream_start = named_refs_end;
        let stream_end = stream_start + stream.len() as u64;

        // Write the file out into a Vec<u8>, checking the layout on the way
        let mut buf = vec![];

        assert_eq!(buf.len() as u64, header_start);
        buf.extend_from_slice(
            SplitstreamHeader {
                magic: SPLITSTREAM_MAGIC,
                version: 0,
                _flags: U16::ZERO,
                algorithm: ObjectID::ALGORITHM,
                lg_blocksize: LG_BLOCKSIZE,
                info: (info_start..info_end).into(),
            }
            .as_bytes(),
        );
        assert_eq!(buf.len() as u64, header_end);

        assert_eq!(buf.len() as u64, info_start);
        buf.extend_from_slice(
            SplitstreamInfo {
                stream_refs: (stream_refs_start..stream_refs_end).into(),
                object_refs: (object_refs_start..object_refs_end).into(),
                stream: (stream_start..stream_end).into(),
                named_refs: (named_refs_start..named_refs_end).into(),
                content_type: self.content_type.into(),
                stream_size: self.total_size.into(),
            }
            .as_bytes(),
        );
        assert_eq!(buf.len() as u64, info_end);

        assert_eq!(buf.len() as u64, stream_refs_start);
        buf.extend_from_slice(self.stream_refs.as_bytes());
        assert_eq!(buf.len() as u64, stream_refs_end);

        assert_eq!(buf.len() as u64, object_refs_start);
        buf.extend_from_slice(self.object_refs.as_bytes());
        assert_eq!(buf.len() as u64, object_refs_end);

        assert_eq!(buf.len() as u64, named_refs_start);
        buf.extend_from_slice(&named_refs);
        assert_eq!(buf.len() as u64, named_refs_end);

        assert_eq!(buf.len() as u64, stream_start);
        buf.extend_from_slice(&stream);
        assert_eq!(buf.len() as u64, stream_end);

        // Store the Vec<u8> into the repository
        self.repo.ensure_object(&buf)
    }

    /// Finalizes the split stream asynchronously.
    ///
    /// This is an async-friendly version of `done()` that runs the final
    /// object storage on a blocking thread pool.
    ///
    /// Returns the fs-verity object ID of the stored splitstream.
    pub async fn done_async(self) -> Result<ObjectID> {
        tokio::task::spawn_blocking(move || self.done()).await?
    }
}

/// Data fragment from a split stream, either inline content or an external object reference.
#[derive(Debug)]
pub enum SplitStreamData<ObjectID: FsVerityHashValue> {
    /// Inline content stored directly in the stream
    Inline(Box<[u8]>),
    /// Reference to an external object
    External(ObjectID),
}

/// Reader for parsing split stream format files with inline content and external object references.
pub struct SplitStreamReader<ObjectID: FsVerityHashValue> {
    decoder: Decoder<'static, BufReader<Take<File>>>,
    inline_bytes: usize,
    /// The content_type ID given when the splitstream was constructed
    pub content_type: u64,
    /// The total size of the original/merged stream, in bytes
    pub total_size: u64,
    object_refs: Vec<ObjectID>,
    named_refs: HashMap<Box<str>, ObjectID>,
}

impl<ObjectID: FsVerityHashValue> std::fmt::Debug for SplitStreamReader<ObjectID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // decoder doesn't impl Debug
        f.debug_struct("SplitStreamReader")
            .field("refs", &self.object_refs)
            .field("inline_bytes", &self.inline_bytes)
            .finish()
    }
}

/// Using the provided [`vec`] as a buffer, read exactly [`size`]
/// bytes of content from [`reader`] into it. Any existing content
/// in [`vec`] will be discarded; however its capacity will be reused,
/// making this function suitable for use in loops.
fn read_into_vec(reader: &mut impl Read, vec: &mut Vec<u8>, size: usize) -> Result<()> {
    vec.resize(size, 0u8);
    reader.read_exact(vec.as_mut_slice())?;
    Ok(())
}

enum ChunkType<ObjectID: FsVerityHashValue> {
    Eof,
    Inline,
    External(ObjectID),
}

impl<ObjectID: FsVerityHashValue> SplitStreamReader<ObjectID> {
    /// Creates a new split stream reader from the provided reader.
    ///
    /// Reads the digest map header from the stream during initialization.
    #[context("Creating new splitstream reader")]
    pub fn new(mut file: File, expected_content_type: Option<u64>) -> Result<Self> {
        let header = SplitstreamHeader::read_from_io(&mut file)
            .map_err(|e| Error::msg(format!("Error reading splitstream header: {e:?}")))?;

        if header.magic != SPLITSTREAM_MAGIC {
            bail!("Invalid splitstream header magic value");
        }

        if header.version != 0 {
            bail!("Invalid splitstream version {}", header.version);
        }

        if header.algorithm != ObjectID::ALGORITHM {
            bail!("Invalid splitstream fs-verity algorithm type");
        }

        if header.lg_blocksize != LG_BLOCKSIZE {
            bail!("Invalid splitstream fs-verity block size");
        }

        let info_bytes = read_range(&mut file, header.info)?;
        // NB: We imagine that `info` might grow in the future, so for forward-compatibility we
        // allow that it is larger than we expect it to be.  If we ever expand the info section
        // then we will also need to come up with a mechanism for a smaller info section for
        // backwards-compatibility.
        let (info, _) = SplitstreamInfo::ref_from_prefix(&info_bytes)
            .map_err(|e| Error::msg(format!("Error reading splitstream metadata: {e:?}")))?;

        let content_type: u64 = info.content_type.into();
        if let Some(expected) = expected_content_type {
            ensure!(content_type == expected, "Invalid splitstream content type");
        }

        let total_size: u64 = info.stream_size.into();

        let stream_refs_bytes = read_range(&mut file, info.stream_refs)?;
        let stream_refs = <[ObjectID]>::ref_from_bytes(&stream_refs_bytes)
            .map_err(|e| Error::msg(format!("Error reading splitstream references: {e:?}")))?;

        let object_refs_bytes = read_range(&mut file, info.object_refs)?;
        let object_refs = <[ObjectID]>::ref_from_bytes(&object_refs_bytes)
            .map_err(|e| Error::msg(format!("Error reading object references: {e:?}")))?;

        let named_refs_bytes = read_range(&mut file, info.named_refs)?;
        let named_refs = Self::read_named_references(&named_refs_bytes, stream_refs)
            .map_err(|e| Error::msg(format!("Error reading splitstream mappings: {e:?}")))?;

        file.seek(SeekFrom::Start(info.stream.start.get()))
            .context("Unable to seek to start of splitstream content")?;
        let decoder = Decoder::new(file.take(info.stream.len()?))
            .context("Unable to decode zstd-compressed content in splitstream")?;

        Ok(Self {
            decoder,
            inline_bytes: 0,
            content_type,
            total_size,
            object_refs: object_refs.to_vec(),
            named_refs,
        })
    }

    fn read_named_references<ObjectId: FsVerityHashValue>(
        section: &[u8],
        references: &[ObjectId],
    ) -> Result<HashMap<Box<str>, ObjectId>> {
        let mut map = HashMap::new();
        let mut buffer = vec![];

        let mut reader = BufReader::new(
            Decoder::new(section).context("Creating zstd decoder for named references section")?,
        );

        loop {
            reader
                .read_until(b'\0', &mut buffer)
                .context("Reading named references section")?;

            let Some(item) = buffer.strip_suffix(b"\0") else {
                ensure!(
                    buffer.is_empty(),
                    "Trailing junk in named references section"
                );
                return Ok(map);
            };

            let (idx_str, name) = std::str::from_utf8(item)
                .context("Reading named references section")?
                .split_once(":")
                .context("Named reference doesn't contain a colon")?;

            let idx: usize = idx_str
                .parse()
                .context("Named reference contains a non-integer index")?;
            let object_id = references
                .get(idx)
                .context("Named reference out of bounds")?;

            map.insert(Box::from(name), object_id.clone());
            buffer.clear();
        }
    }

    /// Iterate the list of named references defined on this split stream.
    pub fn iter_named_refs(&self) -> impl Iterator<Item = (&str, &ObjectID)> {
        self.named_refs.iter().map(|(name, id)| (name.as_ref(), id))
    }

    /// Steal the "named refs" table from this splitstream, destructing it in the process.
    pub fn into_named_refs(self) -> HashMap<Box<str>, ObjectID> {
        self.named_refs
    }

    fn ensure_chunk(
        &mut self,
        eof_ok: bool,
        ext_ok: bool,
        expected_bytes: usize,
    ) -> Result<ChunkType<ObjectID>> {
        if self.inline_bytes == 0 {
            let mut value = I64::ZERO;

            if !read_exactish(&mut self.decoder, value.as_mut_bytes())? {
                ensure!(eof_ok, "Unexpected EOF in splitstream");
                return Ok(ChunkType::Eof);
            }

            // Negative values: (non-empty) inline data
            // Non-negative values: index into object_refs array
            match value.get() {
                n if n < 0i64 => {
                    self.inline_bytes = (n.unsigned_abs().try_into())
                        .context("Splitstream inline section is too large")?;
                }
                n => {
                    ensure!(ext_ok, "Unexpected external reference in splitstream");
                    let idx = usize::try_from(n)
                        .context("Splitstream external reference is too large")?;
                    let id: &ObjectID = (self.object_refs.get(idx))
                        .context("Splitstream external reference is out of range")?;
                    return Ok(ChunkType::External(id.clone()));
                }
            }
        }

        if self.inline_bytes < expected_bytes {
            bail!("Unexpectedly small inline content when parsing splitstream");
        }

        Ok(ChunkType::Inline)
    }

    /// Reads the exact number of inline bytes
    /// Assumes that the data cannot be split across chunks
    pub fn read_inline_exact(&mut self, buffer: &mut [u8]) -> Result<bool> {
        if let ChunkType::Inline = self.ensure_chunk(true, false, buffer.len())? {
            // SAFETY: ensure_chunk() already verified the number of bytes for us
            self.inline_bytes -= buffer.len();
            self.decoder.read_exact(buffer)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn discard_padding(&mut self, size: usize) -> Result<()> {
        let mut buf = [0u8; 512];
        assert!(size <= 512);
        self.ensure_chunk(false, false, size)?;
        self.decoder.read_exact(&mut buf[0..size])?;
        self.inline_bytes -= size;
        Ok(())
    }

    /// Reads an exact amount of data, which may be inline or external.
    ///
    /// The stored_size is the size as recorded in the stream (including any padding),
    /// while actual_size is the actual content size without padding.
    /// Returns either inline content or an external object reference.
    pub fn read_exact(
        &mut self,
        actual_size: usize,
        stored_size: usize,
    ) -> Result<SplitStreamData<ObjectID>> {
        if let ChunkType::External(id) = self.ensure_chunk(false, true, stored_size)? {
            // ...and the padding
            if actual_size < stored_size {
                self.discard_padding(stored_size - actual_size)?;
            }
            Ok(SplitStreamData::External(id))
        } else {
            let mut content = vec![];
            read_into_vec(&mut self.decoder, &mut content, stored_size)?;
            content.truncate(actual_size);
            self.inline_bytes -= stored_size;
            Ok(SplitStreamData::Inline(content.into()))
        }
    }

    /// Concatenates the entire split stream content to the output writer.
    ///
    /// Inline content is written directly, while external references are resolved
    /// using the provided load_data callback function.
    #[context("Concatenating splitstream to output")]
    pub fn cat(&mut self, repo: &Repository<ObjectID>, output: &mut impl Write) -> Result<()> {
        let mut buffer = vec![];

        loop {
            match self.ensure_chunk(true, true, 0)? {
                ChunkType::Eof => break Ok(()),
                ChunkType::Inline => {
                    read_into_vec(&mut self.decoder, &mut buffer, self.inline_bytes)?;
                    self.inline_bytes = 0;
                    output.write_all(&buffer)?;
                }
                ChunkType::External(ref id) => {
                    let mut buffer = [MaybeUninit::<u8>::uninit(); 1024 * 1024];
                    let fd = repo.open_object(id)?;

                    loop {
                        let (result, _) = read(&fd, &mut buffer)?;
                        if result.is_empty() {
                            break;
                        }
                        output.write_all(result)?;
                    }
                }
            }
        }
    }

    /// Traverses the split stream and calls the callback for each object reference.
    ///
    /// This includes both references from the digest map and external references in the stream.
    #[context("Getting object references from splitstream")]
    pub fn get_object_refs(&mut self, mut callback: impl FnMut(&ObjectID)) -> Result<()> {
        for entry in &self.object_refs {
            callback(entry);
        }
        Ok(())
    }

    /// Looks up a named reference
    ///
    /// Returns None if no such reference exists
    pub fn lookup_named_ref(&self, name: &str) -> Option<&ObjectID> {
        self.named_refs.get(name)
    }
}

impl<ObjectID: FsVerityHashValue> Read for SplitStreamReader<ObjectID> {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        match self.ensure_chunk(true, false, 1) {
            Ok(ChunkType::Eof) => Ok(0),
            Ok(ChunkType::Inline) => {
                let n_bytes = std::cmp::min(data.len(), self.inline_bytes);
                self.decoder.read_exact(&mut data[0..n_bytes])?;
                self.inline_bytes -= n_bytes;
                Ok(n_bytes)
            }
            Ok(ChunkType::External(..)) => unreachable!(),
            Err(e) => Err(std::io::Error::other(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsverity::{compute_verity, Sha256HashValue};
    use crate::test::tempdir;
    use rustix::fs::{mkdirat, Mode, CWD};
    use std::io::Cursor;
    use std::path::Path;

    #[test]
    fn test_read_into_vec() -> Result<()> {
        // Test with an empty reader
        let mut reader = Cursor::new(vec![]);
        let mut vec = Vec::new();
        let result = read_into_vec(&mut reader, &mut vec, 0);
        assert!(result.is_ok());
        assert_eq!(vec.len(), 0);

        // Test with a reader that has some data
        let mut reader = Cursor::new(vec![1, 2, 3, 4, 5]);
        let mut vec = Vec::new();
        let result = read_into_vec(&mut reader, &mut vec, 3);
        assert!(result.is_ok());
        assert_eq!(vec.len(), 3);
        assert_eq!(vec, vec![1, 2, 3]);

        // Test reading more than the reader has
        let mut reader = Cursor::new(vec![1, 2, 3]);
        let mut vec = Vec::new();
        let result = read_into_vec(&mut reader, &mut vec, 5);
        assert!(result.is_err());

        // Test reading exactly what the reader has
        let mut reader = Cursor::new(vec![1, 2, 3]);
        let mut vec = Vec::new();
        let result = read_into_vec(&mut reader, &mut vec, 3);
        assert!(result.is_ok());
        assert_eq!(vec.len(), 3);
        assert_eq!(vec, vec![1, 2, 3]);

        // Test reading into a vector with existing capacity
        let mut reader = Cursor::new(vec![1, 2, 3, 4, 5]);
        let mut vec = Vec::with_capacity(10);
        let result = read_into_vec(&mut reader, &mut vec, 4);
        assert!(result.is_ok());
        assert_eq!(vec.len(), 4);
        assert_eq!(vec, vec![1, 2, 3, 4]);
        assert_eq!(vec.capacity(), 10);

        // Test reading into a vector with existing data
        let mut reader = Cursor::new(vec![1, 2, 3]);
        let mut vec = vec![9, 9, 9];
        let result = read_into_vec(&mut reader, &mut vec, 2);
        assert!(result.is_ok());
        assert_eq!(vec.len(), 2);
        assert_eq!(vec, vec![1, 2]);

        Ok(())
    }

    /// Create a test repository in insecure mode (no fs-verity required).
    fn create_test_repo(path: &Path) -> Result<Arc<Repository<Sha256HashValue>>> {
        mkdirat(CWD, path, Mode::from_raw_mode(0o755))?;
        let mut repo = Repository::open_path(CWD, path)?;
        repo.set_insecure(true);
        Ok(Arc::new(repo))
    }

    /// Generate deterministic test data of a given size.
    fn generate_test_data(size: usize, seed: u8) -> Vec<u8> {
        (0..size)
            .map(|i| ((i as u8).wrapping_add(seed)).wrapping_mul(17))
            .collect()
    }

    #[test]
    fn test_splitstream_inline_only() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let inline1 = generate_test_data(32, 0xAB);
        let inline2 = generate_test_data(48, 0xCD);

        let mut writer = repo.create_stream(0);
        writer.write_inline(&inline1);
        writer.write_inline(&inline2);
        let stream_id = repo.write_stream(writer, "test-inline", None)?;

        // Read it back via cat()
        let mut reader = repo.open_stream("test-inline", Some(&stream_id), None)?;
        let mut output = Vec::new();
        reader.cat(&repo, &mut output)?;

        let mut expected = inline1.clone();
        expected.extend(&inline2);
        assert_eq!(output, expected, "inline-only roundtrip must be exact");
        Ok(())
    }

    #[test]
    fn test_splitstream_large_external() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        // 128KB of data
        let large_content = generate_test_data(128 * 1024, 0x42);

        // Compute expected fs-verity digest for this content
        let expected_digest: Sha256HashValue = compute_verity(&large_content);

        let mut writer = repo.create_stream(0);
        writer.write_external(&large_content)?;
        let stream_id = repo.write_stream(writer, "test-external", None)?;

        // Verify the object reference matches the expected digest
        let mut reader = repo.open_stream("test-external", Some(&stream_id), None)?;
        let mut refs = Vec::new();
        reader.get_object_refs(|id| refs.push(id.clone()))?;
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0], expected_digest,
            "external object must have correct fs-verity digest"
        );

        // Verify roundtrip
        let mut reader = repo.open_stream("test-external", Some(&stream_id), None)?;
        let mut output = Vec::new();
        reader.cat(&repo, &mut output)?;

        assert_eq!(output.len(), large_content.len());
        assert_eq!(
            output, large_content,
            "large external content must roundtrip exactly"
        );
        Ok(())
    }

    #[test]
    fn test_splitstream_mixed_content() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        // Simulate a tar-like structure: header (inline) + file content (external) + trailer
        let header = generate_test_data(512, 0x01);
        let file_content = generate_test_data(64 * 1024, 0x02);
        let trailer = generate_test_data(1024, 0x03);

        // Compute expected digest for the external content
        let expected_digest: Sha256HashValue = compute_verity(&file_content);

        let mut writer = repo.create_stream(0);
        writer.write_inline(&header);
        writer.write_external(&file_content)?;
        writer.write_inline(&trailer);
        let stream_id = repo.write_stream(writer, "test-mixed", None)?;

        // Verify the external object has the correct digest
        let mut reader = repo.open_stream("test-mixed", Some(&stream_id), None)?;
        let mut refs = Vec::new();
        reader.get_object_refs(|id| refs.push(id.clone()))?;
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0], expected_digest,
            "external object must have correct fs-verity digest"
        );

        // Verify roundtrip
        let mut reader = repo.open_stream("test-mixed", Some(&stream_id), None)?;
        let mut output = Vec::new();
        reader.cat(&repo, &mut output)?;

        let mut expected = header.clone();
        expected.extend(&file_content);
        expected.extend(&trailer);

        assert_eq!(output.len(), expected.len());
        assert_eq!(output, expected, "mixed content must roundtrip exactly");
        Ok(())
    }

    #[test]
    fn test_splitstream_multiple_externals() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let file1 = generate_test_data(32 * 1024, 0x10);
        let file2 = generate_test_data(256 * 1024, 0x20);
        let file3 = generate_test_data(8 * 1024, 0x30);
        let separator = generate_test_data(64, 0xFF);

        // Compute expected digests
        let expected_digest1: Sha256HashValue = compute_verity(&file1);
        let expected_digest2: Sha256HashValue = compute_verity(&file2);
        let expected_digest3: Sha256HashValue = compute_verity(&file3);

        let mut writer = repo.create_stream(0);
        writer.write_external(&file1)?;
        writer.write_inline(&separator);
        writer.write_external(&file2)?;
        writer.write_inline(&separator);
        writer.write_external(&file3)?;
        let stream_id = repo.write_stream(writer, "test-multi", None)?;

        // Verify the object references have correct digests
        let mut reader = repo.open_stream("test-multi", Some(&stream_id), None)?;
        let mut refs = Vec::new();
        reader.get_object_refs(|id| refs.push(id.clone()))?;
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0], expected_digest1, "file1 digest mismatch");
        assert_eq!(refs[1], expected_digest2, "file2 digest mismatch");
        assert_eq!(refs[2], expected_digest3, "file3 digest mismatch");

        // Verify roundtrip
        let mut reader = repo.open_stream("test-multi", Some(&stream_id), None)?;
        let mut output = Vec::new();
        reader.cat(&repo, &mut output)?;

        let mut expected = file1.clone();
        expected.extend(&separator);
        expected.extend(&file2);
        expected.extend(&separator);
        expected.extend(&file3);

        assert_eq!(output.len(), expected.len());
        assert_eq!(
            output, expected,
            "multiple externals must roundtrip exactly"
        );
        Ok(())
    }

    #[test]
    fn test_splitstream_deduplication() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        // Same chunk appearing multiple times should be deduplicated
        let repeated_chunk = generate_test_data(64 * 1024, 0xDE);
        let unique_chunk = generate_test_data(32 * 1024, 0xAD);

        // Compute expected digests
        let repeated_digest: Sha256HashValue = compute_verity(&repeated_chunk);
        let unique_digest: Sha256HashValue = compute_verity(&unique_chunk);

        let mut writer = repo.create_stream(0);
        writer.write_external(&repeated_chunk)?;
        writer.write_external(&unique_chunk)?;
        writer.write_external(&repeated_chunk)?; // duplicate
        writer.write_external(&repeated_chunk)?; // another duplicate
        let stream_id = repo.write_stream(writer, "test-dedup", None)?;

        // Verify deduplication: only 2 unique objects should be referenced
        let mut reader = repo.open_stream("test-dedup", Some(&stream_id), None)?;
        let mut refs = Vec::new();
        reader.get_object_refs(|id| refs.push(id.clone()))?;
        assert_eq!(refs.len(), 2, "should only have 2 unique object refs");
        assert_eq!(
            refs[0], repeated_digest,
            "first ref should be repeated chunk"
        );
        assert_eq!(refs[1], unique_digest, "second ref should be unique chunk");

        // Verify roundtrip still works
        let mut reader = repo.open_stream("test-dedup", Some(&stream_id), None)?;
        let mut output = Vec::new();
        reader.cat(&repo, &mut output)?;

        let mut expected = repeated_chunk.clone();
        expected.extend(&unique_chunk);
        expected.extend(&repeated_chunk);
        expected.extend(&repeated_chunk);

        assert_eq!(output.len(), expected.len());
        assert_eq!(
            output, expected,
            "deduplicated content must still roundtrip exactly"
        );
        Ok(())
    }

    #[test]
    fn test_splitstream_get_object_refs() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let chunk1 = generate_test_data(16 * 1024, 0x11);
        let chunk2 = generate_test_data(24 * 1024, 0x22);
        let inline_data = generate_test_data(128, 0x33);

        // Compute expected digests
        let expected_digest1: Sha256HashValue = compute_verity(&chunk1);
        let expected_digest2: Sha256HashValue = compute_verity(&chunk2);

        let mut writer = repo.create_stream(0);
        writer.write_inline(&inline_data);
        writer.write_external(&chunk1)?;
        writer.write_external(&chunk2)?;
        let stream_id = repo.write_stream(writer, "test-refs", None)?;

        let mut reader = repo.open_stream("test-refs", Some(&stream_id), None)?;

        let mut refs = Vec::new();
        reader.get_object_refs(|id| refs.push(id.clone()))?;

        // Should have 2 external references with correct digests
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0], expected_digest1, "chunk1 digest mismatch");
        assert_eq!(refs[1], expected_digest2, "chunk2 digest mismatch");

        // Verify content can be read back via the digests
        let obj1 = repo.read_object(&refs[0])?;
        let obj2 = repo.read_object(&refs[1])?;

        assert_eq!(obj1, chunk1, "first external reference must match");
        assert_eq!(obj2, chunk2, "second external reference must match");

        Ok(())
    }

    #[test]
    fn test_splitstream_boundary_sizes() -> Result<()> {
        // Test with sizes around common boundaries (4KB page, 64KB chunk)
        let sizes = [4095, 4096, 4097, 65535, 65536, 65537];

        for size in sizes {
            let tmp = tempdir();
            let repo = create_test_repo(&tmp.path().join("repo"))?;
            let data = generate_test_data(size, size as u8);

            // Compute expected digest
            let expected_digest: Sha256HashValue = compute_verity(&data);

            let mut writer = repo.create_stream(0);
            writer.write_external(&data)?;
            let stream_id = repo.write_stream(writer, "test-boundary", None)?;

            // Verify the digest
            let mut reader = repo.open_stream("test-boundary", Some(&stream_id), None)?;
            let mut refs = Vec::new();
            reader.get_object_refs(|id| refs.push(id.clone()))?;
            assert_eq!(refs.len(), 1);
            assert_eq!(
                refs[0], expected_digest,
                "size {} must have correct digest",
                size
            );

            // Verify roundtrip
            let mut reader = repo.open_stream("test-boundary", Some(&stream_id), None)?;
            let mut output = Vec::new();
            reader.cat(&repo, &mut output)?;

            assert_eq!(
                output.len(),
                data.len(),
                "size {} must roundtrip with correct length",
                size
            );
            assert_eq!(output, data, "size {} must roundtrip exactly", size);
        }

        Ok(())
    }

    #[test]
    fn test_splitstream_content_type() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;
        let content_type = 0xDEADBEEF_u64;

        let mut writer = repo.create_stream(content_type);
        writer.write_inline(b"test data");
        let stream_id = repo.write_stream(writer, "test-ctype", None)?;

        let reader = repo.open_stream("test-ctype", Some(&stream_id), Some(content_type))?;
        assert_eq!(reader.content_type, content_type);

        Ok(())
    }

    #[test]
    fn test_splitstream_total_size_tracking() -> Result<()> {
        let tmp = tempdir();
        let repo = create_test_repo(&tmp.path().join("repo"))?;

        let inline_data = generate_test_data(100, 0x01);
        let external_data = generate_test_data(1000, 0x02);

        let mut writer = repo.create_stream(0);
        writer.write_inline(&inline_data);
        writer.write_external(&external_data)?;
        let stream_id = repo.write_stream(writer, "test-size", None)?;

        let reader = repo.open_stream("test-size", Some(&stream_id), None)?;
        assert_eq!(reader.total_size, 1100, "total size should be tracked");

        Ok(())
    }
}
