//! OSTree static delta parsing and application.
//!
//! Supports applying static deltas (both offline from files and eventually
//! inline during remote pulls). The delta format is documented in the
//! ostree source at `ostree-repo-static-delta-private.h`.

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use gvariant::aligned_bytes::{AlignedBuf, TryAsAligned};
use gvariant::{Marker, Structure, gv};
use rustix::fs::{Mode, OFlags, openat, seek};
use sha2::{Digest, Sha256};

use composefs::fsverity::FsVerityHashValue;
use composefs::repository::Repository;
use composefs::util::Sha256Digest;

use crate::commit::{CommitReader, CommitWriter};
use crate::ostree::{
    ObjectType, OstreeCommit, OstreeDirTree, OstreeFileHeader, should_inline_file,
};
use crate::pull::PullStats;

const OBJTYPE_CSUM_LEN: usize = 33; // 1 byte type + 32 bytes SHA-256

// Delta opcodes
const OP_OPEN_SPLICE_AND_CLOSE: u8 = b'S';
const OP_OPEN: u8 = b'o';
const OP_WRITE: u8 = b'w';
const OP_SET_READ_SOURCE: u8 = b'r';
const OP_UNSET_READ_SOURCE: u8 = b'R';
const OP_CLOSE: u8 = b'c';
const OP_BSPATCH: u8 = b'B';

// Signed delta magic: "OSTSGNDT" in big-endian u64
const SIGNED_DELTA_MAGIC: u64 = 0x4F53_5453_474E_4454;

// ---------- varint codec ----------

fn read_varuint64(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        ensure!(*pos < data.len(), "varint extends past end of data");
        let b = data[*pos];
        *pos += 1;
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        ensure!(shift < 70, "varint too long");
    }
}

// ---------- GVariant framing helpers ----------

fn gv_offset_size(container_size: u64) -> usize {
    match container_size {
        0 => 0,
        0x01..=0xFF => 1,
        0x100..=0xFFFF => 2,
        0x1_0000..=0xFFFF_FFFF => 4,
        _ => 8,
    }
}

fn gv_read_offset(data: &[u8], osz: usize, index: usize) -> u64 {
    let start = index * osz;
    match osz {
        1 => data[start] as u64,
        2 => u16::from_le_bytes(data[start..start + 2].try_into().unwrap()) as u64,
        4 => u32::from_le_bytes(data[start..start + 4].try_into().unwrap()) as u64,
        8 => u64::from_le_bytes(data[start..start + 8].try_into().unwrap()),
        _ => 0,
    }
}

fn align_up(offset: u64, alignment: u64) -> u64 {
    (offset + alignment - 1) & !(alignment - 1)
}

// ---------- Superblock parser ----------

/// The superblock format `(a{sv}tayay(...)aya(uayttay)a(yaytt))` has 8 children.
/// Frame offsets at the end cover 6 variable-size children (all except the last).
/// Child [1] (`t`) is fixed-size (8 bytes).
const N_SUPERBLOCK_CHILDREN: usize = 8;
const N_FRAME_OFFSETS: usize = 6;

struct SuperblockChildRanges {
    ranges: [(u64, u64); N_SUPERBLOCK_CHILDREN],
}

/// Compute child byte ranges from superblock size and frame offsets.
///
/// The superblock tuple `(a{sv} t ay ay (...) ay a(...) a(...))` has:
/// - 7 variable-size children, 1 fixed-size child (`t` at index 1)
/// - 6 frame offsets (for variable children 0,2,3,4,5,6; child 7 is LAST)
///
/// Frame offset[i] stores the *end* of the i-th variable-size child.
/// Start of each child is derived from the end of the previous child + alignment.
fn compute_child_ranges(
    total_size: u64,
    frame_offsets: &[u64; N_FRAME_OFFSETS],
) -> SuperblockChildRanges {
    // Map: for each variable-size child (0,2,3,4,5,6,7), what frame offset index?
    // var_children: [(child_index, frame_offset_index_for_end)]
    // child 0: end = fo[0]
    // child 1: fixed, 8 bytes
    // child 2: end = fo[1]
    // child 3: end = fo[2]
    // child 4: end = fo[3]
    // child 5: end = fo[4]
    // child 6: end = fo[5]
    // child 7: end = total_size - n_frame_offsets * osz (LAST)

    let osz = gv_offset_size(total_size) as u64;
    let data_end = total_size - N_FRAME_OFFSETS as u64 * osz;

    let mut ranges = [(0u64, 0u64); N_SUPERBLOCK_CHILDREN];

    // Child 0: a{sv}, starts at 0, ends at fo[0]
    ranges[0] = (0, frame_offsets[0]);

    // Child 1: t (fixed 8 bytes), starts after child 0 aligned to 8
    let start_1 = align_up(frame_offsets[0], 8);
    ranges[1] = (start_1, start_1 + 8);

    // Child 2: ay, starts after child 1 (no alignment needed for ay)
    let start_2 = ranges[1].1;
    ranges[2] = (start_2, frame_offsets[1]);

    // Child 3: ay, starts after child 2
    let start_3 = frame_offsets[1];
    ranges[3] = (start_3, frame_offsets[2]);

    // Child 4: commit tuple, starts after child 3 aligned to 8
    let start_4 = align_up(frame_offsets[2], 8);
    ranges[4] = (start_4, frame_offsets[3]);

    // Child 5: ay, starts after child 4
    let start_5 = frame_offsets[3];
    ranges[5] = (start_5, frame_offsets[4]);

    // Child 6: a(uayttay), starts after child 5 aligned to 8
    let start_6 = align_up(frame_offsets[4], 8);
    ranges[6] = (start_6, frame_offsets[5]);

    // Child 7: a(yaytt), starts after child 6 (1-byte alignment for outer `a`)
    // Actually a(yaytt) elements contain `t` so alignment is 8
    let start_7 = align_up(frame_offsets[5], 8);
    ranges[7] = (start_7, data_end);

    SuperblockChildRanges { ranges }
}

/// Reads a byte range from a file descriptor via pread.
fn pread_range(fd: &impl AsFd, start: u64, end: u64) -> Result<Vec<u8>> {
    let len = end
        .checked_sub(start)
        .ok_or_else(|| anyhow!("invalid range"))? as usize;
    let mut buf = vec![0u8; len];
    rustix::io::pread(fd, &mut buf, start)?;
    Ok(buf)
}

/// Parsed delta part header from the superblock.
#[derive(Debug)]
pub struct DeltaPartHeader {
    /// SHA-256 checksum of the (compressed) part data.
    pub checksum: Sha256Digest,
    /// Compressed size.
    pub compressed_size: u64,
    /// Uncompressed size.
    pub uncompressed_size: u64,
    /// Objects produced by this part: (type, checksum).
    pub objects: Vec<(ObjectType, Sha256Digest)>,
}

/// Parsed fallback entry from the superblock.
#[derive(Debug)]
pub struct DeltaFallback {
    /// Object type.
    pub obj_type: ObjectType,
    /// SHA-256 checksum.
    pub checksum: Sha256Digest,
    /// Compressed size.
    pub compressed_size: u64,
    /// Uncompressed size.
    pub uncompressed_size: u64,
}

/// Cached index for the `a{sv}` metadata dict in the superblock.
///
/// On construction, reads the offset table and all key strings (which
/// are short but scattered across the file). Values are read on demand
/// via pread, so inline part payloads (potentially huge) are never held
/// in memory until requested.
struct MetadataDictIndex {
    entries: Vec<(String, u64, u64)>,
}

impl MetadataDictIndex {
    fn load(source: &VariantSource, file_offset: u64, dict_size: u64) -> Result<Self> {
        if dict_size == 0 {
            return Ok(MetadataDictIndex { entries: vec![] });
        }

        let osz = gv_offset_size(dict_size);

        // Read the last offset to find last_end (end of data / start of offset table)
        let last_ofs_buf = source.read_range(
            file_offset + dict_size - osz as u64,
            file_offset + dict_size,
        )?;
        let last_end = gv_read_offset(&last_ofs_buf, osz, 0);

        let offset_table_size = dict_size as usize - last_end as usize - osz;
        let n_entries = offset_table_size.checked_div(osz).map_or(0, |n| n + 1);

        // Read the full offset table (small)
        let offsets_buf = source.read_range(
            file_offset + last_end,
            file_offset + last_end + (offset_table_size + osz) as u64,
        )?;

        // Read each entry's key string (short, NUL-terminated at start of entry)
        let mut entries = Vec::with_capacity(n_entries);
        for i in 0..n_entries {
            let end = gv_read_offset(&offsets_buf, osz, i).min(last_end);
            let start = if i == 0 {
                0u64
            } else {
                align_up(gv_read_offset(&offsets_buf, osz, i - 1), 8)
            };
            if end <= start {
                continue;
            }

            let peek_len = 256u64.min(end - start);
            let peek = source.read_range(file_offset + start, file_offset + start + peek_len)?;

            let nul_pos = match peek.iter().position(|&b| b == 0) {
                Some(p) => p,
                None => continue,
            };
            let key = match std::str::from_utf8(&peek[..nul_pos]) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };

            // The value starts after the key's NUL, and the {sv} entry
            // has a framing offset at the end for the variant boundary,
            // but we just store the full entry range — the caller parses
            // the value from the raw entry data.
            entries.push((key, file_offset + start, file_offset + end));
        }

        Ok(MetadataDictIndex { entries })
    }

    /// Read the full raw entry data for the given key.
    fn lookup(&self, source: &VariantSource, key: &str) -> Result<Option<Vec<u8>>> {
        for (k, start, end) in &self.entries {
            if k == key {
                return Ok(Some(source.read_range(*start, *end)?));
            }
        }
        Ok(None)
    }

    /// Find an entry whose key starts with `prefix` and ends with `suffix`.
    fn lookup_by_prefix_suffix(
        &self,
        source: &VariantSource,
        prefix: &str,
        suffix: &str,
    ) -> Result<Option<Vec<u8>>> {
        for (k, start, end) in &self.entries {
            if k.starts_with(prefix) && k.ends_with(suffix) {
                return Ok(Some(source.read_range(*start, *end)?));
            }
        }
        Ok(None)
    }
}

enum VariantSource {
    File(OwnedFd),
    Memory(Vec<u8>),
}

impl VariantSource {
    fn read_range(&self, start: u64, end: u64) -> Result<Vec<u8>> {
        match self {
            VariantSource::File(fd) => pread_range(fd, start, end),
            VariantSource::Memory(data) => {
                let s = start as usize;
                let e = end as usize;
                data.get(s..e).map(|slice| slice.to_vec()).ok_or_else(|| {
                    anyhow!("read range {s}..{e} out of bounds (len={})", data.len())
                })
            }
        }
    }
}

/// Reader for an ostree static delta superblock.
///
/// Uses custom GVariant framing to locate children without loading the
/// entire file into memory (important when inline parts make the
/// superblock very large).
pub struct DeltaSuperblock {
    source: VariantSource,
    /// Byte offset where the superblock variant starts within the data.
    base_offset: u64,
    /// Total size of the superblock variant.
    variant_size: u64,
    children: SuperblockChildRanges,
    metadata_index: MetadataDictIndex,
    swap_endian: bool,
}

impl std::fmt::Debug for DeltaSuperblock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeltaSuperblock")
            .field("variant_size", &self.variant_size)
            .field("swap_endian", &self.swap_endian)
            .finish_non_exhaustive()
    }
}

impl DeltaSuperblock {
    fn init(source: VariantSource, total_size: u64) -> Result<Self> {
        // Check for signed delta wrapper
        let (base_offset, variant_size) = if total_size >= 8 {
            let magic_buf = source.read_range(0, 8)?;
            let magic = u64::from_be_bytes(magic_buf[..8].try_into().unwrap());
            if magic == SIGNED_DELTA_MAGIC {
                // Signed format (taya{sv}): child 0 is fixed (t=8 bytes),
                // child 1 (ay) has one frame offset, child 2 (a{sv}) is LAST.
                let osz = gv_offset_size(total_size);
                let fo_buf = source.read_range(total_size - osz as u64, total_size)?;
                let sb_start = 8u64; // ay starts right after the fixed t
                let sb_end = gv_read_offset(&fo_buf, osz, 0);
                (sb_start, sb_end - sb_start)
            } else {
                (0, total_size)
            }
        } else {
            (0, total_size)
        };

        // Read frame offsets from the superblock variant.
        // They are stored at the end, with the last one (nearest the end)
        // corresponding to the first variable child. We read them in
        // reverse so frame_offsets[0] = end of first variable child.
        let osz = gv_offset_size(variant_size);
        ensure!(osz > 0, "superblock is empty");
        let fo_size = (N_FRAME_OFFSETS * osz) as u64;
        ensure!(
            variant_size >= fo_size,
            "superblock too small for frame offsets"
        );
        let fo_buf = source.read_range(
            base_offset + variant_size - fo_size,
            base_offset + variant_size,
        )?;

        let frame_offsets: [u64; N_FRAME_OFFSETS] =
            std::array::from_fn(|i| gv_read_offset(&fo_buf, osz, N_FRAME_OFFSETS - 1 - i));

        let children = compute_child_ranges(variant_size, &frame_offsets);

        // Cache the metadata dict offset table and key strings
        let (meta_start, meta_end) = children.ranges[0];
        let metadata_index =
            MetadataDictIndex::load(&source, base_offset + meta_start, meta_end - meta_start)?;

        let swap_endian = Self::detect_endianness(&source, &metadata_index)?;

        Ok(DeltaSuperblock {
            source,
            base_offset,
            variant_size,
            children,
            metadata_index,
            swap_endian,
        })
    }

    /// Open a delta superblock from a file path.
    pub fn open(path: &Path) -> Result<Self> {
        let fd = openat(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening delta at {}", path.display()))?;

        let file_size = seek(&fd, rustix::fs::SeekFrom::End(0))?;
        Self::init(VariantSource::File(fd), file_size)
    }

    /// Create a delta superblock from in-memory data.
    pub fn from_data(data: Vec<u8>) -> Result<Self> {
        let size = data.len() as u64;
        Self::init(VariantSource::Memory(data), size)
    }

    fn read_child(&self, index: usize) -> Result<Vec<u8>> {
        let (start, end) = self.children.ranges[index];
        self.source
            .read_range(self.base_offset + start, self.base_offset + end)
    }

    fn read_child_aligned(&self, index: usize) -> Result<AlignedBuf> {
        Ok(self.read_child(index)?.into())
    }

    fn detect_endianness(
        source: &VariantSource,
        metadata_index: &MetadataDictIndex,
    ) -> Result<bool> {
        let entry_data = match metadata_index.lookup(source, "ostree.endianness")? {
            Some(d) => d,
            None => return Ok(false),
        };

        // Parse the small {sv} entry with gvariant
        let aligned: AlignedBuf = entry_data.into();
        let entry = gv!("{sv}").cast(
            aligned
                .try_as_aligned()
                .map_err(|_| anyhow!("endianness entry not aligned"))?,
        );
        let (_key, value) = entry.to_tuple();
        if let Some(v) = value.get(gv!("y")) {
            let native = if cfg!(target_endian = "little") {
                b'l'
            } else {
                b'B'
            };
            return Ok(*v != native);
        }

        Ok(false)
    }

    fn maybe_swap_u64(&self, v: u64) -> u64 {
        if self.swap_endian { v.swap_bytes() } else { v }
    }

    /// Returns the from-commit checksum (None for scratch deltas).
    pub fn from_checksum(&self) -> Result<Option<Sha256Digest>> {
        let data = self.read_child(2)?;
        if data.is_empty() {
            return Ok(None);
        }
        ensure!(
            data.len() == 32,
            "invalid from-checksum length {}",
            data.len()
        );
        Ok(Some(
            data.try_into().map_err(|_| anyhow!("bad from-checksum"))?,
        ))
    }

    /// Returns the to-commit checksum.
    pub fn to_checksum(&self) -> Result<Sha256Digest> {
        let data = self.read_child(3)?;
        ensure!(
            data.len() == 32,
            "invalid to-checksum length {}",
            data.len()
        );
        data.try_into().map_err(|_| anyhow!("bad to-checksum"))
    }

    /// Returns the commit object data.
    pub fn commit_data(&self) -> Result<AlignedBuf> {
        self.read_child_aligned(4)
    }

    /// Parse the part headers from child [6].
    pub fn part_headers(&self) -> Result<Vec<DeltaPartHeader>> {
        let buf = self.read_child_aligned(6)?;
        let aligned = buf
            .try_as_aligned()
            .map_err(|_| anyhow!("part headers not aligned"))?;
        let entries = gv!("a(uayttay)").cast(aligned);

        entries
            .iter()
            .map(|entry| {
                let (_version, checksum_bytes, comp_size, uncomp_size, objects_bytes) =
                    entry.to_tuple();
                let checksum: Sha256Digest =
                    checksum_bytes.try_into().context("invalid part checksum")?;
                let compressed_size = self.maybe_swap_u64(u64::from_be(*comp_size));
                let uncompressed_size = self.maybe_swap_u64(u64::from_be(*uncomp_size));

                let obj_data: &[u8] = objects_bytes;
                ensure!(
                    obj_data.len().is_multiple_of(OBJTYPE_CSUM_LEN),
                    "objects array length {} not a multiple of {OBJTYPE_CSUM_LEN}",
                    obj_data.len()
                );
                let objects = obj_data
                    .chunks_exact(OBJTYPE_CSUM_LEN)
                    .map(|chunk| {
                        let obj_type = ObjectType::from_byte(chunk[0])?;
                        let csum: Sha256Digest = chunk[1..33]
                            .try_into()
                            .map_err(|_| anyhow!("bad object checksum"))?;
                        Ok((obj_type, csum))
                    })
                    .collect::<Result<Vec<_>>>()?;

                Ok(DeltaPartHeader {
                    checksum,
                    compressed_size,
                    uncompressed_size,
                    objects,
                })
            })
            .collect()
    }

    /// Parse the fallback entries from child [7].
    pub fn fallbacks(&self) -> Result<Vec<DeltaFallback>> {
        let buf = self.read_child_aligned(7)?;
        let aligned = buf
            .try_as_aligned()
            .map_err(|_| anyhow!("fallbacks not aligned"))?;
        let entries = gv!("a(yaytt)").cast(aligned);

        entries
            .iter()
            .map(|entry| {
                let (obj_type_byte, checksum_bytes, comp_size, uncomp_size) = entry.to_tuple();
                let obj_type = ObjectType::from_byte(*obj_type_byte)?;
                let checksum: Sha256Digest = checksum_bytes
                    .try_into()
                    .context("invalid fallback checksum")?;
                let compressed_size = self.maybe_swap_u64(u64::from_be(*comp_size));
                let uncompressed_size = self.maybe_swap_u64(u64::from_be(*uncomp_size));
                Ok(DeltaFallback {
                    obj_type,
                    checksum,
                    compressed_size,
                    uncompressed_size,
                })
            })
            .collect()
    }

    /// Read part data for the given part index.
    ///
    /// Tries inline data in the metadata dict first, then falls back
    /// to a numbered file in the same directory.
    pub fn read_part(&self, index: usize, delta_path: &Path) -> Result<Vec<u8>> {
        if let Some(data) = self.read_inline_part(index)? {
            return Ok(data);
        }

        let dir = delta_path
            .parent()
            .ok_or_else(|| anyhow!("delta path has no parent directory"))?;
        let part_path = dir.join(index.to_string());
        let mut data = Vec::new();
        File::open(&part_path)
            .with_context(|| format!("opening delta part {}", part_path.display()))?
            .read_to_end(&mut data)?;
        Ok(data)
    }

    pub(crate) fn read_inline_part(&self, index: usize) -> Result<Option<Vec<u8>>> {
        let suffix = format!("/{index}");
        let entry_data =
            match self
                .metadata_index
                .lookup_by_prefix_suffix(&self.source, "deltas/", &suffix)?
            {
                Some(d) => d,
                None => return Ok(None),
            };

        // Parse the {sv} entry to extract the (yay) value
        let aligned: AlignedBuf = entry_data.into();
        let entry = gv!("{sv}").cast(
            aligned
                .try_as_aligned()
                .map_err(|_| anyhow!("inline part entry not aligned"))?,
        );
        let (_key, value) = entry.to_tuple();
        if let Some(yay) = value.get(gv!("(yay)")) {
            let (comp_type, payload) = yay.to_tuple();
            let mut raw = Vec::with_capacity(1 + payload.len());
            raw.push(*comp_type);
            raw.extend_from_slice(payload);
            return Ok(Some(raw));
        }

        Ok(None)
    }
}

// ---------- Part decompression ----------

pub(crate) fn decompress_part(raw: &[u8]) -> Result<AlignedBuf> {
    ensure!(!raw.is_empty(), "empty delta part");
    let comp_type = raw[0];
    let payload = &raw[1..];

    match comp_type {
        0 => Ok(payload.to_vec().into()),
        b'x' => {
            let mut decoder = xz2::read::XzDecoder::new(payload);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            Ok(decompressed.into())
        }
        _ => bail!("unknown delta part compression type {comp_type:#x}"),
    }
}

// ---------- Part executor ----------

struct DeltaExecState<'a> {
    // Object tracking
    checksum_index: usize,
    objects: &'a [(ObjectType, Sha256Digest)],

    // Payload and operations
    payload: &'a [u8],
    ops: &'a [u8],
    ops_pos: usize,

    // Mode and xattr dicts (indices into these are used by opcodes)
    modes: Vec<(u32, u32, u32)>,
    xattrs: Vec<Vec<(Vec<u8>, Vec<u8>)>>,

    // Current object being built
    content_buf: Vec<u8>,
    content_size: u64,
    current_uid: u32,
    current_gid: u32,
    current_mode: u32,
    current_xattrs: Vec<(Vec<u8>, Vec<u8>)>,

    // Read source for differential ops
    read_source: Option<Vec<u8>>,
}

impl<'a> DeltaExecState<'a> {
    fn read_varuint(&mut self) -> Result<u64> {
        read_varuint64(self.ops, &mut self.ops_pos)
    }

    fn current_object(&self) -> Result<&(ObjectType, Sha256Digest)> {
        self.objects
            .get(self.checksum_index)
            .ok_or_else(|| anyhow!("object index {} out of range", self.checksum_index))
    }

    fn payload_slice(&self, offset: u64, len: u64) -> Result<&'a [u8]> {
        let start = offset as usize;
        let end = start
            .checked_add(len as usize)
            .ok_or_else(|| anyhow!("payload offset overflow"))?;
        self.payload.get(start..end).ok_or_else(|| {
            anyhow!(
                "payload slice {start}..{end} out of range (len={})",
                self.payload.len()
            )
        })
    }
}

/// Execute a single delta part, producing objects into the writer.
///
/// `base` is needed to resolve `SET_READ_SOURCE` opcodes that reference
/// objects from the previous commit.
pub(crate) fn execute_delta_part<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    writer: &mut CommitWriter<ObjectID>,
    base: Option<&CommitReader<ObjectID>>,
    part_data: &AlignedBuf,
    objects: &[(ObjectType, Sha256Digest)],
) -> Result<()> {
    let aligned = part_data
        .try_as_aligned()
        .map_err(|_| anyhow!("part payload not aligned"))?;
    let part = gv!("(a(uuu)aa(ayay)ayay)").cast(aligned);
    let (mode_dict, xattr_dict, payload_var, ops_var) = part.to_tuple();

    // Parse mode dict
    let modes: Vec<(u32, u32, u32)> = mode_dict
        .iter()
        .map(|m| {
            let (uid, gid, mode) = m.to_tuple();
            (u32::from_be(*uid), u32::from_be(*gid), u32::from_be(*mode))
        })
        .collect();

    // Parse xattr dict
    let xattrs: Vec<Vec<(Vec<u8>, Vec<u8>)>> = xattr_dict
        .iter()
        .map(|xa| {
            xa.iter()
                .map(|pair| {
                    let (k, v) = pair.to_tuple();
                    (k.to_vec(), v.to_vec())
                })
                .collect()
        })
        .collect();

    let payload: &[u8] = payload_var;
    let ops: &[u8] = ops_var;

    let mut state = DeltaExecState {
        checksum_index: 0,
        objects,
        payload,
        ops,
        ops_pos: 0,
        modes,
        xattrs,
        content_buf: Vec::new(),
        content_size: 0,
        current_uid: 0,
        current_gid: 0,
        current_mode: 0,
        current_xattrs: Vec::new(),
        read_source: None,
    };

    while state.ops_pos < state.ops.len() {
        let opcode = state.ops[state.ops_pos];
        state.ops_pos += 1;

        match opcode {
            OP_OPEN_SPLICE_AND_CLOSE => {
                dispatch_open_splice_and_close(repo, writer, &mut state)?;
            }
            OP_OPEN => {
                dispatch_open(&mut state)?;
            }
            OP_WRITE => {
                dispatch_write(&mut state)?;
            }
            OP_SET_READ_SOURCE => {
                dispatch_set_read_source(repo, base, &mut state)?;
            }
            OP_UNSET_READ_SOURCE => {
                state.read_source = None;
            }
            OP_CLOSE => {
                dispatch_close(repo, writer, &mut state)?;
            }
            OP_BSPATCH => {
                dispatch_bspatch(&mut state)?;
            }
            _ => bail!("unknown delta opcode {opcode:#x}"),
        }
    }

    Ok(())
}

fn dispatch_open_splice_and_close<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    writer: &mut CommitWriter<ObjectID>,
    state: &mut DeltaExecState,
) -> Result<()> {
    let (obj_type, checksum) = *state.current_object()?;

    if obj_type.is_meta() {
        let content_len = state.read_varuint()? as usize;
        let content_offset = state.read_varuint()?;
        let data = state.payload_slice(content_offset, content_len as u64)?;
        writer.insert(&checksum, None, data);
    } else {
        // File object
        let mode_offset = state.read_varuint()? as usize;
        let xattr_offset = state.read_varuint()? as usize;
        let content_size = state.read_varuint()?;
        let content_offset = state.read_varuint()?;

        let (uid, gid, mode) = *state
            .modes
            .get(mode_offset)
            .ok_or_else(|| anyhow!("mode index {mode_offset} out of range"))?;
        let xattrs = state
            .xattrs
            .get(xattr_offset)
            .ok_or_else(|| anyhow!("xattr index {xattr_offset} out of range"))?
            .clone();

        let content_data = state.payload_slice(content_offset, content_size)?;

        let is_symlink = rustix::fs::FileType::from_raw_mode(mode).is_symlink();
        let symlink_target = if is_symlink {
            std::str::from_utf8(content_data)
                .context("symlink target not UTF-8")?
                .to_string()
        } else {
            String::new()
        };
        let file_header = OstreeFileHeader {
            size: if is_symlink { 0 } else { content_size },
            uid,
            gid,
            mode,
            symlink_target,
            xattrs,
        };

        let file_content = if is_symlink {
            &[] as &[u8]
        } else {
            content_data
        };
        store_file_object(repo, writer, &checksum, &file_header, file_content)?;
    }

    state.checksum_index += 1;
    Ok(())
}

fn dispatch_open(state: &mut DeltaExecState) -> Result<()> {
    let mode_offset = state.read_varuint()? as usize;
    let xattr_offset = state.read_varuint()? as usize;
    let content_size = state.read_varuint()?;

    let (uid, gid, mode) = *state
        .modes
        .get(mode_offset)
        .ok_or_else(|| anyhow!("mode index {mode_offset} out of range"))?;
    let xattrs = state
        .xattrs
        .get(xattr_offset)
        .ok_or_else(|| anyhow!("xattr index {xattr_offset} out of range"))?
        .clone();

    state.content_buf.clear();
    state.content_size = content_size;
    state.current_uid = uid;
    state.current_gid = gid;
    state.current_mode = mode;
    state.current_xattrs = xattrs;

    Ok(())
}

fn dispatch_write(state: &mut DeltaExecState) -> Result<()> {
    let content_size = state.read_varuint()?;
    let content_offset = state.read_varuint()?;

    if let Some(ref source) = state.read_source {
        let start = content_offset as usize;
        let end = start + content_size as usize;
        ensure!(end <= source.len(), "read_source offset out of range");
        state.content_buf.extend_from_slice(&source[start..end]);
    } else {
        let data = state.payload_slice(content_offset, content_size)?;
        state.content_buf.extend_from_slice(data);
    }

    Ok(())
}

fn dispatch_set_read_source<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    base: Option<&CommitReader<ObjectID>>,
    state: &mut DeltaExecState,
) -> Result<()> {
    let source_offset = state.read_varuint()? as usize;
    ensure!(
        source_offset + 32 <= state.payload.len(),
        "read source checksum offset out of range"
    );
    let checksum: Sha256Digest = state.payload[source_offset..source_offset + 32]
        .try_into()
        .map_err(|_| anyhow!("bad read source checksum"))?;

    let base = base.ok_or_else(|| {
        anyhow!(
            "SET_READ_SOURCE references {} but no base commit available",
            hex::encode(checksum)
        )
    })?;

    let (obj_id, file_header_data) = base.lookup(&checksum)?.ok_or_else(|| {
        anyhow!(
            "SET_READ_SOURCE object {} not found in base commit",
            hex::encode(checksum)
        )
    })?;

    if let Some(id) = obj_id {
        let data = repo.read_object(id)?;
        state.read_source = Some(data);
    } else {
        // Inline content: everything after the zlib-sized header
        let header_size = std::mem::size_of::<crate::ostree::SizedVariantHeader>();
        let variant_size = crate::ostree::get_sized_variant_size(file_header_data)?;
        let content_start = header_size + variant_size;
        let content = file_header_data.get(content_start..).unwrap_or(&[]);
        state.read_source = Some(content.to_vec());
    }

    Ok(())
}

fn dispatch_close<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    writer: &mut CommitWriter<ObjectID>,
    state: &mut DeltaExecState,
) -> Result<()> {
    let (_obj_type, checksum) = *state.current_object()?;

    let is_symlink = rustix::fs::FileType::from_raw_mode(state.current_mode).is_symlink();
    let symlink_target = if is_symlink {
        std::str::from_utf8(&state.content_buf)
            .context("symlink target not UTF-8")?
            .to_string()
    } else {
        String::new()
    };
    let file_header = OstreeFileHeader {
        size: if is_symlink { 0 } else { state.content_size },
        uid: state.current_uid,
        gid: state.current_gid,
        mode: state.current_mode,
        symlink_target,
        xattrs: state.current_xattrs.clone(),
    };

    let file_content: &[u8] = if is_symlink { &[] } else { &state.content_buf };
    store_file_object(repo, writer, &checksum, &file_header, file_content)?;

    state.content_buf.clear();
    state.read_source = None;
    state.checksum_index += 1;
    Ok(())
}

fn dispatch_bspatch(state: &mut DeltaExecState) -> Result<()> {
    let offset = state.read_varuint()?;
    let length = state.read_varuint()?;

    let patch_data = state.payload_slice(offset, length)?;
    let source = state
        .read_source
        .as_ref()
        .ok_or_else(|| anyhow!("BSPATCH without read source"))?;

    let mut new_data = Vec::new();
    bsdiff::patch(source, &mut &patch_data[..], &mut new_data).context("bspatch failed")?;

    state.content_buf.extend_from_slice(&new_data);
    Ok(())
}

fn store_file_object<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    writer: &mut CommitWriter<ObjectID>,
    checksum: &Sha256Digest,
    header: &OstreeFileHeader,
    content: &[u8],
) -> Result<()> {
    let zlib_header = header.serialize_zlib_sized();

    if should_inline_file::<ObjectID>(content.len()) {
        let mut data = zlib_header;
        data.with_vec(|v| v.extend_from_slice(content));
        writer.insert(checksum, None, &data);
    } else {
        let obj_id = repo.ensure_object(content)?;
        writer.insert(checksum, Some(&obj_id), &zlib_header);
    }

    Ok(())
}

// ---------- Top-level apply ----------

/// Apply a static delta from a local file.
///
/// The `delta_path` can be either a single-file (inline) delta or the
/// `superblock` file in a delta directory.
pub fn apply_delta_offline<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    delta_path: &Path,
) -> Result<(ObjectID, PullStats)> {
    let superblock = DeltaSuperblock::open(delta_path)?;

    let from_checksum = superblock.from_checksum()?;
    let to_checksum = superblock.to_checksum()?;

    let commit_hex = hex::encode(to_checksum);
    let content_id = format!("ostree-commit-{commit_hex}");
    if let Some(objid) = repo.has_stream(&content_id)? {
        return Ok((
            objid,
            PullStats {
                commit_id: commit_hex,
                ..Default::default()
            },
        ));
    }

    let fallbacks = superblock.fallbacks()?;
    ensure!(
        fallbacks.is_empty(),
        "cannot apply delta offline: contains {} fallback entries",
        fallbacks.len()
    );

    let part_headers = superblock.part_headers()?;

    // Load base commit if this is a non-scratch delta
    let base = if let Some(from) = from_checksum {
        let from_stream = format!("ostree-commit-{}", hex::encode(from));
        ensure!(
            repo.has_stream(&from_stream)?.is_some(),
            "base commit {} not found in repository",
            hex::encode(from)
        );
        Some(CommitReader::<ObjectID>::load(repo, &from_stream)?)
    } else {
        None
    };

    let mut writer = CommitWriter::<ObjectID>::new();
    let mut stats = PullStats {
        commit_id: commit_hex.clone(),
        ..Default::default()
    };

    // Execute all delta parts
    for (i, header) in part_headers.iter().enumerate() {
        let raw = superblock.read_part(i, delta_path)?;

        // Verify checksum of raw part data
        let actual = Sha256::digest(&raw);
        if *actual != header.checksum {
            bail!(
                "delta part {i} checksum mismatch: expected {}, got {}",
                hex::encode(header.checksum),
                hex::encode(actual)
            );
        }

        let decompressed = decompress_part(&raw)?;
        execute_delta_part(
            repo,
            &mut writer,
            base.as_ref(),
            &decompressed,
            &header.objects,
        )?;

        for (obj_type, _) in &header.objects {
            if obj_type.is_meta() {
                stats.metadata_fetched += 1;
            } else {
                stats.files_fetched += 1;
            }
        }
    }

    // Insert the commit object from the superblock
    let commit_data = superblock.commit_data()?;
    writer.insert(&to_checksum, None, &commit_data);
    writer.set_commit_id(&to_checksum);
    stats.metadata_fetched += 1;

    // Inherit unchanged objects from base commit
    if let Some(ref base) = base {
        inherit_base_objects(&mut writer, base, &commit_data)?;
    }

    let verity = writer.serialize(repo, &content_id, None, None)?;
    crate::ensure_ostree_erofs(repo, &stats.commit_id)?;

    Ok((verity, stats))
}

/// Walk the new commit's DAG and copy any objects not already in the
/// writer from the base commit's splitstream.
pub(crate) fn inherit_base_objects<ObjectID: FsVerityHashValue>(
    writer: &mut CommitWriter<ObjectID>,
    base: &CommitReader<ObjectID>,
    commit_data: &[u8],
) -> Result<()> {
    let aligned: AlignedBuf = commit_data.to_vec().into();
    let commit = OstreeCommit::from_data(
        aligned
            .try_as_aligned()
            .map_err(|_| anyhow!("commit data not aligned"))?,
    )?;

    let mut visited = std::collections::HashSet::new();
    inherit_dirmeta(writer, base, &commit.root_metadata)?;
    inherit_dirtree(writer, base, &commit.root_tree, &mut visited)?;

    Ok(())
}

fn inherit_dirmeta<ObjectID: FsVerityHashValue>(
    writer: &mut CommitWriter<ObjectID>,
    base: &CommitReader<ObjectID>,
    id: &Sha256Digest,
) -> Result<()> {
    if writer.contains(id) {
        return Ok(());
    }
    if let Some(data) = base.lookup_data(id)? {
        writer.insert(id, None, data);
    }
    Ok(())
}

fn inherit_dirtree<ObjectID: FsVerityHashValue>(
    writer: &mut CommitWriter<ObjectID>,
    base: &CommitReader<ObjectID>,
    id: &Sha256Digest,
    visited: &mut std::collections::HashSet<Sha256Digest>,
) -> Result<()> {
    if !visited.insert(*id) {
        return Ok(());
    }

    // The dirtree may already be in the writer (produced by the delta) or
    // only in the base. Either way we need to parse it and walk children,
    // because children may still need inheriting from the base.
    if !writer.contains(id) {
        let data = base.lookup_data(id)?.ok_or_else(|| {
            anyhow!(
                "Unexpectedly missing ostree dirtree object {}",
                hex::encode(id)
            )
        })?;
        writer.insert(id, None, data);
    }
    let data: AlignedBuf = writer
        .lookup_data(id)
        .ok_or_else(|| anyhow!("dirtree just inserted but not found"))?[..]
        .to_vec()
        .into();

    let dirtree = OstreeDirTree::from_data(
        data.try_as_aligned()
            .map_err(|_| anyhow!("dirtree not aligned"))?,
    )?;

    for (_name, file_checksum) in &dirtree.files {
        inherit_file(writer, base, file_checksum)?;
    }

    for (_name, tree_checksum, meta_checksum) in &dirtree.dirs {
        inherit_dirmeta(writer, base, meta_checksum)?;
        inherit_dirtree(writer, base, tree_checksum, visited)?;
    }

    Ok(())
}

fn inherit_file<ObjectID: FsVerityHashValue>(
    writer: &mut CommitWriter<ObjectID>,
    base: &CommitReader<ObjectID>,
    id: &Sha256Digest,
) -> Result<()> {
    if writer.contains(id) {
        return Ok(());
    }
    if let Some((obj_id, file_header)) = base.lookup(id)? {
        writer.insert(id, obj_id, file_header);
    }
    Ok(())
}
