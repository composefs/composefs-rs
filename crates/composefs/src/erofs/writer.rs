//! EROFS image generation from composefs trees.
//!
//! The public entry points are:
//!
//! - [`mkfs_erofs`] — generate a single EROFS image using the repository's default format
//! - [`mkfs_erofs_versioned`] — generate an image for a specific [`FormatVersion`]
//!
//! Both require a [`ValidatedFileSystem`], which is the type-safe gate: constructing
//! one runs [`fsck`](crate::tree::FileSystem::fsck) and checks EROFS-specific invariants
//! (e.g. whiteout inodes must not be hardlinked). A validated filesystem cannot panic the
//! writer.
//!
//! ## Format versions
//!
//! Three on-disk formats are supported, selected by [`FormatVersion`]:
//!
//! **V0** (`FormatVersion::V0`) is byte-for-byte compatible with C `mkcomposefs` default
//! output.  It uses compact inodes (32 bytes) where the inode fits, extended (64 bytes)
//! otherwise; collects inodes in BFS order; includes a 256-entry whiteout stub table at the
//! start of the inode area; sets `build_time` to the minimum mtime; and encodes user-visible
//! whiteout files (chr 0,0) via `trusted.overlay.opaque=x` xattrs rather than storing them
//! directly.  The `composefs_version` header field is `0` normally and auto-upgrades to `1`
//! when user whiteouts are present.
//!
//! **V1** (`FormatVersion::V1`, the default) uses the same EROFS layout as V0 but always
//! writes `composefs_version=1` in the header — equivalent to C `mkcomposefs --min-version=1`.
//! This is the recommended default for new repositories.
//!
//! **V2** (`FormatVersion::V2`) is the composefs-rs native format. It always uses extended
//! inodes (64 bytes), collects inodes in DFS order, omits the whiteout stub table, sets
//! `build_time` to 0, and sets `composefs_version` to 2. Whiteout files are stored without
//! escaping.
//!
//! ## Two-pass layout + emit design
//!
//! `write_erofs` is called twice on the same inode list. The first pass uses a `FirstPass`
//! output that counts bytes and records the byte offset of every inode, block, and data
//! region without writing anything. The second pass uses a `SecondPass` output that
//! serializes bytes into a buffer. EROFS node IDs (nids) and cross-region offsets can only
//! be computed after the first pass, so all [`InodeRef::Known`] references are resolved
//! between the two passes.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    mem::size_of,
    num::NonZeroUsize,
    os::unix::ffi::OsStrExt,
};

use log::trace;
use xxhash_rust::xxh32::xxh32;
use zerocopy::{Immutable, IntoBytes};

use crate::{
    erofs::{
        composefs::OverlayMetacopy,
        format::{self, FormatEpoch},
        reader::round_up,
    },
    fsverity::FsVerityHashValue,
    generic_tree::LeafId,
    tree,
};

/// A composefs filesystem tree validated for EROFS serialization.
///
/// Can only be constructed via [`ValidatedFileSystem::new`], which checks
/// that the tree satisfies all EROFS invariants — for example, that no
/// whiteout inode (character device with rdev=0) has `nlink > 1`.
///
/// Passing a `ValidatedFileSystem` to [`mkfs_erofs`] or
/// [`mkfs_erofs_versioned`] therefore cannot panic.
pub struct ValidatedFileSystem<ObjectID: FsVerityHashValue>(pub(crate) tree::FileSystem<ObjectID>);

impl<ObjectID: FsVerityHashValue + std::fmt::Debug> std::fmt::Debug
    for ValidatedFileSystem<ObjectID>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ValidatedFileSystem").field(&self.0).finish()
    }
}

impl<ObjectID: FsVerityHashValue> ValidatedFileSystem<ObjectID> {
    /// Validate `fs` and wrap it. Returns an error if any invariant is violated.
    pub fn new(fs: tree::FileSystem<ObjectID>) -> anyhow::Result<Self> {
        validate_filesystem(&fs)?;
        Ok(Self(fs))
    }
}

impl<ObjectID: FsVerityHashValue> std::ops::Deref for ValidatedFileSystem<ObjectID> {
    type Target = tree::FileSystem<ObjectID>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub(crate) fn validate_filesystem<ObjectID: FsVerityHashValue>(
    fs: &tree::FileSystem<ObjectID>,
) -> anyhow::Result<()> {
    // Check structural invariants: leaf ref bounds, no orphaned leaves.
    fs.fsck()
        .map_err(|e| anyhow::anyhow!("invalid composefs filesystem: {e}"))?;

    // Check EROFS-specific constraint: whiteout inodes (chardev rdev=0) must not be hardlinked.
    let nlinks = fs.nlinks();
    for (idx, leaf) in fs.leaves.iter().enumerate() {
        if matches!(leaf.content, tree::LeafContent::CharacterDevice(0)) {
            let nlink = nlinks[idx];
            if nlink > 1 {
                anyhow::bail!("invalid composefs filesystem: whiteout inode has nlink > 1");
            }
        }
    }
    Ok(())
}

/// Size of one EROFS inode slot in bytes. All inode offsets must be a multiple of this.
const INODE_SLOT_SIZE: usize = 32;

/// EROFS xattr values are addressed in 4-byte words; all xattr offsets and counts use this unit.
const XATTR_WORD_SIZE: usize = size_of::<u32>();

/// Size of the InodeXAttrHeader in bytes, used in xattr_icount calculation.
const INODE_XATTR_HEADER_SIZE: usize = size_of::<format::InodeXAttrHeader>();

/// Returns the byte offset of `pos` within its EROFS block (i.e. `pos % BLOCK_SIZE`).
///
/// `BLOCK_SIZE` (4096) is a nonzero constant, so this operation never panics.
fn block_offset(pos: u64) -> u64 {
    pos % u64::from(format::BLOCK_SIZE)
}

/// Returns the number of bytes from `pos` to the next EROFS block boundary,
/// or `None` if `pos` is already block-aligned (no padding needed).
///
/// When `Some`, the result is always in `1..BLOCK_SIZE`.
fn bytes_to_block_boundary(pos: u64) -> Option<u64> {
    let offset = block_offset(pos);
    if offset == 0 {
        return None;
    }
    let block_size = u64::from(format::BLOCK_SIZE);
    let padding = block_size
        .checked_sub(offset)
        .expect("block_offset(pos) < BLOCK_SIZE by construction");
    debug_assert!(padding >= 1 && padding < block_size);
    Some(padding)
}

/// Deterministic fault injector for writer tests.
///
/// Each field is a probability in [0.0, 1.0]:
///   0.0 = never inject this fault
///   1.0 = always inject this fault
///
/// Construct with `WriterFaults::new(seed)` then set the rates you need.
/// Because `write_erofs` runs twice (layout pass then emit pass), decisions
/// are recorded during the first pass and replayed during the second so that
/// both passes make identical choices and produce a structurally coherent image.
#[cfg(test)]
pub(crate) struct WriterFaults {
    rng: rand::rngs::SmallRng,
    /// Skip the symlink block-boundary padding (produces a malformed image).
    pub skip_symlink_pad_rate: f64,
    /// Decisions recorded during the first pass; replayed during the second.
    decisions: Vec<bool>,
    /// Index into `decisions` during replay.
    replay_idx: usize,
    /// True after `start_replay()` is called.
    replaying: bool,
}

#[cfg(test)]
impl WriterFaults {
    pub fn new(seed: u64) -> Self {
        use rand::SeedableRng;
        Self {
            rng: rand::rngs::SmallRng::seed_from_u64(seed),
            skip_symlink_pad_rate: 0.0,
            decisions: Vec::new(),
            replay_idx: 0,
            replaying: false,
        }
    }

    /// Call between first and second pass to switch to replay mode.
    pub(crate) fn start_replay(&mut self) {
        self.replaying = true;
        self.replay_idx = 0;
    }

    fn should_skip_symlink_pad(&mut self) -> bool {
        if self.replaying {
            let decision = self.decisions[self.replay_idx];
            self.replay_idx += 1;
            decision
        } else {
            use rand::RngExt;
            let decision = self.rng.random::<f64>() < self.skip_symlink_pad_rate;
            self.decisions.push(decision);
            decision
        }
    }
}

/// Bundles the parameters that are constant across a single `write_erofs` call.
struct WriteContext {
    version: format::FormatVersion,
    min_mtime: (u64, u32),
    header_flags: u32,
    /// The `composefs_version` value written to the ComposefsHeader.
    ///
    /// For V2: always 2 (COMPOSEFS_VERSION).
    /// For V1: 0 normally, but 1 when the tree contains user-land whiteouts (char
    /// devices with rdev=0 that were escaped by the V1 writer).  This matches C
    /// mkcomposefs, which bumps `options->version` from 0 to 1 when it encounters
    /// a whiteout in the input tree (before adding the 256 overlay stubs).
    composefs_version: u32,
    #[cfg(test)]
    faults: Option<WriterFaults>,
}

trait Output {
    // --- Recording (first pass only, no-ops in second pass) ---
    fn note_header_emitted(&mut self);
    fn note_superblock_emitted(&mut self);
    fn note_inode(&mut self);
    fn note_inodes_end(&mut self);
    fn note_xattr(&mut self);
    fn note_block(&mut self);
    fn note_end(&mut self);

    // --- Retrieval (None in first pass when offsets not yet known, Some in second pass) ---
    fn get_inode_offset(&self, idx: usize) -> Option<NonZeroUsize>;
    fn get_inodes_end(&self) -> Option<NonZeroUsize>;
    fn get_xattr_offset(&self, idx: usize) -> Option<NonZeroUsize>;
    fn get_block_offset(&self, idx: usize) -> Option<NonZeroUsize>;
    fn get_end(&self) -> Option<NonZeroUsize>;

    // --- I/O ---
    fn write(&mut self, data: &[u8]);
    fn pad(&mut self, alignment: usize);
    fn len(&self) -> usize;

    /// Write `n` zero bytes. Default implementation avoids heap allocation.
    fn write_zeros(&mut self, n: usize) {
        const BUF: [u8; 1024] = [0u8; 1024];
        let mut remaining = n;
        while remaining > 0 {
            let chunk = remaining.min(BUF.len());
            self.write(&BUF[..chunk]);
            remaining -= chunk;
        }
    }

    // --- Typed write methods: note + write bundled, removing duplication ---

    /// Write the composefs header and pad to 1024 bytes.
    fn write_composefs_header(&mut self, hdr: format::ComposefsHeader) {
        self.note_header_emitted();
        self.write(hdr.as_bytes());
        self.pad(1024);
    }

    /// Write the EROFS superblock.
    fn write_superblock(&mut self, sb: format::Superblock) {
        self.note_superblock_emitted();
        self.write(sb.as_bytes());
    }

    // --- Derived helpers ---

    fn write_struct(&mut self, st: impl IntoBytes + Immutable) {
        self.write(st.as_bytes());
    }

    /// Node ID for inode `idx`, or 0 as a placeholder in the first pass.
    fn get_nid(&self, idx: usize) -> u64 {
        let Some(offset) = self.get_inode_offset(idx) else {
            return 0;
        };
        assert_eq!(offset.get() % INODE_SLOT_SIZE, 0);
        (offset.get() / INODE_SLOT_SIZE) as u64
    }

    /// Shared xattr reference value (V1 format), or 0 as a placeholder in the first pass.
    fn get_xattr_v1(&self, idx: usize) -> u32 {
        let (Some(absolute_offset), Some(inodes_end)) =
            (self.get_xattr_offset(idx), self.get_inodes_end())
        else {
            return 0;
        };
        let (absolute_offset, inodes_end) = (absolute_offset.get(), inodes_end.get());
        let offset_within_block = inodes_end % format::BLOCK_SIZE as usize;
        let xattr_offset_from_inodes_end = absolute_offset
            .checked_sub(inodes_end)
            .expect("shared xattr offset must be >= inode table end");
        let raw_ref = (offset_within_block + xattr_offset_from_inodes_end) / XATTR_WORD_SIZE;
        raw_ref
            .try_into()
            .expect("xattr reference index exceeds u32::MAX")
    }

    /// Shared xattr reference value (V2 format), or 0 as a placeholder in the first pass.
    fn get_xattr_v2(&self, idx: usize) -> u32 {
        let Some(offset) = self.get_xattr_offset(idx) else {
            return 0;
        };
        assert_eq!(offset.get() % XATTR_WORD_SIZE, 0);
        (offset.get() / XATTR_WORD_SIZE)
            .try_into()
            .expect("xattr reference index exceeds u32::MAX")
    }

    /// Byte offset of inode `idx`'s block data, or 0 as a placeholder in the first pass.
    fn get_block_start(&self, idx: usize) -> usize {
        self.get_block_offset(idx).map_or(0, NonZeroUsize::get)
    }

    /// Block index of the V1 xattr region, or 0 as a placeholder in the first pass.
    fn get_xattr_blkaddr(&self) -> u32 {
        self.get_inodes_end()
            .map_or(0, |end| (end.get() / format::BLOCK_SIZE as usize) as u32)
    }

    /// Total number of blocks in the image, or 0 as a placeholder in the first pass.
    fn get_block_count(&self) -> u32 {
        self.get_end()
            .map_or(0, |end| (end.get() / format::BLOCK_SIZE as usize) as u32)
    }
}

/// Extended attribute stored in EROFS format.
///
/// The derived Ord sorts by (prefix, suffix, value) which is used for V2.
/// For V1, use `cmp_by_full_key` which sorts by full key name (prefix string + suffix)
/// to match C mkcomposefs behavior.
#[derive(PartialOrd, PartialEq, Eq, Ord, Clone)]
struct XAttr {
    prefix: u8,
    suffix: Box<[u8]>,
    value: Box<[u8]>,
}

impl XAttr {
    /// Compare by full key name (prefix string + suffix), then by value.
    /// This matches C mkcomposefs `cmp_xattr` which uses `strcmp(na->key, nb->key)`.
    /// Uses lazy iterator chaining to avoid heap allocation on every comparison.
    ///
    /// Value tiebreaker uses length-first comparison to match C `xattrs_ht_sort()`,
    /// which compares `value_len` before `memcmp`.  This differs from Rust's
    /// lexicographic `[u8]::cmp` when values have different lengths (e.g.
    /// `\x00\x00` vs `\xee`: lexicographic says `\x00\x00 < \xee`, but
    /// length-first says `\xee < \x00\x00` because 1 < 2).
    fn cmp_by_full_key(&self, other: &Self) -> std::cmp::Ordering {
        let self_key = format::XATTR_PREFIXES[self.prefix as usize]
            .iter()
            .chain(self.suffix.iter());
        let other_key = format::XATTR_PREFIXES[other.prefix as usize]
            .iter()
            .chain(other.suffix.iter());
        self_key.cmp(other_key).then_with(|| {
            self.value
                .len()
                .cmp(&other.value.len())
                .then_with(|| self.value.cmp(&other.value))
        })
    }
}

#[derive(Clone, Default)]
struct InodeXAttrs {
    shared: Vec<usize>,
    local: Vec<XAttr>,
    filter: u32,
}

/// Index into [`InodeCollector::inodes`].  This is NOT an EROFS nid; the nid is computed
/// from the byte offset of the inode during the second pass via [`Output::get_nid`].
type InodeIdx = usize;

/// Reference to an inode in a directory entry.
///
/// Used in [`DirEnt`] during BFS in [`InodeCollector::collect_tree`].  When a hardlink's
/// canonical occurrence hasn't been BFS-processed yet, the entry is stored as
/// `Deferred(leaf_id)` and resolved to `Known(nid)` in the post-BFS resolution pass.
#[derive(Debug, Clone, Copy)]
enum InodeRef {
    Known(InodeIdx),
    Deferred(LeafId),
}

#[derive(Debug)]
struct DirEnt<'a> {
    name: &'a [u8],
    inode: InodeRef,
    file_type: format::FileType,
}

/// Metadata returned by `Inode::inode_meta` used to fill inode header fields.
struct InodeMeta {
    layout: format::DataLayout,
    /// The `i_u` field: meaning depends on layout (rdev, chunk format, or block offset / BLOCK_SIZE).
    i_u: u32,
    size: u64,
    nlink: usize,
}

#[derive(Debug, Default)]
struct Directory<'a> {
    blocks: Box<[Box<[DirEnt<'a>]>]>,
    inline: Box<[DirEnt<'a>]>,
    size: u64,
    nlink: usize,
}

#[derive(Debug)]
struct Leaf<'a, ObjectID: FsVerityHashValue> {
    content: &'a tree::LeafContent<ObjectID>,
    nlink: usize,
    /// Epoch1 only: number of full data blocks for inline content.
    /// Matches C mkcomposefs which splits large inline files into data blocks
    /// plus an optional inline tail. Zero for V2 or small files.
    n_data_blocks: u32,
    /// Epoch1 only: size of the inline tail. When the tail exceeds half a block,
    /// it's promoted to a full data block (n_data_blocks++) and tail becomes 0.
    inline_tail_size: usize,
}

#[derive(Debug)]
enum InodeContent<'a, ObjectID: FsVerityHashValue> {
    Directory(Directory<'a>),
    Leaf(Leaf<'a, ObjectID>),
}

struct Inode<'a, ObjectID: FsVerityHashValue> {
    stat: &'a tree::Stat,
    xattrs: InodeXAttrs,
    content: InodeContent<'a, ObjectID>,
    /// V1 only: this inode was originally a char device with rdev=0 (overlay whiteout)
    /// and has been escaped to a regular file per C mkcomposefs v1.0.8 behavior.
    escaped_whiteout: bool,
}

impl XAttr {
    pub fn write(&self, output: &mut impl Output) {
        output.write_struct(format::XAttrHeader {
            name_len: self.suffix.len() as u8,
            name_index: self.prefix,
            value_size: (self.value.len() as u16).into(),
        });
        output.write(&self.suffix);
        output.write(&self.value);
        output.pad(XATTR_WORD_SIZE);
    }
}

impl InodeXAttrs {
    /// Returns the serialized byte size of this xattr block.
    fn byte_size(&self, version: format::FormatVersion) -> usize {
        let mut counter = FirstPass::default();
        self.write(&mut counter, version);
        counter.offset
    }

    fn add(&mut self, name: &[u8], value: &[u8], version: format::FormatVersion) {
        for (idx, prefix) in format::XATTR_PREFIXES.iter().enumerate().rev() {
            // V1 compatibility: C mkcomposefs v1.0.8 does not include lustre. (index 5)
            // in its prefix table, so lustre.* xattrs use index 0 (raw fallback) in C.
            // Skip index 5 for V1 images to match that behavior.
            if version.epoch() == FormatEpoch::Epoch1 && idx == 5 {
                continue;
            }
            if let Some(suffix) = name.strip_prefix(*prefix) {
                self.filter |= 1 << (xxh32(suffix, format::XATTR_FILTER_SEED + idx as u32) % 32);
                self.local.push(XAttr {
                    prefix: idx as u8,
                    suffix: Box::from(suffix),
                    value: Box::from(value),
                });
                return;
            }
        }
        unreachable!("{:?}", std::str::from_utf8(name)); // worst case: we matched the empty prefix (0)
    }

    fn write(&self, output: &mut impl Output, version: format::FormatVersion) {
        if self.filter != 0 {
            trace!("  write xattrs block");
            output.write_struct(format::InodeXAttrHeader {
                name_filter: (!self.filter).into(),
                shared_count: self.shared.len() as u8,
                ..Default::default()
            });
            for idx in &self.shared {
                trace!("    shared {} @{}", idx, output.len());
                let xattr_ref = match version.epoch() {
                    FormatEpoch::Epoch1 => output.get_xattr_v1(*idx),
                    FormatEpoch::Epoch2 => output.get_xattr_v2(*idx),
                };
                output.write(&xattr_ref.to_le_bytes());
            }
            for attr in &self.local {
                trace!("    local @{}", output.len());
                attr.write(output);
            }
        }
        // our alignment is equal to xattr alignment: no need to pad
    }
}

impl<'a> Directory<'a> {
    pub fn from_entries(entries: Vec<DirEnt<'a>>) -> Self {
        let mut blocks = vec![];
        let mut rest = vec![];

        let mut n_bytes = 0u64;
        let mut nlink = 0;

        trace!("Directory with {} items", entries.len());

        // The content of the directory is fixed at this point so we may as well split it into
        // blocks.  This lets us avoid measuring and re-measuring.
        for entry in entries.into_iter() {
            let entry_size: u64 = (size_of::<format::DirectoryEntryHeader>() + entry.name.len())
                .try_into()
                .unwrap();
            assert!(entry_size <= 4096);

            trace!("    {:?}", entry.file_type);

            if matches!(entry.file_type, format::FileType::Directory) {
                nlink += 1;
            }

            n_bytes += entry_size;
            if n_bytes <= 4096 {
                rest.push(entry);
            } else {
                // It won't fit, so we need to store the existing entries in a block.
                trace!("    block {}", rest.len());
                blocks.push(rest.into_boxed_slice());

                // Start over
                rest = vec![entry];
                n_bytes = entry_size;
            }
        }

        // Don't try to store more than 2048 bytes of tail data
        if n_bytes > 2048 {
            blocks.push(rest.into_boxed_slice());
            rest = vec![];
            n_bytes = 0;
        }

        trace!(
            "  blocks {} inline {} inline_size {n_bytes}",
            blocks.len(),
            rest.len()
        );

        let block_size: u64 = format::BLOCK_SIZE.into();
        let size = block_size * blocks.len() as u64 + n_bytes;
        Self {
            blocks: blocks.into_boxed_slice(),
            inline: rest.into_boxed_slice(),
            size,
            nlink,
        }
    }

    fn write_block(&self, output: &mut impl Output, block: &[DirEnt]) {
        trace!("    write dir block {} @{}", block.len(), output.len());
        let mut nameofs = size_of::<format::DirectoryEntryHeader>() * block.len();

        for entry in block {
            trace!(
                "      entry {:?} name {} @{}",
                entry.file_type,
                nameofs,
                output.len()
            );
            let inode_idx = match entry.inode {
                InodeRef::Known(idx) => idx,
                InodeRef::Deferred(_) => panic!("all inodes must be resolved before writing"),
            };
            output.write_struct(format::DirectoryEntryHeader {
                name_offset: (nameofs as u16).into(),
                inode_offset: output.get_nid(inode_idx).into(),
                file_type: entry.file_type.into(),
                ..Default::default()
            });
            nameofs += entry.name.len();
        }

        for entry in block {
            trace!("      name @{}", output.len());
            output.write(entry.name.as_bytes());
        }
    }

    fn write_inline(&self, output: &mut impl Output) {
        trace!(
            "  write inline len {} expected size {} of {}",
            self.inline.len(),
            self.size % 4096,
            self.size
        );
        self.write_block(output, &self.inline);
    }

    fn write_blocks(&self, output: &mut impl Output) {
        let block_size: usize = format::BLOCK_SIZE.into();
        for block in &self.blocks {
            assert_eq!(output.len() % block_size, 0);
            self.write_block(output, block);
            output.pad(block_size);
        }
    }

    fn inode_meta(&self, block_offset: usize) -> InodeMeta {
        let blkaddr: u32 = (block_offset / 4096)
            .try_into()
            .expect("block address exceeds u32::MAX");
        let (layout, i_u) = if self.inline.is_empty() {
            (format::DataLayout::FlatPlain, blkaddr)
        } else if !self.blocks.is_empty() {
            (format::DataLayout::FlatInline, blkaddr)
        } else {
            (format::DataLayout::FlatInline, 0)
        };
        InodeMeta {
            layout,
            i_u,
            size: self.size,
            nlink: self.nlink,
        }
    }
}

/// Calculates the chunk format bits for an external file based on its size.
///
/// For EROFS chunk-based inodes, the `u` field contains the chunk format
/// which encodes the chunk size as `chunkbits - BLOCK_BITS`.
///
/// The algorithm matches the C implementation:
/// 1. Calculate chunkbits = ilog2(size - 1) + 1
/// 2. Clamp to at least BLOCK_BITS (12)
/// 3. Clamp to at most BLOCK_BITS + 31 (max representable)
/// 4. Return chunkbits - BLOCK_BITS
fn compute_chunk_bitsize(file_size: u64) -> u32 {
    const BLOCK_BITS: u32 = format::BLOCK_BITS as u32;
    const CHUNK_FORMAT_BLKBITS_MASK: u32 = 0x001F; // 31

    // Compute the chunkbits to use for the file size.
    // We want as few chunks as possible, but not an unnecessarily large chunk.
    let mut chunkbits = if file_size > 1 {
        // ilog2(file_size - 1) + 1
        64 - (file_size - 1).leading_zeros()
    } else {
        1
    };

    // At least one logical block
    if chunkbits < BLOCK_BITS {
        chunkbits = BLOCK_BITS;
    }

    // Not larger chunks than max possible
    if chunkbits - BLOCK_BITS > CHUNK_FORMAT_BLKBITS_MASK {
        chunkbits = CHUNK_FORMAT_BLKBITS_MASK + BLOCK_BITS;
    }

    chunkbits
}

fn compute_chunk_format(file_size: u64) -> u32 {
    compute_chunk_bitsize(file_size) - format::BLOCK_BITS as u32
}

fn compute_chunk_count(file_size: u64) -> u32 {
    let chunkbits = compute_chunk_bitsize(file_size);
    let chunksize = 1u64 << chunkbits;
    file_size.div_ceil(chunksize) as u32
}

impl<ObjectID: FsVerityHashValue> Leaf<'_, ObjectID> {
    fn inode_meta(&self, version: format::FormatVersion, block_offset: usize) -> InodeMeta {
        let (layout, i_u, size) = match &self.content {
            tree::LeafContent::Regular(tree::RegularFile::Inline(data)) => {
                if data.is_empty() {
                    (format::DataLayout::FlatPlain, 0, data.len() as u64)
                } else if self.n_data_blocks > 0 {
                    let blkaddr = (block_offset / format::BLOCK_SIZE as usize) as u32;
                    if self.inline_tail_size > 0 {
                        (format::DataLayout::FlatInline, blkaddr, data.len() as u64)
                    } else {
                        (format::DataLayout::FlatPlain, blkaddr, data.len() as u64)
                    }
                } else {
                    (format::DataLayout::FlatInline, 0, data.len() as u64)
                }
            }
            tree::LeafContent::Regular(
                tree::RegularFile::External(.., size)
                | tree::RegularFile::ExternalNoVerity(.., size)
                | tree::RegularFile::Sparse(size),
            ) => {
                let chunk_format = match version.epoch() {
                    // Epoch1: compute chunk format from file size
                    FormatEpoch::Epoch1 => compute_chunk_format(*size),
                    // Epoch2: hardcode 31 (single-chunk layout)
                    FormatEpoch::Epoch2 => 31,
                };
                let i_u = if self.n_data_blocks > 0 {
                    let blkaddr = (block_offset / format::BLOCK_SIZE as usize) as u32;
                    (blkaddr & 0xFFFF0000) | chunk_format
                } else {
                    chunk_format
                };
                (format::DataLayout::ChunkBased, i_u, *size)
            }
            tree::LeafContent::CharacterDevice(rdev) | tree::LeafContent::BlockDevice(rdev) => {
                let rdev32: u32 = (*rdev)
                    .try_into()
                    .expect("device number exceeds EROFS u32 limit");
                (format::DataLayout::FlatPlain, rdev32, 0)
            }
            tree::LeafContent::Fifo | tree::LeafContent::Socket => {
                (format::DataLayout::FlatPlain, 0, 0)
            }
            tree::LeafContent::Symlink(target) => {
                if self.n_data_blocks > 0 {
                    let blkaddr = (block_offset / format::BLOCK_SIZE as usize) as u32;
                    (format::DataLayout::FlatPlain, blkaddr, target.len() as u64)
                } else {
                    (format::DataLayout::FlatInline, 0, target.len() as u64)
                }
            }
        };
        InodeMeta {
            layout,
            i_u,
            size,
            nlink: self.nlink,
        }
    }

    fn write_inline(&self, output: &mut impl Output) {
        match self.content {
            tree::LeafContent::Regular(tree::RegularFile::Inline(data)) => {
                let tail_start = data.len() - self.inline_tail_size;
                output.write(&data[tail_start..]);
            }
            tree::LeafContent::Regular(
                tree::RegularFile::External(..)
                | tree::RegularFile::ExternalNoVerity(..)
                | tree::RegularFile::Sparse(..),
            ) => {
                let n_chunks = self.inline_tail_size / 4;
                for _ in 0..n_chunks {
                    output.write(b"\xff\xff\xff\xff");
                }
            }
            tree::LeafContent::Symlink(target) if self.n_data_blocks == 0 => {
                output.write(target.as_bytes());
            }
            _ => {}
        }
    }

    fn write_data_blocks(&self, output: &mut impl Output) {
        if self.n_data_blocks > 0 {
            let block_size = format::BLOCK_SIZE as usize;
            match self.content {
                tree::LeafContent::Regular(tree::RegularFile::Inline(data)) => {
                    for i in 0..self.n_data_blocks as usize {
                        let start = i * block_size;
                        let end = (start + block_size).min(data.len());
                        if start < data.len() {
                            output.write(&data[start..end]);
                        }
                        output.pad(block_size);
                    }
                }
                tree::LeafContent::Symlink(target) => {
                    let data = target.as_bytes();
                    let len = data.len().min(block_size);
                    output.write(&data[..len]);
                    output.pad(block_size);
                }
                tree::LeafContent::Regular(
                    tree::RegularFile::External(..)
                    | tree::RegularFile::ExternalNoVerity(..)
                    | tree::RegularFile::Sparse(..),
                ) => {
                    const LCFS_MAX_NONINLINE_CHUNKS: usize = 1024;
                    for _ in 0..LCFS_MAX_NONINLINE_CHUNKS {
                        output.write(b"\xff\xff\xff\xff");
                    }
                }
                _ => {}
            }
        }
    }
}

impl<ObjectID: FsVerityHashValue> Inode<'_, ObjectID> {
    fn chunk_inline_tail_size(&self) -> usize {
        match &self.content {
            InodeContent::Leaf(leaf) => leaf.inline_tail_size,
            _ => 0,
        }
    }

    fn file_type(&self) -> format::FileType {
        // V1 whiteout escaping: char device (rdev=0) entries are written as regular files
        // to match C mkcomposefs v1.0.8 behavior.
        if self.escaped_whiteout {
            return format::FileType::RegularFile;
        }
        match &self.content {
            InodeContent::Directory(..) => format::FileType::Directory,
            InodeContent::Leaf(leaf) => match &leaf.content {
                tree::LeafContent::Regular(..) => format::FileType::RegularFile,
                tree::LeafContent::CharacterDevice(..) => format::FileType::CharacterDevice,
                tree::LeafContent::BlockDevice(..) => format::FileType::BlockDevice,
                tree::LeafContent::Fifo => format::FileType::Fifo,
                tree::LeafContent::Socket => format::FileType::Socket,
                tree::LeafContent::Symlink(..) => format::FileType::Symlink,
            },
        }
    }

    fn inode_mode(&self) -> format::ModeField {
        self.file_type() | self.stat.st_mode
    }

    /// Check if this inode can use compact format (32 bytes instead of 64).
    ///
    /// Compact format is used when:
    /// - mtime matches min_mtime (stored in superblock build_time)
    /// - nlink, uid, gid fit in u16
    /// - size fits in u32
    fn fits_in_compact(&self, min_mtime: (u64, u32), size: u64, nlink: usize) -> bool {
        // mtime (both sec and nsec) must match the minimum (which will be stored in superblock
        // build_time / build_time_nsec). The C implementation requires both to match.
        if self.stat.st_mtim_sec as u64 != min_mtime.0 {
            return false;
        }
        if self.stat.st_mtim_nsec != min_mtime.1 {
            return false;
        }

        // nlink must fit in u16
        if nlink > u16::MAX as usize {
            return false;
        }

        // uid and gid must fit in u16
        if self.stat.st_uid > u16::MAX as u32 || self.stat.st_gid > u16::MAX as u32 {
            return false;
        }

        // size must fit in u32
        if size > u32::MAX as u64 {
            return false;
        }

        true
    }

    /// Handle inline tail padding for V1 format.
    ///
    /// Port of C mkcomposefs `compute_erofs_inode_padding_for_tail()`.
    ///
    /// Two branches based on file type:
    /// - Symlinks: pad the *inode start* to a block boundary whenever the inode + xattrs +
    ///   symlink target would cross into a new block (prevents EFSCORRUPTED on old kernels).
    /// - All other FlatInline types (dirs, inline files): pad the *tail* only if it would
    ///   cross into yet another block after inline_start.
    fn pad_inline_tail_v1(
        &self,
        output: &mut impl Output,
        inode_and_xattr_size: u64,
        size: u64,
        #[cfg(test)] ctx: &mut WriteContext,
        #[cfg(not(test))] _ctx: &mut WriteContext,
    ) {
        let block_size = u64::from(format::BLOCK_SIZE);
        let current_pos: u64 = output.len().try_into().unwrap();
        let inline_size = size % block_size;

        if matches!(self.file_type(), format::FileType::Symlink) {
            // Symlink branch: pad *inode start* to a block boundary when
            // inode + xattrs + symlink target would cross into a new block.
            // Matches C: pos_block != end_block.
            //
            // Old kernels (< 6.12) return EFSCORRUPTED from erofs_fill_symlink()
            // when (inode_offset % block_size) + inode_and_xattr_size + inline_size
            // > block_size.  Padding the inode start to a block boundary prevents
            // this because then inode_offset % block_size == 0.
            #[cfg(test)]
            let skip_pad = ctx
                .faults
                .as_mut()
                .map(|f| f.should_skip_symlink_pad())
                .unwrap_or(false);
            #[cfg(not(test))]
            let skip_pad = false;

            if !skip_pad {
                let total_size = inode_and_xattr_size + inline_size;
                // Does [current_pos, current_pos+total_size) cross a block boundary?
                // block_offset tells us how far into the current block we are;
                // if adding total_size exceeds block_size, we spill into the next block.
                if block_offset(current_pos) + total_size > block_size {
                    // Align inode start to the next block boundary so the inode
                    // doesn't straddle a block (prevents EUCLEAN on old kernels).
                    // block_size (4096) is divisible by 32 (EROFS slot size),
                    // so slot alignment is preserved after this padding.
                    // None means current_pos is already block-aligned; no padding needed.
                    if let Some(pad_size) = bytes_to_block_boundary(current_pos) {
                        output.write_zeros(pad_size as usize);
                    }
                }
            }
        } else {
            // Non-symlink branch (dirs, inline files): pad the *tail* to fit
            // within the block that inline_start lands in.
            // Matches C: block_remainder < inline_size, pad = block_remainder
            // rounded up to the next 32-byte slot boundary.
            let inline_start = current_pos
                .checked_add(inode_and_xattr_size)
                .expect("image position + inode header size cannot overflow u64");
            // If inline_start is block-aligned, block_remainder would be BLOCK_SIZE which
            // always exceeds inline_size (< BLOCK_SIZE), so no padding — None is correct.
            if let Some(block_remainder) = bytes_to_block_boundary(inline_start)
                && block_remainder < inline_size
            {
                let pad_size = (block_remainder.div_ceil(INODE_SLOT_SIZE as u64)
                    * INODE_SLOT_SIZE as u64) as usize;
                output.write_zeros(pad_size);
            }
        }
    }

    /// Handle inline tail padding for V2 format (origin/main algorithm).
    fn pad_inline_tail_v2(&self, output: &mut impl Output, inode_and_xattr_size: u64, size: u64) {
        let block_size = u64::from(format::BLOCK_SIZE);
        let inline_start: u64 = output.len().try_into().unwrap();
        let inline_start = inline_start
            .checked_add(inode_and_xattr_size)
            .expect("image position + inode header size cannot overflow u64");
        // Restore origin/main logic: end_of_metadata is the last byte of the metadata,
        // inline_end is the last byte of the inline data.  If they land in different
        // blocks we must pad so the inline data starts at a fresh block boundary.
        let end_of_metadata = inline_start - 1;
        let inline_end = inline_start + (size % block_size);
        if end_of_metadata / block_size != inline_end / block_size {
            let pad_size = (block_size - end_of_metadata % block_size) as usize;
            output.write_zeros(pad_size);
            output.pad(INODE_SLOT_SIZE);
        }
    }

    fn write_inode(&self, output: &mut impl Output, idx: usize, ctx: &mut WriteContext) {
        let version = ctx.version;
        let min_mtime = ctx.min_mtime;
        let meta = match &self.content {
            InodeContent::Directory(dir) => dir.inode_meta(output.get_block_start(idx)),
            InodeContent::Leaf(leaf) => leaf.inode_meta(version, output.get_block_start(idx)),
        };
        let InodeMeta {
            layout,
            i_u: u,
            size,
            nlink,
        } = meta;

        let xattr_size = self.xattrs.byte_size(version);

        // V1: compact inodes when possible; V2: always extended
        let use_compact =
            version.epoch() == FormatEpoch::Epoch1 && self.fits_in_compact(min_mtime, size, nlink);

        let inode_header_size = if use_compact {
            size_of::<format::CompactInodeHeader>()
        } else {
            size_of::<format::ExtendedInodeHeader>()
        };

        // We need to make sure the inline part doesn't overlap a block boundary
        output.pad(INODE_SLOT_SIZE);

        // Epoch1 promoted symlinks: target was moved to a data block but we
        // still need to pad the inode start to a block boundary, matching C
        // compute_erofs_inode_padding_for_tail which uses the original
        // (pre-promotion) total_size for the block-crossing check.
        let is_promoted_symlink = version.epoch() == FormatEpoch::Epoch1
            && matches!(self.file_type(), format::FileType::Symlink)
            && matches!(layout, format::DataLayout::FlatPlain);
        if is_promoted_symlink {
            let block_size = u64::from(format::BLOCK_SIZE);
            let current_pos: u64 = output.len().try_into().unwrap();
            let original_total_size = (inode_header_size + xattr_size) as u64 + size;
            let pos_block = current_pos / block_size;
            let end_block = (current_pos + original_total_size - 1) / block_size;
            if pos_block != end_block
                && let Some(pad_size) = bytes_to_block_boundary(current_pos)
            {
                output.write_zeros(pad_size as usize);
            }
        }

        // Promoted ChunkBased: chunk indices moved to data block, pad inode
        // start to block boundary (matching C compute_erofs_inode_padding_for_tail).
        let is_promoted_chunk_based = version.epoch() == FormatEpoch::Epoch1
            && matches!(layout, format::DataLayout::ChunkBased)
            && self.chunk_inline_tail_size() == 0
            && matches!(&self.content, InodeContent::Leaf(leaf) if leaf.n_data_blocks > 0);
        if is_promoted_chunk_based {
            let current_pos: u64 = output.len().try_into().unwrap();
            if let Some(pad_size) = bytes_to_block_boundary(current_pos) {
                output.write_zeros(pad_size as usize);
            }
        }

        // ChunkBased inodes in Epoch1 have inline chunk index data that
        // needs the same non-symlink tail padding as FlatInline data.
        if version.epoch() == FormatEpoch::Epoch1
            && matches!(layout, format::DataLayout::ChunkBased)
            && self.chunk_inline_tail_size() > 0
        {
            let current_pos: u64 = output.len().try_into().unwrap();
            let non_tail_size = (inode_header_size + xattr_size) as u64;
            let tail_size = self.chunk_inline_tail_size() as u64;
            let inline_start = current_pos + non_tail_size;
            if let Some(block_remainder) = bytes_to_block_boundary(inline_start)
                && block_remainder < tail_size
            {
                let pad_size = (block_remainder.div_ceil(INODE_SLOT_SIZE as u64)
                    * INODE_SLOT_SIZE as u64) as usize;
                output.write_zeros(pad_size);
            }
        }

        if matches!(layout, format::DataLayout::FlatInline) {
            let inode_and_xattr_size: u64 = (inode_header_size + xattr_size).try_into().unwrap();

            match version.epoch() {
                FormatEpoch::Epoch1 => {
                    self.pad_inline_tail_v1(output, inode_and_xattr_size, size, ctx);
                }
                FormatEpoch::Epoch2 => {
                    self.pad_inline_tail_v2(output, inode_and_xattr_size, size);
                }
            }
        }

        let xattr_icount: u16 = match xattr_size {
            0 => 0,
            n => {
                let word_count = n
                    .checked_sub(INODE_XATTR_HEADER_SIZE)
                    .expect("non-empty xattr block must be >= header size")
                    / XATTR_WORD_SIZE;
                (1 + word_count) as u16
            }
        };

        output.note_inode();

        if use_compact {
            let format = format::InodeLayout::Compact | layout;

            // V1: use sequential ino
            let ino = idx as u32;

            output.write_struct(format::CompactInodeHeader {
                format,
                xattr_icount: xattr_icount.into(),
                mode: self.inode_mode(),
                nlink: (nlink as u16).into(),
                size: (size as u32).into(),
                reserved: 0.into(),
                u: u.into(),
                ino: ino.into(),
                uid: (self.stat.st_uid as u16).into(),
                gid: (self.stat.st_gid as u16).into(),
                reserved2: [0; 4],
            });
        } else {
            let format = format::InodeLayout::Extended | layout;

            // V1 uses the BFS index as i_ino (matching C mkcomposefs behaviour).
            // V2 uses the NID (byte offset / INODE_SLOT_SIZE) for 32-bit stat compatibility.
            let ino = match version.epoch() {
                FormatEpoch::Epoch1 => idx as u32,
                FormatEpoch::Epoch2 => (output.len() / INODE_SLOT_SIZE) as u32,
            };

            // Epoch2 does not store sub-second mtime precision (mtime_nsec=0).
            // Epoch1 (V0/V1) preserves full nanosecond precision.
            let mtime_nsec: u32 = match version.epoch() {
                FormatEpoch::Epoch1 => self.stat.st_mtim_nsec,
                FormatEpoch::Epoch2 => 0,
            };
            output.write_struct(format::ExtendedInodeHeader {
                format,
                xattr_icount: xattr_icount.into(),
                mode: self.inode_mode(),
                size: size.into(),
                u: u.into(),
                ino: ino.into(),
                uid: self.stat.st_uid.into(),
                gid: self.stat.st_gid.into(),
                mtime: (self.stat.st_mtim_sec as u64).into(),
                mtime_nsec: mtime_nsec.into(),
                nlink: (nlink as u32).into(),
                ..Default::default()
            });
        }

        self.xattrs.write(output, version);

        match &self.content {
            InodeContent::Directory(dir) => dir.write_inline(output),
            InodeContent::Leaf(leaf) => leaf.write_inline(output),
        };

        output.pad(INODE_SLOT_SIZE);
    }

    fn write_blocks(&self, output: &mut impl Output) {
        match &self.content {
            InodeContent::Directory(dir) => dir.write_blocks(output),
            InodeContent::Leaf(leaf) => leaf.write_data_blocks(output),
        }
    }
}

struct InodeCollector<'a, ObjectID: FsVerityHashValue> {
    inodes: Vec<Inode<'a, ObjectID>>,
    hardlinks: HashMap<LeafId, InodeIdx>,
    fs: &'a tree::FileSystem<ObjectID>,
    nlink_map: Vec<u32>,
    version: format::FormatVersion,
}

impl<'a, ObjectID: FsVerityHashValue> InodeCollector<'a, ObjectID> {
    fn push_inode(
        &mut self,
        stat: &'a tree::Stat,
        content: InodeContent<'a, ObjectID>,
    ) -> InodeIdx {
        let mut xattrs = InodeXAttrs::default();

        // We need to record extra xattrs for some files.  These come first.
        if let InodeContent::Leaf(Leaf {
            content: tree::LeafContent::Regular(tree::RegularFile::External(id, ..)),
            ..
        }) = content
        {
            let metacopy = OverlayMetacopy::new(id);
            xattrs.add(
                format::XATTR_OVERLAY_METACOPY,
                metacopy.as_bytes(),
                self.version,
            );
            let redirect = format!("/{}", id.to_object_pathname());
            xattrs.add(
                format::XATTR_OVERLAY_REDIRECT,
                redirect.as_bytes(),
                self.version,
            );
        } else if let InodeContent::Leaf(Leaf {
            content: tree::LeafContent::Regular(tree::RegularFile::ExternalNoVerity(id, ..)),
            ..
        }) = content
        {
            xattrs.add(format::XATTR_OVERLAY_METACOPY, b"", self.version);
            let redirect = format!("/{}", id.to_object_pathname());
            xattrs.add(
                format::XATTR_OVERLAY_REDIRECT,
                redirect.as_bytes(),
                self.version,
            );
        } else if let InodeContent::Leaf(Leaf {
            content: tree::LeafContent::Regular(tree::RegularFile::Sparse(..)),
            ..
        }) = content
        {
            xattrs.add(format::XATTR_OVERLAY_METACOPY, b"", self.version);
        }

        // Add the normal xattrs.  They're already listed in sorted order.
        for (name, value) in stat.xattrs.iter() {
            let name = name.as_bytes();

            if let Some(escapee) = name.strip_prefix(format::XATTR_OVERLAY_PREFIX) {
                let escaped = [format::XATTR_OVERLAY_ESCAPED_PREFIX, escapee].concat();
                xattrs.add(&escaped, value, self.version);
            } else {
                xattrs.add(name, value, self.version);
            }
        }

        // Allocate an inode for ourselves.  At first we write all xattrs as local.  Later (after
        // we've determined which xattrs ought to be shared) we'll come and move some of them over.
        let inode = self.inodes.len();
        self.inodes.push(Inode {
            stat,
            xattrs,
            content,
            escaped_whiteout: false,
        });
        inode
    }

    fn collect_leaf(&mut self, leaf_id: LeafId) -> InodeIdx {
        let nlink = self.nlink_map[leaf_id.0] as usize;

        if nlink > 1
            && let Some(inode) = self.hardlinks.get(&leaf_id)
        {
            return *inode;
        }

        let leaf = self.fs.leaf(leaf_id);

        // Hardlinked whiteouts are semantically invalid: a whiteout represents the
        // absence of a file in an overlay, so having nlink > 1 is meaningless.
        // ValidatedFileSystem guarantees this invariant was checked at construction time.
        debug_assert!(
            !(matches!(leaf.content, tree::LeafContent::CharacterDevice(0)) && nlink > 1),
            "ValidatedFileSystem guarantees whiteout nlink == 1"
        );
        let (n_data_blocks, inline_tail_size) = if self.version.epoch() == FormatEpoch::Epoch1 {
            match &leaf.content {
                tree::LeafContent::Regular(tree::RegularFile::Inline(data)) => {
                    if data.is_empty() {
                        (0, 0)
                    } else {
                        let block_size = format::BLOCK_SIZE as usize;
                        let mut n_blocks = data.len() / block_size;
                        let mut tail = data.len() % block_size;
                        if tail > block_size / 2 {
                            n_blocks += 1;
                            tail = 0;
                        }
                        (n_blocks as u32, tail)
                    }
                }
                tree::LeafContent::Symlink(target) => {
                    // Initial: no data blocks, tail = target length.
                    // May be promoted to data block later by fixup_symlink_data_blocks
                    // when inode_header + xattr_size + target_len >= BLOCK_SIZE.
                    (0, target.len())
                }
                tree::LeafContent::Regular(
                    tree::RegularFile::External(.., size)
                    | tree::RegularFile::ExternalNoVerity(.., size)
                    | tree::RegularFile::Sparse(size),
                ) if *size > 0 => {
                    let chunk_count = compute_chunk_count(*size);
                    (0, chunk_count as usize * 4)
                }
                _ => (0, 0),
            }
        } else {
            match &leaf.content {
                tree::LeafContent::Regular(tree::RegularFile::Inline(data)) => (0, data.len()),
                tree::LeafContent::Regular(tree::RegularFile::External(..)) => {
                    (0, 4) // single null chunk index
                }
                _ => (0, 0),
            }
        };
        let inode = self.push_inode(
            &leaf.stat,
            InodeContent::Leaf(Leaf {
                content: &leaf.content,
                nlink,
                n_data_blocks,
                inline_tail_size,
            }),
        );

        if nlink > 1 {
            self.hardlinks.insert(leaf_id, inode);
        }

        inode
    }

    /// Collect inodes using depth-first traversal (V2 / origin/main behavior).
    fn collect_dir(&mut self, dir: &'a tree::Directory<ObjectID>, parent: InodeIdx) -> InodeIdx {
        // The root inode number needs to fit in a u16.  That more or less compels us to write the
        // directory inode before the inode of the children of the directory.  Reserve a slot.
        let me = self.push_inode(&dir.stat, InodeContent::Directory(Directory::default()));

        let mut entries = vec![
            DirEnt {
                name: b".",
                inode: InodeRef::Known(me),
                file_type: format::FileType::Directory,
            },
            DirEnt {
                name: b"..",
                inode: InodeRef::Known(parent),
                file_type: format::FileType::Directory,
            },
        ];

        for (name, inode) in dir.sorted_entries() {
            let child = match inode {
                tree::Inode::Directory(dir) => self.collect_dir(dir, me),
                tree::Inode::Leaf(leaf_id, _) => self.collect_leaf(*leaf_id),
            };
            entries.push(DirEnt {
                name: name.as_bytes(),
                inode: InodeRef::Known(child),
                file_type: self.inodes[child].file_type(),
            });
        }

        entries.sort_unstable_by_key(|e| e.name);

        // Now that we know the actual content, we can write it to our reserved slot
        self.inodes[me].content = InodeContent::Directory(Directory::from_entries(entries));
        me
    }

    /// Returns true if this leaf entry is an overlay whiteout stub generated internally
    /// by `add_overlay_whiteouts()`, as opposed to a user-provided whiteout. These stubs
    /// must NOT be escaped during V1 whiteout processing.
    fn is_overlay_whiteout_stub(
        &self,
        name: &[u8],
        leaf_id: LeafId,
        me: InodeIdx,
        root_inode: InodeIdx,
    ) -> bool {
        let root_stat = &self.fs.root.stat;
        let leaf_stat = &self.fs.leaf(leaf_id).stat;
        let selinux_key = std::ffi::OsStr::new("security.selinux");
        let expected_xattrs = if root_stat.xattrs.contains_key(selinux_key) {
            1
        } else {
            0
        };
        let has_correct_xattrs = leaf_stat.xattrs.len() == expected_xattrs
            && (expected_xattrs == 0
                || leaf_stat.xattrs.get(selinux_key) == root_stat.xattrs.get(selinux_key));

        me == root_inode
            && name.len() == 2
            && name
                .iter()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
            && leaf_stat.st_mode == 0o644
            && leaf_stat.st_uid == root_stat.st_uid
            && leaf_stat.st_gid == root_stat.st_gid
            && leaf_stat.st_mtim_sec == root_stat.st_mtim_sec
            && leaf_stat.st_mtim_nsec == root_stat.st_mtim_nsec
            && has_correct_xattrs
    }

    /// Returns true if a leaf content is a V1 overlay whiteout (char device, rdev=0).
    fn is_v1_whiteout(content: &tree::LeafContent<ObjectID>) -> bool {
        matches!(content, tree::LeafContent::CharacterDevice(0))
    }

    /// Collect all inodes using queue-based breadth-first traversal (V1).
    ///
    /// This algorithm matches the C mkcomposefs `lcfs_compute_tree()` function which uses
    /// a linked-list queue to process directories. All nodes at depth N are assigned inode
    /// numbers before any nodes at depth N+1.
    ///
    /// For V1, char device entries with rdev=0 (overlay whiteouts) are escaped to regular
    /// files matching C mkcomposefs v1.0.8 `add_overlayfs_xattrs()` behavior:
    ///   - Child entry: converted to regular file + gets `trusted.overlay.overlay.whiteout=""`
    ///     and `user.overlay.whiteout=""` xattrs.
    ///   - Parent directory: gets `trusted.overlay.overlay.whiteouts=""`,
    ///     `user.overlay.whiteouts=""`, `trusted.overlay.overlay.opaque=x`,
    ///     `user.overlay.opaque=x` xattrs (added at most once per directory).
    fn collect_tree(&mut self, root: &'a tree::Directory<ObjectID>) {
        use std::collections::VecDeque;

        // Pre-pass: for each multi-link leaf, find which directory holds the canonical
        // (first DFS sorted-order) occurrence.
        //
        // In C mkcomposefs, when a dumpfile is parsed, the first occurrence of each
        // inode (same content / nlink target) is the "original" and subsequent occurrences
        // are "hardlinks" (with link_to pointer). During BFS, hardlinks are SKIPPED — only
        // originals get inode numbers. Hardlink directory entries use the original's nid.
        //
        // The dumpfile is written in DFS sorted order (see write_dumpfile). So the canonical
        // occurrence is whichever path appears first in that DFS traversal.
        //
        // We replicate this: when BFS encounters a non-canonical occurrence of a multi-link
        // leaf (its canonical directory doesn't match the current directory), we defer the
        // nid assignment until the canonical occurrence is processed.
        //
        // KEY: we record the DIRECTORY POINTER of the canonical occurrence, not just the
        // leaf_id, because two occurrences of the same leaf share the same leaf_id — we
        // need the directory pointer to distinguish canonical from non-canonical at BFS time.
        let canonical_dirs = Self::find_canonical_dirs(root, &self.nlink_map);

        let root_inode = self.push_inode(&root.stat, InodeContent::Directory(Directory::default()));
        let mut queue: VecDeque<(&'a tree::Directory<ObjectID>, InodeIdx, InodeIdx)> =
            VecDeque::new();
        queue.push_back((root, root_inode, root_inode));

        // dir_entries: accumulates (me, parent, entries) for each directory processed in BFS order.
        // Leaf entries whose canonical occurrence hasn't been BFS-processed yet are stored as
        // InodeRef::Deferred(leaf_id) and resolved in a single post-BFS pass once all canonical
        // inodes have been assigned.
        let mut dir_entries: Vec<(InodeIdx, InodeIdx, Vec<DirEnt<'a>>)> = vec![]; // (me, parent, entries)

        while let Some((dir, parent, me)) = queue.pop_front() {
            let mut entries = vec![
                DirEnt {
                    name: b".",
                    inode: InodeRef::Known(me),
                    file_type: format::FileType::Directory,
                },
                DirEnt {
                    name: b"..",
                    inode: InodeRef::Known(parent),
                    file_type: format::FileType::Directory,
                },
            ];
            let mut dir_has_whiteout = false;

            for (name, inode) in dir.sorted_entries() {
                match inode {
                    tree::Inode::Directory(subdir) => {
                        let child = self.push_inode(
                            &subdir.stat,
                            InodeContent::Directory(Directory::default()),
                        );
                        queue.push_back((subdir, me, child));
                        entries.push(DirEnt {
                            name: name.as_bytes(),
                            inode: InodeRef::Known(child),
                            file_type: format::FileType::Directory,
                        });
                    }
                    tree::Inode::Leaf(leaf_id, _) => {
                        // V1 whiteout escaping: char device with rdev=0 → regular file.
                        // Matches C mkcomposefs v1.0.8 `rewrite_tree_node_for_erofs()`, which
                        // escapes user-provided char devices.
                        //
                        // IMPORTANT: the 256 stubs added by add_overlay_whiteouts() are NOT
                        // escaped in C — they are added AFTER `rewrite_tree_node_for_erofs()`
                        // so they never go through escaping. We skip them by detecting root-level
                        // 2-char hex entries (the names used by add_overlay_whiteouts()) THAT ALSO
                        // exactly match the metadata applied by add_overlay_whiteouts(). This
                        // correctly distinguishes them from user-provided whiteouts that happen
                        // to have a 2-char hex name.
                        let name_bytes = name.as_bytes();
                        let is_stub =
                            self.is_overlay_whiteout_stub(name_bytes, *leaf_id, me, root_inode);

                        // Determine if this occurrence is canonical (first in DFS order).
                        //
                        // For multi-link leaves (nlink > 1), the canonical occurrence is the
                        // one in the directory recorded by find_canonical_dirs(). We compare
                        // the current directory pointer to identify it precisely.
                        //
                        // For single-link leaves (nlink = 1), there is only one occurrence,
                        // so it is always canonical (no entry in canonical_dirs).
                        let nlink = self.nlink_map[leaf_id.0];
                        let is_canonical = if nlink > 1 {
                            // Multi-link: canonical iff this is the recorded canonical directory.
                            // We use pointer identity (std::ptr::eq) to match the current
                            // directory reference against the one recorded during the DFS
                            // pre-pass.  The pointers are stable borrows from the tree, which
                            // outlives this entire function.
                            canonical_dirs
                                .get(leaf_id)
                                .is_some_and(|&p| std::ptr::eq(p, dir))
                        } else {
                            // Single-link: always canonical
                            true
                        };

                        let child_ref = if is_canonical {
                            // Canonical occurrence: create nid now.
                            InodeRef::Known(self.collect_leaf(*leaf_id))
                        } else if let Some(&nid) = self.hardlinks.get(leaf_id) {
                            // Non-canonical, and the canonical has already been processed.
                            InodeRef::Known(nid)
                        } else {
                            // Non-canonical, and canonical hasn't been assigned a nid yet
                            // (canonical is in a deeper directory, not yet BFS-processed).
                            // Store as Deferred; resolved in the post-BFS pass.
                            InodeRef::Deferred(*leaf_id)
                        };

                        // Apply whiteout escaping on the first canonical occurrence only.
                        //
                        // `is_canonical` is true for any entry whose directory pointer matches
                        // the canonical directory, so if a whiteout leaf and its hardlink both
                        // live in the same directory, both appear "canonical" by that check.
                        // We guard with `!escaped_whiteout` to ensure the xattrs are added
                        // exactly once — on the very first encounter of the inode.
                        if is_canonical
                            && matches!(child_ref, InodeRef::Known(_))
                            && self.version.epoch() == FormatEpoch::Epoch1
                            && !is_stub
                            && Self::is_v1_whiteout(&self.fs.leaf(*leaf_id).content)
                        {
                            let InodeRef::Known(child) = child_ref else {
                                unreachable!()
                            };
                            if !self.inodes[child].escaped_whiteout {
                                self.inodes[child].escaped_whiteout = true;
                                // Add per-entry whiteout xattrs (already-escaped names):
                                // C adds OVERLAY_XATTR_ESCAPED_WHITEOUT and OVERLAY_XATTR_USERXATTR_WHITEOUT.
                                self.inodes[child].xattrs.add(
                                    format::XATTR_OVERLAY_WHITEOUT,
                                    b"",
                                    self.version,
                                );
                                self.inodes[child].xattrs.add(
                                    format::XATTR_USERXATTR_WHITEOUT,
                                    b"",
                                    self.version,
                                );
                                dir_has_whiteout = true;
                            }
                        }

                        // file_type for the dir entry: for Deferred entries, use a placeholder;
                        // it will be corrected in the post-BFS resolution pass.
                        let file_type = if let InodeRef::Known(child) = child_ref {
                            // file_type() already returns RegularFile when escaped_whiteout=true
                            self.inodes[child].file_type()
                        } else {
                            // Deferred; file_type will be updated in the resolution pass
                            format::FileType::RegularFile
                        };

                        entries.push(DirEnt {
                            name: name.as_bytes(),
                            inode: child_ref,
                            file_type,
                        });
                    }
                }
            }

            // Epoch1: if this directory had whiteout children, add parent xattrs.
            // C adds WHITEOUTS + USERXATTR_WHITEOUTS for all versions, and
            // OPAQUE + USERXATTR_OPAQUE only for version >= 1.
            if self.version.epoch() == FormatEpoch::Epoch1 && dir_has_whiteout {
                self.inodes[me]
                    .xattrs
                    .add(format::XATTR_OVERLAY_WHITEOUTS, b"", self.version);
                self.inodes[me]
                    .xattrs
                    .add(format::XATTR_USERXATTR_WHITEOUTS, b"", self.version);
                if self.version == format::FormatVersion::V1 {
                    self.inodes[me]
                        .xattrs
                        .add(format::XATTR_OVERLAY_OPAQUE, b"x", self.version);
                    self.inodes[me]
                        .xattrs
                        .add(format::XATTR_USERXATTR_OPAQUE, b"x", self.version);
                }
            }

            entries.sort_unstable_by_key(|e| e.name);

            dir_entries.push((me, parent, entries));
        }

        // Post-BFS: resolve all Deferred entries.
        // At this point all canonical leaves have been assigned nids and are in self.hardlinks.
        for (_me, _parent, entries) in &mut dir_entries {
            for entry in entries.iter_mut() {
                if let InodeRef::Deferred(leaf_id) = entry.inode {
                    let nid = *self
                        .hardlinks
                        .get(&leaf_id)
                        .expect("canonical leaf must have been assigned a nid during BFS");
                    entry.inode = InodeRef::Known(nid);
                    entry.file_type = self.inodes[nid].file_type();
                }
            }
        }

        // Build directory content for each directory inode.
        for (me, _parent, entries) in dir_entries {
            self.inodes[me].content = InodeContent::Directory(Directory::from_entries(entries));
        }
    }

    /// DFS pre-pass: find which directory contains the canonical occurrence of each
    /// multi-link leaf (first encounter in DFS sorted order).
    ///
    /// C mkcomposefs parses dumpfiles in DFS sorted order. The first occurrence of each
    /// leaf (by `LeafId`) is the "original"; subsequent occurrences are "hardlinks".
    /// Only originals get inode numbers in BFS; hardlinks reuse the original's nid.
    ///
    /// The dumpfile writer (`write_dumpfile`) uses DFS sorted traversal, so we replicate
    /// the same traversal here to determine canonical occurrences.
    ///
    /// Note: we cannot simplify to "first BFS encounter wins" because DFS and BFS visit
    /// directories at different depths in different order (e.g. DFS visits `/a/deep/`
    /// before `/b/`, while BFS visits `/b/` first). Changing the canonical ordering
    /// would break binary compatibility with C mkcomposefs.
    ///
    /// Returns a `HashMap<LeafId, *const Directory>` mapping each multi-link leaf to the
    /// directory pointer where its canonical (first DFS) occurrence lives.
    /// Single-link leaves are NOT in the map (they're trivially canonical anywhere).
    ///
    /// We use raw pointers for directory identity comparison (`std::ptr::eq`) rather
    /// than dereferencing.  The pointers are stable `&'a` borrows from the tree which
    /// outlives the entire `collect_tree` call.
    fn find_canonical_dirs(
        root: &'a tree::Directory<ObjectID>,
        nlink_map: &[u32],
    ) -> HashMap<LeafId, *const tree::Directory<ObjectID>> {
        let mut seen: HashSet<LeafId> = HashSet::new();
        let mut canonical_dirs: HashMap<LeafId, *const tree::Directory<ObjectID>> = HashMap::new();
        Self::dfs_find_canonical(root, nlink_map, &mut seen, &mut canonical_dirs);
        canonical_dirs
    }

    fn dfs_find_canonical(
        dir: &'a tree::Directory<ObjectID>,
        nlink_map: &[u32],
        seen: &mut HashSet<LeafId>,
        canonical_dirs: &mut HashMap<LeafId, *const tree::Directory<ObjectID>>,
    ) {
        let dir_ptr: *const tree::Directory<ObjectID> = dir;
        for (_, inode) in dir.sorted_entries() {
            match inode {
                tree::Inode::Directory(subdir) => {
                    Self::dfs_find_canonical(subdir, nlink_map, seen, canonical_dirs);
                }
                tree::Inode::Leaf(leaf_id, _) => {
                    if nlink_map[leaf_id.0] > 1 && seen.insert(*leaf_id) {
                        // First DFS encounter → canonical occurrence is in this directory.
                        canonical_dirs.insert(*leaf_id, dir_ptr);
                        // Second+ encounter → non-canonical (hardlink), dir not recorded
                    }
                    // Single-link leaves are always canonical; no need to record them
                }
            }
        }
    }

    pub fn collect(
        fs: &'a tree::FileSystem<ObjectID>,
        version: format::FormatVersion,
    ) -> Vec<Inode<'a, ObjectID>> {
        let mut this = Self {
            inodes: vec![],
            hardlinks: HashMap::new(),
            fs,
            nlink_map: fs.nlinks(),
            version,
        };

        match version.epoch() {
            FormatEpoch::Epoch1 => this.collect_tree(&fs.root),
            FormatEpoch::Epoch2 => {
                let root_inode = this.collect_dir(&fs.root, 0);
                assert_eq!(root_inode, 0);
            }
        }

        this.inodes
    }
}

/// Takes a list of inodes where each inode contains only local xattr values, determines which
/// xattrs (key, value) pairs appear more than once, and shares them.
///
/// For V1: sorts locals by full key, reverses shared table, uses InodesEnd-relative xattr offsets.
/// For V2: uses natural BTreeMap order (derived Ord), ascending shared table.
fn share_xattrs(
    inodes: &mut [Inode<impl FsVerityHashValue>],
    version: format::FormatVersion,
) -> Vec<XAttr> {
    let mut xattrs: BTreeMap<XAttr, usize> = BTreeMap::new();

    // V1: sort local xattrs by full key to match C behavior
    // V2: don't sort (insertion order is fine, BTreeMap handles shared ordering)
    if version.epoch() == FormatEpoch::Epoch1 {
        for inode in inodes.iter_mut() {
            inode.xattrs.local.sort_by(|a, b| a.cmp_by_full_key(b));
        }
    }

    // Collect all xattrs from the inodes
    for inode in inodes.iter() {
        for attr in &inode.xattrs.local {
            if let Some(count) = xattrs.get_mut(attr) {
                *count += 1;
            } else {
                xattrs.insert(attr.clone(), 1);
            }
        }
    }

    // Share only xattrs with more than one user
    xattrs.retain(|_k, v| *v > 1);

    let (xattrs, shared): (BTreeMap<XAttr, usize>, Vec<XAttr>) = match version.epoch() {
        FormatEpoch::Epoch1 => {
            // C mkcomposefs sorts shared xattrs by full key string (strcmp), then writes
            // them in DESCENDING order in the shared xattr block.  Our BTreeMap is ordered
            // by (prefix_index, suffix, value) which differs from strcmp order when prefix
            // indices don't sort the same way as prefix strings (e.g. "security."=6 sorts
            // numerically after "trusted."=4, but 'security.' < 'trusted.' lexicographically).
            // Collect into a Vec, sort by full key ascending, then reverse = descending.
            let mut sorted: Vec<_> = xattrs.into_iter().collect();
            sorted.sort_by(|(a, _), (b, _)| a.cmp_by_full_key(b));
            let n_shared = sorted.len();
            // Assign indices in descending order: first entry on disk gets the highest ref.
            // After reversal, sorted[0] (ascending-smallest) ends up last on disk.
            // We iterate ascending-sorted and assign index = n-1-i so that the entry
            // written LAST (smallest key in ascending order) gets the SMALLEST index.
            // Reconstruct a map for the lookup phase below.
            let xattrs_map: BTreeMap<XAttr, usize> = sorted
                .iter()
                .enumerate()
                .map(|(i, (k, _))| (k.clone(), n_shared - 1 - i))
                .collect();

            // Return in descending full-key order (last in ascending = first written)
            let mut out = sorted;
            out.reverse();
            let shared_vec = out.into_iter().map(|(k, _)| k).collect();
            (xattrs_map, shared_vec)
        }
        FormatEpoch::Epoch2 => {
            // Ascending order: sequential index assignment
            for (idx, value) in xattrs.values_mut().enumerate() {
                *value = idx;
            }

            // Return in ascending order (natural BTreeMap order)
            let shared_vec = xattrs.keys().cloned().collect();
            (xattrs, shared_vec)
        }
    };

    // Visit each inode and promote xattrs that are in the shared table.
    // This is the same for both V1 and V2: remove from local, push index to shared.
    for inode in inodes.iter_mut() {
        inode.xattrs.local.retain(|attr| {
            if let Some(idx) = xattrs.get(attr) {
                inode.xattrs.shared.push(*idx);
                false
            } else {
                true
            }
        });
    }

    shared
}

fn write_erofs(
    output: &mut impl Output,
    inodes: &[Inode<impl FsVerityHashValue>],
    xattrs: &[XAttr],
    ctx: &mut WriteContext,
) {
    let version = ctx.version;
    let min_mtime = ctx.min_mtime;
    let header_flags = ctx.header_flags;
    let composefs_version: u32 = ctx.composefs_version;
    // Epoch1 (V0/V1) uses minimum mtime for reproducibility; Epoch2 (V2) uses 0.
    let (build_time, build_time_nsec) = match version.epoch() {
        FormatEpoch::Epoch1 => min_mtime,
        FormatEpoch::Epoch2 => (0, 0),
    };

    // Write composefs header (pads to 1024 bytes internally)
    output.write_composefs_header(format::ComposefsHeader {
        magic: format::COMPOSEFS_MAGIC,
        version: format::VERSION,
        flags: header_flags.into(),
        composefs_version: composefs_version.into(),
        ..Default::default()
    });

    // Epoch1 sets xattr_blkaddr; Epoch2 leaves it as 0.
    let xattr_blkaddr = match version.epoch() {
        FormatEpoch::Epoch1 => output.get_xattr_blkaddr(),
        FormatEpoch::Epoch2 => 0,
    };
    output.write_superblock(format::Superblock {
        magic: format::MAGIC_V1,
        blkszbits: format::BLOCK_BITS,
        feature_compat: (format::FEATURE_COMPAT_MTIME | format::FEATURE_COMPAT_XATTR_FILTER).into(),
        root_nid: (output.get_nid(0) as u16).into(),
        inos: (inodes.len() as u64).into(),
        blocks: output.get_block_count().into(),
        build_time: build_time.into(),
        build_time_nsec: build_time_nsec.into(),
        xattr_blkaddr: xattr_blkaddr.into(),
        ..Default::default()
    });

    // Write inode table
    for (idx, inode) in inodes.iter().enumerate() {
        // The inode may add padding to itself, so it notes its own offset
        inode.write_inode(output, idx, ctx);
    }

    // Mark end of inode table (slot-aligned)
    output.pad(INODE_SLOT_SIZE);
    output.note_inodes_end();

    // Write shared xattr table
    for xattr in xattrs {
        output.note_xattr();
        xattr.write(output);
    }

    // Write blocks from inodes that have them
    output.pad(4096);
    for inode in inodes.iter() {
        output.note_block();
        inode.write_blocks(output);
    }

    // That's it
    output.note_end();
}

/// Offsets recorded during the first pass and consumed by the second pass.
/// Only contains values that are actually retrieved; singletons that are
/// write-only (header, superblock) are tracked as bools in `FirstPass`.
#[derive(Default)]
struct Layout {
    /// Byte offset of each inode, indexed by InodeIdx.
    inodes: Vec<NonZeroUsize>,
    /// Byte offset immediately after the last inode (slot-aligned).
    inodes_end: Option<NonZeroUsize>,
    /// Byte offset of each shared xattr entry, indexed sequentially.
    xattrs: Vec<NonZeroUsize>,
    /// Byte offset of each inode's block data region, indexed by InodeIdx.
    blocks: Vec<NonZeroUsize>,
    /// Total byte length of the image.
    end: Option<NonZeroUsize>,
}

#[derive(Default)]
struct FirstPass {
    offset: usize,
    layout: Layout,
    header_emitted: bool,
    superblock_emitted: bool,
}

struct SecondPass {
    output: Vec<u8>,
    layout: Layout,
}

impl Output for FirstPass {
    fn note_header_emitted(&mut self) {
        assert!(!self.header_emitted, "composefs header written twice");
        self.header_emitted = true;
    }
    fn note_superblock_emitted(&mut self) {
        assert!(!self.superblock_emitted, "superblock written twice");
        self.superblock_emitted = true;
    }
    fn note_inode(&mut self) {
        self.layout
            .inodes
            .push(NonZeroUsize::new(self.offset).expect("inode recorded at offset 0"));
    }
    fn note_inodes_end(&mut self) {
        assert!(
            self.layout.inodes_end.is_none(),
            "inodes_end recorded twice"
        );
        self.layout.inodes_end = NonZeroUsize::new(self.offset);
    }
    fn note_xattr(&mut self) {
        self.layout
            .xattrs
            .push(NonZeroUsize::new(self.offset).expect("xattr recorded at offset 0"));
    }
    fn note_block(&mut self) {
        debug_assert_eq!(
            self.offset % format::BLOCK_SIZE as usize,
            0,
            "block data must start at a block-aligned offset"
        );
        self.layout
            .blocks
            .push(NonZeroUsize::new(self.offset).expect("block recorded at offset 0"));
    }
    fn note_end(&mut self) {
        assert!(self.layout.end.is_none(), "end recorded twice");
        self.layout.end = NonZeroUsize::new(self.offset);
    }

    fn get_inode_offset(&self, _idx: usize) -> Option<NonZeroUsize> {
        None
    }
    fn get_inodes_end(&self) -> Option<NonZeroUsize> {
        None
    }
    fn get_xattr_offset(&self, _idx: usize) -> Option<NonZeroUsize> {
        None
    }
    fn get_block_offset(&self, _idx: usize) -> Option<NonZeroUsize> {
        None
    }
    fn get_end(&self) -> Option<NonZeroUsize> {
        None
    }

    fn write(&mut self, data: &[u8]) {
        self.offset += data.len();
    }
    fn pad(&mut self, alignment: usize) {
        self.offset = round_up(self.offset, alignment);
    }
    fn len(&self) -> usize {
        self.offset
    }
}

impl Output for SecondPass {
    fn note_header_emitted(&mut self) {}
    fn note_superblock_emitted(&mut self) {}
    fn note_inode(&mut self) {}
    fn note_inodes_end(&mut self) {
        debug_assert_eq!(
            self.output.len(),
            self.layout
                .inodes_end
                .expect("inodes_end not recorded")
                .get(),
            "second pass diverged from first at inodes_end"
        );
    }
    fn note_xattr(&mut self) {}
    fn note_block(&mut self) {}
    fn note_end(&mut self) {
        debug_assert_eq!(
            self.output.len(),
            self.layout.end.expect("end not recorded").get(),
            "second pass diverged from first at end"
        );
    }

    fn get_inode_offset(&self, idx: usize) -> Option<NonZeroUsize> {
        Some(self.layout.inodes[idx])
    }
    fn get_inodes_end(&self) -> Option<NonZeroUsize> {
        Some(self.layout.inodes_end.expect("inodes_end not recorded"))
    }
    fn get_xattr_offset(&self, idx: usize) -> Option<NonZeroUsize> {
        Some(self.layout.xattrs[idx])
    }
    fn get_block_offset(&self, idx: usize) -> Option<NonZeroUsize> {
        Some(self.layout.blocks[idx])
    }
    fn get_end(&self) -> Option<NonZeroUsize> {
        Some(self.layout.end.expect("end not recorded"))
    }

    fn write(&mut self, data: &[u8]) {
        self.output.extend_from_slice(data);
    }
    fn pad(&mut self, alignment: usize) {
        self.output
            .resize(round_up(self.output.len(), alignment), 0);
    }
    fn len(&self) -> usize {
        self.output.len()
    }
}

/// Calculates the minimum mtime across all inodes in the collection.
///
/// This is used for V1 compatibility where build_time is set to the
/// minimum mtime for reproducibility. Returns `(0, 0)` for an empty slice.
fn calculate_min_mtime(inodes: &[Inode<impl FsVerityHashValue>]) -> (u64, u32) {
    inodes
        .iter()
        .map(|inode| (inode.stat.st_mtim_sec as u64, inode.stat.st_mtim_nsec))
        .reduce(|(a_sec, a_nsec), (b_sec, b_nsec)| {
            if (b_sec, b_nsec) < (a_sec, a_nsec) {
                (b_sec, b_nsec)
            } else {
                (a_sec, a_nsec)
            }
        })
        .unwrap_or((0, 0))
}

/// Return type of [`prepare_erofs_inodes`]:
/// `(inodes, shared_xattrs, min_mtime, header_flags, composefs_version)`.
type PreparedInodes<'a, ObjectID> = (Vec<Inode<'a, ObjectID>>, Vec<XAttr>, (u64, u32), u32, u32);

/// Shared setup for all `mkfs_erofs_*` entry points.
///
/// Epoch1: promote symlink inodes to data-block layout when the inode header +
/// xattrs + target would fill a full block. Must run after share_xattrs (so
/// xattr sizes are final) and after calculate_min_mtime (so compact/extended
/// is deterministic).
fn fixup_epoch1_data_blocks<ObjectID: FsVerityHashValue>(
    inodes: &mut [Inode<ObjectID>],
    version: format::FormatVersion,
    min_mtime: (u64, u32),
) {
    for inode in inodes.iter_mut() {
        let (tail_size, nlink, is_symlink) = match &inode.content {
            InodeContent::Leaf(leaf) if leaf.inline_tail_size > 0 => {
                let is_sym = matches!(leaf.content, tree::LeafContent::Symlink(..));
                (leaf.inline_tail_size, leaf.nlink, is_sym)
            }
            _ => continue,
        };

        if is_symlink {
            let xattr_size = inode.xattrs.byte_size(version);
            let use_compact = inode.fits_in_compact(min_mtime, tail_size as u64, nlink);
            let inode_header_size = if use_compact {
                size_of::<format::CompactInodeHeader>()
            } else {
                size_of::<format::ExtendedInodeHeader>()
            };
            let total_size = inode_header_size + xattr_size + tail_size;
            if total_size >= format::BLOCK_SIZE as usize {
                let leaf = match &mut inode.content {
                    InodeContent::Leaf(leaf) => leaf,
                    _ => unreachable!(),
                };
                leaf.n_data_blocks += 1;
                leaf.inline_tail_size = 0;
            }
        } else {
            let is_chunk_based = match &inode.content {
                InodeContent::Leaf(leaf) => matches!(
                    leaf.content,
                    tree::LeafContent::Regular(
                        tree::RegularFile::External(..)
                            | tree::RegularFile::ExternalNoVerity(..)
                            | tree::RegularFile::Sparse(..)
                    )
                ),
                _ => false,
            };
            if is_chunk_based {
                let xattr_size = inode.xattrs.byte_size(version);
                let overshoot = xattr_size % INODE_SLOT_SIZE;
                if tail_size + overshoot > format::BLOCK_SIZE as usize {
                    let leaf = match &mut inode.content {
                        InodeContent::Leaf(leaf) => leaf,
                        _ => unreachable!(),
                    };
                    leaf.n_data_blocks = 1;
                    leaf.inline_tail_size = 0;
                }
            }
        }
    }
}

/// Collects inodes from the filesystem, injects the Epoch1 opaque xattr on the
/// root directory, computes `header_flags` and `composefs_version`, promotes
/// repeated xattrs to the shared table, and calculates `min_mtime`.
///
/// The `composefs_version` in the header is determined solely by [`FormatVersion`]:
/// - [`FormatVersion::V0`]: `0` normally, auto-bumped to `1` when user whiteouts present
/// - [`FormatVersion::V1`]: always `1`
/// - [`FormatVersion::V2`]: always `2`
///
/// Returns `(inodes, shared_xattrs, min_mtime, header_flags, composefs_version)`.
fn prepare_erofs_inodes<'a, ObjectID: FsVerityHashValue>(
    fs: &'a tree::FileSystem<ObjectID>,
    version: format::FormatVersion,
) -> PreparedInodes<'a, ObjectID> {
    let mut inodes = InodeCollector::collect(fs, version);

    // For Epoch1 formats, add trusted.overlay.opaque xattr to root directory.
    // This is done after collection (and thus after xattr escaping) to match
    // the C implementation behavior.
    if version.epoch() == FormatEpoch::Epoch1 && !inodes.is_empty() {
        inodes[0]
            .xattrs
            .add(format::XATTR_OVERLAY_OPAQUE_ROOT, b"y", version);
    }

    // For Epoch1, compute header flags and composefs_version matching C mkcomposefs behavior.
    // This must be checked before share_xattrs(), while all xattrs are still local.
    let (header_flags, composefs_version) = match version.epoch() {
        FormatEpoch::Epoch1 => {
            // COMPOSEFS_FLAGS_HAS_ACL (bit 0) is set when any inode has POSIX ACL xattrs.
            let has_acl = inodes.iter().any(|inode| {
                inode.xattrs.local.iter().any(|xattr| {
                    xattr.prefix == format::XATTR_INDEX_POSIX_ACL_ACCESS
                        || xattr.prefix == format::XATTR_INDEX_POSIX_ACL_DEFAULT
                })
            });
            let flags = if has_acl {
                format::COMPOSEFS_FLAGS_HAS_ACL.get()
            } else {
                0
            };

            // C library writes composefs_version directly from the version option.
            // V0 always writes 0, V1 always writes 1.
            let cfs_ver = version.composefs_version().get();

            (flags, cfs_ver)
        }
        FormatEpoch::Epoch2 => (0u32, format::COMPOSEFS_VERSION.get()),
    };

    let xattrs = share_xattrs(&mut inodes, version);
    let min_mtime = calculate_min_mtime(&inodes);

    if version.epoch() == FormatEpoch::Epoch1 {
        fixup_epoch1_data_blocks(&mut inodes, version, min_mtime);
    }

    (inodes, xattrs, min_mtime, header_flags, composefs_version)
}

/// Creates an EROFS filesystem image from a composefs tree using the default format (V2).
///
/// This function performs a two-pass generation:
/// 1. First pass determines the layout and sizes of all structures
/// 2. Second pass writes the actual image data
///
/// Returns the complete EROFS image as a byte array.
pub fn mkfs_erofs<ObjectID: FsVerityHashValue>(fs: &ValidatedFileSystem<ObjectID>) -> Box<[u8]> {
    mkfs_erofs_inner(
        &fs.0,
        format::FormatVersion::default(),
        #[cfg(test)]
        None,
    )
}

/// Internal two-pass EROFS image generator shared by all public entry points.
///
/// Runs a layout pass (first pass) followed by an emit pass (second pass).
/// When `faults` is `Some`, decisions are recorded during the first pass and
/// replayed during the second so both passes make identical choices.
///
/// Takes an immutable reference to the filesystem.  For Epoch1 (V0/V1) formats,
/// whiteout stubs are added to a temporary clone so the caller's tree is never
/// mutated.
pub(crate) fn mkfs_erofs_inner<ObjectID: FsVerityHashValue>(
    fs: &tree::FileSystem<ObjectID>,
    version: format::FormatVersion,
    #[cfg(test)] faults: Option<WriterFaults>,
) -> Box<[u8]> {
    // For Epoch1 (V0/V1) formats, whiteout stubs must be present during image
    // generation.  Clone the tree and add stubs to the clone so the caller's
    // filesystem is never mutated.
    let fs_with_whiteouts;
    let fs = if version.epoch() == FormatEpoch::Epoch1 {
        fs_with_whiteouts = {
            let mut cloned = fs.clone();
            cloned.add_overlay_whiteouts();
            cloned
        };
        &fs_with_whiteouts
    } else {
        fs
    };

    let (inodes, xattrs, min_mtime, header_flags, composefs_version) =
        prepare_erofs_inodes(fs, version);

    let mut ctx = WriteContext {
        version,
        min_mtime,
        header_flags,
        composefs_version,
        #[cfg(test)]
        faults,
    };

    // First pass: determine the layout.
    let mut first_pass = FirstPass::default();
    write_erofs(&mut first_pass, &inodes, &xattrs, &mut ctx);

    // Switch fault injector to replay mode so the second pass makes identical choices.
    #[cfg(test)]
    if let Some(ref mut f) = ctx.faults {
        f.start_replay();
    }

    // Second pass: emit the actual bytes.
    let mut second_pass = SecondPass {
        output: vec![],
        layout: first_pass.layout,
    };
    write_erofs(&mut second_pass, &inodes, &xattrs, &mut ctx);

    second_pass.output.into_boxed_slice()
}

/// Creates an EROFS filesystem image from a composefs tree with an explicit format version.
///
/// The `version` parameter controls the format version:
/// - [`FormatVersion::V0`]: C `mkcomposefs` compatible (compact inodes, BFS, whiteout table).
///   `composefs_version` is `0` normally, auto-bumped to `1` when user whiteouts are present.
/// - [`FormatVersion::V1`]: Same layout as V0 but `composefs_version` is always `1`.
///   Equivalent to C `mkcomposefs --min-version=1`.
/// - [`FormatVersion::V2`]: Rust-native format (extended inodes, DFS, `composefs_version=2`).
///
/// Whiteout stubs for Epoch1 formats (V0/V1) are added automatically.
///
/// Returns the complete EROFS image as a byte array.
pub fn mkfs_erofs_versioned<ObjectID: FsVerityHashValue>(
    fs: &ValidatedFileSystem<ObjectID>,
    version: format::FormatVersion,
) -> Box<[u8]> {
    mkfs_erofs_inner(
        &fs.0,
        version,
        #[cfg(test)]
        None,
    )
}

/// Test-only: write a versioned EROFS image with fault injection.
///
/// `faults` controls which writer invariants are intentionally violated.
/// Pass `WriterFaults::new(seed)` with the desired rates set.
#[cfg(test)]
pub(crate) fn mkfs_erofs_with_faults<ObjectID: FsVerityHashValue>(
    fs: &ValidatedFileSystem<ObjectID>,
    version: format::FormatVersion,
    faults: WriterFaults,
) -> Box<[u8]> {
    mkfs_erofs_inner(&fs.0, version, Some(faults))
}

#[cfg(test)]
mod tests {
    use super::compute_chunk_format;

    /// Unit tests for `compute_chunk_format` with boundary values.
    ///
    /// The function converts a file size into the EROFS chunk-format field:
    ///   chunkbits = ilog2(size - 1) + 1, clamped to [BLOCK_BITS=12, 43]
    ///   result    = chunkbits - BLOCK_BITS
    #[test]
    fn test_compute_chunk_format_boundary_values() {
        // size=1: file_size <= 1 branch → chunkbits=1 → clamped to 12 → result 0
        assert_eq!(compute_chunk_format(1), 0, "size=1");
        // size=2: ilog2(1)+1=1 → clamped to 12 → result 0
        assert_eq!(compute_chunk_format(2), 0, "size=2");
        // size=4096: ilog2(4095)+1=12 → no clamp → result 0
        assert_eq!(compute_chunk_format(4096), 0, "size=4096");
        // size=4097: ilog2(4096)+1=13 → result 1
        assert_eq!(compute_chunk_format(4097), 1, "size=4097");
        // size=1<<20: ilog2((1<<20)-1)+1=20 → result 8
        assert_eq!(compute_chunk_format(1 << 20), 8, "size=1<<20");
        // size=(1<<20)+1: ilog2(1<<20)+1=21 → result 9
        assert_eq!(compute_chunk_format((1 << 20) + 1), 9, "size=(1<<20)+1");
    }

    /// Generating a V2 image after a V1 image from the same `FileSystem` must
    /// produce the same bytes as generating V2 alone.
    ///
    /// This is the regression test for the bug where `add_overlay_whiteouts()`
    /// permanently mutated the tree during V1 generation, leaving 256 whiteout
    /// stub entries in the root that then polluted the subsequent V2 image.
    #[test]
    fn test_v2_digest_unaffected_by_prior_v1_generation() {
        use crate::{
            dumpfile::dumpfile_to_filesystem,
            erofs::{
                format::FormatVersion,
                writer::{ValidatedFileSystem, mkfs_erofs_inner},
            },
            fsverity::Sha256HashValue,
        };

        // A modest filesystem with a couple of entries to make the image non-trivial.
        // Format: path size mode nlink uid gid rdev mtime payload content digest
        let dumpfile = concat!(
            "/ 0 40755 2 0 0 0 1000.0 - - -\n",
            "/usr 0 40755 2 0 0 0 1000.0 - - -\n",
            "/usr/lib 0 40755 2 0 0 0 1000.0 - - -\n",
            "/usr/lib/libfoo.so 5 100644 1 0 0 0 1000.0 - hello -\n",
        );

        // Build V2-alone image first (before any V1 has touched the tree).
        let fs_v2_only = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let v2_alone = mkfs_erofs_inner(
            &ValidatedFileSystem::new(fs_v2_only).unwrap().0,
            FormatVersion::V2,
            None,
        );

        // Now build V1 then V2 from the same filesystem.
        let fs_both = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let inner = ValidatedFileSystem::new(fs_both).unwrap().0;
        let root_entries_before = inner.root.entries.len();
        let leaves_before = inner.leaves.len();

        let _v1 = mkfs_erofs_inner(&inner, FormatVersion::V1, None);

        // After V1 generation the tree must be unchanged (clone-based, immutable).
        assert_eq!(
            inner.root.entries.len(),
            root_entries_before,
            "V1 generation unexpectedly modified the root directory"
        );
        assert_eq!(
            inner.leaves.len(),
            leaves_before,
            "V1 generation unexpectedly modified the leaves table"
        );

        let v2_after_v1 = mkfs_erofs_inner(&inner, FormatVersion::V2, None);

        assert_eq!(
            v2_alone, v2_after_v1,
            "V2 image differs depending on whether V1 was generated first"
        );
    }
}
