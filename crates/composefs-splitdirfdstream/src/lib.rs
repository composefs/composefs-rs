//! A data format and IPC protocol for sending a binary stream across local
//! processes via file descriptor passing (DBus, varlink, etc.).
//!
//! Designed for sending tar archives of container image layers that are unpacked
//! into a storage system such as composefs or docker/podman `overlay` storage.
//! More generally it is a mechanism for reassembling any byte stream from a mix
//! of inline bytes and whole-file references, useful whenever the bulk of a
//! stream already lives as files in a content store and copying that bulk inline
//! would be wasteful.
//!
//! External content is identified by `(dirfd_index, filename)` pairs so the
//! receiving side can `openat2` the files itself given a small out-of-band array
//! of directory file descriptors. This avoids passing one open fd per external
//! chunk (which would not scale to streams referencing thousands of files) and
//! suits reconstructing a stream from a content store laid out on disk.
//!
//! # Format
//!
//! A splitdirfdstream is a sequence of chunks with no header or footer. Combined
//! with an out-of-band, ordered array of directory file descriptors `dirfds[0..D]`,
//! it reconstructs a byte stream by concatenating each chunk's contribution:
//!
//! - **Metadata chunk** — raw stream metadata (tar header/padding) carried verbatim.
//! - **InlineData chunk** — file content transported inline (for non-world-readable
//!   files the producer read through a privileged fd).
//! - **FileBackedData chunk** — `content_length` bytes of a file, resolved via
//!   `openat2(dirfds[dirfd_index], filename, RESOLVE_BENEATH)` and read from offset 0.
//!
//! All integers are little-endian. Each chunk begins with a single type byte:
//!
//! | Type byte | Chunk          | Remaining header                                                  | Body                         |
//! |-----------|----------------|-------------------------------------------------------------------|------------------------------|
//! | `0x00`    | Metadata       | `u32 LE` — body length                                            | `length` bytes               |
//! | `0x01`    | InlineData     | `u32 LE` — body length                                            | `length` bytes               |
//! | `0x02`    | FileBackedData | `u64 LE` content_length, `u32 LE` dirfd_index, `u32 LE` name_len | `name_len` bytes of filename |
//!
//! Any other type byte is a hard error ([`Error::UnknownChunkType`]).
//!
//! There is no in-band end-of-stream sentinel: the stream ends at clean EOF at
//! the start of a type byte. A partial read anywhere inside a chunk is a
//! truncation error ([`Error::Truncated`]). Because the format carries no length
//! or checksum of the whole stream, callers that need end-to-end integrity should
//! verify the reconstructed bytes against an expected size and digest out of band.
//!
//! # Chunk layouts
//!
//! ### Metadata
//!
//! ```text
//! +--------+---------------+----------------------------+
//! | 0x00   | length: u32LE | data: `length` raw bytes   |
//! +--------+---------------+----------------------------+
//! ```
//!
//! `data` (`length` bytes) is written verbatim to output (tar headers, padding,
//! etc.). Empty writes are silently dropped by the writer; a zero-length Metadata
//! chunk is never encoded. `length` is bounded by [`MAX_INLINE_CHUNK_SIZE`] (256 MiB).
//!
//! ### InlineData
//!
//! ```text
//! +--------+---------------+----------------------------+
//! | 0x01   | length: u32LE | data: `length` raw bytes   |
//! +--------+---------------+----------------------------+
//! ```
//!
//! `length` is both the byte count of the data that follows and the logical file
//! size the consumer uses for its inline-vs-object storage decision. Unlike
//! FileBackedData, no directory fd is involved; the producer has already read the
//! content through its own privileged fd.
//!
//! A zero-length InlineData **is** written and round-trips correctly — a zero-byte
//! non-world-readable file must still be transported. `length` is bounded by
//! [`MAX_INLINE_CHUNK_SIZE`] (256 MiB), since the data is fully buffered in memory
//! during transport.
//!
//! ### FileBackedData
//!
//! ```text
//! +--------+---------------------+--------------------+-----------------+------------------------------+
//! | 0x02   | content_len: u64LE  | dirfd_index: u32LE | name_len: u32LE | filename: name_len raw bytes |
//! +--------+---------------------+--------------------+-----------------+------------------------------+
//! ```
//!
//! The consumer reads exactly `content_len` bytes starting at offset 0 of the
//! opened file. The explicit `content_len` makes the stream self-framing — entry
//! boundaries never depend on trusting the backing file's size, which closes a
//! TOCTOU window if the underlying store is mutated mid-read.
//!
//! A FileBackedData chunk always starts at offset 0: it references a whole file,
//! not a byte range. This is deliberate — it lets every external reference reflink
//! cleanly (`FICLONE`) when materialized on a CoW filesystem. There is no range
//! variant.
//!
//! `filename` is a path relative to `dirfds[dirfd_index]`. It may contain `/` to
//! traverse subdirectories within that root; it is not NUL-terminated and must not
//! contain NUL.
//!
//! # Limits
//!
//! | Constant | Value | Purpose |
//! |----------|-------|---------|
//! | [`MAX_INLINE_CHUNK_SIZE`] | 256 MiB | Bounds memory for a single Metadata or InlineData chunk body. |
//! | [`MAX_FILENAME_LEN`] | 4096 bytes | Bounds the FileBackedData filename length. |
//!
//! The reader rejects an out-of-range `dirfd_index`, and Metadata or InlineData
//! chunks whose `length` exceeds `MAX_INLINE_CHUNK_SIZE`.
//!
//! # Safety
//!
//! The consuming side should always use `openat2(RESOLVE_BENEATH)` or equivalent.
//! This crate uses `rustix::fs::openat2` with
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, falling back
//! to `openat(O_NOFOLLOW)` on kernels older than 5.6. The [`validate_filename`]
//! function rejects `..` components, absolute paths, and embedded NUL bytes before
//! any syscall is made.
//!
//! The reader performs only *structural* validation (framing, limits); it does
//! **not** validate filename *content*. Callers that consume
//! [`Chunk::FileBackedData`] `.filename` directly must call [`validate_filename`]
//! (or use [`open_beneath`] / [`reconstruct`], which do).
//!
//! # Examples
//!
//! Write a stream, then inspect its chunk structure:
//!
//! ```
//! use composefs_splitdirfdstream::{SplitdirfdstreamWriter, SplitdirfdstreamReader, Chunk};
//!
//! // Write a stream: inline glue bytes plus a reference to dirfds[0]/data/blob.
//! let mut buffer = Vec::new();
//! let mut writer = SplitdirfdstreamWriter::new(&mut buffer);
//! writer.write_metadata(b"tar header bytes").unwrap();
//! writer.write_file_backed_data(0, 5, b"data/blob").unwrap(); // 5 bytes from dirfds[0]/data/blob
//! writer.write_metadata(b"tar padding").unwrap();
//! writer.finish().unwrap();
//!
//! // Inspect the chunk structure.
//! let mut reader = SplitdirfdstreamReader::new(buffer.as_slice());
//! while let Some(chunk) = reader.next_chunk().unwrap() {
//!     match chunk {
//!         Chunk::Metadata(data) => { /* tar header/padding bytes */ }
//!         Chunk::InlineData(data) => { /* inline file content (non-world-readable files) */ }
//!         Chunk::FileBackedData { dirfd_index, length, filename } => { /* (dirfds[i], name, len) */ }
//!     }
//! }
//! ```
//!
//! To reconstruct the full byte stream, supply the directory fds to
//! [`reconstruct`], which resolves and splices each external chunk for you:
//!
//! ```no_run
//! use std::os::fd::BorrowedFd;
//! # fn demo(stream: &[u8], dir: BorrowedFd<'_>, out: &mut Vec<u8>) {
//! let dirfds = [dir];
//! let total = composefs_splitdirfdstream::reconstruct(stream, &dirfds, out).unwrap();
//! # let _ = total;
//! # }
//! ```
//!
//! # API surface
//!
//! | Item | Role |
//! |------|------|
//! | [`SplitdirfdstreamWriter`] | Encode inline + external chunks into the wire format. |
//! | [`SplitdirfdstreamReader`] | Iterate a stream as borrowed [`Chunk`]s. |
//! | [`Chunk`] | `Metadata(&[u8])`, `InlineData(&[u8])`, or `FileBackedData { dirfd_index, length, filename }`. |
//! | [`reconstruct`] | Reconstruct the full byte stream given the directory fds. |
//! | [`open_beneath`] | Safely open one external file beneath a directory fd. |
//! | [`validate_filename`] | The path-safety predicate (reused by the writer/consumer). |
//!
//! # See also
//!
//! This crate is only the stream format. A higher-level control channel —
//! opening a source, negotiating capabilities, and handing over the stream fd
//! plus directory fds over a socket via `SCM_RIGHTS` — is layered on top
//! elsewhere (e.g. the `composefs-storage` layer-transfer service); it carries
//! structured metadata only, with all binary content flowing through this format
//! and the directory fds.

// This is a library: emit diagnostics via the `log` crate (or return them),
// never by writing to the process's stdout/stderr. Genuinely-intentional
// exceptions carry a local `#[allow]` with justification. Test code is exempt.
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::fs::{Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

pub mod transport;
#[cfg(feature = "tokio")]
pub use transport::spawn_self_reaping_producer;
pub use transport::{
    FdLimitError, LayerFdLayout, MAX_FDS_PER_FRAME, build_layer_fd_layout, open_devnull,
    seed_from_id, split_fds_into_frames,
};

/// Maximum size for an inline chunk (256 MiB).
///
/// This limit prevents denial-of-service attacks where a malicious stream
/// could specify an extremely large inline chunk size, causing unbounded
/// memory allocation.
pub const MAX_INLINE_CHUNK_SIZE: usize = 256 * 1024 * 1024;

/// Maximum length of an external filename in bytes.
///
/// Filenames longer than this are rejected by [`validate_filename`] and
/// by the reader before any buffer is resized.
pub const MAX_FILENAME_LEN: usize = 4096;

/// Errors that can occur while reading or writing a splitdirfdstream.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An underlying I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The stream ended in the middle of a chunk.
    #[error("truncated stream: expected {expected} more bytes in chunk")]
    Truncated {
        /// How many bytes were still expected when EOF was encountered.
        ///
        /// Semantics depend on *where* truncation occurred:
        ///
        /// - **Type byte**: `1` if EOF arrived after 0 bytes (but that is
        ///   returned as `Ok(None)`; this only fires for 0 < n < expected).
        /// - **Inline body or FileBackedData header/name**: the *full* declared
        ///   size (i.e. the number passed to `read_exact`), because `read_exact`
        ///   does not report how many bytes it successfully consumed before EOF.
        expected: u64,
    },

    /// An inline chunk's size field exceeds [`MAX_INLINE_CHUNK_SIZE`].
    #[error("inline chunk size {size} exceeds maximum {max}")]
    InlineTooLarge {
        /// The size read from the stream.
        size: usize,
        /// The maximum allowed size.
        max: usize,
    },

    /// An unrecognised chunk type byte was encountered.
    #[error("unknown chunk type byte 0x{0:02x}")]
    UnknownChunkType(u8),

    /// A filename exceeds [`MAX_FILENAME_LEN`] bytes.
    #[error("filename length {len} exceeds maximum {max}")]
    FilenameTooLong {
        /// The length of the filename.
        len: usize,
        /// The maximum allowed length.
        max: usize,
    },

    /// A filename failed validation.
    #[error("invalid filename: {reason}")]
    InvalidFilename {
        /// Human-readable description of why the filename is invalid.
        reason: &'static str,
    },

    /// A dirfd index in an external chunk was out of range.
    #[error("dirfd index {index} out of range (have {count} dirfds)")]
    DirfdIndexOutOfRange {
        /// The index that was out of range.
        index: u32,
        /// The number of dirfds available.
        count: usize,
    },

    /// An external file was shorter than declared in the stream.
    #[error("external file shorter than declared length {declared} (got {actual})")]
    ExternalTooShort {
        /// The length declared in the stream.
        declared: u64,
        /// The number of bytes actually read before EOF.
        actual: u64,
    },
}

impl From<Errno> for Error {
    fn from(e: Errno) -> Self {
        Error::Io(e.into())
    }
}

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// A chunk decoded from a splitdirfdstream.
///
/// Chunks carry either stream metadata (raw tar header/padding bytes),
/// inline-transported file content (non-world-readable files the producer
/// read through a privileged fd), or references to external files identified
/// by a directory fd index and a relative filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk<'a> {
    /// Stream metadata: raw tar header or padding bytes embedded directly in
    /// the stream. Consumers write these verbatim into the output.
    Metadata(&'a [u8]),

    /// Inline-transported file content. The producer read these bytes through
    /// a privileged fd; the consumer decides whether to store them inline
    /// (≤ splitstream threshold) or as an external object based on `data.len()`.
    InlineData(&'a [u8]),

    /// Reference to an external file relative to one of the caller-supplied
    /// directory file descriptors.
    ///
    /// The reader does **not** validate `filename` content — callers that
    /// consume `filename` directly **must** call [`validate_filename`] or use
    /// [`open_beneath`] / [`reconstruct`], which call it internally.
    FileBackedData {
        /// Index into the `dirfds` array supplied to [`reconstruct`].
        dirfd_index: u32,
        /// Number of bytes to read from the file, starting at offset 0.
        length: u64,
        /// Relative filename within `dirfds[dirfd_index]`.
        filename: &'a [u8],
    },
}

/// Writer for building a splitdirfdstream.
///
/// Encodes inline data and dirfd-relative file references into the
/// splitdirfdstream binary format.
///
/// # Example
///
/// ```
/// use composefs_splitdirfdstream::SplitdirfdstreamWriter;
///
/// let mut buffer = Vec::new();
/// let mut writer = SplitdirfdstreamWriter::new(&mut buffer);
/// writer.write_metadata(b"hello").unwrap();
/// writer.write_file_backed_data(0, 42, b"objects/abc123").unwrap();
/// let _buf = writer.finish().unwrap();
/// ```
#[derive(Debug)]
pub struct SplitdirfdstreamWriter<W> {
    writer: W,
}

impl<W: Write> SplitdirfdstreamWriter<W> {
    /// Create a new writer wrapping `writer`.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Write an inline chunk containing `data`.
    ///
    /// Empty slices are silently ignored (no bytes are written).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InlineTooLarge`] if `data.len()` exceeds
    /// [`MAX_INLINE_CHUNK_SIZE`], or propagates I/O errors from the
    /// underlying writer.
    pub fn write_metadata(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if data.len() > MAX_INLINE_CHUNK_SIZE {
            return Err(Error::InlineTooLarge {
                size: data.len(),
                max: MAX_INLINE_CHUNK_SIZE,
            });
        }
        self.writer.write_all(&[0x00u8])?;
        self.writer.write_all(&(data.len() as u32).to_le_bytes())?;
        self.writer.write_all(data)?;
        Ok(())
    }

    /// Write an [`InlineData`](Chunk::InlineData) chunk carrying `data` bytes
    /// of file content transported inline.
    ///
    /// Unlike [`write_metadata`](Self::write_metadata), a zero-length slice IS
    /// written (a zero-byte non-world-readable file must still round-trip).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InlineTooLarge`] if `data.len()` exceeds
    /// [`MAX_INLINE_CHUNK_SIZE`], or propagates I/O errors from the underlying
    /// writer.
    pub fn write_inline_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_INLINE_CHUNK_SIZE {
            return Err(Error::InlineTooLarge {
                size: data.len(),
                max: MAX_INLINE_CHUNK_SIZE,
            });
        }
        self.writer.write_all(&[0x01u8])?;
        self.writer.write_all(&(data.len() as u32).to_le_bytes())?;
        self.writer.write_all(data)?;
        Ok(())
    }

    /// Write a [`FileBackedData`](Chunk::FileBackedData) chunk referencing a
    /// file by dirfd index and relative filename.
    ///
    /// The consumer will open `filename` beneath `dirfds[dirfd_index]` and
    /// read exactly `length` bytes from offset 0.
    ///
    /// `filename` is validated by [`validate_filename`] before writing.
    ///
    /// # Errors
    ///
    /// Returns any [`Error`] produced by [`validate_filename`], or propagates
    /// I/O errors from the underlying writer.
    pub fn write_file_backed_data(
        &mut self,
        dirfd_index: u32,
        length: u64,
        filename: &[u8],
    ) -> Result<()> {
        validate_filename(filename)?;
        self.writer.write_all(&[0x02u8])?;
        self.writer.write_all(&length.to_le_bytes())?;
        self.writer.write_all(&dirfd_index.to_le_bytes())?;
        self.writer
            .write_all(&(filename.len() as u32).to_le_bytes())?;
        self.writer.write_all(filename)?;
        Ok(())
    }

    /// Consume the writer and return the underlying `Write` impl.
    pub fn finish(self) -> Result<W> {
        Ok(self.writer)
    }
}

/// Reader for parsing a splitdirfdstream.
///
/// Yields [`Chunk`] values by parsing the binary format. The internal buffer
/// is reused across calls so that only one chunk's data is live at a time.
///
/// # Example
///
/// ```
/// use composefs_splitdirfdstream::{SplitdirfdstreamReader, Chunk};
///
/// // Manually constructed stream: Metadata "hello"
/// // Format: [0x00][5u32 LE][b"hello"]
/// let mut data = Vec::new();
/// data.push(0x00u8);
/// data.extend_from_slice(&5u32.to_le_bytes());
/// data.extend_from_slice(b"hello");
///
/// let mut reader = SplitdirfdstreamReader::new(data.as_slice());
/// assert_eq!(reader.next_chunk().unwrap(), Some(Chunk::Metadata(b"hello")));
/// assert_eq!(reader.next_chunk().unwrap(), None);
/// ```
#[derive(Debug)]
pub struct SplitdirfdstreamReader<R> {
    reader: R,
    /// Internal buffer reused across [`next_chunk`](SplitdirfdstreamReader::next_chunk) calls.
    buffer: Vec<u8>,
}

impl<R: Read> SplitdirfdstreamReader<R> {
    /// Create a new reader wrapping `reader`.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Vec::new(),
        }
    }

    /// Consume this reader, returning the underlying `Read` impl.
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Return the next chunk from the stream, or `None` at a clean EOF.
    ///
    /// A clean EOF is one where zero bytes have been consumed from the current
    /// type byte. Any partial read (0 < n < expected) is [`Error::Truncated`].
    ///
    /// The returned [`Chunk::FileBackedData`] contains the raw `filename` bytes
    /// without any validation — callers that use `filename` directly **must**
    /// call [`validate_filename`] themselves, or use [`reconstruct`] which does
    /// it internally via [`open_beneath`].
    ///
    /// # Errors
    ///
    /// - [`Error::Truncated`] — stream ended mid-chunk
    /// - [`Error::InlineTooLarge`] — Metadata or InlineData body size exceeds [`MAX_INLINE_CHUNK_SIZE`]
    /// - [`Error::FilenameTooLong`] — filename length exceeds [`MAX_FILENAME_LEN`]
    /// - [`Error::UnknownChunkType`] — unrecognised type byte
    /// - [`Error::Io`] — underlying I/O error
    pub fn next_chunk(&mut self) -> Result<Option<Chunk<'_>>> {
        // Step 1: read the 1-byte type, distinguishing clean EOF from truncation.
        let mut type_byte = [0u8; 1];
        let mut got = 0usize;
        loop {
            match self.reader.read(&mut type_byte[got..]) {
                Ok(0) => {
                    if got == 0 {
                        return Ok(None); // clean EOF at chunk boundary
                    }
                    return Err(Error::Truncated { expected: 1 });
                }
                Ok(n) => {
                    got += n;
                    if got == 1 {
                        break;
                    }
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }

        match type_byte[0] {
            0x00 | 0x01 => {
                // Metadata (0x00) or InlineData (0x01): read 4-byte u32 LE body length.
                let mut len_bytes = [0u8; 4];
                self.reader.read_exact(&mut len_bytes).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        Error::Truncated { expected: 4 }
                    } else {
                        Error::Io(e)
                    }
                })?;
                let length = u32::from_le_bytes(len_bytes) as usize;
                if length > MAX_INLINE_CHUNK_SIZE {
                    return Err(Error::InlineTooLarge {
                        size: length,
                        max: MAX_INLINE_CHUNK_SIZE,
                    });
                }
                self.buffer.resize(length, 0);
                self.reader.read_exact(&mut self.buffer).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        Error::Truncated {
                            expected: length as u64,
                        }
                    } else {
                        Error::Io(e)
                    }
                })?;
                if type_byte[0] == 0x00 {
                    Ok(Some(Chunk::Metadata(&self.buffer)))
                } else {
                    Ok(Some(Chunk::InlineData(&self.buffer)))
                }
            }
            0x02 => {
                // FileBackedData: [u64 LE content_length][u32 LE dirfd_index][u32 LE name_len][name bytes]
                let mut header = [0u8; 16];
                self.reader.read_exact(&mut header).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        Error::Truncated { expected: 16 }
                    } else {
                        Error::Io(e)
                    }
                })?;
                let length = u64::from_le_bytes(header[0..8].try_into().unwrap());
                let dirfd_index = u32::from_le_bytes(header[8..12].try_into().unwrap());
                let name_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
                if name_len > MAX_FILENAME_LEN {
                    return Err(Error::FilenameTooLong {
                        len: name_len,
                        max: MAX_FILENAME_LEN,
                    });
                }
                self.buffer.resize(name_len, 0);
                self.reader.read_exact(&mut self.buffer).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        Error::Truncated {
                            expected: name_len as u64,
                        }
                    } else {
                        Error::Io(e)
                    }
                })?;
                Ok(Some(Chunk::FileBackedData {
                    dirfd_index,
                    length,
                    filename: &self.buffer,
                }))
            }
            other => Err(Error::UnknownChunkType(other)),
        }
    }
}

/// Validate that `filename` is an acceptable external filename.
///
/// Checks, in order:
/// 1. Not empty.
/// 2. Not longer than [`MAX_FILENAME_LEN`].
/// 3. No embedded NUL bytes.
/// 4. Not an absolute path (does not start with `/`).
/// 5. No `..` path components.
///
/// Note that `.` components and empty components (from `//`) are permitted,
/// as the kernel will handle them safely.
///
/// # Errors
///
/// Returns [`Error::InvalidFilename`] or [`Error::FilenameTooLong`] on failure.
pub fn validate_filename(filename: &[u8]) -> Result<()> {
    if filename.is_empty() {
        return Err(Error::InvalidFilename {
            reason: "empty filename",
        });
    }
    if filename.len() > MAX_FILENAME_LEN {
        return Err(Error::FilenameTooLong {
            len: filename.len(),
            max: MAX_FILENAME_LEN,
        });
    }
    if filename.contains(&0u8) {
        return Err(Error::InvalidFilename {
            reason: "embedded NUL",
        });
    }
    if filename[0] == b'/' {
        return Err(Error::InvalidFilename {
            reason: "absolute path",
        });
    }
    for component in filename.split(|&b| b == b'/') {
        if component == b".." {
            return Err(Error::InvalidFilename {
                reason: "`..` component",
            });
        }
    }
    Ok(())
}

/// Open a file at `filename` relative to `dirfd` using safe kernel primitives.
///
/// Internally calls `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
/// RESOLVE_NO_XDEV` when available. On kernels that do not support `openat2`
/// (`ENOSYS`), falls back to plain `openat(2)`.
///
/// # Security note
///
/// The `openat2` path prevents directory escapes (`RESOLVE_BENEATH`), blocks
/// magic-link traversal (`RESOLVE_NO_MAGICLINKS`), prevents crossing filesystem
/// boundaries (`RESOLVE_NO_XDEV`), and **does** allow symlinks as long as they
/// resolve within the base directory. A symlink pointing outside the base
/// directory is still rejected by `RESOLVE_BENEATH`.
///
/// The `openat` fallback does not enforce `RESOLVE_BENEATH` (that kernel
/// feature is unavailable on old kernels), so callers should prefer environments
/// with kernel ≥ 5.6 (where `openat2` is available) when strict confinement is
/// required. [`validate_filename`] is still called before any syscall to reject
/// `..` components and absolute paths.
///
/// # Errors
///
/// Returns any error from [`validate_filename`], or an [`Error::Io`] wrapping
/// the kernel error (`EXDEV` for escape attempts, etc.).
pub fn open_beneath(dirfd: BorrowedFd<'_>, filename: &[u8]) -> Result<OwnedFd> {
    validate_filename(filename)?;

    // Build a CString: validate_filename rejects embedded NUL so this is infallible.
    let cname = CString::new(filename).expect("validate_filename guarantees no NUL");

    // Try openat2 first (Linux ≥ 5.6).
    // RESOLVE_BENEATH  — prevent escaping the base directory via any path tricks.
    // RESOLVE_NO_MAGICLINKS — block /proc/self/fd-style magic links.
    // RESOLVE_NO_XDEV  — prevent crossing filesystem mount boundaries.
    // Symlinks that stay within the base directory are permitted.
    let oflags = OFlags::RDONLY | OFlags::CLOEXEC;
    let result = rustix::fs::openat2(
        dirfd,
        &cname,
        oflags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
    );

    match result {
        Ok(fd) => Ok(fd),
        Err(e) if e == Errno::NOSYS => {
            // Kernel too old for openat2; fall back to plain openat.
            // validate_filename already rejected `..` and absolute paths.
            rustix::fs::openat(
                dirfd,
                &cname,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(Error::from)
        }
        Err(e) => Err(e.into()),
    }
}

/// Reconstruct the byte stream encoded in `stream` by combining inline chunks
/// and external file data, writing all output to `output`.
///
/// For each [`Chunk::FileBackedData`], the corresponding file is opened with
/// [`open_beneath`] using `dirfds[dirfd_index]` as the base directory, and
/// exactly `length` bytes are read from offset 0 via positional reads
/// (`pread(2)`), so the same file can be referenced multiple times without
/// seeking.
///
/// Returns the total number of bytes written to `output`.
///
/// # Errors
///
/// - [`Error::DirfdIndexOutOfRange`] — `dirfd_index` ≥ `dirfds.len()`
/// - [`Error::ExternalTooShort`] — external file has fewer bytes than declared
/// - Any error from [`open_beneath`] or from writing to `output`
pub fn reconstruct<R: Read, W: Write>(
    stream: R,
    dirfds: &[BorrowedFd<'_>],
    output: &mut W,
) -> Result<u64> {
    let mut reader = SplitdirfdstreamReader::new(stream);
    let mut total: u64 = 0;
    const BUF_SIZE: usize = 128 * 1024;

    while let Some(chunk) = reader.next_chunk()? {
        match chunk {
            Chunk::Metadata(data) => {
                output.write_all(data)?;
                total += data.len() as u64;
            }
            Chunk::InlineData(data) => {
                output.write_all(data)?;
                total += data.len() as u64;
            }
            Chunk::FileBackedData {
                dirfd_index,
                length,
                filename,
            } => {
                let idx = dirfd_index as usize;
                if idx >= dirfds.len() {
                    return Err(Error::DirfdIndexOutOfRange {
                        index: dirfd_index,
                        count: dirfds.len(),
                    });
                }
                let fd = open_beneath(dirfds[idx], filename)?;
                // Cap the scratch buffer at BUF_SIZE; never size it from the
                // attacker-controlled `length` (which can be up to u64::MAX),
                // which would overflow `as usize` / wrap on 32-bit and panic
                // under overflow-checks. `to_read` below bounds each read.
                let mut buf =
                    vec![0u8; BUF_SIZE.min(usize::try_from(length).unwrap_or(usize::MAX))];
                let mut remaining = length;
                let mut offset: u64 = 0;
                while remaining > 0 {
                    let to_read = (remaining as usize).min(buf.len());
                    let n =
                        rustix::io::pread(&fd, &mut buf[..to_read], offset).map_err(Error::from)?;
                    if n == 0 {
                        return Err(Error::ExternalTooShort {
                            declared: length,
                            actual: length - remaining,
                        });
                    }
                    output.write_all(&buf[..n])?;
                    remaining -= n as u64;
                    offset += n as u64;
                }
                total += length;
            }
        }
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Write `chunks` into a buffer and read them back, returning the decoded
    /// chunks as `(dirfd_index, length, filename, inline_data)` tuples.
    fn roundtrip_stream(writes: &[WriteCmd<'_>]) -> (Vec<u8>, Vec<DecodedChunk>) {
        let mut buf = Vec::new();
        {
            let mut w = SplitdirfdstreamWriter::new(&mut buf);
            for cmd in writes {
                match cmd {
                    WriteCmd::Metadata(data) => w.write_metadata(data).unwrap(),
                    WriteCmd::InlineData(data) => w.write_inline_data(data).unwrap(),
                    WriteCmd::FileBackedData {
                        dirfd_index,
                        length,
                        filename,
                    } => w
                        .write_file_backed_data(*dirfd_index, *length, filename)
                        .unwrap(),
                }
            }
            w.finish().unwrap();
        }
        let mut reader = SplitdirfdstreamReader::new(buf.as_slice());
        let mut out = Vec::new();
        while let Some(chunk) = reader.next_chunk().unwrap() {
            out.push(DecodedChunk::from(&chunk));
        }
        (buf, out)
    }

    #[derive(Debug)]
    enum WriteCmd<'a> {
        Metadata(&'a [u8]),
        InlineData(&'a [u8]),
        FileBackedData {
            dirfd_index: u32,
            length: u64,
            filename: &'a [u8],
        },
    }

    #[derive(Debug, PartialEq, Eq)]
    enum DecodedChunk {
        Metadata(Vec<u8>),
        InlineData(Vec<u8>),
        FileBackedData {
            dirfd_index: u32,
            length: u64,
            filename: Vec<u8>,
        },
    }

    impl<'a> From<&Chunk<'a>> for DecodedChunk {
        fn from(c: &Chunk<'a>) -> Self {
            match c {
                Chunk::Metadata(d) => DecodedChunk::Metadata(d.to_vec()),
                Chunk::InlineData(d) => DecodedChunk::InlineData(d.to_vec()),
                Chunk::FileBackedData {
                    dirfd_index,
                    length,
                    filename,
                } => DecodedChunk::FileBackedData {
                    dirfd_index: *dirfd_index,
                    length: *length,
                    filename: filename.to_vec(),
                },
            }
        }
    }

    // -------------------------------------------------------------------------
    // Basic wire-format tests
    // -------------------------------------------------------------------------

    #[test]
    fn empty_stream_returns_none() {
        let mut reader = SplitdirfdstreamReader::new(b"".as_slice());
        assert_eq!(reader.next_chunk().unwrap(), None);
    }

    #[test]
    fn roundtrip_inline_only() {
        let (_, chunks) =
            roundtrip_stream(&[WriteCmd::Metadata(b"hello"), WriteCmd::Metadata(b"world")]);
        assert_eq!(
            chunks,
            vec![
                DecodedChunk::Metadata(b"hello".to_vec()),
                DecodedChunk::Metadata(b"world".to_vec()),
            ]
        );
    }

    #[test]
    fn roundtrip_external_only() {
        let (_, chunks) = roundtrip_stream(&[
            WriteCmd::FileBackedData {
                dirfd_index: 0,
                length: 100,
                filename: b"a/b",
            },
            WriteCmd::FileBackedData {
                dirfd_index: 3,
                length: 0,
                filename: b"x/y/z",
            },
        ]);
        assert_eq!(
            chunks,
            vec![
                DecodedChunk::FileBackedData {
                    dirfd_index: 0,
                    length: 100,
                    filename: b"a/b".to_vec()
                },
                DecodedChunk::FileBackedData {
                    dirfd_index: 3,
                    length: 0,
                    filename: b"x/y/z".to_vec()
                },
            ]
        );
    }

    #[test]
    fn roundtrip_mixed_interleaved() {
        let (_, chunks) = roundtrip_stream(&[
            WriteCmd::Metadata(b"header"),
            WriteCmd::FileBackedData {
                dirfd_index: 0,
                length: 7,
                filename: b"blob",
            },
            WriteCmd::Metadata(b"middle"),
            WriteCmd::FileBackedData {
                dirfd_index: 1,
                length: 3,
                filename: b"sub/c",
            },
            WriteCmd::Metadata(b"footer"),
        ]);
        assert_eq!(chunks.len(), 5);
        assert_eq!(chunks[0], DecodedChunk::Metadata(b"header".to_vec()));
        assert_eq!(
            chunks[1],
            DecodedChunk::FileBackedData {
                dirfd_index: 0,
                length: 7,
                filename: b"blob".to_vec()
            }
        );
        assert_eq!(chunks[2], DecodedChunk::Metadata(b"middle".to_vec()));
        assert_eq!(
            chunks[3],
            DecodedChunk::FileBackedData {
                dirfd_index: 1,
                length: 3,
                filename: b"sub/c".to_vec()
            }
        );
        assert_eq!(chunks[4], DecodedChunk::Metadata(b"footer".to_vec()));
    }

    #[test]
    fn empty_inline_is_no_op() {
        let (buf, chunks) = roundtrip_stream(&[
            WriteCmd::Metadata(b""),
            WriteCmd::Metadata(b"real"),
            WriteCmd::Metadata(b""),
        ]);
        // Only "real" produces a chunk; empties are silently dropped.
        assert_eq!(chunks, vec![DecodedChunk::Metadata(b"real".to_vec())]);
        // Buffer: 1-byte type + 4-byte u32 length + 4 bytes data
        assert_eq!(buf.len(), 9);
    }

    #[test]
    fn external_wire_layout() {
        // Verify the exact byte layout for a known external chunk.
        // dirfd_index=2, length=9, filename=b"ab"
        // Format: [0x02][9u64 LE][2u32 LE][2u32 LE][b'a',b'b']
        let mut buf = Vec::new();
        SplitdirfdstreamWriter::new(&mut buf)
            .write_file_backed_data(2, 9, b"ab")
            .unwrap();

        let expected: Vec<u8> = {
            let mut v = Vec::new();
            v.push(0x02u8); // type byte
            v.extend_from_slice(&9u64.to_le_bytes()); // content_length
            v.extend_from_slice(&2u32.to_le_bytes()); // dirfd_index
            v.extend_from_slice(&2u32.to_le_bytes()); // name_len
            v.extend_from_slice(b"ab"); // filename
            v
        };
        assert_eq!(buf, expected);
    }

    #[test]
    fn boundary_inline_sizes() {
        for &size in &[1usize, 7, 8, 9, 255, 256, 257, 4095, 4096, 4097] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let (buf, chunks) = roundtrip_stream(&[WriteCmd::Metadata(&data)]);

            // Wire layout: 1-byte type + 4-byte u32 length + `size` bytes
            assert_eq!(buf.len(), 5 + size, "buf.len() for size={size}");
            assert_eq!(buf[0], 0x00u8, "type byte for size={size}");
            let len_field = u32::from_le_bytes(buf[1..5].try_into().unwrap());
            assert_eq!(len_field, size as u32, "length field for size={size}");

            assert_eq!(
                chunks,
                vec![DecodedChunk::Metadata(data)],
                "data for size={size}"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Reader limit / boundary error tests (hand-crafted buffers)
    // -------------------------------------------------------------------------

    #[test]
    fn unknown_chunk_type_returns_error() {
        // A type byte that is not 0x00, 0x01, or 0x02 must yield UnknownChunkType.
        let buf = vec![0x03u8];
        let mut reader = SplitdirfdstreamReader::new(buf.as_slice());
        let err = reader.next_chunk().unwrap_err();
        assert!(
            matches!(err, Error::UnknownChunkType(0x03)),
            "expected UnknownChunkType(0x03), got {err:?}"
        );
    }

    #[test]
    fn error_unknown_chunk_type() {
        // Feeding byte 0x80 must yield UnknownChunkType(0x80).
        let buf = vec![0x80u8];
        let mut reader = SplitdirfdstreamReader::new(buf.as_slice());
        let err = reader.next_chunk().unwrap_err();
        assert!(
            matches!(err, Error::UnknownChunkType(0x80)),
            "expected UnknownChunkType(0x80), got {err:?}"
        );
    }

    #[test]
    fn error_filename_too_long_in_reader() {
        // [0x02][0u64 LE][0u32 LE][name_len as u32 LE] with name_len > MAX_FILENAME_LEN
        let name_len = MAX_FILENAME_LEN + 1;
        let mut buf = Vec::new();
        buf.push(0x02u8);
        buf.extend_from_slice(&0u64.to_le_bytes()); // content_length
        buf.extend_from_slice(&0u32.to_le_bytes()); // dirfd_index
        buf.extend_from_slice(&(name_len as u32).to_le_bytes()); // name_len
        let mut reader = SplitdirfdstreamReader::new(buf.as_slice());
        let err = reader.next_chunk().unwrap_err();
        assert!(
            matches!(err, Error::FilenameTooLong { len, max } if len == name_len && max == MAX_FILENAME_LEN),
            "expected FilenameTooLong, got {err:?}"
        );
    }

    #[test]
    fn error_inline_too_large() {
        // [0x00][(512 MiB) as u32 LE] — no body needed; length check fires first.
        let size: u32 = 512 * 1024 * 1024;
        let mut buf = Vec::new();
        buf.push(0x00u8);
        buf.extend_from_slice(&size.to_le_bytes());
        let mut reader = SplitdirfdstreamReader::new(buf.as_slice());
        let err = reader.next_chunk().unwrap_err();
        assert!(
            matches!(err, Error::InlineTooLarge { size: s, max } if s == 512*1024*1024 && max == MAX_INLINE_CHUNK_SIZE),
            "expected InlineTooLarge, got {err:?}"
        );
    }

    #[test]
    fn error_truncated_inline_content() {
        // [0x00][100u32 LE] then only 10 data bytes; Truncated{expected:100}.
        let mut buf = Vec::new();
        buf.push(0x00u8);
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 10]);
        let mut reader = SplitdirfdstreamReader::new(buf.as_slice());
        let err = reader.next_chunk().unwrap_err();
        assert!(
            matches!(err, Error::Truncated { expected: 100 }),
            "expected Truncated{{100}}, got {err:?}"
        );
    }

    #[test]
    fn error_truncated_file_backed_data() {
        // [0x02] then only 5 of the 16 required header bytes.
        let mut buf = Vec::new();
        buf.push(0x02u8);
        buf.extend_from_slice(&[0u8; 5]);
        let mut reader = SplitdirfdstreamReader::new(buf.as_slice());
        let err = reader.next_chunk().unwrap_err();
        assert!(
            matches!(err, Error::Truncated { .. }),
            "expected Truncated, got {err:?}"
        );
    }

    #[test]
    fn error_truncated_prefix_after_type_byte() {
        // Type byte 0x00 is read, then EOF before the 4-byte length — Truncated{expected:4}.
        let buf = vec![0x00u8];
        let mut reader = SplitdirfdstreamReader::new(buf.as_slice());
        let err = reader.next_chunk().unwrap_err();
        assert!(
            matches!(err, Error::Truncated { expected: 4 }),
            "expected Truncated{{4}}, got {err:?}"
        );
    }

    #[test]
    fn error_dirfd_index_out_of_range_via_reconstruct() {
        // External chunk references dirfd_index=5 but we supply 1 dirfd.
        let tmp = tempfile::tempdir().unwrap();
        let dir_fd = rustix::fs::open(
            tmp.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();

        let mut buf = Vec::new();
        SplitdirfdstreamWriter::new(&mut buf)
            .write_file_backed_data(5, 0, b"dummy")
            .unwrap();

        let dirfds: &[BorrowedFd<'_>] = &[dir_fd.as_fd()];
        let mut out = Vec::new();
        let err = reconstruct(buf.as_slice(), dirfds, &mut out).unwrap_err();
        assert!(
            matches!(err, Error::DirfdIndexOutOfRange { index: 5, count: 1 }),
            "expected DirfdIndexOutOfRange, got {err:?}"
        );
    }

    // -------------------------------------------------------------------------
    // validate_filename tests (data-driven)
    // -------------------------------------------------------------------------

    /// Expected outcome for a validate_filename test case.
    #[derive(Debug)]
    enum FilenameExpect {
        /// validate_filename must return Ok(()).
        Ok,
        /// validate_filename must return Err(InvalidFilename { reason }) where
        /// `reason` contains the given substring.
        InvalidFilename(&'static str),
        /// validate_filename must return Err(FilenameTooLong { .. }).
        TooLong,
    }

    #[test]
    fn validate_filename_cases() {
        let long_ok: Vec<u8> = vec![b'a'; MAX_FILENAME_LEN];
        let long_bad: Vec<u8> = vec![b'a'; MAX_FILENAME_LEN + 1];

        let cases: &[(&[u8], FilenameExpect)] = &[
            // ── rejection cases ──────────────────────────────────────────────
            (b"", FilenameExpect::InvalidFilename("empty filename")),
            (b"/abs", FilenameExpect::InvalidFilename("absolute path")),
            (b"a/../b", FilenameExpect::InvalidFilename("`..` component")),
            (
                b"../escape",
                FilenameExpect::InvalidFilename("`..` component"),
            ),
            (b"a/b/..", FilenameExpect::InvalidFilename("`..` component")),
            (b"..", FilenameExpect::InvalidFilename("`..` component")), // D2: bare `..`
            (b"foo\0bar", FilenameExpect::InvalidFilename("embedded NUL")),
            (&long_bad, FilenameExpect::TooLong),
            // ── acceptance cases ─────────────────────────────────────────────
            (b"a/b/c", FilenameExpect::Ok),   // normal relative path
            (b"a/./b", FilenameExpect::Ok),   // `.` is allowed
            (&long_ok, FilenameExpect::Ok),   // exactly MAX_FILENAME_LEN
            (b"..foo", FilenameExpect::Ok),   // D5: `..`-prefix but not a component
            (b"foo..", FilenameExpect::Ok),   // D5: `..`-suffix but not a component
            (b"a/..foo", FilenameExpect::Ok), // D5: `..`-prefixed component
            (b"foo../b", FilenameExpect::Ok), // D5: `..`-suffixed component in path
        ];

        for (filename, expect) in cases {
            let result = validate_filename(filename);
            match expect {
                FilenameExpect::Ok => {
                    assert!(
                        result.is_ok(),
                        "validate_filename({filename:?}) should be Ok, got {result:?}"
                    );
                }
                FilenameExpect::InvalidFilename(substr) => {
                    assert!(
                        matches!(&result, Err(Error::InvalidFilename { reason }) if reason.contains(substr)),
                        "validate_filename({filename:?}) should be InvalidFilename containing {substr:?}, got {result:?}"
                    );
                }
                FilenameExpect::TooLong => {
                    assert!(
                        matches!(&result, Err(Error::FilenameTooLong { .. })),
                        "validate_filename({filename:?}) should be FilenameTooLong, got {result:?}"
                    );
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Reconstruction tests
    // -------------------------------------------------------------------------

    fn open_dir(path: &std::path::Path) -> OwnedFd {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    #[test]
    fn reconstruct_inline_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dir_fd = open_dir(tmp.path());

        let mut buf = Vec::new();
        {
            let mut w = SplitdirfdstreamWriter::new(&mut buf);
            w.write_metadata(b"Hello, ").unwrap();
            w.write_metadata(b"world!").unwrap();
            w.finish().unwrap();
        }

        let dirfds: &[BorrowedFd<'_>] = &[dir_fd.as_fd()];
        let mut out = Vec::new();
        let n = reconstruct(buf.as_slice(), dirfds, &mut out).unwrap();
        assert_eq!(out, b"Hello, world!");
        assert_eq!(n, 13);
    }

    #[test]
    fn reconstruct_with_externals() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a"), b"FILEONE").unwrap();
        std::fs::create_dir(tmp.path().join("subdir")).unwrap();
        std::fs::write(tmp.path().join("subdir/b"), b"FILETWO").unwrap();

        let dir_fd = open_dir(tmp.path());

        let mut buf = Vec::new();
        {
            let mut w = SplitdirfdstreamWriter::new(&mut buf);
            w.write_metadata(b"[").unwrap();
            w.write_file_backed_data(0, 7, b"a").unwrap();
            w.write_metadata(b"|").unwrap();
            w.write_file_backed_data(0, 7, b"subdir/b").unwrap();
            w.write_metadata(b"]").unwrap();
            w.finish().unwrap();
        }

        let dirfds: &[BorrowedFd<'_>] = &[dir_fd.as_fd()];
        let mut out = Vec::new();
        let n = reconstruct(buf.as_slice(), dirfds, &mut out).unwrap();
        assert_eq!(out, b"[FILEONE|FILETWO]");
        assert_eq!(n, 17);
    }

    #[test]
    fn reconstruct_same_file_twice() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("data"), b"REPEAT").unwrap();
        let dir_fd = open_dir(tmp.path());

        let mut buf = Vec::new();
        {
            let mut w = SplitdirfdstreamWriter::new(&mut buf);
            w.write_file_backed_data(0, 6, b"data").unwrap();
            w.write_metadata(b"-").unwrap();
            w.write_file_backed_data(0, 6, b"data").unwrap();
            w.finish().unwrap();
        }

        let dirfds: &[BorrowedFd<'_>] = &[dir_fd.as_fd()];
        let mut out = Vec::new();
        let n = reconstruct(buf.as_slice(), dirfds, &mut out).unwrap();
        // pread always starts from offset 0, so both refs read the full file.
        assert_eq!(out, b"REPEAT-REPEAT");
        assert_eq!(n, 13);
    }

    #[test]
    fn reconstruct_length_shorter_than_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("big"), b"ABCDEFGH").unwrap(); // 8 bytes
        let dir_fd = open_dir(tmp.path());

        let mut buf = Vec::new();
        {
            let mut w = SplitdirfdstreamWriter::new(&mut buf);
            w.write_file_backed_data(0, 4, b"big").unwrap(); // only first 4 bytes
            w.finish().unwrap();
        }

        let dirfds: &[BorrowedFd<'_>] = &[dir_fd.as_fd()];
        let mut out = Vec::new();
        let n = reconstruct(buf.as_slice(), dirfds, &mut out).unwrap();
        assert_eq!(out, b"ABCD");
        assert_eq!(n, 4);
    }

    #[test]
    fn reconstruct_length_longer_than_file_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("small"), b"HI").unwrap(); // 2 bytes
        let dir_fd = open_dir(tmp.path());

        let mut buf = Vec::new();
        {
            let mut w = SplitdirfdstreamWriter::new(&mut buf);
            w.write_file_backed_data(0, 100, b"small").unwrap(); // declare 100, file has 2
            w.finish().unwrap();
        }

        let dirfds: &[BorrowedFd<'_>] = &[dir_fd.as_fd()];
        let mut out = Vec::new();
        let err = reconstruct(buf.as_slice(), dirfds, &mut out).unwrap_err();
        assert!(
            matches!(
                err,
                Error::ExternalTooShort {
                    declared: 100,
                    actual: 2
                }
            ),
            "expected ExternalTooShort, got {err:?}"
        );
    }

    /// Build a raw splitdirfdstream buffer containing a single FileBackedData chunk
    /// with a given `length` field and filename, without going through
    /// the writer (so we can set length=u64::MAX which the writer itself would
    /// also accept).
    fn make_external_chunk_buf(dirfd_index: u32, length: u64, filename: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x02u8); // type byte
        buf.extend_from_slice(&length.to_le_bytes()); // content_length
        buf.extend_from_slice(&dirfd_index.to_le_bytes()); // dirfd_index
        buf.extend_from_slice(&(filename.len() as u32).to_le_bytes()); // name_len
        buf.extend_from_slice(filename); // filename
        buf
    }

    #[test]
    fn reconstruct_length_u64_max_does_not_overflow() {
        // Guards the buffer-sizing path: `BUF_SIZE.min(usize::try_from(length).unwrap_or(usize::MAX))`
        // must not panic or produce a wrong result when length = u64::MAX.
        // The file has only a few real bytes; the first pread reads them, the
        // second sees EOF and must return ExternalTooShort — not a panic.
        let tmp = tempfile::tempdir().unwrap();
        let fname = b"tiny";
        std::fs::write(tmp.path().join("tiny"), b"abc").unwrap(); // 3 bytes
        let dir_fd = open_dir(tmp.path());

        let buf = make_external_chunk_buf(0, u64::MAX, fname);

        let dirfds: &[BorrowedFd<'_>] = &[dir_fd.as_fd()];
        let mut out = Vec::new();
        let err = reconstruct(buf.as_slice(), dirfds, &mut out).unwrap_err();
        assert!(
            matches!(
                err,
                Error::ExternalTooShort {
                    declared: u64::MAX,
                    ..
                }
            ),
            "expected ExternalTooShort with declared=u64::MAX, got {err:?}"
        );
    }

    #[test]
    fn reconstruct_multiple_dirfds() {
        let tmp0 = tempfile::tempdir().unwrap();
        let tmp1 = tempfile::tempdir().unwrap();
        std::fs::write(tmp0.path().join("x"), b"FROM0").unwrap();
        std::fs::write(tmp1.path().join("y"), b"FROM1").unwrap();
        let dir0 = open_dir(tmp0.path());
        let dir1 = open_dir(tmp1.path());

        let mut buf = Vec::new();
        {
            let mut w = SplitdirfdstreamWriter::new(&mut buf);
            w.write_file_backed_data(0, 5, b"x").unwrap();
            w.write_metadata(b"+").unwrap();
            w.write_file_backed_data(1, 5, b"y").unwrap();
            w.finish().unwrap();
        }

        let dirfds: &[BorrowedFd<'_>] = &[dir0.as_fd(), dir1.as_fd()];
        let mut out = Vec::new();
        let n = reconstruct(buf.as_slice(), dirfds, &mut out).unwrap();
        assert_eq!(out, b"FROM0+FROM1");
        assert_eq!(n, 11);
    }

    // -------------------------------------------------------------------------
    // open_beneath safety tests
    // -------------------------------------------------------------------------

    #[test]
    fn open_beneath_rejects_escape_via_dotdot() {
        // validate_filename catches ".." before any syscall, so this is
        // kernel-independent.
        let tmp = tempfile::tempdir().unwrap();
        let dir_fd = open_dir(tmp.path());
        let err = open_beneath(dir_fd.as_fd(), b"../anything").unwrap_err();
        assert!(
            matches!(
                err,
                Error::InvalidFilename {
                    reason: "`..` component"
                }
            ),
            "expected InvalidFilename, got {err:?}"
        );
    }

    #[test]
    fn open_beneath_follows_symlink_within_base() {
        // A symlink whose target resolves *within* the base directory must be
        // followed successfully — this is the new behaviour after removing
        // RESOLVE_NO_SYMLINKS.  The l/<linkid> symlinks created by
        // containers/storage are exactly this kind of within-base symlink.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("target"), b"data").unwrap();
        std::os::unix::fs::symlink("target", tmp.path().join("link")).unwrap();

        let dir_fd = open_dir(tmp.path());
        let result = open_beneath(dir_fd.as_fd(), b"link");
        assert!(
            result.is_ok(),
            "symlink resolving within the base directory must be followed; got {result:?}"
        );
    }

    #[test]
    fn open_beneath_rejects_escape_via_symlink() {
        // A symlink whose target escapes the base directory must be rejected
        // (RESOLVE_BENEATH) on kernels with openat2.  On old kernels the
        // fallback cannot enforce this; skip in that case.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("real")).unwrap();
        std::fs::write(tmp.path().join("real/passwd"), b"data").unwrap();
        // Symlink to /etc — outside the base dir.
        std::os::unix::fs::symlink("/etc", tmp.path().join("link")).unwrap();

        let dir_fd = open_dir(tmp.path());

        // Probe openat2 availability.
        let probe = rustix::fs::openat2(
            dir_fd.as_fd(),
            rustix::cstr!("real/passwd"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
        );
        if let Err(e) = probe
            && e == Errno::NOSYS
        {
            // openat2 not available: skip this test.
            return;
        }

        // openat2 is available: symlink escaping outside the base must be rejected.
        let result = open_beneath(dir_fd.as_fd(), b"link/passwd");
        assert!(
            result.is_err(),
            "openat2 path must reject symlink escaping the base directory; got Ok"
        );
    }

    // -------------------------------------------------------------------------
    // InlineData chunk tests
    // -------------------------------------------------------------------------

    #[test]
    fn file_content_wire_layout() {
        // Exact bytes: [0x01][5u32 LE][b"hello"]
        let data = b"hello";
        let mut buf = Vec::new();
        SplitdirfdstreamWriter::new(&mut buf)
            .write_inline_data(data)
            .unwrap();

        let expected: Vec<u8> = {
            let mut v = Vec::new();
            v.push(0x01u8); // type byte
            v.extend_from_slice(&5u32.to_le_bytes()); // length
            v.extend_from_slice(b"hello"); // data
            v
        };
        assert_eq!(buf, expected, "InlineData wire layout mismatch");
    }

    #[test]
    fn roundtrip_file_content_zero_bytes() {
        // Zero-length FileContent must still be written and round-trip.
        let (buf, chunks) = roundtrip_stream(&[WriteCmd::InlineData(b"")]);
        // 1-byte type + 4-byte u32 length + 0 data = 5 bytes
        assert_eq!(buf.len(), 5, "zero-length InlineData should be 5 bytes");
        assert_eq!(chunks, vec![DecodedChunk::InlineData(vec![])]);
    }

    #[test]
    fn roundtrip_file_content() {
        for size in [0usize, 1, 64, 65, 4096] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let (buf, chunks) = roundtrip_stream(&[WriteCmd::InlineData(&data)]);

            // Wire layout: 1-byte type + 4-byte u32 length + `size` bytes
            assert_eq!(buf.len(), 5 + size, "buf.len() for InlineData size={size}");
            assert_eq!(
                chunks,
                vec![DecodedChunk::InlineData(data)],
                "decoded data for size={size}"
            );
        }
    }

    #[test]
    fn reconstruct_file_content() {
        // FileContent in a stream reconstructs to the verbatim bytes.
        let tmp = tempfile::tempdir().unwrap();
        let dir_fd = open_dir(tmp.path());

        let mut buf = Vec::new();
        {
            let mut w = SplitdirfdstreamWriter::new(&mut buf);
            w.write_metadata(b"[").unwrap();
            w.write_inline_data(b"CONTENT").unwrap();
            w.write_metadata(b"]").unwrap();
            w.finish().unwrap();
        }

        let dirfds: &[BorrowedFd<'_>] = &[dir_fd.as_fd()];
        let mut out = Vec::new();
        let n = reconstruct(buf.as_slice(), dirfds, &mut out).unwrap();
        assert_eq!(out, b"[CONTENT]");
        assert_eq!(n, 9);
    }

    // -------------------------------------------------------------------------
    // Proptest suite
    // -------------------------------------------------------------------------

    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        /// Strategy: 1–4 path components of [a-z0-9]{1,8} joined by '/',
        /// always stays below MAX_FILENAME_LEN and never contains `..`.
        fn filename_strategy() -> impl Strategy<Value = Vec<u8>> {
            let component = prop::string::string_regex("[a-z0-9]{1,8}").unwrap();
            prop::collection::vec(component, 1..=4).prop_map(|parts| parts.join("/").into_bytes())
        }

        /// A chunk that carries its own content for proptest generation.
        #[derive(Debug, Clone)]
        enum TestChunk {
            Metadata(Vec<u8>),
            InlineData(Vec<u8>),
            FileBackedData {
                /// Unnormalized index in `0..4`; normalized to `% num_dirs` at test time.
                dirfd_index: usize,
                filename: Vec<u8>,
                content: Vec<u8>,
            },
        }

        fn metadata_strategy() -> impl Strategy<Value = TestChunk> {
            prop::collection::vec(any::<u8>(), 1..=4096).prop_map(TestChunk::Metadata)
        }

        fn file_backed_data_strategy() -> impl Strategy<Value = TestChunk> {
            (
                0usize..4,
                filename_strategy(),
                prop::collection::vec(any::<u8>(), 0..=8192),
            )
                .prop_map(|(idx, name, content)| TestChunk::FileBackedData {
                    dirfd_index: idx,
                    filename: name,
                    content,
                })
        }

        fn inline_data_strategy() -> impl Strategy<Value = TestChunk> {
            prop::collection::vec(any::<u8>(), 0..=4096).prop_map(TestChunk::InlineData)
        }

        fn chunk_strategy() -> impl Strategy<Value = TestChunk> {
            prop_oneof![
                metadata_strategy(),
                file_backed_data_strategy(),
                inline_data_strategy()
            ]
        }

        fn chunks_strategy() -> impl Strategy<Value = Vec<TestChunk>> {
            prop::collection::vec(chunk_strategy(), 0..=32)
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn proptest_roundtrip(chunks in chunks_strategy()) {
                use std::collections::HashMap;

                let num_dirs = 4usize;
                let tmpdirs: Vec<tempfile::TempDir> = (0..num_dirs)
                    .map(|_| tempfile::tempdir().unwrap())
                    .collect();

                // Normalize chunks: assign each External chunk a name of the
                // form "N/<orig>" where N is a small bucket index (0..=3).
                // Using only 4 buckets instead of a per-chunk unique counter
                // means some chunks will intentionally share (dir_idx, name).
                //
                // When two chunks share a (dir_idx, name) key, the *first*
                // chunk's content wins: its bytes are written to disk and both
                // references reconstruct the same content, so the expected
                // output stays well-defined.  This exercises the pread-from-
                // offset-0 restart property (same file opened twice).
                #[derive(Debug)]
                enum ResolvedChunk {
                    Metadata(Vec<u8>),
                    InlineData(Vec<u8>),
                    FileBackedData { dir_idx: usize, unique_name: Vec<u8>, content: Vec<u8> },
                }

                // Map (dir_idx, unique_name) -> first-seen content.
                let mut content_map: HashMap<(usize, Vec<u8>), Vec<u8>> = HashMap::new();

                let mut resolved: Vec<ResolvedChunk> = Vec::with_capacity(chunks.len());
                let mut ext_counter = 0usize;
                for chunk in &chunks {
                    match chunk {
                        TestChunk::Metadata(data) => {
                            resolved.push(ResolvedChunk::Metadata(data.clone()));
                        }
                        TestChunk::InlineData(data) => {
                            resolved.push(ResolvedChunk::InlineData(data.clone()));
                        }
                        TestChunk::FileBackedData { dirfd_index, filename, content } => {
                            let dir_idx = dirfd_index % num_dirs;
                            // Flatten any '/' in the generated name so a file
                            // path can never be a *prefix* of another file path
                            // (which on disk would require the prefix to be both
                            // a regular file and a directory, an impossible
                            // fixture that yields ENOTDIR). The library itself
                            // supports nested paths; this only keeps the
                            // on-disk test fixtures internally consistent.
                            let orig = std::str::from_utf8(filename)
                                .unwrap()
                                .replace('/', "_");
                            // Bucket index cycles through 0..=3 so collisions
                            // happen with probability ~(1 - 3/4^k) for k chunks,
                            // exercising the "same file referenced twice" path.
                            let bucket = ext_counter % 4;
                            ext_counter += 1;
                            let unique_name =
                                format!("{bucket}/{orig}").into_bytes();
                            // Canonical content: first writer wins.
                            let key = (dir_idx, unique_name.clone());
                            let canonical = content_map
                                .entry(key)
                                .or_insert_with(|| content.clone())
                                .clone();
                            resolved.push(ResolvedChunk::FileBackedData {
                                dir_idx,
                                unique_name,
                                content: canonical,
                            });
                        }
                    }
                }

                // Materialize external files on disk (write each unique path once;
                // duplicates are skipped because the file already exists).
                for chunk in &resolved {
                    if let ResolvedChunk::FileBackedData { dir_idx, unique_name, content } = chunk {
                        let path = tmpdirs[*dir_idx].path().join(
                            std::str::from_utf8(unique_name).unwrap()
                        );
                        if !path.exists() {
                            if let Some(parent) = path.parent() {
                                std::fs::create_dir_all(parent).unwrap();
                            }
                            std::fs::write(&path, content).unwrap();
                        }
                    }
                }

                // Build the stream and expected output.
                let mut stream_buf = Vec::new();
                let mut expected_output: Vec<u8> = Vec::new();
                {
                    let mut w = SplitdirfdstreamWriter::new(&mut stream_buf);
                    for chunk in &resolved {
                        match chunk {
                            ResolvedChunk::Metadata(data) => {
                                w.write_metadata(data).unwrap();
                                expected_output.extend_from_slice(data);
                            }
                            ResolvedChunk::InlineData(data) => {
                                w.write_inline_data(data).unwrap();
                                expected_output.extend_from_slice(data);
                            }
                            ResolvedChunk::FileBackedData { dir_idx, unique_name, content } => {
                                let len = content.len() as u64;
                                w.write_file_backed_data(*dir_idx as u32, len, unique_name).unwrap();
                                expected_output.extend_from_slice(content);
                            }
                        }
                    }
                    w.finish().unwrap();
                }

                // Open dir fds.
                let dir_fds: Vec<OwnedFd> = tmpdirs
                    .iter()
                    .map(|d| open_dir(d.path()))
                    .collect();
                let borrowed: Vec<BorrowedFd<'_>> = dir_fds.iter().map(|fd| fd.as_fd()).collect();

                // Verify chunk sequence matches what we wrote.
                {
                    let mut reader = SplitdirfdstreamReader::new(stream_buf.as_slice());
                    let mut res_iter = resolved.iter();
                    while let Some(chunk) = reader.next_chunk().unwrap() {
                        let expected = res_iter.next().unwrap();
                        match (&chunk, expected) {
                            (Chunk::Metadata(data), ResolvedChunk::Metadata(exp)) => {
                                prop_assert_eq!(*data, exp.as_slice());
                            }
                            (Chunk::InlineData(data), ResolvedChunk::InlineData(exp)) => {
                                prop_assert_eq!(*data, exp.as_slice());
                            }
                            (
                                Chunk::FileBackedData { dirfd_index, length, filename },
                                ResolvedChunk::FileBackedData { dir_idx, unique_name, content },
                            ) => {
                                prop_assert_eq!(*dirfd_index, *dir_idx as u32);
                                prop_assert_eq!(*length, content.len() as u64);
                                prop_assert_eq!(*filename, unique_name.as_slice());
                            }
                            _ => {
                                return Err(TestCaseError::fail("chunk type mismatch"));
                            }
                        }
                    }
                }

                // Verify reconstruction produces the expected concatenation.
                let mut out = Vec::new();
                reconstruct(stream_buf.as_slice(), &borrowed, &mut out).unwrap();
                prop_assert_eq!(out, expected_output);
            }
        }
    }
}
