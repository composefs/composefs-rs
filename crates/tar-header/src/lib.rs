//! Zerocopy-based raw tar header structs for safe parsing.
//!
//! This crate provides zero-copy parsing of tar archive headers, supporting
//! POSIX.1-1988, UStar (POSIX.1-2001), and GNU tar formats. All header structs
//! use the [`zerocopy`] crate for safe, efficient memory-mapped access without
//! allocations.
//!
//! # Header Formats
//!
//! Tar archives have evolved through several formats:
//!
//! - **Old (POSIX.1-1988)**: The original Unix tar format with basic fields
//! - **UStar (POSIX.1-2001)**: Adds `magic`/`version`, user/group names, and path prefix
//! - **GNU tar**: Extends UStar with sparse file support and long name/link extensions
//!
//! # Header Field Layout
//!
//! All tar headers are 512 bytes. The common fields (offsets 0-156) are shared:
//!
//! | Offset | Size | Field     | Description                              |
//! |--------|------|-----------|------------------------------------------|
//! | 0      | 100  | name      | File path (null-terminated if < 100)     |
//! | 100    | 8    | mode      | File mode in octal ASCII                 |
//! | 108    | 8    | uid       | Owner user ID in octal ASCII             |
//! | 116    | 8    | gid       | Owner group ID in octal ASCII            |
//! | 124    | 12   | size      | File size in octal ASCII                 |
//! | 136    | 12   | mtime     | Modification time (Unix epoch, octal)    |
//! | 148    | 8    | checksum  | Header checksum in octal ASCII           |
//! | 156    | 1    | typeflag  | Entry type (see [`EntryType`])           |
//! | 157    | 100  | linkname  | Link target for hard/symbolic links      |
//!
//! **UStar extension** (offsets 257-500):
//!
//! | Offset | Size | Field     |
//! |--------|------|-----------|
//! | 257    | 6    | magic     | "ustar\0"                                |
//! | 263    | 2    | version   | "00"                                     |
//! | 265    | 32   | uname     | Owner user name                          |
//! | 297    | 32   | gname     | Owner group name                         |
//! | 329    | 8    | devmajor  | Device major number                      |
//! | 337    | 8    | devminor  | Device minor number                      |
//! | 345    | 155  | prefix    | Path prefix for long names               |
//!
//! **GNU extension** (offsets 257-500, replaces prefix):
//!
//! | Offset | Size | Field       |
//! |--------|------|-------------|
//! | 345    | 12   | atime       | Access time                              |
//! | 357    | 12   | ctime       | Change time                              |
//! | 369    | 12   | offset      | Multivolume offset                       |
//! | 381    | 4    | longnames   | (deprecated)                             |
//! | 386    | 96   | sparse      | 4 × 24-byte sparse descriptors           |
//! | 482    | 1    | isextended  | More sparse headers follow               |
//! | 483    | 12   | realsize    | Real size of sparse file                 |
//!
//! # Example
//!
//! ```
//! use tar_header::{Header, EntryType};
//!
//! // Parse a header from raw bytes
//! let data = [0u8; 512]; // Would normally come from a tar file
//! let header = Header::from_bytes(&data).unwrap();
//!
//! // Access header fields
//! let entry_type = header.entry_type();
//! let path = header.path_bytes();
//! ```
//!
//! # Streaming Parser
//!
//! For parsing complete tar archives with automatic handling of GNU and PAX
//! extensions, see the [`stream`] module:
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::BufReader;
//! use tar_header::stream::{TarStreamParser, Limits};
//!
//! let file = File::open("archive.tar").unwrap();
//! let mut parser = TarStreamParser::new(BufReader::new(file), Limits::default());
//!
//! while let Some(entry) = parser.next_entry().unwrap() {
//!     println!("{} ({} bytes)", entry.path_lossy(), entry.size);
//!     let size = entry.size;
//!     drop(entry);
//!     parser.skip_content(size).unwrap();
//! }
//! ```

pub mod stream;

use std::fmt;

use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Size of a tar header block in bytes.
pub const HEADER_SIZE: usize = 512;

/// Magic string for UStar format headers ("ustar\0").
pub const USTAR_MAGIC: &[u8; 6] = b"ustar\0";

/// Version field for UStar format headers ("00").
pub const USTAR_VERSION: &[u8; 2] = b"00";

/// Magic string for GNU tar format headers ("ustar ").
pub const GNU_MAGIC: &[u8; 6] = b"ustar ";

/// Version field for GNU tar format headers (" \0").
pub const GNU_VERSION: &[u8; 2] = b" \0";

/// Errors that can occur when parsing tar headers.
#[derive(Debug, Error)]
pub enum HeaderError {
    /// The provided data is too short to contain a header.
    #[error("insufficient data: expected {HEADER_SIZE} bytes, got {0}")]
    InsufficientData(usize),

    /// An octal field contains invalid characters.
    #[error("invalid octal field: {0:?}")]
    InvalidOctal(Vec<u8>),

    /// The header checksum does not match the computed value.
    #[error("checksum mismatch: expected {expected}, computed {computed}")]
    ChecksumMismatch {
        /// The checksum value stored in the header.
        expected: u64,
        /// The checksum computed from the header bytes.
        computed: u64,
    },
}

/// Result type for header parsing operations.
pub type Result<T> = std::result::Result<T, HeaderError>;

// ============================================================================
// Raw Header Structs
// ============================================================================

/// Raw 512-byte tar header block.
///
/// This is the most basic representation of a tar header, treating the
/// entire block as an opaque byte array. Use [`Header`] for a higher-level
/// interface with accessor methods.
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawHeader {
    /// The raw header bytes.
    pub bytes: [u8; 512],
}

impl Default for RawHeader {
    fn default() -> Self {
        Self { bytes: [0u8; 512] }
    }
}

impl fmt::Debug for RawHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawHeader")
            .field("name", &truncate_null(&self.bytes[0..100]))
            .finish_non_exhaustive()
    }
}

/// Old-style (POSIX.1-1988) tar header with named fields.
///
/// This represents the original Unix tar format. Fields after `linkname`
/// are undefined in this format and may contain garbage. See module-level
/// documentation for the field layout table.
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct OldHeader {
    /// File path name (null-terminated if shorter than 100 bytes).
    pub name: [u8; 100],
    /// File mode in octal ASCII.
    pub mode: [u8; 8],
    /// Owner user ID in octal ASCII.
    pub uid: [u8; 8],
    /// Owner group ID in octal ASCII.
    pub gid: [u8; 8],
    /// File size in octal ASCII.
    pub size: [u8; 12],
    /// Modification time as Unix timestamp in octal ASCII.
    pub mtime: [u8; 12],
    /// Header checksum in octal ASCII.
    pub checksum: [u8; 8],
    /// Entry type flag.
    pub typeflag: u8,
    /// Link target name for hard/symbolic links.
    pub linkname: [u8; 100],
    /// Padding to fill the 512-byte block.
    pub pad: [u8; 255],
}

impl Default for OldHeader {
    fn default() -> Self {
        Self {
            name: [0u8; 100],
            mode: [0u8; 8],
            uid: [0u8; 8],
            gid: [0u8; 8],
            size: [0u8; 12],
            mtime: [0u8; 12],
            checksum: [0u8; 8],
            typeflag: 0,
            linkname: [0u8; 100],
            pad: [0u8; 255],
        }
    }
}

impl fmt::Debug for OldHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OldHeader")
            .field("name", &String::from_utf8_lossy(truncate_null(&self.name)))
            .field("mode", &String::from_utf8_lossy(truncate_null(&self.mode)))
            .field("typeflag", &self.typeflag)
            .finish_non_exhaustive()
    }
}

/// UStar (POSIX.1-2001) tar header format.
///
/// This format adds a magic number, version, user/group names, device
/// numbers for special files, and a path prefix for long filenames.
/// See module-level documentation for the field layout table.
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct UstarHeader {
    /// File path name (null-terminated if shorter than 100 bytes).
    pub name: [u8; 100],
    /// File mode in octal ASCII.
    pub mode: [u8; 8],
    /// Owner user ID in octal ASCII.
    pub uid: [u8; 8],
    /// Owner group ID in octal ASCII.
    pub gid: [u8; 8],
    /// File size in octal ASCII.
    pub size: [u8; 12],
    /// Modification time as Unix timestamp in octal ASCII.
    pub mtime: [u8; 12],
    /// Header checksum in octal ASCII.
    pub checksum: [u8; 8],
    /// Entry type flag.
    pub typeflag: u8,
    /// Link target name for hard/symbolic links.
    pub linkname: [u8; 100],
    /// Magic string identifying the format ("ustar\0" for UStar).
    pub magic: [u8; 6],
    /// Format version ("00" for UStar).
    pub version: [u8; 2],
    /// Owner user name (null-terminated).
    pub uname: [u8; 32],
    /// Owner group name (null-terminated).
    pub gname: [u8; 32],
    /// Device major number in octal ASCII (for special files).
    pub devmajor: [u8; 8],
    /// Device minor number in octal ASCII (for special files).
    pub devminor: [u8; 8],
    /// Path prefix for names longer than 100 bytes.
    pub prefix: [u8; 155],
    /// Padding to fill the 512-byte block.
    pub pad: [u8; 12],
}

impl Default for UstarHeader {
    fn default() -> Self {
        let mut header = Self {
            name: [0u8; 100],
            mode: [0u8; 8],
            uid: [0u8; 8],
            gid: [0u8; 8],
            size: [0u8; 12],
            mtime: [0u8; 12],
            checksum: [0u8; 8],
            typeflag: 0,
            linkname: [0u8; 100],
            magic: [0u8; 6],
            version: [0u8; 2],
            uname: [0u8; 32],
            gname: [0u8; 32],
            devmajor: [0u8; 8],
            devminor: [0u8; 8],
            prefix: [0u8; 155],
            pad: [0u8; 12],
        };
        header.magic.copy_from_slice(USTAR_MAGIC);
        header.version.copy_from_slice(USTAR_VERSION);
        header
    }
}

impl fmt::Debug for UstarHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UstarHeader")
            .field("name", &String::from_utf8_lossy(truncate_null(&self.name)))
            .field("mode", &String::from_utf8_lossy(truncate_null(&self.mode)))
            .field("typeflag", &self.typeflag)
            .field("magic", &self.magic)
            .field(
                "uname",
                &String::from_utf8_lossy(truncate_null(&self.uname)),
            )
            .finish_non_exhaustive()
    }
}

/// GNU tar sparse file chunk descriptor.
///
/// Each descriptor specifies a region of data in a sparse file.
/// Both offset and numbytes are 12-byte octal ASCII fields.
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct GnuSparseHeader {
    /// Byte offset of this chunk within the file.
    pub offset: [u8; 12],
    /// Number of bytes in this chunk.
    pub numbytes: [u8; 12],
}

impl fmt::Debug for GnuSparseHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GnuSparseHeader")
            .field("offset", &parse_octal(&self.offset).ok())
            .field("numbytes", &parse_octal(&self.numbytes).ok())
            .finish()
    }
}

/// GNU tar header format with sparse file support.
///
/// This format extends UStar with support for sparse files, access/creation
/// times, and long name handling. The prefix field is replaced with
/// additional metadata. See module-level documentation for the field layout table.
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct GnuHeader {
    /// File path name (null-terminated if shorter than 100 bytes).
    pub name: [u8; 100],
    /// File mode in octal ASCII.
    pub mode: [u8; 8],
    /// Owner user ID in octal ASCII.
    pub uid: [u8; 8],
    /// Owner group ID in octal ASCII.
    pub gid: [u8; 8],
    /// File size in octal ASCII (for sparse files, this is the size on disk).
    pub size: [u8; 12],
    /// Modification time as Unix timestamp in octal ASCII.
    pub mtime: [u8; 12],
    /// Header checksum in octal ASCII.
    pub checksum: [u8; 8],
    /// Entry type flag.
    pub typeflag: u8,
    /// Link target name for hard/symbolic links.
    pub linkname: [u8; 100],
    /// Magic string identifying the format ("ustar " for GNU).
    pub magic: [u8; 6],
    /// Format version (" \0" for GNU).
    pub version: [u8; 2],
    /// Owner user name (null-terminated).
    pub uname: [u8; 32],
    /// Owner group name (null-terminated).
    pub gname: [u8; 32],
    /// Device major number in octal ASCII (for special files).
    pub devmajor: [u8; 8],
    /// Device minor number in octal ASCII (for special files).
    pub devminor: [u8; 8],
    /// Access time in octal ASCII.
    pub atime: [u8; 12],
    /// Creation time in octal ASCII.
    pub ctime: [u8; 12],
    /// Offset for multivolume archives.
    pub offset: [u8; 12],
    /// Long names support (deprecated).
    pub longnames: [u8; 4],
    /// Unused padding byte.
    pub unused: u8,
    /// Sparse file chunk descriptors (4 entries).
    pub sparse: [GnuSparseHeader; 4],
    /// Flag indicating more sparse headers follow.
    pub isextended: u8,
    /// Real size of sparse file (uncompressed).
    pub realsize: [u8; 12],
    /// Padding to fill the 512-byte block.
    pub pad: [u8; 17],
}

impl Default for GnuHeader {
    fn default() -> Self {
        let mut header = Self {
            name: [0u8; 100],
            mode: [0u8; 8],
            uid: [0u8; 8],
            gid: [0u8; 8],
            size: [0u8; 12],
            mtime: [0u8; 12],
            checksum: [0u8; 8],
            typeflag: 0,
            linkname: [0u8; 100],
            magic: [0u8; 6],
            version: [0u8; 2],
            uname: [0u8; 32],
            gname: [0u8; 32],
            devmajor: [0u8; 8],
            devminor: [0u8; 8],
            atime: [0u8; 12],
            ctime: [0u8; 12],
            offset: [0u8; 12],
            longnames: [0u8; 4],
            unused: 0,
            sparse: [GnuSparseHeader::default(); 4],
            isextended: 0,
            realsize: [0u8; 12],
            pad: [0u8; 17],
        };
        header.magic.copy_from_slice(GNU_MAGIC);
        header.version.copy_from_slice(GNU_VERSION);
        header
    }
}

impl fmt::Debug for GnuHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GnuHeader")
            .field("name", &String::from_utf8_lossy(truncate_null(&self.name)))
            .field("mode", &String::from_utf8_lossy(truncate_null(&self.mode)))
            .field("typeflag", &self.typeflag)
            .field("magic", &self.magic)
            .field("isextended", &self.isextended)
            .finish_non_exhaustive()
    }
}

/// Extended sparse header block for GNU tar.
///
/// When a file has more than 4 sparse regions, additional sparse headers
/// are stored in separate 512-byte blocks following the main header.
/// Each block contains 21 sparse descriptors plus an `isextended` flag.
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct GnuExtSparseHeader {
    /// Sparse chunk descriptors (21 entries).
    pub sparse: [GnuSparseHeader; 21],
    /// Flag indicating more sparse headers follow.
    pub isextended: u8,
    /// Padding to fill the 512-byte block.
    pub pad: [u8; 7],
}

impl fmt::Debug for GnuExtSparseHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GnuExtSparseHeader")
            .field("isextended", &self.isextended)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Entry Type
// ============================================================================

/// Tar entry type indicating the kind of file system object.
///
/// The type is stored as a single ASCII byte in the header. Some types
/// are extensions defined by POSIX or GNU tar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryType {
    /// Regular file (type '0' or '\0' for old tar compatibility).
    Regular,
    /// Hard link to another file in the archive (type '1').
    Link,
    /// Symbolic link (type '2').
    Symlink,
    /// Character device (type '3').
    Char,
    /// Block device (type '4').
    Block,
    /// Directory (type '5').
    Directory,
    /// FIFO/named pipe (type '6').
    Fifo,
    /// Contiguous file (type '7', rarely used).
    Continuous,
    /// GNU tar long name extension (type 'L').
    GnuLongName,
    /// GNU tar long link extension (type 'K').
    GnuLongLink,
    /// GNU tar sparse file (type 'S').
    GnuSparse,
    /// PAX extended header for next entry (type 'x').
    XHeader,
    /// PAX global extended header (type 'g').
    XGlobalHeader,
    /// Unknown or unsupported entry type.
    Other(u8),
}

impl EntryType {
    /// Parse an entry type from a raw byte value.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            b'0' | b'\0' => EntryType::Regular,
            b'1' => EntryType::Link,
            b'2' => EntryType::Symlink,
            b'3' => EntryType::Char,
            b'4' => EntryType::Block,
            b'5' => EntryType::Directory,
            b'6' => EntryType::Fifo,
            b'7' => EntryType::Continuous,
            b'L' => EntryType::GnuLongName,
            b'K' => EntryType::GnuLongLink,
            b'S' => EntryType::GnuSparse,
            b'x' => EntryType::XHeader,
            b'g' => EntryType::XGlobalHeader,
            other => EntryType::Other(other),
        }
    }

    /// Convert an entry type to its raw byte representation.
    ///
    /// Note that `Regular` is encoded as '0', not '\0'.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            EntryType::Regular => b'0',
            EntryType::Link => b'1',
            EntryType::Symlink => b'2',
            EntryType::Char => b'3',
            EntryType::Block => b'4',
            EntryType::Directory => b'5',
            EntryType::Fifo => b'6',
            EntryType::Continuous => b'7',
            EntryType::GnuLongName => b'L',
            EntryType::GnuLongLink => b'K',
            EntryType::GnuSparse => b'S',
            EntryType::XHeader => b'x',
            EntryType::XGlobalHeader => b'g',
            EntryType::Other(b) => b,
        }
    }

    /// Returns true if this is a regular file entry.
    #[must_use]
    pub fn is_file(self) -> bool {
        matches!(self, EntryType::Regular | EntryType::Continuous)
    }

    /// Returns true if this is a directory entry.
    #[must_use]
    pub fn is_dir(self) -> bool {
        self == EntryType::Directory
    }

    /// Returns true if this is a symbolic link entry.
    #[must_use]
    pub fn is_symlink(self) -> bool {
        self == EntryType::Symlink
    }

    /// Returns true if this is a hard link entry.
    #[must_use]
    pub fn is_hard_link(self) -> bool {
        self == EntryType::Link
    }
}

impl From<u8> for EntryType {
    fn from(byte: u8) -> Self {
        Self::from_byte(byte)
    }
}

impl From<EntryType> for u8 {
    fn from(entry_type: EntryType) -> Self {
        entry_type.to_byte()
    }
}

// ============================================================================
// Header Wrapper
// ============================================================================

/// High-level tar header wrapper with accessor methods.
///
/// This struct wraps a [`RawHeader`] and provides convenient methods for
/// accessing header fields, detecting the format, and verifying checksums.
///
/// # Format Detection
///
/// The format is detected by examining the magic field:
/// - UStar: magic = "ustar\0", version = "00"
/// - GNU: magic = "ustar ", version = " \0"
/// - Old: anything else
///
/// # Example
///
/// ```
/// use tar_header::Header;
///
/// let mut header = Header::new_ustar();
/// assert!(header.is_ustar());
/// assert!(!header.is_gnu());
/// ```
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct Header {
    raw: RawHeader,
}

impl Header {
    /// Create a new header with UStar format magic and version.
    #[must_use]
    pub fn new_ustar() -> Self {
        let mut header = Self {
            raw: RawHeader::default(),
        };
        // Set magic and version for UStar format
        header.raw.bytes[257..263].copy_from_slice(USTAR_MAGIC);
        header.raw.bytes[263..265].copy_from_slice(USTAR_VERSION);
        header
    }

    /// Create a new header with GNU tar format magic and version.
    #[must_use]
    pub fn new_gnu() -> Self {
        let mut header = Self {
            raw: RawHeader::default(),
        };
        // Set magic and version for GNU format
        header.raw.bytes[257..263].copy_from_slice(GNU_MAGIC);
        header.raw.bytes[263..265].copy_from_slice(GNU_VERSION);
        header
    }

    /// Get a reference to the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 512] {
        &self.raw.bytes
    }

    /// Get a mutable reference to the underlying bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8; 512] {
        &mut self.raw.bytes
    }

    /// Parse a header from a byte slice.
    ///
    /// Returns a reference to the header if the slice is at least 512 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::InsufficientData`] if the slice is too short.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Header> {
        if bytes.len() < HEADER_SIZE {
            return Err(HeaderError::InsufficientData(bytes.len()));
        }
        // SAFETY: Header is repr(transparent) over RawHeader, and we verify
        // the slice is properly sized. zerocopy handles alignment.
        let raw = RawHeader::ref_from_bytes(&bytes[..HEADER_SIZE])
            .map_err(|_| HeaderError::InsufficientData(bytes.len()))?;
        // SAFETY: Header is #[repr(transparent)] over RawHeader
        Ok(zerocopy::transmute_ref!(raw))
    }

    /// Parse from exactly 512 bytes without size checking.
    ///
    /// This is useful when you've already validated the buffer size.
    #[must_use]
    pub fn from_bytes_exact(bytes: &[u8; 512]) -> &Header {
        // SAFETY: Header is repr(transparent) over RawHeader which is
        // repr(C) with a [u8; 512] field. Both have the same layout.
        let raw = RawHeader::ref_from_bytes(bytes).expect("size is correct");
        zerocopy::transmute_ref!(raw)
    }

    /// View this header as an old-style header.
    #[must_use]
    pub fn as_old(&self) -> &OldHeader {
        OldHeader::ref_from_bytes(&self.raw.bytes).expect("size is correct")
    }

    /// View this header as a UStar header.
    #[must_use]
    pub fn as_ustar(&self) -> &UstarHeader {
        UstarHeader::ref_from_bytes(&self.raw.bytes).expect("size is correct")
    }

    /// View this header as a GNU header.
    #[must_use]
    pub fn as_gnu(&self) -> &GnuHeader {
        GnuHeader::ref_from_bytes(&self.raw.bytes).expect("size is correct")
    }

    /// Check if this header uses UStar format.
    #[must_use]
    pub fn is_ustar(&self) -> bool {
        self.raw.bytes[257..263] == *USTAR_MAGIC && self.raw.bytes[263..265] == *USTAR_VERSION
    }

    /// Check if this header uses GNU tar format.
    #[must_use]
    pub fn is_gnu(&self) -> bool {
        self.raw.bytes[257..263] == *GNU_MAGIC && self.raw.bytes[263..265] == *GNU_VERSION
    }

    /// Get the entry type.
    #[must_use]
    pub fn entry_type(&self) -> EntryType {
        EntryType::from_byte(self.raw.bytes[156])
    }

    /// Get the entry size (file content length) in bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::InvalidOctal`] if the size field is not valid.
    pub fn entry_size(&self) -> Result<u64> {
        parse_numeric(&self.raw.bytes[124..136])
    }

    /// Get the file mode (permissions).
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::InvalidOctal`] if the mode field is not valid.
    pub fn mode(&self) -> Result<u32> {
        parse_numeric(&self.raw.bytes[100..108]).map(|v| v as u32)
    }

    /// Get the owner user ID.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::InvalidOctal`] if the uid field is not valid.
    pub fn uid(&self) -> Result<u64> {
        parse_numeric(&self.raw.bytes[108..116])
    }

    /// Get the owner group ID.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::InvalidOctal`] if the gid field is not valid.
    pub fn gid(&self) -> Result<u64> {
        parse_numeric(&self.raw.bytes[116..124])
    }

    /// Get the modification time as a Unix timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::InvalidOctal`] if the mtime field is not valid.
    pub fn mtime(&self) -> Result<u64> {
        parse_numeric(&self.raw.bytes[136..148])
    }

    /// Get the raw path bytes from the header.
    ///
    /// This returns only the name field (bytes 0..100). For UStar format,
    /// the prefix field (bytes 345..500) may also contain path components
    /// that should be prepended.
    #[must_use]
    pub fn path_bytes(&self) -> &[u8] {
        truncate_null(&self.raw.bytes[0..100])
    }

    /// Get the raw link name bytes.
    #[must_use]
    pub fn link_name_bytes(&self) -> &[u8] {
        truncate_null(&self.raw.bytes[157..257])
    }

    /// Get the device major number (for character/block devices).
    ///
    /// Returns `None` for old-style headers without device fields.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::InvalidOctal`] if the field is not valid octal.
    pub fn device_major(&self) -> Result<Option<u32>> {
        if !self.is_ustar() && !self.is_gnu() {
            return Ok(None);
        }
        parse_octal(&self.raw.bytes[329..337]).map(|v| Some(v as u32))
    }

    /// Get the device minor number (for character/block devices).
    ///
    /// Returns `None` for old-style headers without device fields.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::InvalidOctal`] if the field is not valid octal.
    pub fn device_minor(&self) -> Result<Option<u32>> {
        if !self.is_ustar() && !self.is_gnu() {
            return Ok(None);
        }
        parse_octal(&self.raw.bytes[337..345]).map(|v| Some(v as u32))
    }

    /// Get the owner user name.
    ///
    /// Returns `None` for old-style headers without user/group name fields.
    #[must_use]
    pub fn username(&self) -> Option<&[u8]> {
        if !self.is_ustar() && !self.is_gnu() {
            return None;
        }
        Some(truncate_null(&self.raw.bytes[265..297]))
    }

    /// Get the owner group name.
    ///
    /// Returns `None` for old-style headers without user/group name fields.
    #[must_use]
    pub fn groupname(&self) -> Option<&[u8]> {
        if !self.is_ustar() && !self.is_gnu() {
            return None;
        }
        Some(truncate_null(&self.raw.bytes[297..329]))
    }

    /// Get the UStar prefix field for long paths.
    ///
    /// Returns `None` for old-style or GNU headers.
    #[must_use]
    pub fn prefix(&self) -> Option<&[u8]> {
        if !self.is_ustar() {
            return None;
        }
        Some(truncate_null(&self.raw.bytes[345..500]))
    }

    /// Verify the header checksum.
    ///
    /// The checksum is computed as the unsigned sum of all header bytes,
    /// treating the checksum field (bytes 148..156) as spaces.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::ChecksumMismatch`] if the checksum is invalid,
    /// or [`HeaderError::InvalidOctal`] if the stored checksum cannot be parsed.
    pub fn verify_checksum(&self) -> Result<()> {
        let expected = parse_octal(&self.raw.bytes[148..156])?;
        let computed = self.compute_checksum();
        if expected == computed {
            Ok(())
        } else {
            Err(HeaderError::ChecksumMismatch { expected, computed })
        }
    }

    /// Compute the header checksum.
    ///
    /// This computes the unsigned sum of all header bytes, treating the
    /// checksum field (bytes 148..156) as spaces (0x20).
    #[must_use]
    pub fn compute_checksum(&self) -> u64 {
        let mut sum: u64 = 0;
        for (i, &byte) in self.raw.bytes.iter().enumerate() {
            if (148..156).contains(&i) {
                // Treat checksum field as spaces
                sum += u64::from(b' ');
            } else {
                sum += u64::from(byte);
            }
        }
        sum
    }

    /// Check if this header represents an empty block (all zeros).
    ///
    /// Two consecutive empty blocks mark the end of a tar archive.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.raw.bytes.iter().all(|&b| b == 0)
    }
}

impl Default for Header {
    fn default() -> Self {
        Self::new_ustar()
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("path", &String::from_utf8_lossy(self.path_bytes()))
            .field("entry_type", &self.entry_type())
            .field("size", &self.entry_size().ok())
            .field("mode", &self.mode().ok().map(|m| format!("{m:04o}")))
            .field("is_ustar", &self.is_ustar())
            .field("is_gnu", &self.is_gnu())
            .finish()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse an octal ASCII field into a u64.
///
/// Octal fields in tar headers are ASCII strings with optional leading
/// spaces and trailing spaces or null bytes. For example:
/// - `"0000644\0"` -> 420 (file mode 0644)
/// - `"     123 "` -> 83
///
/// # Errors
///
/// Returns [`HeaderError::InvalidOctal`] if the field contains invalid
/// characters (anything other than spaces, digits 0-7, or null bytes).
pub fn parse_octal(bytes: &[u8]) -> Result<u64> {
    // Skip leading spaces
    let start = bytes.iter().position(|&b| b != b' ').unwrap_or(bytes.len());
    // Find end (first space or null after digits)
    let end = bytes[start..]
        .iter()
        .position(|&b| b == b' ' || b == b'\0')
        .map_or(bytes.len(), |i| start + i);

    let trimmed = &bytes[start..end];

    if trimmed.is_empty() {
        return Ok(0);
    }

    // Parse the octal string
    let mut value: u64 = 0;
    for &byte in trimmed {
        if !byte.is_ascii_digit() || byte > b'7' {
            return Err(HeaderError::InvalidOctal(bytes.to_vec()));
        }
        value = value
            .checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| HeaderError::InvalidOctal(bytes.to_vec()))?;
    }

    Ok(value)
}

/// Parse a numeric field that may be octal ASCII or GNU base-256 encoded.
///
/// GNU tar uses base-256 encoding for values that don't fit in octal.
/// When the high bit of the first byte is set (0x80), the value is stored
/// as big-endian binary in the remaining bytes. Otherwise, it's parsed as
/// octal ASCII.
///
/// # Errors
///
/// Returns [`HeaderError::InvalidOctal`] if octal parsing fails.
pub fn parse_numeric(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() {
        return Ok(0);
    }

    // Check for GNU base-256 encoding (high bit set)
    if bytes[0] & 0x80 != 0 {
        // Base-256: interpret remaining bytes as big-endian, masking off the
        // high bit of the first byte
        let mut value: u64 = 0;
        for (i, &byte) in bytes.iter().enumerate() {
            let b = if i == 0 { byte & 0x7f } else { byte };
            value = value
                .checked_shl(8)
                .and_then(|v| v.checked_add(u64::from(b)))
                .ok_or_else(|| HeaderError::InvalidOctal(bytes.to_vec()))?;
        }
        Ok(value)
    } else {
        // Standard octal ASCII
        parse_octal(bytes)
    }
}

/// Truncate a byte slice at the first null byte.
///
/// This is used to extract null-terminated strings from fixed-size fields.
/// If no null byte is found, returns the entire slice.
///
/// # Example
///
/// ```
/// use tar_header::truncate_null;
///
/// assert_eq!(truncate_null(b"hello\0world"), b"hello");
/// assert_eq!(truncate_null(b"no null here"), b"no null here");
/// assert_eq!(truncate_null(b"\0empty"), b"");
/// ```
#[must_use]
pub fn truncate_null(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(pos) => &bytes[..pos],
        None => bytes,
    }
}

// ============================================================================
// PAX Extended Headers
// ============================================================================

/// PAX extended header key for the file path.
pub const PAX_PATH: &str = "path";
/// PAX extended header key for the link target path.
pub const PAX_LINKPATH: &str = "linkpath";
/// PAX extended header key for file size.
pub const PAX_SIZE: &str = "size";
/// PAX extended header key for owner user ID.
pub const PAX_UID: &str = "uid";
/// PAX extended header key for owner group ID.
pub const PAX_GID: &str = "gid";
/// PAX extended header key for owner user name.
pub const PAX_UNAME: &str = "uname";
/// PAX extended header key for owner group name.
pub const PAX_GNAME: &str = "gname";
/// PAX extended header key for modification time.
pub const PAX_MTIME: &str = "mtime";
/// PAX extended header key for access time.
pub const PAX_ATIME: &str = "atime";
/// PAX extended header key for change time.
pub const PAX_CTIME: &str = "ctime";
/// PAX extended header prefix for SCHILY extended attributes.
pub const PAX_SCHILY_XATTR: &str = "SCHILY.xattr.";

/// PAX extended header prefix for GNU sparse file extensions.
pub const PAX_GNU_SPARSE: &str = "GNU.sparse.";
/// PAX key for GNU sparse file number of blocks.
pub const PAX_GNU_SPARSE_NUMBLOCKS: &str = "GNU.sparse.numblocks";
/// PAX key for GNU sparse file offset.
pub const PAX_GNU_SPARSE_OFFSET: &str = "GNU.sparse.offset";
/// PAX key for GNU sparse file numbytes.
pub const PAX_GNU_SPARSE_NUMBYTES: &str = "GNU.sparse.numbytes";
/// PAX key for GNU sparse file map.
pub const PAX_GNU_SPARSE_MAP: &str = "GNU.sparse.map";
/// PAX key for GNU sparse file name.
pub const PAX_GNU_SPARSE_NAME: &str = "GNU.sparse.name";
/// PAX key for GNU sparse file format major version.
pub const PAX_GNU_SPARSE_MAJOR: &str = "GNU.sparse.major";
/// PAX key for GNU sparse file format minor version.
pub const PAX_GNU_SPARSE_MINOR: &str = "GNU.sparse.minor";
/// PAX key for GNU sparse file size.
pub const PAX_GNU_SPARSE_SIZE: &str = "GNU.sparse.size";
/// PAX key for GNU sparse file real size.
pub const PAX_GNU_SPARSE_REALSIZE: &str = "GNU.sparse.realsize";

/// Error parsing a PAX extension record.
#[derive(Debug, Error)]
pub enum PaxError {
    /// The record format is malformed.
    #[error("malformed PAX extension record")]
    Malformed,
    /// The key is not valid UTF-8.
    #[error("PAX key is not valid UTF-8: {0}")]
    InvalidKey(#[from] std::str::Utf8Error),
}

/// A single PAX extended header key/value pair.
#[derive(Debug, Clone)]
pub struct PaxExtension<'a> {
    key: &'a [u8],
    value: &'a [u8],
}

impl<'a> PaxExtension<'a> {
    /// Returns the key as a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not valid UTF-8.
    pub fn key(&self) -> std::result::Result<&'a str, std::str::Utf8Error> {
        std::str::from_utf8(self.key)
    }

    /// Returns the raw key bytes.
    #[must_use]
    pub fn key_bytes(&self) -> &'a [u8] {
        self.key
    }

    /// Returns the value as a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not valid UTF-8.
    pub fn value(&self) -> std::result::Result<&'a str, std::str::Utf8Error> {
        std::str::from_utf8(self.value)
    }

    /// Returns the raw value bytes.
    #[must_use]
    pub fn value_bytes(&self) -> &'a [u8] {
        self.value
    }
}

/// Iterator over PAX extended header records.
///
/// PAX extended headers consist of records in the format:
/// `<length> <key>=<value>\n`
///
/// where `<length>` is the total record length including the length field itself.
///
/// # Example
///
/// ```
/// use tar_header::PaxExtensions;
///
/// let data = b"20 path=foo/bar.txt\n";
/// let mut iter = PaxExtensions::new(data);
/// let ext = iter.next().unwrap().unwrap();
/// assert_eq!(ext.key().unwrap(), "path");
/// assert_eq!(ext.value().unwrap(), "foo/bar.txt");
/// ```
#[derive(Debug)]
pub struct PaxExtensions<'a> {
    data: &'a [u8],
}

impl<'a> PaxExtensions<'a> {
    /// Create a new iterator over PAX extension records.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Look up a specific key and return its value as a string.
    ///
    /// Returns `None` if the key is not found or if parsing fails.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&'a str> {
        for ext in PaxExtensions::new(self.data).flatten() {
            if ext.key().ok() == Some(key) {
                return ext.value().ok();
            }
        }
        None
    }

    /// Look up a specific key and parse its value as u64.
    ///
    /// Returns `None` if the key is not found, parsing fails, or the value
    /// is not a valid integer.
    #[must_use]
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|v| v.parse().ok())
    }
}

impl<'a> Iterator for PaxExtensions<'a> {
    type Item = std::result::Result<PaxExtension<'a>, PaxError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        // Find the space separating length from key=value
        let space_pos = self.data.iter().position(|&b| b == b' ')?;

        // Parse the length
        let len_str = std::str::from_utf8(&self.data[..space_pos]).ok()?;
        let len: usize = len_str.parse().ok()?;

        // Validate we have enough data
        if len > self.data.len() || len < space_pos + 2 {
            return Some(Err(PaxError::Malformed));
        }

        // The record should end with newline
        if self.data.get(len.saturating_sub(1)) != Some(&b'\n') {
            return Some(Err(PaxError::Malformed));
        }

        // Extract key=value (excluding length prefix and trailing newline)
        let kv = &self.data[space_pos + 1..len - 1];

        // Find the equals sign
        let eq_pos = match kv.iter().position(|&b| b == b'=') {
            Some(pos) => pos,
            None => return Some(Err(PaxError::Malformed)),
        };

        let key = &kv[..eq_pos];
        let value = &kv[eq_pos + 1..];

        // Advance past this record
        self.data = &self.data[len..];

        Some(Ok(PaxExtension { key, value }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size() {
        assert_eq!(size_of::<RawHeader>(), HEADER_SIZE);
        assert_eq!(size_of::<OldHeader>(), HEADER_SIZE);
        assert_eq!(size_of::<UstarHeader>(), HEADER_SIZE);
        assert_eq!(size_of::<GnuHeader>(), HEADER_SIZE);
        assert_eq!(size_of::<GnuExtSparseHeader>(), HEADER_SIZE);
        assert_eq!(size_of::<Header>(), HEADER_SIZE);
    }

    #[test]
    fn test_sparse_header_size() {
        // Each sparse header is 24 bytes (12 + 12)
        assert_eq!(size_of::<GnuSparseHeader>(), 24);
        // Extended sparse: 21 * 24 + 1 + 7 = 512
        assert_eq!(21 * 24 + 1 + 7, HEADER_SIZE);
    }

    #[test]
    fn test_new_ustar() {
        let header = Header::new_ustar();
        assert!(header.is_ustar());
        assert!(!header.is_gnu());
    }

    #[test]
    fn test_new_gnu() {
        let header = Header::new_gnu();
        assert!(header.is_gnu());
        assert!(!header.is_ustar());
    }

    #[test]
    fn test_from_bytes_insufficient() {
        let short = [0u8; 100];
        let result = Header::from_bytes(&short);
        assert!(matches!(result, Err(HeaderError::InsufficientData(100))));
    }

    #[test]
    fn test_from_bytes_success() {
        let mut data = [0u8; 512];
        // Set up a valid UStar header
        data[257..263].copy_from_slice(USTAR_MAGIC);
        data[263..265].copy_from_slice(USTAR_VERSION);

        let header = Header::from_bytes(&data).unwrap();
        assert!(header.is_ustar());
    }

    #[test]
    fn test_parse_octal() {
        assert_eq!(parse_octal(b"0000644\0").unwrap(), 0o644);
        assert_eq!(parse_octal(b"0000755\0").unwrap(), 0o755);
        assert_eq!(parse_octal(b"     123 ").unwrap(), 0o123);
        assert_eq!(parse_octal(b"0").unwrap(), 0);
        assert_eq!(parse_octal(b"").unwrap(), 0);
        assert_eq!(parse_octal(b"   \0\0\0").unwrap(), 0);
        assert_eq!(parse_octal(b"77777777777").unwrap(), 0o77777777777);
    }

    #[test]
    fn test_parse_octal_invalid() {
        assert!(parse_octal(b"abc").is_err());
        assert!(parse_octal(b"128").is_err()); // 8 and 9 are not octal
    }

    #[test]
    fn test_truncate_null() {
        assert_eq!(truncate_null(b"hello\0world"), b"hello");
        assert_eq!(truncate_null(b"no null"), b"no null");
        assert_eq!(truncate_null(b"\0start"), b"");
        assert_eq!(truncate_null(b""), b"");
    }

    #[test]
    fn test_entry_type_roundtrip() {
        let types = [
            EntryType::Regular,
            EntryType::Link,
            EntryType::Symlink,
            EntryType::Char,
            EntryType::Block,
            EntryType::Directory,
            EntryType::Fifo,
            EntryType::Continuous,
            EntryType::GnuLongName,
            EntryType::GnuLongLink,
            EntryType::GnuSparse,
            EntryType::XHeader,
            EntryType::XGlobalHeader,
        ];

        for t in types {
            let byte = t.to_byte();
            let parsed = EntryType::from_byte(byte);
            assert_eq!(parsed, t);
        }
    }

    #[test]
    fn test_entry_type_old_regular() {
        // Old tar uses '\0' for regular files
        assert_eq!(EntryType::from_byte(b'\0'), EntryType::Regular);
        assert_eq!(EntryType::from_byte(b'0'), EntryType::Regular);
    }

    #[test]
    fn test_entry_type_predicates() {
        assert!(EntryType::Regular.is_file());
        assert!(EntryType::Continuous.is_file());
        assert!(!EntryType::Directory.is_file());

        assert!(EntryType::Directory.is_dir());
        assert!(!EntryType::Regular.is_dir());

        assert!(EntryType::Symlink.is_symlink());
        assert!(EntryType::Link.is_hard_link());
    }

    #[test]
    fn test_checksum_empty_header() {
        let header = Header::new_ustar();
        // Computed checksum should be consistent
        let checksum = header.compute_checksum();
        // For an empty header with only magic/version set, checksum includes:
        // - 148 spaces (0x20) for checksum field = 148 * 32 = 4736
        // - "ustar\0" = 117+115+116+97+114+0 = 559
        // - "00" = 48+48 = 96
        // - Rest are zeros
        assert!(checksum > 0);
    }

    #[test]
    fn test_is_empty() {
        let mut header = Header::new_ustar();
        assert!(!header.is_empty());

        // Create truly empty header
        header.as_mut_bytes().fill(0);
        assert!(header.is_empty());
    }

    #[test]
    fn test_as_format_views() {
        let header = Header::new_ustar();

        // All views should work without panicking
        let _old = header.as_old();
        let _ustar = header.as_ustar();
        let _gnu = header.as_gnu();
    }

    #[test]
    fn test_ustar_default_magic() {
        let ustar = UstarHeader::default();
        assert_eq!(&ustar.magic, USTAR_MAGIC);
        assert_eq!(&ustar.version, USTAR_VERSION);
    }

    #[test]
    fn test_gnu_default_magic() {
        let gnu = GnuHeader::default();
        assert_eq!(&gnu.magic, GNU_MAGIC);
        assert_eq!(&gnu.version, GNU_VERSION);
    }

    #[test]
    fn test_path_bytes() {
        let mut header = Header::new_ustar();
        header.as_mut_bytes()[0..5].copy_from_slice(b"hello");
        assert_eq!(header.path_bytes(), b"hello");
    }

    #[test]
    fn test_link_name_bytes() {
        let mut header = Header::new_ustar();
        header.as_mut_bytes()[157..163].copy_from_slice(b"target");
        assert_eq!(header.link_name_bytes(), b"target");
    }

    #[test]
    fn test_username_groupname() {
        let header = Header::new_ustar();
        assert!(header.username().is_some());
        assert!(header.groupname().is_some());

        // Old-style header should return None
        let mut old_header = Header::new_ustar();
        old_header.as_mut_bytes()[257..265].fill(0);
        assert!(old_header.username().is_none());
        assert!(old_header.groupname().is_none());
    }

    #[test]
    fn test_prefix() {
        let header = Header::new_ustar();
        assert!(header.prefix().is_some());

        let gnu_header = Header::new_gnu();
        // GNU format doesn't use prefix the same way
        assert!(gnu_header.prefix().is_none());
    }

    #[test]
    fn test_device_numbers() {
        let header = Header::new_ustar();
        assert!(header.device_major().unwrap().is_some());
        assert!(header.device_minor().unwrap().is_some());

        // Old-style header should return None
        let mut old_header = Header::new_ustar();
        old_header.as_mut_bytes()[257..265].fill(0);
        assert!(old_header.device_major().unwrap().is_none());
        assert!(old_header.device_minor().unwrap().is_none());
    }

    #[test]
    fn test_debug_impls() {
        // Just ensure Debug impls don't panic
        let header = Header::new_ustar();
        let _ = format!("{header:?}");
        let _ = format!("{:?}", header.as_old());
        let _ = format!("{:?}", header.as_ustar());
        let _ = format!("{:?}", header.as_gnu());
        let _ = format!("{:?}", GnuExtSparseHeader::default());
        let _ = format!("{:?}", GnuSparseHeader::default());
        let _ = format!("{:?}", RawHeader::default());
    }

    #[test]
    fn test_parse_numeric_octal() {
        // parse_numeric should handle octal just like parse_octal
        assert_eq!(parse_numeric(b"0000644\0").unwrap(), 0o644);
        assert_eq!(parse_numeric(b"0000755\0").unwrap(), 0o755);
        assert_eq!(parse_numeric(b"     123 ").unwrap(), 0o123);
        assert_eq!(parse_numeric(b"").unwrap(), 0);
    }

    #[test]
    fn test_parse_numeric_base256() {
        // Base-256 encoding: high bit set, remaining bytes are big-endian value
        // 0x80 0x00 0x00 0x01 = 1 (with marker bit in first byte)
        assert_eq!(parse_numeric(&[0x80, 0x00, 0x00, 0x01]).unwrap(), 1);

        // 0x80 0x00 0x01 0x00 = 256
        assert_eq!(parse_numeric(&[0x80, 0x00, 0x01, 0x00]).unwrap(), 256);

        // 0x80 0xFF = 255 (first byte 0x80 & 0x7f = 0, second byte 0xFF = 255)
        assert_eq!(parse_numeric(&[0x80, 0xFF]).unwrap(), 255);

        // Larger value: 0x80 0x00 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00
        // = 2^40 = 1099511627776
        let bytes = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(parse_numeric(&bytes).unwrap(), 1099511627776);
    }

    #[test]
    fn test_parse_numeric_base256_in_header() {
        // Test that base-256 encoded size field works in Header
        let mut header = Header::new_ustar();

        // Set size field (bytes 124..136) to base-256 encoded value
        // 12-byte field: first byte has 0x80 marker, remaining 11 bytes are the value
        // We want to encode a large value that wouldn't fit in octal
        let size_field = &mut header.as_mut_bytes()[124..136];
        size_field.fill(0);
        size_field[0] = 0x80; // base-256 marker (first byte & 0x7f = 0)
                              // Put value in last 4 bytes for simplicity: 0x12345678
        size_field[8] = 0x12;
        size_field[9] = 0x34;
        size_field[10] = 0x56;
        size_field[11] = 0x78;

        assert_eq!(header.entry_size().unwrap(), 0x12345678);
    }

    #[test]
    fn test_parse_numeric_base256_uid_gid() {
        let mut header = Header::new_ustar();

        // Set uid field (bytes 108..116) to base-256 encoded value
        let uid_field = &mut header.as_mut_bytes()[108..116];
        uid_field.fill(0);
        uid_field[0] = 0x80; // base-256 marker
        uid_field[7] = 0x42; // value = 66
        assert_eq!(header.uid().unwrap(), 66);

        // Set gid field (bytes 116..124) to base-256 encoded value
        let gid_field = &mut header.as_mut_bytes()[116..124];
        gid_field.fill(0);
        gid_field[0] = 0x80; // base-256 marker
        gid_field[6] = 0x01;
        gid_field[7] = 0x00; // value = 256
        assert_eq!(header.gid().unwrap(), 256);
    }

    #[test]
    fn test_parse_octal_edge_cases() {
        // All spaces should return 0
        assert_eq!(parse_octal(b"        ").unwrap(), 0);

        // All nulls should return 0
        assert_eq!(parse_octal(b"\0\0\0\0\0\0").unwrap(), 0);

        // Mixed spaces and nulls
        assert_eq!(parse_octal(b"   \0\0\0").unwrap(), 0);

        // Value at very end with trailing null
        assert_eq!(parse_octal(b"      7\0").unwrap(), 7);

        // Value with no trailing delimiter (field fills entire space)
        assert_eq!(parse_octal(b"0000755").unwrap(), 0o755);

        // Single digit
        assert_eq!(parse_octal(b"7").unwrap(), 7);

        // Leading zeros
        assert_eq!(parse_octal(b"00000001").unwrap(), 1);

        // Max value that fits in 11 octal digits (typical for 12-byte fields)
        assert_eq!(parse_octal(b"77777777777\0").unwrap(), 0o77777777777);
    }

    #[test]
    fn test_from_bytes_exact() {
        let mut data = [0u8; 512];
        // Set up a valid UStar header
        data[257..263].copy_from_slice(USTAR_MAGIC);
        data[263..265].copy_from_slice(USTAR_VERSION);
        data[0..4].copy_from_slice(b"test");

        let header = Header::from_bytes_exact(&data);
        assert!(header.is_ustar());
        assert_eq!(header.path_bytes(), b"test");
    }

    #[test]
    fn test_from_bytes_exact_gnu() {
        let mut data = [0u8; 512];
        data[257..263].copy_from_slice(GNU_MAGIC);
        data[263..265].copy_from_slice(GNU_VERSION);

        let header = Header::from_bytes_exact(&data);
        assert!(header.is_gnu());
        assert!(!header.is_ustar());
    }

    // =========================================================================
    // PAX Extension Tests
    // =========================================================================

    #[test]
    fn test_pax_simple() {
        let data = b"20 path=foo/bar.txt\n";
        let mut iter = PaxExtensions::new(data);
        let ext = iter.next().unwrap().unwrap();
        assert_eq!(ext.key().unwrap(), "path");
        assert_eq!(ext.value().unwrap(), "foo/bar.txt");
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_pax_multiple() {
        let data = b"20 path=foo/bar.txt\n12 uid=1000\n12 gid=1000\n";
        let exts: Vec<_> = PaxExtensions::new(data).collect();
        assert_eq!(exts.len(), 3);
        assert_eq!(exts[0].as_ref().unwrap().key().unwrap(), "path");
        assert_eq!(exts[0].as_ref().unwrap().value().unwrap(), "foo/bar.txt");
        assert_eq!(exts[1].as_ref().unwrap().key().unwrap(), "uid");
        assert_eq!(exts[1].as_ref().unwrap().value().unwrap(), "1000");
        assert_eq!(exts[2].as_ref().unwrap().key().unwrap(), "gid");
        assert_eq!(exts[2].as_ref().unwrap().value().unwrap(), "1000");
    }

    #[test]
    fn test_pax_get() {
        let data = b"20 path=foo/bar.txt\n12 uid=1000\n";
        let pax = PaxExtensions::new(data);
        assert_eq!(pax.get("path"), Some("foo/bar.txt"));
        assert_eq!(pax.get("uid"), Some("1000"));
        assert_eq!(pax.get("missing"), None);
    }

    #[test]
    fn test_pax_get_u64() {
        let data = b"12 uid=1000\n16 size=1234567\n";
        let pax = PaxExtensions::new(data);
        assert_eq!(pax.get_u64("uid"), Some(1000));
        assert_eq!(pax.get_u64("size"), Some(1234567));
        assert_eq!(pax.get_u64("missing"), None);
    }

    #[test]
    fn test_pax_empty() {
        let data = b"";
        let mut iter = PaxExtensions::new(data);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_pax_binary_value() {
        // PAX values can contain binary data (e.g., xattrs)
        // Format: "<len> <key>=<value>\n" where len includes everything
        // 24 = 2 (digits) + 1 (space) + 16 (key) + 1 (=) + 3 (value) + 1 (newline)
        let data = b"24 SCHILY.xattr.foo=\x00\x01\x02\n";
        let mut iter = PaxExtensions::new(data);
        let ext = iter.next().unwrap().unwrap();
        assert_eq!(ext.key().unwrap(), "SCHILY.xattr.foo");
        assert_eq!(ext.value_bytes(), b"\x00\x01\x02");
    }

    #[test]
    fn test_pax_long_path() {
        // Test a path that's exactly at various boundary lengths
        let long_path = "a".repeat(200);
        // PAX format: "length path=value\n" where length includes ALL bytes including itself
        // For 200-char path: 5 (path=) + 1 (\n) + 200 (value) + 1 (space) + 3 (length digits) = 210
        let record = format!("210 path={}\n", long_path);
        let data = record.as_bytes();
        let pax = PaxExtensions::new(data);
        assert_eq!(pax.get("path"), Some(long_path.as_str()));
    }

    #[test]
    fn test_pax_unicode_path() {
        // PAX supports UTF-8 paths
        let data = "35 path=日本語/ファイル.txt\n".as_bytes();
        let pax = PaxExtensions::new(data);
        assert_eq!(pax.get("path"), Some("日本語/ファイル.txt"));
    }

    #[test]
    fn test_pax_mtime_fractional() {
        // PAX mtime can have fractional seconds
        let data = b"22 mtime=1234567890.5\n";
        let pax = PaxExtensions::new(data);
        assert_eq!(pax.get("mtime"), Some("1234567890.5"));
        // get_u64 won't parse fractional
        assert_eq!(pax.get_u64("mtime"), None);
    }

    #[test]
    fn test_pax_schily_xattr() {
        let data = b"30 SCHILY.xattr.user.test=val\n";
        let mut iter = PaxExtensions::new(data);
        let ext = iter.next().unwrap().unwrap();
        let key = ext.key().unwrap();
        assert!(key.starts_with(PAX_SCHILY_XATTR));
        assert_eq!(&key[PAX_SCHILY_XATTR.len()..], "user.test");
    }

    #[test]
    fn test_pax_malformed_no_equals() {
        let data = b"15 pathfoobar\n";
        let mut iter = PaxExtensions::new(data);
        let result = iter.next().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_pax_malformed_wrong_length() {
        // Length says 100 but record is shorter
        let data = b"100 path=foo\n";
        let mut iter = PaxExtensions::new(data);
        let result = iter.next().unwrap();
        assert!(result.is_err());
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[test]
    fn test_path_exactly_100_bytes() {
        // Path that fills entire name field (no null terminator needed)
        let mut header = Header::new_ustar();
        let path = "a".repeat(100);
        header.as_mut_bytes()[0..100].copy_from_slice(path.as_bytes());

        assert_eq!(header.path_bytes().len(), 100);
        assert_eq!(header.path_bytes(), path.as_bytes());
    }

    #[test]
    fn test_link_name_exactly_100_bytes() {
        let mut header = Header::new_ustar();
        let target = "t".repeat(100);
        header.as_mut_bytes()[157..257].copy_from_slice(target.as_bytes());

        assert_eq!(header.link_name_bytes().len(), 100);
        assert_eq!(header.link_name_bytes(), target.as_bytes());
    }

    #[test]
    fn test_prefix_exactly_155_bytes() {
        let mut header = Header::new_ustar();
        let prefix = "p".repeat(155);
        header.as_mut_bytes()[345..500].copy_from_slice(prefix.as_bytes());

        assert_eq!(header.prefix().unwrap().len(), 155);
        assert_eq!(header.prefix().unwrap(), prefix.as_bytes());
    }

    #[test]
    fn test_sparse_header_parsing() {
        let header = Header::new_gnu();
        let gnu = header.as_gnu();

        // Default sparse headers should have zero offset and numbytes
        for sparse in &gnu.sparse {
            assert_eq!(parse_octal(&sparse.offset).unwrap(), 0);
            assert_eq!(parse_octal(&sparse.numbytes).unwrap(), 0);
        }
    }

    #[test]
    fn test_gnu_atime_ctime() {
        let mut header = Header::new_gnu();
        let gnu = header.as_gnu();

        // Default should be zeros
        assert_eq!(parse_octal(&gnu.atime).unwrap(), 0);
        assert_eq!(parse_octal(&gnu.ctime).unwrap(), 0);

        // Set some values (valid octal: 12345670123)
        header.as_mut_bytes()[345..356].copy_from_slice(b"12345670123");
        let gnu = header.as_gnu();
        assert_eq!(parse_octal(&gnu.atime).unwrap(), 0o12345670123);
    }

    #[test]
    fn test_ext_sparse_header() {
        let ext = GnuExtSparseHeader::default();
        assert_eq!(ext.isextended, 0);
        assert_eq!(ext.sparse.len(), 21);

        // Verify size is exactly 512 bytes
        assert_eq!(size_of::<GnuExtSparseHeader>(), HEADER_SIZE);
    }

    #[test]
    fn test_max_octal_values() {
        // 12-byte field max (11 octal digits + null)
        assert_eq!(parse_octal(b"77777777777\0").unwrap(), 0o77777777777);

        // 8-byte field max (7 octal digits + null)
        assert_eq!(parse_octal(b"7777777\0").unwrap(), 0o7777777);
    }

    #[test]
    fn test_base256_max_values() {
        // Large UID that needs base-256
        let mut bytes = [0u8; 8];
        bytes[0] = 0x80; // marker
        bytes[4] = 0xFF;
        bytes[5] = 0xFF;
        bytes[6] = 0xFF;
        bytes[7] = 0xFF;
        assert_eq!(parse_numeric(&bytes).unwrap(), 0xFFFFFFFF);
    }

    #[test]
    fn test_entry_type_gnu_extensions() {
        // GNU long name/link types
        assert!(matches!(EntryType::from_byte(b'L'), EntryType::GnuLongName));
        assert!(matches!(EntryType::from_byte(b'K'), EntryType::GnuLongLink));
        assert!(matches!(EntryType::from_byte(b'S'), EntryType::GnuSparse));
    }

    #[test]
    fn test_entry_type_pax() {
        assert!(matches!(EntryType::from_byte(b'x'), EntryType::XHeader));
        assert!(matches!(
            EntryType::from_byte(b'g'),
            EntryType::XGlobalHeader
        ));
    }

    /// Cross-checking tests against the `tar` crate using proptest.
    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;
        use std::io::Cursor;

        /// Strategy for generating valid file paths (ASCII, no null bytes, reasonable length).
        fn path_strategy() -> impl Strategy<Value = String> {
            proptest::string::string_regex(
                "[a-zA-Z0-9_][a-zA-Z0-9_.+-]*(/[a-zA-Z0-9_][a-zA-Z0-9_.+-]*)*",
            )
            .expect("valid regex")
            .prop_filter("reasonable length", |s| !s.is_empty() && s.len() < 100)
        }

        /// Strategy for generating valid link targets.
        /// Avoids consecutive slashes and `.`/`..` segments which the tar crate normalizes.
        fn link_target_strategy() -> impl Strategy<Value = String> {
            proptest::string::string_regex(
                "[a-zA-Z0-9_][a-zA-Z0-9_+-]*(/[a-zA-Z0-9_][a-zA-Z0-9_+-]*)*",
            )
            .expect("valid regex")
            .prop_filter("reasonable length", |s| !s.is_empty() && s.len() < 100)
        }

        /// Strategy for generating valid user/group names.
        fn name_strategy() -> impl Strategy<Value = String> {
            proptest::string::string_regex("[a-zA-Z_][a-zA-Z0-9_]{0,30}").expect("valid regex")
        }

        /// Strategy for file mode (valid Unix permissions).
        fn mode_strategy() -> impl Strategy<Value = u32> {
            // Standard Unix permission modes
            prop_oneof![
                Just(0o644),    // regular file
                Just(0o755),    // executable
                Just(0o600),    // private
                Just(0o777),    // all permissions
                Just(0o400),    // read-only
                (0u32..0o7777), // any valid mode
            ]
        }

        /// Strategy for uid/gid values that fit in octal.
        fn id_strategy() -> impl Strategy<Value = u64> {
            prop_oneof![
                Just(0u64),
                Just(1000u64),
                Just(65534u64),    // nobody
                (0u64..0o7777777), // fits in 7 octal digits
            ]
        }

        /// Strategy for mtime values.
        fn mtime_strategy() -> impl Strategy<Value = u64> {
            prop_oneof![
                Just(0u64),
                Just(1234567890u64),
                (0u64..0o77777777777u64), // fits in 11 octal digits
            ]
        }

        /// Strategy for file size values.
        fn size_strategy() -> impl Strategy<Value = u64> {
            prop_oneof![
                Just(0u64),
                Just(1u64),
                Just(512u64),
                Just(4096u64),
                (0u64..1024 * 1024), // up to 1 MB
            ]
        }

        /// Test parameters for a regular file entry.
        #[derive(Debug, Clone)]
        struct FileParams {
            path: String,
            mode: u32,
            uid: u64,
            gid: u64,
            mtime: u64,
            size: u64,
            username: String,
            groupname: String,
        }

        fn file_params_strategy() -> impl Strategy<Value = FileParams> {
            (
                path_strategy(),
                mode_strategy(),
                id_strategy(),
                id_strategy(),
                mtime_strategy(),
                size_strategy(),
                name_strategy(),
                name_strategy(),
            )
                .prop_map(
                    |(path, mode, uid, gid, mtime, size, username, groupname)| FileParams {
                        path,
                        mode,
                        uid,
                        gid,
                        mtime,
                        size,
                        username,
                        groupname,
                    },
                )
        }

        /// Test parameters for a symlink entry.
        #[derive(Debug, Clone)]
        struct SymlinkParams {
            path: String,
            target: String,
            uid: u64,
            gid: u64,
            mtime: u64,
        }

        fn symlink_params_strategy() -> impl Strategy<Value = SymlinkParams> {
            (
                path_strategy(),
                link_target_strategy(),
                id_strategy(),
                id_strategy(),
                mtime_strategy(),
            )
                .prop_map(|(path, target, uid, gid, mtime)| SymlinkParams {
                    path,
                    target,
                    uid,
                    gid,
                    mtime,
                })
        }

        /// Test parameters for a directory entry.
        #[derive(Debug, Clone)]
        struct DirParams {
            path: String,
            mode: u32,
            uid: u64,
            gid: u64,
            mtime: u64,
        }

        fn dir_params_strategy() -> impl Strategy<Value = DirParams> {
            (
                path_strategy(),
                mode_strategy(),
                id_strategy(),
                id_strategy(),
                mtime_strategy(),
            )
                .prop_map(|(path, mode, uid, gid, mtime)| DirParams {
                    path,
                    mode,
                    uid,
                    gid,
                    mtime,
                })
        }

        /// Create a tar archive with a single file entry and return the header bytes.
        fn create_file_tar(params: &FileParams) -> Vec<u8> {
            let mut builder = tar::Builder::new(Vec::new());

            let mut header = tar::Header::new_ustar();
            header.set_path(&params.path).unwrap();
            header.set_mode(params.mode);
            header.set_uid(params.uid);
            header.set_gid(params.gid);
            header.set_mtime(params.mtime);
            header.set_size(params.size);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_username(&params.username).unwrap();
            header.set_groupname(&params.groupname).unwrap();
            header.set_cksum();

            // Create dummy content of the right size
            let content = vec![0u8; params.size as usize];
            builder
                .append_data(&mut header, &params.path, content.as_slice())
                .unwrap();

            builder.into_inner().unwrap()
        }

        /// Create a tar archive with a symlink entry and return the header bytes.
        fn create_symlink_tar(params: &SymlinkParams) -> Vec<u8> {
            let mut builder = tar::Builder::new(Vec::new());

            let mut header = tar::Header::new_ustar();
            header.set_path(&params.path).unwrap();
            header.set_mode(0o777);
            header.set_uid(params.uid);
            header.set_gid(params.gid);
            header.set_mtime(params.mtime);
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_link_name(&params.target).unwrap();
            header.set_cksum();

            builder
                .append_data(&mut header, &params.path, std::io::empty())
                .unwrap();

            builder.into_inner().unwrap()
        }

        /// Create a tar archive with a directory entry and return the header bytes.
        fn create_dir_tar(params: &DirParams) -> Vec<u8> {
            let mut builder = tar::Builder::new(Vec::new());

            let mut header = tar::Header::new_ustar();
            // Ensure directory path ends with /
            let path = if params.path.ends_with('/') {
                params.path.clone()
            } else {
                format!("{}/", params.path)
            };
            header.set_path(&path).unwrap();
            header.set_mode(params.mode);
            header.set_uid(params.uid);
            header.set_gid(params.gid);
            header.set_mtime(params.mtime);
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Directory);
            header.set_cksum();

            builder
                .append_data(&mut header, &path, std::io::empty())
                .unwrap();

            builder.into_inner().unwrap()
        }

        /// Extract the first 512-byte header from a tar archive.
        fn extract_header_bytes(tar_data: &[u8]) -> [u8; 512] {
            let mut header = [0u8; 512];
            header.copy_from_slice(&tar_data[..512]);
            header
        }

        /// Compare our Header parsing against tar crate's parsing.
        fn compare_headers(
            our_header: &Header,
            tar_header: &tar::Header,
        ) -> std::result::Result<(), TestCaseError> {
            // Entry type
            let our_type = our_header.entry_type();
            let tar_type = tar_header.entry_type();
            match (our_type, tar_type) {
                (EntryType::Regular, tar::EntryType::Regular) => {}
                (EntryType::Directory, tar::EntryType::Directory) => {}
                (EntryType::Symlink, tar::EntryType::Symlink) => {}
                (EntryType::Link, tar::EntryType::Link) => {}
                (EntryType::Char, tar::EntryType::Char) => {}
                (EntryType::Block, tar::EntryType::Block) => {}
                (EntryType::Fifo, tar::EntryType::Fifo) => {}
                (EntryType::Continuous, tar::EntryType::Continuous) => {}
                (EntryType::GnuLongName, tar::EntryType::GNULongName) => {}
                (EntryType::GnuLongLink, tar::EntryType::GNULongLink) => {}
                (EntryType::GnuSparse, tar::EntryType::GNUSparse) => {}
                (EntryType::XHeader, tar::EntryType::XHeader) => {}
                (EntryType::XGlobalHeader, tar::EntryType::XGlobalHeader) => {}
                _ => {
                    return Err(TestCaseError::fail(format!(
                        "entry type mismatch: ours={our_type:?}, tar={tar_type:?}"
                    )));
                }
            }

            // Size
            let our_size = our_header
                .entry_size()
                .map_err(|e| TestCaseError::fail(format!("our entry_size failed: {e}")))?;
            let tar_size = tar_header
                .size()
                .map_err(|e| TestCaseError::fail(format!("tar size failed: {e}")))?;
            prop_assert_eq!(our_size, tar_size, "size mismatch");

            // Mode
            let our_mode = our_header
                .mode()
                .map_err(|e| TestCaseError::fail(format!("our mode failed: {e}")))?;
            let tar_mode = tar_header
                .mode()
                .map_err(|e| TestCaseError::fail(format!("tar mode failed: {e}")))?;
            prop_assert_eq!(our_mode, tar_mode, "mode mismatch");

            // UID
            let our_uid = our_header
                .uid()
                .map_err(|e| TestCaseError::fail(format!("our uid failed: {e}")))?;
            let tar_uid = tar_header
                .uid()
                .map_err(|e| TestCaseError::fail(format!("tar uid failed: {e}")))?;
            prop_assert_eq!(our_uid, tar_uid, "uid mismatch");

            // GID
            let our_gid = our_header
                .gid()
                .map_err(|e| TestCaseError::fail(format!("our gid failed: {e}")))?;
            let tar_gid = tar_header
                .gid()
                .map_err(|e| TestCaseError::fail(format!("tar gid failed: {e}")))?;
            prop_assert_eq!(our_gid, tar_gid, "gid mismatch");

            // Mtime
            let our_mtime = our_header
                .mtime()
                .map_err(|e| TestCaseError::fail(format!("our mtime failed: {e}")))?;
            let tar_mtime = tar_header
                .mtime()
                .map_err(|e| TestCaseError::fail(format!("tar mtime failed: {e}")))?;
            prop_assert_eq!(our_mtime, tar_mtime, "mtime mismatch");

            // Path bytes
            let our_path = our_header.path_bytes();
            let tar_path = tar_header.path_bytes();
            prop_assert_eq!(our_path, tar_path.as_ref(), "path mismatch");

            // Link name (for symlinks)
            let our_link = our_header.link_name_bytes();
            if let Some(tar_link) = tar_header.link_name_bytes() {
                prop_assert_eq!(our_link, tar_link.as_ref(), "link_name mismatch");
            } else {
                prop_assert!(our_link.is_empty(), "expected empty link name");
            }

            // Username
            if let Some(our_username) = our_header.username() {
                if let Some(tar_username) = tar_header.username_bytes() {
                    prop_assert_eq!(our_username, tar_username, "username mismatch");
                }
            }

            // Groupname
            if let Some(our_groupname) = our_header.groupname() {
                if let Some(tar_groupname) = tar_header.groupname_bytes() {
                    prop_assert_eq!(our_groupname, tar_groupname, "groupname mismatch");
                }
            }

            // Checksum verification
            our_header
                .verify_checksum()
                .map_err(|e| TestCaseError::fail(format!("checksum verification failed: {e}")))?;

            Ok(())
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn test_file_header_crosscheck(params in file_params_strategy()) {
                let tar_data = create_file_tar(&params);
                let header_bytes = extract_header_bytes(&tar_data);

                // Parse with our crate
                let our_header = Header::from_bytes_exact(&header_bytes);

                // Parse with tar crate
                let tar_header = tar::Header::from_byte_slice(&header_bytes);

                compare_headers(our_header, tar_header)?;

                // Additional file-specific checks
                prop_assert!(our_header.entry_type().is_file());
                prop_assert_eq!(our_header.entry_size().unwrap(), params.size);
            }

            #[test]
            fn test_symlink_header_crosscheck(params in symlink_params_strategy()) {
                let tar_data = create_symlink_tar(&params);
                let header_bytes = extract_header_bytes(&tar_data);

                let our_header = Header::from_bytes_exact(&header_bytes);
                let tar_header = tar::Header::from_byte_slice(&header_bytes);

                compare_headers(our_header, tar_header)?;

                // Additional symlink-specific checks
                prop_assert!(our_header.entry_type().is_symlink());
                prop_assert_eq!(
                    our_header.link_name_bytes(),
                    params.target.as_bytes()
                );
            }

            #[test]
            fn test_dir_header_crosscheck(params in dir_params_strategy()) {
                let tar_data = create_dir_tar(&params);
                let header_bytes = extract_header_bytes(&tar_data);

                let our_header = Header::from_bytes_exact(&header_bytes);
                let tar_header = tar::Header::from_byte_slice(&header_bytes);

                compare_headers(our_header, tar_header)?;

                // Additional directory-specific checks
                prop_assert!(our_header.entry_type().is_dir());
            }
        }

        /// Test reading entries from real tar archives created by the tar crate.
        mod archive_tests {
            use super::*;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(64))]

                #[test]
                fn test_multi_entry_archive(
                    files in prop::collection::vec(file_params_strategy(), 1..8),
                    dirs in prop::collection::vec(dir_params_strategy(), 0..4),
                ) {
                    // Build an archive with multiple entries
                    let mut builder = tar::Builder::new(Vec::new());

                    // Add directories first
                    for params in &dirs {
                        let mut header = tar::Header::new_ustar();
                        let path = if params.path.ends_with('/') {
                            params.path.clone()
                        } else {
                            format!("{}/", params.path)
                        };
                        header.set_path(&path).unwrap();
                        header.set_mode(params.mode);
                        header.set_uid(params.uid);
                        header.set_gid(params.gid);
                        header.set_mtime(params.mtime);
                        header.set_size(0);
                        header.set_entry_type(tar::EntryType::Directory);
                        header.set_cksum();
                        builder.append_data(&mut header, &path, std::io::empty()).unwrap();
                    }

                    // Add files
                    for params in &files {
                        let mut header = tar::Header::new_ustar();
                        header.set_path(&params.path).unwrap();
                        header.set_mode(params.mode);
                        header.set_uid(params.uid);
                        header.set_gid(params.gid);
                        header.set_mtime(params.mtime);
                        header.set_size(params.size);
                        header.set_entry_type(tar::EntryType::Regular);
                        header.set_username(&params.username).unwrap();
                        header.set_groupname(&params.groupname).unwrap();
                        header.set_cksum();

                        let content = vec![0u8; params.size as usize];
                        builder.append_data(&mut header, &params.path, content.as_slice()).unwrap();
                    }

                    let tar_data = builder.into_inner().unwrap();

                    // Now iterate through the archive and verify each header
                    let mut archive = tar::Archive::new(Cursor::new(&tar_data));
                    let entries = archive.entries().unwrap();

                    for entry_result in entries {
                        let entry = entry_result.unwrap();
                        let tar_header = entry.header();

                        // Get the raw header bytes from the archive
                        let our_header = Header::from_bytes_exact(tar_header.as_bytes());

                        compare_headers(our_header, tar_header)?;
                    }
                }
            }
        }

        /// Test GNU format headers.
        mod gnu_tests {
            use super::*;

            fn create_gnu_file_tar(params: &FileParams) -> Vec<u8> {
                let mut builder = tar::Builder::new(Vec::new());

                let mut header = tar::Header::new_gnu();
                header.set_path(&params.path).unwrap();
                header.set_mode(params.mode);
                header.set_uid(params.uid);
                header.set_gid(params.gid);
                header.set_mtime(params.mtime);
                header.set_size(params.size);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_username(&params.username).unwrap();
                header.set_groupname(&params.groupname).unwrap();
                header.set_cksum();

                let content = vec![0u8; params.size as usize];
                builder
                    .append_data(&mut header, &params.path, content.as_slice())
                    .unwrap();

                builder.into_inner().unwrap()
            }

            fn create_gnu_symlink_tar(params: &SymlinkParams) -> Vec<u8> {
                let mut builder = tar::Builder::new(Vec::new());

                let mut header = tar::Header::new_gnu();
                header.set_path(&params.path).unwrap();
                header.set_mode(0o777);
                header.set_uid(params.uid);
                header.set_gid(params.gid);
                header.set_mtime(params.mtime);
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_link_name(&params.target).unwrap();
                header.set_cksum();

                builder
                    .append_data(&mut header, &params.path, std::io::empty())
                    .unwrap();

                builder.into_inner().unwrap()
            }

            fn create_gnu_dir_tar(params: &DirParams) -> Vec<u8> {
                let mut builder = tar::Builder::new(Vec::new());

                let mut header = tar::Header::new_gnu();
                let path = if params.path.ends_with('/') {
                    params.path.clone()
                } else {
                    format!("{}/", params.path)
                };
                header.set_path(&path).unwrap();
                header.set_mode(params.mode);
                header.set_uid(params.uid);
                header.set_gid(params.gid);
                header.set_mtime(params.mtime);
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Directory);
                header.set_cksum();

                builder
                    .append_data(&mut header, &path, std::io::empty())
                    .unwrap();

                builder.into_inner().unwrap()
            }

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(128))]

                #[test]
                fn test_gnu_file_header_crosscheck(params in file_params_strategy()) {
                    let tar_data = create_gnu_file_tar(&params);
                    let header_bytes = extract_header_bytes(&tar_data);

                    let our_header = Header::from_bytes_exact(&header_bytes);
                    let tar_header = tar::Header::from_byte_slice(&header_bytes);

                    // Verify it's detected as GNU format
                    prop_assert!(our_header.is_gnu());
                    prop_assert!(!our_header.is_ustar());

                    compare_headers(our_header, tar_header)?;
                }

                #[test]
                fn test_gnu_symlink_header_crosscheck(params in symlink_params_strategy()) {
                    let tar_data = create_gnu_symlink_tar(&params);
                    let header_bytes = extract_header_bytes(&tar_data);

                    let our_header = Header::from_bytes_exact(&header_bytes);
                    let tar_header = tar::Header::from_byte_slice(&header_bytes);

                    prop_assert!(our_header.is_gnu());
                    prop_assert!(our_header.entry_type().is_symlink());

                    compare_headers(our_header, tar_header)?;
                }

                #[test]
                fn test_gnu_dir_header_crosscheck(params in dir_params_strategy()) {
                    let tar_data = create_gnu_dir_tar(&params);
                    let header_bytes = extract_header_bytes(&tar_data);

                    let our_header = Header::from_bytes_exact(&header_bytes);
                    let tar_header = tar::Header::from_byte_slice(&header_bytes);

                    prop_assert!(our_header.is_gnu());
                    prop_assert!(our_header.entry_type().is_dir());

                    compare_headers(our_header, tar_header)?;
                }
            }
        }

        /// Test format detection (UStar vs GNU vs Old).
        mod format_detection_tests {
            use super::*;

            fn create_gnu_file_tar_for_detection(params: &FileParams) -> Vec<u8> {
                let mut builder = tar::Builder::new(Vec::new());

                let mut header = tar::Header::new_gnu();
                header.set_path(&params.path).unwrap();
                header.set_mode(params.mode);
                header.set_uid(params.uid);
                header.set_gid(params.gid);
                header.set_mtime(params.mtime);
                header.set_size(params.size);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_username(&params.username).unwrap();
                header.set_groupname(&params.groupname).unwrap();
                header.set_cksum();

                let content = vec![0u8; params.size as usize];
                builder
                    .append_data(&mut header, &params.path, content.as_slice())
                    .unwrap();

                builder.into_inner().unwrap()
            }

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(128))]

                #[test]
                fn test_ustar_format_detected(params in file_params_strategy()) {
                    let tar_data = create_file_tar(&params);
                    let header_bytes = extract_header_bytes(&tar_data);

                    let our_header = Header::from_bytes_exact(&header_bytes);

                    // UStar headers should be detected correctly
                    prop_assert!(our_header.is_ustar(), "should be UStar");
                    prop_assert!(!our_header.is_gnu(), "should not be GNU");

                    // Check magic bytes directly
                    prop_assert_eq!(&header_bytes[257..263], USTAR_MAGIC);
                    prop_assert_eq!(&header_bytes[263..265], USTAR_VERSION);
                }

                #[test]
                fn test_gnu_format_detected(params in file_params_strategy()) {
                    let tar_data = create_gnu_file_tar_for_detection(&params);
                    let header_bytes = extract_header_bytes(&tar_data);

                    let our_header = Header::from_bytes_exact(&header_bytes);

                    // GNU headers should be detected correctly
                    prop_assert!(our_header.is_gnu(), "should be GNU");
                    prop_assert!(!our_header.is_ustar(), "should not be UStar");

                    // Check magic bytes directly
                    prop_assert_eq!(&header_bytes[257..263], GNU_MAGIC);
                    prop_assert_eq!(&header_bytes[263..265], GNU_VERSION);
                }
            }

            #[test]
            fn test_old_format_detection() {
                // Create a header with no magic (old format)
                let mut header_bytes = [0u8; 512];

                // Set a simple file name
                header_bytes[0..4].copy_from_slice(b"test");

                // Set mode (octal)
                header_bytes[100..107].copy_from_slice(b"0000644");

                // Set size = 0
                header_bytes[124..135].copy_from_slice(b"00000000000");

                // Set typeflag = regular file
                header_bytes[156] = b'0';

                // Compute and set checksum
                let mut checksum: u64 = 0;
                for (i, &byte) in header_bytes.iter().enumerate() {
                    if (148..156).contains(&i) {
                        checksum += u64::from(b' ');
                    } else {
                        checksum += u64::from(byte);
                    }
                }
                let checksum_str = format!("{checksum:06o}\0 ");
                header_bytes[148..156].copy_from_slice(checksum_str.as_bytes());

                let our_header = Header::from_bytes_exact(&header_bytes);

                // Old format: neither UStar nor GNU
                assert!(!our_header.is_ustar());
                assert!(!our_header.is_gnu());

                // But we can still parse basic fields
                assert_eq!(our_header.path_bytes(), b"test");
                assert_eq!(our_header.entry_type(), EntryType::Regular);
            }
        }

        /// Test checksum computation matches tar crate.
        mod checksum_tests {
            use super::*;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(256))]

                #[test]
                fn test_checksum_always_valid(params in file_params_strategy()) {
                    let tar_data = create_file_tar(&params);
                    let header_bytes = extract_header_bytes(&tar_data);

                    let our_header = Header::from_bytes_exact(&header_bytes);

                    // Checksum should always verify for valid tar headers
                    our_header.verify_checksum().map_err(|e| {
                        TestCaseError::fail(format!("checksum failed: {e}"))
                    })?;
                }

                #[test]
                fn test_checksum_recompute(params in file_params_strategy()) {
                    let tar_data = create_file_tar(&params);
                    let header_bytes = extract_header_bytes(&tar_data);

                    let our_header = Header::from_bytes_exact(&header_bytes);

                    // Our computed checksum should match
                    let computed = our_header.compute_checksum();
                    let stored = parse_octal(&header_bytes[148..156]).unwrap();

                    prop_assert_eq!(computed, stored);
                }
            }
        }

        /// Test entry type mapping is complete.
        mod entry_type_tests {
            use super::*;

            #[test]
            fn test_all_entry_types_map_correctly() {
                // Test all known entry type bytes
                let mappings: &[(u8, EntryType, tar::EntryType)] = &[
                    (b'0', EntryType::Regular, tar::EntryType::Regular),
                    (b'\0', EntryType::Regular, tar::EntryType::Regular),
                    (b'1', EntryType::Link, tar::EntryType::Link),
                    (b'2', EntryType::Symlink, tar::EntryType::Symlink),
                    (b'3', EntryType::Char, tar::EntryType::Char),
                    (b'4', EntryType::Block, tar::EntryType::Block),
                    (b'5', EntryType::Directory, tar::EntryType::Directory),
                    (b'6', EntryType::Fifo, tar::EntryType::Fifo),
                    (b'7', EntryType::Continuous, tar::EntryType::Continuous),
                    (b'L', EntryType::GnuLongName, tar::EntryType::GNULongName),
                    (b'K', EntryType::GnuLongLink, tar::EntryType::GNULongLink),
                    (b'S', EntryType::GnuSparse, tar::EntryType::GNUSparse),
                    (b'x', EntryType::XHeader, tar::EntryType::XHeader),
                    (
                        b'g',
                        EntryType::XGlobalHeader,
                        tar::EntryType::XGlobalHeader,
                    ),
                ];

                for &(byte, expected_ours, expected_tar) in mappings {
                    let ours = EntryType::from_byte(byte);
                    let tar_type = tar::EntryType::new(byte);

                    assert_eq!(ours, expected_ours, "our mapping for byte {byte}");
                    assert_eq!(tar_type, expected_tar, "tar mapping for byte {byte}");
                }
            }

            proptest! {
                #[test]
                fn test_entry_type_roundtrip(byte: u8) {
                    let our_type = EntryType::from_byte(byte);
                    let tar_type = tar::EntryType::new(byte);

                    // Both should handle unknown types gracefully
                    let our_byte = our_type.to_byte();
                    let tar_byte = tar_type.as_byte();

                    // For regular files, '\0' maps to '0'
                    if byte == b'\0' {
                        prop_assert_eq!(our_byte, b'0');
                    } else {
                        prop_assert_eq!(our_byte, tar_byte);
                    }
                }
            }
        }
    }
}
