//! Parsed tar entry with resolved metadata.

use std::borrow::Cow;

use crate::EntryType;

/// A fully-resolved tar entry with all extensions applied.
///
/// This represents the "logical" entry after accumulating GNU long name/link
/// and PAX extensions. The path and link_target use `Cow` to avoid allocations
/// when the header's inline fields suffice.
///
/// # Lifetime
///
/// The entry borrows from the parser's internal buffers. It is valid until
/// the next call to [`TarStreamParser::next_entry`].
///
/// [`TarStreamParser::next_entry`]: super::TarStreamParser::next_entry
#[derive(Debug)]
pub struct ParsedEntry<'a> {
    /// The raw 512-byte header bytes for this entry.
    ///
    /// Useful for accessing format-specific fields not exposed here,
    /// or for writing the header to a split stream.
    pub header_bytes: &'a [u8; 512],

    /// The entry type (Regular, Directory, Symlink, etc.).
    pub entry_type: EntryType,

    /// The resolved file path.
    ///
    /// Priority: PAX `path` > GNU long name > header `name` (+ UStar `prefix`).
    /// Borrowed when using header fields, owned when using extensions.
    pub path: Cow<'a, [u8]>,

    /// The resolved link target (for symlinks and hardlinks).
    ///
    /// Priority: PAX `linkpath` > GNU long link > header `linkname`.
    /// `None` for non-link entry types.
    pub link_target: Option<Cow<'a, [u8]>>,

    /// File mode/permissions from header.
    pub mode: u32,

    /// Owner UID (PAX `uid` overrides header).
    pub uid: u64,

    /// Owner GID (PAX `gid` overrides header).
    pub gid: u64,

    /// Modification time as Unix timestamp (PAX `mtime` overrides header).
    ///
    /// Note: PAX mtime can have sub-second precision, but this field
    /// only stores the integer seconds.
    pub mtime: u64,

    /// Content size in bytes.
    ///
    /// For regular files, this is the actual file size. PAX `size` overrides
    /// header size when present.
    pub size: u64,

    /// User name (from header or PAX `uname`).
    pub uname: Option<Cow<'a, [u8]>>,

    /// Group name (from header or PAX `gname`).
    pub gname: Option<Cow<'a, [u8]>>,

    /// Device major number (for block/char devices).
    pub dev_major: Option<u32>,

    /// Device minor number (for block/char devices).
    pub dev_minor: Option<u32>,

    /// Extended attributes from PAX `SCHILY.xattr.*` entries.
    ///
    /// Each tuple is (attribute_name, attribute_value) where the name
    /// has the `SCHILY.xattr.` prefix stripped.
    #[allow(clippy::type_complexity)]
    pub xattrs: Vec<(Cow<'a, [u8]>, Cow<'a, [u8]>)>,

    /// Raw PAX extensions data, if present.
    ///
    /// Allows callers to access any PAX keys not explicitly parsed above
    /// (e.g., `GNU.sparse.*`, `LIBARCHIVE.*`, `SCHILY.acl.*`).
    pub pax_data: Option<Cow<'a, [u8]>>,
}

impl<'a> ParsedEntry<'a> {
    /// Get the path as a lossy UTF-8 string.
    ///
    /// Invalid UTF-8 sequences are replaced with the Unicode replacement character.
    #[must_use]
    pub fn path_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.path)
    }

    /// Get the link target as a lossy UTF-8 string, if present.
    #[must_use]
    pub fn link_target_lossy(&self) -> Option<Cow<'_, str>> {
        self.link_target
            .as_ref()
            .map(|t| String::from_utf8_lossy(t))
    }

    /// Check if this is a regular file entry.
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.entry_type.is_file()
    }

    /// Check if this is a directory entry.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.entry_type.is_dir()
    }

    /// Check if this is a symbolic link entry.
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.entry_type.is_symlink()
    }

    /// Check if this is a hard link entry.
    #[must_use]
    pub fn is_hard_link(&self) -> bool {
        self.entry_type.is_hard_link()
    }

    /// Get the padded size (rounded up to 512-byte boundary).
    ///
    /// This is the number of bytes that follow the header in the tar stream.
    #[must_use]
    pub fn padded_size(&self) -> u64 {
        self.size.next_multiple_of(512)
    }
}
