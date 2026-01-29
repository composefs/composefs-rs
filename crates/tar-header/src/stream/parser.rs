//! Streaming tar parser with GNU and PAX extension support.

use std::borrow::Cow;
use std::io::Read;

use crate::{EntryType, Header, PaxExtensions, HEADER_SIZE, PAX_SCHILY_XATTR};

use super::entry::ParsedEntry;
use super::error::{Result, StreamError};
use super::limits::Limits;

/// Internal state for accumulating metadata entries.
///
/// As we read GNU long name ('L'), GNU long link ('K'), and PAX ('x') entries,
/// we store their contents here until an actual entry arrives.
#[derive(Debug, Default)]
struct PendingMetadata {
    /// Content of the most recent GNU long name entry.
    gnu_long_name: Option<Vec<u8>>,

    /// Content of the most recent GNU long link entry.
    gnu_long_link: Option<Vec<u8>>,

    /// Content of the most recent PAX extended header.
    pax_extensions: Option<Vec<u8>>,

    /// Number of metadata entries accumulated so far.
    count: usize,
}

impl PendingMetadata {
    fn is_empty(&self) -> bool {
        self.gnu_long_name.is_none()
            && self.gnu_long_link.is_none()
            && self.pax_extensions.is_none()
    }
}

/// Streaming tar parser that handles GNU and PAX extensions transparently.
///
/// This parser reads a tar stream and yields [`ParsedEntry`] values for each
/// actual entry (file, directory, symlink, etc.), automatically handling:
///
/// - GNU long name extensions (type 'L')
/// - GNU long link extensions (type 'K')
/// - PAX extended headers (type 'x')
/// - PAX global headers (type 'g') - skipped
///
/// The parser applies configurable security [`Limits`] to prevent resource
/// exhaustion from malicious or malformed archives.
///
/// # Example
///
/// ```no_run
/// use std::fs::File;
/// use std::io::{BufReader, Read};
/// use tar_header::stream::{TarStreamParser, Limits};
///
/// let file = File::open("archive.tar").unwrap();
/// let reader = BufReader::new(file);
/// let mut parser = TarStreamParser::new(reader, Limits::default());
///
/// while let Some(entry) = parser.next_entry().unwrap() {
///     println!("Entry: {:?}", entry.path_lossy());
///     let size = entry.size;
///     let is_file = entry.is_file();
///     drop(entry); // Release borrow before calling skip_content
///     if is_file && size > 0 {
///         parser.skip_content(size).unwrap();
///     }
/// }
/// ```
///
/// # Content Reading
///
/// After `next_entry()` returns an entry, the content bytes (if any) have
/// NOT been read. The caller must either:
///
/// 1. Call [`skip_content`] to skip past the content and padding
/// 2. Read exactly `entry.size` bytes from [`reader`], then call
///    [`skip_padding`] to advance past the padding
///
/// [`skip_content`]: TarStreamParser::skip_content
/// [`reader`]: TarStreamParser::reader
/// [`skip_padding`]: TarStreamParser::skip_padding
#[derive(Debug)]
pub struct TarStreamParser<R> {
    reader: R,
    limits: Limits,
    pending: PendingMetadata,
    /// Buffer for the current header (reused across entries)
    header_buf: [u8; HEADER_SIZE],
    /// Current position in the stream (for error messages)
    pos: u64,
    /// Whether we've seen EOF or end-of-archive marker
    done: bool,
}

impl<R: Read> TarStreamParser<R> {
    /// Create a new tar stream parser with the given reader and limits.
    pub fn new(reader: R, limits: Limits) -> Self {
        Self {
            reader,
            limits,
            pending: PendingMetadata::default(),
            header_buf: [0u8; HEADER_SIZE],
            pos: 0,
            done: false,
        }
    }

    /// Create a new tar stream parser with default limits.
    pub fn with_defaults(reader: R) -> Self {
        Self::new(reader, Limits::default())
    }

    /// Get the current position in the stream.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.pos
    }

    /// Get the next actual entry, handling all metadata entries transparently.
    ///
    /// Returns `Ok(None)` at end of archive (zero block or EOF).
    /// Returns `Err(OrphanedMetadata)` if metadata entries exist but archive ends.
    ///
    /// After this returns `Some(entry)`, the caller must read or skip the
    /// entry's content before calling `next_entry` again.
    pub fn next_entry(&mut self) -> Result<Option<ParsedEntry<'_>>> {
        if self.done {
            return Ok(None);
        }

        loop {
            // Check pending entry limit
            if self.pending.count > self.limits.max_pending_entries {
                return Err(StreamError::TooManyPendingEntries {
                    count: self.pending.count,
                    limit: self.limits.max_pending_entries,
                });
            }

            // Read the next header
            let got_header = read_exact_or_eof(&mut self.reader, &mut self.header_buf)?;
            if !got_header {
                // EOF reached
                self.done = true;
                if !self.pending.is_empty() {
                    return Err(StreamError::OrphanedMetadata);
                }
                return Ok(None);
            }
            self.pos += HEADER_SIZE as u64;

            // Check for zero block (end of archive marker)
            if self.header_buf.iter().all(|&b| b == 0) {
                self.done = true;
                if !self.pending.is_empty() {
                    return Err(StreamError::OrphanedMetadata);
                }
                return Ok(None);
            }

            // Parse and verify header
            let header = Header::from_bytes_exact(&self.header_buf);
            header.verify_checksum()?;

            let entry_type = header.entry_type();
            let size = header.entry_size()?;
            let padded_size = size
                .checked_next_multiple_of(512)
                .ok_or(StreamError::InvalidSize(size))?;

            match entry_type {
                EntryType::GnuLongName => {
                    self.handle_gnu_long_name(size, padded_size)?;
                    continue;
                }
                EntryType::GnuLongLink => {
                    self.handle_gnu_long_link(size, padded_size)?;
                    continue;
                }
                EntryType::XHeader => {
                    self.handle_pax_header(size, padded_size)?;
                    continue;
                }
                EntryType::XGlobalHeader => {
                    // Global PAX headers affect all subsequent entries.
                    // For simplicity, we skip them. A more complete impl
                    // would merge them into parser state.
                    self.skip_bytes(padded_size)?;
                    continue;
                }
                _ => {
                    // This is an actual entry - resolve metadata and return
                    // We need to reset pending BEFORE creating the entry to avoid borrow issues
                    // But we need the pending data to create the entry...
                    // Solution: take ownership of pending data
                    let gnu_long_name = self.pending.gnu_long_name.take();
                    let gnu_long_link = self.pending.gnu_long_link.take();
                    let pax_extensions = self.pending.pax_extensions.take();
                    self.pending.count = 0;

                    let entry = self.resolve_entry_with_pending(
                        gnu_long_name,
                        gnu_long_link,
                        pax_extensions,
                    )?;
                    return Ok(Some(entry));
                }
            }
        }
    }

    /// Skip the content and padding of the current entry.
    ///
    /// Call this after `next_entry()` returns to advance past the entry's data.
    /// This is equivalent to calling `skip_bytes(entry.padded_size())`.
    pub fn skip_content(&mut self, size: u64) -> Result<()> {
        let padded = size
            .checked_next_multiple_of(512)
            .ok_or(StreamError::InvalidSize(size))?;
        self.skip_bytes(padded)
    }

    /// Skip the padding after reading content.
    ///
    /// After reading exactly `content_size` bytes from the reader, call this
    /// to advance past the padding bytes to the next header.
    pub fn skip_padding(&mut self, content_size: u64) -> Result<()> {
        let padded = content_size
            .checked_next_multiple_of(512)
            .ok_or(StreamError::InvalidSize(content_size))?;
        let padding = padded - content_size;
        if padding > 0 {
            self.skip_bytes(padding)?;
        }
        Ok(())
    }

    /// Get a mutable reference to the underlying reader.
    ///
    /// Use this to read entry content after `next_entry()` returns.
    /// Read exactly `entry.size` bytes, then call `skip_padding(entry.size)`.
    pub fn reader(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Consume the parser and return the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Get the current limits.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// Read exactly `len` bytes into a new Vec.
    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Skip `len` bytes (read and discard).
    fn skip_bytes(&mut self, len: u64) -> Result<()> {
        let mut remaining = len;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
            self.reader.read_exact(&mut buf[..to_read])?;
            remaining -= to_read as u64;
        }
        self.pos += len;
        Ok(())
    }

    fn handle_gnu_long_name(&mut self, size: u64, padded_size: u64) -> Result<()> {
        // Check for duplicate
        if self.pending.gnu_long_name.is_some() {
            return Err(StreamError::DuplicateGnuLongName);
        }

        // Check size limit
        if size > self.limits.max_gnu_long_size {
            return Err(StreamError::GnuLongTooLarge {
                size,
                limit: self.limits.max_gnu_long_size,
            });
        }

        // Read content
        let mut data = self.read_vec(size as usize)?;
        self.skip_bytes(padded_size - size)?;

        // Strip trailing null
        data.pop_if(|&mut x| x == 0);

        // Check path length limit
        if data.len() > self.limits.max_path_len {
            return Err(StreamError::PathTooLong {
                len: data.len(),
                limit: self.limits.max_path_len,
            });
        }

        self.pending.gnu_long_name = Some(data);
        self.pending.count += 1;
        Ok(())
    }

    fn handle_gnu_long_link(&mut self, size: u64, padded_size: u64) -> Result<()> {
        // Check for duplicate
        if self.pending.gnu_long_link.is_some() {
            return Err(StreamError::DuplicateGnuLongLink);
        }

        // Check size limit
        if size > self.limits.max_gnu_long_size {
            return Err(StreamError::GnuLongTooLarge {
                size,
                limit: self.limits.max_gnu_long_size,
            });
        }

        // Read content
        let mut data = self.read_vec(size as usize)?;
        self.skip_bytes(padded_size - size)?;

        // Strip trailing null
        data.pop_if(|&mut x| x == 0);

        // Check path length limit
        if data.len() > self.limits.max_path_len {
            return Err(StreamError::PathTooLong {
                len: data.len(),
                limit: self.limits.max_path_len,
            });
        }

        self.pending.gnu_long_link = Some(data);
        self.pending.count += 1;
        Ok(())
    }

    fn handle_pax_header(&mut self, size: u64, padded_size: u64) -> Result<()> {
        // Check for duplicate
        if self.pending.pax_extensions.is_some() {
            return Err(StreamError::DuplicatePaxHeader);
        }

        // Check size limit
        if size > self.limits.max_pax_size {
            return Err(StreamError::PaxTooLarge {
                size,
                limit: self.limits.max_pax_size,
            });
        }

        // Read content
        let data = self.read_vec(size as usize)?;
        self.skip_bytes(padded_size - size)?;

        self.pending.pax_extensions = Some(data);
        self.pending.count += 1;
        Ok(())
    }

    fn resolve_entry_with_pending(
        &self,
        gnu_long_name: Option<Vec<u8>>,
        gnu_long_link: Option<Vec<u8>>,
        pax_extensions: Option<Vec<u8>>,
    ) -> Result<ParsedEntry<'_>> {
        let header = Header::from_bytes_exact(&self.header_buf);

        // Start with header values
        let mut path: Cow<'_, [u8]> = Cow::Borrowed(header.path_bytes());
        let mut link_target: Option<Cow<'_, [u8]>> = None;
        let mut uid = header.uid()?;
        let mut gid = header.gid()?;
        let mut mtime = header.mtime()?;
        let mut entry_size = header.entry_size()?;
        let mut xattrs = Vec::new();
        let mut uname: Option<Cow<'_, [u8]>> = header.username().map(Cow::Borrowed);
        let mut gname: Option<Cow<'_, [u8]>> = header.groupname().map(Cow::Borrowed);

        // Handle UStar prefix for path
        if let Some(prefix) = header.prefix() {
            if !prefix.is_empty() {
                let mut full_path = prefix.to_vec();
                full_path.push(b'/');
                full_path.extend_from_slice(header.path_bytes());
                path = Cow::Owned(full_path);
            }
        }

        // Apply GNU long name (overrides header + prefix)
        if let Some(long_name) = gnu_long_name {
            path = Cow::Owned(long_name);
        }

        // Apply GNU long link
        if let Some(long_link) = gnu_long_link {
            link_target = Some(Cow::Owned(long_link));
        } else {
            let header_link = header.link_name_bytes();
            if !header_link.is_empty() {
                link_target = Some(Cow::Borrowed(header_link));
            }
        }

        // Apply PAX extensions (highest priority)
        let pax_data: Option<Cow<'_, [u8]>> =
            pax_extensions.as_ref().map(|v| Cow::Owned(v.clone()));

        if let Some(ref pax) = pax_extensions {
            let extensions = PaxExtensions::new(pax);

            for ext in extensions {
                let ext = ext?;
                let key = ext.key().map_err(StreamError::from)?;
                let value = ext.value_bytes();

                match key {
                    "path" => {
                        // Check length limit
                        if value.len() > self.limits.max_path_len {
                            return Err(StreamError::PathTooLong {
                                len: value.len(),
                                limit: self.limits.max_path_len,
                            });
                        }
                        path = Cow::Owned(value.to_vec());
                    }
                    "linkpath" => {
                        if value.len() > self.limits.max_path_len {
                            return Err(StreamError::PathTooLong {
                                len: value.len(),
                                limit: self.limits.max_path_len,
                            });
                        }
                        link_target = Some(Cow::Owned(value.to_vec()));
                    }
                    "size" => {
                        if let Ok(v) = ext.value() {
                            if let Ok(s) = v.parse::<u64>() {
                                entry_size = s;
                            }
                        }
                    }
                    "uid" => {
                        if let Ok(v) = ext.value() {
                            if let Ok(u) = v.parse::<u64>() {
                                uid = u;
                            }
                        }
                    }
                    "gid" => {
                        if let Ok(v) = ext.value() {
                            if let Ok(g) = v.parse::<u64>() {
                                gid = g;
                            }
                        }
                    }
                    "mtime" => {
                        // PAX mtime can be a decimal; truncate to integer
                        if let Ok(v) = ext.value() {
                            if let Some(s) = v.split('.').next() {
                                if let Ok(m) = s.parse::<u64>() {
                                    mtime = m;
                                }
                            }
                        }
                    }
                    "uname" => {
                        uname = Some(Cow::Owned(value.to_vec()));
                    }
                    "gname" => {
                        gname = Some(Cow::Owned(value.to_vec()));
                    }
                    _ if key.starts_with(PAX_SCHILY_XATTR) => {
                        let attr_name = &key[PAX_SCHILY_XATTR.len()..];
                        xattrs.push((
                            Cow::Owned(attr_name.as_bytes().to_vec()),
                            Cow::Owned(value.to_vec()),
                        ));
                    }
                    _ => {
                        // Ignore unknown keys
                    }
                }
            }
        }

        // Validate final path length
        if path.len() > self.limits.max_path_len {
            return Err(StreamError::PathTooLong {
                len: path.len(),
                limit: self.limits.max_path_len,
            });
        }

        Ok(ParsedEntry {
            header_bytes: &self.header_buf,
            entry_type: header.entry_type(),
            path,
            link_target,
            mode: header.mode()?,
            uid,
            gid,
            mtime,
            size: entry_size,
            uname,
            gname,
            dev_major: header.device_major()?,
            dev_minor: header.device_minor()?,
            xattrs,
            pax_data,
        })
    }
}

/// Read exactly `buf.len()` bytes, returning false if EOF before any bytes.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => {
                if total == 0 {
                    return Ok(false); // Clean EOF
                }
                return Err(StreamError::UnexpectedEof { pos: 0 });
            }
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}
