//! Split file descriptor stream format for serializing binary data with external chunks.
//!
//! This module implements a binary format for representing serialized binary files
//! (tar archives, zip files, filesystem images, etc.) where data chunks can be stored
//! externally as file descriptors rather than inline in the stream.
//!
//! # Format Overview
//!
//! A splitfdstream is a sequential stream of chunks. Each chunk begins with a signed
//! 64-bit little-endian prefix that determines the chunk type:
//!
//! | Prefix Value | Meaning |
//! |--------------|---------|
//! | `< 0`        | **Inline**: The next `abs(prefix)` bytes are literal data |
//! | `>= 0`       | **External**: Content comes from `fd[prefix + 1]` |
//!
//! # Use Cases
//!
//! The splitfdstream format is designed for scenarios where:
//!
//! - Large binary files need to be transferred with some data stored externally
//! - File descriptors can be passed alongside the stream (e.g., via Unix sockets)
//! - Deduplication is desired by referencing the same external fd multiple times
//! - Zero-copy operations are possible by referencing files directly
//!
//! # Example
//!
//! ```
//! use splitfdstream::{SplitfdstreamWriter, SplitfdstreamReader, Chunk};
//!
//! // Write a stream with mixed inline and external chunks
//! let mut buffer = Vec::new();
//! let mut writer = SplitfdstreamWriter::new(&mut buffer);
//! writer.write_inline(b"inline data").unwrap();
//! writer.write_external(0).unwrap();  // Reference fd[1]
//! writer.write_inline(b"more inline").unwrap();
//! writer.finish().unwrap();
//!
//! // Read the stream back
//! let mut reader = SplitfdstreamReader::new(buffer.as_slice());
//! while let Some(chunk) = reader.next_chunk().unwrap() {
//!     match chunk {
//!         Chunk::Inline(data) => println!("Inline: {} bytes", data.len()),
//!         Chunk::External(fd_index) => println!("External: fd[{}]", fd_index + 1),
//!     }
//! }
//! ```
//!
//! # Wire Format Details
//!
//! The stream consists of a sequence of chunks with no framing header or footer.
//! Each chunk is:
//!
//! 1. An 8-byte signed little-endian integer (the prefix)
//! 2. For inline chunks only: `abs(prefix)` bytes of literal data
//!
//! External chunks have no additional data after the prefix; the content is
//! retrieved from the file descriptor array passed alongside the stream.

use std::io::{self, Read, Write};
use std::os::fd::AsFd;

/// Maximum size for an inline chunk (256 MB).
///
/// This limit prevents denial-of-service attacks where a malicious stream
/// could specify an extremely large inline chunk size, causing unbounded
/// memory allocation.
pub const MAX_INLINE_CHUNK_SIZE: usize = 256 * 1024 * 1024;

/// A chunk read from a splitfdstream.
///
/// Chunks are either inline data embedded in the stream, or references to
/// external file descriptors that should be read separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk<'a> {
    /// Inline data embedded directly in the stream.
    Inline(&'a [u8]),

    /// Reference to an external file descriptor.
    ///
    /// The value is the fd index (0-based), meaning the actual fd is at
    /// position `fd_index + 1` in the fd array (fd\[0\] is typically the
    /// stream itself).
    External(u32),
}

/// Writer for building a splitfdstream.
///
/// The writer encodes inline data and external fd references into the
/// splitfdstream binary format.
///
/// # Example
///
/// ```
/// use splitfdstream::SplitfdstreamWriter;
///
/// let mut buffer = Vec::new();
/// let mut writer = SplitfdstreamWriter::new(&mut buffer);
///
/// // Write some inline data
/// writer.write_inline(b"Hello, world!").unwrap();
///
/// // Reference external fd at index 0 (fd[1])
/// writer.write_external(0).unwrap();
///
/// // Finish and get the underlying writer back
/// let buffer = writer.finish().unwrap();
/// ```
#[derive(Debug)]
pub struct SplitfdstreamWriter<W> {
    writer: W,
}

impl<W: Write> SplitfdstreamWriter<W> {
    /// Create a new splitfdstream writer wrapping the given writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Write inline data to the stream.
    ///
    /// The data is prefixed with a negative i64 indicating the length,
    /// followed by the literal bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying writer fails.
    pub fn write_inline(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        // Prefix is negative length
        let len = data.len() as i64;
        let prefix = -len;
        self.writer.write_all(&prefix.to_le_bytes())?;
        self.writer.write_all(data)?;
        Ok(())
    }

    /// Write an external fd reference to the stream.
    ///
    /// The fd_index is the 0-based index into the fd array. The actual
    /// file descriptor is at position `fd_index + 1` (since fd\[0\] is
    /// typically the stream itself).
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying writer fails.
    pub fn write_external(&mut self, fd_index: u32) -> io::Result<()> {
        // Prefix is fd_index (non-negative), actual fd is at fd_index + 1
        let prefix = fd_index as i64;
        self.writer.write_all(&prefix.to_le_bytes())?;
        Ok(())
    }

    /// Finish writing and return the underlying writer.
    ///
    /// This consumes the writer and returns the underlying `Write` impl.
    pub fn finish(self) -> io::Result<W> {
        Ok(self.writer)
    }
}

/// Reader for parsing a splitfdstream.
///
/// The reader parses the binary format and yields chunks that are either
/// inline data or references to external file descriptors.
///
/// # Example
///
/// ```
/// use splitfdstream::{SplitfdstreamReader, Chunk};
///
/// let data = vec![
///     // Inline chunk: prefix = -5, then 5 bytes
///     0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // -5 as i64 LE
///     b'h', b'e', b'l', b'l', b'o',
/// ];
///
/// let mut reader = SplitfdstreamReader::new(data.as_slice());
/// let chunk = reader.next_chunk().unwrap().unwrap();
/// assert_eq!(chunk, Chunk::Inline(b"hello"));
/// ```
#[derive(Debug)]
pub struct SplitfdstreamReader<R> {
    reader: R,
    /// Buffer for reading inline data
    buffer: Vec<u8>,
}

impl<R: Read> SplitfdstreamReader<R> {
    /// Create a new splitfdstream reader wrapping the given reader.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Vec::new(),
        }
    }

    /// Consume this reader, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Read the next chunk from the stream.
    ///
    /// Returns `Ok(None)` when the stream is exhausted.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Reading from the underlying reader fails
    /// - The stream contains invalid data (e.g., inline size exceeds maximum)
    pub fn next_chunk(&mut self) -> io::Result<Option<Chunk<'_>>> {
        // Read the 8-byte prefix
        let mut prefix_bytes = [0u8; 8];
        match self.reader.read_exact(&mut prefix_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }

        let prefix = i64::from_le_bytes(prefix_bytes);

        if prefix < 0 {
            // Inline chunk: read abs(prefix) bytes
            let len = (-prefix) as usize;
            if len > MAX_INLINE_CHUNK_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "inline chunk size {} exceeds maximum allowed size {}",
                        len, MAX_INLINE_CHUNK_SIZE
                    ),
                ));
            }
            self.buffer.clear();
            self.buffer.resize(len, 0);
            self.reader.read_exact(&mut self.buffer)?;
            Ok(Some(Chunk::Inline(&self.buffer)))
        } else {
            // External chunk: prefix is the fd index
            Ok(Some(Chunk::External(prefix as u32)))
        }
    }
}

/// A helper that reads a file from offset 0 using positional reads.
///
/// This allows reading the same file multiple times without seeking,
/// since each read specifies its position explicitly.
#[derive(Debug)]
struct ReadAtReader<'a, F> {
    file: &'a F,
    offset: u64,
}

impl<'a, F: AsFd> ReadAtReader<'a, F> {
    fn new(file: &'a F) -> Self {
        Self { file, offset: 0 }
    }
}

impl<F: AsFd> Read for ReadAtReader<'_, F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = rustix::io::pread(self.file, buf, self.offset)?;
        self.offset += n as u64;
        Ok(n)
    }
}

/// A `Read` adapter that reconstructs a byte stream from a splitfdstream.
///
/// This struct implements `Read` by combining inline chunks and external file
/// descriptor content into a contiguous byte stream. It can be used with
/// `tar::Archive` to parse tar entries from a splitfdstream.
///
/// External files are read using positional read (pread/read_at), so the
/// same file can be referenced multiple times in the splitfdstream without
/// needing to reopen or seek it.
///
/// # Example
///
/// ```no_run
/// use std::fs::File;
/// use splitfdstream::SplitfdstreamTarReader;
///
/// let stream_data: &[u8] = &[/* splitfdstream bytes */];
/// let files: Vec<File> = vec![/* external files */];
///
/// let mut reader = SplitfdstreamTarReader::new(stream_data, &files);
/// // Use with tar::Archive or any Read consumer
/// ```
#[derive(Debug)]
pub struct SplitfdstreamTarReader<'files, R: Read> {
    reader: SplitfdstreamReader<R>,
    files: &'files [std::fs::File],
    /// Buffer for inline data (partially consumed)
    inline_buffer: Vec<u8>,
    /// Position within inline_buffer
    inline_pos: usize,
    /// Current external file being read (if any)
    current_external: Option<ReadAtReader<'files, std::fs::File>>,
}

impl<'files, R: Read> SplitfdstreamTarReader<'files, R> {
    /// Create a new tar reader from a splitfdstream and files.
    ///
    /// The `files` slice provides the external files referenced by the
    /// splitfdstream. Each external chunk at index N reads from `files[N]`.
    pub fn new(splitfdstream: R, files: &'files [std::fs::File]) -> Self {
        Self {
            reader: SplitfdstreamReader::new(splitfdstream),
            files,
            inline_buffer: Vec::new(),
            inline_pos: 0,
            current_external: None,
        }
    }
}

impl<R: Read> Read for SplitfdstreamTarReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // First, drain any buffered inline data
        if self.inline_pos < self.inline_buffer.len() {
            let remaining = &self.inline_buffer[self.inline_pos..];
            let n = buf.len().min(remaining.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.inline_pos += n;
            return Ok(n);
        }

        // Next, drain current external file if any
        if let Some(ref mut ext) = self.current_external {
            let n = ext.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            // External exhausted, move to next chunk
            self.current_external = None;
        }

        // Get next chunk from splitfdstream
        match self.reader.next_chunk()? {
            None => Ok(0), // EOF
            Some(Chunk::Inline(data)) => {
                let n = buf.len().min(data.len());
                buf[..n].copy_from_slice(&data[..n]);
                if n < data.len() {
                    // Buffer remaining data for next read
                    self.inline_buffer.clear();
                    self.inline_buffer.extend_from_slice(&data[n..]);
                    self.inline_pos = 0;
                }
                Ok(n)
            }
            Some(Chunk::External(idx)) => {
                let idx = idx as usize;
                if idx >= self.files.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "external chunk references fd index {} but only {} files provided",
                            idx,
                            self.files.len()
                        ),
                    ));
                }
                self.current_external = Some(ReadAtReader::new(&self.files[idx]));
                // Recurse to read from the new external
                self.read(buf)
            }
        }
    }
}

/// Reconstruct a stream from splitfdstream + file descriptors.
///
/// This function reads a splitfdstream and writes the reconstructed data to `output`.
/// Inline chunks are written directly, while external chunks are read from the
/// corresponding file descriptors in `files`.
///
/// # Arguments
///
/// * `splitfdstream` - A reader providing the splitfdstream data
/// * `files` - Array of files for external chunks
/// * `output` - Writer to receive the reconstructed stream
///
/// # Returns
///
/// The total number of bytes written to `output`.
///
/// # Errors
///
/// Returns an error if:
/// * Reading from the splitfdstream fails
/// * An external chunk references a file index outside the bounds of `files`
/// * Reading from an external file fails
/// * Writing to the output fails
pub fn reconstruct<R, W>(
    splitfdstream: R,
    files: &[std::fs::File],
    output: &mut W,
) -> io::Result<u64>
where
    R: Read,
    W: Write,
{
    let mut reader = SplitfdstreamReader::new(splitfdstream);
    let mut bytes_written = 0u64;

    while let Some(chunk) = reader.next_chunk()? {
        match chunk {
            Chunk::Inline(data) => {
                output.write_all(data)?;
                bytes_written += data.len() as u64;
            }
            Chunk::External(idx) => {
                let file = files.get(idx as usize).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "external chunk references fd index {} but only {} files provided",
                            idx,
                            files.len()
                        ),
                    )
                })?;
                let mut ext_reader = ReadAtReader::new(file);
                let copied = io::copy(&mut ext_reader, output)?;
                bytes_written += copied;
            }
        }
    }

    Ok(bytes_written)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to write and read back chunks, verifying round-trip.
    fn roundtrip_chunks(
        inline_chunks: &[&[u8]],
        external_indices: &[u32],
        interleave: bool,
    ) -> Vec<(bool, Vec<u8>, u32)> {
        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);

            if interleave {
                let max_len = inline_chunks.len().max(external_indices.len());
                for i in 0..max_len {
                    if i < inline_chunks.len() {
                        writer.write_inline(inline_chunks[i]).unwrap();
                    }
                    if i < external_indices.len() {
                        writer.write_external(external_indices[i]).unwrap();
                    }
                }
            } else {
                for chunk in inline_chunks {
                    writer.write_inline(chunk).unwrap();
                }
                for &idx in external_indices {
                    writer.write_external(idx).unwrap();
                }
            }

            writer.finish().unwrap();
        }

        // Read back
        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let mut results = Vec::new();

        while let Some(chunk) = reader.next_chunk().unwrap() {
            match chunk {
                Chunk::Inline(data) => {
                    results.push((true, data.to_vec(), 0));
                }
                Chunk::External(idx) => {
                    results.push((false, Vec::new(), idx));
                }
            }
        }

        results
    }

    #[test]
    fn test_empty_stream() {
        let buffer: Vec<u8> = Vec::new();
        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        assert!(reader.next_chunk().unwrap().is_none());
    }

    #[test]
    fn test_only_inline_chunks() {
        let chunks: &[&[u8]] = &[b"hello", b"world", b"test"];
        let results = roundtrip_chunks(chunks, &[], false);

        assert_eq!(results.len(), 3);
        assert!(results[0].0); // is_inline
        assert_eq!(results[0].1, b"hello");
        assert!(results[1].0);
        assert_eq!(results[1].1, b"world");
        assert!(results[2].0);
        assert_eq!(results[2].1, b"test");
    }

    #[test]
    fn test_only_external_chunks() {
        let results = roundtrip_chunks(&[], &[0, 5, 42, 100], false);

        assert_eq!(results.len(), 4);
        assert!(!results[0].0); // is_external
        assert_eq!(results[0].2, 0);
        assert!(!results[1].0);
        assert_eq!(results[1].2, 5);
        assert!(!results[2].0);
        assert_eq!(results[2].2, 42);
        assert!(!results[3].0);
        assert_eq!(results[3].2, 100);
    }

    #[test]
    fn test_mixed_inline_external() {
        let inline: &[&[u8]] = &[b"header", b"middle", b"footer"];
        let external: &[u32] = &[0, 1, 2];
        let results = roundtrip_chunks(inline, external, true);

        // Interleaved: inline0, ext0, inline1, ext1, inline2, ext2
        assert_eq!(results.len(), 6);

        assert!(results[0].0);
        assert_eq!(results[0].1, b"header");

        assert!(!results[1].0);
        assert_eq!(results[1].2, 0);

        assert!(results[2].0);
        assert_eq!(results[2].1, b"middle");

        assert!(!results[3].0);
        assert_eq!(results[3].2, 1);

        assert!(results[4].0);
        assert_eq!(results[4].1, b"footer");

        assert!(!results[5].0);
        assert_eq!(results[5].2, 2);
    }

    #[test]
    fn test_large_inline_chunk() {
        // Test with a large chunk to verify i64 handles sizes correctly
        let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);
            writer.write_inline(&large_data).unwrap();
            writer.finish().unwrap();
        }

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let chunk = reader.next_chunk().unwrap().unwrap();

        match chunk {
            Chunk::Inline(data) => {
                assert_eq!(data.len(), 100_000);
                assert_eq!(data, large_data.as_slice());
            }
            Chunk::External(_) => panic!("Expected inline chunk"),
        }

        assert!(reader.next_chunk().unwrap().is_none());
    }

    #[test]
    fn test_empty_inline_chunk_is_skipped() {
        // Empty inline writes should be no-ops
        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);
            writer.write_inline(b"").unwrap();
            writer.write_inline(b"actual").unwrap();
            writer.write_inline(b"").unwrap();
            writer.finish().unwrap();
        }

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let chunk = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk, Chunk::Inline(b"actual"));
        assert!(reader.next_chunk().unwrap().is_none());
    }

    #[test]
    fn test_boundary_sizes() {
        // Test various boundary sizes
        let sizes = [
            1, 7, 8, 9, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097,
        ];

        for &size in &sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

            let mut buffer = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut buffer);
                writer.write_inline(&data).unwrap();
                writer.finish().unwrap();
            }

            // Verify buffer structure: 8-byte prefix + data
            assert_eq!(buffer.len(), 8 + size);

            // Verify prefix is correct negative value
            let prefix = i64::from_le_bytes(buffer[..8].try_into().unwrap());
            assert_eq!(prefix, -(size as i64));

            // Read back and verify
            let mut reader = SplitfdstreamReader::new(buffer.as_slice());
            let chunk = reader.next_chunk().unwrap().unwrap();
            match chunk {
                Chunk::Inline(read_data) => {
                    assert_eq!(read_data.len(), size);
                    assert_eq!(read_data, data.as_slice());
                }
                Chunk::External(_) => panic!("Expected inline"),
            }
        }
    }

    #[test]
    fn test_external_fd_index_zero() {
        // fd_index 0 means fd[1], test this boundary
        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);
            writer.write_external(0).unwrap();
            writer.finish().unwrap();
        }

        // Should be exactly 8 bytes (the prefix)
        assert_eq!(buffer.len(), 8);

        // Prefix should be 0
        let prefix = i64::from_le_bytes(buffer[..8].try_into().unwrap());
        assert_eq!(prefix, 0);

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let chunk = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk, Chunk::External(0));
    }

    #[test]
    fn test_large_fd_index() {
        // Test with maximum u32 fd index
        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);
            writer.write_external(u32::MAX).unwrap();
            writer.finish().unwrap();
        }

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let chunk = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk, Chunk::External(u32::MAX));
    }

    #[test]
    fn test_single_byte_inline() {
        let results = roundtrip_chunks(&[b"x"], &[], false);
        assert_eq!(results.len(), 1);
        assert!(results[0].0);
        assert_eq!(results[0].1, b"x");
    }

    #[test]
    fn test_writer_finish_returns_writer() {
        let mut buffer = Vec::new();
        let writer = SplitfdstreamWriter::new(&mut buffer);
        let returned = writer.finish().unwrap();

        // Verify we got the writer back (can write to it)
        returned.len(); // Just verify it's accessible
    }

    #[test]
    fn test_chunk_equality() {
        assert_eq!(Chunk::Inline(b"test"), Chunk::Inline(b"test"));
        assert_ne!(Chunk::Inline(b"test"), Chunk::Inline(b"other"));
        assert_eq!(Chunk::External(5), Chunk::External(5));
        assert_ne!(Chunk::External(5), Chunk::External(6));
        assert_ne!(Chunk::Inline(b"test"), Chunk::External(0));
    }

    #[test]
    fn test_many_small_chunks() {
        // Stress test with many small chunks
        let chunks: Vec<Vec<u8>> = (0..1000).map(|i| vec![i as u8; (i % 10) + 1]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();

        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);
            for chunk in &chunk_refs {
                writer.write_inline(chunk).unwrap();
            }
            writer.finish().unwrap();
        }

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let mut count = 0;
        while let Some(chunk) = reader.next_chunk().unwrap() {
            match chunk {
                Chunk::Inline(data) => {
                    assert_eq!(data, chunk_refs[count]);
                    count += 1;
                }
                Chunk::External(_) => panic!("Unexpected external"),
            }
        }
        assert_eq!(count, 1000);
    }

    #[test]
    fn test_alternating_inline_external() {
        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);
            for i in 0..50 {
                writer.write_inline(&[i as u8]).unwrap();
                writer.write_external(i as u32).unwrap();
            }
            writer.finish().unwrap();
        }

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let mut inline_count = 0;
        let mut external_count = 0;

        while let Some(chunk) = reader.next_chunk().unwrap() {
            match chunk {
                Chunk::Inline(data) => {
                    assert_eq!(data.len(), 1);
                    assert_eq!(data[0], inline_count as u8);
                    inline_count += 1;
                }
                Chunk::External(idx) => {
                    assert_eq!(idx, external_count as u32);
                    external_count += 1;
                }
            }
        }

        assert_eq!(inline_count, 50);
        assert_eq!(external_count, 50);
    }

    #[test]
    fn test_truncated_prefix_returns_none() {
        // Partial prefix (less than 8 bytes) at end of stream
        let buffer = vec![0x01, 0x02, 0x03]; // Only 3 bytes

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        // Should return None (EOF) since we can't read a complete prefix
        assert!(reader.next_chunk().unwrap().is_none());
    }

    #[test]
    fn test_truncated_data_is_error() {
        // Valid prefix saying 100 bytes, but only 10 bytes of data
        let mut buffer = Vec::new();
        let prefix: i64 = -100; // Inline, 100 bytes
        buffer.extend_from_slice(&prefix.to_le_bytes());
        buffer.extend_from_slice(&[0u8; 10]); // Only 10 bytes

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let result = reader.next_chunk();
        assert!(result.is_err());
    }

    #[test]
    fn test_inline_chunk_size_limit() {
        // Attempt to read a chunk that exceeds MAX_INLINE_CHUNK_SIZE
        let mut buffer = Vec::new();
        // Request 512 MB (exceeds 256 MB limit)
        let prefix: i64 = -(512 * 1024 * 1024);
        buffer.extend_from_slice(&prefix.to_le_bytes());

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let result = reader.next_chunk();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum"));
    }

    mod reconstruct_tests {
        use super::*;
        use std::io::Cursor;
        use tempfile::NamedTempFile;

        #[test]
        fn test_reconstruct_inline_only() {
            // Create a splitfdstream with only inline data
            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                writer.write_inline(b"Hello, ").unwrap();
                writer.write_inline(b"world!").unwrap();
                writer.finish().unwrap();
            }

            let mut output = Vec::new();
            let files: &[std::fs::File] = &[];
            let bytes = reconstruct(stream_buf.as_slice(), files, &mut output).unwrap();

            assert_eq!(output, b"Hello, world!");
            assert_eq!(bytes, 13);
        }

        #[test]
        fn test_reconstruct_empty_stream() {
            let stream_buf: Vec<u8> = Vec::new();
            let mut output = Vec::new();
            let files: &[std::fs::File] = &[];
            let bytes = reconstruct(stream_buf.as_slice(), files, &mut output).unwrap();

            assert!(output.is_empty());
            assert_eq!(bytes, 0);
        }

        #[test]
        fn test_reconstruct_with_external_fds() {
            // Create temp files with known content
            let mut file0 = NamedTempFile::new().unwrap();
            let mut file1 = NamedTempFile::new().unwrap();

            use std::io::Write;
            file0.write_all(b"EXTERNAL0").unwrap();
            file1.write_all(b"EXTERNAL1").unwrap();

            // Create splitfdstream that references these files
            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                writer.write_inline(b"[start]").unwrap();
                writer.write_external(0).unwrap(); // Reference first fd
                writer.write_inline(b"[mid]").unwrap();
                writer.write_external(1).unwrap(); // Reference second fd
                writer.write_inline(b"[end]").unwrap();
                writer.finish().unwrap();
            }

            // Open files for reading
            let f0 = std::fs::File::open(file0.path()).unwrap();
            let f1 = std::fs::File::open(file1.path()).unwrap();
            let files = [f0, f1];

            let mut output = Vec::new();
            let bytes = reconstruct(stream_buf.as_slice(), &files, &mut output).unwrap();

            assert_eq!(output, b"[start]EXTERNAL0[mid]EXTERNAL1[end]");
            assert_eq!(bytes, output.len() as u64);
        }

        #[test]
        fn test_reconstruct_external_fd_out_of_bounds() {
            // Create splitfdstream referencing fd index 5, but only provide 1 file
            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                writer.write_external(5).unwrap(); // Out of bounds
                writer.finish().unwrap();
            }

            let file = NamedTempFile::new().unwrap();
            let f = std::fs::File::open(file.path()).unwrap();
            let files = [f];

            let mut output = Vec::new();
            let result = reconstruct(stream_buf.as_slice(), &files, &mut output);

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("fd index 5"));
        }

        #[test]
        fn test_reconstruct_large_external_file() {
            // Create a larger external file to test efficient copying
            let mut file = NamedTempFile::new().unwrap();
            let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

            use std::io::Write;
            file.write_all(&large_data).unwrap();

            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                writer.write_inline(b"header").unwrap();
                writer.write_external(0).unwrap();
                writer.write_inline(b"footer").unwrap();
                writer.finish().unwrap();
            }

            let f = std::fs::File::open(file.path()).unwrap();
            let files = [f];

            let mut output = Vec::new();
            let bytes = reconstruct(stream_buf.as_slice(), &files, &mut output).unwrap();

            // Verify header + large data + footer
            assert_eq!(&output[..6], b"header");
            assert_eq!(&output[6..100_006], large_data.as_slice());
            assert_eq!(&output[100_006..], b"footer");
            assert_eq!(bytes, 6 + 100_000 + 6);
        }

        #[test]
        fn test_reconstruct_same_fd_multiple_times() {
            // Test that the same fd can be referenced multiple times
            let mut file = NamedTempFile::new().unwrap();

            use std::io::Write;
            file.write_all(b"REPEATED").unwrap();

            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                writer.write_external(0).unwrap();
                writer.write_inline(b"-").unwrap();
                writer.write_external(0).unwrap();
                writer.write_inline(b"-").unwrap();
                writer.write_external(0).unwrap();
                writer.finish().unwrap();
            }

            let f = std::fs::File::open(file.path()).unwrap();
            let files = [f];

            let mut output = Vec::new();
            let bytes = reconstruct(stream_buf.as_slice(), &files, &mut output).unwrap();

            // Each reference uses pread from offset 0, so each reads from start
            assert_eq!(output, b"REPEATED-REPEATED-REPEATED");
            assert_eq!(bytes, 26);
        }

        #[test]
        fn test_into_inner() {
            let data = vec![1, 2, 3, 4];
            let cursor = Cursor::new(data.clone());
            let reader = SplitfdstreamReader::new(cursor);
            let inner = reader.into_inner();
            assert_eq!(inner.into_inner(), data);
        }
    }

    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;
        use std::io::Write;
        use tempfile::NamedTempFile;

        /// Represents a chunk in the stream for testing purposes.
        #[derive(Debug, Clone)]
        enum TestChunk {
            Inline(Vec<u8>),
            External { fd_index: usize, content: Vec<u8> },
        }

        /// Strategy for generating inline chunk data.
        /// Bounded to reasonable sizes to keep tests fast.
        fn inline_data_strategy() -> impl Strategy<Value = Vec<u8>> {
            prop::collection::vec(any::<u8>(), 0..4096)
        }

        /// Strategy for generating external chunk content.
        fn external_content_strategy() -> impl Strategy<Value = Vec<u8>> {
            prop::collection::vec(any::<u8>(), 0..8192)
        }

        /// Strategy for generating a single test chunk.
        /// The fd_index is relative and will be resolved during test execution.
        fn chunk_strategy() -> impl Strategy<Value = TestChunk> {
            prop_oneof![
                inline_data_strategy().prop_map(TestChunk::Inline),
                (0..16usize, external_content_strategy()).prop_map(|(idx, content)| {
                    TestChunk::External {
                        fd_index: idx,
                        content,
                    }
                })
            ]
        }

        /// Strategy for generating a sequence of chunks.
        fn chunks_strategy() -> impl Strategy<Value = Vec<TestChunk>> {
            prop::collection::vec(chunk_strategy(), 0..64)
        }

        /// Execute a roundtrip test: write chunks, read them back, verify reconstruction.
        fn roundtrip_test(chunks: Vec<TestChunk>) -> Result<(), TestCaseError> {
            // Collect unique external contents and assign fd indices
            let mut external_contents: Vec<Vec<u8>> = Vec::new();

            // Normalize fd_indices to actual file indices
            let normalized_chunks: Vec<TestChunk> = chunks
                .into_iter()
                .filter_map(|chunk| match chunk {
                    TestChunk::Inline(data) => {
                        // Skip empty inline chunks (writer skips them)
                        if data.is_empty() {
                            None
                        } else {
                            Some(TestChunk::Inline(data))
                        }
                    }
                    TestChunk::External { fd_index, content } => {
                        // Map fd_index to actual position in external_contents
                        let actual_index = fd_index % 8.max(1); // Limit to 8 files max

                        // Ensure we have enough files
                        while external_contents.len() <= actual_index {
                            external_contents.push(Vec::new());
                        }

                        // Store content (may overwrite previous)
                        external_contents[actual_index] = content.clone();

                        Some(TestChunk::External {
                            fd_index: actual_index,
                            content,
                        })
                    }
                })
                .collect();

            // Create temp files for external data
            let mut temp_files: Vec<NamedTempFile> = Vec::new();
            for content in &external_contents {
                let mut f = NamedTempFile::new().map_err(|e| TestCaseError::fail(e.to_string()))?;
                f.write_all(content)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                temp_files.push(f);
            }

            // Write the splitfdstream
            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                for chunk in &normalized_chunks {
                    match chunk {
                        TestChunk::Inline(data) => {
                            writer
                                .write_inline(data)
                                .map_err(|e| TestCaseError::fail(e.to_string()))?;
                        }
                        TestChunk::External { fd_index, .. } => {
                            writer
                                .write_external(*fd_index as u32)
                                .map_err(|e| TestCaseError::fail(e.to_string()))?;
                        }
                    }
                }
                writer
                    .finish()
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
            }

            // Read back and verify chunk sequence
            let mut reader = SplitfdstreamReader::new(stream_buf.as_slice());
            let mut read_chunks = Vec::new();
            while let Some(chunk) = reader
                .next_chunk()
                .map_err(|e| TestCaseError::fail(e.to_string()))?
            {
                match chunk {
                    Chunk::Inline(data) => read_chunks.push(TestChunk::Inline(data.to_vec())),
                    Chunk::External(idx) => read_chunks.push(TestChunk::External {
                        fd_index: idx as usize,
                        content: external_contents
                            .get(idx as usize)
                            .cloned()
                            .unwrap_or_default(),
                    }),
                }
            }

            // Verify we got the same number of chunks
            prop_assert_eq!(
                normalized_chunks.len(),
                read_chunks.len(),
                "Chunk count mismatch"
            );

            // Verify each chunk matches
            for (i, (expected, actual)) in
                normalized_chunks.iter().zip(read_chunks.iter()).enumerate()
            {
                match (expected, actual) {
                    (TestChunk::Inline(expected_data), TestChunk::Inline(actual_data)) => {
                        prop_assert_eq!(
                            expected_data,
                            actual_data,
                            "Inline chunk {} data mismatch",
                            i
                        );
                    }
                    (
                        TestChunk::External { fd_index: ei, .. },
                        TestChunk::External { fd_index: ai, .. },
                    ) => {
                        prop_assert_eq!(ei, ai, "External chunk {} fd_index mismatch", i);
                    }
                    _ => {
                        return Err(TestCaseError::fail(format!(
                            "Chunk {} type mismatch: expected {:?}, got {:?}",
                            i, expected, actual
                        )));
                    }
                }
            }

            // Verify reconstruction produces correct output
            let files: Vec<std::fs::File> = temp_files
                .iter()
                .map(|f| std::fs::File::open(f.path()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| TestCaseError::fail(e.to_string()))?;

            let mut output = Vec::new();
            reconstruct(stream_buf.as_slice(), &files, &mut output)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;

            // Build expected output
            let mut expected_output = Vec::new();
            for chunk in &normalized_chunks {
                match chunk {
                    TestChunk::Inline(data) => expected_output.extend_from_slice(data),
                    TestChunk::External { fd_index, .. } => {
                        expected_output.extend_from_slice(&external_contents[*fd_index]);
                    }
                }
            }

            prop_assert_eq!(output, expected_output, "Reconstructed output mismatch");

            Ok(())
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn test_arbitrary_chunk_sequences(chunks in chunks_strategy()) {
                roundtrip_test(chunks)?;
            }

            #[test]
            fn test_inline_only_sequences(
                chunks in prop::collection::vec(inline_data_strategy(), 0..32)
            ) {
                let test_chunks: Vec<TestChunk> = chunks.into_iter()
                    .map(TestChunk::Inline)
                    .collect();
                roundtrip_test(test_chunks)?;
            }

            #[test]
            fn test_external_only_sequences(
                chunks in prop::collection::vec(
                    (0..8usize, external_content_strategy()),
                    0..32
                )
            ) {
                let test_chunks: Vec<TestChunk> = chunks.into_iter()
                    .map(|(idx, content)| TestChunk::External { fd_index: idx, content })
                    .collect();
                roundtrip_test(test_chunks)?;
            }

            #[test]
            fn test_alternating_pattern(
                inline_data in prop::collection::vec(inline_data_strategy(), 1..16),
                external_data in prop::collection::vec(external_content_strategy(), 1..16)
            ) {
                let mut test_chunks = Vec::new();
                let max_len = inline_data.len().max(external_data.len());
                for i in 0..max_len {
                    if i < inline_data.len() {
                        test_chunks.push(TestChunk::Inline(inline_data[i].clone()));
                    }
                    if i < external_data.len() {
                        test_chunks.push(TestChunk::External {
                            fd_index: i % 8,
                            content: external_data[i].clone(),
                        });
                    }
                }
                roundtrip_test(test_chunks)?;
            }

            #[test]
            fn test_same_fd_multiple_references(
                content in external_content_strategy(),
                ref_count in 1..10usize
            ) {
                let mut test_chunks = Vec::new();
                for _ in 0..ref_count {
                    test_chunks.push(TestChunk::External {
                        fd_index: 0,
                        content: content.clone(),
                    });
                }
                roundtrip_test(test_chunks)?;
            }

            #[test]
            fn test_varying_chunk_sizes(
                small in prop::collection::vec(any::<u8>(), 0..16),
                medium in prop::collection::vec(any::<u8>(), 256..1024),
                large in prop::collection::vec(any::<u8>(), 4096..8192)
            ) {
                let test_chunks = vec![
                    TestChunk::Inline(small),
                    TestChunk::Inline(medium),
                    TestChunk::Inline(large),
                ];
                roundtrip_test(test_chunks)?;
            }
        }

        /// Test SplitfdstreamTarReader with property-based approach
        mod tar_reader_tests {
            use super::*;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(128))]

                #[test]
                fn test_tar_reader_matches_reconstruct(chunks in chunks_strategy()) {
                    tar_reader_test(chunks)?;
                }
            }

            fn tar_reader_test(chunks: Vec<TestChunk>) -> Result<(), TestCaseError> {
                // Collect unique external contents and assign fd indices
                let mut external_contents: Vec<Vec<u8>> = Vec::new();

                // Normalize fd_indices to actual file indices
                let normalized_chunks: Vec<TestChunk> = chunks
                    .into_iter()
                    .filter_map(|chunk| match chunk {
                        TestChunk::Inline(data) => {
                            if data.is_empty() {
                                None
                            } else {
                                Some(TestChunk::Inline(data))
                            }
                        }
                        TestChunk::External { fd_index, content } => {
                            let actual_index = fd_index % 8.max(1);
                            while external_contents.len() <= actual_index {
                                external_contents.push(Vec::new());
                            }
                            external_contents[actual_index] = content.clone();
                            Some(TestChunk::External {
                                fd_index: actual_index,
                                content,
                            })
                        }
                    })
                    .collect();

                // Create temp files for external data
                let mut temp_files: Vec<NamedTempFile> = Vec::new();
                for content in &external_contents {
                    let mut f =
                        NamedTempFile::new().map_err(|e| TestCaseError::fail(e.to_string()))?;
                    f.write_all(content)
                        .map_err(|e| TestCaseError::fail(e.to_string()))?;
                    temp_files.push(f);
                }

                // Write the splitfdstream
                let mut stream_buf = Vec::new();
                {
                    let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                    for chunk in &normalized_chunks {
                        match chunk {
                            TestChunk::Inline(data) => {
                                writer
                                    .write_inline(data)
                                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                            }
                            TestChunk::External { fd_index, .. } => {
                                writer
                                    .write_external(*fd_index as u32)
                                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                            }
                        }
                    }
                    writer
                        .finish()
                        .map_err(|e| TestCaseError::fail(e.to_string()))?;
                }

                // Open files for reading
                let files: Vec<std::fs::File> = temp_files
                    .iter()
                    .map(|f| std::fs::File::open(f.path()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;

                // Read via SplitfdstreamTarReader
                let mut tar_reader = SplitfdstreamTarReader::new(stream_buf.as_slice(), &files);
                let mut tar_output = Vec::new();
                std::io::copy(&mut tar_reader, &mut tar_output)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;

                // Read via reconstruct
                let mut reconstruct_output = Vec::new();
                reconstruct(stream_buf.as_slice(), &files, &mut reconstruct_output)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;

                prop_assert_eq!(
                    tar_output,
                    reconstruct_output,
                    "TarReader and reconstruct outputs differ"
                );

                Ok(())
            }
        }
    }
}
