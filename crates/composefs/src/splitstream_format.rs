//! # Splitstream
//!
//! Splitstream is a trivial way of storing file formats (like tar) with the "data
//! blocks" stored in the composefs object store with the goal that it's possible
//! to bit-for-bit recreate the entire file.  It's something like the idea behind
//! [tar-split](https://github.com/vbatts/tar-split), with some important
//! differences:
//!
//!  - it's a binary format
//!
//!  - it's based on storing external objects content-addressed in the composefs
//!    object store via their fs-verity digest
//!
//!  - although it's designed with `tar` files in mind, it's not specific to `tar`,
//!    or even to the idea of an archive file: any file format can be stored as a
//!    splitstream, and it might make sense to do so for any file format that
//!    contains large chunks of embedded data
//!
//!  - in addition to the ability to split out chunks of file content (like files
//!    in a `.tar`) to separate files, it is also possible to refer to external
//!    file content, or even other splitstreams, without directly embedding that
//!    content in the referrer, which can be useful for cross-document references
//!    (such as between OCI manifests, configs, and layers)
//!
//!  - the splitstream file itself is stored in the same content-addressed object
//!    store by its own fs-verity hash
//!
//! Splitstream compresses inline file content before it is stored to disk using
//! zstd.  The main reason for this is that, after removing the actual file data,
//! the remaining `tar` metadata contains a very large amount of padding and empty
//! space and compresses extremely well.
//!
//! Splitstream is conceptually independent from composefs: you could use the
//! format with any content-addressed storage system.
//!
//! ## File format
//!
//! What follows is a non-normative documentation of the file format.  The actual
//! definition of the format is "what composefs-rs reads and writes", but this
//! document may be useful to try to understand that format.  If you'd like to
//! implement the format, please get in touch.
//!
//! The format is implemented in
//! [crate::splitstream] and
//! the structs from that file are copy-pasted here.  Please try to keep things
//! roughly in sync when making changes to either side.
//!
//! All integers are little-endian.  In the following `struct` definitions, `U`
//! means 'unsigned little endian' (as per the `zerocopy::little_endian` crate) so
//! `U64` is an unsigned 64bit little-endian integer.
//!
//! ### File ranges ("sections")
//!
//! The file format consists of a fixed-sized header at the start of the file plus
//! a number of sections located at arbitrary locations inside of the file.  All of
//! these sections are referred to by a 64-bit `[start..end)` range expressed in
//! terms of overall byte offsets within the complete file.
//!
//! ```text
//! struct FileRange {
//!     start: U64,
//!     end: U64,
//! }
//! ```
//!
//! ### Header
//!
//! The file starts with a simple fixed-size header.
//!
//! ```text
//! const SPLITSTREAM_MAGIC: [u8; 11] = *b"SplitStream";
//!
//! struct SplitstreamHeader {
//!     pub magic: [u8; 11],  // Contains SPLITSTREAM_MAGIC
//!     pub version: u8,      // must always be 0
//!     pub _flags: U16,      // is currently always 0 (but ignored)
//!     pub algorithm: u8,    // kernel fs-verity algorithm identifier (1 = sha256, 2 = sha512)
//!     pub lg_blocksize: u8, // log2 of the fs-verity block size (12 = 4k, 16 = 64k)
//!     pub info: FileRange,  // can be used to expand/move the info section in the future
//! }
//! ```
//!
//! In addition to magic values and identifiers for the fs-verity algorithm in use,
//! the header is used to find the location and size of the info section.  Future
//! expansions to the file format are imagined to occur by expanding the size of
//! the info section: if the section is larger than expected, the additional bytes
//! will be ignored by the implementation.
//!
//! ### Info section
//!
//! ```text
//! struct SplitstreamInfo {
//!     pub stream_refs: FileRange, // location of the stream references array
//!     pub object_refs: FileRange, // location of the object references array
//!     pub stream: FileRange,      // location of the zstd-compressed stream within the file
//!     pub named_refs: FileRange,  // location of the compressed named references
//!     pub content_type: U64,      // user can put whatever magic identifier they want there
//!     pub stream_size: U64,       // total uncompressed size of inline chunks and external chunks
//! }
//! ```
//!
//! The `content_type` is just an arbitrary identifier that can be used by users of
//! the file format to prevent casual user error when opening a file by its hash
//! value (to prevent showing `.tar` data as if it were json, for example).
//!
//! The `stream_size` is the total size of the original file.
//!
//! ### Stream and object refs sections
//!
//! All referred streams and objects in the file are stored as two separate flat
//! uncompressed arrays of binary fs-verity hash values.  Each of these arrays is
//! referred to from the info section (via `stream_refs` and `object_refs`).
//!
//! The number of items in the array is determined by the size of the section
//! divided by the size of the fs-verity hash value (determined by the algorithm
//! identifier in the header).
//!
//! The values are not in any particular order, but implementations should produce
//! a deterministic output.  For example, the objects reference array produced by
//! the current implementation has the external objects sorted by first-appearance
//! within the stream.
//!
//! The main motivation for storing the references uncompressed, in binary, and in
//! a flat array is to make determining the references contained within a
//! splitstream as simple as possible to improve the efficiency of garbage
//! collection on large repositories.
//!
//! ### The stream
//!
//! The main content of the splitstream is stored in the `stream` section
//! referenced from the info section.  The entire section is zstd compressed.
//!
//! Within the compressed stream, the splitstream is formed from a number of
//! "chunks".  Each chunk starts with a single 64-bit little endian value.  If that
//! number is negative, it refers to an "inline" chunk, and that (absolute) number
//! of bytes of data immediately follow it.  If the number is non-negative then it
//! is an index into the object refs array for an "external" chunk.
//!
//! Zero is a non-negative value, so it's an object reference.  It's not possible
//! to have a zero-byte inline chunk.  This also means that the high/sign bit
//! determines which case (inline vs. external) we have and there are an equal
//! number of both cases.
//!
//! The stream is reassembled by iterating over the chunks and concatenating the
//! result.  For inline chunks, the inline data is taken directly from the
//! splitstream. For external chunks, the content of the external file is used.
//!
//! The stream is over when there are no more chunks.
//!
//! ### Named references
//!
//! It's possible to have named references to other streams.  These are stored in
//! the `named_refs` section referred to from the info section.
//!
//! This section is also zstd-compressed, and is a number of nul-terminated text
//! records (including a terminator after the last record).  Each record has the
//! form `n:name` where `n` is a non-negative integer index into the stream refs
//! array and `name` is an arbitrary name.  The entries are currently sorted by
//! name (by the writer implementation) but the order is not important to the
//! reader.  Whether or not this list is "officially" sorted or not may be pinned
//! down at some future point if a need should arise.
//!
//! An example of the decompressed content of the section might be something like
//! `"0:first\01:second\0"`.
