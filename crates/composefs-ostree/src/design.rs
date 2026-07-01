//! # OSTree
//!
//! composefs-rs has support for importing images from OSTree
//! repositories, by pulling from local or remote OSTree
//! repositories. These images can then be mounted as composefs images,
//! sharing disk (deduplication) with other ostree or other types of
//! images in the composefs repository.
//!
//! Native OSTree repositories are a format similar to a composefs
//! repository, but not quite the same. This means we need some
//! conversions when handling ostree commits in a composefs repository.
//!
//! OSTree images (commits) are fundamentally made up of many small sha256
//! content-addressed objects that reference each other. Each commit is
//! the root of a DAG that defines the total image. Some of the OSTree
//! objects are metadata like directory permissions, or list of files in a
//! directory. These don't really exist in composefs where all metadata is
//! part of the erofs image. However, some objects are large file objects,
//! and these are similar to the file objects in composefs
//! images. However, even these differ, because the checksum defining the
//! object is made up of both the file content and the file metadata.
//!
//! When an OSTree commit is stored in a composefs repo it is stored as a
//! single splitstream file, named `ostree-commit-$commit_id`, which uses
//! external object references to all the file content objects that will
//! be used when creating an erofs image for it. This means OSTree objects
//! for files that would be inlined in the erofs image will not be
//! external objects.
//!
//! OStree commit splitstream objects are created during a pull operation
//! and are used for two things, creating a composefs image by walking the
//! DAG, and serving as a source of already available OSTree object during
//! a pull operation. Such sources are found automatically during pull
//! (e.g. parent commit, or old commit for a ref being pulled) or can be
//! manually specified.
//!
//! ## File format
//!
//! This describes the format of the `ostree-commit-$commit_id` files.
//!
//! ### Splitstream header
//!
//! Since the commit file is a split stream it starts with the splitstream
//! headers. Of these we use two, the named refs and the object
//! refs:
//!
//!  * When an erofs image is created for the commit, it is referenced by
//!    the `composefs.image` named ref.
//!
//!  * Any external file content objects are in the external_refs
//!    table. The index of the references in this header table is used to
//!    refer to the file in the splitstream itself.
//!
//! The splitstream content type used for commits is 0xAFE138C18C463EF1.
//!
//! ### Splitstream content
//!
//! A splitstream is normally a series of internal and external chunks,
//! but the ostree commit uses only one inline chunk. This chunk is
//! basically a serialized form of the "objects" directory of an OSTree
//! repository. I.e. it has a mapping of sha256 to ostree object data.
//! All objects except file objects are stored in the standard ostree
//! object format.
//!
//! OSTree file objects are stored an ostree object stream (i.e. header +
//! content data), except the file content part may be stored
//! by referencing the index of an external object. The object format is,
//! first an 8-byte header that gives the size (in bytes) of a gvariant,
//! then comes the gvariant with the file meta in
//! OSTREE_ZLIB_FILE_HEADER_GVARIANT_FORMAT format, and then the
//! file/symlink inline data. If an external object is referenced for the
//! object then it is expected that there is no inline file data.
//!
//! The high level view of the file looks like this:
//! ```text
//! +---------------+
//! | Header        |
//! +---------------|
//! | Object IDs    |
//! +---------------|
//! | Object Info   |
//! +---------------|
//! | Content       |
//! +---------------+
//! ```
//!
//! The Object IDs is a sorted array of sha256 digests, and you would do
//! lookups in it using a binary search.  The buckets in the header can be
//! used to quickly limit the binary search based on the first byte of a
//! digest.
//!
//! Then, at the same index as the binary searched object you can look up
//! the object info which gives you the offset/length of the object
//! content data and optionally a reference to an external object.
//!
//! The exact form of the data looks like this, packed in order from the
//! start of the splitstream content. All numbers are in little endian.
//!
//! ### Header
//! ```text
//! +-----------------------------------+
//! | u32: index of commit object       |
//! | u32: flags (currently unused)     |
//! | [u32; 256]: end index of bucket   |
//! +-----------------------------------+
//! ```
//!
//! The bucket list contains the end index (in the object ids table) of
//! objects starting with that particular byte, and can be used to quickly
//! limit the search.  We can also compute the total number of objects
//! (n_objects) by looking in the last bucket.
//!
//! ### Object ids
//! ```text
//!  n_objects x (sorted)
//! +--------------------------------------------+
//! |  [u8; 32] ostree object id (binary sha256) |
//! +--------------------------------------------+
//! ```
//!
//! ### Object Info
//! ```text
//!  n_objects x
//! +-----------------------------------+
//! | u32: Offset to per-object data    |
//! | u32: Length of per-object data    |
//! | u32: Index of external object ref |
//! |      or MAXUINT32 if none.        |
//! +-----------------------------------+
//! ```
//!
//! This is an array of information for each object. Once you have found
//! the object id in the object ids table, you would look at the same
//! index in this table to find the information. Offsets to per-object
//! data are in bytes from the start of the content area, which starts at
//! the end of the Objects Info table. All data chunks references are
//! aligned to 8 bytes with respect to the start of the content area.
//! This is useful because GVariants (used by ostree) naturally want
//! 8-byte alignment.
//!
//! # Summary caching
//!
//! When pulling from a remote OSTree repository, the crate downloads and
//! caches the repository's **summary** file to resolve ref names to
//! commit checksums.  The summary is a GVariant in
//! `OSTREE_SUMMARY_GVARIANT_FORMAT`:
//!
//! ```text
//! (a(s(taya{sv}))a{sv})
//!   │                │
//!   │                └─ repository-level metadata
//!   └─ array of (ref_name, (commit_size, checksum, per-ref metadata))
//! ```
//!
//! ## Summary index (flatpak-style repos)
//!
//! Large repositories (e.g. Flathub) serve a **summary index** at
//! `summary.idx` instead of (or in addition to) the plain `summary`
//! file.  The index is a small GVariant that maps subset keys to
//! per-subset subsummary checksums:
//!
//! ```text
//! (a{s(ayaaya{sv})}a{sv})
//!   │                  │
//!   │                  └─ index-level metadata
//!   └─ dict of subset_name → (current_checksum, history, per-subset metadata)
//! ```
//!
//! Subset keys are typically architecture names (e.g. `x86_64`,
//! `aarch64`) or `{subset}-{arch}` combinations (e.g. `free-x86_64`).
//! The actual subsummaries are stored gzip-compressed on the server at
//! `summaries/{checksum}.gz` and have the same GVariant format as a
//! regular OSTree summary.
//!
//! ## Fetch strategy
//!
//! [`RemoteRepo`] uses a two-stage strategy:
//!
//! 1. **Try the summary index**: fetch `summary.idx` (small, always
//!    re-downloaded).  Look up the configured subset key (defaults to
//!    [`std::env::consts::ARCH`]).  If a cached subsummary with a
//!    matching checksum exists, reuse it; otherwise fetch, decompress,
//!    and verify the new subsummary.
//!
//! 2. **Fall back to the plain summary**: if the index is not available
//!    (404), fetch the `summary` file using conditional HTTP
//!    (`If-None-Match` / `If-Modified-Since`) to avoid unnecessary
//!    re-downloads.
//!
//! ## Cache storage
//!
//! Cached summaries are stored as splitstreams in the composefs
//! repository with content type `0x7972616d6d75736f`.
//! The splitstream inline data contains a fixed header, variable-length
//! HTTP caching strings, and the raw summary GVariant bytes.
//!
//! ```text
//! SummaryCacheHeader (36 bytes):
//!   u16 LE  etag_len           — length of ETag string (0 if absent)
//!   u16 LE  last_modified_len  — length of Last-Modified string (0 if absent)
//!   [u8;32] checksum           — SHA-256 of the summary data
//!
//! Variable part:
//!   [etag_len bytes]           — HTTP ETag value
//!   [last_modified_len bytes]  — HTTP Last-Modified value
//!
//! Summary GVariant data:
//!   [raw bytes]                — (a(s(taya{sv}))a{sv}) format
//! ```
//!
//! Stream identifiers:
//! - Plain summary: `ostree-summary-{url_key}`
//! - Subsummary: `ostree-subsummary-{subset}-{url_key}`
//!
//! Where `url_key` is the URL with the scheme stripped and `/` replaced
//! by `-` (e.g. `https://example.com/repo` → `example.com-repo`).
