# Canonical Tar Format

This document defines a canonical, reproducible tar serialization for composefs filesystem trees. This is a prerequisite for pushing images after an [incremental pull](incremental-pulls.md) and complements the [standardized EROFS metadata](standardized-erofs-meta.md) work.

## Motivation

In the [incremental pull](incremental-pulls.md) model, a composefs-aware client fetches only the content objects it doesn't already have, using the EROFS metadata as a table of contents. The client does not download or store the original tar layer bytes. To push this image to another registry, or to verify the OCI `diff_id` if needed, the client must be able to regenerate a byte-identical tar stream from the EROFS metadata and local object store.

Without a canonical tar format, the regenerated tar will almost certainly differ from the original (different header encoding, different entry ordering, different padding), producing different digests.

## Conceptual Model

The canonical tar format is defined as a mapping from composefs dumpfile to tar. The dumpfile is a human-readable textual format that represents a complete filesystem tree and can be converted to/from EROFS. By defining dumpfile-to-tar, we complete a triangle of deterministic conversions:

```
dumpfile ──→ canonical tar
    ↑              │
    │              ↓
    └── EROFS ←────┘
         (via standardized-erofs-meta.md)
```

A client that has an EROFS can convert to dumpfile, then to canonical tar. A builder that has a tar can convert to dumpfile, then to EROFS.

## Specification

### Header Format: pax (POSIX.1-2001)

The canonical format uses pax extended headers exclusively. pax supports long filenames, large file sizes, nanosecond timestamps, arbitrary xattrs, and large uid/gid values without the ambiguities of GNU extensions.

Each entry consists of:
1. *(If pax records are needed)* A pax extended header entry (type `x`) followed by its data blocks
2. The ustar header entry followed by any content data blocks

The pax extended header entry's name is `PaxHeaders.0/<basename>` where `<basename>` is the entry's filename component (truncated to 100 bytes if necessary).

### Global Header

The archive begins with a single pax global extended header (typeflag `g`) containing one record:

```
composefs.canonical-tar=1
```

This allows any client to detect canonical tar format by reading the first entry. Non-composefs tools will ignore the unknown key. No other global extended headers are permitted in the archive.

### Entry Ordering

Entries appear in depth-first pre-order with children sorted by filename using byte-wise comparison. This matches the ordering produced by iterating a `BTreeMap<OsStr, Inode>`, which is the in-memory representation used by composefs.

Example:
```
./
./a/
./a/x
./a/y
./b/
./b/z
./c
```

The root directory entry comes first. Directories are emitted before their children.

### Path Encoding

All paths are relative to the archive root, prefixed with `./`. Directories have a trailing `/`. For example, the dumpfile path `/usr/bin/sh` becomes `./usr/bin/sh` in the tar stream; the dumpfile path `/usr/lib/` becomes `./usr/lib/`.

Paths that fit within 100 bytes are stored entirely in the ustar `name` field. Paths longer than 100 bytes use a pax `path` record; the ustar `name` field is filled with a truncated form and the ustar `prefix` field is left empty. The ustar prefix/name split is never used, as different implementations split at different `/` boundaries, making it a source of non-reproducibility.

### Ustar Header Fields

All header fields use the ustar format (magic `ustar\0`, version `00`).

| Field | Size | Encoding | Notes |
|-------|------|----------|-------|
| name | 100 | Bytes, null-terminated | See path encoding above |
| mode | 8 | Octal, zero-padded, null-terminated | Permission bits only (no file-type bits). E.g. `0000755\0` |
| uid | 8 | Octal, zero-padded, null-terminated | Values > 2,097,151 overflow to pax |
| gid | 8 | Octal, zero-padded, null-terminated | Values > 2,097,151 overflow to pax |
| size | 12 | Octal, zero-padded, null-terminated | File content size. 0 for directories, symlinks, devices, fifos. Values > 8 GiB overflow to pax |
| mtime | 12 | Octal, zero-padded, null-terminated | Seconds since epoch. Values > 8,589,934,591 overflow to pax |
| chksum | 8 | Octal, zero-padded, null-terminated + space | Unsigned sum of all header bytes with chksum field treated as spaces |
| typeflag | 1 | ASCII | See entry types below |
| linkname | 100 | Bytes, null-terminated | Symlink/hardlink target; longer targets use pax `linkpath` |
| magic | 6 | `ustar\0` | |
| version | 2 | `00` | |
| uname | 32 | Empty (null-filled) | Not stored in EROFS; omitted |
| gname | 32 | Empty (null-filled) | Not stored in EROFS; omitted |
| devmajor | 8 | Octal, zero-padded, null-terminated | For block/char devices only; 0 otherwise |
| devminor | 8 | Octal, zero-padded, null-terminated | For block/char devices only; 0 otherwise |
| prefix | 155 | Empty (null-filled) | Never used; long paths use pax `path` instead |

Unused header bytes are zero-filled.

### Entry Types

| Dumpfile entry | typeflag | Notes |
|----------------|----------|-------|
| Regular file | `0` | Content follows header |
| Directory | `5` | Size 0, path has trailing `/` |
| Symlink | `2` | Target in linkname (or pax `linkpath`) |
| Hardlink | `1` | Target in linkname as relative `./`-prefixed path |
| Block device | `4` | devmajor/devminor set |
| Char device | `3` | devmajor/devminor set |
| FIFO | `6` | |

### Pax Extended Headers

Pax records are used only when a value overflows the ustar header capacity. The canonical format does not unconditionally emit pax headers for values that fit in ustar fields.

Pax records are emitted in the following order when present:

1. `path` (if name exceeds ustar prefix/name capacity)
2. `linkpath` (if linkname exceeds 100 bytes)
3. `size` (if > 8 GiB)
4. `uid` (if > 2,097,151)
5. `gid` (if > 2,097,151)
6. `mtime` (if > 8,589,934,591, or if sub-second precision is needed)
7. `SCHILY.xattr.*` records, sorted by full key name (byte-wise)

Each pax record is formatted as `<length> <key>=<value>\n` per POSIX.1-2001. The length field is the total byte count of the record including itself.

#### Xattr Encoding

Extended attributes are encoded as `SCHILY.xattr.<name>` pax records. Values are binary-safe (the pax record length field handles arbitrary bytes). Xattr records are sorted by the full key string (`SCHILY.xattr.security.selinux` before `SCHILY.xattr.user.foo`), using byte-wise comparison.

The following xattrs are NOT included in the canonical tar, as they are composefs implementation details:
- `trusted.overlay.metacopy`
- `trusted.overlay.redirect`
- `user.overlay.metacopy`
- `user.overlay.redirect`

#### Timestamp Precision

If the dumpfile timestamp has a non-zero nanosecond component, the `mtime` pax record is emitted as `<seconds>.<nanoseconds>` (nanoseconds without trailing zeros). If the timestamp is integer seconds and fits in the ustar mtime field, no pax record is emitted.

### Content and Padding

File content is the raw bytes from the object store (for external files, identified by fsverity digest) or the inline bytes (for files ≤ 64 bytes).

Content is followed by zero-padding to the next 512-byte block boundary. The padding bytes are all zero.

### End of Archive

The archive ends with two consecutive 512-byte blocks of zeros, per POSIX.

### Hardlink Handling

When the dumpfile contains hardlinks (multiple paths sharing the same leaf ID), the first path encountered in depth-first sorted order is emitted as a regular entry with full content. Subsequent paths referencing the same leaf are emitted as hardlink entries (typeflag `1`) with the first path as the linkname target.

The hardlink target path uses the same `./`-prefixed encoding as all other paths.

### Whiteout Representation

For per-layer (non-merged) tars, OCI whiteouts are represented as standard whiteout entries:

- **File deletion**: a zero-length regular file named `.wh.<name>` in the parent directory
- **Opaque directory**: a zero-length regular file named `.wh..wh..opq` in the directory

Whiteout entries appear in sorted order alongside regular entries. Their mode is `0000644`, uid/gid are 0, mtime is 0.

For merged/flattened tars, whiteouts do not appear (they have already been processed).

## Compression

This specification defines the uncompressed tar byte stream only. Compression (gzip, zstd, composefs-chunked framing) is a separate concern. The composefs-chunked format described in [incremental-pulls.md](incremental-pulls.md) applies zstd frame boundaries on top of this canonical ordering without changing the entry order or content.

## Implementation Notes

The [tar-core](https://github.com/composefs/tar-core) crate provides the building blocks for producing canonical tar output. It supports both pax and GNU extension modes, deterministic numeric encoding, and pax record construction. The canonical tar generator would use tar-core's `EntryBuilder` in pax mode (`ExtensionMode::Pax`), calling `build_pax_data()` to emit extended headers only when ustar fields overflow.

tar-core does not impose entry ordering; the caller (composefs) controls the order by walking the dumpfile/EROFS tree in sorted depth-first order.

## Relationship to Other Specs

The dumpfile is the canonical filesystem representation that bridges tar and EROFS. This spec defines dumpfile to tar; [standardized-erofs-meta.md](standardized-erofs-meta.md) defines dumpfile to EROFS. Together they enable round-trip conversion.

The OCI layer format (`application/vnd.oci.image.layer.v1.tar`) requires a standards-compliant tar stream. A canonical tar produced by this specification is a valid OCI layer. The `diff_id` is the SHA-256 of the uncompressed canonical tar stream.

## References

- [Incremental pulls](incremental-pulls.md): the primary consumer of canonical tar
- [Standardized EROFS metadata](standardized-erofs-meta.md): the other direction of the round-trip
- [tar-core](https://github.com/composefs/tar-core): sans-IO tar library used by composefs
- [OCI image layer spec](https://github.com/opencontainers/image-spec/blob/main/layer.md): OCI tar layer requirements
- [POSIX.1-2001 pax format](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html): pax extended header specification
