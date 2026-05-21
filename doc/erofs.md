# composefs EROFS image format

composefs images are EROFS filesystem images with composefs-specific extensions. They encode
a directory tree where regular files are stored externally in a content-addressed object store
and referenced by their fs-verity digest. The EROFS image itself carries only metadata: inodes,
directory entries, extended attributes, and chunk index entries that point to the external files.

composefs-rs supports two EROFS format versions. V1 is byte-for-byte compatible with the C
`mkcomposefs` tool. V2 is the composefs-rs native default and drops several V1 constraints
that exist only for C compatibility. New repositories use V2 unless `--erofs-version v1` is
passed to `cfsctl init`.

However, V2 is not mountable by RHEL9 era EROFS, and a goal is to transition to V1 by default
for maximum compatibility.

## Format V1

V1 is selected with `cfsctl init --erofs-version v1`. The `v1_erofs` ro-compat feature flag
is written to `meta.json` so that tools without V1 support open the repository read-only.

**`composefs_version` field values in V1:**

- `0` — no user-visible whiteout files (character devices with rdev=0) in the tree
- `1` — at least one user-visible whiteout file is present

The constant `COMPOSEFS_VERSION_V1` is 0; the field only reaches 1 when user whiteouts are
found. The `--min-version` flag in `mkcomposefs` (mirrored by `mkfs_erofs_v1_min_version`)
forces the value to 1 even when no user whiteouts exist, for forward compatibility.

**Inode layout:** V1 uses compact inodes (32 bytes) when the file data and inode fit within
the constraints of the compact format, and extended inodes (64 bytes) otherwise.

**Inode traversal order:** V1 collects inodes in breadth-first order — all entries at one
directory level before descending.

**Whiteout stub table:** V1 includes 256 synthetic inode entries at the start of the inode
area, one per two-hex-character prefix `00`–`ff`. Each entry is a character-device stub
(chr 0,0) used by the overlay filesystem to resolve whiteout paths against the object store.
V2 omits them entirely.

**Whiteout escaping:** User-visible whiteout files (chr 0,0) in the tree are not stored as
character devices on disk. Instead they receive a `trusted.overlay.opaque=x` xattr and are
serialized differently. The stub entries in the whiteout table are not escaped.

**`build_time`:** The superblock `build_time` field is set to the minimum mtime across all inodes.

**xattr sharing:** Xattr entries are deduplicated using a sort key that is the full xattr name (prefix string concatenated with the suffix).

## Format V2 — Created in composefs-rs

V2 is the default for all repositories created without `--erofs-version v1`.

**`composefs_version` field:** Always `2` (the constant `COMPOSEFS_VERSION`).

**Inode layout:** V2 always uses extended inodes (64 bytes).

**Inode traversal order:** V2 collects inodes in depth-first order — all descendants of a directory before moving to the next sibling.

**No whiteout stub table:** V2 has no synthetic stub entries; whiteout files are stored directly without escaping.

**`build_time`:** Always 0.

**xattr sharing:** Xattr entries are deduplicated using a sort key of (prefix, suffix, value)
rather than the full name string, which can produce a smaller shared xattr area.

## Selecting the format

The format is fixed at repository initialization time and cannot be changed afterward.

```
cfsctl init                    # V2 (default)
cfsctl init --erofs-version v1 # V1 (C-tool compatible)
```

The format is recorded in `meta.json` as the `v1_erofs` ro-compat feature flag: present
means V1, absent means V2. Tools that do not recognize this flag open the repository
read-only rather than writing images in the wrong format.

For the standalone `mkcomposefs` tool, the equivalent flag is `--erofs-version`. The
`--min-version` flag (`mkfs_erofs_v1_min_version` in the Rust API) controls whether the
`composefs_version` field starts at 0 or 1 in V1 images regardless of whether user whiteouts
are present.
