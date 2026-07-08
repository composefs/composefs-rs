//! # composefs EROFS image format
//!
//! composefs images are EROFS filesystem images with composefs-specific extensions. They encode
//! a directory tree where regular files are stored externally in a content-addressed object store
//! and referenced by their fs-verity digest. The EROFS image itself carries only metadata: inodes,
//! directory entries, extended attributes, and chunk index entries that point to the external files.
//!
//! composefs-rs supports three EROFS format versions, selected by
//! [`FormatVersion`][crate::erofs::format::FormatVersion]. V0 and V1 share the same on-disk
//! layout (compact inodes, BFS ordering, whiteout stub table) and are both byte-for-byte
//! compatible with the C `mkcomposefs` tool (in its default and `--min-version=1` modes,
//! respectively); they differ only in the `composefs_version` header field. V2 is
//! composefs-rs's original, now legacy format, predating V1 support, and drops several V0/V1
//! constraints that exist only for C compatibility.
//!
//! `cfsctl init` defaults to V1; pass `--erofs-version 2` to select V2, or `--erofs-version 0`
//! to match the plain (no-flags) default of the C `mkcomposefs` tool. Higher-level tools such as
//! bootc initialize repositories with multiple formats enabled (V1 primary) so that images can be
//! booted on RHEL9-era kernels that require the `composefs.digest=` karg — see
//! [Generating multiple EROFS formats][crate::repository_format#generating-multiple-erofs-formats]
//! for how that's configured.
//!
//! ## Format V0 and V1 — C `mkcomposefs` compatible
//!
//! V0 is selected with `cfsctl init --erofs-version 0` and matches the C `mkcomposefs` tool's
//! plain (no version flags) output. V1 is selected with `cfsctl init --erofs-version 1` (the
//! `cfsctl` default) and matches C `mkcomposefs --min-version=1`. The `v1_erofs` ro-compat
//! feature flag is written to `meta.json` when V1 is the primary format, so that tools without
//! V1 support open the repository read-only; V0 is not covered by a compatibility flag of its
//! own (see [`repository_format`][crate::repository_format] for how the format is recorded).
//!
//! **`composefs_version` field values:**
//!
//! - V0 — `0` (the constant `COMPOSEFS_VERSION_V0`) when no user-visible whiteout files
//!   (character devices with rdev=0) are present in the tree, auto-bumped to `1`
//!   (`COMPOSEFS_VERSION_V1`) when at least one is present.
//! - V1 — always `1` (`COMPOSEFS_VERSION_V1`), regardless of whether user whiteouts are present.
//!   This matches C `mkcomposefs --min-version=1`, which forces the same value for forward
//!   compatibility.
//!
//! **Inode layout:** V0 and V1 use compact inodes (32 bytes) when the file data and inode fit
//! within the constraints of the compact format, and extended inodes (64 bytes) otherwise.
//!
//! **Inode traversal order:** V0 and V1 collect inodes in breadth-first order — all entries at
//! one directory level before descending.
//!
//! **Whiteout stub table:** V0 and V1 include 256 synthetic inode entries at the start of the
//! inode area, one per two-hex-character prefix `00`–`ff`. Each entry is a character-device stub
//! (chr 0,0) used by the overlay filesystem to resolve whiteout paths against the object store.
//! V2 omits them entirely.
//!
//! **Whiteout escaping:** User-visible whiteout files (chr 0,0) in the tree are not stored as
//! character devices on disk. Instead they receive a `trusted.overlay.opaque=x` xattr and are
//! serialized differently. The stub entries in the whiteout table are not escaped.
//!
//! **`build_time`:** The superblock `build_time` field is set to the minimum mtime across all inodes.
//!
//! **xattr sharing:** Xattr entries are deduplicated using a sort key that is the full xattr name (prefix string concatenated with the suffix).
//!
//! ## Format V2 — legacy composefs-rs format
//!
//! V2 is selected with `cfsctl init --erofs-version 2`. It was the `cfsctl` default until V1
//! became the default; repositories created before V1 support was added, and which therefore
//! predate the `erofs_formats` `meta.json` field, are still treated as V2 for backward
//! compatibility.
//!
//! **`composefs_version` field:** Always `2` (the constant `COMPOSEFS_VERSION`).
//!
//! **Inode layout:** V2 always uses extended inodes (64 bytes).
//!
//! **Inode traversal order:** V2 collects inodes in depth-first order — all descendants of a directory before moving to the next sibling.
//!
//! **No whiteout stub table:** V2 has no synthetic stub entries; whiteout files are stored directly without escaping.
//!
//! **`build_time`:** Always 0.
//!
//! **xattr sharing:** Xattr entries are deduplicated using a sort key of (prefix, suffix, value)
//! rather than the full name string, which can produce a smaller shared xattr area.
//!
//! ## Selecting the format
//!
//! The format is fixed at repository initialization time and cannot be changed afterward.
//!
//! ```text
//! cfsctl init                    # V1 (default, C-tool compatible)
//! cfsctl init --erofs-version 2  # V2 (legacy composefs-rs format)
//! cfsctl init --erofs-version 0  # V0 (plain C mkcomposefs compatible)
//! ```
//!
//! The format is recorded in `meta.json` (see [`repository_format`][crate::repository_format])
//! in the `erofs_formats` field, which is authoritative. For backward compatibility with tools
//! that predate that field, the `v1_erofs` ro-compat feature flag is also kept in sync: present
//! means V1, absent means V2 (the legacy default). Tools that do not recognize the flag open the
//! repository read-only rather than writing images in the wrong format.
//!
//! The standalone `mkcomposefs` tool (as opposed to `cfsctl`) has no `--erofs-version` flag;
//! instead its `--version`/`--max-version` flags control whether the `composefs_version` field
//! starts at 0 or 1 (see the `mkcomposefs` man page for details).
