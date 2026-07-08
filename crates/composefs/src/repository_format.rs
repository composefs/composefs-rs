//! # composefs repository design
//!
//! This document describes the current on-disk layout of a composefs repository.
//!
//! At this time, the composefs-rs repository format is not declared stable.
//!
//! ## Location
//!
//! A composefs repository is a directory located anywhere. The location is chosen
//! for the `cfsctl` command as follows:
//!
//!  - `--repo` can specify an arbitrary directory
//!
//!  - if `--user` is specified (default if the current uid is not 0), then the
//!    repository defaults to `~/.var/lib/composefs`.
//!
//!  - if `--system` is specified (default if the current uid is 0), then the
//!    repository defaults to `/sysroot/composefs`.
//!
//! ## Layout
//!
//! A composefs repository has a layout that looks something like
//!
//! ```text
//! composefs
//! ├── meta.json
//! ├── objects
//! │   ├── 00
//! │   │   ├── 002183fb91[...]
//! │   │   ├── [...]
//! │   │   └── ff9d7bd692[...]
//! │   ├── 4e
//! │   │   ├── 67eaccd9fd[...]
//! │   │   └── [...]
//! │   ├── 50
//! │   │   ├── 2b126bca0c[...]
//! │   │   └── [...]
//! │   └── [...]
//! ├── images
//! │   ├── 4e67eaccd9fd[...] -> ../objects/4e/67eaccd9fd[...]
//! │   └── refs
//! │       └── some/name -> ../../images/4e67eaccd9fd[...]
//! └── streams
//!     ├── 502b126bca0c[...] -> ../objects/50/2b126bca0c[...]
//!     └── refs
//!         └── some/name.tar -> ../../streams/502b126bca0c[...]
//! ```
//!
//! ## `meta.json`
//!
//! Added in 0.7.0. This file records repository-level metadata. When present, it is
//! created by `cfsctl init` and contains:
//!
//!  - `version` — the base repository format version (currently `1`).  Tools
//!    must refuse to operate on a repository whose version exceeds what they
//!    understand.
//!
//!  - `algorithm` — the fs-verity digest algorithm identifier, in the format
//!    `fsverity-<hash>-<lg_blocksize>`.  For example `fsverity-sha512-12`
//!    means SHA-512 with 4 KiB (2^12) blocks.
//!
//!  - `features` (optional) — an object with three arrays of feature-flag
//!    strings, following the ext4/XFS/EROFS compatibility model:
//!    - `compatible` — old tools can safely ignore these.
//!    - `read-only-compatible` — old tools may read but must not write.
//!    - `incompatible` — old tools must refuse the repository entirely.
//!
//!    The currently defined feature flags are:
//!      - `v1_erofs` (read-only-compatible) — legacy on-disk signal for the
//!        EROFS format, kept for compatibility with tools that predate the
//!        `erofs_formats` field described below: present → [V1][crate::erofs_format],
//!        absent → V2.  Tools that do not recognise this flag open the
//!        repository read-only rather than accidentally writing images in the
//!        wrong format.
//!
//!  - `erofs_formats` (optional) — the authoritative [`FormatConfig`][crate::erofs::format::FormatConfig]
//!    for this repository, e.g. `{"default": 1}` or, for a repository that
//!    generates both V1 and V2 images, `{"default": 1, "extra": [2]}`.  When
//!    present, this field determines the EROFS format(s) produced by
//!    `commit_image`; the `v1_erofs` flag is derived from it and kept in sync
//!    purely for old-tool compatibility.  When absent (repositories created
//!    before this field existed), the effective format falls back to the
//!    `v1_erofs` flag as described above.
//!
//! When `meta.json` is present, `cfsctl` auto-detects the hash algorithm and
//! errors if `--hash` is explicitly passed with a conflicting value.  When
//! the file is absent (for repositories created before this feature), `--hash`
//! is honored as before and defaults to `sha512`.
//!
//! ### `cfsctl init --erofs-version`
//!
//! The `--erofs-version` flag selects the EROFS format for newly committed
//! images.  It sets `erofs_formats` (and, for V1, the legacy `v1_erofs` flag)
//! in `meta.json`:
//!
//! ```text
//! cfsctl init                          # default: V1 EROFS (C-tool compatible)
//! cfsctl init --erofs-version 2        # V2 EROFS (legacy composefs-rs format)
//! ```
//!
//! **V1** (the `cfsctl` default) uses compact inodes where possible, BFS
//! ordering, and a whiteout stub table, producing output byte-for-byte
//! identical to C `mkcomposefs --min-version=1`.  It is understood by both C
//! `mkcomposefs`/`composefs-info` 1.0.8+ and composefs-rs, making it the best
//! choice for interoperability, which is why it became the default on the
//! path towards a stable composefs-rs 1.0.  The `v1_erofs` ro-compat flag is
//! written to `meta.json` so that tools which predate V1 support open the
//! repository read-only rather than writing images in the wrong format.
//!
//! **V2** uses extended inodes, DFS ordering, and `composefs_version=2` in the
//! EROFS superblock.  This is composefs-rs's original format, now legacy, and
//! is what all repositories created before V1 support was added use — those
//! old repositories (which lack an `erofs_formats` field and the `v1_erofs`
//! flag) continue to default to V2 rather than being silently reinterpreted
//! as V1.  V2 remains available for callers that need it, e.g. higher-level
//! tools (such as bootc) may configure a repository with multiple format
//! versions (V1 primary + V2 extra) so that images are usable on both
//! RHEL9-era and newer kernels.
//!
//! There is also a [V0][crate::erofs_format] format matching the plain
//! (non-`--min-version=1`) default output of C `mkcomposefs`.  It shares V1's
//! on-disk layout and is selectable via `--erofs-version 0`, but — since no
//! repository created before `erofs_formats` existed could have used it — it
//! is not represented by a `meta.json` feature flag of its own; the
//! `erofs_formats` field is authoritative for it.
//!
//! Re-initializing an existing repository with a different `--erofs-version` is
//! rejected with an error; the format version is fixed at init time (see below
//! for how to configure more than one format).
//!
//! ### Generating multiple EROFS formats
//!
//! `erofs_formats` is not limited to a single version: [`FormatConfig`][crate::erofs::format::FormatConfig]
//! has a `default` version (which claims the named ref and is what
//! [`erofs_version()`][crate::repository::Repository::erofs_version] reports)
//! plus an `extra` set of additional versions to generate alongside it, e.g.
//! `{"default": 1, "extra": [2]}` for a repository that produces both V1 and
//! V2 images from every commit.
//!
//! This is an API-level capability, not currently exposed through `cfsctl`:
//! a caller embedding the `composefs` crate directly (such as bootc) builds a
//! [`RepositoryConfig`][crate::repository::RepositoryConfig] with the desired
//! `erofs_formats` and passes it to
//! [`Repository::init_path`][crate::repository::Repository::init_path] at
//! creation time.  As above, there is currently no supported way — via the
//! CLI or the library — to add a format to a repository after it has been
//! initialized; `erofs_formats` is fixed for the lifetime of the repository.
//!
//! Once configured, every commit uses
//! [`FileSystem::commit_images()`][crate::tree::FileSystem::commit_images],
//! which generates one EROFS image per configured version and returns a
//! `HashMap<FormatVersion, ObjectID>`.  Only the `default` version's image
//! receives the optional named ref passed in; images for `extra` versions are
//! still written to `objects/` (content-addressed, like any other image) but
//! are otherwise anonymous, so the caller is responsible for tracking their
//! IDs itself.  [`FileSystem::commit_image()`][crate::tree::FileSystem::commit_image]
//! is a convenience wrapper around `commit_images()` that returns just the
//! `default` version's ID, for callers that don't need `extra` formats.
//!
//! The OCI crate does exactly this for dual-format repositories: it calls
//! `commit_images()` once per image and stores the resulting IDs as two
//! separate named refs on the config splitstream (`composefs.image` for V2,
//! `composefs.image.v1` for V1 — see [EROFS image tracking](#erofs-image-tracking-via-config-splitstream-refs)
//! below), so that both versions of the image stay reachable through GC
//! regardless of which one is the repository's `default`.
//!
//! ## `objects/`
//!
//! This is where the content-addressed data is stored.  The immediate children of
//! this directory are 256 subdirectories from `00` to `ff`.  Each of those
//! directories contains a number of files with 62-character hexidecimal names.
//! Taken together with the directory in which it resides, each filename represents
//! a 256bit hash value which equals the measured fs-verity digest of that file.
//! fs-verity must be enabled for every file.
//!
//! ## `images/`
//!
//! This is where composefs ([EROFS][crate::erofs_format]) images are accounted for.  The images
//! themselves are fs-verity enabled and stored in the object store in the same way
//! as the file data, but the `images/` directory contains symlinks to the images
//! that we know about.  Each symlink is named for the full 256bit fsverity digest.
//!
//! Images are tracked in a separate directory because of the security model of
//! filesystems in the Linux kernel.  Although it would be feasible for "regular
//! users" to mount an erofs in their own mount namespace, the kernel currently
//! disallows it as a way to avoid allowing non-root users to expose the filesystem
//! code to hostile data.  As such, we only mount images that we produced for
//! ourselves (with mkcomposefs), and those are the ones that are linked in this
//! directory.
//!
//! Another way to say it: we must never attempt to mount an arbitrary object: we
//! may only mount via symlinks present in this directory.
//!
//! ## `streams/`
//!
//! This is where [split streams][crate::splitstream] are stored.  As for the images,
//! this is a bunch of 256bit symlinks which are symlinks to data in the object
//! storage.
//!
//! Note: the names of the hashes in this directory are the fs-verity hashes of the
//! content of the splitstream file, not the original file.  More specifically: if
//! you have a tar file with a specific sha256 digest, and you import it into the
//! repository as a splitstream, the resulting filename in this directory will have
//! no relation to the original content.  You can, however, store a reference for
//! it.
//!
//! ## `{images,streams}/refs/`
//!
//! This is where we record which images and streams are currently "requested" by
//! some external user.  When importing a tar file, in addition to creating the
//! file in the objects database and the toplevel symlink in the `streams/`
//! directory, we also assign it a name which is chosen by the software which is
//! performing the import.
//!
//! Each ref is a symlink to the top-level entry in `images/` or `streams/`.
//!
//! There are some rough ideas for how we might namespace this.  Something like
//! this model is imagined:
//!
//! ```text
//! refs
//! ├── system
//! │   └── rootfs
//! │       ├── some_id -> ../../../974d04eaff[...]
//! │       └── [...]
//! ├── 1000                      # uid of a user
//! │   ├── flatpak
//! │   │   ├── some_id -> ../../../f8e2bec500[...]
//! │   │   └── [...]
//! │   └── containers
//! │       ├── some_id -> ../../../96a87f8b4b[...]
//! │       └── [...]
//! └── [...]
//! ```
//!
//! Where the toplevel directories are `system` plus a set of uids.  Each `system`
//! or uid subdirectory is namespaced by the particular piece of software that's
//! responsible for storing the given image or stream.
//!
//! The per-user directories will all be owned by root and have 0700 permissions,
//! but each user will be able to access their own uid-numbered subdirectories by
//! way of an acl.  The reason that we want the directories owned by root is to
//! prevent users from corrupting the layout of the repository.  The reason for the
//! acl is that read-only operations on the repository should be performed
//! directly on the repository and not via some central agent.
//!
//! ## Referring to images and streams
//!
//! Operations that are performed on images or streams (mount, cat, etc.) name the
//! stream in one of two ways:
//!
//!  - via the user-chosen name such as `refs/1000/flatpak/some_id`
//!  - via the fs-verity digest stored in the toplevel dir
//!
//! ie: the name must either start with the string `refs/`, or must be a
//! hexadecimal string (64 characters for sha256, 128 for sha512).
//!
//! In both cases, the name is a path relative to the `images/` or `streams/`
//! directory and this path contains a symlink (either direct or indirect) to the
//! underlying file in `objects/`.
//!
//! When specified via fs-verity digest, the digest is verified before performing
//! the operation.
//!
//! For example:
//!
//! ```sh
//! cfsctl mount refs/system/rootfs/some_id /mnt   # does not check fs-verity
//! cfsctl mount 974d04eaff[...] /mnt              # enforces fs-verity
//! ```
//!
//! ## OCI image storage
//!
//! OCI container images are stored using streams exclusively.  Each OCI artifact
//! (manifest, config, layer) becomes a splitstream, and OCI "tags" are refs under
//! `streams/refs/oci/`.
//!
//! ### Naming conventions
//!
//! | OCI artifact  | Stream name pattern                | Example                            |
//! |---------------|------------------------------------|------------------------------------|
//! | Manifest      | `oci-manifest-{manifest_digest}`   | `oci-manifest-sha256:abc123...`    |
//! | Config        | `oci-config-{config_digest}`       | `oci-config-sha256:def456...`      |
//! | Layer         | `oci-layer-{diff_id}`              | `oci-layer-sha256:ghi789...`       |
//! | Blob          | `oci-blob-{blob_digest}`           | `oci-blob-sha256:jkl012...`        |
//!
//! Tags are stored under `streams/refs/oci/` with percent-encoding for
//! filesystem safety (`/` → `%2F`):
//!
//! ```text
//! streams/refs/oci/myimage:latest → ../../oci-manifest-sha256:abc123...
//! ```
//!
//! ### Splitstream reference chains
//!
//! Each splitstream contains `named_refs` (semantic labels mapping to entries
//! in the `stream_refs` array) and `object_refs` (raw objects referenced by
//! the compressed stream data).  For OCI images the chain is:
//!
//! **Manifest splitstream** (`oci-manifest-sha256:...`):
//!   - `object_refs`: the manifest JSON blob
//!   - `named_refs`:
//!     - `config:{config_digest}` → config splitstream verity
//!     - `{diff_id}` → layer splitstream verity (one per layer)
//!
//! **Config splitstream** (`oci-config-sha256:...`):
//!   - `object_refs`: the config JSON blob
//!   - `named_refs`:
//!     - `{diff_id}` → layer splitstream verity (one per layer)
//!
//! **Layer splitstream** (`oci-layer-sha256:...`):
//!   - `object_refs`: file content objects extracted from the tar
//!   - `named_refs`: none (leaf node)
//!
//! Both the manifest and config redundantly reference the layers.  The GC
//! can reach layers from either path.
//!
//! ### Garbage collection
//!
//! The GC walks all refs under `streams/refs/` to find root splitstreams,
//! then transitively follows `named_refs` (by resolving fs-verity IDs
//! through a stream name map) and collects `object_refs`.  Any object not
//! reachable from a root is deleted.
//!
//! Concretely, for a tagged container image:
//!
//!  1. Tag `streams/refs/oci/myimage:v1` resolves to `oci-manifest-sha256:abc`
//!  2. Walk the manifest: mark its JSON blob and follow `named_refs` to
//!     the config and layer streams
//!  3. Walk the config: mark its JSON blob and follow `named_refs` to layers
//!     (already visited, skipped)
//!  4. Walk each layer: mark all file content objects
//!
//! When a tag is removed, the manifest and everything reachable only from it
//! becomes GC-eligible.  Layers shared between images survive as long as any
//! referencing manifest remains tagged.
//!
//! ### EROFS image tracking via config splitstream refs
//!
//! When an EROFS image is generated from an OCI image (via
//! `create_filesystem` + `commit_image`), its object ID (fs-verity digest)
//! is stored as a named ref on the config splitstream with the key
//! `composefs.image`.
//!
//! GC walks from tag → manifest → config, and finds the `composefs.image`
//! named ref.  The EROFS object ID is added to the live set, keeping the
//! EROFS image alive.  The EROFS image still needs an entry under `images/`
//! for the kernel mount security model (see above), but `images/` is not a
//! GC root — the config ref is what keeps the object alive.
//!
//! This means a single OCI tag is sufficient to keep the entire image
//! (manifest, config, layers, and the EROFS image) alive through GC.
//!
//! ### Bootable image variant
//!
//! For bootable images, a second EROFS may be generated after
//! `transform_for_boot` (stripping `/boot`, etc.).  This boot EROFS is
//! stored as a second named ref on the config, `composefs.image.boot`.
//!
//! Since the config splitstream content changes (new named ref), it gets a
//! new fs-verity digest.  This cascades: the manifest must also be
//! rewritten (its `config:` named ref now points to the new config verity),
//! producing a new manifest verity.  The tag is re-pointed to the new
//! manifest.  The old config and manifest splitstreams become unreferenced
//! and are collected by GC.
//!
//! The result: one tag still keeps everything alive — layers, raw EROFS,
//! and boot EROFS.
//!
//! ### Future: sealed images
//!
//! For sealed/signed images, the EROFS comes pre-built from the registry as
//! part of a composefs OCI artifact (referrer pattern).  The artifact
//! splitstream would hold references to the pre-fetched EROFS layers.  This
//! is complementary to the unsealed case — both use the same GC mechanism
//! (named refs pointing to EROFS objects).
