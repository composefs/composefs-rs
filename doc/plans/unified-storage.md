# Unified Storage for Composefs-Native bootc

Status: Draft plan
Tracking: [bootc#20](https://github.com/bootc-dev/bootc/issues/20), [bootc#1190](https://github.com/bootc-dev/bootc/issues/1190)

## Problem

In composefs-native mode, bootc currently pulls container images directly
from a registry into the composefs repository via skopeo/containers-image-proxy.
This means:

1. `podman run <booted-image>` doesn't work — the image isn't in
   containers-storage, so users can't trivially run or inspect it.
2. No `zstd:chunked` support — the composefs pull path uses raw skopeo
   streaming; it doesn't benefit from the chunked download optimizations
   that containers/storage provides.
3. Two separate network fetch paths — LBIs (logically bound images) already
   go through podman/containers-storage, but the host OS image bypasses it
   entirely.

The ostree backend already has a "unified storage" mode (`bootc image
set-unified`) that pulls the OS image into bootc-owned containers-storage
first, then imports from there into ostree.  We want the composefs-native
equivalent, but with a much better data path: zero-copy reflink import
using the `cstor` module (composefs-rs PR #218).

## Goal

In composefs-native mode, the pull flow is always:

```
registry ──podman pull──▶ bootc containers-storage ──cstor reflink──▶ composefs repo
```

After upgrade, the image remains in containers-storage so `podman run
<booted-image>` works.  During GC, composefs protects images that back
any live deployment from being pruned out of containers-storage.

In the future, the `podman pull` stage could be replaced by a native Rust
fetcher (e.g. based on the `oci-distribution` crate) for environments
where podman is unavailable, but the containers-storage → composefs
import path stays the same.

## Architecture

### Current composefs-native pull flow

```
bootc upgrade
  └─▶ pull_composefs_repo()
        └─▶ composefs_oci::pull_image()       # skopeo → composefs directly
              └─▶ skopeo::pull()              # network fetch, decompress, tar-split
                    └─▶ layers as splitstreams in /sysroot/composefs/
```

### New unified pull flow

```
bootc upgrade
  └─▶ pull_composefs_unified()
        ├─▶ imgstore.pull()                   # podman pull → bootc containers-storage
        │     └─▶ image lands in /sysroot/ostree/bootc/storage/
        │
        └─▶ composefs_oci::pull()             # "containers-storage:<image>" ref
              └─▶ cstor::import_from_containers_storage()
                    └─▶ reflink/hardlink objects from overlay diff/ → composefs objects/
                    └─▶ tar-split reconstruction → splitstreams
                    └─▶ config splitstream with layer refs
```

### Avoiding data duplication

The composefs repo and bootc-owned containers-storage must be on the
same filesystem (both live under `/sysroot/`).  Because the image exists
in both stores, we avoid doubling disk usage via zero-copy linking.  The
`ensure_object_from_file` method in `composefs/src/repository.rs` tries
two strategies:

1. **Reflink** (`FICLONE` ioctl) — zero-copy, shares physical blocks.
   Works on btrfs and XFS with reflinks.  This is the ideal case: the
   composefs object and the overlay `diff/` file share the same data
   blocks on disk.

2. **Hardlink** — zero-copy, shares the same inode.  Works on any
   filesystem (ext4, XFS, btrfs).  Safe here because both files are
   immutable: composefs objects have fs-verity enabled, and
   containers-storage overlay layers are read-only image data owned by
   bootc.  The `st_nlink > 1` is a non-issue since nothing inspects
   link counts on overlay layer files.

The `ensure_object_from_file_zerocopy()` variant errors if neither
succeeds — bootc uses this since it controls the layout and guarantees
a single filesystem.

### Storage locations

```
/sysroot/
├── composefs/                      # composefs repository (SHA-512 verity)
│   ├── objects/                    # content-addressed objects (reflinked from overlay diff/)
│   ├── streams/                    # splitstreams (layers, configs, manifests)
│   │   └── refs/                   # named references (GC roots)
│   └── images/                     # EROFS filesystem images
│       └── refs/                   # named image references
├── ostree/bootc/storage/           # bootc-owned containers-storage
│   └── overlay/                    # overlay driver (layer diffs)
│       ├── <layer-id>/diff/        # ← reflink source for composefs objects
│       └── ...
└── state/deploy/                   # composefs deployment state
    ├── <verity0>/                  # booted deployment
    │   ├── <verity0>.origin        # tracks manifest_digest, container ref
    │   └── ...
    └── <verity1>/                  # staged deployment
        └── ...
```

## Implementation Plan

### Phase 1: Core unified pull for composefs-native

Changes in **bootc** (`bootc_composefs/repo.rs`):

1. **Replace `pull_composefs_repo()` with `pull_composefs_unified()`**:
   - Stage 1: `imgstore.pull()` to fetch the image into bootc-owned
     containers-storage (same infrastructure as LBI pulls and the ostree
     unified path).
   - Stage 2: construct a `containers-storage:<image>` reference and
     call `composefs_oci::pull()`, which routes to
     `cstor::import_from_containers_storage()` for zero-copy reflink
     import.
   - Tag the result as a GC root (same as today).
   - Generate the boot EROFS image (same as today).

   The fetch stage (stage 1) is intentionally a seam point: today it
   calls `podman pull`, but in the future this could be replaced by a
   native Rust fetcher (e.g. `oci-distribution` crate) that writes
   directly into containers-storage format.  The import stage (stage 2)
   stays the same regardless of how the image was fetched.

2. **Update `do_upgrade()` / `do_switch()`** in
   `bootc_composefs/update.rs` to call the unified function.  There is
   no fallback to the old direct-pull path.

3. **Update install path** in `install.rs`:
   - During `bootc install`, the source image is already in the container
     runtime's storage.  Use the cstor path to import directly from
     there into the composefs repo — no redundant re-pull.
   - After install, copy the image into bootc-owned containers-storage
     so it's available for future unified upgrades.

Changes in **composefs-rs**:

4. **Add hardlink support to `ensure_object_from_file()`** in
   `composefs/src/repository.rs`:
   - Currently: create tmpfile → reflink or copy data → enable verity
     on tmpfile → link tmpfile into `objects/<hash>`.
   - New approach for hardlinks: enable fs-verity on the *source file
     in containers-storage* → measure its verity digest to get the
     object ID → hardlink the source directly into `objects/<hash>`.
     This is safe because:
     - bootc owns the containers-storage instance
     - The files are read-only image layer data
     - fs-verity makes them immutable at the kernel level
   - The fallback chain becomes: reflink → hardlink → copy.
   - Add `ObjectStoreMethod::Hardlinked` variant to distinguish in
     stats.

   This is critical for ext4, which is the most common root filesystem
   and does not support reflinks.  The hardlink path avoids all data
   copying — only metadata (the directory entry) is created.

### Phase 2: GC integration

The critical invariant: **if composefs has a live deployment (booted,
staged, or rollback), the corresponding container image must be kept in
containers-storage**.

#### Composefs repo GC (existing, no changes)

The existing `composefs_gc()` in `gc.rs` already:
- Identifies live deployments from bootloader entries
- Reads `.origin` files to find manifest digests
- Tags manifests as GC roots (`localhost/bootc-<manifest>`)
- Runs `repo.gc()` to remove unreferenced composefs objects

No changes needed.

#### Containers-storage GC (new step in composefs_gc)

Add a step to `composefs_gc()` that prunes bootc-owned
containers-storage, keeping images backing live deployments:

```
composefs_gc():
  ... existing phases (boot binary cleanup, state dir cleanup) ...

  # NEW: Build containers-storage root set
  live_images = set()
  for each live deployment:
      read .origin → get container image reference
      live_images.add(image_reference)

  # Also keep LBI images
  for each live deployment:
      query_bound_images(deployment) → add to live_images

  # Prune containers-storage, tolerating missing images
  imgstore.prune_except_roots(live_images)

  ... existing composefs repo GC ...
```

This mirrors the existing `prune_container_store()` in `deploy.rs` that
the ostree backend uses.

#### Edge cases

- **Image manually removed from containers-storage**: The composefs repo
  still has all the data needed to boot.  The deployment is not broken —
  only `podman run <image>` wouldn't work for that image.  GC tolerates
  missing images; it doesn't fail.

- **Shared layers between OS image and LBIs**: containers-storage
  handles layer deduplication internally.  The composefs repo also
  deduplicates by content (verity hash).  No special handling needed.

### Phase 3: `podman run` integration

Once the host image is in containers-storage after an upgrade:

- `podman run <booted-image>` works — the image is in the bootc-owned
  store.
- `podman image prune` won't remove the OS image because it's in
  bootc-owned storage (`/sysroot/ostree/bootc/storage/`), not the
  user's default storage (`/var/lib/containers/storage/`).

For `podman run <booted-image>` to work transparently from the user's
podman, bootc's storage needs to be configured as an additional image
store.  This could be a drop-in `storage.conf` with
`additionalimagestore=<bootc-storage-path>`, or documented for manual
setup.  This is a UX concern that can be addressed incrementally.

## Future: Native Rust fetcher

The `podman pull` stage is a deliberate seam.  Eventually, a native Rust
OCI fetcher (possibly based on `oci-distribution` or a purpose-built
crate) could replace it.  The fetcher would need to:

- Fetch manifests and layer blobs from an OCI registry
- Write them into containers-storage format (overlay driver layout with
  tar-split metadata)
- Support auth, mirrors, and signature verification

The cstor import stage (containers-storage → composefs) would be
unchanged.  This is explicitly out of scope for now.

## Open Questions

1. **Progress reporting for podman pull**:
   [bootc#1016](https://github.com/bootc-dev/bootc/issues/1016) tracks
   getting progress out of podman pulls.  The ostree unified path
   currently shows a spinner.  We should improve this.

2. **containers-storage copy during install**: During `bootc install`,
   the source image is in the container runtime's storage (e.g.
   `/var/lib/containers/storage` on the host) and needs to be copied
   into bootc-owned storage on the target disk.  This is a
   containers-storage → containers-storage copy via `podman image push`
   and is necessarily a full data copy since the source and target are
   on different filesystems (host vs target disk).  This hits
   [container-libs#144](https://github.com/containers/container-libs/issues/144)
   but reflinks wouldn't help here anyway due to the cross-device
   boundary.  The cstor import from bootc-owned storage into composefs
   *does* get zero-copy since both are on the target disk.

## Dependencies

- composefs-rs PR #218 (cstor module) — on `import-cstor-rs-rebase`
- composefs-rs PR #263 (image refs for GC) — on `add-image-refs-for-gc`
- composefs-rs PR #278 (OciDigest cleanup) — on `oci-digest-cleanup`
- bootc composefs-native backend — merged to main
- bootc podstorage.rs / CStorage — existing infrastructure for LBIs
