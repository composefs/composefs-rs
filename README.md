# composefs: The reliability of disk images, the flexibility of files
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcomposefs%2Fcomposefs-rs.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcomposefs%2Fcomposefs-rs?ref=badge_shield)


The composefs project combines several underlying Linux features
to provide a very flexible mechanism to support read-only
mountable filesystem trees, stacking on top of an underlying
"lower" Linux filesystem.

This repository is the primary reference implementation of composefs, written in Rust.
It replaces the [previous C-based implementation](https://github.com/composefs/composefs);
for background on this transition, see [this discussion](https://github.com/composefs/composefs/discussions/423).

## How it works

The key technologies composefs uses are:

- [overlayfs](https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt) as the kernel interface
- [EROFS](https://erofs.docs.kernel.org) for a mountable metadata tree
- [fs-verity](https://www.kernel.org/doc/html/next/filesystems/fsverity.html) (optional) from the lower filesystem

composefs does not store any persistent data itself.
The underlying metadata and data files must be stored in a valid
"lower" Linux filesystem — usually a traditional writable persistent
filesystem such as `ext4`, `xfs`, or `btrfs`.

The tagline — "The reliability of disk images, the flexibility of files" —
captures the core design philosophy. Disk images have desirable
properties: they're efficiently kernel-mountable and explicit about layout,
and tools like [dm-verity](https://docs.kernel.org/admin-guide/device-mapper/verity.html)
provide robust security. But disk images commonly duplicate storage,
are difficult to update incrementally, and are generally inflexible.

composefs provides a similarly high level of reliability, security,
and Linux kernel integration, but with the *flexibility* of files
for content — avoiding doubled disk usage, partition table management,
and similar headaches.

### Separation between metadata and data

A key aspect of composefs is its separation of "data" (non-empty regular
files) from "metadata" (everything else: directories, symlinks, permissions,
ownership, etc.).

composefs produces an [EROFS](https://erofs.docs.kernel.org) filesystem
image that contains only metadata. The non-empty data files live in a
separate "backing store" directory. The EROFS image includes
`trusted.overlay.redirect` extended attributes that tell the overlayfs
mount how to find the real underlying files.

### Shared backing store

The primary use case for composefs is versioned, immutable filesystem
trees — container images and bootable host systems — where multiple
images may share parts of their storage.

By storing files content-addressed (named by the hash of their content),
shared files need to be stored only once on disk yet can appear in
multiple mounts. Crucially, these data files are also shared in the
[page cache](https://static.lwn.net/kerneldoc/admin-guide/mm/concepts.html#page-cache),
allowing multiple running container images to reliably share memory.

### Filesystem integrity

composefs supports [fs-verity](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html)
validation of content files. The digest of each content file is stored
in the EROFS image via `trusted.overlay.metacopy` extended attributes,
which overlayfs validates when the file is accessed. This means backing
content cannot be changed (by mistake or by malice) without detection.

You can also enable fs-verity on the image file itself and pass the expected
digest as a mount option. This provides full trust of both data and metadata,
solving a weakness of fs-verity alone (which can only verify file data,
not metadata like permissions, ownership, or directory structure).

## Use cases

### Container images

For [OCI](https://github.com/opencontainers/image-spec/blob/main/spec.md)
container images, a common approach (used by both Docker and Podman) is
to untar each layer separately and use overlayfs to stitch them together.
composefs improves on this by storing file content in a content-addressed
fashion, allowing sharing between images even when metadata like
timestamps or ownership differs.

Combined with approaches like
[zstd:chunked](https://github.com/containers/storage/pull/775),
this speeds up pulling container images and avoids redundantly
creating files that are already present.

### Bootable host systems

Anywhere one wants versioned immutable filesystem trees ("images"),
composefs provides compelling advantages. In particular, this project
aims to be the successor to [OSTree](https://github.com/ostreedev/ostree/).

OSTree uses a content-addressed object store, but traditionally checks out
into a regular directory (using hardlinks), which is then bind-mounted as
the rootfs. While OSTree supports enabling fs-verity on files in the store,
nothing protects the checkout directories from modification.

composefs replaces this checkout with a directly-mountable image pointing
into the object store. We can enable fs-verity on the composefs image and
embed its digest in the kernel commandline or a Unified Kernel Image (UKI).
Since composefs generation is reproducible, we can verify the generated
image is correct by comparing its digest to one in the metadata produced
at build time. For more on this, see [this tracking issue](https://github.com/ostreedev/ostree/issues/2867).

## Components

### Core libraries

 - [`composefs`](crates/composefs): Core library for composefs operations including filesystem trees,
   fs-verity support, and repository management
 - [`composefs-oci`](crates/composefs-oci): OCI image handling and integration with container registries
 - [`composefs-boot`](crates/composefs-boot): Boot infrastructure support including UKI (Unified Kernel Image)
   and BLS (Boot Loader Specification) integration
 - [`composefs-http`](crates/composefs-http): HTTP support for fetching composefs content
 - [`composefs-fuse`](crates/composefs-fuse): FUSE filesystem implementation

### Command-line tools

 - [`cfsctl`](crates/composefs-ctl/src/main.rs): Primary CLI tool for managing composefs repositories
 - [`composefs-setup-root`](crates/composefs-setup-root/src/main.rs): Early boot tool for setting up
   the root filesystem from a composefs image

### Examples

The [`examples`](examples/) directory contains working demonstrations of building verified OS images:

 - **UKI**: Unified Kernel Image with embedded composefs digest
 - **BLS**: Traditional kernel/initramfs with Boot Loader Specification entries
 - **Unified**: Streamlined UKI build using in-container measurement
 - **Unified-SecureBoot**: UKI with Secure Boot signing support

## Mounting

Images stored in a composefs repository can be mounted using `cfsctl`:

```bash
cfsctl mount <image-name> /mnt
```

The image can be identified by its fs-verity digest or by a `ref/<name>` reference.

The [C implementation (composefs-c)](#composefs-c) provides a `mount.composefs`
helper that supports `mount -t composefs` syntax directly.

## Documentation

 - [Repository format](doc/repository.md)
 - [OCI integration](doc/oci.md)
 - [Splitstream format](doc/splitstream.md)
 - [Examples README](examples/README.md)

## Status

This project is under active development. The repository layout and
on-disk formats may still change.

## Community

- Live chat: [Matrix channel](https://matrix.to/#/#composefs:matrix.org)
- Async forums: [GitHub Discussions](https://github.com/composefs/composefs/discussions)

## composefs-c

The [C implementation](https://github.com/composefs/composefs)
provides `mkcomposefs` and `mount.composefs` and is still packaged in
many distributions. The Go [containers/storage](https://github.com/containers/storage)
library also has integration with `mkcomposefs`. These tools continue to
work, but new feature development is happening here.

## License

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).


[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcomposefs%2Fcomposefs-rs.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcomposefs%2Fcomposefs-rs?ref=badge_large)

## Copyright

Copyright contributors to composefs, established as composefs a Series of LF Projects, LLC.