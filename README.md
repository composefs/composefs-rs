# composefs: The reliability of disk images, the flexibility of files

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

composefs separates metadata (directories, permissions, xattrs) from data
(file content). An EROFS image carries only the metadata; data files live in
a content-addressed backing store, shared across images and in the Linux
[page cache](https://static.lwn.net/kerneldoc/admin-guide/mm/concepts.html#page-cache).
Optional [fs-verity](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html)
provides end-to-end integrity verification of both data and metadata.
For design details, see the [crate documentation](https://docs.rs/composefs).

## Use cases

### Container images

composefs improves on the traditional per-layer overlayfs model for
[OCI](https://github.com/opencontainers/image-spec/blob/main/spec.md)
container images by storing file content in a content-addressed store,
enabling sharing between images and faster pulls via
[zstd:chunked](https://github.com/containers/storage/pull/775).

### Bootable host systems

composefs aims to succeed [OSTree](https://github.com/ostreedev/ostree/)
by replacing hardlink checkouts with directly-mountable images backed by a
shared object store. Combined with fs-verity and a digest embedded in the
kernel commandline or a UKI, this provides cryptographic verification of
the entire filesystem tree. See [this tracking issue](https://github.com/ostreedev/ostree/issues/2867)
for background.

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

 - [API and design documentation](https://docs.rs/composefs)
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

## Copyright

Copyright contributors to composefs, established as composefs a Series of LF Projects, LLC.
