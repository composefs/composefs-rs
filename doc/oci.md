# How to create a composefs from an OCI image

This document is incomplete.  It only serves to document some decisions we've
taken about how to resolve ambiguous situations.

# Data precision

We currently create a composefs image using the granularity of data as
typically appears in OCI tarballs:
 - atime and ctime are not present (these are actually not physically present
   in the erofs inode structure at all, either the compact or extended forms)
 - mtime is set to the mtime from the tar metadata.  The usual tar header only
   stores timestamps in seconds; when PAX extended headers include a fractional
   `mtime`, we preserve that value in erofs' nsec field.
 - we take great care to faithfully represent hardlinks: even though the
   produced filesystem is read-only and we have data de-duplication via the
   objects store, we make sure that hardlinks result in an actual shared inode
   as visible via the `st_ino` and `st_nlink` fields on the mounted filesystem.

We apply these precision restrictions also when creating images by scanning the
filesystem.  For example: even if we get more-accurate timestamp information,
we'll truncate it to the nearest second.

# Merging directories

This is done according to the OCI spec, with an additional clarification: in
case a directory entry is present in multiple layers, we use the tar metadata
from the most-derived layer to determine the attributes (owner, permissions,
mtime) for the directory.

# The root inode

The root inode (/) is a difficult case because OCI container layer tars often
don't include a root directory entry, and when they do, container runtimes
(Podman, Docker) ignore it and use hardcoded defaults.  For example, Podman's
[containers/storage](https://github.com/containers/storage) uses root:root
ownership, mode `0555`, and epoch (0) mtime when extracting layers, but
Docker uses `0755`. In general, the metadata for `/` is not defined.

Because composefs requires (has a goal of providing) precise cryptographically
verifiable filesystem trees, we solve this for OCI by copying the metadata from `/usr`
to the root directory.  The rationale is that `/usr` is always present in
standard filesystem layouts and must be defined explicitly in the OCI layers.

This is implemented via the `copy_root_metadata_from_usr()` method and the
`read_container_root()` convenience function.

When building a filesystem from OCI layers programmatically, use
`Stat::uninitialized()` to create the initial `FileSystem`.  This placeholder
has mode `0` (obviously invalid) to make it clear that the root metadata should
be set before computing digests - typically by calling
`copy_root_metadata_from_usr()` after processing all layers.

# Extended attributes (xattrs)

When reading a container filesystem from a mounted root (as opposed to
processing OCI layer tars directly), host-side xattrs can leak into the
image.  This is particularly problematic for `security.selinux` labels:
if SELinux is enabled at build time, files will have labels like
`container_t` that come from the build host, not from the target system's
policy.

To ensure reproducibility, `read_container_root()` filters xattrs to only
include those in an allowlist.  Currently this is just `security.capability`,
which represents actual file capabilities that should be preserved.

SELinux labels are handled separately by `transform_for_boot()`:
 - If the target filesystem contains a SELinux policy (in `/etc/selinux`),
   all files are relabeled according to that policy
 - If no SELinux policy is found, all `security.selinux` xattrs are stripped

This ensures that:
 - Build-time SELinux labels don't leak into non-SELinux targets
 - SELinux-enabled targets get correct labels from their own policy
 - Other host xattrs (overlayfs internals, etc.) don't pollute the image

See: https://github.com/containers/storage/pull/1608#issuecomment-1600915185

# The /run directory

When processing OCI images via `create_filesystem()`, the `/run` directory
is emptied if present. This is a tmpfs at runtime and should always be
empty in images. Its mtime is set to match `/usr` for consistency with
how root directory metadata is handled.

This makes it possible to work around podman/buildah's `RUN --mount` issue where cache
mounts can leave incomplete directory entries in OCI tar layers (directories
without explicit tar entries inherit incorrect mtimes) by pointing all
such mounts into `/run`, and then redirecting from their final location
via e.g. symlinks into `/run`.

## Container build cache mounts

A practical implication of emptying `/run` is that container authors can
use it for cache mounts without worrying about polluting the final image.

Instead of:
```dockerfile
RUN --mount=type=cache,target=/var/cache/dnf dnf install -y ...
```

Consider:
```dockerfile
RUN rm -rf /var/cache/dnf && ln -sr /run/dnfcache /var/cache/dnf
RUN --mount=type=cache,target=/run/dnfcache dnf install -y ...
```

This avoids potential mtime inconsistencies in `/var/cache` while still
benefiting from build caching.

See: https://github.com/containers/composefs-rs/issues/132

# Emptied directories for boot

When preparing a filesystem for boot via `transform_for_boot()`, certain
additional directories are emptied because their contents should not be
part of the final verified image:

- `/boot`: Contains the UKI which embeds the composefs digest, so including
  it would create a circular dependency
- `/sysroot`: Only has content in ostree-container cases, and traversing
  it for SELinux labeling causes problems

These directories are emptied and their mtime is set to match `/usr` for
consistency with how the root directory metadata is handled.
