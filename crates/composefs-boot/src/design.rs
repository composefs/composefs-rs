//! # Booting from a composefs image
//!
//! This document describes how composefs-rs sets up the root filesystem during
//! early boot. It covers the kernel command-line interface, the expected on-disk
//! layout, kernel requirements, and the step-by-step mount sequence performed by
//! `composefs-setup-root`.
//!
//! The target audience is system integrators and OS developers who are packaging a
//! bootable system using composefs. Familiarity with Linux mount namespaces,
//! overlayfs, and fs-verity is assumed.
//!
//! ## Kernel command-line
//!
//! The initramfs code in composefs supports multiple kernel arguments; it
//! is possible to pre-compute the digest of an image using both e.g. SHA-256 and
//! SHA-512. On an installed system, the repository only supports one digest
//! by default today, and the first found will be selected.
//!
//! Additionally, it is opt-in to enable v1 EROFS, and again the first compatible
//! version will be found.
//!
//! ```text
//! composefs.digest=v1-sha256-12:<digest>   # V1 EROFS image (preferred; RHEL9-era kernels)
//! composefs.digest=v1-sha512-12:<digest>   # V1 EROFS image (SHA-512 variant)
//! composefs.digest=v2-sha512-12:<digest>   # V2 EROFS image (explicit form)
//! composefs=<digest>                       # V2 EROFS image (legacy shorthand)
//! ```
//!
//! The value format is `<version>-<hash>-<lg_blocksize>:<hex_digest>`, where
//! `<version>` is `v1` or `v2`, `<hash>` is `sha256` or `sha512`, and
//! `<lg_blocksize>` is the log2 block size (currently always `12`, i.e. 4096
//! bytes). This mirrors how `meta.json` encodes the algorithm as
//! `fsverity-sha256-12`.
//!
//! `composefs.digest=` is checked first. Multiple entries may appear on the cmdline
//! (one per format/algorithm combination); the initramfs tries each in order and
//! mounts the first image that actually exists in the repository.
//!
//! `composefs=<digest>` is a legacy shorthand equivalent to
//! `composefs.digest=v2-<hash>-12:<digest>` -- the algorithm is inferred from the
//! digest length (64 hex chars -> SHA-256, 128 -> SHA-512). It is checked only when
//! no `composefs.digest=` token matches.
//!
//! **Insecure mode.** Placing `?` immediately after `=` (e.g.
//! `composefs.digest=?v1-sha256-12:<digest>` or `composefs=?<digest>`) makes
//! fs-verity verification optional. The system will boot even when the underlying
//! filesystem does not support fs-verity or the image has no verity metadata
//! attached. This mode exists for development and testing only; it must not be used
//! in production.
//!
//! ## On-disk layout
//!
//! The composefs repository must be present at `/sysroot/composefs` with the
//! standard layout described in the `composefs::repository_format` module.
//!
//! The digest must correspond to a symlink under `images/`.
//!
//! Persistent per-deployment state lives at `/sysroot/state/deploy/<digest>/`,
//! where `<digest>` matches the boot karg digest exactly. The `etc/` and `var/`
//! subdirectories within that directory serve as the upper layers for the
//! corresponding overlayfs mounts.
//!
//! ## Kernel requirements
//!
//! The following kernel features must be available:
//!
//! - **EROFS** filesystem driver (`CONFIG_EROFS_FS`)
//! - **overlayfs** with `metacopy=on` and `redirect_dir=on`
//!   (`CONFIG_OVERLAY_FS`, `CONFIG_OVERLAY_FS_METACOPY`, `CONFIG_OVERLAY_FS_REDIRECT_DIR`)
//! - **fs-verity** unless insecure mode is used (`CONFIG_FS_VERITY`)
//! - The modern Linux mount API (`fsopen` / `fsconfig` / `fsmount` / `move_mount`),
//!   available since kernel 5.2. Kernel >= 6.15 is required for the atomic root
//!   replacement path (the default build). On kernels without `fsconfig_set_fd`
//!   support (e.g. RHEL 9 / kernel < 5.15), a loopback device is created
//!   automatically by `composefs::mountcompat`.
//!
//! ## Kernel argument
//!
//! The boot karg (`composefs.digest=` or `composefs=`) is the authoritative selector for which image is booted.
//! Without the `?` insecure prefix, every file access through the overlayfs is
//! verified against the object's stored digest by the kernel, combining fs-verity
//! on the data objects with overlayfs `verity=require`.
//!
//! ## Other notes
//!
//! As a workaround for a GPT auto-root issue in systemd
//! ([systemd#35017](https://github.com/systemd/systemd/issues/35017)),
//! `composefs-setup-root` attempts to create `/run/systemd/volatile-root` as a
//! symlink pointing to the real block device before performing any mounts. Failure
//! to do so is non-fatal and does not abort the boot sequence.
