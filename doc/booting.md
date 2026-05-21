# Booting from a composefs image

This document describes how composefs-rs sets up the root filesystem during
early boot. It covers the kernel command-line interface, the expected on-disk
layout, kernel requirements, and the step-by-step mount sequence performed by
`composefs-setup-root`.

The target audience is system integrators and OS developers who are packaging a
bootable system using composefs. Familiarity with Linux mount namespaces,
overlayfs, and fs-verity is assumed.

## Kernel command-line

A single kernel argument controls which image is booted:

```
composefs=<digest>
```

`<digest>` is the hex-encoded fs-verity digest of the EROFS metadata image to
mount as root. SHA-256 digests are 64 hex characters; SHA-512 digests are 128
hex characters. `composefs-setup-root` tries SHA-512 first and falls back to
SHA-256 if the length does not match, so both algorithms are supported without
any additional configuration.

**Insecure mode.** Prefixing the digest with `?` (e.g. `composefs=?<digest>`)
makes fs-verity verification optional. The system will boot even when the
underlying filesystem does not support fs-verity or the image has no verity
metadata attached. This mode exists for development and testing only; it must
not be used in production.

Parsing is handled by `composefs_boot::cmdline::get_cmdline_composefs`
(`crates/composefs-boot/src/cmdline.rs`). The splitter follows the kernel's
own logic: tokens are separated by ASCII whitespace, and whitespace inside
double-quoted strings is treated as literal. There is no escape mechanism, so a
literal double-quote character cannot appear in a token value.

## On-disk layout

The composefs repository must be present at `/sysroot/composefs` with the
standard layout described in `doc/repository.md`.

The `composefs=` digest must correspond to a symlink under `images/`.

Persistent per-deployment state lives at `/sysroot/state/deploy/<digest>/`,
where `<digest>` matches the `composefs=` kernel argument exactly. The `etc/`
and `var/` subdirectories within that directory serve as the upper layers for
the corresponding overlayfs mounts.

## Kernel requirements

The following kernel features must be available:

- **EROFS** filesystem driver (`CONFIG_EROFS_FS`)
- **overlayfs** with `metacopy=on` and `redirect_dir=on`
  (`CONFIG_OVERLAY_FS`, `CONFIG_OVERLAY_FS_METACOPY`, `CONFIG_OVERLAY_FS_REDIRECT_DIR`)
- **fs-verity** unless insecure mode is used (`CONFIG_FS_VERITY`)
- The modern Linux mount API (`fsopen` / `fsconfig` / `fsmount` / `move_mount`),
  available since kernel 5.2. Kernel ≥ 6.15 is required for the atomic root
  replacement path (the default build). On kernels without `fsconfig_set_fd`
  support (e.g. RHEL 9 / kernel < 5.15), a loopback device is created
  automatically by `composefs::mountcompat`.

## Kernel argument

The `composefs=` kernel argument is the authoritative selector for which image
Without the `?` insecure prefix, every file access through the overlayfs is
verified against the object's stored digest by the kernel, combining fs-verity
on the data objects with overlayfs `verity=require`.

## Other notes

As a workaround for a GPT auto-root issue in systemd
([systemd#35017](https://github.com/systemd/systemd/issues/35017)),
`composefs-setup-root` attempts to create `/run/systemd/volatile-root` as a
symlink pointing to the real block device before performing any mounts. Failure
to do so is non-fatal and does not abort the boot sequence.
