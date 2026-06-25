//! Root filesystem setup utility for composefs-based boot systems.
//!
//! This utility is designed to run during early boot to mount and configure
//! the root filesystem using composefs images. It handles overlay mounts for
//! writable directories, state management, and system integration.

use std::{
    ffi::OsString,
    fmt::Debug,
    io::ErrorKind,
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Parser;

use rustix::{
    fs::{CWD, Mode, OFlags, major, minor, mkdirat, openat, stat, symlink},
    io::Errno,
    mount::{
        FsMountFlags, MountAttrFlags, OpenTreeFlags, UnmountFlags, fsconfig_create,
        fsconfig_set_string, fsmount, open_tree, unmount,
    },
};
use serde::Deserialize;

use composefs::{
    fsverity::{Algorithm, FsVerityHashValue, Sha256HashValue, Sha512HashValue},
    mount::{FsHandle, mount_at},
    mountcompat::{overlayfs_set_fd, overlayfs_set_lower_and_data_fds, prepare_mount},
    repository::{ImageNotFound, Repository},
};
use composefs_boot::cmdline::{KARG_COMPOSEFS_DIGEST, KARG_V2, parse_digest_value, split_cmdline};

// Config file
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum MountType {
    None,
    Bind,
    Overlay,
    Transient,
}

#[derive(Debug, Default, Deserialize)]
struct RootConfig {
    #[serde(default)]
    transient: bool,
}

#[derive(Debug, Default, Deserialize)]
struct MountConfig {
    mount: Option<MountType>,
    #[serde(default)]
    transient: bool,
}

#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)]
    etc: MountConfig,
    #[serde(default)]
    var: MountConfig,
    #[serde(default)]
    root: RootConfig,
}

// Command-line arguments
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(help = "Execute this command (for testing)")]
    cmd: Vec<OsString>,

    #[arg(
        long,
        default_value = "/sysroot",
        help = "sysroot directory in initramfs"
    )]
    sysroot: PathBuf,

    #[arg(
        long,
        default_value = "/usr/lib/composefs/setup-root-conf.toml",
        help = "Config path (for testing)"
    )]
    config: PathBuf,

    // we want to test in a userns, but can't mount erofs there
    #[arg(long, help = "Bind mount root-fs from (for testing)")]
    root_fs: Option<PathBuf>,

    #[arg(long, help = "Kernel commandline args (for testing)")]
    cmdline: Option<String>,

    #[arg(long, help = "Mountpoint (don't replace sysroot, for testing)")]
    target: Option<PathBuf>,
}

// Helpers
fn open_dir(dirfd: impl AsFd, name: impl AsRef<Path> + Debug) -> rustix::io::Result<OwnedFd> {
    openat(
        dirfd,
        name.as_ref(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .inspect_err(|_| {
        eprintln!("Failed to open dir {name:?}");
    })
}

fn ensure_dir(dirfd: impl AsFd, name: &str, mode: Mode) -> rustix::io::Result<OwnedFd> {
    match mkdirat(dirfd.as_fd(), name, mode) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(err) => Err(err)?,
    }
    open_dir(dirfd, name)
}

fn bind_mount(fd: impl AsFd, path: &str) -> rustix::io::Result<OwnedFd> {
    open_tree(
        fd.as_fd(),
        path,
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_EMPTY_PATH,
    )
    .inspect_err(|_| {
        eprintln!("Open tree failed for {path}");
    })
}

fn mount_tmpfs() -> Result<OwnedFd> {
    let tmpfs = FsHandle::open("tmpfs")?;
    fsconfig_create(tmpfs.as_fd())?;
    Ok(fsmount(
        tmpfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

fn overlay_state(base: impl AsFd, state: impl AsFd, source: &str) -> Result<()> {
    // upper must be 0755: the overlayfs merged view inherits permissions from
    // upperdir, so 0700 would make / (or the mounted subdir) inaccessible to
    // non-root processes (dbus, anything that drops privileges).
    // work is kernel-internal and never visible in the merged view; 0700 is fine.
    // See: https://github.com/composefs/composefs-rs/issues/287
    let upper = ensure_dir(state.as_fd(), "upper", 0o755.into())?;
    let work = ensure_dir(state.as_fd(), "work", 0o700.into())?;

    let overlayfs = FsHandle::open("overlay")?;
    fsconfig_set_string(overlayfs.as_fd(), "source", source)?;
    overlayfs_set_fd(overlayfs.as_fd(), "workdir", work.as_fd())?;
    overlayfs_set_fd(overlayfs.as_fd(), "upperdir", upper.as_fd())?;
    overlayfs_set_lower_and_data_fds(&overlayfs, base.as_fd(), &[])?;
    fsconfig_create(overlayfs.as_fd())?;
    let fs = fsmount(
        overlayfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?;

    Ok(mount_at(fs, base, ".")?)
}

fn overlay_transient(base: impl AsFd) -> Result<()> {
    overlay_state(base, prepare_mount(mount_tmpfs()?)?, "transient")
}

fn open_root_fs(path: &Path) -> Result<OwnedFd> {
    let rootfs = open_tree(
        CWD,
        path,
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )?;

    // https://github.com/bytecodealliance/rustix/issues/975
    // mount_setattr(rootfs.as_fd()), ..., { ... MountAttrFlags::MOUNT_ATTR_RDONLY ... }, ...)?;

    Ok(rootfs)
}

/// Try to mount a composefs image, returning `Ok(None)` if the image does not
/// exist in the repository.  All other errors (permission, verity mismatch,
/// corrupt image, …) are propagated.
fn mount_composefs_image_if_exists(
    sysroot: &OwnedFd,
    name: &str,
    insecure: bool,
) -> Result<Option<OwnedFd>> {
    let result = match name.len() {
        128 => {
            let mut repo = Repository::<Sha512HashValue>::open_path(sysroot, "composefs")?;
            if insecure {
                repo.set_insecure();
            } else {
                repo.require_verity()?;
            }
            repo.mount(name)
        }
        64 => {
            let mut repo = Repository::<Sha256HashValue>::open_path(sysroot, "composefs")?;
            if insecure {
                repo.set_insecure();
            } else {
                repo.require_verity()?;
            }
            repo.mount(name)
        }
        _ => anyhow::bail!("Invalid composefs digest length: {}", name.len()),
    };
    match result {
        Ok(fd) => Ok(Some(fd)),
        Err(e) if e.downcast_ref::<ImageNotFound>().is_some() => Ok(None),
        Err(e) => Err(e).context("Failed to mount composefs image"),
    }
}

fn mount_subdir(
    new_root: impl AsFd,
    state: impl AsFd,
    subdir: &str,
    config: MountConfig,
    default: MountType,
) -> Result<()> {
    let mount_type = match config.mount {
        Some(mt) => mt,
        None => match config.transient {
            true => MountType::Transient,
            false => default,
        },
    };

    match mount_type {
        MountType::None => Ok(()),
        MountType::Bind => Ok(mount_at(bind_mount(&state, subdir)?, &new_root, subdir)?),
        MountType::Overlay => overlay_state(
            open_dir(&new_root, subdir)?,
            open_dir(&state, subdir)?,
            "overlay",
        ),
        MountType::Transient => overlay_transient(open_dir(&new_root, subdir)?),
    }
}

fn gpt_workaround() -> Result<()> {
    // https://github.com/systemd/systemd/issues/35017
    let rootdev = stat("/dev/gpt-auto-root")?;
    let target = format!(
        "/dev/block/{}:{}",
        major(rootdev.st_rdev),
        minor(rootdev.st_rdev)
    );
    symlink(target, "/run/systemd/volatile-root")?;
    Ok(())
}

/// Strips the optional insecure `?` prefix from a karg value.
///
/// Returns `(hex, insecure)` where `hex` is the raw digest string and
/// `insecure` indicates whether the `?` prefix was present.
fn strip_insecure(val: &str) -> (&str, bool) {
    if let Some(stripped) = val.strip_prefix('?') {
        (stripped, true)
    } else {
        (val, false)
    }
}

/// Parses all composefs kargs from the kernel command line, in order.
///
/// Scans cmdline tokens left-to-right, collecting every matching composefs
/// karg of any known type:
/// - `composefs.digest=v1-sha512-12:<hex>` (V1, sha512)
/// - `composefs.digest=v1-sha256-12:<hex>` (V1, sha256)
/// - `composefs=<hex>` (V2 legacy, length-disambiguated)
///
/// The `?` insecure marker may appear directly after `=` for V1, e.g.
/// `composefs.digest=?v1-sha256-12:<hex>`.
///
/// Returns all matches preserving cmdline order.  The caller is expected to
/// try mounting each in sequence and use the first image that actually exists
/// in the repository.
fn parse_composefs_kargs(cmdline: &str) -> Result<Vec<(String, bool)>> {
    let v1_key_prefix = format!("{KARG_COMPOSEFS_DIGEST}=");
    let v2_prefix = format!("{KARG_V2}=");

    let mut results = Vec::new();
    for token in split_cmdline(cmdline) {
        if let Some(val) = token.strip_prefix(&v1_key_prefix) {
            let (val_no_q, insecure) = strip_insecure(val);
            let (desc, hex) = parse_digest_value(val_no_q)
                .with_context(|| format!("parsing {KARG_COMPOSEFS_DIGEST}= value: {val}"))?;
            // Validate the hex digest against the parsed algorithm.
            match desc.algorithm {
                Algorithm::Sha512 { .. } => {
                    Sha512HashValue::from_hex(hex).with_context(|| {
                        format!("parsing {KARG_COMPOSEFS_DIGEST}= sha512 digest")
                    })?;
                }
                Algorithm::Sha256 { .. } => {
                    Sha256HashValue::from_hex(hex).with_context(|| {
                        format!("parsing {KARG_COMPOSEFS_DIGEST}= sha256 digest")
                    })?;
                }
            }
            results.push((hex.to_string(), insecure));
        } else if let Some(val) = token.strip_prefix(&v2_prefix) {
            let (hex, insecure) = strip_insecure(val);
            match hex.len() {
                128 => {
                    Sha512HashValue::from_hex(hex)
                        .with_context(|| "parsing composefs= sha512 digest".to_string())?;
                }
                64 => {
                    Sha256HashValue::from_hex(hex)
                        .with_context(|| "parsing composefs= sha256 digest".to_string())?;
                }
                _ => anyhow::bail!("invalid composefs= digest length: {}", hex.len()),
            }
            results.push((hex.to_string(), insecure));
        }
    }
    Ok(results)
}

fn setup_root(args: Args) -> Result<()> {
    let config = match std::fs::read_to_string(args.config) {
        Ok(text) => toml::from_str(&text)?,
        Err(err) if err.kind() == ErrorKind::NotFound => Config::default(),
        Err(err) => Err(err)?,
    };

    let sysroot = open_dir(CWD, &args.sysroot)
        .with_context(|| format!("Failed to open sysroot {:?}", args.sysroot))?;

    let cmdline = match &args.cmdline {
        Some(cmdline) => cmdline,
        None => &std::fs::read_to_string("/proc/cmdline")?,
    };

    let kargs = parse_composefs_kargs(cmdline)?;
    if kargs.is_empty() {
        anyhow::bail!("no composefs karg found in kernel cmdline");
    }

    let (new_root, image_addr) = match args.root_fs {
        Some(path) => {
            let root = open_root_fs(&path).context("Failed to clone specified root fs")?;
            let addr = kargs[0].0.clone();
            (root, addr)
        }
        None => {
            // Try each karg in cmdline order; use the first image that exists.
            let mut mounted = None;
            for (addr, insecure) in &kargs {
                if let Some(root) = mount_composefs_image_if_exists(&sysroot, addr, *insecure)? {
                    mounted = Some((root, addr.clone()));
                    break;
                }
                eprintln!("composefs: image {addr} not found, trying next karg");
            }
            mounted.with_context(|| {
                let tried: Vec<_> = kargs.iter().map(|(a, _)| a.as_str()).collect();
                format!("no composefs image found (tried: {})", tried.join(", "))
            })?
        }
    };

    // we need to clone this before the next step to make sure we get the old one
    let sysroot_clone = bind_mount(&sysroot, "")?;

    // Ideally we build the new root filesystem together before we mount it, but that only works on
    // 6.15 and later.  Before 6.15 we can't mount into a floating tree, so mount it first.  This
    // will leave an abandoned clone of the sysroot mounted under it, but that's OK for now.
    if cfg!(feature = "pre-6.15") {
        mount_at(&new_root, CWD, &args.sysroot)?;
    }

    if config.root.transient {
        overlay_transient(&new_root)?;
    }

    match mount_at(&sysroot_clone, &new_root, "sysroot") {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(err) => Err(err)?,
    }

    // etc + var
    let state = open_dir(open_dir(&sysroot, "state/deploy")?, &image_addr)?;
    mount_subdir(&new_root, &state, "etc", config.etc, MountType::Overlay)?;
    mount_subdir(&new_root, &state, "var", config.var, MountType::Bind)?;

    if cfg!(not(feature = "pre-6.15")) {
        // Replace the /sysroot with the new composed root filesystem
        unmount(&args.sysroot, UnmountFlags::DETACH)?;
        mount_at(&new_root, CWD, &args.sysroot)?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let _ = gpt_workaround(); // best effort
    setup_root(args)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_no_kargs() {
        // No composefs token at all → empty vec
        let empty_cases = ["", "foo", "composefs", "root=UUID=abc quiet"];
        for case in empty_cases {
            let kargs = parse_composefs_kargs(case).unwrap();
            assert!(kargs.is_empty(), "expected no kargs for {case:?}");
        }
    }

    #[test]
    fn test_parse_invalid_digest_errors() {
        // A composefs= token with a bad value is an error, not silently ignored
        assert!(parse_composefs_kargs("composefs=foo").is_err());
        assert!(parse_composefs_kargs("composefs.digest=v1-sha256-12:notahex").is_err());
    }

    #[test]
    fn test_parse_single_kargs() {
        // Legacy V2: composefs=<sha256>
        let digest_legacy = "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52";
        let kargs = parse_composefs_kargs(&format!("composefs={digest_legacy}")).unwrap();
        assert_eq!(kargs.len(), 1);
        assert_eq!(kargs[0], (digest_legacy.to_string(), false));

        // Legacy V2: composefs=<sha512>
        let digest = "6f06b5e82420abec546d6e6d3ddd612c50cfa9b707c129345b7ec16f456b92fe35df68999b042e1a6a70dfe75f2fed8cf9f67afd0bf08d2374678d75e2f65a02";
        let kargs = parse_composefs_kargs(&format!("composefs={digest}")).unwrap();
        assert_eq!(kargs.len(), 1);
        assert_eq!(kargs[0], (digest.to_string(), false));

        // V1: composefs.digest=v1-sha256-12:<sha256>
        let kargs =
            parse_composefs_kargs(&format!("composefs.digest=v1-sha256-12:{digest_legacy}"))
                .unwrap();
        assert_eq!(kargs.len(), 1);
        assert_eq!(kargs[0], (digest_legacy.to_string(), false));

        // V1: composefs.digest=v1-sha512-12:<sha512>
        let kargs =
            parse_composefs_kargs(&format!("composefs.digest=v1-sha512-12:{digest}")).unwrap();
        assert_eq!(kargs.len(), 1);
        assert_eq!(kargs[0], (digest.to_string(), false));
    }

    #[test]
    fn test_parse_multiple_kargs_preserves_order() {
        let sha256_hex = "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52";
        let sha512_hex = "6f06b5e82420abec546d6e6d3ddd612c50cfa9b707c129345b7ec16f456b92fe\
            35df68999b042e1a6a70dfe75f2fed8cf9f67afd0bf08d2374678d75e2f65a02";
        let other_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // All three types, sha256-v1 first
        let cmdline = format!(
            "composefs.digest=v1-sha256-12:{sha256_hex} \
             composefs.digest=v1-sha512-12:{sha512_hex} \
             composefs={other_sha256}"
        );
        let kargs = parse_composefs_kargs(&cmdline).unwrap();
        assert_eq!(kargs.len(), 3);
        assert_eq!(kargs[0].0, sha256_hex);
        assert_eq!(kargs[1].0, sha512_hex);
        assert_eq!(kargs[2].0, other_sha256);

        // Reversed order
        let cmdline = format!(
            "composefs={other_sha256} \
             composefs.digest=v1-sha512-12:{sha512_hex} \
             composefs.digest=v1-sha256-12:{sha256_hex}"
        );
        let kargs = parse_composefs_kargs(&cmdline).unwrap();
        assert_eq!(kargs.len(), 3);
        assert_eq!(kargs[0].0, other_sha256);
        assert_eq!(kargs[1].0, sha512_hex);
        assert_eq!(kargs[2].0, sha256_hex);
    }

    #[test]
    fn test_parse_insecure() {
        let sha512_hex = "6f06b5e82420abec546d6e6d3ddd612c50cfa9b707c129345b7ec16f456b92fe\
            35df68999b042e1a6a70dfe75f2fed8cf9f67afd0bf08d2374678d75e2f65a02";

        let kargs =
            parse_composefs_kargs(&format!("composefs.digest=?v1-sha512-12:{sha512_hex}")).unwrap();
        assert_eq!(kargs.len(), 1);
        assert_eq!(kargs[0], (sha512_hex.to_string(), true));
    }

    #[test]
    fn test_parse_mixed_insecure_and_secure() {
        let sha256_hex = "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52";
        let sha512_hex = "6f06b5e82420abec546d6e6d3ddd612c50cfa9b707c129345b7ec16f456b92fe\
            35df68999b042e1a6a70dfe75f2fed8cf9f67afd0bf08d2374678d75e2f65a02";

        let cmdline = format!(
            "composefs.digest=?v1-sha256-12:{sha256_hex} \
             composefs.digest=v1-sha512-12:{sha512_hex}"
        );
        let kargs = parse_composefs_kargs(&cmdline).unwrap();
        assert_eq!(kargs.len(), 2);
        assert_eq!(kargs[0], (sha256_hex.to_string(), true));
        assert_eq!(kargs[1], (sha512_hex.to_string(), false));
    }

    #[test]
    fn test_parse_ignores_unrelated_tokens() {
        let sha256_hex = "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52";
        let cmdline =
            format!("root=UUID=abc quiet splash composefs.digest=v1-sha256-12:{sha256_hex} rw");
        let kargs = parse_composefs_kargs(&cmdline).unwrap();
        assert_eq!(kargs.len(), 1);
        assert_eq!(kargs[0], (sha256_hex.to_string(), false));
    }
}
