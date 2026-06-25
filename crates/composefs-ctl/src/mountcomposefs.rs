//! mount.composefs - Mount helper for composefs images.
//!
//! This is a Rust reimplementation of the C mount.composefs tool, providing
//! a compatible command-line interface. When installed as `/usr/sbin/mount.composefs`,
//! the kernel dispatches to it for `mount -t composefs` commands.

use std::ffi::OsString;
use std::os::fd::{AsFd, OwnedFd};

use anyhow::{Context, Result, bail};
use clap::Parser;
use rustix::fs::{CWD, Mode, OFlags};

use composefs::fsverity::{FsVerityHashValue, MeasureVerityError, Sha256HashValue, measure_verity};
use composefs::mount::{MountOptions, VerityRequirement, composefs_fsmount, mount_at};

/// Mount helper for composefs images.
///
/// Supported -o options: basedir=PATH[:PATH], digest=DIGEST, idmap=PATH,
/// verity, tryverity, ro, rw, upperdir=PATH, workdir=PATH
#[derive(Parser, Debug)]
#[command(name = "mount.composefs")]
struct MountArgs {
    /// Filesystem type (must be "composefs")
    #[arg(short = 't', value_name = "TYPE")]
    fstype: Option<String>,

    /// Mount options (comma-separated key[=value] pairs)
    #[arg(short = 'o', value_name = "OPTIONS")]
    options: Option<String>,

    /// Path to the composefs image
    image: String,

    /// Mount point
    mountpoint: String,
}

fn unescape_option(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                result.push(next);
            }
        } else {
            result.push(c);
        }
    }
    result
}

struct ParsedOption {
    key: String,
    value: Option<String>,
}

fn parse_mount_options(options: &str) -> Vec<ParsedOption> {
    let mut result = Vec::new();
    let mut rest = options;

    while !rest.is_empty() {
        let mut equal_pos = None;
        let mut end_pos = rest.len();
        let bytes = rest.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] == b'=' && equal_pos.is_none() {
                equal_pos = Some(i);
            } else if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 1;
            } else if bytes[i] == b',' {
                end_pos = i;
                break;
            }
            i += 1;
        }

        let entry = &rest[..end_pos];
        rest = if end_pos < rest.len() {
            &rest[end_pos + 1..]
        } else {
            ""
        };

        let (key, value) = if let Some(eq) = equal_pos {
            if eq < end_pos {
                (&entry[..eq], Some(unescape_option(&entry[eq + 1..])))
            } else {
                (entry, None)
            }
        } else {
            (entry, None)
        };

        result.push(ParsedOption {
            key: key.to_string(),
            value,
        });
    }

    result
}

fn run_mount(args: impl IntoIterator<Item = OsString>) -> Result<()> {
    let cli =
        MountArgs::try_parse_from(std::iter::once(OsString::from("mount.composefs")).chain(args))?;

    if let Some(ref fstype) = cli.fstype
        && fstype != "composefs"
    {
        bail!("Unsupported fs type '{fstype}'");
    }

    let mut opt_basedir: Option<String> = None;
    let mut opt_digest: Option<String> = None;
    let mut opt_upperdir: Option<String> = None;
    let mut opt_workdir: Option<String> = None;
    let mut opt_idmap: Option<OwnedFd> = None;
    let mut opt_verity = false;
    let mut opt_tryverity = false;
    let mut opt_ro = false;

    if let Some(ref opts_str) = cli.options {
        for opt in parse_mount_options(opts_str) {
            match opt.key.as_str() {
                "basedir" => {
                    opt_basedir = Some(opt.value.context("No value specified for basedir option")?);
                }
                "digest" => {
                    opt_digest = Some(opt.value.context("No value specified for digest option")?);
                }
                "verity" => opt_verity = true,
                "tryverity" => opt_tryverity = true,
                "upperdir" => {
                    opt_upperdir = Some(
                        opt.value
                            .context("No value specified for upperdir option")?,
                    );
                }
                "workdir" => {
                    opt_workdir = Some(opt.value.context("No value specified for workdir option")?);
                }
                "idmap" => {
                    let idmap_path = opt.value.context("No value specified for idmap option")?;
                    let idmap_fd = rustix::fs::open(
                        idmap_path.as_str(),
                        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY,
                        Mode::empty(),
                    )
                    .with_context(|| format!("Failed to open idmap {idmap_path}"))?;
                    opt_idmap = Some(idmap_fd);
                }
                "rw" => opt_ro = false,
                "ro" => opt_ro = true,
                other => bail!("Unsupported option: {other}"),
            }
        }
    }

    let basedir_str = match opt_basedir {
        Some(ref s) => s.as_str(),
        None => {
            bail!("No object dirs specified");
        }
    };

    let mut basedir_fds: Vec<OwnedFd> = Vec::new();
    for dir in basedir_str.split(':') {
        if dir.is_empty() {
            continue;
        }
        let fd = rustix::fs::open(
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Failed to open basedir {dir}"))?;
        basedir_fds.push(fd);
    }
    if basedir_fds.is_empty() {
        bail!("No object dirs specified");
    }

    match (&opt_upperdir, &opt_workdir) {
        (Some(_), None) | (None, Some(_)) => {
            bail!("Both workdir and upperdir must be specified if used");
        }
        _ => {}
    }

    let verity = if opt_verity || opt_digest.is_some() {
        VerityRequirement::Required
    } else if opt_tryverity {
        VerityRequirement::Try
    } else {
        VerityRequirement::Disabled
    };

    let image_fd = rustix::fs::open(
        cli.image.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("Failed to open {}", cli.image))?;

    if let Some(ref digest_hex) = opt_digest {
        let expected = Sha256HashValue::from_hex(digest_hex).context("Invalid digest value")?;
        match measure_verity::<Sha256HashValue>(&image_fd) {
            Ok(measured) => {
                if measured != expected {
                    bail!(
                        "Failed to mount composefs {}: Image has wrong fs-verity",
                        cli.image
                    );
                }
            }
            Err(MeasureVerityError::VerityMissing) => {
                bail!(
                    "Failed to mount composefs {}: Image has no fs-verity",
                    cli.image
                );
            }
            Err(e) => {
                bail!("Failed to mount composefs {}: {e}", cli.image);
            }
        }
    }

    let mut mount_opts = MountOptions::default();
    if let (Some(upper), Some(work)) = (&opt_upperdir, &opt_workdir) {
        let upper_fd = rustix::fs::open(
            upper.as_str(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Failed to open upperdir {upper}"))?;
        let work_fd = rustix::fs::open(
            work.as_str(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Failed to open workdir {work}"))?;
        mount_opts.set_overlay(upper_fd, work_fd);
    }
    if let Some(idmap_fd) = opt_idmap {
        mount_opts.set_idmap(idmap_fd);
    }
    mount_opts.set_read_write(!opt_ro);

    let borrowed: Vec<_> = basedir_fds.iter().map(|fd| fd.as_fd()).collect();
    let fs_fd = composefs_fsmount(image_fd, "composefs", &borrowed, verity, &mount_opts)
        .with_context(|| format!("Failed to mount composefs {}", cli.image))?;

    mount_at(&fs_fd, CWD, cli.mountpoint.as_str())
        .with_context(|| format!("Failed to mount at {}", cli.mountpoint))?;

    Ok(())
}

/// Entry point when invoked as `mount.composefs` via argv[0] symlink.
pub fn run() -> Result<()> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    run_mount(args)
}

/// Entry point when invoked as `cfsctl mount.composefs ...` subcommand.
pub fn run_from_args(args: Vec<OsString>) -> Result<()> {
    run_mount(args)
}
