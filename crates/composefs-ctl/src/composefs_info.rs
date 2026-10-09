//! composefs-info - Query information from composefs images.
//!
//! This is a Rust reimplementation of the C composefs-info tool, providing
//! commands to inspect EROFS images, list objects, and compute fs-verity digests.
//!
//! ## Compatibility status
//!
//! Implemented subcommands:
//! - `ls` — lists files with type suffixes, skips whiteout entries
//! - `dump` — outputs composefs-dump(5) text format (image → tree → dumpfile)
//! - `objects` — lists all backing file object paths (XX/XXXX...)
//! - `missing-objects` — lists objects not present in `--basedir`
//! - `measure-file` — computes fs-verity digest of files
//!
//! Compatibility notes:
//! - `measure-file` tries `FS_IOC_MEASURE_VERITY` first; falls back to
//!   in-process computation when the kernel reports verity is absent or the
//!   filesystem doesn't support it, matching the C `lcfs_fd_get_fsverity()`
//!   behaviour.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::{fs::File, io::Read, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use composefs::{
    dumpfile::write_dumpfile,
    erofs::reader::erofs_to_filesystem,
    fsverity::{FsVerityHashValue, Sha256HashValue, measure_verity_with_fallback},
    generic_tree::{Inode, LeafContent, LeafId},
    tree::FileSystem,
};

/// Query information from composefs images.
#[derive(Parser, Debug)]
#[command(
    name = "composefs-info",
    version,
    about = "Query information from composefs images"
)]
struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    command: Command,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
enum Command {
    /// Simple listing of files and directories in the image.
    Ls {
        /// Filter entries at the root level by name (can be specified multiple times).
        #[arg(long = "filter", action = clap::ArgAction::Append)]
        filter: Vec<String>,
        /// Composefs image files to inspect.
        images: Vec<PathBuf>,
    },

    /// Full dump in composefs-dump(5) format.
    Dump {
        /// Filter entries at the root level by name (can be specified multiple times).
        #[arg(long = "filter", action = clap::ArgAction::Append)]
        filter: Vec<String>,
        /// Composefs image files to dump.
        images: Vec<PathBuf>,
    },

    /// List all backing file object paths.
    Objects {
        /// Composefs image files to inspect.
        images: Vec<PathBuf>,
    },

    /// List backing files not present in basedir.
    MissingObjects {
        /// Base directory for object lookups.
        #[arg(long = "basedir", required = true)]
        basedir: PathBuf,
        /// Composefs image files to inspect.
        images: Vec<PathBuf>,
    },

    /// Print the fs-verity digest of files.
    MeasureFile {
        /// Files to measure.
        files: Vec<PathBuf>,
    },
}

/// Entry point for the composefs-info multi-call mode.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    run_with_cli(cli)
}

/// Entry point when invoked as a hidden `cfsctl composefs-info` subcommand.
///
/// `extra_args` contains everything after the `composefs-info` token as
/// captured by clap's trailing-var-arg mechanism.  A synthetic `argv[0]` is
/// prepended so that `Cli::parse_from` produces the same help text / error
/// messages as the standalone binary.
pub fn run_from_args(extra_args: Vec<std::ffi::OsString>) -> Result<()> {
    let mut argv = vec![std::ffi::OsString::from("composefs-info")];
    argv.extend(extra_args);
    let cli = Cli::parse_from(argv);
    run_with_cli(cli)
}

fn run_with_cli(cli: Cli) -> Result<()> {
    match &cli.command {
        Command::Ls { filter, images } => cmd_ls(filter, images),
        Command::Dump { filter, images } => cmd_dump(filter, images),
        Command::Objects { images } => cmd_objects(images),
        Command::MissingObjects { basedir, images } => cmd_missing_objects(basedir, images),
        Command::MeasureFile { files } => cmd_measure_file(files),
    }
}

/// Print escaped path (matches C implementation behavior).
fn print_escaped<W: Write>(out: &mut W, s: &[u8]) -> std::io::Result<()> {
    for &c in s {
        match c {
            b'\\' => write!(out, "\\\\")?,
            b'\n' => write!(out, "\\n")?,
            b'\r' => write!(out, "\\r")?,
            b'\t' => write!(out, "\\t")?,
            // Non-printable or non-ASCII characters are hex-escaped
            c if !c.is_ascii_graphic() && c != b' ' => write!(out, "\\x{c:02x}")?,
            c => out.write_all(&[c])?,
        }
    }
    Ok(())
}

/// Walk and print entries: directory line first, then recurse into children.
fn ls_print<W: Write>(
    out: &mut W,
    fs: &FileSystem<Sha256HashValue>,
    dir: &composefs::tree::Directory<Sha256HashValue>,
    path: &[u8],
    seen_leaf_ids: &mut HashSet<LeafId>,
    filter: Option<&[String]>,
) -> Result<()> {
    for (name, child) in dir.sorted_entries() {
        let name_bytes = name.as_encoded_bytes();

        if let Some(filter) = filter
            && !filter.is_empty()
        {
            let name_str = name.to_string_lossy();
            if !filter.iter().any(|f| f == name_str.as_ref()) {
                continue;
            }
        }

        let mut child_path = path.to_vec();
        child_path.push(b'/');
        child_path.extend_from_slice(name_bytes);

        match child {
            Inode::Directory(child_dir) => {
                // Print the directory entry with trailing slash.
                print_escaped(out, &child_path)?;
                write!(out, "/\t")?;
                writeln!(out)?;
                // Recurse into the directory.
                ls_print(out, fs, child_dir, &child_path, seen_leaf_ids, None)?;
            }
            Inode::Leaf(leaf_id, _) => {
                let leaf = fs.leaf(*leaf_id);

                print_escaped(out, &child_path)?;

                match &leaf.content {
                    LeafContent::Regular(regular) => {
                        let is_hardlink = !seen_leaf_ids.insert(*leaf_id);
                        if !is_hardlink && let Some(path) = regular.backing_path() {
                            write!(out, "\t@ ")?;
                            print_escaped(out, path.as_bytes())?;
                        }
                    }
                    LeafContent::Symlink(target) => {
                        write!(out, "\t-> ")?;
                        print_escaped(out, target.as_encoded_bytes())?;
                    }
                    _ => {}
                }

                writeln!(out)?;
            }
        }
    }
    Ok(())
}

/// List files and directories in the image.
fn cmd_ls(filter: &[String], images: &[PathBuf]) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for image_path in images {
        let image_data = read_image(image_path)?;
        let fs = erofs_to_filesystem::<Sha256HashValue>(&image_data)
            .with_context(|| format!("Failed to parse image: {image_path:?}"))?;

        let mut seen_leaf_ids = HashSet::new();
        ls_print(
            &mut out,
            &fs,
            &fs.root,
            b"",
            &mut seen_leaf_ids,
            Some(filter),
        )?;
    }

    Ok(())
}

/// Dump the image in composefs-dump(5) text format.
///
/// This matches the C composefs-info dump output: the EROFS image is parsed
/// back into a filesystem tree which is then serialized as a dumpfile.
fn cmd_dump(_filter: &[String], images: &[PathBuf]) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for image_path in images {
        let image_data = read_image(image_path)?;
        let fs = erofs_to_filesystem::<Sha256HashValue>(&image_data)
            .with_context(|| format!("Failed to parse image: {image_path:?}"))?;
        write_dumpfile(&mut out, &fs)
            .with_context(|| format!("Failed to dump image: {image_path:?}"))?;
    }

    Ok(())
}

/// Collect the backing paths of all external files in a parsed filesystem.
///
/// Like `composefs-info` from libcomposefs, these are the payloads (the
/// paths the overlay redirects point at, relative to the object store), so
/// ostree's `xx/<checksum>.file` objects are listed as they are.  Files
/// with only a verity digest have no backing path and aren't listed.
fn collect_objects_from_fs(fs: &FileSystem<Sha256HashValue>) -> BTreeSet<OsString> {
    fs.leaves
        .iter()
        .filter_map(|leaf| match &leaf.content {
            LeafContent::Regular(file) => file.backing_path().map(Cow::into_owned),
            _ => None,
        })
        .collect()
}

/// List all object paths from the images.
fn cmd_objects(images: &[PathBuf]) -> Result<()> {
    for image_path in images {
        let image_data = read_image(image_path)?;
        let fs = erofs_to_filesystem::<Sha256HashValue>(&image_data)
            .with_context(|| format!("Failed to parse image: {image_path:?}"))?;

        for obj in collect_objects_from_fs(&fs) {
            println!("{}", obj.display());
        }
    }
    Ok(())
}

/// Returns an object's path relative to the object store, without the
/// leading slashes a payload may have, so that joining it to the base
/// directory can't replace it (like C's `abs_to_rel_path()`).
fn object_relative_path(obj: &OsStr) -> &Path {
    let mut bytes = obj.as_bytes();
    while let Some(rest) = bytes.strip_prefix(b"/") {
        bytes = rest;
    }
    Path::new(OsStr::from_bytes(bytes))
}

/// List objects not present in basedir.
fn cmd_missing_objects(basedir: &Path, images: &[PathBuf]) -> Result<()> {
    let mut all_objects = BTreeSet::new();

    for image_path in images {
        let image_data = read_image(image_path)?;
        let fs = erofs_to_filesystem::<Sha256HashValue>(&image_data)
            .with_context(|| format!("Failed to parse image: {image_path:?}"))?;
        all_objects.extend(collect_objects_from_fs(&fs));
    }

    for obj in all_objects {
        if !basedir.join(object_relative_path(&obj)).exists() {
            println!("{}", obj.display());
        }
    }

    Ok(())
}

/// Compute and print the fs-verity digest of each file.
fn cmd_measure_file(files: &[PathBuf]) -> Result<()> {
    for path in files {
        let file = File::open(path).with_context(|| format!("Failed to open file: {path:?}"))?;
        let digest = measure_verity_with_fallback::<Sha256HashValue>(file)
            .with_context(|| format!("Failed to measure verity for {path:?}"))?;
        println!("{}", digest.to_hex());
    }
    Ok(())
}

/// Read an entire image file into memory.
fn read_image(path: &PathBuf) -> Result<Vec<u8>> {
    let mut file = File::open(path).with_context(|| format!("Failed to open image: {path:?}"))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .with_context(|| format!("Failed to read image: {path:?}"))?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_relative_path() {
        let cases = [
            ("ab/cdef", "ab/cdef"),
            ("8a/5d74.file", "8a/5d74.file"),
            ("/8a/5d74.file", "8a/5d74.file"),
            ("//8a/5d74.file", "8a/5d74.file"),
            ("/", ""),
            ("///", ""),
            ("", ""),
        ];
        for (obj, expected) in cases {
            let rel = object_relative_path(OsStr::new(obj));
            assert_eq!(rel, Path::new(expected), "{obj}");
            assert!(Path::new("/base").join(rel).starts_with("/base"), "{obj}");
        }
        assert_eq!(
            object_relative_path(OsStr::from_bytes(b"//ab/\xff")),
            Path::new(OsStr::from_bytes(b"ab/\xff"))
        );
    }
}
