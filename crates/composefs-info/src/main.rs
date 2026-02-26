//! composefs-info - Query information from composefs images.
//!
//! This is a Rust reimplementation of the C composefs-info tool, providing
//! commands to inspect EROFS images, list objects, and compute fs-verity digests.

use std::collections::HashSet;
use std::io::Write;
use std::{fs::File, io::Read, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use composefs::{
    erofs::{
        composefs::OverlayMetacopy,
        dump::dump_erofs,
        format::{S_IFCHR, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG},
        reader::{collect_objects, DirectoryBlock, Image, InodeHeader, InodeOps, InodeType},
    },
    fsverity::{FsVerityHashValue, FsVerityHasher, Sha256HashValue},
};
use zerocopy::FromBytes;

/// Query information from composefs images.
#[derive(Parser, Debug)]
#[command(name = "composefs-info", version, about)]
struct Cli {
    /// Filter entries by type or pattern (can be specified multiple times).
    #[arg(long = "filter", action = clap::ArgAction::Append)]
    filter: Vec<String>,

    /// Base directory for object lookups.
    #[arg(long)]
    basedir: Option<PathBuf>,

    /// The subcommand to run.
    #[command(subcommand)]
    command: Command,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
enum Command {
    /// Simple listing of files and directories in the image.
    Ls {
        /// Composefs image files to inspect.
        images: Vec<PathBuf>,
    },

    /// Full dump in composefs-dump(5) format.
    Dump {
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
        /// Composefs image files to inspect.
        images: Vec<PathBuf>,
    },

    /// Print the fs-verity digest of files.
    MeasureFile {
        /// Files to measure.
        files: Vec<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Ls { images } => cmd_ls(&cli, images),
        Command::Dump { images } => cmd_dump(&cli, images),
        Command::Objects { images } => cmd_objects(&cli, images),
        Command::MissingObjects { images } => cmd_missing_objects(&cli, images),
        Command::MeasureFile { files } => cmd_measure_file(files),
    }
}

/// Checks if an inode is a whiteout entry (internal to composefs, should not be listed).
///
/// Whiteout entries are character devices with rdev == 0. They are used for
/// overlayfs whiteout tracking and the xattr hash table.
fn is_whiteout(inode: &InodeType<'_>) -> bool {
    let mode = inode.mode().0.get();
    let ifmt = mode & S_IFMT;
    // Character device with rdev == 0 is a whiteout
    (ifmt == S_IFCHR) && (inode.rdev() == 0)
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

/// Get the backing file path from overlay.metacopy xattr if present.
fn get_backing_path(img: &Image, inode: &InodeType) -> Option<String> {
    let xattrs = inode.xattrs()?;

    // Check shared xattrs
    for id in xattrs.shared() {
        let attr = img.shared_xattr(id.get());
        // trusted. prefix has name_index == 4
        if attr.header.name_index == 4 && attr.suffix() == b"overlay.metacopy" {
            if let Ok(metacopy) = OverlayMetacopy::<Sha256HashValue>::read_from_bytes(attr.value())
            {
                if metacopy.valid() {
                    let hex = metacopy.digest.to_hex();
                    return Some(format!("{}/{}", &hex[..2], &hex[2..]));
                }
            }
        }
    }

    // Check local xattrs
    for attr in xattrs.local() {
        if attr.header.name_index == 4 && attr.suffix() == b"overlay.metacopy" {
            if let Ok(metacopy) = OverlayMetacopy::<Sha256HashValue>::read_from_bytes(attr.value())
            {
                if metacopy.valid() {
                    let hex = metacopy.digest.to_hex();
                    return Some(format!("{}/{}", &hex[..2], &hex[2..]));
                }
            }
        }
    }

    None
}

/// Get symlink target from inode inline data.
fn get_symlink_target<'a>(inode: &'a InodeType<'a>) -> Option<&'a [u8]> {
    inode.inline()
}

/// Entry representing a file in the image for listing.
struct LsEntry {
    path: Vec<u8>,
    nid: u64,
    is_hardlink: bool, // True if this nid was seen before
}

/// Context for collecting directory entries.
struct CollectContext<'a> {
    img: &'a Image<'a>,
    entries: Vec<LsEntry>,
    visited_dirs: HashSet<u64>,
    seen_nids: HashSet<u64>,
    filters: &'a [String],
}

impl<'a> CollectContext<'a> {
    fn new(img: &'a Image<'a>, filters: &'a [String]) -> Self {
        Self {
            img,
            entries: Vec::new(),
            visited_dirs: HashSet::new(),
            seen_nids: HashSet::new(),
            filters,
        }
    }

    /// Walk directory tree and collect all entries.
    fn collect(&mut self, nid: u64, path_prefix: &[u8], depth: usize) {
        if !self.visited_dirs.insert(nid) {
            return; // Already visited directory (prevents infinite recursion)
        }

        let inode = self.img.inode(nid);
        if !inode.mode().is_dir() {
            return;
        }

        // Collect directory entries from blocks and inline data
        let mut dir_entries: Vec<(Vec<u8>, u64)> = Vec::new();

        for blkid in inode.blocks(self.img.blkszbits) {
            let block = self.img.directory_block(blkid);
            for entry in block.entries() {
                if entry.name != b"." && entry.name != b".." {
                    dir_entries.push((entry.name.to_vec(), entry.header.inode_offset.get()));
                }
            }
        }

        if let Some(inline) = inode.inline() {
            if !inline.is_empty() {
                if let Ok(inline_block) = DirectoryBlock::ref_from_bytes(inline) {
                    for entry in inline_block.entries() {
                        if entry.name != b"." && entry.name != b".." {
                            dir_entries
                                .push((entry.name.to_vec(), entry.header.inode_offset.get()));
                        }
                    }
                }
            }
        }

        // Sort entries alphabetically for consistent output
        dir_entries.sort_by(|a, b| a.0.cmp(&b.0));

        for (name, child_nid) in dir_entries {
            let child_inode = self.img.inode(child_nid);

            // Skip whiteout entries (internal to composefs, e.g., xattr hash table buckets)
            if is_whiteout(&child_inode) {
                continue;
            }

            // At depth 0 (root), apply filters if any
            if depth == 0 && !self.filters.is_empty() {
                let name_str = String::from_utf8_lossy(&name);
                if !self.filters.iter().any(|f| f == name_str.as_ref()) {
                    continue;
                }
            }

            // Build full path
            let mut full_path = path_prefix.to_vec();
            full_path.push(b'/');
            full_path.extend_from_slice(&name);

            // Track if this is a hardlink (same nid seen before for non-directory files)
            let is_hardlink = !child_inode.mode().is_dir() && !self.seen_nids.insert(child_nid);

            self.entries.push(LsEntry {
                path: full_path.clone(),
                nid: child_nid,
                is_hardlink,
            });

            // Recurse into subdirectories
            if child_inode.mode().is_dir() {
                self.collect(child_nid, &full_path, depth + 1);
            }
        }
    }
}

/// List files and directories in the image.
fn cmd_ls(cli: &Cli, images: &[PathBuf]) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for image_path in images {
        let image_data = read_image(image_path)?;
        let img = Image::open(&image_data);

        let root_nid = img.sb.root_nid.get() as u64;
        let mut ctx = CollectContext::new(&img, &cli.filter);
        ctx.collect(root_nid, b"", 0);

        for entry in ctx.entries {
            let inode = img.inode(entry.nid);
            let mode = inode.mode().0.get();
            let file_type = mode & S_IFMT;

            // Print escaped path
            print_escaped(&mut out, &entry.path)?;

            match file_type {
                S_IFDIR => {
                    // Directory: trailing slash and tab
                    write!(out, "/\t")?;
                }
                S_IFLNK => {
                    // Symlink: -> target
                    write!(out, "\t-> ")?;
                    if let Some(target) = get_symlink_target(&inode) {
                        print_escaped(&mut out, target)?;
                    }
                }
                S_IFREG => {
                    // Regular file: check for backing path (but not for hardlinks)
                    if !entry.is_hardlink {
                        if let Some(backing_path) = get_backing_path(&img, &inode) {
                            write!(out, "\t@ ")?;
                            print_escaped(&mut out, backing_path.as_bytes())?;
                        }
                    }
                    // Inline files and hardlinks just get the path (nothing appended)
                }
                _ => {
                    // Other file types (block/char devices, fifos, sockets): just path
                }
            }

            writeln!(out)?;
        }
    }

    Ok(())
}

/// Dump the image in composefs-dump(5) format.
fn cmd_dump(cli: &Cli, images: &[PathBuf]) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for image_path in images {
        let image_data = read_image(image_path)?;
        dump_erofs(&mut out, &image_data, &cli.filter)
            .with_context(|| format!("Failed to dump image: {image_path:?}"))?;
    }

    Ok(())
}

/// List all object paths from the images.
fn cmd_objects(cli: &Cli, images: &[PathBuf]) -> Result<()> {
    for image_path in images {
        let image_data = read_image(image_path)?;
        let objects: std::collections::HashSet<Sha256HashValue> =
            collect_objects(&image_data, &cli.filter)
                .context("Failed to collect objects from image")?;

        // Convert to sorted list for deterministic output
        let mut object_list: Vec<_> = objects.into_iter().collect();
        object_list.sort_by_key(|a| a.to_hex());

        for obj in object_list {
            // Output in standard composefs object path format: XX/XXXX...
            let hex = obj.to_hex();
            println!("{}/{}", &hex[..2], &hex[2..]);
        }
    }
    Ok(())
}

/// List objects not present in basedir.
fn cmd_missing_objects(cli: &Cli, images: &[PathBuf]) -> Result<()> {
    let basedir = cli
        .basedir
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--basedir is required for missing-objects command"))?;

    // Collect all objects from all images
    let mut all_objects: HashSet<Sha256HashValue> = HashSet::new();
    for image_path in images {
        let image_data = read_image(image_path)?;
        let objects = collect_objects(&image_data, &cli.filter)
            .context("Failed to collect objects from image")?;
        all_objects.extend(objects);
    }

    // Check which objects are missing from basedir
    let mut missing: Vec<_> = all_objects
        .into_iter()
        .filter(|obj| {
            let hex = obj.to_hex();
            let object_path = basedir.join(format!("{}/{}", &hex[..2], &hex[2..]));
            !object_path.exists()
        })
        .collect();

    // Sort for deterministic output
    missing.sort_by_key(|a| a.to_hex());

    for obj in missing {
        let hex = obj.to_hex();
        println!("{}/{}", &hex[..2], &hex[2..]);
    }

    Ok(())
}

/// Compute and print the fs-verity digest of each file.
fn cmd_measure_file(files: &[PathBuf]) -> Result<()> {
    for path in files {
        let mut file =
            File::open(path).with_context(|| format!("Failed to open file: {path:?}"))?;

        let mut hasher = FsVerityHasher::<Sha256HashValue>::new();
        let mut buf = vec![0u8; FsVerityHasher::<Sha256HashValue>::BLOCK_SIZE];

        loop {
            let n = file
                .read(&mut buf)
                .with_context(|| format!("Failed to read file: {path:?}"))?;
            if n == 0 {
                break;
            }
            hasher.add_block(&buf[..n]);
        }

        let digest = hasher.digest();
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
