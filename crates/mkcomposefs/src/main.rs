//! mkcomposefs - Create composefs images from directories or dumpfiles.
//!
//! This is a Rust reimplementation of the C mkcomposefs tool, providing
//! compatible command-line interface and output format.

use std::{
    ffi::OsString,
    fs::File,
    io::{self, BufReader, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use rustix::fs::CWD;

use composefs::{
    dumpfile::dumpfile_to_filesystem,
    erofs::{format::FormatVersion, writer::mkfs_erofs},
    fs::read_filesystem,
    fsverity::{compute_verity, FsVerityHashValue, Sha256HashValue},
    repository::Repository,
    tree::FileSystem,
};

/// Create a composefs image from a source directory or dumpfile.
///
/// Composefs uses EROFS image files for metadata and separate content-addressed
/// backing directories for regular file data.
#[derive(Parser, Debug)]
#[command(name = "mkcomposefs", version, about)]
struct Args {
    /// Treat SOURCE as a dumpfile in composefs-dump(5) format.
    ///
    /// If SOURCE is `-`, reads from stdin.
    #[arg(long)]
    from_file: bool,

    /// Print the fsverity digest of the image after writing.
    #[arg(long)]
    print_digest: bool,

    /// Print the fsverity digest without writing the image.
    ///
    /// When set, IMAGE must be omitted.
    #[arg(long)]
    print_digest_only: bool,

    /// Set modification time to zero (Unix epoch) for all files.
    #[arg(long)]
    use_epoch: bool,

    /// Exclude device nodes from the image.
    #[arg(long)]
    skip_devices: bool,

    /// Exclude all extended attributes.
    #[arg(long)]
    skip_xattrs: bool,

    /// Only include xattrs with the `user.` prefix.
    #[arg(long)]
    user_xattrs: bool,

    /// Minimum image format version to use (0 or 1).
    #[arg(long, default_value = "0")]
    min_version: u32,

    /// Maximum image format version (for auto-upgrade).
    #[arg(long, default_value = "1")]
    max_version: u32,

    /// Copy regular file content to the given object store directory.
    ///
    /// Files are stored by their fsverity digest in a content-addressed layout
    /// (objects/XX/XXXX...). The directory is created if it doesn't exist.
    ///
    /// Note: Uses composefs-rs Repository format which differs slightly from
    /// the C mkcomposefs format (C uses XX/digest directly, Rust uses objects/XX/digest).
    #[arg(long)]
    digest_store: Option<PathBuf>,

    /// Number of threads to use for digest calculation and file copying.
    #[arg(long)]
    threads: Option<usize>,

    /// The source directory or dumpfile.
    source: PathBuf,

    /// The output image path (use `-` for stdout).
    ///
    /// Must be omitted when using --print-digest-only.
    image: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Validate arguments
    if args.print_digest_only && args.image.is_some() {
        bail!("IMAGE must be omitted when using --print-digest-only");
    }

    if !args.print_digest_only && args.image.is_none() {
        bail!("IMAGE is required (or use --print-digest-only)");
    }

    // Check for unimplemented features
    if args.threads.is_some() {
        todo!("--threads is not yet implemented");
    }

    // Determine format version based on min/max version flags
    // min_version=0 means we can use Format 1.0 (composefs_version=0)
    // min_version=1+ means we should use Format 1.1 (composefs_version=2)
    // Note: Full Format 1.0 support (compact inodes, whiteout table) is not yet
    // implemented. Currently this only affects the composefs_version header and
    // build_time fields.
    let format_version = if args.min_version == 0 {
        FormatVersion::V1_0
    } else {
        FormatVersion::V1_1
    };

    // Open or create digest store if specified
    let repo = if let Some(store_path) = &args.digest_store {
        Some(open_or_create_repository(store_path)?)
    } else {
        None
    };

    // Read input
    let mut fs = if args.from_file {
        read_dumpfile(&args)?
    } else {
        read_directory(&args.source, repo.as_ref())?
    };

    // Apply transformations based on flags
    apply_transformations(&mut fs, &args, format_version)?;

    // Generate EROFS image
    let image = mkfs_erofs(&fs, format_version);

    // Handle output
    if args.print_digest_only {
        let digest = compute_fsverity_digest(&image);
        println!("{digest}");
        return Ok(());
    }

    // Write image
    let image_path = args.image.as_ref().unwrap();
    write_image(image_path, &image)?;

    // Optionally print digest
    if args.print_digest {
        let digest = compute_fsverity_digest(&image);
        println!("{digest}");
    }

    Ok(())
}

/// Read and parse a dumpfile from the given source.
fn read_dumpfile(args: &Args) -> Result<composefs::tree::FileSystem<Sha256HashValue>> {
    let content = if args.source.as_os_str() == "-" {
        // Read from stdin
        let stdin = io::stdin();
        let mut content = String::new();
        stdin.lock().read_to_string(&mut content)?;
        content
    } else {
        // Read from file
        let file = File::open(&args.source)
            .with_context(|| format!("Failed to open dumpfile: {:?}", args.source))?;
        let mut reader = BufReader::new(file);
        let mut content = String::new();
        reader.read_to_string(&mut content)?;
        content
    };

    dumpfile_to_filesystem(&content).context("Failed to parse dumpfile")
}

/// Read a filesystem tree from a directory path.
///
/// If a repository is provided, large file contents are stored in the
/// content-addressed object store and referenced by digest.
fn read_directory(
    path: &Path,
    repo: Option<&Repository<Sha256HashValue>>,
) -> Result<FileSystem<Sha256HashValue>> {
    // Verify the path exists and is a directory
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to access source directory: {path:?}"))?;

    if !metadata.is_dir() {
        bail!("Source path is not a directory: {path:?}");
    }

    // Read the filesystem tree from the directory
    // If repo is provided, large files are stored in the content-addressed store
    // and referenced by their fsverity digest
    read_filesystem(CWD, path, repo)
        .with_context(|| format!("Failed to read directory tree: {path:?}"))
}

/// Open an existing repository or create a new one at the given path.
fn open_or_create_repository(path: &Path) -> Result<Repository<Sha256HashValue>> {
    use rustix::fs::{mkdirat, Mode};

    // Create the directory if it doesn't exist
    match mkdirat(CWD, path, Mode::from_raw_mode(0o755)) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {} // Already exists, that's fine
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to create digest store: {path:?}"))
        }
    }

    let mut repo = Repository::open_path(CWD, path)
        .with_context(|| format!("Failed to open digest store: {path:?}"))?;

    // Enable insecure mode since most filesystems don't support fsverity
    // (tmpfs, overlayfs, ext4 without verity, etc.)
    repo.set_insecure(true);

    Ok(repo)
}

/// Write the image to the specified path (or stdout if `-`).
fn write_image(path: &PathBuf, image: &[u8]) -> Result<()> {
    if path.as_os_str() == "-" {
        let stdout = io::stdout();
        if stdout.is_terminal() {
            bail!(
                "Refusing to write binary image to terminal. Redirect stdout or use a file path."
            );
        }
        stdout.lock().write_all(image)?;
    } else {
        let mut file =
            File::create(path).with_context(|| format!("Failed to create image file: {path:?}"))?;
        file.write_all(image)?;
    }
    Ok(())
}

/// Compute the fsverity digest of the image.
fn compute_fsverity_digest(image: &[u8]) -> String {
    let digest: Sha256HashValue = compute_verity(image);
    digest.to_hex()
}

/// Apply filesystem transformations based on command-line flags.
fn apply_transformations(
    fs: &mut FileSystem<Sha256HashValue>,
    args: &Args,
    format_version: FormatVersion,
) -> Result<()> {
    // Handle xattr filtering
    if args.skip_xattrs {
        // Remove all xattrs
        fs.filter_xattrs(|_| false);
    } else if args.user_xattrs {
        // Keep only user.* xattrs
        fs.filter_xattrs(|name| name.as_encoded_bytes().starts_with(b"user."));
    }

    // Handle --use-epoch (set all mtimes to 0)
    if args.use_epoch {
        set_all_mtimes_to_epoch(fs);
    }

    // Handle --skip-devices (remove device nodes)
    if args.skip_devices {
        remove_device_nodes(fs);
    }

    // For Format 1.0, add overlay whiteout entries for compatibility
    // with the C mkcomposefs tool.
    // Note: The overlay.opaque xattr is added by the writer (not here) to ensure
    // it's not escaped by the trusted.overlay.* escaping logic.
    if format_version == FormatVersion::V1_0 {
        fs.add_overlay_whiteouts();
    }

    Ok(())
}

/// Set all modification times in the filesystem to Unix epoch (0).
///
/// Note: Currently only sets directory mtimes. Leaf node mtimes cannot be
/// modified through the current API because they are behind Rc without
/// interior mutability for st_mtim_sec.
fn set_all_mtimes_to_epoch(fs: &mut FileSystem<Sha256HashValue>) {
    // Set root directory mtime
    fs.root.stat.st_mtim_sec = 0;

    // Recursively set subdirectory mtimes
    fn visit_dir(
        dir: &mut composefs::generic_tree::Directory<composefs::tree::RegularFile<Sha256HashValue>>,
    ) {
        // Get list of subdirectory names
        let subdir_names: Vec<OsString> = dir
            .entries()
            .filter_map(|(name, inode)| {
                if matches!(inode, composefs::generic_tree::Inode::Directory(_)) {
                    Some(name.to_os_string())
                } else {
                    None
                }
            })
            .collect();

        // Visit each subdirectory
        for name in subdir_names {
            if let Ok(subdir) = dir.get_directory_mut(&name) {
                subdir.stat.st_mtim_sec = 0;
                visit_dir(subdir);
            }
        }
    }

    visit_dir(&mut fs.root);

    // TODO: Leaf mtimes are not modified here. The C implementation handles
    // this during tree construction. For full compatibility, we would need
    // to either:
    // 1. Add Cell<i64> for st_mtim_sec in the Stat struct (upstream change)
    // 2. Modify the dumpfile parser to accept a flag for epoch times
    // 3. Rebuild leaves with modified stats (expensive)
    //
    // TODO: Implement when upstream Stat struct supports mutable mtime
}

/// Remove all device nodes (block and character devices) from the filesystem.
fn remove_device_nodes(fs: &mut FileSystem<Sha256HashValue>) {
    use composefs::generic_tree::LeafContent;

    fn process_dir(
        dir: &mut composefs::generic_tree::Directory<composefs::tree::RegularFile<Sha256HashValue>>,
    ) {
        // First, collect names of subdirectories to process
        let subdir_names: Vec<OsString> = dir
            .entries()
            .filter_map(|(name, inode)| {
                if matches!(inode, composefs::generic_tree::Inode::Directory(_)) {
                    Some(name.to_os_string())
                } else {
                    None
                }
            })
            .collect();

        // Recursively process subdirectories
        for name in subdir_names {
            if let Ok(subdir) = dir.get_directory_mut(&name) {
                process_dir(subdir);
            }
        }

        // Collect names of device nodes to remove
        let devices_to_remove: Vec<OsString> = dir
            .entries()
            .filter_map(|(name, inode)| {
                if let composefs::generic_tree::Inode::Leaf(leaf) = inode {
                    if matches!(
                        leaf.content,
                        LeafContent::BlockDevice(_) | LeafContent::CharacterDevice(_)
                    ) {
                        return Some(name.to_os_string());
                    }
                }
                None
            })
            .collect();

        // Remove device nodes
        for name in devices_to_remove {
            dir.remove(&name);
        }
    }

    process_dir(&mut fs.root);
}
