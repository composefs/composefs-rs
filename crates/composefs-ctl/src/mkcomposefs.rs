//! mkcomposefs - Create composefs images from directories or dumpfiles.
//!
//! This is a Rust reimplementation of the C mkcomposefs tool, providing
//! compatible command-line interface and output format.
//!
//! ## Compatibility status
//!
//! See <https://github.com/composefs/composefs/discussions/423> for context.
//!
//! Implemented and tested (byte-for-byte match with C mkcomposefs):
//! - `--from-file`, `--print-digest`, `--print-digest-only`
//! - `--skip-devices`, `--skip-xattrs`, `--user-xattrs`
//! - `--min-version` / `--max-version` (V1 compact inodes, BFS ordering, whiteout table)
//! - `--digest-store` (C-compatible flat `XX/digest` layout via [`FlatDigestStore`])
//! - `--threads` (controls tokio worker threads and verity-computation concurrency)
//! - Source from directory or dumpfile, output to file or stdout
//!
//! Bit-for-bit compatible with the C mkcomposefs by default; use `--hardlinks`
//! to enable host hard-link deduplication (shared EROFS inodes, i_nlink > 1).

use std::{
    ffi::OsString,
    fs::File,
    io::{self, BufReader, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    thread::available_parallelism,
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use rustix::fs::CWD;
use tokio::sync::Semaphore;

use composefs::{
    dumpfile::dumpfile_to_filesystem,
    erofs::{
        format::FormatVersion,
        writer::{ValidatedFileSystem, mkfs_erofs_versioned},
    },
    fs::{
        FlatDigestStore, HardlinkBehavior, ObjectStore, ReadFilesystemOpts,
        read_filesystem_with_opts,
    },
    fsverity::{FsVerityHashValue, Sha256HashValue, compute_verity},
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
    /// Files are stored by their fsverity digest using the same flat layout
    /// as C mkcomposefs: `XX/DIGEST` where XX is the first byte of the digest.
    /// The directory is created if it doesn't exist. The layout is compatible
    /// with digest stores written by the C mkcomposefs tool.
    #[arg(long)]
    digest_store: Option<PathBuf>,

    /// Deduplicate hard-linked files on the source filesystem into shared
    /// EROFS inodes. Without this flag the output is bit-for-bit compatible
    /// with the C mkcomposefs tool.
    #[arg(long)]
    hardlinks: bool,

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

/// Entry point for the mkcomposefs multi-call mode.
pub fn run() -> Result<()> {
    let args = Args::parse();
    run_with_args(args)
}

/// Entry point when invoked as a hidden `cfsctl mkcomposefs` subcommand.
///
/// `extra_args` contains everything after the `mkcomposefs` token as captured
/// by clap's trailing-var-arg mechanism.  A synthetic `argv[0]` is prepended
/// so that `Args::parse_from` produces the same help text / error messages as
/// the standalone binary.
pub fn run_from_args(extra_args: Vec<std::ffi::OsString>) -> Result<()> {
    let mut argv = vec![std::ffi::OsString::from("mkcomposefs")];
    argv.extend(extra_args);
    let args = Args::parse_from(argv);
    run_with_args(args)
}

fn run_with_args(args: Args) -> Result<()> {
    // Validate arguments
    if args.print_digest_only && args.image.is_some() {
        bail!("IMAGE must be omitted when using --print-digest-only");
    }

    if !args.print_digest_only && args.image.is_none() {
        bail!("IMAGE is required (or use --print-digest-only)");
    }

    if args.min_version > args.max_version {
        bail!(
            "Invalid version range: --min-version ({}) must not exceed --max-version ({})",
            args.min_version,
            args.max_version
        );
    }

    // The C composefs tool supports only versions 0 and 1 (LCFS_VERSION_MAX=1).
    // Both use the same C-compatible on-disk format (compact inodes, BFS, whiteout
    // table).  The difference is in the `composefs_version` EROFS header field:
    //   - version 0 (default): starts at 0, auto-upgrades to 1 if a user-visible
    //     whiteout device (chr 0,0) is encountered.
    //   - version 1: always writes composefs_version=1 regardless of content.
    // Versions > 1 are not defined by the C tool and are rejected below.
    if args.min_version > 1 {
        bail!(
            "--min-version {} is not supported; the maximum C-compatible version is 1",
            args.min_version
        );
    }
    // Map C --min-version to our FormatVersion: 0 → V0 (auto-detect), 1 → V1 (always 1).
    let format_version = if args.min_version >= 1 {
        FormatVersion::V1
    } else {
        FormatVersion::V0
    };

    // Open or create the digest store if specified.
    // Always uses the C-compatible flat layout (XX/DIGEST) so that the store
    // is interchangeable with the one written by C mkcomposefs.
    let store: Option<Arc<dyn ObjectStore<Sha256HashValue>>> =
        if let Some(store_path) = &args.digest_store {
            let n = args
                .threads
                .unwrap_or_else(|| available_parallelism().map(|n| n.get()).unwrap_or(4));
            Some(Arc::new(FlatDigestStore::open(store_path, n, true)?))
        } else {
            None
        };

    // Warn if --digest-store is combined with --from-file (store is unused in that case)
    if args.from_file && args.digest_store.is_some() {
        eprintln!("warning: --digest-store is ignored when --from-file is specified");
    }

    // Read input
    let mut fs = if args.from_file {
        read_dumpfile(&args)?
    } else {
        read_directory(
            &args.source,
            store,
            args.threads,
            if args.hardlinks {
                HardlinkBehavior::Tracked
            } else {
                HardlinkBehavior::Break
            },
        )?
    };

    // Apply transformations based on flags
    apply_transformations(&mut fs, &args)?;

    // Generate EROFS image
    let image = mkfs_erofs_versioned(&mut ValidatedFileSystem::new(fs)?, format_version);

    // Write image (skipped when only the digest is requested)
    if !args.print_digest_only {
        let image_path = args.image.as_ref().unwrap();
        write_image(image_path, &image)?;
    }

    // Print digest when requested either way
    if args.print_digest || args.print_digest_only {
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
/// If a store is provided, large file contents are copied there and
/// referenced by digest. The store must implement [`ObjectStore`].
///
/// The `threads` argument controls both the tokio worker thread count and the
/// semaphore used to limit concurrent verity computations. `Some(1)` uses a
/// single-threaded runtime; `None` or `Some(n > 1)` uses the multi-threaded
/// scheduler.
fn read_directory(
    path: &Path,
    store: Option<Arc<dyn ObjectStore<Sha256HashValue>>>,
    threads: Option<usize>,
    hardlinks: HardlinkBehavior,
) -> Result<FileSystem<Sha256HashValue>> {
    use rustix::fs::{Mode, OFlags};

    // Verify the path exists and is a directory
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to access source directory: {path:?}"))?;

    if !metadata.is_dir() {
        bail!("Source path is not a directory: {path:?}");
    }

    // Open a dirfd for the current directory (required by the async API)
    let dirfd = rustix::fs::openat(
        CWD,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("Failed to open current directory")?;

    // Build a tokio runtime appropriate for the requested thread count.
    // --threads 1 → current_thread (no extra OS threads, minimal overhead).
    // --threads N → multi_thread with exactly N worker threads.
    // (default)  → multi_thread with the tokio default (one per logical CPU).
    let rt = match threads {
        Some(1) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create single-threaded tokio runtime")?,
        Some(n) => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(n)
            .enable_all()
            .build()
            .context("Failed to create multi-threaded tokio runtime")?,
        None => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Failed to create multi-threaded tokio runtime")?,
    };

    let path = path.to_path_buf();

    // When a store is present its semaphore is already configured; when there
    // is no store we build the semaphore ourselves so the requested thread
    // count is honoured.
    let semaphore = if store.is_none() {
        let n = threads.unwrap_or_else(|| available_parallelism().map(|n| n.get()).unwrap_or(4));
        Some(Arc::new(Semaphore::new(n)))
    } else {
        None
    };
    rt.block_on(read_filesystem_with_opts(
        dirfd,
        path,
        ReadFilesystemOpts {
            store,
            semaphore,
            hardlinks,
        },
    ))
    .context("Failed to read directory tree")
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
fn apply_transformations(fs: &mut FileSystem<Sha256HashValue>, args: &Args) -> Result<()> {
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

    Ok(())
}

/// Set all modification times in the filesystem to Unix epoch (0).
fn set_all_mtimes_to_epoch(fs: &mut FileSystem<Sha256HashValue>) {
    fs.for_each_stat_mut(|stat| {
        stat.st_mtim_sec = 0;
        stat.st_mtim_nsec = 0;
    });
}

/// Remove all device nodes (block and character devices) from the filesystem.
fn remove_device_nodes(fs: &mut FileSystem<Sha256HashValue>) {
    use composefs::generic_tree::{Inode, LeafContent};

    type Leaf = composefs::generic_tree::Leaf<composefs::tree::RegularFile<Sha256HashValue>>;
    type Dir = composefs::generic_tree::Directory<composefs::tree::RegularFile<Sha256HashValue>>;

    fn process_dir(dir: &mut Dir, leaves: &[Leaf]) {
        // First, collect names of subdirectories to process
        let subdir_names: Vec<OsString> = dir
            .entries()
            .filter_map(|(name, inode)| {
                if matches!(inode, Inode::Directory(_)) {
                    Some(name.to_os_string())
                } else {
                    None
                }
            })
            .collect();

        // Recursively process subdirectories
        for name in subdir_names {
            if let Ok(subdir) = dir.get_directory_mut(&name) {
                process_dir(subdir, leaves);
            }
        }

        // Collect names of device nodes to remove
        let devices_to_remove: Vec<OsString> = dir
            .entries()
            .filter_map(|(name, inode)| {
                if let Inode::Leaf(leaf_id, _) = inode
                    && matches!(
                        leaves[leaf_id.0].content,
                        LeafContent::BlockDevice(_) | LeafContent::CharacterDevice(_)
                    )
                {
                    return Some(name.to_os_string());
                }
                None
            })
            .collect();

        // Remove device nodes
        for name in devices_to_remove {
            dir.remove(&name);
        }
    }

    // Split struct field borrows: Rust allows borrowing different fields simultaneously.
    let FileSystem { root, leaves, .. } = fs;
    process_dir(root, leaves);

    // Compact the leaves table to remove entries now unreferenced after
    // device-node removal.  Without this, fs.fsck() would report orphaned leaves.
    fs.compact();
}
