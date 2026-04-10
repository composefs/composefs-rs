//! Library for `cfsctl` command line utility
//!
//! This crate also re-exports all composefs-rs library crates, so downstream
//! consumers can take a single dependency on `cfsctl` instead of listing each
//! crate individually.
//!
//! ```
//! use cfsctl::composefs::repository::Repository;
//! use cfsctl::composefs::fsverity::Sha256HashValue;
//!
//! let repo = Repository::<Sha256HashValue>::open_path(
//!     rustix::fs::CWD,
//!     "/nonexistent",
//! );
//! assert!(repo.is_err());
//! ```

pub use composefs;
pub use composefs_boot;
#[cfg(feature = "http")]
pub use composefs_http;
#[cfg(feature = "oci")]
pub use composefs_oci;

use std::io::Read;
use std::path::Path;
use std::{ffi::OsString, path::PathBuf};

#[cfg(feature = "oci")]
use std::{fs::create_dir_all, io::IsTerminal};

use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand, ValueEnum};
#[cfg(feature = "oci")]
use comfy_table::{Table, presets::UTF8_FULL};
use rustix::fs::{CWD, Mode, OFlags};
use serde::Serialize;

use composefs_boot::BootOps;
#[cfg(feature = "oci")]
use composefs_boot::write_boot;

#[cfg(feature = "oci")]
use composefs::shared_internals::IO_BUF_CAPACITY;
use composefs::{
    dumpfile::{dump_single_dir, dump_single_file},
    erofs::reader::erofs_to_filesystem,
    fsverity::{Algorithm, FsVerityHashValue, Sha256HashValue, Sha512HashValue},
    generic_tree::{FileSystem, Inode},
    repository::{REPO_METADATA_FILENAME, Repository, read_repo_algorithm, system_path, user_path},
    tree::RegularFile,
};

/// JSON output wrapper for `cfsctl fsck --json`.
#[derive(Serialize)]
struct FsckJsonOutput {
    ok: bool,
    #[serde(flatten)]
    result: composefs::repository::FsckResult,
}

/// JSON output wrapper for `cfsctl oci fsck --json`.
#[cfg(feature = "oci")]
#[derive(Serialize)]
struct OciFsckJsonOutput {
    ok: bool,
    #[serde(flatten)]
    result: composefs_oci::OciFsckResult,
}

/// cfsctl
#[derive(Debug, Parser)]
#[clap(name = "cfsctl", version)]
pub struct App {
    /// Operate on repo at path
    #[clap(long, group = "repopath")]
    repo: Option<PathBuf>,
    /// Operate on repo at standard user location $HOME/.var/lib/composefs
    #[clap(long, group = "repopath")]
    user: bool,
    /// Operate on repo at standard system location /sysroot/composefs
    #[clap(long, group = "repopath")]
    system: bool,

    /// What hash digest type to use for composefs repo.
    /// If omitted, auto-detected from repository metadata (meta.json).
    #[clap(long, value_enum)]
    pub hash: Option<HashType>,

    /// Deprecated: security mode is now auto-detected from meta.json.
    /// Use `cfsctl init --insecure` to create a repo without verity.
    /// Kept for backward compatibility.
    #[clap(long, hide = true)]
    insecure: bool,

    /// Error if the repository does not have fs-verity enabled.
    #[clap(long)]
    require_verity: bool,

    /// Don't open a repository. Only valid for commands that don't need one
    /// (compute-id, create-dumpfile).
    #[clap(long)]
    pub no_repo: bool,

    #[clap(subcommand)]
    cmd: Command,
}

/// The Hash algorithm used for FsVerity computation
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum HashType {
    /// Sha256
    Sha256,
    /// Sha512
    Sha512,
}

/// A reference to an OCI image: either a content digest or a named ref.
///
/// Digests are prefixed with `@` (e.g. `@sha256:abc123…`), while bare
/// names are refs resolved through the repository's ref tree. The `@`
/// prefix is necessary to disambiguate because ref names may contain `:`
/// — OCI digest algorithms are intentionally extensible, so we cannot
/// rely on parse heuristics to distinguish the two.
///
/// Note this differs from the podman/docker convention where `@` appears
/// between the image name and the digest (e.g. `fedora@sha256:abc…`).
/// Here, `@` is always a leading prefix on the entire argument.
///
/// At the repository level, ref names are freeform strings (the only
/// restriction is that they must not start with `@`). In practice,
/// `oci pull` defaults to tagging with the source transport reference
/// (e.g. `docker://quay.io/fedora/fedora:latest`), so most refs in a
/// repository will be container transport names — which naturally never
/// start with `@`.
#[cfg(feature = "oci")]
#[derive(Debug, Clone)]
enum OciReference {
    /// A content-addressable digest such as `sha256:abcdef…`.
    Digest(composefs_oci::OciDigest),
    /// A named ref resolved through the repository's ref tree, typically
    /// a container transport name (e.g. `docker://quay.io/foo:latest`).
    Named(String),
}

#[cfg(feature = "oci")]
impl std::str::FromStr for OciReference {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Some(digest_str) = s.strip_prefix('@') {
            let digest: composefs_oci::OciDigest =
                digest_str.parse().context("Invalid OCI digest after '@'")?;
            Ok(Self::Digest(digest))
        } else {
            Ok(Self::Named(s.to_owned()))
        }
    }
}

#[cfg(feature = "oci")]
impl std::fmt::Display for OciReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Digest(d) => write!(f, "@{d}"),
            Self::Named(n) => write!(f, "{n}"),
        }
    }
}

/// Common options for operations using OCI config manifest streams that may transform the image rootfs
#[cfg(feature = "oci")]
#[derive(Debug, Parser)]
struct OCIConfigFilesystemOptions {
    #[clap(flatten)]
    base_config: OCIConfigOptions,
    /// Whether bootable transformation should be performed on the image rootfs
    #[clap(long)]
    bootable: bool,
}

/// Common options for operations using OCI config manifest streams
#[cfg(feature = "oci")]
#[derive(Debug, Parser)]
struct OCIConfigOptions {
    /// Ref name (e.g. myimage:latest) or @digest (e.g. @sha256:a1b2c3...)
    config_name: OciReference,
    /// verity digest for the manifest stream to be verified against
    config_verity: Option<String>,
}

#[cfg(feature = "oci")]
#[derive(Debug, Subcommand)]
enum OciCommand {
    /// Import a tar layer as a splitstream in the repository
    ImportLayer {
        /// Layer content digest, e.g. sha256:a1b2c3...
        digest: composefs_oci::OciDigest,
        /// Optional human-readable name for the layer
        name: Option<String>,
    },
    /// List the contents of a stored tar layer
    LsLayer {
        /// Layer content digest, e.g. sha256:a1b2c3...
        name: composefs_oci::OciDigest,
    },
    /// Dump the rootfs of a stored OCI image as a composefs dumpfile to stdout
    ///
    /// The image can be specified by ref name or @digest:
    ///   cfsctl oci dump myimage:latest
    ///   cfsctl oci dump @sha256:a1b2c3...
    Dump {
        #[clap(flatten)]
        config_opts: OCIConfigFilesystemOptions,
    },
    /// Pull an OCI image into the repository
    ///
    /// Prints the config stream digest and verity of the stored manifest.
    Pull {
        /// Source image reference, as accepted by skopeo
        image: String,
        /// Tag name to assign to the pulled image (defaults to the image reference)
        name: Option<String>,
        /// Also generate a bootable EROFS image from the pulled OCI image
        #[arg(long)]
        bootable: bool,
    },
    /// List all tagged OCI images in the repository
    #[clap(name = "images")]
    ListImages {
        /// Output as JSON array
        #[clap(long)]
        json: bool,
    },
    /// Show information about an OCI image
    ///
    /// The image can be specified by ref name or @digest:
    ///   cfsctl oci inspect myimage:latest
    ///   cfsctl oci inspect @sha256:a1b2c3...
    ///
    /// By default, outputs JSON with manifest, config, and referrers.
    /// Use --manifest or --config to output just that raw JSON.
    #[clap(name = "inspect")]
    Inspect {
        /// Ref name (e.g. myimage:latest) or @digest (e.g. @sha256:a1b2c3...)
        image: OciReference,
        /// Output only the raw manifest JSON (as originally stored)
        #[clap(long, conflicts_with = "config")]
        manifest: bool,
        /// Output only the raw config JSON (as originally stored)
        #[clap(long, conflicts_with = "manifest")]
        config: bool,
    },
    /// Tag an image with a new name
    ///
    /// Example: cfsctl oci tag sha256:a1b2c3... myimage:latest
    Tag {
        /// Manifest digest, e.g. sha256:a1b2c3...
        manifest_digest: composefs_oci::OciDigest,
        /// Tag name to assign (must not contain '@')
        name: String,
    },
    /// Remove a tag from an image
    Untag {
        /// Tag name to remove
        name: String,
    },
    /// Inspect a stored layer
    ///
    /// By default, outputs the raw tar stream to stdout.
    /// Use --dumpfile for composefs dumpfile format, or --json for metadata.
    #[clap(name = "layer")]
    LayerInspect {
        /// Layer diff_id, e.g. sha256:a1b2c3...
        layer: composefs_oci::OciDigest,
        /// Output as composefs dumpfile format (one entry per line)
        #[clap(long, conflicts_with = "json")]
        dumpfile: bool,
        /// Output layer metadata as JSON
        #[clap(long, conflicts_with = "dumpfile")]
        json: bool,
    },
    /// Mount an OCI image's composefs EROFS at the given mountpoint
    Mount {
        /// Image reference (tag name or manifest digest)
        image: String,
        /// Target mountpoint
        mountpoint: String,
        /// Mount the bootable variant instead of the regular EROFS image
        #[arg(long)]
        bootable: bool,
    },
    /// Compute the composefs image ID of a stored OCI image's rootfs
    ///
    /// The image can be specified by ref name or @digest:
    ///   cfsctl oci compute-id myimage:latest
    ///   cfsctl oci compute-id @sha256:a1b2c3...
    ComputeId {
        #[clap(flatten)]
        config_opts: OCIConfigFilesystemOptions,
    },

    /// Create the composefs image of the rootfs of a stored OCI image, perform bootable transformation, commit it to the repo,
    /// then configure boot for the image by writing new boot resources and bootloader entries to boot partition. Performs
    /// state preparation for composefs-setup-root consumption as well. Note that state preparation here is not suitable for
    /// consumption by bootc.
    PrepareBoot {
        #[clap(flatten)]
        config_opts: OCIConfigOptions,
        /// boot partition mount point
        #[clap(long, default_value = "/boot")]
        bootdir: PathBuf,
        /// Boot entry identifier to use. By default uses ID provided by the image or kernel version
        #[clap(long)]
        entry_id: Option<String>,
        /// additional kernel command line
        #[clap(long)]
        cmdline: Vec<String>,
    },
    /// Check integrity of OCI images in the repository
    ///
    /// Verifies manifest and config content digests, layer references, seal
    /// consistency, and delegates to the underlying repository fsck for object
    /// integrity and splitstream validation.
    Fsck {
        /// Check only the named image instead of all tagged images
        image: Option<String>,
        /// Output results as JSON (always exits 0 unless the check itself fails)
        #[clap(long)]
        json: bool,
    },
}

/// Common options for reading a filesystem from a path
#[derive(Debug, Parser)]
struct FsReadOptions {
    /// The path to the filesystem
    path: PathBuf,
    /// Transform the filesystem for boot (SELinux labels, empty /boot and /sysroot)
    #[clap(long)]
    bootable: bool,
    /// Don't copy /usr metadata to root directory (use if root already has well-defined metadata)
    #[clap(long)]
    no_propagate_usr_to_root: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a new composefs repository with a metadata file.
    ///
    /// Creates the repository directory (if it doesn't exist) and writes
    /// a `meta.json` recording the digest algorithm.  By default fs-verity
    /// is enabled on `meta.json`, signaling that all objects require
    /// verity.  Use `--insecure` to skip (e.g. on tmpfs).
    Init {
        /// The fs-verity algorithm identifier.
        /// Format: fsverity-<hash>-<lg_blocksize>, e.g. fsverity-sha512-12
        #[clap(long, value_parser = clap::value_parser!(Algorithm), default_value = "fsverity-sha512-12")]
        algorithm: Algorithm,
        /// Path to the repository directory (created if it doesn't exist).
        /// If omitted, uses --repo/--user/--system location.
        path: Option<PathBuf>,
        /// Do not enable fs-verity on meta.json (insecure repository).
        #[clap(long)]
        insecure: bool,
        /// Migrate an old-format repository: remove streams/ and images/
        /// (which encode the algorithm) but keep objects/, then write
        /// fresh meta.json.  Streams and images will need to be
        /// re-imported after migration.
        #[clap(long)]
        reset_metadata: bool,
    },
    /// Take a transaction lock on the repository.
    /// This prevents garbage collection from occurring.
    Transaction,
    /// Reconstitutes a split stream and writes it to stdout
    Cat {
        /// the name of the stream to cat, either a content identifier or prefixed with 'ref/'
        name: String,
    },
    /// Perform garbage collection
    GC {
        /// Additional roots to keep (image or stream names)
        #[clap(long, short = 'r')]
        root: Vec<String>,
        /// Preview what would be deleted without actually deleting
        #[clap(long, short = 'n')]
        dry_run: bool,
    },
    /// Imports a composefs image (unsafe!)
    ImportImage { reference: String },
    /// Commands for dealing with OCI images and layers
    #[cfg(feature = "oci")]
    Oci {
        #[clap(subcommand)]
        cmd: OciCommand,
    },
    /// Mounts a composefs image, possibly enforcing fsverity of the image
    Mount {
        /// the name of the image to mount, either an fs-verity hash or prefixed with 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
    },
    /// Read rootfs located at a path, add all files to the repo, then create the composefs image of the rootfs,
    /// commit it to the repo, and print its image object ID
    CreateImage {
        #[clap(flatten)]
        fs_opts: FsReadOptions,
        /// optional reference name for the image, use as 'ref/<name>' elsewhere
        image_name: Option<String>,
    },
    /// Read rootfs located at a path and compute the composefs image object id of the rootfs.
    /// Note that this does not create or commit the composefs image itself, and does not
    /// store any file objects in the repository.
    ComputeId {
        #[clap(flatten)]
        fs_opts: FsReadOptions,
    },
    /// Read rootfs located at a path and dump full content of the rootfs to a composefs dumpfile,
    /// writing to stdout. Does not store any file objects in the repository.
    CreateDumpfile {
        #[clap(flatten)]
        fs_opts: FsReadOptions,
    },
    /// Lists all object IDs referenced by an image
    ImageObjects {
        /// the name of the image to read, either an object ID digest or prefixed with 'ref/'
        name: String,
    },
    /// Extract file information from a composefs image for specified files or directories
    ///
    /// By default, outputs information in composefs dumpfile format
    DumpFiles {
        /// The name of the composefs image to read from, either an object ID digest or prefixed with 'ref/'
        image_name: String,
        /// File or directory paths to process. If a path is a directory, its contents will be listed.
        files: Vec<PathBuf>,
        /// Show backing path information instead of dumpfile format
        /// For each file, prints either "inline" for files stored within the image,
        /// or a path relative to the object store for files stored extrenally
        #[clap(long)]
        backing_path_only: bool,
    },
    /// Check repository integrity
    ///
    /// Verifies fsverity digests of all objects, validates stream and image
    /// symlinks, and checks splitstream internal consistency. Exits with
    /// a non-zero status if corruption is found.
    Fsck {
        /// Output results as JSON (always exits 0 unless the check itself fails)
        #[clap(long)]
        json: bool,
    },
    #[cfg(feature = "http")]
    Fetch { url: String, name: String },
}

/// Acts as a proxy for the `cfsctl` CLI by executing the CLI logic programmatically
///
/// This function behaves the same as invoking the `cfsctl` binary from the
/// command line. It accepts an iterator of CLI-style arguments (excluding
/// the binary name), parses them using `clap`
pub async fn run_from_iter<I>(args: I) -> Result<()>
where
    I: IntoIterator,
    I::Item: Into<OsString> + Clone,
{
    let args = App::parse_from(
        std::iter::once(OsString::from("cfsctl")).chain(args.into_iter().map(Into::into)),
    );

    run_app(args).await
}

#[cfg(feature = "oci")]
fn verity_opt<ObjectID>(opt: &Option<String>) -> Result<Option<ObjectID>>
where
    ObjectID: FsVerityHashValue,
{
    Ok(match opt {
        Some(value) => Some(FsVerityHashValue::from_hex(value)?),
        None => None,
    })
}

/// Resolve the repository path from CLI args without opening it.
///
/// Uses [`user_path`] and [`system_path`] to avoid duplicating
/// path constants.
fn resolve_repo_path(args: &App) -> Result<PathBuf> {
    if let Some(path) = &args.repo {
        Ok(path.clone())
    } else if args.system {
        Ok(system_path())
    } else if args.user {
        user_path()
    } else if rustix::process::getuid().is_root() {
        Ok(system_path())
    } else {
        user_path()
    }
}

/// Determine the effective hash type for a repository.
///
/// Resolution order:
/// 1. If `meta.json` exists, use its algorithm. Error if `--hash` was
///    explicitly passed and conflicts.
/// 2. If no metadata, use `--hash` if given.
/// 3. Otherwise default to sha512.
///
/// Note: we read the metadata file directly here (rather than via
/// `Repository::metadata`) because this runs *before* we know which
/// generic `ObjectID` type to use — that's exactly what we're deciding.
fn resolve_hash_type(repo_path: &Path, cli_hash: Option<HashType>) -> Result<HashType> {
    let repo_fd = rustix::fs::open(
        repo_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening repository {}", repo_path.display()))?;

    let algorithm = read_repo_algorithm(&repo_fd)?.ok_or_else(|| {
        anyhow::anyhow!(
            "{REPO_METADATA_FILENAME} not found in {}; \
             this repository must be initialized with `cfsctl init`",
            repo_path.display(),
        )
    })?;

    let detected = match algorithm {
        Algorithm::Sha256 { .. } => HashType::Sha256,
        Algorithm::Sha512 { .. } => HashType::Sha512,
    };

    // If the user explicitly passed --hash and it doesn't match, error
    if let Some(explicit) = cli_hash
        && explicit != detected
    {
        anyhow::bail!(
            "repository is configured for {algorithm} (from {REPO_METADATA_FILENAME}) \
             but --hash {} was specified",
            match explicit {
                HashType::Sha256 => "sha256",
                HashType::Sha512 => "sha512",
            },
        );
    }

    Ok(detected)
}

/// Top-level dispatch: handle init specially, otherwise open repo and run.
pub async fn run_app(args: App) -> Result<()> {
    // Init is handled before opening a repo since it creates one
    if let Command::Init {
        ref algorithm,
        ref path,
        insecure,
        reset_metadata,
    } = args.cmd
    {
        return run_init(
            algorithm,
            path.as_deref(),
            insecure || args.insecure,
            reset_metadata,
            &args,
        );
    }

    // Commands that only need verity digests (no object storage) can
    // run without opening a repository.
    if args.no_repo
        || matches!(
            args.cmd,
            Command::ComputeId { .. } | Command::CreateDumpfile { .. }
        )
    {
        // If a repo path is available and --no-repo wasn't passed,
        // try to read the hash type from the repo's metadata so that
        // e.g. `cfsctl --repo <sha256-repo> compute-id` uses SHA-256
        // instead of the default SHA-512.
        let effective_hash = if !args.no_repo {
            if let Ok(repo_path) = resolve_repo_path(&args) {
                resolve_hash_type(&repo_path, args.hash)
                    .unwrap_or(args.hash.unwrap_or(HashType::Sha512))
            } else {
                args.hash.unwrap_or(HashType::Sha512)
            }
        } else {
            args.hash.unwrap_or(HashType::Sha512)
        };
        return match effective_hash {
            HashType::Sha256 => run_cmd_without_repo::<Sha256HashValue>(args).await,
            HashType::Sha512 => run_cmd_without_repo::<Sha512HashValue>(args).await,
        };
    }

    let repo_path = resolve_repo_path(&args)?;
    let effective_hash = resolve_hash_type(&repo_path, args.hash)?;

    match effective_hash {
        HashType::Sha256 => run_cmd_with_repo(open_repo::<Sha256HashValue>(&args)?, args).await,
        HashType::Sha512 => run_cmd_with_repo(open_repo::<Sha512HashValue>(&args)?, args).await,
    }
}

/// Handle `cfsctl init`
fn run_init(
    algorithm: &Algorithm,
    path: Option<&Path>,
    insecure: bool,
    reset_metadata: bool,
    args: &App,
) -> Result<()> {
    let repo_path = if let Some(p) = path {
        p.to_path_buf()
    } else {
        resolve_repo_path(args)?
    };

    if reset_metadata {
        composefs::repository::reset_metadata(&repo_path)?;
    }

    // Ensure parent directories exist (init_path only creates the final dir).
    if let Some(parent) = repo_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent directories for {}", repo_path.display()))?;
    }

    // init_path handles idempotency: same algorithm is a no-op,
    // different algorithm is an error.
    let created = match algorithm {
        Algorithm::Sha256 { .. } => {
            Repository::<Sha256HashValue>::init_path(CWD, &repo_path, *algorithm, !insecure)?.1
        }
        Algorithm::Sha512 { .. } => {
            Repository::<Sha512HashValue>::init_path(CWD, &repo_path, *algorithm, !insecure)?.1
        }
    };

    if created {
        println!(
            "Initialized composefs repository at {}",
            repo_path.display()
        );
        println!("  algorithm: {algorithm}");
        if insecure {
            println!("  verity:    not required (insecure)");
        } else {
            println!("  verity:    required");
        }
    } else {
        println!("Repository already initialized at {}", repo_path.display());
    }

    Ok(())
}

/// Open a repo
pub fn open_repo<ObjectID>(args: &App) -> Result<Repository<ObjectID>>
where
    ObjectID: FsVerityHashValue,
{
    let path = resolve_repo_path(args)?;
    let mut repo = Repository::open_path(CWD, path)?;
    // Hidden --insecure flag for backward compatibility; the default
    // now is to inherit the repo config, but if it's specified we
    // disable requiring verity even if the repo says to use it.
    if args.insecure {
        repo.set_insecure();
    }
    if args.require_verity {
        repo.require_verity()?;
    }
    Ok(repo)
}

/// Resolve an [`OciReference`] to an [`OciImage`].
#[cfg(feature = "oci")]
fn resolve_oci_image<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    reference: &OciReference,
) -> Result<composefs_oci::oci_image::OciImage<ObjectID>> {
    match reference {
        OciReference::Digest(digest) => {
            composefs_oci::oci_image::OciImage::open(repo, digest, None)
        }
        OciReference::Named(name) => composefs_oci::oci_image::OciImage::open_ref(repo, name),
    }
}

/// Resolve an [`OciReference`] to a config digest and optional verity.
///
/// When resolving via a named ref, the verity override is ignored since
/// the image metadata provides the correct verity.
#[cfg(feature = "oci")]
fn resolve_oci_config<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    reference: &OciReference,
    verity_override: Option<ObjectID>,
) -> Result<(composefs_oci::OciDigest, Option<ObjectID>)> {
    match reference {
        OciReference::Digest(digest) => Ok((digest.clone(), verity_override)),
        OciReference::Named(_) => {
            let img = resolve_oci_image(repo, reference)?;
            Ok((
                img.config_digest().clone(),
                Some(img.config_verity().clone()),
            ))
        }
    }
}

#[cfg(feature = "oci")]
fn load_filesystem_from_oci_image<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    opts: OCIConfigFilesystemOptions,
) -> Result<FileSystem<RegularFile<ObjectID>>> {
    let verity = verity_opt(&opts.base_config.config_verity)?;
    let (config_digest, config_verity) =
        resolve_oci_config(repo, &opts.base_config.config_name, verity)?;
    let mut fs =
        composefs_oci::image::create_filesystem(repo, &config_digest, config_verity.as_ref())?;
    if opts.bootable {
        fs.transform_for_boot(repo)?;
    }
    Ok(fs)
}

async fn load_filesystem_from_ondisk_fs<ObjectID: FsVerityHashValue>(
    fs_opts: &FsReadOptions,
    repo: Option<Arc<Repository<ObjectID>>>,
) -> Result<FileSystem<RegularFile<ObjectID>>> {
    // The async API needs an OwnedFd; fs_opts.path is typically absolute
    // so the dirfd is unused for path resolution, but required by the API.
    let dirfd = rustix::fs::openat(
        CWD,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut fs = if fs_opts.no_propagate_usr_to_root {
        composefs::fs::read_filesystem(dirfd, fs_opts.path.clone(), repo.clone()).await?
    } else {
        composefs::fs::read_container_root(dirfd, fs_opts.path.clone(), repo.clone()).await?
    };
    if fs_opts.bootable {
        if let Some(repo) = &repo {
            fs.transform_for_boot(repo)?;
        } else {
            let rootfd = rustix::fs::openat(
                CWD,
                &fs_opts.path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            fs.transform_for_boot_from_dir(rootfd)?;
        }
    }
    Ok(fs)
}

fn dump_file_impl(
    fs: FileSystem<RegularFile<impl FsVerityHashValue>>,
    files: &Vec<PathBuf>,
    backing_path_only: bool,
) -> Result<()> {
    let mut out = Vec::new();
    let nlink_map = fs.nlinks();

    for file_path in files {
        let (dir, file) = fs.root.split(file_path.as_os_str())?;

        let (_, file) = dir
            .entries()
            .find(|ent| ent.0 == file)
            .ok_or_else(|| anyhow::anyhow!("{} not found", file_path.display()))?;

        match &file {
            Inode::Directory(directory) => {
                if backing_path_only {
                    anyhow::bail!("{} is a directory", file_path.display());
                }

                dump_single_dir(&mut out, directory, &fs, &nlink_map, file_path.clone())?
            }

            Inode::Leaf(leaf_id, _) => {
                use composefs::generic_tree::LeafContent::*;
                use composefs::tree::RegularFile::*;

                if backing_path_only {
                    let leaf = fs.leaf(*leaf_id);
                    match &leaf.content {
                        Regular(f) => match f {
                            Inline(..) => println!("{} inline", file_path.display()),
                            External(id, _) => {
                                println!("{} {}", file_path.display(), id.to_object_pathname());
                            }
                        },
                        _ => {
                            println!("{} inline", file_path.display())
                        }
                    }

                    continue;
                }

                dump_single_file(&mut out, *leaf_id, &fs, &nlink_map, file_path.clone())?
            }
        };
    }

    if !out.is_empty() {
        let out_str = std::str::from_utf8(&out).unwrap();
        println!("{}", out_str);
    }

    Ok(())
}

/// Run commands that don't require a repository.
pub async fn run_cmd_without_repo<ObjectID: FsVerityHashValue>(args: App) -> Result<()> {
    match args.cmd {
        Command::ComputeId { fs_opts } => {
            let fs = load_filesystem_from_ondisk_fs::<ObjectID>(&fs_opts, None).await?;
            let id = fs.compute_image_id();
            println!("{}", id.to_hex());
        }
        Command::CreateDumpfile { fs_opts } => {
            let fs = load_filesystem_from_ondisk_fs::<ObjectID>(&fs_opts, None).await?;
            fs.print_dumpfile()?;
        }
        _ => {
            anyhow::bail!("--no-repo is only supported for compute-id and create-dumpfile");
        }
    }
    Ok(())
}

/// Run with cmd
pub async fn run_cmd_with_repo<ObjectID>(repo: Repository<ObjectID>, args: App) -> Result<()>
where
    ObjectID: FsVerityHashValue,
{
    let repo = Arc::new(repo);
    match args.cmd {
        Command::Init { .. } => {
            // Handled in run_app before we get here
            unreachable!("init is handled before opening a repository");
        }
        Command::Transaction => {
            // just wait for ^C
            loop {
                std::thread::park();
            }
        }
        Command::Cat { name } => {
            repo.merge_splitstream(&name, None, None, &mut std::io::stdout())?;
        }
        Command::ImportImage { reference } => {
            let image_id = repo.import_image(&reference, &mut std::io::stdin())?;
            println!("{}", image_id.to_id());
        }
        #[cfg(feature = "oci")]
        Command::Oci { cmd: oci_cmd } => match oci_cmd {
            OciCommand::ImportLayer { name, ref digest } => {
                let (object_id, _stats) = composefs_oci::import_layer(
                    &repo,
                    digest,
                    name.as_deref(),
                    tokio::io::BufReader::with_capacity(IO_BUF_CAPACITY, tokio::io::stdin()),
                )
                .await?;
                println!("{}", object_id.to_id());
            }
            OciCommand::LsLayer { ref name } => {
                composefs_oci::ls_layer(&repo, name)?;
            }
            OciCommand::Dump { config_opts } => {
                let fs = load_filesystem_from_oci_image(&repo, config_opts)?;
                fs.print_dumpfile()?;
            }
            OciCommand::Mount {
                ref image,
                ref mountpoint,
                bootable,
            } => {
                let img = if image.starts_with("sha256:") {
                    let digest: composefs_oci::OciDigest =
                        image.parse().context("Parsing manifest digest")?;
                    composefs_oci::oci_image::OciImage::open(&repo, &digest, None)?
                } else {
                    composefs_oci::oci_image::OciImage::open_ref(&repo, image)?
                };
                let erofs_id = if bootable {
                    match img.boot_image_ref() {
                        Some(id) => id,
                        None => anyhow::bail!(
                            "No boot EROFS image linked — try pulling with --bootable"
                        ),
                    }
                } else {
                    match img.image_ref() {
                        Some(id) => id,
                        None => anyhow::bail!(
                            "No composefs EROFS image linked — try re-pulling the image"
                        ),
                    }
                };
                repo.mount_at(&erofs_id.to_hex(), mountpoint.as_str())?;
            }
            OciCommand::ComputeId { config_opts } => {
                let fs = load_filesystem_from_oci_image(&repo, config_opts)?;
                let id = fs.compute_image_id();
                println!("{}", id.to_hex());
            }
            OciCommand::Pull {
                ref image,
                name,
                bootable,
            } => {
                // If no explicit name provided, use the image reference as the tag
                let tag_name = name.as_deref().unwrap_or(image);

                let result =
                    composefs_oci::pull(&repo, image, Some(tag_name), Default::default()).await?;

                println!("manifest {}", result.manifest_digest);
                println!("config   {}", result.config_digest);
                println!("verity   {}", result.manifest_verity.to_hex());
                println!("tagged   {tag_name}");
                println!("objects  {}", result.stats);

                if bootable {
                    let image_verity =
                        composefs_oci::generate_boot_image(&repo, &result.manifest_digest)?;
                    println!("Boot image: {}", image_verity.to_hex());
                }
            }
            OciCommand::ListImages { json } => {
                let images = composefs_oci::oci_image::list_images(&repo)?;

                if json {
                    println!("{}", serde_json::to_string_pretty(&images)?);
                } else if images.is_empty() {
                    println!("No images found");
                } else {
                    let mut table = Table::new();
                    table.load_preset(UTF8_FULL);
                    table.set_header(["NAME", "DIGEST", "ARCH", "LAYERS", "REFS"]);

                    for img in images {
                        let digest_str: &str = img.manifest_digest.as_ref();
                        let digest_short = digest_str.strip_prefix("sha256:").unwrap_or(digest_str);
                        let digest_display = if digest_short.len() > 12 {
                            &digest_short[..12]
                        } else {
                            digest_short
                        };
                        let arch = if img.architecture.is_empty() {
                            "artifact"
                        } else {
                            &img.architecture
                        };
                        table.add_row([
                            img.name.as_str(),
                            digest_display,
                            arch,
                            &img.layer_count.to_string(),
                            &img.referrer_count.to_string(),
                        ]);
                    }
                    println!("{table}");
                }
            }
            OciCommand::Inspect {
                ref image,
                manifest,
                config,
            } => {
                let img = resolve_oci_image(&repo, image)?;

                if manifest {
                    // Output raw manifest JSON exactly as stored
                    let manifest_json = img.read_manifest_json(&repo)?;
                    std::io::Write::write_all(&mut std::io::stdout(), &manifest_json)?;
                    println!();
                } else if config {
                    // Output raw config JSON exactly as stored
                    let config_json = img.read_config_json(&repo)?;
                    std::io::Write::write_all(&mut std::io::stdout(), &config_json)?;
                    println!();
                } else {
                    // Default: output combined JSON with manifest, config, and referrers
                    let output = img.inspect_json(&repo)?;
                    println!("{}", serde_json::to_string_pretty(&output)?);
                }
            }
            OciCommand::Tag {
                ref manifest_digest,
                ref name,
            } => {
                composefs_oci::oci_image::tag_image(&repo, manifest_digest, name)?;
                println!("Tagged {manifest_digest} as {name}");
            }
            OciCommand::Untag { ref name } => {
                composefs_oci::oci_image::untag_image(&repo, name)?;
                println!("Removed tag {name}");
            }
            OciCommand::LayerInspect {
                ref layer,
                dumpfile,
                json,
            } => {
                if json {
                    let info = composefs_oci::layer_info(&repo, layer)?;
                    println!("{}", serde_json::to_string_pretty(&info)?);
                } else if dumpfile {
                    composefs_oci::layer_dumpfile(&repo, layer, &mut std::io::stdout())?;
                } else {
                    // Default: output raw tar, but not to a tty
                    let mut out = std::io::stdout().lock();
                    if out.is_terminal() {
                        anyhow::bail!(
                            "Refusing to write tar data to terminal. \
                            Redirect to a file, pipe to tar, or use --json for metadata."
                        );
                    }
                    composefs_oci::layer_tar(&repo, layer, &mut out)?;
                }
            }

            OciCommand::PrepareBoot {
                config_opts:
                    OCIConfigOptions {
                        ref config_name,
                        ref config_verity,
                    },
                ref bootdir,
                ref entry_id,
                ref cmdline,
            } => {
                let verity = verity_opt(config_verity)?;
                let (config_digest, config_verity) =
                    resolve_oci_config(&repo, config_name, verity)?;
                let mut fs = composefs_oci::image::create_filesystem(
                    &repo,
                    &config_digest,
                    config_verity.as_ref(),
                )?;
                let entries = fs.transform_for_boot(&repo)?;
                let id = fs.commit_image(&repo, None)?;

                let Some(entry) = entries.into_iter().next() else {
                    anyhow::bail!("No boot entries!");
                };

                let cmdline_refs: Vec<&str> = cmdline.iter().map(String::as_str).collect();
                write_boot::write_boot_simple(
                    &repo,
                    entry,
                    &id,
                    repo.is_insecure(),
                    bootdir,
                    None,
                    entry_id.as_deref(),
                    &cmdline_refs,
                )?;

                let state = args
                    .repo
                    .as_ref()
                    .map(|p: &PathBuf| p.parent().unwrap())
                    .unwrap_or(Path::new("/sysroot"))
                    .join("state/deploy")
                    .join(id.to_hex());

                create_dir_all(state.join("var"))?;
                create_dir_all(state.join("etc/upper"))?;
                create_dir_all(state.join("etc/work"))?;
            }
            OciCommand::Fsck { image, json } => {
                let result = if let Some(ref name) = image {
                    composefs_oci::oci_fsck_image(&repo, name).await?
                } else {
                    composefs_oci::oci_fsck(&repo).await?
                };
                if json {
                    let output = OciFsckJsonOutput {
                        ok: result.is_ok(),
                        result,
                    };
                    serde_json::to_writer_pretty(std::io::stdout().lock(), &output)?;
                    println!();
                } else {
                    print!("{result}");
                    if !result.is_ok() {
                        anyhow::bail!("OCI integrity check failed");
                    }
                }
            }
        },
        Command::CreateImage {
            fs_opts,
            ref image_name,
        } => {
            let fs = load_filesystem_from_ondisk_fs(&fs_opts, Some(Arc::clone(&repo))).await?;
            let id = fs.commit_image(&repo, image_name.as_deref())?;
            println!("{}", id.to_id());
        }
        Command::ComputeId { .. } | Command::CreateDumpfile { .. } => {
            // Handled in run_app before opening the repo
            unreachable!("compute-id and create-dumpfile are dispatched without a repo");
        }
        Command::Mount { name, mountpoint } => {
            repo.mount_at(&name, &mountpoint)?;
        }
        Command::ImageObjects { name } => {
            let objects = repo.objects_for_image(&name)?;
            for object in objects {
                println!("{}", object.to_id());
            }
        }
        Command::GC { root, dry_run } => {
            let roots: Vec<&str> = root.iter().map(|s| s.as_str()).collect();
            let result = if dry_run {
                repo.gc_dry_run(&roots)?
            } else {
                repo.gc(&roots)?
            };
            if dry_run {
                println!("Dry run (no files deleted):");
            }
            println!(
                "Objects: {} removed ({} bytes)",
                result.objects_removed, result.objects_bytes
            );
            if result.images_pruned > 0 || result.streams_pruned > 0 {
                println!(
                    "Pruned symlinks: {} images, {} streams",
                    result.images_pruned, result.streams_pruned
                );
            }
        }
        Command::DumpFiles {
            image_name,
            files,
            backing_path_only,
        } => {
            let (img_fd, _) = repo.open_image(&image_name)?;

            let mut img_buf = Vec::new();
            std::fs::File::from(img_fd).read_to_end(&mut img_buf)?;

            dump_file_impl(
                erofs_to_filesystem::<ObjectID>(&img_buf)?,
                &files,
                backing_path_only,
            )?;
        }
        Command::Fsck { json } => {
            let result = repo.fsck().await?;
            if json {
                let output = FsckJsonOutput {
                    ok: result.is_ok(),
                    result,
                };
                serde_json::to_writer_pretty(std::io::stdout().lock(), &output)?;
                println!();
            } else {
                print!("{result}");
                if !result.is_ok() {
                    anyhow::bail!("repository integrity check failed");
                }
            }
        }
        #[cfg(feature = "http")]
        Command::Fetch { url, name } => {
            let (digest, verity) = composefs_http::download(&url, &name, Arc::clone(&repo)).await?;
            println!("content {digest}");
            println!("verity {}", verity.to_hex());
        }
    }
    Ok(())
}
