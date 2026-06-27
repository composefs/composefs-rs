//! Library for `cfsctl` command line utility
//!
//! This crate also re-exports all composefs-rs library crates, so downstream
//! consumers can take a single dependency on `cfsctl` instead of listing each
//! crate individually.
//!
//! ```
//! use composefs_ctl::composefs::repository::Repository;
//! use composefs_ctl::composefs::fsverity::Sha256HashValue;
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

pub mod composefs_info;
pub mod mkcomposefs;
pub mod mountcomposefs;
#[cfg(feature = "oci")]
mod oci_run;
/// Varlink RPC service exposing repository operations over a Unix socket.
pub mod varlink;

#[cfg(any(feature = "oci", feature = "http"))]
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
#[cfg(any(feature = "oci", feature = "http"))]
use std::sync::Mutex;
use std::{ffi::OsString, path::PathBuf};

#[cfg(feature = "oci")]
use std::{fs::create_dir_all, io::IsTerminal};

use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand, ValueEnum};
#[cfg(any(feature = "oci", feature = "ostree"))]
use comfy_table::{Table, presets::UTF8_FULL};
#[cfg(any(feature = "oci", feature = "http"))]
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rustix::fs::{CWD, Mode, OFlags};

#[cfg(any(feature = "oci", feature = "http"))]
use composefs::progress::{
    ComponentId, ProgressEvent, ProgressReporter, ProgressUnit, SharedReporter,
};
use composefs_boot::BootOps;
use composefs_boot::cmdline::ComposefsCmdline;
#[cfg(feature = "oci")]
use composefs_boot::write_boot;

#[cfg(feature = "oci")]
use composefs::shared_internals::IO_BUF_CAPACITY;
use composefs::{
    dumpfile::{dump_single_dir, dump_single_file},
    erofs::{
        format::{FormatConfig, FormatVersion},
        reader::erofs_to_filesystem,
    },
    fsverity::{Algorithm, FsVerityHashValue, Sha256HashValue, Sha512HashValue},
    generic_tree::{FileSystem, Inode},
    mount::MountOptions,
    repository::{
        REPO_METADATA_FILENAME, Repository, RepositoryConfig, read_repo_algorithm, system_path,
        user_path,
    },
    tree::RegularFile,
};

/// An `indicatif`-backed [`ProgressReporter`] for use in the CLI.
///
/// Renders per-component progress bars via [`MultiProgress`].  When a component
/// completes or is skipped the bar is removed; human-readable messages are
/// printed above the bar group via [`MultiProgress::println`].
#[cfg(any(feature = "oci", feature = "http"))]
struct IndicatifReporter {
    multi: MultiProgress,
    bars: Mutex<HashMap<ComponentId, ProgressBar>>,
}

#[cfg(any(feature = "oci", feature = "http"))]
impl IndicatifReporter {
    fn new() -> Self {
        IndicatifReporter {
            multi: MultiProgress::new(),
            bars: Mutex::new(HashMap::new()),
        }
    }

    /// Build a shared reporter from this instance.
    fn into_shared(self) -> SharedReporter {
        Arc::new(self)
    }
}

#[cfg(any(feature = "oci", feature = "http"))]
impl std::fmt::Debug for IndicatifReporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndicatifReporter").finish_non_exhaustive()
    }
}

#[cfg(any(feature = "oci", feature = "http"))]
impl ProgressReporter for IndicatifReporter {
    fn report(&self, event: ProgressEvent) {
        match event {
            ProgressEvent::Started { id, total, unit } => {
                let bar = if let Some(total) = total {
                    self.multi.add(ProgressBar::new(total))
                } else {
                    self.multi.add(ProgressBar::new_spinner())
                };
                let style = match unit {
                    ProgressUnit::Bytes => ProgressStyle::with_template(
                        "[eta {eta}] {bar:40.cyan/blue} {decimal_bytes:>7}/{decimal_total_bytes:7} {msg}",
                    ),
                    ProgressUnit::Items => ProgressStyle::with_template(
                        "[eta {eta}] {bar:40.cyan/blue} {pos:>7}/{len:7} objects {msg}",
                    ),
                    // Future unit variants fall back to a generic spinner.
                    _ => ProgressStyle::with_template(
                        "[eta {eta}] {bar:40.cyan/blue} {pos}/{len} {msg}",
                    ),
                };
                bar.set_style(
                    style
                        .unwrap_or_else(|_| ProgressStyle::default_bar())
                        .progress_chars("##-"),
                );
                bar.set_message(id.to_string());
                self.bars.lock().unwrap().insert(id, bar);
            }
            ProgressEvent::Progress { id, fetched, .. } => {
                if let Some(bar) = self.bars.lock().unwrap().get(&id) {
                    bar.set_position(fetched);
                }
            }
            ProgressEvent::Done { id, .. } => {
                if let Some(bar) = self.bars.lock().unwrap().remove(&id) {
                    bar.finish_and_clear();
                }
            }
            ProgressEvent::Skipped { id } => {
                if let Some(bar) = self.bars.lock().unwrap().remove(&id) {
                    bar.finish_with_message("skipped");
                }
            }
            ProgressEvent::Message(msg) => {
                let _ = self.multi.println(msg);
            }
            // `ProgressEvent` is #[non_exhaustive]: new variants added to the library
            // will be silently ignored here until cfsctl is updated to handle them.
            _ => {}
        }
    }
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

    /// The EROFS format version to use when generating images.
    /// If omitted, the library default (V2) is used.
    #[clap(long, value_enum)]
    pub erofs_version: Option<ErofsVersion>,

    /// Deprecated: security mode is now auto-detected from meta.json.
    /// Use `cfsctl init --insecure` to create a repo without verity.
    /// Kept for backward compatibility.
    #[clap(long, hide = true)]
    insecure: bool,

    /// Error if the repository does not have fs-verity enabled.
    #[clap(long)]
    require_verity: bool,

    /// Don't automatically upgrade old-format repositories.
    /// When set, commands will fail on repos without meta.json instead
    /// of inferring metadata from existing objects.
    #[clap(long)]
    no_upgrade: bool,

    /// Don't open a repository. Only valid for commands that don't need one
    /// (compute-id, create-dumpfile).
    #[clap(long)]
    pub no_repo: bool,

    // TODO: Add a `--verbose` flag to control debug output. Currently,
    // errors like "Layer has incorrect checksum" give no context about
    // which layer failed or what the expected vs actual digests were.
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

/// The EROFS format version used when generating images.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum ErofsVersion {
    /// Format V1: compact inodes, BFS, C-compatible.
    #[clap(name = "1")]
    V1,
    /// Format V2: extended inodes, DFS, current default.
    #[clap(name = "2")]
    V2,
}

impl From<ErofsVersion> for composefs::erofs::format::FormatVersion {
    fn from(v: ErofsVersion) -> Self {
        match v {
            ErofsVersion::V1 => Self::V1,
            ErofsVersion::V2 => Self::V2,
        }
    }
}

/// EROFS format generation mode for `cfsctl init --erofs`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum ErofsMode {
    /// Generate only V1 EROFS (default; compatible with C `mkcomposefs`/`composefs-info` 1.0.8).
    V1,
    /// Generate both V1 and V2 EROFS (dual mode, used by bootc and other multi-format consumers).
    Dual,
}

impl From<ErofsMode> for FormatConfig {
    fn from(m: ErofsMode) -> Self {
        match m {
            ErofsMode::V1 => FormatConfig::single(FormatVersion::V1),
            ErofsMode::Dual => FormatConfig {
                default: FormatVersion::V1,
                extra: [FormatVersion::V2].into(),
            },
        }
    }
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

/// CLI representation of [`composefs_oci::LocalFetchOpt`].
#[cfg(feature = "oci")]
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
enum LocalFetchCli {
    /// Do not use native containers-storage import; use skopeo.
    #[default]
    Disabled,
    /// Use native import with reflink/hardlink/copy fallback.
    Auto,
    /// Use native import; error if zero-copy is not possible.
    Zerocopy,
}

#[cfg(feature = "oci")]
impl From<LocalFetchCli> for composefs_oci::LocalFetchOpt {
    fn from(cli: LocalFetchCli) -> Self {
        match cli {
            LocalFetchCli::Disabled => Self::Disabled,
            LocalFetchCli::Auto => Self::IfPossible,
            LocalFetchCli::Zerocopy => Self::ZeroCopy,
        }
    }
}

/// Options accepted by `--fuse[=<opts>]` on `oci mount`.
///
/// Pass bare `--fuse` to FUSE-mount with defaults, or `--fuse=passthrough`
/// to also enable kernel-bypass reads for external files.
///
/// Multiple options are comma-separated: `--fuse=passthrough,option2`
/// (only `passthrough` is defined today).
#[derive(Debug, Default, Clone)]
struct FuseOptions {
    passthrough: bool,
}

impl std::str::FromStr for FuseOptions {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut opts = FuseOptions::default();
        for token in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            match token {
                "passthrough" => opts.passthrough = true,
                other => anyhow::bail!("unknown fuse option: {other:?} (known: passthrough)"),
            }
        }
        Ok(opts)
    }
}

/// Pull policy for `cfsctl oci run`.
#[cfg(feature = "oci")]
#[derive(Clone, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
enum PullPolicy {
    /// Always pull the image, even if it already exists locally.
    Always,
    /// Pull only if the image is not already present.
    #[default]
    Missing,
    /// Never pull; fail if the image is not present.
    Never,
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

// TODO: Inconsistent argument naming across OCI subcommands. Some use
// `image: String` (Seal, Sign, Verify, Push), some `name: String` (Mount,
// LsLayer), and others use `config_name` via OCIConfigOptions (Dump,
// CreateImage). They also differ in whether they accept tag names,
// manifest digests, or both. Standardize on a consistent convention.
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
        /// Controls whether containers-storage: references use the native
        /// import path with zero-copy reflink/hardlink support.
        #[arg(long, value_enum, default_value_t = LocalFetchCli::Disabled)]
        local_fetch: LocalFetchCli,
        /// Require a valid signature artifact for the pulled image
        #[clap(long)]
        require_signature: bool,
        /// Path to PEM-encoded trusted certificate for signature verification
        #[clap(long)]
        trust_cert: Option<PathBuf>,
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
        /// Writable upper layer directory for overlayfs
        #[arg(long, requires = "workdir")]
        upperdir: Option<PathBuf>,
        /// Work directory for overlayfs (required with --upperdir)
        #[arg(long, requires = "upperdir")]
        workdir: Option<PathBuf>,
        /// Mount read-write (requires --upperdir)
        #[arg(long, requires = "upperdir")]
        read_write: bool,
        /// Serve the EROFS image over FUSE instead of using a kernel composefs mount.
        /// Requires /dev/fuse and blocks until the mount is detached or the process
        /// is killed. Does not require fs-verity on the backing store.
        ///
        /// Accepts an optional comma-separated list of options:
        ///   --fuse              basic FUSE mount
        ///   --fuse=passthrough  also enable kernel-bypass reads (Linux 6.9+, root, non-tmpfs)
        #[cfg_attr(not(feature = "fuse"), arg(hide = true))]
        #[arg(long, num_args = 0..=1, require_equals = false, value_name = "OPTS",
              default_missing_value = "")]
        fuse: Option<FuseOptions>,
        /// Require a valid signature artifact for the image before mounting
        #[clap(long)]
        require_signature: bool,
        /// Path to PEM-encoded trusted certificate for signature verification
        #[clap(long)]
        trust_cert: Option<PathBuf>,
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
    /// Seal a stored OCI image by creating a cloned manifest with embedded verity digest (a.k.a. composefs image object ID)
    /// in the repo, then prints the stream and verity digest of the new sealed manifest
    Seal {
        /// Image reference (tag name or manifest digest)
        image: String,
    },

    /// Compute the composefs boot image karg for a stored OCI image.
    ///
    /// Applies the bootable transformation (SELinux relabeling, empty /boot and /sysroot),
    /// computes the V1 EROFS digest, and prints the full kernel argument string:
    ///
    ///   composefs.digest=<hex>
    ///
    /// This is intended for use in UKI Containerfile builds where no composefs
    /// repository is available.  The output can be written directly to
    /// /etc/kernel/cmdline:
    ///
    ///   cfsctl oci composefs-digest-karg @sha256:abc... > /etc/kernel/cmdline
    ///
    /// The image can be specified by ref name or @digest:
    ///   cfsctl oci composefs-digest-karg myimage:latest
    ///   cfsctl oci composefs-digest-karg @sha256:a1b2c3...
    #[clap(name = "composefs-digest-karg")]
    ComposefsDigestKarg {
        #[clap(flatten)]
        config_opts: OCIConfigOptions,
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
    /// Create a composefs PKCS#7 signature artifact for an image
    Sign {
        /// Image reference (tag name)
        image: String,
        /// Path to PEM-encoded signing certificate
        #[clap(long)]
        cert: PathBuf,
        /// Path to PEM-encoded private key
        #[clap(long)]
        key: PathBuf,
    },
    /// Verify composefs signature artifacts for an image
    Verify {
        /// Image reference (tag name)
        image: String,
        /// Path to PEM-encoded trusted certificate for verification
        #[clap(long)]
        cert: Option<PathBuf>,
    },
    /// Export an OCI image to an OCI layout directory
    Push {
        /// Image reference (tag name)
        image: String,
        /// Destination OCI layout path (optionally prefixed with oci:)
        destination: String,
        /// Also export signature/composefs artifacts
        #[clap(long)]
        signatures: bool,
    },
    /// Export signature artifacts for an image to an OCI layout directory
    ExportSignatures {
        /// Image reference (tag name)
        image: String,
        /// Path to the OCI layout directory (must already exist)
        oci_layout_path: PathBuf,
    },
    /// Run a container with composefs integrity enforcement
    ///
    /// Pulls the image if missing (unless --pull=never), optionally verifies
    /// a PKCS#7 signature, mounts the composefs EROFS overlay, generates an
    /// OCI runtime bundle, and execs into crun (or --runtime).
    Run {
        /// Image reference (tag name or manifest digest)
        image: String,
        /// Container name (defaults to the image tag component)
        #[arg(long)]
        name: Option<String>,
        /// Verify a PKCS#7 signature before running
        #[arg(long)]
        require_signature: bool,
        /// Path to PEM-encoded trusted certificate for signature verification
        #[arg(long)]
        trust_cert: Option<PathBuf>,
        /// When to pull the image
        #[arg(long, value_enum, default_value = "missing")]
        pull: PullPolicy,
        /// OCI runtime binary (default: search PATH for crun, then runc)
        #[arg(long)]
        runtime: Option<PathBuf>,
        /// Additional environment variables (KEY=VALUE)
        #[arg(long = "env", short = 'e')]
        envs: Vec<String>,
        /// Network mode
        #[arg(long, value_enum, default_value = "host")]
        network: oci_run::NetworkMode,
        /// Bind mounts in src:dst[:ro] form
        #[arg(long = "volume", short = 'v')]
        volumes: Vec<String>,
        /// Remove the bundle directory after the container exits
        #[arg(long, default_value = "true")]
        rm: bool,
        /// Override the bundle directory (default: /run/cfsctl/<name>)
        #[arg(long)]
        bundle_dir: Option<PathBuf>,
        /// Command override (arguments after --)
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Stop a running container and clean up its composefs mount
    Stop {
        /// Container name
        name: String,
        /// Override the bundle directory (default: /run/cfsctl/<name>)
        #[arg(long)]
        bundle_dir: Option<PathBuf>,
    },
    /// Serve the varlink RPC API (alias: same service as top-level `varlink`).
    ///
    /// Kept for discoverability under the `oci` subcommand.
    Varlink {
        /// Unix socket path to listen on (omit when using systemd socket activation).
        #[clap(long)]
        address: Option<PathBuf>,
    },
}

#[cfg(feature = "ostree")]
#[derive(Debug, Subcommand)]
enum OstreeCommand {
    PullLocal {
        ostree_repo_path: PathBuf,
        /// Ostree ref name or commit ID (64-character hex)
        ostree_ref: String,
        #[clap(long)]
        base_name: Option<String>,
    },
    Pull {
        ostree_repo_url: String,
        /// Ostree ref name or commit ID (64-character hex)
        ostree_ref: String,
        #[clap(long)]
        base_name: Option<String>,
    },
    /// Mount an ostree commit's composefs EROFS at the given mountpoint
    Mount {
        /// Ostree commit ref or commit ID
        commit: String,
        /// Target mountpoint
        mountpoint: String,
        /// Writable upper layer directory for overlayfs
        #[arg(long, requires = "workdir")]
        upperdir: Option<PathBuf>,
        /// Work directory for overlayfs (required with --upperdir)
        #[arg(long, requires = "upperdir")]
        workdir: Option<PathBuf>,
        /// Mount read-write (requires --upperdir)
        #[arg(long, requires = "upperdir")]
        read_write: bool,
    },
    /// Dump the filesystem of an ostree commit as a composefs dumpfile to stdout
    Dump {
        /// Ostree commit ref name
        commit_name: String,
    },
    /// Compute the composefs image ID of an ostree commit
    ComputeId {
        /// Ostree commit ref name
        commit_name: String,
    },
    /// Show the contents of an ostree commit
    Inspect {
        /// Ostree ref name, commit ID, or commit ID prefix
        source: String,
        /// Print only the commit metadata key-value pairs
        #[clap(long)]
        metadata: bool,
    },
    /// Tag an ostree commit with a name
    ///
    /// The source can be an ostree commit checksum or an existing ref name.
    Tag {
        /// Ostree commit checksum (hex) or existing ref name
        source: String,
        /// Tag name to assign
        name: String,
    },
    /// Remove a named ostree reference
    Untag {
        /// Tag name to remove
        name: String,
    },
    /// List all ostree commits in the repository
    #[clap(name = "images")]
    ListCommits,
}

#[cfg(feature = "rhel9")]
#[derive(Debug, Subcommand)]
enum KeyringCommand {
    /// Add a CA certificate to the kernel's .fs-verity keyring.
    /// Requires CAP_SYS_ADMIN (root).
    AddCert {
        /// Path to a PEM-encoded X.509 certificate file
        cert: PathBuf,
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
        /// Default EROFS format version for images in this repository.
        /// V1 is compatible with C `mkcomposefs` 1.0.8.
        /// If omitted, falls back to the global `--erofs-version` flag, then defaults to V2.
        #[clap(long)]
        erofs_version: Option<ErofsVersion>,
        /// EROFS format generation mode.
        ///
        /// Controls which EROFS format versions are produced when committing images:
        ///   v1    Generate only V1 EROFS (default; C-tool compatible)
        ///   dual  Generate both V1 and V2 EROFS (used by bootc)
        ///
        /// If omitted, defaults to `v1`.
        #[clap(long, value_enum)]
        erofs: Option<ErofsMode>,
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
    #[cfg(feature = "ostree")]
    Ostree {
        #[clap(subcommand)]
        cmd: OstreeCommand,
    },
    /// Mounts a composefs image, possibly enforcing fsverity of the image
    Mount {
        /// the name of the image to mount, either an fs-verity hash or prefixed with 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
        /// Writable upper layer directory for overlayfs
        #[arg(long, requires = "workdir")]
        upperdir: Option<PathBuf>,
        /// Work directory for overlayfs (required with --upperdir)
        #[arg(long, requires = "upperdir")]
        workdir: Option<PathBuf>,
        /// Mount read-write (requires --upperdir)
        #[arg(long, requires = "upperdir")]
        read_write: bool,
    },
    /// Serve an EROFS composefs image over FUSE at the given mountpoint.
    ///
    /// Reads the EROFS image, opens /dev/fuse, mounts and attaches the
    /// FUSE filesystem at `<mountpoint>`, then blocks serving requests
    /// until killed or unmounted. External file objects are resolved
    /// via the repository given by `--repo`.
    #[cfg(feature = "fuse")]
    FuseServe {
        /// Path to the EROFS composefs image file.
        image: PathBuf,
        /// Directory to attach the FUSE mount at (must already exist).
        mountpoint: PathBuf,
        /// Enable FUSE passthrough for external files (Linux 6.9+;
        /// requires root and a non-tmpfs backing filesystem).
        #[clap(long)]
        passthrough: bool,
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
    /// Read rootfs located at a path and compute the composefs kernel argument string.
    ///
    /// Like compute-id but outputs the full kernel argument rather than the bare digest,
    /// choosing the argument name based on the EROFS format version:
    ///
    ///   V1: composefs.digest=v1-sha256-12:<hex>
    ///   V2: composefs=<hex>
    ///
    /// Use --erofs-version to select the format.
    /// The boot transformation (SELinux relabeling, empty /boot and /sysroot) is
    /// always applied — this command produces a karg for a sealed boot image.
    ///
    /// Example (in a Containerfile):
    ///   cfsctl --erofs-version 1 compute-karg /mnt/base > /etc/kernel/cmdline
    #[clap(name = "compute-karg")]
    ComputeKarg {
        /// The path to the filesystem
        path: PathBuf,
        /// Don't copy /usr metadata to root directory (use if root already has well-defined metadata)
        #[clap(long)]
        no_propagate_usr_to_root: bool,
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
    #[cfg(feature = "rhel9")]
    /// Commands for managing the kernel keyring (requires root)
    Keyring {
        #[clap(subcommand)]
        cmd: KeyringCommand,
    },
    #[cfg(feature = "http")]
    Fetch { url: String, name: String },
    /// Serve the varlink RPC API on a Unix socket or systemd socket.
    ///
    /// A single service answers both the `org.composefs.Repository` and (when
    /// the `oci` feature is enabled) `org.composefs.Oci` interfaces on one
    /// socket.
    Varlink {
        /// Unix socket path to listen on (omit when using systemd socket activation).
        #[clap(long)]
        address: Option<PathBuf>,
    },

    /// Run mkcomposefs (C-compatible image builder); hidden, also available via argv0 dispatch.
    #[clap(hide = true, name = "mkcomposefs")]
    Mkcomposefs {
        /// Arguments forwarded verbatim to mkcomposefs
        #[clap(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<std::ffi::OsString>,
    },

    /// Run composefs-info (C-compatible image inspector); hidden, also available via argv0 dispatch.
    #[clap(hide = true, name = "composefs-info")]
    ComposefsInfo {
        /// Arguments forwarded verbatim to composefs-info
        #[clap(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<std::ffi::OsString>,
    },
}

#[cfg(feature = "rhel9")]
fn run_keyring_cmd(cmd: &KeyringCommand) -> Result<()> {
    match cmd {
        // TODO: Check for CAP_SYS_ADMIN before attempting to inject
        // the certificate. Currently the kernel returns an opaque error.
        // A clear "keyring add-cert requires root privileges" message
        // would be much more helpful.
        KeyringCommand::AddCert { cert } => {
            let cert_pem = std::fs::read(cert).context("failed to read certificate file")?;
            composefs::fsverity::inject_fsverity_cert(&cert_pem)?;
            println!("Certificate added to .fs-verity keyring");
        }
    }
    Ok(())
}

/// Run the CLI using `std::env::args()`, as if invoked from the command line.
pub async fn run_from_args() -> Result<()> {
    run_app(App::parse()).await
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

fn get_mount_options(
    upperdir: Option<&Path>,
    workdir: Option<&Path>,
    read_write: bool,
) -> Result<MountOptions> {
    let mut options = MountOptions::default();
    if let (Some(u), Some(w)) = (upperdir, workdir) {
        let upper_fd = rustix::fs::open(
            u,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Opening upperdir '{}'", u.display()))?;
        let work_fd = rustix::fs::open(
            w,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Opening workdir '{}'", w.display()))?;
        options.set_overlay(upper_fd, work_fd);
    }
    options.set_read_write(read_write);
    Ok(options)
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
/// 2. If no metadata and `upgrade` is true, infer from existing objects.
/// 3. If no metadata and `upgrade` is false, error.
///
/// Note: we read the metadata file directly here (rather than via
/// `Repository::metadata`) because this runs *before* we know which
/// generic `ObjectID` type to use — that's exactly what we're deciding.
fn resolve_hash_type(
    repo_path: &Path,
    cli_hash: Option<HashType>,
    upgrade: bool,
) -> Result<HashType> {
    let repo_fd = rustix::fs::open(
        repo_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening repository {}", repo_path.display()))?;

    let algorithm = match read_repo_algorithm(&repo_fd)? {
        Some(alg) => alg,
        None if upgrade => {
            // No meta.json — try to infer from objects (old-format repo).
            // open_upgrade will write meta.json later when the repo is opened.
            composefs::repository::infer_repo_algorithm(&repo_fd).with_context(|| {
                format!(
                    "no {REPO_METADATA_FILENAME} in {}; tried to infer algorithm from objects",
                    repo_path.display(),
                )
            })?
        }
        None => {
            anyhow::bail!(
                "{REPO_METADATA_FILENAME} not found in {}; \
                 this repository must be initialized with `cfsctl init`",
                repo_path.display(),
            );
        }
    };

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

/// If this process was launched via systemd socket activation with no arguments,
/// serve the varlink API on the activated socket and return `true`.
/// Otherwise return `false` (the caller should proceed with normal CLI parsing).
pub async fn run_if_socket_activated() -> Result<bool> {
    // Only take the pre-clap shortcut for a bare invocation (`argv[0]` only).
    // Check argv before touching the activation env so the latter is consumed
    // only when we actually intend to serve from this shortcut.
    if std::env::args_os().len() != 1 {
        return Ok(false);
    }
    let Some(listener) = crate::varlink::try_activated_listener()? else {
        return Ok(false);
    };
    let service = crate::varlink::CfsctlService::activated();
    crate::varlink::serve_activated(service, listener).await?;
    Ok(true)
}

/// Top-level dispatch: handle init and keyring specially, otherwise open repo and run.
pub async fn run_app(args: App) -> Result<()> {
    // Hidden compat subcommands: forward all trailing args to the respective tool.
    if let Command::Mkcomposefs { args: extra } = args.cmd {
        return mkcomposefs::run_from_args(extra);
    }
    if let Command::ComposefsInfo { args: extra } = args.cmd {
        return composefs_info::run_from_args(extra);
    }

    // Handle commands that don't need a repository first
    #[cfg(feature = "rhel9")]
    if let Command::Keyring { ref cmd } = args.cmd {
        return run_keyring_cmd(cmd);
    }

    // Init is handled before opening a repo since it creates one
    if let Command::Init {
        ref algorithm,
        ref path,
        insecure,
        reset_metadata,
        erofs_version: ref init_erofs_version,
        erofs: init_erofs,
    } = args.cmd
    {
        // --erofs controls the FormatConfig (which versions to generate); default V2-only.
        let erofs_formats = init_erofs
            .map(FormatConfig::from)
            .unwrap_or(FormatConfig::single(FormatVersion::V2));
        // Prefer the subcommand-level --erofs-version; fall back to global flag.
        // If neither is given, default to V2.
        let erofs_version = init_erofs_version
            .or(args.erofs_version)
            .map(composefs::erofs::format::FormatVersion::from)
            .unwrap_or(composefs::erofs::format::FormatVersion::V2);
        return run_init(
            algorithm,
            path.as_deref(),
            insecure || args.insecure,
            reset_metadata,
            erofs_version,
            erofs_formats,
            &args,
        );
    }

    // Varlink serve commands: dispatch before opening a repo (service opens repos lazily).
    if let Command::Varlink { ref address } = args.cmd {
        let service = crate::varlink::CfsctlService::from_app(&args);
        return crate::varlink::serve(service, address.as_deref()).await;
    }
    #[cfg(feature = "oci")]
    if let Command::Oci {
        cmd: OciCommand::Varlink { ref address },
    } = args.cmd
    {
        let service = crate::varlink::CfsctlService::from_app(&args);
        return crate::varlink::serve(service, address.as_deref()).await;
    }

    // Commands that only need verity digests (no object storage) can
    // run without opening a repository.
    if args.no_repo
        || matches!(
            args.cmd,
            Command::ComputeId { .. }
                | Command::ComputeKarg { .. }
                | Command::CreateDumpfile { .. }
        )
    {
        // If a repo path is available and --no-repo wasn't passed,
        // try to read the hash type from the repo's metadata so that
        // e.g. `cfsctl --repo <sha256-repo> compute-id` uses SHA-256
        // instead of the default SHA-512.
        let effective_hash = if !args.no_repo {
            if let Ok(repo_path) = resolve_repo_path(&args) {
                resolve_hash_type(&repo_path, args.hash, !args.no_upgrade)
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
    let effective_hash = resolve_hash_type(&repo_path, args.hash, !args.no_upgrade)?;

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
    erofs_version: composefs::erofs::format::FormatVersion,
    erofs_formats: FormatConfig,
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
    let config = {
        let mut c = RepositoryConfig::new(*algorithm);
        // erofs_version is the default format; fold it into the FormatConfig.
        c.erofs_formats = FormatConfig {
            default: erofs_version,
            ..erofs_formats
        };
        if insecure { c.set_insecure() } else { c }
    };
    let created = match algorithm {
        Algorithm::Sha256 { .. } => {
            Repository::<Sha256HashValue>::init_path(CWD, &repo_path, config)?.1
        }
        Algorithm::Sha512 { .. } => {
            Repository::<Sha512HashValue>::init_path(CWD, &repo_path, config)?.1
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

/// Open a repo, auto-upgrading old-format repos unless `--no-upgrade` was passed.
pub fn open_repo<ObjectID>(args: &App) -> Result<Repository<ObjectID>>
where
    ObjectID: FsVerityHashValue,
{
    let path = resolve_repo_path(args)?;
    let mut repo = if args.no_upgrade {
        Repository::open_path(CWD, path)?
    } else {
        let (repo, _upgraded) = Repository::open_upgrade(CWD, path)?;
        repo
    };
    // Hidden --insecure flag for backward compatibility; the default
    // now is to inherit the repo config, but if it's specified we
    // disable requiring verity even if the repo says to use it.
    if args.insecure {
        repo.set_insecure();
    }
    if args.require_verity {
        repo.require_verity()?;
    }
    // If the user explicitly passed --erofs-version, override the stored
    // repo setting for this invocation only (does not rewrite meta.json).
    if let Some(version) = args.erofs_version {
        repo.set_erofs_version(version.into());
    }
    Ok(repo)
}

/// Open a composefs repository at the given path with explicit options.
///
/// Used by varlink handlers and tests that need to specify the path directly.
pub fn open_repo_at<ObjectID>(
    path: &Path,
    insecure: bool,
    require_verity: bool,
    no_upgrade: bool,
) -> Result<Repository<ObjectID>>
where
    ObjectID: FsVerityHashValue,
{
    let mut repo = if no_upgrade {
        Repository::open_path(CWD, path)?
    } else {
        let (repo, _upgraded) = Repository::open_upgrade(CWD, path)?;
        repo
    };
    if insecure {
        repo.set_insecure();
    }
    if require_verity {
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
                            Inline(..) | Sparse(..) => println!("{} inline", file_path.display()),
                            External(id, _) | ExternalNoVerity(id, _) => {
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
    let erofs_version = args
        .erofs_version
        .map(composefs::erofs::format::FormatVersion::from);
    match args.cmd {
        Command::ComputeId { fs_opts } => {
            let fs = load_filesystem_from_ondisk_fs::<ObjectID>(&fs_opts, None).await?;
            let version = erofs_version.unwrap_or_default();
            let vfs = composefs::erofs::writer::ValidatedFileSystem::new(fs)?;
            let id = composefs::fsverity::compute_verity::<ObjectID>(
                &composefs::erofs::writer::mkfs_erofs_versioned(&vfs, version),
            );
            println!("{}", id.to_hex());
        }
        Command::ComputeKarg {
            path,
            no_propagate_usr_to_root,
        } => {
            let fs_opts = FsReadOptions {
                path,
                bootable: true,
                no_propagate_usr_to_root,
            };
            let fs = load_filesystem_from_ondisk_fs::<ObjectID>(&fs_opts, None).await?;
            let version = erofs_version.unwrap_or_default();
            let id = composefs::fsverity::compute_verity::<ObjectID>(
                &composefs::erofs::writer::mkfs_erofs_versioned(
                    &composefs::erofs::writer::ValidatedFileSystem::new(fs)?,
                    version,
                ),
            );
            let karg = match version {
                FormatVersion::V0 | FormatVersion::V1 => {
                    ComposefsCmdline::new_v1(id, args.insecure)
                }
                FormatVersion::V2 => ComposefsCmdline::new_v2(id, args.insecure),
            };
            println!("{}", karg.to_cmdline_arg());
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
                composefs_oci::ls_layer(&repo, name, std::io::stdout())?;
            }
            OciCommand::Dump { config_opts } => {
                let fs = load_filesystem_from_oci_image(&repo, config_opts)?;
                fs.print_dumpfile()?;
            }
            OciCommand::Mount {
                ref image,
                ref mountpoint,
                bootable,
                ref upperdir,
                ref workdir,
                read_write,
                fuse,
                require_signature,
                ref trust_cert,
            } => {
                if require_signature && trust_cert.is_none() {
                    anyhow::bail!("--require-signature requires --trust-cert");
                }

                let img = if image.starts_with("sha256:") {
                    let digest: composefs_oci::OciDigest =
                        image.parse().context("Parsing manifest digest")?;
                    composefs_oci::oci_image::OciImage::open(&repo, &digest, None)?
                } else {
                    composefs_oci::oci_image::OciImage::open_ref(&repo, image)?
                };

                if require_signature {
                    let cert_path = trust_cert.as_ref().unwrap();
                    let cert_pem = std::fs::read(cert_path)
                        .with_context(|| format!("failed to read certificate: {cert_path:?}"))?;
                    let verifier =
                        composefs_oci::signing::FsVeritySignatureVerifier::from_pem(&cert_pem)?;
                    let verified_count =
                        composefs_oci::verify_image_signatures(&repo, image, Some(&verifier))?;
                    println!(
                        "Signature verification passed ({verified_count} signatures verified)"
                    );
                }

                let erofs_id = if bootable {
                    match img.boot_image_ref(repo.erofs_version()) {
                        Some(id) => id,
                        None => anyhow::bail!(
                            "No boot EROFS image linked — try pulling with --bootable"
                        ),
                    }
                } else {
                    match img.image_ref(repo.erofs_version()) {
                        Some(id) => id,
                        None => anyhow::bail!(
                            "No composefs EROFS image linked — try re-pulling the image"
                        ),
                    }
                };
                if let Some(fuse_opts) = fuse {
                    #[cfg(feature = "fuse")]
                    {
                        use composefs_fuse::{
                            FuseConfig, mount_fuse, open_fuse, serve_tree_fuse_fd,
                        };

                        // Read the EROFS image from the repository's images/ directory.
                        let (image_fd, _verified) = repo.open_image(&erofs_id.to_hex())?;
                        let erofs_bytes = {
                            let mut buf = Vec::new();
                            std::fs::File::from(image_fd).read_to_end(&mut buf)?;
                            buf
                        };
                        let filesystem = erofs_to_filesystem::<ObjectID>(&erofs_bytes)
                            .context("parsing EROFS image")?;

                        let dev_fuse = open_fuse()?;
                        let mnt_fd = mount_fuse(&dev_fuse, &Default::default())?;
                        composefs::mount::mount_at(&mnt_fd, CWD, mountpoint.as_str())
                            .with_context(|| format!("attaching FUSE mount at {mountpoint}"))?;

                        // Hold mnt_fd alive for the session duration — it pins the FUSE
                        // superblock so the connection stays alive while we serve.
                        let _mnt_fd = mnt_fd;

                        serve_tree_fuse_fd(
                            dev_fuse,
                            Arc::new(filesystem),
                            Arc::clone(&repo),
                            FuseConfig {
                                passthrough: fuse_opts.passthrough,
                            },
                        )
                        .context("FUSE session error")?;
                    }
                    #[cfg(not(feature = "fuse"))]
                    {
                        let _ = fuse_opts;
                        anyhow::bail!("cfsctl was built without FUSE support");
                    }
                } else {
                    let mount_options =
                        get_mount_options(upperdir.as_deref(), workdir.as_deref(), read_write)?;
                    repo.mount_at(&erofs_id.to_hex(), mountpoint.as_str(), &mount_options)?;
                }
            }
            OciCommand::ComputeId { config_opts } => {
                let fs = load_filesystem_from_oci_image(&repo, config_opts)?;
                let id = fs.compute_image_id(repo.erofs_version());
                println!("{}", id.to_hex());
            }
            OciCommand::ComposefsDigestKarg { config_opts } => {
                let verity = verity_opt(&config_opts.config_verity)?;
                let (config_digest, config_verity) =
                    resolve_oci_config(&repo, &config_opts.config_name, verity)?;
                let mut fs = composefs_oci::image::create_filesystem(
                    &repo,
                    &config_digest,
                    config_verity.as_ref(),
                )?;
                fs.transform_for_boot(&repo)?;
                let mut vfs = composefs::erofs::writer::ValidatedFileSystem::new(fs)?;
                let digest = composefs::fsverity::compute_verity::<ObjectID>(
                    &composefs::erofs::writer::mkfs_erofs_versioned(
                        &mut vfs,
                        composefs::erofs::format::FormatVersion::V1,
                    ),
                );
                let karg = ComposefsCmdline::new_v1(digest, repo.is_insecure());
                println!("{}", karg.to_cmdline_arg());
            }
            OciCommand::Pull {
                ref image,
                name,
                bootable,
                local_fetch,
                require_signature,
                ref trust_cert,
            } => {
                if require_signature && trust_cert.is_none() {
                    anyhow::bail!("--require-signature requires --trust-cert");
                }

                // If no explicit name provided, use the image reference as the tag
                let tag_name = name.as_deref().unwrap_or(image);

                let reporter: SharedReporter = IndicatifReporter::new().into_shared();
                let opts = composefs_oci::PullOptions {
                    local_fetch: local_fetch.into(),
                    progress: Some(reporter),
                    ..Default::default()
                };

                let result = composefs_oci::pull(&repo, image, Some(tag_name), opts).await?;

                println!("manifest {}", result.manifest_digest);
                println!("config   {}", result.config_digest);
                println!("verity   {}", result.manifest_verity.to_hex());
                println!("tagged   {tag_name}");
                println!("objects  {}", result.stats);

                if bootable {
                    // Resolve the tag to get the current manifest (already
                    // rewritten with image_ref_v1 populated by the pull) so
                    // generate_boot_image can preserve it in the boot manifest.
                    // This equals result.manifest_digest, which now also
                    // reflects the post-rewrite digest.
                    let (current_manifest_digest, _) =
                        composefs_oci::oci_image::resolve_ref(&repo, tag_name)?;
                    let image_verity = composefs_oci::generate_boot_image(
                        &repo,
                        &current_manifest_digest,
                        Some(tag_name),
                    )?;
                    println!("Boot image: {}", image_verity.to_hex());
                }

                if require_signature {
                    let cert_path = trust_cert.as_ref().unwrap();
                    let cert_pem = std::fs::read(cert_path)
                        .with_context(|| format!("failed to read certificate: {cert_path:?}"))?;
                    let verifier =
                        composefs_oci::signing::FsVeritySignatureVerifier::from_pem(&cert_pem)?;
                    let verified_count =
                        composefs_oci::verify_image_signatures(&repo, tag_name, Some(&verifier))?;
                    println!(
                        "Signature verification passed ({verified_count} signatures verified)"
                    );
                }
            }
            OciCommand::ListImages { json } => {
                let images = composefs_oci::oci_image::list_images(&repo)?;

                if json {
                    let reply = crate::varlink::ListImagesReply {
                        images: images
                            .iter()
                            .map(crate::varlink::ImageEntry::from)
                            .collect(),
                    };
                    serde_json::to_writer_pretty(std::io::stdout().lock(), &reply)?;
                    println!();
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
                    let output = crate::varlink::OciInspectReply::from_image(&repo, &img)?;
                    println!("{}", serde_json::to_string_pretty(&output)?);
                }
            }
            // TODO: This only accepts a raw manifest digest (sha256:...),
            // not a tag name. If a user provides a tag name as the source,
            // tag_image creates a broken symlink. Consider resolving tag
            // names to digests here, like Seal/Sign/Verify do.
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
            OciCommand::Seal { ref image } => {
                let repo = Arc::new(repo);
                let manifest_digest = composefs_oci::seal_image(&repo, image)?;
                println!("Sealed {image} -> {manifest_digest}");
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
                let ids = fs.commit_images(&repo, None)?;
                let fmt_config = repo.default_format_config();
                // Prefer V1 digest; fall back to V2.
                let id = ids
                    .get(&FormatVersion::V1)
                    .or_else(|| ids.get(&FormatVersion::V2))
                    .ok_or_else(|| anyhow::anyhow!("commit_images produced no images"))?
                    .clone();

                let insecure = repo.is_insecure();
                let karg = if fmt_config.default == FormatVersion::V1
                    && !fmt_config.extra.contains(&FormatVersion::V2)
                {
                    // V1-only repo → composefs.digest=v1-...: (with optional ? for insecure)
                    ComposefsCmdline::new_v1(id, insecure)
                } else {
                    // BOTH or V2-only repo → composefs= (with optional ? for insecure)
                    ComposefsCmdline::new_v2(id, insecure)
                };

                let Some(entry) = entries.into_iter().next() else {
                    anyhow::bail!("No boot entries!");
                };

                let cmdline_refs: Vec<&str> = cmdline.iter().map(String::as_str).collect();
                write_boot::write_boot_simple(
                    &repo,
                    entry,
                    &karg,
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
                    .join(karg.digest().to_hex());

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
                    let output = crate::varlink::OciFsckReply::from(&result);
                    serde_json::to_writer_pretty(std::io::stdout().lock(), &output)?;
                    println!();
                } else {
                    print!("{result}");
                    if !result.is_ok() {
                        anyhow::bail!("OCI integrity check failed");
                    }
                }
            }
            OciCommand::Sign {
                ref image,
                ref cert,
                ref key,
            } => {
                // TODO: Warn if the image hasn't been sealed yet. Signing an
                // unsealed image creates a valid signature, but the image can't
                // be mounted (mount requires a sealed config). This is almost
                // certainly a user mistake.
                let cert_pem = std::fs::read(cert).context("failed to read certificate file")?;
                let key_pem = std::fs::read(key).context("failed to read private key file")?;
                let signing_key =
                    composefs_oci::signing::FsVeritySigningKey::from_pem(&cert_pem, &key_pem)?;
                let (artifact_digest, _) = composefs_oci::sign_image(&repo, image, &signing_key)?;
                println!("{artifact_digest}");
            }
            OciCommand::Verify {
                ref image,
                ref cert,
            } => {
                let img = composefs_oci::OciImage::open_ref(&repo, image)?;
                let manifest_digest = img.manifest_digest();

                let referrers = composefs_oci::oci_image::list_referrers(&repo, manifest_digest)?;

                if referrers.is_empty() {
                    anyhow::bail!("no signature artifacts found for {image}");
                }

                let verifier = match cert {
                    Some(cert_path) => {
                        let cert_pem = std::fs::read(cert_path).with_context(|| {
                            format!("failed to read certificate: {cert_path:?}")
                        })?;
                        Some(composefs_oci::signing::FsVeritySignatureVerifier::from_pem(
                            &cert_pem,
                        )?)
                    }
                    None => None,
                };

                let config_digest = img.config_digest();
                let algorithm = ObjectID::ALGORITHM;

                let mut digest_ok_all = true;
                let mut found_composefs = false;
                let mut verified_count = 0usize;

                for (artifact_digest, artifact_verity) in &referrers {
                    let artifact_image = composefs_oci::OciImage::open(
                        &repo,
                        artifact_digest,
                        Some(artifact_verity),
                    )
                    .with_context(|| format!("opening referrer {artifact_digest}"))?;

                    match artifact_image.manifest().artifact_type() {
                        Some(composefs_oci::OciMediaType::Other(t))
                            if t == composefs_oci::signature::ARTIFACT_TYPE => {}
                        _ => continue,
                    }

                    found_composefs = true;
                    let parsed = composefs_oci::signature::parse_signature_artifact(
                        artifact_image.manifest(),
                    )
                    .with_context(|| format!("parsing artifact {artifact_digest}"))?;

                    println!("Signature artifact (algorithm: {})", parsed.algorithm);

                    // Composefs sealing artifacts always use EROFS v1.
                    let per_layer_digests =
                        composefs_oci::compute_per_layer_digests(&repo, config_digest, None)?;
                    let merged_digest: ObjectID =
                        composefs_oci::compute_merged_digest(&repo, config_digest, None)?;
                    let merged_hex = merged_digest.to_hex();

                    let layer_descriptors = artifact_image.layer_descriptors();
                    let mut layer_idx = 0usize;
                    let sig_layer_offset = 0;
                    // Track whether this particular artifact verified with
                    // the given cert (relevant for multi-signer scenarios).
                    let mut artifact_verified = true;

                    for (entry_idx, entry) in parsed.signature_entries.iter().enumerate() {
                        let (label, expected_hex) = match entry.sig_type {
                            composefs_oci::signature::SignatureType::Layer => {
                                let lbl = format!("  layer[{layer_idx}]:");
                                let expected = per_layer_digests.get(layer_idx).map(|d| d.to_hex());
                                layer_idx += 1;
                                (lbl, expected)
                            }
                            composefs_oci::signature::SignatureType::Merged => {
                                ("  merged:  ".to_string(), Some(merged_hex.clone()))
                            }
                            other => {
                                println!("  {:?}: skipped", other);
                                continue;
                            }
                        };

                        let digest_matches = match &expected_hex {
                            Some(expected) => *expected == entry.digest,
                            None => {
                                println!("{label} no expected digest - SKIP");
                                digest_ok_all = false;
                                continue;
                            }
                        };

                        if !digest_matches {
                            println!("{label} digest MISMATCH");
                            digest_ok_all = false;
                            continue;
                        }

                        if let Some(ref verifier) = verifier {
                            let layer_desc = layer_descriptors
                                .get(sig_layer_offset + entry_idx)
                                .context("layer descriptor out of bounds")?;
                            let blob_digest = layer_desc.digest();

                            if layer_desc.size() == 0u64 {
                                println!("{label} digest matches but no signature blob");
                                artifact_verified = false;
                                continue;
                            }

                            let blob_verity = artifact_image
                                .layer_verity(blob_digest.as_ref())
                                .ok_or_else(|| {
                                    anyhow::anyhow!("verity not found for {blob_digest}")
                                })?;
                            let signature_blob = composefs_oci::oci_image::open_blob(
                                &repo,
                                blob_digest,
                                Some(blob_verity),
                            )?;

                            let digest_bytes =
                                hex::decode(&entry.digest).context("invalid hex digest")?;

                            match verifier.verify_raw(
                                &signature_blob,
                                algorithm.kernel_id(),
                                &digest_bytes,
                            ) {
                                Ok(()) => {
                                    println!("{label} signature verified");
                                    verified_count += 1;
                                }
                                Err(e) => {
                                    println!("{label} not verified by this cert: {e}");
                                    artifact_verified = false;
                                }
                            }
                        } else {
                            println!("{label} digest matches");
                        }
                    }

                    if verifier.is_some() && !artifact_verified {
                        println!("  (artifact not signed by given cert, skipping)");
                    }
                }

                if !found_composefs {
                    anyhow::bail!("no composefs signature artifacts found for {image}");
                }

                if verifier.is_some() {
                    if verified_count == 0 {
                        anyhow::bail!("no signature artifacts verified with the given certificate");
                    }
                    println!("\nVerification passed ({verified_count} signatures verified)");
                } else {
                    if !digest_ok_all {
                        anyhow::bail!("digest verification failed for one or more entries");
                    }
                    println!(
                        "\nDigest check passed. NOTE: no certificate provided, signatures were NOT cryptographically verified."
                    );
                    println!(
                        "To verify signatures, use: cfsctl oci verify {image} --cert <certificate.pem>"
                    );
                }
            }
            OciCommand::Push {
                ref image,
                ref destination,
                signatures,
            } => {
                // Parse destination: strip "oci:" prefix, handle "oci:/path:tag" syntax
                let dest = destination.strip_prefix("oci:").unwrap_or(destination);

                // Parse optional tag from path — only split on the last colon if
                // it isn't part of an absolute path (i.e. not position 0 like "/tmp/foo")
                let (path_str, dest_tag) = if let Some(colon_pos) = dest.rfind(':') {
                    // Don't split on the colon right after a drive letter or at position 0
                    if colon_pos > 0
                        && !dest[..colon_pos].ends_with('/')
                        && !dest[colon_pos + 1..].contains('/')
                    {
                        (&dest[..colon_pos], Some(&dest[colon_pos + 1..]))
                    } else {
                        (dest, None)
                    }
                } else {
                    (dest, None)
                };

                let oci_layout_path = std::path::Path::new(path_str);
                std::fs::create_dir_all(oci_layout_path).with_context(|| {
                    format!(
                        "creating destination directory: {}",
                        oci_layout_path.display()
                    )
                })?;

                let img = composefs_oci::OciImage::open_ref(&repo, image)?;
                let tag = dest_tag.or(Some(image));

                composefs_oci::export_image_to_oci_layout(
                    &repo,
                    &img,
                    oci_layout_path,
                    tag,
                    signatures,
                )
                .context("exporting image to OCI layout")?;

                println!("Exported {} to {}", image, oci_layout_path.display());
                if let Some(t) = tag {
                    println!("Tagged as {t}");
                }
            }
            OciCommand::ExportSignatures {
                ref image,
                ref oci_layout_path,
            } => {
                let img = composefs_oci::OciImage::open_ref(&repo, image)?;
                let manifest_digest = img.manifest_digest();

                let count = composefs_oci::export_referrers_to_oci_layout(
                    &repo,
                    manifest_digest,
                    oci_layout_path,
                    None,
                )
                .context("exporting signatures to OCI layout")?;

                if count == 0 {
                    println!("No signature artifacts found for {image}");
                } else {
                    println!(
                        "Exported {count} signature artifact(s) to {}",
                        oci_layout_path.display()
                    );
                }
            }
            OciCommand::Run {
                ref image,
                name,
                require_signature,
                ref trust_cert,
                pull,
                runtime,
                envs,
                network,
                volumes,
                rm,
                bundle_dir,
                cmd,
            } => {
                if require_signature && trust_cert.is_none() {
                    anyhow::bail!("--require-signature requires --trust-cert");
                }

                // Derive a container name from the image reference when not specified.
                let name = name.unwrap_or_else(|| {
                    image
                        .split('/')
                        .next_back()
                        .unwrap_or(image)
                        .split(':')
                        .next()
                        .unwrap_or(image)
                        .to_string()
                });

                let bundle_dir =
                    bundle_dir.unwrap_or_else(|| PathBuf::from(format!("/run/cfsctl/{name}")));
                let rootfs = bundle_dir.join("rootfs");

                // --- Pull policy ---
                let img = match pull {
                    PullPolicy::Always => {
                        // Always (re)pull before running.
                        let tag_name = image.as_str();
                        let reporter: SharedReporter = IndicatifReporter::new().into_shared();
                        let opts = composefs_oci::PullOptions {
                            progress: Some(reporter),
                            ..Default::default()
                        };
                        composefs_oci::pull(&repo, image, Some(tag_name), opts).await?;
                        if image.starts_with("sha256:") {
                            let digest: composefs_oci::OciDigest =
                                image.parse().context("Parsing manifest digest")?;
                            composefs_oci::oci_image::OciImage::open(&repo, &digest, None)?
                        } else {
                            composefs_oci::oci_image::OciImage::open_ref(&repo, image)?
                        }
                    }
                    PullPolicy::Missing => {
                        // Only pull if not present.
                        let maybe_img = if image.starts_with("sha256:") {
                            let digest: composefs_oci::OciDigest =
                                image.parse().context("Parsing manifest digest")?;
                            composefs_oci::oci_image::OciImage::open(&repo, &digest, None).ok()
                        } else {
                            composefs_oci::oci_image::OciImage::open_ref(&repo, image).ok()
                        };
                        match maybe_img {
                            Some(img) => img,
                            None => {
                                let tag_name = image.as_str();
                                let reporter: SharedReporter =
                                    IndicatifReporter::new().into_shared();
                                let opts = composefs_oci::PullOptions {
                                    progress: Some(reporter),
                                    ..Default::default()
                                };
                                composefs_oci::pull(&repo, image, Some(tag_name), opts).await?;
                                if image.starts_with("sha256:") {
                                    let digest: composefs_oci::OciDigest =
                                        image.parse().context("Parsing manifest digest")?;
                                    composefs_oci::oci_image::OciImage::open(&repo, &digest, None)?
                                } else {
                                    composefs_oci::oci_image::OciImage::open_ref(&repo, image)?
                                }
                            }
                        }
                    }
                    PullPolicy::Never => {
                        // Fail if not present.
                        if image.starts_with("sha256:") {
                            let digest: composefs_oci::OciDigest =
                                image.parse().context("Parsing manifest digest")?;
                            composefs_oci::oci_image::OciImage::open(&repo, &digest, None)?
                        } else {
                            composefs_oci::oci_image::OciImage::open_ref(&repo, image)?
                        }
                    }
                };

                // --- Signature verification ---
                if require_signature {
                    let cert_path = trust_cert.as_ref().expect("trust_cert checked above");
                    let cert_pem = std::fs::read(cert_path)
                        .with_context(|| format!("failed to read certificate: {cert_path:?}"))?;
                    let verifier =
                        composefs_oci::signing::FsVeritySignatureVerifier::from_pem(&cert_pem)?;
                    let verified_count =
                        composefs_oci::verify_image_signatures(&repo, image, Some(&verifier))?;
                    println!(
                        "Signature verification passed ({verified_count} signatures verified)"
                    );
                }

                // --- Resolve composefs EROFS image id ---
                let erofs_id = img
                    .image_ref(repo.erofs_version())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "No composefs EROFS image linked for {image} — try re-pulling"
                        )
                    })?
                    .to_hex();

                // --- Mount composefs ---
                std::fs::create_dir_all(&rootfs)
                    .with_context(|| format!("creating rootfs directory: {}", rootfs.display()))?;
                repo.mount_at(
                    &erofs_id,
                    rootfs.to_str().context("rootfs path is not valid UTF-8")?,
                    &composefs::mount::MountOptions::default(),
                )?;

                // Cleanup helper: unmount and remove bundle if anything below
                // fails before exec() hands off to the runtime.
                let cleanup = || {
                    let _ = rustix::mount::unmount(&rootfs, rustix::mount::UnmountFlags::DETACH);
                    let _ = std::fs::remove_dir_all(&bundle_dir);
                };

                // --- Read OCI image config for process settings ---
                let image_config = match img
                    .config()
                    .ok_or_else(|| anyhow::anyhow!("OCI image has no config block"))
                {
                    Ok(c) => c,
                    Err(e) => {
                        cleanup();
                        return Err(e);
                    }
                };

                // --- Generate OCI runtime spec ---
                let overrides = oci_run::RunOverrides {
                    name: name.clone(),
                    extra_env: envs,
                    network,
                    volumes,
                    cmd_override: cmd,
                };
                let spec = match oci_run::generate_spec(&rootfs, image_config, &overrides) {
                    Ok(s) => s,
                    Err(e) => {
                        cleanup();
                        return Err(e);
                    }
                };
                if let Err(e) = oci_run::write_bundle(&bundle_dir, &spec) {
                    cleanup();
                    return Err(e);
                }

                // --- Find OCI runtime ---
                let runtime_path = match runtime {
                    Some(p) => p,
                    None => {
                        // Search PATH for crun, then runc.
                        ["crun", "runc"]
                            .iter()
                            .find_map(|name| {
                                std::env::var_os("PATH").and_then(|path_var| {
                                    std::env::split_paths(&path_var).find_map(|dir| {
                                        let candidate = dir.join(name);
                                        if candidate.is_file() {
                                            Some(candidate)
                                        } else {
                                            None
                                        }
                                    })
                                })
                            })
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "no OCI runtime found in PATH; install crun or runc, \
                                     or use --runtime"
                                )
                            })?
                    }
                };

                // --- Optionally register cleanup on exit via `--rm` ---
                // crun's `--rm` flag handles removing the container state, but
                // we also need to unmount the composefs overlay.  We register
                // a SIGCHLD/atexit handler via a wrapper script if --rm is set.
                // For now we implement the simple path: exec directly and rely
                // on crun --rm for state cleanup; unmount is left for `stop`.
                let mut runtime_cmd = std::process::Command::new(&runtime_path);
                runtime_cmd.arg("run");
                if rm {
                    runtime_cmd.arg("--rm");
                }
                runtime_cmd.arg("--bundle");
                runtime_cmd.arg(&bundle_dir);
                runtime_cmd.arg(&name);

                // exec() replaces the current process; it only returns on error.
                use std::os::unix::process::CommandExt as _;
                let err = runtime_cmd.exec();
                // exec failed — clean up the mount we created.
                cleanup();
                anyhow::bail!("exec {:?} failed: {err}", runtime_path);
            }
            OciCommand::Stop { name, bundle_dir } => {
                let bundle_dir =
                    bundle_dir.unwrap_or_else(|| PathBuf::from(format!("/run/cfsctl/{name}")));
                let rootfs = bundle_dir.join("rootfs");

                // Ask the runtime to delete the container state (best-effort).
                let _ = std::process::Command::new("crun")
                    .args(["delete", "-f", &name])
                    .status();

                // Unmount the composefs overlay (best-effort; ignore ENOENT/EINVAL).
                let _ = rustix::mount::unmount(&rootfs, rustix::mount::UnmountFlags::DETACH);

                // Remove the bundle directory.
                if bundle_dir.exists() {
                    std::fs::remove_dir_all(&bundle_dir).with_context(|| {
                        format!("removing bundle directory: {}", bundle_dir.display())
                    })?;
                }

                println!("Stopped and cleaned up container {name}");
            }
            OciCommand::Varlink { .. } => {
                unreachable!("varlink is handled before opening a repository")
            }
        },
        #[cfg(feature = "ostree")]
        Command::Ostree { cmd: ostree_cmd } => match ostree_cmd {
            OstreeCommand::PullLocal {
                ref ostree_repo_path,
                ref ostree_ref,
                base_name,
            } => {
                eprintln!("Fetching {ostree_ref}");
                let (verity, stats) = composefs_ostree::pull_local(
                    &repo,
                    ostree_repo_path,
                    ostree_ref,
                    base_name.as_deref(),
                )
                .await?;

                let image_id = composefs_ostree::get_image_ref(&repo, &stats.commit_id)?;
                println!("commit  {}", stats.commit_id);
                println!("verity  {}", verity.to_hex());
                println!("image   {}", image_id.to_hex());
                if !composefs_ostree::is_commit_id(ostree_ref) {
                    println!("tagged  {ostree_ref}");
                }
                println!(
                    "objects {} metadata + {} files fetched",
                    stats.metadata_fetched, stats.files_fetched
                );
            }
            OstreeCommand::Pull {
                ref ostree_repo_url,
                ref ostree_ref,
                base_name,
            } => {
                eprintln!("Fetching {ostree_ref}");
                let (verity, stats) = composefs_ostree::pull(
                    &repo,
                    ostree_repo_url,
                    ostree_ref,
                    base_name.as_deref(),
                )
                .await?;

                let image_id = composefs_ostree::get_image_ref(&repo, &stats.commit_id)?;
                println!("commit  {}", stats.commit_id);
                println!("verity  {}", verity.to_hex());
                println!("image   {}", image_id.to_hex());
                if !composefs_ostree::is_commit_id(ostree_ref) {
                    println!("tagged  {ostree_ref}");
                }
                println!(
                    "objects {} metadata + {} files fetched",
                    stats.metadata_fetched, stats.files_fetched
                );
            }
            OstreeCommand::Mount {
                ref commit,
                ref mountpoint,
                ref upperdir,
                ref workdir,
                read_write,
            } => {
                let mount_options =
                    get_mount_options(upperdir.as_deref(), workdir.as_deref(), read_write)?;
                let image_id = composefs_ostree::get_image_ref(&repo, commit)?;
                repo.mount_at(&image_id.to_hex(), mountpoint.as_str(), &mount_options)?;
            }
            OstreeCommand::Dump { ref commit_name } => {
                let fs = composefs_ostree::create_filesystem(&repo, commit_name)?;
                fs.print_dumpfile()?;
            }
            OstreeCommand::ComputeId { ref commit_name } => {
                let image_id = composefs_ostree::ensure_ostree_erofs(&repo, commit_name)?;
                println!("{}", image_id.to_hex());
            }
            OstreeCommand::Inspect {
                ref source,
                metadata,
            } => {
                composefs_ostree::inspect(&repo, source, metadata)?;
            }
            OstreeCommand::Tag {
                ref source,
                ref name,
            } => {
                composefs_ostree::tag(&repo, source, name)?;
                println!("Tagged {source} as {name}");
            }
            OstreeCommand::Untag { ref name } => {
                composefs_ostree::untag(&repo, name)?;
            }
            OstreeCommand::ListCommits => {
                let commits = composefs_ostree::list_commits(&repo)?;
                if commits.is_empty() {
                    println!("No ostree commits found");
                } else {
                    let mut table = Table::new();
                    table.load_preset(UTF8_FULL);
                    table.set_header(["NAME", "COMMIT"]);
                    for c in commits {
                        table.add_row([c.name.as_str(), &c.commit_id]);
                    }
                    println!("{table}");
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
        Command::ComputeId { .. }
        | Command::ComputeKarg { .. }
        | Command::CreateDumpfile { .. } => {
            // Handled in run_app before opening the repo
            unreachable!(
                "compute-id, compute-karg, and create-dumpfile are dispatched without a repo"
            );
        }
        Command::Mount {
            name,
            mountpoint,
            ref upperdir,
            ref workdir,
            read_write,
        } => {
            let mount_options =
                get_mount_options(upperdir.as_deref(), workdir.as_deref(), read_write)?;
            repo.mount_at(&name, &mountpoint, &mount_options)?;
        }
        #[cfg(feature = "fuse")]
        Command::FuseServe {
            ref image,
            ref mountpoint,
            passthrough,
        } => {
            use composefs_fuse::{FuseConfig, mount_fuse, open_fuse, serve_tree_fuse_fd};

            let erofs_bytes = std::fs::read(image)
                .with_context(|| format!("reading EROFS image {}", image.display()))?;
            let filesystem =
                erofs_to_filesystem::<ObjectID>(&erofs_bytes).context("parsing EROFS image")?;

            let dev_fuse = open_fuse()?;
            let mnt_fd = mount_fuse(&dev_fuse, &Default::default())?;
            composefs::mount::mount_at(&mnt_fd, CWD, mountpoint)
                .with_context(|| format!("attaching FUSE mount at {}", mountpoint.display()))?;

            // Hold mnt_fd alive for the session duration — it pins the FUSE
            // superblock so the connection stays alive while we serve.
            let _mnt_fd = mnt_fd;

            serve_tree_fuse_fd(
                dev_fuse,
                Arc::new(filesystem),
                Arc::clone(&repo),
                FuseConfig { passthrough },
            )
            .context("FUSE session error")?;
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
                let output = crate::varlink::FsckReply::from(&result);
                serde_json::to_writer_pretty(std::io::stdout().lock(), &output)?;
                println!();
            } else {
                print!("{result}");
                if !result.is_ok() {
                    anyhow::bail!("repository integrity check failed");
                }
            }
        }
        #[cfg(feature = "rhel9")]
        Command::Keyring { .. } => {
            unreachable!("keyring commands are handled before opening a repository")
        }
        Command::Mkcomposefs { .. } | Command::ComposefsInfo { .. } => {
            unreachable!("mkcomposefs/composefs-info are handled before opening a repository")
        }
        Command::Varlink { .. } => {
            unreachable!("varlink is handled before opening a repository")
        }
        #[cfg(feature = "http")]
        Command::Fetch { url, name } => {
            let reporter: SharedReporter = IndicatifReporter::new().into_shared();
            let (digest, verity) = composefs_http::download(
                &url,
                &name,
                Arc::clone(&repo),
                composefs_http::DownloadOptions {
                    progress: Some(reporter),
                },
            )
            .await?;
            println!("content {digest}");
            println!("verity {}", verity.to_hex());
        }
    }
    Ok(())
}

#[cfg(test)]
#[cfg(any(feature = "oci", feature = "http"))]
mod tests {
    use super::*;
    use composefs::progress::{ProgressEvent, ProgressUnit};

    // ── IndicatifReporter ────────────────────────────────────────────────────

    /// A complete valid lifecycle (Started → Progress → Done) must not panic,
    /// even without a real terminal (indicatif handles headless gracefully).
    #[test]
    fn test_indicatif_reporter_valid_lifecycle() {
        let reporter = IndicatifReporter::new();
        // Message before any component
        reporter.report(ProgressEvent::Message("starting pull".into()));
        // Byte-tracked component
        reporter.report(ProgressEvent::Started {
            id: "sha256:abc".into(),
            total: Some(1_000_000),
            unit: ProgressUnit::Bytes,
        });
        reporter.report(ProgressEvent::Progress {
            id: "sha256:abc".into(),
            fetched: 500_000,
            total: Some(1_000_000),
        });
        reporter.report(ProgressEvent::Done {
            id: "sha256:abc".into(),
            transferred: 1_000_000,
        });
        // Item-counted component (HTTP objects)
        reporter.report(ProgressEvent::Started {
            id: "objects:stream".into(),
            total: Some(200),
            unit: ProgressUnit::Items,
        });
        reporter.report(ProgressEvent::Progress {
            id: "objects:stream".into(),
            fetched: 100,
            total: Some(200),
        });
        reporter.report(ProgressEvent::Done {
            id: "objects:stream".into(),
            transferred: 200,
        });
        // Skipped component
        reporter.report(ProgressEvent::Started {
            id: "sha256:cached".into(),
            total: None,
            unit: ProgressUnit::Bytes,
        });
        reporter.report(ProgressEvent::Skipped {
            id: "sha256:cached".into(),
        });
    }

    /// Progress/Done events for an ID that was never `Started` must not panic.
    ///
    /// This guards against error-recovery paths where a `Started` event may
    /// have been suppressed or the reporter was attached after the operation
    /// began.
    #[test]
    fn test_indicatif_reporter_unknown_id_no_panic() {
        let reporter = IndicatifReporter::new();
        // Progress for unknown ID — should silently ignore
        reporter.report(ProgressEvent::Progress {
            id: "ghost".into(),
            fetched: 42,
            total: None,
        });
        // Done for unknown ID — should silently ignore
        reporter.report(ProgressEvent::Done {
            id: "ghost".into(),
            transferred: 42,
        });
        // Skipped for unknown ID — should silently ignore
        reporter.report(ProgressEvent::Skipped { id: "ghost".into() });
    }

    /// A spinner-style bar (unknown total) must not panic.
    #[test]
    fn test_indicatif_reporter_spinner_lifecycle() {
        let reporter = IndicatifReporter::new();
        // Started with unknown total → spinner
        reporter.report(ProgressEvent::Started {
            id: "layer:unknown-size".into(),
            total: None,
            unit: ProgressUnit::Bytes,
        });
        reporter.report(ProgressEvent::Progress {
            id: "layer:unknown-size".into(),
            fetched: 1024,
            total: None,
        });
        reporter.report(ProgressEvent::Done {
            id: "layer:unknown-size".into(),
            transferred: 2048,
        });
    }

    /// Multiple concurrent components must not interfere with each other.
    #[test]
    fn test_indicatif_reporter_multiple_concurrent_components() {
        let reporter = IndicatifReporter::new();
        // Start two layers in parallel
        reporter.report(ProgressEvent::Started {
            id: "layer:a".into(),
            total: Some(100),
            unit: ProgressUnit::Bytes,
        });
        reporter.report(ProgressEvent::Started {
            id: "layer:b".into(),
            total: Some(200),
            unit: ProgressUnit::Bytes,
        });
        // Interleaved progress
        reporter.report(ProgressEvent::Progress {
            id: "layer:a".into(),
            fetched: 50,
            total: Some(100),
        });
        reporter.report(ProgressEvent::Progress {
            id: "layer:b".into(),
            fetched: 100,
            total: Some(200),
        });
        // Layer B finishes first
        reporter.report(ProgressEvent::Done {
            id: "layer:b".into(),
            transferred: 200,
        });
        // Layer A finishes
        reporter.report(ProgressEvent::Done {
            id: "layer:a".into(),
            transferred: 100,
        });
    }
}
