//! Library for `cfsctl` command line utility

use std::{ffi::OsString, path::PathBuf};

#[cfg(feature = "oci")]
use std::{fs::create_dir_all, io::IsTerminal, path::Path};

#[cfg(any(feature = "oci", feature = "http"))]
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
#[cfg(feature = "oci")]
use comfy_table::{presets::UTF8_FULL, Table};

use rustix::fs::CWD;

#[cfg(feature = "oci")]
use composefs_boot::{write_boot, BootOps};

use composefs::{
    fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue},
    repository::Repository,
};

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

    /// What hash digest type to use for composefs repo
    #[clap(long, value_enum, default_value_t = HashType::Sha512)]
    pub hash: HashType,

    /// Sets the repository to insecure before running any operation and
    /// prepend '?' to the composefs kernel command line when writing
    /// boot entry.
    #[clap(long)]
    insecure: bool,

    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Default)]
/// TODO: Hash type
pub enum HashType {
    /// Sha256
    Sha256,
    /// Sha512
    #[default]
    Sha512,
}

/// Common options for operations using OCI config manifest streams that may transform the image rootfs
#[derive(Debug, Parser)]
struct OCIConfigFilesystemOptions {
    #[clap(flatten)]
    base_config: OCIConfigOptions,
    /// Whether bootable transformation should be performed on the image rootfs
    #[clap(long)]
    bootable: bool,
}

/// Common options for operations using OCI config manifest streams
#[derive(Debug, Parser)]
struct OCIConfigOptions {
    /// the name of the target OCI manifest stream, either a stream ID in format oci-config-<hash_type>:<hash_digest> or a reference in 'ref/'
    config_name: String,
    /// verity digest for the manifest stream to be verified against
    config_verity: Option<String>,
}

#[cfg(feature = "oci")]
#[derive(Debug, Subcommand)]
enum OciCommand {
    /// Stores a tar layer file as a splitstream in the repository.
    ImportLayer {
        digest: String,
        name: Option<String>,
    },
    /// Lists the contents of a tar stream
    LsLayer {
        /// the name of the stream to list, either a stream ID in format oci-config-<hash_type>:<hash_digest> or a reference in 'ref/'
        name: String,
    },
    /// Dump full content of the rootfs of a stored OCI image to a composefs dumpfile and write to stdout
    Dump {
        #[clap(flatten)]
        config_opts: OCIConfigFilesystemOptions,
    },
    /// Pull an OCI image to be stored in repo then prints the stream and verity digest of its manifest
    Pull {
        /// source image reference, as accepted by skopeo
        image: String,
        /// optional reference name for the manifest, use as 'ref/<name>' elsewhere
        name: Option<String>,
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
    /// By default, outputs JSON with manifest, config, and referrers.
    /// Use --manifest or --config to output just that raw JSON.
    #[clap(name = "inspect")]
    Inspect {
        /// Image reference (tag name or manifest digest)
        image: String,
        /// Output only the raw manifest JSON (as originally stored)
        #[clap(long, conflicts_with = "config")]
        manifest: bool,
        /// Output only the raw config JSON (as originally stored)
        #[clap(long, conflicts_with = "manifest")]
        config: bool,
    },
    /// Tag an image with a new name
    Tag {
        /// Manifest digest (sha256:...)
        manifest_digest: String,
        /// Tag name to assign
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
        /// Layer diff_id (sha256:...)
        layer: String,
        /// Output as composefs dumpfile format (one entry per line)
        #[clap(long, conflicts_with = "json")]
        dumpfile: bool,
        /// Output layer metadata as JSON
        #[clap(long, conflicts_with = "dumpfile")]
        json: bool,
    },
    /// Compute the composefs image object id of the rootfs of a stored OCI image
    ComputeId {
        #[clap(flatten)]
        config_opts: OCIConfigFilesystemOptions,
    },
    /// Create the composefs image of the rootfs of a stored OCI image, commit it to the repo, and print its image object ID
    CreateImage {
        #[clap(flatten)]
        config_opts: OCIConfigFilesystemOptions,
        /// optional reference name for the image, use as 'ref/<name>' elsewhere
        #[clap(long)]
        image_name: Option<String>,
    },
    /// Seal a stored OCI image by creating a cloned manifest with embedded verity digest (a.k.a. composefs image object ID)
    /// in the repo, then prints the stream and verity digest of the new sealed manifest
    Seal {
        #[clap(flatten)]
        config_opts: OCIConfigOptions,
    },
    /// Mounts a stored and sealed OCI image by looking up its composefs image. Note that the composefs image must be built
    /// and committed to the repo first
    Mount {
        /// the name of the target OCI manifest stream, either a stream ID in format oci-config-<hash_type>:<hash_digest> or a reference in 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
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
    /// Read rootfs located at a path, add all files to the repo, then compute the composefs image object id of the rootfs.
    /// Note that this does not create or commit the composefs image itself.
    ComputeId {
        #[clap(flatten)]
        fs_opts: FsReadOptions,
    },
    /// Read rootfs located at a path, add all files to the repo, then dump full content of the rootfs to a composefs dumpfile
    /// and write to stdout.
    CreateDumpfile {
        #[clap(flatten)]
        fs_opts: FsReadOptions,
    },
    /// Lists all object IDs referenced by an image
    ImageObjects {
        /// the name of the image to read, either an object ID digest or prefixed with 'ref/'
        name: String,
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

    match args.hash {
        HashType::Sha256 => run_cmd_with_repo(open_repo::<Sha256HashValue>(&args)?, args).await,
        HashType::Sha512 => run_cmd_with_repo(open_repo::<Sha512HashValue>(&args)?, args).await,
    }
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

/// Open a repo
pub fn open_repo<ObjectID>(args: &App) -> Result<Repository<ObjectID>>
where
    ObjectID: FsVerityHashValue,
{
    let mut repo = (if let Some(path) = &args.repo {
        Repository::open_path(CWD, path)
    } else if args.system {
        Repository::open_system()
    } else if args.user {
        Repository::open_user()
    } else if rustix::process::getuid().is_root() {
        Repository::open_system()
    } else {
        Repository::open_user()
    })?;

    repo.set_insecure(args.insecure);

    Ok(repo)
}

/// Run with cmd
pub async fn run_cmd_with_repo<ObjectID>(repo: Repository<ObjectID>, args: App) -> Result<()>
where
    ObjectID: FsVerityHashValue,
{
    match args.cmd {
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
            OciCommand::ImportLayer { name, digest } => {
                let (object_id, _stats) = composefs_oci::import_layer(
                    &Arc::new(repo),
                    &digest,
                    name.as_deref(),
                    &mut std::io::stdin(),
                )?;
                println!("{}", object_id.to_id());
            }
            OciCommand::LsLayer { name } => {
                composefs_oci::ls_layer(&repo, &name)?;
            }
            OciCommand::Dump {
                config_opts:
                    OCIConfigFilesystemOptions {
                        base_config:
                            OCIConfigOptions {
                                ref config_name,
                                ref config_verity,
                            },
                        bootable,
                    },
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(&repo)?;
                }
                fs.print_dumpfile()?;
            }
            OciCommand::ComputeId {
                config_opts:
                    OCIConfigFilesystemOptions {
                        base_config:
                            OCIConfigOptions {
                                ref config_name,
                                ref config_verity,
                            },
                        bootable,
                    },
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(&repo)?;
                }
                let id = fs.compute_image_id();
                println!("{}", id.to_hex());
            }
            OciCommand::CreateImage {
                config_opts:
                    OCIConfigFilesystemOptions {
                        base_config:
                            OCIConfigOptions {
                                ref config_name,
                                ref config_verity,
                            },
                        bootable,
                    },
                ref image_name,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(&repo)?;
                }
                let image_id = fs.commit_image(&repo, image_name.as_deref())?;
                println!("{}", image_id.to_id());
            }
            OciCommand::Pull { ref image, name } => {
                // If no explicit name provided, use the image reference as the tag
                let tag_name = name.as_deref().unwrap_or(image);
                let (result, stats) =
                    composefs_oci::pull_image(&Arc::new(repo), image, Some(tag_name), None).await?;

                println!("manifest {}", result.manifest_digest);
                println!("config   {}", result.config_digest);
                println!("verity   {}", result.manifest_verity.to_hex());
                println!("tagged   {tag_name}");
                println!(
                    "objects  {} copied, {} already present, {} bytes copied, {} bytes inlined",
                    stats.objects_copied,
                    stats.objects_already_present,
                    stats.bytes_copied,
                    stats.bytes_inlined,
                );
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
                    table.set_header(["NAME", "DIGEST", "ARCH", "SEALED", "LAYERS", "REFS"]);

                    for img in images {
                        let digest_short = img
                            .manifest_digest
                            .strip_prefix("sha256:")
                            .unwrap_or(&img.manifest_digest);
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
                        let sealed = if img.sealed { "yes" } else { "no" };
                        table.add_row([
                            img.name.as_str(),
                            digest_display,
                            arch,
                            sealed,
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
                let img = if image.starts_with("sha256:") {
                    composefs_oci::oci_image::OciImage::open(&repo, image, None)?
                } else {
                    composefs_oci::oci_image::OciImage::open_ref(&repo, image)?
                };

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
            OciCommand::Seal {
                config_opts:
                    OCIConfigOptions {
                        ref config_name,
                        ref config_verity,
                    },
            } => {
                let verity = verity_opt(config_verity)?;
                let (digest, verity) =
                    composefs_oci::seal(&Arc::new(repo), config_name, verity.as_ref())?;
                println!("config {digest}");
                println!("verity {}", verity.to_id());
            }
            OciCommand::Mount {
                ref name,
                ref mountpoint,
            } => {
                composefs_oci::mount(&repo, name, mountpoint, None)?;
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
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
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
                    args.insecure,
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
        },
        Command::ComputeId { fs_opts } => {
            let mut fs = if fs_opts.no_propagate_usr_to_root {
                composefs::fs::read_filesystem(CWD, &fs_opts.path, Some(&repo))?
            } else {
                composefs::fs::read_container_root(CWD, &fs_opts.path, Some(&repo))?
            };
            if fs_opts.bootable {
                fs.transform_for_boot(&repo)?;
            }
            let id = fs.compute_image_id();
            println!("{}", id.to_hex());
        }
        Command::CreateImage {
            fs_opts,
            ref image_name,
        } => {
            let mut fs = if fs_opts.no_propagate_usr_to_root {
                composefs::fs::read_filesystem(CWD, &fs_opts.path, Some(&repo))?
            } else {
                composefs::fs::read_container_root(CWD, &fs_opts.path, Some(&repo))?
            };
            if fs_opts.bootable {
                fs.transform_for_boot(&repo)?;
            }
            let id = fs.commit_image(&repo, image_name.as_deref())?;
            println!("{}", id.to_id());
        }
        Command::CreateDumpfile { fs_opts } => {
            let mut fs = if fs_opts.no_propagate_usr_to_root {
                composefs::fs::read_filesystem(CWD, &fs_opts.path, Some(&repo))?
            } else {
                composefs::fs::read_container_root(CWD, &fs_opts.path, Some(&repo))?
            };
            if fs_opts.bootable {
                fs.transform_for_boot(&repo)?;
            }
            fs.print_dumpfile()?;
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
        #[cfg(feature = "http")]
        Command::Fetch { url, name } => {
            let (digest, verity) = composefs_http::download(&url, &name, Arc::new(repo)).await?;
            println!("content {digest}");
            println!("verity {}", verity.to_hex());
        }
    }
    Ok(())
}
