//! Varlink RPC service for `cfsctl`.
//!
//! Exposes a subset of repository operations over a Unix-socket varlink
//! interface (`org.composefs.Repository`) so that integration tests and
//! external callers can consume structured replies instead of scraping the
//! human-oriented CLI output.
//!
//! Repositories are accessed through opaque `u64` handles: a client calls
//! `OpenRepository` to obtain a handle, passes it to every subsequent method,
//! and frees it with `CloseRepository`. No repository is opened at startup, so
//! every call must carry a handle. Each handle stores an already-opened
//! `Repository<ObjectID>` monomorphized over the digest algorithm detected at
//! open time, wrapped in an `Arc` so the streaming `Pull` method can move an
//! owned clone into its `'static` reply stream.
//!
//! The zlink server serializes `Service::handle` calls (a single task holds
//! one `&mut self` borrow at a time), so the handle table is a plain
//! `HashMap` with no interior locking.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use composefs::fsverity::{Algorithm, FsVerityHashValue, Sha256HashValue, Sha512HashValue};
use composefs::repository::{FsckResult, Repository, RepositoryConfig, system_path, user_path};
use rustix::fs::CWD;
use serde::{Deserialize, Serialize};

use crate::{App, HashType, open_repo_at, resolve_hash_type};

/// Result of a repository consistency check, mirrored for the varlink wire
/// format.
///
/// This is a flattened, snake_case projection of
/// [`composefs::repository::FsckResult`]; field names follow the varlink
/// convention rather than the camelCase used by the JSON CLI output.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct FsckReply {
    /// Whether the repository passed the integrity check with no errors.
    pub ok: bool,
    /// Whether the repository has a `meta.json` metadata file.
    pub has_metadata: bool,
    /// Number of objects whose fs-verity digests were verified.
    pub objects_checked: u64,
    /// Number of objects found to have a bad fs-verity digest.
    pub objects_corrupted: u64,
    /// Number of splitstreams verified.
    pub streams_checked: u64,
    /// Number of splitstreams with issues (bad header, missing refs, etc.).
    pub streams_corrupted: u64,
    /// Number of images verified.
    pub images_checked: u64,
    /// Number of images with issues.
    pub images_corrupted: u64,
    /// Number of broken symlinks found.
    pub broken_links: u64,
    /// Number of missing objects referenced by streams.
    pub missing_objects: u64,
    /// Human-readable descriptions of each error found.
    ///
    /// These are the `Display` rendering of the library's structured
    /// `FsckError` variants; they carry stable `fsck: <kind>:` prefixes.
    // TODO: expose the structured `FsckError` variants over the wire once a
    // varlink-friendly representation (e.g. a tagged struct) is settled on,
    // so clients can match on error kind instead of parsing strings.
    pub errors: Vec<String>,
}

impl From<&FsckResult> for FsckReply {
    fn from(result: &FsckResult) -> Self {
        Self {
            ok: result.is_ok(),
            has_metadata: result.has_metadata(),
            objects_checked: result.objects_checked(),
            objects_corrupted: result.objects_corrupted(),
            streams_checked: result.streams_checked(),
            streams_corrupted: result.streams_corrupted(),
            images_checked: result.images_checked(),
            images_corrupted: result.images_corrupted(),
            broken_links: result.broken_links(),
            missing_objects: result.missing_objects(),
            errors: result.errors().iter().map(|e| e.to_string()).collect(),
        }
    }
}

/// Result of a garbage-collection run for the varlink wire format.
///
/// Wraps the canonical [`composefs::repository::GcResult`] and adds the
/// `dry_run` flag (which the library type does not carry).
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct GcReply {
    /// What was (or would be) removed.
    pub result: composefs::repository::GcResult,
    /// Whether this was a dry run (no files actually deleted).
    pub dry_run: bool,
}

/// Reply listing the objects referenced by a single image.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct ImageObjectsReply {
    /// The fs-verity object IDs referenced by the image, sorted for
    /// deterministic output.
    pub object_ids: Vec<String>,
}

/// Errors that may be returned by the `org.composefs.Repository` interface.
#[derive(Debug, zlink::ReplyError, zlink::introspect::ReplyError)]
#[zlink(interface = "org.composefs.Repository")]
pub enum RepositoryError {
    /// The repository could not be found or opened at the configured path.
    RepoNotFound {
        /// Description of the failure.
        message: String,
    },
    /// The given handle does not refer to an open repository.
    InvalidHandle {
        /// The handle that was not found.
        handle: u64,
    },
    /// The request did not specify a valid repository selector.
    InvalidSpec {
        /// Description of the problem with the selector.
        message: String,
    },
    /// The named image/ref does not exist in the repository.
    NoSuchRef {
        /// The ref name that was not found.
        reference: String,
    },
    /// An unexpected internal error occurred while servicing the request.
    InternalError {
        /// Description of the failure.
        message: String,
    },
}

/// Reply carrying an opaque repository handle and basic repository metadata.
///
/// The `hash_algorithm` and `objects_device_id` fields let a client making a
/// cross-repository copy decide whether zero-copy (reflink / hardlink)
/// transfer is viable for a given source–destination pair:
///
/// * **`hash_algorithm`** — `"sha256"` or `"sha512"`. Hardlink (zero-copy)
///   requires both repositories to use the same algorithm, because fs-verity
///   is enabled on the *shared* inode. Reflink and regular copy work across
///   algorithms (each produces a fresh inode re-digested under the
///   destination's algorithm).
///
/// * **`objects_device_id`** — the `st_dev` of the repository's objects
///   directory. Both reflink (`FICLONE`) and hardlink (`linkat`) require
///   source and destination to reside on the same filesystem; comparing
///   `objects_device_id` from both sides lets the client detect this up front.
///   Note: `st_dev` is only meaningful when both servers share a mount
///   namespace (the typical same-host deployment). If they do not, the
///   worst case is a failed `PutLayer` (EXDEV), not silent data corruption.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct OpenRepositoryReply {
    /// The opaque handle to pass to subsequent repository methods.
    pub handle: u64,

    /// The fs-verity hash algorithm used by this repository (`"sha256"` or
    /// `"sha512"`).
    ///
    /// `None` on old servers that do not report this field (serde default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,

    /// The `st_dev` of the repository's objects directory, as a decimal u64.
    ///
    /// Clients comparing two repositories should treat matching values as
    /// "likely same filesystem" (and thus eligible for reflink/hardlink).
    /// `None` on old servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objects_device_id: Option<u64>,
}

/// Reply from initializing a repository.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct InitRepositoryReply {
    /// `true` if a new repository was created; `false` if one already existed
    /// at the requested path with the same algorithm (idempotent).
    pub created: bool,
}

/// An opened repository, monomorphized over its detected hash algorithm.
///
/// Stored as an [`Arc`] so streaming methods can clone an owned handle into a
/// `'static` reply stream without borrowing the service.
#[derive(Debug, Clone)]
pub(crate) enum OpenRepo {
    /// A repository using the SHA-256 digest algorithm.
    Sha256(Arc<Repository<Sha256HashValue>>),
    /// A repository using the SHA-512 digest algorithm.
    Sha512(Arc<Repository<Sha512HashValue>>),
}

impl OpenRepo {
    /// The fs-verity hash algorithm name for this repository.
    fn hash_algorithm(&self) -> &'static str {
        match self {
            OpenRepo::Sha256(_) => "sha256",
            OpenRepo::Sha512(_) => "sha512",
        }
    }

    /// The `st_dev` of the repository's objects directory, if available.
    fn objects_device_id(&self) -> Option<u64> {
        let stat_it = |fd: &std::os::fd::OwnedFd| -> Option<u64> {
            rustix::fs::fstat(fd).ok().map(|s| s.st_dev)
        };
        match self {
            OpenRepo::Sha256(r) => r.objects_dir().ok().and_then(stat_it),
            OpenRepo::Sha512(r) => r.objects_dir().ok().and_then(stat_it),
        }
    }
}

/// A single entry in the service's open-repository table.
#[derive(Debug)]
struct HandleEntry {
    /// The opened repository.
    repo: OpenRepo,
    /// Owning connection id, recorded for a future per-connection disconnect
    /// hook that will reclaim handles left open by a vanished client. `Option`
    /// to leave room for handles not tied to a specific connection.
    #[allow(dead_code)]
    owner: Option<usize>,
}

/// Process-wide repository open options, fixed at startup.
#[derive(Debug, Clone)]
struct OpenOptions {
    /// Open the repository in insecure (no verity required) mode.
    insecure: bool,
    /// Require fs-verity to be enabled on the repository.
    require_verity: bool,
    /// Skip auto-upgrading old-format repositories.
    no_upgrade: bool,
}

impl OpenOptions {
    /// Derive the open options from parsed CLI arguments.
    fn from_app(args: &App) -> Self {
        Self {
            insecure: args.insecure,
            require_verity: args.require_verity,
            no_upgrade: args.no_upgrade,
        }
    }
}

impl Default for OpenOptions {
    /// The uid-default open options used by the socket-activated entry point,
    /// which serves before CLI parsing and so has no `App` to consult.
    fn default() -> Self {
        Self {
            insecure: false,
            require_verity: false,
            no_upgrade: false,
        }
    }
}

/// Varlink service implementation backing the `org.composefs.Repository` (and,
/// with the `oci` feature, `org.composefs.Oci`) interfaces.
///
/// Holds a table of opened repositories keyed by opaque handle. The zlink
/// server serializes calls to a single service, so the table is a plain
/// `HashMap` with no interior locking.
#[derive(Debug)]
pub(crate) struct CfsctlService {
    /// Open repositories keyed by opaque handle.
    repos: HashMap<u64, HandleEntry>,
    /// Monotonically increasing handle counter; `0` is reserved as "none".
    next_handle: u64,
    /// Repository open options fixed at startup.
    open_opts: OpenOptions,
}

impl Default for CfsctlService {
    fn default() -> Self {
        Self::new()
    }
}

impl CfsctlService {
    /// Construct an empty service with the given repository open options.
    ///
    /// No repository is opened at startup: a client must explicitly select one
    /// with `OpenRepository` and pass the returned handle to every subsequent
    /// call.
    fn with_open_opts(open_opts: OpenOptions) -> Self {
        Self {
            repos: HashMap::new(),
            next_handle: 0,
            open_opts,
        }
    }

    /// Construct a service from parsed CLI arguments.
    ///
    /// The open flags (`--insecure`/`--require-verity`/`--no-upgrade`) carry
    /// into repositories opened later via `OpenRepository`; the repository
    /// selection flags (`--repo`/`--user`/`--system`) do not apply, since the
    /// varlink service opens repositories on demand rather than at startup.
    pub(crate) fn from_app(args: &App) -> Self {
        Self::with_open_opts(OpenOptions::from_app(args))
    }

    /// Construct a service for the socket-activated entry point, which serves
    /// before CLI parsing and so has no `App` to consult. Uses default open
    /// options; the client supplies repository paths via `OpenRepository`.
    pub(crate) fn activated() -> Self {
        Self::with_open_opts(OpenOptions::default())
    }

    /// Construct a service with default open options.
    pub(crate) fn new() -> Self {
        Self::with_open_opts(OpenOptions::default())
    }

    /// Construct an insecure service for in-process tests.
    ///
    /// The `insecure` flag disables fs-verity requirements so that tests can
    /// use repositories created on tmpfs or without verity support.
    #[cfg(test)]
    pub(crate) fn insecure_for_test() -> Self {
        Self::with_open_opts(OpenOptions {
            insecure: true,
            require_verity: false,
            no_upgrade: false,
        })
    }

    /// Allocate a fresh, never-reused handle. Starts at `1` (`0` is "none").
    fn next_handle(&mut self) -> u64 {
        self.next_handle += 1;
        self.next_handle
    }

    /// Look up an open repository by handle for the Repository interface.
    ///
    /// Returns an owned [`OpenRepo`] (a cheap `Arc` clone) so callers do not
    /// hold a borrow of `self` across the subsequent `.await`.
    fn lookup_repo(&self, handle: u64) -> std::result::Result<OpenRepo, RepositoryError> {
        self.repos
            .get(&handle)
            .map(|entry| entry.repo.clone())
            .ok_or(RepositoryError::InvalidHandle { handle })
    }

    /// Look up an open repository by handle for the OCI interface.
    ///
    /// Like [`Self::lookup_repo`] but reports the OCI-interface error so the
    /// wire error name is `org.composefs.Oci.InvalidHandle`.
    #[cfg(feature = "oci")]
    fn lookup_oci(&self, handle: u64) -> std::result::Result<OpenRepo, oci::OciError> {
        self.repos
            .get(&handle)
            .map(|entry| entry.repo.clone())
            .ok_or(oci::OciError::InvalidHandle { handle })
    }

    /// Resolve, open and register a repository at `path`, returning the reply
    /// with the handle and repository metadata.
    ///
    /// The digest algorithm is detected from the repository metadata; both
    /// resolution and open failures are reported as
    /// [`RepositoryError::RepoNotFound`].
    fn do_open(
        &mut self,
        path: &Path,
        owner: Option<usize>,
    ) -> std::result::Result<OpenRepositoryReply, RepositoryError> {
        let hash_type = resolve_hash_type(path, None, !self.open_opts.no_upgrade).map_err(|e| {
            RepositoryError::RepoNotFound {
                message: format!("{e:#}"),
            }
        })?;
        let repo = match hash_type {
            HashType::Sha256 => OpenRepo::Sha256(Arc::new(
                open_repo_at::<Sha256HashValue>(
                    path,
                    self.open_opts.insecure,
                    self.open_opts.require_verity,
                    self.open_opts.no_upgrade,
                )
                .map_err(|e| RepositoryError::RepoNotFound {
                    message: format!("{e:#}"),
                })?,
            )),
            HashType::Sha512 => OpenRepo::Sha512(Arc::new(
                open_repo_at::<Sha512HashValue>(
                    path,
                    self.open_opts.insecure,
                    self.open_opts.require_verity,
                    self.open_opts.no_upgrade,
                )
                .map_err(|e| RepositoryError::RepoNotFound {
                    message: format!("{e:#}"),
                })?,
            )),
        };
        let handle = self.next_handle();
        let hash_algorithm = Some(repo.hash_algorithm().to_string());
        let objects_device_id = repo.objects_device_id();
        self.repos.insert(handle, HandleEntry { repo, owner });
        Ok(OpenRepositoryReply {
            handle,
            hash_algorithm,
            objects_device_id,
        })
    }

    /// Resolve a repository selector (`path`/`user`/`system`) to a path.
    ///
    /// Exactly one of the three must be set; otherwise
    /// [`RepositoryError::InvalidSpec`] is returned.
    fn resolve_selector(
        path: Option<String>,
        user: Option<bool>,
        system: Option<bool>,
    ) -> std::result::Result<PathBuf, RepositoryError> {
        let user = user.unwrap_or(false);
        let system = system.unwrap_or(false);
        match (path, user, system) {
            (Some(p), false, false) => Ok(PathBuf::from(p)),
            (None, true, false) => user_path().map_err(|e| RepositoryError::InvalidSpec {
                message: format!("{e:#}"),
            }),
            (None, false, true) => Ok(system_path()),
            _ => Err(RepositoryError::InvalidSpec {
                message: "exactly one of `path`, `user`, `system` must be set".into(),
            }),
        }
    }
}

/// Open the repository and run an fsck.
async fn run_fsck<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    metadata_only: bool,
) -> std::result::Result<FsckResult, RepositoryError> {
    let result = if metadata_only {
        repo.fsck_metadata_only().await
    } else {
        repo.fsck().await
    };
    result.map_err(|e| RepositoryError::InternalError {
        message: format!("{e:#}"),
    })
}

/// Run garbage collection (or a dry run) on a repository.
async fn run_gc<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    dry_run: bool,
    roots: Vec<String>,
) -> std::result::Result<GcReply, RepositoryError> {
    let root_refs: Vec<&str> = roots.iter().map(String::as_str).collect();
    let result = if dry_run {
        repo.gc_dry_run(&root_refs)
    } else {
        repo.gc(&root_refs)
    }
    .map_err(|e| RepositoryError::InternalError {
        message: format!("{e:#}"),
    })?;
    Ok(GcReply { result, dry_run })
}

/// Collect the objects referenced by an image.
async fn run_image_objects<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: String,
) -> std::result::Result<ImageObjectsReply, RepositoryError> {
    let objects = repo.objects_for_image(&name).map_err(|e| {
        if let Some(nf) = e.downcast_ref::<composefs::ImageNotFound>() {
            RepositoryError::NoSuchRef {
                reference: nf.name.clone(),
            }
        } else {
            RepositoryError::InternalError {
                message: format!("{e:#}"),
            }
        }
    })?;
    let mut object_ids: Vec<String> = objects.iter().map(|id| id.to_id()).collect();
    object_ids.sort();
    Ok(ImageObjectsReply { object_ids })
}

/// A single image reference entry.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct ImageRefEntry {
    /// The reference name.
    pub name: String,
    /// The fs-verity digest the reference points to.
    pub digest: String,
}

/// Reply listing all named image references in the repository.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct ListImageRefsReply {
    /// The image references.
    pub images: Vec<ImageRefEntry>,
}

/// Collect all named image references from the repository.
pub fn run_list_image_refs<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
) -> std::result::Result<ListImageRefsReply, RepositoryError> {
    let refs = repo
        .list_image_refs("")
        .map_err(|e| RepositoryError::InternalError {
            message: format!("{e:#}"),
        })?;
    let images = refs
        .into_iter()
        .map(|(name, target)| {
            let digest = target.rsplit('/').next().unwrap_or(&target).to_string();
            ImageRefEntry { name, digest }
        })
        .collect();
    Ok(ListImageRefsReply { images })
}

/// Options for a `Mount` call. All fields are optional for forward
/// compatibility — new mount options can be added without breaking the
/// wire format.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, zlink::introspect::Type)]
pub struct MountParams {
    /// Whether to set up an overlayfs upper layer.
    /// When true, the fd array must contain two fds: upperdir and workdir.
    pub overlay: Option<bool>,
    /// Whether to mount read-write (only meaningful with overlay).
    pub read_write: Option<bool>,
}

impl MountParams {
    /// Build [`MountOptions`] from these params, consuming the expected fds.
    fn to_mount_options(
        &self,
        fds: Vec<std::os::fd::OwnedFd>,
    ) -> std::result::Result<composefs::mount::MountOptions, RepositoryError> {
        let overlay = self.overlay.unwrap_or(false);

        let mut expected_fds = 0;
        if overlay {
            expected_fds += 2;
        }

        if fds.len() != expected_fds {
            return Err(RepositoryError::InvalidSpec {
                message: format!(
                    "Mount expects {expected_fds} fds for the requested options, got {}",
                    fds.len()
                ),
            });
        }

        let mut options = composefs::mount::MountOptions::default();
        let mut fd_iter = fds.into_iter();
        if overlay {
            let upperdir = fd_iter.next().unwrap();
            let workdir = fd_iter.next().unwrap();
            options.set_overlay(upperdir, workdir);
        }
        options.set_read_write(self.read_write.unwrap_or(false));

        Ok(options)
    }
}

/// Reply for a `Mount` call — just an fd_index referencing the mount fd.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zlink::introspect::Type)]
pub struct MountReply {
    /// Index into the fd vector of the detached mount file descriptor.
    pub fd_index: u32,
}

fn run_mount<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
    params: &MountParams,
    fds: Vec<std::os::fd::OwnedFd>,
) -> std::result::Result<(MountReply, Vec<std::os::fd::OwnedFd>), RepositoryError> {
    let options = params.to_mount_options(fds)?;

    let mount_fd =
        repo.mount_with_options(name, &options)
            .map_err(|e| RepositoryError::InternalError {
                message: format!("{e:#}"),
            })?;

    Ok((MountReply { fd_index: 0 }, vec![mount_fd]))
}

#[cfg(feature = "oci")]
fn run_oci_mount<ObjectID: composefs::fsverity::FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    image: &str,
    bootable: bool,
    params: &MountParams,
    fds: Vec<std::os::fd::OwnedFd>,
) -> std::result::Result<(MountReply, Vec<std::os::fd::OwnedFd>), oci::OciError> {
    let img = if image.starts_with("sha256:") {
        let digest: composefs_oci::OciDigest =
            image.parse().map_err(|e| oci::OciError::InternalError {
                message: format!("Invalid manifest digest: {e}"),
            })?;
        composefs_oci::OciImage::open(repo, &digest, None)
    } else {
        composefs_oci::OciImage::open_ref(repo, image)
    }
    .map_err(|e| oci::OciError::NoSuchImage {
        image: format!("{image}: {e:#}"),
    })?;

    let erofs_id = if bootable {
        img.boot_image_ref(repo.erofs_version())
    } else {
        img.image_ref(repo.erofs_version())
    }
    .ok_or_else(|| oci::OciError::InternalError {
        message: if bootable {
            "No boot EROFS image linked".into()
        } else {
            "No composefs EROFS image linked".into()
        },
    })?;

    let options = params
        .to_mount_options(fds)
        .map_err(|e| oci::OciError::InternalError {
            message: format!("{e:?}"),
        })?;
    let mount_fd = repo
        .mount_with_options(&erofs_id.to_hex(), &options)
        .map_err(|e| oci::OciError::InternalError {
            message: format!("{e:#}"),
        })?;

    Ok((MountReply { fd_index: 0 }, vec![mount_fd]))
}

/// Initialize (or verify) a repository at `path` with the given algorithm.
///
/// Creates parent directories if needed, then delegates to
/// [`Repository::init_path`]. Returns `true` when a new repository was
/// created and `false` when an identical one already existed (idempotent).
/// A conflicting existing repository (different algorithm) is an error.
fn run_init_repository(
    path: &Path,
    algorithm: Algorithm,
    insecure: bool,
) -> std::result::Result<InitRepositoryReply, RepositoryError> {
    // Ensure parent directories exist (init_path only creates the final dir).
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| RepositoryError::InternalError {
            message: format!("creating parent directories for {}: {e:#}", path.display()),
        })?;
    }

    let created = match algorithm {
        Algorithm::Sha256 { .. } => {
            let config = if insecure {
                RepositoryConfig::new(algorithm).set_insecure()
            } else {
                RepositoryConfig::new(algorithm)
            };
            Repository::<Sha256HashValue>::init_path(CWD, path, config)
                .map_err(|e| RepositoryError::InternalError {
                    message: format!("{e:#}"),
                })?
                .1
        }
        Algorithm::Sha512 { .. } => {
            let config = if insecure {
                RepositoryConfig::new(algorithm).set_insecure()
            } else {
                RepositoryConfig::new(algorithm)
            };
            Repository::<Sha512HashValue>::init_path(CWD, path, config)
                .map_err(|e| RepositoryError::InternalError {
                    message: format!("{e:#}"),
                })?
                .1
        }
    };
    Ok(InitRepositoryReply { created })
}

/// OCI helper functions backing the `org.composefs.Oci` interface, gated behind
/// the `oci` feature.
#[cfg(feature = "oci")]
async fn run_list_images<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    filter: Option<String>,
) -> std::result::Result<Vec<oci::ImageEntry>, oci::OciError> {
    composefs_oci::oci_image::list_images(repo)
        .map(|imgs| {
            imgs.iter()
                .filter(|img| match &filter {
                    Some(needle) => img.name.contains(needle.as_str()),
                    None => true,
                })
                .map(oci::ImageEntry::from)
                .collect()
        })
        .map_err(|e| oci::OciError::InternalError {
            message: format!("{e:#}"),
        })
}

/// Run an OCI-aware consistency check on a repository.
///
/// When `image` is `Some`, only that tagged image is checked; otherwise all
/// tagged images are checked.
#[cfg(feature = "oci")]
async fn run_oci_fsck<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    image: Option<String>,
) -> std::result::Result<oci::OciFsckReply, oci::OciError> {
    let result = match image {
        Some(name) => composefs_oci::oci_fsck_image(repo, &name).await,
        None => composefs_oci::oci_fsck(repo).await,
    }
    .map_err(|e| oci::OciError::InternalError {
        message: format!("{e:#}"),
    })?;
    Ok(oci::OciFsckReply::from(&result))
}

/// Inspect a single OCI image.
#[cfg(feature = "oci")]
async fn run_inspect<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    image: String,
) -> std::result::Result<oci::OciInspectReply, oci::OciError> {
    let reference: crate::OciReference =
        image.parse().map_err(|e| oci::OciError::InternalError {
            message: format!("invalid image reference: {e:#}"),
        })?;
    let img = crate::resolve_oci_image(repo, &reference).map_err(|e| {
        if let Some(nf) = e.downcast_ref::<composefs_oci::OciRefNotFound>() {
            oci::OciError::NoSuchImage {
                image: nf.name.clone(),
            }
        } else if let Some(nf) = e.downcast_ref::<composefs_oci::OciImageNotFound>() {
            oci::OciError::NoSuchImage {
                image: nf.digest.clone(),
            }
        } else {
            oci::OciError::InternalError {
                message: format!("{e:#}"),
            }
        }
    })?;

    oci::OciInspectReply::from_image(repo, &img).map_err(|e| oci::OciError::InternalError {
        message: format!("{e:#}"),
    })
}

/// Tag a manifest digest with a name.
#[cfg(feature = "oci")]
async fn run_tag<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    manifest_digest: String,
    name: String,
) -> std::result::Result<(), oci::OciError> {
    let digest: composefs_oci::OciDigest =
        manifest_digest
            .parse()
            .map_err(|e| oci::OciError::InternalError {
                message: format!("invalid digest: {e}"),
            })?;
    composefs_oci::oci_image::tag_image(repo, &digest, &name).map_err(|e| {
        oci::OciError::InternalError {
            message: format!("{e:#}"),
        }
    })
}

/// Remove a tag.
#[cfg(feature = "oci")]
async fn run_untag<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: String,
) -> std::result::Result<(), oci::OciError> {
    composefs_oci::oci_image::untag_image(repo, &name).map_err(|e| oci::OciError::InternalError {
        message: format!("{e:#}"),
    })
}

/// Compute the composefs image ID for an OCI image.
///
/// Mirrors the CLI `compute-id` path: digest references (`@sha256:…`) use the
/// supplied `verity` override, while named refs derive both the config digest
/// and verity from the stored image metadata (ignoring `verity`).
#[cfg(feature = "oci")]
async fn run_compute_id<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    image: String,
    verity: Option<String>,
    bootable: bool,
) -> std::result::Result<oci::OciComputeIdReply, oci::OciError> {
    let reference: crate::OciReference =
        image.parse().map_err(|e| oci::OciError::InternalError {
            message: format!("invalid image reference: {e:#}"),
        })?;
    let verity_override =
        crate::verity_opt::<ObjectID>(&verity).map_err(|e| oci::OciError::InternalError {
            message: format!("invalid verity: {e:#}"),
        })?;
    let (config_digest, config_verity) =
        crate::resolve_oci_config(repo, &reference, verity_override).map_err(|e| {
            oci::OciError::InternalError {
                message: format!("{e:#}"),
            }
        })?;

    let mut fs =
        composefs_oci::image::create_filesystem(repo, &config_digest, config_verity.as_ref())
            .map_err(|e| oci::OciError::InternalError {
                message: format!("{e:#}"),
            })?;
    if bootable {
        use composefs_boot::BootOps as _;
        fs.transform_for_boot(repo)
            .map_err(|e| oci::OciError::InternalError {
                message: format!("{e:#}"),
            })?;
    }
    let id = fs.compute_image_id(repo.erofs_version());
    Ok(oci::OciComputeIdReply {
        image_id: id.to_hex(),
    })
}

// The `zlink::service` macro emits several `pub` helper enums (method dispatch,
// reply params, etc.) as siblings of the impl block. Those cannot be annotated
// individually, so the macro invocation lives in a dedicated private submodule
// where `missing_docs` is relaxed. The generated `Service` trait impl applies
// to `CfsctlService` regardless of the module it is written in.
//
// There are two variants of this module selected at compile time. The macro
// cannot cfg-gate individual methods (it doesn't propagate `#[cfg]`), and the
// dispatch enum derives its variants from wire method names (so both
// interfaces must live in ONE impl block). So when the `oci` feature is on we
// emit a single impl that hosts BOTH `org.composefs.Repository` and
// `org.composefs.Oci`; otherwise we emit a Repository-only impl.
//
// The interface attribute on each method is "sticky": once a method sets
// `interface = "org.composefs.Oci"` the macro keeps using it for subsequent
// methods until changed. The Repository methods come first and inherit the
// seeded `org.composefs.Repository` interface.
#[cfg(not(feature = "oci"))]
mod service_impl {
    #![allow(missing_docs)]

    use super::{
        CfsctlService, FsckReply, GcReply, ImageObjectsReply, InitRepositoryReply,
        ListImageRefsReply, MountParams, MountReply, OpenRepo, OpenRepositoryReply,
        RepositoryError, run_fsck, run_gc, run_image_objects, run_init_repository,
        run_list_image_refs, run_mount,
    };
    use composefs::fsverity::{Algorithm, Sha256HashValue, Sha512HashValue};

    #[zlink::service(
        interface = "org.composefs.Repository",
        vendor = "org.composefs",
        product = "cfsctl",
        version = env!("CARGO_PKG_VERSION"),
        url = "https://github.com/composefs/composefs-rs"
    )]
    impl<Sock> CfsctlService {
        /// Initialize a new repository at the given path, or verify that an
        /// existing one matches the requested algorithm (idempotent).
        ///
        /// Creates the directory (and any parents) if they do not exist.
        /// `algorithm` must be a valid fs-verity algorithm string such as
        /// `"fsverity-sha512-12"` (the default) or `"fsverity-sha256-12"`.
        /// When omitted the service default (`fsverity-sha512-12`) is used.
        /// The `insecure` flag mirrors `cfsctl init --insecure`: when `true`,
        /// fs-verity is not required on `meta.json`.
        async fn init_repository(
            &mut self,
            path: String,
            algorithm: Option<String>,
            insecure: Option<bool>,
        ) -> std::result::Result<InitRepositoryReply, RepositoryError> {
            let algorithm: Algorithm = algorithm
                .as_deref()
                .unwrap_or("fsverity-sha512-12")
                .parse()
                .map_err(|e| RepositoryError::InvalidSpec {
                    message: format!("invalid algorithm: {e}"),
                })?;
            let insecure = insecure.unwrap_or(self.open_opts.insecure);
            run_init_repository(std::path::Path::new(&path), algorithm, insecure)
        }

        /// Open and validate a repository, returning an opaque handle.
        ///
        /// Exactly one of `path`, `user`, `system` must be set.
        async fn open_repository(
            &mut self,
            path: Option<String>,
            user: Option<bool>,
            system: Option<bool>,
            #[zlink(connection)] conn: &mut zlink::Connection<Sock>,
        ) -> std::result::Result<OpenRepositoryReply, RepositoryError> {
            let selected = Self::resolve_selector(path, user, system)?;
            self.do_open(&selected, Some(conn.id()))
        }

        /// Close a previously opened repository handle.
        async fn close_repository(
            &mut self,
            handle: u64,
        ) -> std::result::Result<(), RepositoryError> {
            self.repos
                .remove(&handle)
                .map(|_| ())
                .ok_or(RepositoryError::InvalidHandle { handle })
        }

        /// Check repository integrity and return the structured result.
        ///
        /// When `metadata_only` is true, the expensive per-object fs-verity
        /// verification is skipped; only metadata and symlink structure are
        /// checked.
        async fn fsck(
            &self,
            handle: u64,
            metadata_only: Option<bool>,
        ) -> std::result::Result<FsckReply, RepositoryError> {
            let metadata_only = metadata_only.unwrap_or(false);
            let result = match self.lookup_repo(handle)? {
                OpenRepo::Sha256(ref r) => run_fsck::<Sha256HashValue>(r, metadata_only).await,
                OpenRepo::Sha512(ref r) => run_fsck::<Sha512HashValue>(r, metadata_only).await,
            }?;
            Ok(FsckReply::from(&result))
        }

        /// Run garbage collection (or a dry run) and return what was removed.
        async fn gc(
            &self,
            handle: u64,
            dry_run: bool,
            roots: Vec<String>,
        ) -> std::result::Result<GcReply, RepositoryError> {
            match self.lookup_repo(handle)? {
                OpenRepo::Sha256(ref r) => run_gc::<Sha256HashValue>(r, dry_run, roots).await,
                OpenRepo::Sha512(ref r) => run_gc::<Sha512HashValue>(r, dry_run, roots).await,
            }
        }

        /// List the objects referenced by a single image.
        async fn image_objects(
            &self,
            handle: u64,
            name: String,
        ) -> std::result::Result<ImageObjectsReply, RepositoryError> {
            match self.lookup_repo(handle)? {
                OpenRepo::Sha256(ref r) => run_image_objects::<Sha256HashValue>(r, name).await,
                OpenRepo::Sha512(ref r) => run_image_objects::<Sha512HashValue>(r, name).await,
            }
        }

        /// List all named image references in the repository.
        async fn list_image_refs(
            &self,
            handle: u64,
        ) -> std::result::Result<ListImageRefsReply, RepositoryError> {
            match self.lookup_repo(handle)? {
                OpenRepo::Sha256(ref r) => run_list_image_refs::<Sha256HashValue>(r),
                OpenRepo::Sha512(ref r) => run_list_image_refs::<Sha512HashValue>(r),
            }
        }

        /// Create a detached mount of an image and return the mount fd.
        ///
        /// If overlay upper/work directories are needed, pass them as two fds
        /// (upperdir, workdir) via SCM_RIGHTS. The returned fd is a detached
        /// mount that the caller can attach with `move_mount()`.
        #[zlink(return_fds)]
        async fn mount(
            &self,
            handle: u64,
            name: String,
            options: MountParams,
            #[zlink(fds)] fds: Vec<std::os::fd::OwnedFd>,
        ) -> (
            std::result::Result<MountReply, RepositoryError>,
            Vec<std::os::fd::OwnedFd>,
        ) {
            let result = match self.lookup_repo(handle) {
                Ok(OpenRepo::Sha256(ref r)) => {
                    run_mount::<Sha256HashValue>(r, &name, &options, fds)
                }
                Ok(OpenRepo::Sha512(ref r)) => {
                    run_mount::<Sha512HashValue>(r, &name, &options, fds)
                }
                Err(e) => Err(e),
            };
            match result {
                Ok((reply, fds)) => (Ok(reply), fds),
                Err(e) => (Err(e), vec![]),
            }
        }
    }
}

// Combined variant: hosts BOTH the `org.composefs.Repository` and
// `org.composefs.Oci` interfaces from a single impl block on `CfsctlService`,
// so one service answers both interfaces on one socket. See the comment above
// for why this can't be cfg-gated method-by-method.
#[cfg(feature = "oci")]
mod service_impl {
    #![allow(missing_docs)]

    use super::layer_sync::{
        FinalizeImageReply, GetInfoReply, GetLayerReply, HasLayerReply, LayerRef, PutLayerReply,
    };
    use super::oci::{
        ListImagesReply, OciComputeIdReply, OciError, OciFsckReply, OciInspectReply, PullProgress,
        parse_local_fetch, pull_stream,
    };
    use super::{
        CfsctlService, FsckReply, GcReply, ImageObjectsReply, InitRepositoryReply,
        ListImageRefsReply, MountParams, MountReply, OpenRepo, OpenRepositoryReply,
        RepositoryError, run_compute_id, run_fsck, run_gc, run_image_objects, run_init_repository,
        run_inspect, run_list_image_refs, run_list_images, run_mount, run_oci_fsck, run_oci_mount,
        run_tag, run_untag,
    };
    use composefs::fsverity::{Algorithm, FsVerityHashValue, Sha256HashValue, Sha512HashValue};
    use composefs_oci::layer_transport::{RepoLayerSource, serve_get_layer};
    use composefs_oci::varlink_types::GetLayerParams;
    use composefs_splitdirfdstream::seed_from_id;

    #[zlink::service(
        interface = "org.composefs.Repository",
        vendor = "org.composefs",
        product = "cfsctl",
        version = env!("CARGO_PKG_VERSION"),
        url = "https://github.com/composefs/composefs-rs"
    )]
    impl<Sock> CfsctlService {
        // --- org.composefs.Repository (inherits the seeded interface) ---

        /// Initialize a new repository at the given path, or verify that an
        /// existing one matches the requested algorithm (idempotent).
        ///
        /// Creates the directory (and any parents) if they do not exist.
        /// `algorithm` must be a valid fs-verity algorithm string such as
        /// `"fsverity-sha512-12"` (the default) or `"fsverity-sha256-12"`.
        /// When omitted the service default (`fsverity-sha512-12`) is used.
        /// The `insecure` flag mirrors `cfsctl init --insecure`: when `true`,
        /// fs-verity is not required on `meta.json`.
        async fn init_repository(
            &mut self,
            path: String,
            algorithm: Option<String>,
            insecure: Option<bool>,
        ) -> std::result::Result<InitRepositoryReply, RepositoryError> {
            let algorithm: Algorithm = algorithm
                .as_deref()
                .unwrap_or("fsverity-sha512-12")
                .parse()
                .map_err(|e| RepositoryError::InvalidSpec {
                    message: format!("invalid algorithm: {e}"),
                })?;
            let insecure = insecure.unwrap_or(self.open_opts.insecure);
            run_init_repository(std::path::Path::new(&path), algorithm, insecure)
        }

        /// Open and validate a repository, returning an opaque handle.
        ///
        /// Exactly one of `path`, `user`, `system` must be set.
        async fn open_repository(
            &mut self,
            path: Option<String>,
            user: Option<bool>,
            system: Option<bool>,
            #[zlink(connection)] conn: &mut zlink::Connection<Sock>,
        ) -> std::result::Result<OpenRepositoryReply, RepositoryError> {
            let selected = Self::resolve_selector(path, user, system)?;
            self.do_open(&selected, Some(conn.id()))
        }

        /// Close a previously opened repository handle.
        async fn close_repository(
            &mut self,
            handle: u64,
        ) -> std::result::Result<(), RepositoryError> {
            self.repos
                .remove(&handle)
                .map(|_| ())
                .ok_or(RepositoryError::InvalidHandle { handle })
        }

        /// Check repository integrity and return the structured result.
        ///
        /// When `metadata_only` is true, the expensive per-object fs-verity
        /// verification is skipped; only metadata and symlink structure are
        /// checked.
        async fn fsck(
            &self,
            handle: u64,
            metadata_only: Option<bool>,
        ) -> std::result::Result<FsckReply, RepositoryError> {
            let metadata_only = metadata_only.unwrap_or(false);
            let result = match self.lookup_repo(handle)? {
                OpenRepo::Sha256(ref r) => run_fsck::<Sha256HashValue>(r, metadata_only).await,
                OpenRepo::Sha512(ref r) => run_fsck::<Sha512HashValue>(r, metadata_only).await,
            }?;
            Ok(FsckReply::from(&result))
        }

        /// Run garbage collection (or a dry run) and return what was removed.
        async fn gc(
            &self,
            handle: u64,
            dry_run: bool,
            roots: Vec<String>,
        ) -> std::result::Result<GcReply, RepositoryError> {
            match self.lookup_repo(handle)? {
                OpenRepo::Sha256(ref r) => run_gc::<Sha256HashValue>(r, dry_run, roots).await,
                OpenRepo::Sha512(ref r) => run_gc::<Sha512HashValue>(r, dry_run, roots).await,
            }
        }

        /// List the objects referenced by a single image.
        async fn image_objects(
            &self,
            handle: u64,
            name: String,
        ) -> std::result::Result<ImageObjectsReply, RepositoryError> {
            match self.lookup_repo(handle)? {
                OpenRepo::Sha256(ref r) => run_image_objects::<Sha256HashValue>(r, name).await,
                OpenRepo::Sha512(ref r) => run_image_objects::<Sha512HashValue>(r, name).await,
            }
        }

        /// List all named image references in the repository.
        async fn list_image_refs(
            &self,
            handle: u64,
        ) -> std::result::Result<ListImageRefsReply, RepositoryError> {
            match self.lookup_repo(handle)? {
                OpenRepo::Sha256(ref r) => run_list_image_refs::<Sha256HashValue>(r),
                OpenRepo::Sha512(ref r) => run_list_image_refs::<Sha512HashValue>(r),
            }
        }

        /// Create a detached mount of an image and return the mount fd.
        ///
        /// If overlay upper/work directories are needed, pass them as two fds
        /// (upperdir, workdir) via SCM_RIGHTS. The returned fd is a detached
        /// mount that the caller can attach with `move_mount()`.
        #[zlink(return_fds)]
        async fn mount(
            &self,
            handle: u64,
            name: String,
            options: MountParams,
            #[zlink(fds)] fds: Vec<std::os::fd::OwnedFd>,
        ) -> (
            std::result::Result<MountReply, RepositoryError>,
            Vec<std::os::fd::OwnedFd>,
        ) {
            let result = match self.lookup_repo(handle) {
                Ok(OpenRepo::Sha256(ref r)) => {
                    run_mount::<Sha256HashValue>(r, &name, &options, fds)
                }
                Ok(OpenRepo::Sha512(ref r)) => {
                    run_mount::<Sha512HashValue>(r, &name, &options, fds)
                }
                Err(e) => Err(e),
            };
            match result {
                Ok((reply, fds)) => (Ok(reply), fds),
                Err(e) => (Err(e), vec![]),
            }
        }

        // --- org.composefs.Oci ---
        //
        // The first OCI method sets `interface = "org.composefs.Oci"`; the
        // macro then keeps that interface sticky for subsequent methods. Each
        // OCI method is still annotated explicitly for clarity.

        /// List tagged OCI images in the repository.
        ///
        /// When `filter` is given, only images whose name contains that
        /// substring are returned.
        #[zlink(interface = "org.composefs.Oci")]
        async fn list_images(
            &self,
            handle: u64,
            filter: Option<String>,
        ) -> std::result::Result<ListImagesReply, OciError> {
            let images = match self.lookup_oci(handle)? {
                OpenRepo::Sha256(ref r) => run_list_images::<Sha256HashValue>(r, filter).await,
                OpenRepo::Sha512(ref r) => run_list_images::<Sha512HashValue>(r, filter).await,
            }?;
            Ok(ListImagesReply { images })
        }

        /// Run an OCI-aware consistency check on the repository.
        ///
        /// Renamed on the wire to `Check` so it does not collide with the
        /// repository-level `Fsck` method (the dispatch enum keys on the wire
        /// method name, which must be globally unique across both interfaces).
        #[zlink(interface = "org.composefs.Oci", rename = "Check")]
        async fn oci_fsck(
            &self,
            handle: u64,
            image: Option<String>,
        ) -> std::result::Result<OciFsckReply, OciError> {
            match self.lookup_oci(handle)? {
                OpenRepo::Sha256(ref r) => run_oci_fsck::<Sha256HashValue>(r, image).await,
                OpenRepo::Sha512(ref r) => run_oci_fsck::<Sha512HashValue>(r, image).await,
            }
        }

        /// Inspect a single OCI image.
        #[zlink(interface = "org.composefs.Oci")]
        async fn inspect(
            &self,
            handle: u64,
            image: String,
        ) -> std::result::Result<OciInspectReply, OciError> {
            match self.lookup_oci(handle)? {
                OpenRepo::Sha256(ref r) => run_inspect::<Sha256HashValue>(r, image).await,
                OpenRepo::Sha512(ref r) => run_inspect::<Sha512HashValue>(r, image).await,
            }
        }

        /// Tag a manifest digest with a name.
        #[zlink(interface = "org.composefs.Oci")]
        async fn tag(
            &self,
            handle: u64,
            manifest_digest: String,
            name: String,
        ) -> std::result::Result<(), OciError> {
            match self.lookup_oci(handle)? {
                OpenRepo::Sha256(ref r) => {
                    run_tag::<Sha256HashValue>(r, manifest_digest, name).await
                }
                OpenRepo::Sha512(ref r) => {
                    run_tag::<Sha512HashValue>(r, manifest_digest, name).await
                }
            }
        }

        /// Remove a tag.
        #[zlink(interface = "org.composefs.Oci")]
        async fn untag(&self, handle: u64, name: String) -> std::result::Result<(), OciError> {
            match self.lookup_oci(handle)? {
                OpenRepo::Sha256(ref r) => run_untag::<Sha256HashValue>(r, name).await,
                OpenRepo::Sha512(ref r) => run_untag::<Sha512HashValue>(r, name).await,
            }
        }

        /// Compute the composefs image ID for an OCI image.
        #[zlink(interface = "org.composefs.Oci")]
        async fn compute_id(
            &self,
            handle: u64,
            image: String,
            verity: Option<String>,
            bootable: bool,
        ) -> std::result::Result<OciComputeIdReply, OciError> {
            match self.lookup_oci(handle)? {
                OpenRepo::Sha256(ref r) => {
                    run_compute_id::<Sha256HashValue>(r, image, verity, bootable).await
                }
                OpenRepo::Sha512(ref r) => {
                    run_compute_id::<Sha512HashValue>(r, image, verity, bootable).await
                }
            }
        }

        /// Pull an OCI image into the repository, streaming progress.
        ///
        /// Emits zero or more intermediate [`PullProgress`] frames describing
        /// fetch progress (only when `more` is true), followed by exactly one
        /// terminal frame whose `completed` field is set, carrying the pull result.
        #[zlink(interface = "org.composefs.Oci", more)]
        #[allow(clippy::too_many_arguments)]
        async fn pull(
            &self,
            more: bool,
            handle: u64,
            image: String,
            name: Option<String>,
            local_fetch: String,
            storage_root: Option<String>,
            bootable: bool,
        ) -> impl zlink::futures_util::Stream<
            Item = std::result::Result<zlink::Reply<PullProgress>, OciError>,
        > {
            let lf = parse_local_fetch(&local_fetch);
            let sr = storage_root.map(std::path::PathBuf::from);
            // Resolve the handle synchronously and clone an owned Arc out so the
            // returned stream owns everything it needs ('static). On a missing
            // handle, yield a one-shot error stream (`pull_stream` and the
            // error path share the same boxed-trait-object return type).
            match self.repos.get(&handle).map(|entry| &entry.repo) {
                Some(OpenRepo::Sha256(r)) => {
                    pull_stream::<Sha256HashValue>(r.clone(), image, name, lf, sr, bootable, more)
                }
                Some(OpenRepo::Sha512(r)) => {
                    pull_stream::<Sha512HashValue>(r.clone(), image, name, lf, sr, bootable, more)
                }
                None => {
                    use zlink::futures_util::stream;
                    Box::pin(stream::once(async move {
                        Err(OciError::InvalidHandle { handle })
                    }))
                }
            }
        }

        /// Mount an OCI image and return the detached mount fd.
        ///
        /// Resolves the image by ref name or `sha256:` digest, finds its
        /// EROFS image (or boot variant if `bootable` is true), and creates
        /// a composefs mount. If `options.overlay` is true, the fd array
        /// must contain upperdir and workdir fds.
        #[zlink(interface = "org.composefs.Oci", return_fds)]
        async fn oci_mount(
            &self,
            handle: u64,
            image: String,
            bootable: bool,
            options: MountParams,
            #[zlink(fds)] fds: Vec<std::os::fd::OwnedFd>,
        ) -> (
            std::result::Result<MountReply, OciError>,
            Vec<std::os::fd::OwnedFd>,
        ) {
            let result = match self.lookup_oci(handle) {
                Ok(OpenRepo::Sha256(ref r)) => {
                    run_oci_mount::<Sha256HashValue>(r, &image, bootable, &options, fds)
                }
                Ok(OpenRepo::Sha512(ref r)) => {
                    run_oci_mount::<Sha512HashValue>(r, &image, bootable, &options, fds)
                }
                Err(e) => Err(e),
            };
            match result {
                Ok((reply, fds)) => (Ok(reply), fds),
                Err(e) => (Err(e), vec![]),
            }
        }

        // --- org.composefs.Oci (layer-sync methods) ---
        //
        // These methods were previously under org.composefs.LayerSync but have
        // been folded into the Oci interface. Each carries an explicit `interface`
        // annotation so the wire names land under the correct interface namespace.

        /// Return the capability tokens supported by this service.
        ///
        /// Currently advertises `"splitdirfdstream-v0"`.
        #[zlink(interface = "org.composefs.Oci")]
        async fn get_info(&self) -> std::result::Result<GetInfoReply, OciError> {
            Ok(GetInfoReply {
                features: vec!["splitdirfdstream-v0".into()],
            })
        }

        /// Check whether the layer splitstream for `diff_id` is present.
        ///
        /// Returns `present = true` and the hex verity if found; `present =
        /// false` and `layer_verity = None` if not.
        #[zlink(interface = "org.composefs.Oci")]
        async fn has_layer(
            &self,
            handle: u64,
            diff_id: String,
        ) -> std::result::Result<HasLayerReply, OciError> {
            let diff_id_parsed: composefs_oci::OciDigest =
                diff_id.parse().map_err(|e| OciError::InvalidDigest {
                    message: format!("{e}"),
                })?;
            let content_id = composefs_oci::layer_content_id(&diff_id_parsed);

            fn check<ObjectID: FsVerityHashValue>(
                repo: &composefs::repository::Repository<ObjectID>,
                content_id: &str,
            ) -> std::result::Result<HasLayerReply, OciError> {
                match repo
                    .has_stream(content_id)
                    .map_err(|e| OciError::InternalError {
                        message: format!("{e:#}"),
                    })? {
                    Some(verity) => Ok(HasLayerReply {
                        present: true,
                        layer_verity: Some(verity.to_hex()),
                    }),
                    None => Ok(HasLayerReply {
                        present: false,
                        layer_verity: None,
                    }),
                }
            }

            match self.lookup_oci(handle)? {
                OpenRepo::Sha256(ref r) => check::<Sha256HashValue>(r, &content_id),
                OpenRepo::Sha512(ref r) => check::<Sha512HashValue>(r, &content_id),
            }
        }

        /// Stream the layer as a `splitdirfdstream` over a pipe, with the full
        /// hardened streaming fd-transport contract.
        ///
        /// This is a **streaming** method (`more`): it yields multiple frames,
        /// each carrying a batch of FDs.  The client must concatenate FD batches
        /// from all frames to reconstruct the logical array:
        ///
        /// ```text
        /// [ pipe_read | <dirfds region: dir_count fds> | <lifetime fds: keepalive + extras> ]
        /// ```
        ///
        /// The dirfds region uses sparse placement (hash-determined slot assignment);
        /// lifetime fds are opaque tokens the client must hold until done reading.
        ///
        /// **Non-streaming** (`more=false`): all fds in a single frame; returns
        /// `FdLimitExceeded` if the total exceeds `MAX_FDS_PER_FRAME` (retry with
        /// `more=true`).
        ///
        /// The producer runs on `spawn_blocking` so the async task is never blocked.
        /// For the repo case there is no external lock to release, so `keepalive_read`
        /// is moved into the producer closure and dropped when the producer finishes.
        #[zlink(interface = "org.composefs.Oci", more, return_fds)]
        async fn get_layer(
            &self,
            more: bool,
            handle: u64,
            params: GetLayerParams,
            #[zlink(fds)] _fds: Vec<std::os::fd::OwnedFd>,
        ) -> impl zlink::futures_util::Stream<
            Item = (
                std::result::Result<zlink::Reply<GetLayerReply>, OciError>,
                Vec<std::os::fd::OwnedFd>,
            ),
        > + Unpin {
            use zlink::futures_util::stream::{self, StreamExt as _};

            type StreamItem = (
                std::result::Result<zlink::Reply<GetLayerReply>, OciError>,
                Vec<std::os::fd::OwnedFd>,
            );

            macro_rules! err_stream {
                ($e:expr) => {
                    return stream::iter(std::iter::once::<StreamItem>((Err($e), vec![])))
                        .left_stream()
                };
            }

            // ── Extract diff_id from params (repo service requires it) ─────────
            let diff_id = match params.diff_id {
                Some(d) => d,
                None => err_stream!(OciError::InvalidRequest {
                    message: "GetLayer: diff_id is required for the repo service".into(),
                }),
            };

            // ── Parse diff_id ─────────────────────────────────────────────────
            let diff_id_parsed: composefs_oci::OciDigest = match diff_id.parse() {
                Ok(d) => d,
                Err(e) => err_stream!(OciError::InvalidDigest {
                    message: format!("{e}"),
                }),
            };
            let content_id = composefs_oci::layer_content_id(&diff_id_parsed);

            // ── Drive serve_get_layer via the LayerSource trait ───────────────
            fn do_serve_get_layer<ObjectID: FsVerityHashValue>(
                repo: &std::sync::Arc<composefs::repository::Repository<ObjectID>>,
                content_id: &str,
                diff_id_str: &str,
                more: bool,
            ) -> std::result::Result<composefs_oci::layer_transport::GetLayerFrames, OciError>
            {
                let verity = repo
                    .has_stream(content_id)
                    .map_err(|e| OciError::InternalError {
                        message: format!("{e:#}"),
                    })?
                    .ok_or_else(|| OciError::NoSuchLayer {
                        diff_id: diff_id_str.to_string(),
                    })?;

                let seed = seed_from_id(content_id);
                let source = RepoLayerSource {
                    repo: repo.clone(),
                    layer_verity: verity,
                };

                serve_get_layer(source, seed, more).map_err(|e| match e {
                    composefs_oci::layer_transport::ServeGetLayerError::FdLimitExceeded(e) => {
                        OciError::FdLimitExceeded {
                            fd_count: e.fd_count as u64,
                            max_per_frame: e.max_per_frame as u64,
                        }
                    }
                    composefs_oci::layer_transport::ServeGetLayerError::Other(e) => {
                        OciError::InternalError {
                            message: format!("{e:#}"),
                        }
                    }
                })
            }

            let frames = match self.lookup_oci(handle) {
                Ok(OpenRepo::Sha256(ref r)) => {
                    do_serve_get_layer::<Sha256HashValue>(r, &content_id, &diff_id, more)
                }
                Ok(OpenRepo::Sha512(ref r)) => {
                    do_serve_get_layer::<Sha512HashValue>(r, &content_id, &diff_id, more)
                }
                Err(e) => Err(e),
            };

            let frames = match frames {
                Ok(f) => f,
                Err(e) => err_stream!(e),
            };

            let dir_count = frames.dir_count;
            let batches = frames.batches;
            let n_frames = batches.len();
            let reply = GetLayerReply { dir_count };

            stream::iter(batches.into_iter().enumerate().map(move |(i, batch)| {
                let is_last = i == n_frames - 1;
                (
                    Ok(zlink::Reply::new(Some(reply.clone())).set_continues(Some(!is_last))),
                    batch,
                )
            }))
            .right_stream()
        }

        /// Receive a layer as a `splitdirfdstream` from the client and import
        /// it into the server's repository, verifying content integrity.
        ///
        /// The client supplies:
        /// * `fds[0]` — read end of a pipe carrying the `splitdirfdstream` bytes.
        /// * `fds[1..]` — source object directories (the splitdirfdstream's
        ///   `dirfd_index` selects among them; objects dir is index 0).
        ///
        /// The server runs the verified drain on a `spawn_blocking` thread so the
        /// async task is not blocked while data flows through the pipe.  The layer
        /// content is only committed if its reconstructed sha256 matches `diff_id`;
        /// on mismatch [`OciError::DiffIdMismatch`] is returned and no stream
        /// is committed.
        ///
        /// The server always drains the pipe to avoid wedging the client's writer
        /// even if the layer is already present — the import is idempotent.
        #[zlink(interface = "org.composefs.Oci")]
        async fn put_layer(
            &self,
            handle: u64,
            diff_id: String,
            zerocopy: bool,
            #[zlink(fds)] fds: Vec<std::os::fd::OwnedFd>,
        ) -> std::result::Result<PutLayerReply, OciError> {
            // Validate the fd count: fds[0] = pipe read, fds[1..] = dir fds.
            if fds.len() < 2 {
                return Err(OciError::InvalidRequest {
                    message: format!(
                        "expected at least 2 fds (1 pipe + >=1 dir fd), got {}",
                        fds.len()
                    ),
                });
            }

            let diff_id_parsed: composefs_oci::OciDigest =
                diff_id.parse().map_err(|e| OciError::InvalidDigest {
                    message: format!("{e}"),
                })?;

            let content_id = composefs_oci::layer_content_id(&diff_id_parsed);

            // Check whether the layer is already present (for the reply flag).
            // We still proceed with the drain regardless to avoid wedging the
            // client's writer if it is already producing.
            let already_present = match self.lookup_oci(handle)? {
                OpenRepo::Sha256(ref r) => r
                    .has_stream(&content_id)
                    .map_err(|e| OciError::InternalError {
                        message: format!("{e:#}"),
                    })?
                    .is_some(),
                OpenRepo::Sha512(ref r) => r
                    .has_stream(&content_id)
                    .map_err(|e| OciError::InternalError {
                        message: format!("{e:#}"),
                    })?
                    .is_some(),
            };

            // Split fds: pipe_read + dir_fds.
            let mut fds = fds;
            let pipe_read = fds.remove(0);
            let dir_fds = fds; // remaining fds are the dir fds

            async fn run_put_layer<ObjectID: FsVerityHashValue>(
                repo: std::sync::Arc<composefs::repository::Repository<ObjectID>>,
                pipe_read: std::os::fd::OwnedFd,
                dir_fds: Vec<std::os::fd::OwnedFd>,
                diff_id: composefs_oci::OciDigest,
                zerocopy: bool,
                already_present: bool,
            ) -> std::result::Result<PutLayerReply, OciError> {
                tokio::task::spawn_blocking(move || {
                    composefs_oci::layer_sync::drain_splitdirfdstream_verified(
                        repo,
                        pipe_read,
                        dir_fds,
                        &diff_id,
                        zerocopy,
                        composefs::repository::ImportContext::default(),
                    )
                })
                .await
                .map_err(|e| OciError::InternalError {
                    message: format!("spawn_blocking panic: {e}"),
                })?
                .map(|(verity, stats, _ctx)| PutLayerReply {
                    layer_verity: verity.to_hex(),
                    already_present,
                    objects_reflinked: stats.objects_reflinked,
                    objects_hardlinked: stats.objects_hardlinked,
                    objects_copied: stats.objects_copied,
                    objects_already_present: stats.objects_already_present,
                })
                .map_err(|e| match e {
                    composefs_oci::layer_sync::VerifiedDrainError::DiffIdMismatch {
                        expected,
                        actual,
                    } => OciError::DiffIdMismatch { expected, actual },
                    composefs_oci::layer_sync::VerifiedDrainError::Other(err) => {
                        OciError::InternalError {
                            message: format!("{err:#}"),
                        }
                    }
                })
            }

            match self.lookup_oci(handle)? {
                OpenRepo::Sha256(ref r) => {
                    run_put_layer::<Sha256HashValue>(
                        r.clone(),
                        pipe_read,
                        dir_fds,
                        diff_id_parsed,
                        zerocopy,
                        already_present,
                    )
                    .await
                }
                OpenRepo::Sha512(ref r) => {
                    run_put_layer::<Sha512HashValue>(
                        r.clone(),
                        pipe_read,
                        dir_fds,
                        diff_id_parsed,
                        zerocopy,
                        already_present,
                    )
                    .await
                }
            }
        }

        /// Finalize an OCI image after all layers have been imported.
        ///
        /// Given the raw manifest and config JSON bytes and the ordered list of
        /// `(diff_id, layer_verity)` pairs (as returned by `PutLayer`), this
        /// method writes the config and manifest splitstreams, generates the
        /// composefs EROFS image, and optionally tags the manifest. Idempotent.
        ///
        /// Returns the digest and verity strings for both the manifest and config
        /// splitstreams.
        #[zlink(interface = "org.composefs.Oci")]
        async fn finalize_image(
            &self,
            handle: u64,
            manifest_json: String,
            config_json: String,
            layers: Vec<LayerRef>,
            name: Option<String>,
        ) -> std::result::Result<FinalizeImageReply, OciError> {
            async fn run_finalize<ObjectID: FsVerityHashValue>(
                repo: std::sync::Arc<composefs::repository::Repository<ObjectID>>,
                manifest_json: String,
                config_json: String,
                layers: Vec<LayerRef>,
                name: Option<String>,
            ) -> std::result::Result<FinalizeImageReply, OciError> {
                // Parse each LayerRef into (OciDigest, ObjectID).
                let mut layer_refs: Vec<(composefs_oci::OciDigest, ObjectID)> =
                    Vec::with_capacity(layers.len());
                for lr in &layers {
                    let diff_id: composefs_oci::OciDigest =
                        lr.diff_id.parse().map_err(|e| OciError::InvalidDigest {
                            message: format!("diff_id {:?}: {e}", lr.diff_id),
                        })?;
                    let verity = ObjectID::from_hex(&lr.layer_verity).map_err(|e| {
                        OciError::InvalidDigest {
                            message: format!("layer_verity {:?}: {e}", lr.layer_verity),
                        }
                    })?;
                    layer_refs.push((diff_id, verity));
                }

                tokio::task::spawn_blocking(move || {
                    composefs_oci::layer_sync::finalize_oci_image(
                        &repo,
                        manifest_json.as_bytes(),
                        config_json.as_bytes(),
                        &layer_refs,
                        name.as_deref(),
                    )
                })
                .await
                .map_err(|e| OciError::InternalError {
                    message: format!("spawn_blocking panic: {e}"),
                })?
                .map(
                    |((manifest_digest, manifest_verity), (config_digest, config_verity))| {
                        FinalizeImageReply {
                            manifest_digest: manifest_digest.to_string(),
                            manifest_verity: manifest_verity.to_hex(),
                            config_digest: config_digest.to_string(),
                            config_verity: config_verity.to_hex(),
                        }
                    },
                )
                .map_err(|e| OciError::InternalError {
                    message: format!("{e:#}"),
                })
            }

            match self.lookup_oci(handle)? {
                OpenRepo::Sha256(ref r) => {
                    run_finalize::<Sha256HashValue>(
                        r.clone(),
                        manifest_json,
                        config_json,
                        layers,
                        name,
                    )
                    .await
                }
                OpenRepo::Sha512(ref r) => {
                    run_finalize::<Sha512HashValue>(
                        r.clone(),
                        manifest_json,
                        config_json,
                        layers,
                        name,
                    )
                    .await
                }
            }
        }
    }
}

/// A `Listener` that yields a single pre-connected socket, then blocks forever.
///
/// Used for socket activation where a connected socket pair is
/// passed on fd 3. After the first `accept()` returns the connection, subsequent
/// calls pend indefinitely (the server will be killed by the parent process once
/// the connection closes).
#[derive(Debug)]
pub(crate) struct ActivatedListener {
    /// The connection to yield on the first accept(), consumed after use.
    conn: Option<zlink::Connection<zlink::unix::Stream>>,
}

impl zlink::Listener for ActivatedListener {
    type Socket = zlink::unix::Stream;

    async fn accept(&mut self) -> zlink::Result<Option<zlink::Connection<Self::Socket>>> {
        match self.conn.take() {
            Some(conn) => Ok(Some(conn)),
            None => std::future::pending().await,
        }
    }
}

/// An inherited socket-activation fd, classified by its listening state.
pub(crate) enum ActivatedSocket {
    /// A pre-connected stream (`varlinkctl exec:` transport): one connection
    /// on fd 3. Served via [`ActivatedListener`].
    Connected(ActivatedListener),
    /// A listening socket (systemd `.socket` with `Accept=no`, or the test
    /// harness): served with a normal accept loop.
    Listening(zlink::unix::Listener),
}

/// Try to classify a socket-activation fd inherited from the service manager.
///
/// Uses `libsystemd` to receive file descriptors (checks `LISTEN_FDS`/
/// `LISTEN_PID` and clears the env vars). Returns `None` when the process
/// was not socket-activated.
///
/// When a fd is present its socket type is inspected via `SO_ACCEPTCONN`:
/// - **Listening**: the fd is a bound, listening socket (e.g. passed by the
///   test harness or a systemd `.socket` unit with `Accept=no`) — wrapped as
///   [`ActivatedSocket::Listening`].
/// - **Connected**: the fd is an already-connected stream (e.g. `varlinkctl
///   exec:`) — wrapped as [`ActivatedSocket::Connected`].
#[allow(unsafe_code)]
pub(crate) fn try_activated_listener() -> Result<Option<ActivatedSocket>> {
    use std::os::fd::{FromRawFd as _, IntoRawFd as _, OwnedFd};

    let fds = libsystemd::activation::receive_descriptors(true)
        .map_err(|e| anyhow::anyhow!("Failed to receive activation fds: {e}"))?;

    let fd = match fds.into_iter().next() {
        Some(fd) => fd,
        None => return Ok(None),
    };

    // SAFETY: `receive_descriptors` validated the fd and transferred ownership
    // via `IntoRawFd`.  We immediately re-wrap the raw integer as an `OwnedFd`
    // so that Rust's ownership rules track the fd from this point forward.
    let owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(fd.into_raw_fd()) };

    // Query SO_ACCEPTCONN to distinguish a pre-connected stream (varlinkctl
    // `exec:`) from a listening socket (systemd socket unit / test harness).
    let is_listening = rustix::net::sockopt::socket_acceptconn(&owned)
        .context("querying SO_ACCEPTCONN on activation fd")?;

    if is_listening {
        // The fd is a bound, listening Unix socket.  Hand it to zlink's
        // Listener adapter, which calls set_nonblocking and wraps it in tokio.
        let listener = zlink::unix::Listener::try_from(owned)
            .context("converting listening activation fd to zlink Listener")?;
        Ok(Some(ActivatedSocket::Listening(listener)))
    } else {
        // The fd is an already-connected stream (e.g. varlinkctl exec:).
        // `From<OwnedFd>` for `UnixStream` is safe — ownership is transferred.
        let std_stream = std::os::unix::net::UnixStream::from(owned);
        std_stream
            .set_nonblocking(true)
            .context("setting systemd socket to non-blocking")?;
        let tokio_stream = tokio::net::UnixStream::from_std(std_stream)
            .context("converting systemd UnixStream to tokio")?;
        let zlink_stream =
            zlink::unix::Stream::try_from(tokio_stream).map_err(|e| anyhow::anyhow!(e))?;
        let conn = zlink::Connection::new(zlink_stream);
        Ok(Some(ActivatedSocket::Connected(ActivatedListener {
            conn: Some(conn),
        })))
    }
}

/// Serve `service` on an already-obtained socket-activated connected listener.
///
/// Status is logged, never written to stdout: under socket activation (e.g.
/// varlinkctl's `exec:` transport) the parent may treat our stdout as part of
/// the protocol handshake, and any stray bytes there reset the connection.
///
/// The server loop runs inside a [`tokio::task::LocalSet`] so request handlers
/// can `spawn_local` `!Send` work (see [`pull_stream`]).  Both serve paths
/// wrap exactly one `LocalSet`.
pub(crate) async fn serve_activated<S>(service: S, listener: ActivatedListener) -> Result<()>
where
    S: zlink::Service<zlink::unix::Stream>,
{
    log::info!("Listening on systemd-activated socket");
    let server = zlink::Server::new(listener, service);
    tokio::task::LocalSet::new()
        .run_until(server.run())
        .await
        .context("running varlink server (activated)")
}

/// Serve `service` on a listening [`zlink::unix::Listener`] inside a
/// [`tokio::task::LocalSet`].
///
/// Used for both the socket-activated listening fd path and the normal
/// `bind`-a-fresh-socket path (see [`serve`]).
pub(crate) async fn serve_on_listener<S>(service: S, listener: zlink::unix::Listener) -> Result<()>
where
    S: zlink::Service<zlink::unix::Stream>,
{
    let server = zlink::Server::new(listener, service);
    tokio::task::LocalSet::new()
        .run_until(server.run())
        .await
        .context("running varlink server")
}

/// Serve `service` on the appropriate socket, auto-detecting the source.
///
/// Resolution order:
/// 1. A socket-activation fd inherited from the service manager:
///    - If listening (`SO_ACCEPTCONN`): serve with a normal accept loop.
///    - If connected (`varlinkctl exec:`): serve single-shot.
/// 2. A freshly bound socket at `address` (which must be `Some`).
pub(crate) async fn serve<S>(service: S, address: Option<&Path>) -> Result<()>
where
    S: zlink::Service<zlink::unix::Stream>,
{
    match try_activated_listener()? {
        Some(ActivatedSocket::Connected(l)) => return serve_activated(service, l).await,
        Some(ActivatedSocket::Listening(listener)) => {
            log::info!("Listening on systemd-activated socket");
            return serve_on_listener(service, listener).await;
        }
        None => {}
    }
    let address = address.context("no --address given and not socket-activated")?;
    let listener = zlink::unix::bind(address)
        .with_context(|| format!("binding varlink socket at {}", address.display()))?;
    log::info!("Listening on {}", address.display());
    serve_on_listener(service, listener).await
}

/// Varlink support for the OCI interface (`org.composefs.Oci`).
///
/// Gated behind the `oci` feature; collected in one module so the feature
/// gate lives in a single place rather than on every item.
#[cfg(feature = "oci")]
pub mod oci {
    use super::*;

    /// Summary of a stored OCI image for the varlink wire format.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct ImageEntry {
        /// Tag/name of the image.
        pub name: String,
        /// Manifest digest, e.g. "sha256:...".
        pub manifest_digest: String,
        /// Whether this is a container image (vs an artifact).
        pub is_container: bool,
        /// Architecture (empty for artifacts).
        pub architecture: String,
        /// Operating system (empty for artifacts).
        pub os: String,
        /// Creation timestamp, if recorded.
        pub created: Option<String>,
        /// Number of layers/blobs.
        pub layer_count: u64,
        /// Number of OCI referrers (signatures, attestations, etc.).
        pub referrer_count: u64,
    }

    impl From<&composefs_oci::oci_image::ImageInfo> for ImageEntry {
        fn from(info: &composefs_oci::oci_image::ImageInfo) -> Self {
            Self {
                name: info.name.clone(),
                manifest_digest: info.manifest_digest.to_string(),
                is_container: info.is_container,
                architecture: info.architecture.clone(),
                os: info.os.clone(),
                created: info.created.clone(),
                layer_count: info.layer_count as u64,
                referrer_count: info.referrer_count as u64,
            }
        }
    }

    /// Reply format for listing OCI images.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct ListImagesReply {
        /// The images found in the repository.
        pub images: Vec<ImageEntry>,
    }

    /// Result of an OCI-level consistency check for the varlink wire format.
    ///
    /// Flattened projection of [`composefs_oci::oci_fsck`]'s `OciFsckResult`; the
    /// embedded [`FsckReply`] carries the underlying repository-level results.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct OciFsckReply {
        /// Whether no corruption or errors were found at any level.
        pub ok: bool,
        /// Number of OCI images checked.
        pub images_checked: u64,
        /// Number of OCI images found to have issues.
        pub images_corrupted: u64,
        /// Human-readable descriptions of each OCI-level error found.
        pub errors: Vec<String>,
        /// The underlying repository-level fsck results.
        pub repo: FsckReply,
    }

    impl From<&composefs_oci::OciFsckResult> for OciFsckReply {
        fn from(result: &composefs_oci::OciFsckResult) -> Self {
            Self {
                ok: result.is_ok(),
                images_checked: result.images_checked(),
                images_corrupted: result.images_corrupted(),
                errors: result.errors().iter().map(|e| e.to_string()).collect(),
                repo: FsckReply::from(result.repo_result()),
            }
        }
    }

    /// Reply with the manifest, config and referrers of a single OCI image.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct OciInspectReply {
        /// The raw manifest JSON as stored, as a UTF-8 string.
        pub manifest: String,
        /// The raw config JSON as stored, as a UTF-8 string.
        pub config: String,
        /// Digests of the OCI referrers (signatures, attestations, etc.).
        pub referrers: Vec<String>,
        /// Hex fs-verity ID of the linked composefs EROFS image, if any.
        pub composefs_erofs: Option<String>,
        /// Hex fs-verity ID of the linked bootable composefs EROFS image, if any.
        ///
        /// Present when the image was pulled with `bootable` support; bootc and
        /// other GC-aware callers use this to keep the derived boot EROFS object
        /// alive alongside the primary image.
        pub composefs_boot_erofs: Option<String>,
    }

    impl OciInspectReply {
        /// Build an inspect reply from a resolved image, reading its manifest,
        /// config and referrers from the repository.
        pub fn from_image<ObjectID: FsVerityHashValue>(
            repo: &Repository<ObjectID>,
            img: &composefs_oci::oci_image::OciImage<ObjectID>,
        ) -> anyhow::Result<Self> {
            let manifest = String::from_utf8(img.read_manifest_json(repo)?)
                .context("manifest is not valid UTF-8")?;
            let config = String::from_utf8(img.read_config_json(repo)?)
                .context("config is not valid UTF-8")?;
            let referrers = composefs_oci::oci_image::list_referrers(repo, img.manifest_digest())?
                .iter()
                .map(|(digest, _verity)| digest.to_string())
                .collect();
            Ok(Self {
                manifest,
                config,
                referrers,
                composefs_erofs: img.image_ref(repo.erofs_version()).map(|id| id.to_hex()),
                composefs_boot_erofs: img
                    .boot_image_ref(repo.erofs_version())
                    .map(|id| id.to_hex()),
            })
        }
    }

    /// Reply carrying the computed composefs image ID for an OCI image.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct OciComputeIdReply {
        /// The hex-encoded composefs image ID.
        pub image_id: String,
    }

    /// A single progress frame emitted by the streaming `Pull` method.
    ///
    /// varlink has no tagged/data-union type, so a sum-of-events is modelled as a
    /// struct with one optional field per event shape: exactly one field is set
    /// per frame, and its presence acts as the discriminant. (zlink does support
    /// nested struct fields, hence the dedicated [`Started`]/[`Progress`]/etc.
    /// payload types rather than a flat bag of always-empty columns.)
    ///
    /// The stream yields zero or more intermediate frames (with `continues=true`)
    /// describing fetch progress, followed by exactly one terminal frame whose
    /// [`completed`](PullProgress::completed) field is set (and `continues=false`)
    /// carrying the pull result.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct PullProgress {
        /// A new component started downloading.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub started: Option<Started>,
        /// Incremental transfer progress for a component.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub progress: Option<Progress>,
        /// A component was skipped because it was already present.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub skipped: Option<Skipped>,
        /// A component finished downloading.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub done: Option<Done>,
        /// A human-readable status message.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub message: Option<String>,
        /// The terminal frame carrying the pull result. Its presence marks the
        /// end of the stream (the reply also has `continues=false`).
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub completed: Option<Completed>,
    }

    /// Unit of measurement for [`Started`]/[`Progress`] counters.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, zlink::introspect::Type)]
    pub enum ProgressUnit {
        /// Counters are byte counts.
        Bytes,
        /// Counters are discrete item counts.
        Items,
    }

    impl From<composefs::progress::ProgressUnit> for ProgressUnit {
        fn from(unit: composefs::progress::ProgressUnit) -> Self {
            use composefs::progress::ProgressUnit as U;
            match unit {
                U::Bytes => ProgressUnit::Bytes,
                U::Items => ProgressUnit::Items,
                // `ProgressUnit` is `#[non_exhaustive]`; default to items.
                _ => ProgressUnit::Items,
            }
        }
    }

    /// A new component (layer/object) started downloading.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct Started {
        /// Component id (layer/object digest).
        pub id: String,
        /// Total bytes/items to transfer, if known.
        pub total: Option<u64>,
        /// Unit of `total` and subsequent [`Progress`] counters.
        pub unit: ProgressUnit,
    }

    /// Incremental transfer progress for a component.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct Progress {
        /// Component id (layer/object digest).
        pub id: String,
        /// Bytes/items transferred so far.
        pub fetched: u64,
        /// Total bytes/items to transfer, if known.
        pub total: Option<u64>,
    }

    /// A component was skipped because it was already present.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct Skipped {
        /// Component id (layer/object digest).
        pub id: String,
    }

    /// A component finished downloading.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct Done {
        /// Component id (layer/object digest).
        pub id: String,
        /// Total bytes/items actually transferred.
        pub transferred: u64,
    }

    /// The result of a completed pull.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct Completed {
        /// Manifest digest of the pulled image.
        pub manifest_digest: String,
        /// Config digest of the pulled image.
        pub config_digest: String,
        /// Hex fs-verity of the manifest splitstream.
        pub manifest_verity: String,
        /// Hex fs-verity of the config splitstream.
        pub config_verity: String,
        /// `Display` rendering of the import stats.
        pub stats: String,
        /// Hex fs-verity of the generated boot EROFS image, when a bootable pull
        /// was requested; `None` otherwise.
        pub boot_image: Option<String>,
    }

    impl PullProgress {
        /// An empty frame with every variant cleared. Construct a frame by
        /// setting exactly one field.
        fn empty() -> Self {
            PullProgress {
                started: None,
                progress: None,
                skipped: None,
                done: None,
                message: None,
                completed: None,
            }
        }
    }

    impl From<composefs::progress::ProgressEvent> for PullProgress {
        /// Map a library [`composefs::progress::ProgressEvent`] to a wire frame,
        /// consuming the event so owned fields (e.g. a `Message` string) move
        /// rather than clone.
        fn from(event: composefs::progress::ProgressEvent) -> Self {
            use composefs::progress::ProgressEvent;

            let mut p = PullProgress::empty();
            match event {
                ProgressEvent::Started { id, total, unit } => {
                    p.started = Some(Started {
                        id: id.into_inner(),
                        total,
                        unit: unit.into(),
                    });
                }
                ProgressEvent::Progress { id, fetched, total } => {
                    p.progress = Some(Progress {
                        id: id.into_inner(),
                        fetched,
                        total,
                    });
                }
                ProgressEvent::Skipped { id } => {
                    p.skipped = Some(Skipped {
                        id: id.into_inner(),
                    });
                }
                ProgressEvent::Done { id, transferred } => {
                    p.done = Some(Done {
                        id: id.into_inner(),
                        transferred,
                    });
                }
                ProgressEvent::Message(s) => {
                    p.message = Some(s);
                }
                // `ProgressEvent` is `#[non_exhaustive]`; map unknown variants to a
                // message frame so future additions remain forward-compatible.
                other => {
                    p.message = Some(format!("{other:?}"));
                }
            }
            p
        }
    }

    /// A [`composefs::progress::ProgressReporter`] that forwards each event as a
    /// [`PullProgress`] frame over an unbounded channel to the streaming method.
    struct ChannelReporter {
        tx: tokio::sync::mpsc::UnboundedSender<PullProgress>,
    }

    impl std::fmt::Debug for ChannelReporter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ChannelReporter").finish_non_exhaustive()
        }
    }

    impl composefs::progress::ProgressReporter for ChannelReporter {
        fn report(&self, event: composefs::progress::ProgressEvent) {
            // The receiver may have been dropped (client cancelled the stream);
            // dropping the event is the right behaviour in that case.
            let _ = self.tx.send(PullProgress::from(event));
        }
    }

    /// Aborts the wrapped pull task when dropped.
    ///
    /// If the client disconnects before the stream completes, dropping the
    /// returned stream drops this guard, which aborts the in-flight pull instead
    /// of leaking the task.
    struct AbortOnDrop {
        handle: Option<tokio::task::JoinHandle<std::result::Result<(), OciError>>>,
    }

    impl AbortOnDrop {
        /// Take the join handle out, disarming the abort-on-drop behaviour.
        fn take(&mut self) -> Option<tokio::task::JoinHandle<std::result::Result<(), OciError>>> {
            self.handle.take()
        }
    }

    impl std::fmt::Debug for AbortOnDrop {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AbortOnDrop").finish_non_exhaustive()
        }
    }

    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            if let Some(handle) = &self.handle {
                handle.abort();
            }
        }
    }

    /// Parse the wire `local_fetch` string into a [`composefs_oci::LocalFetchOpt`].
    ///
    /// Unknown values fall back to [`LocalFetchOpt::Disabled`](composefs_oci::LocalFetchOpt::Disabled).
    pub(crate) fn parse_local_fetch(value: &str) -> composefs_oci::LocalFetchOpt {
        use composefs_oci::LocalFetchOpt;
        match value {
            "auto" | "if-possible" => LocalFetchOpt::IfPossible,
            "zerocopy" | "zero-copy" => LocalFetchOpt::ZeroCopy,
            _ => LocalFetchOpt::Disabled,
        }
    }

    /// Run a streaming pull against an already-opened repository, returning a
    /// boxed stream of [`PullProgress`] frames.
    ///
    /// The return type is a concrete boxed trait object rather than `impl Stream`
    /// so that both monomorphisations (Sha256/Sha512) of this generic function
    /// produce the *same* type — letting the non-generic service `pull` method
    /// unify the two match arms under a single `impl Stream` return.
    ///
    /// When `more` is `false` the client asked for a single reply, so no progress
    /// reporter is attached and the stream yields only the terminal `completed`
    /// frame (or an error).
    ///
    /// The pull task uses [`tokio::task::spawn_local`], not [`tokio::spawn`]:
    /// `composefs_oci::pull` is `!Send` (the `get_layer` zlink proxy returns a
    /// `!Send` `ReplyStream`), and the server loop runs inside a `LocalSet`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn pull_stream<ObjectID: FsVerityHashValue>(
        repo: Arc<Repository<ObjectID>>,
        image: String,
        name: Option<String>,
        local_fetch: composefs_oci::LocalFetchOpt,
        storage_root: Option<PathBuf>,
        bootable: bool,
        more: bool,
    ) -> std::pin::Pin<
        Box<
            dyn zlink::futures_util::Stream<
                    Item = std::result::Result<zlink::Reply<PullProgress>, OciError>,
                >,
        >,
    > {
        use zlink::futures_util::stream;

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<PullProgress>();
        // Only attach a progress reporter when the client wants streaming frames.
        let reporter: Option<composefs::progress::SharedReporter> = if more {
            Some(std::sync::Arc::new(ChannelReporter { tx: tx.clone() }))
        } else {
            None
        };

        // The task owns everything it needs ('static): it runs the pull, builds the
        // terminal `completed` frame from the result (plus optional boot image),
        // and sends it through the channel before the sender drops.  Pull errors
        // are carried out via the task's `JoinHandle` return value.
        let task_tx = tx.clone();
        let handle = tokio::task::spawn_local(async move {
            let opts = composefs_oci::PullOptions {
                local_fetch,
                storage_root: storage_root.as_deref(),
                progress: reporter,
                ..Default::default()
            };
            let result = composefs_oci::pull(&repo, &image, name.as_deref(), opts)
                .await
                .map_err(|e| OciError::InternalError {
                    message: format!("{e:#}"),
                })?;

            let boot_image = if bootable {
                let id = composefs_oci::generate_boot_image(&repo, &result.manifest_digest)
                    .map_err(|e| OciError::InternalError {
                        message: format!("{e:#}"),
                    })?;
                Some(id.to_hex())
            } else {
                None
            };

            let completed = PullProgress {
                completed: Some(Completed {
                    manifest_digest: result.manifest_digest.to_string(),
                    config_digest: result.config_digest.to_string(),
                    manifest_verity: result.manifest_verity.to_hex(),
                    config_verity: result.config_verity.to_hex(),
                    stats: result.stats.to_string(),
                    boot_image,
                }),
                ..PullProgress::empty()
            };
            // If the receiver is gone the client cancelled; that's fine.
            let _ = task_tx.send(completed);
            Ok(())
        });

        // Drop our extra sender handle so the channel closes once the task's clone
        // is dropped (i.e. when the task finishes).
        drop(tx);

        struct State {
            rx: tokio::sync::mpsc::UnboundedReceiver<PullProgress>,
            handle: Option<AbortOnDrop>,
            done: bool,
        }

        let state = State {
            rx,
            handle: Some(AbortOnDrop {
                handle: Some(handle),
            }),
            done: false,
        };

        let stream = stream::unfold(state, |mut state| async move {
            if state.done {
                return None;
            }
            match state.rx.recv().await {
                Some(frame) => {
                    let is_completed = frame.completed.is_some();
                    if is_completed {
                        state.done = true;
                        // Disarm the abort guard: the task has produced its result
                        // frame and is finished, so there is nothing left to abort.
                        if let Some(guard) = state.handle.as_mut() {
                            let _ = guard.take();
                        }
                    }
                    let reply = zlink::Reply::new(Some(frame)).set_continues(Some(!is_completed));
                    Some((Ok(reply), state))
                }
                None => {
                    // Channel closed without a terminal frame: the pull failed (or
                    // the task panicked). Await the join handle to recover the error.
                    state.done = true;
                    // Take the join handle out (disarming the abort guard, since
                    // the task has already finished) and recover the pull error.
                    let join = state.handle.as_mut().and_then(AbortOnDrop::take);
                    let err = match join {
                        Some(join) => match join.await {
                            Ok(Ok(())) => OciError::InternalError {
                                message: "pull completed without a result frame".to_string(),
                            },
                            Ok(Err(e)) => e,
                            Err(_) => OciError::InternalError {
                                message: "pull task panicked".to_string(),
                            },
                        },
                        None => OciError::InternalError {
                            message: "pull task panicked".to_string(),
                        },
                    };
                    Some((Err(err), state))
                }
            }
        });

        Box::pin(stream)
    }

    /// Errors that may be returned by the `org.composefs.Oci` interface.
    #[derive(Debug, zlink::ReplyError, zlink::introspect::ReplyError)]
    #[zlink(interface = "org.composefs.Oci")]
    pub enum OciError {
        /// The repository could not be found or opened at the configured path.
        RepoNotFound {
            /// Description of the failure.
            message: String,
        },
        /// The given handle does not refer to an open repository.
        InvalidHandle {
            /// The handle that was not found.
            handle: u64,
        },
        /// The named OCI image/reference does not exist.
        NoSuchImage {
            /// The image reference that was not found.
            image: String,
        },
        /// An unexpected internal error occurred while servicing the request.
        InternalError {
            /// Description of the failure.
            message: String,
        },
        /// The requested layer (by diff-id) is not present in the repository.
        NoSuchLayer {
            /// The diff-id that was not found.
            diff_id: String,
        },
        /// A supplied digest/diff-id string was malformed.
        InvalidDigest {
            /// Human-readable description of the parse failure.
            message: String,
        },
        /// Received layer content did not hash to the declared diff-id.
        ///
        /// The stream was NOT committed; the client must retry with correct data.
        DiffIdMismatch {
            /// The diff_id that was declared by the client.
            expected: String,
            /// The sha256 digest of the data that was actually received.
            actual: String,
        },
        /// The request was malformed (e.g. wrong fd count).
        InvalidRequest {
            /// Human-readable description of what was wrong.
            message: String,
        },
        /// The total fd count exceeds [`MAX_FDS_PER_FRAME`] for a `more=false` call.
        ///
        /// The client must retry with `more=true` (streaming mode).
        FdLimitExceeded {
            /// Total number of fds that would be sent.
            fd_count: u64,
            /// The per-frame cap that was exceeded.
            max_per_frame: u64,
        },
    }
}

/// Reply types for the layer-sync methods of the `org.composefs.Oci` interface,
/// gated behind the `oci` feature (they depend on [`composefs_oci::layer_sync`]).
///
/// The four layer-sync methods (`GetInfo`, `HasLayer`, `GetLayer`, `PutLayer`)
/// are part of `org.composefs.Oci`; this module merely collects their reply
/// structs to keep them separate from the rest of the OCI wire types.
#[cfg(feature = "oci")]
pub mod layer_sync {
    use super::*;

    /// Reply from `GetInfo`: capability tokens supported by this service.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct GetInfoReply {
        /// Capability tokens advertised by this service instance.
        ///
        /// Currently only `"splitdirfdstream-v0"` is defined.
        pub features: Vec<String>,
    }

    /// Reply from `HasLayer`: whether the layer is present in the repository.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct HasLayerReply {
        /// Whether the layer splitstream for the given diff-id is present.
        pub present: bool,
        /// Hex-encoded fs-verity hash of the layer splitstream, if present.
        pub layer_verity: Option<String>,
    }

    /// Reply from `GetLayer`: the number of diff-directory slots in the logical FD array.
    ///
    /// `GetLayer` is a **streaming** method (`more`): it yields multiple frames,
    /// each carrying a batch of FDs.  The client MUST concatenate the FD batches
    /// from all frames (in arrival order) to reconstruct the full logical FD array:
    ///
    /// - `fds[0]` — data pipe read end (carries the `splitdirfdstream` bytes).
    /// - `fds[1..=dir_count]` — the dirfds region (`dir_count` slots total).  The
    ///   real objects-directory fd sits at a sparse, hash-determined index within
    ///   this region; the remaining (gap) slots hold inert dummy fds that
    ///   `reconstruct` never dereferences.  The sparse placement is encoded in each
    ///   `FileBackedData` chunk's `dirfd_index`; the client passes the whole region
    ///   to `drain_splitdirfdstream` / `reconstruct` unchanged and must NOT assume
    ///   the dir is at a fixed index.
    /// - `fds[dir_count+1..]` — opaque lifetime FDs.  The client MUST hold every
    ///   one of these open until it has finished reading and processing all dir fds,
    ///   then close them all to signal completion to the server.  The count of
    ///   trailing FDs is unspecified by contract; the client keeps open whatever it
    ///   does not otherwise recognise.  This lifetime-FD convention is part of the
    ///   `splitdirfdstream-v0` feature.
    ///
    /// Each transport frame carries at most `MAX_FDS_PER_FRAME` (240) fds, safely
    /// below the kernel `SCM_MAX_FD` (253) limit.  Every frame carries the same
    /// `dir_count`; the client should use the value from any frame (they are all
    /// identical).  The stream terminates when a frame with `continues=false` is
    /// received.
    ///
    /// A non-streaming (`more=false`) call delivers all fds in a single frame; if
    /// the layer requires more than `MAX_FDS_PER_FRAME` fds the call returns
    /// `FdLimitExceeded` and the client must retry with `more=true`.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct GetLayerReply {
        /// Number of diff-directory file descriptors in the full logical FD array
        /// (i.e. `fds[1..=dir_count]` after concatenating all frames' batches).
        pub dir_count: u32,
    }

    /// Reply from `PutLayer`: the verity hash of the imported layer, whether
    /// it was already present, and per-object transfer statistics.
    ///
    /// The object-count fields let the client verify that zero-copy transfer
    /// actually took place (e.g. assert `objects_reflinked > 0` in tests) and
    /// accumulate aggregate stats for user-facing output.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct PutLayerReply {
        /// Hex-encoded fs-verity hash of the committed layer splitstream.
        pub layer_verity: String,
        /// `true` if the layer was already present before this call.
        ///
        /// The server always drains the pipe regardless (to avoid wedging
        /// the client's writer), so the stream is re-imported idempotently.
        pub already_present: bool,

        /// Number of objects that were reflinked (FICLONE) into the
        /// destination. Non-zero only when source and dest share a filesystem.
        #[serde(default)]
        pub objects_reflinked: u64,
        /// Number of objects hardlinked into the destination (zerocopy mode).
        #[serde(default)]
        pub objects_hardlinked: u64,
        /// Number of objects byte-copied into the destination.
        #[serde(default)]
        pub objects_copied: u64,
        /// Number of objects already present in the destination (skipped).
        #[serde(default)]
        pub objects_already_present: u64,
    }

    /// A single (diff_id, layer_verity) pair passed to `FinalizeImage`.
    ///
    /// The client builds this list from the `PutLayer` replies it received while
    /// copying layers to the destination repository.  The order must match the
    /// manifest layer order.
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct LayerRef {
        /// OCI diff-id of the layer (e.g. `"sha256:abcd..."`).
        pub diff_id: String,
        /// Hex-encoded fs-verity hash of the layer splitstream in the destination
        /// repository, as returned by `PutLayer`.
        pub layer_verity: String,
    }

    /// Reply from `FinalizeImage`: digest and verity strings for the manifest
    /// and config splitstreams that were written (or already existed).
    #[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
    pub struct FinalizeImageReply {
        /// OCI digest of the manifest (e.g. `"sha256:abcd..."`).
        pub manifest_digest: String,
        /// Hex-encoded fs-verity hash of the manifest splitstream.
        pub manifest_verity: String,
        /// OCI digest of the config (e.g. `"sha256:abcd..."`).
        pub config_digest: String,
        /// Hex-encoded fs-verity hash of the config splitstream.
        pub config_verity: String,
    }
}

/// Typed Rust client bindings (the native-API mirror of the on-the-wire
/// varlink interfaces). These let a Rust consumer — the integration tests
/// today, and a future cfsctl-as-client — call the service with generated,
/// type-checked proxy methods, in addition to the wire protocol exercised by
/// external clients such as `varlinkctl`.
pub mod proxy {
    #![allow(missing_docs)]

    #[cfg(feature = "oci")]
    use super::layer_sync::{
        FinalizeImageReply, GetInfoReply, GetLayerReply, HasLayerReply, LayerRef, PutLayerReply,
    };
    #[cfg(feature = "oci")]
    use super::oci::{
        ListImagesReply, OciComputeIdReply, OciError, OciFsckReply, OciInspectReply, PullProgress,
    };
    use super::{
        FsckReply, GcReply, ImageObjectsReply, InitRepositoryReply, OpenRepositoryReply,
        RepositoryError,
    };
    #[cfg(feature = "oci")]
    pub use composefs_oci::varlink_types::GetLayerParams;
    #[cfg(feature = "oci")]
    use zlink::futures_util::Stream;

    /// Typed client for the `org.composefs.Repository` interface.
    #[zlink::proxy(interface = "org.composefs.Repository")]
    pub trait RepositoryProxy {
        /// Initialize a new repository (or verify an existing one).
        async fn init_repository(
            &mut self,
            path: &str,
            algorithm: Option<&str>,
            insecure: Option<bool>,
        ) -> zlink::Result<Result<InitRepositoryReply, RepositoryError>>;

        /// Open and validate a repository, returning an opaque handle.
        async fn open_repository(
            &mut self,
            path: Option<&str>,
            user: Option<bool>,
            system: Option<bool>,
        ) -> zlink::Result<Result<OpenRepositoryReply, RepositoryError>>;

        /// Close a previously opened repository handle.
        async fn close_repository(
            &mut self,
            handle: u64,
        ) -> zlink::Result<Result<(), RepositoryError>>;

        /// Check repository integrity.
        async fn fsck(
            &mut self,
            handle: u64,
            metadata_only: Option<bool>,
        ) -> zlink::Result<Result<FsckReply, RepositoryError>>;

        /// Run garbage collection (or a dry run).
        async fn gc(
            &mut self,
            handle: u64,
            dry_run: bool,
            roots: Vec<String>,
        ) -> zlink::Result<Result<GcReply, RepositoryError>>;

        /// List the objects referenced by a single image.
        async fn image_objects(
            &mut self,
            handle: u64,
            name: &str,
        ) -> zlink::Result<Result<ImageObjectsReply, RepositoryError>>;
    }

    /// Typed client for the `org.composefs.Oci` interface.
    #[cfg(feature = "oci")]
    #[zlink::proxy(interface = "org.composefs.Oci")]
    pub trait OciProxy {
        /// List tagged OCI images.
        async fn list_images(
            &mut self,
            handle: u64,
            filter: Option<&str>,
        ) -> zlink::Result<Result<ListImagesReply, OciError>>;

        /// Run an OCI-aware consistency check (wire method `Check`).
        #[zlink(rename = "Check")]
        async fn oci_fsck(
            &mut self,
            handle: u64,
            image: Option<&str>,
        ) -> zlink::Result<Result<OciFsckReply, OciError>>;

        /// Inspect a single OCI image.
        async fn inspect(
            &mut self,
            handle: u64,
            image: &str,
        ) -> zlink::Result<Result<OciInspectReply, OciError>>;

        /// Tag a manifest digest with a name.
        async fn tag(
            &mut self,
            handle: u64,
            manifest_digest: &str,
            name: &str,
        ) -> zlink::Result<Result<(), OciError>>;

        /// Remove a tag.
        async fn untag(&mut self, handle: u64, name: &str) -> zlink::Result<Result<(), OciError>>;

        /// Compute the composefs image ID for an OCI image.
        async fn compute_id(
            &mut self,
            handle: u64,
            image: &str,
            verity: Option<&str>,
            bootable: bool,
        ) -> zlink::Result<Result<OciComputeIdReply, OciError>>;

        /// Pull an OCI image, streaming progress frames.
        #[zlink(more, rename = "Pull")]
        async fn pull(
            &mut self,
            handle: u64,
            image: &str,
            name: Option<&str>,
            local_fetch: &str,
            storage_root: Option<&str>,
            bootable: bool,
        ) -> zlink::Result<impl Stream<Item = zlink::Result<Result<PullProgress, OciError>>>>;

        /// Query capability tokens supported by the service.
        async fn get_info(&mut self) -> zlink::Result<Result<GetInfoReply, OciError>>;

        /// Check whether a layer is present in the repository.
        async fn has_layer(
            &mut self,
            handle: u64,
            diff_id: &str,
        ) -> zlink::Result<Result<HasLayerReply, OciError>>;

        /// Stream the layer as a `splitdirfdstream` with full hardened fd-transport
        /// contract (sparse dirfds, keepalive, lifetime fds, multi-frame).
        ///
        /// Drive the returned stream to completion (until `continues=false`),
        /// concatenating each frame's fd batch in order to reconstruct the full
        /// logical FD array `[pipe_read, dirfds.., lifetime_fds..]`.
        #[zlink(more, return_fds)]
        async fn get_layer(
            &mut self,
            handle: u64,
            params: GetLayerParams,
        ) -> zlink::Result<
            impl zlink::futures_util::Stream<
                Item = zlink::Result<(Result<GetLayerReply, OciError>, Vec<std::os::fd::OwnedFd>)>,
            >,
        >;

        /// Receive a layer as a `splitdirfdstream` from the client and import
        /// it into the server's repository with diff_id verification.
        ///
        /// `fds[0]` is the pipe read end; `fds[1..]` are source object dirs.
        async fn put_layer(
            &mut self,
            handle: u64,
            diff_id: &str,
            zerocopy: bool,
            #[zlink(fds)] fds: Vec<std::os::fd::OwnedFd>,
        ) -> zlink::Result<Result<PutLayerReply, OciError>>;

        /// Finalize an OCI image after all layers have been imported.
        ///
        /// `layers` must be in manifest layer order; each entry pairs the layer's
        /// OCI diff-id with the hex verity returned by `PutLayer`.  `name` is the
        /// tag to assign (optional). Idempotent.
        async fn finalize_image(
            &mut self,
            handle: u64,
            manifest_json: &str,
            config_json: &str,
            layers: Vec<LayerRef>,
            name: Option<&str>,
        ) -> zlink::Result<Result<FinalizeImageReply, OciError>>;
    }
}

#[cfg(feature = "oci")]
pub(crate) use oci::*;

/// Spawn a `CfsctlService` in-process over a Unix socket pair for testing.
///
/// Returns a connected client [`zlink::unix::Connection`] and a
/// [`std::thread::JoinHandle`] for the server thread.
///
/// Mirrors the pattern in `composefs-storage`'s `spawn_in_process`: the zlink
/// server is `!Send` so it runs on a dedicated OS thread with its own
/// current-thread Tokio runtime and [`tokio::task::LocalSet`].
///
/// The server thread exits when the client connection is closed.
#[cfg(feature = "oci")]
pub(crate) fn spawn_in_process(
    service: CfsctlService,
) -> std::io::Result<(zlink::unix::Connection, std::thread::JoinHandle<()>)> {
    let (client_std, server_std) = std::os::unix::net::UnixStream::pair()?;
    client_std.set_nonblocking(true)?;
    server_std.set_nonblocking(true)?;

    let client_stream = tokio::net::UnixStream::from_std(client_std)?;
    let client_zlink =
        zlink::unix::Stream::try_from(client_stream).map_err(std::io::Error::other)?;
    let client_conn = zlink::Connection::new(client_zlink);

    let handle = std::thread::Builder::new()
        .name("cfsctl-service-server".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("CfsctlService server runtime build failed: {e:#?}");
                    return;
                }
            };
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, async move {
                let server_stream = match tokio::net::UnixStream::from_std(server_std) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("CfsctlService server stream conversion failed: {e:#?}");
                        return;
                    }
                };
                let server_zlink = match zlink::unix::Stream::try_from(server_stream) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("CfsctlService server zlink stream conversion failed: {e:#?}");
                        return;
                    }
                };
                let listener = zlink::ReadyListener::new(server_zlink);
                let server = zlink::Server::new(listener, service);
                if let Err(e) = server.run().await {
                    log::warn!("CfsctlService in-process server error: {e:#?}");
                }
            });
        })?;

    Ok((client_conn, handle))
}

#[cfg(all(test, feature = "oci"))]
mod layer_sync_tests {
    //! In-process round-trip tests for the layer-sync methods of the
    //! `org.composefs.Oci` interface.
    //!
    //! These mirror the in-process transport test in
    //! `composefs-storage`'s `cstor_service.rs`.

    use std::io::Read as _;
    use std::os::fd::AsFd as _;
    use std::sync::Arc;

    use composefs::fsverity::{FsVerityHashValue as _, Sha256HashValue};
    use composefs::repository::{Repository, RepositoryConfig};
    use composefs_splitdirfdstream::reconstruct;

    use super::layer_sync::GetLayerReply;
    use super::oci::OciError;
    use super::proxy::{OciProxy, RepositoryProxy as _};
    use super::{CfsctlService, spawn_in_process};
    use composefs_oci::varlink_types::GetLayerParams;

    /// Drive a streaming `get_layer` call to completion, collecting all FDs.
    ///
    /// Returns `(reply, all_fds)` where `all_fds` is the concatenated FD vector
    /// from all frames in arrival order:
    /// ```text
    /// [ pipe_read | dirfds region (dir_count) | lifetime fds ]
    /// ```
    async fn collect_get_layer<C>(
        client: &mut C,
        handle: u64,
        diff_id: &str,
    ) -> Result<(GetLayerReply, Vec<std::os::fd::OwnedFd>), OciError>
    where
        C: OciProxy,
    {
        use zlink::futures_util::StreamExt as _;

        let params = GetLayerParams {
            diff_id: Some(diff_id.to_owned()),
            storage: None,
            ..Default::default()
        };
        let mut stream = std::pin::pin!(
            client
                .get_layer(handle, params)
                .await
                .expect("get_layer transport error")
        );

        let mut all_fds: Vec<std::os::fd::OwnedFd> = Vec::new();
        let mut last_reply: Option<GetLayerReply> = None;

        while let Some(item) = stream.next().await {
            let (result, fds) = item.expect("get_layer stream error");
            match result {
                Ok(reply) => {
                    last_reply = Some(reply);
                }
                Err(e) => return Err(e),
            }
            all_fds.extend(fds);
        }

        Ok((last_reply.expect("get_layer stream was empty"), all_fds))
    }

    /// Like `collect_get_layer` but splits the fd array into:
    /// - `pipe_and_dirfds`: `fds[0..=dir_count]` (pipe + dirfds region)
    /// - `lifetime_fds`: `fds[dir_count+1..]` (keepalive + extras)
    ///
    /// Returns `(dir_count, pipe_and_dirfds, lifetime_fds)`.
    async fn collect_get_layer_split<C>(
        client: &mut C,
        handle: u64,
        diff_id: &str,
    ) -> (
        GetLayerReply,
        Vec<std::os::fd::OwnedFd>,
        Vec<std::os::fd::OwnedFd>,
    )
    where
        C: OciProxy,
    {
        let (reply, mut all_fds) = collect_get_layer(client, handle, diff_id)
            .await
            .expect("get_layer failed");
        let dir_count = reply.dir_count as usize;
        // pipe_and_dirfds = fds[0..=dir_count] (1 + dir_count)
        let pipe_and_dirfds_len = 1 + dir_count;
        assert!(
            all_fds.len() >= pipe_and_dirfds_len,
            "expected at least {pipe_and_dirfds_len} fds, got {}",
            all_fds.len()
        );
        let lifetime_fds = all_fds.split_off(pipe_and_dirfds_len);
        (reply, all_fds, lifetime_fds)
    }

    /// Build a trivial tar stream with one file at `size` bytes and return the
    /// raw bytes.  Content is deterministic (repeating `i % 251`).
    fn build_tar_layer(file_size: usize) -> Vec<u8> {
        let content: Vec<u8> = (0..file_size).map(|i| (i % 251) as u8).collect();
        let mut builder = ::tar::Builder::new(vec![]);
        let mut header = ::tar::Header::new_ustar();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o644);
        header.set_entry_type(::tar::EntryType::Regular);
        header.set_size(file_size as u64);
        builder
            .append_data(&mut header, format!("file_{file_size}"), &content[..])
            .unwrap();
        builder.into_inner().unwrap()
    }

    /// Create an insecure test repo.
    fn create_test_repo() -> (Arc<Repository<Sha256HashValue>>, tempfile::TempDir) {
        let tempdir = tempfile::TempDir::new().unwrap();
        let (repo, _) = Repository::init_path(
            rustix::fs::CWD,
            tempdir.path().join("repo"),
            RepositoryConfig::default().set_insecure(),
        )
        .unwrap();
        (Arc::new(repo), tempdir)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_layer_sync_in_process() {
        // --- set up a repo and import a synthetic layer ---
        let (repo, _tempdir) = create_test_repo();

        // Build a tar layer that has one large (>64-byte = external) file.
        let tar_bytes = build_tar_layer(128 * 1024); // 128 KiB — external object
        let diff_id = composefs_oci::sha256_content_digest(&tar_bytes);
        let (verity, _stats) =
            composefs_oci::import_layer(&repo, &diff_id, None, tar_bytes.as_slice())
                .await
                .expect("import_layer");

        // Record expected cat() output for comparison later.
        let mut expected = Vec::<u8>::new();
        {
            let mut reader = repo
                .open_stream("", Some(&verity), Some(composefs_oci::LAYER_CONTENT_TYPE))
                .expect("open_stream for cat");
            reader.cat(&repo, &mut expected).expect("cat");
        }

        let repo_path = _tempdir.path().join("repo").to_str().unwrap().to_string();

        // --- build and start the in-process service ---
        let service = CfsctlService::insecure_for_test();
        let (mut client, _server_handle) = spawn_in_process(service).unwrap();

        // OpenRepository to get a handle + metadata.
        let open_reply = client
            .open_repository(Some(&repo_path), None, None)
            .await
            .unwrap()
            .expect("open_repository");
        let handle = open_reply.handle;

        // Validate the new metadata fields.
        assert_eq!(
            open_reply.hash_algorithm.as_deref(),
            Some("sha256"),
            "hash_algorithm must be sha256 for a Sha256HashValue repo"
        );
        assert!(
            open_reply.objects_device_id.is_some(),
            "objects_device_id must be reported"
        );

        // --- GetInfo ---
        let info = client.get_info().await.unwrap().expect("get_info");
        assert!(
            info.features.contains(&"splitdirfdstream-v0".to_string()),
            "expected splitdirfdstream-v0 in features"
        );

        // --- HasLayer: present ---
        let has = client
            .has_layer(handle, diff_id.as_ref())
            .await
            .unwrap()
            .expect("has_layer");
        assert!(has.present, "layer must be present");
        assert_eq!(
            has.layer_verity.as_deref(),
            Some(verity.to_hex().as_str()),
            "verity mismatch"
        );

        // --- HasLayer: absent ---
        let fake_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let has_absent = client
            .has_layer(handle, fake_digest)
            .await
            .unwrap()
            .expect("has_layer absent");
        assert!(!has_absent.present, "absent layer must not be present");
        assert!(has_absent.layer_verity.is_none());

        // --- GetLayer: e2e round-trip ---
        // The new streaming form: collect all frames' fds, then split into
        // pipe+dirfds (wire positions 0..=dir_count) and lifetime fds (rest).
        let (get_reply, pipe_and_dirfds, lifetime_fds) =
            collect_get_layer_split(&mut client, handle, diff_id.as_ref()).await;
        let dir_count = get_reply.dir_count as usize;

        // Keep lifetime fds alive until we are done reading the stream.
        let _lifetime_fds = lifetime_fds;

        // fds[0] = pipe read; fds[1..=dir_count] = dirfds region (sparse).
        let pipe_fd = pipe_and_dirfds[0].as_fd();
        let dir_fds: Vec<_> = pipe_and_dirfds[1..=dir_count]
            .iter()
            .map(|f| f.as_fd())
            .collect();

        // Read the splitdirfdstream from the pipe to EOF.
        let pipe_owned = rustix::io::dup(pipe_fd).expect("dup pipe read");
        let mut pipe_file = std::fs::File::from(pipe_owned);
        let mut stream_bytes = Vec::new();
        pipe_file.read_to_end(&mut stream_bytes).unwrap();
        assert!(!stream_bytes.is_empty(), "stream must be non-empty");

        // Reconstruct via the sparse dirfds region.
        let mut actual = Vec::new();
        reconstruct(stream_bytes.as_slice(), &dir_fds, &mut actual)
            .expect("reconstruct splitdirfdstream");

        similar_asserts::assert_eq!(
            actual,
            expected,
            "reconstructed layer must equal cat() output"
        );

        // --- GetLayer: unknown diff-id ---
        let err = collect_get_layer(&mut client, handle, fake_digest).await;
        match err {
            Err(super::oci::OciError::NoSuchLayer { .. }) => {}
            other => panic!("expected NoSuchLayer, got {other:?}"),
        }
    }

    /// Full GetLayer→PutLayer relay: serve repo A via one in-process server,
    /// call `get_layer` to obtain the stream fds, then relay them to a second
    /// in-process server hosting repo B via `put_layer`.
    ///
    /// Asserts:
    /// - `put_layer` succeeds with `already_present = false`.
    /// - repo B has the layer committed and its `cat` output matches repo A.
    /// - A second `put_layer` with the same data returns `already_present = true`.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_put_layer_relay() {
        // --- set up repo A with a layer containing an external object ---
        let (repo_a, _td_a) = create_test_repo();
        let tar_bytes = build_tar_layer(128 * 1024); // 128 KiB — external object
        let diff_id = composefs_oci::sha256_content_digest(&tar_bytes);
        let (verity_a, _) =
            composefs_oci::import_layer(&repo_a, &diff_id, None, tar_bytes.as_slice())
                .await
                .expect("import_layer into repo_a");

        // expected cat() output for later comparison
        let mut expected = Vec::<u8>::new();
        {
            let mut reader = repo_a
                .open_stream("", Some(&verity_a), Some(composefs_oci::LAYER_CONTENT_TYPE))
                .expect("open_stream for cat");
            reader.cat(&repo_a, &mut expected).expect("cat");
        }
        let repo_a_path = _td_a.path().join("repo").to_str().unwrap().to_string();

        // --- set up repo B (empty) ---
        let (repo_b, _td_b) = create_test_repo();
        let repo_b_path = _td_b.path().join("repo").to_str().unwrap().to_string();

        // --- start two in-process services ---
        let service_a = CfsctlService::insecure_for_test();
        let (mut client_a, _srv_a) = spawn_in_process(service_a).unwrap();

        let service_b = CfsctlService::insecure_for_test();
        let (mut client_b, _srv_b) = spawn_in_process(service_b).unwrap();

        // Open repos via each service.
        let handle_a = client_a
            .open_repository(Some(&repo_a_path), None, None)
            .await
            .unwrap()
            .expect("open_repository A")
            .handle;
        let handle_b = client_b
            .open_repository(Some(&repo_b_path), None, None)
            .await
            .unwrap()
            .expect("open_repository B")
            .handle;

        // --- GetLayer from service A ---
        // Collect all frames; split into pipe+dirfds and lifetime fds.
        let (get_reply, pipe_and_dirfds, lifetime_fds) =
            collect_get_layer_split(&mut client_a, handle_a, diff_id.as_ref()).await;
        let dir_count = get_reply.dir_count as usize;

        // --- PutLayer into service B (first time) ---
        // PutLayer receives fds[0..=dir_count] (pipe + dirfds region).
        // We hold lifetime_fds open until put_layer returns.
        let put_fds = pipe_and_dirfds; // fds[0] = pipe, fds[1..=dir_count] = dirs
        let put_reply = client_b
            .put_layer(handle_b, diff_id.as_ref(), false, put_fds)
            .await
            .unwrap()
            .expect("put_layer");
        // Drop lifetime fds after put_layer completes.
        drop(lifetime_fds);

        assert!(
            !put_reply.already_present,
            "first put_layer must report already_present = false"
        );
        assert!(
            dir_count > 0,
            "dir_count must be > 0 (dirfds region has at least one slot)"
        );

        // The layer has one large external object; at least one object must
        // have been stored via copy (same-host in-process, but tmpfs may not
        // support reflink). Verify the stats are populated.
        let total_stored =
            put_reply.objects_reflinked + put_reply.objects_hardlinked + put_reply.objects_copied;
        assert!(
            total_stored + put_reply.objects_already_present > 0,
            "put_layer must report at least one object stored, got {put_reply:?}"
        );

        // Verify repo B now has the layer.
        let content_id = composefs_oci::layer_content_id(&diff_id);
        assert!(
            repo_b
                .has_stream(&content_id)
                .expect("has_stream B")
                .is_some(),
            "repo B must have the layer after put_layer"
        );

        // Verify the cat() output matches.
        let verity_b: Sha256HashValue =
            Sha256HashValue::from_hex(&put_reply.layer_verity).expect("parse layer_verity hex");
        let mut actual = Vec::<u8>::new();
        {
            let mut reader = repo_b
                .open_stream("", Some(&verity_b), Some(composefs_oci::LAYER_CONTENT_TYPE))
                .expect("open_stream B for cat");
            reader.cat(&repo_b, &mut actual).expect("cat B");
        }
        similar_asserts::assert_eq!(actual, expected, "repo B cat must equal repo A cat");

        // --- PutLayer a second time (idempotent): already_present = true ---
        let (get_reply2, pipe_and_dirfds2, lifetime_fds2) =
            collect_get_layer_split(&mut client_a, handle_a, diff_id.as_ref()).await;
        let _ = get_reply2;

        let put_reply2 = client_b
            .put_layer(handle_b, diff_id.as_ref(), false, pipe_and_dirfds2)
            .await
            .unwrap()
            .expect("put_layer 2nd");
        drop(lifetime_fds2);

        assert!(
            put_reply2.already_present,
            "second put_layer must report already_present = true"
        );
    }

    /// Negative: `put_layer` with a wrong diff_id must return `DiffIdMismatch`
    /// and repo B must NOT have the stream committed.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_put_layer_wrong_diff_id() {
        let (repo_a, _td_a) = create_test_repo();
        let tar_bytes = build_tar_layer(128 * 1024);
        let correct_diff_id = composefs_oci::sha256_content_digest(&tar_bytes);
        let (_verity_a, _) =
            composefs_oci::import_layer(&repo_a, &correct_diff_id, None, tar_bytes.as_slice())
                .await
                .expect("import_layer");
        let repo_a_path = _td_a.path().join("repo").to_str().unwrap().to_string();

        let (_repo_b, _td_b) = create_test_repo();
        let repo_b_path = _td_b.path().join("repo").to_str().unwrap().to_string();

        let service_a = CfsctlService::insecure_for_test();
        let (mut client_a, _srv_a) = spawn_in_process(service_a).unwrap();
        let service_b = CfsctlService::insecure_for_test();
        let (mut client_b, _srv_b) = spawn_in_process(service_b).unwrap();

        let handle_a = client_a
            .open_repository(Some(&repo_a_path), None, None)
            .await
            .unwrap()
            .expect("open_repository A")
            .handle;
        let handle_b = client_b
            .open_repository(Some(&repo_b_path), None, None)
            .await
            .unwrap()
            .expect("open_repository B")
            .handle;

        // Get layer fds from A (collect streaming frames, split off lifetime fds).
        let (_get_reply, pipe_and_dirfds, lifetime_fds) =
            collect_get_layer_split(&mut client_a, handle_a, correct_diff_id.as_ref()).await;

        // Deliberately supply the wrong diff_id to service B.
        let wrong_diff_id =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let put_err = client_b
            .put_layer(handle_b, wrong_diff_id, false, pipe_and_dirfds)
            .await
            .unwrap();
        drop(lifetime_fds);

        match put_err {
            Err(super::oci::OciError::DiffIdMismatch { expected, actual }) => {
                assert_eq!(expected, wrong_diff_id);
                assert_eq!(actual, correct_diff_id.to_string());
            }
            other => panic!("expected DiffIdMismatch, got {other:?}"),
        }

        // The wrong stream must NOT be committed in repo B.
        let wrong_content_id = composefs_oci::layer_content_id(
            &wrong_diff_id.parse::<composefs_oci::OciDigest>().unwrap(),
        );
        assert!(
            _repo_b
                .has_stream(&wrong_content_id)
                .expect("has_stream B")
                .is_none(),
            "repo B must NOT have a stream for the wrong diff_id"
        );
    }

    // -------------------------------------------------------------------------
    // Helpers shared by the finalize_image test
    // -------------------------------------------------------------------------

    /// Build a minimal tar layer with a valid OCI directory structure.
    ///
    /// Creates `./`, `./usr/`, `./usr/share/`, and one data file of `payload_size`
    /// bytes at `./usr/share/data_<payload_size>`.
    fn build_oci_tar_layer(payload_size: usize) -> Vec<u8> {
        let mut builder = ::tar::Builder::new(vec![]);

        for (path, is_dir) in &[("./", true), ("./usr/", true), ("./usr/share/", true)] {
            let mut hdr = ::tar::Header::new_ustar();
            hdr.set_entry_type(::tar::EntryType::Directory);
            hdr.set_uid(0);
            hdr.set_gid(0);
            hdr.set_mode(0o755);
            hdr.set_size(0);
            let _ = is_dir; // suppress unused warning
            builder
                .append_data(&mut hdr, path, std::io::empty())
                .unwrap();
        }

        let content: Vec<u8> = (0..payload_size).map(|i| (i % 251) as u8).collect();
        let mut file_hdr = ::tar::Header::new_ustar();
        file_hdr.set_entry_type(::tar::EntryType::Regular);
        file_hdr.set_uid(0);
        file_hdr.set_gid(0);
        file_hdr.set_mode(0o644);
        file_hdr.set_size(payload_size as u64);
        builder
            .append_data(
                &mut file_hdr,
                format!("./usr/share/data_{payload_size}"),
                content.as_slice(),
            )
            .unwrap();

        builder.into_inner().unwrap()
    }

    /// Build a minimal OCI config JSON with the given diff-id strings.
    ///
    /// Produces a JSON that `oci_spec::image::ImageConfiguration` would accept,
    /// without pulling in the `oci_spec` builders (not available in composefs-ctl).
    fn make_config_json(diff_ids: &[String]) -> String {
        let ids: Vec<String> = diff_ids.iter().map(|d| format!("\"{d}\"")).collect();
        format!(
            r#"{{"architecture":"amd64","os":"linux","rootfs":{{"type":"layers","diff_ids":[{}]}},"config":{{}}}}"#,
            ids.join(",")
        )
    }

    /// Build a minimal OCI manifest JSON referencing `config_digest_str`.
    fn make_manifest_json(
        config_json: &str,
        config_digest_str: &str,
        diff_ids: &[String],
    ) -> String {
        let layer_entries: Vec<String> = diff_ids
            .iter()
            .map(|d| {
                format!(
                    r#"{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{d}","size":1}}"#
                )
            })
            .collect();
        format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest_str}","size":{}}},"layers":[{}]}}"#,
            config_json.len(),
            layer_entries.join(",")
        )
    }

    /// Round-trip test for the `FinalizeImage` varlink method.
    ///
    /// Imports a layer directly into repo B, then calls `finalize_image` via
    /// the in-process varlink service on B, and asserts:
    /// - The reply digests are non-empty.
    /// - The manifest and config splitstreams now exist in repo B.
    /// - The composefs EROFS image was generated.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_finalize_image_roundtrip() {
        use composefs_oci::OciDigest;

        let (repo_b, _td_b) = create_test_repo();
        let repo_b_path = _td_b.path().join("repo").to_str().unwrap().to_string();

        // Import a layer directly into repo_b.
        let tar_bytes = build_oci_tar_layer(128 * 1024);
        let diff_id = composefs_oci::sha256_content_digest(&tar_bytes);
        let (layer_verity, _) =
            composefs_oci::import_layer(&repo_b, &diff_id, None, tar_bytes.as_slice())
                .await
                .expect("import_layer into repo_b");

        // Build config + manifest JSON.
        let diff_ids = vec![diff_id.to_string()];
        let config_json = make_config_json(&diff_ids);
        let config_digest = composefs_oci::sha256_content_digest(config_json.as_bytes());
        let manifest_json = make_manifest_json(&config_json, config_digest.as_ref(), &diff_ids);

        // Start the in-process service on repo B.
        let service_b = CfsctlService::insecure_for_test();
        let (mut client_b, _srv_b) = spawn_in_process(service_b).unwrap();

        let handle_b = client_b
            .open_repository(Some(&repo_b_path), None, None)
            .await
            .unwrap()
            .expect("open_repository B")
            .handle;

        // Build the LayerRef list.
        let layers = vec![super::layer_sync::LayerRef {
            diff_id: diff_id.to_string(),
            layer_verity: layer_verity.to_hex(),
        }];

        // Call finalize_image.
        let reply = client_b
            .finalize_image(
                handle_b,
                &manifest_json,
                &config_json,
                layers,
                Some("finalize-test:v1"),
            )
            .await
            .unwrap()
            .expect("finalize_image");

        // Digests must be non-empty strings.
        assert!(
            !reply.manifest_digest.is_empty(),
            "manifest_digest must be non-empty"
        );
        assert!(
            !reply.manifest_verity.is_empty(),
            "manifest_verity must be non-empty"
        );
        assert!(
            !reply.config_digest.is_empty(),
            "config_digest must be non-empty"
        );
        assert!(
            !reply.config_verity.is_empty(),
            "config_verity must be non-empty"
        );

        // Manifest and config splitstreams must now exist in repo_b.
        let manifest_digest: OciDigest = reply.manifest_digest.parse().unwrap();
        let config_digest2: OciDigest = reply.config_digest.parse().unwrap();

        let manifest_id = composefs_oci::oci_image::manifest_identifier(&manifest_digest);
        assert!(
            repo_b
                .has_stream(&manifest_id)
                .expect("has_stream manifest")
                .is_some(),
            "manifest splitstream must exist in repo_b"
        );

        // The config stream key follows the pattern "oci-config-<digest>".
        let config_id2 = format!("oci-config-{config_digest2}");
        assert!(
            repo_b
                .has_stream(&config_id2)
                .expect("has_stream config")
                .is_some(),
            "config splitstream must exist in repo_b"
        );

        // EROFS must have been generated.
        let manifest_verity =
            Sha256HashValue::from_hex(&reply.manifest_verity).expect("parse manifest_verity");
        let erofs = composefs_oci::composefs_erofs_for_manifest(
            &repo_b,
            &manifest_digest,
            Some(&manifest_verity),
            repo_b.erofs_version(),
        )
        .expect("composefs_erofs_for_manifest");
        assert!(
            erofs.is_some(),
            "EROFS image must exist after finalize_image"
        );
    }
}
