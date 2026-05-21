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

/// Reply carrying an opaque repository handle.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct OpenRepositoryReply {
    /// The opaque handle to pass to subsequent repository methods.
    pub handle: u64,
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

    /// Resolve, open and register a repository at `path`, returning its handle.
    ///
    /// The digest algorithm is detected from the repository metadata; both
    /// resolution and open failures are reported as
    /// [`RepositoryError::RepoNotFound`].
    fn do_open(
        &mut self,
        path: &Path,
        owner: Option<usize>,
    ) -> std::result::Result<u64, RepositoryError> {
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
        self.repos.insert(handle, HandleEntry { repo, owner });
        Ok(handle)
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
        CfsctlService, FsckReply, GcReply, ImageObjectsReply, InitRepositoryReply, OpenRepo,
        OpenRepositoryReply, RepositoryError, run_fsck, run_gc, run_image_objects,
        run_init_repository,
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
            let handle = self.do_open(&selected, Some(conn.id()))?;
            Ok(OpenRepositoryReply { handle })
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
    }
}

// Combined variant: hosts BOTH the `org.composefs.Repository` and
// `org.composefs.Oci` interfaces from a single impl block on `CfsctlService`,
// so one service answers both interfaces on one socket. See the comment above
// for why this can't be cfg-gated method-by-method.
#[cfg(feature = "oci")]
mod service_impl {
    #![allow(missing_docs)]

    use super::oci::{
        ListImagesReply, OciComputeIdReply, OciError, OciFsckReply, OciInspectReply, PullProgress,
        parse_local_fetch, pull_stream,
    };
    use super::{
        CfsctlService, FsckReply, GcReply, ImageObjectsReply, InitRepositoryReply, OpenRepo,
        OpenRepositoryReply, RepositoryError, run_compute_id, run_fsck, run_gc, run_image_objects,
        run_init_repository, run_inspect, run_list_images, run_oci_fsck, run_tag, run_untag,
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
            let handle = self.do_open(&selected, Some(conn.id()))?;
            Ok(OpenRepositoryReply { handle })
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
        > + Send {
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

    async fn accept(&mut self) -> zlink::Result<zlink::Connection<Self::Socket>> {
        match self.conn.take() {
            Some(conn) => Ok(conn),
            None => std::future::pending().await,
        }
    }
}

/// Try to build an [`ActivatedListener`] from a socket-activated fd.
///
/// Uses `libsystemd` to receive file descriptors passed by the service
/// manager (checks `LISTEN_FDS`/`LISTEN_PID` and clears the env vars).
/// Returns `None` when the process was not socket-activated.
#[allow(unsafe_code)]
pub(crate) fn try_activated_listener() -> Result<Option<ActivatedListener>> {
    use std::os::fd::{FromRawFd as _, IntoRawFd as _};

    let fds = libsystemd::activation::receive_descriptors(true)
        .map_err(|e| anyhow::anyhow!("Failed to receive activation fds: {e}"))?;

    let fd = match fds.into_iter().next() {
        Some(fd) => fd,
        None => return Ok(None),
    };

    // SAFETY: `libsystemd::activation::receive_descriptors(true)` validated
    // the fd and transferred ownership. `into_raw_fd()` consumes the
    // `FileDescriptor` wrapper, giving us sole ownership of a valid fd.
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd.into_raw_fd()) };
    std_stream
        .set_nonblocking(true)
        .context("setting systemd socket to non-blocking")?;
    let tokio_stream = tokio::net::UnixStream::from_std(std_stream)
        .context("converting systemd UnixStream to tokio")?;
    let zlink_stream = zlink::unix::Stream::from(tokio_stream);
    let conn = zlink::Connection::from(zlink_stream);
    Ok(Some(ActivatedListener { conn: Some(conn) }))
}

/// Serve `service` on an already-obtained socket-activated listener.
///
/// Status is logged, never written to stdout: under socket activation (e.g.
/// varlinkctl's `exec:` transport) the parent may treat our stdout as part of
/// the protocol handshake, and any stray bytes there reset the connection.
pub(crate) async fn serve_activated<S>(service: S, listener: ActivatedListener) -> Result<()>
where
    S: zlink::Service<zlink::unix::Stream>,
{
    log::info!("Listening on systemd-activated socket");
    let server = zlink::Server::new(listener, service);
    server
        .run()
        .await
        .context("running varlink server (activated)")
}

/// Serve `service` either on a systemd-activated connected socket or by
/// binding a fresh Unix socket at `address`.
///
/// Socket activation takes precedence: if the process was started with a
/// connected activation socket, `address` is ignored. Otherwise `address`
/// must be `Some`, or this returns an error.
pub(crate) async fn serve<S>(service: S, address: Option<&Path>) -> Result<()>
where
    S: zlink::Service<zlink::unix::Stream>,
{
    if let Some(activated) = try_activated_listener()? {
        return serve_activated(service, activated).await;
    }
    let address = address.context("no --address given and not socket-activated")?;
    let listener = zlink::unix::bind(address)
        .with_context(|| format!("binding varlink socket at {}", address.display()))?;
    log::info!("Listening on {}", address.display());
    let server = zlink::Server::new(listener, service);
    server.run().await.context("running varlink server")
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
                composefs_erofs: img.image_ref().map(|id| id.to_hex()),
                composefs_boot_erofs: img.boot_image_ref().map(|id| id.to_hex()),
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
                > + Send,
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
        let handle = tokio::spawn(async move {
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
    use super::oci::{
        ListImagesReply, OciComputeIdReply, OciError, OciFsckReply, OciInspectReply, PullProgress,
    };
    use super::{
        FsckReply, GcReply, ImageObjectsReply, InitRepositoryReply, OpenRepositoryReply,
        RepositoryError,
    };
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
    }
}

#[cfg(feature = "oci")]
pub(crate) use oci::*;
