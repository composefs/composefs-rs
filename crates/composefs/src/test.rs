//! Test utilities for composefs.
//!
//! This module provides helpers for writing tests, including temporary
//! directory allocation and repository initialization.
//!
//! These are test helpers (exposed for downstream crates' tests), so the
//! diagnostics here intentionally go to stderr.
#![allow(clippy::print_stderr)]

use std::{ffi::OsString, fs::create_dir_all, path::PathBuf, sync::Arc};

use once_cell::sync::Lazy;
use rustix::fs::CWD;
use tempfile::TempDir;

use crate::{fsverity::FsVerityHashValue, repository::Repository};

static TMPDIR: Lazy<OsString> = Lazy::new(|| {
    if let Some(path) = std::env::var_os("CFS_TEST_TMPDIR") {
        eprintln!("temporary directory from $CFS_TEST_TMPDIR: {path:?}");
        path
    } else {
        // We can't use /tmp because that's usually a tmpfs (no fsverity)
        // We also can't use /var/tmp because it's an overlayfs in toolbox (no fsverity)
        // So let's try something in the user's homedir?
        let home = std::env::var("HOME").expect("$HOME must be set when running tests");
        let tmp = PathBuf::from(home).join(".var/tmp");
        create_dir_all(&tmp).expect("can't create ~/.var/tmp");
        eprintln!("temporary directory from ~/.var/tmp: {tmp:?}");
        tmp.into()
    }
});

/// Allocate a temporary directory.
///
/// This creates a temporary directory in a location that supports fs-verity
/// when possible (avoiding tmpfs and overlayfs).
pub fn tempdir() -> TempDir {
    TempDir::with_prefix_in("composefs-test-", TMPDIR.as_os_str()).unwrap()
}

#[cfg(test)]
pub(crate) fn tempfile() -> std::fs::File {
    tempfile::tempfile_in(TMPDIR.as_os_str()).unwrap()
}

/// A test repository with its backing temporary directory.
///
/// The repository is configured in insecure mode so tests can run on
/// filesystems that don't support fs-verity. The temporary directory
/// is cleaned up when this struct is dropped.
#[derive(Debug)]
pub struct TestRepo<ObjectID: FsVerityHashValue> {
    /// The repository, wrapped in Arc for sharing.
    pub repo: Arc<Repository<ObjectID>>,
    /// Path to the repository directory within the tempdir.
    repo_path: PathBuf,
    /// The backing temporary directory (kept alive for the repo's lifetime).
    _tempdir: TempDir,
}

impl<ObjectID: FsVerityHashValue> TestRepo<ObjectID> {
    /// Create a new test repository in insecure mode.
    ///
    /// The repository is created in a temporary directory and configured
    /// to work without fs-verity support.
    pub fn new() -> Self {
        let dir = tempdir();
        let repo_path = dir.path().join("repo");
        let (repo, _) = Repository::init_path(CWD, &repo_path, ObjectID::ALGORITHM, false)
            .expect("initializing test repo");
        Self {
            repo: Arc::new(repo),
            repo_path,
            _tempdir: dir,
        }
    }

    /// Returns the filesystem path of the repository root.
    ///
    /// Useful in tests that need to manipulate the on-disk layout directly
    /// (e.g. corruption tests for fsck).
    pub fn path(&self) -> &std::path::Path {
        &self.repo_path
    }

    /// Returns a capability-based directory handle for the repository root.
    ///
    /// Tests should use this instead of raw `std::fs` operations to ensure
    /// all filesystem manipulation is scoped to the repository directory.
    ///
    /// Only available when compiling this crate's own tests (cap-std is a
    /// dev-dependency). Cross-crate consumers should construct a
    /// `cap_std::fs::Dir` from [`path()`](Self::path) directly.
    #[cfg(test)]
    pub fn dir(&self) -> cap_std::fs::Dir {
        cap_std::fs::Dir::open_ambient_dir(&self.repo_path, cap_std::ambient_authority()).unwrap()
    }
}

impl<ObjectID: FsVerityHashValue> Default for TestRepo<ObjectID> {
    fn default() -> Self {
        Self::new()
    }
}

/// Proptest strategies for generating random `tree::FileSystem` instances.
///
/// These strategies build the tree directly (not through dumpfile strings),
/// which means they can express things like hardlinks (shared `Rc<Leaf>`)
/// that are awkward to generate as text.
///
/// The spec types are hash-type-agnostic: external file references store
/// raw random bytes, and `build_filesystem` constructs the appropriate
/// `ObjectID` from them via `from_hex`. This lets the same generated spec
/// be used with both `Sha256HashValue` and `Sha512HashValue`.
#[cfg(test)]
pub(crate) mod proptest_strategies {
    use std::{
        collections::BTreeMap,
        ffi::{OsStr, OsString},
        mem,
        os::unix::ffi::OsStringExt,
    };

    use proptest::prelude::*;

    use crate::{
        INLINE_CONTENT_MAX_V0,
        fsverity::FsVerityHashValue,
        generic_tree::LeafId,
        tree::{self, RegularFile},
    };

    /// Maximum filename length (single directory entry name) on Linux.
    /// This is `NAME_MAX` from POSIX / `<linux/limits.h>`, and also the
    /// EROFS limit (`EROFS_NAME_LEN`).
    const NAME_MAX: usize = 255;

    use crate::SYMLINK_MAX;

    /// Strategy for valid filenames as OsString.
    ///
    /// Linux filenames are arbitrary bytes except `/` (0x2F) and `\0` (0x00),
    /// with a max length of [`NAME_MAX`] (255) bytes.  We generate a mix of
    /// ASCII names and binary names, occasionally long, to exercise directory
    /// entry layout edge cases.
    pub fn filename() -> impl Strategy<Value = OsString> {
        prop_oneof![
            // Short ASCII names (common case)
            6 => proptest::string::string_regex("[a-zA-Z0-9._-]{1,20}")
                .expect("valid regex")
                .prop_map(OsString::from),
            // Binary names with arbitrary bytes (no NUL or /)
            3 => prop::collection::vec(1..=0xFEu8, 1..=30)
                .prop_map(|mut v| { v.iter_mut().for_each(|b| if *b == b'/' { *b = b'_' }); OsString::from_vec(v) }),
            // Long ASCII names (up to NAME_MAX)
            1 => proptest::string::string_regex(&format!("[a-zA-Z0-9._-]{{100,{NAME_MAX}}}"))
                .expect("valid regex")
                .prop_map(OsString::from),
        ]
        .prop_filter("reserved names", |s| s != "." && s != "..")
    }

    /// Strategy for `tree::Stat` with random metadata.
    pub fn stat() -> impl Strategy<Value = tree::Stat> {
        (
            0..=0o7777u32,        // permission bits
            0..=65535u32,         // uid
            0..=65535u32,         // gid
            0..=2_000_000_000i64, // mtime
            xattrs(),
        )
            .prop_map(|(mode, uid, gid, mtime, xattrs)| tree::Stat {
                st_mode: mode,
                st_uid: uid,
                st_gid: gid,
                st_mtim_sec: mtime,
                xattrs,
            })
    }

    /// Strategy for xattr keys covering all erofs prefix namespaces.
    ///
    /// The erofs format uses prefix indices to compress xattr names:
    ///   0 = "" (fallback), 1 = "user.", 2 = "system.posix_acl_access",
    ///   3 = "system.posix_acl_default", 4 = "trusted.", 5 = "lustre.",
    ///   6 = "security."
    ///
    /// The writer also escapes `trusted.overlay.*` → `trusted.overlay.overlay.*`,
    /// so we must test that path too.
    fn xattr_key() -> impl Strategy<Value = String> {
        prop_oneof![
            // user.* namespace (index 1) — most common
            3 => (0..5u32).prop_map(|n| format!("user.test_{n}")),
            // security.* namespace (index 6) — e.g. SELinux
            2 => prop_oneof![
                Just("security.selinux".to_string()),
                Just("security.ima".to_string()),
                Just("security.capability".to_string()),
            ],
            // trusted.* but NOT overlay (index 4)
            1 => (0..3u32).prop_map(|n| format!("trusted.test_{n}")),
            // trusted.overlay.* — exercises the escape/unescape path
            2 => prop_oneof![
                Just("trusted.overlay.custom".to_string()),
                Just("trusted.overlay.origin".to_string()),
                Just("trusted.overlay.upper".to_string()),
                // This one tests double-escaping: it becomes
                // trusted.overlay.overlay.overlay.nested on disk
                Just("trusted.overlay.overlay.nested".to_string()),
            ],
            // system.posix_acl_access (index 2) — exact name, no suffix
            1 => Just("system.posix_acl_access".to_string()),
            // system.posix_acl_default (index 3) — exact name, no suffix
            1 => Just("system.posix_acl_default".to_string()),
        ]
    }

    /// Strategy for 0-4 extended attributes across diverse namespaces.
    fn xattrs() -> impl Strategy<Value = BTreeMap<Box<OsStr>, Box<[u8]>>> {
        prop::collection::vec(
            (xattr_key(), prop::collection::vec(any::<u8>(), 0..=20)),
            0..=4,
        )
        .prop_map(|pairs| {
            let mut map = BTreeMap::new();
            for (key, value) in pairs {
                map.insert(Box::from(OsStr::new(&key)), value.into_boxed_slice());
            }
            map
        })
    }

    /// Strategy for symlink targets as OsString.
    ///
    /// Symlink targets on Linux are arbitrary bytes except `\0`, up to
    /// [`SYMLINK_MAX`] (1024) bytes, matching the XFS limit.
    fn symlink_target() -> impl Strategy<Value = OsString> {
        prop_oneof![
            // Short path-like ASCII target (common case)
            6 => proptest::string::string_regex("[a-zA-Z0-9/._-]{1,50}")
                .expect("valid regex")
                .prop_map(OsString::from),
            // Binary target with arbitrary bytes (no NUL)
            3 => prop::collection::vec(1..=0xFFu8, 1..=100)
                .prop_map(OsString::from_vec),
            // Long ASCII target (up to SYMLINK_MAX)
            1 => proptest::string::string_regex(&format!("[a-zA-Z0-9/._-]{{100,{SYMLINK_MAX}}}"))
                .expect("valid regex")
                .prop_map(OsString::from),
        ]
    }

    /// Hash-type-agnostic leaf content for the spec.
    ///
    /// External file references store raw hash bytes rather than a concrete
    /// `ObjectID` type, so the same spec works with any hash algorithm.
    #[derive(Debug)]
    pub enum LeafContentSpec {
        Inline(Vec<u8>),
        /// External file: random hash bytes (truncated to hash size at build time) and size.
        External(Vec<u8>, u64),
        Symlink(OsString),
        BlockDevice(u64),
        CharacterDevice(u64),
        Fifo,
    }

    /// Strategy for hash-type-agnostic leaf content.
    fn leaf_content_spec() -> impl Strategy<Value = LeafContentSpec> {
        // Generate 64 random bytes — enough for both Sha256 (32) and Sha512 (64).
        // build_filesystem will truncate to the right size.
        // Inline file data is capped at INLINE_CONTENT_MAX_V0 (64 bytes) to match
        // the composefs invariant: larger files must be external (ChunkBased).
        (
            0..10u8,
            prop::collection::vec(any::<u8>(), 0..=INLINE_CONTENT_MAX_V0),
            symlink_target(),
            prop::collection::vec(any::<u8>(), 64..=64),
            1..=1_000_000u64,
            0..=65535u64,
        )
            .prop_map(
                |(tag, file_data, symlink_target, hash_bytes, ext_size, rdev)| match tag {
                    0..=3 => LeafContentSpec::Inline(file_data),
                    4 => LeafContentSpec::External(hash_bytes, ext_size),
                    5..=6 => LeafContentSpec::Symlink(symlink_target),
                    7 => LeafContentSpec::BlockDevice(rdev),
                    8 => LeafContentSpec::CharacterDevice(rdev),
                    _ => LeafContentSpec::Fifo,
                },
            )
    }

    /// A hash-type-agnostic leaf node specification.
    #[derive(Debug)]
    pub struct LeafSpec {
        pub stat: tree::Stat,
        pub content: LeafContentSpec,
    }

    fn leaf_spec() -> impl Strategy<Value = LeafSpec> {
        (stat(), leaf_content_spec()).prop_map(|(stat, content)| LeafSpec { stat, content })
    }

    /// Strategy for a list of uniquely-named leaf specs.
    fn named_leaf_specs(max_entries: usize) -> impl Strategy<Value = Vec<(OsString, LeafSpec)>> {
        prop::collection::vec((filename(), leaf_spec()), 0..=max_entries).prop_map(|entries| {
            let mut seen = std::collections::HashSet::new();
            entries
                .into_iter()
                .filter(|(name, _)| seen.insert(name.clone()))
                .collect()
        })
    }

    /// Description of a directory to be built, including potential hardlinks.
    #[derive(Debug)]
    pub struct DirSpec {
        /// Stat metadata for this directory.
        pub stat: tree::Stat,
        /// Leaf entries in this directory.
        pub leaves: Vec<(OsString, LeafSpec)>,
        /// Subdirectory entries.
        pub subdirs: Vec<(OsString, DirSpec)>,
    }

    /// Description of a filesystem to be built, with hardlink info.
    #[derive(Debug)]
    pub struct FsSpec {
        /// Root directory specification.
        pub root: DirSpec,
        /// Hardlink pairs: which leaf to link and where.
        pub hardlinks: Vec<HardlinkSpec>,
    }

    /// Specification for a hardlink: which leaf to link and where.
    #[derive(Debug, Clone)]
    pub struct HardlinkSpec {
        /// Index into the flat list of all leaves (to pick which one to hardlink).
        pub source_index: usize,
        /// Name for the hardlink in the root directory.
        pub link_name: OsString,
    }

    /// Strategy for a subdirectory (no further nesting).
    fn subdir_spec() -> impl Strategy<Value = (OsString, DirSpec)> {
        (filename(), stat(), named_leaf_specs(10)).prop_map(|(name, stat, leaves)| {
            (
                name,
                DirSpec {
                    stat,
                    leaves,
                    subdirs: vec![],
                },
            )
        })
    }

    /// Strategy for unique subdirectories.
    fn unique_subdirs(max: usize) -> impl Strategy<Value = Vec<(OsString, DirSpec)>> {
        prop::collection::vec(subdir_spec(), 0..=max).prop_map(|dirs| {
            let mut seen = std::collections::HashSet::new();
            dirs.into_iter()
                .filter(|(name, _)| seen.insert(name.clone()))
                .collect()
        })
    }

    /// Strategy for generating a complete `FsSpec`.
    ///
    /// Generates a root directory with up to 15 file entries and up to 5
    /// subdirectories (each with up to 10 entries, max depth 2). Then
    /// optionally generates 0-3 hardlinks that reference existing leaves.
    pub fn filesystem_spec() -> impl Strategy<Value = FsSpec> {
        (
            stat(),
            named_leaf_specs(15),
            unique_subdirs(5),
            // Hardlink candidates: (source index placeholder, link name)
            prop::collection::vec((any::<usize>(), filename()), 0..=3),
        )
            .prop_map(
                |(root_stat, mut root_leaves, mut root_subdirs, hl_candidates)| {
                    // Deduplicate names across files and subdirs
                    let mut seen: std::collections::HashSet<OsString> =
                        std::collections::HashSet::new();
                    root_subdirs.retain(|(name, _)| seen.insert(name.clone()));
                    root_leaves.retain(|(name, _)| seen.insert(name.clone()));

                    // Count total leaves for hardlink source index range
                    let total_leaves: usize = root_leaves.len()
                        + root_subdirs
                            .iter()
                            .map(|(_, d)| d.leaves.len())
                            .sum::<usize>();

                    let hardlinks = if total_leaves > 0 {
                        hl_candidates
                            .into_iter()
                            .map(|(idx, name)| HardlinkSpec {
                                source_index: idx % total_leaves,
                                link_name: name,
                            })
                            .collect()
                    } else {
                        vec![]
                    };

                    FsSpec {
                        root: DirSpec {
                            stat: root_stat,
                            leaves: root_leaves,
                            subdirs: root_subdirs,
                        },
                        hardlinks,
                    }
                },
            )
    }

    /// Convert a `LeafContentSpec` into a concrete `tree::LeafContent<ObjectID>`.
    fn build_leaf_content<ObjectID: FsVerityHashValue>(
        spec: LeafContentSpec,
    ) -> tree::LeafContent<ObjectID> {
        match spec {
            LeafContentSpec::Inline(data) => {
                tree::LeafContent::Regular(RegularFile::Inline(data.into_boxed_slice()))
            }
            LeafContentSpec::External(hash_bytes, size) => {
                let hash_len = mem::size_of::<ObjectID>();
                let hex = hex::encode(&hash_bytes[..hash_len]);
                let hash = ObjectID::from_hex(&hex).unwrap();
                tree::LeafContent::Regular(RegularFile::External(hash, size))
            }
            LeafContentSpec::Symlink(target) => {
                tree::LeafContent::Symlink(target.into_boxed_os_str())
            }
            LeafContentSpec::BlockDevice(rdev) => tree::LeafContent::BlockDevice(rdev),
            LeafContentSpec::CharacterDevice(rdev) => tree::LeafContent::CharacterDevice(rdev),
            LeafContentSpec::Fifo => tree::LeafContent::Fifo,
        }
    }

    /// Build a `tree::FileSystem` from an `FsSpec`, consuming it.
    ///
    /// Generic over `ObjectID` — the same spec produces correctly-typed
    /// external file references for any hash algorithm.
    pub fn build_filesystem<ObjectID: FsVerityHashValue>(
        spec: FsSpec,
    ) -> tree::FileSystem<ObjectID> {
        let mut fs = tree::FileSystem::new(spec.root.stat);

        let mut all_leaf_ids: Vec<LeafId> = Vec::new();
        let mut used_names: std::collections::HashSet<OsString> = std::collections::HashSet::new();

        // Insert root-level leaves
        for (name, leaf_spec) in spec.root.leaves {
            let leaf_id = fs.push_leaf(leaf_spec.stat, build_leaf_content(leaf_spec.content));
            all_leaf_ids.push(leaf_id);
            used_names.insert(name.clone());
            fs.root.insert(&name, tree::Inode::leaf(leaf_id));
        }

        // Insert subdirectories
        for (dir_name, dir_spec) in spec.root.subdirs {
            let mut subdir = tree::Directory::new(dir_spec.stat);
            for (name, leaf_spec) in dir_spec.leaves {
                let leaf_id = fs.push_leaf(leaf_spec.stat, build_leaf_content(leaf_spec.content));
                all_leaf_ids.push(leaf_id);
                subdir.insert(&name, tree::Inode::leaf(leaf_id));
            }
            used_names.insert(dir_name.clone());
            fs.root
                .insert(&dir_name, tree::Inode::Directory(Box::new(subdir)));
        }

        // Insert hardlinks into the root directory
        for hl in &spec.hardlinks {
            if !all_leaf_ids.is_empty() {
                let idx = hl.source_index % all_leaf_ids.len();
                if used_names.insert(hl.link_name.clone()) {
                    let leaf_id = all_leaf_ids[idx];
                    fs.root.insert(&hl.link_name, tree::Inode::leaf(leaf_id));
                }
            }
        }

        fs
    }
}
