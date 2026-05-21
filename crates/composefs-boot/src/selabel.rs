//! SELinux security context labeling for filesystem trees.
//!
//! This module implements SELinux policy parsing and file labeling functionality.
//! It reads SELinux policy files (file_contexts, file_contexts.subs, etc.) and applies
//! appropriate security.selinux extended attributes to filesystem nodes. The implementation
//! uses regex automata for efficient pattern matching against file paths and types.

use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs::File,
    io::{BufRead, BufReader, Cursor, Read},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use fn_error_context::context;
use regex_automata::{Anchored, Input, hybrid::dfa, util::syntax};
use rustix::{
    fd::AsFd,
    fs::{Mode, OFlags, openat},
    io::Errno,
};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    tree::{Directory, DirectoryRef, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
};

/// The SELinux security context extended attribute name.
///
/// This xattr stores the SELinux label for a file (e.g., `system_u:object_r:bin_t:s0`).
/// When reading from mounted filesystems, this xattr often contains build-host labels
/// that should be stripped or regenerated based on the target system's policy.
pub const XATTR_SECURITY_SELINUX: &str = "security.selinux";

/* We build the entire SELinux policy into a single "lazy DFA" such that:
 *
 *  - the input string is the filename plus a single character representing the type of the file,
 *    using the 'file type' codes listed in selabel_file(5): 'b', 'c', 'd', 'p', 'l', 's', and '-'
 *
 *  - the output pattern ID is the index of the selected context
 *
 * The 'subs' mapping is handled as a hash table.  We consult it each time we enter a directory and
 * perform the substitution a single time at that point instead of doing it for each contained
 * file.
 *
 * We could maybe add a string table to deduplicate contexts to save memory (as they are often
 * repeated).  It's not an order-of-magnitude kind of gain, though, and it would increase code
 * complexity, and slightly decrease efficiency.
 *
 * Note: we are not 100% compatible with PCRE here, so it's theoretically possible that someone
 * could write a policy that we can't properly handle...
 */

#[context("Processing SELinux substitutions file")]
fn process_subs_file(file: impl Read, aliases: &mut HashMap<OsString, OsString>) -> Result<()> {
    // r"\s*([^\s]+)\s+([^\s]+)\s*";
    for (line_nr, item) in BufReader::new(file).lines().enumerate() {
        let line = item?;
        let mut parts = line.split_whitespace();
        let alias = match parts.next() {
            None => continue, // empty line or line with only whitespace
            Some(comment) if comment.starts_with("#") => continue,
            Some(alias) => alias,
        };
        let Some(original) = parts.next() else {
            bail!("{line_nr}: missing original path");
        };
        ensure!(parts.next().is_none(), "{line_nr}: trailing data");

        aliases.insert(OsString::from(alias), OsString::from(original));
    }
    Ok(())
}

fn process_spec_file(
    file: impl Read,
    regexps: &mut Vec<String>,
    contexts: &mut Vec<String>,
) -> Result<()> {
    // r"\s*([^\s]+)\s+(?:-([-bcdpls])\s+)?([^\s]+)\s*";
    for (line_nr, item) in BufReader::new(file).lines().enumerate() {
        let line = item?;

        let mut parts = line.split_whitespace();
        let regex = match parts.next() {
            None => continue, // empty line or line with only whitespace
            Some(comment) if comment.starts_with("#") => continue,
            Some(regex) => regex,
        };

        /* TODO: https://github.com/rust-lang/rust/issues/51114
         *  match parts.next() {
         *      Some(opt) if let Some(ifmt) = opt.strip_prefix("-") => ...
         */
        let Some(next) = parts.next() else {
            bail!("{line_nr}: missing separator after regex");
        };
        if let Some(ifmt) = next.strip_prefix("-") {
            ensure!(
                ["b", "c", "d", "p", "l", "s", "-"].contains(&ifmt),
                "{line_nr}: invalid type code -{ifmt}"
            );
            let Some(context) = parts.next() else {
                bail!("{line_nr}: missing context field");
            };
            regexps.push(format!("^({regex}){ifmt}$"));
            contexts.push(context.to_string());
        } else {
            let context = next;
            regexps.push(format!("^({regex}).$"));
            contexts.push(context.to_string());
        }
        ensure!(parts.next().is_none(), "{line_nr}: trailing data");
    }

    Ok(())
}

struct Policy {
    aliases: HashMap<OsString, OsString>,
    dfa: dfa::DFA,
    cache: dfa::Cache,
    contexts: Vec<String>,
}

/// Open a file in the composefs store, handling inline vs external files.
pub fn open_file<H: FsVerityHashValue>(
    dir: DirectoryRef<'_, H>,
    filename: impl AsRef<OsStr>,
    repo: &Repository<H>,
) -> Result<Option<Box<dyn Read>>> {
    match dir.get_file_opt(filename.as_ref())? {
        Some(file) => match file {
            RegularFile::Inline(data) => Ok(Some(Box::new(Cursor::new(data.clone())))),
            RegularFile::External(id, ..) => Ok(Some(Box::new(File::from(repo.open_object(id)?)))),
        },
        None => Ok(None),
    }
}

/// Open a file from an on-disk directory, returning None if it doesn't exist.
fn open_file_from_dir(
    dirfd: impl AsFd,
    filename: impl AsRef<OsStr>,
) -> Result<Option<Box<dyn Read>>> {
    match openat(
        dirfd,
        filename.as_ref(),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(Box::new(File::from(fd)))),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

impl Policy {
    /// Build a SELinux policy from file_contexts files opened via a callback.
    ///
    /// The callback takes a filename (e.g. "file_contexts", "file_contexts.subs")
    /// and returns an optional reader for that file.
    #[context("Building SELinux policy")]
    fn build_from(mut open: impl FnMut(&str) -> Result<Option<Box<dyn Read>>>) -> Result<Self> {
        let mut aliases = HashMap::new();
        let mut regexps = vec![];
        let mut contexts = vec![];

        for suffix in ["", ".local", ".homedirs"] {
            let name = format!("file_contexts{suffix}");
            if let Some(file) = open(&name)? {
                process_spec_file(file, &mut regexps, &mut contexts)
                    .with_context(|| format!("SELinux spec file {name}"))?;
            } else if suffix.is_empty() {
                bail!("SELinux policy is missing mandatory file_contexts file");
            }
        }

        for suffix in [".subs", ".subs_dist"] {
            let name = format!("file_contexts{suffix}");
            if let Some(file) = open(&name)? {
                process_subs_file(file, &mut aliases)
                    .with_context(|| format!("SELinux subs file {name}"))?;
            }
        }

        // The DFA matches the first-found.  We want to match the last-found.
        regexps.reverse();
        contexts.reverse();

        let mut builder = dfa::Builder::new();
        builder.syntax(
            syntax::Config::new()
                .unicode(false)
                .utf8(false)
                .line_terminator(0),
        );
        builder.configure(
            dfa::Config::new()
                .cache_capacity(10_000_000)
                .skip_cache_capacity_check(true),
        );
        let dfa = builder.build_many(&regexps)?;
        let cache = dfa.create_cache();

        Ok(Policy {
            aliases,
            dfa,
            cache,
            contexts,
        })
    }

    pub fn check_aliased(&self, filename: &OsStr) -> Option<&OsStr> {
        self.aliases.get(filename).map(|x| x.as_os_str())
    }

    // mut because it touches the cache
    pub fn lookup(&mut self, filename: &OsStr, ifmt: u8) -> Option<&str> {
        let key = &[filename.as_bytes(), &[ifmt]].concat();
        let input = Input::new(&key).anchored(Anchored::Yes);

        match self
            .dfa
            .try_search_fwd(&mut self.cache, &input)
            .expect("regex troubles")
        {
            Some(halfmatch) => match self.contexts[halfmatch.pattern()].as_str() {
                "<<none>>" => None,
                ctx => Some(ctx),
            },
            None => None,
        }
    }
}

fn relabel(stat: &mut Stat, path: &Path, ifmt: u8, policy: &mut Policy) {
    let key = OsStr::new(XATTR_SECURITY_SELINUX);

    if let Some(label) = policy.lookup(path.as_os_str(), ifmt) {
        stat.xattrs
            .insert(Box::from(key), Box::from(label.as_bytes()));
    } else {
        stat.xattrs.remove(key);
    }
}

fn relabel_dir<H: FsVerityHashValue>(
    dir: &mut Directory<H>,
    leaves: &mut Vec<Leaf<H>>,
    path: &mut PathBuf,
    policy: &mut Policy,
    // Tracks the SELinux label committed when a LeafId was first labeled.
    // `None` means the leaf was labeled but with no security.selinux xattr.
    // Absence from the map means the leaf hasn't been labeled yet.
    labeled: &mut HashMap<composefs::generic_tree::LeafId, Option<Box<[u8]>>>,
) {
    use composefs::generic_tree::LeafId;

    relabel(&mut dir.stat, path, b'd', policy);

    // Collect entry names and types to avoid borrow conflicts during mutation.
    let children: Vec<(Box<OsStr>, Option<LeafId>)> = dir
        .sorted_entries()
        .map(|(name, inode)| {
            let id = match inode {
                Inode::Leaf(id, _) => Some(*id),
                Inode::Directory(_) => None,
            };
            (Box::from(name), id)
        })
        .collect();

    for (name, leaf_id) in children {
        path.push(Path::new(&name));
        let aliased_path = policy.check_aliased(path.as_os_str()).map(PathBuf::from);
        let effective_path = aliased_path.as_deref().unwrap_or(path.as_path());

        if let Some(id) = leaf_id {
            // Compute what label this path would get.
            let ifmt = match leaves[id.0].content {
                LeafContent::Regular(..) => b'-',
                LeafContent::Fifo => b'p',
                LeafContent::Socket => b's',
                LeafContent::Symlink(..) => b'l',
                LeafContent::BlockDevice(..) => b'b',
                LeafContent::CharacterDevice(..) => b'c',
            };
            let new_label: Option<&str> = policy.lookup(effective_path.as_os_str(), ifmt);

            // Check if this LeafId was already labeled (i.e., is a hardlink).
            let effective_id = if let Some(prev_label) = labeled.get(&id) {
                // Compare the previously-committed label with the new one.
                let labels_match = match (prev_label.as_deref(), new_label) {
                    (Some(p), Some(n)) => p == n.as_bytes(),
                    (None, None) => true,
                    _ => false,
                };

                if labels_match {
                    // Same label: share the leaf as-is.
                    id
                } else {
                    // Different label: break the hardlink by cloning the leaf
                    // into a new slot and updating this directory entry to
                    // point to the clone.
                    let clone = leaves[id.0].clone();
                    let new_id = LeafId(leaves.len());
                    leaves.push(clone);
                    // Update the directory entry to use the new LeafId.
                    dir.remap_leaf(name.as_ref(), new_id);
                    new_id
                }
            } else {
                id
            };

            // Apply the label to the (possibly cloned) leaf.
            let key = OsStr::new(XATTR_SECURITY_SELINUX);
            if let Some(label) = new_label {
                leaves[effective_id.0]
                    .stat
                    .xattrs
                    .insert(Box::from(key), Box::from(label.as_bytes()));
            } else {
                leaves[effective_id.0].stat.xattrs.remove(key);
            }

            // Record the label committed to this LeafId.
            labeled
                .entry(effective_id)
                .or_insert_with(|| new_label.map(|l| Box::from(l.as_bytes())));
        } else {
            let mut sub_path = effective_path.to_path_buf();
            let subdir = dir.get_directory_mut(name.as_ref()).unwrap();
            relabel_dir(subdir, leaves, &mut sub_path, policy, labeled);
        }

        path.pop();
    }
}

fn parse_config(file: impl Read) -> Result<Option<String>> {
    for line in BufReader::new(file).lines() {
        if let Some((key, value)) = line?.split_once('=') {
            // this might be a comment, but then key will start with '#'
            if key.trim().eq_ignore_ascii_case("SELINUXTYPE") {
                return Ok(Some(value.trim().to_string()));
            }
        }
    }
    Ok(None)
}

fn strip_selinux_labels<H: FsVerityHashValue>(fs: &mut FileSystem<H>) {
    fs.for_each_stat_mut(|stat| {
        stat.xattrs.remove(OsStr::new(XATTR_SECURITY_SELINUX));
    });
}

/// Build a Policy from a file-open callback, or return None if /etc/selinux/config
/// is missing or doesn't specify a policy type.
fn build_policy(
    mut open_config: impl FnMut(&str) -> Result<Option<Box<dyn Read>>>,
    mut open_policy_file: impl FnMut(&str, &str) -> Result<Option<Box<dyn Read>>>,
) -> Result<Option<Policy>> {
    let Some(etc_selinux_config) = open_config("config")? else {
        return Ok(None);
    };

    let Some(policy_name) = parse_config(etc_selinux_config)? else {
        return Ok(None);
    };

    let policy = Policy::build_from(|filename| open_policy_file(&policy_name, filename))?;
    Ok(Some(policy))
}

/// Apply a pre-built policy to the filesystem tree, or strip labels if no policy.
fn apply_policy<H: FsVerityHashValue>(fs: &mut FileSystem<H>, policy: Option<Policy>) -> bool {
    match policy {
        Some(mut policy) => {
            let mut path = PathBuf::from("/");
            let mut labeled = HashMap::new();
            let FileSystem { root, leaves } = fs;
            relabel_dir(root, leaves, &mut path, &mut policy, &mut labeled);
            true
        }
        None => {
            strip_selinux_labels(fs);
            false
        }
    }
}

/// Applies SELinux security contexts to all files in a filesystem tree.
///
/// Reads the SELinux policy from /etc/selinux/config and corresponding policy files,
/// then labels all filesystem nodes with appropriate security.selinux extended attributes.
///
/// If no SELinux policy is found in the target filesystem, any existing `security.selinux`
/// xattrs are stripped. This prevents build-time SELinux labels (e.g., `container_t`) from
/// leaking into the final image when targeting a non-SELinux host.
///
/// # Arguments
///
/// * `fs` - The filesystem to label
/// * `repo` - The composefs repository
///
/// # Returns
///
/// Returns `Ok(true)` if SELinux labeling was performed (policy was found),
/// or `Ok(false)` if no policy was found and existing labels were stripped.
#[context("Applying SELinux labels to filesystem")]
pub fn selabel<H: FsVerityHashValue>(fs: &mut FileSystem<H>, repo: &Repository<H>) -> Result<bool> {
    // Build the policy while only borrowing fs.root immutably.
    let policy = {
        let root = fs.as_dir();
        let Some(etc_selinux) = root.get_directory_ref_opt("etc/selinux".as_ref())? else {
            strip_selinux_labels(fs);
            return Ok(false);
        };

        build_policy(
            |filename| open_file(etc_selinux, filename, repo),
            |policy_name, filename| {
                let dir = etc_selinux
                    .get_directory_ref(policy_name.as_ref())?
                    .get_directory_ref("contexts/files".as_ref())?;
                open_file(dir, filename, repo)
            },
        )?
    };

    // Now we can mutably borrow fs for relabeling.
    Ok(apply_policy(fs, policy))
}

/// Applies SELinux security contexts by reading policy files from an on-disk directory.
///
/// This is an alternative to [`selabel`] that reads SELinux policy files directly from
/// a mounted filesystem via a directory file descriptor, rather than from a composefs
/// repository. This avoids the need to store file objects in the repository just to
/// compute SELinux labels.
///
/// The directory fd should point to the root of the filesystem being labeled
/// (the same filesystem that was read into the `FileSystem` tree).
///
/// # Arguments
///
/// * `fs` - The filesystem tree to label
/// * `rootfs` - A directory fd pointing to the root of the on-disk filesystem
///
/// # Returns
///
/// Returns `Ok(true)` if SELinux labeling was performed (policy was found),
/// or `Ok(false)` if no policy was found and existing labels were stripped.
#[context("Applying SELinux labels to filesystem from directory")]
pub fn selabel_from_dir(
    fs: &mut FileSystem<impl FsVerityHashValue>,
    rootfs: impl AsFd,
) -> Result<bool> {
    // Open /etc/selinux as a directory fd, treating NOENT as "no policy"
    let etc_selinux = match openat(
        &rootfs,
        "etc/selinux",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => {
            strip_selinux_labels(fs);
            return Ok(false);
        }
        Err(e) => return Err(e.into()),
    };

    let policy = build_policy(
        |filename| open_file_from_dir(&etc_selinux, filename),
        |policy_name, filename| {
            let path = format!("{policy_name}/contexts/files/{filename}");
            open_file_from_dir(&etc_selinux, path)
        },
    )?;

    Ok(apply_policy(fs, policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    use composefs::dumpfile::dumpfile_to_filesystem;
    use composefs::fsverity::Sha256HashValue;
    use composefs::generic_tree::LeafId;
    use composefs::test::TestRepo;
    use indoc::indoc;

    /// Walk the directory tree and collect every LeafId referenced anywhere in it.
    fn collect_leaf_ids(dir: &Directory<Sha256HashValue>) -> Vec<LeafId> {
        let mut ids = Vec::new();
        for inode in dir.inodes() {
            match inode {
                Inode::Directory(sub) => ids.extend(collect_leaf_ids(sub)),
                Inode::Leaf(id, _) => ids.push(*id),
            }
        }
        ids
    }

    /// Assert that no LeafId is referenced more than once in the filesystem —
    /// i.e., after selabel has broken all cross-domain hardlinks, every path
    /// has its own unique inode.
    fn assert_no_hardlinks(fs: &FileSystem<Sha256HashValue>) {
        let ids = collect_leaf_ids(&fs.root);
        let mut seen = std::collections::HashSet::new();
        for id in &ids {
            assert!(
                seen.insert(id.0),
                "LeafId {} is shared between two paths after selabel (hardlink not broken)",
                id.0,
            );
        }
    }

    /// Get the SELinux label from a Stat's xattrs, if any.
    fn selinux_label(stat: &Stat) -> Option<String> {
        stat.xattrs
            .get(OsStr::new(XATTR_SECURITY_SELINUX))
            .map(|v| String::from_utf8_lossy(v).into())
    }

    /// Look up a path in the filesystem and return its SELinux label.
    ///
    /// Panics if the path doesn't exist.  Returns `None` if the node
    /// has no `security.selinux` xattr.
    fn get_label(fs: &FileSystem<Sha256HashValue>, path: &str) -> Option<String> {
        if path == "/" {
            return selinux_label(&fs.root.stat);
        }
        let p = Path::new(path);
        let parent = p.parent().unwrap();
        let name = p.file_name().unwrap();
        let root = fs.as_dir();
        let dir = if parent == Path::new("/") {
            root
        } else {
            root.get_directory_ref(parent.as_os_str()).unwrap()
        };
        match dir
            .lookup(name)
            .unwrap_or_else(|| panic!("{path} not found"))
        {
            Inode::Directory(d) => selinux_label(&d.stat),
            Inode::Leaf(leaf_id, _) => selinux_label(&fs.leaf(*leaf_id).stat),
        }
    }

    /// Build a filesystem with an embedded SELinux policy from the given
    /// raw file_contexts content, then merge in additional entries from a
    /// dumpfile string.
    ///
    /// `file_contexts` and values in `extra_policy_files` are raw bytes
    /// (real tabs, newlines, etc.).
    ///
    /// `extra_policy_files` can supply additional policy files like
    /// `file_contexts.local` or `file_contexts.subs`.
    fn build_fs_with_selinux(
        file_contexts: &[u8],
        extra_policy_files: &[(&str, &[u8])],
        fs_entries: &str,
    ) -> FileSystem<Sha256HashValue> {
        use composefs::dumpfile::write_dumpfile;

        let dir_stat = || Stat {
            st_mode: 0o40755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 0,
            st_mtim_nsec: 0,
            xattrs: Default::default(),
        };

        let mut fs = FileSystem::<Sha256HashValue>::new(dir_stat());

        // Helper: push an inline file leaf and return its Inode.
        let push_inline =
            |fs: &mut FileSystem<Sha256HashValue>, data: &[u8]| -> Inode<Sha256HashValue> {
                let id = fs.push_leaf(
                    Stat {
                        st_mode: 0o100644,
                        st_uid: 0,
                        st_gid: 0,
                        st_mtim_sec: 0,
                        st_mtim_nsec: 0,
                        xattrs: Default::default(),
                    },
                    LeafContent::Regular(RegularFile::Inline(data.to_vec().into_boxed_slice())),
                );
                Inode::leaf(id)
            };

        // Build a tree containing the SELinux policy files, serialize it
        // via the dumpfile writer so escaping is handled correctly, then
        // append the caller's additional entries and parse the whole thing.
        let selinux_config = b"SELINUX=enforcing\nSELINUXTYPE=targeted\n";

        // Create the directory tree
        for path in [
            "etc",
            "etc/selinux",
            "etc/selinux/targeted",
            "etc/selinux/targeted/contexts",
            "etc/selinux/targeted/contexts/files",
        ] {
            let (dir, name) = fs.root.split_mut(path.as_ref()).unwrap();
            dir.insert(name, Inode::Directory(Box::new(Directory::new(dir_stat()))));
        }
        let config_inode = push_inline(&mut fs, selinux_config);
        fs.root
            .get_directory_mut("etc/selinux".as_ref())
            .unwrap()
            .insert(OsStr::new("config"), config_inode);

        // Insert file_contexts and extra policy files
        let fc_inode = push_inline(&mut fs, file_contexts);
        let extra_inodes: Vec<_> = extra_policy_files
            .iter()
            .map(|(name, content)| (name.to_string(), push_inline(&mut fs, content)))
            .collect();

        let files_dir = fs
            .root
            .get_directory_mut("etc/selinux/targeted/contexts/files".as_ref())
            .unwrap();
        files_dir.insert(OsStr::new("file_contexts"), fc_inode);
        for (name, inode) in extra_inodes {
            files_dir.insert(OsStr::new(&name), inode);
        }

        // Serialize via the proper dumpfile writer, append extra entries, re-parse
        let mut buf = Vec::new();
        write_dumpfile(&mut buf, &fs).unwrap();
        let mut dumpfile = String::from_utf8(buf).unwrap();
        dumpfile.push_str(fs_entries);
        dumpfile_to_filesystem(&dumpfile).unwrap()
    }

    /// Verify that selabel() applies the correct SELinux contexts from
    /// an in-memory filesystem's embedded policy files.
    #[test]
    fn selabel_applies_correct_labels() {
        let file_contexts = indoc! {b"
            /\t\tsystem_u:object_r:root_t:s0
            /usr\t\tsystem_u:object_r:usr_t:s0
            /usr/bin(/.*)?\t\tsystem_u:object_r:bin_t:s0
            /etc(/.*)?\t\tsystem_u:object_r:etc_t:s0
        "};

        let fs_entries = "\
/boot 0 40755 2 0 0 0 0.0 - - -
/etc/hostname 9 100644 1 0 0 0 0.0 - testhost\\n -
/sysroot 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 1000.0 - - -
/usr/bin 0 40755 2 0 0 0 1000.0 - - -
/usr/bin/hello 21 100755 1 0 0 0 0.0 - #!/bin/sh\\necho\\x20hello\\n -
";
        let mut fs = build_fs_with_selinux(file_contexts, &[], fs_entries);
        let test_repo = TestRepo::<Sha256HashValue>::new();

        assert!(selabel(&mut fs, &test_repo.repo).unwrap());

        assert_eq!(get_label(&fs, "/").unwrap(), "system_u:object_r:root_t:s0");
        assert_eq!(
            get_label(&fs, "/usr").unwrap(),
            "system_u:object_r:usr_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/usr/bin").unwrap(),
            "system_u:object_r:bin_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/usr/bin/hello").unwrap(),
            "system_u:object_r:bin_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/etc").unwrap(),
            "system_u:object_r:etc_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/etc/hostname").unwrap(),
            "system_u:object_r:etc_t:s0"
        );
    }

    /// Verify that selabel() strips pre-existing labels when no policy is found.
    #[test]
    fn selabel_strips_when_no_policy() {
        let dumpfile = "\
/ 0 40755 2 0 0 0 0.0 - - -
/file 1 100644 1 0 0 0 0.0 - x - security.selinux=old_label
";
        let mut fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let test_repo = TestRepo::<Sha256HashValue>::new();

        assert!(!selabel(&mut fs, &test_repo.repo).unwrap());
        assert!(get_label(&fs, "/").is_none());
        assert!(get_label(&fs, "/file").is_none());
    }

    /// Verify that type-specific file_contexts rules (e.g. `-d`, `--`, `-l`)
    /// label different inode types independently.
    #[test]
    fn selabel_type_specific_labels() {
        // /var/log directories get var_log_dir_t, regular files get
        // var_log_t, and symlinks get var_log_link_t.
        let file_contexts = indoc! {b"
            /var(/.*)?		system_u:object_r:var_t:s0
            /var/log(/.*)? -d system_u:object_r:var_log_dir_t:s0
            /var/log(/.*)? -- system_u:object_r:var_log_t:s0
            /var/log(/.*)? -l system_u:object_r:var_log_link_t:s0
        "};

        let fs_entries = "\
/var 0 40755 2 0 0 0 0.0 - - -
/var/log 0 40755 2 0 0 0 0.0 - - -
/var/log/messages 10 100644 1 0 0 0 0.0 - 0123456789 -
/var/log/current 4 120777 1 0 0 0 0.0 /var/log/messages - -
";
        let mut fs = build_fs_with_selinux(file_contexts, &[], fs_entries);
        let test_repo = TestRepo::<Sha256HashValue>::new();

        assert!(selabel(&mut fs, &test_repo.repo).unwrap());

        assert_eq!(
            get_label(&fs, "/var").unwrap(),
            "system_u:object_r:var_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/var/log").unwrap(),
            "system_u:object_r:var_log_dir_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/var/log/messages").unwrap(),
            "system_u:object_r:var_log_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/var/log/current").unwrap(),
            "system_u:object_r:var_log_link_t:s0"
        );
    }

    /// Verify that file_contexts.subs aliases redirect labeling lookups.
    #[test]
    fn selabel_subs_aliases() {
        let file_contexts = indoc! {b"
            /home(/.*)?		system_u:object_r:home_t:s0
        "};
        let subs_content = b"/srv/home /home\n";

        let fs_entries = "\
/home 0 40755 2 0 0 0 0.0 - - -
/home/user.txt 5 100644 1 0 0 0 0.0 - hello -
/srv 0 40755 2 0 0 0 0.0 - - -
/srv/home 0 40755 2 0 0 0 0.0 - - -
/srv/home/data.txt 5 100644 1 0 0 0 0.0 - world -
";
        let mut fs = build_fs_with_selinux(
            file_contexts,
            &[("file_contexts.subs", subs_content)],
            fs_entries,
        );
        let test_repo = TestRepo::<Sha256HashValue>::new();

        assert!(selabel(&mut fs, &test_repo.repo).unwrap());

        assert_eq!(
            get_label(&fs, "/home").unwrap(),
            "system_u:object_r:home_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/home/user.txt").unwrap(),
            "system_u:object_r:home_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/srv/home").unwrap(),
            "system_u:object_r:home_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/srv/home/data.txt").unwrap(),
            "system_u:object_r:home_t:s0"
        );
    }

    /// Verify that <<none>> in file_contexts suppresses labeling.
    #[test]
    fn selabel_none_context() {
        let file_contexts = indoc! {b"
            /tmp(/.*)?		system_u:object_r:tmp_t:s0
            /tmp/private(/.*)?		<<none>>
        "};

        let fs_entries = "\
/tmp 0 40755 2 0 0 0 0.0 - - -
/tmp/scratch.txt 5 100644 1 0 0 0 0.0 - hello -
/tmp/private 0 40755 2 0 0 0 0.0 - - -
/tmp/private/secret.txt 6 100644 1 0 0 0 0.0 - secret -
";
        let mut fs = build_fs_with_selinux(file_contexts, &[], fs_entries);
        let test_repo = TestRepo::<Sha256HashValue>::new();

        assert!(selabel(&mut fs, &test_repo.repo).unwrap());

        assert_eq!(
            get_label(&fs, "/tmp").unwrap(),
            "system_u:object_r:tmp_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/tmp/scratch.txt").unwrap(),
            "system_u:object_r:tmp_t:s0"
        );
        assert!(get_label(&fs, "/tmp/private").is_none());
        assert!(get_label(&fs, "/tmp/private/secret.txt").is_none());
    }

    /// Verify that file_contexts.local overrides are processed.
    #[test]
    fn selabel_local_overrides() {
        let file_contexts = indoc! {b"
            /opt(/.*)?		system_u:object_r:opt_t:s0
        "};
        let local_content = indoc! {b"
            /opt/custom(/.*)?		system_u:object_r:custom_t:s0
        "};

        let fs_entries = "\
/opt 0 40755 2 0 0 0 0.0 - - -
/opt/readme.txt 7 100644 1 0 0 0 0.0 - default -
/opt/custom 0 40755 2 0 0 0 0.0 - - -
/opt/custom/app 3 100755 1 0 0 0 0.0 - app -
";
        let mut fs = build_fs_with_selinux(
            file_contexts,
            &[("file_contexts.local", local_content)],
            fs_entries,
        );
        let test_repo = TestRepo::<Sha256HashValue>::new();

        assert!(selabel(&mut fs, &test_repo.repo).unwrap());

        assert_eq!(
            get_label(&fs, "/opt").unwrap(),
            "system_u:object_r:opt_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/opt/readme.txt").unwrap(),
            "system_u:object_r:opt_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/opt/custom").unwrap(),
            "system_u:object_r:custom_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/opt/custom/app").unwrap(),
            "system_u:object_r:custom_t:s0"
        );
    }

    /// Verify labeling of device nodes and FIFOs with type-specific rules.
    #[test]
    fn selabel_device_and_fifo_labels() {
        let file_contexts = indoc! {b"
            /dev(/.*)?		system_u:object_r:device_t:s0
            /dev(/.*)? -b system_u:object_r:fixed_disk_device_t:s0
            /dev(/.*)? -c system_u:object_r:tty_device_t:s0
            /dev(/.*)? -p system_u:object_r:fifo_t:s0
        "};

        let fs_entries = "\
/dev 0 40755 2 0 0 0 0.0 - - -
/dev/sda 0 60660 1 0 0 2049 0.0 - - -
/dev/tty0 0 20666 1 0 0 1024 0.0 - - -
/dev/initctl 0 10644 1 0 0 0 0.0 - - -
";
        let mut fs = build_fs_with_selinux(file_contexts, &[], fs_entries);
        let test_repo = TestRepo::<Sha256HashValue>::new();

        assert!(selabel(&mut fs, &test_repo.repo).unwrap());

        assert_eq!(
            get_label(&fs, "/dev").unwrap(),
            "system_u:object_r:device_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/dev/sda").unwrap(),
            "system_u:object_r:fixed_disk_device_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/dev/tty0").unwrap(),
            "system_u:object_r:tty_device_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/dev/initctl").unwrap(),
            "system_u:object_r:fifo_t:s0"
        );
    }

    /// Verify that hardlinked files that receive *different* SELinux labels from
    /// the policy are given independent labels — the hardlink is "broken" in the
    /// in-memory tree so each path has its own Stat with the correct label.
    ///
    /// Without this fix, `selabel` would overwrite the first path's label with the
    /// second path's label (since both point at the same `leaves[id]` slot).
    #[test]
    fn selabel_breaks_hardlinks_with_different_labels() {
        // /usr/bin/foo gets usr_t, /opt/foo (hardlink) gets opt_t.
        let file_contexts = indoc! {b"
            /(/.*)?		system_u:object_r:default_t:s0
            /usr(/.*)?	system_u:object_r:usr_t:s0
            /opt(/.*)?	system_u:object_r:opt_t:s0
        "};

        // /usr/bin/foo is written first (the "original"); /opt/foo is a hardlink.
        // Note: /etc already exists in the tree (SELinux policy lives there),
        // so we use /opt as the second directory to avoid conflicts.
        // The original must appear before the hardlink in dumpfile order.
        let fs_entries = "\
/opt 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/bin 0 40755 2 0 0 0 0.0 - - -
/usr/bin/foo 5 100644 2 0 0 0 0.0 - hello -
/opt/foo 0 @120000 - - - - 0.0 /usr/bin/foo - -
";
        let mut fs = build_fs_with_selinux(file_contexts, &[], fs_entries);
        let test_repo = TestRepo::<Sha256HashValue>::new();

        assert!(selabel(&mut fs, &test_repo.repo).unwrap());

        // Each path must carry its own correct label.
        assert_eq!(
            get_label(&fs, "/usr/bin/foo"),
            Some("system_u:object_r:usr_t:s0".into()),
            "/usr/bin/foo should have usr_t"
        );
        assert_eq!(
            get_label(&fs, "/opt/foo"),
            Some("system_u:object_r:opt_t:s0".into()),
            "/opt/foo should have opt_t"
        );

        // After breaking the hardlink the two entries must refer to *different* LeafIds.
        let usr_bin = fs.as_dir().get_directory_ref("usr/bin".as_ref()).unwrap();
        let opt = fs.as_dir().get_directory_ref("opt".as_ref()).unwrap();
        let foo_usr_id = match usr_bin.lookup(OsStr::new("foo")).unwrap() {
            Inode::Leaf(id, _) => *id,
            _ => panic!("expected leaf"),
        };
        let foo_opt_id = match opt.lookup(OsStr::new("foo")).unwrap() {
            Inode::Leaf(id, _) => *id,
            _ => panic!("expected leaf"),
        };
        assert_ne!(
            foo_usr_id, foo_opt_id,
            "hardlink should have been broken into separate LeafIds"
        );
    }

    /// Simulate the real-world Fedora/CentOS bootc pattern where RPM packages
    /// hardlink license files between `/usr/lib/<pkg>/` (gets `lib_t`) and
    /// `/usr/share/licenses/<pkg>/` (gets `usr_t`).
    ///
    /// After selabel the filesystem must contain **no hardlinks at all** —
    /// every path must reference its own unique LeafId so that each file
    /// carries the label dictated by its own location.
    ///
    /// This is the pattern observed in `ghcr.io/bootc-dev/dev-bootc:fedora-44-uki`
    /// where ~70 files triggered the hardlink-breaking path.
    #[test]
    fn selabel_no_hardlinks_after_labeling_bootable_layout() {
        // Approximate the Fedora targeted policy distinctions that matter here:
        //   /usr/lib(/.*)?  -> lib_t   (libraries and their bundled docs)
        //   /usr/share(/.*)? -> usr_t  (architecture-independent data)
        let file_contexts = indoc! {b"
            /(/.*)?                             system_u:object_r:default_t:s0
            /usr(/.*)?                          system_u:object_r:usr_t:s0
            /usr/lib(/.*)?                      system_u:object_r:lib_t:s0
            /usr/share(/.*)?                    system_u:object_r:usr_t:s0
        "};

        // Three packages, each with a file in /usr/lib/<pkg>/ hardlinked to
        // /usr/share/licenses/<pkg>/COPYING — exactly the pattern RPM uses to
        // share identical license text across sub-packages.
        //
        // The "primary" inode is listed first (under /usr/lib); the
        // /usr/share/licenses entry is a hardlink (@120000 notation) back to it.
        let fs_entries = "\
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/pkgA 0 40755 2 0 0 0 0.0 - - -
/usr/lib/pkgA/COPYING 674 100644 2 0 0 0 0.0 - GPL2 -
/usr/lib/pkgB 0 40755 2 0 0 0 0.0 - - -
/usr/lib/pkgB/COPYING 674 100644 2 0 0 0 0.0 - GPL2 -
/usr/lib/pkgC 0 40755 2 0 0 0 0.0 - - -
/usr/lib/pkgC/COPYING 1024 100644 2 0 0 0 0.0 - APACHE2 -
/usr/share 0 40755 2 0 0 0 0.0 - - -
/usr/share/licenses 0 40755 2 0 0 0 0.0 - - -
/usr/share/licenses/pkgA 0 40755 2 0 0 0 0.0 - - -
/usr/share/licenses/pkgA/COPYING 0 @120000 - - - - 0.0 /usr/lib/pkgA/COPYING - -
/usr/share/licenses/pkgB 0 40755 2 0 0 0 0.0 - - -
/usr/share/licenses/pkgB/COPYING 0 @120000 - - - - 0.0 /usr/lib/pkgB/COPYING - -
/usr/share/licenses/pkgC 0 40755 2 0 0 0 0.0 - - -
/usr/share/licenses/pkgC/COPYING 0 @120000 - - - - 0.0 /usr/lib/pkgC/COPYING - -
";
        let mut fs = build_fs_with_selinux(file_contexts, &[], fs_entries);
        let test_repo = TestRepo::<Sha256HashValue>::new();

        assert!(selabel(&mut fs, &test_repo.repo).unwrap());

        // The /usr/lib files get lib_t; the /usr/share/licenses files get usr_t.
        assert_eq!(
            get_label(&fs, "/usr/lib/pkgA/COPYING"),
            Some("system_u:object_r:lib_t:s0".into()),
        );
        assert_eq!(
            get_label(&fs, "/usr/share/licenses/pkgA/COPYING"),
            Some("system_u:object_r:usr_t:s0".into()),
        );
        assert_eq!(
            get_label(&fs, "/usr/lib/pkgB/COPYING"),
            Some("system_u:object_r:lib_t:s0".into()),
        );
        assert_eq!(
            get_label(&fs, "/usr/share/licenses/pkgB/COPYING"),
            Some("system_u:object_r:usr_t:s0".into()),
        );
        assert_eq!(
            get_label(&fs, "/usr/lib/pkgC/COPYING"),
            Some("system_u:object_r:lib_t:s0".into()),
        );
        assert_eq!(
            get_label(&fs, "/usr/share/licenses/pkgC/COPYING"),
            Some("system_u:object_r:usr_t:s0".into()),
        );

        // The target filesystem must not contain any residual hardlinks —
        // every path must have its own unique leaf so each can carry its own label.
        assert_no_hardlinks(&fs);
    }

    /// Verify that selabel() overwrites pre-existing labels with the policy's
    /// labels, rather than accumulating or skipping them.
    #[test]
    fn selabel_replaces_stale_labels() {
        let file_contexts = indoc! {b"
            /(/.*)?		system_u:object_r:default_t:s0
            /usr(/.*)?		system_u:object_r:usr_t:s0
        "};

        let fs_entries = "\
/usr 0 40755 2 0 0 0 0.0 - - - security.selinux=unconfined_u:object_r:container_file_t:s0:c0,c1
/usr/lib 0 40755 2 0 0 0 0.0 - - - security.selinux=unconfined_u:object_r:container_file_t:s0:c0,c1
/usr/lib/readme.txt 5 100644 1 0 0 0 0.0 - hello - security.selinux=unconfined_u:object_r:container_file_t:s0:c0,c1
";
        let mut fs = build_fs_with_selinux(file_contexts, &[], fs_entries);
        let test_repo = TestRepo::<Sha256HashValue>::new();

        assert!(selabel(&mut fs, &test_repo.repo).unwrap());

        assert_eq!(
            get_label(&fs, "/usr").unwrap(),
            "system_u:object_r:usr_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/usr/lib").unwrap(),
            "system_u:object_r:usr_t:s0"
        );
        assert_eq!(
            get_label(&fs, "/usr/lib/readme.txt").unwrap(),
            "system_u:object_r:usr_t:s0"
        );
    }
}
