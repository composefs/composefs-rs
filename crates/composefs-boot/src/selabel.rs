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

use anyhow::{bail, ensure, Context, Result};
use fn_error_context::context;
use regex_automata::{hybrid::dfa, util::syntax, Anchored, Input};
use rustix::{
    fd::AsFd,
    fs::{openat, Mode, OFlags},
    io::Errno,
};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
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
    dir: &Directory<H>,
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

fn relabel(stat: &Stat, path: &Path, ifmt: u8, policy: &mut Policy) {
    let mut xattrs = stat.xattrs.borrow_mut();
    let key = OsStr::new(XATTR_SECURITY_SELINUX);

    if let Some(label) = policy.lookup(path.as_os_str(), ifmt) {
        xattrs.insert(Box::from(key), Box::from(label.as_bytes()));
    } else {
        xattrs.remove(key);
    }
}

fn relabel_leaf<H: FsVerityHashValue>(leaf: &Leaf<H>, path: &Path, policy: &mut Policy) {
    let ifmt = match leaf.content {
        LeafContent::Regular(..) => b'-',
        LeafContent::Fifo => b'p', // NB: 'pipe', not 'fifo'
        LeafContent::Socket => b's',
        LeafContent::Symlink(..) => b'l',
        LeafContent::BlockDevice(..) => b'b',
        LeafContent::CharacterDevice(..) => b'c',
    };
    relabel(&leaf.stat, path, ifmt, policy);
}

fn relabel_inode<H: FsVerityHashValue>(inode: &Inode<H>, path: &mut PathBuf, policy: &mut Policy) {
    match inode {
        Inode::Directory(ref dir) => relabel_dir(dir, path, policy),
        Inode::Leaf(ref leaf) => relabel_leaf(leaf, path, policy),
    }
}

fn relabel_dir<H: FsVerityHashValue>(dir: &Directory<H>, path: &mut PathBuf, policy: &mut Policy) {
    relabel(&dir.stat, path, b'd', policy);

    for (name, inode) in dir.sorted_entries() {
        path.push(name);
        match policy.check_aliased(path.as_os_str()) {
            Some(original) => relabel_inode(inode, &mut PathBuf::from(original), policy),
            None => relabel_inode(inode, path, policy),
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

fn strip_selinux_labels<H: FsVerityHashValue>(fs: &FileSystem<H>) {
    fs.for_each_stat(|stat| {
        stat.xattrs
            .borrow_mut()
            .remove(OsStr::new(XATTR_SECURITY_SELINUX));
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
            relabel_dir(&fs.root, &mut path, &mut policy);
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
        let Some(etc_selinux) = fs.root.get_directory_opt("etc/selinux".as_ref())? else {
            strip_selinux_labels(fs);
            return Ok(false);
        };

        build_policy(
            |filename| open_file(etc_selinux, filename, repo),
            |policy_name, filename| {
                let dir = etc_selinux
                    .get_directory(policy_name.as_ref())?
                    .get_directory("contexts/files".as_ref())?;
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
