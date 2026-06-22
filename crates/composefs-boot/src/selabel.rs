//! SELinux security context labeling for filesystem trees.
//!
//! This module implements SELinux policy parsing and file labeling functionality.
//! It reads SELinux policy files (file_contexts, file_contexts.subs, etc.) and applies
//! appropriate security.selinux extended attributes to filesystem nodes. The implementation
//! uses a hybrid approach: a regex-automata lazy DFA for patterns the Rust regex
//! engine supports, with pcre2 fallback for PCRE2-specific features (e.g. lookarounds).

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
use pcre2::bytes::Regex;
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

/* We try to compile all reversed SELinux regex patterns into a single
 * regex-automata lazy DFA.  If any pattern uses PCRE2-only features
 * (e.g. lookarounds), the all-at-once build fails and we fall back to
 * per-pattern classification: a syntax parse identifies the incompatible
 * patterns, which become individual PCRE2 fallbacks while everything else
 * goes into one big DFA.
 *
 * Lookup searches the DFA for the best (lowest-index) match, then checks
 * PCRE2 fallbacks that might have even higher priority.  Since fallbacks
 * are sorted by index we stop as soon as we pass the DFA result.
 *
 * The input to the matcher is the filename plus a single file-type
 * character using the codes from selabel_file(5): 'b','c','d','p','l','s','-'.
 */

/// Strategy for compiling SELinux regex patterns into matchers.
/// Only used in tests to compare the three approaches; production
/// code always uses `Hybrid`.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchStrategy {
    /// Single regex-automata lazy DFA over all patterns.
    /// Fastest lookup but fails on patterns with PCRE2 features.
    Dfa,
    /// Individual PCRE2 regexes with first-match linear scan.
    Pcre,
    /// DFA for all compatible patterns + PCRE2 fallback for the rest.
    Hybrid,
}

/// Lazy DFA state for the bulk of the patterns.
struct DfaState {
    dfa: dfa::DFA,
    cache: dfa::Cache,
    /// Maps DFA pattern ID → global context index.
    context_map: Vec<usize>,
}

/// A single PCRE2 pattern that couldn't be compiled into the DFA
/// (e.g. because it uses lookarounds).
struct PcreFallback {
    /// Global context index (position in the reversed pattern list).
    index: usize,
    regex: Regex,
}

/// Compiled regex matcher for SELinux file_contexts patterns.
///
/// Holds one lazy DFA covering all DFA-compatible patterns plus individual
/// PCRE2 regexes for patterns that need lookarounds.  Lookup searches both
/// and returns the lowest-index (= highest-priority) match.
struct Matcher {
    /// DFA covering all DFA-compatible patterns, if any.
    dfa: Option<DfaState>,
    /// PCRE2 patterns sorted by global index (ascending priority).
    pcre_fallbacks: Vec<PcreFallback>,
}

struct Policy {
    aliases: HashMap<OsString, OsString>,
    matcher: Matcher,
    /// Context strings, indexed by reversed position (0 = highest priority).
    contexts: Vec<String>,
}

/// Syntax configuration shared between the DFA builder and the pattern
/// compatibility check.  Patterns that fail to parse with this config
/// need PCRE2 (e.g. because they use lookarounds).
fn dfa_syntax_config() -> syntax::Config {
    syntax::Config::new()
        .unicode(false)
        .utf8(false)
        .line_terminator(0)
}

fn make_dfa_builder() -> dfa::Builder {
    let mut builder = dfa::Builder::new();
    builder.syntax(dfa_syntax_config());
    builder.configure(
        dfa::Config::new()
            .cache_capacity(10_000_000)
            .skip_cache_capacity_check(true),
    );
    builder
}

/// Check whether a pattern can be compiled by the regex-automata engine.
/// This is a pure syntax parse — much cheaper than building a DFA.
fn is_dfa_compatible(syntax_config: &syntax::Config, pattern: &str) -> bool {
    syntax::parse_with(pattern, syntax_config).is_ok()
}

impl Matcher {
    /// Build a compiled matcher from pre-parsed (and reversed) regexp patterns.
    ///
    /// Tries to compile all patterns into a single lazy DFA.  If that fails
    /// (e.g. some patterns use PCRE2 lookarounds), falls back to per-pattern
    /// classification: compatible patterns go into one DFA, the rest become
    /// individual PCRE2 regexes.
    fn build(regexps: &[String]) -> Result<Self> {
        let builder = make_dfa_builder();
        match builder.build_many(regexps) {
            Ok(dfa) => {
                let cache = dfa.create_cache();
                Ok(Matcher {
                    dfa: Some(DfaState {
                        dfa,
                        cache,
                        context_map: (0..regexps.len()).collect(),
                    }),
                    pcre_fallbacks: vec![],
                })
            }
            Err(_) => Self::build_partitioned(&builder, regexps),
        }
    }

    /// Build a matcher using a specific strategy (for test comparisons).
    #[cfg(test)]
    fn build_with_strategy(strategy: MatchStrategy, regexps: &[String]) -> Result<Self> {
        match strategy {
            MatchStrategy::Hybrid => Self::build(regexps),
            MatchStrategy::Dfa => {
                let dfa = make_dfa_builder().build_many(regexps)?;
                let cache = dfa.create_cache();
                Ok(Matcher {
                    dfa: Some(DfaState {
                        dfa,
                        cache,
                        context_map: (0..regexps.len()).collect(),
                    }),
                    pcre_fallbacks: vec![],
                })
            }
            MatchStrategy::Pcre => {
                let mut fallbacks = Vec::with_capacity(regexps.len());
                for (i, r) in regexps.iter().enumerate() {
                    fallbacks.push(PcreFallback {
                        index: i,
                        regex: Regex::new(r)
                            .with_context(|| format!("Compiling PCRE2 regex: {r}"))?,
                    });
                }
                Ok(Matcher {
                    dfa: None,
                    pcre_fallbacks: fallbacks,
                })
            }
        }
    }

    /// Partition patterns: DFA-compatible ones go into one big DFA,
    /// the rest become individual PCRE2 fallbacks.
    ///
    /// Uses a syntax-level parse to classify each pattern, which is much
    /// cheaper than building a DFA per pattern.
    fn build_partitioned(builder: &dfa::Builder, regexps: &[String]) -> Result<Self> {
        let syntax_config = dfa_syntax_config();
        let mut dfa_indices = Vec::new();
        let mut dfa_patterns = Vec::new();
        let mut pcre_fallbacks = Vec::new();

        for (i, pattern) in regexps.iter().enumerate() {
            if is_dfa_compatible(&syntax_config, pattern) {
                dfa_indices.push(i);
                dfa_patterns.push(pattern.as_str());
            } else {
                pcre_fallbacks.push(PcreFallback {
                    index: i,
                    regex: Regex::new(pattern)
                        .with_context(|| format!("Compiling PCRE2 regex: {pattern}"))?,
                });
            }
        }

        let dfa_state = if dfa_patterns.is_empty() {
            None
        } else {
            let dfa = builder.build_many(&dfa_patterns)?;
            let cache = dfa.create_cache();
            Some(DfaState {
                dfa,
                cache,
                context_map: dfa_indices,
            })
        };

        Ok(Matcher {
            dfa: dfa_state,
            pcre_fallbacks,
        })
    }

    /// Look up a key (filename + file-type byte) and return the matching
    /// context index, or `None` if no pattern matched.
    ///
    /// When both a DFA pattern and a PCRE2 fallback match, the one with
    /// the lower index (= higher priority) wins.
    fn lookup(&mut self, key: &[u8]) -> Option<usize> {
        // Search the DFA for the lowest-index match among DFA patterns.
        let dfa_idx = self.dfa.as_mut().and_then(|d| {
            let input = Input::new(key).anchored(Anchored::Yes);
            d.dfa
                .try_search_fwd(&mut d.cache, &input)
                .expect("DFA search error")
                .map(|hm| d.context_map[hm.pattern().as_usize()])
        });

        // Scan PCRE2 fallbacks that could beat the DFA match (lower index).
        // They're sorted by index, so we stop as soon as one matches or
        // we pass the DFA result.
        for fb in &self.pcre_fallbacks {
            if dfa_idx.is_some_and(|d| fb.index >= d) {
                break;
            }
            if fb.regex.is_match(key).unwrap_or(false) {
                return Some(fb.index);
            }
        }

        dfa_idx
    }
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

        // We want to match the last-found.
        regexps.reverse();
        contexts.reverse();

        let matcher = Matcher::build(&regexps)?;

        Ok(Policy {
            aliases,
            matcher,
            contexts,
        })
    }

    pub fn check_aliased(&self, filename: &OsStr) -> Option<&OsStr> {
        self.aliases.get(filename).map(|x| x.as_os_str())
    }

    // mut because it touches the DFA cache
    pub fn lookup(&mut self, filename: &OsStr, ifmt: u8) -> Option<&str> {
        let key = [filename.as_bytes(), &[ifmt]].concat();
        self.matcher.lookup(&key).and_then(|idx| {
            let ctx = self.contexts[idx].as_str();
            (ctx != "<<none>>").then_some(ctx)
        })
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

    /// Verify that a positive lookahead (PCRE2-only feature) in file_contexts
    /// forces the affected chunk to fall back to pcre2 and still labels correctly.
    #[test]
    fn selabel_pcre2_positive_lookahead() {
        let file_contexts = indoc! {b"
            /(/.*)?		system_u:object_r:default_t:s0
            /opt(/.*)?		system_u:object_r:opt_t:s0
            /opt/(?=protected).*		system_u:object_r:protected_t:s0
        "};

        let fs_entries = "\
/opt 0 40755 2 0 0 0 0.0 - - -
/opt/protected_data 5 100644 1 0 0 0 0.0 - hello -
/opt/other_file 5 100644 1 0 0 0 0.0 - world -
";
        let mut fs = build_fs_with_selinux(file_contexts, &[], fs_entries);
        let test_repo = TestRepo::<Sha256HashValue>::new();

        assert!(selabel(&mut fs, &test_repo.repo).unwrap());

        // Lookahead matches: "protected_data" starts with "protected"
        assert_eq!(
            get_label(&fs, "/opt/protected_data").unwrap(),
            "system_u:object_r:protected_t:s0"
        );
        // Lookahead does not match: falls through to /opt(/.*)?
        assert_eq!(
            get_label(&fs, "/opt/other_file").unwrap(),
            "system_u:object_r:opt_t:s0"
        );
    }

    /// Verify that a negative lookahead (PCRE2-only feature) correctly excludes
    /// paths from matching while still labeling non-excluded paths.
    #[test]
    fn selabel_pcre2_negative_lookahead() {
        // The negative lookahead (?!backup) excludes filenames starting with "backup".
        let file_contexts = indoc! {b"
            /(/.*)?		system_u:object_r:default_t:s0
            /srv(/.*)?		system_u:object_r:srv_t:s0
            /srv/(?!backup).*		system_u:object_r:srv_public_t:s0
        "};

        let fs_entries = "\
/srv 0 40755 2 0 0 0 0.0 - - -
/srv/website 5 100644 1 0 0 0 0.0 - hello -
/srv/backup_2024 5 100644 1 0 0 0 0.0 - world -
";
        let mut fs = build_fs_with_selinux(file_contexts, &[], fs_entries);
        let test_repo = TestRepo::<Sha256HashValue>::new();

        assert!(selabel(&mut fs, &test_repo.repo).unwrap());

        // Negative lookahead succeeds: "website" doesn't start with "backup"
        assert_eq!(
            get_label(&fs, "/srv/website").unwrap(),
            "system_u:object_r:srv_public_t:s0"
        );
        // Negative lookahead fails: "backup_2024" starts with "backup",
        // so the pattern doesn't match; falls through to /srv(/.*)?
        assert_eq!(
            get_label(&fs, "/srv/backup_2024").unwrap(),
            "system_u:object_r:srv_t:s0"
        );
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

    /// Verify that all three match strategies produce identical results
    /// for a representative set of patterns and paths.
    #[test]
    fn matcher_strategies_agree() {
        let file_contexts = indoc! {b"
            /\t\tsystem_u:object_r:root_t:s0
            /usr\t\tsystem_u:object_r:usr_t:s0
            /usr/bin(/.*)?\t\tsystem_u:object_r:bin_t:s0
            /etc(/.*)?\t\tsystem_u:object_r:etc_t:s0
            /var(/.*)?  -d  system_u:object_r:var_dir_t:s0
            /var(/.*)?  --  system_u:object_r:var_file_t:s0
            /tmp(/.*)?  <<none>>
        "};

        let mut regexps = vec![];
        let mut contexts = vec![];
        process_spec_file(file_contexts.as_slice(), &mut regexps, &mut contexts).unwrap();
        regexps.reverse();
        contexts.reverse();

        let mut matchers: Vec<(MatchStrategy, Matcher)> = [
            MatchStrategy::Dfa,
            MatchStrategy::Pcre,
            MatchStrategy::Hybrid,
        ]
        .into_iter()
        .map(|s| (s, Matcher::build_with_strategy(s, &regexps).unwrap()))
        .collect();

        // Paths to test, paired with the file-type byte.
        let test_cases: &[(&[u8], u8)] = &[
            (b"/", b'd'),
            (b"/usr", b'd'),
            (b"/usr/bin", b'd'),
            (b"/usr/bin/hello", b'-'),
            (b"/etc", b'd'),
            (b"/etc/hostname", b'-'),
            (b"/var", b'd'),
            (b"/var/log", b'd'),
            (b"/var/spool/mail", b'-'),
            (b"/tmp", b'd'),
            (b"/tmp/scratch", b'-'),
            (b"/nonexistent", b'-'),
        ];

        // Collect results from first strategy, then assert all others match.
        let expected: Vec<_> = {
            let (_, m) = &mut matchers[0];
            test_cases
                .iter()
                .map(|(path, ifmt)| {
                    let key = [*path, &[*ifmt]].concat();
                    m.lookup(&key)
                })
                .collect()
        };

        for (strategy, m) in &mut matchers[1..] {
            for (i, (path, ifmt)) in test_cases.iter().enumerate() {
                let key = [*path, &[*ifmt]].concat();
                let result = m.lookup(&key);
                assert_eq!(
                    result,
                    expected[i],
                    "{strategy:?} disagrees with {:?} on path {:?} (ifmt={ifmt:?}): \
                     got {result:?}, expected {:?}",
                    MatchStrategy::Dfa,
                    String::from_utf8_lossy(path),
                    expected[i],
                );
            }
        }
    }

    /// Verify that hybrid lookup with PCRE2 lookaround patterns interleaved
    /// among DFA patterns produces the same results as pure PCRE2, and that
    /// the priority interleaving is correct (a PCRE2 pattern at a lower index
    /// must beat a DFA match at a higher index, and vice versa).
    #[test]
    fn hybrid_lookaround_priority() {
        // Patterns are listed in file_contexts order (low-to-high priority).
        // After reversing, index 0 = highest priority.
        //
        // We mix in negative-lookahead patterns (PCRE2-only) at various
        // positions so the hybrid matcher must correctly interleave DFA
        // and PCRE2 results.
        let patterns: &[(&str, &str)] = &[
            // Low priority (will be at high indices after reverse)
            (r"/(.*)?", "system_u:object_r:default_t:s0"),
            (r"/usr(.*)?", "system_u:object_r:usr_t:s0"),
            // PCRE2-only: lookahead (mid priority)
            (r"/usr/bin/(?!bad).*", "system_u:object_r:bin_ok_t:s0"),
            // DFA-compatible (mid priority, higher than above)
            (r"/usr/bin/good", "system_u:object_r:bin_good_t:s0"),
            // PCRE2-only: lookahead (high priority)
            (r"/etc/(?!shadow).*", "system_u:object_r:etc_public_t:s0"),
            // DFA-compatible (highest priority)
            (r"/etc/hostname", "system_u:object_r:hostname_t:s0"),
        ];

        let mut regexps: Vec<String> = patterns
            .iter()
            .map(|(re, _)| format!("^({re}).$"))
            .collect();
        let mut contexts: Vec<String> = patterns.iter().map(|(_, ctx)| ctx.to_string()).collect();
        regexps.reverse();
        contexts.reverse();

        let mut pcre = Matcher::build_with_strategy(MatchStrategy::Pcre, &regexps).unwrap();
        let mut hybrid = Matcher::build_with_strategy(MatchStrategy::Hybrid, &regexps).unwrap();

        let test_cases: &[(&[u8], u8, &str)] = &[
            // /etc/hostname: DFA pattern at index 0 (highest priority) wins.
            (b"/etc/hostname", b'-', "system_u:object_r:hostname_t:s0"),
            // /etc/passwd: PCRE2 lookahead at index 1 matches (not "shadow").
            (b"/etc/passwd", b'-', "system_u:object_r:etc_public_t:s0"),
            // /etc/shadow: PCRE2 lookahead at index 1 does NOT match,
            // falls through to DFA default_t.
            (b"/etc/shadow", b'-', "system_u:object_r:default_t:s0"),
            // /usr/bin/good: DFA pattern at index 2 wins over PCRE2 at index 3.
            (b"/usr/bin/good", b'-', "system_u:object_r:bin_good_t:s0"),
            // /usr/bin/hello: PCRE2 lookahead at index 3 matches (not "bad").
            (b"/usr/bin/hello", b'-', "system_u:object_r:bin_ok_t:s0"),
            // /usr/bin/bad: PCRE2 lookahead at index 3 does NOT match,
            // falls through to DFA usr_t.
            (b"/usr/bin/bad", b'-', "system_u:object_r:usr_t:s0"),
        ];

        for (path, ifmt, expected) in test_cases {
            let key = [*path, &[*ifmt]].concat();
            let path_str = String::from_utf8_lossy(path);

            let pcre_idx = pcre.lookup(&key);
            let hybrid_idx = hybrid.lookup(&key);

            assert_eq!(
                pcre_idx, hybrid_idx,
                "hybrid disagrees with pcre2 on {path_str}: \
                 pcre2={pcre_idx:?} hybrid={hybrid_idx:?}"
            );

            let label = pcre_idx.map(|i| contexts[i].as_str());
            assert_eq!(
                label,
                Some(*expected),
                "{path_str}: expected {expected}, got {label:?}"
            );
        }
    }

    mod proptest_matcher {
        use super::*;
        use proptest::prelude::*;
        use proptest::strategy::ValueTree;

        /// A path segment: 1–8 lowercase ASCII characters.
        fn path_segment() -> impl Strategy<Value = String> {
            "[a-z][a-z0-9_]{0,7}"
        }

        /// An absolute directory path with 1–4 segments.
        fn dir_path() -> impl Strategy<Value = String> {
            proptest::collection::vec(path_segment(), 1..=4)
                .prop_map(|segs| format!("/{}", segs.join("/")))
        }

        /// A filename (no slashes).
        fn filename() -> impl Strategy<Value = String> {
            "[a-z][a-z0-9_.]{0,11}"
        }

        /// One SELinux-like pattern+context, in pre-`process_spec_file` format
        /// (i.e. the anchored `^(...).$` regex).
        #[derive(Debug, Clone)]
        enum PatternKind {
            /// Exact file: `^(/dir/file).$`
            Exact(String),
            /// Directory wildcard: `^(/dir(/.*)?).$`
            DirWild(String),
            /// Negative lookahead (PCRE2-only): `^(/dir/(?!name).*).$`
            Lookahead(String, String),
        }

        fn pattern_kind() -> impl Strategy<Value = PatternKind> {
            prop_oneof![
                8 => (dir_path(), filename()).prop_map(|(d, f)| PatternKind::Exact(
                    format!("{d}/{f}")
                )),
                4 => dir_path().prop_map(PatternKind::DirWild),
                1 => (dir_path(), filename()).prop_map(|(d, f)| PatternKind::Lookahead(d, f)),
            ]
        }

        impl PatternKind {
            fn to_regexp(&self) -> String {
                match self {
                    PatternKind::Exact(path) => format!("^({path}).$"),
                    PatternKind::DirWild(dir) => format!("^({dir}(/.*)?).$"),
                    PatternKind::Lookahead(dir, excluded) => {
                        format!("^({dir}/(?!{excluded}).*).$")
                    }
                }
            }

            fn context(&self, idx: usize) -> String {
                format!("system_u:object_r:rule{idx}_t:s0")
            }
        }

        /// Generate test paths that have a chance of matching the patterns.
        fn test_path(dirs: &[String]) -> impl Strategy<Value = Vec<u8>> + '_ {
            let ifmt = prop_oneof![Just(b'-'), Just(b'd'), Just(b'l'),];

            let path = prop_oneof![
                // Path under one of the generated directories.
                (proptest::sample::select(dirs.to_vec()), filename())
                    .prop_map(|(d, f)| format!("{d}/{f}")),
                // Just a directory itself.
                proptest::sample::select(dirs.to_vec()),
                // Random path unlikely to match anything specific.
                dir_path(),
            ];

            (path, ifmt).prop_map(|(p, i)| [p.as_bytes(), &[i]].concat())
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(20))]

            /// Property: for any generated set of patterns (including some
            /// with lookarounds) and paths, PCRE2 and Hybrid matchers must
            /// produce identical lookup results.
            #[test]
            fn hybrid_matches_pcre2(
                patterns in proptest::collection::vec(pattern_kind(), 20..=200),
                path_count in 50..=200usize,
            ) {
                // Build regexp + context lists.
                let mut regexps = Vec::new();
                let mut contexts = Vec::new();

                // Catch-all at lowest priority.
                regexps.push("^(/(.*)?).$$".to_string());
                contexts.push("system_u:object_r:default_t:s0".to_string());

                for (i, pat) in patterns.iter().enumerate() {
                    regexps.push(pat.to_regexp());
                    contexts.push(pat.context(i));
                }

                regexps.reverse();
                contexts.reverse();

                let mut pcre = Matcher::build_with_strategy(
                    MatchStrategy::Pcre, &regexps,
                ).unwrap();
                let mut hybrid = Matcher::build(&regexps).unwrap();

                // Collect directory paths used in patterns for targeted path generation.
                let dirs: Vec<String> = patterns.iter().filter_map(|p| match p {
                    PatternKind::Exact(path) => {
                        path.rsplit_once('/').map(|(d, _)| d.to_string())
                    }
                    PatternKind::DirWild(d) | PatternKind::Lookahead(d, _) => {
                        Some(d.clone())
                    }
                }).collect();

                // Ensure we have at least one directory for sampling.
                let dirs = if dirs.is_empty() {
                    vec!["/fallback".to_string()]
                } else {
                    dirs
                };

                let path_strategy = proptest::collection::vec(
                    test_path(&dirs), path_count,
                );
                let mut runner = proptest::test_runner::TestRunner::new(
                    ProptestConfig::default(),
                );
                let paths = path_strategy
                    .new_tree(&mut runner)
                    .unwrap()
                    .current();

                for key in &paths {
                    let pcre_result = pcre.lookup(key);
                    let hybrid_result = hybrid.lookup(key);
                    prop_assert_eq!(
                        pcre_result, hybrid_result,
                        "disagreement on {:?}",
                        String::from_utf8_lossy(key),
                    );
                }
            }
        }
    }
}
