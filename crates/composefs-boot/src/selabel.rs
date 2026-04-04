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
    io::{BufRead, BufReader, Read},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use fn_error_context::context;
use regex_automata::{Anchored, Input, hybrid::dfa, util::syntax};

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
pub fn openat<'a, H: FsVerityHashValue>(
    dir: &'a Directory<H>,
    filename: impl AsRef<OsStr>,
    repo: &Repository<H>,
) -> Result<Option<Box<dyn Read + 'a>>> {
    match dir.get_file_opt(filename.as_ref())? {
        Some(file) => match file {
            RegularFile::Inline(data) => Ok(Some(Box::new(&**data))),
            RegularFile::External(id, ..) => Ok(Some(Box::new(File::from(repo.open_object(id)?)))),
        },
        None => Ok(None),
    }
}

impl Policy {
    #[context("Building SELinux policy")]
    pub fn build<H: FsVerityHashValue>(dir: &Directory<H>, repo: &Repository<H>) -> Result<Self> {
        let mut aliases = HashMap::new();
        let mut regexps = vec![];
        let mut contexts = vec![];

        for suffix in ["", ".local", ".homedirs"] {
            if let Some(file) = openat(dir, format!("file_contexts{suffix}"), repo)? {
                process_spec_file(file, &mut regexps, &mut contexts)
                    .with_context(|| format!("SELinux spec file file_contexts{suffix}"))?;
            } else if suffix.is_empty() {
                bail!("SELinux policy is missing mandatory file_contexts file");
            }
        }

        for suffix in [".subs", ".subs_dist"] {
            if let Some(file) = openat(dir, format!("file_contexts{suffix}"), repo)? {
                process_subs_file(file, &mut aliases)
                    .with_context(|| format!("SELinux subs file file_contexts{suffix}"))?;
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
        Inode::Directory(dir) => relabel_dir(dir, path, policy),
        Inode::Leaf(leaf) => relabel_leaf(leaf, path, policy),
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
    // if /etc/selinux/config doesn't exist then strip any existing labels
    let Some(etc_selinux) = fs.root.get_directory_opt("etc/selinux".as_ref())? else {
        strip_selinux_labels(fs);
        return Ok(false);
    };

    let Some(etc_selinux_config) = openat(etc_selinux, "config", repo)? else {
        strip_selinux_labels(fs);
        return Ok(false);
    };

    let Some(policy) = parse_config(etc_selinux_config)? else {
        strip_selinux_labels(fs);
        return Ok(false);
    };

    let dir = etc_selinux
        .get_directory(policy.as_ref())?
        .get_directory("contexts/files".as_ref())?;

    let mut policy = Policy::build(dir, repo)?;
    let mut path = PathBuf::from("/");
    relabel_dir(&fs.root, &mut path, &mut policy);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    use composefs::dumpfile::dumpfile_to_filesystem;
    use composefs::fsverity::Sha256HashValue;
    use composefs::test::TestRepo;
    use indoc::indoc;

    /// Get the SELinux label from a Stat's xattrs, if any.
    fn selinux_label(stat: &Stat) -> Option<String> {
        stat.xattrs
            .borrow()
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
        let dir = if parent == Path::new("/") {
            &fs.root
        } else {
            fs.root.get_directory(parent.as_os_str()).unwrap()
        };
        match dir
            .lookup(name)
            .unwrap_or_else(|| panic!("{path} not found"))
        {
            Inode::Directory(d) => selinux_label(&d.stat),
            Inode::Leaf(l) => selinux_label(&l.stat),
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

        // Build a tree containing the SELinux policy files, serialize it
        // via the dumpfile writer so escaping is handled correctly, then
        // append the caller's additional entries and parse the whole thing.
        let selinux_config = b"SELINUX=enforcing\nSELINUXTYPE=targeted\n";

        let inline = |data: &[u8]| {
            Inode::Leaf(std::rc::Rc::new(Leaf {
                stat: Stat {
                    st_mode: 0o100644,
                    st_uid: 0,
                    st_gid: 0,
                    st_mtim_sec: 0,
                    xattrs: Default::default(),
                },
                content: LeafContent::Regular(RegularFile::Inline(
                    data.to_vec().into_boxed_slice(),
                )),
            }))
        };

        let dir_stat = || Stat {
            st_mode: 0o40755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 0,
            xattrs: Default::default(),
        };

        let mut fs = FileSystem::<Sha256HashValue>::new(dir_stat());

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
        fs.root
            .get_directory_mut("etc/selinux".as_ref())
            .unwrap()
            .insert(OsStr::new("config"), inline(selinux_config));

        // Insert file_contexts and extra policy files
        let files_dir = fs
            .root
            .get_directory_mut("etc/selinux/targeted/contexts/files".as_ref())
            .unwrap();
        files_dir.insert(OsStr::new("file_contexts"), inline(file_contexts));
        for (name, content) in extra_policy_files {
            files_dir.insert(OsStr::new(name), inline(content));
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
