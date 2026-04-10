//! OCI image processing and filesystem construction.
//!
//! This module handles the conversion of OCI container image layers into composefs filesystems.
//! It processes tar entries from container layers, handles overlayfs semantics like whiteouts,
//! and constructs the final filesystem tree that can be mounted or analyzed.
//!
//! The main functionality centers around `create_filesystem()` which takes an OCI image configuration
//! and builds a complete filesystem by processing all layers in order. The `process_entry()` function
//! handles individual tar entries and implements overlayfs whiteout semantics for proper layer merging.

use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

use anyhow::{Context, Result, ensure};
use composefs::util::DigestWrite;
use fn_error_context::context;
use sha2::{Digest, Sha256};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    tree::{Directory, FileSystem, Inode, Stat},
};

use containers_image_proxy::oci_spec::image::Digest as OciDigest;

use crate::skopeo::TAR_LAYER_CONTENT_TYPE;
use crate::tar::{TarEntry, TarItem};

/// Processes a single tar entry and adds it to the filesystem.
///
/// Handles various tar entry types (regular files, directories, symlinks, hardlinks, devices, fifos)
/// and implements overlayfs whiteout semantics for proper layer merging. Files named `.wh.<name>`
/// delete the corresponding file, and `.wh..wh.opq` marks a directory as opaque (clearing all contents).
///
/// Returns an error if the entry cannot be processed or added to the filesystem.
#[context("Processing tar entry")]
pub fn process_entry<ObjectID: FsVerityHashValue>(
    filesystem: &mut FileSystem<ObjectID>,
    entry: TarEntry<ObjectID>,
) -> Result<()> {
    if entry.path.file_name().is_none() {
        // special handling for the root directory
        ensure!(
            matches!(entry.item, TarItem::Directory),
            "Unpacking layer tar: filename {:?} must be a directory",
            entry.path
        );

        // Update the stat, but don't do anything else
        filesystem.set_root_stat(entry.stat);
        return Ok(());
    }

    let inode = match entry.item {
        TarItem::Directory => Inode::Directory(Box::from(Directory::new(entry.stat))),
        TarItem::Leaf(content) => {
            let id = filesystem.push_leaf(entry.stat, content);
            Inode::leaf(id)
        }
        TarItem::Hardlink(target) => {
            let (dir, filename) = filesystem.root.split(&target)?;
            Inode::leaf(dir.leaf_id(filename)?)
        }
    };

    let (dir, filename) = filesystem
        .root
        .split_mut(entry.path.as_os_str())
        .with_context(|| {
            format!(
                "Error unpacking container layer file {:?} {:?}",
                entry.path, inode
            )
        })?;

    let bytes = filename.as_bytes();
    if let Some(whiteout) = bytes.strip_prefix(b".wh.") {
        if whiteout == b".wh..opq" {
            // complete name is '.wh..wh..opq'
            dir.clear();
        } else {
            dir.remove(OsStr::from_bytes(whiteout));
        }
    } else {
        dir.merge(filename, inode);
    }

    Ok(())
}

/// Creates a filesystem from the given OCI container.  No special transformations are performed to
/// make the filesystem bootable.
///
/// OCI container layer tars often don't include a root directory entry, and when they do,
/// container runtimes typically ignore it (using hardcoded defaults instead). This makes
/// root metadata non-deterministic. To ensure consistent digests, this function copies
/// root metadata from `/usr` after processing all layers.
/// See: <https://github.com/containers/storage/pull/743>
///
/// If `config_verity` is given it is used to get the OCI config splitstream by its fs-verity ID
/// and the entire process is substantially faster.  If it is not given, the config and layers will
/// be hashed to ensure that they match their claimed blob IDs.
pub fn create_filesystem<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    config_name: &OciDigest,
    config_verity: Option<&ObjectID>,
) -> Result<FileSystem<ObjectID>> {
    let mut filesystem = FileSystem::new(Stat::uninitialized());

    let oc = crate::open_config(repo, config_name, config_verity)?;
    let config = oc.config;
    let map = oc.layer_refs;

    for diff_id in config.rootfs().diff_ids() {
        let layer_verity = map
            .get(diff_id.as_str())
            .context("OCI config splitstream missing named ref to layer {diff_id}")?;

        if config_verity.is_none() {
            // We don't have any proof that the named references in the config splitstream are
            // trustworthy. We have no choice but to perform expensive validation of the layer
            // stream.
            let mut layer_stream =
                repo.open_stream("", Some(layer_verity), Some(TAR_LAYER_CONTENT_TYPE))?;
            let mut context = DigestWrite(Sha256::new());
            layer_stream.cat(repo, &mut context)?;
            let content_hash = crate::sha256_output_to_digest(context.finalize());
            ensure!(
                content_hash.as_ref() == diff_id,
                "Layer has incorrect checksum"
            );
        }

        let mut layer_stream =
            repo.open_stream("", Some(layer_verity), Some(TAR_LAYER_CONTENT_TYPE))?;
        while let Some(entry) = crate::tar::get_entry(&mut layer_stream)? {
            process_entry(&mut filesystem, entry)?;
        }
    }

    // Apply OCI container transformations for consistent digests.
    // See https://github.com/containers/composefs-rs/issues/132
    filesystem.transform_for_oci()?;

    // Whiteout processing and layer merging can leave orphaned leaves.
    filesystem.compact();

    debug_assert!(
        filesystem.fsck().is_ok(),
        "create_filesystem produced invalid filesystem"
    );
    Ok(filesystem)
}

#[cfg(test)]
mod test {
    use composefs::{
        dumpfile::write_dumpfile,
        fsverity::Sha256HashValue,
        tree::{LeafContent, RegularFile, Stat},
    };
    use std::{collections::BTreeMap, io::BufRead, path::PathBuf};

    use super::*;

    fn file_entry<ObjectID: FsVerityHashValue>(path: &str) -> TarEntry<ObjectID> {
        TarEntry {
            path: PathBuf::from(path),
            stat: Stat {
                st_mode: 0o644,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                xattrs: BTreeMap::new(),
            },
            item: TarItem::Leaf(LeafContent::Regular(RegularFile::Inline([].into()))),
        }
    }

    fn dir_entry<ObjectID: FsVerityHashValue>(path: &str) -> TarEntry<ObjectID> {
        TarEntry {
            path: PathBuf::from(path),
            stat: Stat {
                st_mode: 0o755,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                xattrs: BTreeMap::new(),
            },
            item: TarItem::Directory,
        }
    }

    fn assert_files(fs: &FileSystem<impl FsVerityHashValue>, expected: &[&str]) -> Result<()> {
        let mut out = vec![];
        write_dumpfile(&mut out, fs)?;
        let actual: Vec<String> = out
            .lines()
            .map(|line| line.unwrap().split_once(' ').unwrap().0.into())
            .collect();

        similar_asserts::assert_eq!(actual, expected);
        Ok(())
    }

    fn append_tar_dir(builder: &mut ::tar::Builder<Vec<u8>>, name: &str) {
        let mut header = ::tar::Header::new_ustar();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o755);
        header.set_entry_type(::tar::EntryType::Directory);
        header.set_size(0);
        builder
            .append_data(&mut header, name, std::io::empty())
            .unwrap();
    }

    /// Append a regular file with explicit content bytes to a tar builder.
    fn append_tar_file(builder: &mut ::tar::Builder<Vec<u8>>, name: &str, content: &[u8]) {
        let mut header = ::tar::Header::new_ustar();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o644);
        header.set_entry_type(::tar::EntryType::Regular);
        header.set_size(content.len() as u64);
        builder.append_data(&mut header, name, content).unwrap();
    }

    /// Append a symlink entry to a tar builder.
    fn append_tar_symlink(builder: &mut ::tar::Builder<Vec<u8>>, name: &str, target: &str) {
        let mut header = ::tar::Header::new_ustar();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o777);
        header.set_entry_type(::tar::EntryType::Symlink);
        header.set_size(0);
        builder.append_link(&mut header, name, target).unwrap();
    }

    /// Append a hardlink entry to a tar builder.
    fn append_tar_hardlink(builder: &mut ::tar::Builder<Vec<u8>>, name: &str, target: &str) {
        let mut header = ::tar::Header::new_ustar();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o644);
        header.set_entry_type(::tar::EntryType::Link);
        header.set_size(0);
        builder.append_link(&mut header, name, target).unwrap();
    }

    /// Build a realistic busybox-like container filesystem as a tar archive.
    ///
    /// Exercises directories, regular files (both inline and external), symlinks,
    /// and hardlinks. Returns `(tar_bytes, "sha256:<hex>")`.
    fn build_baseimage() -> (Vec<u8>, String) {
        let mut builder = ::tar::Builder::new(vec![]);

        // Directories (sorted at each level for deterministic output)
        append_tar_dir(&mut builder, "bin"); // will be replaced by symlink below
        append_tar_dir(&mut builder, "etc");
        append_tar_dir(&mut builder, "tmp");
        append_tar_dir(&mut builder, "usr");
        append_tar_dir(&mut builder, "usr/bin");
        append_tar_dir(&mut builder, "usr/lib");
        append_tar_dir(&mut builder, "usr/share");
        append_tar_dir(&mut builder, "usr/share/doc");
        append_tar_dir(&mut builder, "var");
        append_tar_dir(&mut builder, "var/log");

        // Regular files — inline (<=64 bytes, the INLINE_CONTENT_MAX_V0 threshold)
        append_tar_file(&mut builder, "etc/hostname", b"busybox-container\n");
        append_tar_file(
            &mut builder,
            "etc/resolv.conf",
            b"nameserver 8.8.8.8\nnameserver 8.8.4.4\n",
        );

        // Regular files — external (>64 bytes)
        append_tar_file(
            &mut builder,
            "etc/passwd",
            b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n\
              daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        );

        // Large external files with recognizable byte patterns
        let busybox_content: Vec<u8> = (0..65536u64).map(|i| (i % 251) as u8).collect();
        append_tar_file(&mut builder, "usr/bin/busybox", &busybox_content);

        let libc_content: Vec<u8> = (0..32768u64).map(|i| (i % 241) as u8).collect();
        append_tar_file(&mut builder, "usr/lib/libc.so", &libc_content);

        let readme_content = "composefs-rs test image\n\
            This is a synthetic busybox-like filesystem used for round-trip testing.\n\
            It exercises inline files, external files, symlinks, and hardlinks.\n\
            The filesystem layout mimics a minimal container image with /usr merge.\n\
            Generated by build_baseimage() in the composefs-oci test suite.\n\
            ----\n\
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod\n\
            tempor incididunt ut labore et dolore magna aliqua.\n";
        append_tar_file(
            &mut builder,
            "usr/share/doc/README",
            readme_content.as_bytes(),
        );

        let messages_content: Vec<u8> = (0..8192u64).map(|i| (i % 239) as u8).collect();
        append_tar_file(&mut builder, "var/log/messages", &messages_content);

        // Symlinks (sorted within each directory)
        append_tar_symlink(&mut builder, "usr/bin/cat", "busybox");
        append_tar_symlink(&mut builder, "usr/bin/ls", "busybox");
        append_tar_symlink(&mut builder, "usr/bin/sh", "busybox");
        append_tar_symlink(&mut builder, "usr/lib/libc.so.6", "libc.so");

        // Hardlink: /usr/bin/cp -> /usr/bin/busybox (must appear after busybox)
        append_tar_hardlink(&mut builder, "usr/bin/cp", "usr/bin/busybox");

        // Directory symlink: /bin -> usr/bin (after /usr/bin directory exists)
        // We already created /bin as a directory above; overwrite it with a symlink.
        // In tar, later entries replace earlier ones, so this replaces the dir.
        append_tar_symlink(&mut builder, "bin", "usr/bin");

        let data = builder.into_inner().unwrap();
        let diff_id = crate::sha256_content_digest(&data).to_string();
        (data, diff_id)
    }

    /// Comprehensive round-trip test: build a busybox-like tar layer via
    /// `build_baseimage()`, import it with `import_layer()`, read it back
    /// with `get_entry()`, and verify every entry type round-trips correctly.
    #[tokio::test]
    async fn test_build_baseimage_roundtrip() -> Result<()> {
        use composefs::{INLINE_CONTENT_MAX_V0, repository::Repository, test::tempdir};
        use rustix::fs::CWD;
        use std::ffi::OsStr;
        use std::sync::Arc;

        let (tar_data, diff_id_str) = build_baseimage();
        let diff_id: OciDigest = diff_id_str.parse()?;

        let repo_dir = tempdir();
        let repo_path = repo_dir.path().join("repo");
        let (repo, _) = Repository::<Sha256HashValue>::init_path(
            CWD,
            &repo_path,
            composefs::fsverity::Algorithm::SHA256,
            false,
        )?;
        let repo = Arc::new(repo);
        let (verity, _stats) =
            crate::import_layer(&repo, &diff_id, Some("layer"), &tar_data[..]).await?;

        let mut stream = repo.open_stream("refs/layer", Some(&verity), None)?;
        let mut entries = vec![];
        while let Some(entry) = crate::tar::get_entry(&mut stream)? {
            entries.push(entry);
        }

        // Build a lookup by path for easier assertions
        let by_path = |p: &str| -> &TarEntry<Sha256HashValue> {
            entries
                .iter()
                .find(|e| e.path == PathBuf::from(p))
                .unwrap_or_else(|| panic!("missing entry for {p}"))
        };

        // --- Directories ---
        let expected_dirs = [
            "/bin", // initial dir entry (later overwritten by symlink in tar, but splitstream preserves order)
            "/etc",
            "/tmp",
            "/usr",
            "/usr/bin",
            "/usr/lib",
            "/usr/share",
            "/usr/share/doc",
            "/var",
            "/var/log",
        ];
        for dir in &expected_dirs {
            let entry = by_path(dir);
            assert!(
                matches!(entry.item, TarItem::Directory),
                "{dir} should be a directory, got {:?}",
                entry.item
            );
            assert_eq!(entry.stat.st_mode, 0o755, "{dir} mode");
        }

        // --- Inline files (<=INLINE_CONTENT_MAX_V0 bytes) ---
        let hostname = by_path("/etc/hostname");
        match &hostname.item {
            TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(data))) => {
                assert_eq!(data.as_ref(), b"busybox-container\n");
                assert!(
                    data.len() <= INLINE_CONTENT_MAX_V0,
                    "hostname should be inline ({} bytes <= {INLINE_CONTENT_MAX_V0})",
                    data.len()
                );
            }
            other => panic!("expected inline file for /etc/hostname, got {other:?}"),
        }

        let resolv = by_path("/etc/resolv.conf");
        match &resolv.item {
            TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(data))) => {
                assert!(data.starts_with(b"nameserver"));
                assert!(
                    data.len() <= INLINE_CONTENT_MAX_V0,
                    "resolv.conf should be inline ({} bytes <= {INLINE_CONTENT_MAX_V0})",
                    data.len()
                );
            }
            other => panic!("expected inline file for /etc/resolv.conf, got {other:?}"),
        }

        // --- External files (>INLINE_CONTENT_MAX_V0 bytes) ---
        let passwd = by_path("/etc/passwd");
        match &passwd.item {
            TarItem::Leaf(LeafContent::Regular(RegularFile::External(_, size))) => {
                assert!(
                    *size as usize > INLINE_CONTENT_MAX_V0,
                    "passwd should be external ({size} bytes > {INLINE_CONTENT_MAX_V0})"
                );
            }
            other => panic!("expected external file for /etc/passwd, got {other:?}"),
        }

        let busybox = by_path("/usr/bin/busybox");
        match &busybox.item {
            TarItem::Leaf(LeafContent::Regular(RegularFile::External(_, size))) => {
                assert_eq!(*size, 65536, "busybox should be 64KB");
            }
            other => panic!("expected external file for /usr/bin/busybox, got {other:?}"),
        }

        let libc = by_path("/usr/lib/libc.so");
        match &libc.item {
            TarItem::Leaf(LeafContent::Regular(RegularFile::External(_, size))) => {
                assert_eq!(*size, 32768, "libc.so should be 32KB");
            }
            other => panic!("expected external file for /usr/lib/libc.so, got {other:?}"),
        }

        let readme = by_path("/usr/share/doc/README");
        match &readme.item {
            TarItem::Leaf(LeafContent::Regular(RegularFile::External(_, size))) => {
                assert!(
                    *size as usize > INLINE_CONTENT_MAX_V0,
                    "README should be external ({size} bytes)"
                );
            }
            other => panic!("expected external file for README, got {other:?}"),
        }

        let messages = by_path("/var/log/messages");
        match &messages.item {
            TarItem::Leaf(LeafContent::Regular(RegularFile::External(_, size))) => {
                assert_eq!(*size, 8192, "messages should be 8KB");
            }
            other => panic!("expected external file for /var/log/messages, got {other:?}"),
        }

        // --- Symlinks ---
        let symlinks = [
            ("/usr/bin/cat", "busybox"),
            ("/usr/bin/ls", "busybox"),
            ("/usr/bin/sh", "busybox"),
            ("/usr/lib/libc.so.6", "libc.so"),
        ];
        for (path, target) in &symlinks {
            let entry = by_path(path);
            match &entry.item {
                TarItem::Leaf(LeafContent::Symlink(t)) => {
                    assert_eq!(&**t, OsStr::new(target), "{path} symlink target");
                }
                other => panic!("expected symlink for {path}, got {other:?}"),
            }
        }

        // --- Hardlink ---
        // The hardlink /usr/bin/cp -> /usr/bin/busybox appears as a Hardlink variant
        let cp = by_path("/usr/bin/cp");
        match &cp.item {
            TarItem::Hardlink(target) => {
                assert_eq!(target, OsStr::new("/usr/bin/busybox"), "cp hardlink target");
            }
            other => panic!("expected hardlink for /usr/bin/cp, got {other:?}"),
        }

        // The /bin symlink replaces the earlier /bin directory in the tar stream.
        // Both entries appear in the splitstream since it preserves raw tar order.
        // Find the *last* /bin entry, which should be the symlink.
        let bin_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.path == PathBuf::from("/bin"))
            .collect();
        assert!(
            bin_entries.len() >= 2,
            "/bin should appear as both a directory and a symlink"
        );
        let last_bin = bin_entries.last().unwrap();
        match &last_bin.item {
            TarItem::Leaf(LeafContent::Symlink(t)) => {
                assert_eq!(&**t, OsStr::new("usr/bin"), "/bin symlink target");
            }
            other => panic!("expected symlink for final /bin, got {other:?}"),
        }

        // --- Total entry count ---
        // 10 dirs + 7 files + 4 symlinks + 1 hardlink + 1 /bin symlink = 23
        // Plus the original /bin dir entry = 24 total
        let expected_count = 10  // directories (including initial /bin)
            + 7   // regular files
            + 4   // symlinks (cat, ls, sh, libc.so.6)
            + 1   // hardlink (cp)
            + 1; // /bin symlink (replaces the dir)
        assert_eq!(
            entries.len(),
            expected_count,
            "total entry count (dirs + files + symlinks + hardlinks)"
        );

        Ok(())
    }

    #[test]
    fn test_process_entry() -> Result<()> {
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        // both with and without leading slash should be supported
        process_entry(&mut fs, dir_entry("/a"))?;
        process_entry(&mut fs, dir_entry("b"))?;
        process_entry(&mut fs, dir_entry("c"))?;
        assert_files(&fs, &["/", "/a", "/b", "/c"])?;

        // add some files
        process_entry(&mut fs, file_entry("/a/b"))?;
        process_entry(&mut fs, file_entry("/a/c"))?;
        process_entry(&mut fs, file_entry("/b/a"))?;
        process_entry(&mut fs, file_entry("/b/c"))?;
        process_entry(&mut fs, file_entry("/c/a"))?;
        process_entry(&mut fs, file_entry("/c/c"))?;
        assert_files(
            &fs,
            &[
                "/", "/a", "/a/b", "/a/c", "/b", "/b/a", "/b/c", "/c", "/c/a", "/c/c",
            ],
        )?;

        // try some whiteouts
        process_entry(&mut fs, file_entry(".wh.a"))?; // entire dir
        process_entry(&mut fs, file_entry("/b/.wh..wh..opq"))?; // opaque dir
        process_entry(&mut fs, file_entry("/c/.wh.c"))?; // single file
        assert_files(&fs, &["/", "/b", "/c", "/c/a"])?;

        Ok(())
    }

    // --- Whiteout-specific tests ---

    #[test]
    fn test_whiteout_file_removes_entry() -> Result<()> {
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/etc"))?;
        process_entry(&mut fs, file_entry("/etc/hosts"))?;
        process_entry(&mut fs, file_entry("/etc/passwd"))?;
        assert_files(&fs, &["/", "/etc", "/etc/hosts", "/etc/passwd"])?;

        // Whiteout hosts — only hosts should be removed
        process_entry(&mut fs, file_entry("/etc/.wh.hosts"))?;
        assert_files(&fs, &["/", "/etc", "/etc/passwd"])?;

        Ok(())
    }

    #[test]
    fn test_whiteout_nonexistent_file_is_noop() -> Result<()> {
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/etc"))?;
        process_entry(&mut fs, file_entry("/etc/hosts"))?;
        assert_files(&fs, &["/", "/etc", "/etc/hosts"])?;

        // Whiteout a file that doesn't exist — should be a no-op
        process_entry(&mut fs, file_entry("/etc/.wh.nosuchfile"))?;
        assert_files(&fs, &["/", "/etc", "/etc/hosts"])?;

        Ok(())
    }

    #[test]
    fn test_whiteout_directory() -> Result<()> {
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/usr"))?;
        process_entry(&mut fs, dir_entry("/usr/local"))?;
        process_entry(&mut fs, file_entry("/usr/local/bin"))?;
        process_entry(&mut fs, dir_entry("/etc"))?;
        assert_files(&fs, &["/", "/etc", "/usr", "/usr/local", "/usr/local/bin"])?;

        // Whiteout the directory /usr/local (removes the entire subtree)
        process_entry(&mut fs, file_entry("/usr/.wh.local"))?;
        assert_files(&fs, &["/", "/etc", "/usr"])?;

        Ok(())
    }

    #[test]
    fn test_whiteout_in_root_directory() -> Result<()> {
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/mydir"))?;
        process_entry(&mut fs, file_entry("/toplevel"))?;
        assert_files(&fs, &["/", "/mydir", "/toplevel"])?;

        // Whiteout in root (no leading dir component)
        process_entry(&mut fs, file_entry("/.wh.toplevel"))?;
        assert_files(&fs, &["/", "/mydir"])?;

        // Also works without leading slash
        process_entry(&mut fs, file_entry(".wh.mydir"))?;
        assert_files(&fs, &["/"])?;

        Ok(())
    }

    #[test]
    fn test_whiteout_in_nested_directory() -> Result<()> {
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/a"))?;
        process_entry(&mut fs, dir_entry("/a/b"))?;
        process_entry(&mut fs, dir_entry("/a/b/c"))?;
        process_entry(&mut fs, file_entry("/a/b/c/deep"))?;
        assert_files(&fs, &["/", "/a", "/a/b", "/a/b/c", "/a/b/c/deep"])?;

        process_entry(&mut fs, file_entry("/a/b/c/.wh.deep"))?;
        assert_files(&fs, &["/", "/a", "/a/b", "/a/b/c"])?;

        Ok(())
    }

    #[test]
    fn test_opaque_whiteout_clears_directory() -> Result<()> {
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/etc"))?;
        process_entry(&mut fs, file_entry("/etc/hosts"))?;
        process_entry(&mut fs, file_entry("/etc/passwd"))?;
        process_entry(&mut fs, file_entry("/etc/resolv.conf"))?;
        assert_files(
            &fs,
            &["/", "/etc", "/etc/hosts", "/etc/passwd", "/etc/resolv.conf"],
        )?;

        // Opaque whiteout — clears all entries in /etc
        process_entry(&mut fs, file_entry("/etc/.wh..wh..opq"))?;
        assert_files(&fs, &["/", "/etc"])?;

        Ok(())
    }

    #[test]
    fn test_opaque_whiteout_then_add_new_entries() -> Result<()> {
        // This is a very common pattern in container images: the layer
        // marks a dir opaque (hiding all lower-layer contents), then
        // adds new entries in the same directory.
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/etc"))?;
        process_entry(&mut fs, file_entry("/etc/old_config"))?;
        process_entry(&mut fs, file_entry("/etc/another_old"))?;
        assert_files(&fs, &["/", "/etc", "/etc/another_old", "/etc/old_config"])?;

        // Opaque whiteout clears everything
        process_entry(&mut fs, file_entry("/etc/.wh..wh..opq"))?;
        assert_files(&fs, &["/", "/etc"])?;

        // Then re-add new entries
        process_entry(&mut fs, file_entry("/etc/new_config"))?;
        process_entry(&mut fs, file_entry("/etc/new_other"))?;
        assert_files(&fs, &["/", "/etc", "/etc/new_config", "/etc/new_other"])?;

        Ok(())
    }

    #[test]
    fn test_multiple_whiteouts_in_single_layer() -> Result<()> {
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/usr"))?;
        process_entry(&mut fs, file_entry("/usr/a"))?;
        process_entry(&mut fs, file_entry("/usr/b"))?;
        process_entry(&mut fs, file_entry("/usr/c"))?;
        process_entry(&mut fs, file_entry("/usr/d"))?;
        assert_files(&fs, &["/", "/usr", "/usr/a", "/usr/b", "/usr/c", "/usr/d"])?;

        // Multiple whiteouts in the same directory
        process_entry(&mut fs, file_entry("/usr/.wh.a"))?;
        process_entry(&mut fs, file_entry("/usr/.wh.c"))?;
        assert_files(&fs, &["/", "/usr", "/usr/b", "/usr/d"])?;

        Ok(())
    }

    #[test]
    fn test_double_whiteout_is_idempotent() -> Result<()> {
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/d"))?;
        process_entry(&mut fs, file_entry("/d/target"))?;
        assert_files(&fs, &["/", "/d", "/d/target"])?;

        // Whiteout the same file twice — the second is a no-op
        process_entry(&mut fs, file_entry("/d/.wh.target"))?;
        assert_files(&fs, &["/", "/d"])?;

        process_entry(&mut fs, file_entry("/d/.wh.target"))?;
        assert_files(&fs, &["/", "/d"])?;

        Ok(())
    }

    #[test]
    fn test_whiteout_unusual_name_dot_wh_dot() -> Result<()> {
        // ".wh..wh." (without trailing "opq") is a whiteout for a file
        // literally named ".wh." — it is NOT an opaque whiteout.
        // The code checks `whiteout == b".wh..opq"` for the complete
        // filename ".wh..wh..opq", so ".wh..wh." won't match.
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/d"))?;
        process_entry(&mut fs, file_entry("/d/real_file"))?;
        assert_files(&fs, &["/", "/d", "/d/real_file"])?;

        // ".wh..wh." is interpreted as a whiteout for the file named ".wh."
        // (strip ".wh." prefix → ".wh." remainder). Since no file named ".wh."
        // exists, it's a no-op. Crucially, it is NOT treated as an opaque
        // whiteout — those require the exact name ".wh..wh..opq".
        process_entry(&mut fs, file_entry("/d/.wh..wh."))?;
        assert_files(&fs, &["/", "/d", "/d/real_file"])?;

        // Note: a tar entry named ".wh." is consumed as a whiteout for "" (empty
        // name), which is effectively a no-op — the file is never stored.
        process_entry(&mut fs, file_entry("/d/.wh."))?;
        assert_files(&fs, &["/", "/d", "/d/real_file"])?;

        Ok(())
    }

    #[test]
    fn test_whiteout_across_multiple_directories() -> Result<()> {
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/a"))?;
        process_entry(&mut fs, dir_entry("/b"))?;
        process_entry(&mut fs, file_entry("/a/file1"))?;
        process_entry(&mut fs, file_entry("/a/file2"))?;
        process_entry(&mut fs, file_entry("/b/file1"))?;
        process_entry(&mut fs, file_entry("/b/file2"))?;
        assert_files(
            &fs,
            &[
                "/", "/a", "/a/file1", "/a/file2", "/b", "/b/file1", "/b/file2",
            ],
        )?;

        // Whiteout file1 in /a and file2 in /b independently
        process_entry(&mut fs, file_entry("/a/.wh.file1"))?;
        process_entry(&mut fs, file_entry("/b/.wh.file2"))?;
        assert_files(&fs, &["/", "/a", "/a/file2", "/b", "/b/file1"])?;

        Ok(())
    }

    #[test]
    fn test_opaque_whiteout_with_subdirectories() -> Result<()> {
        // Opaque whiteout should clear subdirectories too
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/parent"))?;
        process_entry(&mut fs, dir_entry("/parent/child"))?;
        process_entry(&mut fs, file_entry("/parent/child/deep"))?;
        process_entry(&mut fs, file_entry("/parent/sibling"))?;
        assert_files(
            &fs,
            &[
                "/",
                "/parent",
                "/parent/child",
                "/parent/child/deep",
                "/parent/sibling",
            ],
        )?;

        process_entry(&mut fs, file_entry("/parent/.wh..wh..opq"))?;
        assert_files(&fs, &["/", "/parent"])?;

        Ok(())
    }

    #[test]
    fn test_whiteout_then_recreate() -> Result<()> {
        // Delete a file with whiteout, then re-add it in the same layer
        let mut fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());

        process_entry(&mut fs, dir_entry("/etc"))?;
        process_entry(&mut fs, file_entry("/etc/config"))?;
        assert_files(&fs, &["/", "/etc", "/etc/config"])?;

        // Whiteout and then re-add
        process_entry(&mut fs, file_entry("/etc/.wh.config"))?;
        assert_files(&fs, &["/", "/etc"])?;

        process_entry(&mut fs, file_entry("/etc/config"))?;
        assert_files(&fs, &["/", "/etc", "/etc/config"])?;

        Ok(())
    }
}
