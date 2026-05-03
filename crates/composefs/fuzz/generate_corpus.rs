//! Generate seed corpus files for the EROFS fuzz targets.
//!
//! Each seed is a valid EROFS image that exercises a distinct reader code path:
//! inline/external files, special file types, xattrs, directory
//! layouts, hardlinks, and edge cases around inode sizing.
//!
//! Run via: `cargo run --manifest-path crates/composefs/fuzz/Cargo.toml --bin generate-corpus`
//! or:      `just generate-corpus`

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;

use composefs::erofs::format::FormatVersion;
use composefs::erofs::writer::{mkfs_erofs, mkfs_erofs_versioned};
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue};
use composefs::generic_tree::{self, LeafContent, Stat};
use composefs::tree::{self, FileSystem, RegularFile};

type Dir = tree::Directory<Sha256HashValue>;
type Inode = tree::Inode<Sha256HashValue>;

/// Create a Stat with the given mode, uid, gid, mtime.
fn stat(mode: u32, uid: u32, gid: u32, mtime: i64) -> Stat {
    Stat {
        st_mode: mode,
        st_uid: uid,
        st_gid: gid,
        st_mtim_sec: mtime,
        st_mtim_nsec: 0,
        xattrs: BTreeMap::new(),
    }
}

/// Create a default directory stat (0o755, root, mtime=0).
fn dir_stat() -> Stat {
    stat(0o755, 0, 0, 0)
}

/// Create a default file stat (0o644, root, mtime=0).
fn file_stat() -> Stat {
    stat(0o644, 0, 0, 0)
}

/// Build a FileSystem with just an empty root directory.
fn empty_root() -> FileSystem<Sha256HashValue> {
    FileSystem::new(dir_stat())
}

/// Insert a subdirectory into a directory, returning a mutable reference to it.
fn insert_dir<'a>(parent: &'a mut Dir, name: &str, s: Stat) -> &'a mut Dir {
    parent.insert(
        OsStr::new(name),
        Inode::Directory(Box::new(generic_tree::Directory::new(s))),
    );
    parent.get_directory_mut(OsStr::new(name)).unwrap()
}

/// Generate both V1 and V2 images for a filesystem, pushing them into seeds.
///
/// The V2 image uses the name as-is. The V1 image appends "_v1" to the name.
/// For V1, overlay whiteouts are added before writing (required for C compat).
fn push_both_versions(
    seeds: &mut Vec<(String, Vec<u8>)>,
    name: &str,
    build_fs: impl Fn() -> FileSystem<Sha256HashValue>,
) {
    // V2 (default)
    let fs = build_fs();
    let image = mkfs_erofs(&fs);
    seeds.push((name.to_string(), image.into()));

    // V1 (C-compatible)
    let mut fs = build_fs();
    fs.add_overlay_whiteouts();
    let image = mkfs_erofs_versioned(&fs, FormatVersion::V1);
    seeds.push((format!("{name}_v1"), image.into()));
}

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();

    // 1. Empty root
    push_both_versions(&mut seeds, "empty_root", empty_root);

    // 2. Single inline file (small content stored in inode)
    push_both_versions(&mut seeds, "single_inline_file", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            file_stat(),
            LeafContent::Regular(RegularFile::Inline(
                b"Hello, world!".to_vec().into_boxed_slice(),
            )),
        );
        fs.root.insert(OsStr::new("hello.txt"), Inode::leaf(id));
        fs
    });

    // 3. Single external (chunk-based) regular file
    push_both_versions(&mut seeds, "single_external_file", || {
        let mut fs = empty_root();
        let hash = Sha256HashValue::EMPTY;
        let id = fs.push_leaf(
            file_stat(),
            LeafContent::Regular(RegularFile::External(hash, 65536)),
        );
        fs.root.insert(OsStr::new("data.bin"), Inode::leaf(id));
        fs
    });

    // 4. Symlink
    push_both_versions(&mut seeds, "symlink", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            stat(0o777, 0, 0, 0),
            LeafContent::Symlink(OsString::from("/target/path").into_boxed_os_str()),
        );
        fs.root.insert(OsStr::new("link"), Inode::leaf(id));
        fs
    });

    // 5. FIFO
    push_both_versions(&mut seeds, "fifo", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(file_stat(), LeafContent::Fifo);
        fs.root.insert(OsStr::new("mypipe"), Inode::leaf(id));
        fs
    });

    // 6. Character device
    push_both_versions(&mut seeds, "chardev", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            stat(0o666, 0, 0, 0),
            LeafContent::CharacterDevice(makedev(1, 3)),
        );
        fs.root.insert(OsStr::new("null"), Inode::leaf(id));
        fs
    });

    // 7. Block device
    push_both_versions(&mut seeds, "blockdev", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            stat(0o660, 0, 6, 0),
            LeafContent::BlockDevice(makedev(8, 0)),
        );
        fs.root.insert(OsStr::new("sda"), Inode::leaf(id));
        fs
    });

    // 8. Socket
    push_both_versions(&mut seeds, "socket", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(file_stat(), LeafContent::Socket);
        fs.root.insert(OsStr::new("mysock"), Inode::leaf(id));
        fs
    });

    // 9. Nested directories: /a/b/c/file
    push_both_versions(&mut seeds, "nested_dirs", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            file_stat(),
            LeafContent::Regular(RegularFile::Inline(
                b"nested content".to_vec().into_boxed_slice(),
            )),
        );
        let a = insert_dir(&mut fs.root, "a", dir_stat());
        let b = insert_dir(a, "b", dir_stat());
        let c = insert_dir(b, "c", dir_stat());
        c.insert(OsStr::new("file"), Inode::leaf(id));
        fs
    });

    // 10. Many entries (20+ files to exercise multi-block directories)
    push_both_versions(&mut seeds, "many_entries", || {
        let mut fs = empty_root();
        for i in 0..25 {
            let name = format!("file_{i:03}");
            let content = format!("content of file {i}");
            let id = fs.push_leaf(
                file_stat(),
                LeafContent::Regular(RegularFile::Inline(
                    content.into_bytes().into_boxed_slice(),
                )),
            );
            fs.root.insert(OsStr::new(&name), Inode::leaf(id));
        }
        fs
    });

    // 11. Extended attributes
    push_both_versions(&mut seeds, "xattrs", || {
        let mut fs = empty_root();
        let mut xattrs = BTreeMap::new();
        xattrs.insert(
            Box::from(OsStr::new("security.selinux")),
            Box::from(b"system_u:object_r:usr_t:s0".as_slice()),
        );
        xattrs.insert(
            Box::from(OsStr::new("user.test")),
            Box::from(b"test_value".as_slice()),
        );
        let xattr_stat = Stat {
            xattrs,
            ..file_stat()
        };
        let id = fs.push_leaf(
            xattr_stat,
            LeafContent::Regular(RegularFile::Inline(
                b"has xattrs".to_vec().into_boxed_slice(),
            )),
        );
        fs.root.insert(OsStr::new("xattr_file"), Inode::leaf(id));
        fs
    });

    // 12. Mixed types — one of every file type in a single directory
    push_both_versions(&mut seeds, "mixed_types", || {
        let mut fs = empty_root();
        let ids = [
            fs.push_leaf(
                file_stat(),
                LeafContent::Regular(RegularFile::Inline(
                    b"data".to_vec().into_boxed_slice(),
                )),
            ),
            fs.push_leaf(
                stat(0o777, 0, 0, 0),
                LeafContent::Symlink(OsString::from("regular").into_boxed_os_str()),
            ),
            fs.push_leaf(file_stat(), LeafContent::Fifo),
            fs.push_leaf(file_stat(), LeafContent::Socket),
            fs.push_leaf(
                stat(0o666, 0, 0, 0),
                LeafContent::CharacterDevice(makedev(1, 3)),
            ),
            fs.push_leaf(
                stat(0o660, 0, 6, 0),
                LeafContent::BlockDevice(makedev(8, 0)),
            ),
        ];
        let names = ["regular", "link", "pipe", "sock", "chrdev", "blkdev"];
        for (name, id) in names.iter().zip(ids.iter()) {
            fs.root.insert(OsStr::new(name), Inode::leaf(*id));
        }
        insert_dir(&mut fs.root, "subdir", dir_stat());
        let hash = Sha256HashValue::EMPTY;
        let ext_id = fs.push_leaf(
            file_stat(),
            LeafContent::Regular(RegularFile::External(hash, 4096)),
        );
        fs.root.insert(OsStr::new("external"), Inode::leaf(ext_id));
        fs
    });

    // 13. Hardlink — two entries sharing the same LeafId (nlink > 1)
    {
        let mut fs = empty_root();
        let shared_id = fs.push_leaf(
            file_stat(),
            LeafContent::Regular(RegularFile::Inline(
                b"shared content".to_vec().into_boxed_slice(),
            )),
        );
        fs.root
            .insert(OsStr::new("original"), Inode::leaf(shared_id));
        fs.root
            .insert(OsStr::new("hardlink"), Inode::leaf(shared_id));
        let image = mkfs_erofs(&fs);
        seeds.push(("hardlink".to_string(), image.into()));
    }

    // 14. Large inline — file with maximum inline content (just under 4096 bytes)
    push_both_versions(&mut seeds, "large_inline", || {
        let mut fs = empty_root();
        let content = vec![0xABu8; 4000]; // just under block size
        let id = fs.push_leaf(
            file_stat(),
            LeafContent::Regular(RegularFile::Inline(content.into_boxed_slice())),
        );
        fs.root
            .insert(OsStr::new("large_inline.bin"), Inode::leaf(id));
        fs
    });

    // 15. Deep nesting — 8 levels of directories
    push_both_versions(&mut seeds, "deep_nesting", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            file_stat(),
            LeafContent::Regular(RegularFile::Inline(
                b"deep".to_vec().into_boxed_slice(),
            )),
        );
        let names = ["d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8"];
        let mut current = &mut fs.root;
        for name in &names {
            current = insert_dir(current, name, dir_stat());
        }
        current.insert(OsStr::new("deep_file"), Inode::leaf(id));
        fs
    });

    // 16. Nonzero mtime
    push_both_versions(&mut seeds, "nonzero_mtime", || {
        let mut fs = FileSystem::new(stat(0o755, 0, 0, 1000000));
        let id1 = fs.push_leaf(
            stat(0o644, 0, 0, 500000),
            LeafContent::Regular(RegularFile::Inline(
                b"old file".to_vec().into_boxed_slice(),
            )),
        );
        let id2 = fs.push_leaf(
            stat(0o644, 0, 0, 1700000000),
            LeafContent::Regular(RegularFile::Inline(
                b"new file".to_vec().into_boxed_slice(),
            )),
        );
        fs.root.insert(OsStr::new("old"), Inode::leaf(id1));
        fs.root.insert(OsStr::new("new"), Inode::leaf(id2));
        fs
    });

    // 17. Large uid/gid — forces extended inodes
    push_both_versions(&mut seeds, "large_uid_gid", || {
        let big_id = u16::MAX as u32 + 1; // 65536, won't fit in u16
        let mut fs = FileSystem::new(stat(0o755, big_id, big_id, 0));
        let id = fs.push_leaf(
            stat(0o644, big_id, big_id, 0),
            LeafContent::Regular(RegularFile::Inline(
                b"big ids".to_vec().into_boxed_slice(),
            )),
        );
        fs.root.insert(OsStr::new("bigids.txt"), Inode::leaf(id));
        fs
    });

    // Write seeds to corpus directories for both fuzz targets
    let targets = ["read_image", "debug_image"];
    for target in &targets {
        let corpus_dir = manifest_dir.join("corpus").join(target);
        fs::create_dir_all(&corpus_dir)
            .unwrap_or_else(|e| panic!("create {}: {e}", corpus_dir.display()));
    }

    let mut count = 0;
    for (name, data) in &seeds {
        for target in &targets {
            let corpus_dir = manifest_dir.join("corpus").join(target);
            let path = corpus_dir.join(name);
            fs::write(&path, data).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        }
        count += 1;
        println!("{count:>4}  {size:>6} bytes  {name}", size = data.len());
    }
    println!(
        "\nGenerated {count} seed files for {} fuzz targets",
        targets.len()
    );
}

/// Encode major/minor device numbers into a single u64 (Linux encoding).
fn makedev(major: u32, minor: u32) -> u64 {
    let maj = major as u64;
    let min = minor as u64;
    ((maj & 0xfffff000) << 32) | ((maj & 0xfff) << 8) | ((min & 0xffffff00) << 12) | (min & 0xff)
}
