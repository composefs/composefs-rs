//! Generate seed corpus files for the EROFS, dumpfile, and splitstream fuzz targets.
//!
//! EROFS seeds are valid images that exercise distinct reader code paths:
//! inline/external files, special file types, xattrs, directory
//! layouts, hardlinks, and edge cases around inode sizing.
//! Dumpfile seeds are individual writer-generated entries; splitstream seeds
//! cover empty, inline, and mixed content in both header layouts.
//!
//! Run via: `cargo run --manifest-path crates/composefs/fuzz/Cargo.toml --bin generate-corpus`
//! or:      `just generate-corpus`

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::path::Path;

use composefs::erofs::format::FormatVersion;
use composefs::erofs::writer::{ValidatedFileSystem, mkfs_erofs, mkfs_erofs_versioned};
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

/// Generate V0, V1, and V2 images for a filesystem, pushing them into seeds.
///
/// The V2 image uses the name as-is; V1 appends "_v1"; V0 appends "_v0".
/// V0/V1 whiteout stubs are added automatically by the writer.
fn push_all_versions(
    seeds: &mut Vec<(String, Vec<u8>)>,
    name: &str,
    build_fs: impl Fn() -> FileSystem<Sha256HashValue>,
) {
    // V2 (Rust-native extended inodes, DFS ordering, no stubs)
    let image = mkfs_erofs(&ValidatedFileSystem::new(build_fs()).unwrap());
    seeds.push((name.to_string(), image.into()));

    // V1 (compact inodes, always composefs_version=1, stubs injected)
    let image = mkfs_erofs_versioned(
        &ValidatedFileSystem::new(build_fs()).unwrap(),
        FormatVersion::V1,
    );
    seeds.push((format!("{name}_v1"), image.into()));

    // V0 (compact inodes, composefs_version auto-bumps to 1 only if whiteouts present)
    let image = mkfs_erofs_versioned(
        &ValidatedFileSystem::new(build_fs()).unwrap(),
        FormatVersion::V0,
    );
    seeds.push((format!("{name}_v0"), image.into()));
}

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    generate_dumpfile_corpus(manifest_dir);
    generate_splitstream_corpus(manifest_dir);

    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();

    // 1. Empty root
    push_all_versions(&mut seeds, "empty_root", empty_root);

    // 2. Single inline file (small content stored in inode)
    push_all_versions(&mut seeds, "single_inline_file", || {
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
    push_all_versions(&mut seeds, "single_external_file", || {
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
    push_all_versions(&mut seeds, "symlink", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            stat(0o777, 0, 0, 0),
            LeafContent::Symlink(OsString::from("/target/path").into_boxed_os_str()),
        );
        fs.root.insert(OsStr::new("link"), Inode::leaf(id));
        fs
    });

    // 5. FIFO
    push_all_versions(&mut seeds, "fifo", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(file_stat(), LeafContent::Fifo);
        fs.root.insert(OsStr::new("mypipe"), Inode::leaf(id));
        fs
    });

    // 6. Character device
    push_all_versions(&mut seeds, "chardev", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            stat(0o666, 0, 0, 0),
            LeafContent::CharacterDevice(makedev(1, 3)),
        );
        fs.root.insert(OsStr::new("null"), Inode::leaf(id));
        fs
    });

    // 7. Block device
    push_all_versions(&mut seeds, "blockdev", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            stat(0o660, 0, 6, 0),
            LeafContent::BlockDevice(makedev(8, 0)),
        );
        fs.root.insert(OsStr::new("sda"), Inode::leaf(id));
        fs
    });

    // 8. Socket
    push_all_versions(&mut seeds, "socket", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(file_stat(), LeafContent::Socket);
        fs.root.insert(OsStr::new("mysock"), Inode::leaf(id));
        fs
    });

    // 9. Nested directories: /a/b/c/file
    push_all_versions(&mut seeds, "nested_dirs", || {
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
    push_all_versions(&mut seeds, "many_entries", || {
        let mut fs = empty_root();
        for i in 0..25 {
            let name = format!("file_{i:03}");
            let content = format!("content of file {i}");
            let id = fs.push_leaf(
                file_stat(),
                LeafContent::Regular(RegularFile::Inline(content.into_bytes().into_boxed_slice())),
            );
            fs.root.insert(OsStr::new(&name), Inode::leaf(id));
        }
        fs
    });

    // 11. Extended attributes
    push_all_versions(&mut seeds, "xattrs", || {
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
    push_all_versions(&mut seeds, "mixed_types", || {
        let mut fs = empty_root();
        let ids = [
            fs.push_leaf(
                file_stat(),
                LeafContent::Regular(RegularFile::Inline(b"data".to_vec().into_boxed_slice())),
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
    push_all_versions(&mut seeds, "hardlink", || {
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
        fs
    });

    // 14. Large inline — file with maximum inline content (just under 4096 bytes)
    push_all_versions(&mut seeds, "large_inline", || {
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
    push_all_versions(&mut seeds, "deep_nesting", || {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            file_stat(),
            LeafContent::Regular(RegularFile::Inline(b"deep".to_vec().into_boxed_slice())),
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
    push_all_versions(&mut seeds, "nonzero_mtime", || {
        let mut fs = FileSystem::new(stat(0o755, 0, 0, 1000000));
        let id1 = fs.push_leaf(
            stat(0o644, 0, 0, 500000),
            LeafContent::Regular(RegularFile::Inline(b"old file".to_vec().into_boxed_slice())),
        );
        let id2 = fs.push_leaf(
            stat(0o644, 0, 0, 1700000000),
            LeafContent::Regular(RegularFile::Inline(b"new file".to_vec().into_boxed_slice())),
        );
        fs.root.insert(OsStr::new("old"), Inode::leaf(id1));
        fs.root.insert(OsStr::new("new"), Inode::leaf(id2));
        fs
    });

    // 17. Large uid/gid — forces extended inodes
    push_all_versions(&mut seeds, "large_uid_gid", || {
        let big_id = u16::MAX as u32 + 1; // 65536, won't fit in u16
        let mut fs = FileSystem::new(stat(0o755, big_id, big_id, 0));
        let id = fs.push_leaf(
            stat(0o644, big_id, big_id, 0),
            LeafContent::Regular(RegularFile::Inline(b"big ids".to_vec().into_boxed_slice())),
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

fn write_seed(manifest_dir: &Path, target: &str, name: &str, data: &[u8]) {
    let dir = manifest_dir.join("corpus").join(target);
    fs::create_dir_all(&dir).expect("creating corpus directory");
    fs::write(dir.join(name), data).expect("writing corpus seed");
}

fn generate_dumpfile_corpus(manifest_dir: &Path) {
    use composefs::dumpfile::{write_directory, write_hardlink, write_leaf};

    let mut stat = file_stat();
    for (key, value) in [
        ("user.empty", b"".as_slice()),
        ("user.dash", b"-".as_slice()),
        ("user.equals=", b"=\0\xff\n".as_slice()),
    ] {
        stat.xattrs.insert(OsStr::new(key).into(), value.into());
    }
    let mut line = String::new();
    write_directory(&mut line, Path::new("/"), &stat, 2).unwrap();
    write_seed(
        manifest_dir,
        "dumpfile",
        "directory_xattrs",
        line.as_bytes(),
    );

    let leaves: [tree::LeafContent<Sha256HashValue>; 9] = [
        LeafContent::Regular(RegularFile::Inline(b"-\0\xff\n".as_slice().into())),
        LeafContent::Regular(RegularFile::Inline(b"".as_slice().into())),
        LeafContent::Regular(RegularFile::Sparse(4096)),
        LeafContent::Regular(RegularFile::External(Sha256HashValue::EMPTY, 65536)),
        LeafContent::Symlink(OsStr::new("-").into()),
        LeafContent::Fifo,
        LeafContent::Socket,
        LeafContent::CharacterDevice(makedev(1, 3)),
        LeafContent::BlockDevice(makedev(8, 0)),
    ];
    for (i, content) in leaves.iter().enumerate() {
        line.clear();
        write_leaf(&mut line, Path::new("/file name"), &stat, content, 1).unwrap();
        write_seed(
            manifest_dir,
            "dumpfile",
            &format!("leaf_{i}"),
            line.as_bytes(),
        );
    }
    line.clear();
    write_hardlink(&mut line, Path::new("/link"), OsStr::new("/file name")).unwrap();
    write_seed(manifest_dir, "dumpfile", "hardlink", line.as_bytes());
}

fn generate_splitstream_corpus(manifest_dir: &Path) {
    use composefs::splitstream::new_to_old_format;
    use composefs::test::TestRepo;

    let test_repo = TestRepo::<Sha256HashValue>::new();
    let repo = &test_repo.repo;
    for name in ["empty", "inline", "mixed"] {
        let mut writer = repo.create_stream(42).unwrap();
        if name != "empty" {
            writer.write_inline(b"inline fuzz seed");
        }
        if name == "mixed" {
            writer.write_external(b"external fuzz seed").unwrap();
            writer.write_inline(b"trailer");
            writer.add_named_stream_ref("named", &Sha256HashValue::EMPTY);
        }
        let id = writer.done().unwrap();
        let mut bytes = Vec::new();
        fs::File::from(repo.open_object(&id).unwrap())
            .read_to_end(&mut bytes)
            .unwrap();
        write_seed(manifest_dir, "splitstream", name, &bytes);
        write_seed(
            manifest_dir,
            "splitstream",
            &format!("{name}_old"),
            &new_to_old_format(&bytes),
        );
    }
}

/// Encode major/minor device numbers into a single u64 (Linux encoding).
fn makedev(major: u32, minor: u32) -> u64 {
    let maj = major as u64;
    let min = minor as u64;
    ((maj & 0xfffff000) << 32) | ((maj & 0xfff) << 8) | ((min & 0xffffff00) << 12) | (min & 0xff)
}
