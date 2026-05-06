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

use composefs::erofs::writer::mkfs_erofs;
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

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut seeds: Vec<(&str, Vec<u8>)> = Vec::new();

    // 1. Empty root
    {
        let fs = empty_root();
        let image = mkfs_erofs(&fs);
        seeds.push(("empty_root", image.into()));
    }

    // 2. Single inline file (small content stored in inode)
    {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            file_stat(),
            LeafContent::Regular(RegularFile::Inline(
                b"Hello, world!".to_vec().into_boxed_slice(),
            )),
        );
        fs.root.insert(OsStr::new("hello.txt"), Inode::leaf(id));
        let image = mkfs_erofs(&fs);
        seeds.push(("single_inline_file", image.into()));
    }

    // 3. Single external (chunk-based) regular file
    {
        let mut fs = empty_root();
        let hash = Sha256HashValue::EMPTY;
        let id = fs.push_leaf(
            file_stat(),
            LeafContent::Regular(RegularFile::External(hash, 65536)),
        );
        fs.root.insert(OsStr::new("data.bin"), Inode::leaf(id));
        let image = mkfs_erofs(&fs);
        seeds.push(("single_external_file", image.into()));
    }

    // 4. Symlink
    {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            stat(0o777, 0, 0, 0),
            LeafContent::Symlink(OsString::from("/target/path").into_boxed_os_str()),
        );
        fs.root.insert(OsStr::new("link"), Inode::leaf(id));
        let image = mkfs_erofs(&fs);
        seeds.push(("symlink", image.into()));
    }

    // 5. FIFO
    {
        let mut fs = empty_root();
        let id = fs.push_leaf(file_stat(), LeafContent::Fifo);
        fs.root.insert(OsStr::new("mypipe"), Inode::leaf(id));
        let image = mkfs_erofs(&fs);
        seeds.push(("fifo", image.into()));
    }

    // 6. Character device
    {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            stat(0o666, 0, 0, 0),
            LeafContent::CharacterDevice(makedev(1, 3)),
        );
        fs.root.insert(OsStr::new("null"), Inode::leaf(id));
        let image = mkfs_erofs(&fs);
        seeds.push(("chardev", image.into()));
    }

    // 7. Block device
    {
        let mut fs = empty_root();
        let id = fs.push_leaf(
            stat(0o660, 0, 6, 0),
            LeafContent::BlockDevice(makedev(8, 0)),
        );
        fs.root.insert(OsStr::new("sda"), Inode::leaf(id));
        let image = mkfs_erofs(&fs);
        seeds.push(("blockdev", image.into()));
    }

    // 8. Socket
    {
        let mut fs = empty_root();
        let id = fs.push_leaf(file_stat(), LeafContent::Socket);
        fs.root.insert(OsStr::new("mysock"), Inode::leaf(id));
        let image = mkfs_erofs(&fs);
        seeds.push(("socket", image.into()));
    }

    // 9. Nested directories: /a/b/c/file
    {
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
        let image = mkfs_erofs(&fs);
        seeds.push(("nested_dirs", image.into()));
    }

    // 10. Many entries (20+ files to exercise multi-block directories)
    {
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
        let image = mkfs_erofs(&fs);
        seeds.push(("many_entries", image.into()));
    }

    // 11. Extended attributes
    {
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
        let image = mkfs_erofs(&fs);
        seeds.push(("xattrs", image.into()));
    }

    // 12. Mixed types — one of every file type in a single directory
    {
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
        let image = mkfs_erofs(&fs);
        seeds.push(("mixed_types", image.into()));
    }

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
        seeds.push(("hardlink", image.into()));
    }

    // 14. Large inline — file with maximum inline content (just under 4096 bytes)
    {
        let mut fs = empty_root();
        let content = vec![0xABu8; 4000]; // just under block size
        let id = fs.push_leaf(
            file_stat(),
            LeafContent::Regular(RegularFile::Inline(content.into_boxed_slice())),
        );
        fs.root
            .insert(OsStr::new("large_inline.bin"), Inode::leaf(id));
        let image = mkfs_erofs(&fs);
        seeds.push(("large_inline", image.into()));
    }

    // 15. Deep nesting — 8 levels of directories
    {
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
        let image = mkfs_erofs(&fs);
        seeds.push(("deep_nesting", image.into()));
    }

    // 16. Nonzero mtime
    {
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
        let image = mkfs_erofs(&fs);
        seeds.push(("nonzero_mtime", image.into()));
    }

    // 17. Large uid/gid — forces extended inodes
    {
        let big_id = u16::MAX as u32 + 1; // 65536, won't fit in u16
        let mut fs = FileSystem::new(stat(0o755, big_id, big_id, 0));
        let id = fs.push_leaf(
            stat(0o644, big_id, big_id, 0),
            LeafContent::Regular(RegularFile::Inline(
                b"big ids".to_vec().into_boxed_slice(),
            )),
        );
        fs.root.insert(OsStr::new("bigids.txt"), Inode::leaf(id));
        let image = mkfs_erofs(&fs);
        seeds.push(("large_uid_gid", image.into()));
    }

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
