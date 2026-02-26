//! Tests for mkfs

use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::OsStr,
    io::Write,
    process::{Command, Stdio},
    rc::Rc,
};

use similar_asserts::assert_eq;
use tempfile::NamedTempFile;

use composefs::{
    dumpfile::write_dumpfile,
    erofs::{debug::debug_img, format::FormatVersion, writer::mkfs_erofs},
    fsverity::{FsVerityHashValue, Sha256HashValue},
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
};

fn default_stat() -> Stat {
    Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 0,
        xattrs: RefCell::new(BTreeMap::new()),
    }
}

fn mkfs_erofs_default<ObjectID: FsVerityHashValue>(fs: &FileSystem<ObjectID>) -> Box<[u8]> {
    mkfs_erofs(fs, FormatVersion::default())
}

/// Create a Format 1.0 compatible image with all transformations applied.
/// This includes adding the whiteout table and overlay.opaque xattr.
///
/// Note: This takes ownership of the filesystem to avoid Rc clone issues.
/// When FileSystem is cloned, Rc<Leaf> strong_count increments, which would
/// incorrectly affect nlink calculations in the writer.
fn mkfs_erofs_v1_0(mut fs: FileSystem<Sha256HashValue>) -> Box<[u8]> {
    // Apply Format 1.0 transformations (whiteouts + opaque xattr added by mkfs_erofs for V1_0)
    fs.add_overlay_whiteouts();
    mkfs_erofs(&fs, FormatVersion::V1_0)
}

fn debug_fs(fs: FileSystem<impl FsVerityHashValue>) -> String {
    let image = mkfs_erofs_default(&fs);
    let mut output = vec![];
    debug_img(&mut output, &image).unwrap();
    String::from_utf8(output).unwrap()
}

fn empty(_fs: &mut FileSystem<impl FsVerityHashValue>) {}

#[test]
fn test_empty() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    empty(&mut fs);
    insta::assert_snapshot!(debug_fs(fs));
}

fn add_leaf<ObjectID: FsVerityHashValue>(
    dir: &mut Directory<ObjectID>,
    name: impl AsRef<OsStr>,
    content: LeafContent<ObjectID>,
) {
    dir.insert(
        name.as_ref(),
        Inode::Leaf(Rc::new(Leaf {
            content,
            stat: Stat {
                st_gid: 0,
                st_uid: 0,
                st_mode: 0,
                st_mtim_sec: 0,
                xattrs: RefCell::new(BTreeMap::new()),
            },
        })),
    );
}

fn simple(fs: &mut FileSystem<Sha256HashValue>) {
    let ext_id = Sha256HashValue::from_hex(
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
    )
    .unwrap();
    add_leaf(&mut fs.root, "fifo", LeafContent::Fifo);
    add_leaf(
        &mut fs.root,
        "regular-inline",
        LeafContent::Regular(RegularFile::Inline((*b"hihi").into())),
    );
    add_leaf(
        &mut fs.root,
        "regular-external",
        LeafContent::Regular(RegularFile::External(ext_id, 1234)),
    );
    add_leaf(&mut fs.root, "chrdev", LeafContent::CharacterDevice(123));
    add_leaf(&mut fs.root, "blkdev", LeafContent::BlockDevice(123));
    add_leaf(&mut fs.root, "socket", LeafContent::Socket);
    add_leaf(
        &mut fs.root,
        "symlink",
        LeafContent::Symlink(OsStr::new("/target").into()),
    );
}

#[test]
fn test_simple() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    simple(&mut fs);
    insta::assert_snapshot!(debug_fs(fs));
}

/// Test nested directory structure to establish baseline for V1_1 format.
///
/// This test creates a multi-level directory structure with files at various depths
/// to verify the BFS inode ordering is correctly captured in snapshots. The ordering
/// matches C mkcomposefs for bit-for-bit compatibility in V1_0 format, and this
/// same ordering is used for V1_1 format for consistency.
fn nested(fs: &mut FileSystem<Sha256HashValue>) {
    let ext_id = Sha256HashValue::from_hex(
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    )
    .unwrap();

    // Create /a/b/c/deep-file
    let mut dir_c = Directory::new(default_stat());
    add_leaf(
        &mut dir_c,
        "deep-file",
        LeafContent::Regular(RegularFile::Inline((*b"deep content").into())),
    );

    let mut dir_b = Directory::new(default_stat());
    dir_b.insert(OsStr::new("c"), Inode::Directory(Box::new(dir_c)));
    add_leaf(
        &mut dir_b,
        "mid-file",
        LeafContent::Regular(RegularFile::Inline((*b"mid content").into())),
    );

    let mut dir_a = Directory::new(default_stat());
    dir_a.insert(OsStr::new("b"), Inode::Directory(Box::new(dir_b)));
    add_leaf(
        &mut dir_a,
        "shallow-file",
        LeafContent::Regular(RegularFile::External(ext_id.clone(), 4096)),
    );

    fs.root
        .insert(OsStr::new("a"), Inode::Directory(Box::new(dir_a)));

    // Create /x/y/z-file to test BFS ordering across sibling directories
    let mut dir_y = Directory::new(default_stat());
    add_leaf(
        &mut dir_y,
        "z-file",
        LeafContent::Regular(RegularFile::Inline((*b"xyz").into())),
    );

    let mut dir_x = Directory::new(default_stat());
    dir_x.insert(OsStr::new("y"), Inode::Directory(Box::new(dir_y)));

    fs.root
        .insert(OsStr::new("x"), Inode::Directory(Box::new(dir_x)));

    // Add a file at root level too
    add_leaf(
        &mut fs.root,
        "root-file",
        LeafContent::Regular(RegularFile::Inline((*b"root").into())),
    );
}

/// Snapshot test for nested directory structure.
///
/// This establishes the baseline for V1_1 format with subdirectories.
/// The inode ordering follows BFS (breadth-first search) to match C mkcomposefs,
/// which processes all nodes at depth N before any nodes at depth N+1.
#[test]
fn test_nested() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    nested(&mut fs);
    insta::assert_snapshot!(debug_fs(fs));
}

fn foreach_case(f: fn(&FileSystem<Sha256HashValue>)) {
    for case in [empty, simple, nested] {
        let mut fs = FileSystem::new(default_stat());
        case(&mut fs);
        f(&fs);
    }
}

#[test_with::executable(fsck.erofs)]
fn test_fsck() {
    foreach_case(|fs| {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&mkfs_erofs_default(fs)).unwrap();
        let mut fsck = Command::new("fsck.erofs").arg(tmp.path()).spawn().unwrap();
        assert!(fsck.wait().unwrap().success());
    });
}

fn dump_image(img: &[u8]) -> String {
    let mut dump = vec![];
    debug_img(&mut dump, img).unwrap();
    String::from_utf8(dump).unwrap()
}

/// Get the path to mkcomposefs binary.
/// Uses MKCOMPOSEFS_PATH env var if set, otherwise looks for "mkcomposefs" in PATH.
fn mkcomposefs_path() -> std::path::PathBuf {
    std::env::var("MKCOMPOSEFS_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("mkcomposefs"))
}

#[test_with::executable(mkcomposefs)]
fn test_vs_mkcomposefs() {
    let mkcomposefs_cmd = mkcomposefs_path();

    // Build two separate filesystems for each test case to avoid Rc clone issues.
    // When FileSystem is cloned, Rc<Leaf> strong_count increments, which would
    // incorrectly affect nlink calculations in the writer.
    for case in [empty, simple] {
        // Build filesystem for Rust mkfs
        let mut fs_rust = FileSystem::new(default_stat());
        case(&mut fs_rust);

        // Build separate filesystem for C mkcomposefs (to preserve Rc counts)
        let mut fs_c = FileSystem::new(default_stat());
        case(&mut fs_c);

        // Use Format 1.0 for Rust to match C mkcomposefs --min-version=0
        // This includes whiteout table and overlay.opaque transformations
        let image = mkfs_erofs_v1_0(fs_rust);

        let mut mkcomposefs = Command::new(&mkcomposefs_cmd)
            .args(["--min-version=0", "--from-file", "-", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        let mut stdin = mkcomposefs.stdin.take().unwrap();
        write_dumpfile(&mut stdin, &fs_c).unwrap();
        drop(stdin);

        let output = mkcomposefs.wait_with_output().unwrap();
        assert!(output.status.success());
        let mkcomposefs_image = output.stdout.into_boxed_slice();

        if image != mkcomposefs_image {
            let dump = dump_image(&image);
            let mkcomposefs_dump = dump_image(&mkcomposefs_image);
            assert_eq!(mkcomposefs_dump, dump);
        }
        assert_eq!(image, mkcomposefs_image); // fallback if the dump is somehow the same
    }
}
