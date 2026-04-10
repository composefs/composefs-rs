//! Tests for mkfs

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    io::Write,
    process::{Command, Stdio},
};

use similar_asserts::assert_eq;
use tempfile::NamedTempFile;

use composefs::{
    dumpfile::write_dumpfile,
    erofs::{debug::debug_img, writer::mkfs_erofs},
    fsverity::{FsVerityHashValue, Sha256HashValue},
    tree::{FileSystem, Inode, LeafContent, RegularFile, Stat},
};

fn default_stat() -> Stat {
    Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 0,
        xattrs: BTreeMap::new(),
    }
}

fn debug_fs(fs: FileSystem<impl FsVerityHashValue>) -> String {
    let image = mkfs_erofs(&fs);
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
    fs: &mut FileSystem<ObjectID>,
    name: impl AsRef<OsStr>,
    content: LeafContent<ObjectID>,
) {
    let leaf_id = fs.push_leaf(
        Stat {
            st_gid: 0,
            st_uid: 0,
            st_mode: 0,
            st_mtim_sec: 0,
            xattrs: BTreeMap::new(),
        },
        content,
    );
    fs.root.insert(name.as_ref(), Inode::leaf(leaf_id));
}

fn simple(fs: &mut FileSystem<Sha256HashValue>) {
    let ext_id = Sha256HashValue::from_hex(
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
    )
    .unwrap();
    add_leaf(fs, "fifo", LeafContent::Fifo);
    add_leaf(
        fs,
        "regular-inline",
        LeafContent::Regular(RegularFile::Inline((*b"hihi").into())),
    );
    add_leaf(
        fs,
        "regular-external",
        LeafContent::Regular(RegularFile::External(ext_id, 1234)),
    );
    add_leaf(fs, "chrdev", LeafContent::CharacterDevice(123));
    add_leaf(fs, "blkdev", LeafContent::BlockDevice(123));
    add_leaf(fs, "socket", LeafContent::Socket);
    add_leaf(
        fs,
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

fn foreach_case(f: fn(&FileSystem<Sha256HashValue>)) {
    for case in [empty, simple] {
        let mut fs = FileSystem::new(default_stat());
        case(&mut fs);
        f(&fs);
    }
}

#[test_with::executable(fsck.erofs)]
fn test_fsck() {
    foreach_case(|fs| {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&mkfs_erofs(fs)).unwrap();
        let mut fsck = Command::new("fsck.erofs").arg(tmp.path()).spawn().unwrap();
        assert!(fsck.wait().unwrap().success());
    });
}

fn dump_image(img: &[u8]) -> String {
    let mut dump = vec![];
    debug_img(&mut dump, img).unwrap();
    String::from_utf8(dump).unwrap()
}

#[test]
fn test_erofs_digest_stability() {
    // Pin digests for each test case — any change to the EROFS writer that
    // alters byte-level output will break these, which is the point: composefs
    // image digest stability is critical for the bootc sealed UKI trust chain.
    let cases: &[(&str, fn(&mut FileSystem<Sha256HashValue>), &str)] = &[
        (
            "empty",
            empty,
            "086b702a519b57d6ef5aea6f8b3f2be24355cd1fb835cd80fb4e3d388b24d5a5",
        ),
        (
            "simple",
            simple,
            "a8fcd41f8b313bede69f462f2af0a38d64b99a6333f5df884ea9ab4037fac722",
        ),
    ];

    for (name, case, expected_digest) in cases {
        let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
        case(&mut fs);
        let image = mkfs_erofs(&fs);
        let digest = composefs::fsverity::compute_verity::<Sha256HashValue>(&image);
        let hex = digest.to_hex();
        assert_eq!(
            &hex, expected_digest,
            "{name}: EROFS digest changed — if this is intentional, update the pinned value"
        );
    }
}

#[should_panic]
#[test_with::executable(mkcomposefs)]
fn test_vs_mkcomposefs() {
    foreach_case(|fs| {
        let image = mkfs_erofs(fs);

        let mut mkcomposefs = Command::new("mkcomposefs")
            .args(["--min-version=3", "--from-file", "-", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        let mut stdin = mkcomposefs.stdin.take().unwrap();
        write_dumpfile(&mut stdin, fs).unwrap();
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
    });
}
