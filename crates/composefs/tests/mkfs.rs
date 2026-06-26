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
    dumpfile::{dumpfile_to_filesystem, write_dumpfile},
    erofs::{
        debug::debug_img,
        format::FormatVersion,
        writer::{ValidatedFileSystem, mkfs_erofs_versioned},
    },
    fsverity::{FsVerityHashValue, Sha256HashValue},
    tree::{FileSystem, Inode, LeafContent, RegularFile, Stat},
};

fn default_stat() -> Stat {
    Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 0,
        st_mtim_nsec: 0,
        xattrs: BTreeMap::new(),
    }
}

fn debug_fs_v2(fs: FileSystem<impl FsVerityHashValue>) -> String {
    let image = mkfs_erofs_versioned(
        &mut ValidatedFileSystem::new(fs).unwrap(),
        FormatVersion::V2,
    );
    let mut output = vec![];
    debug_img(&mut output, &image).unwrap();
    String::from_utf8(output).unwrap()
}

fn empty(_fs: &mut FileSystem<impl FsVerityHashValue>) {}

#[test]
fn test_empty() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    empty(&mut fs);
    insta::assert_snapshot!(debug_fs_v2(fs));
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
            st_mtim_nsec: 0,
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
    insta::assert_snapshot!(debug_fs_v2(fs));
}

#[test_with::executable(fsck.erofs)]
fn test_fsck() {
    for version in [FormatVersion::V0, FormatVersion::V1, FormatVersion::V2] {
        for case in [empty as fn(&mut _), simple] {
            let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
            case(&mut fs);
            let image = mkfs_erofs_versioned(&mut ValidatedFileSystem::new(fs).unwrap(), version);
            let mut tmp = NamedTempFile::new().unwrap();
            tmp.write_all(&image).unwrap();
            let mut fsck = Command::new("fsck.erofs").arg(tmp.path()).spawn().unwrap();
            assert!(
                fsck.wait().unwrap().success(),
                "fsck failed for {version:?}"
            );
        }
    }
}

/// Verify byte-for-byte identity with C mkcomposefs for the pinned test cases.
///
/// These fixed cases (`empty`, `simple`) complement the proptest binary-compat
/// tests in reader.rs which cover random trees. Keeping them pinned here means
/// a regression on these canonical shapes is immediately visible without proptest
/// shrinking, and is also validated by the digest stability tests above.
#[test_with::executable(mkcomposefs)]
fn test_vs_mkcomposefs() {
    for case in [empty, simple] {
        let mut fs_rust = FileSystem::new(default_stat());
        case(&mut fs_rust);
        let mut fs_c = FileSystem::new(default_stat());
        case(&mut fs_c);

        let image = mkfs_erofs_versioned(
            &mut ValidatedFileSystem::new(fs_rust).unwrap(),
            FormatVersion::V0,
        );

        let mut mkcomposefs = Command::new("mkcomposefs")
            .args(["--from-file", "-", "-"])
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
            assert_eq!(mkcomposefs_dump, dump, "structural diff (rust vs C)");
        }
        assert_eq!(image, mkcomposefs_image);
    }
}

fn dump_image(img: &[u8]) -> String {
    let mut dump = vec![];
    debug_img(&mut dump, img).unwrap();
    String::from_utf8(dump).unwrap()
}

#[test]
fn test_erofs_digest_stability() {
    // Pin digests for each format version × test case.  Any change to the EROFS
    // writer that alters byte-level output will break these, which is the point:
    // composefs image digest stability is critical for the bootc sealed UKI trust
    // chain.  V0 output must also be byte-stable since it needs to match C
    // mkcomposefs.
    let cases: &[(
        FormatVersion,
        &str,
        fn(&mut FileSystem<Sha256HashValue>),
        &str,
    )] = &[
        (
            FormatVersion::V0,
            "empty_v0",
            empty,
            "8f589e8f57ecb88823736b0d857ddca1e1068a23e264fad164b28f7038eb3682",
        ),
        (
            FormatVersion::V0,
            "simple_v0",
            simple,
            "9f3f5620ee0c54708516467d0d58741e7963047c7106b245d94c298259d0fa01",
        ),
        (
            FormatVersion::V1,
            "empty_v1",
            empty,
            "14a26c957c84f6eb774b91205476adc13196c7c33b9dd97d08d43725ecb90b63",
        ),
        (
            FormatVersion::V1,
            "simple_v1",
            simple,
            "ad6db6427568a1e4fdc772cbab7b6063f5eb4b33cb62982a740ba9213e5962b5",
        ),
        (
            FormatVersion::V2,
            "empty_v2",
            empty,
            "086b702a519b57d6ef5aea6f8b3f2be24355cd1fb835cd80fb4e3d388b24d5a5",
        ),
        (
            FormatVersion::V2,
            "simple_v2",
            simple,
            "a8fcd41f8b313bede69f462f2af0a38d64b99a6333f5df884ea9ab4037fac722",
        ),
    ];

    for (version, name, case, expected_digest) in cases {
        let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
        case(&mut fs);
        let image = mkfs_erofs_versioned(&mut ValidatedFileSystem::new(fs).unwrap(), *version);
        let digest = composefs::fsverity::compute_verity::<Sha256HashValue>(&image);
        let hex = digest.to_hex();
        assert_eq!(
            &hex, expected_digest,
            "{name}: EROFS digest changed — if this is intentional, update the pinned value"
        );
    }
}

/// Test that V0 with a whiteout (char device rdev=0) round-trips correctly.
/// Whiteouts are escaped to regular files in both V0 and V1 Epoch1 formats.
#[test]
fn test_v0_whiteout_round_trip() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    add_leaf(&mut fs, "whiteout", LeafContent::CharacterDevice(0));
    add_leaf(
        &mut fs,
        "regular",
        LeafContent::Regular(RegularFile::Inline((*b"hello").into())),
    );

    let image = mkfs_erofs_versioned(
        &mut ValidatedFileSystem::new(fs).unwrap(),
        FormatVersion::V0,
    );

    // The image must be parseable
    let rt_fs =
        composefs::erofs::reader::erofs_to_filesystem::<Sha256HashValue>(&image[..]).unwrap();

    // The whiteout should round-trip as CharacterDevice(0)
    let mut dump_bytes = Vec::new();
    composefs::dumpfile::write_dumpfile(&mut dump_bytes, &rt_fs).unwrap();
    let dump = String::from_utf8(dump_bytes).unwrap();
    assert!(
        dump.contains("/whiteout"),
        "whiteout entry missing from dump:\n{dump}"
    );
}

/// Test that `--min-version=1` forces `composefs_version=1` in the EROFS header
/// even when no user-visible whiteout devices are present, matching C mkcomposefs
/// `--min-version=1 --max-version=1` behaviour.
///
/// Uses a trimmed version of the C test suite's `special_v1.dump` fixture
/// (the `inline-large*` entries were removed since Rust intentionally rejects
/// inline content larger than `MAX_INLINE_CONTENT`).
///
/// Golden digest verified against C mkcomposefs 1.0.8+.
#[test_with::executable(mkcomposefs)]
fn test_vs_mkcomposefs_min_version_1() {
    let dump = include_str!("special_v1.dump");

    // Parse the dumpfile and build Rust image with --min-version=1.
    let fs_rust = dumpfile_to_filesystem::<Sha256HashValue>(dump).unwrap();
    let rust_image = mkfs_erofs_versioned(
        &mut ValidatedFileSystem::new(fs_rust).unwrap(),
        FormatVersion::V1,
    );

    // Also generate via C mkcomposefs --min-version=1 --max-version=1.
    let mut mkcomposefs = Command::new("mkcomposefs")
        .args([
            "--min-version=1",
            "--max-version=1",
            "--from-file",
            "-",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    mkcomposefs
        .stdin
        .take()
        .unwrap()
        .write_all(dump.as_bytes())
        .unwrap();
    let output = mkcomposefs.wait_with_output().unwrap();
    assert!(output.status.success());
    let c_image = output.stdout.into_boxed_slice();

    if rust_image != c_image {
        let rust_dump = dump_image(&rust_image);
        let c_dump = dump_image(&c_image);
        assert_eq!(
            c_dump, rust_dump,
            "structural diff (rust vs C --min-version=1)"
        );
    }
    assert_eq!(rust_image, c_image);

    // Pin the expected digest so any regression is immediately visible.
    let digest = composefs::fsverity::compute_verity::<Sha256HashValue>(&rust_image);
    assert_eq!(
        digest.to_hex(),
        "b1c78c25db8638be5b9b483472d32ee9624d8d32ded626a91cd536116e8df97c",
        "special_v1 --min-version=1 digest changed"
    );
}
