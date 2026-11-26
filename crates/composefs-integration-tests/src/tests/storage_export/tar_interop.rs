//! Independent Go reconstruction of layers with extended tar metadata.

use std::{
    ffi::OsStr,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
    },
    path::Path,
    sync::Arc,
};

use anyhow::Result;
use composefs::{
    fsverity::{FsVerityHashValue, Sha512HashValue},
    repository::{Repository, RepositoryConfig},
};
use xshell::{Shell, cmd};

use super::{
    OverlayMountCleanup, VerityTempDir, append, copy_to_storage, require_privileged, store_image,
    top_layer,
};
use crate::integration_test;

const MTIME_SECONDS: u64 = 123;
const MTIME_NANOS: i64 = 123_456_789;
// Exceed the repository splitter's inline threshold to retain a file reference.
const PAYLOAD_SIZE: usize = 128 * 1024 + 1;
const BYTE_PATH: &[u8] = b"implicit-\xff/payload-\xfe";

fn header(kind: tar::EntryType, mode: u32) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_mode(mode);
    header.set_uid(123);
    header.set_gid(456);
    header.set_mtime(MTIME_SECONDS);
    header.set_size(0);
    header.set_cksum();
    header
}

fn complex_tar() -> Result<(Vec<u8>, String, Vec<u8>)> {
    let mut tar = tar::Builder::new(Vec::new());
    let attributes = b"13 uid=12345\n14 mtime=99.5\n13 path=nope\n";
    let mut global = header(tar::EntryType::XGlobalHeader, 0o644);
    global.set_size(attributes.len() as u64);
    tar.append_data(&mut global, "global", attributes.as_slice())?;
    append(&mut tar, ".", &[], true)?;
    append(&mut tar, "data", &[], true)?;
    let long_name = format!("data/{}", "long-name-".repeat(16));
    let payload = vec![73; PAYLOAD_SIZE];
    tar.append_pax_extensions([
        ("mtime", b"123.123456789".as_slice()),
        ("SCHILY.xattr.user.fixture", b"pax-value"),
    ])?;
    let mut regular = header(tar::EntryType::Regular, 0o640);
    regular.set_size(payload.len() as u64);
    // append_data emits a GNU long-name header for this path.
    tar.append_data(&mut regular, &long_name, payload.as_slice())?;

    let mut hardlink = header(tar::EntryType::Link, 0o600);
    hardlink.set_uid(999);
    hardlink.set_gid(998);
    hardlink.set_mtime(456);
    // Conflicting hardlink metadata must survive reconstruction without
    // changing the target inode. The long target also requires GNU long-link.
    tar.append_link(&mut hardlink, "alias", &long_name)?;
    let mut symlink = header(tar::EntryType::Symlink, 0o777);
    tar.append_link(&mut symlink, "symlink", &long_name)?;
    tar.append_data(
        &mut header(tar::EntryType::Fifo, 0o620),
        "fifo",
        std::io::empty(),
    )?;
    let mut device = header(tar::EntryType::Char, 0o600);
    device.set_device_major(1)?;
    device.set_device_minor(3)?;
    tar.append_data(&mut device, "device", std::io::empty())?;
    append_byte_paths(&mut tar, &payload)?;
    Ok((tar.into_inner()?, long_name, payload))
}

fn append_byte_paths(tar: &mut tar::Builder<Vec<u8>>, payload: &[u8]) -> Result<()> {
    let path = OsStr::from_bytes(BYTE_PATH);
    let mut regular = header(tar::EntryType::Regular, 0o640);
    regular.set_size(payload.len() as u64);
    tar.append_data(&mut regular, path, payload)?;
    tar.append_link(
        &mut header(tar::EntryType::Link, 0o640),
        OsStr::from_bytes(b"alias-\xfd"),
        path,
    )?;
    tar.append_link(
        &mut header(tar::EntryType::Symlink, 0o777),
        OsStr::from_bytes(b"symlink-\xfc"),
        path,
    )?;
    Ok(())
}

fn check_byte_paths(diff: &Path, payload: &[u8]) -> Result<()> {
    let path = OsStr::from_bytes(BYTE_PATH);
    assert_eq!(std::fs::read(diff.join(path))?, payload);
    let target = std::fs::metadata(diff.join(path))?;
    let alias = std::fs::metadata(diff.join(OsStr::from_bytes(b"alias-\xfd")))?;
    assert_eq!((alias.dev(), alias.ino()), (target.dev(), target.ino()));
    assert_eq!(
        std::fs::read_link(diff.join(OsStr::from_bytes(b"symlink-\xfc")))?,
        Path::new(path)
    );
    Ok(())
}

fn privileged_storage_export_complex_tar() -> Result<()> {
    if require_privileged("privileged_storage_export_complex_tar")?.is_some() {
        return Ok(());
    }
    let sh = Shell::new()?;
    let temp = tempfile::tempdir()?;
    let verity = VerityTempDir::new()?;
    let repo_path = verity.path().join("source");
    let (repo, _) = Repository::<Sha512HashValue>::init_path(
        rustix::fs::CWD,
        &repo_path,
        RepositoryConfig::new(Sha512HashValue::ALGORITHM),
    )?;
    let repo = Arc::new(repo);
    let (tar, long_name, payload) = complex_tar()?;
    let digest = tokio::runtime::Runtime::new()?.block_on(store_image(&repo, &[&tar]))?;
    let graph = verity.path().join("graph");
    let _mount = OverlayMountCleanup(&graph);
    let run = temp.path().join("run");
    let image_id = copy_to_storage(&repo_path, &graph, &run, &format!("@{digest}"), &[])?;
    let layer = top_layer(&graph, &image_id)?;
    let diff = graph.join("overlay").join(layer).join("diff");
    check_byte_paths(&diff, &payload)?;
    assert!(!diff.join("global").exists());
    assert!(!diff.join("nope").exists());
    assert_eq!(std::fs::read(diff.join(&long_name))?, payload);
    let target = std::fs::metadata(diff.join(&long_name))?;
    let alias = std::fs::metadata(diff.join("alias"))?;
    assert!(target.is_file());
    assert_eq!((alias.dev(), alias.ino()), (target.dev(), target.ino()));
    for metadata in [&target, &alias] {
        assert_eq!(
            (
                metadata.mode() & 0o7777,
                metadata.uid(),
                metadata.gid(),
                metadata.mtime(),
                metadata.mtime_nsec(),
            ),
            (0o640, 123, 456, MTIME_SECONDS as i64, MTIME_NANOS)
        );
    }
    for path in [&long_name, "alias"] {
        let mut value = [0; 32];
        let n = rustix::fs::lgetxattr(diff.join(path), "user.fixture", &mut value)?;
        assert_eq!(&value[..n], b"pax-value");
    }
    assert_eq!(
        std::fs::read_link(diff.join("symlink"))?,
        std::path::Path::new(&long_name)
    );
    for (path, mode) in [("symlink", 0o777), ("fifo", 0o620), ("device", 0o600)] {
        let metadata = std::fs::symlink_metadata(diff.join(path))?;
        assert_eq!(
            (
                metadata.mode() & 0o7777,
                metadata.uid(),
                metadata.gid(),
                metadata.mtime(),
                metadata.mtime_nsec(),
            ),
            (mode, 123, 456, MTIME_SECONDS as i64, 0),
            "{path}"
        );
    }
    assert!(
        std::fs::symlink_metadata(diff.join("fifo"))?
            .file_type()
            .is_fifo()
    );
    let device = std::fs::symlink_metadata(diff.join("device"))?;
    assert!(device.file_type().is_char_device());
    assert_eq!(device.rdev(), rustix::fs::makedev(1, 3));

    // Go's tar-split reader, rather than the Rust reconstruction helper, is
    // the oracle for all header encodings, payload checksums and padding.
    let source = format!(
        "containers-storage:[overlay@{}+{}]@{}",
        graph.display(),
        run.display(),
        image_id
    );
    let output = temp.path().join("oci");
    let destination = format!("oci:{}:test", output.display());
    cmd!(sh, "skopeo copy --preserve-digests {source} {destination}").run()?;
    let diff_id = composefs_oci::sha256_content_digest(&tar);
    assert_eq!(
        std::fs::read(output.join("blobs/sha256").join(diff_id.digest()))?,
        tar
    );
    Ok(())
}
integration_test!(privileged_storage_export_complex_tar);
