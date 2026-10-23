use super::*;
use composefs::{
    erofs::{
        format::FormatVersion,
        writer::{ValidatedFileSystem, mkfs_erofs_versioned},
    },
    fsverity::{FsVerityHashValue, Sha256HashValue},
    tree::{Directory, FileSystem, Inode, LeafContent, RegularFile, Stat},
};

const VERSIONS: [FormatVersion; 3] = [FormatVersion::V0, FormatVersion::V1, FormatVersion::V2];
const ROOT: INodeNo = INodeNo(1);

fn stat() -> Stat {
    Stat {
        st_mode: 0o754,
        st_uid: 123,
        st_gid: 456,
        st_mtim_sec: 42,
        st_mtim_nsec: 0,
        xattrs: Default::default(),
    }
}

fn fixture(version: FormatVersion, many: bool) -> ComposefsFuse {
    let mut fs = FileSystem::<Sha256HashValue>::new(stat());
    fs.root
        .stat
        .xattrs
        .insert(OsStr::new("user.root").into(), Box::new([]));
    let mut file_stat = stat();
    for (name, value) in [
        ("user.test", "value"),
        ("trusted.overlay.test", "escaped"),
        ("security.test", "label"),
    ] {
        file_stat
            .xattrs
            .insert(OsStr::new(name).into(), value.as_bytes().into());
    }
    let file = fs.push_leaf(
        file_stat.clone(),
        LeafContent::Regular(RegularFile::Inline(b"abcdef".to_vec().into())),
    );
    fs.root.insert(OsStr::new("file"), Inode::leaf(file));
    fs.root.insert(OsStr::new("hardlink"), Inode::leaf(file));
    let shared = fs.push_leaf(
        file_stat,
        LeafContent::Regular(RegularFile::Inline(b"shared".to_vec().into())),
    );
    fs.root.insert(OsStr::new("shared"), Inode::leaf(shared));
    fs.root.insert(
        OsStr::new("emptydir"),
        Inode::Directory(Box::new(Directory::new(stat()))),
    );
    let mut subdir = Directory::new(stat());
    subdir.insert(OsStr::new("nested"), Inode::leaf(file));
    fs.root
        .insert(OsStr::new("subdir"), Inode::Directory(Box::new(subdir)));
    for (name, content) in [
        (
            "link",
            LeafContent::Symlink(OsStr::from_bytes(b"file\xff").into()),
        ),
        ("whiteout", LeafContent::CharacterDevice(0)),
        ("char", LeafContent::CharacterDevice(123)),
        ("block", LeafContent::BlockDevice(456)),
        ("fifo", LeafContent::Fifo),
        ("socket", LeafContent::Socket),
        (
            "empty",
            LeafContent::Regular(RegularFile::Inline(Box::new([]))),
        ),
        (
            "external",
            LeafContent::Regular(RegularFile::External(Sha256HashValue::EMPTY, 8192)),
        ),
        ("sparse", LeafContent::Regular(RegularFile::Sparse(8192))),
        (
            "tail",
            LeafContent::Regular(RegularFile::Inline(vec![b't'; 4097].into())),
        ),
    ] {
        let id = fs.push_leaf(stat(), content);
        fs.root.insert(OsStr::new(name), Inode::leaf(id));
    }
    if many {
        for i in 0..300 {
            fs.root
                .insert(OsStr::new(&format!("entry-{i:03}")), Inode::leaf(file));
        }
    }
    let bytes = mkfs_erofs_versioned(&ValidatedFileSystem::new(fs).unwrap(), version);
    ComposefsFuse {
        image: Image::open(Vec::leak(bytes.into())).unwrap(),
        objects_fd: Arc::new(open("/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap()),
        overlay_xattr: None,
        handles: Mutex::new(FuseHandles::default()),
    }
}

fn attr(fs: &ComposefsFuse, name: &str) -> FileAttr {
    fs.lookup_attr(ROOT, OsStr::new(name)).unwrap()
}

#[test]
fn inode_numbers_and_types() {
    for root in [Nid(0), Nid(1), Nid(37)] {
        assert_eq!(Nid::from_fuse_ino(INodeNo(0), root), None);
        for nid in [Nid(0), Nid(1), Nid(37), Nid(100)] {
            let ino = nid.to_fuse_ino(root);
            assert_eq!(ino, INodeNo(if nid == root { 1 } else { nid.0 + 2 }));
            assert_eq!(Nid::from_fuse_ino(ino, root), Some(nid));
        }
    }
    for (mode, kind) in [
        (S_IFREG, FileType::RegularFile),
        (S_IFDIR, FileType::Directory),
        (S_IFCHR, FileType::CharDevice),
        (S_IFBLK, FileType::BlockDevice),
        (S_IFIFO, FileType::NamedPipe),
        (S_IFLNK, FileType::Symlink),
        (S_IFSOCK, FileType::Socket),
        (0, FileType::RegularFile),
    ] {
        assert_eq!(mode_to_filetype(mode | 0o754), kind);
    }
}

#[test]
fn lookup_attributes_and_readlink() {
    for version in VERSIONS {
        let fs = fixture(version, false);
        let file = attr(&fs, "file");
        assert_eq!(file, attr(&fs, "hardlink"));
        let subdir = attr(&fs, "subdir");
        assert_eq!(
            fs.lookup_attr(subdir.ino, OsStr::new("nested")).unwrap(),
            file
        );
        for (name, kind, size, rdev) in [
            ("file", FileType::RegularFile, 6, 0),
            ("link", FileType::Symlink, 5, 0),
            ("emptydir", FileType::Directory, 0, 0),
            ("char", FileType::CharDevice, 0, 123),
            ("block", FileType::BlockDevice, 0, 456),
            ("fifo", FileType::NamedPipe, 0, 0),
            ("socket", FileType::Socket, 0, 0),
        ] {
            let a = attr(&fs, name);
            assert_eq!(
                (a.kind, a.size, a.rdev, a.perm, a.uid, a.gid),
                (kind, size, rdev, 0o754, 123, 456)
            );
            assert_eq!((a.blocks, a.blksize, a.flags), (1, 4096, 0));
            assert_eq!((a.atime, a.ctime, a.crtime), (a.mtime, a.mtime, a.mtime));
            assert_eq!(a.mtime, SystemTime::UNIX_EPOCH + Duration::from_secs(42));
            assert_eq!(fs.get_fileattr(a.ino).unwrap(), a);
        }
        assert_eq!(file.nlink, 3);
        fs.readlink_data(attr(&fs, "link").ino, |r| {
            assert_eq!(r, Ok(b"file\xff".as_slice()))
        });
        // readlink intentionally accepts any inode with inline data.
        fs.readlink_data(file.ino, |r| assert_eq!(r, Ok(b"abcdef".as_slice())));
        fs.readlink_data(attr(&fs, "empty").ino, |r| {
            assert_eq!(r, Err(fuser::Errno::EINVAL))
        });
        for name in ["missing", ".", "..", "whiteout", "subdir/nested"] {
            assert_eq!(
                fs.lookup_attr(ROOT, OsStr::new(name)),
                Err(fuser::Errno::ENOENT)
            );
        }
    }
}

#[test]
fn invalid_inode_errnos() {
    let fs = fixture(FormatVersion::V2, false);
    for (ino, lookup, getattr, readlink) in [
        (
            INodeNo(0),
            fuser::Errno::EINVAL,
            fuser::Errno::EINVAL,
            fuser::Errno::EINVAL,
        ),
        (
            INodeNo(u64::MAX),
            fuser::Errno::EBADF,
            fuser::Errno::EIO,
            fuser::Errno::EINVAL,
        ),
    ] {
        assert_eq!(fs.lookup_attr(ino, OsStr::new("file")), Err(lookup));
        assert_eq!(fs.get_fileattr(ino), Err(getattr));
        fs.readlink_data(ino, |r| assert_eq!(r, Err(readlink)));
        assert_eq!(
            fs.read_dir(ino, 0, |_, _, _, _| panic!("unexpected entry")),
            Err(lookup)
        );
        assert_eq!(
            fs.read_dir_plus(ino, 0, |_, _, _, _| panic!("unexpected entry")),
            Err(lookup)
        );
        assert_eq!(fs.get_xattr(ino, OsStr::new("user.test"), 0), Err(lookup));
        assert_eq!(fs.list_xattrs(ino, 0), Err(lookup));
        assert_eq!(fs.open_handle(ino), Err(lookup));
    }
}

type Entry = (INodeNo, u64, FileType, Vec<u8>);

fn directory(
    fs: &ComposefsFuse,
    ino: INodeNo,
    offset: u64,
    capacity: usize,
    plus: bool,
) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut full = false;
    let mut add = |ino, offset, kind, name: &OsStr| {
        assert!(!full, "traversal continued after full buffer");
        full = entries.len() == capacity;
        if !full {
            entries.push((ino, offset, kind, name.as_bytes().to_vec()));
        }
        full
    };
    if plus {
        fs.read_dir_plus(ino, offset, |child, cookie, name, attrs| {
            assert_eq!(*attrs, fs.get_fileattr(child).unwrap());
            add(child, cookie, attrs.kind, name)
        })
        .unwrap();
    } else {
        fs.read_dir(ino, offset, &mut add).unwrap();
    }
    entries
}

#[test]
fn directory_offsets_and_full_buffers() {
    for version in VERSIONS {
        for many in [false, true] {
            let fs = fixture(version, many);
            if many {
                let inode = fs.get_inode(fs.root_nid()).unwrap();
                assert!(!fs.image.inode_blocks(&inode).unwrap().is_empty());
            }
            for plus in [false, true] {
                for ino in [ROOT, attr(&fs, "emptydir").ino, attr(&fs, "subdir").ino] {
                    let all = directory(&fs, ino, 0, usize::MAX, plus);
                    assert_eq!(all[0], (ino, 1, FileType::Directory, b".".to_vec()));
                    // Existing behavior uses the current inode for '..', even in subdirectories.
                    assert_eq!(all[1], (ino, 2, FileType::Directory, b"..".to_vec()));
                    let mut expected = if ino == ROOT {
                        vec![
                            "block", "char", "empty", "emptydir", "external", "fifo", "file",
                            "hardlink", "link", "shared", "socket", "sparse", "subdir", "tail",
                        ]
                        .into_iter()
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                    } else if ino == attr(&fs, "subdir").ino {
                        vec!["nested".into()]
                    } else {
                        vec![]
                    };
                    if ino == ROOT && many {
                        expected.extend((0..300).map(|i| format!("entry-{i:03}")));
                    }
                    expected.sort();
                    // Inline tails precede blocks; compare membership without imposing sorted traversal.
                    let mut names = all[2..].iter().map(|e| e.3.clone()).collect::<Vec<_>>();
                    names.sort();
                    assert_eq!(
                        names,
                        expected
                            .iter()
                            .map(|n| n.as_bytes().to_vec())
                            .collect::<Vec<_>>()
                    );
                    for e in &all[2..] {
                        let a = fs.lookup_attr(ino, OsStr::from_bytes(&e.3)).unwrap();
                        assert_eq!((e.0, e.2), (a.ino, a.kind));
                    }
                    for (i, e) in all.iter().enumerate() {
                        assert_eq!(e.1, i as u64 + 1);
                    }
                    for offset in 0..=all.len() + 1 {
                        let suffix = &all[offset.min(all.len())..];
                        assert_eq!(directory(&fs, ino, offset as u64, usize::MAX, plus), suffix);
                        for capacity in [0, 1, 2, 4] {
                            assert_eq!(
                                directory(&fs, ino, offset as u64, capacity, plus),
                                &suffix[..capacity.min(suffix.len())]
                            );
                        }
                    }
                    let mut resumed = Vec::new();
                    loop {
                        let page =
                            directory(&fs, ino, resumed.last().map_or(0, |e: &Entry| e.1), 2, plus);
                        if page.is_empty() {
                            break;
                        }
                        resumed.extend(page);
                    }
                    assert_eq!(resumed, all);
                }
            }
        }
    }
}

#[test]
fn xattr_names_values_and_sizes() {
    for version in VERSIONS {
        let mut fs = fixture(version, false);
        for mode in [
            None,
            Some(OverlayXattrMode::User),
            Some(OverlayXattrMode::Trusted),
        ] {
            fs.overlay_xattr = mode;
            assert_eq!(
                fs.get_xattr(ROOT, OsStr::new("user.root"), 0),
                Ok(XattrReply::Size(0))
            );
            assert_eq!(
                fs.get_xattr(ROOT, OsStr::new("user.root"), 1),
                Ok(XattrReply::Data(vec![]))
            );
            for name in ["file", "shared"] {
                let ino = attr(&fs, name).ino;
                let overlay = match mode {
                    None => "trusted.overlay.test",
                    Some(OverlayXattrMode::User) => "user.overlay.overlay.test",
                    Some(OverlayXattrMode::Trusted) => "trusted.overlay.overlay.test",
                };
                let mut names = ["security.test", "user.test", overlay];
                names.sort();
                let XattrReply::Data(list) = fs.list_xattrs(ino, u32::MAX).unwrap() else {
                    panic!("expected data")
                };
                let mut actual = list
                    .split(|b| *b == 0)
                    .filter(|n| !n.is_empty())
                    .collect::<Vec<_>>();
                actual.sort();
                assert_eq!(
                    actual,
                    names.iter().map(|n| n.as_bytes()).collect::<Vec<_>>()
                );
                assert_eq!(list.last(), Some(&0));
                assert_eq!(list.len(), names.iter().map(|n| n.len() + 1).sum::<usize>());
                assert_eq!(
                    fs.list_xattrs(ino, 0),
                    Ok(XattrReply::Size(list.len() as u32))
                );
                assert_eq!(
                    fs.list_xattrs(ino, list.len() as u32 - 1),
                    Err(fuser::Errno::ERANGE)
                );
                assert_eq!(
                    fs.list_xattrs(ino, list.len() as u32),
                    Ok(XattrReply::Data(list))
                );
                for (key, value) in [
                    ("user.test", b"value".as_slice()),
                    ("security.test", b"label"),
                    (overlay, b"escaped"),
                ] {
                    for size in [0, value.len() as u32 - 1, value.len() as u32, u32::MAX] {
                        let expected = if size == 0 {
                            Ok(XattrReply::Size(value.len() as u32))
                        } else if size < value.len() as u32 {
                            Err(fuser::Errno::ERANGE)
                        } else {
                            Ok(XattrReply::Data(value.to_vec()))
                        };
                        assert_eq!(fs.get_xattr(ino, OsStr::new(key), size), expected);
                    }
                }
                assert_eq!(
                    fs.get_xattr(ino, OsStr::new("missing"), 0),
                    Err(fuser::Errno::ENODATA)
                );
            }
            let empty = attr(&fs, "emptydir").ino;
            assert_eq!(fs.list_xattrs(empty, 0), Ok(XattrReply::Size(0)));
            assert_eq!(fs.list_xattrs(empty, 1), Ok(XattrReply::Data(vec![])));
        }
    }
}

#[test]
fn open_read_release_content_selection() {
    for version in VERSIONS {
        let mut fs = fixture(version, false);
        for mode in [
            None,
            Some(OverlayXattrMode::User),
            Some(OverlayXattrMode::Trusted),
        ] {
            fs.overlay_xattr = mode;
            for (name, data) in [
                ("file", b"abcdef".as_slice()),
                ("link", b"file\xff"),
                ("tail", b"t"),
            ] {
                let ino = attr(&fs, name).ino;
                let first = fs.open_handle(ino).unwrap();
                let second = fs.open_handle(ino).unwrap();
                assert_eq!(second.0, first.0 + 1);
                for (offset, size, expected) in
                    [(0, 0, b"".as_slice()), (0, 99, data), (999, 99, b"")]
                {
                    fs.read_handle(first, offset, size, |r| assert_eq!(r, Ok(expected)));
                }
                if name == "file" {
                    for (offset, size, expected) in
                        [(2, 2, b"cd".as_slice()), (5, 99, b"f"), (6, 1, b"")]
                    {
                        fs.read_handle(first, offset, size, |r| assert_eq!(r, Ok(expected)));
                    }
                }
                assert_eq!(fs.release_handle(first), Ok(()));
                fs.read_handle(first, 0, 1, |r| assert_eq!(r, Err(fuser::Errno::EBADF)));
                assert_eq!(fs.release_handle(first), Err(fuser::Errno::EBADF));
                fs.read_handle(second, 0, 99, |r| assert_eq!(r, Ok(data)));
                assert_eq!(fs.release_handle(second), Ok(()));
            }
            for name in ["empty", "external", "sparse", "fifo"] {
                let ino = attr(&fs, name).ino;
                assert_eq!(
                    fs.open_handle(ino),
                    Err(if mode.is_some() {
                        fuser::Errno::EOPNOTSUPP
                    } else {
                        fuser::Errno::EIO
                    })
                );
            }
        }
        assert!(fs.handles.lock().unwrap().handles.is_empty());
        fs.read_handle(FileHandle(u64::MAX), 0, 1, |r| {
            assert_eq!(r, Err(fuser::Errno::EBADF))
        });
        assert_eq!(
            fs.release_handle(FileHandle(u64::MAX)),
            Err(fuser::Errno::EBADF)
        );
    }
}

#[test]
fn redirected_objects_and_fd_errors() {
    let mut fs = fixture(FormatVersion::V2, false);
    let tmp = tempfile::tempdir().unwrap();
    fs.objects_fd = Arc::new(
        open(
            tmp.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap(),
    );
    let ino = attr(&fs, "external").ino;
    let inode = fs
        .get_inode(Nid::from_fuse_ino(ino, fs.root_nid()).unwrap())
        .unwrap();
    assert_eq!(inode.data_layout().unwrap(), DataLayout::ChunkBased);
    let redirect = find_raw_xattr(&fs.image, &inode, format::XATTR_OVERLAY_REDIRECT).unwrap();
    let path = tmp.path().join(OsStr::from_bytes(
        redirect.strip_prefix(b"/").unwrap_or(&redirect),
    ));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"object contents").unwrap();
    let fh = fs.open_handle(ino).unwrap();
    assert!(matches!(
        fs.handles.lock().unwrap().handles.get(&fh.0),
        Some(OpenHandle::Fd(_))
    ));
    for (offset, size, data) in [
        (0, 99, b"object contents".as_slice()),
        (7, 3, b"con"),
        (99, 1, b""),
    ] {
        fs.read_handle(fh, offset, size, |r| assert_eq!(r, Ok(data)));
    }
    assert_eq!(fs.release_handle(fh), Ok(()));
    std::fs::remove_file(&path).unwrap();
    assert_eq!(fs.open_handle(ino), Err(fuser::Errno::EIO));
    std::os::unix::fs::symlink("/dev/null", &path).unwrap();
    assert_eq!(fs.open_handle(ino), Err(fuser::Errno::EIO));
    let bad = FileHandle(999);
    fs.handles.lock().unwrap().handles.insert(
        bad.0,
        OpenHandle::Fd(
            open(
                tmp.path(),
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap(),
        ),
    );
    fs.read_handle(bad, 0, 1, |r| assert_eq!(r, Err(fuser::Errno::EISDIR)));
    assert_eq!(fs.release_handle(bad), Ok(()));
}

#[test]
fn overlay_whiteout_visibility() {
    for version in VERSIONS {
        let mut fs = fixture(version, false);
        assert_eq!(
            fs.lookup_attr(ROOT, OsStr::new("whiteout")),
            Err(fuser::Errno::ENOENT)
        );
        for mode in [OverlayXattrMode::User, OverlayXattrMode::Trusted] {
            fs.overlay_xattr = Some(mode);
            let a = attr(&fs, "whiteout");
            let inode = fs
                .get_inode(Nid::from_fuse_ino(a.ino, fs.root_nid()).unwrap())
                .unwrap();
            assert!(is_overlayfs_whiteout(&fs.image, &inode));
            assert!(!fs.is_hidden(Nid::from_fuse_ino(a.ino, fs.root_nid()).unwrap()));
            assert_eq!((a.size, a.rdev), (0, 0));
            assert_eq!(
                a.kind,
                if is_whiteout(&fs.image, &inode) {
                    FileType::RegularFile
                } else {
                    FileType::CharDevice
                }
            );
            for plus in [false, true] {
                let entries = directory(&fs, ROOT, 0, usize::MAX, plus);
                assert!(entries.iter().any(|e| e.3 == b"whiteout"));
            }
        }
    }
}
