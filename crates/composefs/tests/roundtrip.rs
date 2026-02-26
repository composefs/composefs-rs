//! Round-trip tests verifying dump→mkfs→dump reproducibility.
//!
//! These tests verify that filesystem structures can be written to an EROFS
//! image and read back with equivalent content. This is similar to the C
//! composefs `test-checksums.sh` which tests the full pipeline.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    rc::Rc,
};

use composefs::{
    dumpfile::dumpfile_to_filesystem,
    erofs::{
        format::{self, FormatVersion, XATTR_PREFIXES},
        reader::{DirectoryBlock, Image, InodeHeader, InodeOps},
        writer::mkfs_erofs,
    },
    fsverity::{FsVerityHashValue, Sha256HashValue},
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
};
use zerocopy::FromBytes;

/// Helper to create a default Stat
fn default_stat() -> Stat {
    Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 0,
        xattrs: RefCell::new(BTreeMap::new()),
    }
}

/// Helper to add a leaf inode
fn add_leaf(
    dir: &mut Directory<Sha256HashValue>,
    name: &OsStr,
    content: LeafContent<Sha256HashValue>,
) {
    dir.insert(
        name,
        Inode::Leaf(Rc::new(Leaf {
            content,
            stat: default_stat(),
        })),
    );
}

/// Helper to add a leaf with custom stat
fn add_leaf_with_stat(
    dir: &mut Directory<Sha256HashValue>,
    name: &OsStr,
    content: LeafContent<Sha256HashValue>,
    stat: Stat,
) {
    dir.insert(name, Inode::Leaf(Rc::new(Leaf { content, stat })));
}

/// Helper to add an empty subdirectory
fn add_subdir(dir: &mut Directory<Sha256HashValue>, name: &OsStr) {
    dir.insert(
        name,
        Inode::Directory(Box::new(Directory::new(default_stat()))),
    );
}

fn mkfs_erofs_default(fs: &FileSystem<Sha256HashValue>) -> Box<[u8]> {
    mkfs_erofs(fs, FormatVersion::default())
}

// ============================================================================
// Filesystem reconstruction from EROFS image
// ============================================================================

/// Reconstructed entry from reading an EROFS image
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconstructedEntry {
    name: OsString,
    is_dir: bool,
    mode_permissions: u16, // Just the permission bits (lower 12 bits)
    size: u64,
    inline_data: Option<Vec<u8>>,
    xattrs: Vec<(String, Vec<u8>)>, // (full name, value)
}

/// Gets the inode number from a directory entry header
fn entry_nid(entry: &composefs::erofs::reader::DirectoryEntry<'_>) -> u64 {
    entry.header.inode_offset.get()
}

/// Collects directory entries from an EROFS image starting at the given inode
fn collect_entries(img: &Image, nid: u64) -> Vec<ReconstructedEntry> {
    let inode = img.inode(nid);
    let mut entries = Vec::new();

    // Collect from inline directory data
    if let Some(inline) = inode.inline() {
        if inode.mode().is_dir() {
            if let Ok(inline_block) = DirectoryBlock::ref_from_bytes(inline) {
                for entry in inline_block.entries() {
                    if entry.name != b"." && entry.name != b".." {
                        entries.push(reconstruct_entry(img, entry.name, entry_nid(&entry)));
                    }
                }
            }
        }
    }

    // Collect from directory blocks
    for blkid in inode.blocks(img.blkszbits) {
        let block = img.directory_block(blkid);
        for entry in block.entries() {
            if entry.name != b"." && entry.name != b".." {
                entries.push(reconstruct_entry(img, entry.name, entry_nid(&entry)));
            }
        }
    }

    // Sort by name for consistent comparison
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

/// Reconstructs an entry from an inode
fn reconstruct_entry(img: &Image, name: &[u8], nid: u64) -> ReconstructedEntry {
    let inode = img.inode(nid);
    let mode = inode.mode().0.get();
    let is_dir = inode.mode().is_dir();
    let size = inode.size();

    // Get inline data for non-directories
    let inline_data = if !is_dir {
        inode.inline().map(|d| d.to_vec())
    } else {
        None
    };

    // Collect xattrs
    let mut xattrs = Vec::new();
    if let Some(inode_xattrs) = inode.xattrs() {
        // Shared xattrs
        for id in inode_xattrs.shared() {
            let xattr = img.shared_xattr(id.get());
            let prefix_idx = xattr.header.name_index as usize;
            let prefix: &[u8] = if prefix_idx < XATTR_PREFIXES.len() {
                XATTR_PREFIXES[prefix_idx]
            } else {
                b""
            };
            let full_name = format!(
                "{}{}",
                String::from_utf8_lossy(prefix),
                String::from_utf8_lossy(xattr.suffix())
            );
            xattrs.push((full_name, xattr.value().to_vec()));
        }

        // Local xattrs
        for xattr in inode_xattrs.local() {
            let prefix_idx = xattr.header.name_index as usize;
            let prefix: &[u8] = if prefix_idx < XATTR_PREFIXES.len() {
                XATTR_PREFIXES[prefix_idx]
            } else {
                b""
            };
            let full_name = format!(
                "{}{}",
                String::from_utf8_lossy(prefix),
                String::from_utf8_lossy(xattr.suffix())
            );
            xattrs.push((full_name, xattr.value().to_vec()));
        }
    }
    xattrs.sort_by(|a, b| a.0.cmp(&b.0));

    ReconstructedEntry {
        name: OsStr::from_bytes(name).to_os_string(),
        is_dir,
        mode_permissions: mode & 0o7777,
        size,
        inline_data,
        xattrs,
    }
}

/// Verifies that an entry exists in the image with expected properties
fn verify_entry_exists<'a>(
    entries: &'a [ReconstructedEntry],
    name: &str,
) -> &'a ReconstructedEntry {
    entries
        .iter()
        .find(|e| e.name == OsStr::new(name))
        .unwrap_or_else(|| panic!("Entry '{}' not found in image", name))
}

// ============================================================================
// Test cases
// ============================================================================

/// Test case definition for data-driven testing
struct RoundtripTestCase {
    name: &'static str,
    setup: fn(&mut FileSystem<Sha256HashValue>),
    verify: fn(&Image, &[ReconstructedEntry]),
}

/// Empty filesystem test
fn setup_empty(_fs: &mut FileSystem<Sha256HashValue>) {
    // Nothing to add - empty filesystem
}

fn verify_empty(_img: &Image, entries: &[ReconstructedEntry]) {
    assert!(
        entries.is_empty(),
        "Empty filesystem should have no entries"
    );
}

/// Simple inline file test
fn setup_simple_inline_file(fs: &mut FileSystem<Sha256HashValue>) {
    add_leaf(
        &mut fs.root,
        OsStr::new("hello.txt"),
        LeafContent::Regular(RegularFile::Inline(b"Hello, World!".to_vec().into())),
    );
}

fn verify_simple_inline_file(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "hello.txt");
    assert!(!entry.is_dir);
    assert_eq!(entry.size, 13);
    assert_eq!(entry.inline_data, Some(b"Hello, World!".to_vec()));
}

/// Multiple files test
fn setup_multiple_files(fs: &mut FileSystem<Sha256HashValue>) {
    add_leaf(
        &mut fs.root,
        OsStr::new("file1.txt"),
        LeafContent::Regular(RegularFile::Inline(b"content1".to_vec().into())),
    );
    add_leaf(
        &mut fs.root,
        OsStr::new("file2.txt"),
        LeafContent::Regular(RegularFile::Inline(b"content2".to_vec().into())),
    );
    add_leaf(
        &mut fs.root,
        OsStr::new("file3.txt"),
        LeafContent::Regular(RegularFile::Inline(b"content3".to_vec().into())),
    );
}

fn verify_multiple_files(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 3);
    let e1 = verify_entry_exists(entries, "file1.txt");
    assert_eq!(e1.inline_data, Some(b"content1".to_vec()));
    let e2 = verify_entry_exists(entries, "file2.txt");
    assert_eq!(e2.inline_data, Some(b"content2".to_vec()));
    let e3 = verify_entry_exists(entries, "file3.txt");
    assert_eq!(e3.inline_data, Some(b"content3".to_vec()));
}

/// Directory with entries test
fn setup_directory_with_entries(fs: &mut FileSystem<Sha256HashValue>) {
    add_subdir(&mut fs.root, OsStr::new("subdir"));
    let subdir = fs.root.get_directory_mut(OsStr::new("subdir")).unwrap();
    subdir.insert(
        OsStr::new("nested.txt"),
        Inode::Leaf(Rc::new(Leaf {
            content: LeafContent::Regular(RegularFile::Inline(b"nested content".to_vec().into())),
            stat: default_stat(),
        })),
    );
}

fn verify_directory_with_entries(img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let subdir_entry = verify_entry_exists(entries, "subdir");
    assert!(subdir_entry.is_dir);

    // Find the subdir's nid and verify its contents
    let root_nid = img.sb.root_nid.get() as u64;
    let root_inode = img.inode(root_nid);

    let mut subdir_nid = None;
    if let Some(inline) = root_inode.inline() {
        if let Ok(block) = DirectoryBlock::ref_from_bytes(inline) {
            for entry in block.entries() {
                if entry.name == b"subdir" {
                    subdir_nid = Some(entry_nid(&entry));
                }
            }
        }
    }

    let subdir_nid = subdir_nid.expect("subdir not found");
    let subdir_entries = collect_entries(img, subdir_nid);
    assert_eq!(subdir_entries.len(), 1);
    let nested = verify_entry_exists(&subdir_entries, "nested.txt");
    assert_eq!(nested.inline_data, Some(b"nested content".to_vec()));
}

/// Symlink test
fn setup_symlink(fs: &mut FileSystem<Sha256HashValue>) {
    add_leaf(
        &mut fs.root,
        OsStr::new("link"),
        LeafContent::Symlink(Box::from(OsStr::new("/target/path"))),
    );
}

fn verify_symlink(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "link");
    assert!(!entry.is_dir);
    // Symlink target is stored as inline data
    assert_eq!(entry.inline_data, Some(b"/target/path".to_vec()));
}

/// FIFO test
fn setup_fifo(fs: &mut FileSystem<Sha256HashValue>) {
    add_leaf(&mut fs.root, OsStr::new("myfifo"), LeafContent::Fifo);
}

fn verify_fifo(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "myfifo");
    assert!(!entry.is_dir);
    assert_eq!(entry.size, 0);
}

/// Device files test
fn setup_devices(fs: &mut FileSystem<Sha256HashValue>) {
    add_leaf(
        &mut fs.root,
        OsStr::new("chardev"),
        LeafContent::CharacterDevice(0x0501), // major=5, minor=1 (like /dev/console)
    );
    add_leaf(
        &mut fs.root,
        OsStr::new("blockdev"),
        LeafContent::BlockDevice(0x0801), // major=8, minor=1 (like /dev/sda1)
    );
}

fn verify_devices(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 2);
    let _ = verify_entry_exists(entries, "chardev");
    let _ = verify_entry_exists(entries, "blockdev");
}

/// External file (with fsverity hash) test
fn setup_external_file(fs: &mut FileSystem<Sha256HashValue>) {
    let hash = Sha256HashValue::from_hex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    add_leaf(
        &mut fs.root,
        OsStr::new("external"),
        LeafContent::Regular(RegularFile::External(hash, 4096)),
    );
}

fn verify_external_file(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "external");
    assert!(!entry.is_dir);
    assert_eq!(entry.size, 4096);
    // External files have xattrs for overlay.metacopy and overlay.redirect
    assert!(
        entry
            .xattrs
            .iter()
            .any(|(k, _): &(String, Vec<u8>)| k.contains("metacopy")),
        "External file should have metacopy xattr"
    );
}

/// File with xattrs test
fn setup_file_with_xattrs(fs: &mut FileSystem<Sha256HashValue>) {
    let mut xattrs = BTreeMap::new();
    xattrs.insert(
        Box::from(OsStr::new("user.custom")),
        Box::from(b"custom_value".as_slice()),
    );
    xattrs.insert(
        Box::from(OsStr::new("security.selinux")),
        Box::from(b"system_u:object_r:user_t:s0".as_slice()),
    );

    let stat = Stat {
        st_mode: 0o644,
        st_uid: 1000,
        st_gid: 1000,
        st_mtim_sec: 1234567890,
        xattrs: RefCell::new(xattrs),
    };

    add_leaf_with_stat(
        &mut fs.root,
        OsStr::new("with_xattrs"),
        LeafContent::Regular(RegularFile::Inline(b"data".to_vec().into())),
        stat,
    );
}

fn verify_file_with_xattrs(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "with_xattrs");
    assert!(!entry.is_dir);
    assert_eq!(entry.mode_permissions, 0o644);

    // Verify xattrs are present
    assert!(
        entry
            .xattrs
            .iter()
            .any(|(k, v)| k == "user.custom" && v == b"custom_value"),
        "Should have user.custom xattr"
    );
    assert!(
        entry.xattrs.iter().any(|(k, _)| k == "security.selinux"),
        "Should have security.selinux xattr"
    );
}

/// Hardlinks test
fn setup_hardlinks(fs: &mut FileSystem<Sha256HashValue>) {
    let shared_leaf = Rc::new(Leaf {
        content: LeafContent::Regular(RegularFile::Inline(b"shared content".to_vec().into())),
        stat: default_stat(),
    });

    fs.root
        .insert(OsStr::new("file1"), Inode::Leaf(Rc::clone(&shared_leaf)));
    fs.root
        .insert(OsStr::new("file2"), Inode::Leaf(Rc::clone(&shared_leaf)));
    fs.root
        .insert(OsStr::new("file3"), Inode::Leaf(shared_leaf));
}

fn verify_hardlinks(img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 3);

    // All three should have the same content
    let e1 = verify_entry_exists(entries, "file1");
    let e2 = verify_entry_exists(entries, "file2");
    let e3 = verify_entry_exists(entries, "file3");

    assert_eq!(e1.inline_data, Some(b"shared content".to_vec()));
    assert_eq!(e2.inline_data, Some(b"shared content".to_vec()));
    assert_eq!(e3.inline_data, Some(b"shared content".to_vec()));

    // Verify they point to the same inode in the image
    let root_nid = img.sb.root_nid.get() as u64;
    let root_inode = img.inode(root_nid);

    let mut nids = Vec::new();
    if let Some(inline) = root_inode.inline() {
        if let Ok(block) = DirectoryBlock::ref_from_bytes(inline) {
            for entry in block.entries() {
                if entry.name == b"file1" || entry.name == b"file2" || entry.name == b"file3" {
                    nids.push(entry_nid(&entry));
                }
            }
        }
    }
    for blkid in root_inode.blocks(img.blkszbits) {
        let block = img.directory_block(blkid);
        for entry in block.entries() {
            if entry.name == b"file1" || entry.name == b"file2" || entry.name == b"file3" {
                nids.push(entry_nid(&entry));
            }
        }
    }

    // All hardlinks should point to the same nid
    assert_eq!(nids.len(), 3);
    assert!(
        nids.iter().all(|&n| n == nids[0]),
        "Hardlinks should point to same inode"
    );
}

/// Deep nested directories test
fn setup_deep_nesting(fs: &mut FileSystem<Sha256HashValue>) {
    add_subdir(&mut fs.root, OsStr::new("a"));
    let a = fs.root.get_directory_mut(OsStr::new("a")).unwrap();
    a.insert(
        OsStr::new("b"),
        Inode::Directory(Box::new(Directory::new(default_stat()))),
    );
    let b = a.get_directory_mut(OsStr::new("b")).unwrap();
    b.insert(
        OsStr::new("c"),
        Inode::Directory(Box::new(Directory::new(default_stat()))),
    );
    let c = b.get_directory_mut(OsStr::new("c")).unwrap();
    c.insert(
        OsStr::new("deepfile.txt"),
        Inode::Leaf(Rc::new(Leaf {
            content: LeafContent::Regular(RegularFile::Inline(b"deep content".to_vec().into())),
            stat: default_stat(),
        })),
    );
}

fn verify_deep_nesting(img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let a = verify_entry_exists(entries, "a");
    assert!(a.is_dir);

    // Navigate through the nested structure
    let root_nid = img.sb.root_nid.get() as u64;

    // Helper to find a directory entry by name
    let find_entry_nid = |parent_nid: u64, name: &[u8]| -> Option<u64> {
        let inode = img.inode(parent_nid);
        if let Some(inline) = inode.inline() {
            if let Ok(block) = DirectoryBlock::ref_from_bytes(inline) {
                for entry in block.entries() {
                    if entry.name == name {
                        return Some(entry_nid(&entry));
                    }
                }
            }
        }
        for blkid in inode.blocks(img.blkszbits) {
            let block = img.directory_block(blkid);
            for entry in block.entries() {
                if entry.name == name {
                    return Some(entry_nid(&entry));
                }
            }
        }
        None
    };

    let a_nid = find_entry_nid(root_nid, b"a").expect("a not found");
    let b_nid = find_entry_nid(a_nid, b"b").expect("b not found");
    let c_nid = find_entry_nid(b_nid, b"c").expect("c not found");
    let c_entries = collect_entries(img, c_nid);
    assert_eq!(c_entries.len(), 1);
    let deepfile = verify_entry_exists(&c_entries, "deepfile.txt");
    assert_eq!(deepfile.inline_data, Some(b"deep content".to_vec()));
}

/// Large directory (many entries) test
fn setup_large_directory(fs: &mut FileSystem<Sha256HashValue>) {
    // Add enough entries to span multiple directory blocks
    for i in 0..100 {
        let name = format!("file{:03}", i);
        add_leaf(
            &mut fs.root,
            OsStr::new(&name),
            LeafContent::Regular(RegularFile::Inline(
                format!("content{}", i).into_bytes().into(),
            )),
        );
    }
}

fn verify_large_directory(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 100);
    for i in 0..100 {
        let name = format!("file{:03}", i);
        let entry = verify_entry_exists(entries, &name);
        assert!(!entry.is_dir);
        assert_eq!(
            entry.inline_data,
            Some(format!("content{}", i).into_bytes())
        );
    }
}

/// Empty file test
fn setup_empty_file(fs: &mut FileSystem<Sha256HashValue>) {
    add_leaf(
        &mut fs.root,
        OsStr::new("empty"),
        LeafContent::Regular(RegularFile::Inline(Box::new([]))),
    );
}

fn verify_empty_file(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "empty");
    assert!(!entry.is_dir);
    assert_eq!(entry.size, 0);
    // Empty inline files may have None or Some([]) for inline_data
}

/// Mixed content test
fn setup_mixed_content(fs: &mut FileSystem<Sha256HashValue>) {
    // Regular inline file
    add_leaf(
        &mut fs.root,
        OsStr::new("inline.txt"),
        LeafContent::Regular(RegularFile::Inline(b"inline".to_vec().into())),
    );

    // Symlink
    add_leaf(
        &mut fs.root,
        OsStr::new("link"),
        LeafContent::Symlink(Box::from(OsStr::new("target"))),
    );

    // FIFO
    add_leaf(&mut fs.root, OsStr::new("fifo"), LeafContent::Fifo);

    // Subdirectory with content
    add_subdir(&mut fs.root, OsStr::new("subdir"));
    let subdir = fs.root.get_directory_mut(OsStr::new("subdir")).unwrap();
    subdir.insert(
        OsStr::new("nested"),
        Inode::Leaf(Rc::new(Leaf {
            content: LeafContent::Regular(RegularFile::Inline(b"nested".to_vec().into())),
            stat: default_stat(),
        })),
    );
}

fn verify_mixed_content(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 4);
    let _ = verify_entry_exists(entries, "inline.txt");
    let _ = verify_entry_exists(entries, "link");
    let _ = verify_entry_exists(entries, "fifo");
    let subdir = verify_entry_exists(entries, "subdir");
    assert!(subdir.is_dir);
}

// ============================================================================
// Test runner
// ============================================================================

const TEST_CASES: &[RoundtripTestCase] = &[
    RoundtripTestCase {
        name: "empty",
        setup: setup_empty,
        verify: verify_empty,
    },
    RoundtripTestCase {
        name: "simple_inline_file",
        setup: setup_simple_inline_file,
        verify: verify_simple_inline_file,
    },
    RoundtripTestCase {
        name: "multiple_files",
        setup: setup_multiple_files,
        verify: verify_multiple_files,
    },
    RoundtripTestCase {
        name: "directory_with_entries",
        setup: setup_directory_with_entries,
        verify: verify_directory_with_entries,
    },
    RoundtripTestCase {
        name: "symlink",
        setup: setup_symlink,
        verify: verify_symlink,
    },
    RoundtripTestCase {
        name: "fifo",
        setup: setup_fifo,
        verify: verify_fifo,
    },
    RoundtripTestCase {
        name: "devices",
        setup: setup_devices,
        verify: verify_devices,
    },
    RoundtripTestCase {
        name: "external_file",
        setup: setup_external_file,
        verify: verify_external_file,
    },
    RoundtripTestCase {
        name: "file_with_xattrs",
        setup: setup_file_with_xattrs,
        verify: verify_file_with_xattrs,
    },
    RoundtripTestCase {
        name: "hardlinks",
        setup: setup_hardlinks,
        verify: verify_hardlinks,
    },
    RoundtripTestCase {
        name: "deep_nesting",
        setup: setup_deep_nesting,
        verify: verify_deep_nesting,
    },
    RoundtripTestCase {
        name: "large_directory",
        setup: setup_large_directory,
        verify: verify_large_directory,
    },
    RoundtripTestCase {
        name: "empty_file",
        setup: setup_empty_file,
        verify: verify_empty_file,
    },
    RoundtripTestCase {
        name: "mixed_content",
        setup: setup_mixed_content,
        verify: verify_mixed_content,
    },
];

/// Runs all data-driven test cases
#[test]
fn test_roundtrip_all_cases() {
    for case in TEST_CASES {
        println!("Running test case: {}", case.name);

        // Setup filesystem
        let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
        (case.setup)(&mut fs);

        // Generate EROFS image
        let image = mkfs_erofs_default(&fs);

        // Open and read the image
        let img = Image::open(&image);

        // Collect root entries
        let root_nid = img.sb.root_nid.get() as u64;
        let entries = collect_entries(&img, root_nid);

        // Run verification
        (case.verify)(&img, &entries);

        println!("  PASSED: {}", case.name);
    }
}

// ============================================================================
// Individual test functions for better error reporting
// ============================================================================

#[test]
fn test_roundtrip_empty() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_empty(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_empty(&img, &entries);
}

#[test]
fn test_roundtrip_simple_inline_file() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_simple_inline_file(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_simple_inline_file(&img, &entries);
}

#[test]
fn test_roundtrip_multiple_files() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_multiple_files(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_multiple_files(&img, &entries);
}

#[test]
fn test_roundtrip_directory_with_entries() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_directory_with_entries(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_directory_with_entries(&img, &entries);
}

#[test]
fn test_roundtrip_symlink() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_symlink(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_symlink(&img, &entries);
}

#[test]
fn test_roundtrip_fifo() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_fifo(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_fifo(&img, &entries);
}

#[test]
fn test_roundtrip_devices() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_devices(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_devices(&img, &entries);
}

#[test]
fn test_roundtrip_external_file() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_external_file(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_external_file(&img, &entries);
}

#[test]
fn test_roundtrip_file_with_xattrs() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_file_with_xattrs(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_file_with_xattrs(&img, &entries);
}

#[test]
fn test_roundtrip_hardlinks() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_hardlinks(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_hardlinks(&img, &entries);
}

#[test]
fn test_roundtrip_deep_nesting() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_deep_nesting(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_deep_nesting(&img, &entries);
}

#[test]
fn test_roundtrip_large_directory() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_large_directory(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_large_directory(&img, &entries);
}

#[test]
fn test_roundtrip_empty_file() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_empty_file(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_empty_file(&img, &entries);
}

#[test]
fn test_roundtrip_mixed_content() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_mixed_content(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_mixed_content(&img, &entries);
}

// ============================================================================
// Dumpfile roundtrip tests (dump -> parse -> mkfs -> read)
// ============================================================================

/// Tests that a dumpfile can be parsed, converted to mkfs, and read back
#[test]
fn test_dumpfile_roundtrip_simple() {
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/file.txt 5 100644 1 0 0 0 1000.0 - hello -
/subdir 4096 40755 2 0 0 0 1000.0 - - -
/subdir/nested.txt 6 100644 1 0 0 0 1000.0 - world! -
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);

    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);

    assert_eq!(entries.len(), 2);
    let file = verify_entry_exists(&entries, "file.txt");
    assert_eq!(file.inline_data, Some(b"hello".to_vec()));

    let subdir = verify_entry_exists(&entries, "subdir");
    assert!(subdir.is_dir);
}

/// Tests dumpfile roundtrip with various file types
#[test]
fn test_dumpfile_roundtrip_file_types() {
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/regular 10 100644 1 0 0 0 1000.0 - content123 -
/symlink 7 120777 1 0 0 0 1000.0 /target - -
/fifo 0 10644 1 0 0 0 1000.0 - - -
/chardev 0 20644 1 0 0 1281 1000.0 - - -
/blockdev 0 60644 1 0 0 2049 1000.0 - - -
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);

    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);

    assert_eq!(entries.len(), 5);
    verify_entry_exists(&entries, "regular");
    verify_entry_exists(&entries, "symlink");
    verify_entry_exists(&entries, "fifo");
    verify_entry_exists(&entries, "chardev");
    verify_entry_exists(&entries, "blockdev");
}

/// Tests dumpfile roundtrip with hardlinks
#[test]
fn test_dumpfile_roundtrip_hardlinks() {
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/original 11 100644 3 0 0 0 1000.0 - hello_world -
/link1 0 @120000 3 0 0 0 0.0 /original - -
/link2 0 @120000 3 0 0 0 0.0 /original - -
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);

    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);

    assert_eq!(entries.len(), 3);

    // All three should have the same content
    let original = verify_entry_exists(&entries, "original");
    let link1 = verify_entry_exists(&entries, "link1");
    let link2 = verify_entry_exists(&entries, "link2");

    assert_eq!(original.inline_data, Some(b"hello_world".to_vec()));
    assert_eq!(link1.inline_data, Some(b"hello_world".to_vec()));
    assert_eq!(link2.inline_data, Some(b"hello_world".to_vec()));
}

/// Tests dumpfile roundtrip with xattrs
#[test]
fn test_dumpfile_roundtrip_xattrs() {
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/with_xattr 4 100644 1 0 0 0 1000.0 - test - user.custom=value123
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);

    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);

    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(&entries, "with_xattr");

    // Verify xattr is present
    assert!(
        entry
            .xattrs
            .iter()
            .any(|(k, v)| k == "user.custom" && v == b"value123"),
        "Should have user.custom xattr with value 'value123', got: {:?}",
        entry.xattrs
    );
}

// ============================================================================
// Image consistency tests
// ============================================================================

/// Verifies that writing the same filesystem twice produces identical images
#[test]
fn test_deterministic_output() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    add_leaf(
        &mut fs.root,
        OsStr::new("file1"),
        LeafContent::Regular(RegularFile::Inline(b"content1".to_vec().into())),
    );
    add_leaf(
        &mut fs.root,
        OsStr::new("file2"),
        LeafContent::Regular(RegularFile::Inline(b"content2".to_vec().into())),
    );
    add_subdir(&mut fs.root, OsStr::new("dir"));

    let image1 = mkfs_erofs_default(&fs);

    // Build the same filesystem again
    let mut fs2 = FileSystem::<Sha256HashValue>::new(default_stat());
    add_leaf(
        &mut fs2.root,
        OsStr::new("file1"),
        LeafContent::Regular(RegularFile::Inline(b"content1".to_vec().into())),
    );
    add_leaf(
        &mut fs2.root,
        OsStr::new("file2"),
        LeafContent::Regular(RegularFile::Inline(b"content2".to_vec().into())),
    );
    add_subdir(&mut fs2.root, OsStr::new("dir"));

    let image2 = mkfs_erofs_default(&fs2);

    assert_eq!(
        image1, image2,
        "Same filesystem should produce identical images"
    );
}

/// Tests that the image can be opened and basic metadata is correct
#[test]
fn test_image_metadata() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    add_leaf(
        &mut fs.root,
        OsStr::new("test"),
        LeafContent::Regular(RegularFile::Inline(b"test".to_vec().into())),
    );

    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image);

    // Verify basic image properties
    assert_eq!(img.sb.magic.get(), format::MAGIC_V1.get());
    assert_eq!(img.blkszbits, format::BLOCK_BITS);
    assert_eq!(img.block_size, format::BLOCK_SIZE as usize);

    // Verify root inode is a directory
    let root = img.root();
    assert!(root.mode().is_dir());
}
