//! Tests for the streaming tar parser.

use std::io::Cursor;

use crate::EntryType;

use super::*;

/// Helper to create a tar archive using the tar crate.
fn create_tar_with<F>(f: F) -> Vec<u8>
where
    F: FnOnce(&mut tar::Builder<&mut Vec<u8>>),
{
    let mut data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut data);
        f(&mut builder);
        builder.finish().unwrap();
    }
    data
}

/// Helper to append a file to a tar builder.
fn append_file(builder: &mut tar::Builder<&mut Vec<u8>>, path: &str, content: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_uid(1000);
    header.set_gid(1000);
    header.set_mtime(1234567890);
    header.set_size(content.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    builder.append_data(&mut header, path, content).unwrap();
}

// =============================================================================
// Basic parsing tests
// =============================================================================

#[test]
fn test_empty_tar() {
    let data = create_tar_with(|_| {});
    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_single_file() {
    let data = create_tar_with(|b| {
        append_file(b, "hello.txt", b"Hello, World!");
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), b"hello.txt");
    assert_eq!(entry.entry_type, EntryType::Regular);
    assert_eq!(entry.size, 13);
    assert_eq!(entry.mode, 0o644);
    assert_eq!(entry.uid, 1000);
    assert_eq!(entry.gid, 1000);
    assert_eq!(entry.mtime, 1234567890);

    let size = entry.size;
    drop(entry);
    parser.skip_content(size).unwrap();

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_multiple_files() {
    let data = create_tar_with(|b| {
        append_file(b, "file1.txt", b"Content 1");
        append_file(b, "file2.txt", b"Content 2");
        append_file(b, "file3.txt", b"Content 3");
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    for i in 1..=3 {
        let entry = parser.next_entry().unwrap().expect("should have entry");
        assert_eq!(entry.path.as_ref(), format!("file{}.txt", i).as_bytes());
        let size = entry.size;
        drop(entry);
        parser.skip_content(size).unwrap();
    }

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_directory() {
    let data = create_tar_with(|b| {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        b.append_data(&mut header, "mydir/", std::io::empty())
            .unwrap();
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), b"mydir/");
    assert_eq!(entry.entry_type, EntryType::Directory);
    assert!(entry.is_dir());

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_symlink() {
    let data = create_tar_with(|b| {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        b.append_link(&mut header, "link", "target").unwrap();
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), b"link");
    assert_eq!(entry.entry_type, EntryType::Symlink);
    assert!(entry.is_symlink());
    assert_eq!(entry.link_target.as_ref().unwrap().as_ref(), b"target");

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_hardlink() {
    let data = create_tar_with(|b| {
        // First create a regular file
        append_file(b, "original.txt", b"content");

        // Then create a hard link to it
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        b.append_link(&mut header, "hardlink.txt", "original.txt")
            .unwrap();
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    // Skip original file
    let entry1 = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry1.path.as_ref(), b"original.txt");
    let size = entry1.size;
    drop(entry1);
    parser.skip_content(size).unwrap();

    // Check hardlink
    let entry2 = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry2.path.as_ref(), b"hardlink.txt");
    assert_eq!(entry2.entry_type, EntryType::Link);
    assert!(entry2.is_hard_link());
    assert_eq!(
        entry2.link_target.as_ref().unwrap().as_ref(),
        b"original.txt"
    );

    assert!(parser.next_entry().unwrap().is_none());
}

// =============================================================================
// GNU long name/link tests
// =============================================================================

#[test]
fn test_gnu_long_name() {
    // Create a path that exceeds 100 bytes
    let long_path = format!("very/long/path/{}", "x".repeat(120));

    let data = create_tar_with(|b| {
        append_file(b, &long_path, b"content");
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), long_path.as_bytes());
    assert_eq!(entry.entry_type, EntryType::Regular);

    let size = entry.size;
    drop(entry);
    parser.skip_content(size).unwrap();
    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_gnu_long_link() {
    let long_target = "t".repeat(120);

    let data = create_tar_with(|b| {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        b.append_link(&mut header, "link", &long_target).unwrap();
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), b"link");
    assert!(entry.is_symlink());
    assert_eq!(
        entry.link_target.as_ref().unwrap().as_ref(),
        long_target.as_bytes()
    );

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_gnu_long_name_and_link() {
    let long_path = "p".repeat(120);
    let long_target = "t".repeat(120);

    let data = create_tar_with(|b| {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        b.append_link(&mut header, &long_path, &long_target)
            .unwrap();
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), long_path.as_bytes());
    assert_eq!(
        entry.link_target.as_ref().unwrap().as_ref(),
        long_target.as_bytes()
    );

    assert!(parser.next_entry().unwrap().is_none());
}

// =============================================================================
// PAX extension tests
// =============================================================================

#[test]
fn test_pax_long_path() {
    // Use tar crate's PAX builder for paths > 100 bytes
    let long_path = format!("pax/path/{}", "y".repeat(200));

    let data = create_tar_with(|b| {
        let mut header = tar::Header::new_ustar();
        header.set_mode(0o644);
        header.set_size(7);
        header.set_entry_type(tar::EntryType::Regular);
        // This will create a PAX header for the long path
        b.append_data(&mut header, &long_path, b"content".as_slice())
            .unwrap();
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), long_path.as_bytes());

    let size = entry.size;
    drop(entry);
    parser.skip_content(size).unwrap();
    assert!(parser.next_entry().unwrap().is_none());
}

// =============================================================================
// Security limit tests
// =============================================================================

#[test]
fn test_path_too_long() {
    let long_path = "x".repeat(200);

    let data = create_tar_with(|b| {
        append_file(b, &long_path, b"content");
    });

    let limits = Limits {
        max_path_len: 100,
        ..Default::default()
    };
    let mut parser = TarStreamParser::new(Cursor::new(data), limits);

    let err = parser.next_entry().unwrap_err();
    assert!(matches!(
        err,
        StreamError::PathTooLong {
            len: 200,
            limit: 100
        }
    ));
}

#[test]
fn test_gnu_long_too_large() {
    let long_path = "x".repeat(200);

    let data = create_tar_with(|b| {
        append_file(b, &long_path, b"content");
    });

    let limits = Limits {
        max_gnu_long_size: 100,
        ..Default::default()
    };
    let mut parser = TarStreamParser::new(Cursor::new(data), limits);

    let err = parser.next_entry().unwrap_err();
    assert!(matches!(err, StreamError::GnuLongTooLarge { .. }));
}

// =============================================================================
// Cross-checking with tar crate
// =============================================================================

#[test]
fn test_crosscheck_simple() {
    let data = create_tar_with(|b| {
        append_file(b, "file1.txt", b"Hello");
        append_file(b, "file2.txt", b"World");
    });

    // Parse with tar crate
    let mut tar_archive = tar::Archive::new(Cursor::new(data.clone()));
    let tar_entries: Vec<_> = tar_archive.entries().unwrap().collect();

    // Parse with our crate
    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());
    let mut our_entries = Vec::new();
    while let Some(entry) = parser.next_entry().unwrap() {
        let info = (
            entry.path.to_vec(),
            entry.size,
            entry.mode,
            entry.uid,
            entry.gid,
            entry.mtime,
        );
        let size = entry.size;
        drop(entry);
        our_entries.push(info);
        parser.skip_content(size).unwrap();
    }

    assert_eq!(tar_entries.len(), our_entries.len());

    for (tar_entry, our_entry) in tar_entries.into_iter().zip(our_entries.into_iter()) {
        let tar_entry = tar_entry.unwrap();
        let tar_header = tar_entry.header();

        assert_eq!(
            tar_header.path_bytes().as_ref(),
            our_entry.0.as_slice(),
            "path mismatch"
        );
        assert_eq!(tar_header.size().unwrap(), our_entry.1, "size mismatch");
        assert_eq!(tar_header.mode().unwrap(), our_entry.2, "mode mismatch");
        assert_eq!(tar_header.uid().unwrap(), our_entry.3, "uid mismatch");
        assert_eq!(tar_header.gid().unwrap(), our_entry.4, "gid mismatch");
        assert_eq!(tar_header.mtime().unwrap(), our_entry.5, "mtime mismatch");
    }
}

#[test]
fn test_crosscheck_gnu_long_names() {
    let paths = vec![
        "short.txt".to_string(),
        format!("medium/{}", "m".repeat(80)),
        format!("long/{}", "l".repeat(150)),
    ];

    let data = create_tar_with(|b| {
        for path in &paths {
            append_file(b, path, b"content");
        }
    });

    // Parse with tar crate
    let mut tar_archive = tar::Archive::new(Cursor::new(data.clone()));
    let tar_paths: Vec<_> = tar_archive
        .entries()
        .unwrap()
        .map(|e| e.unwrap().path().unwrap().to_path_buf())
        .collect();

    // Parse with our crate
    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());
    let mut our_paths = Vec::new();
    while let Some(entry) = parser.next_entry().unwrap() {
        let path = String::from_utf8_lossy(&entry.path).to_string();
        let size = entry.size;
        drop(entry);
        our_paths.push(path);
        parser.skip_content(size).unwrap();
    }

    assert_eq!(tar_paths.len(), our_paths.len());
    for (tar_path, our_path) in tar_paths.into_iter().zip(our_paths.into_iter()) {
        assert_eq!(tar_path.to_string_lossy(), our_path);
    }
}

// =============================================================================
// Edge cases
// =============================================================================

#[test]
fn test_empty_file() {
    let data = create_tar_with(|b| {
        append_file(b, "empty.txt", b"");
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), b"empty.txt");
    assert_eq!(entry.size, 0);

    // No content to skip for empty file
    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_read_content() {
    let data = create_tar_with(|b| {
        append_file(b, "file.txt", b"Hello, World!");
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.size, 13);
    let size = entry.size;
    drop(entry);

    // Read the actual content
    let mut content = vec![0u8; size as usize];
    std::io::Read::read_exact(parser.reader(), &mut content).unwrap();
    assert_eq!(content, b"Hello, World!");

    // Skip padding
    parser.skip_padding(size).unwrap();

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_padded_size() {
    let data = create_tar_with(|b| {
        append_file(b, "file.txt", b"x"); // 1 byte, padded to 512
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.size, 1);
    assert_eq!(entry.padded_size(), 512);

    let size = entry.size;
    drop(entry);
    parser.skip_content(size).unwrap();
    assert!(parser.next_entry().unwrap().is_none());
}

// =============================================================================
// Proptest cross-checking
// =============================================================================

mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy for generating valid file paths.
    fn path_strategy() -> impl Strategy<Value = String> {
        proptest::string::string_regex("[a-zA-Z0-9_][a-zA-Z0-9_.+-]{0,50}")
            .expect("valid regex")
            .prop_filter("non-empty", |s| !s.is_empty())
    }

    /// Strategy for file content.
    fn content_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..1024)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn test_roundtrip_single_file(path in path_strategy(), content in content_strategy()) {
            let data = create_tar_with(|b| {
                append_file(b, &path, &content);
            });

            let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

            let entry = parser.next_entry().unwrap().expect("should have entry");
            prop_assert_eq!(entry.path.as_ref(), path.as_bytes());
            prop_assert_eq!(entry.size, content.len() as u64);
            let size = entry.size;
            drop(entry);

            // Read content and verify
            let mut read_content = vec![0u8; size as usize];
            if size > 0 {
                std::io::Read::read_exact(parser.reader(), &mut read_content).unwrap();
                parser.skip_padding(size).unwrap();
            }
            prop_assert_eq!(read_content, content);

            prop_assert!(parser.next_entry().unwrap().is_none());
        }

        #[test]
        fn test_roundtrip_multiple_files(
            paths in prop::collection::vec(path_strategy(), 1..8)
        ) {
            let data = create_tar_with(|b| {
                for (i, path) in paths.iter().enumerate() {
                    let content = format!("content{}", i);
                    append_file(b, path, content.as_bytes());
                }
            });

            // Parse with tar crate
            let mut tar_archive = tar::Archive::new(Cursor::new(data.clone()));
            let tar_count = tar_archive.entries().unwrap().count();

            // Parse with our crate
            let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());
            let mut our_count = 0;
            while let Some(entry) = parser.next_entry().unwrap() {
                our_count += 1;
                let size = entry.size;
                drop(entry);
                parser.skip_content(size).unwrap();
            }

            prop_assert_eq!(tar_count, our_count);
            prop_assert_eq!(our_count, paths.len());
        }
    }
}
