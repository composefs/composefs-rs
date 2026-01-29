//! TAR archive processing and split stream conversion.
//!
//! This module handles the conversion of tar archives (container image layers) into composefs split streams.
//! It provides both synchronous and asynchronous tar processing, intelligently deciding whether to store
//! file content inline in the split stream or externally in the object store based on file size.
//!
//! Key components include the `split()` and `split_async()` functions for converting tar streams,
//! `get_entry()` for reading back tar entries from split streams, and comprehensive support for
//! tar format features including GNU long names, PAX extensions, and various file types.
//! The `TarEntry` and `TarItem` types represent processed tar entries in composefs format.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    io::Read,
    os::unix::prelude::{OsStrExt, OsStringExt},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{bail, ensure, Result};
use bytes::Bytes;
use rustix::fs::makedev;
use tar::PaxExtensions;
use tar_header::{EntryType, Header};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt},
    sync::mpsc,
};

use composefs::{
    dumpfile,
    fsverity::FsVerityHashValue,
    repository::{ObjectStoreMethod, Repository},
    splitstream::{SplitStreamBuilder, SplitStreamData, SplitStreamReader, SplitStreamWriter},
    tree::{LeafContent, RegularFile, Stat},
    util::{read_exactish, read_exactish_async},
    INLINE_CONTENT_MAX,
};

use crate::ImportStats;

fn read_header<R: Read>(reader: &mut R) -> Result<Option<Header>> {
    let mut header = Header::new_gnu();
    if read_exactish(reader, header.as_mut_bytes())? {
        Ok(Some(header))
    } else {
        Ok(None)
    }
}

async fn read_header_async(reader: &mut (impl AsyncRead + Unpin)) -> Result<Option<Header>> {
    let mut header = Header::new_gnu();
    if read_exactish_async(reader, header.as_mut_bytes()).await? {
        Ok(Some(header))
    } else {
        Ok(None)
    }
}

/// Splits the tar file from tar_stream into a Split Stream.  The store_data function is
/// responsible for ensuring that "external data" is in the composefs repository and returns the
/// fsverity hash value of that data.
pub fn split(
    tar_stream: &mut impl Read,
    writer: &mut SplitStreamWriter<impl FsVerityHashValue>,
) -> Result<ImportStats> {
    let mut stats = ImportStats::default();
    let mut buffer = vec![0u8; 1024 * 1024];

    while let Some(header) = read_header(tar_stream)? {
        // the header always gets stored as inline data
        writer.write_inline(header.as_bytes());
        stats.bytes_inlined += header.as_bytes().len() as u64;

        if header.as_bytes() == &[0u8; 512] {
            continue;
        }

        // read the corresponding data, if there is any
        let actual_size = header.entry_size()? as usize;
        let storage_size = actual_size.next_multiple_of(512);

        if header.entry_type() == EntryType::Regular && actual_size > INLINE_CONTENT_MAX {
            use std::io::Write;

            let mut limited_stream = tar_stream.take(actual_size as u64);
            let tmpfile_fd = writer.repo().create_object_tmpfile()?;
            let mut tmpfile = std::io::BufWriter::new(File::from(tmpfile_fd));

            loop {
                let bytes_read = limited_stream.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                tmpfile.write_all(&buffer[..bytes_read])?;
            }

            let tmpfile = tmpfile.into_inner()?;
            let (object_id, method) = writer
                .repo()
                .finalize_object_tmpfile(tmpfile, actual_size as u64)?;
            match method {
                ObjectStoreMethod::Copied => {
                    stats.objects_copied += 1;
                    stats.bytes_copied += actual_size as u64;
                }
                ObjectStoreMethod::AlreadyPresent => {
                    stats.objects_already_present += 1;
                }
            }
            writer.add_external_size(actual_size as u64);
            writer.write_reference(object_id)?;

            let padding_size = storage_size.checked_sub(actual_size).unwrap();
            if padding_size > 0 {
                tar_stream.read_exact(&mut buffer[..padding_size])?;
                writer.write_inline(&buffer[..padding_size]);
                stats.bytes_inlined += padding_size as u64;
            }
        } else {
            tar_stream
                .take(storage_size as u64)
                .read_exact(&mut buffer[..storage_size])?;
            writer.write_inline(&buffer[..storage_size]);
            stats.bytes_inlined += storage_size as u64;
        }
    }
    Ok(stats)
}

/// Receive data from channel, write to tmpfile, compute verity, and store object.
///
/// This runs in a blocking task to avoid blocking the async runtime.
fn receive_and_finalize_object<ObjectID: FsVerityHashValue>(
    rx: mpsc::Receiver<Bytes>,
    size: u64,
    repo: &Repository<ObjectID>,
) -> Result<(ObjectID, ObjectStoreMethod)> {
    use std::io::Write;

    // Create tmpfile in the blocking context
    let tmpfile_fd = repo.create_object_tmpfile()?;
    let mut tmpfile = std::io::BufWriter::new(File::from(tmpfile_fd));

    // Receive chunks and write to tmpfile
    let mut rx = rx;
    while let Some(chunk) = rx.blocking_recv() {
        tmpfile.write_all(&chunk)?;
    }

    // Flush and get the File back
    let tmpfile = tmpfile.into_inner()?;

    // Finalize: enable verity, get digest, link into objects/
    repo.finalize_object_tmpfile(tmpfile, size)
}

/// Asynchronously splits a tar archive into a composefs split stream.
///
/// Similar to `split()` but processes the tar stream asynchronously with parallel
/// object storage. Large files are streamed to O_TMPFILE via a channel, and their
/// fs-verity digests are computed in background blocking tasks. This avoids blocking
/// the async runtime while allowing multiple files to be processed concurrently.
///
/// Concurrency is limited to `available_parallelism()` to avoid overwhelming the
/// system with too many concurrent I/O operations.
///
/// Files larger than `INLINE_CONTENT_MAX` are stored externally in the object store,
/// while smaller files and metadata are stored inline in the split stream.
///
/// # Arguments
/// * `tar_stream` - The async buffered tar stream to read from
/// * `repo` - The repository for creating tmpfiles and storing objects
/// * `content_type` - The content type identifier for the splitstream
///
/// Returns the fs-verity object ID of the stored splitstream and import statistics.
pub async fn split_async<ObjectID: FsVerityHashValue>(
    mut tar_stream: impl AsyncBufRead + Unpin,
    repo: Arc<Repository<ObjectID>>,
    content_type: u64,
) -> Result<(ObjectID, ImportStats)> {
    // Use the repository's shared semaphore to limit concurrent object storage
    let semaphore = repo.write_semaphore();

    let mut builder = SplitStreamBuilder::new(repo.clone(), content_type);

    while let Some(header) = read_header_async(&mut tar_stream).await? {
        // The header always gets stored as inline data
        builder.push_inline(header.as_bytes());

        if header.as_bytes() == &[0u8; 512] {
            continue;
        }

        // Read the corresponding data, if there is any
        let actual_size = header.entry_size()? as usize;
        let storage_size = actual_size.next_multiple_of(512);

        if header.entry_type() == EntryType::Regular && actual_size > INLINE_CONTENT_MAX {
            // Large file: stream to O_TMPFILE via channel to avoid blocking async runtime

            // Acquire permit before starting
            let permit = semaphore.clone().acquire_owned().await?;

            // Create a channel for streaming data to the blocking task.
            // Buffer a few chunks to allow async/blocking to run concurrently.
            let (tx, rx) = mpsc::channel::<Bytes>(4);

            // Spawn blocking task that receives data, writes to tmpfile, computes verity
            let repo_clone = repo.clone();
            let handle = tokio::task::spawn_blocking(move || {
                let result = receive_and_finalize_object(rx, actual_size as u64, &repo_clone);
                drop(permit); // Release permit when done
                result
            });

            // Send data chunks to the blocking task using fill_buf to avoid extra copies
            let mut remaining = actual_size;
            while remaining > 0 {
                let chunk = tar_stream.fill_buf().await?;
                if chunk.is_empty() {
                    bail!("unexpected EOF reading tar entry");
                }
                let chunk_size = std::cmp::min(remaining, chunk.len());
                // If send fails, the receiver dropped (task panicked/errored)
                if tx
                    .send(Bytes::copy_from_slice(&chunk[..chunk_size]))
                    .await
                    .is_err()
                {
                    break;
                }
                tar_stream.consume(chunk_size);
                remaining -= chunk_size;
            }
            drop(tx); // Close channel to signal EOF

            // Push external entry to builder (will be resolved at finish())
            builder.push_external(handle, actual_size as u64);

            // Read and push padding inline (must come after external ref)
            let padding_size = storage_size - actual_size;
            if padding_size > 0 {
                let mut padding = vec![0u8; padding_size];
                tar_stream.read_exact(&mut padding).await?;
                builder.push_inline(&padding);
            }
        } else {
            // Small file or non-regular entry: buffer and write inline
            let mut buffer = vec![0u8; storage_size];
            tar_stream.read_exact(&mut buffer).await?;
            builder.push_inline(&buffer);
        }
    }

    // Finalize: await all handles, build stream, store it
    let (object_id, ss_stats) = builder.finish().await?;
    Ok((object_id, ImportStats::from_split_stream_stats(&ss_stats)))
}

/// Represents the content type of a tar entry.
///
/// Tar entries can be directories, regular files/symlinks/devices (leaf nodes), or hardlinks
/// to existing files. This enum captures the different types of content that can appear in a tar archive.
#[derive(Debug)]
pub enum TarItem<ObjectID: FsVerityHashValue> {
    /// A directory entry.
    Directory,
    /// A leaf node (regular file, symlink, device, or fifo).
    Leaf(LeafContent<ObjectID>),
    /// A hardlink pointing to another path.
    Hardlink(OsString),
}

/// Represents a complete tar entry extracted from a split stream.
///
/// Contains the full metadata and content for a single file or directory from a tar archive,
/// including its path, stat information (permissions, ownership, timestamps), and the actual content.
#[derive(Debug)]
pub struct TarEntry<ObjectID: FsVerityHashValue> {
    /// The absolute path of the entry in the filesystem.
    pub path: PathBuf,
    /// File metadata (mode, uid, gid, mtime, xattrs).
    pub stat: Stat,
    /// The content or type of this entry.
    pub item: TarItem<ObjectID>,
}

impl<ObjectID: FsVerityHashValue> fmt::Display for TarEntry<ObjectID> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.item {
            TarItem::Hardlink(ref target) => dumpfile::write_hardlink(fmt, &self.path, target),
            TarItem::Directory => dumpfile::write_directory(fmt, &self.path, &self.stat, 1),
            TarItem::Leaf(ref content) => {
                dumpfile::write_leaf(fmt, &self.path, &self.stat, content, 1)
            }
        }
    }
}

/// Build a file path from tar metadata (PAX > GNU > header name + UStar prefix).
fn path_from_tar(pax: Option<Box<[u8]>>, gnu: Vec<u8>, header: &Header) -> PathBuf {
    // Prepend leading /
    let mut path = vec![b'/'];

    if let Some(name) = pax {
        // PAX extended header has highest priority
        path.extend(name);
    } else if !gnu.is_empty() {
        // GNU long name has second priority
        path.extend(gnu);
    } else {
        // Standard header - check for UStar prefix field
        if let Some(prefix) = header.prefix() {
            if !prefix.is_empty() {
                path.extend(prefix);
                path.push(b'/');
            }
        }
        path.extend(header.path_bytes());
    }

    // Drop trailing '/' characters in case of directories.
    path.pop_if(|x| x == &b'/');

    PathBuf::from(OsString::from_vec(path))
}

/// Build a link target path from tar metadata (PAX > GNU > header link_name).
/// Link targets don't use the UStar prefix field - they use the linkname field directly.
fn link_target_from_tar(pax: Option<Box<[u8]>>, gnu: Vec<u8>, short: &[u8]) -> PathBuf {
    // Prepend leading /
    let mut path = vec![b'/'];
    if let Some(name) = pax {
        path.extend(name);
    } else if !gnu.is_empty() {
        path.extend(gnu);
    } else {
        path.extend(short);
    }

    // Drop trailing '/' characters.
    path.pop_if(|x| x == &b'/');

    PathBuf::from(OsString::from_vec(path))
}

fn symlink_target_from_tar(pax: Option<Box<[u8]>>, gnu: Vec<u8>, short: &[u8]) -> Box<OsStr> {
    if let Some(name) = pax {
        OsStr::from_bytes(name.as_ref()).into()
    } else if !gnu.is_empty() {
        OsStr::from_bytes(&gnu).into()
    } else {
        OsStr::from_bytes(short).into()
    }
}

/// Reads and parses the next tar entry from a split stream.
///
/// Decodes tar headers and data from a composefs split stream, handling both inline and
/// external content storage. Supports GNU long name/link extensions, PAX headers, and
/// extended attributes. Returns `None` when the end of the archive is reached.
///
/// Returns the parsed tar entry, or `None` if the end of the stream is reached.
pub fn get_entry<ObjectID: FsVerityHashValue>(
    reader: &mut SplitStreamReader<ObjectID>,
) -> Result<Option<TarEntry<ObjectID>>> {
    // We don't have a way to drive the standard tar crate that lets us feed it random bits of
    // header data while continuing to handle the external references as references.  That means we
    // have to do the header interpretation ourselves, including handling of PAX/GNU extensions for
    // xattrs and long filenames.
    //
    // We try to use as much of the tar crate as possible to help us with this.
    let mut gnu_longlink: Vec<u8> = vec![];
    let mut gnu_longname: Vec<u8> = vec![];
    let mut pax_longlink: Option<Box<[u8]>> = None;
    let mut pax_longname: Option<Box<[u8]>> = None;
    let mut xattrs = BTreeMap::new();

    let mut buf = [0u8; 512];
    loop {
        if !reader.read_inline_exact(&mut buf)? || buf == [0u8; 512] {
            return Ok(None);
        }

        let header = Header::from_bytes_exact(&buf);

        let size = header.entry_size()?;
        let stored_size = size.next_multiple_of(512);

        let item = match reader.read_exact(size as usize, stored_size as usize)? {
            SplitStreamData::External(id) => match header.entry_type() {
                EntryType::Regular | EntryType::Continuous => {
                    ensure!(
                        size as usize > INLINE_CONTENT_MAX,
                        "Splitstream incorrectly stored a small ({size} byte) file external"
                    );
                    TarItem::Leaf(LeafContent::Regular(RegularFile::External(id, size)))
                }
                _ => bail!("Unsupported external-chunked entry {header:?} {id:?}"),
            },
            SplitStreamData::Inline(content) => match header.entry_type() {
                EntryType::GnuLongLink => {
                    gnu_longlink.extend(content);
                    gnu_longlink.pop_if(|x| *x == b'\0');

                    continue;
                }
                EntryType::GnuLongName => {
                    gnu_longname.extend(content);
                    gnu_longname.pop_if(|x| *x == b'\0');
                    continue;
                }
                EntryType::XGlobalHeader => {
                    // Global PAX headers affect all subsequent entries.
                    // For simplicity, we skip them (matching tar-rs and TarStreamParser behavior).
                    // A more complete implementation would merge them into parser state.
                    continue;
                }
                EntryType::XHeader => {
                    for item in PaxExtensions::new(&content) {
                        let extension = item?;
                        let key = extension.key()?;
                        let value = Box::from(extension.value_bytes());

                        if key == "path" {
                            pax_longname = Some(value);
                        } else if key == "linkpath" {
                            pax_longlink = Some(value);
                        } else if let Some(xattr) = key.strip_prefix("SCHILY.xattr.") {
                            xattrs.insert(Box::from(OsStr::new(xattr)), value);
                        }
                    }
                    continue;
                }
                EntryType::Directory => TarItem::Directory,
                EntryType::Regular | EntryType::Continuous => {
                    ensure!(
                        content.len() <= INLINE_CONTENT_MAX,
                        "Splitstream incorrectly stored a large ({} byte) file inline",
                        content.len()
                    );
                    TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(content)))
                }
                EntryType::Link => TarItem::Hardlink({
                    let link_name = header.link_name_bytes();
                    link_target_from_tar(pax_longlink, gnu_longlink, link_name).into_os_string()
                }),
                EntryType::Symlink => TarItem::Leaf(LeafContent::Symlink({
                    let link_name = header.link_name_bytes();
                    symlink_target_from_tar(pax_longlink, gnu_longlink, link_name)
                })),
                EntryType::Block => TarItem::Leaf(LeafContent::BlockDevice(
                    match (header.device_major()?, header.device_minor()?) {
                        (Some(major), Some(minor)) => makedev(major, minor),
                        _ => bail!("Device entry without device numbers?"),
                    },
                )),
                EntryType::Char => TarItem::Leaf(LeafContent::CharacterDevice(
                    match (header.device_major()?, header.device_minor()?) {
                        (Some(major), Some(minor)) => makedev(major, minor),
                        _ => bail!("Device entry without device numbers?"),
                    },
                )),
                EntryType::Fifo => TarItem::Leaf(LeafContent::Fifo),
                _ => {
                    todo!("Unsupported entry {:?}", header);
                }
            },
        };

        return Ok(Some(TarEntry {
            path: path_from_tar(pax_longname, gnu_longname, header),
            stat: Stat {
                st_uid: header.uid()? as u32,
                st_gid: header.gid()? as u32,
                st_mode: header.mode()?,
                st_mtim_sec: header.mtime()? as i64,
                xattrs: RefCell::new(xattrs),
            },
            item,
        }));
    }
}

#[cfg(test)]
mod tests {
    use crate::TAR_LAYER_CONTENT_TYPE;

    use super::*;
    use composefs::{
        fsverity::Sha256HashValue, generic_tree::LeafContent, repository::Repository,
        splitstream::SplitStreamReader,
    };
    use std::{io::Cursor, path::Path, sync::Arc};
    use tar::Builder;

    use once_cell::sync::Lazy;
    use std::sync::Mutex;

    static TEST_TEMPDIRS: Lazy<Mutex<Vec<tempfile::TempDir>>> =
        Lazy::new(|| Mutex::new(Vec::new()));

    pub(crate) fn create_test_repository() -> Result<Arc<Repository<Sha256HashValue>>> {
        // Create a temporary repository for testing and store it in static
        let tempdir = tempfile::TempDir::new().unwrap();
        let fd = rustix::fs::open(
            tempdir.path(),
            rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::PATH,
            0.into(),
        )?;

        // Store tempdir in static to keep it alive
        {
            let mut guard = TEST_TEMPDIRS.lock().unwrap();
            guard.push(tempdir);
        }

        let mut repo = Repository::open_path(&fd, ".").unwrap();
        repo.set_insecure(true);

        Ok(Arc::new(repo))
    }

    /// Helper method to append a file to a tar builder with sensible defaults
    fn append_file(
        builder: &mut Builder<&mut Vec<u8>>,
        path: &str,
        content: &[u8],
    ) -> Result<tar::Header> {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_mtime(1234567890);
        header.set_size(content.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        builder.append_data(&mut header, path, content)?;
        Ok(header)
    }

    /// Helper method to process tar data through split/get_entry pipeline
    fn read_all_via_splitstream(tar_data: Vec<u8>) -> Result<Vec<TarEntry<Sha256HashValue>>> {
        let mut tar_cursor = Cursor::new(tar_data);
        let repo = create_test_repository()?;
        let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);

        let _stats = split(&mut tar_cursor, &mut writer)?;
        let object_id = writer.done()?;

        let mut reader: SplitStreamReader<Sha256HashValue> = SplitStreamReader::new(
            repo.open_object(&object_id)?.into(),
            Some(TAR_LAYER_CONTENT_TYPE),
        )?;

        let mut entries = Vec::new();
        while let Some(entry) = get_entry(&mut reader)? {
            entries.push(entry);
        }
        Ok(entries)
    }

    #[test]
    fn test_empty_tar() {
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            builder.finish().unwrap();
        }

        let mut tar_cursor = Cursor::new(tar_data);
        let repo = create_test_repository().unwrap();
        let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);

        split(&mut tar_cursor, &mut writer).unwrap();
        let object_id = writer.done().unwrap();

        let mut reader: SplitStreamReader<Sha256HashValue> = SplitStreamReader::new(
            repo.open_object(&object_id).unwrap().into(),
            Some(TAR_LAYER_CONTENT_TYPE),
        )
        .unwrap();
        assert!(get_entry(&mut reader).unwrap().is_none());
    }

    #[test]
    fn test_single_small_file() {
        let mut tar_data = Vec::new();
        let original_header = {
            let mut builder = Builder::new(&mut tar_data);

            // Add one small regular file
            let content = b"Hello, World!";
            let header = append_file(&mut builder, "hello.txt", content).unwrap();

            builder.finish().unwrap();
            header
        };

        let mut tar_cursor = Cursor::new(tar_data);
        let repo = create_test_repository().unwrap();
        let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);

        split(&mut tar_cursor, &mut writer).unwrap();
        let object_id = writer.done().unwrap();

        let mut reader: SplitStreamReader<Sha256HashValue> = SplitStreamReader::new(
            repo.open_object(&object_id).unwrap().into(),
            Some(TAR_LAYER_CONTENT_TYPE),
        )
        .unwrap();

        // Should have exactly one entry
        let entry = get_entry(&mut reader)
            .unwrap()
            .expect("Should have one entry");
        assert_eq!(entry.path, PathBuf::from("/hello.txt"));
        assert!(matches!(
            entry.item,
            TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(_)))
        ));

        // Use the helper to compare header and stat
        assert_header_stat_equal(&original_header, &entry.stat, "hello.txt");

        if let TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(ref content))) = entry.item {
            assert_eq!(content.as_ref(), b"Hello, World!");
        }

        // Should be no more entries
        assert!(get_entry(&mut reader).unwrap().is_none());
    }

    #[test]
    fn test_inline_threshold() {
        let mut tar_data = Vec::new();
        let (threshold_header, over_threshold_header) = {
            let mut builder = Builder::new(&mut tar_data);

            // File exactly at the threshold should be inline
            let threshold_content = vec![b'X'; INLINE_CONTENT_MAX];
            let header1 =
                append_file(&mut builder, "threshold_file.txt", &threshold_content).unwrap();

            // File just over threshold should be external
            let over_threshold_content = vec![b'Y'; INLINE_CONTENT_MAX + 1];
            let header2 = append_file(
                &mut builder,
                "over_threshold_file.txt",
                &over_threshold_content,
            )
            .unwrap();

            builder.finish().unwrap();
            (header1, header2)
        };

        let mut tar_cursor = Cursor::new(tar_data);
        let repo = create_test_repository().unwrap();
        let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);

        split(&mut tar_cursor, &mut writer).unwrap();
        let object_id = writer.done().unwrap();

        let mut reader: SplitStreamReader<Sha256HashValue> = SplitStreamReader::new(
            repo.open_object(&object_id).unwrap().into(),
            Some(TAR_LAYER_CONTENT_TYPE),
        )
        .unwrap();
        let mut entries = Vec::new();

        while let Some(entry) = get_entry(&mut reader).unwrap() {
            entries.push(entry);
        }

        assert_eq!(entries.len(), 2);

        // First file should be inline
        assert_eq!(entries[0].path, PathBuf::from("/threshold_file.txt"));
        assert_header_stat_equal(&threshold_header, &entries[0].stat, "threshold_file.txt");
        if let TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(ref content))) =
            entries[0].item
        {
            assert_eq!(content.len(), INLINE_CONTENT_MAX);
            assert_eq!(content[0], b'X');
        } else {
            panic!("Expected inline regular file for threshold file");
        }

        // Second file should be external
        assert_eq!(entries[1].path, PathBuf::from("/over_threshold_file.txt"));
        assert_header_stat_equal(
            &over_threshold_header,
            &entries[1].stat,
            "over_threshold_file.txt",
        );
        if let TarItem::Leaf(LeafContent::Regular(RegularFile::External(_, size))) = entries[1].item
        {
            assert_eq!(size, (INLINE_CONTENT_MAX + 1) as u64);
        } else {
            panic!("Expected external regular file for over-threshold file");
        }
    }

    #[test]
    fn test_round_trip_simple() {
        // Create a simple tar with various file types
        let mut original_tar = Vec::new();
        let (small_header, large_header) = {
            let mut builder = Builder::new(&mut original_tar);

            // Add a small file
            let small_content = b"Small file content";
            let header1 = append_file(&mut builder, "small.txt", small_content).unwrap();

            // Add a large file
            let large_content = vec![b'L'; INLINE_CONTENT_MAX + 100];
            let header2 = append_file(&mut builder, "large.txt", &large_content).unwrap();

            builder.finish().unwrap();
            (header1, header2)
        };

        // Split the tar
        let mut tar_cursor = Cursor::new(original_tar.clone());
        let repo = create_test_repository().unwrap();
        let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);
        split(&mut tar_cursor, &mut writer).unwrap();
        let object_id = writer.done().unwrap();

        // Read back entries and compare with original headers
        let mut reader: SplitStreamReader<Sha256HashValue> = SplitStreamReader::new(
            repo.open_object(&object_id).unwrap().into(),
            Some(TAR_LAYER_CONTENT_TYPE),
        )
        .unwrap();
        let mut entries = Vec::new();

        while let Some(entry) = get_entry(&mut reader).unwrap() {
            entries.push(entry);
        }

        assert_eq!(entries.len(), 2, "Should have exactly 2 entries");

        // Compare small file
        assert_eq!(entries[0].path, PathBuf::from("/small.txt"));
        assert_header_stat_equal(&small_header, &entries[0].stat, "small.txt");

        if let TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(ref content))) =
            entries[0].item
        {
            assert_eq!(content.as_ref(), b"Small file content");
        } else {
            panic!("Expected inline regular file for small.txt");
        }

        // Compare large file
        assert_eq!(entries[1].path, PathBuf::from("/large.txt"));
        assert_header_stat_equal(&large_header, &entries[1].stat, "large.txt");

        if let TarItem::Leaf(LeafContent::Regular(RegularFile::External(ref id, size))) =
            entries[1].item
        {
            assert_eq!(size, (INLINE_CONTENT_MAX + 100) as u64);
            // Verify the external content matches
            use std::io::Read;
            let mut external_data = Vec::new();
            std::fs::File::from(repo.open_object(id).unwrap())
                .read_to_end(&mut external_data)
                .unwrap();
            let expected_content = vec![b'L'; INLINE_CONTENT_MAX + 100];
            assert_eq!(
                external_data, expected_content,
                "External file content should match"
            );
        } else {
            panic!("Expected external regular file for large.txt");
        }
    }

    #[test]
    fn test_special_filename_cases() {
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);

            // Test file with special characters
            let content1 = b"Special chars content";
            append_file(&mut builder, "file-with_special.chars@123", content1).unwrap();

            // Test file with long filename
            let long_name = "a".repeat(100);
            let content2 = b"Long filename content";
            append_file(&mut builder, &long_name, content2).unwrap();

            builder.finish().unwrap();
        };

        let entries = read_all_via_splitstream(tar_data).unwrap();
        assert_eq!(entries.len(), 2);

        // Verify special characters filename
        assert_eq!(
            entries[0].path,
            PathBuf::from("/file-with_special.chars@123")
        );
        assert_eq!(
            entries[0].path.file_name().unwrap(),
            "file-with_special.chars@123"
        );

        // Verify long filename
        let expected_long_path = format!("/{}", "a".repeat(100));
        assert_eq!(entries[1].path, PathBuf::from(expected_long_path));
        assert_eq!(entries[1].path.file_name().unwrap(), &*"a".repeat(100));
    }

    #[test]
    fn test_gnu_long_filename_reproduction() {
        // Create a very long path that will definitely trigger GNU long name extensions
        let very_long_path = format!(
            "very/long/path/that/exceeds/the/normal/tar/header/limit/{}",
            "x".repeat(120)
        );
        let content = b"Content for very long path";

        // Use append_data to create a tar with a very long filename that triggers GNU extensions
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            append_file(&mut builder, &very_long_path, content).unwrap();
            builder.finish().unwrap();
        };

        let entries = read_all_via_splitstream(tar_data).unwrap();
        assert_eq!(entries.len(), 1);
        let abspath = format!("/{very_long_path}");
        assert_eq!(entries[0].path, Path::new(&abspath));
    }

    #[test]
    fn test_gnu_longlink() {
        let very_long_path = format!(
            "very/long/path/that/exceeds/the/normal/tar/header/limit/{}",
            "x".repeat(120)
        );

        // Use append_data to create a tar with a very long filename that triggers GNU extensions
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o777);
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_uid(0);
            header.set_gid(0);
            builder
                .append_link(&mut header, "long-symlink", &very_long_path)
                .unwrap();
            builder.finish().unwrap();
        };

        let entries = read_all_via_splitstream(tar_data).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0].item {
            TarItem::Leaf(LeafContent::Symlink(ref target)) => {
                assert_eq!(&**target, OsStr::new(&very_long_path));
            }
            _ => unreachable!(),
        };
    }

    /// Compare a tar::Header with a composefs Stat structure for equality
    fn assert_header_stat_equal(header: &tar::Header, stat: &Stat, msg_prefix: &str) {
        assert_eq!(
            header.mode().unwrap(),
            stat.st_mode,
            "{msg_prefix}: mode mismatch"
        );
        assert_eq!(
            header.uid().unwrap() as u32,
            stat.st_uid,
            "{msg_prefix}: uid mismatch"
        );
        assert_eq!(
            header.gid().unwrap() as u32,
            stat.st_gid,
            "{msg_prefix}: gid mismatch"
        );
        assert_eq!(
            header.mtime().unwrap() as i64,
            stat.st_mtim_sec,
            "{msg_prefix}: mtime mismatch"
        );
    }

    /// Benchmark for tar split processing via Repository API.
    ///
    /// Run with: cargo test --release --lib -p composefs-oci bench_tar_split -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_tar_split() {
        use std::time::Instant;

        // Configuration: 10000 files of 200KB each = 2GB total
        const NUM_FILES: usize = 10000;
        const FILE_SIZE: usize = 200 * 1024; // 200KB
        const ITERATIONS: usize = 3;

        println!("\n=== Tar Split Benchmark ===");
        println!(
            "Configuration: {} files of {}KB each, {} iterations",
            NUM_FILES,
            FILE_SIZE / 1024,
            ITERATIONS
        );

        // Generate deterministic test data
        fn generate_test_data(size: usize, seed: u8) -> Vec<u8> {
            (0..size)
                .map(|i| ((i as u8).wrapping_add(seed)).wrapping_mul(17))
                .collect()
        }

        // Build a tar archive in memory with many large files
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            for i in 0..NUM_FILES {
                let content = generate_test_data(FILE_SIZE, i as u8);
                let filename = format!("file_{:04}.bin", i);
                append_file(&mut builder, &filename, &content).unwrap();
            }
            builder.finish().unwrap();
        }

        let tar_size = tar_data.len();
        println!(
            "Tar archive size: {} bytes ({:.2} MB)",
            tar_size,
            tar_size as f64 / (1024.0 * 1024.0)
        );

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        let mut times = Vec::with_capacity(ITERATIONS);
        for i in 0..ITERATIONS {
            let repo = create_test_repository().unwrap();
            let tar_data_clone = tar_data.clone();

            let start = Instant::now();
            rt.block_on(async {
                split_async(&tar_data_clone[..], repo, TAR_LAYER_CONTENT_TYPE)
                    .await
                    .map(|(id, _stats)| id)
            })
            .unwrap();
            let elapsed = start.elapsed();
            times.push(elapsed);
            println!("Iteration {}: {:?}", i + 1, elapsed);
        }

        let total: std::time::Duration = times.iter().sum();
        let avg = total / ITERATIONS as u32;
        println!("\n=== Summary ===");
        println!(
            "Average: {:?}  ({:.2} MB/s)",
            avg,
            (tar_size as f64 / (1024.0 * 1024.0)) / avg.as_secs_f64()
        );
    }

    /// Test that split_async produces correct output for mixed content.
    #[tokio::test]
    async fn test_split_streaming_roundtrip() {
        // Create a tar with a mix of small (inline) and large (external) files
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);

            // Small file (should be inline)
            let small_content = b"Small file content";
            append_file(&mut builder, "small.txt", small_content).unwrap();

            // Large file (should be external/streamed)
            let large_content = vec![b'L'; INLINE_CONTENT_MAX + 100];
            append_file(&mut builder, "large.txt", &large_content).unwrap();

            // Another small file
            let small2_content = b"Another small file";
            append_file(&mut builder, "small2.txt", small2_content).unwrap();

            builder.finish().unwrap();
        }

        let repo = create_test_repository().unwrap();

        // Use split_async which returns (object_id, stats)
        let (object_id, _stats) = split_async(&tar_data[..], repo.clone(), TAR_LAYER_CONTENT_TYPE)
            .await
            .unwrap();

        // Read back and verify
        let mut reader: SplitStreamReader<Sha256HashValue> = SplitStreamReader::new(
            repo.open_object(&object_id).unwrap().into(),
            Some(TAR_LAYER_CONTENT_TYPE),
        )
        .unwrap();

        let mut entries = Vec::new();
        while let Some(entry) = get_entry(&mut reader).unwrap() {
            entries.push(entry);
        }

        assert_eq!(entries.len(), 3, "Should have 3 entries");

        // Verify small file (inline)
        assert_eq!(entries[0].path, PathBuf::from("/small.txt"));
        if let TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(ref content))) =
            entries[0].item
        {
            assert_eq!(content.as_ref(), b"Small file content");
        } else {
            panic!("Expected inline regular file for small.txt");
        }

        // Verify large file (external)
        assert_eq!(entries[1].path, PathBuf::from("/large.txt"));
        if let TarItem::Leaf(LeafContent::Regular(RegularFile::External(ref id, size))) =
            entries[1].item
        {
            assert_eq!(size, (INLINE_CONTENT_MAX + 100) as u64);
            // Verify the external content matches
            let mut external_data = Vec::new();
            std::fs::File::from(repo.open_object(id).unwrap())
                .read_to_end(&mut external_data)
                .unwrap();
            let expected_content = vec![b'L'; INLINE_CONTENT_MAX + 100];
            assert_eq!(
                external_data, expected_content,
                "External file content should match"
            );
        } else {
            panic!("Expected external regular file for large.txt");
        }

        // Verify second small file (inline)
        assert_eq!(entries[2].path, PathBuf::from("/small2.txt"));
        if let TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(ref content))) =
            entries[2].item
        {
            assert_eq!(content.as_ref(), b"Another small file");
        } else {
            panic!("Expected inline regular file for small2.txt");
        }
    }

    /// Test split_async with multiple large files.
    #[tokio::test]
    async fn test_split_streaming_multiple_large_files() {
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);

            // Three large files to test parallel streaming
            for i in 0..3 {
                let content = vec![(i + 0x41) as u8; INLINE_CONTENT_MAX + 1000]; // 'A', 'B', 'C'
                let filename = format!("file{}.bin", i);
                append_file(&mut builder, &filename, &content).unwrap();
            }

            builder.finish().unwrap();
        }

        let repo = create_test_repository().unwrap();

        let (object_id, _stats) = split_async(&tar_data[..], repo.clone(), TAR_LAYER_CONTENT_TYPE)
            .await
            .unwrap();

        // Read back and verify
        let mut reader: SplitStreamReader<Sha256HashValue> = SplitStreamReader::new(
            repo.open_object(&object_id).unwrap().into(),
            Some(TAR_LAYER_CONTENT_TYPE),
        )
        .unwrap();

        let mut entries = Vec::new();
        while let Some(entry) = get_entry(&mut reader).unwrap() {
            entries.push(entry);
        }

        assert_eq!(entries.len(), 3, "Should have 3 entries");

        for (i, entry) in entries.iter().enumerate() {
            let expected_path = format!("/file{}.bin", i);
            assert_eq!(entry.path, PathBuf::from(&expected_path));

            if let TarItem::Leaf(LeafContent::Regular(RegularFile::External(ref id, size))) =
                entry.item
            {
                assert_eq!(size, (INLINE_CONTENT_MAX + 1000) as u64);
                let mut external_data = Vec::new();
                std::fs::File::from(repo.open_object(id).unwrap())
                    .read_to_end(&mut external_data)
                    .unwrap();
                let expected_content = vec![(i + 0x41) as u8; INLINE_CONTENT_MAX + 1000];
                assert_eq!(
                    external_data, expected_content,
                    "External file {} content should match",
                    i
                );
            } else {
                panic!("Expected external regular file for file{}.bin", i);
            }
        }
    }

    // ==========================================================================
    // Long path format tests using proptest
    // ==========================================================================
    //
    // Tar archives use different mechanisms for paths > 100 characters:
    // - GNU LongName: type 'L' entry before actual entry (used by tar crate with new_gnu())
    // - UStar prefix: 155-byte prefix field + 100-byte name field (max ~255 bytes)
    // - PAX extended: type 'x' entry with key=value pairs (unlimited length)

    /// Table-driven test for specific path length edge cases and format triggers.
    #[test]
    fn test_longpath_formats() {
        // (description, path generator, use_gnu_header)
        // The tar crate auto-selects format based on path length and header type
        let cases: &[(&str, fn() -> String, bool)] = &[
            // Basic name field (≤100 chars)
            ("short path", || "short.txt".to_string(), false),
            ("exactly 100 chars", || "x".repeat(100), false),
            // UStar prefix (101-255 chars with /)
            (
                "ustar prefix",
                || format!("{}/{}", "dir".repeat(40), "file.txt"),
                false,
            ),
            (
                "max ustar (~254 chars)",
                || format!("{}/{}", "p".repeat(154), "n".repeat(99)),
                false,
            ),
            // GNU LongName (>100 chars with gnu header)
            (
                "gnu longname",
                || format!("{}/{}", "a".repeat(80), "b".repeat(50)),
                true,
            ),
            // PAX (>255 chars, any header)
            (
                "pax extended",
                || format!("{}/{}", "sub/".repeat(60), "file.txt"),
                false,
            ),
        ];

        for (desc, make_path, use_gnu) in cases {
            let path = make_path();
            let content = b"test content";

            let mut tar_data = Vec::new();
            {
                let mut builder = Builder::new(&mut tar_data);
                let mut header = if *use_gnu {
                    tar::Header::new_gnu()
                } else {
                    tar::Header::new_ustar()
                };
                header.set_mode(0o644);
                header.set_uid(1000);
                header.set_gid(1000);
                header.set_mtime(1234567890);
                header.set_size(content.len() as u64);
                header.set_entry_type(tar::EntryType::Regular);
                builder
                    .append_data(&mut header, &path, &content[..])
                    .unwrap();
                builder.finish().unwrap();
            }

            let entries = read_all_via_splitstream(tar_data).unwrap();
            assert_eq!(entries.len(), 1, "{desc}: expected 1 entry");
            assert_eq!(
                entries[0].path,
                PathBuf::from(format!("/{}", path)),
                "{desc}: path mismatch (len={})",
                path.len()
            );
        }
    }

    /// Table-driven test for hardlinks with long targets.
    #[test]
    fn test_longpath_hardlinks() {
        let cases: &[(&str, fn() -> String, bool)] = &[
            ("short target", || "target.txt".to_string(), true),
            (
                "gnu longlink",
                || format!("{}/{}", "c".repeat(80), "d".repeat(50)),
                true,
            ),
            (
                "pax linkpath",
                || format!("{}/{}", "sub/".repeat(60), "target.txt"),
                false,
            ),
        ];

        for (desc, make_target, use_gnu) in cases {
            let target_path = make_target();
            let link_name = "hardlink";
            let content = b"target content";

            let mut tar_data = Vec::new();
            {
                let mut builder = Builder::new(&mut tar_data);

                // Create target file
                let mut header = if *use_gnu {
                    tar::Header::new_gnu()
                } else {
                    tar::Header::new_ustar()
                };
                header.set_mode(0o644);
                header.set_uid(1000);
                header.set_gid(1000);
                header.set_mtime(1234567890);
                header.set_size(content.len() as u64);
                header.set_entry_type(tar::EntryType::Regular);
                builder
                    .append_data(&mut header, &target_path, &content[..])
                    .unwrap();

                // Create hardlink
                let mut link_header = if *use_gnu {
                    tar::Header::new_gnu()
                } else {
                    tar::Header::new_ustar()
                };
                link_header.set_mode(0o644);
                link_header.set_uid(1000);
                link_header.set_gid(1000);
                link_header.set_mtime(1234567890);
                link_header.set_size(0);
                link_header.set_entry_type(tar::EntryType::Link);
                builder
                    .append_link(&mut link_header, link_name, &target_path)
                    .unwrap();

                builder.finish().unwrap();
            }

            let entries = read_all_via_splitstream(tar_data).unwrap();
            assert_eq!(entries.len(), 2, "{desc}: expected 2 entries");
            assert_eq!(
                entries[0].path,
                PathBuf::from(format!("/{}", target_path)),
                "{desc}"
            );
            assert_eq!(
                entries[1].path,
                PathBuf::from(format!("/{}", link_name)),
                "{desc}"
            );

            match &entries[1].item {
                TarItem::Hardlink(target) => {
                    assert_eq!(
                        target.to_str().unwrap(),
                        format!("/{}", target_path),
                        "{desc}: hardlink target mismatch"
                    );
                }
                _ => panic!("{desc}: expected hardlink entry"),
            }
        }
    }

    /// Verify UStar prefix field is actually used for paths > 100 chars.
    #[test]
    fn test_ustar_prefix_field_used() {
        // Path must be > 100 chars to trigger prefix usage, but filename must be <= 100 chars
        let dir_path =
            "usr/lib/python3.12/site-packages/some-very-long-package-name-here/__pycache__/subdir";
        let filename = "module_name_with_extra_stuff.cpython-312.opt-2.pyc";
        let full_path = format!("{dir_path}/{filename}");

        // Verify our test setup: full path > 100 chars, filename <= 100 chars
        assert!(
            full_path.len() > 100,
            "full path must exceed 100 chars to use prefix"
        );
        assert!(filename.len() <= 100, "filename must fit in name field");

        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            let mut header = tar::Header::new_ustar();
            header.set_mode(0o644);
            header.set_size(4);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_path(&full_path).unwrap();
            header.set_cksum();
            builder.append(&header, b"test".as_slice()).unwrap();
            builder.finish().unwrap();
        }

        // Verify prefix field (bytes 345-500) is populated
        let prefix_field = &tar_data[345..500];
        let prefix_str = std::str::from_utf8(prefix_field)
            .unwrap()
            .trim_end_matches('\0');
        assert_eq!(
            prefix_str, dir_path,
            "UStar prefix field should contain directory"
        );

        let entries = read_all_via_splitstream(tar_data).unwrap();
        assert_eq!(entries[0].path, PathBuf::from(format!("/{full_path}")));
    }

    /// Property-based tests for tar path handling.
    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        /// Strategy for generating valid path components.
        fn path_component() -> impl Strategy<Value = String> {
            proptest::string::string_regex("[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,30}")
                .expect("valid regex")
                .prop_filter("non-empty", |s| !s.is_empty())
        }

        /// Strategy for generating paths with a target total length.
        fn path_with_length(min_len: usize, max_len: usize) -> impl Strategy<Value = String> {
            prop::collection::vec(path_component(), 1..20)
                .prop_map(|components| components.join("/"))
                .prop_filter("length in range", move |p| {
                    p.len() >= min_len && p.len() <= max_len
                })
        }

        /// Create a tar archive with a single file and verify round-trip.
        fn roundtrip_path(path: &str) {
            let content = b"proptest content";

            let mut tar_data = Vec::new();
            {
                let mut builder = Builder::new(&mut tar_data);
                let mut header = tar::Header::new_ustar();
                header.set_mode(0o644);
                header.set_uid(1000);
                header.set_gid(1000);
                header.set_mtime(1234567890);
                header.set_size(content.len() as u64);
                header.set_entry_type(tar::EntryType::Regular);
                builder
                    .append_data(&mut header, path, &content[..])
                    .unwrap();
                builder.finish().unwrap();
            }

            let entries = read_all_via_splitstream(tar_data).unwrap();
            assert_eq!(entries.len(), 1, "expected 1 entry for path: {path}");
            assert_eq!(
                entries[0].path,
                PathBuf::from(format!("/{path}")),
                "path mismatch"
            );
        }

        /// Create a tar archive with a hardlink and verify round-trip.
        fn roundtrip_hardlink(target_path: &str) {
            let link_name = "link";
            let content = b"target content";

            let mut tar_data = Vec::new();
            {
                let mut builder = Builder::new(&mut tar_data);

                let mut header = tar::Header::new_ustar();
                header.set_mode(0o644);
                header.set_uid(1000);
                header.set_gid(1000);
                header.set_mtime(1234567890);
                header.set_size(content.len() as u64);
                header.set_entry_type(tar::EntryType::Regular);
                builder
                    .append_data(&mut header, target_path, &content[..])
                    .unwrap();

                let mut link_header = tar::Header::new_ustar();
                link_header.set_mode(0o644);
                link_header.set_uid(1000);
                link_header.set_gid(1000);
                link_header.set_mtime(1234567890);
                link_header.set_size(0);
                link_header.set_entry_type(tar::EntryType::Link);
                builder
                    .append_link(&mut link_header, link_name, target_path)
                    .unwrap();

                builder.finish().unwrap();
            }

            let entries = read_all_via_splitstream(tar_data).unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].path, PathBuf::from(format!("/{target_path}")));

            match &entries[1].item {
                TarItem::Hardlink(target) => {
                    assert_eq!(target.to_str().unwrap(), format!("/{target_path}"));
                }
                _ => panic!("expected hardlink"),
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn test_short_paths(path in path_with_length(1, 100)) {
                roundtrip_path(&path);
            }

            #[test]
            fn test_medium_paths(path in path_with_length(101, 255)) {
                roundtrip_path(&path);
            }

            #[test]
            fn test_long_paths(path in path_with_length(256, 500)) {
                roundtrip_path(&path);
            }

            #[test]
            fn test_hardlink_targets(target in path_with_length(1, 400)) {
                roundtrip_hardlink(&target);
            }
        }
    }
}
