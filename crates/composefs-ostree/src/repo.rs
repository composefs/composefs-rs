//! Access layer for local and remote ostree repositories.
//!
//! Provides the [`OstreeRepo`] trait for fetching objects and files, with
//! concrete implementations for local filesystem repos ([`LocalRepo`]) and
//! HTTP-served repos ([`RemoteRepo`]).

use anyhow::{Context, Result, anyhow, bail};
use configparser::ini::Ini;
use flate2::read::DeflateDecoder;
use gvariant::aligned_bytes::AlignedBuf;
use reqwest::{Client, Url};
use rustix::fd::AsRawFd;
use rustix::fs::{FileType, Mode, OFlags, fstat, getxattr, listxattr, openat, readlinkat};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::{
    fs::File,
    future::Future,
    io::{Read, empty},
    os::fd::{AsFd, OwnedFd},
    path::Path,
    sync::Arc,
};
use tokio::io::AsyncReadExt;
use tokio_stream::StreamExt;
use tokio_util::io::StreamReader;

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    util::{ErrnoFilter, Sha256Digest, parse_sha256},
};

use crate::ostree::{
    ObjectType, OstreeDirMeta, OstreeFileHeader, RepoMode, SizedVariantHeader, get_object_pathname,
    get_sized_variant_size, parse_xattr_data, should_inline_file,
};

struct HashingReader<'a, R: Read> {
    inner: &'a mut R,
    hasher: &'a mut Sha256,
}

impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
        }
        Ok(n)
    }
}

fn hash_and_store_file<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    header: &OstreeFileHeader,
    mut file_data: AlignedBuf,
    reader: &mut impl Read,
    expected_checksum: &Sha256Digest,
) -> Result<(AlignedBuf, Option<ObjectID>)> {
    let mut hasher = Sha256::new();
    let sized_regular_header = header.serialize_regular_sized();
    hasher.update(&*sized_regular_header);

    let obj_id = if should_inline_file::<ObjectID>(header.size as usize) {
        let mut file_content = Vec::new();
        reader.read_to_end(&mut file_content)?;
        hasher.update(&file_content);
        file_data.with_vec(|v| v.extend_from_slice(&file_content));
        None
    } else {
        let hashing_reader = HashingReader {
            inner: reader,
            hasher: &mut hasher,
        };
        let obj_id = repo.ensure_object_from_reader(hashing_reader, header.size)?;
        Some(obj_id)
    };

    let actual_checksum = hasher.finalize();
    if *actual_checksum != *expected_checksum {
        bail!(
            "Unexpected file checksum {}, expected {}",
            hex::encode(actual_checksum),
            hex::encode(expected_checksum)
        );
    }

    Ok((file_data, obj_id))
}

/// Abstraction over local and remote ostree repository access.
///
/// Implemented by [`LocalRepo`] (on-disk) and [`RemoteRepo`] (HTTP).
/// Pass an implementor to [`crate::pull()`] to fetch an ostree commit.
pub trait OstreeRepo<ObjectID: FsVerityHashValue>: Send + Sync {
    /// Resolve a named ref (e.g. `fedora/40/x86_64`) to its commit checksum.
    fn resolve_ref(&self, ref_name: &str) -> impl Future<Output = Result<Sha256Digest>> + Send;
    /// Fetch a metadata object (commit, dirtree, dirmeta) by checksum.
    fn fetch_object(
        &self,
        checksum: &Sha256Digest,
        object_type: ObjectType,
    ) -> impl Future<Output = Result<AlignedBuf>> + Send;
    /// Fetch a file object by checksum, returning the header and optional object ID.
    fn fetch_file(
        &self,
        checksum: &Sha256Digest,
    ) -> impl Future<Output = Result<(AlignedBuf, Option<ObjectID>)>> + Send;
}

/// Fetches ostree objects over HTTP from an archive-z2 repository.
#[derive(Debug)]
pub struct RemoteRepo<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    client: Client,
    url: Url,
}

impl<ObjectID: FsVerityHashValue> RemoteRepo<ObjectID> {
    /// Create a new remote ostree repo client for the given URL.
    pub fn new(repo: &Arc<Repository<ObjectID>>, url: &str) -> Result<Self> {
        Ok(RemoteRepo {
            repo: repo.clone(),
            client: Client::new(),
            url: Url::parse(url)?,
        })
    }

    fn url_for(&self, segments: &[&str]) -> Url {
        let mut url = self.url.clone();
        url.path_segments_mut()
            .expect("repo URL is not cannot-be-a-base")
            .pop_if_empty()
            .extend(segments);
        url
    }
}

impl<ObjectID: FsVerityHashValue> OstreeRepo<ObjectID> for RemoteRepo<ObjectID> {
    async fn resolve_ref(&self, ref_name: &str) -> Result<Sha256Digest> {
        // TODO: Support summary format
        let url = self.url_for(&["refs", "heads", ref_name]);

        let response = self.client.get(url.clone()).send().await?;
        response.error_for_status_ref()?;
        let t = response
            .text()
            .await
            .with_context(|| format!("Cannot get ostree ref at {}", url))?;

        Ok(parse_sha256(t.trim())?)
    }

    async fn fetch_object(
        &self,
        checksum: &Sha256Digest,
        object_type: ObjectType,
    ) -> Result<AlignedBuf> {
        let dir = format!("{:02x}", checksum[0]);
        let name = format!(
            "{}{}",
            hex::encode(&checksum[1..]),
            object_type.extension(RepoMode::Archive)
        );
        let url = self.url_for(&["objects", &dir, &name]);

        let response = self.client.get(url.clone()).send().await?;
        response.error_for_status_ref()?;
        let b = response
            .bytes()
            .await
            .with_context(|| format!("Cannot get ostree object at {}", url))?;

        Ok(b.to_vec().into())
    }

    async fn fetch_file(&self, checksum: &Sha256Digest) -> Result<(AlignedBuf, Option<ObjectID>)> {
        let dir = format!("{:02x}", checksum[0]);
        let name = format!(
            "{}{}",
            hex::encode(&checksum[1..]),
            ObjectType::File.extension(RepoMode::Archive)
        );
        let url = self.url_for(&["objects", &dir, &name]);

        let response = self.client.get(url.clone()).send().await?;
        response.error_for_status_ref()?;

        let byte_stream = response
            .bytes_stream()
            .map(|r| r.map_err(std::io::Error::other));
        let mut reader = StreamReader::new(byte_stream);

        // Read the sized variant header from the stream
        let header_size = size_of::<SizedVariantHeader>();
        let mut header_buf = vec![0u8; header_size];
        reader
            .read_exact(&mut header_buf)
            .await
            .with_context(|| format!("Cannot read ostree file header at {}", url))?;

        let variant_size = get_sized_variant_size(&header_buf)?;
        header_buf.resize(header_size + variant_size, 0u8);
        reader
            .read_exact(&mut header_buf[header_size..])
            .await
            .with_context(|| format!("Cannot read ostree file variant at {}", url))?;

        let file_header: AlignedBuf = header_buf.into();

        let header = OstreeFileHeader::from_zlib_sized(&file_header)?;

        let checksum = *checksum;
        let repo = self.repo.clone();

        // Convert the async stream to a sync reader for decompression
        let sync_reader = tokio_util::io::SyncIoBridge::new(reader);
        let mut decompressor = DeflateDecoder::new(sync_reader);

        tokio::task::spawn_blocking(move || {
            hash_and_store_file(&repo, &header, file_header, &mut decompressor, &checksum)
        })
        .await
        .context("spawn_blocking failed")?
    }
}

fn proc_self_fd(fd: &impl AsFd) -> String {
    format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd())
}

// Returns empty string instead of None for non-symlinks to match the ostree metadata format
fn read_symlink_target(fd: &impl AsFd, is_symlink: bool) -> Result<String> {
    if is_symlink {
        readlinkat(fd, "", [])?
            .into_string()
            .map_err(|_| anyhow!("symlink target is not valid UTF-8"))
    } else {
        Ok(String::new())
    }
}

fn read_xattr_value(path: &str, name: &CStr) -> Result<Vec<u8>> {
    let mut buffer = [MaybeUninit::new(0u8); 65536];
    let (value, _) = getxattr(path, name, &mut buffer)?;
    Ok(value.to_vec())
}

fn read_xattrs_from_path(fd: &impl AsFd) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let filename = proc_self_fd(fd);

    let mut names_buf = [MaybeUninit::new(0); 65536];
    let (names, _) = listxattr(&filename, &mut names_buf)?;

    let mut xattrs = names
        .split_inclusive(|c| *c == 0)
        .map(|name| {
            let name = CStr::from_bytes_with_nul(name)?;
            let value = read_xattr_value(&filename, name)?;
            Ok((name.to_bytes_with_nul().to_vec(), value))
        })
        .collect::<Result<Vec<_>>>()?;

    xattrs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(xattrs)
}

/// Reads ostree objects from a local on-disk repository (any mode).
#[derive(Debug)]
pub struct LocalRepo<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    mode: RepoMode,
    dir: OwnedFd,
    objects: OwnedFd,
}

impl<ObjectID: FsVerityHashValue> LocalRepo<ObjectID> {
    /// Open a local ostree repository at the given path.
    pub fn open_path(
        repo: &Arc<Repository<ObjectID>>,
        dirfd: impl AsFd,
        path: impl AsRef<Path>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let repofd = openat(
            &dirfd,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Cannot open ostree repository at {}", path.display()))?;

        let configfd = openat(
            &repofd,
            "config",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Cannot open ostree repo config file at {}", path.display()))?;

        let mut config_data = String::new();

        File::from(configfd)
            .read_to_string(&mut config_data)
            .with_context(|| "Can't read config file")?;

        let mut config = Ini::new();
        let map = config
            .read(config_data)
            .map_err(|e| anyhow!(e))
            .context("Can't read config file")?;

        let core = map
            .get("core")
            .ok_or_else(|| anyhow!("No [core] section in config"))?;

        let mode: RepoMode = core
            .get("mode")
            .and_then(|v| v.as_deref())
            .ok_or_else(|| anyhow!("No mode in [core] section in config"))?
            .parse()?;

        let objectsfd = openat(
            &repofd,
            "objects",
            OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY,
            0o666.into(),
        )
        .with_context(|| {
            format!(
                "Cannot open ostree repository objects directory at {}",
                path.display()
            )
        })?;

        Ok(Self {
            repo: repo.clone(),
            mode,
            dir: repofd,
            objects: objectsfd,
        })
    }

    pub(crate) fn open_object_flags(
        &self,
        checksum: &Sha256Digest,
        object_type: ObjectType,
        flags: OFlags,
    ) -> Result<OwnedFd> {
        let path = get_object_pathname(self.mode, checksum, object_type);

        openat(&self.objects, &path, flags | OFlags::CLOEXEC, Mode::empty())
            .with_context(|| format!("Cannot open ostree objects object at {}", path))
    }

    pub(crate) fn open_object(
        &self,
        checksum: &Sha256Digest,
        object_type: ObjectType,
    ) -> Result<OwnedFd> {
        self.open_object_flags(checksum, object_type, OFlags::RDONLY | OFlags::NOFOLLOW)
    }

    pub(crate) fn read_ref(&self, ref_name: &str) -> Result<Sha256Digest> {
        let path1 = format!("refs/{}", ref_name);
        let path2 = format!("refs/heads/{}", ref_name);

        let fd1 = openat(
            &self.dir,
            &path1,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .filter_errno(Errno::NOENT)
        .with_context(|| format!("Cannot open ostree ref at {}", path1))?;

        let fd = match fd1 {
            Some(fd) => fd,
            None => openat(
                &self.dir,
                &path2,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| format!("Cannot open ostree ref at {}", path2))?,
        };

        let mut buffer = String::new();
        File::from(fd)
            .read_to_string(&mut buffer)
            .with_context(|| "Can't read ref file")?;

        Ok(parse_sha256(buffer.trim())?)
    }

    async fn fetch_file_bare(
        &self,
        checksum: &Sha256Digest,
    ) -> Result<(AlignedBuf, Box<dyn Read>)> {
        let path_fd =
            self.open_object_flags(checksum, ObjectType::File, OFlags::PATH | OFlags::NOFOLLOW)?;

        let st = fstat(&path_fd)?;
        let disk_filetype = FileType::from_raw_mode(st.st_mode);

        let (uid, gid, mode, xattrs, symlink_target) = match self.mode {
            RepoMode::Bare => {
                let xattrs = read_xattrs_from_path(&path_fd)?;
                let symlink_target = read_symlink_target(&path_fd, disk_filetype.is_symlink())?;
                (st.st_uid, st.st_gid, st.st_mode, xattrs, symlink_target)
            }
            RepoMode::BareUser => {
                let fd_path = proc_self_fd(&path_fd);
                let name = c"user.ostreemeta";
                let aligned: AlignedBuf = read_xattr_value(&fd_path, name)?.into();
                let meta = OstreeDirMeta::from_data(&aligned)?;

                let is_symlink = FileType::from_raw_mode(meta.mode).is_symlink();
                let symlink_target = if is_symlink {
                    let mut target = Vec::new();
                    File::open(&fd_path)?.read_to_end(&mut target)?;
                    if target.last() == Some(&0) {
                        target.pop();
                    }
                    String::from_utf8(target)
                        .map_err(|_| anyhow!("symlink target is not valid UTF-8"))?
                } else {
                    String::new()
                };
                (meta.uid, meta.gid, meta.mode, meta.xattrs, symlink_target)
            }
            RepoMode::BareUserOnly => {
                let symlink_target = read_symlink_target(&path_fd, disk_filetype.is_symlink())?;
                (0, 0, st.st_mode, vec![], symlink_target)
            }
            RepoMode::BareSplitXAttrs => {
                let xattr_fd = self.open_object(checksum, ObjectType::FileXAttrsLink)?;
                let mut xattr_data = Vec::new();
                File::from(xattr_fd).read_to_end(&mut xattr_data)?;
                let aligned: AlignedBuf = xattr_data.into();
                let xattrs = parse_xattr_data(&aligned)?;
                let symlink_target = read_symlink_target(&path_fd, disk_filetype.is_symlink())?;
                (st.st_uid, st.st_gid, st.st_mode, xattrs, symlink_target)
            }
            RepoMode::Archive => {
                bail!("Archive mode should not use fetch_file_bare");
            }
        };

        let is_symlink = FileType::from_raw_mode(mode).is_symlink();
        let header = OstreeFileHeader {
            size: if is_symlink { 0 } else { st.st_size as u64 },
            uid,
            gid,
            mode,
            symlink_target,
            xattrs,
        };
        let zlib_header = header.serialize_zlib_sized();

        if is_symlink {
            Ok((zlib_header, Box::new(empty())))
        } else {
            Ok((zlib_header, Box::new(File::open(proc_self_fd(&path_fd))?)))
        }
    }

    async fn fetch_file_archive(
        &self,
        checksum: &Sha256Digest,
    ) -> Result<(AlignedBuf, Box<dyn Read>)> {
        let fd = self.open_object(checksum, ObjectType::File)?;
        let mut file = File::from(fd);

        let mut header_buf = AlignedBuf::new();

        // Read variant size header
        let header_size = size_of::<SizedVariantHeader>();
        header_buf.with_vec(|v| {
            v.resize(header_size, 0u8);
            file.read_exact(v)
        })?;

        // Read variant
        let variant_size = get_sized_variant_size(&header_buf)?;
        header_buf.with_vec(|v| {
            v.resize(header_size + variant_size, 0u8);
            file.read_exact(&mut v[header_size..])
        })?;

        // Decompress rest
        Ok((header_buf, Box::new(DeflateDecoder::new(file))))
    }
}

impl<ObjectID: FsVerityHashValue> OstreeRepo<ObjectID> for LocalRepo<ObjectID> {
    async fn resolve_ref(&self, ref_name: &str) -> Result<Sha256Digest> {
        self.read_ref(ref_name)
    }

    async fn fetch_object(
        &self,
        checksum: &Sha256Digest,
        object_type: ObjectType,
    ) -> Result<AlignedBuf> {
        let fd = self.open_object(checksum, object_type)?;

        let mut buffer = Vec::new();
        File::from(fd).read_to_end(&mut buffer)?;
        Ok(buffer.into())
    }

    async fn fetch_file(&self, checksum: &Sha256Digest) -> Result<(AlignedBuf, Option<ObjectID>)> {
        let (header_buf, mut rest) = if self.mode == RepoMode::Archive {
            self.fetch_file_archive(checksum).await?
        } else {
            self.fetch_file_bare(checksum).await?
        };

        let header = OstreeFileHeader::from_zlib_sized(&header_buf)?;
        hash_and_store_file(&self.repo, &header, header_buf, &mut rest, checksum)
    }
}
