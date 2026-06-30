//! Access layer for local and remote ostree repositories.
//!
//! Provides the [`OstreeRepo`] trait for fetching objects and files, with
//! concrete implementations for local filesystem repos ([`LocalRepo`]) and
//! HTTP-served repos ([`RemoteRepo`]).

use anyhow::{Context, Result, anyhow, bail};
use configparser::ini::Ini;
use flate2::read::DeflateDecoder;
use gvariant::aligned_bytes::{AlignedBuf, TryAsAligned};
use reqwest::{Client, StatusCode, Url, header};
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
use tokio::sync::OnceCell;
use tokio_stream::StreamExt;
use tokio_util::io::StreamReader;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

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

const OSTREE_SUMMARY_CONTENT_TYPE: u64 = u64::from_le_bytes(*b"osummary");

/// Fixed header for a cached summary splitstream blob.
///
/// Followed by `etag_len` bytes of ETag, `last_modified_len` bytes of
/// Last-Modified, then the raw summary gvariant data.
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
struct SummaryCacheHeader {
    etag_len: u16,
    last_modified_len: u16,
    checksum: Sha256Digest,
}

struct SummaryCacheInfo {
    etag: Option<String>,
    last_modified: Option<String>,
    checksum: Sha256Digest,
}

/// Cached summary data with lazy gvariant lookup.
struct SummaryCache {
    data: AlignedBuf,
}

impl SummaryCache {
    fn resolve_ref(&self, ref_name: &str) -> Option<Sha256Digest> {
        use gvariant::{Marker, Structure, gv};

        let aligned = self.data.try_as_aligned().ok()?;
        let summary = gv!("(a(s(taya{sv}))a{sv})").cast(aligned);
        let (refs_array, _metadata) = summary.to_tuple();

        for entry in refs_array.iter() {
            let (name, ref_data) = entry.to_tuple();
            if name.to_str() == ref_name {
                let (_commit_size, checksum_bytes, _per_ref_metadata) = ref_data.to_tuple();
                return checksum_bytes.try_into().ok();
            }
        }

        None
    }

    fn list_refs(&self) -> Result<Vec<(String, Sha256Digest)>> {
        use gvariant::{Marker, Structure, gv};

        let aligned = self
            .data
            .try_as_aligned()
            .map_err(|_| anyhow!("summary data not aligned"))?;
        let summary = gv!("(a(s(taya{sv}))a{sv})").cast(aligned);
        let (refs_array, _metadata) = summary.to_tuple();

        refs_array
            .iter()
            .map(|entry| {
                let (name, ref_data) = entry.to_tuple();
                let (_commit_size, checksum_bytes, _per_ref_metadata) = ref_data.to_tuple();
                let checksum: Sha256Digest = checksum_bytes
                    .try_into()
                    .context("invalid checksum in summary")?;
                Ok((name.to_str().to_string(), checksum))
            })
            .collect()
    }
}

/// Parsed summary index (`summary.idx`) with lazy subset lookup.
struct SummaryIndex {
    data: AlignedBuf,
}

impl SummaryIndex {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(SummaryIndex {
            data: bytes.to_vec().into(),
        })
    }

    fn lookup_checksum(&self, subset: &str) -> Result<Option<Sha256Digest>> {
        use gvariant::{Marker, Structure, gv};

        let aligned = self
            .data
            .try_as_aligned()
            .map_err(|_| anyhow!("summary index not aligned"))?;
        let index = gv!("(a{s(ayaaya{sv})}a{sv})").cast(aligned);
        let (subsummaries, _metadata) = index.to_tuple();

        for entry in subsummaries.iter() {
            let (name, info) = entry.to_tuple();
            if name.to_str() == subset {
                let (current_checksum, _history, _per_entry_metadata) = info.to_tuple();
                return Ok(Some(
                    current_checksum
                        .try_into()
                        .context("invalid subsummary checksum in index")?,
                ));
            }
        }

        Ok(None)
    }
}

fn summary_url_key(url: &Url) -> String {
    let host = url.host_str().unwrap_or("unknown");
    let path = url.path().trim_end_matches('/');
    format!("{host}{path}").replace('/', "-")
}

fn write_summary_cache<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    stream_id: &str,
    info: &SummaryCacheInfo,
    summary_data: &[u8],
) -> Result<()> {
    let etag_bytes = info.etag.as_deref().unwrap_or("").as_bytes();
    let lm_bytes = info.last_modified.as_deref().unwrap_or("").as_bytes();

    let header = SummaryCacheHeader {
        etag_len: u16::to_le(
            u16::try_from(etag_bytes.len()).context("ETag too long for cache header")?,
        ),
        last_modified_len: u16::to_le(
            u16::try_from(lm_bytes.len()).context("Last-Modified too long for cache header")?,
        ),
        checksum: info.checksum,
    };

    let mut ss = repo.create_stream(OSTREE_SUMMARY_CONTENT_TYPE)?;
    ss.write_inline(header.as_bytes());
    ss.write_inline(etag_bytes);
    ss.write_inline(lm_bytes);
    ss.write_inline(summary_data);
    repo.write_stream(ss, stream_id, None)?;
    Ok(())
}

use composefs::splitstream::SplitStreamReader;

fn read_summary_cache_header<ObjectID: FsVerityHashValue>(
    reader: &mut SplitStreamReader<ObjectID>,
) -> Result<SummaryCacheInfo> {
    let header_size = size_of::<SummaryCacheHeader>();
    let mut header_buf = vec![0u8; header_size];
    reader
        .read_inline_exact(&mut header_buf)
        .context("reading summary cache header")?;
    let header = SummaryCacheHeader::ref_from_bytes(&header_buf)
        .map_err(|e| anyhow!("summary cache header: {e:?}"))?;

    let etag_len = u16::from_le(header.etag_len) as usize;
    let last_modified_len = u16::from_le(header.last_modified_len) as usize;

    let etag = if etag_len > 0 {
        let mut buf = vec![0u8; etag_len];
        reader.read_inline_exact(&mut buf).context("reading etag")?;
        Some(
            std::str::from_utf8(&buf)
                .context("etag is not UTF-8")?
                .to_string(),
        )
    } else {
        None
    };
    let last_modified = if last_modified_len > 0 {
        let mut buf = vec![0u8; last_modified_len];
        reader
            .read_inline_exact(&mut buf)
            .context("reading last-modified")?;
        Some(
            std::str::from_utf8(&buf)
                .context("last-modified is not UTF-8")?
                .to_string(),
        )
    } else {
        None
    };

    Ok(SummaryCacheInfo {
        etag,
        last_modified,
        checksum: header.checksum,
    })
}

fn read_summary_cache_data<ObjectID: FsVerityHashValue>(
    reader: &mut SplitStreamReader<ObjectID>,
    repo: &Repository<ObjectID>,
) -> Result<SummaryCache> {
    let mut data = Vec::new();
    reader.cat(repo, &mut data)?;
    Ok(SummaryCache { data: data.into() })
}

fn open_cached_summary<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    stream_id: &str,
) -> Result<Option<SplitStreamReader<ObjectID>>> {
    if repo.has_stream(stream_id)?.is_some() {
        Ok(Some(repo.open_stream(
            stream_id,
            None,
            Some(OSTREE_SUMMARY_CONTENT_TYPE),
        )?))
    } else {
        Ok(None)
    }
}

/// Fetches ostree objects over HTTP from an archive-z2 repository.
pub struct RemoteRepo<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    client: Client,
    url: Url,
    summary_subset: String,
    summary: OnceCell<Option<SummaryCache>>,
}

impl<ObjectID: FsVerityHashValue> std::fmt::Debug for RemoteRepo<ObjectID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteRepo")
            .field("url", &self.url)
            .field("summary_subset", &self.summary_subset)
            .finish_non_exhaustive()
    }
}

impl<ObjectID: FsVerityHashValue> RemoteRepo<ObjectID> {
    /// Create a new remote ostree repo client for the given URL.
    pub fn new(repo: &Arc<Repository<ObjectID>>, url: &str) -> Result<Self> {
        Ok(RemoteRepo {
            repo: repo.clone(),
            client: Client::new(),
            url: Url::parse(url)?,
            summary_subset: std::env::consts::ARCH.to_string(),
            summary: OnceCell::new(),
        })
    }

    /// Override the summary index subset key (defaults to the system architecture).
    ///
    /// For flatpak repos this can be e.g. `"free-x86_64"` for a subset, or
    /// just `"x86_64"` for all refs on that architecture.
    pub fn with_summary_subset(mut self, subset: &str) -> Self {
        self.summary_subset = subset.to_string();
        self
    }

    /// List all refs available in the remote summary.
    ///
    /// Returns `(ref_name, commit_checksum)` pairs. Fetches and caches the
    /// summary if not already loaded.
    pub async fn list_remote_refs(&self) -> Result<Vec<(String, Sha256Digest)>> {
        let cache = self
            .load_summary()
            .await?
            .ok_or_else(|| anyhow!("no summary available from remote"))?;
        cache.list_refs()
    }

    fn url_for(&self, segments: &[&str]) -> Url {
        let mut url = self.url.clone();
        url.path_segments_mut()
            .expect("repo URL is not cannot-be-a-base")
            .pop_if_empty()
            .extend(segments);
        url
    }

    async fn load_summary(&self) -> Result<Option<&SummaryCache>> {
        let cached = self
            .summary
            .get_or_try_init(|| self.fetch_summary())
            .await?;
        Ok(cached.as_ref())
    }

    async fn fetch_summary(&self) -> Result<Option<SummaryCache>> {
        // Try the summary index first (flatpak-style repos)
        if let Some(cache) = self.try_fetch_indexed_summary().await? {
            return Ok(Some(cache));
        }
        // Fall back to plain summary with conditional HTTP
        self.fetch_plain_summary().await
    }

    async fn try_fetch_indexed_summary(&self) -> Result<Option<SummaryCache>> {
        use flate2::read::GzDecoder;

        let url = self.url_for(&["summary.idx"]);
        let response = match self.client.get(url).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => return Ok(None),
        };

        let index_bytes = response.bytes().await?;
        let index = SummaryIndex::from_bytes(&index_bytes)?;

        let checksum = match index.lookup_checksum(&self.summary_subset)? {
            Some(c) => c,
            None => return Ok(None),
        };

        let url_key = summary_url_key(&self.url);
        let stream_id = format!("ostree-subsummary-{}-{url_key}", self.summary_subset);

        // Check if we have a cached subsummary with a matching checksum
        if let Some(mut reader) = open_cached_summary(&self.repo, &stream_id)?
            && let Ok(info) = read_summary_cache_header(&mut reader)
            && info.checksum == checksum
        {
            return Ok(Some(read_summary_cache_data(&mut reader, &self.repo)?));
        }

        // Fetch the new subsummary (gzipped)
        let checksum_hex = hex::encode(checksum);
        let filename = format!("{checksum_hex}.gz");
        let sub_url = self.url_for(&["summaries", &filename]);
        let response = self
            .client
            .get(sub_url.clone())
            .send()
            .await
            .with_context(|| format!("Fetching subsummary from {sub_url}"))?;
        response
            .error_for_status_ref()
            .with_context(|| format!("Fetching subsummary from {sub_url}"))?;

        let compressed = response
            .bytes()
            .await
            .with_context(|| format!("Reading subsummary from {sub_url}"))?;

        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut summary_data = Vec::new();
        decoder
            .read_to_end(&mut summary_data)
            .context("Decompressing subsummary")?;

        let actual = Sha256::digest(&summary_data);
        if *actual != checksum {
            bail!(
                "subsummary checksum mismatch: expected {}, got {}",
                checksum_hex,
                hex::encode(actual)
            );
        }

        let info = SummaryCacheInfo {
            etag: None,
            last_modified: None,
            checksum,
        };
        write_summary_cache(&self.repo, &stream_id, &info, &summary_data)?;

        Ok(Some(SummaryCache {
            data: summary_data.into(),
        }))
    }

    async fn fetch_plain_summary(&self) -> Result<Option<SummaryCache>> {
        let url_key = summary_url_key(&self.url);
        let stream_id = format!("ostree-summary-{url_key}");
        let url = self.url_for(&["summary"]);

        // Read cached header for conditional HTTP (without reading the summary data)
        let mut cached_reader = open_cached_summary(&self.repo, &stream_id)?;
        let cached_info = cached_reader
            .as_mut()
            .and_then(|r| read_summary_cache_header(r).ok());

        let mut request = self.client.get(url.clone());
        if let Some(ref info) = cached_info {
            if let Some(ref etag) = info.etag {
                request = request.header(header::IF_NONE_MATCH, etag.as_str());
            } else if let Some(ref lm) = info.last_modified {
                request = request.header(header::IF_MODIFIED_SINCE, lm.as_str());
            }
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("Fetching summary from {url}"))?;

        if response.status() == StatusCode::NOT_MODIFIED
            && let Some(mut reader) = cached_reader
        {
            return Ok(Some(read_summary_cache_data(&mut reader, &self.repo)?));
        }

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        response
            .error_for_status_ref()
            .with_context(|| format!("Fetching summary from {url}"))?;

        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let last_modified = response
            .headers()
            .get(header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let summary_data = response
            .bytes()
            .await
            .with_context(|| format!("Reading summary from {url}"))?;

        let data_checksum: Sha256Digest = Sha256::digest(&summary_data).into();
        let info = SummaryCacheInfo {
            etag,
            last_modified,
            checksum: data_checksum,
        };
        write_summary_cache(&self.repo, &stream_id, &info, &summary_data)?;

        Ok(Some(SummaryCache {
            data: summary_data.to_vec().into(),
        }))
    }
}

impl<ObjectID: FsVerityHashValue> OstreeRepo<ObjectID> for RemoteRepo<ObjectID> {
    async fn resolve_ref(&self, ref_name: &str) -> Result<Sha256Digest> {
        if let Some(cache) = self.load_summary().await?
            && let Some(checksum) = cache.resolve_ref(ref_name)
        {
            return Ok(checksum);
        }

        // Fall back to direct ref file fetch (for repos without summaries)
        let url = self.url_for(&["refs", "heads", ref_name]);
        let response = self.client.get(url.clone()).send().await?;
        response.error_for_status_ref()?;
        let t = response
            .text()
            .await
            .with_context(|| format!("Cannot get ostree ref at {url}"))?;
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
