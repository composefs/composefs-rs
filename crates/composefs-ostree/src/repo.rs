//! Ostree repo support

use anyhow::{Context, Error, Result, bail};
use configparser::ini::Ini;
use flate2::read::DeflateDecoder;
use gvariant::aligned_bytes::{A8, AlignedBuf, AlignedSlice};
use gvariant::{Marker, Structure, gv};
use reqwest::{Client, Url};
use rustix::fd::AsRawFd;
use rustix::fs::{FileType, Mode, OFlags, fstat, openat, readlinkat};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    future::Future,
    io::{Read, empty},
    os::fd::{AsFd, OwnedFd},
    path::Path,
    sync::Arc,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    util::{ErrnoFilter, Sha256Digest, parse_sha256},
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

#[derive(Debug, PartialEq, Copy, Clone)]
pub(crate) enum RepoMode {
    Bare,
    Archive,
    BareUser,
    BareUserOnly,
    BareSplitXAttrs,
}

#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub(crate) enum ObjectType {
    File,
    DirTree,
    DirMeta,
    Commit,
    TombstoneCommit,
    PayloadLink,
    FileXAttrs,
    FileXAttrsLink,
}

impl ObjectType {
    pub fn extension(&self, repo_mode: RepoMode) -> &'static str {
        match self {
            ObjectType::File => {
                if repo_mode == RepoMode::Archive {
                    ".filez"
                } else {
                    ".file"
                }
            }
            ObjectType::DirTree => ".dirtree",
            ObjectType::DirMeta => ".dirmeta",
            ObjectType::Commit => ".commit",
            ObjectType::TombstoneCommit => ".commit-tombstone",
            ObjectType::PayloadLink => ".payload-link",
            ObjectType::FileXAttrs => ".file-xattrs",
            ObjectType::FileXAttrsLink => ".file-xattrs-link",
        }
    }
}

impl std::str::FromStr for RepoMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<RepoMode> {
        match s {
            "bare" => Ok(RepoMode::Bare),
            "archive" | "archive-z2" => Ok(RepoMode::Archive),
            "bare-user" => Ok(RepoMode::BareUser),
            "bare-user-only" => Ok(RepoMode::BareUserOnly),
            "bare-split-xattrs" => Ok(RepoMode::BareSplitXAttrs),
            _ => Err(Error::msg(format!("Unsupported repo mode {}", s))),
        }
    }
}

fn get_object_pathname(mode: RepoMode, checksum: &Sha256Digest, object_type: ObjectType) -> String {
    format!(
        "{:02x}/{}{}",
        checksum[0],
        hex::encode(&checksum[1..]),
        object_type.extension(mode)
    )
}

fn size_prefix(data: &[u8]) -> AlignedBuf {
    let mut buf = AlignedBuf::new();
    let svh = SizedVariantHeader {
        size: u32::to_be(data.len() as u32),
        padding: 0,
    };
    buf.with_vec(|v| v.extend_from_slice(svh.as_bytes()));
    buf.with_vec(|v| v.extend_from_slice(data));
    buf
}

fn should_inline_file<ObjectID: FsVerityHashValue>(file_size: usize) -> bool {
    // We inline small files in the commit object itself, to avoid
    // wasting space storing both the digest and the separate data
    // Note: This isn't really a hard ABI like INLINE_CONTENT_MAX_V0,
    // but we also don't want to use composefs.MAX_INLINE_CONTENT as
    // that could be unnecessarily large, depending on ObjectID size.
    file_size <= size_of::<ObjectID>() * 2
}

pub(crate) fn get_sized_variant_size(data: &[u8]) -> Result<usize> {
    let variant_header_size = size_of::<SizedVariantHeader>();
    if data.len() < variant_header_size {
        bail!("Sized variant too small");
    }

    let aligned: AlignedBuf = data[0..variant_header_size].to_vec().into();
    let h = SizedVariantHeader::ref_from_bytes(&aligned)
        .map_err(|e| Error::msg(format!("Sized variant header: {:?}", e)))?;
    Ok(u32::from_be(h.size) as usize)
}

pub(crate) fn split_sized_variant(data: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    let variant_size = get_sized_variant_size(data)?;
    let header_size = size_of::<SizedVariantHeader>();
    if data.len() < header_size + variant_size {
        bail!("Sized variant too small");
    }

    let sized_data = &data[0..header_size + variant_size];
    let variant_data = &data[header_size..header_size + variant_size];
    let remaining_data = &data[header_size + variant_size..];

    Ok((sized_data, variant_data, remaining_data))
}

pub(crate) fn ostree_zlib_file_header_to_regular(zlib_header_data: &AlignedSlice<A8>) -> Vec<u8> {
    let data = gv!("(tuuuusa(ayay))").cast(zlib_header_data);
    let (_size, uid, gid, mode, zero, symlink_target, xattrs_data) = data.to_tuple();
    let mut s = Vec::<(&[u8], &[u8])>::new();
    for x in xattrs_data.iter() {
        let (key, value) = x.to_tuple();
        s.push((key, value))
    }

    gv!("(uuuusa(ayay))").serialize_to_vec(&(*uid, *gid, *mode, *zero, symlink_target.to_str(), &s))
}

/* This is how ostree stores gvariants on disk when used as a header for filez objects */
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub(crate) struct SizedVariantHeader {
    size: u32,
    padding: u32,
}

pub(crate) trait OstreeRepo<ObjectID: FsVerityHashValue> {
    fn fetch_object(
        &self,
        checksum: &Sha256Digest,
        object_type: ObjectType,
    ) -> impl Future<Output = Result<AlignedBuf>>;
    fn fetch_file(
        &self,
        checksum: &Sha256Digest,
    ) -> impl Future<Output = Result<(AlignedBuf, Option<ObjectID>)>>;
}

#[derive(Debug)]
pub(crate) struct RemoteRepo<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    client: Client,
    url: Url,
}

impl<ObjectID: FsVerityHashValue> RemoteRepo<ObjectID> {
    pub fn new(repo: &Arc<Repository<ObjectID>>, url: &str) -> Result<Self> {
        Ok(RemoteRepo {
            repo: repo.clone(),
            client: Client::new(),
            url: Url::parse(url)?,
        })
    }

    pub async fn resolve_ref(&self, ref_name: &str) -> Result<Sha256Digest> {
        // TODO: Support summary format
        let path = format!("refs/heads/{}", ref_name);
        let url = self.url.join(&path)?;

        let t = self
            .client
            .get(url.clone())
            .send()
            .await?
            .text()
            .await
            .with_context(|| format!("Cannot get ostree ref at {}", url))?;

        Ok(parse_sha256(t.trim())?)
    }
}

impl<ObjectID: FsVerityHashValue> OstreeRepo<ObjectID> for RemoteRepo<ObjectID> {
    async fn fetch_object(
        &self,
        checksum: &Sha256Digest,
        object_type: ObjectType,
    ) -> Result<AlignedBuf> {
        let path = format!(
            "objects/{}",
            get_object_pathname(RepoMode::Archive, checksum, object_type)
        );
        let url = self.url.join(&path)?;

        let response = self.client.get(url.clone()).send().await?;
        response.error_for_status_ref()?;
        let b = response
            .bytes()
            .await
            .with_context(|| format!("Cannot get ostree object at {}", url))?;

        Ok(b.to_vec().into())
    }

    async fn fetch_file(&self, checksum: &Sha256Digest) -> Result<(AlignedBuf, Option<ObjectID>)> {
        let path = format!(
            "objects/{}",
            get_object_pathname(RepoMode::Archive, checksum, ObjectType::File)
        );
        let url = self.url.join(&path)?;

        let response = self.client.get(url.clone()).send().await?;
        response.error_for_status_ref()?;

        let data = response
            .bytes()
            .await
            .with_context(|| format!("Cannot get ostree file at {}", url))?;

        let (file_header, variant_data, compressed_data) = split_sized_variant(&data)?;

        // Force align the data as there is a gvariant-rs bug (https://github.com/ostreedev/gvariant-rs/pull/9)
        let mut aligned_variant_data = AlignedBuf::new();
        aligned_variant_data.with_vec(|v| v.extend_from_slice(variant_data));

        let zlib_data = gv!("(tuuuusa(ayay))").cast(&*aligned_variant_data);
        let (file_size, ..) = zlib_data.to_tuple();
        let file_size = u64::from_be(*file_size);

        // Compute the checksum of (regular) header + data
        let mut hasher = Sha256::new();
        let regular_header = ostree_zlib_file_header_to_regular(&aligned_variant_data);
        let sized_regular_header = size_prefix(&regular_header);
        hasher.update(&*sized_regular_header);

        // Decompress rest
        let mut uncompressed = DeflateDecoder::new(compressed_data);

        let mut file_data = file_header.to_vec();
        let obj_id = if should_inline_file::<ObjectID>(file_size as usize) {
            let mut file_content = Vec::new();
            uncompressed.read_to_end(&mut file_content)?;
            hasher.update(&file_content);
            file_data.extend_from_slice(&file_content);
            None
        } else {
            let hashing_reader = HashingReader {
                inner: &mut uncompressed,
                hasher: &mut hasher,
            };
            let obj_id = self
                .repo
                .ensure_object_from_reader(hashing_reader, file_size)?;
            Some(obj_id)
        };

        let actual_checksum = hasher.finalize();
        if *actual_checksum != *checksum {
            bail!(
                "Unexpected file checksum {:?}, expected {:?}",
                actual_checksum,
                checksum
            );
        }

        Ok((file_data.into(), obj_id))
    }
}

#[derive(Debug)]
pub(crate) struct LocalRepo<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    mode: RepoMode,
    dir: OwnedFd,
    objects: OwnedFd,
}

impl<ObjectID: FsVerityHashValue> LocalRepo<ObjectID> {
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
            .map_err(Error::msg)
            .with_context(|| "Can't read config file")?;

        let core = if let Some(core_map) = map.get("core") {
            core_map
        } else {
            return Err(Error::msg("No [core] section in config"));
        };

        let mode = if let Some(Some(mode)) = core.get("mode") {
            mode.parse()?
        } else {
            return Err(Error::msg("No mode in [core] section in config"));
        };

        if mode != RepoMode::Archive && mode != RepoMode::BareUserOnly {
            return Err(Error::msg(format!("Unsupported repo mode {mode:?}")));
        }

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

    pub fn open_object_flags(
        &self,
        checksum: &Sha256Digest,
        object_type: ObjectType,
        flags: OFlags,
    ) -> Result<OwnedFd> {
        let path = get_object_pathname(self.mode, checksum, object_type);

        openat(&self.objects, &path, flags | OFlags::CLOEXEC, Mode::empty())
            .with_context(|| format!("Cannot open ostree objects object at {}", path))
    }

    pub fn open_object(&self, checksum: &Sha256Digest, object_type: ObjectType) -> Result<OwnedFd> {
        self.open_object_flags(checksum, object_type, OFlags::RDONLY | OFlags::NOFOLLOW)
    }

    pub fn read_ref(&self, ref_name: &str) -> Result<Sha256Digest> {
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

        let fd = if let Some(fd) = fd1 {
            fd
        } else {
            openat(
                &self.dir,
                &path2,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| format!("Cannot open ostree ref at {}", path2))?
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

        let filetype = FileType::from_raw_mode(st.st_mode);

        let symlink_target = if filetype.is_symlink() {
            readlinkat(&path_fd, "", [])?.into_string()?
        } else {
            String::from("")
        };

        let xattrs = Vec::<(&[u8], &[u8])>::new();

        let (uid, gid, mode) = match self.mode {
            RepoMode::Bare => {
                // TODO: Read xattrs from disk
                (st.st_uid, st.st_gid, st.st_mode)
            }
            RepoMode::BareUser => {
                // TODO: read user.ostreemeta xattr
                bail!("BareUser not supported yet")
            }
            RepoMode::BareUserOnly => (0, 0, st.st_mode),
            _ => {
                bail!("Unsupported repo mode {:?}", self.mode)
            }
        };

        let v = gv!("(tuuuusa(ayay))").serialize_to_vec(&(
            u64::to_be(st.st_size as u64),
            u32::to_be(uid),
            u32::to_be(gid),
            u32::to_be(mode),
            u32::to_be(0), // rdev
            &symlink_target,
            &xattrs,
        ));

        let zlib_header = size_prefix(&v);

        if filetype.is_symlink() {
            Ok((zlib_header, Box::new(empty())))
        } else {
            let fd_path = format!("/proc/self/fd/{}", path_fd.as_fd().as_raw_fd());
            Ok((zlib_header, Box::new(File::open(fd_path)?)))
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
        let (mut header_buf, mut rest) = if self.mode == RepoMode::Archive {
            self.fetch_file_archive(checksum).await?
        } else {
            self.fetch_file_bare(checksum).await?
        };

        // Force align the data as there is a gvariant-rs bug (https://github.com/ostreedev/gvariant-rs/pull/9)
        let mut aligned_variant_data = AlignedBuf::new();
        let header_size = size_of::<SizedVariantHeader>();
        aligned_variant_data.with_vec(|v| v.extend_from_slice(&header_buf[header_size..]));

        // Compute the checksum of (regular) header + data
        let mut hasher = Sha256::new();
        let regular_header = ostree_zlib_file_header_to_regular(&aligned_variant_data);
        let sized_regular_header = size_prefix(&regular_header);
        hasher.update(&*sized_regular_header);

        // TODO: Stream files into repo instead of reading it all
        let mut file_content = Vec::new();
        rest.read_to_end(&mut file_content)?;
        hasher.update(&file_content);

        // Ensure matching checksum
        let actual_checksum = hasher.finalize();
        if *actual_checksum != *checksum {
            bail!(
                "Unexpected file checksum {}, expected {}",
                hex::encode(actual_checksum),
                hex::encode(checksum)
            );
        }

        let obj_id = if should_inline_file::<ObjectID>(file_content.len()) {
            header_buf.with_vec(|v| v.extend_from_slice(&file_content));
            None
        } else {
            Some(self.repo.ensure_object(&file_content)?)
        };

        Ok((header_buf, obj_id))
    }
}
