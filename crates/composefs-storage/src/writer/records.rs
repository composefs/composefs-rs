//! Reading and updating containers/storage metadata records.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD};
use cap_std::fs::Dir;
use oci_spec::image::{Descriptor, ImageConfiguration, ImageManifest, MediaType};
use rustix::fs::{Mode, OFlags};
use serde_json::Value;

use super::*;

mod model;
pub(super) use model::{
    ContainerRecord, ImageRecord, LayerFlags, LayerRecord, MountRecord, Record,
};

#[cfg(test)]
mod tests;

pub(super) const REGULAR: u32 = 0o100000;
pub(super) const DIRECTORY: u32 = 0o040000;
pub(super) const SHA256_HEX_LENGTH: usize = 64;
// containers/storage/{layers,images}.go use owner-only metadata directories and
// JSON/tar-split files. Extraction also starts with owner-only permissions.
pub(super) const PRIVATE_DIR_MODE: u32 = 0o700;
pub(super) const PRIVATE_FILE_MODE: u32 = 0o600;
// containers/storage/drivers/overlay/overlay.go creates searchable scaffolding
// and readable link files. Implicit tar parents also use the usual 0755 default.
pub(super) const DEFAULT_DIR_MODE: u32 = 0o755;
pub(super) const CONTROL_FILE_MODE: u32 = 0o644;
const RECORD_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct ValidatedImage {
    pub raw: RawImage,
    pub config_digest: OciDigest,
    pub id: String,
    pub diff_ids: Vec<OciDigest>,
    pub layer_descriptors: Vec<oci_spec::image::Descriptor>,
    pub created: String,
}

impl ValidatedImage {
    pub fn new(raw: RawImage) -> Result<Self> {
        let manifest = validate_manifest(&raw.manifest_json, &raw.expected_manifest)?;
        let config = validate_config(&raw.config_json, manifest.config())?;
        let config_digest = manifest.config().digest().clone();
        let id = config_digest.digest().to_owned();
        let diff_ids = validate_layer_descriptors(manifest.layers(), config.rootfs().diff_ids())?;
        for history in config.history().iter().flatten() {
            if let Some(created) = history.created() {
                go_time(created)?;
            }
        }
        let created = match config.created() {
            Some(value) => {
                let parsed = go_time(value)?;
                parsed.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
            }
            None => now(),
        };
        Ok(Self {
            raw,
            config_digest,
            id,
            diff_ids,
            layer_descriptors: manifest.layers().clone(),
            created,
        })
    }

    pub fn uncompressed_size(&self, index: usize) -> Option<u64> {
        let descriptor = &self.layer_descriptors[index];
        (descriptor.media_type() == &oci_spec::image::MediaType::ImageLayer)
            .then_some(descriptor.size())
    }
}

fn validate_manifest(bytes: &[u8], expected: &OciDigest) -> Result<ImageManifest> {
    digest_hex(expected)?;
    check_digest("manifest", expected, &digest(bytes))?;
    let manifest: ImageManifest = serde_json::from_slice(bytes)?;
    if manifest.schema_version() != 2
        || manifest.media_type() != &Some(MediaType::ImageManifest)
        || manifest.config().media_type() != &MediaType::ImageConfig
    {
        return Err(ImportError::Malformed(
            "requires a single-platform OCI image manifest and config".into(),
        ));
    }
    let value: Value = serde_json::from_slice(bytes)?;
    if value.get("artifactType").is_some() || value.get("subject").is_some() {
        return Err(ImportError::Malformed(
            "artifacts and referrers are not supported".into(),
        ));
    }
    Ok(manifest)
}

fn validate_config(bytes: &[u8], descriptor: &Descriptor) -> Result<ImageConfiguration> {
    digest_hex(descriptor.digest())?;
    check_digest("config", descriptor.digest(), &digest(bytes))?;
    if descriptor.size() != bytes.len() as u64 {
        return Err(ImportError::Malformed(
            "config descriptor size mismatch".into(),
        ));
    }
    let config: ImageConfiguration = serde_json::from_slice(bytes)?;
    if config.os().to_string() != "linux" || config.rootfs().typ() != "layers" {
        return Err(ImportError::Malformed(
            "requires a Linux layered image config".into(),
        ));
    }
    Ok(config)
}

fn validate_layer_descriptors(
    layers: &[Descriptor],
    diff_ids: &[String],
) -> Result<Vec<OciDigest>> {
    let diff_ids = diff_ids
        .iter()
        .map(|s| {
            let d = s
                .parse::<OciDigest>()
                .map_err(|e| ImportError::Malformed(e.to_string()))?;
            digest_hex(&d)?;
            Ok(d)
        })
        .collect::<Result<Vec<_>>>()?;
    if diff_ids.len() != layers.len() || diff_ids.len() > overlay::MAX_IMAGE_LAYERS {
        return Err(ImportError::Malformed(format!(
            "layer/config count mismatch or overlay depth exceeds {}",
            overlay::MAX_IMAGE_LAYERS
        )));
    }
    for (layer, diff) in layers.iter().zip(&diff_ids) {
        digest_hex(layer.digest())?;
        if !matches!(
            layer.media_type().to_string().as_str(),
            "application/vnd.oci.image.layer.v1.tar"
                | "application/vnd.oci.image.layer.v1.tar+gzip"
                | "application/vnd.oci.image.layer.v1.tar+zstd"
        ) {
            return Err(ImportError::Malformed(format!(
                "unsupported layer descriptor: {}",
                layer.media_type()
            )));
        }
        if layer.media_type() == &MediaType::ImageLayer {
            check_digest(
                "uncompressed layer descriptor",
                diff,
                layer.digest().as_ref(),
            )?;
        }
    }
    Ok(diff_ids)
}

fn go_time(value: &str) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|e| ImportError::Malformed(format!("invalid OCI creation time: {e}")))?;
    // Both images.json and Go's OCI-config decoder use time.Time. Keep the
    // raw OCI bytes, and reject spellings accepted only by chrono.
    if value.as_bytes().get(10) != Some(&b'T')
        || value.ends_with('z')
        || parsed.timestamp_subsec_nanos() >= 1_000_000_000
    {
        return Err(ImportError::Malformed(
            "OCI creation time is not Go-compatible RFC3339".into(),
        ));
    }
    Ok(parsed)
}

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(openssl::sha::sha256(bytes)))
}

pub(super) fn digest_hex(digest: &OciDigest) -> Result<&str> {
    let s: &str = digest.as_ref();
    let hex = s.strip_prefix("sha256:").filter(|s| {
        s.len() == SHA256_HEX_LENGTH
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    });
    hex.ok_or_else(|| {
        ImportError::Malformed(format!("requires a lowercase SHA-256 OCI digest: {s}"))
    })
}

pub(super) fn check_digest(kind: &'static str, expected: &OciDigest, actual: &str) -> Result<()> {
    if expected.as_ref() != actual {
        return Err(ImportError::DigestMismatch {
            kind,
            expected: expected.to_string(),
            actual: actual.into(),
        });
    }
    Ok(())
}

pub(super) fn random_id() -> Result<String> {
    let mut bytes = [0u8; 32];
    openssl::rand::rand_bytes(&mut bytes).map_err(std::io::Error::other)?;
    Ok(hex::encode(bytes))
}

/// Match containers/image/storage/storage_dest.go:layerID for full layer blobs.
pub(super) fn layer_id(parent: &str, diff_id: &OciDigest) -> String {
    if parent.is_empty() {
        diff_id.digest().to_owned()
    } else {
        hex::encode(openssl::sha::sha256(
            format!("{parent}+{}", diff_id.digest()).as_bytes(),
        ))
    }
}

pub(super) fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

pub(super) fn safe_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id == "."
        || id == ".."
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(ImportError::RecoveryRequired(format!(
            "unsafe storage ID {id:?}"
        )));
    }
    Ok(())
}

pub(super) fn find_by_id<'a, T: Record>(records: &'a [T], id: &str) -> Option<&'a T> {
    records.iter().find(|record| record.id() == id)
}

pub(super) fn find_by_id_mut<'a, T: Record>(records: &'a mut [T], id: &str) -> Option<&'a mut T> {
    records.iter_mut().find(|record| record.id() == id)
}

/// Treat a missing filesystem entry as None, preserving every other error.
pub(super) fn allow_missing<T, E: Into<ImportError>>(
    result: std::result::Result<T, E>,
) -> Result<Option<T>> {
    match result.map_err(Into::into) {
        Ok(value) => Ok(Some(value)),
        Err(ImportError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub(super) fn records<T: Record>(dir: &Dir, name: &str) -> Result<Vec<T>> {
    let Some(mut file) = allow_missing(dir.open(name))? else {
        return Ok(Vec::new());
    };
    if file.metadata()?.len() > RECORD_LIMIT {
        return Err(ImportError::UnsupportedStore(format!(
            "{name} exceeds record size limit"
        )));
    }
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    parse_records(&data, name)
}

fn parse_records<T: Record>(data: &[u8], name: &str) -> Result<Vec<T>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let records: Vec<T> = serde_json::from_slice(data).map_err(|error: serde_json::Error| {
        if error.is_data() {
            ImportError::RecoveryRequired(format!("invalid record in {name}: {error}"))
        } else {
            error.into()
        }
    })?;
    let mut ids = std::collections::HashSet::new();
    for record in &records {
        let id = record.id();
        safe_id(id)?;
        if !ids.insert(id) {
            return Err(ImportError::RecoveryRequired(format!(
                "invalid or duplicate record in {name}"
            )));
        }
    }
    Ok(records)
}

/// Read metadata files from a store directory that may not have been created.
pub(super) fn records_in<T: Record>(root: &Dir, path: &str, names: &[&str]) -> Result<Vec<T>> {
    let Some(dir) = allow_missing(open_dir(root, Path::new(path)))? else {
        return Ok(Vec::new());
    };
    let mut values = Vec::new();
    for name in names {
        values.extend(records(&dir, name)?);
    }
    Ok(values)
}

pub(super) fn sync_dir(dir: &Dir) -> Result<()> {
    // A caller-supplied cap-std directory may use O_PATH, which cannot fsync.
    let readable = open_dir(dir, Path::new("."))?;
    rustix::fs::fsync(&readable)?;
    Ok(())
}

/// Flush directory changes on a worker, accepting caller handles that use O_PATH.
pub(super) async fn sync_dir_async(dir: &Dir) -> Result<()> {
    let dir = dir.try_clone()?;
    // Writes have already happened; keep the flush queued if its waiter is dropped.
    tokio::task::spawn_blocking(move || sync_dir(&dir)).await?
}

pub(super) fn open_dir(dir: &Dir, path: &Path) -> Result<Dir> {
    let fd = rustix::fs::openat(
        dir,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(Dir::from_std_file(fd.into()))
}

/// Create a directory; callers provide transaction durability barriers.
pub(super) fn create_dir(dir: &Dir, name: impl AsRef<Path>, mode: u32) -> Result<Dir> {
    let name = name.as_ref();
    rustix::fs::mkdirat(dir, name, Mode::from_bits_truncate(mode))?;
    let child = open_dir(dir, name)?;
    rustix::fs::fchmod(&child, Mode::from_bits_truncate(mode))?;
    Ok(child)
}

pub(super) fn atomic_write(dir: &Dir, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let temp = format!(".tmp-{}", random_id()?);
    let result = (|| {
        let fd = rustix::fs::openat(
            dir,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(mode),
        )?;
        let mut file = File::from(fd);
        file.write_all(bytes)?;
        rustix::fs::fchmod(&file, Mode::from_bits_truncate(mode))?;
        file.sync_all()?;
        dir.rename(&temp, dir, name)?;
        sync_dir(dir)
    })();
    if result.is_err()
        && let Err(error) = allow_missing(dir.remove_file(&temp))
    {
        tracing::warn!(%error, "removing unpublished metadata file");
    }
    result
}

/// Replace metadata on a worker, retaining its owner until the write finishes.
pub(super) async fn atomic_write_async<T: Send + 'static>(
    dir: Dir,
    name: String,
    bytes: Vec<u8>,
    mode: u32,
    owner: T,
) -> Result<T> {
    tokio::task::spawn_blocking(move || {
        atomic_write(&dir, &name, &bytes, mode)?;
        Ok(owner)
    })
    .await?
}

pub(super) fn big_data_name(key: &str) -> String {
    if key
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.')
    {
        key.into()
    } else {
        format!("={}", STANDARD.encode(key))
    }
}
