//! Shared layer import logic for OCI container images.
//!
//! This module provides common functionality for importing OCI image layers
//! into a composefs repository, shared between the skopeo proxy path and
//! direct OCI layout import.

use std::sync::Arc;

use anyhow::{bail, Result};
use async_compression::tokio::bufread::{GzipDecoder, ZstdDecoder};
use oci_spec::image::MediaType;
use tokio::io::{AsyncRead, AsyncWriteExt, BufReader};

use composefs::fsverity::FsVerityHashValue;
use composefs::repository::{ObjectStoreMethod, Repository};
use composefs::shared_internals::IO_BUF_CAPACITY;

use crate::skopeo::TAR_LAYER_CONTENT_TYPE;
use crate::tar::split_async;

/// Check if a media type represents a tar-based layer.
pub fn is_tar_media_type(media_type: &MediaType) -> bool {
    matches!(
        media_type,
        MediaType::ImageLayer
            | MediaType::ImageLayerGzip
            | MediaType::ImageLayerZstd
            | MediaType::ImageLayerNonDistributable
            | MediaType::ImageLayerNonDistributableGzip
            | MediaType::ImageLayerNonDistributableZstd
    )
}

/// Wrap an async reader with the appropriate decompressor for the media type.
///
/// Returns a boxed reader that decompresses the stream if needed.
/// The output is `AsyncRead` (not `AsyncBufRead`) because `split_async`
/// does its own buffering via `BytesMut`.
pub fn decompress_async<'a, R>(
    reader: R,
    media_type: &MediaType,
) -> Result<Box<dyn AsyncRead + Unpin + Send + 'a>>
where
    R: AsyncRead + Unpin + Send + 'a,
{
    let buf = BufReader::new(reader);
    let reader: Box<dyn AsyncRead + Unpin + Send> = match media_type {
        MediaType::ImageLayer | MediaType::ImageLayerNonDistributable => {
            Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, buf))
        }
        MediaType::ImageLayerGzip | MediaType::ImageLayerNonDistributableGzip => Box::new(
            BufReader::with_capacity(IO_BUF_CAPACITY, GzipDecoder::new(buf)),
        ),
        MediaType::ImageLayerZstd | MediaType::ImageLayerNonDistributableZstd => Box::new(
            BufReader::with_capacity(IO_BUF_CAPACITY, ZstdDecoder::new(buf)),
        ),
        _ => bail!("Unsupported layer media type for decompression: {media_type}"),
    };
    Ok(reader)
}

/// Import a tar layer from an async reader into the repository.
///
/// The reader should already be decompressed (use `decompress_async` first).
/// Returns the fs-verity object ID and import stats of the imported splitstream.
pub async fn import_tar_async<ObjectID, R>(
    repo: Arc<Repository<ObjectID>>,
    reader: R,
) -> Result<(ObjectID, crate::ImportStats)>
where
    ObjectID: FsVerityHashValue,
    R: AsyncRead + Unpin + Send,
{
    split_async(reader, repo, TAR_LAYER_CONTENT_TYPE).await
}

/// Store raw bytes from an async reader as a repository object.
///
/// Streams the raw bytes into a repository object without creating a splitstream.
/// Use this for non-tar blobs (OCI artifacts) where the caller will create
/// the splitstream wrapper.
///
/// Returns (object_id, size, store_method) of the stored object.
pub async fn store_blob_async<ObjectID, R>(
    repo: &Repository<ObjectID>,
    mut reader: R,
) -> Result<(ObjectID, u64, ObjectStoreMethod)>
where
    ObjectID: FsVerityHashValue,
    R: AsyncRead + Unpin,
{
    let tmpfile = repo.create_object_tmpfile()?;
    let mut writer = tokio::fs::File::from(std::fs::File::from(tmpfile));
    let size = tokio::io::copy(&mut reader, &mut writer).await?;
    writer.flush().await?;
    let tmpfile = writer.into_std().await;
    let (object_id, method) = repo.finalize_object_tmpfile(tmpfile, size)?;
    Ok((object_id, size, method))
}
