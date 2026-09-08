//! Shared layer import logic for OCI container images.
//!
//! This module provides common functionality for importing OCI image layers
//! into a composefs repository, shared between the skopeo proxy path and
//! direct OCI layout import.

use std::sync::Arc;

use anyhow::{Result, bail};
use async_compression::tokio::bufread::{GzipDecoder, ZstdDecoder};
use containers_image_proxy::oci_spec::image::MediaType;
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
        MediaType::ImageLayerGzip | MediaType::ImageLayerNonDistributableGzip => {
            let mut decoder = GzipDecoder::new(buf);
            // Gzip layers may concatenate multiple members; keep decoding past
            // the first member boundary instead of truncating there
            // (bootc-dev/bootc#2408).
            decoder.multiple_members(true);
            Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, decoder))
        }
        MediaType::ImageLayerZstd | MediaType::ImageLayerNonDistributableZstd => {
            let mut decoder = ZstdDecoder::new(buf);
            // zstd:chunked layers are multi-frame streams with interleaved
            // skippable frames (bootc-dev/bootc#2408); keep decoding past the
            // first frame boundary instead of truncating there. Decoding
            // multiple members requires async-compression >= 0.4.43, which
            // fixed a hang on a corrupt later frame
            // (Nullus157/async-compression#470).
            decoder.multiple_members(true);
            Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, decoder))
        }
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

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write as _};

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tokio::io::AsyncReadExt as _;

    use super::*;

    /// Zstd skippable-frame magic numbers span 0x184D2A50..=0x184D2A5F (RFC 8878 §3.1.2).
    const ZSTD_SKIPPABLE_MAGIC: u32 = 0x184D2A50;

    /// Encode `data` as a standalone zstd frame.
    fn zstd_frame(data: &[u8]) -> Vec<u8> {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Build a zstd skippable frame (magic + LE size + payload) wrapping `payload`.
    fn zstd_skippable_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(8 + payload.len());
        frame.extend_from_slice(&ZSTD_SKIPPABLE_MAGIC.to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// Encode `data` as a standalone gzip member.
    fn gzip_member(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Run `compressed` through `decompress_async` for `media_type` and collect the output.
    async fn decompress_to_vec(media_type: MediaType, compressed: Vec<u8>) -> Vec<u8> {
        let mut reader = decompress_async(Cursor::new(compressed), &media_type).unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn multi_member_streams_decode_fully() {
        // Skippable frames at the start, between real frames, and trailing
        // must not perturb the decoded output.
        let mut zstd_with_skippable = zstd_skippable_frame(b"leading skippable junk");
        zstd_with_skippable.extend(zstd_frame(b"first "));
        zstd_with_skippable.extend(zstd_skippable_frame(b"between-frame skippable junk"));
        zstd_with_skippable.extend(zstd_frame(b"second"));
        zstd_with_skippable.extend(zstd_skippable_frame(b"trailing skippable junk"));

        let cases: &[(&str, MediaType, Vec<u8>, &[u8])] = &[
            (
                "zstd multi-frame concatenation",
                MediaType::ImageLayerZstd,
                [
                    zstd_frame(b"first frame content, "),
                    zstd_frame(b"second frame content"),
                ]
                .concat(),
                b"first frame content, second frame content",
            ),
            (
                "zstd skippable frames at start, between, and trailing",
                MediaType::ImageLayerZstd,
                zstd_with_skippable,
                b"first second",
            ),
            (
                "gzip multi-member concatenation",
                MediaType::ImageLayerGzip,
                [
                    gzip_member(b"first member content, "),
                    gzip_member(b"second member content"),
                ]
                .concat(),
                b"first member content, second member content",
            ),
        ];

        for (name, media_type, compressed, expected) in cases {
            let out = decompress_to_vec(media_type.clone(), compressed.clone()).await;
            assert_eq!(out.as_slice(), *expected, "case: {name}");
        }
    }

    #[tokio::test]
    async fn corrupt_second_zstd_frame_errors_promptly() {
        // async-compression < 0.4.43 could loop forever on a corrupt later
        // frame with multiple_members enabled
        // (Nullus157/async-compression#470); the Cargo.toml floor plus this
        // test pin the fixed behavior.
        let mut compressed = zstd_frame(b"valid first frame");
        compressed.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]); // zstd magic...
        compressed.extend_from_slice(&[0xff; 32]); // ...then garbage

        let mut reader =
            decompress_async(Cursor::new(compressed), &MediaType::ImageLayerZstd).unwrap();
        let mut out = Vec::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            reader.read_to_end(&mut out),
        )
        .await
        .expect("decoding a corrupt frame must fail promptly, not hang");
        assert!(
            read.is_err(),
            "corrupt second frame must error, got {read:?}"
        );
    }
}
