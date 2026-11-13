use std::io::{Seek, SeekFrom};
use std::os::fd::AsFd;

use composefs_splitdirfdstream::{SplitDirFdStream, SplitdirfdstreamWriter, build_layer_fd_layout};

use super::*;

#[tokio::test]
async fn splitdirfd_layers_preserve_payloads_and_reject_invalid_sources() {
    let payload = vec![57; 128 * 1024 + 1];
    let tar = tar_bytes(&payload, false);
    for mode in [
        "metadata",
        "inline",
        "file",
        "index",
        "path",
        "length",
        "digest",
        "truncated",
        "fifo",
    ] {
        let (temp, writer) = store().await;
        let source = temp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("payload"), &payload).unwrap();
        let source = Dir::open_ambient_dir(&source, ambient_authority()).unwrap();
        let mut data = tempfile::tempfile().unwrap();
        let layout = build_layer_fd_layout(
            data.try_clone().unwrap().into(),
            vec![rustix::io::dup(source.as_fd()).unwrap()],
            123,
        )
        .unwrap();
        let mut encoded = SplitdirfdstreamWriter::new(Vec::new());
        // Empty inline bodies are legal and must not look like EOF.
        encoded.write_inline_data(&[]).unwrap();
        match mode {
            "metadata" | "truncated" => encoded.write_metadata(&tar).unwrap(),
            "inline" => encoded.write_inline_data(&tar).unwrap(),
            _ => {
                encoded.write_metadata(&tar[..1024]).unwrap();
                encoded
                    .write_file_backed_data(
                        if mode == "index" {
                            layout.dir_count
                        } else {
                            layout.real_indices[0]
                        },
                        payload.len() as u64 - u64::from(mode == "length"),
                        b"payload",
                    )
                    .unwrap();
                encoded
                    .write_metadata(&tar[1024 + payload.len()..])
                    .unwrap();
            }
        }
        let mut encoded = encoded.finish().unwrap();
        if mode == "path" {
            let name = encoded
                .windows(7)
                .rposition(|bytes| bytes == b"payload")
                .unwrap();
            encoded[name..name + 7].copy_from_slice(b"../evil");
        }
        if mode == "digest" {
            source.write("payload", vec![58; payload.len()]).unwrap();
        }
        if mode == "fifo" {
            source.remove_file("payload").unwrap();
            rustix::fs::mkfifoat(&source, "payload", rustix::fs::Mode::RUSR).unwrap();
        }
        if mode == "truncated" {
            encoded.pop();
        }
        data.write_all(&encoded).unwrap();
        data.seek(SeekFrom::Start(0)).unwrap();
        drop(data);
        let stream = SplitDirFdStream::from_fds(layout.dir_count, layout.fds_all).unwrap();
        let mut import = writer
            .begin_image(image(&[&tar]), Default::default())
            .await
            .unwrap();
        let result = import.put_layer_stream(0, stream).await;
        // The consumer releases lifetime FDs on success and on errors.
        assert_eq!(
            rustix::io::read(&layout.keepalive_read, &mut [0]).unwrap(),
            0
        );
        match mode {
            "metadata" | "inline" | "file" => {
                let layer = result.unwrap();
                assert_eq!(layer.diff_id.as_ref(), records::digest(&tar));
                let diff = temp
                    .path()
                    .join("graph/overlay")
                    .join(&layer.storage_layer_id)
                    .join("diff");
                assert_eq!(std::fs::read(diff.join("payload")).unwrap(), payload);
                if mode == "file" {
                    assert_eq!(
                        layer.stats.reflinked_bytes + layer.stats.copied_bytes,
                        payload.len() as u64
                    );
                    assert_eq!(layer.stats.inline_bytes, 0);
                } else {
                    assert_eq!(layer.stats.inline_bytes, payload.len() as u64);
                }
            }
            _ => {
                let ImportError::Layer { source, .. } = result.unwrap_err() else {
                    panic!("expected a layer error for {mode}");
                };
                match (mode, *source) {
                    (
                        "index",
                        ImportError::SplitDirFd(
                            composefs_splitdirfdstream::Error::DirfdIndexOutOfRange { .. },
                        ),
                    )
                    | (
                        "path",
                        ImportError::SplitDirFd(
                            composefs_splitdirfdstream::Error::InvalidFilename { .. },
                        ),
                    )
                    | (
                        "truncated",
                        ImportError::SplitDirFd(composefs_splitdirfdstream::Error::Truncated {
                            ..
                        }),
                    )
                    | ("digest", ImportError::DigestMismatch { .. }) => {}
                    ("length", ImportError::Malformed(message)) => {
                        assert_eq!(message, "file reference and tar size disagree")
                    }
                    ("fifo", ImportError::Malformed(message)) => {
                        assert_eq!(
                            message,
                            "file reference is not a regular file of the declared length"
                        )
                    }
                    (_, error) => panic!("unexpected {mode} error: {error}"),
                }
                let layers: Vec<Value> = serde_json::from_slice(
                    &std::fs::read(temp.path().join("graph/overlay-layers/layers.json")).unwrap(),
                )
                .unwrap();
                assert!(layers.is_empty(), "failed {mode} layer retained a record");
                assert!(
                    !temp
                        .path()
                        .join("graph/overlay-images/images.json")
                        .exists()
                );
            }
        }
        import.abort().await.unwrap();
    }
}
