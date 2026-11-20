use std::cell::Cell;
use std::io::{Seek, SeekFrom};

use composefs_splitdirfdstream::{SplitDirFdStream, SplitdirfdstreamWriter};

use super::*;

// A descriptor-only source, with no repository or completion future. Mutable
// protocol state need only be Send, not Sync, as for a remote connection.
struct Source {
    raw: RawImage,
    data: Vec<u8>,
    requested: Cell<usize>,
    request_error: bool,
    truncate: bool,
}

impl ImageSource for Source {
    type Error = std::io::Error;

    fn manifest_digest(&self) -> &str {
        self.raw.expected_manifest.as_ref()
    }

    fn manifest_json(&self) -> &[u8] {
        &self.raw.manifest_json
    }

    fn config_json(&self) -> &[u8] {
        &self.raw.config_json
    }

    async fn get_layer(&mut self, index: usize) -> std::io::Result<SplitDirFdStream> {
        assert_eq!(index, 0);
        self.requested.set(self.requested.get() + 1);
        if self.request_error {
            return Err(std::io::Error::other("source request failed"));
        }
        let mut writer = SplitdirfdstreamWriter::new(Vec::new());
        writer.write_metadata(&self.data).unwrap();
        let mut encoded = writer.finish().unwrap();
        if self.truncate {
            encoded.pop();
        }
        let mut file = tempfile::tempfile()?;
        file.write_all(&encoded)?;
        file.seek(SeekFrom::Start(0))?;
        SplitDirFdStream::from_fds(
            0,
            vec![file.into(), composefs_splitdirfdstream::open_devnull()?],
        )
    }
}

#[tokio::test]
async fn image_import_preserves_manifest_bytes_without_media_type() {
    let temp = TempDir::new().unwrap();
    let root = Dir::open_ambient_dir(temp.path(), ambient_authority()).unwrap();
    let tar = tar_bytes(b"payload", false);
    let mut raw = image(&[&tar]);
    let mut manifest: Value = serde_json::from_slice(&raw.manifest_json).unwrap();
    manifest.as_object_mut().unwrap().remove("mediaType");
    manifest["extension"] = json!({"preserved": true});
    // Unknown fields and whitespace must survive publication as well.
    raw.manifest_json = serde_json::to_vec_pretty(&manifest).unwrap();
    raw.manifest_json.push(b'\n');
    raw.expected_manifest = records::digest(&raw.manifest_json).parse().unwrap();
    let expected = raw.expected_manifest.clone();
    let original = raw.manifest_json.clone();
    let name = format!("localhost/image@{expected}");
    let mut source = Source {
        raw,
        data: tar,
        requested: Cell::new(0),
        request_error: false,
        truncate: false,
    };
    let published = import_image(
        &mut source,
        store_location(&root, "graph", &root, "run"),
        std::slice::from_ref(&name),
        Default::default(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(published.manifest_digest, expected);
    assert_eq!(source.requested.get(), 1);
    let images_path = temp.path().join("graph/overlay-images");
    let data = images_path.join(&published.image_id);
    for key in ["manifest".to_owned(), format!("manifest-{expected}")] {
        assert_eq!(
            std::fs::read(data.join(records::big_data_name(&key))).unwrap(),
            original
        );
    }
    let images: Vec<Value> =
        serde_json::from_slice(&std::fs::read(images_path.join("images.json")).unwrap()).unwrap();
    assert_eq!(images[0]["digest"], expected.to_string());
    assert_eq!(images[0]["names"], json!([name]));
    assert_eq!(
        images[0]["big-data-digests"]["manifest"],
        expected.to_string()
    );
}

#[tokio::test]
async fn invalid_names_are_rejected_before_creating_the_store_or_requesting_layers() {
    let tar = tar_bytes(b"payload", false);
    for name in [
        "image".into(),
        "image:latest".into(),
        "localhost/image".into(),
        "docker.io/image:latest".into(),
        format!("localhost/image@{}", records::digest(b"unrelated manifest")),
    ] {
        let temp = TempDir::new().unwrap();
        let root = Dir::open_ambient_dir(temp.path(), ambient_authority()).unwrap();
        let mut source = Source {
            raw: image(&[&tar]),
            data: tar.clone(),
            requested: Cell::new(0),
            request_error: false,
            truncate: false,
        };
        let error = import_image(
            &mut source,
            store_location(&root, "graph", &root, "run"),
            &["localhost/image:valid".into(), name.clone()],
            Default::default(),
            None,
        )
        .await
        .unwrap_err();
        if name.contains('@') {
            assert!(matches!(
                error,
                ImportError::DigestMismatch {
                    kind: "image name manifest digest",
                    ..
                }
            ));
        } else {
            assert!(
                matches!(error, ImportError::Malformed(message) if message.contains("must be fully qualified"))
            );
        }
        assert_eq!(source.requested.get(), 0);
        assert!(!temp.path().join("graph").exists());
        assert!(!temp.path().join("run").exists());
    }
}

#[tokio::test]
async fn publication_checks_names_and_preserves_matching_digest_references() {
    let (temp, writer) = store().await;
    let tar = tar_bytes(b"payload", false);
    let raw = image(&[&tar]);
    let manifest = raw.expected_manifest.clone();
    let mut import = writer.begin_image(raw, Default::default()).await.unwrap();
    import
        .put_layer(0, TarSource(Cursor::new(tar.clone())))
        .await
        .unwrap();
    import
        .prepare_publication()
        .await
        .unwrap()
        .finish(&["localhost/image:original".into()])
        .await
        .unwrap();

    let images_path = temp.path().join("graph/overlay-images/images.json");
    let original = std::fs::read(&images_path).unwrap();
    for name in [
        "image:latest".into(),
        format!("localhost/image@{}", records::digest(b"unrelated manifest")),
    ] {
        let mut import = writer
            .begin_image(image(&[&tar]), Default::default())
            .await
            .unwrap();
        assert!(matches!(
            import.layer_status(0).unwrap(),
            LayerStatus::Reusable(_)
        ));
        let error = import
            .prepare_publication()
            .await
            .unwrap()
            .finish(&["localhost/image:valid".into(), name.clone()])
            .await
            .unwrap_err();
        if name.contains('@') {
            assert!(matches!(
                error,
                ImportError::DigestMismatch {
                    kind: "image name manifest digest",
                    ..
                }
            ));
        } else {
            assert!(matches!(error, ImportError::Malformed(_)));
        }
        assert_eq!(std::fs::read(&images_path).unwrap(), original);
    }

    let names = vec![
        format!("localhost/pinned@{manifest}"),
        format!("localhost/pinned:release@{manifest}"),
    ];
    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    import.layer_status(0).unwrap();
    let published = import
        .prepare_publication()
        .await
        .unwrap()
        .finish(&names)
        .await
        .unwrap();
    assert!(published.already_present);
    assert_eq!(published.manifest_digest, manifest);
    let images: Vec<Value> = serde_json::from_slice(&std::fs::read(&images_path).unwrap()).unwrap();
    assert_eq!(
        images[0]["names"],
        json!(["localhost/image:original", names[0], names[1]])
    );
    assert_eq!(
        images[0]["names-history"],
        json!([names[1], names[0], "localhost/image:original"])
    );
    assert_eq!(images[0]["digest"], manifest.to_string());
}

#[tokio::test]
async fn image_import_failures_do_not_publish_or_retain_locks() {
    let tar = tar_bytes(b"expected payload", false);
    for mode in ["request", "truncated", "digest", "metadata"] {
        let temp = TempDir::new().unwrap();
        let root = Dir::open_ambient_dir(temp.path(), ambient_authority()).unwrap();
        let mut source = Source {
            raw: image(&[&tar]),
            data: if mode == "digest" {
                tar_bytes(b"different payload", false)
            } else {
                tar.clone()
            },
            requested: Cell::new(0),
            request_error: mode == "request",
            truncate: mode == "truncated",
        };
        if mode == "metadata" {
            source.raw.config_json = b"{}".to_vec();
        }
        let error = import_image(
            &mut source,
            store_location(&root, "graph", &root, "run"),
            &[],
            Default::default(),
            None,
        )
        .await
        .unwrap_err();
        match (mode, error) {
            ("request", ImportError::Source { index, source }) => {
                assert_eq!(index, 0);
                assert_eq!(source.to_string(), "source request failed");
            }
            ("truncated", ImportError::Layer { source, .. }) => assert!(matches!(
                *source,
                ImportError::SplitDirFd(composefs_splitdirfdstream::Error::Truncated { .. })
            )),
            ("digest", ImportError::Layer { source, .. }) => {
                assert!(matches!(*source, ImportError::DigestMismatch { .. }));
            }
            ("metadata", ImportError::DigestMismatch { .. }) => {}
            (_, error) => panic!("unexpected {mode} failure: {error}"),
        }
        assert_eq!(source.requested.get(), usize::from(mode != "metadata"));
        assert!(
            !temp
                .path()
                .join("graph/overlay-images/images.json")
                .exists()
        );

        // Awaiting a failed import includes cleanup and releases its locks.
        let mut retry = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            open_store(temp.path()).begin_image(image(&[&tar]), Default::default()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(retry.layer_status(0).unwrap(), LayerStatus::Missing);
        retry.abort().await.unwrap();
    }
}
