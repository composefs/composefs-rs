use std::ffi::OsStr;
use std::io::Cursor;
use std::io::{Read, Write};
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

use cap_std::ambient_authority;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::records::{self, ImageRecord};
use super::*;

mod async_tests;

mod initialize_tests;

mod mapping_tests;
mod reuse_tests;
mod splitdirfd_tests;

async fn store() -> (TempDir, TestStore) {
    let temp = TempDir::new().unwrap();
    let root = Dir::open_ambient_dir(temp.path(), ambient_authority()).unwrap();
    StorageWriter::ensure(store_location(&root, "graph", &root, "run"))
        .await
        .unwrap();
    let writer = open_store(temp.path());
    (temp, writer)
}

fn store_location(graph_parent: &Dir, graph: &str, run_parent: &Dir, run: &str) -> StoreLocation {
    StoreLocation {
        graphroot: graph_parent.try_clone().unwrap(),
        graphroot_path: Some(graph.into()),
        runroot: Some(run_parent.try_clone().unwrap()),
        runroot_path: Some(run.into()),
    }
}

struct TestStore(std::path::PathBuf);

fn open_store(root: &std::path::Path) -> TestStore {
    TestStore(root.to_owned())
}

impl TestStore {
    async fn begin_image(&self, image: RawImage, options: ImportOptions) -> Result<ImageImport> {
        StorageWriter::open(StoreLocation::new(
            Dir::open_ambient_dir(self.0.join("graph"), ambient_authority()).unwrap(),
            Some(Dir::open_ambient_dir(self.0.join("run"), ambient_authority()).unwrap()),
        ))?
        .begin_image(image, options)
        .await
    }
}

fn tar_bytes(payload: &[u8], link: bool) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    let mut root = tar::Header::new_gnu();
    root.set_entry_type(tar::EntryType::Directory);
    root.set_mode(0o755);
    root.set_uid(rustix::process::geteuid().as_raw() as u64);
    root.set_gid(rustix::process::getegid().as_raw() as u64);
    root.set_mtime(123);
    root.set_size(0);
    root.set_cksum();
    tar.append_data(&mut root, ".", std::io::empty()).unwrap();
    let mut header = root.clone();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_size(payload.len() as u64);
    header.set_cksum();
    tar.append_data(&mut header, "payload", payload).unwrap();
    if link {
        header.set_entry_type(tar::EntryType::Link);
        header.set_mode(0o600);
        header.set_mtime(456);
        header.set_size(0);
        header.set_link_name("payload").unwrap();
        header.set_cksum();
        tar.append_data(&mut header, "alias", std::io::empty())
            .unwrap();
    }
    tar.into_inner().unwrap()
}

// Bypass tar::Builder's path validation to exercise names accepted by Go.
fn append_raw_path(
    tar: &mut tar::Builder<Vec<u8>>,
    header: &mut tar::Header,
    path: &str,
    data: &[u8],
) {
    let name = &mut header.as_mut_bytes()[..100];
    name.fill(0);
    name[..path.len()].copy_from_slice(path.as_bytes());
    header.set_cksum();
    tar.append(header, data).unwrap();
}

pub(super) fn image(layers: &[&[u8]]) -> RawImage {
    let ids: Vec<_> = layers.iter().map(|l| records::digest(l)).collect();
    let config=serde_json::to_vec_pretty(&json!({"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":ids},"config":{}})).unwrap();
    let manifest=serde_json::to_vec_pretty(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":config.len(),"digest":records::digest(&config)},
        "layers":layers.iter().map(|l|json!({"mediaType":"application/vnd.oci.image.layer.v1.tar","size":l.len(),"digest":records::digest(l)})).collect::<Vec<_>>() })).unwrap();
    RawImage {
        expected_manifest: records::digest(&manifest).parse().unwrap(),
        manifest_json: manifest,
        config_json: config,
    }
}

#[tokio::test]
async fn layer_records_retain_original_blob_identity() {
    use oci_spec::image::MediaType;

    let tar = tar_bytes(b"compressed layer payload", false);
    for media_type in [
        MediaType::ImageLayer,
        MediaType::ImageLayerGzip,
        MediaType::ImageLayerZstd,
    ] {
        let blob = match media_type {
            MediaType::ImageLayerGzip => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&tar).unwrap();
                encoder.finish().unwrap()
            }
            MediaType::ImageLayerZstd => zstd::stream::encode_all(tar.as_slice(), 0).unwrap(),
            _ => tar.clone(),
        };
        let blob_digest = records::digest(&blob);
        let (temp, writer) = store().await;
        let mut raw = image(&[&tar]);
        let mut manifest: Value = serde_json::from_slice(&raw.manifest_json).unwrap();
        manifest["layers"][0] = json!({
            "mediaType": media_type,
            "digest": blob_digest,
            "size": blob.len(),
        });
        raw.manifest_json = serde_json::to_vec(&manifest).unwrap();
        raw.expected_manifest = records::digest(&raw.manifest_json).parse().unwrap();
        let mut import = writer.begin_image(raw, Default::default()).await.unwrap();
        let layer = import
            .put_layer(0, TarSource(Cursor::new(tar.clone())))
            .await
            .unwrap();
        import
            .prepare_publication()
            .await
            .unwrap()
            .finish(&[])
            .await
            .unwrap();
        let root = temp.path().join("graph");
        let layers: Vec<Value> = serde_json::from_slice(
            &std::fs::read(root.join("overlay-layers/layers.json")).unwrap(),
        )
        .unwrap();
        let record = layers
            .iter()
            .find(|record| record["id"] == layer.storage_layer_id)
            .unwrap();
        assert_eq!(record["diff-digest"], records::digest(&tar));
        assert_eq!(record["diff-size"], tar.len());
        assert_eq!(record["compressed-diff-digest"], blob_digest);
        assert_eq!(record["compressed-size"], blob.len());
        assert_eq!(record["compression"], 0);
        assert_eq!(reconstruct(&root, &layer.storage_layer_id), tar);
    }
}

#[tokio::test]
async fn identity_reuse_and_name_policy() {
    let (temp, writer) = store().await;
    let tar = tar_bytes(b"contents", true);
    let raw = image(&[&tar]);
    let manifest = raw.manifest_json.clone();
    let config = raw.config_json.clone();
    let mut import = writer
        .begin_image(raw, ImportOptions::default())
        .await
        .unwrap();
    let layer = import
        .put_layer(0, TarSource(Cursor::new(tar.clone())))
        .await
        .unwrap();
    let published = import
        .prepare_publication()
        .await
        .unwrap()
        .finish(&["example.test/image:latest".into()])
        .await
        .unwrap();
    assert!(!published.already_present);
    let root = temp.path().join("graph");
    let data = root.join("overlay-images").join(&published.image_id);
    assert_eq!(std::fs::read(data.join("manifest")).unwrap(), manifest);
    assert_eq!(
        std::fs::read(data.join(records::big_data_name(published.config_digest.as_ref()))).unwrap(),
        config
    );
    let diff = root
        .join("overlay")
        .join(&layer.storage_layer_id)
        .join("diff");
    assert_eq!(std::fs::read(diff.join("payload")).unwrap(), b"contents");
    let a = std::fs::metadata(diff.join("payload")).unwrap();
    let b = std::fs::metadata(diff.join("alias")).unwrap();
    assert_eq!(a.ino(), b.ino());
    assert_eq!(a.mode() & 0o7777, 0o644);
    assert_eq!(a.mtime(), 123);
    assert_eq!(reconstruct(&root, &layer.storage_layer_id), tar);
    let mut retry = writer
        .begin_image(image(&[&tar]), ImportOptions::default())
        .await
        .unwrap();
    assert_eq!(
        retry.layer_status(0).unwrap(),
        LayerStatus::Reusable(layer.storage_layer_id)
    );
    let result = retry
        .prepare_publication()
        .await
        .unwrap()
        .finish(&["example.test/image:latest".into()])
        .await
        .unwrap();
    assert!(result.already_present);
    assert_eq!(result.stats.reused_layers, 1);
}

#[tokio::test]
async fn ownership_sets_record_headers_including_hardlinks() {
    for has_entries in [false, true] {
        let (temp, writer) = store().await;
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let link_uid = if uid == 42 { 43 } else { 42 };
        let link_gid = if gid == 84 { 85 } else { 84 };
        let mut tar = tar::Builder::new(Vec::new());
        if has_entries {
            let template = tar_bytes(b"x", false);
            let mut header = tar::Header::from_byte_slice(&template[512..1024]).clone();
            tar.append_data(&mut header, "implicit/payload", b"x".as_slice())
                .unwrap();
            header.set_entry_type(tar::EntryType::Link);
            header.set_size(0);
            header.set_uid(link_uid.into());
            header.set_gid(link_gid.into());
            header.set_link_name("implicit/payload").unwrap();
            tar.append_data(&mut header, "alias", std::io::empty())
                .unwrap();
        }
        let tar = tar.into_inner().unwrap();
        let mut import = writer
            .begin_image(image(&[&tar]), Default::default())
            .await
            .unwrap();
        let layer = import
            .put_layer(0, TarSource(Cursor::new(tar.clone())))
            .await
            .unwrap();
        import
            .prepare_publication()
            .await
            .unwrap()
            .finish(&[])
            .await
            .unwrap();
        let graph = temp.path().join("graph");
        let layers: Vec<Value> = serde_json::from_slice(
            &std::fs::read(graph.join("overlay-layers/layers.json")).unwrap(),
        )
        .unwrap();
        for (key, mut expected) in [
            (
                "uidset",
                if has_entries {
                    vec![uid, link_uid]
                } else {
                    vec![]
                },
            ),
            (
                "gidset",
                if has_entries {
                    vec![gid, link_gid]
                } else {
                    vec![]
                },
            ),
        ] {
            expected.sort_unstable();
            assert_eq!(
                layers[0][key],
                json!(expected),
                "{key}, entries={has_entries}"
            );
        }
        if has_entries {
            // A hardlink header contributes IDs without changing the shared
            // inode's ownership under our GNU tar extraction semantics.
            let diff = graph.join(format!("overlay/{}/diff", layer.storage_layer_id));
            let target = std::fs::metadata(diff.join("implicit/payload")).unwrap();
            let alias = std::fs::metadata(diff.join("alias")).unwrap();
            assert_eq!(
                (alias.uid(), alias.gid(), alias.ino()),
                (uid, gid, target.ino())
            );
        }
        assert_eq!(reconstruct(&graph, &layer.storage_layer_id), tar);
    }
}

#[tokio::test]
async fn name_history_prepends_requested_names_in_go_order() {
    let (temp, writer) = store().await;
    let tar = tar_bytes(b"contents", false);
    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    import
        .put_layer(0, TarSource(Cursor::new(tar.clone())))
        .await
        .unwrap();
    import
        .prepare_publication()
        .await
        .unwrap()
        .finish(&["localhost/example:old".into()])
        .await
        .unwrap();

    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    import.layer_status(0).unwrap();
    import
        .prepare_publication()
        .await
        .unwrap()
        .finish(&[
            "localhost/example:first".into(),
            "localhost/example:second".into(),
            "localhost/example:third".into(),
            "localhost/example:first".into(),
        ])
        .await
        .unwrap();
    let images: Vec<Value> = serde_json::from_slice(
        &std::fs::read(temp.path().join("graph/overlay-images/images.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        images[0]["names"],
        json!([
            "localhost/example:old",
            "localhost/example:first",
            "localhost/example:second",
            "localhost/example:third"
        ])
    );
    assert_eq!(
        images[0]["names-history"],
        json!([
            "localhost/example:third",
            "localhost/example:second",
            "localhost/example:first",
            "localhost/example:old"
        ])
    );
}

#[tokio::test]
async fn missing_published_image_data_requires_recovery() {
    for missing in ["directory", "manifest", "config"] {
        for during_finish in [false, true] {
            let (temp, writer) = store().await;
            let tar = tar_bytes(b"contents", false);
            let mut import = writer
                .begin_image(image(&[&tar]), Default::default())
                .await
                .unwrap();
            let layer = import
                .put_layer(0, TarSource(Cursor::new(tar.clone())))
                .await
                .unwrap();
            let published = import
                .prepare_publication()
                .await
                .unwrap()
                .finish(&["localhost/example:latest".into()])
                .await
                .unwrap();
            let graph = temp.path().join("graph");
            let records = graph.join("overlay-images/images.json");
            let original = std::fs::read(&records).unwrap();
            let mut retry = if during_finish {
                Some({
                    let mut import = writer
                        .begin_image(image(&[&tar]), Default::default())
                        .await
                        .unwrap();
                    import.layer_status(0).unwrap();
                    import
                })
            } else {
                None
            };
            let data = graph.join("overlay-images").join(&published.image_id);
            match missing {
                "directory" => std::fs::remove_dir_all(data).unwrap(),
                "manifest" => std::fs::remove_file(data.join("manifest")).unwrap(),
                "config" => std::fs::remove_file(
                    data.join(records::big_data_name(published.config_digest.as_ref())),
                )
                .unwrap(),
                _ => unreachable!(),
            }
            let result = if let Some(import) = retry.take() {
                import
                    .prepare_publication()
                    .await
                    .unwrap()
                    .finish(&[])
                    .await
                    .map(|_| ())
            } else {
                writer
                    .begin_image(image(&[&tar]), Default::default())
                    .await
                    .map(|_| ())
            };
            assert!(
                matches!(result, Err(ImportError::RecoveryRequired(_))),
                "{missing}, during_finish={during_finish}: {result:?}"
            );
            assert_eq!(std::fs::read(&records).unwrap(), original);
            assert_eq!(reconstruct(&graph, &layer.storage_layer_id), tar);
        }
    }
}

#[tokio::test]
async fn non_object_store_records_report_the_invalid_record() {
    for value in [
        json!(null),
        json!(false),
        json!(42),
        json!("layer"),
        json!([]),
    ] {
        let (temp, writer) = store().await;
        std::fs::write(
            temp.path().join("graph/overlay-layers/layers.json"),
            serde_json::to_vec(&vec![value]).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            writer.begin_image(image(&[]), Default::default()).await,
            Err(ImportError::RecoveryRequired(message))
                if message.starts_with("invalid record in layers.json:")
        ));
    }
}

#[tokio::test]
async fn malformed_known_metadata_is_rejected_without_rewriting_records() {
    for (directory, filename, value) in [
        (
            "overlay-layers",
            "layers.json",
            json!({"id":"layer","diff-size":"large"}),
        ),
        (
            "overlay-layers",
            "volatile-layers.json",
            json!({"id":"layer","flags":false}),
        ),
        (
            "overlay-images",
            "images.json",
            json!({"id":"image","mapped-layers":42}),
        ),
        (
            "overlay-images",
            "images.json",
            json!({"id":"image","names":[false]}),
        ),
        (
            "overlay-containers",
            "containers.json",
            json!({"id":"container","layer":false}),
        ),
    ] {
        let (temp, writer) = store().await;
        let graph = temp.path().join("graph");
        let directory = graph.join(directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(filename);
        let bytes = serde_json::to_vec(&vec![value]).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(
            matches!(
                writer.begin_image(image(&[]), Default::default()).await,
                Err(ImportError::RecoveryRequired(_))
            ),
            "{directory:?}/{filename}"
        );
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        assert_eq!(
            std::fs::read_dir(graph.join("overlay/l")).unwrap().count(),
            0
        );
    }
}

fn reconstruct(root: &std::path::Path, id: &str) -> Vec<u8> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let file = std::fs::File::open(root.join(format!("overlay-layers/{id}.tar-split.gz"))).unwrap();
    let mut decoder = flate2::read::GzDecoder::new(file);
    let mut json = String::new();
    decoder.read_to_string(&mut json).unwrap();
    let mut output = Vec::new();
    for (position, line) in json.lines().enumerate() {
        let value: Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["position"], position);
        if value["type"] == 2 {
            output.extend(STANDARD.decode(value["payload"].as_str().unwrap()).unwrap());
        } else if value["size"].as_u64().unwrap() != 0 {
            let name = match value["name_raw"].as_str() {
                Some(raw) => STANDARD.decode(raw).unwrap(),
                None => value["name"].as_str().unwrap().as_bytes().to_vec(),
            };
            let bytes = std::fs::read(
                root.join(format!("overlay/{id}/diff"))
                    .join(OsStr::from_bytes(&name)),
            )
            .unwrap();
            let checksum = crc::Crc::<u64>::new(&crc::CRC_64_GO_ISO)
                .checksum(&bytes)
                .to_be_bytes();
            assert_eq!(
                STANDARD.decode(value["payload"].as_str().unwrap()).unwrap(),
                checksum
            );
            assert_eq!(bytes.len() as u64, value["size"].as_u64().unwrap());
            output.extend(bytes);
        }
    }
    output
}

#[tokio::test]
async fn parent_chains_and_conflicting_names() {
    let (temp, writer) = store().await;
    let a = tar_bytes(b"a", false);
    let b = tar_bytes(b"b", false);
    let mut first = writer
        .begin_image(image(&[&a]), ImportOptions::default())
        .await
        .unwrap();
    first
        .put_layer(0, TarSource(Cursor::new(a.clone())))
        .await
        .unwrap();
    let first = first
        .prepare_publication()
        .await
        .unwrap()
        .finish(&["localhost/example:test".into()])
        .await
        .unwrap();
    let mut second = writer
        .begin_image(image(&[&a, &b]), ImportOptions::default())
        .await
        .unwrap();
    assert_eq!(second.layer_status(1).unwrap(), LayerStatus::NeedsParent);
    assert!(matches!(
        second.layer_status(0).unwrap(),
        LayerStatus::Reusable(_)
    ));
    second
        .put_layer(1, TarSource(Cursor::new(b.clone())))
        .await
        .unwrap();
    assert!(matches!(
        second
            .prepare_publication()
            .await
            .unwrap()
            .finish(&["localhost/example:test".into()])
            .await,
        Err(ImportError::NameConflict(_))
    ));
    let mut retry = writer
        .begin_image(
            image(&[&a, &b]),
            ImportOptions {
                names: NamePolicy::Reassign,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    retry.layer_status(0).unwrap();
    retry.layer_status(1).unwrap();
    let second = retry
        .prepare_publication()
        .await
        .unwrap()
        .finish(&["localhost/example:test".into()])
        .await
        .unwrap();
    assert_eq!(second.stats.reused_layers, 2);
    assert_eq!(second.layer_ids[0], first.layer_ids[0]);
    let root = temp.path().join("graph");
    assert_eq!(
        std::fs::read_to_string(root.join(format!("overlay/{}/lower-layers", second.layer_ids[1])))
            .unwrap(),
        first.layer_ids[0]
    );
    let records: Vec<Value> =
        serde_json::from_slice(&std::fs::read(root.join("overlay-images/images.json")).unwrap())
            .unwrap();
    let old = records
        .iter()
        .find(|record| record["id"] == first.image_id)
        .unwrap();
    assert_eq!(old["names"], json!([]));
    assert_eq!(old["names-history"], json!(["localhost/example:test"]));
    assert_eq!(reconstruct(&root, &second.layer_ids[1]), b);
}

#[tokio::test]
async fn rejects_metadata_and_manifest_variants_before_installing_layers() {
    let (temp, writer) = store().await;
    let tar = tar_bytes(b"a", false);
    let mut raw = image(&[&tar]);
    raw.config_json.push(b' ');
    assert!(matches!(
        writer.begin_image(raw, Default::default()).await,
        Err(ImportError::DigestMismatch { kind: "config", .. })
    ));
    assert!(
        std::fs::read(temp.path().join("graph/storage.lock"))
            .unwrap()
            .is_empty()
    );
    let mut first = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    first
        .put_layer(0, TarSource(Cursor::new(tar.clone())))
        .await
        .unwrap();
    first
        .prepare_publication()
        .await
        .unwrap()
        .finish(&[])
        .await
        .unwrap();
    let mut variant = image(&[&tar]);
    variant.manifest_json.push(b' ');
    variant.expected_manifest = records::digest(&variant.manifest_json).parse().unwrap();
    assert!(matches!(
        writer.begin_image(variant, Default::default()).await,
        Err(ImportError::ManifestVariantConflict(_))
    ));
    assert_eq!(
        std::fs::read_dir(temp.path().join("graph/overlay/l"))
            .unwrap()
            .count(),
        1
    );
}

#[tokio::test]
async fn recovery_removes_incomplete_namespace_but_refuses_live_references() {
    for (mounted, with_runroot) in [(false, false), (false, true), (true, false), (true, true)] {
        let (temp, _) = store().await;
        let graph = temp.path().join("graph");
        let writer = StorageWriter::open(StoreLocation::new(
            Dir::open_ambient_dir(&graph, ambient_authority()).unwrap(),
            with_runroot.then(|| {
                Dir::open_ambient_dir(temp.path().join("run"), ambient_authority()).unwrap()
            }),
        ))
        .unwrap();
        std::fs::create_dir_all(graph.join("overlay/interrupted/diff")).unwrap();
        std::os::unix::fs::symlink("../interrupted/diff", graph.join("overlay/l/SHORT")).unwrap();
        std::fs::write(
            graph.join("overlay-layers/layers.json"),
            br#"[{"id":"interrupted","flags":{"incomplete":true}}]"#,
        )
        .unwrap();
        if mounted {
            std::fs::write(
                temp.path().join("run/overlay-layers/mountpoints.json"),
                br#"[{"id":"interrupted","count":1,"path":"/live"}]"#,
            )
            .unwrap();
        }
        let tar = tar_bytes(b"a", false);
        let result = writer.begin_image(image(&[&tar]), Default::default()).await;
        if mounted && with_runroot {
            assert!(matches!(result, Err(ImportError::RecoveryRequired(_))));
            assert!(graph.join("overlay/l/SHORT").symlink_metadata().is_ok());
        } else {
            result.unwrap().abort().await.unwrap();
            assert!(!graph.join("overlay/interrupted").exists());
            assert!(graph.join("overlay/l/SHORT").symlink_metadata().is_err());
        }
    }
}

#[tokio::test]
async fn reserved_tar_ownership_is_rejected_as_malformed() {
    for (owner, pax) in [("uid", false), ("gid", false), ("uid", true), ("gid", true)] {
        let (temp, writer) = store().await;
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::from_byte_slice(&tar_bytes(b"x", false)[512..1024]).clone();
        if pax {
            tar.append_pax_extensions([(owner, b"4294967295".as_slice())])
                .unwrap();
        } else if owner == "uid" {
            header.set_uid(u64::from(u32::MAX));
        } else {
            header.set_gid(u64::from(u32::MAX));
        }
        header.set_cksum();
        tar.append_data(&mut header, "payload", b"x".as_slice())
            .unwrap();
        let tar = tar.into_inner().unwrap();
        let mut import = writer
            .begin_image(image(&[&tar]), Default::default())
            .await
            .unwrap();
        let error = import
            .put_layer(0, TarSource(Cursor::new(tar.clone())))
            .await
            .unwrap_err();
        let ImportError::Layer {
            index: 0, source, ..
        } = error
        else {
            panic!("expected a layer error for {owner} (PAX={pax}): {error:?}");
        };
        assert!(
            matches!(*source, ImportError::Malformed(_)),
            "{owner} (PAX={pax}): {source:?}"
        );
        import.abort().await.unwrap();
        let graph = temp.path().join("graph");
        assert_eq!(
            std::fs::read_dir(graph.join("overlay/l")).unwrap().count(),
            0
        );
        let layers: Value = serde_json::from_slice(
            &std::fs::read(graph.join("overlay-layers/layers.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(layers, json!([]));
        assert!(!graph.join("overlay-images/images.json").exists());
    }
}

#[tokio::test]
async fn tar_duplicates_are_rejected() {
    let (temp, writer) = store().await;
    let tar = tar_bytes(b"a", false);
    let mut duplicate = tar.clone();
    duplicate.truncate(1536);
    duplicate.extend_from_slice(&tar);
    let mut import = writer
        .begin_image(image(&[&duplicate]), Default::default())
        .await
        .unwrap();
    assert!(
        import
            .put_layer(0, TarSource(Cursor::new(duplicate.clone())))
            .await
            .is_err()
    );
    import.abort().await.unwrap();
    assert_eq!(
        std::fs::read_dir(temp.path().join("graph/overlay/l"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn pax_mtime_overrides_replace_fractional_seconds() {
    for (mtime, nanos) in [("124", 0), ("124.25", 250_000_000), ("124.000000001", 1)] {
        let (temp, writer) = store().await;
        let mut tar = tar::Builder::new(Vec::new());
        tar.append_pax_extensions([("mtime", b"123.5".as_slice()), ("mtime", mtime.as_bytes())])
            .unwrap();
        let mut header =
            tar::Header::from_byte_slice(&tar_bytes(b"payload", false)[512..1024]).clone();
        tar.append_data(&mut header, "payload", b"payload".as_slice())
            .unwrap();
        let tar = tar.into_inner().unwrap();
        let mut import = writer
            .begin_image(image(&[&tar]), Default::default())
            .await
            .unwrap();
        let layer = import
            .put_layer(0, TarSource(Cursor::new(tar.clone())))
            .await
            .unwrap();
        import
            .prepare_publication()
            .await
            .unwrap()
            .finish(&[])
            .await
            .unwrap();
        let root = temp.path().join("graph");
        let metadata = std::fs::metadata(
            root.join(format!("overlay/{}/diff/payload", layer.storage_layer_id)),
        )
        .unwrap();
        assert_eq!(
            (metadata.mtime(), metadata.mtime_nsec()),
            (124, nanos),
            "final mtime={mtime}"
        );
        assert_eq!(reconstruct(&root, &layer.storage_layer_id), tar);
    }
}

#[tokio::test]
async fn byte_paths_and_link_targets_round_trip() {
    let (temp, writer) = store().await;
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::from_byte_slice(&tar_bytes(b"", false)[..512]).clone();
    let directory = OsStr::from_bytes(b"explicit-\xff");
    tar.append_data(&mut header, directory, std::io::empty())
        .unwrap();
    // This path requires a GNU long-name header as well as a byte-only
    // implicit parent. The hardlink target requires a GNU long-link header.
    let name = [
        b"explicit-\xff/implicit-\xfe/".as_slice(),
        &[b'x'; 110],
        b"-\xfd",
    ]
    .concat();
    let path = OsStr::from_bytes(&name);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(7);
    tar.append_data(&mut header, path, b"content".as_slice())
        .unwrap();
    header.set_entry_type(tar::EntryType::Link);
    header.set_size(0);
    tar.append_link(&mut header, OsStr::from_bytes(b"alias-\xfc"), path)
        .unwrap();
    header.set_entry_type(tar::EntryType::Symlink);
    tar.append_link(&mut header, OsStr::from_bytes(b"symlink-\xfb"), path)
        .unwrap();
    // PAX paths must also retain their bytes. Its zero-length payload still
    // needs a name_raw record, although reconstruction does not open it.
    let pax_path = OsStr::from_bytes(b"pax-\xfa/empty-\xf9");
    tar.append_pax_extensions([("path", pax_path.as_bytes())])
        .unwrap();
    header.set_entry_type(tar::EntryType::Regular);
    tar.append_data(&mut header, "unused", std::io::empty())
        .unwrap();
    let tar = tar.into_inner().unwrap();
    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    let layer = import
        .put_layer(0, TarSource(Cursor::new(tar.clone())))
        .await
        .unwrap();
    import.abort().await.unwrap();
    let root = temp.path().join("graph");
    let diff = root.join(format!("overlay/{}/diff", layer.storage_layer_id));
    assert_eq!(std::fs::read(diff.join(path)).unwrap(), b"content");
    assert_eq!(
        std::fs::metadata(diff.join(path)).unwrap().ino(),
        std::fs::metadata(diff.join(OsStr::from_bytes(b"alias-\xfc")))
            .unwrap()
            .ino()
    );
    assert_eq!(
        std::fs::read_link(diff.join(OsStr::from_bytes(b"symlink-\xfb"))).unwrap(),
        std::path::Path::new(path)
    );
    assert_eq!(std::fs::read(diff.join(pax_path)).unwrap(), b"");
    assert!(!diff.join("unused").exists());
    assert_eq!(reconstruct(&root, &layer.storage_layer_id), tar);
}

#[tokio::test]
async fn global_pax_headers_are_preserved_without_applying_attributes() {
    for with_entries in [false, true] {
        let (temp, writer) = store().await;
        let mut tar = tar::Builder::new(Vec::new());
        let template = tar_bytes(b"content", false);
        let mut global = tar::Header::from_byte_slice(&template[512..1024]).clone();
        global.set_entry_type(tar::EntryType::XGlobalHeader);
        let attributes = b"13 uid=12345\n14 mtime=99.5\n13 path=nope\n";
        global.set_size(attributes.len() as u64);
        // Repeated global names are metadata, not duplicate filesystem paths.
        for index in 0..2 {
            tar.append_data(&mut global, "global", attributes.as_slice())
                .unwrap();
            if with_entries {
                if index == 0 {
                    tar.append_pax_extensions([("mtime", b"123.25".as_slice())])
                        .unwrap();
                }
                let mut header = tar::Header::from_byte_slice(&template[512..1024]).clone();
                tar.append_data(
                    &mut header,
                    format!("payload{index}"),
                    b"content".as_slice(),
                )
                .unwrap();
            }
        }
        let tar = tar.into_inner().unwrap();
        let mut import = writer
            .begin_image(image(&[&tar]), Default::default())
            .await
            .unwrap();
        let layer = import
            .put_layer(0, TarSource(Cursor::new(tar.clone())))
            .await
            .unwrap();
        import.abort().await.unwrap();
        let root = temp.path().join("graph");
        let diff = root.join(format!("overlay/{}/diff", layer.storage_layer_id));
        assert_eq!(
            std::fs::read_dir(&diff).unwrap().count(),
            if with_entries { 2 } else { 0 }
        );
        if with_entries {
            for (index, nanos) in [(0, 250_000_000), (1, 0)] {
                let path = diff.join(format!("payload{index}"));
                assert_eq!(std::fs::read(&path).unwrap(), b"content");
                let metadata = std::fs::metadata(path).unwrap();
                assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
                assert_eq!((metadata.mtime(), metadata.mtime_nsec()), (123, nanos));
            }
        }
        assert_eq!(reconstruct(&root, &layer.storage_layer_id), tar);
    }
}

#[tokio::test]
async fn unsupported_xattrs_are_ignored_but_other_errors_fail_the_layer() {
    use rustix::io::Errno;
    use tar::EntryType;

    for (kind, key, error) in [
        (EntryType::Regular, "unsupported.fixture", None),
        (EntryType::Directory, "unsupported.fixture", None),
        (EntryType::Symlink, "unsupported.fixture", None),
        (EntryType::Regular, "user.", Some(Errno::INVAL)),
        (EntryType::Symlink, "user.fixture", Some(Errno::PERM)),
    ] {
        let (temp, writer) = store().await;
        let mut tar = tar::Builder::new(Vec::new());
        // An unknown namespace produces EOPNOTSUPP on ordinary Linux filesystems,
        // exercising the same failure as a filesystem without xattr support.
        let pax_key = format!("SCHILY.xattr.{key}");
        let mut xattrs = vec![(pax_key.as_str(), b"value".as_slice())];
        if kind != EntryType::Symlink {
            xattrs.push(("SCHILY.xattr.user.fixture", b"retained"));
        }
        tar.append_pax_extensions(xattrs).unwrap();
        let mut header = tar::Header::from_byte_slice(&tar_bytes(b"", false)[..512]).clone();
        header.set_entry_type(kind);
        if kind == EntryType::Symlink {
            header.set_link_name("target").unwrap();
        }
        tar.append_data(&mut header, "entry", std::io::empty())
            .unwrap();
        let tar = tar.into_inner().unwrap();
        let mut import = writer
            .begin_image(image(&[&tar]), Default::default())
            .await
            .unwrap();
        let result = import
            .put_layer(0, TarSource(Cursor::new(tar.clone())))
            .await;
        if let Some(errno) = error {
            let ImportError::Layer { source, .. } = result.unwrap_err() else {
                panic!("expected layer error for {kind:?}, {key}");
            };
            assert!(
                matches!(*source, ImportError::Io(e) if e.raw_os_error() == Some(errno.raw_os_error()))
            );
            continue;
        }
        let layer = result.unwrap();
        import
            .prepare_publication()
            .await
            .unwrap()
            .finish(&[])
            .await
            .unwrap();
        let root = temp.path().join("graph");
        let path = root.join(format!("overlay/{}/diff/entry", layer.storage_layer_id));
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.mtime(), 123);
        if kind == EntryType::Symlink {
            assert_eq!(
                std::fs::read_link(&path).unwrap(),
                std::path::Path::new("target")
            );
        } else {
            let mut value = [0; 64];
            let n = rustix::fs::lgetxattr(&path, "user.fixture", &mut value).unwrap();
            assert_eq!(&value[..n], b"retained");
        }
        assert_eq!(reconstruct(&root, &layer.storage_layer_id), tar);
    }
}

#[tokio::test]
async fn pax_metadata_links_and_implicit_directories_round_trip() {
    let (temp, writer) = store().await;
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::from_byte_slice(&tar_bytes(b"", false)[..512]).clone();
    tar.append_pax_extensions([("SCHILY.xattr.user.root", b"root-only".as_slice())])
        .unwrap();
    tar.append_data(&mut header, ".", std::io::empty()).unwrap();
    tar.append_pax_extensions([
        ("mtime", b"123.123456789".as_slice()),
        ("SCHILY.xattr.user.fixture", b"value"),
        ("SCHILY.xattr.security.selinux", b"invalid-container-label"),
    ])
    .unwrap();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o640);
    header.set_size(7);
    header.set_cksum();
    tar.append_data(&mut header, "implicit/payload", b"content".as_slice())
        .unwrap();
    header.set_entry_type(tar::EntryType::Link);
    header.set_mode(0o600);
    header.set_mtime(456);
    header.set_size(0);
    header.set_link_name("implicit/payload").unwrap();
    header.set_cksum();
    tar.append_data(&mut header, "alias", std::io::empty())
        .unwrap();
    header.set_entry_type(tar::EntryType::Symlink);
    header
        .set_link_name("/an/absolute/dangling/target")
        .unwrap();
    header.set_cksum();
    tar.append_data(&mut header, "symlink", std::io::empty())
        .unwrap();
    header.set_entry_type(tar::EntryType::Fifo);
    header.set_cksum();
    tar.append_data(&mut header, "fifo", std::io::empty())
        .unwrap();
    let tar = tar.into_inner().unwrap();
    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    let layer = import
        .put_layer(0, TarSource(Cursor::new(tar.clone())))
        .await
        .unwrap();
    import
        .prepare_publication()
        .await
        .unwrap()
        .finish(&[])
        .await
        .unwrap();
    let root = temp.path().join("graph");
    let diff = root.join(format!("overlay/{}/diff", layer.storage_layer_id));
    let payload = std::fs::File::open(diff.join("implicit/payload")).unwrap();
    let metadata = payload.metadata().unwrap();
    assert_eq!(
        (
            metadata.mode() & 0o7777,
            metadata.mtime(),
            metadata.mtime_nsec()
        ),
        (0o640, 123, 123456789)
    );
    assert_eq!(
        std::fs::metadata(diff.join("alias")).unwrap().ino(),
        metadata.ino()
    );
    let mut value = [0; 64];
    let n = rustix::fs::fgetxattr(&payload, "user.fixture", &mut value).unwrap();
    assert_eq!(&value[..n], b"value");
    let implicit = std::fs::File::open(diff.join("implicit")).unwrap();
    assert_eq!(
        rustix::fs::fgetxattr(&implicit, "user.root", &mut value),
        Err(rustix::io::Errno::NODATA)
    );
    assert_eq!(
        std::fs::read_link(diff.join("symlink")).unwrap(),
        std::path::Path::new("/an/absolute/dangling/target")
    );
    assert_eq!(
        std::fs::symlink_metadata(diff.join("fifo")).unwrap().mode() & 0o170000,
        0o010000
    );
    assert_eq!(reconstruct(&root, &layer.storage_layer_id), tar);
}

#[tokio::test]
async fn tar_path_cleaning_preserves_links_and_original_tar_bytes() {
    for path in [
        "/payload",
        "a/../payload",
        "/a/../payload",
        "a/b/../../payload",
        "//./a//../payload",
        "/../../payload",
    ] {
        let (temp, writer) = store().await;
        let template = tar_bytes(b"contents", false);
        let mut tar = tar::Builder::new(Vec::new());
        let mut root = tar::Header::from_byte_slice(&template[..512]).clone();
        append_raw_path(&mut tar, &mut root, "/", &[]);
        let mut header = tar::Header::from_byte_slice(&template[512..1024]).clone();
        append_raw_path(&mut tar, &mut header, path, b"contents");
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        let target = if path == "/../../payload" {
            "/payload"
        } else {
            path
        };
        header.set_link_name_literal(target.as_bytes()).unwrap();
        append_raw_path(&mut tar, &mut header, "unused/../alias", &[]);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name_literal(path.as_bytes()).unwrap();
        append_raw_path(&mut tar, &mut header, "/symlink", &[]);
        let tar = tar.into_inner().unwrap();
        let mut import = writer
            .begin_image(image(&[&tar]), Default::default())
            .await
            .unwrap();
        let layer = import
            .put_layer(0, TarSource(Cursor::new(tar.clone())))
            .await
            .unwrap();
        import
            .prepare_publication()
            .await
            .unwrap()
            .finish(&[])
            .await
            .unwrap();
        let graph = temp.path().join("graph");
        let diff = graph.join(format!("overlay/{}/diff", layer.storage_layer_id));
        assert_eq!(std::fs::read(diff.join("payload")).unwrap(), b"contents");
        assert_eq!(
            std::fs::metadata(diff.join("payload")).unwrap().ino(),
            std::fs::metadata(diff.join("alias")).unwrap().ino()
        );
        assert_eq!(
            std::fs::read_link(diff.join("symlink")).unwrap(),
            std::path::Path::new(path)
        );
        assert!(!diff.join("a").exists());
        assert!(!diff.join("unused").exists());
        assert_eq!(reconstruct(&graph, &layer.storage_layer_id), tar);
    }
}

#[tokio::test]
async fn escaping_hardlink_targets_are_rejected() {
    for target in ["../payload", "a/../../payload", "/../../payload"] {
        let (_temp, writer) = store().await;
        let template = tar_bytes(b"contents", false);
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::from_byte_slice(&template[512..1024]).clone();
        append_raw_path(&mut tar, &mut header, "payload", b"contents");
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        header.set_link_name_literal(target.as_bytes()).unwrap();
        append_raw_path(&mut tar, &mut header, "alias", &[]);
        let tar = tar.into_inner().unwrap();
        let mut import = writer
            .begin_image(image(&[&tar]), Default::default())
            .await
            .unwrap();
        let error = import
            .put_layer(0, TarSource(Cursor::new(tar.clone())))
            .await
            .unwrap_err();
        let ImportError::Layer { source, .. } = error else {
            panic!("expected a layer error: {error:?}");
        };
        assert!(
            matches!(*source, ImportError::Malformed(ref message) if message.contains("escaping tar path")),
            "{target}: {source:?}"
        );
        import.abort().await.unwrap();
    }
}

#[tokio::test]
async fn normalized_tar_path_aliases_are_rejected_as_duplicates() {
    for path in ["/payload", "unused/../payload", "/unused/../payload"] {
        let (_temp, writer) = store().await;
        let template = tar_bytes(b"contents", false);
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::from_byte_slice(&template[512..1024]).clone();
        append_raw_path(&mut tar, &mut header, "payload", b"contents");
        append_raw_path(&mut tar, &mut header, path, b"contents");
        let tar = tar.into_inner().unwrap();
        let mut import = writer
            .begin_image(image(&[&tar]), Default::default())
            .await
            .unwrap();
        let error = import
            .put_layer(0, TarSource(Cursor::new(tar.clone())))
            .await
            .unwrap_err();
        let ImportError::Layer { source, .. } = error else {
            panic!("expected a layer error: {error:?}");
        };
        assert!(
            matches!(*source, ImportError::Malformed(ref message) if message.contains("duplicate tar path")),
            "{path}: {source:?}"
        );
        import.abort().await.unwrap();
    }
}

#[tokio::test]
async fn escaping_paths_and_symlink_parents_never_escape_the_layer() {
    for path in [
        "../escaped",
        "parent/../../escaped",
        "symlink/escaped",
        "/symlink/escaped",
        "a/../symlink/escaped",
        "/a/../symlink/escaped",
    ] {
        let (temp, writer) = store().await;
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::from_byte_slice(&tar_bytes(b"", false)[..512]).clone();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name(temp.path()).unwrap();
        header.set_cksum();
        tar.append_data(&mut header, "symlink", std::io::empty())
            .unwrap();
        let mut bytes = tar.into_inner().unwrap();
        bytes.truncate(512);
        header.set_entry_type(tar::EntryType::Regular);
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        header.set_cksum();
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(&[0; 1024]);
        let mut import = writer
            .begin_image(image(&[&bytes]), Default::default())
            .await
            .unwrap();
        assert!(
            import
                .put_layer(0, TarSource(Cursor::new(bytes.clone())))
                .await
                .is_err(),
            "{path}"
        );
        import.abort().await.unwrap();
        assert!(!temp.path().join("escaped").exists());
        assert_eq!(
            std::fs::read_dir(temp.path().join("graph/overlay/l"))
                .unwrap()
                .count(),
            0
        );
    }
}

#[tokio::test]
async fn creation_time_is_canonical_in_records_without_changing_config_bytes() {
    for (created, history, expected) in [
        (
            "2020-01-01T00:00:00+00:00",
            None,
            Some("2020-01-01T00:00:00Z"),
        ),
        ("2020-01-01t00:00:00z", None, None),
        ("2016-12-31T23:59:60Z", None, None),
        ("2020-01-01T00:00:00Z", Some("2020-01-01t00:00:00z"), None),
    ] {
        let (temp, writer) = store().await;
        let mut raw = image(&[]);
        let mut config: Value = serde_json::from_slice(&raw.config_json).unwrap();
        config["created"] = created.into();
        if let Some(history) = history {
            config["history"] = json!([{"created":history}]);
        }
        raw.config_json = serde_json::to_vec_pretty(&config).unwrap();
        let mut manifest: Value = serde_json::from_slice(&raw.manifest_json).unwrap();
        manifest["config"]["digest"] = records::digest(&raw.config_json).into();
        manifest["config"]["size"] = raw.config_json.len().into();
        raw.manifest_json = serde_json::to_vec(&manifest).unwrap();
        raw.expected_manifest = records::digest(&raw.manifest_json).parse().unwrap();
        match expected {
            Some(expected) => {
                let validated = records::ValidatedImage::new(raw).unwrap();
                assert_eq!(validated.created, expected);
                let config = validated.raw.config_json.clone();
                let published = writer
                    .begin_image(validated.raw, Default::default())
                    .await
                    .unwrap()
                    .prepare_publication()
                    .await
                    .unwrap()
                    .finish(&[])
                    .await
                    .unwrap();
                let dir = Dir::open_ambient_dir(
                    temp.path().join("graph/overlay-images"),
                    ambient_authority(),
                )
                .unwrap();
                assert_eq!(
                    records::records::<ImageRecord>(&dir, "images.json").unwrap()[0]
                        .created
                        .as_deref(),
                    Some(expected)
                );
                let data = dir
                    .read(format!(
                        "{}/{}",
                        published.image_id,
                        records::big_data_name(published.config_digest.as_ref())
                    ))
                    .unwrap();
                assert_eq!(data, config);
            }
            None => assert!(matches!(
                writer.begin_image(raw, Default::default()).await,
                Err(ImportError::Malformed(_))
            )),
        }
    }
}

#[tokio::test]
async fn whiteouts_cannot_replace_entries_already_created_in_the_layer() {
    for kind in ["file", "directory", "implicit-directory", "symlink"] {
        let (temp, writer) = store().await;
        let template = tar_bytes(b"x", false);
        let mut header = tar::Header::from_byte_slice(&template[512..1024]).clone();
        let mut tar = tar::Builder::new(Vec::new());
        let (path, contents) = match kind {
            "directory" => {
                header.set_entry_type(tar::EntryType::Directory);
                ("target", b"".as_slice())
            }
            "symlink" => {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_link_name("/outside").unwrap();
                ("target", b"".as_slice())
            }
            "implicit-directory" => ("target/child", b"x".as_slice()),
            "file" => ("target", b"x".as_slice()),
            _ => unreachable!(),
        };
        header.set_size(contents.len() as u64);
        tar.append_data(&mut header, path, contents).unwrap();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(0);
        tar.append_data(&mut header, ".wh.target", std::io::empty())
            .unwrap();
        let tar = tar.into_inner().unwrap();
        let mut import = writer
            .begin_image(image(&[&tar]), Default::default())
            .await
            .unwrap();
        let error = import
            .put_layer(0, TarSource(Cursor::new(tar)))
            .await
            .unwrap_err();
        let ImportError::Layer {
            index: 0, source, ..
        } = error
        else {
            panic!("expected layer error for {kind}: {error:?}");
        };
        assert!(
            matches!(*source, ImportError::Malformed(ref message)
            if message == "whiteout target already exists in this layer: \"target\""),
            "{kind}: {source:?}"
        );
        assert!(import.abort().await.unwrap().retained_layers.is_empty());
        let graph = temp.path().join("graph");
        let layers: Value = serde_json::from_slice(
            &std::fs::read(graph.join("overlay-layers/layers.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(layers, json!([]));
        assert_eq!(
            std::fs::read_dir(graph.join("overlay/l")).unwrap().count(),
            0
        );
        assert_eq!(std::fs::read_dir(graph.join("overlay")).unwrap().count(), 1);
        assert!(!graph.join("overlay-images/images.json").exists());
    }
}

#[tokio::test]
async fn same_layer_parent_replacements_are_rejected() {
    for file_backed in [false, true] {
        for (replacement, directory) in [
            ("outer/implicit", false),
            ("outer", false),
            ("outer/implicit", true),
        ] {
            let (temp, writer) = store().await;
            let payload = vec![37; 128 * 1024 + 1];
            let template = tar_bytes(&payload, false);
            let mut tar = tar::Builder::new(Vec::new());
            let mut root = tar::Header::from_byte_slice(&template[..512]).clone();
            tar.append_data(&mut root, ".", std::io::empty()).unwrap();
            let mut header = tar::Header::from_byte_slice(&template[512..1024]).clone();
            tar.append_data(&mut header, "outer/implicit/child", payload.as_slice())
                .unwrap();
            header.set_entry_type(if directory {
                tar::EntryType::Directory
            } else {
                tar::EntryType::Regular
            });
            header.set_mode(0o751);
            header.set_mtime(456);
            let contents = if directory {
                b"".as_slice()
            } else {
                b"replacement"
            };
            header.set_size(contents.len() as u64);
            tar.append_data(&mut header, replacement, contents).unwrap();
            let tar = tar.into_inner().unwrap();
            let mut import = writer
                .begin_image(image(&[&tar]), Default::default())
                .await
                .unwrap();
            let result = if file_backed {
                let (_file, source, _named) = file_source(&tar, &payload, false);
                import.put_layer(0, source).await
            } else {
                import
                    .put_layer(0, TarSource(Cursor::new(tar.clone())))
                    .await
            };
            let graph = temp.path().join("graph");
            if directory {
                // A directory header after its children updates metadata
                // without invalidating any earlier tar payload references.
                let layer = result.unwrap();
                let diff = graph.join(format!("overlay/{}/diff", layer.storage_layer_id));
                let metadata = std::fs::metadata(diff.join(replacement)).unwrap();
                assert_eq!((metadata.mode() & 0o7777, metadata.mtime()), (0o751, 456));
                assert_eq!(
                    std::fs::read(diff.join("outer/implicit/child")).unwrap(),
                    payload
                );
                assert_eq!(reconstruct(&graph, &layer.storage_layer_id), tar);
                import.abort().await.unwrap();
            } else {
                let error = result.unwrap_err();
                let ImportError::Layer {
                    index: 0, source, ..
                } = error
                else {
                    panic!("expected a layer error: {error:?}");
                };
                assert!(matches!(*source, ImportError::Malformed(ref message)
                    if message == &format!("non-directory entry replaces parent of earlier layer entries: {replacement:?}")));
                assert!(import.abort().await.unwrap().retained_layers.is_empty());
                let layers: Value = serde_json::from_slice(
                    &std::fs::read(graph.join("overlay-layers/layers.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(layers, json!([]));
                assert_eq!(
                    std::fs::read_dir(graph.join("overlay/l")).unwrap().count(),
                    0
                );
                assert_eq!(std::fs::read_dir(graph.join("overlay")).unwrap().count(), 1);
                assert!(!graph.join("overlay-images/images.json").exists());
            }
        }
    }
}

#[tokio::test]
async fn implicit_upper_directories_keep_lower_metadata() {
    let (temp, writer) = store().await;
    let mut base = tar::Builder::new(Vec::new());
    let mut header = tar::Header::from_byte_slice(&tar_bytes(b"", false)[..512]).clone();
    header.set_mode(0o701);
    header.set_cksum();
    base.append_pax_extensions([("SCHILY.xattr.user.fixture", b"lower".as_slice())])
        .unwrap();
    base.append_data(&mut header, "private", std::io::empty())
        .unwrap();
    let base = base.into_inner().unwrap();
    let mut upper = tar::Builder::new(Vec::new());
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_cksum();
    upper
        .append_data(&mut header, "private/new", std::io::empty())
        .unwrap();
    let upper = upper.into_inner().unwrap();
    let mut import = writer
        .begin_image(image(&[&base, &upper]), Default::default())
        .await
        .unwrap();
    import
        .put_layer(0, TarSource(Cursor::new(base.clone())))
        .await
        .unwrap();
    let layer = import
        .put_layer(1, TarSource(Cursor::new(upper.clone())))
        .await
        .unwrap();
    import
        .prepare_publication()
        .await
        .unwrap()
        .finish(&[])
        .await
        .unwrap();
    let private = std::fs::File::open(temp.path().join(format!(
        "graph/overlay/{}/diff/private",
        layer.storage_layer_id
    )))
    .unwrap();
    let stat = private.metadata().unwrap();
    assert_eq!(stat.mode() & 0o7777, 0o701);
    assert_eq!(stat.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(stat.mtime(), 123);
    let mut value = [0; 32];
    let n = rustix::fs::fgetxattr(&private, "user.fixture", &mut value).unwrap();
    assert_eq!(&value[..n], b"lower");
}

#[tokio::test]
async fn host_default_acls_do_not_leak_into_image_entries() {
    let (temp, writer) = store().await;
    let overlay = std::fs::File::open(temp.path().join("graph/overlay")).unwrap();
    // Linux POSIX ACL xattr v2: owner, a named user, group, mask, other.
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in [
        (1u16, 7u16, u32::MAX),
        (2, 4, rustix::process::geteuid().as_raw()),
        (4, 5, u32::MAX),
        (16, 5, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&permissions.to_le_bytes());
        acl.extend_from_slice(&id.to_le_bytes());
    }
    rustix::fs::fsetxattr(
        &overlay,
        "system.posix_acl_default",
        &acl,
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
    let tar = tar_bytes(b"contents", false);
    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    let layer = import
        .put_layer(0, TarSource(Cursor::new(tar.clone())))
        .await
        .unwrap();
    import
        .prepare_publication()
        .await
        .unwrap()
        .finish(&[])
        .await
        .unwrap();
    for name in [".", "payload"] {
        let file = std::fs::File::open(temp.path().join(format!(
            "graph/overlay/{}/diff/{name}",
            layer.storage_layer_id
        )))
        .unwrap();
        let mut value = [0; 128];
        assert_eq!(
            rustix::fs::fgetxattr(&file, "system.posix_acl_access", &mut value),
            Err(rustix::io::Errno::NODATA)
        );
        assert_eq!(
            rustix::fs::fgetxattr(&file, "system.posix_acl_default", &mut value),
            Err(rustix::io::Errno::NODATA)
        );
    }
}

struct FileSource {
    prefix: Cursor<Vec<u8>>,
    file: Option<std::fs::File>,
    suffix: Cursor<Vec<u8>>,
}
impl LayerSource for FileSource {
    fn next_chunk(&mut self, buffer: &mut [u8]) -> Result<Option<LayerChunk>> {
        let n = self.prefix.read(buffer)?;
        if n > 0 {
            return Ok(Some(LayerChunk::Inline(n)));
        }
        if let Some(file) = self.file.take() {
            let length = file.metadata()?.len();
            return Ok(Some(LayerChunk::File { file, length }));
        }
        let n = self.suffix.read(buffer)?;
        Ok((n > 0).then_some(LayerChunk::Inline(n)))
    }
}

fn file_source(
    tar: &[u8],
    payload: &[u8],
    memfd: bool,
) -> (std::fs::File, FileSource, Option<tempfile::NamedTempFile>) {
    let named = if memfd {
        None
    } else {
        Some(tempfile::NamedTempFile::new().unwrap())
    };
    let mut file = if memfd {
        std::fs::File::from(
            rustix::fs::memfd_create("storage-import-test", rustix::fs::MemfdFlags::CLOEXEC)
                .unwrap(),
        )
    } else {
        named.as_ref().unwrap().as_file().try_clone().unwrap()
    };
    file.write_all(payload).unwrap();
    rustix::fs::fchmod(&file, rustix::fs::Mode::from_bits_truncate(0o644)).unwrap();
    let time = rustix::time::Timespec {
        tv_sec: 123,
        tv_nsec: 0,
    };
    rustix::fs::futimens(
        &file,
        &rustix::fs::Timestamps {
            last_access: time,
            last_modification: time,
        },
    )
    .unwrap();
    let source = FileSource {
        prefix: Cursor::new(tar[..1024].to_vec()),
        file: Some(file.try_clone().unwrap()),
        suffix: Cursor::new(tar[1024 + payload.len()..].to_vec()),
    };
    (file, source, named)
}

#[tokio::test]
async fn file_backed_sharing_and_cross_filesystem_copy_preserve_sources() {
    for (allow, memfd, mismatch) in [
        (false, false, ""),
        (true, false, ""),
        (true, true, ""),
        (true, false, "mode"),
        (true, false, "xattr"),
    ] {
        let (temp, writer) = store().await;
        let payload = vec![73; 128 * 1024 + 1];
        let tar = tar_bytes(&payload, true);
        let (file, source, _named) = file_source(&tar, &payload, memfd);
        match mismatch {
            "mode" => {
                rustix::fs::fchmod(&file, rustix::fs::Mode::from_bits_truncate(0o600)).unwrap()
            }
            "xattr" => rustix::fs::fsetxattr(
                &file,
                "user.source",
                b"preserve",
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap(),
            _ => {}
        }
        let before = file.metadata().unwrap();
        let mut import = writer
            .begin_image(
                image(&[&tar]),
                ImportOptions {
                    sharing: SharingOptions {
                        allow_compatible_hardlinks: allow,
                    },
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let layer = import.put_layer(0, source).await.unwrap();
        import
            .prepare_publication()
            .await
            .unwrap()
            .finish(&[])
            .await
            .unwrap();
        assert_eq!(
            layer.stats.copied_bytes + layer.stats.reflinked_bytes + layer.stats.hardlinked_bytes,
            payload.len() as u64
        );
        if !allow || !mismatch.is_empty() {
            assert_eq!(layer.stats.hardlinked_files, 0);
        } else if !memfd && layer.stats.reflinked_files == 0 {
            assert_eq!(layer.stats.hardlinked_files, 1);
        }
        if memfd {
            assert_eq!(layer.stats.copied_files, 1);
        }
        let after = file.metadata().unwrap();
        if mismatch == "xattr" {
            let mut buffer = [0; 32];
            let n = rustix::fs::fgetxattr(&file, "user.source", &mut buffer).unwrap();
            assert_eq!(&buffer[..n], b"preserve");
        }
        assert_eq!(
            (
                before.mode(),
                before.uid(),
                before.gid(),
                before.mtime(),
                before.mtime_nsec()
            ),
            (
                after.mode(),
                after.uid(),
                after.gid(),
                after.mtime(),
                after.mtime_nsec()
            )
        );
        let root = temp.path().join("graph");
        let target = root.join(format!("overlay/{}/diff/payload", layer.storage_layer_id));
        let stat = std::fs::metadata(target).unwrap();
        assert_eq!(
            (stat.ino(), stat.dev()) == (after.ino(), after.dev()),
            layer.stats.hardlinked_files == 1
        );
        assert_eq!(reconstruct(&root, &layer.storage_layer_id), tar);
    }
}

#[tokio::test]
async fn diff_mismatch_cleans_incomplete_state() {
    let (temp, writer) = store().await;
    let tar = tar_bytes(b"contents", false);
    let wrong = tar_bytes(b"different", false);
    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    assert!(
        import
            .put_layer(0, TarSource(Cursor::new(wrong)))
            .await
            .is_err()
    );
    import.abort().await.unwrap();
    let layer_json = std::fs::read(temp.path().join("graph/overlay-layers/layers.json")).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&layer_json).unwrap(),
        json!([])
    );
    assert_eq!(
        std::fs::read_dir(temp.path().join("graph/overlay/l"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn recovery_validates_before_taking_ownership_of_unsupported_layers() {
    let (temp, writer) = store().await;
    let graph = temp.path().join("graph");
    std::fs::create_dir_all(graph.join("overlay/interrupted/diff")).unwrap();
    std::os::unix::fs::symlink("../interrupted/diff", graph.join("overlay/l/SHORT")).unwrap();
    let record = json!({"id":"interrupted","flags":{"incomplete":true,"caller-defined":1}});
    let path = graph.join("overlay-layers/layers.json");
    let original = serde_json::to_vec(&vec![record]).unwrap();
    std::fs::write(&path, &original).unwrap();
    let tar = tar_bytes(b"contents", false);
    assert!(matches!(
        writer.begin_image(image(&[&tar]), Default::default()).await,
        Err(ImportError::UnsupportedStore(_))
    ));
    assert!(graph.join("overlay/interrupted/diff").exists());
    assert!(graph.join("overlay/l/SHORT").symlink_metadata().is_ok());
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[tokio::test]
async fn unrelated_mapped_layers_and_custom_flags_do_not_block_publication() {
    for filename in ["layers.json", "volatile-layers.json"] {
        for (key, value) in [
            (
                "uidmap",
                json!([{"container_id":0,"host_id":100000,"size":65536}]),
            ),
            (
                "gidmap",
                json!([{"container_id":0,"host_id":100000,"size":65536}]),
            ),
            ("flags", json!({"caller-defined":{"value":[1,true]}})),
        ] {
            let (temp, writer) = store().await;
            let path = temp.path().join("graph/overlay-layers").join(filename);
            let mut unrelated = json!({"id":"unrelated","parent":"","custom":"preserve"});
            unrelated[key] = value;
            std::fs::write(&path, serde_json::to_vec(&vec![unrelated.clone()]).unwrap()).unwrap();
            let tar = tar_bytes(b"contents", false);
            let mut import = writer
                .begin_image(image(&[&tar]), Default::default())
                .await
                .unwrap();
            assert_eq!(import.layer_status(0).unwrap(), LayerStatus::Missing);
            import
                .put_layer(0, TarSource(Cursor::new(tar.clone())))
                .await
                .unwrap();
            import
                .prepare_publication()
                .await
                .unwrap()
                .finish(&[])
                .await
                .unwrap();
            let records: Vec<Value> =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert!(records.contains(&unrelated), "{filename}: {key}");
        }
    }
}

#[tokio::test]
async fn layer_reuse_refuses_incompatible_records_at_go_layer_ids() {
    for target in [0, 1] {
        for (key, value, compatible) in [
            (
                "uidmap",
                json!([{"container_id":0,"host_id":100000,"size":65536}]),
                false,
            ),
            (
                "gidmap",
                json!([{"container_id":0,"host_id":100000,"size":65536}]),
                false,
            ),
            ("flags", json!({"caller-defined":true}), false),
            ("flags", json!({"volatile":true}), false),
            (
                "flags",
                json!({"incomplete":false,"expected-layer-diffid":"placeholder"}),
                true,
            ),
        ] {
            let (temp, writer) = store().await;
            let a = tar_bytes(b"base", false);
            let b = tar_bytes(b"top", false);
            let mut import = writer
                .begin_image(image(&[&a, &b]), Default::default())
                .await
                .unwrap();
            import
                .put_layer(0, TarSource(Cursor::new(a.clone())))
                .await
                .unwrap();
            import
                .put_layer(1, TarSource(Cursor::new(b.clone())))
                .await
                .unwrap();
            import.abort().await.unwrap();
            let path = temp.path().join("graph/overlay-layers/layers.json");
            let mut layers: Vec<Value> =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            layers[target][key] = value.clone();
            if compatible {
                layers[target]["flags"]["expected-layer-diffid"] =
                    layers[target]["diff-digest"].clone();
            }
            let original = layers[target].clone();
            std::fs::write(&path, serde_json::to_vec(&layers).unwrap()).unwrap();
            let original_bytes = std::fs::read(&path).unwrap();
            let mut retry = writer
                .begin_image(image(&[&a, &b]), Default::default())
                .await
                .unwrap();
            if !compatible {
                for index in 0..target {
                    assert!(matches!(
                        retry.layer_status(index as u32).unwrap(),
                        LayerStatus::Reusable(_)
                    ));
                }
                assert!(matches!(
                    retry.layer_status(target as u32),
                    Err(ImportError::MetadataConflict(_))
                ));
                retry.abort().await.unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
                continue;
            }
            let base = retry
                .put_layer(0, TarSource(Cursor::new(a.clone())))
                .await
                .unwrap();
            let top = retry
                .put_layer(1, TarSource(Cursor::new(b.clone())))
                .await
                .unwrap();
            assert!(base.reused, "base: {key}, target={target}");
            assert!(top.reused, "top: {key}, target={target}");
            retry
                .prepare_publication()
                .await
                .unwrap()
                .finish(&[])
                .await
                .unwrap();
            let mut layers: Vec<Value> =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert!(layers.contains(&original));
            // Published images also validate flags when retaining an entire chain.
            layers[target]["flags"] = json!({"caller-defined":true});
            std::fs::write(&path, serde_json::to_vec(&layers).unwrap()).unwrap();
            assert!(matches!(
                writer
                    .begin_image(image(&[&a, &b]), Default::default())
                    .await,
                Err(ImportError::UnsupportedStore(_))
            ));
        }
    }
}

#[tokio::test]
async fn preserves_unrelated_records_and_complete_orphans() {
    let (temp, writer) = store().await;
    let root = temp.path().join("graph");
    let unrelated = json!({"id":"old-image","names":["old:tag"],"custom":{"future":[1,2]}});
    std::fs::write(
        root.join("overlay-images/images.json"),
        serde_json::to_vec(&vec![unrelated.clone()]).unwrap(),
    )
    .unwrap();
    let tar = tar_bytes(b"contents", false);
    let mut import = writer
        .begin_image(image(&[&tar]), ImportOptions::default())
        .await
        .unwrap();
    let layer = import
        .put_layer(0, TarSource(Cursor::new(tar.clone())))
        .await
        .unwrap();
    let abort = import.abort().await.unwrap();
    assert_eq!(abort.retained_layers, vec![layer.storage_layer_id.clone()]);
    let mut retry = writer
        .begin_image(image(&[&tar]), ImportOptions::default())
        .await
        .unwrap();
    assert_eq!(
        retry.layer_status(0).unwrap(),
        LayerStatus::Reusable(layer.storage_layer_id)
    );
    retry
        .prepare_publication()
        .await
        .unwrap()
        .finish(&[])
        .await
        .unwrap();
    let records: Vec<Value> =
        serde_json::from_slice(&std::fs::read(root.join("overlay-images/images.json")).unwrap())
            .unwrap();
    assert_eq!(
        records
            .iter()
            .find(|record| record["id"] == "old-image")
            .unwrap(),
        &unrelated
    );
}
