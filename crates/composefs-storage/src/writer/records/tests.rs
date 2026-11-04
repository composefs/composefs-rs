use serde_json::json;

use super::super::tests::image;
use super::*;

fn round_trip<T: Record + serde::Serialize>(value: Value) -> T {
    let bytes = serde_json::to_vec(&vec![&value]).unwrap();
    let mut records = parse_records::<T>(&bytes, "records.json").unwrap();
    assert_eq!(serde_json::to_value(&records[0]).unwrap(), value);
    records.pop().unwrap()
}

#[test]
fn typed_records_preserve_unknown_fields_and_explicit_empty_values() {
    for value in [
        json!({"id":"layer", "future":null}),
        json!({
            "id":"layer", "parent":"", "diff-size":-1, "uidset":[], "gidset":[],
            "uidmap":[{"container_id":0,"host_id":100000,"size":65536,"future":null}],
            "flags":{"incomplete":false,"expected-layer-diffid":"expected","future":{"values":[1,null,true]}},
            "custom":{"future":[1,2]}
        }),
    ] {
        let layer = round_trip::<LayerRecord>(value);
        assert!(!layer.is_incomplete());
        assert_eq!(layer.uncompressed_size(), None);
    }
    round_trip::<ImageRecord>(json!({
        "id":"image", "layer":"", "names":[], "names-history":[], "mapped-layers":["mapped"],
        "big-data-names":[], "big-data-sizes":{"manifest":-1}, "big-data-digests":{},
        "flags":{"custom":null}, "custom":{"future":[1,2]}
    }));
    round_trip::<ContainerRecord>(json!({"id":"container", "layer":"writable", "future":null}));
    round_trip::<MountRecord>(json!({"id":"layer", "count":0, "path":"", "future":{"key":42}}));
}

#[test]
fn optional_null_fields_normalize_to_absent_while_unknown_nulls_are_retained() {
    let bytes = br#"[{"id":"layer","parent":null,"uidmap":null,"flags":null,"future":null}]"#;
    let layers = parse_records::<LayerRecord>(bytes, "layers.json").unwrap();
    assert_eq!(layers[0].parent(), "");
    assert!(layers[0].is_reusable());
    assert_eq!(
        serde_json::to_value(layers).unwrap(),
        json!([{"id":"layer","future":null}])
    );
    let bytes = br#"[{"id":"image","names":null,"mapped-layers":null,"future":null}]"#;
    let images = parse_records::<ImageRecord>(bytes, "images.json").unwrap();
    assert_eq!(
        serde_json::to_value(images).unwrap(),
        json!([{"id":"image","future":null}])
    );
}

#[test]
fn malformed_known_record_fields_are_rejected() {
    for patch in [
        json!({"parent":false}),
        json!({"diff-digest":42}),
        json!({"diff-size":"large"}),
        json!({"flags":[]}),
        json!({"flags":{"incomplete":"true"}}),
        json!({"flags":{"incomplete":null}}),
        json!({"flags":{"expected-layer-diffid":null}}),
        json!({"uidmap":{}}),
        json!({"uidmap":[{"container_id":"root","host_id":0,"size":1}]}),
    ] {
        let mut value = json!({"id":"layer"});
        value
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        let bytes = serde_json::to_vec(&vec![value]).unwrap();
        assert!(
            matches!(
                parse_records::<LayerRecord>(&bytes, "layers.json"),
                Err(ImportError::RecoveryRequired(_))
            ),
            "{patch}"
        );
    }
    for patch in [
        json!({"layer":false}),
        json!({"names":[42]}),
        json!({"names-history":"old"}),
        json!({"mapped-layers":{}}),
        json!({"big-data-sizes":{"manifest":"large"}}),
    ] {
        let mut value = json!({"id":"image"});
        value
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        let bytes = serde_json::to_vec(&vec![value]).unwrap();
        assert!(
            matches!(
                parse_records::<ImageRecord>(&bytes, "images.json"),
                Err(ImportError::RecoveryRequired(_))
            ),
            "{patch}"
        );
    }
}

#[test]
fn typed_records_require_safe_unique_ids() {
    for values in [
        json!([{}]),
        json!([{"id":42}]),
        json!([{"id":""}]),
        json!([{"id":"../outside"}]),
        json!([{"id":"same"},{"id":"same"}]),
    ] {
        let bytes = serde_json::to_vec(&values).unwrap();
        assert!(
            matches!(
                parse_records::<LayerRecord>(&bytes, "layers.json"),
                Err(ImportError::RecoveryRequired(_))
            ),
            "{values}"
        );
    }
}

fn descriptor(media_type: MediaType, bytes: &[u8]) -> Descriptor {
    serde_json::from_value(json!({
        "mediaType": media_type,
        "digest": digest(bytes),
        "size": bytes.len(),
    }))
    .unwrap()
}

#[test]
fn allow_missing_only_suppresses_missing_entries() {
    use std::io::{Error, ErrorKind};

    assert_eq!(allow_missing(Ok::<_, Error>(42)).unwrap(), Some(42));
    assert_eq!(
        allow_missing(Err::<(), _>(rustix::io::Errno::NOENT)).unwrap(),
        None
    );
    for kind in [
        ErrorKind::NotFound,
        ErrorKind::PermissionDenied,
        ErrorKind::NotADirectory,
        ErrorKind::InvalidData,
    ] {
        let result = allow_missing(Err::<(), _>(Error::new(kind, "original error")));
        let wrapped = allow_missing(Err::<(), _>(ImportError::Io(Error::new(
            kind,
            "original error",
        ))));
        for result in [result, wrapped] {
            if kind == ErrorKind::NotFound {
                assert_eq!(result.unwrap(), None);
            } else {
                let ImportError::Io(error) = result.unwrap_err() else {
                    panic!("lost the I/O error for {kind:?}");
                };
                assert_eq!(error.kind(), kind);
                assert_eq!(error.to_string(), "original error");
            }
        }
    }
    assert!(matches!(
        allow_missing(Err::<(), _>(ImportError::Malformed("original error".into()))),
        Err(ImportError::Malformed(message)) if message == "original error"
    ));
}

#[test]
fn manifest_validation() {
    let raw = image(&[]);
    let config = descriptor(MediaType::ImageConfig, &raw.config_json);
    let base: Value = serde_json::from_slice(&raw.manifest_json).unwrap();
    let manifest = validate_manifest(&raw.manifest_json, &raw.expected_manifest).unwrap();
    assert_eq!(manifest.config(), &config);
    assert!(manifest.layers().is_empty());

    let mut without_media_type = base.clone();
    without_media_type
        .as_object_mut()
        .unwrap()
        .remove("mediaType");
    let bytes = serde_json::to_vec(&without_media_type).unwrap();
    let manifest = validate_manifest(&bytes, &digest(&bytes).parse().unwrap()).unwrap();
    assert_eq!(manifest.media_type(), &None);
    assert_eq!(manifest.config(), &config);
    assert!(manifest.layers().is_empty());

    for (patch, expected) in [
        (
            json!({"schemaVersion": 1}),
            "requires a single-platform OCI image manifest and config",
        ),
        (
            json!({"mediaType": null}),
            "requires a single-platform OCI image manifest and config",
        ),
        (
            json!({"mediaType": "application/vnd.docker.distribution.manifest.v2+json"}),
            "requires a single-platform OCI image manifest and config",
        ),
        (
            json!({"mediaType": "application/vnd.oci.image.index.v1+json"}),
            "requires a single-platform OCI image manifest and config",
        ),
        (
            json!({"config": descriptor(MediaType::ImageLayer, b"{}")}),
            "requires a single-platform OCI image manifest and config",
        ),
        (
            json!({"artifactType": null}),
            "artifacts and referrers are not supported",
        ),
        (
            json!({"subject": null}),
            "artifacts and referrers are not supported",
        ),
    ] {
        let mut value = base.clone();
        value
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        let bytes = serde_json::to_vec(&value).unwrap();
        let error = validate_manifest(&bytes, &digest(&bytes).parse().unwrap()).unwrap_err();
        assert!(
            matches!(error, ImportError::Malformed(ref message) if message == expected),
            "{patch}: {error}"
        );
    }
}

#[test]
fn config_validation() {
    let raw = image(&[]);
    let base: Value = serde_json::from_slice(&raw.config_json).unwrap();
    for (os, rootfs, accepted) in [
        ("linux", "layers", true),
        ("windows", "layers", false),
        ("linux", "other", false),
    ] {
        let mut config = base.clone();
        config["os"] = os.into();
        config["rootfs"]["type"] = rootfs.into();
        let bytes = serde_json::to_vec(&config).unwrap();
        let result = validate_config(&bytes, &descriptor(MediaType::ImageConfig, &bytes));
        if accepted {
            let config = result.unwrap();
            assert_eq!(config.os().to_string(), os);
            assert_eq!(config.rootfs().typ(), rootfs);
            assert!(config.rootfs().diff_ids().is_empty());
        } else {
            assert!(
                matches!(result, Err(ImportError::Malformed(ref message)) if message == "requires a Linux layered image config"),
                "{os}/{rootfs}: {result:?}"
            );
        }
    }
}

#[test]
fn metadata_identity_and_json_validation() {
    let bytes = b"invalid JSON";
    let expected = digest(bytes).parse().unwrap();
    assert!(matches!(
        validate_manifest(bytes, &expected),
        Err(ImportError::Json(_))
    ));
    assert!(matches!(
        validate_config(bytes, &descriptor(MediaType::ImageConfig, bytes)),
        Err(ImportError::Json(_))
    ));
    assert!(matches!(
        validate_manifest(bytes, &digest(b"other").parse().unwrap()),
        Err(ImportError::DigestMismatch {
            kind: "manifest",
            ..
        })
    ));
    let config = descriptor(MediaType::ImageConfig, b"other");
    assert!(matches!(
        validate_config(bytes, &config),
        Err(ImportError::DigestMismatch { kind: "config", .. })
    ));
    let mut config = descriptor(MediaType::ImageConfig, bytes);
    config.set_size(bytes.len() as u64 + 1);
    assert!(matches!(
        validate_config(bytes, &config),
        Err(ImportError::Malformed(ref message)) if message == "config descriptor size mismatch"
    ));
    for invalid in [
        format!("sha512:{}", "0".repeat(128)),
        format!("sha384:{}", "0".repeat(96)),
    ] {
        let expected = invalid.parse().unwrap();
        assert!(matches!(
            validate_manifest(bytes, &expected),
            Err(ImportError::Malformed(_))
        ));
        config.set_digest(expected);
        assert!(matches!(
            validate_config(bytes, &config),
            Err(ImportError::Malformed(_))
        ));
    }
}

#[test]
fn layer_descriptor_validation() {
    let diff = digest(b"tar");
    for (media_type, blob, accepted) in [
        (MediaType::ImageLayer, b"tar".as_slice(), true),
        (MediaType::ImageLayer, b"different".as_slice(), false),
        (MediaType::ImageLayerGzip, b"compressed".as_slice(), true),
        (MediaType::ImageLayerZstd, b"compressed".as_slice(), true),
        (
            MediaType::ImageLayerNonDistributable,
            b"tar".as_slice(),
            false,
        ),
        (MediaType::ImageConfig, b"tar".as_slice(), false),
    ] {
        let result = validate_layer_descriptors(
            &[descriptor(media_type.clone(), blob)],
            std::slice::from_ref(&diff),
        );
        if accepted {
            assert_eq!(result.unwrap(), vec![diff.parse::<OciDigest>().unwrap()]);
        } else if media_type == MediaType::ImageLayer {
            assert!(
                matches!(
                    result,
                    Err(ImportError::DigestMismatch {
                        kind: "uncompressed layer descriptor",
                        ..
                    })
                ),
                "{result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(ImportError::Malformed(ref message)) if message == &format!("unsupported layer descriptor: {media_type}")),
                "{result:?}"
            );
        }
    }
}

#[test]
fn layer_digest_validation() {
    let diff = digest(b"tar");
    let mut layer = descriptor(MediaType::ImageLayer, b"tar");
    assert!(matches!(
        validate_layer_descriptors(std::slice::from_ref(&layer), &["invalid digest".into()]),
        Err(ImportError::Malformed(_))
    ));
    for invalid in [
        format!("sha512:{}", "0".repeat(128)),
        format!("sha384:{}", "0".repeat(96)),
    ] {
        layer.set_digest(diff.parse().unwrap());
        assert!(
            matches!(
                validate_layer_descriptors(
                    std::slice::from_ref(&layer),
                    std::slice::from_ref(&invalid)
                ),
                Err(ImportError::Malformed(_))
            ),
            "{invalid}"
        );
        layer.set_digest(invalid.parse().unwrap());
        assert!(
            matches!(
                validate_layer_descriptors(
                    std::slice::from_ref(&layer),
                    std::slice::from_ref(&diff)
                ),
                Err(ImportError::Malformed(_))
            ),
            "{invalid}"
        );
    }
}

#[test]
fn layer_count_validation() {
    let layer = descriptor(MediaType::ImageLayer, b"tar");
    let diff = digest(b"tar");
    let max = overlay::MAX_IMAGE_LAYERS;
    for (layers, diffs, accepted) in [
        (0, 0, true),
        (1, 1, true),
        (0, 1, false),
        (1, 0, false),
        (max, max, true),
        (max + 1, max + 1, false),
    ] {
        let result =
            validate_layer_descriptors(&vec![layer.clone(); layers], &vec![diff.clone(); diffs]);
        if accepted {
            assert_eq!(
                result.unwrap(),
                vec![diff.parse::<OciDigest>().unwrap(); diffs]
            );
        } else {
            assert!(
                matches!(result, Err(ImportError::Malformed(ref message)) if message == &format!("layer/config count mismatch or overlay depth exceeds {max}")),
                "layers={layers}, diffs={diffs}: {result:?}"
            );
        }
    }
}
