use super::*;

fn mapping() -> Value {
    json!([{"container_id":0,"host_id":100000,"size":65536}])
}

async fn import_layers(writer: &TestStore, layers: &[&[u8]]) -> ImageImport {
    let mut import = writer
        .begin_image(image(layers), Default::default())
        .await
        .unwrap();
    for (index, bytes) in layers.iter().enumerate() {
        import
            .put_layer(index as u32, TarSource(Cursor::new(bytes.to_vec())))
            .await
            .unwrap();
    }
    import
}

#[tokio::test]
async fn unmapped_candidates_can_coexist_with_multiple_mapping_variants() {
    let (temp, writer) = store().await;
    let tar = tar_bytes(b"contents", false);
    let retained = import_layers(&writer, &[&tar]).await.abort().await.unwrap();
    let graph = temp.path().join("graph");
    let path = graph.join("overlay-layers/layers.json");
    let canonical: Vec<Value> = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut layers = Vec::new();
    for (id, key) in [("uid-variant", "uidmap"), ("gid-variant", "gidmap")] {
        let mut variant = canonical[0].clone();
        variant["id"] = id.into();
        variant[key] = mapping();
        std::fs::create_dir_all(graph.join(format!("overlay/{id}/diff"))).unwrap();
        std::fs::copy(
            graph.join(format!(
                "overlay-layers/{}.tar-split.gz",
                retained.retained_layers[0]
            )),
            graph.join(format!("overlay-layers/{id}.tar-split.gz")),
        )
        .unwrap();
        layers.push(variant);
    }
    // Put mapped candidates first so selection cannot accidentally rely on order.
    layers.extend(canonical);
    std::fs::write(&path, serde_json::to_vec(&layers).unwrap()).unwrap();
    let original = std::fs::read(&path).unwrap();
    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    assert_eq!(
        import.layer_status(0).unwrap(),
        LayerStatus::Reusable(retained.retained_layers[0].clone())
    );
    let published = import
        .prepare_publication()
        .await
        .unwrap()
        .finish(&[])
        .await
        .unwrap();
    assert_eq!(published.layer_ids, retained.retained_layers);
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[tokio::test]
async fn new_chains_require_compatible_layouts_at_go_layer_ids() {
    for (layout, reusable) in [
        ("rotated", false),
        ("template", false),
        ("lower-layers", false),
        ("short-link", false),
        ("legacy", true),
        ("id-based", true),
    ] {
        let (temp, writer) = store().await;
        let a = tar_bytes(b"base", false);
        let b = tar_bytes(b"top", false);
        let retained = import_layers(&writer, &[&a, &b])
            .await
            .abort()
            .await
            .unwrap();
        let graph = temp.path().join("graph");
        let top = graph.join("overlay").join(&retained.retained_layers[1]);
        match layout {
            "rotated" => {
                std::fs::rename(top.join("diff"), top.join("diff1")).unwrap();
                std::fs::create_dir(top.join("diff")).unwrap();
            }
            "template" => std::fs::write(top.join("lower"), "l/TEMPLATE").unwrap(),
            "lower-layers" => std::fs::write(top.join("lower-layers"), "template-id").unwrap(),
            "short-link" => {
                let link = std::fs::read_to_string(top.join("link")).unwrap();
                let path = graph.join("overlay/l").join(link);
                std::fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink("../template/diff", path).unwrap();
            }
            "legacy" => std::fs::remove_file(top.join("lower-layers")).unwrap(),
            "id-based" => std::fs::remove_file(top.join("lower")).unwrap(),
            _ => unreachable!(),
        }
        let mut import = writer
            .begin_image(image(&[&a, &b]), Default::default())
            .await
            .unwrap();
        assert_eq!(
            import.layer_status(0).unwrap(),
            LayerStatus::Reusable(retained.retained_layers[0].clone()),
            "{layout}"
        );
        if !reusable {
            let original = std::fs::read(graph.join("overlay-layers/layers.json")).unwrap();
            assert!(
                matches!(
                    import.layer_status(1),
                    Err(ImportError::MetadataConflict(_))
                ),
                "{layout}"
            );
            assert!(
                matches!(
                    import.put_layer(1, TarSource(Cursor::new(b.clone()))).await,
                    Err(ImportError::MetadataConflict(_))
                ),
                "{layout}"
            );
            import.abort().await.unwrap();
            assert_eq!(
                std::fs::read(graph.join("overlay-layers/layers.json")).unwrap(),
                original
            );
            continue;
        }
        assert_eq!(
            import.layer_status(1).unwrap(),
            LayerStatus::Reusable(retained.retained_layers[1].clone()),
            "{layout}"
        );
        let top = import
            .put_layer(1, TarSource(Cursor::new(b.clone())))
            .await
            .unwrap();
        assert_eq!(top.reused, reusable, "{layout}");
        assert_eq!(
            top.storage_layer_id == retained.retained_layers[1],
            reusable
        );
        assert_eq!(reconstruct(&graph, &top.storage_layer_id), b);
        import.abort().await.unwrap();
    }
}

#[tokio::test]
async fn existing_images_retain_mapped_chains_for_name_updates() {
    for key in ["uidmap", "gidmap", "both", "unshifted"] {
        let (temp, writer) = store().await;
        let a = tar_bytes(b"base", false);
        let b = tar_bytes(b"top", false);
        let published = import_layers(&writer, &[&a, &b])
            .await
            .prepare_publication()
            .await
            .unwrap()
            .finish(&["localhost/example:original".into()])
            .await
            .unwrap();
        let graph = temp.path().join("graph");
        let layer_path = graph.join("overlay-layers/layers.json");
        let mut layers: Vec<Value> =
            serde_json::from_slice(&std::fs::read(&layer_path).unwrap()).unwrap();
        if key == "both" {
            layers[0]["uidmap"] = mapping();
            layers[1]["gidmap"] = mapping();
        } else if key != "unshifted" {
            layers[1][key] = mapping();
        }
        std::fs::write(&layer_path, serde_json::to_vec(&layers).unwrap()).unwrap();
        let original_layers = std::fs::read(&layer_path).unwrap();
        let top = graph.join("overlay").join(&published.layer_ids[1]);
        std::fs::rename(top.join("diff"), top.join("diff1")).unwrap();
        std::fs::create_dir(top.join("diff")).unwrap();
        let image_path = graph.join("overlay-images/images.json");
        let mut images: Vec<Value> =
            serde_json::from_slice(&std::fs::read(&image_path).unwrap()).unwrap();
        // Preserve alternate-top metadata without interpreting those layouts.
        images[0]["mapped-layers"] = json!(["another-mapping"]);
        images[0]["custom"] = json!({"preserve":true});
        std::fs::write(&image_path, serde_json::to_vec(&images).unwrap()).unwrap();

        let mut import = writer
            .begin_image(image(&[&a, &b]), Default::default())
            .await
            .unwrap();
        // The entire image is selected together, including parents, before any
        // status queries. Supplying an empty source must never start extraction.
        assert_eq!(
            import.layer_status(1).unwrap(),
            LayerStatus::Reusable(published.layer_ids[1].clone())
        );
        for index in 0..2 {
            assert!(
                import
                    .put_layer(index, TarSource(Cursor::new(Vec::new())))
                    .await
                    .unwrap()
                    .reused
            );
        }
        let retry = import
            .prepare_publication()
            .await
            .unwrap()
            .finish(&["localhost/example:updated".into()])
            .await
            .unwrap();
        assert!(retry.already_present);
        assert_eq!(retry.layer_ids, published.layer_ids);
        assert_eq!(
            retry.stats,
            MaterializationStats {
                reused_layers: 2,
                reused_bytes: (a.len() + b.len()) as u64,
                ..Default::default()
            }
        );
        assert_eq!(std::fs::read(&layer_path).unwrap(), original_layers);
        let updated: Vec<Value> =
            serde_json::from_slice(&std::fs::read(&image_path).unwrap()).unwrap();
        images[0]["names"] = json!(["localhost/example:original", "localhost/example:updated"]);
        images[0]["names-history"] =
            json!(["localhost/example:updated", "localhost/example:original"]);
        assert_eq!(updated, images);
        assert!(!top.join("diff/payload").exists());
        assert_eq!(std::fs::read(top.join("diff1/payload")).unwrap(), b"top");

        // A different image cannot replace a mapped/rotated canonical ID.
        let extra = tar_bytes(b"extra", false);
        let mut import = writer
            .begin_image(image(&[&a, &b, &extra]), Default::default())
            .await
            .unwrap();
        if key == "both" {
            assert!(matches!(
                import.layer_status(0),
                Err(ImportError::MetadataConflict(_))
            ));
        } else {
            import.layer_status(0).unwrap();
            assert!(matches!(
                import.layer_status(1),
                Err(ImportError::MetadataConflict(_))
            ));
        }
        import.abort().await.unwrap();
    }
}

#[tokio::test]
async fn existing_images_still_validate_layer_identity_and_presence() {
    for problem in [
        "digest",
        "parent",
        "incomplete",
        "diff",
        "tar-split",
        "size",
        "writable",
    ] {
        let (temp, writer) = store().await;
        let tar = tar_bytes(b"contents", false);
        let published = import_layers(&writer, &[&tar])
            .await
            .prepare_publication()
            .await
            .unwrap()
            .finish(&[])
            .await
            .unwrap();
        let graph = temp.path().join("graph");
        let path = graph.join("overlay-layers/layers.json");
        let mut layers: Vec<Value> =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        layers[0]["uidmap"] = mapping();
        match problem {
            "digest" => layers[0]["diff-digest"] = records::digest(b"different").into(),
            "parent" => layers[0]["parent"] = published.layer_ids[0].clone().into(),
            "incomplete" => layers[0]["flags"] = json!({"incomplete":true}),
            "diff" => std::fs::remove_dir_all(
                graph
                    .join("overlay")
                    .join(&published.layer_ids[0])
                    .join("diff"),
            )
            .unwrap(),
            "tar-split" => std::fs::remove_file(graph.join(format!(
                "overlay-layers/{}.tar-split.gz",
                published.layer_ids[0]
            )))
            .unwrap(),
            "size" => layers[0]["diff-size"] = 1.into(),
            "writable" => {
                let dir = graph.join("overlay-containers");
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(
                    dir.join("containers.json"),
                    serde_json::to_vec(&json!([{"id":"container","layer":published.layer_ids[0]}]))
                        .unwrap(),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let original_layers = serde_json::to_vec(&layers).unwrap();
        std::fs::write(&path, &original_layers).unwrap();
        let images = graph.join("overlay-images/images.json");
        let original_images = std::fs::read(&images).unwrap();
        let result = writer.begin_image(image(&[&tar]), Default::default()).await;
        match problem {
            "digest" | "parent" => assert!(
                matches!(result, Err(ImportError::MetadataConflict(_))),
                "{problem}: {result:?}"
            ),
            "size" => assert!(
                matches!(result, Err(ImportError::Malformed(_))),
                "{problem}: {result:?}"
            ),
            _ => assert!(
                matches!(result, Err(ImportError::RecoveryRequired(_))),
                "{problem}: {result:?}"
            ),
        }
        assert_eq!(std::fs::read(path).unwrap(), original_layers);
        assert_eq!(std::fs::read(images).unwrap(), original_images);
    }
}

#[tokio::test]
async fn recovery_removes_mapped_layers_only_when_unreferenced() {
    for key in ["uidmap", "gidmap"] {
        for reference in [
            "none",
            "image",
            "mapped-image",
            "child",
            "container",
            "mount",
        ] {
            let (temp, writer) = store().await;
            let graph = temp.path().join("graph");
            let dir = graph.join("overlay/interrupted");
            std::fs::create_dir_all(dir.join("diff")).unwrap();
            std::fs::create_dir(dir.join("diff1")).unwrap();
            std::fs::write(dir.join("diff1/payload"), b"shifted contents").unwrap();
            let link = graph.join("overlay/l/SHORT");
            std::os::unix::fs::symlink("../interrupted/diff", &link).unwrap();
            let tar_split = graph.join("overlay-layers/interrupted.tar-split.gz");
            std::fs::write(&tar_split, b"partial").unwrap();
            let mut record = json!({"id":"interrupted","flags":{"incomplete":true}});
            record[key] = mapping();
            let mut layers = vec![record];
            let target = match reference {
                "none" => None,
                "image" => Some((
                    graph.join("overlay-images/images.json"),
                    json!({"id":"other","layer":"interrupted"}),
                )),
                "mapped-image" => Some((
                    graph.join("overlay-images/images.json"),
                    json!({"id":"other","mapped-layers":["interrupted"]}),
                )),
                "child" => {
                    layers.push(json!({"id":"child","parent":"interrupted"}));
                    None
                }
                "container" => Some((
                    graph.join("overlay-containers/containers.json"),
                    json!({"id":"other","layer":"interrupted"}),
                )),
                "mount" => Some((
                    temp.path().join("run/overlay-layers/mountpoints.json"),
                    json!({"id":"interrupted","count":1}),
                )),
                _ => unreachable!(),
            };
            if let Some((path, record)) = target {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, serde_json::to_vec(&vec![record]).unwrap()).unwrap();
            }
            let path = graph.join("overlay-layers/layers.json");
            let original = serde_json::to_vec(&layers).unwrap();
            std::fs::write(&path, &original).unwrap();
            let result = writer.begin_image(image(&[]), Default::default()).await;
            if reference == "none" {
                result.unwrap().abort().await.unwrap();
                assert!(!dir.exists());
                assert!(link.symlink_metadata().is_err());
                assert!(!tar_split.exists());
                let layers: Vec<Value> =
                    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                assert!(layers.is_empty());
            } else {
                assert!(
                    matches!(result, Err(ImportError::RecoveryRequired(_))),
                    "{key}, {reference}: {result:?}"
                );
                assert_eq!(std::fs::read(path).unwrap(), original);
                assert_eq!(
                    std::fs::read(dir.join("diff1/payload")).unwrap(),
                    b"shifted contents"
                );
                assert_eq!(std::fs::read(tar_split).unwrap(), b"partial");
                assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
            }
        }
    }
}
