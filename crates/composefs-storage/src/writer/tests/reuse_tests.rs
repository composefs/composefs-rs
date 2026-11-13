use super::*;

#[test]
fn layer_ids_match_go_parent_and_diff_id_vectors() {
    for (parent, diff, expected) in [
        (String::new(), "a".repeat(64), "a".repeat(64)),
        (
            "a".repeat(64),
            "b".repeat(64),
            "76f79efda453922cda1cecb6ec9e7cf9d86ea968c6dd199d4030dd00078a1686".into(),
        ),
        (
            "1234567890abcdef".repeat(4),
            "a".repeat(64),
            "f030f2df183c79a73526b7d39392035a5cfc9537aafcbccf4940bb76d618bcea".into(),
        ),
    ] {
        let diff = format!("sha256:{diff}").parse().unwrap();
        assert_eq!(records::layer_id(&parent, &diff), expected);
    }
}

#[tokio::test]
async fn new_chains_preserve_arbitrary_id_layers_and_create_go_ids() {
    let (temp, writer) = store().await;
    let tar = tar_bytes(b"legacy layer", false);
    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    let old = import
        .put_layer(0, TarSource(Cursor::new(tar.clone())))
        .await
        .unwrap();
    import.abort().await.unwrap();
    let graph = temp.path().join("graph");
    let legacy = "legacy-layer";
    std::fs::rename(
        graph.join(format!("overlay/{}", old.storage_layer_id)),
        graph.join(format!("overlay/{legacy}")),
    )
    .unwrap();
    std::fs::rename(
        graph.join(format!(
            "overlay-layers/{}.tar-split.gz",
            old.storage_layer_id
        )),
        graph.join(format!("overlay-layers/{legacy}.tar-split.gz")),
    )
    .unwrap();
    let link = std::fs::read_to_string(graph.join(format!("overlay/{legacy}/link"))).unwrap();
    let link_path = graph.join("overlay/l").join(link);
    std::fs::remove_file(&link_path).unwrap();
    std::os::unix::fs::symlink(format!("../{legacy}/diff"), &link_path).unwrap();
    let path = graph.join("overlay-layers/layers.json");
    let mut layers: Vec<Value> = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    layers[0]["id"] = legacy.into();
    let original = layers[0].clone();
    std::fs::write(&path, serde_json::to_vec(&layers).unwrap()).unwrap();

    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    assert_eq!(import.layer_status(0).unwrap(), LayerStatus::Missing);
    let layer = import
        .put_layer(0, TarSource(Cursor::new(tar.clone())))
        .await
        .unwrap();
    assert_eq!(layer.storage_layer_id, old.storage_layer_id);
    assert!(!layer.reused);
    import
        .prepare_publication()
        .await
        .unwrap()
        .finish(&[])
        .await
        .unwrap();
    let layers: Vec<Value> = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(layers.len(), 2);
    assert!(layers.contains(&original));
    assert_eq!(reconstruct(&graph, legacy), tar);
    assert_eq!(reconstruct(&graph, &layer.storage_layer_id), tar);
}

#[tokio::test]
async fn failed_installation_preserves_preexisting_dangling_links() {
    let (temp, writer) = store().await;
    let tar = tar_bytes(b"expected", false);
    let id = records::digest(&tar)
        .strip_prefix("sha256:")
        .unwrap()
        .to_owned();
    let graph = temp.path().join("graph");
    let link = graph.join("overlay/l/EXISTING");
    let target = format!("../{id}/diff");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let mut import = writer
        .begin_image(image(&[&tar]), Default::default())
        .await
        .unwrap();
    let result = import
        .put_layer(0, TarSource(Cursor::new(tar_bytes(b"wrong", false))))
        .await;
    assert!(
        matches!(result, Err(ImportError::Layer { source, .. }) if matches!(*source, ImportError::DigestMismatch { .. }))
    );
    import.abort().await.unwrap();
    assert_eq!(
        std::fs::read_link(link).unwrap(),
        std::path::Path::new(&target)
    );
    assert_eq!(
        std::fs::read_dir(graph.join("overlay/l")).unwrap().count(),
        1
    );
    assert!(!graph.join(format!("overlay/{id}")).exists());
    assert!(
        !graph
            .join(format!("overlay-layers/{id}.tar-split.gz"))
            .exists()
    );
}

#[tokio::test]
async fn layer_id_collisions_never_take_ownership_of_existing_data() {
    for collision in [
        "stable",
        "volatile",
        "overlay",
        "symlink",
        "metadata",
        "tar-split",
    ] {
        let (temp, writer) = store().await;
        let graph = temp.path().join("graph");
        let tar = tar_bytes(b"new layer", false);
        let id = records::digest(&tar)
            .strip_prefix("sha256:")
            .unwrap()
            .to_owned();
        let layer_path = graph.join("overlay-layers/layers.json");
        let volatile_path = graph.join("overlay-layers/volatile-layers.json");
        let occupied = match collision {
            "metadata" => graph.join(format!("overlay-layers/{id}")),
            "tar-split" => graph.join(format!("overlay-layers/{id}.tar-split.gz")),
            _ => graph.join(format!("overlay/{id}")),
        };
        match collision {
            "symlink" => std::os::unix::fs::symlink("missing", &occupied).unwrap(),
            "tar-split" => std::fs::write(&occupied, b"preserve").unwrap(),
            _ => {
                std::fs::create_dir(&occupied).unwrap();
                std::fs::write(occupied.join("marker"), b"preserve").unwrap();
            }
        }
        if matches!(collision, "stable" | "volatile") {
            let path = if collision == "stable" {
                &layer_path
            } else {
                &volatile_path
            };
            std::fs::write(
                path,
                serde_json::to_vec(&json!([{"id":id,"diff-digest":records::digest(b"different")}]))
                    .unwrap(),
            )
            .unwrap();
        }
        let original_layers = std::fs::read(&layer_path).ok();
        let original_volatile = std::fs::read(&volatile_path).ok();
        let mut import = writer
            .begin_image(image(&[&tar]), Default::default())
            .await
            .unwrap();
        let result = import.put_layer(0, TarSource(Cursor::new(tar))).await;
        if matches!(collision, "stable" | "volatile") {
            assert!(
                matches!(result, Err(ImportError::MetadataConflict(_))),
                "{collision}"
            );
        } else {
            assert!(
                matches!(result, Err(ImportError::RecoveryRequired(_))),
                "{collision}"
            );
        }
        import.abort().await.unwrap();
        assert_eq!(
            std::fs::read(&layer_path).ok(),
            original_layers,
            "{collision}"
        );
        assert_eq!(
            std::fs::read(&volatile_path).ok(),
            original_volatile,
            "{collision}"
        );
        match collision {
            "symlink" => assert_eq!(
                std::fs::read_link(&occupied).unwrap(),
                std::path::Path::new("missing")
            ),
            "tar-split" => assert_eq!(std::fs::read(&occupied).unwrap(), b"preserve"),
            _ => assert_eq!(std::fs::read(occupied.join("marker")).unwrap(), b"preserve"),
        }
    }
}
