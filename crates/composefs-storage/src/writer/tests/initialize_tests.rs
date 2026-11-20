use super::*;

#[tokio::test]
async fn constructors_resolve_optional_root_paths_independently() {
    for (graph_path, run_path) in [
        (false, None),
        (false, Some(false)),
        (false, Some(true)),
        (true, None),
        (true, Some(false)),
        (true, Some(true)),
    ] {
        let temp = TempDir::new().unwrap();
        let parent = Dir::open_ambient_dir(temp.path(), ambient_authority()).unwrap();
        if !graph_path {
            parent.create_dir("graph").unwrap();
        }
        if run_path == Some(false) {
            parent.create_dir("run").unwrap();
        }
        let location = || StoreLocation {
            graphroot: if graph_path {
                parent.try_clone().unwrap()
            } else {
                parent.open_dir("graph").unwrap()
            },
            graphroot_path: graph_path.then(|| "graph".into()),
            runroot: run_path.map(|path| {
                if path {
                    parent.try_clone().unwrap()
                } else {
                    parent.open_dir("run").unwrap()
                }
            }),
            runroot_path: run_path.and_then(|path| path.then(|| "run".into())),
        };
        assert!(matches!(
            StorageWriter::open(location()),
            Err(ImportError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound
        ));
        assert_eq!(temp.path().join("graph").exists(), !graph_path);
        assert_eq!(temp.path().join("run").exists(), run_path == Some(false));
        assert!(!temp.path().join("graph/overlay").exists());

        let writer = StorageWriter::ensure(location()).await.unwrap();
        let raw = image(&[]);
        let manifest = raw.manifest_json.clone();
        let published = writer
            .begin_image(raw, Default::default())
            .await
            .unwrap()
            .prepare_publication()
            .await
            .unwrap()
            .finish(&[])
            .await
            .unwrap();
        let storage = crate::Storage::open(temp.path().join("graph")).unwrap();
        let stored = crate::Image::open(&storage, &published.image_id).unwrap();
        assert_eq!(stored.read_manifest_raw().unwrap(), manifest);
        assert_eq!(
            temp.path().join("run/overlay-layers").is_dir(),
            run_path.is_some()
        );
        StorageWriter::open(location())
            .unwrap()
            .begin_image(image(&[]), Default::default())
            .await
            .unwrap()
            .abort()
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn ensure_creates_roots_and_preserves_a_populated_store() {
    let temp = TempDir::new().unwrap();
    let runtime = TempDir::new().unwrap();
    let parent = Dir::open_ambient_dir(temp.path(), ambient_authority()).unwrap();
    let run_parent = Dir::open_ambient_dir(runtime.path(), ambient_authority()).unwrap();
    let writer = StorageWriter::ensure(store_location(
        &parent,
        "nested/graph",
        &run_parent,
        "nested/run",
    ))
    .await
    .unwrap();
    let graph = temp.path().join("nested/graph");
    for (path, mode) in [
        ("", 0o700),
        ("overlay", 0o755),
        ("overlay/l", 0o755),
        ("overlay-layers", 0o700),
        ("overlay-images", 0o700),
    ] {
        let metadata = std::fs::metadata(graph.join(path)).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.mode() & 0o777, mode, "{path}");
    }
    assert!(runtime.path().join("nested/run/overlay-layers").is_dir());
    assert!(!graph.join("overlay-layers/layers.json").exists());
    assert!(!graph.join("overlay-images/images.json").exists());

    let tar = tar_bytes(b"contents", false);
    let raw = image(&[&tar]);
    let manifest = raw.manifest_json.clone();
    let mut import = writer.begin_image(raw, Default::default()).await.unwrap();
    let layer = import
        .put_layer(0, TarSource(Cursor::new(tar.clone())))
        .await
        .unwrap();
    let published = import
        .prepare_publication()
        .await
        .unwrap()
        .finish(&["localhost/example:ensured".into()])
        .await
        .unwrap();
    let records_path = graph.join("overlay-images/images.json");
    let mut images: Value = serde_json::from_slice(&std::fs::read(&records_path).unwrap()).unwrap();
    images[0]["custom"] = json!({"preserve":true});
    let original = serde_json::to_vec(&images).unwrap();
    std::fs::write(&records_path, &original).unwrap();
    rustix::fs::chmodat(
        rustix::fs::CWD,
        graph.join("overlay"),
        rustix::fs::Mode::from_bits_truncate(0o711),
        rustix::fs::AtFlags::empty(),
    )
    .unwrap();
    let locks: Vec<_> = [
        "storage.lock",
        "overlay-layers/layers.lock",
        "overlay-images/images.lock",
    ]
    .into_iter()
    .map(|path| {
        let metadata = std::fs::metadata(graph.join(path)).unwrap();
        (
            path,
            metadata.ino(),
            std::fs::read(graph.join(path)).unwrap(),
        )
    })
    .collect();
    for _ in 0..2 {
        StorageWriter::ensure(store_location(
            &parent,
            "nested/graph",
            &run_parent,
            "nested/run",
        ))
        .await
        .unwrap();
        assert_eq!(std::fs::read(&records_path).unwrap(), original);
        assert_eq!(
            std::fs::metadata(graph.join("overlay")).unwrap().mode() & 0o777,
            0o711
        );
        for (path, inode, token) in &locks {
            assert_eq!(std::fs::metadata(graph.join(path)).unwrap().ino(), *inode);
            assert_eq!(&std::fs::read(graph.join(path)).unwrap(), token);
        }
        assert_eq!(reconstruct(&graph, &layer.storage_layer_id), tar);
    }
    let storage = crate::Storage::open(&graph).unwrap();
    let image = crate::Image::open(&storage, &published.image_id).unwrap();
    assert_eq!(image.read_manifest_raw().unwrap(), manifest);
}

#[tokio::test]
async fn ensure_repairs_partial_scaffolding() {
    let temp = TempDir::new().unwrap();
    let parent = Dir::open_ambient_dir(temp.path(), ambient_authority()).unwrap();
    parent.create_dir_all("graph/overlay").unwrap();
    StorageWriter::ensure(store_location(&parent, "graph", &parent, "run"))
        .await
        .unwrap();
    for path in [
        "graph/overlay/l",
        "graph/overlay-layers",
        "graph/overlay-images",
        "run/overlay-layers",
    ] {
        assert!(temp.path().join(path).is_dir(), "{path}");
    }
}

#[tokio::test]
async fn ensure_waits_for_the_graph_lock_and_can_be_cancelled() {
    for cancel in [false, true] {
        let temp = TempDir::new().unwrap();
        let parent = Dir::open_ambient_dir(temp.path(), ambient_authority()).unwrap();
        parent.create_dir("graph").unwrap();
        let graph = parent.open_dir("graph").unwrap();
        let held = crate::writer::locking::LockFile::open(&graph, "storage.lock")
            .unwrap()
            .write()
            .await
            .unwrap();
        let ensure = || StorageWriter::ensure(store_location(&parent, "graph", &parent, "run"));
        let mut pending = Box::pin(ensure());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut pending)
                .await
                .is_err()
        );
        assert!(!temp.path().join("graph/overlay").exists());
        if cancel {
            drop(pending);
            pending = Box::pin(ensure());
        }
        drop(held);
        tokio::time::timeout(std::time::Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap();
        assert!(temp.path().join("graph/overlay/l").is_dir());
    }
}

#[tokio::test]
async fn concurrent_ensure_calls_share_the_same_lock_files() {
    let temp = TempDir::new().unwrap();
    let parent = Dir::open_ambient_dir(temp.path(), ambient_authority()).unwrap();
    let (first, second) = tokio::join!(
        StorageWriter::ensure(store_location(&parent, "graph", &parent, "run")),
        StorageWriter::ensure(store_location(&parent, "graph", &parent, "run")),
    );
    let import = first
        .unwrap()
        .begin_image(image(&[]), Default::default())
        .await
        .unwrap();
    let mut pending = Box::pin(second.unwrap().begin_image(image(&[]), Default::default()));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut pending)
            .await
            .is_err()
    );
    import.abort().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap()
        .abort()
        .await
        .unwrap();
}
