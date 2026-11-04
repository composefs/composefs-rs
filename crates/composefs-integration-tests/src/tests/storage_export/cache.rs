//! A single Go store must reload Rust publications and name changes.

use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use composefs::{
    fsverity::{FsVerityHashValue, Sha512HashValue},
    repository::{Repository, RepositoryConfig},
};
use containers_image_proxy::{ImageProxy, OpenedImage};
use tokio::io::AsyncReadExt;

use super::{OverlayMountCleanup, append, copy_to_storage, store_image, top_layer};
use crate::{
    integration_test,
    tests::privileged::{VerityTempDir, require_privileged},
};

async fn read_blob(
    proxy: &ImageProxy,
    image: &OpenedImage,
    digest: &composefs_oci::OciDigest,
    size: u64,
) -> Result<Vec<u8>> {
    let (mut reader, driver) = proxy.get_blob(image, digest, size).await?;
    let mut bytes = Vec::new();
    let (read, finished) = tokio::join!(reader.read_to_end(&mut bytes), driver);
    read?;
    finished?;
    assert_eq!(bytes.len() as u64, size);
    Ok(bytes)
}

/// Reopen each source while retaining the proxy process and its cached Go store.
/// Reading the actual layer also populates Go's layer-store cache.
async fn check_image(
    proxy: &ImageProxy,
    reference: &str,
    manifest_digest: &composefs_oci::OciDigest,
    image_id: &str,
    expected_layer: &[u8],
) -> Result<()> {
    let image = proxy.open_image(reference).await?;
    let (actual_digest, manifest) = proxy.fetch_manifest(&image).await?;
    assert_eq!(actual_digest, manifest_digest.to_string());
    assert_eq!(manifest.config().digest().digest(), image_id);
    // GetFullConfig normalizes JSON; GetBlob preserves the original config bytes.
    let config = read_blob(
        proxy,
        &image,
        manifest.config().digest(),
        manifest.config().size(),
    )
    .await?;
    assert_eq!(
        composefs_oci::sha256_content_digest(&config).digest(),
        image_id
    );
    let layers = proxy
        .get_layer_info(&image)
        .await?
        .context("Skopeo does not support layer information")?;
    assert_eq!(layers.len(), 1);
    let layer = &layers[0];
    assert_eq!(
        layer.digest,
        composefs_oci::sha256_content_digest(expected_layer)
    );
    assert_eq!(layer.size, expected_layer.len() as u64);
    let actual = read_blob(proxy, &image, &layer.digest, layer.size).await?;
    assert_eq!(actual, expected_layer);
    proxy.close_image(&image).await?;
    Ok(())
}

fn privileged_storage_export_cache_reload() -> Result<()> {
    if require_privileged("privileged_storage_export_cache_reload")?.is_some() {
        return Ok(());
    }
    let verity = VerityTempDir::new()?;
    let temp = tempfile::tempdir()?;
    let graph = verity.path().join("graph");
    let _mount = OverlayMountCleanup(&graph);
    let run = temp.path().join("run");
    let repo_path = verity.path().join("source");
    let (repo, _) = Repository::<Sha512HashValue>::init_path(
        rustix::fs::CWD,
        &repo_path,
        RepositoryConfig::new(Sha512HashValue::ALGORITHM),
    )?;
    let repo = Arc::new(repo);
    let layers = [b"before publication".as_slice(), b"after publication"]
        .into_iter()
        .map(|payload| {
            let mut tar = tar::Builder::new(Vec::new());
            append(&mut tar, "payload", payload, false)?;
            Ok(tar.into_inner()?)
        })
        .collect::<Result<Vec<_>>>()?;
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async {
        let original = store_image(&repo, &[&layers[0]]).await?;
        let original_id = copy_to_storage(
            &repo_path,
            &graph,
            &run,
            &format!("@{original}"),
            &["--name", "localhost/cache:latest"],
        )?;
        let transport = format!(
            "containers-storage:[overlay@{}+{}:overlay.mount_program=]",
            graph.display(),
            run.display()
        );
        let named = format!("{transport}localhost/cache:latest");
        // GetStore caches by graphroot/runroot within this one Skopeo process.
        // Closing a storage image source does not close or recreate that store.
        let proxy = ImageProxy::new().await?;
        check_image(&proxy, &named, &original, &original_id, &layers[0]).await?;

        let published = store_image(&repo, &[&layers[1]]).await?;
        let published_id =
            copy_to_storage(&repo_path, &graph, &run, &format!("@{published}"), &[])?;
        ensure!(published_id != original_id, "fixture must add a new image");
        ensure!(
            top_layer(&graph, &published_id)? != top_layer(&graph, &original_id)?,
            "fixture must add a new layer"
        );
        let by_id = format!("{transport}@{published_id}");
        check_image(&proxy, &by_id, &published, &published_id, &layers[1]).await?;
        // The original association still resolves after refreshing both caches.
        check_image(&proxy, &named, &original, &original_id, &layers[0]).await?;

        assert_eq!(
            copy_to_storage(
                &repo_path,
                &graph,
                &run,
                &format!("@{published}"),
                &["--name", "localhost/cache:latest", "--reassign"],
            )?,
            published_id
        );
        check_image(&proxy, &named, &published, &published_id, &layers[1]).await?;
        proxy.finalize().await?;
        Ok(())
    });
    drop(runtime);
    drop(repo);
    result
}
integration_test!(privileged_storage_export_cache_reload);
