//! Integration test for pulling `zstd:chunked`-compressed OCI layers.
//!
//! `zstd:chunked` layers are multi-frame zstd streams (one frame per
//! chunk, plus skippable framing metadata carrying the chunk table of
//! contents), so pulling one exercises the decoder's multi-frame path.

use anyhow::Result;
use xshell::{Shell, cmd};

use crate::tests::cli::{OCI_LAYOUT_COMPOSEFS_ID, create_oci_layout, init_insecure_repo};
use crate::{cfsctl, have_skopeo, integration_test};

/// Regression test for multi-frame zstd decoding: before the decode fix,
/// every `zstd:chunked` pull silently imported a truncated tar because the
/// decoder stopped at the first frame boundary.
///
/// Recompresses the deterministic OCI layout from [`create_oci_layout`] to
/// `zstd:chunked` with skopeo and pulls it with `cfsctl oci pull oci:`. The
/// `oci:` import path shares `decompress_async()` with the skopeo-proxy
/// registry path, so this exercises the same decoder a `docker://` pull
/// would without needing a registry.
fn test_zstd_chunked_pull() -> Result<()> {
    if !have_skopeo() {
        eprintln!("skopeo not found, skipping zstd:chunked pull test");
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let fixture_dir = tempfile::tempdir()?;

    // Build the plain-gzip fixture locally (no network).
    let src_layout = create_oci_layout(fixture_dir.path())?;
    let dst_layout = fixture_dir.path().join("zstd-chunked-image");

    // Recompress into zstd:chunked. --dest-force-compress-format makes this
    // deterministic regardless of the source's compression (without it,
    // skopeo may leave a layer alone if it judges the codec family already
    // matches the target).
    let copy_result = cmd!(
        sh,
        "skopeo copy --dest-compress-format zstd:chunked --dest-force-compress-format oci:{src_layout} oci:{dst_layout}:chunked"
    )
    .ignore_status()
    .output()?;
    if !copy_result.status.success() {
        eprintln!(
            "skopeo copy --dest-compress-format zstd:chunked failed (installed skopeo may \
             predate zstd:chunked support); skipping zstd:chunked pull test. stderr:\n{}",
            String::from_utf8_lossy(&copy_result.stderr)
        );
        return Ok(());
    }

    // Assert the produced manifest actually carries the zstd:chunked TOC
    // annotation, so this fixture can never silently degrade to plain zstd
    // (e.g. a future skopeo treating the format as unsupported and falling
    // back quietly, or the flags above ceasing to be honored).
    let raw_manifest = cmd!(sh, "skopeo inspect --raw oci:{dst_layout}:chunked").read()?;
    let manifest: serde_json::Value = serde_json::from_str(&raw_manifest)?;
    let layers = manifest["layers"]
        .as_array()
        .expect("manifest should have a layers array");
    assert_eq!(layers.len(), 1, "expected the single-layer test fixture");
    let toc_checksum =
        layers[0]["annotations"]["io.github.containers.zstd-chunked.manifest-checksum"].as_str();
    assert!(
        toc_checksum.is_some_and(|d| d.starts_with("sha256:")),
        "layer should carry the zstd:chunked TOC manifest-checksum annotation \
         (fixture degraded to plain zstd?), got manifest: {raw_manifest}"
    );

    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();
    let pull_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{dst_layout}:chunked chunked-image"
    )
    .read()?;
    assert!(
        pull_output.contains("manifest sha256:"),
        "expected manifest digest in pull output, got: {pull_output}"
    );
    assert!(
        pull_output.contains("tagged") && pull_output.contains("chunked-image"),
        "expected tagged confirmation, got: {pull_output}"
    );

    // The recompressed image carries the same diff_ids as the gzip original,
    // so the imported composefs image ID must be byte-identical to the
    // pinned gzip result.
    let config_digest = pull_output
        .lines()
        .find_map(|l| l.strip_prefix("config").map(|s| s.trim().to_string()))
        .expect("config digest in pull output");
    let at_config_digest = format!("@{config_digest}");
    let image_id = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci compute-id {at_config_digest}"
    )
    .read()?;
    assert_eq!(
        image_id.trim(),
        OCI_LAYOUT_COMPOSEFS_ID,
        "zstd:chunked pull produced a different composefs image ID than the identical content \
         pulled as plain gzip — the multi-frame decode likely truncated the tar stream"
    );

    Ok(())
}
integration_test!(test_zstd_chunked_pull);
