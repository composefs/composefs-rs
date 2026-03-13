//! Integration tests that use podman-built container images.
//!
//! These tests exercise the `containers-storage:` pull transport and the
//! full seal/sign/verify/export pipeline against real podman-built images.
//! Podman must be available; if it is not, the tests will fail rather than
//! silently passing.

use std::path::{Path, PathBuf};

use anyhow::Result;
use xshell::{Shell, cmd};

use crate::{cfsctl, integration_test};

/// Generate a self-signed X.509 certificate and private key for testing.
fn generate_test_cert(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let sh = Shell::new()?;
    let key_path = dir.join("test-key.pem");
    let cert_path = dir.join("test-cert.pem");
    cmd!(
        sh,
        "openssl req -x509 -newkey rsa:2048 -keyout {key_path} -out {cert_path} -days 1 -nodes -subj /CN=test-ca"
    )
    .run()?;
    Ok((cert_path, key_path))
}

/// Build a minimal image from scratch via podman and return the full image name.
///
/// The image contains a single file (`/usr/bin/hello.txt`) so it is not
/// runnable, but composefs only needs to store and seal it.
fn podman_build_scratch_image(sh: &Shell, tag: &str) -> Result<String> {
    let build_dir = tempfile::tempdir()?;
    let build_path = build_dir.path();
    let containerfile = build_path.join("Containerfile");
    std::fs::write(
        &containerfile,
        "FROM scratch\nCOPY hello.txt /usr/bin/hello.txt\n",
    )?;
    std::fs::write(
        build_path.join("hello.txt"),
        "hello from composefs podman test\n",
    )?;

    cmd!(sh, "podman build -t {tag} -f {containerfile} {build_path}").run()?;

    let full_name = format!("localhost/{tag}");
    Ok(full_name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Build a small image via podman, pull it into a composefs repo via
/// `containers-storage:`, and inspect the result.
fn test_podman_build_pull_inspect() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    let tag = "composefs-test-podman-inspect";
    let full_name = podman_build_scratch_image(&sh, tag)?;

    // Pull via containers-storage transport
    let pull_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull containers-storage:{full_name} test-podman"
    )
    .read()?;
    assert!(
        pull_output.contains("manifest sha256:"),
        "expected manifest digest in pull output, got: {pull_output}"
    );

    // Inspect and validate JSON structure
    let inspect_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-podman"
    )
    .read()?;
    let inspect: serde_json::Value = serde_json::from_str(&inspect_output)?;

    // Must have manifest with layers
    let manifest = &inspect["manifest"];
    let layers = manifest["layers"]
        .as_array()
        .expect("expected layers array in manifest");
    assert!(!layers.is_empty(), "expected at least one layer");

    // Must have config with architecture
    let config = &inspect["config"];
    assert!(
        config.get("architecture").is_some(),
        "expected architecture in config"
    );

    // Not sealed yet
    let images_json = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images --json").read()?;
    let images: Vec<serde_json::Value> = serde_json::from_str(&images_json)?;
    let img = images
        .iter()
        .find(|i| i["name"].as_str() == Some("test-podman"))
        .expect("test-podman not found in images list");
    assert_eq!(img["sealed"], false, "image should not be sealed yet");

    // Referrers should be empty
    let referrers = inspect["referrers"]
        .as_array()
        .expect("expected referrers array");
    assert!(referrers.is_empty(), "expected no referrers on fresh image");

    // Cleanup
    let _ = cmd!(sh, "podman rmi {tag}").run();

    Ok(())
}
integration_test!(test_podman_build_pull_inspect);

/// Full pipeline: podman build -> pull -> seal -> sign -> verify -> inspect -> export.
fn test_podman_build_seal_sign_verify() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // 1. Build
    let tag = "composefs-test-podman-pipeline";
    let full_name = podman_build_scratch_image(&sh, tag)?;

    // 2. Pull via containers-storage
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull containers-storage:{full_name} test-podman"
    )
    .read()?;

    // 3. Seal — creates sealed config + new manifest, updates the tag
    let seal_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci seal test-podman").read()?;
    assert!(
        seal_output.contains("Sealed") && seal_output.contains("sha256:"),
        "expected sealed manifest digest in seal output, got: {seal_output}"
    );

    // 4. Sign
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    let sign_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-podman --cert {cert} --key {key}"
    )
    .read()?;
    assert!(
        sign_output.contains("sha256:"),
        "expected artifact digest in sign output, got: {sign_output}"
    );

    // 5. Verify
    let verify_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci verify test-podman --cert {cert}"
    )
    .read()?;
    assert!(
        verify_output.contains("verified"),
        "expected verification success, got: {verify_output}"
    );

    // 6. Inspect — referrers should be non-empty now
    let inspect_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-podman"
    )
    .read()?;
    let inspect: serde_json::Value = serde_json::from_str(&inspect_output)?;
    let referrers = inspect["referrers"]
        .as_array()
        .expect("expected referrers array");
    assert!(
        !referrers.is_empty(),
        "expected at least one referrer after signing"
    );

    // 7. Export to OCI layout
    let output_dir = tempfile::tempdir()?;
    let output_path = output_dir.path().join("exported");
    let push_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci push test-podman oci:{output_path}"
    )
    .read()?;
    assert!(
        push_output.contains("Exported"),
        "expected export confirmation, got: {push_output}"
    );
    assert!(
        output_path.join("oci-layout").exists(),
        "expected oci-layout file in export"
    );
    assert!(
        output_path.join("index.json").exists(),
        "expected index.json in export"
    );

    // 8. Cleanup
    let _ = cmd!(sh, "podman rmi {tag}").run();

    Ok(())
}
integration_test!(test_podman_build_seal_sign_verify);

/// After podman build + pull + sign, export signatures and validate the
/// artifact structure: EROFS layers, signature layers, ordering, and
/// non-empty blobs.
fn test_podman_build_sign_export_artifact_structure() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Build and pull
    let tag = "composefs-test-podman-artifact";
    let full_name = podman_build_scratch_image(&sh, tag)?;
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull containers-storage:{full_name} test-podman"
    )
    .read()?;

    // Sign
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-podman --cert {cert} --key {key}"
    )
    .read()?;

    // Export signatures
    let export_dir = tempfile::tempdir()?;
    let export = export_dir.path();
    let export_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci export-signatures test-podman {export}"
    )
    .read()?;
    assert!(
        export_output.contains("Exported"),
        "expected export confirmation, got: {export_output}"
    );

    // Parse the artifact manifest from the exported OCI layout
    let index: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(export.join("index.json"))?)?;
    let manifest_desc = &index["manifests"]
        .as_array()
        .expect("expected manifests array")[0];
    let hash = manifest_desc["digest"]
        .as_str()
        .expect("expected digest")
        .strip_prefix("sha256:")
        .expect("expected sha256: prefix");
    let manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        export.join("blobs").join("sha256").join(hash),
    )?)?;

    let layers = manifest["layers"]
        .as_array()
        .expect("expected layers array");
    assert!(!layers.is_empty(), "expected non-empty layers");

    // Separate EROFS and signature layers
    let erofs_layers: Vec<&serde_json::Value> = layers
        .iter()
        .filter(|l| l["mediaType"].as_str() == Some("application/vnd.composefs.v1.erofs"))
        .collect();
    let sig_layers: Vec<&serde_json::Value> = layers
        .iter()
        .filter(|l| l["mediaType"].as_str() == Some("application/vnd.composefs.signature.v1+pkcs7"))
        .collect();

    assert!(
        !erofs_layers.is_empty(),
        "expected at least one EROFS layer"
    );
    assert!(
        !sig_layers.is_empty(),
        "expected at least one signature layer"
    );

    // EROFS layers must precede signature layers
    let last_erofs_idx = layers
        .iter()
        .rposition(|l| l["mediaType"].as_str() == Some("application/vnd.composefs.v1.erofs"))
        .unwrap();
    let first_sig_idx = layers
        .iter()
        .position(|l| {
            l["mediaType"].as_str() == Some("application/vnd.composefs.signature.v1+pkcs7")
        })
        .unwrap();
    assert!(
        last_erofs_idx < first_sig_idx,
        "EROFS layers (last at {last_erofs_idx}) must precede signature layers (first at {first_sig_idx})"
    );

    // Verify EROFS blobs are non-empty
    for layer in &erofs_layers {
        let digest = layer["digest"]
            .as_str()
            .expect("expected digest on EROFS layer");
        let layer_hash = digest
            .strip_prefix("sha256:")
            .expect("expected sha256: prefix");
        let blob_path = export.join("blobs").join("sha256").join(layer_hash);
        let metadata = std::fs::metadata(&blob_path)
            .unwrap_or_else(|_| panic!("EROFS blob not found at {}", blob_path.display()));
        assert!(
            metadata.len() > 0,
            "EROFS blob {} is empty",
            blob_path.display()
        );
    }

    // Cleanup
    let _ = cmd!(sh, "podman rmi {tag}").run();

    Ok(())
}
integration_test!(test_podman_build_sign_export_artifact_structure);
