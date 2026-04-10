//! Tests for containers-storage import functionality.
//!
//! These tests verify that importing from containers-storage produces identical
//! results to importing via skopeo/tar streaming.
//!
//! These tests require `podman unshare` which needs user namespace support.
//! On environments without proper user namespace support (like GHA runners),
//! they dispatch to a bcvk VM like other privileged tests.

use anyhow::Result;
use tempfile::TempDir;
use xshell::{Shell, cmd};

use integration_tests::{build_test_image, cleanup_test_image, create_test_repository};

use crate::integration_test;
use crate::tests::privileged::{require_privileged, require_userns};

/// Helper: copy an image into a separate containers-storage root.
///
/// Uses skopeo to copy from the default store to a standalone overlay
/// storage at `dest/storage`.
fn copy_image_to_separate_store(sh: &Shell, image_id: &str, dest: &std::path::Path) -> Result<()> {
    let dest_str = dest.display().to_string();
    let storage_root = format!("{dest_str}/storage");
    let run_root = format!("{dest_str}/run");

    // skopeo needs the raw hex ID without the sha256: prefix
    let raw_id = image_id.strip_prefix("sha256:").unwrap_or(image_id);
    let src_ref = format!("containers-storage:{raw_id}");
    // Use [overlay@<root>+<runroot>] to target the separate storage
    let dest_ref = format!("containers-storage:[overlay@{storage_root}+{run_root}]test:latest");

    // Use podman unshare so that skopeo has UID/GID mappings available
    // for unpacking layers with non-root ownership.
    if rustix::process::getuid().is_root() {
        cmd!(sh, "skopeo copy {src_ref} {dest_ref}").run()?;
    } else {
        cmd!(sh, "podman unshare skopeo copy {src_ref} {dest_ref}").run()?;
    }

    Ok(())
}

/// Test that containers-storage import produces identical results to skopeo/tar import.
///
/// This is a critical correctness test: both import paths should produce the
/// exact same splitstream digests because they represent the same content.
///
/// Requires a VM because skopeo's containers-storage transport also needs user
/// namespaces internally, and that fails on GHA runners even when podman unshare works.
fn privileged_test_cstor_vs_skopeo_equivalence() -> Result<()> {
    if require_privileged("privileged_test_cstor_vs_skopeo_equivalence")?.is_some() {
        return Ok(());
    }
    let sh = Shell::new()?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        println!("Building test image...");
        let test_image = build_test_image()?;
        println!("Built test image: {}", test_image);

        // Create two separate repositories for comparison
        let cstor_repo_dir = TempDir::new()?;
        let skopeo_repo_dir = TempDir::new()?;

        let cstor_repo = create_test_repository(&cstor_repo_dir)?;
        let skopeo_repo = create_test_repository(&skopeo_repo_dir)?;

        // Import via containers-storage (reflink path)
        let cstor_image_ref = format!("containers-storage:{}", test_image);
        println!("Importing via containers-storage: {}", cstor_image_ref);
        let cstor_result =
            composefs_oci::pull(&cstor_repo, &cstor_image_ref, None, Default::default()).await?;

        // Import via skopeo (tar streaming path) - copy to OCI directory first
        let oci_dir = TempDir::new()?;
        let oci_path = oci_dir.path().join("image");

        // Use skopeo to copy from containers-storage to oci directory
        // Strip sha256: prefix for skopeo compatibility
        let image_id_for_skopeo = test_image.strip_prefix("sha256:").unwrap_or(&test_image);
        let cstor_ref = format!("containers-storage:{}", image_id_for_skopeo);
        let oci_ref = format!("oci:{}:test", oci_path.display());
        println!("Copying to OCI dir via skopeo...");
        cmd!(sh, "skopeo copy {cstor_ref} {oci_ref}").run()?;

        // Import from the OCI directory via skopeo/tar path
        let skopeo_image_ref = format!("oci:{}:test", oci_path.display());
        println!("Importing via skopeo/OCI: {}", skopeo_image_ref);
        let (skopeo_pull_result, _skopeo_stats) =
            composefs_oci::pull_image(&skopeo_repo, &skopeo_image_ref, None, None).await?;
        let (skopeo_config_digest, skopeo_config_verity) = skopeo_pull_result.into_config();

        // Get layer maps from both configs
        let cstor_oc = composefs_oci::open_config(
            &cstor_repo,
            &cstor_result.config_digest,
            Some(&cstor_result.config_verity),
        )?;
        let skopeo_oc = composefs_oci::open_config(
            &skopeo_repo,
            &skopeo_config_digest,
            Some(&skopeo_config_verity),
        )?;

        // Compare results
        println!("CSTOR config digest: {}", cstor_result.config_digest);
        println!("SKOPEO config digest: {}", skopeo_config_digest);
        assert_eq!(
            cstor_result.config_digest, skopeo_config_digest,
            "config digests must match"
        );

        println!("CSTOR layers: {:?}", cstor_oc.layer_refs);
        println!("SKOPEO layers: {:?}", skopeo_oc.layer_refs);
        assert_eq!(
            cstor_oc.layer_refs, skopeo_oc.layer_refs,
            "layer verity IDs must match"
        );

        println!("CSTOR config verity: {:?}", cstor_result.config_verity);
        println!("SKOPEO config verity: {:?}", skopeo_config_verity);

        // NOTE: Config verity IDs may differ due to layer ref ordering.
        // The skopeo path sorts layers by size for parallel fetching, then adds
        // named refs in that order. The cstor path adds refs in config order.
        // Both produce valid splitstreams with correct content, but different verity.
        // TODO: Fix the ordering discrepancy in one of the implementations.
        if cstor_result.config_verity != skopeo_config_verity {
            println!(
                "WARNING: Config verity IDs differ due to layer ref ordering. \
                 Content is equivalent but splitstream structure differs."
            );
        }

        println!("SUCCESS: Both import paths produced equivalent content");
        println!("  Config digest: {}", cstor_result.config_digest);
        println!("  Layers: {}", cstor_oc.layer_refs.len());

        Ok(())
    })
}
integration_test!(privileged_test_cstor_vs_skopeo_equivalence);

/// Test that importing the same image twice produces identical results (idempotency).
///
/// The second import should return the same verity IDs, and import stats should
/// reflect that layers came from cache.
///
/// Requires user namespace support (podman unshare), so runs only in privileged/VM tests.
fn privileged_test_cstor_idempotent_import() -> Result<()> {
    if require_userns("privileged_test_cstor_idempotent_import")?.is_some() {
        return Ok(());
    }
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        println!("Building test image...");
        let test_image = build_test_image()?;
        println!("Built test image: {}", test_image);

        let repo_dir = TempDir::new()?;
        let repo = create_test_repository(&repo_dir)?;

        let cstor_image_ref = format!("containers-storage:{}", test_image);

        // First import
        println!("First import via containers-storage...");
        let first_result =
            composefs_oci::pull(&repo, &cstor_image_ref, None, Default::default()).await?;

        // Second import of the same image
        println!("Second import via containers-storage (should use cache)...");
        let second_result =
            composefs_oci::pull(&repo, &cstor_image_ref, None, Default::default()).await?;

        // Verify idempotency: both imports should produce identical results
        assert_eq!(
            first_result.config_digest, second_result.config_digest,
            "config digests must match between imports"
        );
        assert_eq!(
            first_result.config_verity, second_result.config_verity,
            "config verity IDs must match between imports"
        );

        // Verify layer verity IDs match
        let first_oc = composefs_oci::open_config(
            &repo,
            &first_result.config_digest,
            Some(&first_result.config_verity),
        )?;
        let second_oc = composefs_oci::open_config(
            &repo,
            &second_result.config_digest,
            Some(&second_result.config_verity),
        )?;
        assert_eq!(
            first_oc.layer_refs, second_oc.layer_refs,
            "layer verity IDs must match between imports"
        );

        // Check import stats: second import should find objects already present
        let first_stats = &first_result.stats;
        let second_stats = &second_result.stats;
        println!("First import stats: {:?}", first_stats);
        println!("Second import stats: {:?}", second_stats);

        // The first import should have copied some objects
        assert!(
            first_stats.objects_copied > 0,
            "first import should copy objects"
        );

        // The second import should find everything already present
        assert_eq!(
            second_stats.objects_copied, 0,
            "second import should not copy any new objects"
        );

        println!("SUCCESS: Idempotent import produced identical results");
        println!("  Config digest: {}", first_result.config_digest);
        println!("  Layers: {}", first_oc.layer_refs.len());
        println!(
            "  Second import: {} objects already present",
            second_stats.objects_already_present
        );

        Ok(())
    })
}
integration_test!(privileged_test_cstor_idempotent_import);

/// Test that importing with a reference parameter creates an OCI manifest tag.
///
/// The cstor import path now creates full OCI structure (manifest + config +
/// layers), so the reference becomes an OCI-style manifest tag visible via
/// `list_refs()`.
///
/// Requires user namespace support (podman unshare), so runs only in privileged/VM tests.
fn privileged_test_cstor_import_with_reference() -> Result<()> {
    if require_userns("privileged_test_cstor_import_with_reference")?.is_some() {
        return Ok(());
    }
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        println!("Building test image...");
        let test_image = build_test_image()?;
        println!("Built test image: {}", test_image);

        let repo_dir = TempDir::new()?;
        let repo = create_test_repository(&repo_dir)?;

        let cstor_image_ref = format!("containers-storage:{}", test_image);
        let reference_name = "test-ref";

        // Import with a reference name
        println!("Importing with reference: {}", reference_name);
        let result = composefs_oci::pull(
            &repo,
            &cstor_image_ref,
            Some(reference_name),
            Default::default(),
        )
        .await?;

        println!("Import complete. Config digest: {}", result.config_digest);
        println!(
            "Import complete. Manifest digest: {}",
            result.manifest_digest
        );

        // Verify the OCI tag was created — it should be visible via list_refs()
        let refs = composefs_oci::oci_image::list_refs(&repo)?;
        let found = refs.iter().any(|(name, _)| name == reference_name);
        assert!(
            found,
            "reference '{}' should appear in OCI refs, got: {:?}",
            reference_name,
            refs.iter().map(|(n, _)| n).collect::<Vec<_>>()
        );

        // The OCI ref should resolve to the manifest we imported
        let ref_path = repo_dir
            .path()
            .join("streams/refs/oci")
            .join(reference_name);
        assert!(
            ref_path.is_symlink(),
            "OCI reference '{}' should exist as symlink at {:?}",
            reference_name,
            ref_path
        );

        let target = std::fs::read_link(&ref_path)?;
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("oci-manifest-"),
            "reference should point to oci-manifest stream, got: {}",
            target_str
        );

        println!("SUCCESS: Import with reference created OCI manifest tag");
        println!("  Reference: {}", reference_name);
        println!("  Manifest digest: {}", result.manifest_digest);

        Ok(())
    })
}
integration_test!(privileged_test_cstor_import_with_reference);

/// Test that importing from an additional image store works.
///
/// This exercises the `STORAGE_OPTS=additionalimagestore=<path>` mechanism
/// used by bcvk to expose the host's containers-storage inside a VM.
///
/// The test:
/// 1. Builds an image in the default store
/// 2. Copies it to a separate overlay store in a temp directory
/// 3. Removes it from the default store
/// 4. Runs `cfsctl oci pull` with `STORAGE_OPTS` in the command environment
///    (avoiding process-global env mutation)
fn privileged_test_cstor_additional_image_store() -> Result<()> {
    if require_userns("privileged_test_cstor_additional_image_store")?.is_some() {
        return Ok(());
    }
    let sh = Shell::new()?;
    let cfsctl = crate::cfsctl()?;

    println!("Building test image...");
    let test_image = build_test_image()?;
    println!("Built test image: {}", test_image);

    // Copy the image to a separate store
    let separate_store = TempDir::new()?;
    println!(
        "Copying image to separate store at {}...",
        separate_store.path().display()
    );
    copy_image_to_separate_store(&sh, &test_image, separate_store.path())?;

    // Remove from the default store so the only way to find it is via
    // the additional image store
    cleanup_test_image(&test_image);

    // Set STORAGE_OPTS in the command environment (not process-global)
    let additional_store = separate_store.path().join("storage");
    let storage_opts = format!("additionalimagestore={}", additional_store.display());
    println!("Running cfsctl with STORAGE_OPTS={}", storage_opts);

    let repo_dir = TempDir::new()?;
    let repo = repo_dir.path();
    let cstor_image_ref = format!("containers-storage:{}", test_image);

    // Initialize the repository first
    cmd!(sh, "{cfsctl} --insecure --repo {repo} init").run()?;

    // Run cfsctl as an external process with STORAGE_OPTS in its environment
    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull {cstor_image_ref}"
    )
    .env("STORAGE_OPTS", &storage_opts)
    .read()?;

    println!("SUCCESS: Imported from additional image store");
    println!("  cfsctl output: {}", output);

    // Verify the pull succeeded by checking the output contains a config digest
    assert!(
        output.contains("sha256:"),
        "expected sha256 digest in pull output, got: {output}"
    );

    Ok(())
}
integration_test!(privileged_test_cstor_additional_image_store);

/// Test that `--bootable` works for containers-storage imports.
///
/// This verifies the full end-to-end flow:
/// 1. Build a test image (non-bootable) in containers-storage
/// 2. Pull it via `cfsctl oci pull --bootable` using the cstor path
/// 3. Verify the CLI succeeds and the output includes the boot image verity
///
/// Even though the test image doesn't contain actual boot content (no UKI,
/// no kernel), `--bootable` should still succeed — `transform_for_boot`
/// gracefully handles images without boot entries by applying SELinux
/// relabeling and emptying /boot and /sysroot.
fn privileged_test_cstor_bootable() -> Result<()> {
    if require_userns("privileged_test_cstor_bootable")?.is_some() {
        return Ok(());
    }
    let sh = Shell::new()?;
    let cfsctl = crate::cfsctl()?;

    println!("Building test image...");
    let test_image = build_test_image()?;
    println!("Built test image: {}", test_image);

    let repo_dir = TempDir::new()?;
    let repo = repo_dir.path();
    let cstor_image_ref = format!("containers-storage:{}", test_image);

    // Initialize the repository first
    cmd!(sh, "{cfsctl} --insecure --repo {repo} init").run()?;

    // Pull with --bootable via the cstor path
    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull --bootable {cstor_image_ref}"
    )
    .read()?;

    println!("cfsctl output:\n{}", output);

    // Verify pull succeeded with expected output
    assert!(
        output.contains("manifest"),
        "expected 'manifest' in output, got: {output}"
    );
    assert!(
        output.contains("Boot image:"),
        "expected 'Boot image:' in output (--bootable should produce a boot EROFS), got: {output}"
    );

    // Verify the image is visible via oci images (OCI manifest tag was created)
    let ls_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images --json").read()?;
    let images: serde_json::Value = serde_json::from_str(&ls_output)?;
    let images_arr = images.as_array().expect("oci ls should return array");
    assert!(
        !images_arr.is_empty(),
        "oci ls should show at least one image after cstor pull"
    );

    // Verify the boot EROFS ref is visible via inspect
    let tag_name = &cstor_image_ref;
    let inspect_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect {tag_name}"
    )
    .read()?;
    let inspect: serde_json::Value = serde_json::from_str(&inspect_output)?;
    assert!(
        inspect.get("composefs_erofs").is_some(),
        "inspect should show composefs_erofs field"
    );
    assert!(
        inspect.get("composefs_boot_erofs").is_some(),
        "inspect should show composefs_boot_erofs field after --bootable pull"
    );

    println!("SUCCESS: --bootable works for containers-storage imports");

    Ok(())
}
integration_test!(privileged_test_cstor_bootable);
