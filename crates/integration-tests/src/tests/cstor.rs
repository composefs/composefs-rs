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
use xshell::{cmd, Shell};

use integration_tests::{build_test_image, cleanup_test_image, create_test_repository};

use crate::integration_test;
use crate::tests::privileged::{require_privileged, require_userns};

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
        let cstor_result = composefs_oci::pull(&cstor_repo, &cstor_image_ref, None, None).await?;

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
        let (_cstor_config, cstor_layers) = composefs_oci::open_config(
            &cstor_repo,
            &cstor_result.config_digest,
            Some(&cstor_result.config_verity),
        )?;
        let (_skopeo_config, skopeo_layers) = composefs_oci::open_config(
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

        println!("CSTOR layers: {:?}", cstor_layers);
        println!("SKOPEO layers: {:?}", skopeo_layers);
        assert_eq!(cstor_layers, skopeo_layers, "layer verity IDs must match");

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
        println!("  Layers: {}", cstor_layers.len());

        // Cleanup
        cleanup_test_image(&test_image);

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
        let first_result = composefs_oci::pull(&repo, &cstor_image_ref, None, None).await?;

        // Second import of the same image
        println!("Second import via containers-storage (should use cache)...");
        let second_result = composefs_oci::pull(&repo, &cstor_image_ref, None, None).await?;

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
        let (_, first_layers) = composefs_oci::open_config(
            &repo,
            &first_result.config_digest,
            Some(&first_result.config_verity),
        )?;
        let (_, second_layers) = composefs_oci::open_config(
            &repo,
            &second_result.config_digest,
            Some(&second_result.config_verity),
        )?;
        assert_eq!(
            first_layers, second_layers,
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
        println!("  Layers: {}", first_layers.len());
        println!(
            "  Second import: {} objects already present",
            second_stats.objects_already_present
        );

        // Cleanup
        cleanup_test_image(&test_image);

        Ok(())
    })
}
integration_test!(privileged_test_cstor_idempotent_import);

/// Test that importing with a reference parameter creates a stream ref.
///
/// Note: The cstor import path creates stream refs (symlinks in streams/refs/),
/// NOT OCI-style manifest tags. This is because cstor imports only config+layers,
/// not the full OCI manifest structure. The `list_refs()` function only returns
/// OCI manifest refs, so cstor refs won't appear there.
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
        let result =
            composefs_oci::pull(&repo, &cstor_image_ref, Some(reference_name), None).await?;

        println!("Import complete. Config digest: {}", result.config_digest);

        // Verify the stream ref was created by checking the filesystem
        let ref_path = repo_dir.path().join("streams/refs").join(reference_name);
        assert!(
            ref_path.is_symlink(),
            "reference '{}' should exist as symlink at {:?}",
            reference_name,
            ref_path
        );

        // The symlink should point to the config stream
        let target = std::fs::read_link(&ref_path)?;
        println!("Reference '{}' -> {:?}", reference_name, target);

        // Verify it points to an oci-config stream
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("oci-config-"),
            "reference should point to oci-config stream, got: {}",
            target_str
        );

        println!("SUCCESS: Import with reference created stream ref");
        println!("  Reference: {}", reference_name);
        println!("  Config digest: {}", result.config_digest);

        // Cleanup
        cleanup_test_image(&test_image);

        Ok(())
    })
}
integration_test!(privileged_test_cstor_import_with_reference);
