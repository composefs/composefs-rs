//! CLI integration tests that run on the host without root.
//!
//! Each test invokes `cfsctl --insecure` as a subprocess against a fresh
//! temp-dir repository. No network access, no fs-verity, no special
//! privileges required — these are the fast "does the CLI basically work"
//! smoke tests.

use anyhow::Result;
use xshell::{cmd, Shell};

use crate::{cfsctl, create_test_rootfs, integration_test};

fn test_gc_empty_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} gc").read()?;
    assert!(
        output.contains("Objects: 0 removed"),
        "expected zero objects removed, got: {output}"
    );
    Ok(())
}
integration_test!(test_gc_empty_repo);

fn test_create_image_from_path() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs}"
    )
    .read()?;
    assert!(
        !output.trim().is_empty(),
        "expected image ID output, got nothing"
    );
    Ok(())
}
integration_test!(test_create_image_from_path);

fn test_create_image_idempotent() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    let id1 = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs}"
    )
    .read()?;
    let id2 = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs}"
    )
    .read()?;
    assert_eq!(
        id1.trim(),
        id2.trim(),
        "creating the same image twice should produce the same ID"
    );
    Ok(())
}
integration_test!(test_create_image_idempotent);

fn test_create_and_list_objects() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    // Create with a ref name so we can look it up easily
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    let objects = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} image-objects refs/my-image"
    )
    .read()?;
    assert!(
        !objects.trim().is_empty(),
        "expected at least one object, got nothing"
    );
    Ok(())
}
integration_test!(test_create_and_list_objects);

fn test_gc_after_create() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs}"
    )
    .read()?;

    // GC with no roots — everything should be collected
    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} gc").read()?;
    assert!(
        output.contains("removed"),
        "expected GC output mentioning removed objects, got: {output}"
    );
    Ok(())
}
integration_test!(test_gc_after_create);

fn test_gc_dry_run() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    // Create an image with a ref name so we can reference it later
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    // Dry-run GC
    let gc_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} gc --dry-run").read()?;
    assert!(
        gc_output.contains("Dry run"),
        "expected dry run header, got: {gc_output}"
    );

    // Image should still be accessible after dry run
    let objects = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} image-objects refs/my-image"
    )
    .read()?;
    assert!(
        !objects.trim().is_empty(),
        "image should still exist after dry-run GC"
    );
    Ok(())
}
integration_test!(test_gc_dry_run);

fn test_oci_images_empty_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images").read()?;
    assert!(
        output.contains("No images found"),
        "expected 'No images found', got: {output}"
    );
    Ok(())
}
integration_test!(test_oci_images_empty_repo);

fn test_oci_images_json_empty_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images --json").read()?;
    // Empty JSON array
    let parsed: serde_json::Value = serde_json::from_str(&output)?;
    assert!(
        parsed.as_array().map(|a| a.is_empty()).unwrap_or(false),
        "expected empty JSON array, got: {output}"
    );
    Ok(())
}
integration_test!(test_oci_images_json_empty_repo);

/// Creates a minimal OCI image layout directory for testing using the ocidir crate.
///
/// Returns the path to the OCI layout directory.
fn create_oci_layout(parent: &std::path::Path) -> Result<std::path::PathBuf> {
    use cap_std_ext::cap_std;
    use ocidir::oci_spec::image::{
        ConfigBuilder, ImageConfigurationBuilder, Platform, PlatformBuilder, RootFsBuilder,
    };

    let oci_dir = parent.join("oci-image");
    std::fs::create_dir_all(&oci_dir)?;

    let dir = cap_std::fs::Dir::open_ambient_dir(&oci_dir, cap_std::ambient_authority())?;
    let ocidir = ocidir::OciDir::ensure(dir)?;

    // Create a new empty manifest
    let mut manifest = ocidir.new_empty_manifest()?.build()?;

    // Create runtime config (required for seal operation)
    let runtime_config = ConfigBuilder::default().build()?;

    // Create config with architecture and OS
    let rootfs = RootFsBuilder::default()
        .typ("layers")
        .diff_ids(Vec::<String>::new())
        .build()?;
    let mut config = ImageConfigurationBuilder::default()
        .architecture("amd64")
        .os("linux")
        .rootfs(rootfs)
        .config(runtime_config)
        .build()?;

    // Create a layer with proper directory structure for composefs
    let mut layer_builder = ocidir.create_layer(None)?;
    {
        // Create /usr directory (required by composefs)
        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_size(0);
        dir_header.set_mode(0o755);
        dir_header.set_uid(0);
        dir_header.set_gid(0);
        dir_header.set_mtime(1234567890);
        dir_header.set_cksum();
        layer_builder.append_data(&mut dir_header, "usr/", &[] as &[u8])?;

        // Create a test file
        let data = b"hello from test layer\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1234567890);
        header.set_cksum();
        layer_builder.append_data(&mut header, "hello.txt", &data[..])?;
    }
    let layer = layer_builder.into_inner()?.complete()?;

    // Push the layer to manifest and config
    ocidir.push_layer(&mut manifest, &mut config, layer, "test layer", None);

    // Create platform for the manifest
    let platform: Platform = PlatformBuilder::default()
        .architecture("amd64")
        .os("linux")
        .build()?;

    // Insert manifest and config into the OCI directory
    ocidir.insert_manifest_and_config(manifest, config, None, platform)?;

    Ok(oci_dir)
}

fn test_oci_pull_and_inspect() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    // Pull from OCI layout
    let pull_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;
    assert!(
        pull_output.contains("manifest sha256:"),
        "expected manifest digest in output, got: {pull_output}"
    );
    assert!(
        pull_output.contains("tagged") && pull_output.contains("test-image"),
        "expected tagged confirmation, got: {pull_output}"
    );

    // List images
    let list_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images").read()?;
    assert!(
        list_output.contains("test-image"),
        "expected test-image in list, got: {list_output}"
    );

    // List images as JSON
    let json_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images --json").read()?;
    let images: serde_json::Value = serde_json::from_str(&json_output)?;
    let arr = images.as_array().expect("expected array");
    assert_eq!(arr.len(), 1, "expected 1 image");
    assert_eq!(arr[0]["name"], "test-image");
    assert_eq!(arr[0]["architecture"], "amd64");

    // Inspect the image
    let inspect_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-image"
    )
    .read()?;
    let inspect: serde_json::Value = serde_json::from_str(&inspect_output)?;
    assert!(
        inspect.get("manifest").is_some(),
        "expected manifest in inspect output"
    );
    assert!(
        inspect.get("config").is_some(),
        "expected config in inspect output"
    );
    assert!(
        inspect.get("referrers").is_some(),
        "expected referrers in inspect output"
    );

    // Inspect --manifest
    let manifest_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-image --manifest"
    )
    .read()?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_output)?;
    assert_eq!(manifest["schemaVersion"], 2);
    assert!(manifest.get("config").is_some());
    assert!(manifest.get("layers").is_some());

    // Inspect --config
    let config_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-image --config"
    )
    .read()?;
    let config: serde_json::Value = serde_json::from_str(&config_output)?;
    assert_eq!(config["architecture"], "amd64");
    assert_eq!(config["os"], "linux");

    Ok(())
}
integration_test!(test_oci_pull_and_inspect);

fn test_oci_layer_inspect() -> Result<()> {
    use composefs_oci::composefs::dumpfile_parse::{Entry, Item};
    use std::io::Read;
    use std::path::Path;

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    // Pull from OCI layout
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // Get the layer diff_id from the config
    let config_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-image --config"
    )
    .read()?;
    let config: serde_json::Value = serde_json::from_str(&config_output)?;
    let diff_ids = config["rootfs"]["diff_ids"]
        .as_array()
        .expect("expected diff_ids array");
    assert_eq!(diff_ids.len(), 1, "expected 1 layer");
    let layer_id = diff_ids[0].as_str().expect("expected string");

    // Test --json output
    let json_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci layer {layer_id} --json"
    )
    .read()?;
    let info: serde_json::Value = serde_json::from_str(&json_output)?;
    assert_eq!(info["diffId"], layer_id);
    assert!(info["verity"].as_str().is_some(), "expected verity hash");
    assert!(info["size"].as_u64().unwrap() > 0, "expected non-zero size");
    assert_eq!(
        info["entryCount"].as_u64().unwrap(),
        2,
        "expected 2 entries (usr/ and hello.txt)"
    );
    // Check splitstream metadata
    let splitstream = info
        .get("splitstream")
        .expect("expected splitstream metadata");
    assert!(
        splitstream["externalObjects"].as_u64().is_some(),
        "expected externalObjects"
    );
    assert!(
        splitstream["externalSize"].as_u64().is_some(),
        "expected externalSize"
    );
    assert!(
        splitstream["inlineSize"].as_u64().is_some(),
        "expected inlineSize"
    );

    // Test --dumpfile output - parse each line with the dumpfile parser
    let dumpfile_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci layer {layer_id} --dumpfile"
    )
    .read()?;

    let mut found_hello_txt = false;
    for line in dumpfile_output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry = Entry::parse(line)
            .unwrap_or_else(|e| panic!("failed to parse dumpfile line '{line}': {e}"));

        if entry.path.as_ref() == Path::new("/hello.txt") {
            found_hello_txt = true;
            // Verify it's a regular file with inline content
            match &entry.item {
                Item::RegularInline { content, .. } => {
                    assert_eq!(
                        content.as_ref(),
                        b"hello from test layer\n",
                        "hello.txt content mismatch"
                    );
                }
                other => panic!("expected RegularInline for hello.txt, got {:?}", other),
            }
            assert_eq!(entry.uid, 0, "expected uid 0");
            assert_eq!(entry.gid, 0, "expected gid 0");
            // Mode 0o644 + regular file bit (0o100000) = 0o100644 = 33188
            assert_eq!(entry.mode, 0o100644, "expected mode 0o100644");
        }
    }
    assert!(found_hello_txt, "expected to find /hello.txt in dumpfile");

    // Test raw tar output - parse as actual tar and verify contents
    let tar_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci layer {layer_id}").output()?;
    let mut archive = tar::Archive::new(tar_output.stdout.as_slice());
    let mut found_in_tar = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path.as_ref() == Path::new("hello.txt") {
            found_in_tar = true;
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            assert_eq!(content, "hello from test layer\n", "tar content mismatch");
        }
    }
    assert!(found_in_tar, "expected to find hello.txt in tar output");

    Ok(())
}
integration_test!(test_oci_layer_inspect);

/// Test tagging and untagging OCI images.
///
/// Verifies that:
/// - An image can be tagged with multiple names
/// - Tags appear in `oci images` output
/// - Tags can be removed with `oci untag`
/// - Untagging one name doesn't affect other tags
fn test_oci_tag_and_untag() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    // Pull and tag with first name
    let pull_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} myimage:v1"
    )
    .read()?;

    // Extract manifest digest from pull output (e.g., "manifest sha256:abc...")
    let manifest_digest = pull_output
        .lines()
        .find(|line| line.contains("manifest sha256:"))
        .and_then(|line| line.split_whitespace().find(|s| s.starts_with("sha256:")))
        .expect("expected manifest digest in pull output");

    // Add a second tag using the manifest digest
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci tag {manifest_digest} myimage:latest"
    )
    .read()?;

    // Both tags should appear in list
    let list_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images --json").read()?;
    let images: serde_json::Value = serde_json::from_str(&list_output)?;
    let names: Vec<&str> = images
        .as_array()
        .unwrap()
        .iter()
        .map(|img| img["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"myimage:v1"), "expected myimage:v1 in list");
    assert!(
        names.contains(&"myimage:latest"),
        "expected myimage:latest in list"
    );

    // Remove one tag
    cmd!(sh, "{cfsctl} --insecure --repo {repo} oci untag myimage:v1").read()?;

    // Only the remaining tag should appear
    let list_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images --json").read()?;
    let images: serde_json::Value = serde_json::from_str(&list_output)?;
    let names: Vec<&str> = images
        .as_array()
        .unwrap()
        .iter()
        .map(|img| img["name"].as_str().unwrap())
        .collect();
    assert!(
        !names.contains(&"myimage:v1"),
        "myimage:v1 should be removed"
    );
    assert!(
        names.contains(&"myimage:latest"),
        "myimage:latest should still exist"
    );

    Ok(())
}
integration_test!(test_oci_tag_and_untag);

/// Test that GC removes untagged OCI images.
///
/// Verifies that:
/// - After untagging all references, GC collects the image
/// - Objects are actually removed from the repository
fn test_oci_gc_removes_untagged() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    // Pull an image
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // Verify it exists
    let list_before = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images --json").read()?;
    let images_before: Vec<serde_json::Value> = serde_json::from_str(&list_before)?;
    assert_eq!(images_before.len(), 1, "expected 1 image before untag");

    // Untag it
    cmd!(sh, "{cfsctl} --insecure --repo {repo} oci untag test-image").read()?;

    // Run GC
    let gc_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} gc").read()?;
    assert!(
        gc_output.contains("removed"),
        "expected GC to report removed objects: {gc_output}"
    );

    // Verify image is gone
    let list_after = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images --json").read()?;
    let images_after: Vec<serde_json::Value> = serde_json::from_str(&list_after)?;
    assert!(
        images_after.is_empty(),
        "expected no images after GC, got: {:?}",
        images_after
    );

    // Verify objects were actually removed (streams dir should be mostly empty)
    let streams_dir = repo.join("streams");
    let stream_count = if streams_dir.exists() {
        std::fs::read_dir(&streams_dir)?
            .filter(|e| e.as_ref().map(|e| e.file_name() != "refs").unwrap_or(false))
            .count()
    } else {
        0
    };
    assert_eq!(
        stream_count, 0,
        "expected no non-ref streams after GC, got {}",
        stream_count
    );

    Ok(())
}
integration_test!(test_oci_gc_removes_untagged);

/// Test layer tar roundtrip: import a layer, extract as tar, verify integrity.
///
/// This verifies that the splitstream storage correctly preserves tar content
/// by comparing the original tar with the reconstructed one.
fn test_layer_tar_roundtrip() -> Result<()> {
    use std::io::Read;

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    // Pull the image
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // Get the layer diff_id
    let config_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-image --config"
    )
    .read()?;
    let config: serde_json::Value = serde_json::from_str(&config_output)?;
    let layer_id = config["rootfs"]["diff_ids"][0]
        .as_str()
        .expect("expected layer diff_id");

    // Extract the layer as tar
    let tar_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci layer {layer_id}").output()?;
    assert!(tar_output.status.success(), "layer extraction failed");

    // Parse the tar and collect file entries
    let mut archive = tar::Archive::new(tar_output.stdout.as_slice());
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().to_string();
        let mut content = Vec::new();
        entry.read_to_end(&mut content)?;
        entries.push((path, content));
    }

    // Verify we got the expected files (usr/ directory and hello.txt)
    assert_eq!(
        entries.len(),
        2,
        "expected 2 entries in layer (usr/ and hello.txt)"
    );

    // Find hello.txt and verify content
    let hello_entry = entries
        .iter()
        .find(|(path, _)| path == "hello.txt")
        .expect("expected hello.txt in layer");
    assert_eq!(
        hello_entry.1, b"hello from test layer\n",
        "hello.txt content mismatch"
    );

    // Verify usr/ directory exists
    assert!(
        entries
            .iter()
            .any(|(path, _)| path == "usr" || path == "usr/"),
        "expected usr/ directory in layer"
    );

    Ok(())
}
integration_test!(test_layer_tar_roundtrip);

/// Test computing the composefs image ID for an OCI image.
///
/// This verifies that we can compute the filesystem verity hash for an image,
/// which is the prerequisite for sealing and mounting.
fn test_compute_image_id() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    // Pull an image
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // Get the config digest from inspect output
    let inspect_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-image"
    )
    .read()?;
    let inspect: serde_json::Value = serde_json::from_str(&inspect_output)?;
    let config_digest = inspect["manifest"]["config"]["digest"]
        .as_str()
        .expect("expected config digest");

    // Compute the image ID
    let compute_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci compute-id {config_digest}"
    )
    .read()?;

    // The output should be a valid hex digest
    // composefs uses SHA-256 fs-verity which produces 64 hex chars
    // (but the underlying digest could be longer in some configurations)
    let image_id = compute_output.trim();
    assert!(
        image_id.len() >= 64,
        "image ID should be at least 64 hex chars, got {} chars: {}",
        image_id.len(),
        image_id
    );
    assert!(
        image_id.chars().all(|c| c.is_ascii_hexdigit()),
        "image ID should be hex, got: {}",
        image_id
    );

    // Computing the same image should produce the same ID (deterministic)
    let compute_output2 = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci compute-id {config_digest}"
    )
    .read()?;
    assert_eq!(
        image_id,
        compute_output2.trim(),
        "compute-id should be deterministic"
    );

    Ok(())
}
integration_test!(test_compute_image_id);
