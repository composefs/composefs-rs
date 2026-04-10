//! CLI integration tests that run on the host without root.
//!
//! Each test invokes `cfsctl --insecure` as a subprocess against a fresh
//! temp-dir repository. No network access, no fs-verity, no special
//! privileges required — these are the fast "does the CLI basically work"
//! smoke tests.

use anyhow::Result;
use rustix::path::Arg;
use xshell::{Shell, cmd};

use crate::{cfsctl, create_test_rootfs, integration_test};

// Pinned composefs image ID for the deterministic OCI layout built by
// create_oci_layout() (single layer with usr/ dir + hello.txt, mtime=1234567890).
const OCI_LAYOUT_COMPOSEFS_ID: &str = "f26c6eb439749b82f0d1520e83455bb21766572fb2b5cfe009dd7749a61caf74e0c42c56f1a2cbd9d\
     359e7d172c8e2c65641666c9a18cc484a8b0f6e4e6d47ab";

/// Create a fresh initialized insecure repository in a tempdir.
///
/// Returns the tempdir (for lifetime) and the path to the repo.
fn init_insecure_repo(sh: &Shell, cfsctl: &std::path::Path) -> Result<tempfile::TempDir> {
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    cmd!(sh, "{cfsctl} --repo {repo} init --insecure").read()?;
    Ok(repo_dir)
}

fn test_gc_empty_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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

    // Create a simple layer with a usr/ directory and one file
    let mut layer_builder = ocidir.create_layer(None)?;
    {
        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_size(0);
        dir_header.set_mode(0o755);
        dir_header.set_uid(0);
        dir_header.set_gid(0);
        dir_header.set_mtime(1234567890);
        dir_header.set_cksum();
        layer_builder.append_data(&mut dir_header, "usr/", &[] as &[u8])?;
    }
    {
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
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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

    // Verify composefs image digest stability.
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
        "OCI layout composefs image ID changed — the EROFS writer produced \
         different output for the same deterministic OCI image"
    );

    Ok(())
}
integration_test!(test_oci_pull_and_inspect);

/// Verify that `oci compute-id` works with both a bare config digest and
/// a ref name, producing the same result either way.
fn test_oci_compute_id_by_ref() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    let pull_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-ref-image"
    )
    .read()?;

    let config_digest = pull_output
        .lines()
        .find_map(|l| l.strip_prefix("config").map(|s| s.trim().to_string()))
        .expect("config digest in pull output");

    // compute-id via @digest
    let at_config_digest = format!("@{config_digest}");
    let id_by_digest = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci compute-id {at_config_digest}"
    )
    .read()?;

    // compute-id via ref name
    let id_by_ref = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci compute-id test-ref-image"
    )
    .read()?;

    assert_eq!(
        id_by_digest.trim(),
        id_by_ref.trim(),
        "compute-id should produce the same result whether given a digest or a ref"
    );

    assert_eq!(
        id_by_ref.trim(),
        OCI_LAYOUT_COMPOSEFS_ID,
        "composefs image ID should match expected value"
    );

    Ok(())
}
integration_test!(test_oci_compute_id_by_ref);

fn test_oci_layer_inspect() -> Result<()> {
    use composefs_oci::composefs::dumpfile_parse::{Entry, Item};
    use std::io::Read;
    use std::path::Path;

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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
        "expected exactly 2 entries (usr/ + hello.txt)"
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

fn test_dump_files() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    // should be of the form /usr/bin/hello <path>
    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} dump-files refs/my-image /usr/bin/hello --backing-path-only"
    )
    .read()?;

    let path = output.split_whitespace().nth(1).unwrap();

    assert!(
        path != "inline",
        "usr/bin/hello should've been large enough to be stored in objects directory"
    );

    let path = path.strip_prefix("/").unwrap_or(path);

    let full_path = repo.join("objects").join(path);

    assert!(full_path.exists());

    let file_hash = cmd!(sh, "sha512sum")
        .arg(rootfs.join("usr/bin/hello").as_str()?)
        .read()?;

    let file_hash = file_hash.split_whitespace().next().unwrap().trim();

    let obj_file_hash = cmd!(sh, "sha512sum").arg(full_path.as_str()?).read()?;
    let obj_file_hash = obj_file_hash.split_whitespace().next().unwrap().trim();

    assert_eq!(file_hash, obj_file_hash);

    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} dump-files refs/my-image /usr/lib/readme.txt --backing-path-only"
    )
    .read()?;

    let path = output.split_whitespace().nth(1).unwrap();

    assert!(
        path == "inline",
        "usr/lib/readme.txt should've been stored inline"
    );

    Ok(())
}
integration_test!(test_dump_files);

/// Corrupt the first object found in the repository.
///
/// Walks `objects/XX/` directories, deletes the first regular file found,
/// and replaces it with junk data. Panics if no object is found.
fn corrupt_one_object(repo: &std::path::Path) -> Result<()> {
    use cap_std_ext::cap_std;

    let dir = cap_std::fs::Dir::open_ambient_dir(repo, cap_std::ambient_authority())?;
    let objects = std::path::Path::new("objects");
    for entry in dir.read_dir(objects)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let sub_path = objects.join(entry.file_name());
        let sub = dir.open_dir(&sub_path)?;
        for obj_entry in sub.entries()? {
            let obj_entry = obj_entry?;
            if obj_entry.file_type()?.is_file() {
                let rel = sub_path.join(obj_entry.file_name());
                dir.remove_file(&rel)?;
                dir.write(&rel, b"CORRUPTED DATA")?;
                return Ok(());
            }
        }
    }
    anyhow::bail!("no object found to corrupt");
}

fn test_init_creates_metadata() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Init with default algorithm (--repo before subcommand)
    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} init").read()?;
    assert!(
        output.contains("Initialized"),
        "expected initialization message, got: {output}"
    );
    assert!(
        output.contains("fsverity-sha512-12"),
        "expected algorithm in output, got: {output}"
    );

    // Check meta.json exists and is valid
    let meta_path = repo.join("meta.json");
    assert!(meta_path.exists(), "meta.json should exist after init");

    let meta_content = std::fs::read_to_string(&meta_path)?;
    let meta: serde_json::Value = serde_json::from_str(&meta_content)?;
    assert_eq!(meta["version"], 1);
    assert_eq!(meta["algorithm"], "fsverity-sha512-12");
    assert!(
        meta.get("features").is_some(),
        "features key should always be present"
    );

    Ok(())
}
integration_test!(test_init_creates_metadata);

fn test_init_sha256() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} init --algorithm fsverity-sha256-12"
    )
    .read()?;
    assert!(
        output.contains("fsverity-sha256-12"),
        "expected sha256 algorithm, got: {output}"
    );

    // Verify operations work with auto-detected hash
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;
    let image_id = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs}"
    )
    .read()?;
    assert!(
        !image_id.trim().is_empty(),
        "should produce image ID with auto-detected sha256"
    );

    Ok(())
}
integration_test!(test_init_sha256);

fn test_init_idempotent() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    cmd!(sh, "{cfsctl} --insecure --repo {repo} init").read()?;

    // Second init with same algorithm should succeed (idempotent)
    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} init").read()?;
    assert!(
        output.contains("already initialized"),
        "expected idempotent message, got: {output}"
    );

    Ok(())
}
integration_test!(test_init_idempotent);

fn test_init_conflict() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    cmd!(sh, "{cfsctl} --insecure --repo {repo} init").read()?;

    // Re-init with different algorithm should fail
    let result = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} init --algorithm fsverity-sha256-12"
    )
    .read();
    assert!(
        result.is_err(),
        "re-init with different algorithm should fail"
    );

    Ok(())
}
integration_test!(test_init_conflict);

fn test_hash_mismatch_errors() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Init as sha512 repo
    cmd!(sh, "{cfsctl} --insecure --repo {repo} init").read()?;

    // Explicitly passing --hash sha256 on a sha512 repo should error
    let result = cmd!(sh, "{cfsctl} --insecure --hash sha256 --repo {repo} gc").read();
    assert!(
        result.is_err(),
        "should error when --hash sha256 used on sha512 repo"
    );

    Ok(())
}
integration_test!(test_hash_mismatch_errors);

fn test_hash_match_ok() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Init as sha512 repo
    cmd!(sh, "{cfsctl} --insecure --repo {repo} init").read()?;

    // Explicitly passing --hash sha512 on a sha512 repo should work
    let output = cmd!(sh, "{cfsctl} --insecure --hash sha512 --repo {repo} gc").read()?;
    assert!(
        output.contains("Objects: 0 removed"),
        "should succeed with matching --hash, got: {output}"
    );

    Ok(())
}
integration_test!(test_hash_match_ok);

fn test_no_metadata_errors() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Use repo without init (no meta.json) - should error
    let result = cmd!(sh, "{cfsctl} --insecure --repo {repo} gc").read();
    assert!(
        result.is_err(),
        "should fail without meta.json, got: {result:?}"
    );

    // Should also fail with explicit --hash sha256 (no metadata)
    let result = cmd!(sh, "{cfsctl} --insecure --hash sha256 --repo {repo} gc").read();
    assert!(
        result.is_err(),
        "should fail with --hash sha256 and no metadata, got: {result:?}"
    );

    Ok(())
}
integration_test!(test_no_metadata_errors);

fn test_init_creates_directory() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let parent = tempfile::tempdir()?;
    let repo = parent.path().join("new-repo");

    // Init with positional path argument
    let output = cmd!(sh, "{cfsctl} --insecure init {repo}").read()?;
    assert!(
        output.contains("Initialized"),
        "expected initialization message, got: {output}"
    );
    assert!(repo.exists(), "repo directory should be created");
    assert!(
        repo.join("meta.json").exists(),
        "meta.json should exist in created dir"
    );

    Ok(())
}
integration_test!(test_init_creates_directory);

fn test_auto_detect_hash_for_operations() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;

    // Create a sha256 repo
    let repo_dir = tempfile::tempdir()?;
    let repo256 = repo_dir.path();
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo256} init --algorithm fsverity-sha256-12"
    )
    .read()?;

    // Create a sha512 repo
    let repo_dir2 = tempfile::tempdir()?;
    let repo512 = repo_dir2.path();
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo512} init --algorithm fsverity-sha512-12"
    )
    .read()?;

    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    // Create image in sha256 repo (no --hash flag needed)
    let id256 = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo256} create-image {rootfs}"
    )
    .read()?;

    // Create image in sha512 repo (no --hash flag needed)
    let id512 = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo512} create-image {rootfs}"
    )
    .read()?;

    // The image IDs should differ because different hash algorithms produce
    // different fs-verity digests
    assert_ne!(
        id256.trim(),
        id512.trim(),
        "sha256 and sha512 should produce different image IDs"
    );

    Ok(())
}
integration_test!(test_auto_detect_hash_for_operations);

fn test_fsck_empty_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} fsck --json").read()?;
    let v: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(v["ok"], true);
    assert_eq!(v["objectsChecked"], 0);
    assert_eq!(v["objectsCorrupted"], 0);
    assert!(v["errors"].as_array().unwrap().is_empty());
    Ok(())
}
integration_test!(test_fsck_empty_repo);

fn test_fsck_healthy_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} fsck --json").read()?;
    let v: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(v["ok"], true);
    assert!(v["objectsChecked"].as_u64().unwrap() > 0);
    assert_eq!(v["objectsCorrupted"], 0);
    assert!(v["errors"].as_array().unwrap().is_empty());
    Ok(())
}
integration_test!(test_fsck_healthy_repo);

fn test_fsck_detects_corrupted_object() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;
    corrupt_one_object(repo)?;

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} fsck --json").read()?;
    let v: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(v["ok"], false);
    assert!(v["objectsCorrupted"].as_u64().unwrap() > 0);
    assert!(!v["errors"].as_array().unwrap().is_empty());
    Ok(())
}
integration_test!(test_fsck_detects_corrupted_object);

/// Verify that without --json, fsck exits non-zero on corruption.
fn test_fsck_nonzero_exit_on_corruption() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;
    corrupt_one_object(repo)?;

    cmd!(sh, "{cfsctl} --insecure --repo {repo} fsck")
        .run()
        .expect_err("fsck without --json should exit non-zero on corruption");
    Ok(())
}
integration_test!(test_fsck_nonzero_exit_on_corruption);

fn test_oci_fsck_healthy() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci fsck --json").read()?;
    let v: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(v["ok"], true);
    assert_eq!(v["imagesChecked"], 1);
    assert_eq!(v["imagesCorrupted"], 0);
    Ok(())
}
integration_test!(test_oci_fsck_healthy);

fn test_oci_fsck_detects_corrupted_manifest() -> Result<()> {
    use cap_std_ext::cap_std;

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // Find the manifest stream symlink and corrupt its backing object
    let dir = cap_std::fs::Dir::open_ambient_dir(repo, cap_std::ambient_authority())?;
    let streams = std::path::Path::new("streams");
    let mut corrupted = false;
    for entry in dir.read_dir(streams)? {
        let entry = entry?;
        let name = entry.file_name();
        if !name.as_encoded_bytes().starts_with(b"oci-manifest-") {
            continue;
        }
        let symlink_rel = streams.join(&name);
        let target = dir.read_link(&symlink_rel)?;
        let obj_rel = streams.join(&target);
        if dir.exists(&obj_rel) {
            dir.remove_file(&obj_rel)?;
            dir.write(&obj_rel, b"CORRUPTED MANIFEST DATA")?;
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "should have found a manifest object to corrupt");

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci fsck --json").read()?;
    let v: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(v["ok"], false);
    Ok(())
}
integration_test!(test_oci_fsck_detects_corrupted_manifest);

fn test_oci_fsck_single_image() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // Check a specific image by name
    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci fsck --json test-image"
    )
    .read()?;
    let v: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(v["ok"], true);
    assert_eq!(v["imagesChecked"], 1);

    // A nonexistent image is a hard error (not a corruption finding)
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci fsck nonexistent-image"
    )
    .run()
    .expect_err("oci fsck should fail for nonexistent image");
    Ok(())
}
integration_test!(test_oci_fsck_single_image);

fn test_compute_id_no_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    let output = cmd!(
        sh,
        "{cfsctl} --no-repo compute-id --no-propagate-usr-to-root {rootfs}"
    )
    .read()?;
    assert!(
        !output.trim().is_empty(),
        "expected image ID output, got nothing"
    );
    // Should be a valid hex digest
    assert!(
        output.trim().chars().all(|c| c.is_ascii_hexdigit()),
        "expected hex digest, got: {output}"
    );
    Ok(())
}
integration_test!(test_compute_id_no_repo);

fn test_compute_id_no_repo_matches_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    let id_no_repo = cmd!(
        sh,
        "{cfsctl} --no-repo compute-id --no-propagate-usr-to-root {rootfs}"
    )
    .read()?;
    let id_with_repo = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} compute-id --no-propagate-usr-to-root {rootfs}"
    )
    .read()?;
    assert_eq!(
        id_no_repo.trim(),
        id_with_repo.trim(),
        "--no-repo and --repo should produce the same digest"
    );
    Ok(())
}
integration_test!(test_compute_id_no_repo_matches_repo);

fn test_create_dumpfile_no_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    let output = cmd!(
        sh,
        "{cfsctl} --no-repo create-dumpfile --no-propagate-usr-to-root {rootfs}"
    )
    .read()?;
    assert!(
        output.contains("/usr/bin/hello"),
        "expected dumpfile to contain /usr/bin/hello, got: {output}"
    );
    assert!(
        output.contains("/etc/hostname"),
        "expected dumpfile to contain /etc/hostname, got: {output}"
    );
    Ok(())
}
integration_test!(test_create_dumpfile_no_repo);

fn test_no_repo_rejects_create_image() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --no-repo create-image --no-propagate-usr-to-root {rootfs}"
    )
    .run()
    .expect_err("create-image should fail with --no-repo");
    Ok(())
}
integration_test!(test_no_repo_rejects_create_image);

fn test_fsck_detects_broken_image_ref() -> Result<()> {
    use cap_std_ext::cap_std;

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    // Break the ref chain: images/refs/my-image -> ../HEXID -> ../objects/...
    // by removing the intermediate image symlink.
    let dir = cap_std::fs::Dir::open_ambient_dir(repo, cap_std::ambient_authority())?;
    let refs_path = std::path::Path::new("images/refs");
    let mut broken = false;
    if dir.exists(refs_path) {
        for entry in dir.read_dir(refs_path)? {
            let entry = entry?;
            let entry_rel = refs_path.join(entry.file_name());
            if dir.symlink_metadata(&entry_rel)?.is_symlink() {
                let target = dir.read_link(&entry_rel)?;
                let resolved = refs_path.join(&target);
                if dir.symlink_metadata(&resolved).is_ok() {
                    dir.remove_file(&resolved)?;
                    broken = true;
                    break;
                }
            }
        }
    }
    assert!(broken, "should have found an image ref to break");

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} fsck --json").read()?;
    let v: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(v["ok"], false);
    assert!(v["brokenLinks"].as_u64().unwrap() > 0);
    Ok(())
}
integration_test!(test_fsck_detects_broken_image_ref);

fn test_init_insecure() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    let output = cmd!(sh, "{cfsctl} --repo {repo} init --insecure").read()?;
    assert!(
        output.contains("Initialized"),
        "expected initialization message, got: {output}"
    );
    assert!(
        output.contains("insecure"),
        "expected insecure in output, got: {output}"
    );

    // Operations should work without --insecure flag (auto-detected)
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;
    let image_id = cmd!(sh, "{cfsctl} --repo {repo} create-image {rootfs}").read()?;
    assert!(
        !image_id.trim().is_empty(),
        "should produce image ID on insecure repo"
    );

    let output = cmd!(sh, "{cfsctl} --repo {repo} gc").read()?;
    assert!(
        output.contains("Objects:"),
        "gc should work on insecure repo, got: {output}"
    );

    Ok(())
}
integration_test!(test_init_insecure);

fn test_require_verity_fails_on_insecure_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Create an insecure repo
    cmd!(sh, "{cfsctl} --repo {repo} init --insecure").read()?;

    // --require-verity should fail
    let result = cmd!(sh, "{cfsctl} --require-verity --repo {repo} gc").read();
    assert!(
        result.is_err(),
        "--require-verity should fail on insecure repo"
    );

    Ok(())
}
integration_test!(test_require_verity_fails_on_insecure_repo);

fn test_missing_metadata_fails() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Legacy repo: no init, no meta.json — should fail at open time
    let result = cmd!(sh, "{cfsctl} --repo {repo} gc").read();
    assert!(
        result.is_err(),
        "repo without meta.json should fail to open"
    );

    Ok(())
}
integration_test!(test_missing_metadata_fails);

fn test_old_format_repo_gives_migration_hint() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Simulate an old-format repo: has objects/ but no meta.json
    std::fs::create_dir(repo.join("objects"))?;

    // Should fail with a helpful migration hint
    let result = cmd!(sh, "{cfsctl} --repo {repo} gc").read();
    assert!(result.is_err(), "old-format repo should fail to open");

    Ok(())
}
integration_test!(test_old_format_repo_gives_migration_hint);

fn test_init_reset_metadata() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
    let repo = repo_dir.path();

    // Create some content so streams/ and images/ exist
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;
    cmd!(sh, "{cfsctl} --repo {repo} create-image {rootfs}").read()?;

    // Verify streams/ and/or images/ exist
    assert!(
        repo.join("streams").exists() || repo.join("images").exists(),
        "repo should have streams/ or images/ after create-image"
    );

    // Reset metadata — should remove streams/ and images/ but keep objects/
    let output = cmd!(
        sh,
        "{cfsctl} --repo {repo} init --insecure --reset-metadata"
    )
    .read()?;
    assert!(
        output.contains("Initialized") || output.contains("Removed"),
        "expected init output after reset, got: {output}"
    );

    // streams/ and images/ should be gone
    assert!(
        !repo.join("streams").exists(),
        "streams/ should be removed after --reset-metadata"
    );
    assert!(
        !repo.join("images").exists(),
        "images/ should be removed after --reset-metadata"
    );

    // objects/ should still exist
    assert!(
        repo.join("objects").exists(),
        "objects/ should be preserved after --reset-metadata"
    );

    // Repo should be usable again
    let output = cmd!(sh, "{cfsctl} --repo {repo} gc").read()?;
    assert!(
        output.contains("Objects:"),
        "gc should work after --reset-metadata, got: {output}"
    );

    Ok(())
}
integration_test!(test_init_reset_metadata);

fn test_init_reset_metadata_changes_algorithm() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Init with sha256
    cmd!(
        sh,
        "{cfsctl} --repo {repo} init --insecure --algorithm fsverity-sha256-12"
    )
    .read()?;

    // Trying to re-init with sha512 without --reset-metadata should fail
    let result = cmd!(
        sh,
        "{cfsctl} --repo {repo} init --insecure --algorithm fsverity-sha512-12"
    )
    .read();
    assert!(
        result.is_err(),
        "re-init with different algorithm should fail without --reset-metadata"
    );

    // With --reset-metadata it should succeed
    let output = cmd!(
        sh,
        "{cfsctl} --repo {repo} init --insecure --reset-metadata --algorithm fsverity-sha512-12"
    )
    .read()?;
    assert!(
        output.contains("Initialized"),
        "expected init output after reset with new algorithm, got: {output}"
    );

    Ok(())
}
integration_test!(test_init_reset_metadata_changes_algorithm);

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
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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
    let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
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
    // Digests must be prefixed with '@' to distinguish from named refs
    let config_ref = format!("@{config_digest}");

    // Compute the image ID
    let compute_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci compute-id {config_ref}"
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
        "{cfsctl} --insecure --repo {repo} oci compute-id {config_ref}"
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
