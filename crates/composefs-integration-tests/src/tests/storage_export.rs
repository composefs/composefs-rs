//! CLI publication consumed by Go, with isolated primary and additional stores.

mod cache;
mod fixtures;
mod recovery;
mod tar_interop;

use std::{
    collections::BTreeSet,
    io::Cursor,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result};
use composefs::{
    fsverity::{FsVerityHashValue, Sha512HashValue},
    repository::{Repository, RepositoryConfig},
};
use xshell::{Shell, cmd};

use super::privileged::{VerityTempDir, require_privileged};
use crate::{cfsctl, integration_test};
use fixtures::{raw_image, raw_image_with_config};

// Opening a Go overlay store can leave a private bind mount on its driver
// directory. Remove that mount before the backing loop filesystem is dropped.
struct OverlayMountCleanup<'a>(&'a Path);

impl Drop for OverlayMountCleanup<'_> {
    fn drop(&mut self) {
        let path = self.0.join("overlay");
        match rustix::mount::unmount(&path, rustix::mount::UnmountFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOENT) => {}
            Err(error) => eprintln!("unmounting {}: {error}", path.display()),
        }
    }
}

fn append(tar: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8], directory: bool) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(if directory {
        tar::EntryType::Directory
    } else {
        tar::EntryType::Regular
    });
    header.set_mode(
        if directory || path.starts_with("usr/") || path.starts_with("lib") {
            0o755
        } else {
            0o644
        },
    );
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(123);
    header.set_size(data.len() as u64);
    header.set_cksum();
    tar.append_data(&mut header, path, data)?;
    Ok(())
}

async fn store_image(
    repo: &Arc<Repository<Sha512HashValue>>,
    layers: &[&[u8]],
) -> Result<composefs_oci::OciDigest> {
    let mut refs = Vec::new();
    for bytes in layers {
        let (id, _) = composefs_oci::tar::split_async(
            Cursor::new(bytes),
            Arc::clone(repo),
            composefs_oci::LAYER_CONTENT_TYPE,
        )
        .await?;
        refs.push((composefs_oci::sha256_content_digest(bytes), id));
    }
    let raw = raw_image(layers)?;
    // These fixtures exercise layer orderings that EROFS tree construction
    // does not support. Store their OCI streams without generating an EROFS.
    let (_, config_verity) = composefs_oci::write_config_raw(
        repo,
        &raw.config_json,
        refs.iter()
            .map(|(diff, verity)| (diff.as_ref().into(), verity.clone()))
            .collect(),
        None,
        None,
        &Default::default(),
    )?;
    let manifest = containers_image_proxy::oci_spec::image::ImageManifest::from_reader(
        raw.manifest_json.as_slice(),
    )?;
    let digest = composefs_oci::sha256_content_digest(manifest.to_string()?.as_bytes());
    composefs_oci::oci_image::write_manifest(
        repo,
        &manifest,
        &digest,
        &config_verity,
        &refs,
        None,
    )?;
    Ok(digest)
}

fn copy_to_storage(
    repo: &Path,
    graph: &Path,
    run: &Path,
    image: &str,
    options: &[&str],
) -> Result<String> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    cmd!(sh, "{cfsctl} --repo {repo} oci copy-to-storage {image} --graphroot {graph} --runroot {run} {options...}")
        .read()
        .context("cfsctl oci copy-to-storage")
}

fn top_layer(graph: &Path, image_id: &str) -> Result<String> {
    let images: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(graph.join("overlay-images/images.json"))?)?;
    images
        .iter()
        .find(|image| image["id"] == image_id)
        .and_then(|image| image["layer"].as_str())
        .map(str::to_owned)
        .context("published image has no top layer")
}

fn check_compressed_layer_reuse(sh: &Shell, root: &Path) -> Result<()> {
    let cfsctl = cfsctl()?;
    let fixture = tempfile::tempdir()?;
    let layout = super::cli::create_oci_layout(fixture.path())?;
    let source = format!("oci:{}", layout.display());
    let raw_manifest = cmd!(sh, "skopeo inspect --raw {source}").output()?.stdout;
    let mut manifest: serde_json::Value = serde_json::from_slice(&raw_manifest)?;
    // The shared fixture omits the optional manifest media type; the storage
    // writer requires an explicit OCI image manifest.
    manifest["mediaType"] = "application/vnd.oci.image.manifest.v1+json".into();
    let raw_manifest = serde_json::to_vec(&manifest)?;
    let manifest_digest = composefs_oci::sha256_content_digest(&raw_manifest);
    std::fs::write(
        layout.join("blobs/sha256").join(manifest_digest.digest()),
        &raw_manifest,
    )?;
    let index_path = layout.join("index.json");
    let mut index: serde_json::Value = serde_json::from_slice(&std::fs::read(&index_path)?)?;
    index["manifests"][0]["digest"] = manifest_digest.to_string().into();
    index["manifests"][0]["size"] = raw_manifest.len().into();
    std::fs::write(index_path, serde_json::to_vec(&index)?)?;
    let layer = &manifest["layers"][0];
    assert_eq!(
        layer["mediaType"],
        "application/vnd.oci.image.layer.v1.tar+gzip"
    );
    let blob_digest: composefs_oci::OciDigest = layer["digest"].as_str().unwrap().parse()?;

    let repo_path = root.join("compressed-source");
    Repository::<Sha512HashValue>::init_path(
        rustix::fs::CWD,
        &repo_path,
        RepositoryConfig::new(Sha512HashValue::ALGORITHM),
    )?;
    cmd!(
        sh,
        "{cfsctl} --repo {repo_path} oci pull {source} compressed-source"
    )
    .run()?;
    let graph = root.join("compressed-graph");
    let run = fixture.path().join("run");
    let image_id = copy_to_storage(
        &repo_path,
        &graph,
        &run,
        "compressed-source",
        &["--name", "localhost/compressed:rust"],
    )?;
    let layers_path = graph.join("overlay-layers/layers.json");
    let before = std::fs::read(&layers_path)?;
    let top = top_layer(&graph, &image_id)?;

    // Go must recognize the original compressed digest without fetching the blob.
    // Remove it from the source so a missed reuse lookup fails instead of
    // silently downloading and extracting another copy of the layer.
    std::fs::remove_file(layout.join("blobs/sha256").join(blob_digest.digest()))?;
    let destination = format!(
        "containers-storage:[overlay@{}+{}]localhost/compressed:go",
        graph.display(),
        run.display(),
    );
    cmd!(sh, "skopeo copy --preserve-digests {source} {destination}").run()?;
    assert_eq!(std::fs::read(&layers_path)?, before);
    let records: Vec<serde_json::Value> = serde_json::from_slice(&before)?;
    let record = records.iter().find(|record| record["id"] == top).unwrap();
    assert_eq!(record["compressed-diff-digest"], blob_digest.to_string());
    assert_eq!(record["compressed-size"], layer["size"]);
    assert_eq!(top_layer(&graph, &image_id)?, top);
    let copied = cmd!(sh, "skopeo inspect --raw {destination}").output()?;
    assert_eq!(copied.stdout, raw_manifest);
    Ok(())
}

/// Bundle a real executable and its loader/libraries without a registry pull.
fn base_layer(sh: &Shell) -> Result<Vec<u8>> {
    let mut tar = tar::Builder::new(Vec::new());
    append(&mut tar, ".", &[], true)?;
    append(&mut tar, "usr", &[], true)?;
    let executable = "/usr/bin/test";
    let libraries = cmd!(sh, "ldd {executable}").read()?;
    let mut paths = BTreeSet::from([executable]);
    paths.extend(libraries.split_whitespace().filter(|s| s.starts_with('/')));
    let mut directories = BTreeSet::from([
        "opaque".to_owned(),
        "dir-before".to_owned(),
        "temporary".to_owned(),
    ]);
    for path in &paths {
        let path = std::path::Path::new(path.trim_start_matches('/'));
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty() && *p != std::path::Path::new("usr"))
        {
            directories.insert(parent.to_str().unwrap().to_owned());
        }
    }
    for directory in directories {
        append(&mut tar, &directory, &[], true)?;
    }
    for path in paths {
        append(
            &mut tar,
            path.trim_start_matches('/'),
            &std::fs::read(path)?,
            false,
        )?;
    }
    for path in [
        "removed",
        "opaque/old",
        "replace-before",
        "dir-before/old",
        "temporary/old",
    ] {
        append(&mut tar, path, b"base", false)?;
    }
    Ok(tar.into_inner()?)
}

fn upper_layer() -> Result<Vec<u8>> {
    let mut tar = tar::Builder::new(Vec::new());
    for (path, data) in [
        // Encoded whiteout entry names can themselves match materialized
        // whiteout targets. Both targets must survive conversion.
        (".wh..wh.b", b"".as_slice()),
        (".wh.b", b""),
        (".wh.removed", b"".as_slice()),
        ("opaque/.wh..wh..opq", b""),
        ("opaque/new", b"upper"),
        (".wh.replace-before", b""),
        ("replace-before", b"upper"),
        (".wh.dir-before", b""),
        ("dir-before/new", b"upper"),
    ] {
        append(&mut tar, path, data, false)?;
        if path == ".wh.dir-before" {
            append(&mut tar, "dir-before", &[], true)?;
        }
    }
    // Replacing a directory from the lower layer remains supported.
    append(&mut tar, "temporary", &vec![73; 128 * 1024 + 1], false)?;
    Ok(tar.into_inner()?)
}

fn backing_label(file: &std::fs::File) -> Result<Vec<u8>> {
    let mut label = vec![0; 4096];
    match rustix::fs::fgetxattr(file, "security.selinux", &mut label) {
        Ok(n) => {
            label.truncate(n);
            Ok(label)
        }
        Err(rustix::io::Errno::NODATA | rustix::io::Errno::OPNOTSUPP) => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

async fn check_hardlinks_preserve_source_labels(root: &std::path::Path) -> Result<()> {
    let payload = vec![37; 128 * 1024 + 1];
    let mut tar = tar::Builder::new(Vec::new());
    append(&mut tar, "payload", &payload, false)?;
    let tar = tar.into_inner()?;
    let mut differing_creation_label = false;
    for (index, label) in [
        "system_u:object_r:usr_t:s0",
        "system_u:object_r:container_var_lib_t:s0",
    ]
    .into_iter()
    .enumerate()
    {
        let repo_path = root.join(format!("label-source-{index}"));
        let (repo, _) = Repository::<Sha512HashValue>::init_path(
            rustix::fs::CWD,
            &repo_path,
            RepositoryConfig::new(Sha512HashValue::ALGORITHM),
        )?;
        let repo = Arc::new(repo);
        let digest = store_image(&repo, &[&tar]).await?;
        let object = repo.ensure_object(&payload)?;
        let source = std::fs::File::from(repo.open_object(&object)?);
        // Give the repository payload metadata matching the tar header, so
        // hardlink eligibility differs only in the host-policy SELinux label.
        rustix::fs::fchmod(&source, rustix::fs::Mode::from_bits_truncate(0o644))?;
        source.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(123))?;
        rustix::fs::fsetxattr(
            &source,
            "security.selinux",
            label.as_bytes(),
            rustix::fs::XattrFlags::empty(),
        )?;
        let before = backing_label(&source)?;
        assert_eq!(
            before.strip_suffix(&[0]).unwrap_or(&before),
            label.as_bytes()
        );
        let graph = root.join(format!("label-graph-{index}"));
        let run = root.join(format!("label-run-{index}"));
        let image_id = copy_to_storage(
            &repo_path,
            &graph,
            &run,
            &format!("@{digest}"),
            &["--allow-hardlinks"],
        )?;
        let layer = top_layer(&graph, &image_id)?;
        let diff = graph.join(format!("overlay/{layer}/diff"));
        let target = std::fs::File::open(diff.join("payload"))?;
        assert_eq!(target.metadata()?.ino(), source.metadata()?.ino());
        assert_eq!(backing_label(&target)?, before);
        assert_eq!(backing_label(&source)?, before);
        let probe = std::fs::File::create(diff.join("creation-probe"))?;
        differing_creation_label |= backing_label(&probe)? != before;
    }
    assert!(
        differing_creation_label,
        "fixture must exercise a source label different from normal creation"
    );
    Ok(())
}

async fn check_implicit_directory_ownership(
    repo: &Arc<Repository<Sha512HashValue>>,
    repo_path: &Path,
    graph: &Path,
    run: &Path,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_mode(0o701);
    header.set_uid(1000);
    header.set_gid(1001);
    header.set_size(0);
    header.set_mtime(123);
    header.set_cksum();
    for path in ["a", "a/b"] {
        tar.append_data(&mut header, path, std::io::empty())?;
    }
    let base = tar.into_inner()?;
    for (marker, before) in [
        (Some("a/.wh..wh..opq"), true),
        (Some("a/.wh..wh..opq"), false),
        (Some(".wh.a"), true),
        (None, false),
    ] {
        let mut tar = tar::Builder::new(Vec::new());
        let mut paths = vec!["a/b/new"];
        if let Some(marker) = marker {
            if before {
                paths.insert(0, marker);
            } else {
                paths.push(marker);
            }
        }
        for path in paths {
            if path == "a/b/new" {
                append(&mut tar, path, &[], false)?;
            } else {
                let mut whiteout = header.clone();
                whiteout.set_entry_type(tar::EntryType::Regular);
                whiteout.set_uid(60000);
                whiteout.set_gid(60001);
                tar.append_data(&mut whiteout, path, std::io::empty())?;
            }
        }
        let mut hardlink = header.clone();
        hardlink.set_entry_type(tar::EntryType::Link);
        hardlink.set_uid(42);
        hardlink.set_gid(43);
        hardlink.set_link_name("a/b/new")?;
        tar.append_data(&mut hardlink, "alias", std::io::empty())?;
        let upper = tar.into_inner()?;
        let digest = store_image(repo, &[&base, &upper]).await?;
        let image_id = copy_to_storage(repo_path, graph, run, &format!("@{digest}"), &[])?;
        let layer = top_layer(graph, &image_id)?;
        let records: Vec<serde_json::Value> =
            serde_json::from_slice(&std::fs::read(graph.join("overlay-layers/layers.json"))?)?;
        let base_layer = records
            .iter()
            .find(|record| record["id"] == layer)
            .and_then(|record| record["parent"].as_str())
            .context("upper layer has no parent")?;
        // Record explicit header owners only: include the hardlink header,
        // exclude whiteouts and root/parent metadata restored without headers.
        for (id, uids, gids) in [
            (
                base_layer,
                serde_json::json!([1000]),
                serde_json::json!([1001]),
            ),
            (
                layer.as_str(),
                serde_json::json!([0, 42]),
                serde_json::json!([0, 43]),
            ),
        ] {
            let record = records
                .iter()
                .find(|r| r["id"].as_str() == Some(id))
                .unwrap();
            assert_eq!(record["uidset"], uids, "{marker:?}, before={before}");
            assert_eq!(record["gidset"], gids, "{marker:?}, before={before}");
        }
        let metadata = std::fs::metadata(graph.join(format!("overlay/{layer}/diff/a/b")))?;
        assert_eq!(
            (metadata.mode() & 0o7777, metadata.uid(), metadata.gid()),
            if marker.is_some() {
                (0o755, 0, 0)
            } else {
                (0o701, 1000, 1001)
            },
            "{marker:?}, before={before}"
        );
    }
    Ok(())
}

async fn check_whiteout_default_acls(
    repo: &Arc<Repository<Sha512HashValue>>,
    repo_path: &Path,
    graph: &Path,
    run: &Path,
) -> Result<()> {
    use rustix::fs::{self, FileType, Mode, XattrFlags};

    let overlay = std::fs::File::open(graph.join("overlay"))?;
    // Linux POSIX ACL xattr v2: owner, named user, group, mask, other.
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in [
        (1u16, 7u16, u32::MAX),
        (2, 4, 1234),
        (4, 5, u32::MAX),
        (16, 5, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&permissions.to_le_bytes());
        acl.extend_from_slice(&id.to_le_bytes());
    }
    fs::fsetxattr(
        &overlay,
        "system.posix_acl_default",
        &acl,
        XattrFlags::empty(),
    )?;
    let probe = graph.join("overlay/acl-probe");
    fs::mknodat(
        &overlay,
        "acl-probe",
        FileType::CharacterDevice,
        Mode::empty(),
        0,
    )?;
    let mut value = [0; 128];
    // Ensure the fixture really does give mode-zero devices an inherited ACL.
    assert!(fs::lgetxattr(&probe, "system.posix_acl_access", &mut value)? > 0);
    std::fs::remove_file(probe)?;

    let mut tar = tar::Builder::new(Vec::new());
    append(&mut tar, ".wh.acl-target", &[], false)?;
    let tar = tar.into_inner()?;
    let digest = store_image(repo, &[&tar]).await?;
    let image_id = copy_to_storage(repo_path, graph, run, &format!("@{digest}"), &[])?;
    let layer = top_layer(graph, &image_id)?;
    let target = graph.join(format!("overlay/{layer}/diff/acl-target"));
    let metadata = std::fs::symlink_metadata(&target)?;
    assert!(metadata.file_type().is_char_device());
    assert_eq!(metadata.rdev(), 0);
    assert_eq!(metadata.mode() & 0o7777, 0);
    for key in ["system.posix_acl_access", "system.posix_acl_default"] {
        assert_eq!(
            fs::lgetxattr(&target, key, &mut value),
            Err(rustix::io::Errno::NODATA),
            "{key}"
        );
    }
    fs::fremovexattr(&overlay, "system.posix_acl_default")?;
    Ok(())
}

fn podman_store_args<'a>(graph: &'a Path, run: &'a Path) -> [&'a str; 8] {
    [
        "--root",
        graph.to_str().unwrap(),
        "--runroot",
        run.to_str().unwrap(),
        "--storage-driver",
        "overlay",
        "--storage-opt",
        "overlay.mount_program=",
    ]
}

struct ExportFixture {
    repo: Arc<Repository<Sha512HashValue>>,
    repo_path: std::path::PathBuf,
    layers: [Vec<u8>; 2],
    config: Vec<u8>,
    manifest: Vec<u8>,
    digest: composefs_oci::OciDigest,
    image_id: String,
}

async fn create_export_fixture(sh: &Shell, repo_path: &Path) -> Result<ExportFixture> {
    let layers = [base_layer(sh)?, upper_layer()?];
    // A secure SHA-512 repository exercises the same exporter as the insecure
    // SHA-256/SHA-512 unit fixtures, including retained external file references.
    let (repo, _) = Repository::<Sha512HashValue>::init_path(
        rustix::fs::CWD,
        repo_path,
        RepositoryConfig::new(Sha512HashValue::ALGORITHM),
    )?;
    let repo = Arc::new(repo);
    let mut refs = Vec::new();
    for bytes in &layers {
        let diff = composefs_oci::sha256_content_digest(bytes);
        let (id, _) = composefs_oci::tar::split_async(
            Cursor::new(bytes),
            repo.clone(),
            composefs_oci::LAYER_CONTENT_TYPE,
        )
        .await?;
        refs.push((diff, id));
    }
    let raw = raw_image_with_config(
        &[&layers[0], &layers[1]],
        serde_json::json!({
            "created":"2020-01-02T03:04:05Z", "architecture":std::env::consts::ARCH.replace("x86_64", "amd64").replace("aarch64", "arm64"),
            "os":"linux",
            "config":{"Entrypoint":["/usr/bin/test"]}
        }),
    )?;
    let ((digest, _), _) = composefs_oci::layer_sync::finalize_oci_image(
        &repo,
        &raw.manifest_json,
        &raw.config_json,
        &refs,
        Some("export-source"),
        None,
    )?;
    let image_id = composefs_oci::sha256_content_digest(&raw.config_json)
        .digest()
        .to_owned();
    Ok(ExportFixture {
        repo,
        repo_path: repo_path.to_owned(),
        layers,
        config: raw.config_json,
        manifest: raw.manifest_json,
        digest,
        image_id,
    })
}

fn check_name_reassignment(
    sh: &Shell,
    fixture: &ExportFixture,
    graph: &Path,
    run: &Path,
    unrelated: &str,
) -> Result<()> {
    let repo_path = &fixture.repo_path;
    let image_id = fixture.image_id.as_str();
    let primary = podman_store_args(graph, run);
    // Names conflict by default; --reassign explicitly moves a name from a
    // different image without disturbing that image's other names.
    cmd!(
        sh,
        "podman {primary...} tag {unrelated} localhost/moved:latest"
    )
    .run()?;
    let cfsctl = cfsctl()?;
    let images_path = graph.join("overlay-images/images.json");
    let before_conflict = std::fs::read(&images_path)?;
    let conflict = cmd!(sh, "{cfsctl} --repo {repo_path} oci copy-to-storage export-source --graphroot {graph} --runroot {run} --name localhost/moved")
        .ignore_status()
        .output()?;
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("image name already assigned"));
    assert_eq!(std::fs::read(&images_path)?, before_conflict);
    assert_eq!(
        copy_to_storage(
            repo_path,
            graph,
            run,
            "export-source",
            &["--name", "localhost/moved", "--reassign"],
        )?,
        image_id
    );
    Ok(())
}

fn check_materialized_whiteouts(graph: &Path, top: &str) -> Result<()> {
    let diff = graph.join("overlay").join(top).join("diff");
    for target in [".wh.b", "b"] {
        let metadata = std::fs::symlink_metadata(diff.join(target))
            .with_context(|| format!("materialized whiteout target {target}"))?;
        assert!(metadata.file_type().is_char_device(), "{target}");
        assert_eq!(metadata.rdev(), 0, "{target}");
    }
    Ok(())
}

fn check_skopeo_round_trip(
    sh: &Shell,
    fixture: &ExportFixture,
    graph: &Path,
    run: &Path,
    output: &Path,
    top: &str,
) -> Result<()> {
    let image_id = fixture.image_id.as_str();
    let digest = &fixture.digest;
    let manifest = fixture.manifest.as_slice();
    let config = fixture.config.as_slice();
    let config_digest = composefs_oci::sha256_content_digest(config);
    let layers = &fixture.layers;
    let transport = format!(
        "containers-storage:[overlay@{}+{}]",
        graph.display(),
        run.display()
    );
    for identity in [
        format!("@{image_id}"),
        format!("localhost/exported@{digest}"),
        "localhost/exported".into(),
        "localhost/exported:latest".into(),
        "localhost/exported:also".into(),
        "localhost/moved:latest".into(),
    ] {
        let source = format!("{transport}{identity}");
        let actual = cmd!(sh, "skopeo inspect --raw {source}")
            .ignore_status()
            .output()?;
        anyhow::ensure!(
            actual.status.success(),
            "skopeo inspect {source}: {}",
            String::from_utf8_lossy(&actual.stderr)
        );
        assert_eq!(actual.stdout, manifest);
    }
    let source = format!("{transport}@{image_id}");
    let destination = format!("oci:{}:test", output.display());
    cmd!(sh, "skopeo copy --preserve-digests {source} {destination}").run()?;
    for bytes in layers {
        let diff = composefs_oci::sha256_content_digest(bytes);
        assert_eq!(
            std::fs::read(output.join("blobs/sha256").join(diff.digest()))?,
            *bytes
        );
    }
    assert_eq!(
        std::fs::read(output.join("blobs/sha256").join(config_digest.digest()))?,
        config
    );
    let layers_path = graph.join("overlay-layers/layers.json");
    let before_roundtrip = std::fs::read(&layers_path)?;
    let roundtrip_source = format!("oci:{}:test", output.display());
    let roundtrip_destination = format!("{transport}localhost/exported:roundtrip");
    cmd!(
        sh,
        "skopeo copy --preserve-digests {roundtrip_source} {roundtrip_destination}"
    )
    .run()?;
    assert_eq!(std::fs::read(&layers_path)?, before_roundtrip);
    assert_eq!(top_layer(graph, image_id)?, top);
    Ok(())
}

fn check_additional_image_store(
    sh: &Shell,
    graph: &Path,
    consumer_graph: &Path,
    consumer_run: &Path,
) -> Result<()> {
    let additional = format!("additionalimagestore={}", graph.display());
    let consumer = podman_store_args(consumer_graph, consumer_run);
    for (operator, path) in [
        ("!", "/removed"),
        ("!", "/opaque/old"),
        ("-f", "/opaque/new"),
        ("-f", "/replace-before"),
        ("!", "/dir-before/old"),
        ("-f", "/dir-before/new"),
        ("-f", "/temporary"),
    ] {
        let args = if operator == "!" {
            vec!["!", "-e", path]
        } else {
            vec![operator, path]
        };
        cmd!(sh, "podman {consumer...} --storage-opt {additional} run --pull=never --rm --network=none --security-opt label=disable localhost/exported:latest {args...}").run()?;
    }
    Ok(())
}

fn check_mapped_layer_preservation(
    sh: &Shell,
    fixture: &ExportFixture,
    graph: &Path,
    run: &Path,
) -> Result<()> {
    let repo_path = &fixture.repo_path;
    let image_id = fixture.image_id.as_str();
    let digest = &fixture.digest;
    let primary = podman_store_args(graph, run);
    let images_path = graph.join("overlay-images/images.json");
    let layers_path = graph.join("overlay-layers/layers.json");
    // Force Go to create a physically shifted variant rather than an ID-mapped
    // mount. Rust must preserve it when republishing the same image.
    let mapped_container = cmd!(sh, "podman {primary...} create --network=none --security-opt label=disable --uidmap 0:100000:65536 --gidmap 0:100000:65536 localhost/exported:latest -f /temporary")
        .env("_CONTAINERS_OVERLAY_DISABLE_IDMAP", "yes")
        .read()?;
    let original_images = std::fs::read(&images_path)?;
    let mut images: Vec<serde_json::Value> = serde_json::from_slice(&original_images)?;
    let image = images
        .iter_mut()
        .find(|image| image["id"] == image_id)
        .unwrap();
    let mapped_top = image["mapped-layers"][0].as_str().unwrap().to_owned();
    let original_layers = std::fs::read(&layers_path)?;
    let records: Vec<serde_json::Value> = serde_json::from_slice(&original_layers)?;
    let mapped = records
        .iter()
        .find(|layer| layer["id"] == mapped_top)
        .unwrap();
    assert!(!mapped["uidmap"].as_array().unwrap().is_empty());
    assert!(!mapped["gidmap"].as_array().unwrap().is_empty());
    assert!(
        graph
            .join("overlay")
            .join(&mapped_top)
            .join("diff1")
            .is_dir()
    );

    // Exercise an image whose primary is mapped, with its canonical top as an
    // alternative. No Go process is active while the test changes the record.
    image["mapped-layers"][0] = image["layer"].clone();
    image["layer"] = mapped_top.clone().into();
    std::fs::write(&images_path, serde_json::to_vec(&images)?)?;
    let mapped_retry = copy_to_storage(repo_path, graph, run, &format!("@{digest}"), &[])?;
    assert_eq!(mapped_retry, image_id);
    assert_eq!(top_layer(graph, image_id)?, mapped_top);
    assert_eq!(std::fs::read(&layers_path)?, original_layers);
    let actual: Vec<serde_json::Value> = serde_json::from_slice(&std::fs::read(&images_path)?)?;
    assert_eq!(actual, images);
    // Restore the original dependency order before Go removes the variants.
    std::fs::write(&images_path, original_images)?;
    cmd!(sh, "podman {primary...} rm {mapped_container}").run()?;
    Ok(())
}

fn check_verbose_reuse(
    sh: &Shell,
    fixture: &ExportFixture,
    graph: &Path,
    run: &Path,
    top: &str,
) -> Result<()> {
    let repo_path = &fixture.repo_path;
    let image_id = fixture.image_id.as_str();
    let digest = &fixture.digest;
    let cfsctl = cfsctl()?;
    let layers_path = graph.join("overlay-layers/layers.json");
    let before_retry = std::fs::read(&layers_path)?;
    let image = format!("@{digest}");
    let progress_id = format!("storage-export:{digest}");
    let retry = cmd!(sh, "{cfsctl} --repo {repo_path} oci copy-to-storage {image} --graphroot {graph} --runroot {run} --verbose")
        .env("RUST_LOG", "off")
        .output()?;
    assert!(retry.status.success());
    assert_eq!(retry.stdout, format!("{image_id}\n").as_bytes());
    assert_eq!(
        String::from_utf8(retry.stderr)?.lines().collect::<Vec<_>>(),
        [
            format!("{progress_id}: starting (total 2)"),
            "Reusing layer 1/2".into(),
            format!("{progress_id}: 1/2"),
            "Reusing layer 2/2".into(),
            format!("{progress_id}: 2/2"),
            "Publishing image to containers/storage".into(),
            format!("{progress_id}: completed 2"),
        ]
    );
    assert_eq!(top_layer(graph, image_id)?, top);
    assert_eq!(std::fs::read(&layers_path)?, before_retry);
    Ok(())
}

fn check_image_removal(
    sh: &Shell,
    graph: &Path,
    run: &Path,
    image_id: &str,
    unrelated: &str,
) -> Result<()> {
    let primary = podman_store_args(graph, run);
    cmd!(sh, "podman {primary...} rmi --force {image_id}").run()?;
    let format = "{{.Id}}";
    let remaining = cmd!(
        sh,
        "podman {primary...} image inspect --format {format} localhost/unrelated:latest"
    )
    .read()?;
    assert_eq!(
        remaining.trim().trim_start_matches("sha256:"),
        unrelated.trim().trim_start_matches("sha256:")
    );
    Ok(())
}

fn check_fresh_store_publish(
    sh: &Shell,
    fixture: &ExportFixture,
    fresh_graph: &Path,
    fresh_run: &Path,
) -> Result<()> {
    let repo_path = &fixture.repo_path;
    let image_id = fixture.image_id.as_str();
    let image = format!("@{}", fixture.digest);
    let progress_id = format!("storage-export:{}", fixture.digest);
    let manifest = fixture.manifest.as_slice();
    let cfsctl = cfsctl()?;
    // Let the CLI initialize and publish before Go first opens this store.
    let fresh = cmd!(sh, "{cfsctl} --repo {repo_path} oci copy-to-storage {image} --graphroot {fresh_graph} --name localhost/fresh:latest --verbose")
        .env("RUST_LOG", "off")
        .output()?;
    assert!(fresh.status.success());
    assert_eq!(fresh.stdout, format!("{image_id}\n").as_bytes());
    assert_eq!(
        String::from_utf8(fresh.stderr)?.lines().collect::<Vec<_>>(),
        [
            format!("{progress_id}: starting (total 2)"),
            "Importing layer 1/2".into(),
            format!("{progress_id}: 1/2"),
            "Importing layer 2/2".into(),
            format!("{progress_id}: 2/2"),
            "Publishing image to containers/storage".into(),
            format!("{progress_id}: completed 2"),
        ]
    );
    assert!(!fresh_run.exists());
    let fresh_source = format!(
        "containers-storage:[overlay@{}+{}]@{}",
        fresh_graph.display(),
        fresh_run.display(),
        image_id
    );
    let raw = cmd!(sh, "skopeo inspect --raw {fresh_source}").output()?;
    assert!(raw.status.success());
    assert_eq!(raw.stdout, manifest);
    let fresh_options = podman_store_args(fresh_graph, fresh_run);
    cmd!(sh, "podman {fresh_options...} run --pull=never --rm --network=none --security-opt label=disable localhost/fresh:latest -f /temporary").run()?;
    Ok(())
}

fn privileged_storage_export_go_consumers() -> Result<()> {
    if require_privileged("privileged_storage_export_go_consumers")?.is_some() {
        return Ok(());
    }
    let sh = Shell::new()?;
    let temp = tempfile::tempdir()?;
    let verity = VerityTempDir::new()?;
    // Native overlay cannot use the VM's virtiofs-backed root as its upper.
    let graph = verity.path().join("graph");
    let run = temp.path().join("run");
    let primary = podman_store_args(&graph, &run);
    let runtime = tokio::runtime::Runtime::new()?;
    cmd!(sh, "podman {primary...} info").ignore_stdout().run()?;
    let fixture = runtime.block_on(create_export_fixture(&sh, &verity.path().join("source")))?;
    let base = temp.path().join("base.tar");
    std::fs::write(&base, &fixture.layers[0])?;
    let unrelated = cmd!(
        sh,
        "podman {primary...} import {base} localhost/unrelated:latest"
    )
    .read()?;
    assert_eq!(
        copy_to_storage(
            &fixture.repo_path,
            &graph,
            &run,
            "export-source",
            &[
                "--name",
                "localhost/exported",
                "--name",
                "localhost/exported:also"
            ],
        )?,
        fixture.image_id
    );
    check_name_reassignment(&sh, &fixture, &graph, &run, &unrelated)?;
    let top = top_layer(&graph, &fixture.image_id)?;
    check_materialized_whiteouts(&graph, &top)?;
    check_skopeo_round_trip(&sh, &fixture, &graph, &run, &temp.path().join("oci"), &top)?;
    check_additional_image_store(
        &sh,
        &graph,
        &verity.path().join("consumer"),
        &temp.path().join("consumer-run"),
    )?;
    check_mapped_layer_preservation(&sh, &fixture, &graph, &run)?;
    check_verbose_reuse(&sh, &fixture, &graph, &run, &top)?;
    check_image_removal(&sh, &graph, &run, &fixture.image_id, &unrelated)?;
    runtime.block_on(check_implicit_directory_ownership(
        &fixture.repo,
        &fixture.repo_path,
        &graph,
        &run,
    ))?;
    runtime.block_on(check_whiteout_default_acls(
        &fixture.repo,
        &fixture.repo_path,
        &graph,
        &run,
    ))?;
    check_fresh_store_publish(
        &sh,
        &fixture,
        &verity.path().join("fresh/graph"),
        &temp.path().join("fresh/run"),
    )?;
    runtime.block_on(check_hardlinks_preserve_source_labels(verity.path()))?;
    check_compressed_layer_reuse(&sh, verity.path())?;
    Ok(())
}
integration_test!(privileged_storage_export_go_consumers);
