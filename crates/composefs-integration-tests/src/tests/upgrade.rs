//! Upgrade tests: a repository written by a released cfsctl must keep
//! working with this one, and stay readable by the release after this one
//! wrote to it (a rollback).
//!
//! Set `CFSCTL_PATH_RELEASE` to a released cfsctl binary to run these
//! tests (they're ignored otherwise); `just test-upgrade` builds the
//! pinned release and runs them.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rand::rngs::Xoshiro256PlusPlus;
use rand::{RngReader, SeedableRng};
use xshell::{Shell, cmd};

use crate::{cfsctl, integration_test};

/// Environment variable naming the released cfsctl binary.
const CFSCTL_PATH_RELEASE: &str = "CFSCTL_PATH_RELEASE";

/// Larger than the inline threshold, so files of this size are stored as
/// external objects.
const LARGE_FILE_SIZE: u64 = 64 * 1024;

/// The content of a large file: a fixed-seed pseudorandom stream, so
/// each image has its own objects and every run the same ones.
fn large_file(seed: u64) -> impl Read {
    RngReader(Xoshiro256PlusPlus::seed_from_u64(seed)).take(LARGE_FILE_SIZE)
}

/// One test image: its OCI layout name, tag and whether it's pulled as
/// bootable.
struct Fixture {
    name: &'static str,
    bootable: bool,
    seed: u64,
}

/// Images the release pulls.
const RELEASE_IMAGES: &[Fixture] = &[
    Fixture {
        name: "plain",
        bootable: false,
        seed: 1,
    },
    Fixture {
        name: "bootable",
        bootable: true,
        seed: 2,
    },
];

/// The image the current cfsctl pulls before rolling back, with layers
/// and objects the release hasn't seen.
const NEW_IMAGE: Fixture = Fixture {
    name: "new",
    bootable: false,
    seed: 3,
};

/// Writes a single-layer OCI layout for `fixture` under `parent`: a small
/// (inline) and a large (external) file, plus the directories a bootable
/// image needs.
fn create_layout(parent: &Path, fixture: &Fixture) -> Result<PathBuf> {
    use cap_std_ext::cap_std;
    use ocidir::oci_spec::image::{
        ConfigBuilder, ImageConfigurationBuilder, Platform, PlatformBuilder, RootFsBuilder,
    };

    const MTIME: u64 = 1234567890;

    let path = parent.join(fixture.name);
    std::fs::create_dir_all(&path)?;
    let dir = cap_std::fs::Dir::open_ambient_dir(&path, cap_std::ambient_authority())?;
    let ocidir = ocidir::OciDir::ensure(dir)?;

    let mut manifest = ocidir.new_empty_manifest()?.build()?;
    let rootfs = RootFsBuilder::default()
        .typ("layers")
        .diff_ids(Vec::<String>::new())
        .build()?;
    let mut config = ImageConfigurationBuilder::default()
        .architecture("amd64")
        .os("linux")
        .rootfs(rootfs)
        .config(ConfigBuilder::default().build()?)
        .build()?;

    let mut layer = ocidir.create_layer(None)?;
    let dirs: &[&str] = if fixture.bootable {
        &["usr/", "boot/", "sysroot/"]
    } else {
        &["usr/"]
    };
    for dir in dirs {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_mtime(MTIME);
        header.set_cksum();
        layer.append_data(&mut header, dir, &[] as &[u8])?;
    }
    let small = format!("small file in {}\n", fixture.name);
    let files: [(&str, u64, Box<dyn Read>); 2] = [
        (
            "usr/small.txt",
            small.len() as u64,
            Box::new(small.as_bytes()),
        ),
        (
            "usr/large.bin",
            LARGE_FILE_SIZE,
            Box::new(large_file(fixture.seed)),
        ),
    ];
    for (name, size, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_mtime(MTIME);
        header.set_cksum();
        layer.append_data(&mut header, name, data)?;
    }
    let layer = layer.into_inner()?.complete()?;
    ocidir.push_layer(&mut manifest, &mut config, layer, "test layer", None);

    let platform: Platform = PlatformBuilder::default()
        .architecture("amd64")
        .os("linux")
        .build()?;
    ocidir.insert_manifest_and_config(manifest, config, None, platform)?;
    Ok(path)
}

/// The (name, manifest digest) pairs of the tagged images, sorted.
fn list_images(sh: &Shell, cfsctl: &Path, repo: &Path) -> Result<Vec<(String, String)>> {
    let output = cmd!(sh, "{cfsctl} --repo {repo} oci images --json").read()?;
    let json: serde_json::Value =
        serde_json::from_str(&output).with_context(|| format!("parsing oci images: {output}"))?;
    let mut images = json["images"]
        .as_array()
        .with_context(|| format!("no images array in: {output}"))?
        .iter()
        .map(|image| {
            let field = |key: &str| {
                image[key]
                    .as_str()
                    .map(String::from)
                    .with_context(|| format!("image without {key}: {image}"))
            };
            Ok((field("name")?, field("manifest_digest")?))
        })
        .collect::<Result<Vec<_>>>()?;
    images.sort();
    Ok(images)
}

/// Asserts that `oci fsck` (which includes the repository-level fsck)
/// finds no problems.
fn assert_fsck_ok(sh: &Shell, cfsctl: &Path, repo: &Path) -> Result<()> {
    let output = cmd!(sh, "{cfsctl} --repo {repo} oci fsck --json").read()?;
    let json: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(
        json["ok"],
        true,
        "{} oci fsck failed: {output}",
        cfsctl.display()
    );
    Ok(())
}

/// What a cfsctl binary reports about one image.
#[derive(Debug, PartialEq)]
struct ImageState {
    dump: String,
    image_id: String,
}

fn image_state(sh: &Shell, cfsctl: &Path, repo: &Path, fixture: &Fixture) -> Result<ImageState> {
    let name = fixture.name;
    let bootable = fixture.bootable.then_some("--bootable");
    Ok(ImageState {
        dump: cmd!(sh, "{cfsctl} --repo {repo} oci dump {name} {bootable...}").read()?,
        image_id: cmd!(
            sh,
            "{cfsctl} --repo {repo} oci compute-id {name} {bootable...}"
        )
        .read()?,
    })
}

/// Asserts that this cfsctl links the image to the EROFS the release
/// generated at pull time, i.e. one with the ID it computes.
fn assert_linked_erofs(sh: &Shell, cfsctl: &Path, repo: &Path, fixture: &Fixture) -> Result<()> {
    let name = fixture.name;
    let output = cmd!(sh, "{cfsctl} --repo {repo} oci inspect {name}").read()?;
    let json: serde_json::Value = serde_json::from_str(&output)?;
    let key = if fixture.bootable {
        "composefs_boot_erofs"
    } else {
        "composefs_erofs"
    };
    let state = image_state(sh, cfsctl, repo, fixture)?;
    assert_eq!(
        json[key].as_str(),
        Some(state.image_id.as_str()),
        "{name}: {key} in oci inspect: {output}"
    );
    Ok(())
}

/// Every file under the repository's objects/ directory, relative to it.
fn list_objects(repo: &Path) -> Result<BTreeSet<PathBuf>> {
    fn walk(dir: &Path, base: &Path, out: &mut BTreeSet<PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, base, out)?;
            } else {
                out.insert(path.strip_prefix(base)?.to_path_buf());
            }
        }
        Ok(())
    }
    let objects = repo.join("objects");
    let mut out = BTreeSet::new();
    walk(&objects, &objects, &mut out)?;
    Ok(out)
}

fn test_upgrade_from_release_repo() -> Result<()> {
    let old = PathBuf::from(
        std::env::var_os(CFSCTL_PATH_RELEASE)
            .with_context(|| format!("{CFSCTL_PATH_RELEASE} is not set"))?,
    );
    let new = cfsctl()?;
    let sh = Shell::new()?;
    let old_version = cmd!(sh, "{old} --version").read()?;
    eprintln!("upgrading from {old_version}");

    let fixture_dir = tempfile::tempdir()?;
    let work_dir = tempfile::tempdir()?;
    let repo = work_dir.path().join("repo");
    let repo = repo.as_path();

    // The release creates the repository with its defaults (which pin
    // e.g. the EROFS format in meta.json) and pulls the images.
    cmd!(sh, "{old} --repo {repo} init --insecure").run()?;
    for fixture in RELEASE_IMAGES {
        let layout = create_layout(fixture_dir.path(), fixture)?;
        let name = fixture.name;
        let bootable = fixture.bootable.then_some("--bootable");
        cmd!(
            sh,
            "{old} --repo {repo} oci pull oci:{layout} {name} {bootable...}"
        )
        .run()?;
    }
    assert_fsck_ok(&sh, &old, repo)?;
    let old_images = list_images(&sh, &old, repo)?;
    let old_states = RELEASE_IMAGES
        .iter()
        .map(|fixture| image_state(&sh, &old, repo, fixture))
        .collect::<Result<Vec<_>>>()?;

    // This cfsctl sees the same images, with the same content and the
    // same image IDs, finds the EROFS images the release generated, and
    // finds the repository consistent (fsck also checks object content).
    let check_upgraded = || -> Result<()> {
        assert_eq!(list_images(&sh, &new, repo)?, old_images);
        for (fixture, old_state) in RELEASE_IMAGES.iter().zip(&old_states) {
            similar_asserts::assert_eq!(
                image_state(&sh, &new, repo, fixture)?,
                *old_state,
                "{} differs from {old_version}",
                fixture.name
            );
            assert_linked_erofs(&sh, &new, repo, fixture)?;
        }
        assert_fsck_ok(&sh, &new, repo)
    };
    check_upgraded()?;

    // gc keeps the same objects as the release's would (pulls leave some
    // garbage behind), and collecting it breaks nothing.
    let gc_result = |cfsctl: &Path, copy: &str| -> Result<BTreeSet<PathBuf>> {
        let copy = work_dir.path().join(copy);
        cmd!(sh, "cp -a {repo} {copy}").run()?;
        cmd!(sh, "{cfsctl} --repo {copy} gc").run()?;
        list_objects(&copy)
    };
    assert_eq!(gc_result(&new, "gc-new")?, gc_result(&old, "gc-old")?);
    cmd!(sh, "{new} --repo {repo} gc").run()?;
    check_upgraded()?;

    // This cfsctl pulls an image with new layers and objects, then the
    // release reads everything back, as after rolling back to it.
    let layout = create_layout(fixture_dir.path(), &NEW_IMAGE)?;
    let name = NEW_IMAGE.name;
    cmd!(sh, "{new} --repo {repo} oci pull oci:{layout} {name}").run()?;
    let new_images = list_images(&sh, &new, repo)?;
    assert_eq!(new_images.len(), old_images.len() + 1);
    assert_eq!(list_images(&sh, &old, repo)?, new_images);
    for fixture in RELEASE_IMAGES.iter().chain([&NEW_IMAGE]) {
        similar_asserts::assert_eq!(
            image_state(&sh, &old, repo, fixture)?,
            image_state(&sh, &new, repo, fixture)?,
            "{old_version} sees {} differently",
            fixture.name
        );
    }
    assert_fsck_ok(&sh, &old, repo)?;

    Ok(())
}
integration_test!(
    test_upgrade_from_release_repo,
    requires_env = CFSCTL_PATH_RELEASE
);
