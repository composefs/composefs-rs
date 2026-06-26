//! EROFS digest stability tests for the OCI → composefs pipeline.

use anyhow::{Result, bail};
use xshell::{Shell, cmd};

use crate::tests::privileged::require_privileged_with_memory;
use crate::{cfsctl, integration_test};

/// A pinned container image for digest stability testing.
struct ContainerImage {
    /// Human-readable label for test output.
    label: &'static str,
    /// Primary OCI image reference — the ghcr.io mirror (docker:// prefix).
    ///
    /// The mirror is populated by the `mirror-fixture-images.yml` workflow after
    /// a PR that adds a new entry to `ci/fixture-images.txt` is merged to main.
    /// During the PR itself the mirror does not exist yet, so the test falls back
    /// to `upstream_ref` when this pull fails.
    image_ref: &'static str,
    /// Upstream OCI image reference used as a fallback when `image_ref` is
    /// unavailable (e.g. a PR that adds a new mirror entry before it has been
    /// pushed).  Should be pinned by digest for reproducibility.
    upstream_ref: &'static str,
    /// Expected composefs image ID without `--bootable` (V2 EROFS).
    expected_id: &'static str,
    /// Expected composefs image ID with `--bootable` (V2 EROFS), or
    /// `None` if the image lacks /sysroot and doesn't support bootable
    /// transformation.
    expected_bootable_id: Option<&'static str>,
    /// Expected composefs image ID without `--bootable` using V1 EROFS writer.
    expected_v1_id: &'static str,
    /// Expected composefs image ID with `--bootable` using V1 EROFS writer, or
    /// `None` if the image lacks /sysroot and doesn't support bootable
    /// transformation.
    expected_v1_bootable_id: Option<&'static str>,
}

// RHEL UBI 10.1, build 1772441712 (amd64).
// Mirrored from registry.access.redhat.com/ubi10/ubi:10.1-1772441712
// via ci/fixture-images.txt.  UBI is a general-purpose container image
// without /sysroot, so `--bootable` is not supported.
const UBI10: ContainerImage = ContainerImage {
    label: "ubi10",
    image_ref: "docker://ghcr.io/composefs/ci-fixture-ubi10:10.1-1772441712",
    upstream_ref: "docker://registry.access.redhat.com/ubi10/ubi:10.1-1772441712",
    expected_id: "ff8dad033a3e6015d63d6b00c16918da27bf96cc8ddd824e521549db01013227\
                  87c30a3f49e5716f8f6052d78b46308dfaaccf0dfc504d26fe58d468810c0b0e",
    expected_bootable_id: None,
    expected_v1_id: "ece359ddb403598b193d856215289f870cb672f5e6e5e1626841a12d648bf9ee\
                     dc337d386ca01bb207ec01f3251a69c598982a173155b723a50c642817d4bdcf",
    expected_v1_bootable_id: None,
};

// centos-bootc stream10, pinned by manifest digest so the test is
// reproducible even if the :stream10 tag moves forward.
// Mirrored from quay.io/centos-bootc/centos-bootc via ci/fixture-images.txt.
// This is the closest to the actual bootc sealed UKI production path.
const CENTOS_BOOTC: ContainerImage = ContainerImage {
    label: "centos-bootc",
    image_ref: "docker://ghcr.io/composefs/ci-fixture-centos-bootc:stream10-d1913e3d",
    upstream_ref: "docker://quay.io/centos-bootc/centos-bootc@sha256:d1913e3d616b9acb7fc2e3331be8baf844048bca2681a23d34e53e75eb18f3d0",
    expected_id: "ad575e0570dfb74cbc837f41715d3fba890dd983d992332eaeee93493ce112ee\
                  50d3dc5f6f2a3214cc92412fe3ae936e2e9c0eac24ea787e83ef13c0a718a193",
    expected_bootable_id: Some(
        "79c840369bf1ef414d71731166967a01f6616039bc0e1d4c5353bed02e0d2bd9\
         4459e22407bb885f1d6ce44a04add35adf0d00ca8a23f90544a99a76fdadb65b",
    ),
    expected_v1_id: "6588e6ad260c57610f7c8cda080a8adc1ed8c0d21d9eb8b7c6cccaa5aa8a564c\
                     727125c6b700da2048480f01b74926e13b48c131d5dda3245f14b80d88a297f9",
    expected_v1_bootable_id: Some(
        "a2beab402884373c4ac3301e370ea93061281e6f13f6556ae6f6bc062ad95fb7\
         07046b325359605fe55654dc3d0f30d6093e1b9afcb602e3b25397c09868dbdd",
    ),
};

// debian-bootc, pinned by manifest list digest.
// Mirrored from ghcr.io/bootcrew/debian-bootc via ci/fixture-images.txt.
// Bootable image used for the cstor/filesystem digest equivalence test.
// Unlike centos-bootc, this image's layers explicitly include directory
// entries with their mtimes, avoiding implicit parent directory creation
// that can cause mtime divergence between the OCI and on-disk paths.
const DEBIAN_BOOTC: ContainerImage = ContainerImage {
    label: "debian-bootc",
    image_ref: "docker://ghcr.io/composefs/ci-fixture-debian-bootc:latest-0c5dcc18",
    upstream_ref: "docker://ghcr.io/bootcrew/debian-bootc@sha256:0c5dcc181868fea93e78454e90a36df6b577be61917467c230bebf105065c995",
    expected_id: "1b3d620895453d8f88af65cb34ad95d1973c81ad7a105fe76c81aff7f26eec71\
                  4b422c032f499d25929f058a163aa1d5ff68ebb6850ada6d7d0b1874ad52f8e7",
    expected_bootable_id: Some(
        "013ed0f7275cb635075107bde6394bc19cf4e09ff1189b283048282d31fa2043\
         875b076e44344b17d38ee7e3ba22557381c1626357edf349b978602970b73d49",
    ),
    expected_v1_id: "48fdfe53e9dc1b600a5920c8ea224e5f442b0fb3109ecb0f9e3bec7e05a80c7f\
                     ad5ed91cd517637e36fb5b544c2f00b4f530ac6ddcbe94e8eb4b51f03452e150",
    expected_v1_bootable_id: Some(
        "e48ed9c8cfe9b3b2bf121c779f7002eab0c332196b01b0b4441ac8de55a36c34\
         b1fd61b040ceb61d434ad69b6ad2dba4df064b6fb1127d6637796c27f86483f1",
    ),
};

// Ubuntu 26.04 (resolute), pinned by manifest digest.
// Mirrored from docker.io/library/ubuntu via ci/fixture-images.txt.
// Ubuntu 26.04 uses umoci/PAX format tars produced by Rockcraft, which emit
// GNU-style record padding after the end-of-archive blocks.  This exercises
// the trailing-padding preservation fix in split_async() — without it the
// reconstructed tar is shorter than the original and the diff_id checksum
// fails in the @digest code path of create_filesystem().
const UBUNTU_RESOLUTE: ContainerImage = ContainerImage {
    label: "ubuntu-resolute",
    image_ref: "docker://ghcr.io/composefs/ci-fixture-ubuntu-resolute:26.04-d31acef2",
    upstream_ref: "docker://docker.io/library/ubuntu@sha256:d31acef2a964b6df1f2b7e20a1525c4f2378024e087a4f8a8a9a4247e6a79573",
    expected_id: "150caabb982d7005db1a1d0480d57a95e84b160aa2b1159f9aae66e92ba07b36\
                  11ea38e1836eff923dc3a1a617c18494757be0f5e3db16cc7a522981b3f42d40",
    expected_bootable_id: None,
    expected_v1_id: "595ada47acc169edb079f4d25efeee7d0212d53cbc1b9e723e9eee9043dcb2e1\
                     0d9c6cdd7ec7f369cfad9e72db3c0dc1de7cbdbbdfbe12b23edc8650dcba03e7",
    expected_v1_bootable_id: None,
};

/// All container images to test.
const CONTAINER_IMAGES: &[&ContainerImage] =
    &[&UBI10, &CENTOS_BOOTC, &DEBIAN_BOOTC, &UBUNTU_RESOLUTE];

/// Return `true` if network tests should be skipped.
fn skip_network() -> bool {
    std::env::var_os("COMPOSEFS_SKIP_NETWORK").is_some()
}

/// Pull an OCI image and return the config digest from the pull output.
///
/// Tries `image.image_ref` (the ghcr.io mirror) first.  If that fails —
/// which is expected for PRs that add a new mirror entry before it has been
/// pushed — falls back to `image.upstream_ref` with a warning.
fn pull_image(
    sh: &Shell,
    cfsctl: &std::path::Path,
    repo: &std::path::Path,
    image: &ContainerImage,
    name: &str,
) -> Result<String> {
    let candidates = [(image.image_ref, false), (image.upstream_ref, true)];
    let mut last_err = None;
    for (image_ref, is_fallback) in candidates {
        if is_fallback {
            eprintln!(
                "WARNING: mirror pull failed for {}; falling back to upstream {image_ref}",
                image.label,
            );
        }
        match try_pull_image(sh, cfsctl, repo, image_ref, name) {
            Ok(config) => return Ok(config),
            Err(e) => {
                eprintln!("Pull of {image_ref} failed: {e:#}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap())
}

fn try_pull_image(
    sh: &Shell,
    cfsctl: &std::path::Path,
    repo: &std::path::Path,
    image_ref: &str,
    name: &str,
) -> Result<String> {
    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull {image_ref} {name}"
    )
    .read()?;

    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("config") {
            return Ok(rest.trim().to_string());
        }
    }
    bail!("could not find config digest in pull output:\n{output}")
}

/// Compute the composefs image ID for a pulled OCI image (V2 EROFS, via repo default).
///
/// The `config_digest` should be a bare OCI digest (e.g. `sha256:abc...`);
/// this function adds the `@` prefix required by the CLI.
fn compute_id(
    sh: &Shell,
    cfsctl: &std::path::Path,
    repo: &std::path::Path,
    config_digest: &str,
    bootable: bool,
) -> Result<String> {
    let at_digest = format!("@{config_digest}");
    let output = if bootable {
        cmd!(
            sh,
            "{cfsctl} --insecure --repo {repo} oci compute-id --bootable {at_digest}"
        )
        .read()?
    } else {
        cmd!(
            sh,
            "{cfsctl} --insecure --repo {repo} oci compute-id {at_digest}"
        )
        .read()?
    };
    Ok(output.trim().to_string())
}

/// Compute the composefs image ID using the V1 EROFS writer.
///
/// `--erofs-version 1` is a global flag and must appear before the subcommand.
fn compute_id_v1(
    sh: &Shell,
    cfsctl: &std::path::Path,
    repo: &std::path::Path,
    config_digest: &str,
    bootable: bool,
) -> Result<String> {
    let at_digest = format!("@{config_digest}");
    let output = if bootable {
        cmd!(
            sh,
            "{cfsctl} --insecure --erofs-version 1 --repo {repo} oci compute-id --bootable {at_digest}"
        )
        .read()?
    } else {
        cmd!(
            sh,
            "{cfsctl} --insecure --erofs-version 1 --repo {repo} oci compute-id {at_digest}"
        )
        .read()?
    };
    Ok(output.trim().to_string())
}

/// Table-driven OCI container digest stability test.
///
/// Pulls each pinned container image from a registry, computes the composefs
/// image ID for both plain and `--bootable` transforms using both V1 and V2
/// EROFS writers explicitly, and asserts they match the expected values.
///
/// Skipped when `COMPOSEFS_SKIP_NETWORK=1` is set.
fn test_oci_container_digest_stability() -> Result<()> {
    if skip_network() {
        eprintln!("Skipping (COMPOSEFS_SKIP_NETWORK is set)");
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;

    for image in CONTAINER_IMAGES {
        eprintln!("--- {} ---", image.label);
        let repo_dir = tempfile::tempdir()?;
        let repo = repo_dir.path();
        // Use V2 explicitly: compute_id() tests V2 hashes; V1 is
        // tested separately via compute_id_v1() with --erofs-version 1.
        cmd!(
            sh,
            "{cfsctl} --repo {repo} init --insecure --erofs-version 2"
        )
        .read()?;

        eprintln!("Pulling {} (this may take a while)...", image.label);
        let config = pull_image(&sh, &cfsctl, repo, image, image.label)?;

        // V2: plain image ID
        let plain_id = compute_id(&sh, &cfsctl, repo, &config, false)?;
        eprintln!("{} composefs V2 image ID: {plain_id}", image.label);
        assert_eq!(
            plain_id, image.expected_id,
            "{}: composefs image ID changed — the EROFS V2 writer or OCI \
             pipeline produced different output for the same image",
            image.label,
        );

        // V2: bootable image ID (only for images that support it)
        if let Some(expected_bootable) = image.expected_bootable_id {
            let bootable_id = compute_id(&sh, &cfsctl, repo, &config, true)?;
            eprintln!(
                "{} composefs V2 image ID (bootable): {bootable_id}",
                image.label
            );
            assert_eq!(
                bootable_id, expected_bootable,
                "{}: bootable composefs image ID changed — the EROFS V2 writer or \
                 boot transform produced different output for the same image",
                image.label,
            );

            assert_ne!(
                plain_id, bootable_id,
                "{}: plain and --bootable image IDs should differ \
                 (bootable applies SELinux relabeling, empties /boot and /sysroot)",
                image.label,
            );
        }

        // V1: plain image ID
        let v1_plain_id = compute_id_v1(&sh, &cfsctl, repo, &config, false)?;
        eprintln!("{} composefs V1 image ID: {v1_plain_id}", image.label);
        assert_eq!(
            v1_plain_id, image.expected_v1_id,
            "{}: composefs V1 image ID changed — the EROFS V1 writer or OCI \
             pipeline produced different output for the same image",
            image.label,
        );

        // V1 and V2 must produce different digests for the same image.
        assert_ne!(
            v1_plain_id, plain_id,
            "{}: V1 and V2 EROFS image IDs should differ",
            image.label,
        );

        // V1: bootable image ID (only for images that support it)
        if let Some(expected_v1_bootable) = image.expected_v1_bootable_id {
            let v1_bootable_id = compute_id_v1(&sh, &cfsctl, repo, &config, true)?;
            eprintln!(
                "{} composefs V1 image ID (bootable): {v1_bootable_id}",
                image.label
            );
            assert_eq!(
                v1_bootable_id, expected_v1_bootable,
                "{}: bootable composefs V1 image ID changed — the EROFS V1 writer or \
                 boot transform produced different output for the same image",
                image.label,
            );

            assert_ne!(
                v1_plain_id, v1_bootable_id,
                "{}: plain and --bootable V1 image IDs should differ \
                 (bootable applies SELinux relabeling, empties /boot and /sysroot)",
                image.label,
            );
        }
    }

    Ok(())
}
integration_test!(test_oci_container_digest_stability);

/// Expand /var tmpfs to ~80% of RAM.  In bcvk VMs /var is a small tmpfs;
/// this gives podman room to unpack image layers.
fn try_expand_var(sh: &Shell) {
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo")
        && let Some(kb) = meminfo
            .lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u64>().ok())
    {
        let size = format!("{}k", kb * 80 / 100);
        let _ = cmd!(sh, "mount -o remount,size={size} /var")
            .ignore_status()
            .quiet()
            .run();
    }
}

/// Verify that the bootable EROFS digest of a pinned image is identical
/// across all three computation paths, for both V1 and V2 formats:
///
/// 1. **OCI registry** — verified by `test_oci_container_digest_stability`,
///    which pins the expected value in each image's `expected_bootable_id`
/// 2. **containers-storage** — tar-split reconstruction from podman storage
/// 3. **on-disk filesystem** — `cfsctl compute-id --bootable <mountpoint>`
///
/// Path 2 is the bootc *import* path; path 3 is the bootc *verification*
/// path (via `read_container_root` / `compute_composefs_digest`).
///
/// On digest mismatch, captures dumpfiles from both paths and emits a
/// unified diff to help identify the divergent entries.
fn check_digest_equivalence(image: &ContainerImage) -> Result<()> {
    let expected_v2 = image
        .expected_bootable_id
        .expect("image must have expected_bootable_id for equivalence test");
    let expected_v1 = image
        .expected_v1_bootable_id
        .expect("image must have expected_v1_bootable_id for equivalence test");

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    try_expand_var(&sh);

    // Pull into podman.  Strip "docker://" for containers-storage refs.
    let image_ref = image.upstream_ref;
    let bare_ref = image_ref.strip_prefix("docker://").unwrap_or(image_ref);
    eprintln!("Pulling {} into podman...", image.label);
    cmd!(sh, "podman pull {image_ref}").run()?;

    // Mount the container for the on-disk filesystem path.
    let cid = cmd!(sh, "podman create {image_ref} /bin/true").read()?;
    let cid = cid.trim();
    let mountpoint = cmd!(sh, "podman mount {cid}").read()?;
    let mountpoint = mountpoint.trim();

    // Test both V1 and V2 explicitly.
    for (version, expected) in [("1", expected_v1), ("2", expected_v2)] {
        eprintln!("  --- V{version} ---");

        let repo_dir = tempfile::tempdir()?;
        let repo = repo_dir.path();
        cmd!(
            sh,
            "{cfsctl} --insecure --repo {repo} init --erofs-version {version}"
        )
        .read()?;

        let cstor_ref = format!("containers-storage:{bare_ref}");
        eprintln!("  Importing via containers-storage (V{version})...");
        let pull_out = cmd!(
            sh,
            "{cfsctl} --insecure --repo {repo} oci pull --local-fetch auto {cstor_ref}"
        )
        .read()?;

        let config = pull_out
            .lines()
            .find_map(|l| l.strip_prefix("config").map(|r| r.trim().to_string()))
            .ok_or_else(|| {
                anyhow::anyhow!("{}: no config in cstor output:\n{pull_out}", image.label)
            })?;

        let cstor_digest = compute_id(&sh, &cfsctl, repo, &config, true)?;
        eprintln!("  containers-storage V{version}: {cstor_digest}");

        let fs_digest = cmd!(
            sh,
            "{cfsctl} --insecure --erofs-version {version} --repo {repo} compute-id --bootable {mountpoint}"
        )
        .read()
        .map(|s| s.trim().to_string());

        // If digests mismatch, capture dumpfiles *before* unmounting.
        let mismatch = match &fs_digest {
            Ok(d) => d != &cstor_digest,
            Err(_) => true,
        };

        let diff_output = if mismatch {
            eprintln!("  MISMATCH detected — capturing dumpfiles for diff...");

            let at_config = format!("@{config}");
            let cstor_dump = cmd!(
                sh,
                "{cfsctl} --insecure --repo {repo} oci dump --bootable {at_config}"
            )
            .read()
            .unwrap_or_else(|e| format!("(failed to dump cstor: {e})"));

            let fs_dump = cmd!(
                sh,
                "{cfsctl} --no-repo create-dumpfile --bootable {mountpoint}"
            )
            .read()
            .unwrap_or_else(|e| format!("(failed to dump on-disk: {e})"));

            let cstor_path = std::env::temp_dir().join("cstor.dumpfile");
            let fs_path = std::env::temp_dir().join("fs.dumpfile");
            std::fs::write(&cstor_path, &cstor_dump)?;
            std::fs::write(&fs_path, &fs_dump)?;

            let diff = cmd!(sh, "diff -u {cstor_path} {fs_path}")
                .ignore_status()
                .read()
                .unwrap_or_else(|e| format!("(diff failed: {e})"));

            Some(diff)
        } else {
            None
        };

        let fs_digest = fs_digest?;
        eprintln!("  on-disk filesystem V{version}: {fs_digest}");

        if let Some(ref diff) = diff_output {
            eprintln!(
                "\n=== V{version} dumpfile diff (containers-storage vs on-disk) ===\n\
                 {diff}\n=== end diff ===\n"
            );
        }

        if cstor_digest != expected || fs_digest != expected {
            // Clean up before bailing.
            cmd!(sh, "podman umount {cid}").ignore_status().run()?;
            cmd!(sh, "podman rm -f {cid}").ignore_status().run()?;
            bail!(
                "{label} V{version}: digest mismatch!\n\
                 \x20  expected (pinned): {expected}\n\
                 \x20  containers-storage: {cstor_digest}\n\
                 \x20  on-disk filesystem: {fs_digest}",
                label = image.label,
            );
        }

        eprintln!("  OK V{version}: all three paths match: {expected}");
    }

    cmd!(sh, "podman umount {cid}").ignore_status().run()?;
    cmd!(sh, "podman rm -f {cid}").ignore_status().run()?;

    Ok(())
}

fn privileged_test_digest_equivalence_debian_bootc() -> Result<()> {
    if skip_network() {
        eprintln!("Skipping (COMPOSEFS_SKIP_NETWORK is set)");
        return Ok(());
    }
    if require_privileged_with_memory("privileged_test_digest_equivalence_debian_bootc", "10G")?
        .is_some()
    {
        return Ok(());
    }
    check_digest_equivalence(&DEBIAN_BOOTC)
}
integration_test!(privileged_test_digest_equivalence_debian_bootc);

/// centos-bootc currently fails the on-disk filesystem path due to
/// directory mtime divergence: some layers create files without explicit
/// directory entries, so parent directory mtimes differ between the OCI
/// metadata reconstruction and the on-disk extraction.
///
/// Tracked in: <https://github.com/containers/composefs-rs/issues/132>
fn privileged_test_digest_equivalence_centos_bootc() -> Result<()> {
    if skip_network() {
        eprintln!("Skipping (COMPOSEFS_SKIP_NETWORK is set)");
        return Ok(());
    }
    if require_privileged_with_memory("privileged_test_digest_equivalence_centos_bootc", "10G")?
        .is_some()
    {
        return Ok(());
    }
    eprintln!(
        "SKIP: centos-bootc has dir mtime divergence between OCI and on-disk paths \
         (https://github.com/containers/composefs-rs/issues/132)"
    );
    Ok(())
}
integration_test!(privileged_test_digest_equivalence_centos_bootc);
