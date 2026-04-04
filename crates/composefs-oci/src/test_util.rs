/// Shared test utilities for composefs-oci.
///
/// Provides helpers to build multi-layer OCI images from composefs dumpfile
/// strings, so that `transform_for_boot` actually extracts boot entries and
/// produces a filesystem different from the raw OCI one.
///
/// Each layer is a `&str` in standard composefs dumpfile format:
///
/// ```text
/// /path size mode nlink uid gid rdev mtime payload content digest
/// ```
///
/// For example:
///
/// ```text
/// /usr/bin 0 40755 2 0 0 0 0.0 - - -
/// /usr/bin/hello 5 100644 1 0 0 0 0.0 - world -
/// /usr/bin/sh 0 120777 1 0 0 0 0.0 busybox - -
/// ```
use std::collections::HashMap;
use std::io::Read as _;
use std::sync::Arc;

use crate::oci_image::write_manifest;
use crate::skopeo::OCI_CONFIG_CONTENT_TYPE;
use composefs::dumpfile_parse::{Entry, Item};
use composefs::fsverity::Sha256HashValue;
use composefs::repository::Repository;
use containers_image_proxy::oci_spec::image::{
    ConfigBuilder, DescriptorBuilder, Digest as OciDigest, ImageConfigurationBuilder,
    ImageManifestBuilder, MediaType, RootFsBuilder,
};
use rustix::fs::FileType;
use sha2::{Digest, Sha256};

fn hash(bytes: &[u8]) -> OciDigest {
    let mut context = Sha256::new();
    context.update(bytes);
    format!("sha256:{}", hex::encode(context.finalize()))
        .parse()
        .unwrap()
}

/// Convert composefs dumpfile lines into tar bytes.
///
/// Parses each line as a composefs [`Entry`] and builds the corresponding
/// tar entry.  The root directory (`/`) is skipped since tar archives don't
/// include it.  Only regular files (inline), directories, and symlinks are
/// supported — this is sufficient for test images.
fn dumpfile_to_tar(dumpfile: &str) -> Vec<u8> {
    let mut builder = ::tar::Builder::new(vec![]);

    for line in dumpfile.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let entry =
            Entry::parse(line).unwrap_or_else(|e| panic!("bad dumpfile line {line:?}: {e}"));

        // Skip the root directory — tar doesn't need it
        if entry.path.as_ref() == std::path::Path::new("/") {
            continue;
        }

        // Strip leading / for tar paths
        let path = entry
            .path
            .to_str()
            .expect("non-UTF8 path")
            .trim_start_matches('/');

        let ty = FileType::from_raw_mode(entry.mode);
        match ty {
            FileType::Directory => {
                let mut header = ::tar::Header::new_ustar();
                header.set_uid(entry.uid.into());
                header.set_gid(entry.gid.into());
                header.set_mode(entry.mode & 0o7777);
                header.set_entry_type(::tar::EntryType::Directory);
                header.set_size(0);
                builder
                    .append_data(&mut header, path, std::io::empty())
                    .unwrap();
            }
            FileType::RegularFile => match &entry.item {
                Item::RegularInline { content, .. } => {
                    let mut header = ::tar::Header::new_ustar();
                    header.set_uid(entry.uid.into());
                    header.set_gid(entry.gid.into());
                    header.set_mode(entry.mode & 0o7777);
                    header.set_entry_type(::tar::EntryType::Regular);
                    header.set_size(content.len() as u64);
                    builder
                        .append_data(&mut header, path, &content[..])
                        .unwrap();
                }
                Item::Regular { size, .. } => {
                    // External file with no inline content — create sized entry
                    let mut header = ::tar::Header::new_ustar();
                    header.set_uid(entry.uid.into());
                    header.set_gid(entry.gid.into());
                    header.set_mode(entry.mode & 0o7777);
                    header.set_entry_type(::tar::EntryType::Regular);
                    header.set_size(*size);
                    builder
                        .append_data(&mut header, path, std::io::repeat(0u8).take(*size))
                        .unwrap();
                }
                other => panic!("unexpected regular file item variant: {other:?}"),
            },
            FileType::Symlink => {
                let target = match &entry.item {
                    Item::Symlink { target, .. } => target,
                    other => panic!("expected Symlink item, got {other:?}"),
                };
                let mut header = ::tar::Header::new_ustar();
                header.set_uid(entry.uid.into());
                header.set_gid(entry.gid.into());
                header.set_mode(entry.mode & 0o7777);
                header.set_entry_type(::tar::EntryType::Symlink);
                header.set_size(0);
                header
                    .set_link_name(target.as_ref())
                    .expect("failed to set symlink target");
                builder
                    .append_data(&mut header, path, std::io::empty())
                    .unwrap();
            }
            other => panic!("unsupported file type in test dumpfile: {other:?}"),
        }
    }

    builder.into_inner().unwrap()
}

/// Return value from image creation helpers.
#[allow(dead_code)]
pub struct TestImage {
    pub manifest_digest: OciDigest,
    pub manifest_verity: Sha256HashValue,
    pub config_digest: OciDigest,
}

/// Create an OCI image from multiple layers, each described in composefs
/// dumpfile format.
///
/// For each layer: parses the dumpfile, builds tar bytes, imports via
/// [`import_layer`](crate::import_layer), then assembles a proper OCI
/// config and manifest referencing all layers in order.
async fn create_multi_layer_image(
    repo: &Arc<Repository<Sha256HashValue>>,
    tag: Option<&str>,
    layers: &[&str],
) -> TestImage {
    let mut layer_digests = Vec::new();
    let mut layer_verities_map: HashMap<Box<str>, Sha256HashValue> = HashMap::new();
    let mut layer_descriptors = Vec::new();

    for dumpfile in layers {
        let tar_data = dumpfile_to_tar(dumpfile);
        let digest = hash(&tar_data);

        let (verity, _stats) = crate::import_layer(repo, &digest, None, &tar_data[..])
            .await
            .unwrap();

        let descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayerGzip)
            .digest(digest.clone())
            .size(tar_data.len() as u64)
            .build()
            .unwrap();

        layer_verities_map.insert(digest.to_string().into_boxed_str(), verity);
        layer_digests.push(digest.to_string());
        layer_descriptors.push(descriptor);
    }

    // Build OCI config
    let rootfs = RootFsBuilder::default()
        .typ("layers")
        .diff_ids(layer_digests.clone())
        .build()
        .unwrap();

    let cfg = ConfigBuilder::default().build().unwrap();

    let config = ImageConfigurationBuilder::default()
        .architecture("amd64")
        .os("linux")
        .rootfs(rootfs)
        .config(cfg)
        .build()
        .unwrap();

    let config_json = config.to_string().unwrap();
    let config_digest = hash(config_json.as_bytes());

    let mut config_stream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE).unwrap();
    for (digest, verity) in &layer_verities_map {
        config_stream.add_named_stream_ref(digest, verity);
    }
    config_stream
        .write_external(config_json.as_bytes())
        .unwrap();
    let config_verity = repo
        .write_stream(
            config_stream,
            &crate::config_identifier(&config_digest),
            None,
        )
        .unwrap();

    // Build OCI manifest
    let config_descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageConfig)
        .digest(config_digest.clone())
        .size(config_json.len() as u64)
        .build()
        .unwrap();

    let manifest = ImageManifestBuilder::default()
        .schema_version(2u32)
        .media_type(MediaType::ImageManifest)
        .config(config_descriptor)
        .layers(layer_descriptors)
        .build()
        .unwrap();

    let manifest_json = manifest.to_string().unwrap();
    let manifest_digest = hash(manifest_json.as_bytes());

    let (_stored_digest, manifest_verity) = write_manifest(
        repo,
        &manifest,
        &manifest_digest,
        &config_verity,
        &layer_verities_map,
        tag,
    )
    .unwrap();

    TestImage {
        manifest_digest,
        manifest_verity,
        config_digest,
    }
}

// ---------------------------------------------------------------------------
// Layer definitions in composefs dumpfile format
//
// Format: /path size mode nlink uid gid rdev mtime payload content digest
//
// Directories:  /path 0 40755 2 0 0 0 0.0 - - -
// Inline files: /path <len> 100644 1 0 0 0 0.0 - <content> -
// Executables:  /path <len> 100755 1 0 0 0 0.0 - <content> -
// Symlinks:     /path <targetlen> 120777 1 0 0 0 0.0 <target> - -
// ---------------------------------------------------------------------------

const LAYER_ROOT_STRUCTURE: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/bin 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/share 0 40755 2 0 0 0 0.0 - - -
/etc 0 40755 2 0 0 0 0.0 - - -
/var 0 40755 2 0 0 0 0.0 - - -
/tmp 0 40755 2 0 0 0 0.0 - - -
";

const LAYER_BUSYBOX: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/bin 0 40755 2 0 0 0 0.0 - - -
/usr/bin/busybox 22 100755 1 0 0 0 0.0 - busybox-binary-content -
/usr/bin/sh 7 120777 1 0 0 0 0.0 busybox - -
";

const LAYER_CORE_UTILS: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/bin 0 40755 2 0 0 0 0.0 - - -
/usr/bin/ls 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/cat 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/cp 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/mv 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/rm 7 120777 1 0 0 0 0.0 busybox - -
";

const LAYER_CONFIG: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/etc 0 40755 2 0 0 0 0.0 - - -
/etc/os-release 26 100644 1 0 0 0 0.0 - ID=test\\nVERSION_ID=1.0\\n -
/etc/hostname 9 100644 1 0 0 0 0.0 - testhost\\n -
/etc/passwd 36 100644 1 0 0 0 0.0 - root:x:0:0:root:/root:/usr/bin/sh\\n -
";

const LAYER_APP: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/share 0 40755 2 0 0 0 0.0 - - -
/usr/share/myapp 0 40755 2 0 0 0 0.0 - - -
/usr/share/myapp/data.txt 16 100644 1 0 0 0 0.0 - application-data -
/usr/bin 0 40755 2 0 0 0 0.0 - - -
/usr/bin/myapp 26 100755 1 0 0 0 0.0 - #!/usr/bin/sh\\necho\\x20hello\\n -
";

const LAYER_BOOT_DIRS: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/boot 0 40755 2 0 0 0 0.0 - - -
/boot/EFI 0 40755 2 0 0 0 0.0 - - -
/boot/EFI/Linux 0 40755 2 0 0 0 0.0 - - -
/sysroot 0 40755 2 0 0 0 0.0 - - -
";

const LAYER_KERNEL_MODULES_DIR: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.1.0 0 40755 2 0 0 0 0.0 - - -
";

// Version-specific boot layers.  v1 and v2 share userspace (layers 1-5
// and 14-20) but ship different kernels, initramfs, modules, and UKIs.
// This exercises shared-object deduplication in the repo and ensures GC
// correctly handles content referenced by multiple images.

const LAYER_KERNEL_V1: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.1.0 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.1.0/vmlinuz 28 100755 1 0 0 0 0.0 - fake-kernel-6.1.0-image-v1 -
";

const LAYER_KERNEL_V2: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.2.0 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.2.0/vmlinuz 28 100755 1 0 0 0 0.0 - fake-kernel-6.2.0-image-v2 -
";

const LAYER_INITRAMFS_V1: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.1.0 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.1.0/initramfs.img 24 100644 1 0 0 0 0.0 - fake-initramfs-6.1.0-v1 -
";

const LAYER_INITRAMFS_V2: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.2.0 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.2.0/initramfs.img 24 100644 1 0 0 0 0.0 - fake-initramfs-6.2.0-v2 -
";

const LAYER_KERNEL_MODULES_V1: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.1.0 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.1.0/modules.dep 14 100644 1 0 0 0 0.0 - kmod-deps-v1\\n -
/usr/lib/modules/6.1.0/modules.alias 16 100644 1 0 0 0 0.0 - kmod-aliases-v1\\n -
";

const LAYER_KERNEL_MODULES_V2: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.2.0 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules/6.2.0/modules.dep 14 100644 1 0 0 0 0.0 - kmod-deps-v2\\n -
/usr/lib/modules/6.2.0/modules.alias 16 100644 1 0 0 0 0.0 - kmod-aliases-v2\\n -
";

const LAYER_UKI_V1: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/boot 0 40755 2 0 0 0 0.0 - - -
/boot/EFI 0 40755 2 0 0 0 0.0 - - -
/boot/EFI/Linux 0 40755 2 0 0 0 0.0 - - -
/boot/EFI/Linux/test-6.1.0.efi 21 100755 1 0 0 0 0.0 - MZ-fake-uki-6.1.0-v1 -
";

const LAYER_UKI_V2: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/boot 0 40755 2 0 0 0 0.0 - - -
/boot/EFI 0 40755 2 0 0 0 0.0 - - -
/boot/EFI/Linux 0 40755 2 0 0 0 0.0 - - -
/boot/EFI/Linux/test-6.2.0.efi 21 100755 1 0 0 0 0.0 - MZ-fake-uki-6.2.0-v2 -
";

const LAYER_SYSTEMD: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/systemd 0 40755 2 0 0 0 0.0 - - -
/usr/lib/systemd/system 0 40755 2 0 0 0 0.0 - - -
/usr/lib/systemd/system/multi-user.target 0 100644 1 0 0 0 0.0 - - -
";

const LAYER_SYSROOT_MARKER: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/sysroot 0 40755 2 0 0 0 0.0 - - -
/sysroot/.ostree-root 0 100644 1 0 0 0 0.0 - - -
";

const LAYER_LIBS_1: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/libc.so.6 16 100644 1 0 0 0 0.0 - fake-libc-content -
/usr/lib/libm.so.6 16 100644 1 0 0 0 0.0 - fake-libm-content -
";

const LAYER_LIBS_2: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/libpthread.so.0 22 100644 1 0 0 0 0.0 - fake-libpthread-content -
/usr/lib/libdl.so.2 16 100644 1 0 0 0 0.0 - fake-libdl-content -
";

const LAYER_LOCALE: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/share 0 40755 2 0 0 0 0.0 - - -
/usr/share/locale 0 40755 2 0 0 0 0.0 - - -
/usr/share/locale/en_US 0 40755 2 0 0 0 0.0 - - -
/usr/share/locale/en_US/LC_MESSAGES 0 40755 2 0 0 0 0.0 - - -
/usr/share/locale/en_US/LC_MESSAGES/messages 11 100644 1 0 0 0 0.0 - fake-locale -
";

const LAYER_DOCS: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/share 0 40755 2 0 0 0 0.0 - - -
/usr/share/doc 0 40755 2 0 0 0 0.0 - - -
/usr/share/doc/readme.txt 21 100644 1 0 0 0 0.0 - documentation-content -
";

const LAYER_NSS_CONFIG: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/etc 0 40755 2 0 0 0 0.0 - - -
/etc/nsswitch.conf 27 100644 1 0 0 0 0.0 - passwd:files\\ngroup:files\\n -
/etc/resolv.conf 22 100644 1 0 0 0 0.0 - nameserver\\x20127.0.0.53\\n -
";

const LAYER_ZONEINFO: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/share 0 40755 2 0 0 0 0.0 - - -
/usr/share/zoneinfo 0 40755 2 0 0 0 0.0 - - -
/usr/share/zoneinfo/UTC 12 100644 1 0 0 0 0.0 - fake-tz-data -
";

const LAYER_VAR_LOG: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/var 0 40755 2 0 0 0 0.0 - - -
/var/log 0 40755 2 0 0 0 0.0 - - -
/var/log/.keepdir 0 100644 1 0 0 0 0.0 - - -
";

/// Base image layers: a busybox-like app image (5 layers).
const BASE_LAYERS: &[&str] = &[
    LAYER_ROOT_STRUCTURE,
    LAYER_BUSYBOX,
    LAYER_CORE_UTILS,
    LAYER_CONFIG,
    LAYER_APP,
];

/// Shared userspace layers used by all bootable image versions.
/// These are identical across v1/v2, so the repo deduplicates them.
const SHARED_SYSTEM_LAYERS: &[&str] = &[
    LAYER_SYSTEMD,
    LAYER_SYSROOT_MARKER,
    LAYER_LIBS_1,
    LAYER_LIBS_2,
    LAYER_LOCALE,
    LAYER_DOCS,
    LAYER_NSS_CONFIG,
    LAYER_ZONEINFO,
    LAYER_VAR_LOG,
];

/// Build the full layer list for a bootable image at the given version.
fn bootable_layers(version: u32) -> Vec<&'static str> {
    let (kernel, initramfs, modules, uki) = match version {
        1 => (
            LAYER_KERNEL_V1,
            LAYER_INITRAMFS_V1,
            LAYER_KERNEL_MODULES_V1,
            LAYER_UKI_V1,
        ),
        2 => (
            LAYER_KERNEL_V2,
            LAYER_INITRAMFS_V2,
            LAYER_KERNEL_MODULES_V2,
            LAYER_UKI_V2,
        ),
        _ => panic!("unsupported test image version: {version}"),
    };

    let mut layers = Vec::with_capacity(20);
    // Layers 1-5: base userspace (shared across versions)
    layers.extend_from_slice(BASE_LAYERS);
    // Layers 6-7: boot directory structure (shared)
    layers.push(LAYER_BOOT_DIRS);
    layers.push(LAYER_KERNEL_MODULES_DIR);
    // Layers 8-11: version-specific boot content
    layers.push(kernel);
    layers.push(initramfs);
    layers.push(modules);
    layers.push(uki);
    // Layers 12-20: shared system content
    layers.extend_from_slice(SHARED_SYSTEM_LAYERS);
    layers
}

/// Create a base (non-bootable) test OCI image with 5 layers.
///
/// Layers contain a busybox-like userspace: root directory structure, busybox
/// binary with shell symlink, core utility symlinks, configuration files, and
/// a small application.
pub async fn create_base_image(
    repo: &Arc<Repository<Sha256HashValue>>,
    tag: Option<&str>,
) -> TestImage {
    create_multi_layer_image(repo, tag, BASE_LAYERS).await
}

/// Create a bootable test OCI image with 20 layers.
///
/// `version` controls the kernel/initramfs/UKI content:
///   - v1: kernel 6.1.0, UKI test-6.1.0.efi
///   - v2: kernel 6.2.0, UKI test-6.2.0.efi
///
/// Userspace layers (busybox, libs, systemd, configs) are identical across
/// versions — when both v1 and v2 are pulled into the same repo, the shared
/// layers are deduplicated.  This exercises GC correctness with content
/// referenced by multiple images.
pub async fn create_bootable_image(
    repo: &Arc<Repository<Sha256HashValue>>,
    tag: Option<&str>,
    version: u32,
) -> TestImage {
    let layers = bootable_layers(version);
    create_multi_layer_image(repo, tag, &layers).await
}

/// Create a base test OCI image in a repository at the given path.
///
/// This is a convenience wrapper for integration tests that work with repo
/// paths rather than `Repository` handles. Opens the repo, creates the
/// image with `create_base_image`, generates the EROFS, and returns.
pub fn create_test_oci_image(repo_path: &std::path::Path, tag: &str) -> anyhow::Result<()> {
    let (mut repo, _) = Repository::<Sha256HashValue>::init_path(
        rustix::fs::CWD,
        repo_path,
        composefs::fsverity::Algorithm::SHA256,
        false,
    )?;
    repo.set_insecure();
    let repo = Arc::new(repo);
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(create_base_image(&repo, Some(tag)));
    ensure_erofs_for_image(&repo, tag)?;
    Ok(())
}

/// Create a bootable test OCI image in a repository at the given path.
///
/// Like [`create_test_oci_image`] but builds a 20-layer bootable image
/// (version 1) and generates both the plain EROFS and the boot EROFS.
/// Requires the `boot` feature.
#[cfg(feature = "boot")]
pub fn create_test_bootable_oci_image(
    repo_path: &std::path::Path,
    tag: &str,
) -> anyhow::Result<()> {
    let (mut repo, _) = Repository::<Sha256HashValue>::init_path(
        rustix::fs::CWD,
        repo_path,
        composefs::fsverity::Algorithm::SHA256,
        false,
    )?;
    repo.set_insecure();
    let repo = Arc::new(repo);
    let rt = tokio::runtime::Runtime::new()?;
    let img = rt.block_on(create_bootable_image(&repo, Some(tag), 1));
    ensure_erofs_for_image(&repo, tag)?;
    crate::boot::generate_boot_image(&repo, &img.manifest_digest)?;
    Ok(())
}

/// Generate the composefs EROFS for a tagged OCI image and link it to the
/// config splitstream.
///
/// This is the test-visible wrapper around the crate-internal
/// `ensure_oci_composefs_erofs`. Integration tests that create images via
/// `create_base_image` (which bypasses `pull_image`) need this to populate
/// the EROFS ref before testing `cfsctl oci mount`.
pub fn ensure_erofs_for_image(
    repo: &Arc<Repository<Sha256HashValue>>,
    tag: &str,
) -> anyhow::Result<Sha256HashValue> {
    let oci = crate::oci_image::OciImage::open_ref(repo, tag)?;
    let erofs_id = crate::ensure_oci_composefs_erofs(
        repo,
        oci.manifest_digest(),
        Some(oci.manifest_verity()),
        Some(tag),
    )?
    .ok_or_else(|| anyhow::anyhow!("image is not a container image"))?;
    Ok(erofs_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use composefs::test::TestRepo;

    #[test]
    fn test_dumpfile_to_tar_directory() {
        let tar_data = dumpfile_to_tar(
            "/ 0 40755 2 0 0 0 0.0 - - -\n\
             /mydir 0 40755 2 0 0 0 0.0 - - -\n",
        );
        let mut archive = ::tar::Archive::new(&tar_data[..]);
        let entries: Vec<_> = archive
            .entries()
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1); // root is skipped
        assert_eq!(entries[0].path().unwrap().to_str().unwrap(), "mydir");
        assert_eq!(
            entries[0].header().entry_type(),
            ::tar::EntryType::Directory
        );
        assert_eq!(entries[0].header().mode().unwrap(), 0o755);
    }

    #[test]
    fn test_dumpfile_to_tar_file() {
        let tar_data = dumpfile_to_tar(
            "/ 0 40755 2 0 0 0 0.0 - - -\n\
             /hello 5 100644 1 0 0 0 0.0 - world -\n",
        );
        let mut archive = ::tar::Archive::new(&tar_data[..]);
        let mut entries = archive.entries().unwrap();
        let mut entry = entries.next().unwrap().unwrap();
        assert_eq!(entry.path().unwrap().to_str().unwrap(), "hello");
        assert_eq!(entry.header().entry_type(), ::tar::EntryType::Regular);
        assert_eq!(entry.header().mode().unwrap(), 0o644);
        let mut content = String::new();
        std::io::Read::read_to_string(&mut entry, &mut content).unwrap();
        assert_eq!(content, "world");
    }

    #[test]
    fn test_dumpfile_to_tar_executable() {
        let tar_data = dumpfile_to_tar(
            "/ 0 40755 2 0 0 0 0.0 - - -\n\
             /bin/app 14 100755 1 0 0 0 0.0 - binary-content -\n",
        );
        let mut archive = ::tar::Archive::new(&tar_data[..]);
        let entries: Vec<_> = archive
            .entries()
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(entries[0].header().mode().unwrap(), 0o755);
    }

    #[test]
    fn test_dumpfile_to_tar_symlink() {
        let tar_data = dumpfile_to_tar(
            "/ 0 40755 2 0 0 0 0.0 - - -\n\
             /usr/bin/sh 7 120777 1 0 0 0 0.0 busybox - -\n",
        );
        let mut archive = ::tar::Archive::new(&tar_data[..]);
        let entries: Vec<_> = archive
            .entries()
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header().entry_type(), ::tar::EntryType::Symlink);
        assert_eq!(
            entries[0].link_name().unwrap().unwrap().to_str().unwrap(),
            "busybox"
        );
    }

    #[tokio::test]
    async fn test_create_base_image() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = create_base_image(repo, Some("base:v1")).await;
        assert!(img.manifest_digest.to_string().starts_with("sha256:"));
        assert!(img.config_digest.to_string().starts_with("sha256:"));
    }

    #[tokio::test]
    async fn test_create_bootable_image() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = create_bootable_image(repo, Some("boot:v1"), 1).await;
        assert!(img.manifest_digest.to_string().starts_with("sha256:"));
        assert!(img.config_digest.to_string().starts_with("sha256:"));
    }

    /// v1 and v2 share userspace layers but differ in kernel/UKI.
    /// Pulling both into the same repo deduplicates the shared content.
    #[tokio::test]
    async fn test_versioned_images_share_layers() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let v1 = create_bootable_image(repo, Some("os:v1"), 1).await;
        let v2 = create_bootable_image(repo, Some("os:v2"), 2).await;

        // Different manifests (different kernel content)
        assert_ne!(v1.manifest_digest, v2.manifest_digest);
        // Different configs (different layer digests for kernel layers)
        assert_ne!(v1.config_digest, v2.config_digest);

        // Both should be openable
        let oci_v1 = crate::oci_image::OciImage::open_ref(repo, "os:v1").unwrap();
        let oci_v2 = crate::oci_image::OciImage::open_ref(repo, "os:v2").unwrap();
        assert!(oci_v1.is_container_image());
        assert!(oci_v2.is_container_image());

        // Untagging v1 and running GC should collect v1-specific objects
        // (its manifest, config, and version-specific layer streams)
        // but shared layers must survive for v2.
        crate::oci_image::untag_image(repo, "os:v1").unwrap();
        let gc = repo.gc(&[]).unwrap();
        // v1-specific: manifest splitstream + config splitstream + manifest JSON +
        // config JSON + 4 version-specific layer splitstreams (kernel, initramfs,
        // modules, UKI — each has unique content per version)
        assert_eq!(gc.objects_removed, 8, "v1-specific objects collected");
        // 4 v1-specific layer streams + manifest + config = 6 stream symlinks
        // (the 16 shared layers are still live via v2)
        assert_eq!(gc.streams_pruned, 6, "v1-specific stream symlinks pruned");

        // v2 should still be fully intact after v1 is GC'd
        let oci_v2 = crate::oci_image::OciImage::open_ref(repo, "os:v2").unwrap();
        assert!(oci_v2.is_container_image());

        // GC again — nothing more should be collected (shared layers are live)
        let gc2 = repo.gc(&[]).unwrap();
        assert_eq!(gc2.objects_removed, 0, "no more objects to collect");
        assert_eq!(gc2.streams_pruned, 0, "no more streams to prune");
        assert_eq!(gc2.images_pruned, 0, "no images to prune");
    }
}
