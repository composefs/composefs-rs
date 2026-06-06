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
use std::sync::Arc;

use crate::oci_image::write_manifest;
use crate::skopeo::OCI_CONFIG_CONTENT_TYPE;
use composefs::dumpfile_parse::{Entry, Item};
use composefs::fsverity::Sha256HashValue;
use composefs::repository::{Repository, RepositoryConfig};
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

/// Write a PAX extended header entry followed by the real entry to a
/// [`tar::Builder`].
///
/// The `xattrs` are encoded as `SCHILY.xattr.<name>=<value>` PAX records,
/// which is the de-facto standard used by GNU tar, BSD tar, and all
/// container runtimes.
fn append_with_xattrs<W: std::io::Write>(
    builder: &mut ::tar::Builder<W>,
    header: &mut ::tar::Header,
    path: &str,
    data: &[u8],
    xattrs: &[(String, Vec<u8>)],
) {
    // Build the PAX extended header payload using tar_core's PaxBuilder.
    let mut pax = tar_core::builder::PaxBuilder::new();
    for (key, value) in xattrs {
        pax.add(&format!("SCHILY.xattr.{key}"), value);
    }
    let pax_data = pax.finish();

    // Write the PAX header entry (type 'x').
    let mut pax_header = ::tar::Header::new_ustar();
    pax_header.set_entry_type(::tar::EntryType::XHeader);
    pax_header.set_size(pax_data.len() as u64);
    pax_header.set_mode(0o644);
    let pax_path = format!("PaxHeader/{path}");
    builder
        .append_data(&mut pax_header, &pax_path, &pax_data[..])
        .unwrap();

    // Write the actual entry immediately after (same archive stream).
    builder.append_data(header, path, data).unwrap();
}

/// Convert composefs dumpfile lines into tar bytes.
///
/// Parses each line as a composefs [`Entry`] and builds the corresponding
/// tar entry.  The root directory (`/`) is skipped since tar archives don't
/// include it.  Regular files (inline and external), directories, and
/// symlinks are supported.  Any xattrs present (e.g. `security.capability`)
/// are emitted as PAX extended headers.
///
/// External files (`Item::Regular` with no inline content) get
/// deterministic pseudo-random data from a seeded RNG (keyed on file size).
pub fn dumpfile_to_tar(dumpfile: &str) -> Vec<u8> {
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

        // Collect xattrs for PAX headers.
        let xattrs: Vec<(String, Vec<u8>)> = entry
            .xattrs
            .iter()
            .map(|x| {
                let key = x
                    .key
                    .to_str()
                    .unwrap_or_else(|| panic!("non-UTF8 xattr key: {:?}", x.key));
                (key.to_owned(), x.value.to_vec())
            })
            .collect();
        let has_xattrs = !xattrs.is_empty();

        let ty = FileType::from_raw_mode(entry.mode);
        match ty {
            FileType::Directory => {
                let mut header = ::tar::Header::new_ustar();
                header.set_uid(entry.uid.into());
                header.set_gid(entry.gid.into());
                header.set_mode(entry.mode & 0o7777);
                header.set_entry_type(::tar::EntryType::Directory);
                header.set_size(0);
                if has_xattrs {
                    append_with_xattrs(&mut builder, &mut header, path, &[], &xattrs);
                } else {
                    builder
                        .append_data(&mut header, path, std::io::empty())
                        .unwrap();
                }
            }
            FileType::RegularFile => {
                let content: Vec<u8> = match &entry.item {
                    Item::RegularInline { content, .. } => content.to_vec(),
                    Item::Regular { size, .. } => {
                        use rand::{RngExt, SeedableRng, rngs::SmallRng};
                        let mut rng = SmallRng::seed_from_u64(*size);
                        let mut buf = vec![0u8; *size as usize];
                        rng.fill(&mut buf[..]);
                        buf
                    }
                    other => panic!("unexpected regular file item variant: {other:?}"),
                };
                let mut header = ::tar::Header::new_ustar();
                header.set_uid(entry.uid.into());
                header.set_gid(entry.gid.into());
                header.set_mode(entry.mode & 0o7777);
                header.set_entry_type(::tar::EntryType::Regular);
                header.set_size(content.len() as u64);
                if has_xattrs {
                    append_with_xattrs(&mut builder, &mut header, path, &content, &xattrs);
                } else {
                    builder
                        .append_data(&mut header, path, &content[..])
                        .unwrap();
                }
            }
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
                if has_xattrs {
                    append_with_xattrs(&mut builder, &mut header, path, &[], &xattrs);
                } else {
                    builder
                        .append_data(&mut header, path, std::io::empty())
                        .unwrap();
                }
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
pub async fn create_multi_layer_image(
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

    let layer_verities_vec: Vec<(Box<str>, Sha256HashValue)> =
        layer_verities_map.into_iter().collect();
    let (_stored_digest, manifest_verity) = write_manifest(
        repo,
        &manifest,
        &manifest_digest,
        &config_verity,
        &layer_verities_vec,
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
// Format: /path size mode nlink uid gid rdev mtime payload content digest [xattr=val ...]
//
// Directories:  /path 0 40755 2 0 0 0 0.0 - - -
// Inline files: /path <len> 100644 1 0 0 0 0.0 - <content> -
// External:     /path <len> 100644 1 0 0 0 0.0 / - -   (data is auto-generated)
// Executables:  /path <len> 100755 1 0 0 0 0.0 - <content> -
// Symlinks:     /path <targetlen> 120777 1 0 0 0 0.0 <target> - -
//
// Xattrs are appended as space-separated key=value pairs after the digest
// (e.g. security.capability for file capabilities).
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

/// Busybox layer with a 4 KiB binary (external, > INLINE_CONTENT_MAX_V0).
const LAYER_BUSYBOX: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/bin 0 40755 2 0 0 0 0.0 - - -
/usr/bin/busybox 4096 100755 1 0 0 0 0.0 / - -
/usr/bin/sh 7 120777 1 0 0 0 0.0 busybox - -
";

/// Core utils layer.  `/usr/bin/ping` carries a `security.capability` xattr
/// granting CAP_NET_RAW (VFS_CAP_REVISION_2), which is the realistic pattern
/// seen in real container images.
const LAYER_CORE_UTILS: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/bin 0 40755 2 0 0 0 0.0 - - -
/usr/bin/ls 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/cat 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/cp 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/mv 7 120777 1 0 0 0 0.0 busybox - -
/usr/bin/ping 7 120777 1 0 0 0 0.0 busybox - - security.capability=\\x02\\x00\\x00\\x02\\x00\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00
/usr/bin/rm 7 120777 1 0 0 0 0.0 busybox - -
";

/// Config layer with /etc/passwd as a 100-byte external file.
const LAYER_CONFIG: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/etc 0 40755 2 0 0 0 0.0 - - -
/etc/os-release 26 100644 1 0 0 0 0.0 - ID=test\\nVERSION_ID=1.0\\n -
/etc/hostname 9 100644 1 0 0 0 0.0 - test-host -
/etc/passwd 100 100644 1 0 0 0 0.0 / - -
";

/// App layer with a 512-byte README and 256-byte JSON (both external).
const LAYER_APP: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/share 0 40755 2 0 0 0 0.0 - - -
/usr/share/doc 0 40755 2 0 0 0 0.0 - - -
/usr/share/doc/README 512 100644 1 0 0 0 0.0 / - -
/var 0 40755 2 0 0 0 0.0 - - -
/var/data 0 40755 2 0 0 0 0.0 - - -
/var/data/app.json 256 100644 1 0 0 0 0.0 / - -
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
/usr/lib/libc.so.6 8192 100644 1 0 0 0 0.0 / - -
/usr/lib/libm.so.6 4096 100644 1 0 0 0 0.0 / - -
";

const LAYER_LIBS_2: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/libpthread.so.0 4096 100644 1 0 0 0 0.0 / - -
/usr/lib/libdl.so.2 2048 100644 1 0 0 0 0.0 / - -
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

/// A minimal `/etc/selinux` policy layer suitable for testing SELinux labeling.
///
/// Contains:
/// - `/etc/selinux/config` selecting the `targeted` policy
/// - `/etc/selinux/targeted/contexts/files/file_contexts` with a small but
///   representative set of rules covering `/`, `/usr`, `/etc`, `/boot`, and
///   `/var` subtrees
///
/// All entries are inline so no object store is needed.
pub const LAYER_SELINUX: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/etc 0 40755 2 0 0 0 0.0 - - -
/etc/selinux 0 40755 2 0 0 0 0.0 - - -
/etc/selinux/config 39 100644 1 0 0 0 0.0 - SELINUX=enforcing\\nSELINUXTYPE=targeted\\n -
/etc/selinux/targeted 0 40755 2 0 0 0 0.0 - - -
/etc/selinux/targeted/contexts 0 40755 2 0 0 0 0.0 - - -
/etc/selinux/targeted/contexts/files 0 40755 2 0 0 0 0.0 - - -
/etc/selinux/targeted/contexts/files/file_contexts 190 100644 1 0 0 0 0.0 - /(/.*)?\\tsystem_u:object_r:root_t:s0\\n/usr(/.*)?\\tsystem_u:object_r:usr_t:s0\\n/etc(/.*)?\\tsystem_u:object_r:etc_t:s0\\n/boot(/.*)?\\tsystem_u:object_r:boot_t:s0\\n/var(/.*)?\\tsystem_u:object_r:var_t:s0\\n -
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

// ---------------------------------------------------------------------------
// Builder API
// ---------------------------------------------------------------------------

/// Flags controlling optional OS features in a test image.
#[derive(Debug, Clone, Default)]
pub struct OsFeatures {
    pub selinux: bool,
}

/// Which kernel/UKI content to embed in a bootable image.
#[derive(Debug, Clone, Copy)]
pub enum KernelVersion {
    V1,
    V2,
}

/// The high-level shape of the test OS image.
#[derive(Debug, Clone, Copy)]
pub enum OsProfile {
    /// Minimal busybox-like userspace, no kernel (was `create_base_image`).
    Minimal,
    /// Full bootable image with kernel, initramfs, and UKI.
    Bootable { version: KernelVersion },
}

/// Builder for a test OS image.
///
/// Compose a test image from a profile, optional feature flags, and any number
/// of extra dumpfile layers injected on top via [`OsImage::with_layer`]:
///
/// ```rust,ignore
/// let img = OsImage::bootable(KernelVersion::V1)
///     .with_selinux()
///     .with_layer("/usr/lib/os-release 0 100644 1 0 0 0 0.0 - ID=myos\\n -")
///     .build_oci(repo, Some("test:v1"))
///     .await;
/// ```
#[derive(Debug, Clone)]
pub struct OsImage {
    pub profile: OsProfile,
    pub features: OsFeatures,
    /// Extra dumpfile layers appended after the profile layers and feature layers.
    extra_layers: Vec<String>,
}

impl OsImage {
    /// Minimal busybox-like image with no kernel.
    pub fn minimal() -> Self {
        Self {
            profile: OsProfile::Minimal,
            features: OsFeatures::default(),
            extra_layers: Vec::new(),
        }
    }

    /// Full bootable image for the given kernel version.
    pub fn bootable(version: KernelVersion) -> Self {
        Self {
            profile: OsProfile::Bootable { version },
            features: OsFeatures::default(),
            extra_layers: Vec::new(),
        }
    }

    /// Add the SELinux policy layer.
    pub fn with_selinux(mut self) -> Self {
        self.features.selinux = true;
        self
    }

    /// Append an extra dumpfile layer on top of all profile and feature layers.
    ///
    /// `dumpfile` is a composefs dumpfile string — the same format used by the
    /// `LAYER_*` constants in this module.  Entries in later layers override
    /// earlier ones, exactly as OCI layer stacking works.
    ///
    /// This is the primary extension point for callers that need to inject
    /// specific files (e.g. `/usr/lib/os-release`, `/etc/passwd`, or custom
    /// application content) without having to assemble a full image from scratch.
    pub fn with_layer(mut self, dumpfile: impl Into<String>) -> Self {
        self.extra_layers.push(dumpfile.into());
        self
    }

    /// Assemble the ordered list of dumpfile layer strings for this image.
    fn layer_strings(&self) -> Vec<std::borrow::Cow<'static, str>> {
        let mut layers: Vec<std::borrow::Cow<'static, str>> = match self.profile {
            OsProfile::Minimal => BASE_LAYERS.iter().map(|s| (*s).into()).collect(),
            OsProfile::Bootable { version } => {
                let (kernel, initramfs, modules, uki) = match version {
                    KernelVersion::V1 => (
                        LAYER_KERNEL_V1,
                        LAYER_INITRAMFS_V1,
                        LAYER_KERNEL_MODULES_V1,
                        LAYER_UKI_V1,
                    ),
                    KernelVersion::V2 => (
                        LAYER_KERNEL_V2,
                        LAYER_INITRAMFS_V2,
                        LAYER_KERNEL_MODULES_V2,
                        LAYER_UKI_V2,
                    ),
                };
                let mut v: Vec<std::borrow::Cow<'static, str>> =
                    Vec::with_capacity(BASE_LAYERS.len() + 11);
                // Layers 1-5: base userspace (shared across versions)
                v.extend(BASE_LAYERS.iter().map(|s| (*s).into()));
                // Layers 6-7: boot directory structure (shared)
                v.push(LAYER_BOOT_DIRS.into());
                v.push(LAYER_KERNEL_MODULES_DIR.into());
                // Layers 8-11: version-specific boot content
                v.push(kernel.into());
                v.push(initramfs.into());
                v.push(modules.into());
                v.push(uki.into());
                // Layers 12-20: shared system content
                v.extend(SHARED_SYSTEM_LAYERS.iter().map(|s| (*s).into()));
                v
            }
        };
        if self.features.selinux {
            layers.push(LAYER_SELINUX.into());
        }
        layers.extend(self.extra_layers.iter().cloned().map(Into::into));
        layers
    }

    /// Build the OCI image in `repo` with optional `tag`.
    pub async fn build_oci(
        &self,
        repo: &Arc<Repository<Sha256HashValue>>,
        tag: Option<&str>,
    ) -> TestImage {
        let layers = self.layer_strings();
        let layer_refs: Vec<&str> = layers.iter().map(|s| s.as_ref()).collect();
        create_multi_layer_image(repo, tag, &layer_refs).await
    }

    /// Build a merged [`composefs::tree::FileSystem`] by importing all layers
    /// into the given repository and then assembling the filesystem tree.
    ///
    /// This is useful for unit tests that need a `FileSystem` to pass to
    /// [`composefs_boot::BootOps::transform_for_boot`] without going through
    /// a full OCI pull.
    pub async fn build_filesystem(
        &self,
        repo: &Arc<Repository<Sha256HashValue>>,
    ) -> composefs::tree::FileSystem<Sha256HashValue> {
        let img = self.build_oci(repo, None).await;
        crate::image::create_filesystem(repo, &img.config_digest, None)
            .expect("valid test filesystem")
    }
}

// ---------------------------------------------------------------------------
// Backward-compatible free functions
// ---------------------------------------------------------------------------

/// Create a base (non-bootable) test OCI image with 5 layers.
///
/// Layers contain a busybox-like userspace: root directory structure, busybox
/// binary with shell symlink, core utility symlinks, configuration files, and
/// a small application.
pub async fn create_base_image(
    repo: &Arc<Repository<Sha256HashValue>>,
    tag: Option<&str>,
) -> TestImage {
    OsImage::minimal().build_oci(repo, tag).await
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
    let kv = match version {
        1 => KernelVersion::V1,
        2 => KernelVersion::V2,
        _ => panic!("unsupported test image version: {version}"),
    };
    OsImage::bootable(kv).build_oci(repo, tag).await
}

/// Create a base test OCI image in a repository at the given path.
///
/// This is a convenience wrapper for integration tests that work with repo
/// paths rather than `Repository` handles. Opens the repo, creates the
/// image with `create_base_image`, generates the EROFS, and returns.
pub fn create_test_oci_image(repo_path: &std::path::Path, tag: &str) -> anyhow::Result<()> {
    let (repo, _) = Repository::<Sha256HashValue>::init_path(
        rustix::fs::CWD,
        repo_path,
        RepositoryConfig::default().set_insecure(),
    )?;
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
    let (repo, _) = Repository::<Sha256HashValue>::init_path(
        rustix::fs::CWD,
        repo_path,
        RepositoryConfig::default().set_insecure(),
    )?;
    let repo = Arc::new(repo);
    let rt = tokio::runtime::Runtime::new()?;
    let img = rt.block_on(create_bootable_image(&repo, Some(tag), 1));
    ensure_erofs_for_image(&repo, tag)?;
    crate::boot::generate_boot_image(&repo, &img.manifest_digest, Some(tag))?;
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

/// Build an OCI layout directory on disk from dumpfile layer strings.
///
/// Each entry in `layers` is a dumpfile string (same format as
/// [`create_multi_layer_image`] uses).  Returns a [`tempfile::TempDir`]
/// containing a valid OCI layout that can be read by `oci-delta`,
/// `import_oci_layout`, or any OCI-aware tool.
#[cfg(test)]
pub fn build_oci_layout(layers: &[&str]) -> tempfile::TempDir {
    use cap_std_ext::cap_std;
    use containers_image_proxy::oci_spec::image::{
        ConfigBuilder, ImageConfigurationBuilder, PlatformBuilder, RootFsBuilder,
    };
    use std::io::Write;

    let dir = tempfile::tempdir().expect("creating tempdir");
    let cap_dir =
        cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();
    let ocidir = ocidir::OciDir::ensure(cap_dir).unwrap();

    let mut manifest = ocidir.new_empty_manifest().unwrap().build().unwrap();
    let mut config = ImageConfigurationBuilder::default()
        .architecture("amd64")
        .os("linux")
        .rootfs(
            RootFsBuilder::default()
                .typ("layers")
                .diff_ids(Vec::<String>::new())
                .build()
                .unwrap(),
        )
        .config(ConfigBuilder::default().build().unwrap())
        .build()
        .unwrap();

    for dumpfile in layers {
        let tar_data = dumpfile_to_tar(dumpfile);
        let mut layer_writer = ocidir.create_gzip_layer(None).unwrap();
        layer_writer.write_all(&tar_data).unwrap();
        let layer = layer_writer.complete().unwrap();
        ocidir.push_layer(&mut manifest, &mut config, layer, "layer", None);
    }

    let config_desc = ocidir.write_config(config).unwrap();
    manifest.set_config(config_desc);
    let platform = PlatformBuilder::default()
        .architecture("amd64")
        .os(containers_image_proxy::oci_spec::image::Os::default())
        .build()
        .unwrap();
    ocidir.insert_manifest(manifest, None, platform).unwrap();

    dir
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

    #[tokio::test]
    async fn test_os_image_builder_selinux() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = OsImage::bootable(KernelVersion::V1)
            .with_selinux()
            .build_oci(repo, Some("selinux:v1"))
            .await;
        assert!(
            img.manifest_digest.to_string().starts_with("sha256:"),
            "manifest_digest should start with sha256:"
        );
    }

    #[tokio::test]
    async fn test_os_image_with_layer() {
        use std::ffi::OsStr;

        // Inject a custom /usr/lib/os-release on top of the minimal image.
        let os_release = "/usr/lib/os-release 0 100644 1 0 0 0 0.0 - ID=myos\\nVERSION_ID=42\\n -";
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;
        let fs = OsImage::minimal()
            .with_layer(os_release)
            .build_filesystem(repo)
            .await;

        // Verify the injected file is present and readable.
        let root = fs.as_dir();
        let usr_lib = root
            .get_directory_ref("usr/lib".as_ref())
            .expect("usr/lib exists");
        let file = usr_lib
            .get_file_opt(OsStr::new("os-release"))
            .expect("lookup succeeded")
            .expect("os-release present");
        let content = match file {
            composefs::tree::RegularFile::Inline(data) => data.clone(),
            _ => panic!("expected inline file"),
        };
        assert_eq!(&*content, b"ID=myos\nVERSION_ID=42\n");
    }

    #[tokio::test]
    async fn test_build_filesystem_bootable() {
        // build_filesystem on a bootable image should produce /boot and /sysroot dirs.
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;
        let fs = OsImage::bootable(KernelVersion::V1)
            .build_filesystem(repo)
            .await;
        let root = fs.as_dir();
        assert!(
            root.get_directory_ref("boot".as_ref()).is_ok(),
            "/boot should exist"
        );
        assert!(
            root.get_directory_ref("sysroot".as_ref()).is_ok(),
            "/sysroot should exist"
        );
        assert!(
            root.get_directory_ref("usr/lib/modules/6.1.0".as_ref())
                .is_ok(),
            "/usr/lib/modules/6.1.0 should exist"
        );
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
