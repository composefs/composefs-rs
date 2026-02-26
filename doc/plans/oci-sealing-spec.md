# OCI Sealing Specification for Composefs

This document defines how composefs integrates with OCI container images to provide cryptographic verification of complete filesystem trees. The specification is based on original design discussion in [composefs/composefs#294](https://github.com/composefs/composefs/issues/294).

## Problem Statement

Container images need cryptographic verification that efficiently covers the entire filesystem tree without requiring re-hashing of all content. Current OCI signature mechanisms (cosign, GPG) can sign manifests, but verifying the complete filesystem tree at runtime is extremely expensive because the only known digests are those of the tar layers.

Hence verifying the integrity of an individual file would require re-synthesizing the entire tarball (using tar-split or equivalent) and computing its digest.

## Related projects

- **[containerd EROFS snapshotter](https://github.com/containerd/containerd/blob/main/docs/snapshotters/erofs.md)**: Converts OCI layers to EROFS blobs with optional fsverity protection. Supports `enable_fsverity = true` to enable fs-verity on layer blobs. Uses reproducible builds with erofs-utils 1.8+ (`-T0 --mkfs-time`). dm-verity integration is planned but not yet implemented.

## Solution

The core primitive of composefs is fsverity, which allows incremental online verification of individual files. The complete filesystem tree metadata is itself stored as a file which can be verified in the same way. The critical design question is how to embed the composefs digest within OCI image metadata such that external signatures can efficiently cover the entire filesystem tree.

## Core Design

"composefs digest" here means the fsverity digest of the EROFS metadata file. The EROFS generation must be reproducible — given identical input filesystem trees, implementations must produce byte-for-byte identical EROFS images. See [standardized-erofs-meta.md](standardized-erofs-meta.md) for the goals and open questions around EROFS serialization standardization. However, fsverity is configurable based on digest (SHA-256 or SHA-512 currently) as well as block size (4k and e.g. 64k).

For standardized short form of the combination, a string of the form `fsverity-${DIGEST}-${BLOCKSIZEBITS}` is used. The `fsverity-` prefix makes clear this is an fsverity Merkle tree digest, not a simple hash:

- `fsverity-sha256-12` (SHA-256, 4k block size, 2^12)
- `fsverity-sha512-12` (SHA-512, 4k block size)
- `fsverity-sha256-16` (SHA-256, 64k block size, 2^16)
- `fsverity-sha512-16` (SHA-512, 64k block size)

Digests are encoded as lowercase hexadecimal.

### Recommended default algorithm

The suggested default is `fsverity-sha512-12` - this maximizes compatibility as
not every system can support higher page sizes, and also maximizes security (there are
post-quantum crypto arguments against SHA-256).

### Composefs Digest Storage

Composefs digests can be stored in two locations:

1. **Signature artifact** (primary): As annotations on the signature artifact layers, alongside the PKCS#7 signatures. This is the recommended approach because it allows signing existing unmodified OCI images — the original manifest is never touched.

2. **Manifest annotations** (optional): As annotations on the image manifest layers. This is a convenience for tools that want to verify composefs digests without fetching a separate artifact. When both are present, they MUST agree.

When using manifest annotations, in [the manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md),
each layer may have an annotation with a composefs digest.

```json
{
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
      "size": 32654,
      "annotations": {
        "composefs.layer.fsverity-sha512-12": "3abb6677af34ac57c0ca5828fd94f9d886c26ce59a8ce60ecf6778079423dccff1d6f19cb655805d56098e6d38a1a710dee59523eed7511e5a9e4b8ccb3a4686"
      }
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
      "size": 16724,
      "annotations": {
        "composefs.layer.fsverity-sha512-12": "63e22ec2fbeebabf005e58fbfb0eee607c4aa417045a68a0cc63767b048e3559268d35e72f367d3b2dbd5dbddf12fc4397762ba149260b3795a0391713bddcd7"
      }
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
      "size": 73109,
      "annotations": {
        "composefs.layer.fsverity-sha512-12": "2b59d179d9815994f687383a886ea34109889756efca5ab27318cc67ce2a21261d12fa6fee6b8c716f72214ead55ee0d789d6c35cff977d40ef5728ba9188a80"
      }
    }
  ]
}
```

Additionally, an optional merged digest may be provided on the **final layer only**, representing the *flattened* merged filesystem tree of the complete stack of all layers. The rationale is that it makes it easier for a runtime to avoid the overhead of individual mounts if it chooses to do so. This is especially suitable for e.g. a "base image" whose stack of mounts would commonly be shared with higher level applications.

```json
{
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
      "size": 32654,
      "annotations": {
        "composefs.layer.fsverity-sha512-12": "3abb6677af34ac57c0ca5828fd94f9d886c26ce59a8ce60ecf6778079423dccff1d6f19cb655805d56098e6d38a1a710dee59523eed7511e5a9e4b8ccb3a4686"
      }
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
      "size": 16724,
      "annotations": {
        "composefs.layer.fsverity-sha512-12": "63e22ec2fbeebabf005e58fbfb0eee607c4aa417045a68a0cc63767b048e3559268d35e72f367d3b2dbd5dbddf12fc4397762ba149260b3795a0391713bddcd7",
        "composefs.merged.fsverity-sha512-12": "d015f70f8bee6cf6453dd5b771eec18994b861c646cec18e2a9dfdec93f631fbb9030e60cfc82b552d33b9a134312a876ef4e519bffe3ef872aefbd84e6198b3"
      }
    }
  ]
}
```

Note: The `composefs.merged.fsverity-sha512-12` annotation appears only on the final layer and represents the complete flattened filesystem of all layers merged together.

#### Whiteout Handling in Merged Filesystem

The merged EROFS represents a fully flattened filesystem and is designed to be mounted directly, not stacked with other EROFS layers via overlayfs. During the merge process, OCI whiteouts (`.wh.*` files and opaque directory markers) are fully processed: files and directories marked for deletion in upper layers are removed from the merged result. The final merged EROFS contains no whiteout entries — it is a clean, whiteout-free snapshot of the complete filesystem tree as it would appear after all layers are applied.

### Signatures

#### Linux kernel fsverity signatures (recommended)

The primary signature mechanism is Linux kernel [fsverity built-in signature verification](https://docs.kernel.org/filesystems/fsverity.html#built-in-signature-verification). The kernel's `FS_IOC_ENABLE_VERITY` ioctl accepts a PKCS#7 signature that is verified against the `.fs-verity` keyring. This provides a clear chain of trust: the same component that controls data access (the kernel) also validates the signature. The kernel additionally integrates with the [IPE](https://docs.kernel.org/admin-guide/LSM/ipe.html) (Integrity Policy Enforcement) subsystem.

The recommended delivery mechanism for these signatures is a separate OCI artifact using the Referrer pattern, described below. This enables signing existing unmodified OCI images.

Signatures MAY also be embedded as manifest annotations using a `.signature` suffix on digest annotations (e.g. `composefs.layer.fsverity-sha512-12.signature` with base64-encoded PKCS#7), though this requires modifying the image manifest.

#### Digest-only verification (alternative)

Kernel-based signing is not required. An implementation may instead rely on external trust in the composefs digests themselves — for example, by trusting the OCI manifest (verified via cosign/sigstore/GPG) and treating the composefs digest annotations as authoritative. In this model:

```
External signature (cosign/sigstore/GPG)
  ↓ signs
OCI Manifest (includes composefs digest annotations)
  ↓
Composefs EROFS image (verified against digest)
  ↓
Complete filesystem tree
```

The userspace tooling performing this verification must be trusted. A key benefit of composefs is that verification of large data is on-demand and continuous via the kernel's fsverity — the composefs digest covers the complete filesystem tree, so verifying it is cheap even though the underlying data may be large.

#### Replacing diff_id validation

The OCI image specification requires a `diff_id` in the [image config](https://github.com/opencontainers/image-spec/blob/main/config.md) for each layer, which is the digest of the uncompressed tar stream. This is expensive to validate after extraction and provides no path to continual kernel-enforced verification. With composefs, validating `diff_id` becomes redundant: the composefs digest already cryptographically covers the complete filesystem tree derived from the layer.

#### Separate Signing Artifacts with Referrer Support

Composefs fsverity signatures can be stored as separate OCI artifacts, discoverable via the OCI referrer pattern. This follows the same approach as cosign: the signature artifact references the sealed image through the `subject` field and can be found via the `/referrers` API.

Each layer in the signature artifact is a raw PKCS#7 DER-encoded signature blob — exactly the format expected by `FS_IOC_ENABLE_VERITY`. No JSON wrapping or base64 encoding.

##### Signature Artifact Structure

The signature artifact is an OCI image manifest following the [artifacts guidance](https://github.com/opencontainers/image-spec/blob/main/artifacts-guidance.md) pattern (empty config, content in layers):

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.composefs.signature.v1",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
      "digest": "sha256:aaa...",
      "size": 456,
      "annotations": {
        "composefs.signature.type": "manifest",
        "composefs.digest": "ab12...manifest-fsverity-digest..."
      }
    },
    {
      "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
      "digest": "sha256:bbb...",
      "size": 789,
      "annotations": {
        "composefs.signature.type": "config",
        "composefs.digest": "cd34...config-fsverity-digest..."
      }
    },
    {
      "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
      "digest": "sha256:ccc...",
      "size": 1234,
      "annotations": {
        "composefs.signature.type": "layer",
        "composefs.digest": "3abb6677af34ac57...layer-1-composefs-digest..."
      }
    },
    {
      "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
      "digest": "sha256:ddd...",
      "size": 1234,
      "annotations": {
        "composefs.signature.type": "layer",
        "composefs.digest": "63e22ec2fbeeba...layer-2-composefs-digest..."
      }
    },
    {
      "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
      "digest": "sha256:eee...",
      "size": 1234,
      "annotations": {
        "composefs.signature.type": "merged",
        "composefs.digest": "d015f70f8bee6c...merged-composefs-digest..."
      }
    }
  ],
  "subject": {
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
    "size": 7682
  },
  "annotations": {
    "composefs.algorithm": "fsverity-sha512-12"
  }
}
```

##### Layer Ordering

Each layer carries two annotations: `composefs.signature.type` identifies the group, and `composefs.digest` carries the fsverity digest that the PKCS#7 blob signs. This makes the artifact self-contained — a consumer can verify composefs digests using only the signature artifact and the image layers, without requiring composefs annotations on the original image manifest.

The layers MUST appear in this order:

1. One `type: "manifest"` — signature for the sealed image manifest, stored as a file with fsverity
2. One `type: "config"` — signature for the image config, stored as a file with fsverity
3. N `type: "layer"` entries — one per manifest layer, in manifest order. Each signature is applied to the EROFS blob via `FS_IOC_ENABLE_VERITY`.
4. Zero or one `type: "merged"` entry — if present, this is the signature for the merged digest on the final layer, representing the complete flattened filesystem.

Position within each group determines which source object is signed. The number of `layer` entries MUST equal the number of layers in the source manifest.

This design enables signing existing unmodified OCI images: compute composefs digests for each layer, sign them, and push the signature artifact as a referrer. The original image is never touched.

##### Signature Format

Each layer blob is a raw PKCS#7 signature encoded using [DER](https://en.wikipedia.org/wiki/X.690#DER_encoding) (Distinguished Encoding Rules, ITU-T X.690) over the kernel's `fsverity_formatted_digest`:

```c
struct fsverity_formatted_digest {
    char magic[8];          /* "FSVerity" */
    __le16 digest_algorithm;
    __le16 digest_size;
    __u8 digest[];
};
```

Composefs algorithm identifiers map to kernel constants with no salt:
- `fsverity-sha512-12` → `FS_VERITY_HASH_ALG_SHA512`, 4096-byte blocks
- `fsverity-sha256-12` → `FS_VERITY_HASH_ALG_SHA256`, 4096-byte blocks
- `fsverity-sha512-16` → `FS_VERITY_HASH_ALG_SHA512`, 65536-byte blocks
- `fsverity-sha256-16` → `FS_VERITY_HASH_ALG_SHA256`, 65536-byte blocks

All entries in a single signature artifact MUST use the same algorithm. The algorithm is declared in the `composefs.algorithm` annotation on the signature artifact manifest (e.g. `fsverity-sha512-12`).

For manifest and config signatures, the fsverity digest is computed over the exact JSON bytes as stored in the registry. These files are stored locally with fsverity enabled so that reads are kernel-verified.

##### Discovery and Verification

Discovery uses the standard [OCI Distribution Spec referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers):
```
GET /v2/<name>/referrers/<digest>?artifactType=application/vnd.composefs.signature.v1
```

Verification:
1. Check `subject` matches the sealed image manifest digest
2. Extract layers in order and match to source objects by position
3. Read the `composefs.digest` annotation from each layer to learn the expected fsverity digest
4. For each signature, pass to `FS_IOC_ENABLE_VERITY` when enabling verity on the corresponding file (manifest JSON, config JSON, or EROFS layer blob)
5. The kernel handles PKCS#7 validation — failed verification prevents reading the file
6. If the source manifest also has composefs digest annotations, verify they match the artifact's `composefs.digest` values

```
External CA/Keystore
  ↓ issues certificate for .fs-verity keyring
PKCS#7 signatures (from artifact layers)
  ↓ applied via FS_IOC_ENABLE_VERITY to each file
Manifest JSON, Config JSON, EROFS layer blobs
  ↓ kernel fsverity enforcement on every read
Runtime file access
```

##### Implementation Considerations

This specification depends on Linux kernel fsverity (CONFIG_FS_VERITY, CONFIG_FS_VERITY_BUILTIN_SIGNATURES). Signature validation and file access enforcement are handled by the kernel.

Manifest and config objects should be stored as regular files (not splitstream) so that fsverity can be enabled on them directly.

Not all signature types are required. Implementations MAY omit entire groups (e.g. no manifest/config signatures, or no merged signatures). When a group is omitted, its entries are simply absent from the layers array and the relative ordering of the remaining groups is preserved. The `layer` group MUST always be present.

Clients that pull images with composefs signature artifacts are expected to also store the signature artifact locally alongside the image. This enables offline verification and allows fsverity signatures to be applied when files are later accessed. However, local storage of the signature artifact is not strictly required — a client could re-fetch the artifact from the registry when needed, or operate in digest-only mode where the composefs digests themselves are trusted without kernel signature verification.

##### Media Types

- `application/vnd.composefs.signature.v1`: Artifact type for signature manifests
- `application/vnd.composefs.signature.v1+pkcs7`: Layer media type for PKCS#7 DER signature blobs

## Storage model

It is recommended to store the config, manifest and unpacked layers. The EROFS can be generated on-demand or cached (via an index associated with a given manifest).

## Relationship to Booting with composefs

OCI sealing is independent from but complementary to composefs boot verification (UKI, BLS, etc.). These are separate mechanisms operating at different stages of the system lifecycle with different trust models.

It is expected that boot-sealed images would *also* be OCI sealed, although this is not strictly required.

### Bootable composefs UKI and kernel command line

The default model implemented is that the UKI's kernel command line includes the digest of a slightly modified EROFS (without `/boot` among other things).

However, it would also be possible to instead load signing keys into the kernel fsverity chain from the initramfs (which may be the same or different keys used for application images), and use the exact same scheme for mounting the root filesystem from the initramfs.

## Future Directions

### Dumpfile Digest as Canonical Identifier

The fsverity digest ties implementations to a specific EROFS format; for more details on this, see [this issue](https://github.com/composefs/composefs/issues/198). A dumpfile digest (classic SHA or fsverity digest) of the composefs dumpfile format would enable format evolution.

This would also be stored as an annotation:

```json
{
  "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
  "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
  "size": 32654,
  "annotations": {
    "composefs.layer.fsverity-sha512-12": "3abb6677af34ac57c0ca5828fd94f9d886c26ce59a8ce60ecf6778079423dccff1d6f19cb655805d56098e6d38a1a710dee59523eed7511e5a9e4b8ccb3a4686",
    "composefs.layer.fsverity-sha512-12.signature": "MIIBkgYJKo...base64-encoded-pkcs7...",
    "composefs.dumpfile.sha512": "62d4b68bc4d336ff0982b93832d9a1f1d40206b49218299e5ac2e50f683d23f17bb99a1f3805339232abebd702eeda204827cfde244bf833e42b67a2fe632dc0"
  }
}
```

A downside though is that because the mapping from the tar layer to the EROFS was not pre-computed server side, there is no way to attach a kernel-native signature. However, it does still allow efficient validation of the complete filesystem tree, given only the saved metadata (e.g. tar-split or splitstream) in combination with the fsverity digests of content.

### Integration with zstd:chunked

Both zstd:chunked and composefs add new digests to OCI images. The zstd:chunked table-of-contents (TOC) has high overlap with the composefs dumpfile format, as both are metadata about filesystem structure that identify files and their content. The TOC currently uses SHA256 while composefs requires fsverity.

Adding fsverity to zstd:chunked TOC entries would allow using the TOC digest as a canonical composefs identifier. This would support a direct TOC → dumpfile → composefs pipeline, with a single metadata format serving both zstd:chunked and composefs use cases.

## References

**Design discussion**: [composefs/composefs#294](https://github.com/composefs/composefs/issues/294)

**Experimental implementations**:
- [composefs_experiments](https://github.com/allisonkarlitskaya/composefs_experiments)
- [composefs-oci-experimental](https://github.com/cgwalters/composefs-oci-experimental)

**Related issues**:
- [containers/container-libs#108](https://github.com/containers/container-libs/issues/108) - fsverity in zstd:chunked TOC
- [containers/container-libs#112](https://github.com/containers/container-libs/issues/112) - per-layer vs flattened
- [composefs/composefs#409](https://github.com/composefs/composefs/issues/409) - non-root mounting

**Standards**:
- [OCI Image Specification](https://github.com/opencontainers/image-spec)

## Contributors

This specification synthesizes ideas from Colin Walters (original design proposals and iteration), Allison Karlitskaya (implementation and practical refinements), Alexander Larsson (security model and non-root mounting insights), and Giuseppe Scrivano (across the board) with assistance from Claude Sonnet 4.5 and Claude Opus 4.
