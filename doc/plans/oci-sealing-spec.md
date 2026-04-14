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

"composefs digest" here means the fsverity digest of the EROFS metadata file. fsverity is configurable based on digest algorithm (SHA-256 or SHA-512 currently) and block size (4k or 64k).

For standardized short form of the combination, a string of the form `fsverity-${DIGEST}-${BLOCKSIZEBITS}` is used. The `fsverity-` prefix makes clear this is an fsverity Merkle tree digest, not a simple hash:

- `fsverity-sha256-12` (SHA-256, 4k block size, 2^12)
- `fsverity-sha512-12` (SHA-512, 4k block size)
- `fsverity-sha256-16` (SHA-256, 64k block size, 2^16)
- `fsverity-sha512-16` (SHA-512, 64k block size)

Digests are encoded as lowercase hexadecimal.

### EROFS Provisioning Modes

There are two modes for how the EROFS metadata image is obtained by a client. erofs-alongside is the primary mode and the focus of this specification. canonical-EROFS is a future evolution that builds on it.

#### EROFS-alongside mode (primary)

In this mode, the EROFS metadata image is built server-side as part of a composefs OCI artifact which is also stored on the registry. It's important to emphasize that this process can happen independent of the image build; it operates similarly to a signature. Clients unaware of composefs work as before.

This is the primary mode because:

- It works today without cross-implementation EROFS standardization — the exact EROFS bytes are authored by the image publisher, so there is no need for multiple implementations to agree on a bit-for-bit identical layout.
- EROFS is a natural metadata format for incremental pulls and content-addressed object stores (see [Incremental Pulls](#incremental-pulls-via-erofs-alongside) in Future Directions). Any incremental fetch mechanism needs a separate metadata format, and EROFS — natively supported by the Linux kernel with multiple userspace parsers — is a strong fit.
- The EROFS here is just metadata; the tar layer is still required for content.

EROFS metadata layers in the artifact may optionally be compressed with zstd for wire transfer. See [EROFS Layer Compression](#erofs-layer-compression) below for details. See [Composefs Artifact Structure](#composefs-artifact-structure) below for more information about the layout.

To prevent the "representational ambiguity" problem — what happens when the tar layer and the prebuilt EROFS disagree — the client MUST verify consistency:

1. Fetch the composefs artifact and verify that it has a 1-to-1 correspondence with the source image manifest: each layer in the manifest must have exactly one matching EROFS metadata entry in the artifact (identified by position). A mismatch in count is a fatal error.
2. For each layer, verify the metadata correspondence between the tar layer and the EROFS:
   - Parse the tarball to extract a filesystem tree representation (file paths, modes, ownership, xattrs, and fsverity content digests)
   - Walk the corresponding EROFS metadata to extract the same representation
   - Compare the two — they must agree on all filesystem metadata and content references. Any disagreement is a fatal error.

This consistency check operates at the semantic filesystem level, not at the EROFS byte level. It does not require a canonical EROFS specification, but it does require agreement on how tar entries map to filesystem metadata (see [doc/oci.md](../oci.md) for OCI-to-composefs conversion decisions).

**Security consideration: parsing untrusted EROFS.** In this mode, the EROFS image is data fetched from a registry. When fsverity signatures are present, the EROFS signature is verified before mount — trust in the EROFS is trust in the publisher, the same as any signed artifact. However, the userspace consistency check (step 2 above) still parses the EROFS before signature verification, and in the unsigned/digest-only case, the EROFS is entirely attacker-controlled at parse time. This is an attack surface distinction from canonical-EROFS mode, where the EROFS is locally generated from trusted inputs.

To mitigate this, EROFS parsing code — both userspace and in-kernel — should be written in memory-safe languages or otherwise hardened. The composefs-rs userspace parser is written in Rust. The Linux kernel's EROFS implementation is fuzz-tested via syzbot and has been hardened over multiple release cycles. Implementations SHOULD validate EROFS structural integrity (superblock magic, bounds checks, inode consistency) before performing the semantic consistency check or mounting.

#### Canonical-EROFS mode (future)

This mode is not yet usable — it is blocked on the EROFS standardization work described in [standardized-erofs-meta.md](standardized-erofs-meta.md).

In this mode, no EROFS metadata is shipped on the wire. The client and server generate the EROFS using a standardized canonical process:

```
tar layer → dumpfile → EROFS metadata
```

This requires a finalized canonical EROFS specification that guarantees byte-for-byte identical output across implementations given identical input. Without this guarantee, fsverity digests computed by different implementations would not match, and signatures would fail to verify.

In this mode, the composefs digest annotations on the image manifest (or in the composefs artifact) serve as the sole reference. The client generates the EROFS, computes its fsverity digest, and verifies it matches the annotation. No EROFS bytes need to be stored on the registry.

Canonical-EROFS is best understood as a future tightening of erofs-alongside: once a canonical EROFS specification is defined, erofs-alongside artifacts could be required to use the canonical layout. This would allow clients to verify the EROFS against the tar layer by regenerating it locally, without needing to parse the shipped EROFS at all. In effect, the shipped EROFS would become a cache of a deterministic computation.

#### Digest-only mode (future, requires canonical-EROFS)

Once canonical-EROFS is available, a further simplification becomes possible: **no composefs artifact at all**. The composefs digest is placed directly on the image manifest layer annotations (see [Composefs Digest Storage](#composefs-digest-storage)), and the client generates the canonical EROFS locally, verifying its fsverity digest against the annotation.

This is the cleanest end state — the OCI image carries only standard tar layers with a composefs digest annotation, and composefs is purely a client-side optimization. No separate artifact, no EROFS on the wire, no signatures beyond whatever already covers the manifest (cosign, sigstore, etc.).

This mode is a natural consequence of canonical-EROFS and does not require additional specification beyond what is already defined for manifest annotations and canonical EROFS generation.

### Recommended default algorithm

The suggested default is `fsverity-sha512-12` - this maximizes compatibility as
not every system can support higher page sizes, and also maximizes security (there are
post-quantum crypto arguments against SHA-256).

### Composefs Digest Storage

Composefs digests — the fsverity digests of EROFS metadata images — can be stored as annotations. This is most relevant in canonical-EROFS mode, where the digest is the primary mechanism for verifying a locally-generated EROFS. In erofs-alongside mode, the EROFS metadata itself is shipped in the composefs artifact and the digest can be computed from it directly, so annotations serve mainly as a convenience for discovery.

Digests can appear in two locations:

1. **Composefs artifact** (primary): As annotations on the composefs artifact layers. This is the recommended approach because it allows signing existing unmodified OCI images — the original manifest is never touched.

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

### EROFS Layer Compression

EROFS metadata layers in the composefs artifact MAY be compressed with zstd for wire transfer. Compression is indicated by the media type suffix, following the same convention as OCI tar layers (`tar+gzip`, `tar+zstd`):

- `application/vnd.composefs.v1.erofs` — uncompressed EROFS metadata (the blob is a raw EROFS image)
- `application/vnd.composefs.v1.erofs+zstd` — zstd-compressed EROFS metadata (the blob is a zstd-compressed EROFS image)

The compressed blob is a single zstd frame containing the complete EROFS image. Consumers decompress the blob before storing locally. The decompressed result is identical to what would have been shipped with the uncompressed media type.

Producers SHOULD use `application/vnd.composefs.v1.erofs+zstd` when pushing EROFS metadata layers. Consumers MUST accept both compressed and uncompressed variants.

All layers within a single composefs artifact SHOULD use the same compression (either all compressed or all uncompressed), but consumers MUST handle mixed compression within an artifact by inspecting each layer's media type individually.

The `composefs.digest` annotation on each layer always refers to the fsverity digest of the *uncompressed* EROFS image, regardless of whether the layer is compressed on the wire. This ensures digest stability: the same EROFS image produces the same composefs digest whether pushed compressed or uncompressed. This is analogous to how OCI tar layers have both a `digest` (of the compressed blob, used for registry fetching) and a `diff_id` (of the uncompressed tar, used for identity) — except that `composefs.digest` is a fsverity Merkle tree digest rather than a flat hash, giving it the additional property of enabling continuous kernel-enforced verification.

#### Motivation

EROFS metadata compresses well with zstd, achieving a consistent 2.7-3.6:1 ratio across tested container images. For full image pulls the savings are modest (EROFS metadata is typically 0.4-1.3% of content size), but for incremental pull scenarios the compressed size becomes significant. When a client already has most content objects locally and only needs to fetch a small delta, the EROFS metadata — which describes the *complete* filesystem tree — can exceed the content delta in size. Compression reduces this cost substantially: for example, a 55 MiB merged EROFS for a desktop image compresses to ~15 MiB.

See the [incremental pulls design](incremental-pulls.md) for the full context on why EROFS transfer size matters for update scenarios.

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

#### Composefs Artifact Structure

Composefs data — signatures and optionally prebuilt EROFS metadata (erofs-alongside mode) — is stored as a separate OCI artifact, discoverable via the OCI referrer pattern. This follows the same approach as cosign: the composefs artifact references the sealed image through the `subject` field and can be found via the `/referrers` API.

Signature layers are raw PKCS#7 DER-encoded blobs — exactly the format expected by `FS_IOC_ENABLE_VERITY`. No JSON wrapping or base64 encoding. Prebuilt EROFS layers (when present) are EROFS images, optionally zstd-compressed (see [EROFS Layer Compression](#erofs-layer-compression)).

##### Artifact Manifest

The composefs artifact is an OCI image manifest following the [artifacts guidance](https://github.com/opencontainers/image-spec/blob/main/artifacts-guidance.md) pattern (empty config, content in layers):

The provisioning mode is indicated by the `artifactType`:

- `application/vnd.composefs.erofs-alongside.v1` — the artifact contains prebuilt EROFS metadata layers alongside optional signatures
- `application/vnd.composefs.canonical.v1` *(future)* — the artifact contains only signatures; the client generates the EROFS locally

This allows clients to discover which mode is available via the referrers API filtered by `artifactType`.

**EROFS-alongside example** (prebuilt EROFS on registry, zstd-compressed):

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.composefs.erofs-alongside.v1",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/vnd.composefs.v1.erofs+zstd",
      "digest": "sha256:fff...",
      "size": 2816,
      "annotations": {
        "composefs.erofs.type": "layer",
        "composefs.digest": "3abb6677af34ac57...layer-1-composefs-digest..."
      }
    },
    {
      "mediaType": "application/vnd.composefs.v1.erofs+zstd",
      "digest": "sha256:ggg...",
      "size": 1408,
      "annotations": {
        "composefs.erofs.type": "layer",
        "composefs.digest": "63e22ec2fbeeba...layer-2-composefs-digest..."
      }
    },
    {
      "mediaType": "application/vnd.composefs.v1.erofs+zstd",
      "digest": "sha256:hhh...",
      "size": 4096,
      "annotations": {
        "composefs.erofs.type": "merged",
        "composefs.digest": "d015f70f8bee6c...merged-composefs-digest..."
      }
    },
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

**Canonical-EROFS example** *(future — not yet usable)*:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.composefs.canonical.v1",
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

Each layer carries annotations that identify its role. Signature layers use `composefs.signature.type`; EROFS metadata layers (erofs-alongside mode only) use `composefs.erofs.type`. Both carry `composefs.digest` with the fsverity digest. This makes the artifact self-contained — a consumer can verify composefs digests using only the composefs artifact and the image layers, without requiring composefs annotations on the original image manifest.

The layers MUST appear in this order:

1. **(erofs-alongside only)** N EROFS metadata entries with `composefs.erofs.type: "layer"` — one per manifest layer, in manifest order. Each is an EROFS metadata image, either raw or zstd-compressed per its media type.
2. **(erofs-alongside only)** Zero or one EROFS metadata entry with `composefs.erofs.type: "merged"` — the flattened merged EROFS for the complete image.
3. **(Optional)** One signature with `composefs.signature.type: "manifest"` — signature for the sealed image manifest, stored as a file with fsverity
4. **(Optional)** One signature with `composefs.signature.type: "config"` — signature for the image config, stored as a file with fsverity
5. N signature entries with `composefs.signature.type: "layer"` — one per manifest layer, in manifest order. Each signature is applied to the EROFS blob via `FS_IOC_ENABLE_VERITY`.
6. Zero or one signature with `composefs.signature.type: "merged"` — if present, this is the signature for the merged EROFS representing the complete flattened filesystem.

Position within each group determines which source object the entry corresponds to. The number of `layer`-type entries (both EROFS and signature) MUST equal the number of layers in the source manifest. When an erofs-alongside EROFS layer and its corresponding signature layer both carry `composefs.digest`, they MUST agree.

This design enables signing existing unmodified OCI images: compute composefs digests for each layer, sign them, and push the composefs artifact as a referrer. The original image is never touched.

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

All entries in a single composefs artifact MUST use the same algorithm. The algorithm is declared in the `composefs.algorithm` annotation on the composefs artifact manifest (e.g. `fsverity-sha512-12`).

For manifest and config signatures, the fsverity digest is computed over the exact JSON bytes as stored in the registry. These files are stored locally with fsverity enabled so that reads are kernel-verified.

##### Discovery and Verification

Discovery uses the standard [OCI Distribution Spec referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers):
```
GET /v2/<name>/referrers/<digest>?artifactType=application/vnd.composefs.erofs-alongside.v1
GET /v2/<name>/referrers/<digest>?artifactType=application/vnd.composefs.canonical.v1
```

Verification depends on the mode:

**EROFS-alongside** (`artifactType: application/vnd.composefs.erofs-alongside.v1`):
1. Check `subject` matches the sealed image manifest digest
2. Extract EROFS metadata layers from the artifact, decompressing if zstd-compressed (determined by media type)
3. Fetch and unpack each tar layer; generate a canonical in-memory metadata representation (e.g. composefs dumpfile) from the tar and compare against the EROFS metadata — disagreement is fatal
4. The EROFS metadata is used directly (no local generation needed)
5. If signature layers are present, apply them via `FS_IOC_ENABLE_VERITY` to the EROFS files
6. If the source manifest has composefs digest annotations, verify they match the artifact's `composefs.digest` values

**Canonical-EROFS** *(future)* (`artifactType: application/vnd.composefs.canonical.v1`):
1. Check `subject` matches the sealed image manifest digest
2. Read `composefs.digest` annotations from signature layers (or from the source manifest annotations) to learn the expected fsverity digests
3. Generate the EROFS locally from the tar layers using the canonical process
4. Compute the fsverity digest of the locally generated EROFS and verify it matches the expected digest
5. If signature layers are present, apply them via `FS_IOC_ENABLE_VERITY` to the EROFS files

In both modes, the kernel handles PKCS#7 validation when signatures are used — failed verification prevents reading the file.

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

Kernel-level signature verification depends on Linux kernel fsverity (CONFIG_FS_VERITY, CONFIG_FS_VERITY_BUILTIN_SIGNATURES). Signature validation and file access enforcement are handled by the Linux kernel.

When signatures are present, the manifest and config signature entries MUST also be present — there is no reason to sign individual layers without also signing the manifest and config that reference them. The merged entry remains optional.

In erofs-alongside mode, the EROFS `layer` group MUST always be present (that is the primary purpose of the artifact). Signature layers are optional — an erofs-alongside artifact without signatures is valid and supports digest-only verification. This is the expected common case: a composefs artifact is attached to an existing image to provide EROFS metadata, without requiring the publisher to have signing keys.

In canonical-EROFS mode, the composefs artifact exists only to carry signatures (the EROFS is generated locally). If an implementation uses digest-only verification, it does not need a composefs artifact at all — the `composefs.layer.*` annotations on the image manifest are sufficient.

Clients that pull images with composefs artifacts are expected to also store the artifact locally alongside the image (it's just a small amount of metadata), and to attach the signatures to the corresponding files at the Linux kernel level. This enables offline verification and allows fsverity signatures to be applied when files are later accessed. However, local storage of the artifact is not strictly required — a client could re-fetch the artifact from the registry when needed, or operate in digest-only mode where the composefs digests themselves are trusted without kernel signature verification.

Implementations should focus on erofs-alongside mode, which works today. Once the canonical EROFS specification is finalized, implementations SHOULD support both modes.

##### Media Types

- `application/vnd.composefs.erofs-alongside.v1`: Artifact type for erofs-alongside composefs artifacts (EROFS metadata + optional signatures)
- `application/vnd.composefs.canonical.v1`: Artifact type for canonical-EROFS composefs artifacts (signatures only)
- `application/vnd.composefs.v1.erofs`: Layer media type for uncompressed prebuilt EROFS metadata images (erofs-alongside only)
- `application/vnd.composefs.v1.erofs+zstd`: Layer media type for zstd-compressed prebuilt EROFS metadata images (erofs-alongside only). See [EROFS Layer Compression](#erofs-layer-compression).
- `application/vnd.composefs.signature.v1+pkcs7`: Layer media type for PKCS#7 DER signature blobs

## Storage model

It is recommended to store the config, manifest and unpacked layers.

In erofs-alongside mode, the prebuilt EROFS is fetched from the registry and stored directly. In canonical-EROFS mode, the EROFS is generated locally on-demand or cached (indexed by manifest digest). In either case, the composefs artifact itself should be stored locally to enable offline signature verification.

## Relationship to Booting with composefs

OCI sealing is independent from but complementary to composefs boot verification (UKI, BLS, etc.). These are separate mechanisms operating at different stages of the system lifecycle with different trust models.

It is expected that boot-sealed images would *also* be OCI sealed, although this is not strictly required.

### Bootable composefs UKI and kernel command line

The default model implemented is that the UKI's kernel command line includes the fsverity digest of a slightly modified EROFS (without `/boot` among other things). This currently relies on canonical-EROFS mode since the digest must match between what the UKI embeds at build time and what the client generates at boot time.

With erofs-alongside mode, it would also be possible to instead load signing keys into the kernel fsverity chain from the initramfs (which may be the same or different keys used for application images), and use the composefs artifact signature scheme for mounting the root filesystem from the initramfs. This would remove the dependency on canonical EROFS generation for boot.

## Future Directions

### Incremental Pulls via EROFS-alongside

In erofs-alongside mode, the EROFS metadata contains fsverity digests of all content objects, so the client can determine which objects it already has locally and only fetch the missing ones from the tar layer. The EROFS effectively acts as a table of contents — a metadata format that is natively supported by the Linux kernel and has multiple userspace parsers.

A key advantage over existing approaches (zstd:chunked, eStargz) is that the composefs digest eliminates the need to verify the OCI `diff_id`, which in turn eliminates the need for tar-split metadata. The tar layer becomes purely a content delivery mechanism — each fetched object is verified independently by its fsverity digest against the trusted EROFS.

To push an incrementally-pulled image, the client must regenerate the tar layer deterministically. This requires a canonical tar format — see [canonical-tar.md](canonical-tar.md).

See [incremental-pulls.md](incremental-pulls.md) for the full design, including the composefs-chunked layer format, offset map structure, and pull protocol.

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
