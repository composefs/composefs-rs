//! # OCI Sealing Specification for Composefs
//!
//! This document defines how composefs integrates with OCI container images to provide cryptographic verification of complete filesystem trees. The specification is based on original design discussion in [composefs/composefs#294](https://github.com/composefs/composefs/issues/294).
//!
//! ## Problem Statement
//!
//! We want to address a threat model for example where the filesystem (or block device) may have been mutated by malicious (or accidental) activity. Such changes should be detected immediately and efficiently, even while a container is running.
//!
//! To address this, container images need cryptographic verification that efficiently covers all components (manifest, config and filesystem tree).
//!
//! Current OCI signature mechanisms (cosign, GPG) can sign manifests, which then covers the compressed and uncompressed tar archive streams. But verifying the correspondence between the tar archive and the unpacked filesystem representation is very expensive.
//!
//! An obvious mechanism to address the threat model would be to store everything in memory: First verify the manifest, then the config, then unpack the tar archives into memory. But this would mean a slow and expensive "first start", and also be problematic for large container images that have unused portions.
//!
//! ## Related projects
//!
//! - **[containerd EROFS snapshotter](https://github.com/containerd/containerd/blob/main/docs/snapshotters/erofs.md)**: Converts OCI layers to EROFS blobs with optional fsverity protection. Supports `enable_fsverity = true` to enable fs-verity on layer blobs. Uses reproducible builds with erofs-utils 1.8+ (`-T0 --mkfs-time`). dm-verity integration is planned but not yet implemented.
//!
//! ## Efficient sealing with composefs
//!
//! The core primitive of composefs is fsverity, which allows incremental online verification of individual files. The complete filesystem tree metadata is itself stored as a file which can be verified in the same way. The critical design question is how to embed the composefs digest within OCI image metadata such that external signatures can efficiently cover the entire filesystem tree.
//!
//! "composefs digest" here means the fsverity digest of the EROFS metadata file. fsverity is configurable based on digest algorithm (SHA-256 or SHA-512 currently) and block size (4k or 64k).
//!
//! For standardized short form of the combination, a string of the form `fsverity-${DIGEST}-${BLOCKSIZEBITS}` is used. The `fsverity-` prefix makes clear this is an fsverity Merkle tree digest, not a simple hash:
//!
//! - `fsverity-sha256-12` (SHA-256, 4k block size, 2^12)
//! - `fsverity-sha512-12` (SHA-512, 4k block size)
//! - `fsverity-sha256-16` (SHA-256, 64k block size, 2^16)
//! - `fsverity-sha512-16` (SHA-512, 64k block size)
//!
//! Digests are encoded as lowercase hexadecimal.
//!
//! (Note at the current time, only 4k blocks are supported by the composefs-rs implementation)
//!
//! ### Key components: fsverity digest and signature
//!
//! An OCI image has 3 key components, and we want to provide integrity for all of them:
//!
//! - manifest
//! - config
//! - layers (at least when manifested as a merged filesystem tree)
//!
//! ### Possible approach: Manifest to fsverity digest verification in userspace
//!
//! There is widespread use of tools like [cosign](https://github.com/sigstore/cosign) to verify integrity of the manifest. It is possible to achieve our goal by just verifying the manifest on start (ensuring that e.g. the cosign trusted roots are first verified - a well understood problem).
//!
//! Once we verify the manifest, we can cheaply verify the config by checking its digest (it's just small JSON).
//!
//! Then if we embedded a digest for the composefs filesystem tree in the manifest (or config), we have efficiently established trust.
//!
//! This is strongly related to model effectively used by "sealed UKIs" today - the kernel command line is covered by Secure Boot, which includes the fsverity digest, and the initramfs mounting code checks that digest.
//!
//! ### Linux Kernel-based approach: Include fsverity signatures
//!
//! A different but more powerful alternative is to use a signature scheme supported by the Linux kernel to sign the fsverity digest, and include a signature for all three objects of the manifest, config and the EROFS.
//!
//! Each of these three things is a file, and when an image is unpacked, the signature can be applied to the file backing it.
//!
//! ### Composefs integrity metadata modes
//!
//! There are two modes for how trust can be established for an OCI image.
//!
//! - **composefs-meta-artifact**: An OCI artifact that only includes metadata: cryptographic checksums and signatures
//! - **composefs-meta-included**: Instead of a separate artifact, metadata is included inline in the manifest as annotations.
//!
//! #### Annotation key scheme
//!
//! Both modes use the same role-prefixed annotation keys. The role appears as the second component of the key, making each annotation self-describing regardless of where it appears.
//!
//! | Object | Digest annotation | Inline location |
//! |---|---|---|
//! | Per-layer EROFS | `composefs.layer.erofs.v1.fsverity-{alg}-{bs}` | On the layer descriptor |
//! | Merged EROFS | `composefs.merged.erofs.v1.fsverity-{alg}-{bs}` | Manifest top-level `annotations` |
//! | Merged boot variant | `composefs.merged.bootable.erofs.v1.fsverity-{alg}-{bs}` | Manifest top-level `annotations` |
//! | Config | `composefs.config.fsverity-{alg}-{bs}` | On the config descriptor |
//! | Manifest | `composefs.manifest.fsverity-{alg}-{bs}` | *(artifact mode only)* |
//!
//! Annotations live on the descriptor of the object they describe when one exists (layers, config). The merged EROFS has no descriptor in the image manifest, so its digest goes in the manifest's top-level `annotations`.
//!
//! The signature annotation key is simply the digest key with `.sig` appended (e.g. `composefs.merged.erofs.v1.fsverity-sha512-12.sig`). Signature values are base64-encoded PKCS#7 DER blobs — the exact format consumed by `FS_IOC_ENABLE_VERITY` after decoding. In artifact mode the signature travels as a raw layer blob rather than a base64 annotation, but the digest annotation keys are identical across both modes.
//!
//! The `erofs.v1` segment in EROFS annotation keys denotes version 1 of the composefs EROFS metadata format. It appears only on annotations whose digest covers a locally-generated EROFS object. Config and manifest annotations omit it because their digest is taken over the raw JSON bytes as stored in the registry — there is no composefs-specific format to version. This gives two annotation key shapes:
//!
//! - `composefs.{role}.erofs.v{N}.fsverity-{alg}-{bs}` — for EROFS objects (layer, merged, merged.bootable)
//! - `composefs.{role}.fsverity-{alg}-{bs}` — for plain JSON files (config, manifest)
//!
//! The `manifest` row applies to artifact mode only. Inline mode cannot represent a manifest digest or signature because adding the annotation would change the manifest bytes being signed — the document would be self-referential. Inline mode instead relies on out-of-band manifest trust (cosign, pinned digest, etc.).
//!
//! #### Choosing a mode
//!
//! The two modes reflect a tradeoff between logistical simplicity and capability.
//!
//! Artifact mode works with unmodified existing images: compute the composefs digests, optionally sign them, and push the result as a referrer. The original image is never touched. It also supports signing the manifest itself, providing the strongest possible chain of trust. The tradeoff is that the artifact must be copied alongside the image; tools that are unaware of the OCI referrers API will not propagate it automatically.
//!
//! Inline mode embeds everything directly in the image manifest, so a plain `skopeo copy` or any other OCI-aware tool will carry the composefs metadata along automatically. The cost is that the manifest itself cannot be signed (the annotation would change the bytes), and there is a tighter coupling between image generation and the signing step.
//!
//! | | Artifact mode | Inline mode |
//! |---|---|---|
//! | Works with unmodified images | Yes | No |
//! | Survives naive `skopeo copy` | No | Yes |
//! | Can sign manifest | Yes | No |
//! | Alters image manifest digest | No | Yes |
//! | Separate artifact required | Yes | No |
//!
//! #### OCI artifact based composefs metadata
//!
//! In this mode, additional digests (and optionally signatures) are shipped as an OCI artifact that acts as a "referrer" to the main OCI image. This is very similar to a [cosign](https://github.com/sigstore/cosign) signature.
//!
//! The OCI artifact includes:
//!
//! - At least one fsverity digest (+ optional signature) for a composefs-EROFS
//! - A fsverity digest+signature for the config
//! - A fsverity digest+signature for the manifest
//!
//! Like bootc sealed UKIs, it is required for EROFS generation to be exactly bit-for-bit reproducible across implementations.
//!
//! An `erofs.v1` composefs digest MUST be included, using either `fsverity-sha256-12` or `fsverity-sha512-12`. The `erofs.v1` in the key identifies the EROFS metadata format version, while `fsverity-{alg}-{bs}` identifies the digest algorithm and block size. The artifact MAY include alternate digests — this could mean both `sha256` and `sha512` for example. It is also possible to use `erofs.v2` or other block sizes in a future version.
//!
//! ##### Artifact Manifest
//!
//! The composefs artifact is an OCI image manifest following the [artifacts guidance](https://github.com/opencontainers/image-spec/blob/main/artifacts-guidance.md) pattern (empty config, content in layers), with `artifactType` set to `application/vnd.composefs.metadata.v1`.
//!
//! The artifact carries fsverity digests and optional signatures. Each layer has a role-prefixed annotation identifying the fsverity digest of the object it covers — using `composefs.{role}.erofs.v1.fsverity-{alg}-{bs}` for EROFS objects and `composefs.{role}.fsverity-{alg}-{bs}` for plain JSON files. The client always generates the EROFS locally using canonical generation and verifies it against the expected digest.
//!
//! ```json
//! {
//!   "schemaVersion": 2,
//!   "mediaType": "application/vnd.oci.image.manifest.v1+json",
//!   "artifactType": "application/vnd.composefs.metadata.v1",
//!   "config": {
//!     "mediaType": "application/vnd.oci.empty.v1+json",
//!     "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
//!     "size": 2
//!   },
//!   "layers": [
//!     {
//!       "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
//!       "digest": "sha256:aaa...",
//!       "size": 456,
//!       "annotations": {
//!         "composefs.manifest.fsverity-sha512-12": "ab12...manifest-fsverity-digest..."
//!       }
//!     },
//!     {
//!       "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
//!       "digest": "sha256:bbb...",
//!       "size": 789,
//!       "annotations": {
//!         "composefs.config.fsverity-sha512-12": "cd34...config-fsverity-digest..."
//!       }
//!     },
//!     {
//!       "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
//!       "digest": "sha256:ccc...",
//!       "size": 1234,
//!       "annotations": {
//!         "composefs.merged.erofs.v1.fsverity-sha512-12": "d015f70f8bee6c...merged-composefs-digest..."
//!       }
//!     },
//!     {
//!       "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
//!       "digest": "sha256:ddd...",
//!       "size": 1234,
//!       "annotations": {
//!         "composefs.merged.bootable.erofs.v1.fsverity-sha512-12": "e826a91b3c...boot-composefs-digest..."
//!       }
//!     }
//!   ],
//!   "subject": {
//!     "mediaType": "application/vnd.oci.image.manifest.v1+json",
//!     "digest": "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
//!     "size": 7682
//!   }
//! }
//! ```text
//!
//! The `merged` role refers to the complete flattened filesystem of all layers. The `merged.bootable` role refers to the boot variant — a modified EROFS that excludes `/boot` and applies other boot-specific transformations, as described in [Relationship to Booting with composefs](#relationship-to-booting-with-composefs) below.
//!
//! ##### Layer Ordering
//!
//! Each layer carries a role-prefixed annotation that identifies both the role and the fsverity digest of the covered object. This makes the artifact self-contained — a consumer can verify composefs digests using only the artifact and the image layers, without requiring composefs annotations on the original image manifest.
//!
//! The layers MUST appear in this order:
//!
//! 1. **(Optional)** One signature with `composefs.manifest.fsverity-*` annotation — signature for the sealed image manifest
//! 2. **(Optional)** One signature with `composefs.config.fsverity-*` annotation — signature for the image config
//! 3. One signature with `composefs.merged.erofs.v1.fsverity-*` annotation — signature for the merged EROFS representing the complete flattened filesystem
//! 4. **(Optional)** One signature with `composefs.merged.bootable.erofs.v1.fsverity-*` annotation — signature for the boot variant of the merged EROFS (with `/boot` excluded, etc.)
//!
//! This design enables signing existing unmodified OCI images: compute composefs digests, sign them, and push the composefs artifact as a referrer. The original image is never touched.
//!
//! ##### Signature Format
//!
//! Each signature layer blob is a raw PKCS#7 signature encoded using [DER](https://en.wikipedia.org/wiki/X.690#DER_encoding) (Distinguished Encoding Rules, ITU-T X.690) over the kernel's `fsverity_formatted_digest`:
//!
//! ```c
//! struct fsverity_formatted_digest {
//!     char magic[8];          /* "FSVerity" */
//!     __le16 digest_algorithm;
//!     __le16 digest_size;
//!     __u8 digest[];
//! };
//! ```text
//!
//! Composefs algorithm identifiers map to kernel constants with no salt:
//! - `fsverity-sha512-12` → `FS_VERITY_HASH_ALG_SHA512`, 4096-byte blocks
//! - `fsverity-sha256-12` → `FS_VERITY_HASH_ALG_SHA256`, 4096-byte blocks
//! - `fsverity-sha512-16` → `FS_VERITY_HASH_ALG_SHA512`, 65536-byte blocks
//! - `fsverity-sha256-16` → `FS_VERITY_HASH_ALG_SHA256`, 65536-byte blocks
//!
//! All entries in a single composefs artifact MUST use the same algorithm, which is encoded in the annotation key (e.g. `composefs.merged.erofs.v1.fsverity-sha512-12`).
//!
//! For manifest and config signatures, the fsverity digest is computed over the exact JSON bytes as stored in the registry. These files are stored locally with fsverity enabled so that reads are kernel-verified.
//!
//! ##### Discovery and Verification
//!
//! Discovery uses the standard [OCI Distribution Spec referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers):
//! ```text
//! GET /v2/<name>/referrers/<digest>?artifactType=application/vnd.composefs.metadata.v1
//! ```text
//!
//! Verification:
//!
//! 1. Check `subject` matches the sealed image manifest digest
//! 2. Read the role-prefixed annotations from the artifact layers to learn the expected fsverity digests for the manifest, config, merged EROFS, and (if present) the boot variant — using `composefs.{role}.erofs.v1.fsverity-*` for EROFS objects and `composefs.{role}.fsverity-*` for plain JSON files
//! 3. Generate the EROFS locally from the tar layers using canonical generation
//! 4. Compute the fsverity digest of the locally generated EROFS and verify it matches the expected digest
//! 5. If signature layers are present, apply them via `FS_IOC_ENABLE_VERITY` to the EROFS files
//!
//! The kernel handles PKCS#7 validation when signatures are used — failed verification prevents reading the file.
//!
//! ```text
//! External CA/Keystore
//!   ↓ issues certificate for .fs-verity keyring
//! PKCS#7 signatures (from artifact layers)
//!   ↓ applied via FS_IOC_ENABLE_VERITY to each file
//! Manifest JSON, Config JSON, EROFS blobs
//!   ↓ kernel fsverity enforcement on every read
//! Runtime file access
//! ```text
//!
//! ##### Implementation Considerations
//!
//! Kernel-level signature verification depends on Linux kernel fsverity (CONFIG_FS_VERITY, CONFIG_FS_VERITY_BUILTIN_SIGNATURES). Signature validation and file access enforcement are handled by the Linux kernel.
//!
//! When signatures are present, the manifest and config signature entries MUST also be present — there is no reason to sign the merged EROFS without also signing the manifest and config that reference it. The `merged.bootable` entry is optional and only relevant for bootable images.
//!
//! The composefs artifact carries digests and optional signatures. If an implementation uses digest-only verification (trusting the composefs digests via the manifest chain), it does not need a composefs artifact at all — the inline annotations on the image manifest (layer descriptors, config descriptor, and top-level annotations) are sufficient, and at minimum `merged` (plus `config`) must be present for that verification path.
//!
//! Clients that pull images with composefs artifacts are expected to also store the artifact locally alongside the image (it's just a small amount of metadata), and to attach the signatures to the corresponding files at the Linux kernel level. This enables offline verification and allows fsverity signatures to be applied when files are later accessed. However, local storage of the artifact is not strictly required — a client could re-fetch the artifact from the registry when needed, or operate in digest-only mode where the composefs digests themselves are trusted without kernel signature verification.
//!
//! ##### Media Types
//!
//! - `application/vnd.composefs.metadata.v1`: Artifact type for composefs metadata artifacts (digests + optional signatures)
//! - `application/vnd.composefs.signature.v1+pkcs7`: Layer media type for PKCS#7 DER signature blobs
//!
//! #### Inline composefs metadata
//!
//! In this mode, digests and optional signatures are embedded as annotations directly in the OCI image manifest. The main advantage is logistics: any standard OCI tool that copies the image will automatically carry the composefs metadata along, with no awareness of referrers or separate artifacts needed. The main disadvantage is that the manifest itself cannot be covered by a composefs digest or signature — adding the annotation would change the manifest bytes being signed, making the document self-referential. Trust in the manifest must therefore be established through other means, such as cosign signatures or referencing the image by a pinned digest that is itself verified out-of-band.
//!
//! When fsverity signatures are added in inline mode there is also a tighter coupling between signing and image generation: injecting the annotations changes the manifest digest, which is the most common identifier for an image. The underlying image can still be uniquely identified by its configuration digest, but tooling needs to be aware of this.
//!
//! ##### Digest-only example
//!
//! Each annotation lives on the descriptor of the object it describes. Per-layer EROFS digests go on the layer descriptor, the config fsverity digest goes on the config descriptor, and the merged EROFS digest goes in the manifest's top-level `annotations` (since there is no descriptor for the merged filesystem).
//!
//! ```json
//! {
//!   "schemaVersion": 2,
//!   "mediaType": "application/vnd.oci.image.manifest.v1+json",
//!   "config": {
//!     "mediaType": "application/vnd.oci.image.config.v1+json",
//!     "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
//!     "size": 7023,
//!     "annotations": {
//!       "composefs.config.fsverity-sha512-12": "cd34f91a2b3e5678901234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
//!     }
//!   },
//!   "layers": [
//!     {
//!       "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
//!       "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
//!       "size": 32654,
//!       "annotations": {
//!         "composefs.layer.erofs.v1.fsverity-sha512-12": "3abb6677af34ac57c0ca5828fd94f9d886c26ce59a8ce60ecf6778079423dccff1d6f19cb655805d56098e6d38a1a710dee59523eed7511e5a9e4b8ccb3a4686"
//!       }
//!     },
//!     {
//!       "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
//!       "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
//!       "size": 16724,
//!       "annotations": {
//!         "composefs.layer.erofs.v1.fsverity-sha512-12": "7f2b8a4e6c1d3f5a9b0e2d4c6a8f1e3b5d7c9a0b2e4f6d8a1c3e5b7d9f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c"
//!       }
//!     }
//!   ],
//!   "annotations": {
//!     "composefs.merged.erofs.v1.fsverity-sha512-12": "d015f70f8bee6cf6453dd5b771eec18994b861c646cec18e2a9dfdec93f631fbb9030e60cfc82b552d33b9a134312a876ef4e519bffe3ef872aefbd84e6198b3"
//!   }
//! }
//! ```text
//!
//! Each layer's `composefs.layer.erofs.v1.fsverity-sha512-12` covers the EROFS generated from that individual layer's tar content. The `composefs.config.fsverity-sha512-12` on the config descriptor covers the image config JSON as stored in the registry. The `composefs.merged.erofs.v1.fsverity-sha512-12` at the manifest level represents the complete flattened filesystem of all layers merged together.
//!
//! ##### Inline signatures example
//!
//! Signatures are added by appending `.sig` to the corresponding digest key. The value is a base64-encoded PKCS#7 DER blob — the same bytes that would appear raw in an artifact mode signature layer, just wrapped in base64 for transport as a JSON string.
//!
//! ```json
//! {
//!   "schemaVersion": 2,
//!   "mediaType": "application/vnd.oci.image.manifest.v1+json",
//!   "config": {
//!     "mediaType": "application/vnd.oci.image.config.v1+json",
//!     "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
//!     "size": 7023,
//!     "annotations": {
//!       "composefs.config.fsverity-sha512-12": "cd34f91a2b3e5678901234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
//!       "composefs.config.fsverity-sha512-12.sig": "MIIEpAIBAAKCAQEA7y2W9nMmQ4rPbSTf8xHuKzJeXdCwOqVvBjPfHl2qA6uZm0tD5nSc1iEkFbGhWxLP8UoVYdNa7RjMf3pOeQ9wCqIlZvBm4tYxKnGuBcWb..."
//!     }
//!   },
//!   "layers": [
//!     {
//!       "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
//!       "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
//!       "size": 32654,
//!       "annotations": {
//!         "composefs.layer.erofs.v1.fsverity-sha512-12": "3abb6677af34ac57c0ca5828fd94f9d886c26ce59a8ce60ecf6778079423dccff1d6f19cb655805d56098e6d38a1a710dee59523eed7511e5a9e4b8ccb3a4686"
//!       }
//!     },
//!     {
//!       "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
//!       "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
//!       "size": 16724,
//!       "annotations": {
//!         "composefs.layer.erofs.v1.fsverity-sha512-12": "7f2b8a4e6c1d3f5a9b0e2d4c6a8f1e3b5d7c9a0b2e4f6d8a1c3e5b7d9f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c"
//!       }
//!     }
//!   ],
//!   "annotations": {
//!     "composefs.merged.erofs.v1.fsverity-sha512-12": "d015f70f8bee6cf6453dd5b771eec18994b861c646cec18e2a9dfdec93f631fbb9030e60cfc82b552d33b9a134312a876ef4e519bffe3ef872aefbd84e6198b3",
//!     "composefs.merged.erofs.v1.fsverity-sha512-12.sig": "MIIEpAIBAAKCAQEA3x7V8mLkP2nQoRfT6wYsHzJdXcBvNqWuAiOeGk1pZ5tYl9sC4mRb0hDjEaFgVwKP7TnUXcMz6QiLe2oNdR8vBpHkYuAl3sXwJmFtOcZa..."
//!   }
//! }
//! ```text
//!
//! A few things worth noting about inline signatures:
//!
//! - The `.sig` values are base64-encoded PKCS#7 DER, identical in content to the raw blobs stored in artifact mode signature layers. To apply them locally, base64-decode the value and pass the result to `FS_IOC_ENABLE_VERITY`.
//! - There is no manifest signature in inline mode. Adding a `composefs.manifest.fsverity-sha512-12` annotation would alter the manifest bytes, invalidating any digest computed before the annotation was added.
//! - For large certificate chains, the base64-encoded signature annotation may be several kilobytes. If annotation size is a concern — for example, registries or tooling that imposes limits — use artifact mode instead, where signatures travel as separate layer blobs.
//!
//! #### Whiteout Handling in Merged Filesystem
//!
//! The merged EROFS represents a fully flattened filesystem and is designed to be mounted directly, not stacked with other EROFS layers via overlayfs. During the merge process, OCI whiteouts (`.wh.*` files and opaque directory markers) are fully processed: files and directories marked for deletion in upper layers are removed from the merged result. The final merged EROFS contains no whiteout entries — it is a clean, whiteout-free snapshot of the complete filesystem tree as it would appear after all layers are applied.
//!
//! ### Runtime verification
//!
//! #### Linux kernel fsverity signatures
//!
//! The primary signature mechanism is Linux kernel [fsverity built-in signature verification](https://docs.kernel.org/filesystems/fsverity.html#built-in-signature-verification). The kernel's `FS_IOC_ENABLE_VERITY` ioctl accepts a PKCS#7 signature that is verified against the `.fs-verity` keyring. This provides a clear chain of trust: the same component that controls data access (the Linux kernel) also validates the signature. The Linux kernel has subsystems that can build on top of fsverity signatures, such as [IPE](https://docs.kernel.org/admin-guide/LSM/ipe.html) (Integrity Policy Enforcement).
//!
//! #### Digest-only verification
//!
//! Verifying only the digest via userspace comparison with an expected digest (e.g. chaining from trust in the manifest to trust of the included digest) still allows efficient verification of the content, and the Linux kernel based fsverity enforcement of digests of individual objects ensures that malicious or accidental modifications are detected efficiently.
//!
//! However, because the Linux kernel did not itself establish trust in the digest, kernel based security systems such as IPE above are unaware of it.
//!
//! The userspace tooling performing this verification must itself be trusted. An operating system typically establishes this trust by running from a verified base — for example a bootc container configured as a "sealed UKI", or a root filesystem protected by dm-verity.
//!
//! A key benefit of composefs is that verification of large data is on-demand and continuous via the kernel's fsverity — the composefs digest covers the complete filesystem tree, so verifying it is cheap even though the underlying data may be large.
//!
//! #### Replacing diff_id validation
//!
//! The OCI image specification requires a `diff_id` in the [image config](https://github.com/opencontainers/image-spec/blob/main/config.md) for each layer, which is the digest of the uncompressed tar stream. This is expensive to validate after extraction and provides no path to continual kernel-enforced verification. With composefs, validating `diff_id` becomes redundant: the composefs digest already cryptographically covers the complete filesystem tree derived from the layer for the purposes of a runtime mount.
//!
//! It is however still useful for clients to verify `diff_id` when pushing a tar stream to a registry, etc.
//!
//! ## Storage model
//!
//! The composefs model is to store the manifest, config and the metadata EROFS all as files with fsverity enabled. For OCI containers, the layer tarballs are unpacked into the object store as well, with fsverity enabled on non-inline files.
//!
//! ## Relationship to Booting with composefs
//!
//! OCI sealing is independent from but complementary to the mechanism of "sealed UKIs" that embed a `composefs=` kernel command line digest.
//!
//! It is expected that boot-sealed images would *also* be OCI sealed, although this is not strictly required.
//!
//! One possible future direction for composefs/bootc UKIs would to instead load signing keys into the kernel fsverity chain from the initramfs (which may be the same or different keys used for application images), and use the composefs artifact signature scheme for mounting the root filesystem from the initramfs. However, a mechanism to determine which filesystem root to use would also be required.
//!
//! ## Future Directions
//!
//! ### Incremental Pulls
//!
//! The composefs digest for an EROFS includes fsverity digests of all content objects, so a client can determine which objects it already has locally and only fetch the missing ones from the tar layer. A minimal object-id to tar-stream offset map (shipped in the composefs metadata artifact) would serve as a table of contents for range-based fetching.
//!
//! A key advantage over existing approaches (zstd:chunked, eStargz) is that the composefs digest eliminates the need to verify the OCI `diff_id`, which in turn eliminates the need for tar-split metadata. The tar layer becomes purely a content delivery mechanism — each fetched object is verified independently by its fsverity digest.
//!
//! To push an incrementally-pulled image, the client must regenerate the tar layer deterministically. This requires a canonical tar format — see [`canonical_tar_spec`](crate::canonical_tar_spec).
//!
//! See [`incremental_pulls_spec`](crate::incremental_pulls_spec) for more design detail, including the composefs-chunked layer format, offset map structure, and pull protocol.
//!
//! ### Integration with zstd:chunked
//!
//! Both zstd:chunked and composefs add new digests to OCI images. The zstd:chunked table-of-contents (TOC) has high overlap with the composefs dumpfile format, as both are metadata about filesystem structure that identify files and their content. The TOC currently uses SHA256 while composefs requires fsverity.
//!
//! Adding fsverity to zstd:chunked TOC entries would allow using the TOC digest as a canonical composefs identifier. This would support a direct TOC → dumpfile → composefs pipeline, with a single metadata format serving both zstd:chunked and composefs use cases.
//!
//! ## References
//!
//! **Design discussion**: [composefs/composefs#294](https://github.com/composefs/composefs/issues/294)
//!
//! **Experimental implementations**:
//! - [composefs_experiments](https://github.com/allisonkarlitskaya/composefs_experiments)
//! - [composefs-oci-experimental](https://github.com/cgwalters/composefs-oci-experimental)
//!
//! **Related issues**:
//! - [containers/container-libs#108](https://github.com/containers/container-libs/issues/108) - fsverity in zstd:chunked TOC
//! - [containers/container-libs#112](https://github.com/containers/container-libs/issues/112) - per-layer vs flattened
//! - [composefs/composefs#409](https://github.com/composefs/composefs/issues/409) - non-root mounting
//!
//! **Standards**:
//! - [OCI Image Specification](https://github.com/opencontainers/image-spec)
//!
//! ## Contributors
//!
//! This specification synthesizes ideas from Colin Walters (original design proposals and iteration), Allison Karlitskaya (implementation and practical refinements), Alexander Larsson (security model and non-root mounting insights), and Giuseppe Scrivano (across the board) with assistance from Claude Sonnet 4.5 and Claude Opus 4.
