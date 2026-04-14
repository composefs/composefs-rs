# Incremental Pulls via EROFS-alongside

Status: Provisional

There's two large things missing from OCI:

- dm-verity like integrity
- standard incremental fetching and deltas

The composefs artifact model fixes the first. This proposal builds on top of the composefs artifact, giving a model for incremental fetches.

## Core proposal

Existing approaches to incremental container image pulls (zstd:chunked and eStargz) embed a JSON table of contents (TOC) inside the compressed layer blob. The client reads the TOC, determines which file chunks it already has locally, and fetches missing chunks via HTTP range requests.

The two formats handle diff_id verification differently. zstd:chunked also embeds tar-split reconstruction data in the blob, allowing the client to reassemble the exact original uncompressed tar stream and verify its SHA-256 digest against the OCI `diff_id`. eStargz does *not* include tar-split, which means it cannot verify the diff_id at all; clients must set `insecure_allow_unpredictable_image_contents` to use it. This is a significant practical limitation of eStargz.

Composefs changes this picture fundamentally. In erofs-alongside mode, the EROFS metadata image (shipped as a separate OCI artifact) already contains the complete filesystem tree with fsverity digests for every content object. Composefs-based clients know the objects they already have, and using the metadata EROFS can compute which ones they are missing.

All that is needed then is a mapping between the fsverity digests and the location in the tar stream.

When the EROFS is trusted (via kernel fsverity signature or the OCI manifest signature chain covering the composefs digest), the `diff_id` verification becomes redundant: the composefs digest already cryptographically covers the complete filesystem tree. This eliminates the need for tar-split metadata entirely and simplifies the pull, verification, and push paths.

### Comparison with existing approaches

| Aspect | zstd:chunked | eStargz | composefs incremental |
|--------|-------------|---------|----------------------|
| TOC format | JSON in zstd skippable frame | JSON in gzip member | EROFS metadata (separate OCI artifact) |
| TOC reuse | Discarded after pull | Discarded after pull | Mounted directly by the kernel |
| Tar-split | Embedded in blob | Not available | Not needed |
| diff_id verification | Yes (via tar-split) | No (`insecure_allow_unpredictable_image_contents`) | Redundant (composefs digest covers the tree) |
| Content digests | SHA-256 | SHA-256 | fsverity (SHA-256 or SHA-512 Merkle tree) |
| Dedup granularity | Sub-file chunks (~64 KiB, rolling checksum) | Per-file | Whole files (by fsverity digest) |
| Kernel integration | None (userspace only) | None (userspace only) | EROFS + overlayfs + fsverity |
| Push after incremental pull | Reconstruct via tar-split | Cannot reconstruct original tar | Canonical tar generation (see below) |

## Design

### Layer Format: composefs-chunked

A composefs-chunked layer is a valid `tar+zstd` blob that any OCI client can pull and decompress normally. The difference is in how the zstd compression is structured internally: large files are compressed as independent zstd frames, making them individually addressable via byte offset.

Tar entries are in **canonical order**, the same deterministic ordering defined by the [canonical tar format](canonical-tar.md). This is essential: a client that does an incremental pull must be able to regenerate byte-identical tar for push, so the entry ordering cannot be compression-driven.

The zstd frame boundaries are an overlay on top of the canonical ordering. For files above a size threshold (e.g. 4 KiB), the compressor closes and restarts the zstd frame around the file's payload, making it independently decompressible. Files below the threshold are simply compressed together with their neighbors in whatever order they naturally appear. The threshold aligns with the filesystem block size.

Files ≤ 64 bytes are already inline in the EROFS metadata (`INLINE_CONTENT_MAX`) and are never fetched from the tar layer during an incremental pull, regardless of framing.

Unlike zstd:chunked, there are no trailing skippable frames (no embedded JSON TOC, no tar-split data). The EROFS in the composefs artifact serves as the TOC.

Unlike zstd:chunked, there is no sub-file content-defined chunking. Composefs deduplicates at the whole-file level (by fsverity digest), so rolling-checksum chunk boundaries provide no dedup benefit. This simplifies the format and the offset map.

### Offset Map

The offset map tells the client where each individually-framed file lives within the compressed layer blob. It is stored as an additional layer in the composefs OCI artifact, with media type `application/vnd.composefs.v1.offset-map`.

For each individually-compressed file, the map contains:

```
{ fsverity_digest, layer_index, byte_offset, compressed_size }
```

- `fsverity_digest`: the fsverity digest of the file content (matches the EROFS inode's content reference)
- `layer_index`: position in the image manifest's `layers` array (0-indexed)
- `byte_offset`: byte offset of the payload zstd frame within the compressed blob
- `compressed_size`: size of the compressed zstd frame in bytes

Only files above the individually-framed threshold have entries in the offset map. Files below the threshold that a client needs must be fetched by downloading the surrounding range or falling back to a full layer fetch (acceptable since these files are small by definition).

The format should be compact. A sorted array of fixed-size records (digest + u32 layer index + u64 offset + u64 size) works well and enables binary search by digest. For a layer with 10,000 individually-framed files using SHA-512 fsverity digests, the offset map is roughly 10,000 × (64 + 4 + 8 + 8) = ~820 KiB uncompressed, which compresses well.

### Pull Protocol

**Full pull (non-composefs client).** The layer is a valid tar+zstd blob. Pull, decompress, extract. Standard OCI behavior, no awareness of composefs needed.

**Incremental pull (composefs-aware client):**

1. Fetch the composefs artifact (EROFS layers + offset map + optional signatures)
2. Walk the EROFS metadata to extract the set of fsverity digests for all non-inline content objects
3. Query the local object store: which of these digests do we already have?
4. For missing digests, look up byte ranges in the offset map
5. Merge adjacent/nearby ranges to reduce HTTP requests (same optimization as zstd:chunked)
6. Issue HTTP range requests against the layer blob(s) to fetch missing objects
7. Decompress each frame independently, write to the object store, enable fsverity
8. Verify each object: the computed fsverity digest must match what the EROFS references

No tar reassembly, no diff_id verification, no tar-split. Trust is rooted in the EROFS (signed or digest-verified via the manifest chain), and each content object is independently verified by its fsverity digest.

### Push After Incremental Pull

An incrementally-pulled image does not have the original tar layer bytes stored locally. To push the image to another registry, the client must regenerate the tar layer. For the pushed image to be identical to the original (same layer digests, same manifest), this regeneration must be deterministic.

This requires a **canonical tar format**: a well-defined, reproducible mapping from filesystem metadata (EROFS or dumpfile) + content objects to a tar byte stream. See [canonical-tar.md](canonical-tar.md) for this specification.

With a canonical tar:
- The original image builder produces the tar using the canonical format
- An incrementally-pulling client can regenerate byte-identical tar from EROFS + object store
- The pushed image has the same layer digests and diff_id as the original
- The canonical tar can also be used to lazily verify the diff_id if needed, without storing tar-split

### Composefs Artifact Integration

The offset map is an additional layer in the existing composefs OCI artifact. In erofs-alongside mode with incremental pull support, the artifact layers are ordered:

1. N EROFS metadata layers (one per image layer, `application/vnd.composefs.v1.erofs+zstd` or `application/vnd.composefs.v1.erofs`)
2. N offset map layers (one per image layer, `application/vnd.composefs.v1.offset-map`)
3. *(Optional)* Signature layers (`application/vnd.composefs.signature.v1+pkcs7`)

Each offset map layer carries a `composefs.offset-map.type: "layer"` annotation and a `composefs.offset-map.layer-index` annotation identifying which manifest layer it corresponds to.

Layers that are not composefs-chunked (e.g. standard tar+gzip layers in a mixed image) simply have no offset map entry. A missing offset map for a layer means the client must fall back to a full fetch for that layer.

## Security Considerations

**Trust model.** The EROFS is the root of trust for the filesystem tree. Each content object fetched via range request is verified independently by computing its fsverity digest and comparing it to the EROFS reference. An attacker who controls the registry cannot serve incorrect content without detection, since the fsverity digest is a Merkle tree hash that the kernel enforces on every read after `FS_IOC_ENABLE_VERITY`.

**No tar-split, no diff_id.** By not verifying the diff_id, we are explicitly trusting the composefs digest chain rather than the OCI config's `rootfs.diff_ids`. This is a stronger verification (fsverity Merkle tree of the complete filesystem vs. flat SHA-256 of an opaque tar stream) but it does mean that a composefs-aware client and a non-composefs client may disagree if the tar and EROFS are inconsistent. The erofs-alongside consistency check (tar vs EROFS semantic comparison) at image seal time prevents this.

**Offset map integrity.** The offset map is part of the composefs artifact, which is covered by the artifact's manifest digest and optionally by signatures. A tampered offset map could point to wrong byte ranges, but the client verifies each fetched object's fsverity digest, so tampered offsets result in verification failure, not incorrect data.

## Future Directions

**Registry-level compression.** The [OCI distribution-spec proposal for registry-level compression](https://github.com/opencontainers/distribution-spec/issues/235) would allow registries to handle compression/decompression, serving uncompressed byte ranges from compressed blobs. This would eliminate the need for independent zstd framing entirely; the client could request raw byte ranges of uncompressed file content. The offset map would then contain offsets into the *uncompressed* tar stream, which are easier to compute (they fall out of tar generation directly).

**Sub-file chunking.** The current design operates at whole-file granularity. For images with very large files that change incrementally between versions (e.g. RPM databases, locale archives), sub-file content-defined chunking could reduce transfer sizes. The offset map format is extensible to support multiple entries per file. This is deferred as a non-goal for the initial design.

**Cross-layer dedup.** The composefs object store already deduplicates across layers (objects are stored by fsverity digest). The incremental pull protocol naturally benefits from this: if layer A and layer B share a file, pulling layer A populates the object store, and layer B's pull skips that file. No additional mechanism is needed.

## References

- [OCI sealing specification](oci-sealing-spec.md): erofs-alongside mode and composefs artifacts
- [Canonical tar format](canonical-tar.md): reproducible tar generation for push after incremental pull
- [Standardized EROFS metadata](standardized-erofs-meta.md): canonical EROFS generation (separate concern)
- [composefs/composefs#294](https://github.com/composefs/composefs/issues/294): original design discussion
- [zstd:chunked implementation](https://github.com/containers/storage/tree/main/pkg/chunked): reference for partial pull mechanics
- [OCI distribution-spec #235](https://github.com/opencontainers/distribution-spec/issues/235): registry-level compression proposal
