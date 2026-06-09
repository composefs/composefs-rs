# Standardized EROFS Metadata Serialization

This document outlines the goal of standardizing how composefs serializes filesystem trees to EROFS metadata images.

## Relationship to OCI Sealing Modes

The [OCI sealing specification](oci-sealing-spec.md) defines two EROFS provisioning modes. This standardization work is specifically required for **canonical-EROFS mode**, where the client generates the EROFS locally and must produce a byte-identical result to what the server (or any other implementation) would generate.

**EROFS-alongside mode** does not require this standardization because the publisher ships the exact EROFS bytes to clients. EROFS-alongside can be used today without solving the problems described here.

However, even in erofs-alongside mode, a canonical dumpfile representation is valuable for the consistency check between the tar layer and the prebuilt EROFS (see erofs-alongside verification in the OCI sealing spec).

## Goal

Standardize how a filesystem tree, expressed canonically as a composefs dumpfile (or equivalent representation), is serialized to EROFS metadata. This enables reproducible EROFS generation across implementations and is a prerequisite for canonical-EROFS mode in the OCI sealing specification.

## Conceptual Model

The canonical transformation model is:

```
tar layer → dumpfile → EROFS metadata
```

Even when implementations optimize by going directly from tar to EROFS for efficiency, the canonical model remains tar → dumpfile → EROFS. This means:

1. Two implementations processing the same tar layer should produce equivalent dumpfiles
2. Two implementations processing the same dumpfile MUST produce byte-identical EROFS images
3. Therefore, two implementations processing the same tar layer should produce byte-identical EROFS images

The dumpfile serves as the canonical intermediate representation that defines the filesystem tree independent of serialization format.

## Why This Matters

- **Canonical-EROFS OCI sealing**: Canonical-EROFS mode in the OCI sealing specification depends entirely on this standardization. Without it, fsverity digests computed by different implementations would not match, and signatures would fail to verify.
- **Reproducible EROFS generation**: Given identical inputs, composefs-c, composefs-rs, and any future implementations must produce byte-for-byte identical EROFS images
- **Ecosystem compatibility**: Container runtimes, build tools, and registries can use different implementations interchangeably
- **UKI boot**: The sealed UKI boot model embeds a composefs digest in the kernel command line, which must match the EROFS generated at boot time — this is inherently a canonical-EROFS use case

Note: EROFS-alongside mode provides an alternative path that avoids these requirements, at the cost of shipping EROFS metadata on the registry. See [oci-sealing-spec.md](oci-sealing-spec.md) for a comparison.

## Current State

This standardization is a work in progress:

- **[composefs/composefs#423](https://github.com/composefs/composefs/discussions/423)**: Discussion on compatible EROFS output across implementations
- **[composefs-rs PR #225](https://github.com/composefs/composefs-rs/pull/225)**: Initial reimplementation of composefs-c in Rust, with compatible EROFS output as a key goal

## Open Questions

The following details need to be standardized (future work):

### EROFS Format Options
- EROFS format version and feature flags
- Block size (currently 4096)
- Compression settings (composefs uses uncompressed metadata)

### Inode Representation
- Compact vs extended inode format
- Inode numbering scheme
- Handling of hardlinks (inode sharing)

### Metadata Ordering
- Inode table ordering (depth-first? breadth-first? by path?)
- Directory entry ordering within directories
- Xattr key ordering within an inode
- Shared xattr table construction algorithm

### Content Handling
- Inline data threshold (currently ~64 bytes for external, but exact cutoff matters)
- External file references via overlay metacopy xattrs
- Symlink target storage

### OCI-Specific Concerns
- Whiteout representation (should not appear in final EROFS — processed during merge)
- Root inode metadata normalization (copying from `/usr`)
- Timestamp precision (seconds only, matching tar limitations)

## References

- [Splitstream binary format](../splitstream.md) — related binary format for storing tar data
- [OCI sealing specification](oci-sealing-spec.md) — depends on reproducible EROFS generation
- [EROFS documentation](https://docs.kernel.org/filesystems/erofs.html) — kernel filesystem documentation
