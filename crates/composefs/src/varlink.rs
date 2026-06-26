//! # Varlink API
//!
//! `cfsctl varlink` exposes a [varlink] RPC service over a Unix socket
//! with two interfaces:
//!
//! - **`org.composefs.Repository`** — repository lifecycle, integrity
//!   checks, garbage collection, and mounting
//! - **`org.composefs.Oci`** — OCI container image operations (listing,
//!   pulling, inspecting, tagging, mounting)
//!
//! This API is language-agnostic and usable from any varlink client.
//! Like the Rust crate API, it is not yet declared stable.
//!
//! [varlink]: https://varlink.org
//!
//! ## Starting the service
//!
//! ```sh
//! cfsctl varlink --address /run/composefs/composefs.sock
//! ```
//!
//! Systemd socket activation is also supported — if `cfsctl varlink` is
//! started with an activated socket, the `--address` flag is not needed.
//!
//! ## Discovering the full API
//!
//! The complete interface definitions — every method, type, and error —
//! are available at runtime via the standard varlink introspection
//! protocol.  Use [`varlinkctl`] to dump them:
//!
//! ```sh
//! # List available interfaces
//! varlinkctl list-interfaces /run/composefs/composefs.sock
//!
//! # Full IDL for the Repository interface
//! varlinkctl introspect /run/composefs/composefs.sock \
//!     org.composefs.Repository
//!
//! # Full IDL for the OCI interface
//! varlinkctl introspect /run/composefs/composefs.sock \
//!     org.composefs.Oci
//! ```
//!
//! For `exec:`-style transports (no long-running socket), `varlinkctl`
//! can launch `cfsctl` as a subprocess:
//!
//! ```sh
//! varlinkctl introspect exec:cfsctl\ varlink org.composefs.Repository
//! ```
//!
//! [`varlinkctl`]: https://www.freedesktop.org/software/systemd/man/latest/varlinkctl.html
//!
//! ## Session model
//!
//! Repositories are accessed through opaque `u64` handles.  A client
//! calls `OpenRepository` to obtain a handle, passes it to every
//! subsequent method, and releases it with `CloseRepository`.  No
//! repository is opened at startup.
//!
//! ## Examples
//!
//! The examples below use `varlinkctl call`.  Any varlink client works —
//! the wire format is JSON over a Unix socket.
//!
//! ### Open and close a repository
//!
//! ```sh
//! # Open the system repository (/sysroot/composefs)
//! varlinkctl call /run/composefs/composefs.sock \
//!     org.composefs.Repository.OpenRepository '{"system": true}'
//! # → {"handle": 1}
//!
//! # Open at a specific path
//! varlinkctl call /run/composefs/composefs.sock \
//!     org.composefs.Repository.OpenRepository \
//!     '{"path": "/srv/composefs"}'
//! # → {"handle": 2}
//!
//! # Release a handle when done
//! varlinkctl call /run/composefs/composefs.sock \
//!     org.composefs.Repository.CloseRepository '{"handle": 1}'
//! ```
//!
//! ### Check repository integrity
//!
//! ```sh
//! # Full check (verifies fs-verity on every object)
//! varlinkctl call /run/composefs/composefs.sock \
//!     org.composefs.Repository.Fsck '{"handle": 1}'
//! # → {"ok": true, "has_metadata": true, "objects_checked": 1542, ...}
//!
//! # Fast metadata-only check (skips per-object verification)
//! varlinkctl call /run/composefs/composefs.sock \
//!     org.composefs.Repository.Fsck \
//!     '{"handle": 1, "metadata_only": true}'
//! ```
//!
//! ### List and pull OCI images
//!
//! ```sh
//! varlinkctl call /run/composefs/composefs.sock \
//!     org.composefs.Oci.ListImages '{"handle": 1}'
//! # → {"images": [{"name": "myimage:latest",
//! #     "manifest_digest": "sha256:abc...", ...}, ...]}
//!
//! # Pull with streaming progress
//! varlinkctl call --more /run/composefs/composefs.sock \
//!     org.composefs.Oci.Pull '{
//!       "handle": 1,
//!       "image": "quay.io/fedora/fedora:latest",
//!       "local_fetch": "decompressed",
//!       "bootable": false,
//!       "more": true
//!     }'
//! # Streams progress, then a final "completed" frame
//! ```
//!
//! ### Inspect, tag, and untag
//!
//! ```sh
//! varlinkctl call /run/composefs/composefs.sock \
//!     org.composefs.Oci.Inspect \
//!     '{"handle": 1, "image": "myimage:latest"}'
//! # → {"manifest": "{...}", "config": "{...}", ...}
//!
//! varlinkctl call /run/composefs/composefs.sock \
//!     org.composefs.Oci.Tag '{
//!       "handle": 1,
//!       "manifest_digest": "sha256:abc123...",
//!       "name": "myimage:v2"
//!     }'
//!
//! varlinkctl call /run/composefs/composefs.sock \
//!     org.composefs.Oci.Untag \
//!     '{"handle": 1, "name": "myimage:old"}'
//! ```
//!
//! ### Garbage collection
//!
//! ```sh
//! # Dry run
//! varlinkctl call /run/composefs/composefs.sock \
//!     org.composefs.Repository.Gc \
//!     '{"handle": 1, "dry_run": true, "roots": []}'
//!
//! # Collect for real
//! varlinkctl call /run/composefs/composefs.sock \
//!     org.composefs.Repository.Gc \
//!     '{"handle": 1, "dry_run": false, "roots": []}'
//! ```
//!
//! ### Mounting
//!
//! The `Mount` and `OciMount` methods return a detached mount file
//! descriptor via `SCM_RIGHTS`.  The caller attaches it with
//! `move_mount(2)`.  For overlay mounts, the caller passes upperdir and
//! workdir fds in the request.
//!
//! These methods require a varlink client that supports fd passing;
//! `varlinkctl` does not currently support this.
