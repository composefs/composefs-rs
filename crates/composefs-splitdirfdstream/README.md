# composefs-splitdirfdstream

A data format and IPC protocol for sending a binary stream across local
processes via file descriptor passing (DBus, varlink, etc.). Designed for
sending tar archives of container image layers that are unpacked into a storage
system such as composefs or docker/podman `overlay` storage.

See the [crate documentation](https://docs.rs/composefs-splitdirfdstream) (or
run `cargo doc --open`) for the wire format, chunk layouts, limits, safety
model, and API surface.

## License

Licensed under the same terms as the
[composefs-rs](https://github.com/containers/composefs-rs) workspace.
