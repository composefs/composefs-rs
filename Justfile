# Justfile for composefs-rs
# Run `just --list` to see available targets.
# --------------------------------------------------------------------

mod bootc

# Build all crates
build:
    cargo build --workspace

# Build in release mode
build-release:
    cargo build --workspace --release

# Run unit tests (excludes integration-tests crate)
test:
    cargo test --workspace --exclude integration-tests

# Run clippy lints
clippy:
    cargo clippy --workspace -- -D warnings

# Run rustfmt check
fmt-check:
    cargo fmt --all -- --check

# Format code
fmt:
    cargo fmt --all

# Run all checks (clippy + fmt + test)
check: clippy fmt-check test

COMPOSEFS_TEST_IMAGE := "localhost/composefs-rs-test:latest"

# Run integration tests (builds cfsctl first); pass extra args to the harness
test-integration *ARGS: build
    CFSCTL_PATH=$(pwd)/target/debug/cfsctl cargo run -p integration-tests --bin cfsctl-integration-tests -- {{ ARGS }}

# Run only the fast unprivileged integration tests (no root, no VM)
integration-unprivileged: build
    CFSCTL_PATH=$(pwd)/target/debug/cfsctl cargo run -p integration-tests --bin cfsctl-integration-tests -- --skip privileged_

# Build the test container image for VM-based integration tests
integration-container-build:
    podman build -t {{COMPOSEFS_TEST_IMAGE}} -f Containerfile .

# Run all integration tests; privileged tests dispatch to a bcvk VM
integration-container: build integration-container-build
    COMPOSEFS_TEST_IMAGE={{COMPOSEFS_TEST_IMAGE}} \
        CFSCTL_PATH=$(pwd)/target/debug/cfsctl \
        cargo run -p integration-tests --bin cfsctl-integration-tests

# Run all tests with all features enabled
test-all:
    cargo test --workspace --all-features

# Build with containers-storage feature
build-cstorage:
    cargo build --workspace --features containers-storage

# Run integration tests (requires podman and skopeo)
integration-test: build-release
    cargo run --release -p integration-tests --bin integration-tests

# Clean build artifacts
clean:
    cargo clean
