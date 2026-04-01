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

# Verify cfsctl builds with each optional feature combination
check-feature-combos:
    cargo clippy -p cfsctl --no-default-features -- -D warnings
    cargo clippy -p cfsctl --no-default-features --features oci -- -D warnings
    cargo clippy -p cfsctl --no-default-features --features http -- -D warnings
    cargo clippy -p composefs-oci -- -D warnings
    cargo clippy -p composefs-oci --features boot -- -D warnings

# Run rustfmt check
fmt-check:
    cargo fmt --all -- --check

# Format code
fmt:
    cargo fmt --all

# Run all checks (clippy + fmt + test)
check: clippy check-feature-combos fmt-check test

# Base image for test container builds.
# Override to test on a different distro, e.g.:
#   just base_image=quay.io/centos-bootc/centos-bootc:stream10 test-integration-vm
base_image := env("COMPOSEFS_BASE_IMAGE", "ghcr.io/bootcrew/debian-bootc:latest")

# cfsctl feature flags for the container build.  Defaults match the base_image:
#   debian (>= 6.15 kernel): no compat features needed
#   centos stream10 (6.12):  pre-6.15
#   centos stream9 (5.14):   rhel9
cfsctl_features := env("COMPOSEFS_CFSCTL_FEATURES", "pre-6.15")

# Derive test image name from base_image
_test_image := if base_image =~ "debian" { "localhost/composefs-rs-test-debian:latest" } else if base_image =~ "stream9" { "localhost/composefs-rs-test-c9s:latest" } else { "localhost/composefs-rs-test:latest" }

# Run unprivileged integration tests against the cfsctl binary (no root, no VM)
test-integration: build
    CFSCTL_PATH=$(pwd)/target/debug/cfsctl cargo run -p integration-tests --bin cfsctl-integration-tests -- --skip privileged_

# Build the test container image for VM-based integration tests
_integration-container-build:
    podman build --build-arg base_image={{base_image}} --build-arg cfsctl_features={{cfsctl_features}} -t {{_test_image}} .

# Run all integration tests including privileged VM tests (requires podman + libvirt)
test-integration-vm: build _integration-container-build
    COMPOSEFS_TEST_IMAGE={{_test_image}} \
        CFSCTL_PATH=$(pwd)/target/debug/cfsctl \
        cargo run -p integration-tests --bin cfsctl-integration-tests

# Run everything: checks + full integration tests including VM
ci: check test-integration-vm

# Run a specific erofs fuzz target (e.g., `just fuzz read_image -- -max_total_time=60`)
fuzz target *ARGS:
    cd crates/composefs && cargo +nightly fuzz run {{target}} {{ARGS}}

# Run all erofs fuzz targets for a given duration each (default: 120 seconds)
fuzz-all seconds="120":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/fuzz-logs
    for target in $(cd crates/composefs && cargo +nightly fuzz list); do
        echo "--- Fuzzing $target for {{seconds}}s ---"
        log="target/fuzz-logs/$target.log"
        if (cd crates/composefs && cargo +nightly fuzz run "$target" -- -max_total_time={{seconds}}) > "$log" 2>&1; then
            echo "  $target: OK"
            tail -1 "$log"
        else
            echo "  $target: FAILED"
            cat "$log"
            exit 1
        fi
    done

# Generate seed corpus for fuzz targets
generate-corpus:
    cargo run --manifest-path crates/composefs/fuzz/Cargo.toml --bin generate-corpus

# List available fuzz targets
fuzz-list:
    cd crates/composefs && cargo +nightly fuzz list

# Clean build artifacts
clean:
    cargo clean
