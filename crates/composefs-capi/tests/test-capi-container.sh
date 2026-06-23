#!/bin/bash
# Run the C composefs test suite (test-checksums, test-units) against the
# Rust-built libcomposefs shared library inside a container.
#
# Usage: test-capi-container.sh [composefs-c-repo]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
C_REPO="${1:-}"

cargo build --release -p composefs-capi --manifest-path="$REPO_DIR/Cargo.toml"

BUILD_CTX=$(mktemp -d)
trap 'rm -rf "$BUILD_CTX"' EXIT

cp "$REPO_DIR/target/release/libcomposefs_capi.so" "$BUILD_CTX/"

if [ -n "$C_REPO" ]; then
    cp -a "$(cd "$C_REPO" && pwd)" "$BUILD_CTX/composefs-c"
else
    git clone --depth=1 https://github.com/composefs/composefs.git "$BUILD_CTX/composefs-c"
fi

podman build --no-cache -f "$SCRIPT_DIR/Containerfile.test-capi" "$BUILD_CTX"
