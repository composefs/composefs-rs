# Containerfile for composefs-rs integration testing
#
# Builds cfsctl and integration test binaries, then produces a bootable
# (bootc-compatible) container image suitable for privileged integration
# testing via `bcvk ephemeral run-ssh`.
#
# Build:
#   podman build --tag composefs-rs-test .
#   podman build --build-arg base_image=ghcr.io/bootcrew/debian-bootc:latest --tag composefs-rs-test-debian .
#
# Uses BuildKit-style cache mounts for fast incremental Rust builds.
# Note: when switching between base images locally, run
#   podman system prune --volumes
# to clear stale build caches that may be incompatible across distros.

ARG base_image=quay.io/centos-bootc/centos-bootc:stream10
ARG cfsctl_features=pre-6.15

# -- source snapshot (keeps layer graph clean) --
FROM scratch AS src
COPY . /src

# -- build stage --
FROM ${base_image} AS build
ARG cfsctl_features

COPY --from=src /src/contrib /src/contrib
RUN /src/contrib/packaging/install-build-deps.sh

COPY --from=src /src /src
WORKDIR /src

# Fetch dependencies (network-intensive, cached separately)
RUN --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo fetch

# Build cfsctl, the integration test binary and libcomposefs.
# Separate invocations: features are scoped to composefs-ctl and must not
# be passed to composefs-integration-tests, which has no optional features.
# libcomposefs only gets rhel9 (pre-6.15 is its default).
RUN --network=none \
    --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo build --release -p composefs-ctl --features="${cfsctl_features}" && \
    cargo build --release -p composefs-integration-tests && \
    capi_features=$(echo "${cfsctl_features}" | tr ', ' '\n\n' | grep -x rhel9 || true) && \
    cargo build --release -p composefs-capi --features="${capi_features}" && \
    cp /src/target/release/cfsctl /usr/bin/cfsctl && \
    cp /src/target/release/cfsctl-integration-tests /usr/bin/cfsctl-integration-tests && \
    mkdir -p /usr/lib/composefs-rs-test && \
    cp /src/target/release/libcomposefs_capi.so /usr/lib/composefs-rs-test/libcomposefs.so.1

# A C program calling our libcomposefs (not the distribution's), for the
# privileged libcomposefs tests
RUN --network=none \
    ln -s libcomposefs.so.1 /usr/lib/composefs-rs-test/libcomposefs.so && \
    gcc -o /usr/bin/lcfs-mount-test /src/crates/composefs-capi/tests/lcfs-mount-test.c \
        -I/src/crates/composefs-capi/include -L/usr/lib/composefs-rs-test -lcomposefs \
        -Wl,-rpath,/usr/lib/composefs-rs-test

# -- final bootable image --
FROM ${base_image}

COPY --from=src /src/contrib /src/contrib
RUN /src/contrib/packaging/install-test-deps.sh && rm -rf /src

COPY --from=build /usr/bin/cfsctl /usr/bin/cfsctl
COPY --from=build /usr/bin/cfsctl-integration-tests /usr/bin/cfsctl-integration-tests
COPY --from=build /usr/lib/composefs-rs-test /usr/lib/composefs-rs-test
COPY --from=build /usr/bin/lcfs-mount-test /usr/bin/lcfs-mount-test
