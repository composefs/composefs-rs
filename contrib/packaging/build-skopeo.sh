#!/bin/bash
# Build skopeo with the splitfdstream support that `cfsctl oci pull` needs
# for containers-storage: images (skopeo's image proxy method
# OpenVarlinkSocket, protocol version >= 0.2.9).
#
# Distribution skopeo packages predate it, so the test image carries its own
# build.  The support is not in a container-libs release yet; once it is,
# this script (and the Containerfile stage that runs it) can go away.
#
# Usage: build-skopeo.sh DESTDIR
#
# SKOPEO_REPO/SKOPEO_REF and CONTAINER_LIBS_REPO/CONTAINER_LIBS_REF select
# the sources.
set -euo pipefail

# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

dest=${1:?usage: build-skopeo.sh DESTDIR}

skopeo_repo=${SKOPEO_REPO:-https://github.com/containers/skopeo}
skopeo_ref=${SKOPEO_REF:-main}
libs_repo=${CONTAINER_LIBS_REPO:-https://github.com/giuseppe/container-libs}
libs_ref=${CONTAINER_LIBS_REF:-splitfdstream}

case "${ID}" in
    centos|fedora|rhel) pkg_install golang git ;;
    debian|ubuntu) pkg_install golang-go git ca-certificates ;;
    *)
        echo "Unsupported distro: ${ID}" >&2
        exit 1
        ;;
esac

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

git clone --depth 1 --branch "${skopeo_ref}" "${skopeo_repo}" "${work}/skopeo"
git clone --depth 1 --branch "${libs_ref}" "${libs_repo}" "${work}/container-libs"
git -C "${work}/container-libs" log -1 --format='container-libs %H'

cd "${work}/skopeo"
for mod in storage common; do
    go mod edit -replace "go.podman.io/${mod}=${work}/container-libs/${mod}"
done
go mod edit -replace "go.podman.io/image/v5=${work}/container-libs/image"

# The distribution's Go may be older than the one skopeo asks for; let it
# fetch the newer toolchain.  The pure-Go build (no cgo, no btrfs or
# devicemapper) gives a static binary with no extra build dependencies.
export GOTOOLCHAIN=auto GOFLAGS=-mod=mod CGO_ENABLED=0
go mod tidy
go build -o "${dest}/skopeo" \
    -tags "containers_image_openpgp exclude_graphdriver_btrfs exclude_graphdriver_devicemapper" \
    ./cmd/skopeo
"${dest}/skopeo" --version
