#!/bin/sh
# Generate source + vendor tarballs and a rewritten spec file for RPM builds.
# Used by Packit's create-archive action (see .packit.yaml).
#
# Produces in target/:
#   composefs-rs-$VERSION.tar.zstd         (source)
#   composefs-rs-$VERSION-vendor.tar.zstd  (vendored cargo deps)
#   composefs.spec                         (spec with Version/Source rewritten)
set -eu

NAME="composefs-rs"
SPEC_IN="contrib/packaging/composefs.spec"

cd "$(git rev-parse --show-toplevel)"
mkdir -p target

# Determine version: tagged release or timestamp.gABBREV snapshot
if v=$(git describe --tags --exact-match 2>/dev/null); then
    VERSION="${v#v}"
    VERSION=$(echo "$VERSION" | sed 's/-/./g')
else
    TIMESTAMP=$(date -u -d @"$(git show -s --format=%ct)" +%Y%m%d%H%M)
    ABBREV=$(git rev-parse --short=10 HEAD)
    VERSION="${TIMESTAMP}.g${ABBREV}"
fi

NAMEV="${NAME}-${VERSION}"
PREFIX="${NAMEV}/"
TAR="target/${NAMEV}.tar"
SRCTAR="target/${NAMEV}.tar.zstd"
VENDORTAR="target/${NAMEV}-vendor.tar.zstd"

echo "Version: ${VERSION}"

# Source tarball from git
git archive --format=tar --prefix="${PREFIX}" -o "${TAR}" HEAD

TMPDIR=$(mktemp -d -p target)
trap 'rm -rf "${TMPDIR}"' EXIT

# Vendor tarball via cargo-vendor-filterer, or with PACK_VENDOR=cargo via
# plain `cargo vendor` (larger, as it keeps all platforms, but needs no
# extra tools).
case "${PACK_VENDOR:-filterer}" in
    filterer)
        VENDOR_CONFIG=$(cargo vendor-filterer --prefix=vendor --format=tar.zstd "${VENDORTAR}")
        ;;
    cargo)
        VENDOR_CONFIG=$(cargo vendor "${TMPDIR}/vendor")
        tar -C "${TMPDIR}" --zstd -cf "${VENDORTAR}" vendor
        rm -rf "${TMPDIR}/vendor"
        ;;
    *)
        echo "error: unknown PACK_VENDOR=${PACK_VENDOR}" >&2
        exit 1
        ;;
esac

if test -z "${VENDOR_CONFIG}"; then
    echo "error: vendoring printed no source replacement config" >&2
    exit 1
fi

# Fix the vendor config to use a relative "vendor" directory
echo "${VENDOR_CONFIG}" | sed 's|^directory = ".*"|directory = "vendor"|' > "${TMPDIR}/vendor-config.toml"

# Embed .cargo/vendor-config.toml into the source tarball
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
tar -rf "${TAR}" \
    --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@${SOURCE_DATE_EPOCH}" \
    --transform="s,^,${PREFIX}.cargo/," \
    -C "${TMPDIR}" vendor-config.toml

# Compress source tarball
zstd --rm -f "${TAR}" -o "${SRCTAR}"

# Rewrite spec file
SRCNAME=$(basename "${SRCTAR}")
VENDORNAME=$(basename "${VENDORTAR}")
sed \
    -e "s|^Version:.*|Version: ${VERSION}|" \
    -e "s|^Source0:.*|Source0: ${SRCNAME}|" \
    -e "s|^Source1:.*|Source1: ${VENDORNAME}|" \
    "${SPEC_IN}" > target/composefs.spec

echo "Generated:"
echo "  ${SRCTAR}"
echo "  ${VENDORTAR}"
echo "  target/composefs.spec"
