#!/bin/sh
set -eu

PREFIX="${1:-/usr/local}"
LIBDIR="${LIBDIR:-${PREFIX}/lib}"
INCLUDEDIR="${INCLUDEDIR:-${PREFIX}/include}"
PKGCONFIGDIR="${PKGCONFIGDIR:-${LIBDIR}/pkgconfig}"

VERSION="1.4.0"
SOVERSION="1"

# Find the built library
PROFILE="${PROFILE:-release}"
TARGETDIR="${CARGO_TARGET_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/target}"
SOFILE="${TARGETDIR}/${PROFILE}/libcomposefs_capi.so"
AFILE="${TARGETDIR}/${PROFILE}/libcomposefs_capi.a"

if [ ! -f "$SOFILE" ]; then
    echo "error: $SOFILE not found. Run 'cargo build --release -p composefs-capi' first." >&2
    exit 1
fi

install -d "${LIBDIR}" "${INCLUDEDIR}/libcomposefs" "${PKGCONFIGDIR}"

# Shared library with soname symlinks
install -m 755 "$SOFILE" "${LIBDIR}/libcomposefs.so.${VERSION}"
ln -sf "libcomposefs.so.${VERSION}" "${LIBDIR}/libcomposefs.so.${SOVERSION}"
ln -sf "libcomposefs.so.${SOVERSION}" "${LIBDIR}/libcomposefs.so"

# Static library
if [ -f "$AFILE" ]; then
    install -m 644 "$AFILE" "${LIBDIR}/libcomposefs.a"
fi

# Public headers only (private/ subdirectory is not installed)
SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
for h in "${SCRIPTDIR}"/include/libcomposefs/*.h; do
    install -m 644 "$h" "${INCLUDEDIR}/libcomposefs/"
done

# pkg-config
sed -e "s|@PREFIX@|${PREFIX}|g" \
    -e "s|@LIBDIR@|${LIBDIR}|g" \
    -e "s|@INCLUDEDIR@|${INCLUDEDIR}|g" \
    -e "s|@VERSION@|${VERSION}|g" \
    "${SCRIPTDIR}/composefs.pc.in" > "${PKGCONFIGDIR}/composefs.pc"

echo "Installed libcomposefs ${VERSION} to ${PREFIX}"
