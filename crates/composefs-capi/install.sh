#!/bin/sh
set -eu

PREFIX="${1:-/usr/local}"
LIBDIR="${LIBDIR:-${PREFIX}/lib}"
INCLUDEDIR="${INCLUDEDIR:-${PREFIX}/include}"
PKGCONFIGDIR="${PKGCONFIGDIR:-${LIBDIR}/pkgconfig}"
DESTDIR="${DESTDIR:-}"

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

install -d "${DESTDIR}${LIBDIR}" "${DESTDIR}${INCLUDEDIR}/libcomposefs" "${DESTDIR}${PKGCONFIGDIR}"

# Shared library with soname symlinks
install -m 755 "$SOFILE" "${DESTDIR}${LIBDIR}/libcomposefs.so.${VERSION}"
ln -sf "libcomposefs.so.${VERSION}" "${DESTDIR}${LIBDIR}/libcomposefs.so.${SOVERSION}"
ln -sf "libcomposefs.so.${SOVERSION}" "${DESTDIR}${LIBDIR}/libcomposefs.so"

# Static library
if [ -f "$AFILE" ]; then
    install -m 644 "$AFILE" "${DESTDIR}${LIBDIR}/libcomposefs.a"
fi

# Public headers only (private/ subdirectory is not installed)
SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
for h in "${SCRIPTDIR}"/include/libcomposefs/*.h; do
    install -m 644 "$h" "${DESTDIR}${INCLUDEDIR}/libcomposefs/"
done

# pkg-config (use non-DESTDIR paths so the .pc file is relocatable)
sed -e "s|@PREFIX@|${PREFIX}|g" \
    -e "s|@LIBDIR@|${LIBDIR}|g" \
    -e "s|@INCLUDEDIR@|${INCLUDEDIR}|g" \
    -e "s|@VERSION@|${VERSION}|g" \
    "${SCRIPTDIR}/composefs.pc.in" > "${DESTDIR}${PKGCONFIGDIR}/composefs.pc"

echo "Installed libcomposefs ${VERSION} to ${DESTDIR}${PREFIX}"
