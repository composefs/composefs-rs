#!/bin/bash
# Shared helpers for composefs-rs packaging scripts.
#
# Sources /etc/os-release and provides distro-agnostic functions for
# bootstrapping APT on debian-bootc images and installing packages.

# shellcheck source=/dev/null
. /etc/os-release
export ID

# debian_apt_init — bootstrap the /var directory structure that APT and
# dpkg need to function.  debian-bootc images use OSTree's /var as a
# mutable state partition, so it starts completely empty.  This is
# idempotent and safe to call multiple times.
debian_apt_init() {
    mkdir -p /var/lib/apt/lists/partial \
             /var/lib/dpkg/info /var/lib/dpkg/updates /var/lib/dpkg/triggers \
             /var/cache/apt/archives/partial \
             /var/log /run/lock
    touch /var/lib/dpkg/status /var/lib/dpkg/available
}

# pkg_install PACKAGE... — install packages using the system package
# manager.  On Debian/Ubuntu this handles the full APT bootstrap cycle;
# on Fedora/CentOS/RHEL it uses dnf.
#
# APT::Sandbox::User=root works around setgroups(2) failures that happen
# inside rootless podman builds where the process cannot change groups.
pkg_install() {
    case "${ID}" in
        centos|fedora|rhel)
            dnf install -y "$@"
            dnf clean all
            ;;
        debian|ubuntu)
            export DEBIAN_FRONTEND=noninteractive
            debian_apt_init
            apt-get -o APT::Sandbox::User=root update
            apt-get -o APT::Sandbox::User=root \
                    -o Dpkg::Options::="--force-confold" \
                    -o Dpkg::Options::="--force-confdef" \
                install -y --no-install-recommends "$@"
            rm -rf /var/lib/apt/lists/*
            ;;
        *)
            echo "Unsupported distro: ${ID}" >&2
            return 1
            ;;
    esac
}
