#!/bin/bash
# Install runtime / test dependencies for composefs-rs integration tests.
#
# This runs in the final bootable image and installs everything needed
# for `cfsctl-integration-tests` to run, including SSH and networking
# configuration for bcvk VM-based testing.
set -euo pipefail

# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

case "${ID}" in
    centos|fedora|rhel)
        pkg_install composefs openssl podman skopeo xfsprogs
        ;;
    debian|ubuntu)
        pkg_install \
            openssl e2fsprogs bubblewrap openssh-server \
            podman skopeo

        # OSTree symlink targets — /root, /home, /srv, etc. are symlinks
        # into /var on OSTree systems, so the target directories must exist.
        mkdir -p /var/roothome /var/home /var/srv /var/opt /var/mnt /var/local

        # Enable systemd-networkd with DHCP so that bcvk VMs get
        # network connectivity automatically.
        mkdir -p /etc/systemd/network
        printf '[Match]\nName=en*\n\n[Network]\nDHCP=yes\n' \
            > /etc/systemd/network/80-vm-dhcp.network
        systemctl enable systemd-networkd

        # Configure sshd for bcvk — allow root login with keys and
        # relax StrictModes (the OSTree symlink layout confuses the
        # ownership checks otherwise).
        mkdir -p /etc/ssh/sshd_config.d
        printf 'PermitRootLogin prohibit-password\nStrictModes no\n' \
            > /etc/ssh/sshd_config.d/99-bcvk.conf

        # Regenerate initramfs with the systemd-creds module so that
        # bcvk can import credentials into the VM at boot.
        for kdir in /usr/lib/modules/*/; do
            KVER=$(basename "${kdir}")
            dracut --force --add "systemd-creds" \
                "/usr/lib/modules/${KVER}/initramfs.img" "${KVER}"
        done
        ;;
    *)
        echo "Unsupported distro: ${ID}" >&2
        exit 1
        ;;
esac
