#!/usr/bin/bash

check() {
    return 0
}

depends() {
    return 0
}

install() {
    inst \
        "/usr/bin/strace" /bin/strace
    inst \
        "${moddir}/composefs-setup-root" /bin/composefs-setup-root
    inst \
        "${moddir}/composefs-setup-root.service" \
        "${systemdsystemunitdir}/composefs-setup-root.service"
    if [ -e "${moddir}/setup-root-conf.toml" ]; then
        inst \
            "${moddir}/setup-root-conf.toml" /usr/lib/composefs/setup-root-conf.toml
    fi

    $SYSTEMCTL -q --root "${initdir}" add-wants \
        'initrd-root-fs.target' 'composefs-setup-root.service'
}
