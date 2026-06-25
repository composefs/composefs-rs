#!/bin/bash
# Test helper functions, adapted from composefs test-lib.sh

fatal() {
    echo $@ 1>&2; exit 1
}

_fatal_print_file() {
    file="$1"
    shift
    ls -al "$file" >&2
    sed -e 's/^/# /' < "$file" >&2
    fatal "$@"
}

assert_file_has_content () {
    fpath=$1
    shift
    for re in "$@"; do
        if ! grep -q -e "$re" "$fpath"; then
            _fatal_print_file "$fpath" "File '$fpath' doesn't match regexp '$re'"
        fi
    done
}

assert_streq () {
    if test "$1" != "$2"; then
        echo "assertion failed: $1 = $2" 1>&2
        return 1
    fi
}

check_fsverity () {
    fsverity --version >/dev/null 2>&1 || return 1
    tmpfile=$(mktemp --tmpdir lcfs-fsverity.XXXXXX)
    echo foo > $tmpfile
    fsverity enable $tmpfile >/dev/null 2>&1  || return 1
    return 0
}

[[ -v has_fsverity ]] || has_fsverity=$(if check_fsverity; then echo y; else echo n; fi)

echo Test options: has_fsverity=$has_fsverity
