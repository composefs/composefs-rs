#!/bin/bash
# Tests for mount.composefs, adapted from composefs tests/test-units.sh
#
# Requires: root (for mount operations), fsverity-utils
# Usage: test-mount-composefs.sh /path/to/cfsctl

set -e

CFSCTL=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
test -x "$CFSCTL" || { echo "Usage: $0 /path/to/cfsctl" >&2; exit 1; }

# Its more likely that fsverity works in /var/tmp than in /tmp (which
# is typically tmpfs) so use that here.
export TMPDIR=${TMPDIR:-/var/tmp}

workdir=$(mktemp --directory --tmpdir lcfs-test.XXXXXX)
trap 'rm -rf -- "$workdir"' EXIT

. $(dirname $0)/test-lib.sh

function makeimage () {
    local dir=$1
    $CFSCTL mkcomposefs --digest-store=$dir/objects $dir/root $dir/test.cfs
}

function test_mount_digest () {
    local dir=$1

    if [ $has_fsverity = y ]; then
        echo foo > $dir/root/a-file
        makeimage $dir

        $CFSCTL mount.composefs -o basedir=$dir/objects,digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa $dir/test.cfs $dir/mnt 2> $dir/stderr && fatal "non-fsverity mount should not succeed"
        assert_file_has_content $dir/stderr "Image has no fs-verity"

        fsverity enable $dir/test.cfs

        $CFSCTL mount.composefs -o basedir=$dir/objects,digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa $dir/test.cfs $dir/mnt 2> $dir/stderr && fatal "wrong fsverity mount should not succeed"
        assert_file_has_content $dir/stderr "Image has wrong fs-verity"

        local DIGEST=$(fsverity measure $dir/test.cfs | awk "{ print \$1 }" | sed s/sha256://)

        # We should either successfully mount, or start trying and fail for one of these reasons:
        #  * Permission denied, if not root
        #  * No such file or directory, if /dev/loop-control is missing
        #  * Operation not permitted, when running in a sandbox
        # What should not happen is that it should fail for fs-verity reasons before trying to mount.
        $CFSCTL mount.composefs -o basedir=$dir/objects,digest=$DIGEST $dir/test.cfs $dir/mnt 2> $dir/stderr || assert_file_has_content $dir/stderr "Permission denied\|No such file or directory\|Operation not permitted"
        umount $dir/mnt 2> /dev/null || true
    fi
}

function test_mount_basic () {
    local dir=$1

    dd if=/dev/zero bs=1 count=1024 2>/dev/null > $dir/root/a-file
    makeimage $dir

    # Try to mount; we may not have root or the right kernel, so accept
    # permission/sandbox failures.
    $CFSCTL mount.composefs -o basedir=$dir/objects $dir/test.cfs $dir/mnt 2> $dir/stderr || {
        assert_file_has_content $dir/stderr "Permission denied\|No such file or directory\|Operation not permitted"
        return 0
    }

    # If we got here, mounting succeeded — verify the file exists
    test -f $dir/mnt/a-file || fatal "a-file not found in mount"

    umount $dir/mnt
}

TESTS="test_mount_basic test_mount_digest"
res=0
for i in $TESTS; do
    testdir=$(mktemp -d $workdir/$i.XXXXXX)
    mkdir $testdir/root $testdir/objects $testdir/mnt
    if $i $testdir ; then
        echo "Test $i: OK"
    else
        res=1
        echo "Test $i: FAILED"
    fi

    rm -rf $testdir
done

exit $res
