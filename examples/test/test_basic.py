#!/usr/bin/python3

import os
from collections.abc import AsyncGenerator

import pytest

import testthing


@pytest.fixture
async def machine() -> AsyncGenerator[testthing.VirtualMachine, None]:
    image = os.getenv("TEST_IMAGE")
    if not image:
        raise RuntimeError("TEST_IMAGE environment variable must be set")
    with testthing.IpcDirectory() as ipc:
        async with testthing.VirtualMachine(image=image, ipc=ipc, verbose=True) as vm:
            yield vm


async def test_basic(machine: testthing.VirtualMachine) -> None:
    m = machine

    # root filesystem is read-only, or writable until a reboot with root.transient
    transient = bool(os.getenv("ROOT_TRANSIENT"))
    if transient:
        await m.execute("touch /a")
    else:
        with pytest.raises(testthing.SubprocessError):
            await m.execute("touch /a")

    # the content of /sysroot is what we expect
    expected = set[str](("composefs", "state"))
    if os.getenv("FS_FORMAT", "") in ("ext4", ""):
        expected.add("lost+found")

    output = await m.execute("ls /sysroot")
    assert set(output.splitlines()) == expected

    # make sure /etc and /var persist across a reboot
    await m.write("/etc/persists.conf", "hihi conf")
    await m.write("/var/persists.db", "hihi db")
    await m.reboot()
    if transient:
        with pytest.raises(testthing.SubprocessError):
            await m.execute("test -e /a")
    assert await m.execute("cat /etc/persists.conf") == "hihi conf"
    await m.execute("rm /etc/persists.conf")
    assert await m.execute("cat /var/persists.db") == "hihi db"
    await m.execute("rm /var/persists.db")
