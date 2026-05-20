#!/usr/bin/python
# SPDX-License-Identifier: GPL-3.0-or-later

"""test.thing - A simple modern VM runner.

https://codeberg.org/lis/test.thing

A simple VM runner script exposing an API useful for use as a pytest fixture.
Can also be used to run a VM and login via the console.

Each VM is allocated an identifier: 'tt.0', 'tt.1', etc.

For each VM, an ephemeral ssh key is created and used to connect to the VM via
vsock with systemd-ssh-proxy, which works even if the guest doesn't have
networking configured.  The ephemeral key means that access is limited to the
current user (since vsock connections are otherwise available to all users on
the host system).  The guest needs to have systemd 256 for this to work.

An ssh control socket is created for sending commands and can also be used
externally, avoiding the need to authenticate.  A suggested ssh config:

```
Host tt.*
        ControlPath ${XDG_RUNTIME_DIR}/test.thing/%h/ssh
```

And then you can say `ssh tt.0` or `scp file tt.0:/tmp`.
"""

__version__ = "0.3.1"

import argparse
import asyncio
import contextlib
import ctypes
import functools
import itertools
import json
import logging
import os
import pathlib
import re
import shlex
import shutil
import signal
import socket
import sys
import traceback
import weakref
from collections.abc import AsyncGenerator, Callable, Iterable, Mapping
from pathlib import Path
from types import TracebackType
from typing import Never, Self

logger = logging.getLogger(__name__)


# This is basically tempfile.TemporaryDirectory but sequentially-allocated.
# We do that so we can easily interact with the VMs from outside (with ssh).
class IpcDirectory:
    """A context manager for the VM IPC directory.

    This is very similar to tempfile.TemporaryDirectory() except that the
    allocation is predictable (sequential): the created directory will be
    `/run/user/$uid/test.thing/tt.n` for the smallest `n` that we find.

    It works the same way:

        with IpcDirectory() as path:
            ...use path...

    The directory gets tagged with a `pid` file containing the pid and pidfd
    inode of the current process.  This could be helpful for pruning dead
    directories, but is currently unused.
    """

    finalizer: Callable[[], None] | None = None

    def __enter__(self) -> Path:
        """Create a unique directory.

        This will sequentially allocate the first available 'tt.0', 'tt.1',
        etc. directory and return it as a `Path`.
        """
        pid = os.getpid()
        pidfd = os.pidfd_open(pid)
        try:
            buf = os.fstat(pidfd)
            unique_id = f"{pid} {buf.st_ino}\n"
        finally:
            os.close(pidfd)

        tt_dir = Path(os.environ["XDG_RUNTIME_DIR"]) / "test.thing"
        for n in range(10000):
            tmpdir = tt_dir / f"tt.{n}"

            try:
                tmpdir.mkdir(exist_ok=False, parents=True, mode=0o700)
            except FileExistsError:
                continue

            self.finalizer = weakref.finalize(self, shutil.rmtree, tmpdir)
            (tmpdir / "pid").write_text(unique_id)
            return tmpdir

        raise FileExistsError

    def __exit__(self, *args: object) -> None:
        """Delete the IPC directory and its contents."""
        del args
        if self.finalizer:
            self.finalizer()


def _vsock_listen(family: socket.SocketKind) -> tuple[socket.socket, int]:
    """Bind a vsock to a free port number and start listening on it.

    Returns the socket and the chosen port number.
    """
    sock = socket.socket(socket.AF_VSOCK, family)
    sock.bind((-1, -1))
    sock.listen()
    _, port = sock.getsockname()
    return (sock, port)


async def _wait_stdin(msg: str) -> None:
    r"""Wait until stdin sees \n or EOF.

    This prints the given message to stdout without adding an extra newline.

    The input is consumed (and discarded) up to the \n and maybe more...
    """
    done = asyncio.Event()

    def stdin_ready() -> None:
        data = os.read(0, 4096)
        if not data:
            sys.stdout.write("\n")
        if not data or b"\n" in data:
            done.set()

    loop = asyncio.get_running_loop()
    loop.add_reader(0, stdin_ready)
    sys.stdout.write(msg)
    sys.stdout.flush()
    try:
        await done.wait()
    finally:
        loop.remove_reader(0)


def _normalize_args(
    *args: str | pathlib.PurePath | tuple[str | pathlib.PurePath, ...],
) -> Iterable[Iterable[str]]:
    for chunk in args:
        if not isinstance(chunk, tuple):
            yield (str(chunk),)
        elif len(chunk) != 0:
            yield map(str, chunk)


def _pretty_print_args(
    *args: str | pathlib.PurePath | tuple[str | pathlib.PurePath, ...],
) -> str:
    """Pretty-print a nested argument list.

    This takes the argument list format used by test.thing and turns it into a
    format that looks like a nicer version of `set -x` from POSIX shell.
    """
    if not any(isinstance(arg, tuple) for arg in args):
        # No tuples: use the boring format
        return shlex.join(map(str, args))

    # There are tuples: use the fancy format
    return " \\\n      ".join(map(shlex.join, _normalize_args(*args)))


def _find_qemu() -> Path:
    for candidate in ("qemu-kvm", "kvm"):
        if cmd := shutil.which(candidate):
            return Path(cmd)

    raise FileNotFoundError("Unable to find qemu-kvm")


def _find_ovmf() -> tuple[str | tuple[str, str], ...]:
    # Prefer split CODE+VARS pflash files (required on RHEL10/CentOS10 QEMU
    # where -bios with the combined file hangs).  Fall back to -bios with a
    # combined image for Ubuntu CI and Arch.
    split_candidates = [
        ("/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/edk2/ovmf/OVMF_VARS.fd"),
        ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
    ]
    for code, varst in split_candidates:
        if Path(code).exists() and Path(varst).exists():
            # Copy VARS so UEFI can write to it without modifying the original.
            import tempfile, shutil, atexit
            tmp = tempfile.NamedTemporaryFile(suffix=".fd", delete=False)
            shutil.copy2(varst, tmp.name)
            atexit.register(lambda p=tmp.name: Path(p).unlink(missing_ok=True))
            return (
                ("-machine", "q35"),
                ("-drive", f"if=pflash,format=raw,readonly=on,file={code}"),
                ("-drive", f"if=pflash,format=raw,file={tmp.name}"),
            )

    bios_candidates = [
        # path for Ubuntu (GitHub Actions runners)
        "/usr/share/ovmf/OVMF.fd",
        # path for Arch
        "/usr/share/edk2/x64/OVMF.4m.fd",
    ]
    for path in map(Path, bios_candidates):
        if path.exists():
            return (("-bios", str(path)),)

    raise FileNotFoundError("Unable to find OVMF UEFI BIOS")


async def _qmp_command(ipc: Path, command: str) -> object:
    reader, writer = await asyncio.open_unix_connection(ipc / "qmp")

    async def execute(command: str) -> object:
        writer.write((json.dumps({"execute": command}) + "\n").encode())
        await writer.drain()
        while True:
            response = json.loads(await reader.readline())
            if "event" in response:
                continue
            if "return" in response:
                return response["return"]
            raise RuntimeError(f"Got error response from qmp: {response!r}")

    # Trivial handshake (ignore them, send nothing)
    _ = json.loads(await reader.readline())
    await execute("qmp_capabilities")

    response = await execute(command)

    writer.close()
    await writer.wait_closed()

    return response


def _ssh_direct_args(
    ipc: Path, private: Path, port: int
) -> tuple[str | Path | tuple[str | Path, ...], ...]:
    options = {
        # Fake that we know the host key
        "KnownHostsCommand": "/bin/echo %H %t %K",
        # Use systemd-ssh-proxy to connect via vsock
        "ProxyCommand": f"/usr/lib/systemd/systemd-ssh-proxy vsock/{port} 22",
        "ProxyUseFdpass": "yes",
        # Try to prevent interactive prompting and/or updating known_hosts
        # files or otherwise interacting with the environment
        "BatchMode": "yes",
        "IdentitiesOnly": "yes",
        "PKCS11Provider": "none",
        "PasswordAuthentication": "no",
        "StrictHostKeyChecking": "yes",
        "UserKnownHostsFile": "/dev/null",
    }

    return (
        ("-F", "none"),  # don't use the user's config
        ("-i", private),
        *(("-o", f"{k} {v}") for k, v in options.items()),
        ("-l", "root"),
        ipc.name,  # the name is ignored but displayed in messages
    )


@functools.cache
def _stderr_is_tty() -> bool:
    return os.isatty(2)


class GuestPath(pathlib.PurePosixPath):
    """A path on the virtual machine guest.

    This aims to support similar operations to pathlib.Path (with similar
    APIs), but most operations are async and many have slightly different
    feature sets.
    """

    __slots__ = ("_vm",)

    def __init__(self, *args: str | os.PathLike[str], vm: "VirtualMachine") -> None:
        """Create a GuestPath for a path on a guest."""
        super().__init__(*args)
        self._vm = vm

    def with_segments(self, *pathsegments: str | os.PathLike[str]) -> Self:
        """Create a new path by combining the given pathsegments."""
        return type(self)(*pathsegments, vm=self._vm)

    async def mkdir(self, *, mode: int | None = None, parents: bool = False) -> None:
        """Create a directory."""
        await self._vm.execute(
            "mkdir",
            "-p" if parents else (),
            ("-m", f"{mode:0o}") if mode is not None else (),
            self,
        )

    async def chmod(self, mode: int | str, *, follow_symlinks: bool = True) -> None:
        """Change a file mode."""
        await self._vm.execute(
            "chmod",
            "-h" if not follow_symlinks else (),
            f"{mode:0o}" if isinstance(mode, int) else mode,
            self,
        )

    async def chown(
        self,
        owner: str | tuple[str | int | None, str | int | None],
        *,
        follow_symlinks: bool = True,
    ) -> None:
        """Change the owner of a file.

        The owner can be a string like 'user:group' or a pair of (user, group)
        where each can be a string, int, or None (to make no change).
        """
        if isinstance(owner, tuple):
            user, group = owner
            owner = f"{user or ''}:{group or ''}"

        await self._vm.execute(
            "chown", "-h" if not follow_symlinks else (), owner, self
        )

    async def write_bytes(self, data: bytes, *, append: bool = False) -> None:
        """Write or append to to a binary file."""
        await self._vm.execute(
            "dd",
            "status=none",
            ("conv=notrunc", "oflag=append") if append else (),
            f"of={self}",
            input=data,
        )

    async def read_text(self) -> str:
        """Read a text file."""
        return await self._vm.execute("cat", self)

    async def write_text(self, data: str, *, append: bool = False) -> None:
        """Write or append to a text file."""
        await self.write_bytes(data.encode(), append=append)

    async def unlink(
        self, *, missing_ok: bool = False, recursive: bool = False
    ) -> None:
        """Unlink the given file."""
        await self._vm.execute(
            "rm", "-f" if missing_ok else (), "-r" if recursive else (), self
        )

    async def rmdir(self) -> None:
        """Remove a directory."""
        await self._vm.execute("rmdir", self)


class VirtualMachine:
    """A handle to a running virtual machine.

    This is meant to be used as an async context manager like so:

    with IpcDirectory() as ipc:
        image = Path("...")
        async with VirtualMachine(image, ipc=ipc) as vm:
            await vm.execute("cat", "/usr/lib/os-release")

    The user of the context manager runs in context of an asyncio.TaskGroup and
    will be cancelled if anything unexpected happens (ssh connection lost, VM
    exiting, etc).

    When the context manager is exited the machine is taken down.

    When the machine is running it is also possible to access it from outside.
    See the documentation for the module.
    """

    """ssh command-line arguments for executing commands"""
    ssh_args: tuple[str | Path | tuple[str | Path, ...], ...]

    """ssh command-line arguments to be used to connect directly to the vsock"""
    ssh_direct_args: tuple[str | Path | tuple[str | Path, ...], ...] | None

    # our three background tasks
    _notify_server_task: asyncio.Task[None] | None = None
    _ssh_control_task: asyncio.Task[None] | None = None
    _qemu_task: asyncio.Task[None] | None = None

    def __init__(
        self,
        image: Path | str,
        *,
        ipc: Path,
        attach_console: bool = False,
        credentials: Mapping[str, str] = {},
        cpus: int = 4,
        identity: tuple[Path, str | None] | None = None,
        memory: int | str = "4G",
        sit: bool = False,
        snapshot: bool = True,
        status_messages: bool = False,
        timeout: float = 30.0,
        verbose: bool = False,
    ) -> None:
        """Construct a VM.

        The kwargs allow customizing the behaviour:
          - attach_console: if qemu should connect the console to stdio
          - credentials: extra system credentials
          - cpus: the number of CPUs
          - identity: a path to an ssh private key and the public key as a string.
            If the public key is specified as None then it won't be configured on
            the guest.  The default (None) is to generate an ephemeral keypair.
          - memory: how much memory the guest gets in MiB, or a string like "4G"
          - sit: if we should "sit" when an exception occurs: print the exception
            and wait for input (to allow inspecting the running VM)
          - snapshot: if the 'snapshot' option is used on the disk (changes are
            transient)
          - status_messages: if we should do output of status messages (stderr)
          - timeout: how long to wait for the VM to start, or 'inf'
          - verbose: if we should do output of verbose messages (stderr)
        """
        self.image = image
        self._ipc = ipc
        self._attach_console = attach_console
        self._cpus = cpus
        self._credentials = credentials
        self._identity = identity
        self._memory = memory
        self._sit = sit
        self._snapshot = snapshot
        self._status_messages = status_messages
        self._timeout = timeout
        self._verbose = verbose

        self._tasks = asyncio.TaskGroup()
        self._ssh_control_ready = asyncio.Event()
        self._qemu_exited = asyncio.Event()
        self._shutdown_ok = False

        self.root = GuestPath("/", vm=self)
        self.home = GuestPath(".", vm=self)

    async def _run(
        self,
        *args: str | Path | tuple[str | Path, ...],
        check: bool = True,
        stdin: int | None = None,
        stdout: int | None = None,
    ) -> int:
        """Run a process, waiting for it to exit.

        This takes the same arguments as _spawn, plus a "check" argument (True by
        default) which works in the usual way.
        """
        process = await self._spawn(*args, stdin=stdin, stdout=stdout)
        returncode = await process.wait()
        if check and returncode != 0:
            raise SubprocessError(args, returncode=returncode)
        return returncode

    def _clear_status_message(self) -> None:
        if _stderr_is_tty():
            sys.stderr.write("\r\033[2K")

    def _print_status(self, line: str) -> None:
        if self._status_messages:
            if os.isatty(2):
                sys.stderr.write("\r\033[2K  " + line + "\r")
            else:
                sys.stderr.write(line + "\n")

    def _print_verbose(self, line: str) -> None:
        if self._verbose:
            self._clear_status_message()
            sys.stderr.write(line + "\n")

    async def _spawn(
        self,
        *args: str | Path | tuple[str | Path, ...],
        stdin: int | None = None,
        stdout: int | None = None,
    ) -> asyncio.subprocess.Process:
        """Spawn a process.

        This has a couple of extra niceties: the args list is flattened, Path is
        converted to str, the spawned process is logged to stderr for debugging,
        and we call PR_SET_PDEATHSIG with SIGTERM after forking to make sure the
        process exits with us.

        The flattening allows grouping logically-connected arguments together,
        producing nicer verbose output, allowing for adding groups of arguments
        from helper functions or comprehensions, and works nicely with code
        formatters:

        For example:

        private = Path(...)
        options = { ... }

        ssh = await _spawn(
            "ssh",
            ("-i", private),
            *(("-o", f"{k} {v}") for k, v in options.items()),
            ("-l", "root", "x"),
            ...
        )

        The type of the groups is `tuple`.  It could be `Sequence` but this would
        also allow using bare strings, which would be split into their individual
        characters.  Using `tuple` prevents this from happening.
        """
        # This might be complicated: do it before the fork
        prctl = ctypes.CDLL(None, use_errno=True).prctl

        def pr_set_pdeathsig() -> None:
            PR_SET_PDEATHSIG = 1  # noqa: N806
            if prctl(PR_SET_PDEATHSIG, signal.SIGTERM):
                os._exit(1)  # should never happen

        if self._verbose:
            self._print_verbose(f"+ {_pretty_print_args(*args)}\n")

        return await asyncio.subprocess.create_subprocess_exec(
            *itertools.chain(*_normalize_args(*args)),
            stdin=stdin,
            stdout=stdout,
            preexec_fn=pr_set_pdeathsig,
        )

    async def _ssh_keygen(self) -> tuple[Path, str]:
        """Create a ssh key in the given directory.

        Returns the path to the private key and the public key as a string.
        """
        private_key = self._ipc / "id"

        await self._run(
            "ssh-keygen",
            "-q",  # quiet
            ("-t", "ed25519"),
            ("-N", ""),  # no passphrase
            ("-C", ""),  # no comment
            ("-f", f"{private_key}"),
            stdin=asyncio.subprocess.DEVNULL,
        )

        return private_key, (self._ipc / "id.pub").read_text().strip()

    def _sd_notify(self, line: str) -> None:
        logger.debug("sd_notify:%s", line)

        # Only print target updates when ssh is offline
        if self._ssh_control_task is not None:
            return

        key, _, value = line.partition("=")
        if key == "X_SYSTEMD_UNIT_ACTIVE":
            self._print_status(f"Reached target: {value}")
            # Waiting for ssh-access.target creates issues with pam_nologin
            if value == "multi-user.target":
                self._ssh_control_task = self._tasks.create_task(self._ssh_control())

        elif key == "X_SYSTEMD_UNIT_INACTIVE":
            self._print_status(f"Unit inactive: {value}")
        elif key == "X_SYSTEMD_SHUTDOWN":
            self._print_status(f"Shutdown: {value}")

    async def _sd_notify_connection(self, conn: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        try:
            while data := await loop.sock_recv(conn, 65536):
                for line in data.decode().splitlines():
                    self._sd_notify(line)

        finally:
            conn.close()

    async def _sd_notify_server(self, listener: socket.socket) -> None:
        """Listen on the socket for incoming sd-notify connections.

        `callback` is called with each notification.

        The socket is consumed and will be closed when the server exits (which
        happens via cancelling its task).
        """
        loop = asyncio.get_running_loop()

        # AbstractEventLoop.sock_accept() expects a non-blocking socket
        listener.setblocking(False)  # noqa: FBT003

        try:
            while True:
                conn, _ = await loop.sock_accept(listener)
                self._tasks.create_task(self._sd_notify_connection(conn))
        finally:
            # If we have a listener but don't accept the connections then the
            # guest can deadlock.  Make sure we close it when we exit.
            listener.close()

    async def _qemu(
        self,
        *,
        port: int,
        public: str | None,
    ) -> None:
        creds = {
            **self._credentials,
            "vmm.notify_socket": f"vsock:2:{port}",
        }

        if public is not None:
            creds["ssh.ephemeral-authorized_keys-all"] = public

        drive = f"file={self.image},format=qcow2,if=virtio,media=disk"
        if self._snapshot:
            # the image can still be written even with snapshot=true, using
            # an explicit commit, but readonly files are still protected.
            drive = drive + ",snapshot=on"

        # we don't have a good way to dynamically allocate guest-cid so we
        # assign it to the same numeric value as the port number the kernel
        # gave us when we created our notify-socket listener (which is unique)
        guest_cid = port

        args = (
            _find_qemu(),
            "-nodefaults",
            *_find_ovmf(),
            ("-cpu", "host"),
            ("-smp", f"{self._cpus}"),
            ("-m", f"{self._memory}"),
            ("-display", "none"),
            ("-qmp", f"unix:{self._ipc}/qmp,server,wait=off"),
            ("-device", f"vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid={guest_cid}"),
            # Console stuff...
            ("-device", "virtio-serial"),
            ("-device", "virtconsole,chardev=console"),
            (
                "-smbios",
                "type=11,value=io.systemd.boot.kernel-cmdline-extra=console=hvc0",
            ),
            *(
                (
                    ("-chardev", "stdio,mux=on,signal=off,id=console"),
                    ("-mon", "chardev=console,mode=readline"),
                )
                if self._attach_console
                else (
                    # In the cases that the console isn't directed to stdio
                    # then we write it to a log file instead.  Unfortunately,
                    # we also get a getty in our log file:
                    # https://github.com/systemd/systemd/issues/37928
                    ("-chardev", f"file,path={self._ipc}/console,id=console"),
                )
            ),
            ("-drive", drive),
            # Credentials
            *(
                ("-smbios", f"type=11,value=io.systemd.credential:{k}={v}")
                for k, v in creds.items()
            ),
        )

        qemu = None
        try:
            self._print_status("Waiting for guest")
            qemu = await self._spawn(*args)
            returncode = await qemu.wait()
            if not self._shutdown_ok:
                raise SubprocessError(args, returncode)
        except asyncio.CancelledError:
            logger.debug("qemu task cancelled")
            if qemu is not None:
                logger.debug("Terminating qemu")
                qemu.terminate()
                try:
                    logger.debug("Waiting for qemu to quit")
                    await asyncio.shield(asyncio.wait_for(qemu.wait(), 5))
                except TimeoutError:
                    logger.debug("Timed out -- killing qemu")
                    qemu.kill()
                    await asyncio.shield(qemu.wait())
        finally:
            logger.debug("qemu exited")
            self._qemu_exited.set()

    async def _ssh_control(self) -> None:
        ssh = None
        try:
            assert self.ssh_direct_args is not None

            self._print_status("ssh control socket: Connecting")

            control_socket = self._ipc / "ssh"

            args = (
                "ssh",
                *self.ssh_direct_args,
                ("-N", "-n"),  # no command, stdin disconnected
                ("-M", "-S", control_socket),  # listen on the control socket
            )
            ssh = await self._spawn(
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
            )

            # ssh sends EOF after the connection succeeds
            assert ssh.stdout
            await ssh.stdout.read()

            # ..but that might have been because of an error, so check if the
            # control socket actually exists
            if not control_socket.exists():
                raise SubprocessError(args, await ssh.wait())

            # we're online!
            self._ssh_control_ready.set()
            self._print_status("ssh control socket: Connected")
            self._clear_status_message()

            returncode = await ssh.wait()
            if not self._shutdown_ok:
                raise SubprocessError(args, returncode)
        except asyncio.CancelledError:
            if ssh is not None:
                ssh.terminate()
                await asyncio.shield(ssh.wait())
        finally:
            # We try to reset our state best as possible here to deal with
            # reboots in the shutdown_ok case: we want the control socket
            # reestablished when the machine comes back.
            self._ssh_control_ready.clear()
            self._ssh_control_task = None

    async def __aenter__(self) -> Self:
        """Start the virtual machine."""
        await self._tasks.__aenter__()

        self.ssh_args = (
            ("-F", "none"),  # don't use the user's config
            ("-S", self._ipc / "ssh"),  # connect via the control socket
            self._ipc.name,  # the name is ignored but displayed in messages
        )

        try:
            if self._identity is None:
                self._identity = await self._ssh_keygen()

            private, public = self._identity

            notify_listener, port = _vsock_listen(socket.SOCK_SEQPACKET)
            self.ssh_direct_args = _ssh_direct_args(self._ipc, private, port)

            # It goes like this:
            #  - we start listening on the sd-notify socket
            #  - we start qemu
            #  - at some point the guest will notify that ssh is ready
            #    - this causes us to spawn the ssh control task
            #  - once connected, _ssh_control_ready gets set
            #  - we wait for that, so when it's done, we're done

            self._notify_server_task = self._tasks.create_task(
                self._sd_notify_server(notify_listener)
            )

            self._qemu_task = self._tasks.create_task(
                self._qemu(port=port, public=public)
            )

            # the notify socket server will create the ssh control socket task
            # which, in turn, sets this ready once it's online.
            try:
                await asyncio.wait_for(self._ssh_control_ready.wait(), self._timeout)
            except TimeoutError as exc:
                self._clear_status_message()

                try:
                    log = (self._ipc / "console").read_text(errors="replace")
                except FileNotFoundError:
                    log = ""

                # Remove ANSI escapes and weird/excessive line endings
                log = re.sub(r"\033\[[0-9;]*[A-Za-z]", "", log)
                log_lines = re.split(r"[\r\n]+", log)

                lines = [
                    "Timed out waiting for the VM to start (after {self._timeout}s).",
                    "Console log:" if log_lines else "Console log unavailable.",
                    *log_lines,
                ]

                raise TimeoutError("\n".join(lines) + "\n") from exc

        except:
            exc_info = sys.exc_info()
            logger.debug("Startup failed: %r", exc_info)
            await self._tasks.__aexit__(*exc_info)
            raise
        else:
            logger.debug("Startup was successful")
            return self
        finally:
            logger.debug("Startup is done")
            self._clear_status_message()

    async def __aexit__(
        self,
        et: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Stop the virtual machine."""
        self._shutdown_ok = True

        try:
            if self._sit and exc is not None:
                current = asyncio.current_task()
                cancelled = current and current.cancelled()

                # This will report exceptions thrown from inside of the context managed
                # block but won't work properly in case we were cancelled due to an
                # error elsewhere (ie: qemu unexpectedly exiting) because at that point
                # the main task will have been cancelled and we won't be able to block
                # while waiting to read from stdin.  That's ok: the goal if this is to
                # catch test failures, not infra failures.
                if not cancelled:
                    sys.stderr.write(
                        f"\n🤦 {traceback.format_exception(et, exc, tb)}\n"
                    )
                    await self.sit()

            assert self._notify_server_task is not None
            self._notify_server_task.cancel()

            if self._ssh_control_task is not None:
                task = self._ssh_control_task
                task.cancel()
                await task

            # If we're in snapshot mode then we don't have to do a clean shutdown
            with contextlib.suppress(FileNotFoundError):
                await self.qmp("quit" if self._snapshot else "system_powerdown")

        finally:
            # If the TaskGroup fails (possibly by way of 'exc') and shutdown
            # also failed then the error from the shutdown will be suppressed.
            await self._tasks.__aexit__(et, exc, tb)
            if exc is not None:
                raise exc

    def get_id(self) -> str:
        """Get the machine identifier like `tt.0`, `tt.1`, etc."""
        return self._ipc.name

    async def wait_exit(self) -> None:
        """Wait for the VM to exit."""
        self._shutdown_ok = True
        await self._qemu_exited.wait()

    async def sit(self) -> None:
        """Wait for the user to press Enter."""
        # <pitti> lis: the ages old design question: does the button show
        # the current state or the future one when you press it :)
        # <lis> pitti: that's exactly my question.  by taking the one with
        # both then i don't have to choose! :D
        # <lis> although to be honest, i find your argument convincing.
        # i'll put the ⏸️ back
        # <pitti> lis: it was more of a joke -- I actually agree that a
        # play/pause button is nicer
        # <lis> too late lol
        await _wait_stdin("⏸️ ")

    async def _ssh_cmd(self, *args: tuple[str | Path, ...]) -> None:
        await self._run("ssh", *self.ssh_args, *args)

    async def forward_port(self, spec: str) -> None:
        """Set up a port forward.

        The `spec` is the format used by `ssh -L`, and looks something like
        `2222:127.0.0.1:22`.
        """
        return await self._ssh_cmd(("-O", "forward"), ("-L", spec))

    async def cancel_port(self, spec: str) -> None:
        """Cancel a previous forward."""
        return await self._ssh_cmd(("-O", "cancel"), ("-L", spec))

    async def execute(
        self,
        cmd: str,
        *args: str | GuestPath | tuple[str | GuestPath, ...],
        check: bool = True,
        direct: bool = False,
        input: bytes | str | None = b"",  # noqa:A002  # shadows `input()` but so does subprocess module
        environment: Mapping[str, str] = {},
        stdout: int | None = asyncio.subprocess.PIPE,
    ) -> str:
        """Execute a command on the guest.

        If a single argument is given, it is expected to be a valid shell
        script.  If multiple arguments are given, they will interpreted as an
        argument vector and will be properly quoted before being sent to the guest.
        """
        if args:
            cmd = shlex.join(itertools.chain(*_normalize_args(cmd, *args)))

        assert self.ssh_direct_args is not None
        full_command = (
            "ssh",
            *(self.ssh_direct_args if direct else self.ssh_args),
            ("--", "set -eu;"),
            tuple(f"export {k}={shlex.quote(v)};" for k, v in environment.items()),
            cmd,
        )

        ssh = await self._spawn(
            *full_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=stdout,
        )
        input_bytes = input.encode() if isinstance(input, str) else input
        output, _ = await ssh.communicate(input_bytes)
        returncode = await ssh.wait()
        if check and returncode != 0:
            raise SubprocessError(full_command, returncode, output)
        return output.decode()

    async def write(
        self,
        dest: str | GuestPath,
        content: str | bytes,
        *,
        mkdir: bool = True,
        owner: str | tuple[str | int | None, str | int | None] | None = None,
        perm: str | int | None = None,
    ) -> None:
        """Write a file into the test machine.

        Arguments:
            dest: The file name in the machine to write to
            content: Raw data to write to file
            append: If True, append to existing file instead of replacing it
            mkdir: if the parent directory should be created
            owner: If set, call chown on the file with the given owner string
            perm: Optional file permission as chmod shell string or integer

        """
        dest = GuestPath(dest, vm=self)

        if mkdir:
            await dest.parent.mkdir(parents=True)

        if isinstance(content, str):
            await dest.write_text(content)
        else:
            await dest.write_bytes(content)

        if owner is not None:
            await dest.chown(owner)

        if perm:
            await dest.chmod(perm)

    @contextlib.asynccontextmanager
    async def disconnected(self) -> AsyncGenerator[None]:
        """Temporarily disconnect the control socket.

        On enter, disconnect the ssh control socket from the guest system.
        Inside of the block it's possible to perform commands that would
        otherwise result in the control socket being destroyed (which would be
        a hard error).

        On exit from the block, the connection is reestablished.

        The most obvious use-case for this is rebooting.
        """
        assert self._ssh_control_task is not None
        assert self._ssh_control_ready.is_set()
        self._ssh_control_ready.clear()
        self._ssh_control_task.cancel()
        self._ssh_control_task = None

        try:
            yield
        finally:
            await self._ssh_control_ready.wait()

    async def reboot(self) -> None:
        """Reboot the guest, waiting until it's back online."""
        async with self.disconnected():
            await self.execute("reboot", direct=True)

    async def qmp(self, command: str) -> object:
        """Send a QMP command to the hypervisor.

        This can be used for things like modifying the hardware configuration.
        Don't power it off this way: the correct way to stop the VM is to exit
        the context manager.
        """
        return await _qmp_command(self._ipc, command)


class SubprocessError(Exception):
    """An exception thrown when a subprocess failed unexpectedly."""

    def __init__(
        self,
        args: tuple[str | Path | tuple[str | Path, ...], ...],
        returncode: int,
        output: bytes | None = None,
    ) -> None:
        """Create a SubprocessError instance.

        - args: the arguments to the command that failed
        - returncode: the non-zero return code
        """
        self.args = args
        self.returncode = returncode
        self.output = output

        if returncode < 0:
            msg = f"Subprocess terminated by {signal.Signals(-returncode).name}"
        else:
            msg = f"Subprocess exited unexpectedly with return code {returncode}:\n"

        super().__init__(f"{msg}\n{_pretty_print_args(*args)}\n\n")


def cleanup_on_signal() -> None:
    """Register SIGHUP and SIGTERM signal handlers to cleanly exit.

    This raises an exception, cleaning up running subprocesses and the IPC
    directory, in contrast to the default interpreter behaviour of a direct
    exit.
    """

    def _term(*args: object) -> Never:
        del args
        # This raises SystemExit which will bubble out of the handler
        sys.exit("I don't blame you.")

    signal.signal(signal.SIGHUP, _term)
    signal.signal(signal.SIGTERM, _term)


def _main() -> None:
    parser = argparse.ArgumentParser(
        description="test.thing - a simple modern VM runner"
    )
    parser.add_argument(
        "--maintain", "-m", action="store_true", help="Changes are permanent"
    )
    parser.add_argument(
        "--attach", "-a", action="store_true", help="Attach to the VM console"
    )
    parser.add_argument(
        "--sit", "-s", action="store_true", help="Wait for enter key on exceptions"
    )
    parser.add_argument(
        "--debug", "-d", action="store_true", help="Enable debug output"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print verbose output"
    )
    parser.add_argument(
        "--ssh-key", "-i", type=Path, help="Path to SSH private key (default: generate)"
    )
    parser.add_argument(
        "--timeout", type=float, help="For startup, in seconds, or 'inf' (default: 30)"
    )
    parser.add_argument("image", type=Path, help="The path to a qcow2 VM image to run")
    args = parser.parse_args()

    identity = (args.ssh_key, None) if args.ssh_key else None

    async def _async_main() -> None:
        cleanup_on_signal()

        with IpcDirectory() as ipc:
            async with VirtualMachine(
                args.image,
                ipc=ipc,
                attach_console=args.attach,
                identity=identity,
                sit=args.sit,
                snapshot=not args.maintain,
                status_messages=not args.attach,
                timeout=args.timeout,
                verbose=args.verbose,
            ) as vm:
                if not args.attach:
                    await _wait_stdin(
                        f"\nVM running: {vm.get_id()}\n\nEnter or EOF to exit ⏸️ "
                    )
                else:
                    await vm.wait_exit()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    try:
        asyncio.run(_async_main(), debug=args.debug)
    except* (SubprocessError, TimeoutError) as eg:
        for exc in eg.exceptions:
            sys.stdout.write(f"{exc}\n")
        sys.exit("I'm sorry it didn't work out.")


if __name__ == "__main__":
    _main()
