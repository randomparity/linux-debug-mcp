from __future__ import annotations

import errno
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class ProcessIdentity:
    """A pid plus a start-time fingerprint so pid reuse cannot cause a foreign match.
    `start_time` is an opaque string token (Linux: /proc stat field 19); None when the
    platform cannot supply one (e.g. macOS), which callers treat as 'unverifiable'."""

    pid: int
    start_time: str | None
    argv0: str | None


class ProcessIdentityProbe(Protocol):
    def identity(self, pid: int) -> ProcessIdentity | None: ...

    def is_alive(self, pid: int) -> bool: ...

    def looks_like(self, pid: int, name_substr: str) -> bool: ...

    def owns_listener(self, pid: int, host: str, port: int) -> bool | None: ...


class ProcProcessIdentityProbe:
    """Default Linux `/proc` implementation. The single home for the start-time
    fingerprint technique (ADR 0004); the qemu-gdbstub provider and the agent-proxy
    backend both consume this seam rather than re-reading /proc."""

    def identity(self, pid: int) -> ProcessIdentity | None:
        stat_path = Path("/proc") / str(pid) / "stat"
        try:
            stat_text = stat_path.read_text(encoding="utf-8")
        except OSError:
            return None
        _prefix, separator, suffix = stat_text.rpartition(") ")
        start_time: str | None = None
        if separator:
            fields = suffix.split()
            if len(fields) >= 20:
                start_time = fields[19]
        argv0 = self._argv0(pid)
        return ProcessIdentity(pid=pid, start_time=start_time, argv0=argv0)

    def is_alive(self, pid: int) -> bool:
        if self._is_zombie(pid):
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError as exc:
            return exc.errno != errno.ESRCH
        return True

    def looks_like(self, pid: int, name_substr: str) -> bool:
        argv0 = self._argv0(pid)
        if argv0 is None:
            return False
        return name_substr in Path(argv0).name

    def owns_listener(self, pid: int, host: str, port: int) -> bool | None:
        """True iff `pid` owns the LISTEN socket bound to the **exact** `host:port` we
        advertise. Returns None when ownership cannot be determined (no /proc/net, e.g.
        macOS, or our own fds are unreadable) so callers fail closed rather than treat
        'unknown' as proven. Matching is address-specific (round-5 F2): a foreign listener
        on 127.0.0.1:port while our child holds 127.0.1.1:port must NOT pass."""
        if not Path("/proc/net/tcp").exists():
            return None  # indeterminable (no /proc/net)
        inode = self._listen_inode(host, port)
        if inode is None:
            return False  # no LISTEN socket on the exact advertised host:port
        fd_dir = Path("/proc") / str(pid) / "fd"
        try:
            entries = list(fd_dir.iterdir())
        except OSError:
            return None  # cannot read our own fds → indeterminable, fail closed
        target = f"socket:[{inode}]"
        for entry in entries:
            try:
                if os.readlink(entry) == target:
                    return True
            except OSError:
                continue
        return False

    @staticmethod
    def _expected_addr_hex(host: str) -> str | None:
        """The /proc/net local-address hex (little-endian per 32-bit word) for `host`."""
        try:
            return f"{int.from_bytes(socket.inet_aton(host), 'little'):08X}"
        except OSError:
            pass
        try:
            packed = socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            return None
        return "".join(f"{int.from_bytes(packed[i : i + 4], 'little'):08X}" for i in range(0, 16, 4))

    def _listen_inode(self, host: str, port: int) -> str | None:
        expected = self._expected_addr_hex(host)
        if expected is None:
            return None
        proc_net = "/proc/net/tcp6" if len(expected) == 32 else "/proc/net/tcp"
        try:
            lines = Path(proc_net).read_text(encoding="utf-8").splitlines()[1:]
        except OSError:
            return None
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                continue
            addr_hex, _sep, port_hex = fields[1].rpartition(":")
            try:
                listening = fields[3] == "0A" and int(port_hex, 16) == port
            except ValueError:
                continue  # malformed /proc/net row — skip, never crash the probe
            if not listening:
                continue
            if addr_hex.upper() != expected:
                continue  # exact advertised address only (F2: 127.0.0.1 ≠ 127.0.1.1, ≠ 0.0.0.0)
            return fields[9]
        return None

    def _argv0(self, pid: int) -> str | None:
        cmdline_path = Path("/proc") / str(pid) / "cmdline"
        try:
            cmdline = cmdline_path.read_bytes()
        except OSError:
            return None
        if not cmdline:
            return None
        return cmdline.split(b"\0", 1)[0].decode("utf-8", errors="ignore")

    def _is_zombie(self, pid: int) -> bool:
        stat_path = Path("/proc") / str(pid) / "stat"
        try:
            stat_text = stat_path.read_text(encoding="utf-8")
        except OSError:
            return False
        _prefix, separator, suffix = stat_text.rpartition(") ")
        if not separator:
            return False
        fields = suffix.split()
        return bool(fields and fields[0] == "Z")
