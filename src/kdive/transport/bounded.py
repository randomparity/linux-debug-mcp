from __future__ import annotations

import os
import select
import socket
import stat
import subprocess  # nosec B404
import threading
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass


class BoundedIOTimeout(TimeoutError):
    """A bounded IO step did not complete before its deadline."""


class BoundedIOCancelled(Exception):
    """A bounded IO step observed its cancel event set."""


@dataclass(frozen=True)
class Deadline:
    """A monotonic deadline. `remaining()` never goes negative."""

    at: float
    clock: Callable[[], float] = time.monotonic

    @classmethod
    def after(cls, seconds: float, *, clock: Callable[[], float] = time.monotonic) -> Deadline:
        return cls(clock() + seconds, clock=clock)

    def remaining(self) -> float:
        return max(0.0, self.at - self.clock())

    def expired(self) -> bool:
        return self.remaining() <= 0.0


def check_not_cancelled(cancel: threading.Event) -> None:
    if cancel.is_set():
        raise BoundedIOCancelled("operation cancelled")


def _slice(deadline: Deadline, cancel: threading.Event) -> float:
    check_not_cancelled(cancel)
    remaining = deadline.remaining()
    if remaining <= 0.0:
        raise BoundedIOTimeout("deadline exceeded")
    return remaining


def connect_tcp(host: str, port: int, *, deadline: Deadline, cancel: threading.Event) -> socket.socket:
    remaining = _slice(deadline, cancel)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(remaining)
        sock.connect((host, port))
    except TimeoutError as exc:
        sock.close()
        raise BoundedIOTimeout(f"connect to {host}:{port} timed out") from exc
    except OSError:
        sock.close()
        raise
    sock.settimeout(None)
    return sock


def wait_for_listener(host: str, port: int, *, deadline: Deadline, cancel: threading.Event) -> None:
    """Block until something is listening on host:port, bounded by deadline + cancel.

    Polls connect_tcp with exponential backoff (10ms → 200ms cap) and swallows the transient
    ECONNREFUSED / BoundedIOTimeout that mean "nobody is listening yet". A successful connect
    is closed immediately — this is a readiness probe, not a usable connection. Raises
    BoundedIOTimeout when the deadline expires without a listener appearing.

    Use at process-startup boundaries (e.g. just after fork+exec of a server) where the bind+
    listen syscalls race the parent's first connect attempt. Do NOT use on hot paths that
    must fail fast on a closed port — connect_tcp's single-attempt semantics are the right
    fit there.
    """
    backoff = 0.01
    while True:
        check_not_cancelled(cancel)
        if deadline.expired():
            raise BoundedIOTimeout(f"listener never appeared on {host}:{port} before the deadline")
        try:
            sock = connect_tcp(host, port, deadline=deadline, cancel=cancel)
        except (BoundedIOTimeout, OSError):
            # Sleep at most until the deadline so we never overshoot.
            time.sleep(min(backoff, deadline.remaining()))
            backoff = min(backoff * 2, 0.2)
            continue
        sock.close()
        return


def allocate_loopback_ports(count: int) -> list[tuple[int, socket.socket]]:
    """Bind `count` ephemeral 127.0.0.1 ports and return (port, held_socket) pairs.

    The caller keeps each socket bound until immediately before exec, then closes it
    (race-minimized allocation, §6.1). On any failure, all sockets are closed.
    """
    holders: list[tuple[int, socket.socket]] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", 0))
            except OSError:
                sock.close()
                raise
            holders.append((sock.getsockname()[1], sock))
    except OSError:
        for _port, sock in holders:
            sock.close()
        raise
    return holders


def await_accept(listener: socket.socket, *, deadline: Deadline, cancel: threading.Event) -> socket.socket:
    while True:
        remaining = _slice(deadline, cancel)
        readable, _, _ = select.select([listener], [], [], min(remaining, 0.2))
        if readable:
            conn, _addr = listener.accept()
            return conn


def open_device(path: str, *, deadline: Deadline, cancel: threading.Event) -> int:
    """Open a serial **character device** / PTY slave non-blocking and return an fd.

    `O_NONBLOCK` ensures the open does not block waiting on carrier (DCD) on a real serial
    line. Rejects non-character-special paths (FIFOs, regular files): serial sources are
    ttys/PTYs, and a unix-socket source is connected elsewhere — so a FIFO/regular path is
    a configuration error, not a thing to wait on. (`O_RDWR|O_NONBLOCK` on a FIFO would
    return immediately without proving any peer, which is why this rejects rather than
    polls for writability.)
    """
    check_not_cancelled(cancel)
    if deadline.expired():
        raise BoundedIOTimeout("deadline exceeded")
    mode = os.stat(path).st_mode
    if not stat.S_ISCHR(mode):
        raise OSError(f"{path!r} is not a character device (expected a serial port or PTY slave)")
    return os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY)


def spawn(
    argv: list[str],
    *,
    deadline: Deadline,
    cancel: threading.Event,
    pass_fds: Collection[int] = (),
) -> subprocess.Popen[bytes]:
    """Start a subprocess with no shell.

    Spawn itself is non-blocking; the deadline/cancel are checked before exec so a
    cancelled attach never spawns.
    """
    _slice(deadline, cancel)
    # list argv, never a shell — not a shell injection vector
    return subprocess.Popen(argv, shell=False, pass_fds=pass_fds)  # nosec B603
