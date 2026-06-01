from __future__ import annotations

import os
import signal
import socket
import subprocess  # nosec B404
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from kdive.seams.process_identity import ProcessIdentityProbe, ProcProcessIdentityProbe
from kdive.transport.core.bounded import (
    BoundedIOTimeout,
    Deadline,
    allocate_loopback_ports,
    check_not_cancelled,
    connect_tcp,
    spawn,
    wait_for_listener,
)

AGENT_PROXY = "agent-proxy"
ON_PARTIAL = Callable[[str, object], None]


class _ProxyProcess(Protocol):
    """Structural view of the spawned agent-proxy process.

    Real production code passes a `subprocess.Popen`; unit tests pass a `_FakeProc`
    with the same attribute/method shape. Stay narrow so test fakes remain trivial.
    """

    pid: int

    def terminate(self) -> None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float | None = None) -> int: ...
    def poll(self) -> int | None: ...


# Telnet IAC BREAK — what a client sends agent-proxy's console port to request a target
# break. agent-proxy.c defaultBrkStr = {0xff, 0xf3}. Under -s003 agent-proxy emits the
# alternate byte 0x03 to the *target* line instead of a real serial break.
_BREAK_ESCAPE = b"\xff\xf3"
_S003_TARGET_ALTERNATE = b"\x03"


@dataclass(frozen=True)
class LocalDeviceSource:
    device: str
    baud: int = 115200


@dataclass(frozen=True)
class RemoteTerminalServerSource:
    host: str
    port: int


ProxySource = LocalDeviceSource | RemoteTerminalServerSource


@dataclass
class ProxyHandle:
    process: _ProxyProcess
    backend_pid: int
    backend_start_time: str | None
    console_port: int
    gdb_port: int
    sockets: list[socket.socket] = field(default_factory=list)


class ProxyBackend(Protocol):
    def start(
        self,
        source: ProxySource,
        *,
        supports_uart_break: bool,
        cancel: threading.Event,
        deadline: Deadline,
        on_partial: ON_PARTIAL,
        inherit_fds: tuple[int, ...] = (),
    ) -> ProxyHandle: ...

    def health(self, handle: ProxyHandle) -> str: ...

    def send_break(self, handle: ProxyHandle) -> None: ...

    def stop(self, handle: ProxyHandle) -> None: ...

    def stop_by_identity(self, pid: int, start_time: str | None) -> bool: ...


class ProxyIdentityError(Exception):
    """A listener on an allocated port could not be verified as the spawned child."""


def _source_argv(source: ProxySource) -> list[str]:
    if isinstance(source, LocalDeviceSource):
        return ["0", f"{source.device},{source.baud}"]
    return [source.host, str(source.port)]


class AgentProxyBackend:
    """Supervises an agent-proxy child that demuxes a console^gdb port pair (§6.1).
    No shell: argv is a list, ports are ints, endpoints are loopback-only."""

    def __init__(
        self,
        *,
        spawner: Callable[..., _ProxyProcess] = spawn,
        identity_probe: ProcessIdentityProbe | None = None,
    ) -> None:
        self._spawn = spawner
        self._identity = identity_probe or ProcProcessIdentityProbe()

    MAX_ATTEMPTS = 5

    def start(
        self,
        source: ProxySource,
        *,
        supports_uart_break: bool,
        cancel: threading.Event,
        deadline: Deadline,
        on_partial: ON_PARTIAL,
        inherit_fds: tuple[int, ...] = (),
        _verify: bool = True,
    ) -> ProxyHandle:
        """Spawn agent-proxy and verify our child owns the allocated listeners. On a
        verification failure (a foreign process won the bind race, §6.1), reap OUR child
        — never the foreigner — and retry on fresh ports until verified, the deadline
        passes, or MAX_ATTEMPTS is reached."""
        last_error: ProxyIdentityError | None = None
        for _attempt in range(self.MAX_ATTEMPTS):
            check_not_cancelled(cancel)
            if deadline.expired():
                break
            handle = self._spawn_once(
                source,
                supports_uart_break=supports_uart_break,
                cancel=cancel,
                deadline=deadline,
                on_partial=on_partial,
                inherit_fds=inherit_fds,
            )
            try:
                if handle.backend_start_time is None:
                    # No start-time fingerprint ⇒ the fenced close path could never reap this
                    # child later (F2). Fail closed now, while we still hold the Popen.
                    raise ProxyIdentityError("spawned agent-proxy has no start-time fingerprint")
                if _verify:
                    self._verify_identity(handle, deadline=deadline, cancel=cancel)
            except ProxyIdentityError as exc:
                last_error = exc
                self._reap(handle.process)  # reap OUR fresh child directly; foreign listener untouched
                continue
            except BaseException:  # noqa: B036  # reap child on ANY exit incl. cancel, then re-raise
                self._reap(handle.process)
                raise
            return handle
        raise last_error or ProxyIdentityError("agent-proxy attach did not verify before the deadline")

    def _spawn_once(
        self,
        source: ProxySource,
        *,
        supports_uart_break: bool,
        cancel: threading.Event,
        deadline: Deadline,
        on_partial: ON_PARTIAL,
        inherit_fds: tuple[int, ...] = (),
    ) -> ProxyHandle:
        holders = allocate_loopback_ports(2)
        console_port, gdb_port = holders[0][0], holders[1][0]
        # Force LOOPBACK binding (round-7 F1): agent-proxy defaults to INADDR_ANY (0.0.0.0),
        # which would expose console/RSP off-host AND fail the exact-127.0.0.1 ownership check.
        # agent-proxy's native `virt_IP:port` syntax binds the given address (setup_local_port).
        argv = [AGENT_PROXY, f"127.0.0.1:{console_port}^127.0.0.1:{gdb_port}", *_source_argv(source)]
        if not supports_uart_break:
            argv.append("-s003")
        # Release the held ports immediately before exec (race-minimized window, §6.1).
        for _port, sock in holders:
            sock.close()
        # pass_fds keeps the source-exclusivity lock fd open in the child so the lock tracks
        # the device-holder's lifetime, surviving a parent crash (round-10 F1).
        process = self._spawn(argv, deadline=deadline, cancel=cancel, pass_fds=inherit_fds)
        # Everything after the Popen exists must reap the child on ANY failure (round-8 F1):
        # `identity()` or `on_partial()` (which may fsync the durable record in Layer 4) can
        # raise, and the handle has not been returned yet, so start()'s cleanup would never
        # see it. Reap here before re-raising.
        try:
            pid = int(process.pid)
            # Capture the start-time fingerprint BEFORE publishing cleanup authority (round-5
            # F1): a crash after this partial must leave reconciliation with pid+start_time,
            # never pid-only. Emit both atomically as one partial.
            identity = self._identity.identity(pid)
            start_time = identity.start_time if identity else None
            on_partial("backend_process", {"pid": pid, "start_time": start_time})
            return ProxyHandle(
                process=process,
                backend_pid=pid,
                backend_start_time=start_time,
                console_port=console_port,
                gdb_port=gdb_port,
            )
        except BaseException:  # noqa: B036  # reap child on ANY exit incl. cancel, then re-raise
            self._reap(process)
            raise

    def _verify_identity(self, handle: ProxyHandle, *, deadline: Deadline, cancel: threading.Event) -> None:
        # Confirm OUR spawned child is the listener on BOTH allocated ports. A foreign
        # process that won the bind race (§6.1) answers TCP but does NOT own the socket,
        # so listener ownership — not mere reachability — is the discriminator. (RSP
        # framing is NOT a usable signal here: a live kernel behind agent-proxy is not in
        # kgdb until broken in, so the gdb port stays silent.) FAIL CLOSED: require
        # `owns_listener is True` for both ports. `None` (ownership unverifiable — no
        # /proc/net, or /proc/<pid>/fd unreadable) is a REJECT, not a pass, so a foreign
        # listener can never slip through on an indeterminable host. In prod agent-proxy
        # is Linux-only (ownership is determinable); unit tests inject the verdict via a
        # fake probe. A failure raises; start() reaps OUR child and retries on fresh ports.
        if not self._identity.is_alive(handle.backend_pid):
            raise ProxyIdentityError("spawned agent-proxy child is not alive")
        if not self._identity.looks_like(handle.backend_pid, "agent-proxy"):
            raise ProxyIdentityError("spawned child is not agent-proxy")
        for port in (handle.console_port, handle.gdb_port):
            # bind+listen races fork+exec: on a slow runner the child hasn't reached
            # setup_local_port's listen() by the time the parent connects, so a single
            # connect_tcp would get ECONNREFUSED and start()'s respawn loop would just
            # hit the same race on every attempt. Poll for the listener within the
            # shared deadline before checking ownership.
            try:
                wait_for_listener("127.0.0.1", port, deadline=deadline, cancel=cancel)
            except (BoundedIOTimeout, OSError) as exc:
                raise ProxyIdentityError(f"allocated port {port} has no listener") from exc
            # Address-specific (F2): prove ownership of the exact 127.0.0.1:port we advertise.
            if self._identity.owns_listener(handle.backend_pid, "127.0.0.1", port) is not True:
                raise ProxyIdentityError(
                    f"cannot positively confirm our child owns 127.0.0.1:{port} "
                    "(foreign bind or ownership unverifiable) — failing closed"
                )

    TERM_GRACE = 5.0
    KILL_GRACE = 2.0

    def _reap(self, process: _ProxyProcess) -> None:
        # Terminate → wait → kill → wait an OWNED Popen (no fingerprint gate — the caller
        # holds this exact Popen, so it is unambiguously ours). Reaps the child: no zombie,
        # no CPU-spinning poll loop, and a foreign pid can never be signalled.
        try:
            process.terminate()
            process.wait(timeout=self.TERM_GRACE)
            return
        except subprocess.TimeoutExpired:
            pass
        except (ProcessLookupError, OSError):
            return
        try:
            process.kill()
            process.wait(timeout=self.KILL_GRACE)
        except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
            pass

    def health(self, handle: ProxyHandle) -> str:
        if not self._identity_current(handle):
            return "degraded"
        for port in (handle.console_port, handle.gdb_port):
            # Re-run the SAME address-specific ownership check as attach (round-8 F2): the
            # child may still be alive but a foreign process may now own the loopback port.
            # False/None ⇒ degraded, so health never blesses a stolen endpoint.
            if self._identity.owns_listener(handle.backend_pid, "127.0.0.1", port) is not True:
                return "degraded"
            try:
                conn = connect_tcp("127.0.0.1", port, deadline=Deadline.after(2.0), cancel=threading.Event())
                conn.close()
            except (BoundedIOTimeout, OSError):
                return "degraded"
        return "ready"

    def send_break(self, handle: ProxyHandle) -> None:
        # Revalidate ownership at SEND time (round-9 F1): never write BREAK control bytes to
        # a recycled/foreign listener. Fail closed if our child is no longer current or no
        # longer owns the console port. The exact escape is pinned by the PTY test (§6.4).
        if not self._identity_current(handle):
            raise ProxyIdentityError("send_break: agent-proxy child is no longer current")
        if self._identity.owns_listener(handle.backend_pid, "127.0.0.1", handle.console_port) is not True:
            raise ProxyIdentityError(f"send_break: child no longer owns console 127.0.0.1:{handle.console_port}")
        conn = connect_tcp("127.0.0.1", handle.console_port, deadline=Deadline.after(2.0), cancel=threading.Event())
        try:
            # Re-verify ownership of the connected port immediately before the write, shrinking
            # the check-then-write window to this adjacency. The residual race cannot be fully
            # eliminated; the start-time fingerprint + this double check is the mitigation (§8.4).
            if self._identity.owns_listener(handle.backend_pid, "127.0.0.1", handle.console_port) is not True:
                raise ProxyIdentityError(f"send_break: child no longer owns console 127.0.0.1:{handle.console_port}")
            conn.sendall(_BREAK_ESCAPE)
        finally:
            conn.close()

    def stop(self, handle: ProxyHandle) -> None:
        # Public close path (called much later, when pid reuse is possible): gate on the
        # start-time fingerprint so a REUSED pid is never signalled, then reap. If this is
        # no longer our child (exited / pid reused), just poll() to reap our own exited
        # child if present. Idempotent.
        if not self._identity_current(handle):
            handle.process.poll()
            return
        self._reap(handle.process)

    def stop_by_identity(self, pid: int, start_time: str | None) -> bool:
        # Stateless fenced reaper for crash recovery (round-6 F1): used by Layer-4
        # reconciliation when the in-memory ProxyHandle/Popen is gone and only the durable
        # (pid, start_time) survives. Signal by pid ONLY when the live start-time fingerprint
        # matches — a reused pid is never signalled; a None fingerprint is unfenceable and
        # refuses to signal (leak > kill-wrong-process). os.kill is safe here precisely
        # because the fingerprint match proves it is still our old child.
        #
        # Returns True iff we issued a kill against a fingerprint-matched live backend. False on a
        # None fingerprint, a missing/mismatched live identity, or an immediate
        # ProcessLookupError/PermissionError — i.e. no live backend was reaped. Reconciliation
        # uses this to decide whether to close admission (live orphan we just killed) vs. only
        # emit the lifecycle event (record present but backend already dead / unfenceable).
        if start_time is None:
            return False
        observed = self._identity.identity(pid)
        if observed is None or observed.start_time != start_time:
            return False
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            return False
        deadline = Deadline.after(self.TERM_GRACE)
        while not deadline.expired():
            if not self._identity.is_alive(pid):
                return True
            time.sleep(0.05)
        recheck = self._identity.identity(pid)
        if recheck is not None and recheck.start_time == start_time:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                return True  # we SIGTERM'd a live backend; SIGKILL race is post-reap
        return True

    def _identity_current(self, handle: ProxyHandle) -> bool:
        if not self._identity.is_alive(handle.backend_pid):
            return False
        observed = self._identity.identity(handle.backend_pid)
        if observed is None or observed.start_time is None:
            return False
        return observed.start_time == handle.backend_start_time
