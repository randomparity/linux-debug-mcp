from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from linux_debug_mcp.seams.process_identity import ProcessIdentityProbe, ProcProcessIdentityProbe
from linux_debug_mcp.transport.bounded import Deadline, allocate_loopback_ports, check_not_cancelled, spawn

AGENT_PROXY = "agent-proxy"
ON_PARTIAL = Callable[[str, object], None]


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
    process: object
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

    def stop_by_identity(self, pid: int, start_time: str | None) -> None: ...


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
        spawner: Callable[..., object] = spawn,
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
        """Verify that the spawned child owns the allocated listeners. Filled in Task 5."""
        raise NotImplementedError("filled in Task 5")

    def _reap(self, process: object) -> None:
        """Terminate and wait for the given process. Filled in Task 5."""
        raise NotImplementedError("filled in Task 5")

    def health(self, handle: ProxyHandle) -> str:
        """Return a health string for the given handle. Filled in Task 5."""
        raise NotImplementedError("filled in Task 5")

    def send_break(self, handle: ProxyHandle) -> None:
        """Send a UART break signal through the proxy. Filled in Task 5."""
        raise NotImplementedError("filled in Task 5")

    def stop(self, handle: ProxyHandle) -> None:
        """Stop the agent-proxy child gracefully. Filled in Task 5."""
        raise NotImplementedError("filled in Task 5")

    def stop_by_identity(self, pid: int, start_time: str | None) -> None:
        """Stop a process identified by pid + start-time fingerprint. Filled in Task 5."""
        raise NotImplementedError("filled in Task 5")

    def _identity_current(self, handle: ProxyHandle) -> bool:
        """Check whether the handle's pid + start_time still matches the live process. Filled in Task 5."""
        raise NotImplementedError("filled in Task 5")
