from __future__ import annotations

import contextlib
import enum
import fcntl
import logging
import os
import secrets
import select
import socket
import stat
import tempfile
import termios
import threading
import tty
import unicodedata
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType

from kdive.domain import ErrorCategory
from kdive.safety.runtime_locks import RuntimeLockError, device_lock_filename, private_runtime_lock_dir
from kdive.transport.backends.proxy import (
    AgentProxyBackend,
    LocalDeviceSource,
    ProxyBackend,
    ProxyHandle,
    RemoteTerminalServerSource,
)
from kdive.transport.core.base import (
    BackendAttachment,
    BreakResources,
    EndpointExposure,
    LineRole,
    OpenRequest,
    TcpEndpoint,
    Transport,
    TransportCapability,
    TransportLocality,
    TransportSession,
    UnixSocketEndpoint,
)
from kdive.transport.core.bounded import Deadline, await_accept, check_not_cancelled, open_device

OnPartial = Callable[[str, object], None]

logger = logging.getLogger(__name__)

_BRIDGE_BUFFER = 4096
# Per-direction outbound buffer ceiling. The relay stops reading a source once its outbound
# buffer reaches this cap, so memory is bounded and the kernel/tty applies upstream backpressure
# to the producer instead of the bridge dropping bytes or evicting a slow peer (plan §F1).
_RELAY_CAP = 262144
_ACCEPT_GRACE_SECONDS = 86400.0
_THREAD_JOIN_TIMEOUT = 2.0
_SOCKET_NAME = "c.sock"
# AF_UNIX sun_path is capped (~104 bytes on darwin, 108 on Linux). The bound socket lives
# under socket_dir when that fits; a longer socket_dir overflows the cap, so the per-session
# dir falls back to a short runtime tempdir. Either way the parent dir is owner-only (0700)
# and the socket is owner-only (0600), so the access boundary is unchanged (§8.4).
_AF_UNIX_MAX = 100


class _PumpStep(enum.Enum):
    """Outcome of one direction of a bridge pump step. The pump must tell a client
    disconnect (re-accept a fresh client) apart from source-device death (stop): a failed
    transfer is attributed to the side that broke, never conflated (plan §3, F1 race)."""

    CONTINUE = "continue"
    CLIENT_GONE = "client_gone"
    SOURCE_DEAD = "source_dead"


class SerialLocalConfigError(Exception):
    """A serial-local request is malformed (bad device path, control chars)."""

    def __init__(self, message: str, *, category: ErrorCategory) -> None:
        super().__init__(message)
        self.category = category


class SerialLocalConflictError(Exception):
    """The physical source line is already driven by another attach."""

    def __init__(self, message: str, *, category: ErrorCategory) -> None:
        super().__init__(message)
        self.category = category


class SerialConsoleBridge:
    """Pumps bytes both directions between a serial source fd and a per-session
    owner-only unix-domain socket. OS file permissions are the access boundary."""

    def __init__(self, *, socket_path: str, session_dir: str, source_fd: int) -> None:
        self.socket_path = socket_path
        self._session_dir = session_dir
        self._source_fd = source_fd
        self._listener: socket.socket | None = None
        self._conn: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @classmethod
    def open(cls, *, socket_dir: Path, device: str, deadline: Deadline, cancel: threading.Event) -> SerialConsoleBridge:
        source_fd = open_device(device, deadline=deadline, cancel=cancel)
        try:
            cls._raw_if_tty(source_fd)
            session_dir = cls._make_session_dir(socket_dir)
        except BaseException:
            os.close(source_fd)
            raise
        socket_path = str(session_dir / _SOCKET_NAME)
        bridge = cls(socket_path=socket_path, session_dir=str(session_dir), source_fd=source_fd)
        try:
            bridge._listen()
            bridge._start_pump()
            return bridge
        except BaseException:
            # The bridge now owns source_fd + session_dir, and may own a bound listener and
            # on-disk socket inode. stop() closes conn/listener/source and removes both the
            # socket file and the session dir, suppressing double-close; it is the single
            # cleanup path for any failure after the bridge exists (listen, chmod, thread start).
            bridge.stop()
            raise

    @staticmethod
    def _raw_if_tty(fd: int) -> None:
        # A real serial line has no local echo or canonical line editing. Put a tty/PTY
        # source into raw mode so the bridge forwards bytes verbatim and does not echo
        # client input back as device output. Non-tty char devices have no termios state.
        if not os.isatty(fd):
            return
        with contextlib.suppress(termios.error):
            tty.setraw(fd)

    @staticmethod
    def _make_session_dir(socket_dir: Path) -> Path:
        preferred = socket_dir / secrets.token_hex(8)
        if len(str(preferred / _SOCKET_NAME)) <= _AF_UNIX_MAX:
            socket_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.mkdir(preferred, 0o700)
            session_dir = preferred
        else:
            session_dir = Path(tempfile.mkdtemp(prefix="kdive-serial-"))
            os.chmod(session_dir, 0o700)
        if stat.S_IMODE(os.stat(session_dir).st_mode) != 0o700:
            raise SerialLocalConfigError(
                f"per-session dir {str(session_dir)!r} is not owner-only (0700)",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        return session_dir

    def _listen(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(self.socket_path)
            os.chmod(self.socket_path, 0o600)
            if stat.S_IMODE(os.stat(self.socket_path).st_mode) != 0o600:
                raise SerialLocalConfigError(
                    f"console socket {self.socket_path!r} is not owner-only (0600)",
                    category=ErrorCategory.CONFIGURATION_ERROR,
                )
            listener.listen(1)
        except BaseException:
            listener.close()
            raise
        self._listener = listener

    def _start_pump(self) -> None:
        thread = threading.Thread(target=self._pump, name="serial-local-bridge", daemon=True)
        self._thread = thread
        thread.start()

    def _pump(self) -> None:
        listener = self._listener
        if listener is None:
            return
        # Session-lifetime worker: re-accept across client reconnects until the source dies or
        # stop() is requested (matches the agent-proxy listeners; plan §3 "session-lifetime worker").
        while not self._stop.is_set():
            try:
                conn = await_accept(listener, deadline=Deadline.after(_ACCEPT_GRACE_SECONDS), cancel=self._stop)
            except BaseException:
                return
            self._conn = conn
            try:
                source_alive = self._copy_loop(conn)
            finally:
                self._close_conn(conn)
            if not source_alive:
                return  # source EOF/error: the line is gone, do not spin re-accepting

    def _copy_loop(self, conn: socket.socket) -> bool:
        """Buffered, EAGAIN-tolerant bidirectional relay. Hold one bounded outbound buffer per
        direction; each iteration select on the fds that have room to read or bytes to flush, then
        service whichever are ready. EWOULDBLOCK on a write is a retry, never fatal; partial
        transfers trim only the bytes moved; the per-direction cap bounds memory and lets the
        kernel/tty back-pressure the producer (plan §F1). Return True if the source is still
        healthy (client left → caller re-accepts), False on source EOF/error or stop."""
        conn.setblocking(False)
        to_client = b""  # device output buffered toward the client
        to_device = b""  # client input buffered toward the source
        while not self._stop.is_set():
            rlist, wlist = self._select_lists(conn, to_client, to_device)
            try:
                readable, writable, _ = select.select(rlist, wlist, [], 0.2)
            except (OSError, ValueError):
                return False
            steps: list[_PumpStep] = []
            if self._source_fd in readable:
                to_client, step = self._read_source(to_client)
                steps.append(step)
            if conn in readable:
                to_device, step = self._read_client(conn, to_device)
                steps.append(step)
            if conn in writable:
                to_client, step = self._write_client(conn, to_client)
                steps.append(step)
            if self._source_fd in writable:
                to_device, step = self._write_source(to_device)
                steps.append(step)
            outcome = self._outcome(steps)
            if outcome is not None:
                return outcome
        return False  # stop requested

    def _select_lists(self, conn: socket.socket, to_client: bytes, to_device: bytes) -> tuple[list, list]:
        # Read a source only while its outbound buffer has room (gates memory + applies upstream
        # backpressure); watch a peer for writability only while we have bytes to flush, so a stuck
        # peer makes select block on the 0.2 s slice rather than spin.
        rlist: list = []
        if len(to_client) < _RELAY_CAP:
            rlist.append(self._source_fd)
        if len(to_device) < _RELAY_CAP:
            rlist.append(conn)
        wlist: list = []
        if to_client:
            wlist.append(conn)
        if to_device:
            wlist.append(self._source_fd)
        return rlist, wlist

    @staticmethod
    def _outcome(steps: list[_PumpStep]) -> bool | None:
        # Source death wins over a client departure: a dead line must stop, not re-accept.
        if _PumpStep.SOURCE_DEAD in steps:
            return False
        if _PumpStep.CLIENT_GONE in steps:
            return True
        return None

    def _close_conn(self, conn: socket.socket) -> None:
        self._conn = None
        with contextlib.suppress(OSError):
            conn.close()

    def _read_source(self, to_client: bytes) -> tuple[bytes, _PumpStep]:
        try:
            data = os.read(self._source_fd, _BRIDGE_BUFFER)
        except BlockingIOError:
            return to_client, _PumpStep.CONTINUE
        except OSError:
            return to_client, _PumpStep.SOURCE_DEAD
        if not data:
            return to_client, _PumpStep.SOURCE_DEAD
        return to_client + data, _PumpStep.CONTINUE

    def _read_client(self, conn: socket.socket, to_device: bytes) -> tuple[bytes, _PumpStep]:
        try:
            data = conn.recv(_BRIDGE_BUFFER)
        except BlockingIOError:
            return to_device, _PumpStep.CONTINUE
        except OSError:
            return to_device, _PumpStep.CLIENT_GONE
        if not data:
            return to_device, _PumpStep.CLIENT_GONE
        return to_device + data, _PumpStep.CONTINUE

    def _write_client(self, conn: socket.socket, to_client: bytes) -> tuple[bytes, _PumpStep]:
        try:
            sent = conn.send(to_client)  # send (not sendall) to honor partials on a non-blocking socket
        except BlockingIOError:
            return to_client, _PumpStep.CONTINUE
        except OSError:
            return to_client, _PumpStep.CLIENT_GONE
        return to_client[sent:], _PumpStep.CONTINUE

    def _write_source(self, to_device: bytes) -> tuple[bytes, _PumpStep]:
        try:
            sent = os.write(self._source_fd, to_device)
        except BlockingIOError:
            return to_device, _PumpStep.CONTINUE
        except OSError:
            return to_device, _PumpStep.SOURCE_DEAD
        return to_device[sent:], _PumpStep.CONTINUE

    def stop(self) -> None:
        self._stop.set()
        # Close only the listener: it unblocks an in-flight await_accept, but the data fds must
        # stay open until the pump is gone. _stop + the 0.2 s select slice terminate _copy_loop on
        # their own, so the join below cannot deadlock waiting on a closed source_fd/conn.
        if self._listener is not None:
            with contextlib.suppress(OSError):
                self._listener.close()
        # Join first: after this the pump can no longer touch source_fd or conn, so closing them
        # cannot race a live read/recv/send/write on a recycled fd integer (plan §F2).
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=_THREAD_JOIN_TIMEOUT)
        # The pump closes its own conn via _close_conn's finally, so self._conn is usually None;
        # close it defensively in case the pump never accepted a client.
        if self._conn is not None:
            with contextlib.suppress(OSError):
                self._conn.close()
        with contextlib.suppress(OSError):
            os.close(self._source_fd)
        for target in (self.socket_path, self._session_dir):
            self._unlink(target)

    @staticmethod
    def _unlink(target: str) -> None:
        try:
            if os.path.isdir(target):
                os.rmdir(target)
            else:
                os.unlink(target)
        except FileNotFoundError:
            return
        except OSError:
            logger.debug("failed to remove serial bridge path %s", target, exc_info=True)

    @property
    def session_dir(self) -> str:
        return self._session_dir

    def is_alive(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive() and os.path.exists(self.socket_path)


class SerialLocalTransport(Transport):
    """Bridges a local serial source to a per-session owner-only unix socket
    (console-only) or delegates to agent-proxy for console+gdb demux (§6.1, §8.4)."""

    def __init__(
        self,
        *,
        socket_dir,
        proxy: ProxyBackend | None = None,
        identity_probe=None,
        lock_dir: Path | None = None,
    ) -> None:
        self._socket_dir = Path(socket_dir)
        # Source-exclusivity locks live in a host-global, uid-isolated dir so two runs
        # targeting the same physical line serialize across runs (§4.7). Tests inject a
        # per-test dir to avoid touching the shared host dir; prod resolves it lazily.
        self._lock_dir = Path(lock_dir) if lock_dir is not None else None
        self._proxy = proxy if proxy is not None else AgentProxyBackend(identity_probe=identity_probe)
        self._bridges: dict[str, SerialConsoleBridge] = {}
        self._proxy_handles: dict[tuple[int, str | None], ProxyHandle] = {}
        self._bridge_lock_fds: dict[str, int] = {}
        self._proxy_lock_fds: dict[tuple[int, str | None], int] = {}

    @property
    def capability(self) -> TransportCapability:
        return TransportCapability(
            provider_name="serial-local",
            locality=TransportLocality.LOCAL,
            provides_console=True,
            provides_rsp=True,
            supports_uart_break=True,
            endpoint_exposure=EndpointExposure.LOOPBACK_LOCAL,
        )

    def attach(
        self,
        request: OpenRequest,
        *,
        cancel: threading.Event,
        deadline: Deadline,
        on_partial: OnPartial,
        secrets: Mapping[str, str] = MappingProxyType({}),
    ) -> BackendAttachment:
        check_not_cancelled(cancel)
        device = self._validate_source(request)
        on_partial("source_open", {"path": device})
        lock_fd = self._acquire_source_lock(device)
        try:
            if request.transport_ref.line_role in (LineRole.DEDICATED_DEBUG, LineRole.RSP):
                return self._attach_demux(
                    request, device, lock_fd, cancel=cancel, deadline=deadline, on_partial=on_partial
                )
            return self._attach_console_only(device, lock_fd, cancel=cancel, deadline=deadline, on_partial=on_partial)
        except BaseException:
            self._close_fd(lock_fd)
            raise

    def _validate_source(self, request: OpenRequest) -> str:
        target_ref = request.transport_ref.target_ref
        device = target_ref.get("device")
        if not isinstance(device, str) or not device:
            raise SerialLocalConfigError(
                "serial-local target_ref must carry a non-empty 'device' path",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        if any(unicodedata.category(char) == "Cc" for char in device):
            raise SerialLocalConfigError(
                f"serial-local device path must not contain control characters, got {device!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        if not device.startswith("/"):
            raise SerialLocalConfigError(
                f"serial-local device path must be absolute, got {device!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        return device

    def _acquire_source_lock(self, device: str) -> int:
        try:
            lock_dir = self._lock_dir or private_runtime_lock_dir()
        except RuntimeLockError as exc:
            raise SerialLocalConfigError(str(exc), category=ErrorCategory.INFRASTRUCTURE_FAILURE) from exc
        lock_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = lock_dir / device_lock_filename(self._source_lock_key(device))
        lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(lock_fd)
            raise SerialLocalConflictError(
                f"serial source {device!r} is already attached by another session",
                category=ErrorCategory.TRANSPORT_CONFLICT,
            ) from exc
        os.set_inheritable(lock_fd, True)
        return lock_fd

    @staticmethod
    def _source_lock_key(device: str) -> str:
        """Source-exclusivity identity. For a local character device, the device number
        (major/minor) so every path to one node — symlink, hardlink, distinct mknod node,
        bind mount — collapses to a single lock. Falls back to the canonical path for paths
        that are not a local char device (a remote-terminal-server placeholder, or a device
        that does not exist yet). The stat-vs-open window (a symlink swapped between this stat
        and the later open) needs an untrusted writer in /dev (root/udev) and is out of scope
        for the local-only threat model (§8.4)."""
        try:
            info = os.stat(device)
        except OSError:
            return os.path.realpath(device)
        if not stat.S_ISCHR(info.st_mode):
            return os.path.realpath(device)
        return f"rdev:{info.st_rdev}"

    def _attach_demux(
        self,
        request: OpenRequest,
        device: str,
        lock_fd: int,
        *,
        cancel: threading.Event,
        deadline: Deadline,
        on_partial: OnPartial,
        secrets: Mapping[str, str] = MappingProxyType({}),
    ) -> BackendAttachment:
        opts = request.transport_ref.opts
        target_ref = request.transport_ref.target_ref
        source = self._build_source(device, target_ref)
        handle = self._proxy.start(
            source,
            supports_uart_break=bool(opts.get("supports_uart_break", True)),
            cancel=cancel,
            deadline=deadline,
            on_partial=on_partial,
            inherit_fds=(lock_fd,),
        )
        key = (handle.backend_pid, handle.backend_start_time)
        self._proxy_handles[key] = handle
        self._proxy_lock_fds[key] = lock_fd
        return BackendAttachment(
            console_endpoint=TcpEndpoint(host="127.0.0.1", port=handle.console_port),
            rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=handle.gdb_port),
            backend_pid=handle.backend_pid,
            backend_start_time=handle.backend_start_time,
        )

    @staticmethod
    def _build_source(device: str, target_ref) -> LocalDeviceSource | RemoteTerminalServerSource:
        host = target_ref.get("host")
        port = target_ref.get("port")
        if host is not None and port is not None:
            try:
                port_int = int(port)
            except (TypeError, ValueError) as exc:
                raise SerialLocalConfigError(
                    f"serial-local target_ref['port'] must be an integer, got {port!r}",
                    category=ErrorCategory.CONFIGURATION_ERROR,
                ) from exc
            return RemoteTerminalServerSource(host=str(host), port=port_int)
        raw_baud = target_ref.get("baud", 115200)
        try:
            baud = int(raw_baud)
        except (TypeError, ValueError) as exc:
            raise SerialLocalConfigError(
                f"serial-local target_ref['baud'] must be an integer, got {raw_baud!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
            ) from exc
        return LocalDeviceSource(device=device, baud=baud)

    def _attach_console_only(
        self,
        device: str,
        lock_fd: int,
        *,
        cancel: threading.Event,
        deadline: Deadline,
        on_partial: OnPartial,
        secrets: Mapping[str, str] = MappingProxyType({}),
    ) -> BackendAttachment:
        bridge = SerialConsoleBridge.open(socket_dir=self._socket_dir, device=device, deadline=deadline, cancel=cancel)
        # Record the resolved socket path so Layer-4 reconciliation can find the inode even on
        # the mkdtemp fallback branch, where it lives outside <run>/debug/ (F4). on_partial may
        # raise (a durable-record fsync); if it does, tear the bridge down before propagating so
        # the freed source lock cannot be re-acquired against a still-live line (§4.7, F1).
        try:
            on_partial("console_socket", {"socket_path": bridge.socket_path, "session_dir": bridge.session_dir})
        except BaseException:
            bridge.stop()
            raise
        self._bridges[bridge.socket_path] = bridge
        self._bridge_lock_fds[bridge.socket_path] = lock_fd
        return BackendAttachment(
            console_endpoint=UnixSocketEndpoint(path=bridge.socket_path, mode=0o600),
            rsp_endpoint=None,
            backend_pid=None,
            backend_start_time=None,
        )

    def close(self, session: TransportSession) -> None:
        if session.backend_pid:
            self._close_demux(session)
            return
        console = session.console_endpoint
        if isinstance(console, UnixSocketEndpoint):
            self._close_console_only(console.path)

    def reap_backend(self, pid: int, start_time: str | None) -> None:
        # Start-time-fenced kill of the agent-proxy backend (ADR 0004); the single TD-07 reap hook
        # Layer-4 teardown/rollback call instead of reaching transport._proxy directly. May raise;
        # the caller suppresses.
        self._proxy.stop_by_identity(pid, start_time)

    def _close_demux(self, session: TransportSession) -> None:
        pid = session.backend_pid
        if pid is None:  # callers (close/health) only reach here for a demuxed session
            return
        key = (pid, session.backend_start_time)
        handle = self._proxy_handles.pop(key, None)
        if handle is not None:
            self._proxy.stop(handle)
        else:
            self._proxy.stop_by_identity(pid, session.backend_start_time)
        self._close_fd(self._proxy_lock_fds.pop(key, None))

    def _close_console_only(self, socket_path: str) -> None:
        bridge = self._bridges.pop(socket_path, None)
        if bridge is not None:
            bridge.stop()
        self._close_fd(self._bridge_lock_fds.pop(socket_path, None))

    def health(self, session: TransportSession) -> str:
        if session.backend_pid:
            key = (session.backend_pid, session.backend_start_time)
            handle = self._proxy_handles.get(key)
            return "degraded" if handle is None else self._proxy.health(handle)
        console = session.console_endpoint
        if isinstance(console, UnixSocketEndpoint):
            bridge = self._bridges.get(console.path)
            if bridge is not None and bridge.is_alive():
                return "ready"
        return "degraded"

    def break_resources(self, session: TransportSession) -> BreakResources | None:
        """Resolve the live agent-proxy + handle for this demuxed session so the break mechanism can
        send an agent-proxy/UART break over the console (#82 / ADR 0024). A console-only session, or
        a session whose proxy handle is no longer held, exposes no break handle -> None, which
        ``inject_break_for_session`` maps to ``break_inject_unavailable`` (never a silent no-op)."""
        pid = session.backend_pid
        if pid is None:
            return None
        handle = self._proxy_handles.get((pid, session.backend_start_time))
        if handle is None:
            return None
        return BreakResources(proxy=self._proxy, proxy_handle=handle)

    @staticmethod
    def _close_fd(fd: int | None) -> None:
        if fd is None:
            return
        with contextlib.suppress(OSError):
            os.close(fd)
