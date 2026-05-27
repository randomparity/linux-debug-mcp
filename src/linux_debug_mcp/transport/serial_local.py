from __future__ import annotations

import contextlib
import fcntl
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
from collections.abc import Callable
from pathlib import Path

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.safety.runtime_locks import RuntimeLockError, device_lock_filename, private_runtime_lock_dir
from linux_debug_mcp.transport.base import (
    BackendAttachment,
    EndpointExposure,
    LineRole,
    OpenRequest,
    TcpEndpoint,
    Transport,
    TransportCapability,
    TransportLocality,
    UnixSocketEndpoint,
)
from linux_debug_mcp.transport.bounded import Deadline, await_accept, check_not_cancelled, open_device
from linux_debug_mcp.transport.proxy import (
    AgentProxyBackend,
    LocalDeviceSource,
    ProxyBackend,
    ProxyHandle,
    RemoteTerminalServerSource,
)

OnPartial = Callable[[str, object], None]

_BRIDGE_BUFFER = 4096
_ACCEPT_GRACE_SECONDS = 86400.0
_THREAD_JOIN_TIMEOUT = 2.0
_SOCKET_NAME = "c.sock"
# AF_UNIX sun_path is capped (~104 bytes on darwin, 108 on Linux). The bound socket lives
# under socket_dir when that fits; a longer socket_dir overflows the cap, so the per-session
# dir falls back to a short runtime tempdir. Either way the parent dir is owner-only (0700)
# and the socket is owner-only (0600), so the access boundary is unchanged (§8.4).
_AF_UNIX_MAX = 100


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
            session_dir = Path(tempfile.mkdtemp(prefix="ldm-serial-"))
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
        """Pump until the client leaves or the source dies. Return True if the source is still
        healthy (client left → caller re-accepts), False if the source fd hit EOF/error or a
        watched fd became unusable (caller stops)."""
        conn.setblocking(False)
        while not self._stop.is_set():
            try:
                readable, _, _ = select.select([self._source_fd, conn], [], [], 0.2)
            except (OSError, ValueError):
                return False
            if self._source_fd in readable and not self._device_to_client(conn):
                return False  # source EOF/error → device gone
            if conn in readable and not self._client_to_device(conn):
                return True  # client EOF/error/clean close → re-accept a new client
        return False  # stop requested

    def _close_conn(self, conn: socket.socket) -> None:
        self._conn = None
        with contextlib.suppress(OSError):
            conn.close()

    def _device_to_client(self, conn: socket.socket) -> bool:
        try:
            data = os.read(self._source_fd, _BRIDGE_BUFFER)
        except BlockingIOError:
            return True
        except OSError:
            return False
        if not data:
            return False
        try:
            conn.sendall(data)
        except OSError:
            return False
        return True

    def _client_to_device(self, conn: socket.socket) -> bool:
        try:
            data = conn.recv(_BRIDGE_BUFFER)
        except BlockingIOError:
            return True
        except OSError:
            return False
        if not data:
            return False
        try:
            os.write(self._source_fd, data)
        except OSError:
            return False
        return True

    def stop(self) -> None:
        self._stop.set()
        for closeable in (self._conn, self._listener):
            if closeable is not None:
                with contextlib.suppress(OSError):
                    closeable.close()
        with contextlib.suppress(OSError):
            os.close(self._source_fd)
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=_THREAD_JOIN_TIMEOUT)
        for target in (self.socket_path, self._session_dir):
            self._unlink(target)

    @staticmethod
    def _unlink(target: str) -> None:
        try:
            if os.path.isdir(target):
                os.rmdir(target)
            else:
                os.unlink(target)
        except OSError:
            pass

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
        deadline,
        on_partial: OnPartial,
    ) -> BackendAttachment:
        check_not_cancelled(cancel)
        bounded = deadline if isinstance(deadline, Deadline) else Deadline.after(float(deadline))
        device = self._validate_source(request)
        on_partial("source_open", {"path": device})
        lock_fd = self._acquire_source_lock(device)
        try:
            if request.transport_ref.line_role in (LineRole.DEDICATED_DEBUG, LineRole.RSP):
                return self._attach_demux(
                    request, device, lock_fd, cancel=cancel, deadline=bounded, on_partial=on_partial
                )
            return self._attach_console_only(device, lock_fd, cancel=cancel, deadline=bounded, on_partial=on_partial)
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
        # Key the lock on the canonical path so symlink aliases and "/.." segments collapse to
        # one lock (§4.7). realpath resolves the filesystem name, not hardware identity: two
        # genuinely distinct nodes for one chip still slip through. device stays the open target.
        lock_path = lock_dir / device_lock_filename(os.path.realpath(device))
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

    def _attach_demux(
        self,
        request: OpenRequest,
        device: str,
        lock_fd: int,
        *,
        cancel: threading.Event,
        deadline: Deadline,
        on_partial: OnPartial,
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
            return RemoteTerminalServerSource(host=str(host), port=int(port))
        return LocalDeviceSource(device=device, baud=int(target_ref.get("baud", 115200)))

    def _attach_console_only(
        self,
        device: str,
        lock_fd: int,
        *,
        cancel: threading.Event,
        deadline: Deadline,
        on_partial: OnPartial,
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

    def close(self, session) -> None:
        if getattr(session, "backend_pid", None):
            self._close_demux(session)
            return
        console = getattr(session, "console_endpoint", None)
        if isinstance(console, UnixSocketEndpoint):
            self._close_console_only(console.path)

    def _close_demux(self, session) -> None:
        key = (session.backend_pid, getattr(session, "backend_start_time", None))
        handle = self._proxy_handles.pop(key, None)
        if handle is not None:
            self._proxy.stop(handle)
        else:
            self._proxy.stop_by_identity(session.backend_pid, getattr(session, "backend_start_time", None))
        self._close_fd(self._proxy_lock_fds.pop(key, None))

    def _close_console_only(self, socket_path: str) -> None:
        bridge = self._bridges.pop(socket_path, None)
        if bridge is not None:
            bridge.stop()
        self._close_fd(self._bridge_lock_fds.pop(socket_path, None))

    def health(self, session) -> str:
        if getattr(session, "backend_pid", None):
            key = (session.backend_pid, getattr(session, "backend_start_time", None))
            handle = self._proxy_handles.get(key)
            return "degraded" if handle is None else self._proxy.health(handle)
        console = getattr(session, "console_endpoint", None)
        if isinstance(console, UnixSocketEndpoint):
            bridge = self._bridges.get(console.path)
            if bridge is not None and bridge.is_alive():
                return "ready"
        return "degraded"

    @staticmethod
    def _close_fd(fd: int | None) -> None:
        if fd is None:
            return
        with contextlib.suppress(OSError):
            os.close(fd)
