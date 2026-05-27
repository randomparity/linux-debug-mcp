import os
import socket
import stat
import threading

import pytest

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.seams.target import ConsoleKind, PlatformMetadata, TargetKey
from linux_debug_mcp.transport.base import (
    BackendAttachment,
    LineRole,
    OpenRequest,
    TcpEndpoint,
    TransportRef,
    UnixSocketEndpoint,
)
from linux_debug_mcp.transport.bounded import Deadline
from linux_debug_mcp.transport.serial_local import SerialLocalConfigError, SerialLocalTransport


def _platform() -> PlatformMetadata:
    return PlatformMetadata(
        console_kind=ConsoleKind.UART,
        console_count=1,
        dedicated_debug_line=False,
        ssh_reachable=False,
    )


def _request(line_role, target_ref, tmp_path) -> OpenRequest:
    return OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="vm1"),
        generation=0,
        transport_ref=TransportRef(
            provider="serial-local",
            channel_id="con0",
            line_role=line_role,
            target_ref=target_ref,
        ),
        platform=_platform(),
    )


class _StubSession:
    def __init__(self, console_endpoint=None, rsp_endpoint=None, backend_pid=None, backend_start_time=None):
        self.console_endpoint = console_endpoint
        self.rsp_endpoint = rsp_endpoint
        self.backend_pid = backend_pid
        self.backend_start_time = backend_start_time


def test_console_only_path_bridges_a_pty_device_to_an_owner_only_unix_socket(tmp_path):
    import pty

    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks")
    request = _request(LineRole.SHARED_CONSOLE, {"device": peripheral_name}, tmp_path)
    result = transport.attach(
        request, cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None
    )
    try:
        assert isinstance(result, BackendAttachment)
        assert isinstance(result.console_endpoint, UnixSocketEndpoint)
        assert result.rsp_endpoint is None
        mode = stat.S_IMODE(os.stat(result.console_endpoint.path).st_mode)
        assert mode == 0o600  # OS perms are the access-control boundary (§8.4)
        # The per-session parent dir is owner-only, closing the pre-chmod window (F3).
        parent_mode = stat.S_IMODE(os.stat(os.path.dirname(result.console_endpoint.path)).st_mode)
        assert parent_mode == 0o700

        # Bytes on the wire (round-1 review F2): a client gets device output and vice versa.
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(result.console_endpoint.path)
        client.settimeout(2.0)
        os.write(controller_fd, b"from-device\n")
        assert b"from-device" in client.recv(64)
        client.sendall(b"to-device\n")
        assert b"to-device" in os.read(controller_fd, 64)
        client.close()
    finally:
        transport.close(_StubSession(result.console_endpoint))  # bounded stop + unlink
        assert not os.path.exists(result.console_endpoint.path)
        os.close(controller_fd)
        os.close(peripheral_fd)


def test_console_only_attach_emits_a_console_socket_partial(tmp_path):
    """Reconciliation (Layer 4) scans the run dir, but the console socket can fall back to a
    tempdir outside it (F4). attach must emit a console_socket partial recording the resolved
    socket path so the durable record links the inode back regardless of the fallback."""
    import pty

    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks")
    request = _request(LineRole.SHARED_CONSOLE, {"device": peripheral_name}, tmp_path)
    partials: list[tuple[str, object]] = []
    result = transport.attach(
        request,
        cancel=threading.Event(),
        deadline=Deadline.after(2.0),
        on_partial=lambda kind, value: partials.append((kind, value)),
    )
    try:
        console_events = [value for kind, value in partials if kind == "console_socket"]
        assert console_events, "expected a console_socket partial for Layer-4 reconciliation"
        assert console_events[0]["socket_path"] == result.console_endpoint.path
        assert console_events[0]["session_dir"] == os.path.dirname(result.console_endpoint.path)
    finally:
        transport.close(_StubSession(result.console_endpoint))
        os.close(controller_fd)
        os.close(peripheral_fd)


def test_console_only_open_failure_after_listen_leaves_no_socket_or_session_dir(tmp_path, monkeypatch):
    """If the post-_listen step (thread start) raises, open() must route through stop():
    no leaked listener fd, no orphan socket inode, no leftover session dir, not registered."""
    import pty

    from linux_debug_mcp.transport import serial_local

    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)
    captured = {}

    def _boom(self):
        # The listener is bound and the 0600 socket + 0700 session dir exist on disk here.
        captured["socket_path"] = self.socket_path
        captured["session_dir"] = self._session_dir
        raise RuntimeError("simulated thread-start failure")

    monkeypatch.setattr(serial_local.SerialConsoleBridge, "_start_pump", _boom)
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks")
    request = _request(LineRole.SHARED_CONSOLE, {"device": peripheral_name}, tmp_path)
    try:
        with pytest.raises(RuntimeError):
            transport.attach(
                request, cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None
            )
        assert not os.path.exists(captured["socket_path"])  # socket inode unlinked
        assert not os.path.exists(captured["session_dir"])  # session dir removed
        assert transport._bridges == {}  # never registered
    finally:
        os.close(controller_fd)
        os.close(peripheral_fd)


def test_console_only_attach_cleans_up_when_console_socket_partial_raises(tmp_path):
    """on_partial may raise (e.g. a Layer-4 durable fsync). If the console_socket partial
    raises, attach must tear the bridge down — release the source fd + listener + socket inode
    + session dir + pump thread — before propagating, or a later attach re-acquires the freed
    source lock and double-drives the line (§4.7, the F1 invariant the F4 fix regressed on)."""
    import pty

    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks")
    request = _request(LineRole.SHARED_CONSOLE, {"device": peripheral_name}, tmp_path)
    captured = {}

    def _on_partial(kind, value):
        if kind == "console_socket":
            captured["socket_path"] = value["socket_path"]
            captured["session_dir"] = value["session_dir"]
            raise RuntimeError("simulated durable-record fsync failure")

    try:
        with pytest.raises(RuntimeError):
            transport.attach(
                request, cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=_on_partial
            )
        assert not os.path.exists(captured["socket_path"])  # socket inode unlinked
        assert not os.path.exists(captured["session_dir"])  # session dir removed
        assert transport._bridges == {}  # bridge not registered / not leaked
    finally:
        os.close(controller_fd)
        os.close(peripheral_fd)


class _RecordingProxy:
    def __init__(self):
        from linux_debug_mcp.transport.proxy import ProxyHandle

        self.handle = ProxyHandle(
            process=object(), backend_pid=9100, backend_start_time="3", console_port=5001, gdb_port=5002
        )
        self.stopped = []
        self.stopped_by_identity = []

    def start(self, source, *, supports_uart_break, cancel, deadline, on_partial, inherit_fds=()):
        on_partial("backend_pid", self.handle.backend_pid)
        return self.handle

    def health(self, handle):
        return "ready"

    def send_break(self, handle): ...

    def stop(self, handle):
        self.stopped.append(handle)

    def stop_by_identity(self, pid, start_time):
        self.stopped_by_identity.append((pid, start_time))


def test_console_plus_gdb_path_delegates_to_proxy_and_returns_tcp_endpoints(tmp_path):
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks", proxy=_RecordingProxy())
    request = _request(LineRole.DEDICATED_DEBUG, {"device": "/dev/ttyUSB0", "baud": 115200}, tmp_path)
    result = transport.attach(
        request, cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None
    )
    assert isinstance(result.console_endpoint, TcpEndpoint)
    assert isinstance(result.rsp_endpoint, TcpEndpoint)
    assert result.backend_pid == 9100


def test_demux_close_stops_the_exact_proxy_handle_and_is_idempotent(tmp_path):
    """The demux ProxyHandle must be retained at attach so close() can reap agent-proxy
    (round-2 review F3). close() passes the SAME handle start() returned, and is idempotent."""
    proxy = _RecordingProxy()
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks", proxy=proxy)
    request = _request(LineRole.DEDICATED_DEBUG, {"device": "/dev/ttyUSB0", "baud": 115200}, tmp_path)
    result = transport.attach(
        request, cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None
    )
    session = _StubSession(
        console_endpoint=result.console_endpoint,
        rsp_endpoint=result.rsp_endpoint,
        backend_pid=result.backend_pid,
        backend_start_time=result.backend_start_time,
    )
    transport.close(session)
    transport.close(session)  # idempotent: no second stop, no error
    assert proxy.stopped == [proxy.handle]


def test_close_for_a_reused_pid_does_not_stop_a_different_live_session(tmp_path):
    """Session A (pid P, start_time sA) closed and removed; session B reuses pid P with a
    different start_time. A stale close for A must NOT pop/stop B (round-9 F2)."""
    proxy = _RecordingProxy()
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks", proxy=proxy)
    # B is the only live handle: same pid, different start_time.
    transport._proxy_handles[(proxy.handle.backend_pid, "B-start")] = proxy.handle
    stale_a = _StubSession(
        rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=5002),
        backend_pid=proxy.handle.backend_pid,
        backend_start_time="A-start",
    )
    transport.close(stale_a)  # different (pid, start_time) key ⇒ no match
    assert proxy.stopped == []  # B was not stopped
    assert (proxy.handle.backend_pid, "B-start") in transport._proxy_handles


def test_rejects_target_ref_with_control_characters(tmp_path):
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks")
    request = _request(LineRole.SHARED_CONSOLE, {"device": "/dev/tty\n0"}, tmp_path)
    with pytest.raises(SerialLocalConfigError) as exc:
        transport.attach(request, cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None)
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_concurrent_attach_to_the_same_source_is_refused(tmp_path):
    """Two attaches against the same physical line ⇒ the second is refused with
    TRANSPORT_CONFLICT, never double-driven (spec §4.7, round-7 F2)."""
    import pty

    from linux_debug_mcp.transport.serial_local import SerialLocalConflictError

    master, slave = pty.openpty()
    name = os.ttyname(slave)
    shared_lock_dir = tmp_path / "locks"
    t1 = SerialLocalTransport(socket_dir=tmp_path, lock_dir=shared_lock_dir)
    r1 = t1.attach(
        _request(LineRole.SHARED_CONSOLE, {"device": name}, tmp_path),
        cancel=threading.Event(),
        deadline=Deadline.after(2.0),
        on_partial=lambda *_: None,
    )
    try:
        t2 = SerialLocalTransport(socket_dir=tmp_path, lock_dir=shared_lock_dir)
        with pytest.raises(SerialLocalConflictError) as exc:
            t2.attach(
                _request(LineRole.SHARED_CONSOLE, {"device": name}, tmp_path),
                cancel=threading.Event(),
                deadline=Deadline.after(2.0),
                on_partial=lambda *_: None,
            )
        assert exc.value.category == ErrorCategory.TRANSPORT_CONFLICT
    finally:
        t1.close(_StubSession(r1.console_endpoint))
        os.close(master)
        os.close(slave)


def test_same_device_different_socket_dir_still_conflicts(tmp_path):
    """Two runs target the same physical line from different per-run socket_dirs. The
    source lock is host-global (shared lock_dir), so the second attach is refused even
    though the socket_dirs differ — the cross-run guarantee F1 regressed on (spec §4.7)."""
    import pty

    from linux_debug_mcp.transport.serial_local import SerialLocalConflictError

    master, slave = pty.openpty()
    name = os.ttyname(slave)
    shared_lock_dir = tmp_path / "locks"
    t1 = SerialLocalTransport(socket_dir=tmp_path / "run-a", lock_dir=shared_lock_dir)
    r1 = t1.attach(
        _request(LineRole.SHARED_CONSOLE, {"device": name}, tmp_path),
        cancel=threading.Event(),
        deadline=Deadline.after(2.0),
        on_partial=lambda *_: None,
    )
    try:
        t2 = SerialLocalTransport(socket_dir=tmp_path / "run-b", lock_dir=shared_lock_dir)
        with pytest.raises(SerialLocalConflictError) as exc:
            t2.attach(
                _request(LineRole.SHARED_CONSOLE, {"device": name}, tmp_path),
                cancel=threading.Event(),
                deadline=Deadline.after(2.0),
                on_partial=lambda *_: None,
            )
        assert exc.value.category == ErrorCategory.TRANSPORT_CONFLICT
    finally:
        t1.close(_StubSession(r1.console_endpoint))
        os.close(master)
        os.close(slave)


def test_symlinked_device_alias_conflicts_with_canonical_path(tmp_path):
    """A device reached by a symlink alias (e.g. /dev/serial/by-id/...) must collapse to the
    same source lock as its canonical path; otherwise both flocks succeed and the one physical
    line is double-driven (spec §4.7). The lock key is os.path.realpath(device)."""
    import pty

    from linux_debug_mcp.transport.serial_local import SerialLocalConflictError

    master, slave = pty.openpty()
    name = os.ttyname(slave)
    alias = tmp_path / "ttyAlias"
    os.symlink(name, alias)
    shared_lock_dir = tmp_path / "locks"
    t1 = SerialLocalTransport(socket_dir=tmp_path / "run-a", lock_dir=shared_lock_dir)
    r1 = t1.attach(
        _request(LineRole.SHARED_CONSOLE, {"device": name}, tmp_path),
        cancel=threading.Event(),
        deadline=Deadline.after(2.0),
        on_partial=lambda *_: None,
    )
    try:
        t2 = SerialLocalTransport(socket_dir=tmp_path / "run-b", lock_dir=shared_lock_dir)
        with pytest.raises(SerialLocalConflictError) as exc:
            t2.attach(
                _request(LineRole.SHARED_CONSOLE, {"device": str(alias)}, tmp_path),
                cancel=threading.Event(),
                deadline=Deadline.after(2.0),
                on_partial=lambda *_: None,
            )
        assert exc.value.category == ErrorCategory.TRANSPORT_CONFLICT
    finally:
        t1.close(_StubSession(r1.console_endpoint))
        os.close(master)
        os.close(slave)


def test_different_devices_do_not_conflict(tmp_path):
    """Distinct physical lines hash to distinct lock files in the shared lock_dir, so
    both attaches succeed; the source lock is per-device, not a global mutex."""
    import pty

    master_a, slave_a = pty.openpty()
    master_b, slave_b = pty.openpty()
    shared_lock_dir = tmp_path / "locks"
    t1 = SerialLocalTransport(socket_dir=tmp_path / "run-a", lock_dir=shared_lock_dir)
    t2 = SerialLocalTransport(socket_dir=tmp_path / "run-b", lock_dir=shared_lock_dir)
    r1 = t1.attach(
        _request(LineRole.SHARED_CONSOLE, {"device": os.ttyname(slave_a)}, tmp_path),
        cancel=threading.Event(),
        deadline=Deadline.after(2.0),
        on_partial=lambda *_: None,
    )
    r2 = t2.attach(
        _request(LineRole.SHARED_CONSOLE, {"device": os.ttyname(slave_b)}, tmp_path),
        cancel=threading.Event(),
        deadline=Deadline.after(2.0),
        on_partial=lambda *_: None,
    )
    try:
        assert isinstance(r1.console_endpoint, UnixSocketEndpoint)
        assert isinstance(r2.console_endpoint, UnixSocketEndpoint)
    finally:
        t1.close(_StubSession(r1.console_endpoint))
        t2.close(_StubSession(r2.console_endpoint))
        for fd in (master_a, slave_a, master_b, slave_b):
            os.close(fd)


def test_demux_health_is_degraded_when_the_in_memory_handle_is_lost(tmp_path):
    """A durable demux session with backend_pid but an empty handle map (post-restart)
    reports 'degraded', it does not raise KeyError (round-7 F3)."""
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks", proxy=_RecordingProxy())
    session = _StubSession(
        console_endpoint=TcpEndpoint(host="127.0.0.1", port=5001),
        rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=5002),
        backend_pid=9100,
    )
    assert transport.health(session) == "degraded"
