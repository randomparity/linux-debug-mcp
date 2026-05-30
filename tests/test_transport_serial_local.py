import os
import socket
import stat
import threading

import pytest

from kdive.domain import ErrorCategory
from kdive.seams.target import ConsoleKind, PlatformMetadata, TargetKey
from kdive.transport.base import (
    BackendAttachment,
    LineRole,
    OpenRequest,
    TcpEndpoint,
    TransportRef,
    UnixSocketEndpoint,
)
from kdive.transport.bounded import Deadline
from kdive.transport.serial_local import SerialLocalConfigError, SerialLocalTransport


def _read_until(fd: int, needle: bytes, timeout: float = 2.0) -> bytes:
    """Read from a (blocking) fd until `needle` appears or the deadline passes, polling via
    select so a stalled pump fails the test on a bounded timeout rather than hanging."""
    import select as _select
    import time as _time

    deadline = _time.monotonic() + timeout
    buf = b""
    while needle not in buf:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            return buf
        readable, _, _ = _select.select([fd], [], [], remaining)
        if readable:
            buf += os.read(fd, 64)
    return buf


def _write_all(fd: int, data: bytes, stop: threading.Event, timeout: float = 10.0) -> int:
    """Write every byte of `data` to a (possibly back-pressured) fd, waiting for writability via
    select so the relay's upstream backpressure stalls — not busy-spins — the writer. Returns
    early on `stop` so teardown never strands the writer thread."""
    import select as _select
    import time as _time

    deadline = _time.monotonic() + timeout
    view = memoryview(data)
    sent = 0
    while sent < len(data):
        if stop.is_set() or _time.monotonic() >= deadline:
            return sent
        _, writable, _ = _select.select([], [fd], [], 0.2)
        if not writable:
            continue
        try:
            sent += os.write(fd, view[sent : sent + 65536])
        except BlockingIOError:
            continue
    return sent


def _recv_exactly(sock: socket.socket, n: int, timeout: float = 10.0) -> bytes:
    """Drain `n` bytes from a stream socket, returning short on EOF/timeout so a pump that
    evicts the client (closing the conn) makes the caller's length assertion fail."""
    import time as _time

    deadline = _time.monotonic() + timeout
    buf = b""
    while len(buf) < n:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            return buf
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(65536)
        except OSError:
            return buf
        if not chunk:
            return buf
        buf += chunk
    return buf


def _read_exactly_fd(fd: int, n: int, timeout: float = 10.0) -> bytes:
    """Read `n` bytes from a blocking fd, polling via select so a torn-down pump (no further
    device writes) fails the caller's assertion on a bounded timeout rather than hanging."""
    import select as _select
    import time as _time

    deadline = _time.monotonic() + timeout
    buf = b""
    while len(buf) < n:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            return buf
        readable, _, _ = _select.select([fd], [], [], min(remaining, 0.2))
        if not readable:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            return buf
        buf += chunk
    return buf


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


def test_console_only_bridge_survives_client_reconnect(tmp_path):
    """The console-only pump is a session-lifetime worker (plan §3): a client disconnect must
    not strand the line. After client1 leaves, the bridge stays 'ready' and a fresh client2 on
    the same socket path round-trips bytes again. Pre-fix the pump dies after one accept (F1)."""
    import pty

    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks")
    request = _request(LineRole.SHARED_CONSOLE, {"device": peripheral_name}, tmp_path)
    result = transport.attach(
        request, cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None
    )
    session = _StubSession(result.console_endpoint)
    try:
        path = result.console_endpoint.path
        client1 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client1.connect(path)
        client1.settimeout(2.0)
        os.write(controller_fd, b"hello-1\n")
        assert b"hello-1" in client1.recv(64)
        client1.close()

        client2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client2.connect(path)
        client2.settimeout(2.0)
        # Sync on client->device first: a console drops device output written while no client
        # is attached, so confirm the pump has re-accepted client2 before asserting delivery.
        client2.sendall(b"ping\n")
        assert b"ping" in _read_until(controller_fd, b"ping")
        os.write(controller_fd, b"hello-2\n")
        assert b"hello-2" in client2.recv(64)
        assert transport.health(session) == "ready"
        client2.close()
    finally:
        transport.close(session)
        os.close(controller_fd)
        os.close(peripheral_fd)


def test_console_only_bridge_does_not_evict_a_slow_client_and_loses_no_bytes(tmp_path):
    """Device→client backpressure (plan §F1): a client that reads slowly during a burst must not
    be evicted, and not one console byte may be dropped. A payload larger than the socket send
    buffer is written to the pty controller while the client drains lazily; the bridge buffers and
    applies upstream backpressure rather than misreading a full send buffer as a client departure.
    Pre-fix `sendall` on the non-blocking socket raises BlockingIOError → CLIENT_GONE → the slow
    client is evicted (conn closed) and the in-flight chunk is lost."""
    import pty

    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks")
    request = _request(LineRole.SHARED_CONSOLE, {"device": peripheral_name}, tmp_path)
    result = transport.attach(
        request, cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None
    )
    session = _StubSession(result.console_endpoint)
    payload = bytes(range(256)) * 4096  # 1 MiB: larger than the socket send buffer and the relay cap
    stop = threading.Event()
    # Non-blocking master: the writer stalls in select (not in os.write) so it observes `stop` and
    # exits promptly at teardown — otherwise a write wedged on a full pty buffer would block the
    # later os.close(controller_fd) forever on the pre-fix (eviction) path.
    os.set_blocking(controller_fd, False)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    writer = threading.Thread(target=_write_all, args=(controller_fd, payload, stop), daemon=True)
    try:
        client.connect(result.console_endpoint.path)
        writer.start()
        # Let the writer saturate the socket send buffer before draining. Pre-fix this is exactly
        # the moment the pump's sendall raises BlockingIOError and evicts the (merely slow) client;
        # post-fix the relay caps its buffer and back-pressures the writer with no eviction or loss.
        import time as _time

        _time.sleep(0.5)
        received = _recv_exactly(client, len(payload))
        assert received == payload  # in order, nothing dropped
        assert transport.health(session) == "ready"  # not evicted
    finally:
        stop.set()
        writer.join(timeout=2.0)
        transport.close(session)
        client.close()
        os.close(peripheral_fd)  # close the slave before the master so the master close cannot drain-block
        os.close(controller_fd)


def test_console_only_bridge_handles_partial_writes_to_a_busy_device(tmp_path):
    """Client→device backpressure (plan §F1): a busy device (its consumer not draining) must not
    tear the whole line down, and no typed input may be dropped on a short write. The client sends
    a payload larger than the pty buffer while the controller is drained lazily; the bridge buffers
    and back-pressures the client. Pre-fix `os.write` to the non-blocking device raises EAGAIN →
    SOURCE_DEAD (teardown) or returns a short count whose tail is silently discarded."""
    import pty

    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks")
    request = _request(LineRole.SHARED_CONSOLE, {"device": peripheral_name}, tmp_path)
    result = transport.attach(
        request, cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None
    )
    session = _StubSession(result.console_endpoint)
    payload = bytes(range(256)) * 4096  # 1 MiB
    writer_error: list[BaseException] = []
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def _send_payload():
        try:
            client.sendall(payload)
        except OSError as exc:  # the bridge closed the conn underneath us (pre-fix teardown / cleanup)
            writer_error.append(exc)

    writer = threading.Thread(target=_send_payload, daemon=True)
    try:
        client.connect(result.console_endpoint.path)
        writer.start()
        received = _read_exactly_fd(controller_fd, len(payload))
        assert received == payload  # in order, nothing dropped
        assert transport.health(session) == "ready"  # line not torn down
    finally:
        transport.close(session)  # closes the bridge conn → unblocks a client.sendall stalled on backpressure
        writer.join(timeout=2.0)
        client.close()
        os.close(peripheral_fd)  # close the slave before the master so the master close cannot drain-block
        os.close(controller_fd)


def test_stop_joins_the_pump_before_closing_the_source_fd(tmp_path, monkeypatch):
    """stop() must join the pump thread before it closes the data fds (plan §F2). Otherwise the
    pump can run os.read/recv/send/os.write on a just-closed source_fd integer that a concurrent
    attach on another device may have recycled → cross-session console cross-talk. We park the
    pump in select, then record its liveness at the instant the source fd is closed: it must
    already be dead. Pre-fix the source fd is closed before the join → pump still live → RED."""
    import pty
    import time as _time

    from kdive.transport import serial_local

    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks")
    request = _request(LineRole.SHARED_CONSOLE, {"device": peripheral_name}, tmp_path)
    result = transport.attach(
        request, cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None
    )
    session = _StubSession(result.console_endpoint)
    bridge = transport._bridges[result.console_endpoint.path]
    source_fd = bridge._source_fd

    real_close = serial_local.os.close
    alive_at_source_close: list[bool] = []

    def _recording_close(fd):
        if fd == source_fd:
            alive_at_source_close.append(bridge._thread.is_alive())
        return real_close(fd)

    # Park the pump in a deliberately slow select so it stays alive across stop()'s teardown
    # window, making the join-vs-close ordering observable rather than a scheduling coin-flip.
    # Closing the conn no longer wakes it (it is sleeping, not in a real select syscall).
    real_select = serial_local.select.select
    parked = threading.Event()

    def _slow_select(rlist, wlist, xlist, timeout=None):
        parked.set()
        _time.sleep(0.5)
        return real_select(rlist, wlist, xlist, 0)

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(result.console_endpoint.path)
        client.settimeout(2.0)
        os.write(controller_fd, b"sync\n")  # confirm the pump has accepted and is in _copy_loop
        assert b"sync" in client.recv(64)
        monkeypatch.setattr(serial_local.select, "select", _slow_select)
        monkeypatch.setattr(serial_local.os, "close", _recording_close)
        assert parked.wait(2.0)  # the pump is now sleeping inside the patched select
        transport.close(session)
        assert alive_at_source_close == [False]  # pump joined before the source fd was closed
    finally:
        client.close()
        os.close(peripheral_fd)
        os.close(controller_fd)


def test_write_client_retries_on_ewouldblock(tmp_path):
    """`_write_client` honors non-blocking socket semantics: EWOULDBLOCK is a retry (CONTINUE,
    buffer unchanged), a real OSError is a client departure (CLIENT_GONE), and a partial send
    trims only the bytes actually written so the unsent tail is retried (plan §F1)."""
    from kdive.transport.serial_local import SerialConsoleBridge, _PumpStep

    bridge = SerialConsoleBridge(socket_path=str(tmp_path / "c.sock"), session_dir=str(tmp_path), source_fd=-1)

    class _WouldBlock:
        def send(self, data):
            raise BlockingIOError("send buffer full")

    class _Broken:
        def send(self, data):
            raise BrokenPipeError("client closed")

    class _Partial:
        def send(self, data):
            return 2

    assert bridge._write_client(_WouldBlock(), b"abcde") == (b"abcde", _PumpStep.CONTINUE)
    assert bridge._write_client(_Broken(), b"abcde") == (b"abcde", _PumpStep.CLIENT_GONE)
    assert bridge._write_client(_Partial(), b"abcde") == (b"cde", _PumpStep.CONTINUE)


def test_read_source_eof_is_source_death(tmp_path):
    """`_read_source` maps a source EOF (`os.read` → b"") to SOURCE_DEAD so a genuinely dead
    line stops the pump rather than spinning re-accepting (plan §F1)."""
    from kdive.transport.serial_local import SerialConsoleBridge, _PumpStep

    read_fd, write_fd = os.pipe()
    os.close(write_fd)  # the source end is gone → EOF on the next read
    bridge = SerialConsoleBridge(socket_path=str(tmp_path / "c.sock"), session_dir=str(tmp_path), source_fd=read_fd)
    try:
        assert bridge._read_source(b"") == (b"", _PumpStep.SOURCE_DEAD)
    finally:
        os.close(read_fd)


def test_write_source_eagain_retries(tmp_path):
    """`_write_source` treats EAGAIN on a full non-blocking device as a retry (CONTINUE, buffer
    unchanged) — never SOURCE_DEAD — so device backpressure does not tear the line down (plan §F1)."""
    from kdive.transport.serial_local import SerialConsoleBridge, _PumpStep

    read_fd, write_fd = os.pipe()
    os.set_blocking(write_fd, False)
    bridge = SerialConsoleBridge(socket_path=str(tmp_path / "c.sock"), session_dir=str(tmp_path), source_fd=write_fd)
    try:
        try:
            while True:
                os.write(write_fd, b"x" * 65536)  # fill the pipe until it would block
        except BlockingIOError:
            pass
        assert bridge._write_source(b"pending") == (b"pending", _PumpStep.CONTINUE)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_console_only_bridge_stops_when_source_device_closes(tmp_path):
    """Source-device death (not a client disconnect) must exit the pump cleanly rather than
    spin re-accepting on a dead fd. Closing the pty controller drives the source to EOF; the
    bridge then reports 'degraded' and stays registered until Layer-4 close() (§4.7, F1)."""
    import pty
    import time

    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks")
    request = _request(LineRole.SHARED_CONSOLE, {"device": peripheral_name}, tmp_path)
    result = transport.attach(
        request, cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None
    )
    session = _StubSession(result.console_endpoint)
    closed: set[int] = set()
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(result.console_endpoint.path)
        client.settimeout(2.0)
        os.close(controller_fd)  # source EOF: the physical line is gone
        closed.add(controller_fd)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and transport.health(session) != "degraded":
            time.sleep(0.05)
        assert transport.health(session) == "degraded"
        client.close()
    finally:
        transport.close(session)
        if controller_fd not in closed:
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

    from kdive.transport import serial_local

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
            transport.attach(request, cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=_on_partial)
        assert not os.path.exists(captured["socket_path"])  # socket inode unlinked
        assert not os.path.exists(captured["session_dir"])  # session dir removed
        assert transport._bridges == {}  # bridge not registered / not leaked
    finally:
        os.close(controller_fd)
        os.close(peripheral_fd)


class _RecordingProxy:
    def __init__(self):
        from kdive.transport.proxy import ProxyHandle

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
        return False


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

    from kdive.transport.serial_local import SerialLocalConflictError

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

    from kdive.transport.serial_local import SerialLocalConflictError

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

    from kdive.transport.serial_local import SerialLocalConflictError

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


def test_source_lock_key_uses_device_number_for_char_devices(tmp_path):
    """The source-exclusivity lock keys on the device number (st_rdev) for a local char device,
    so every path to one node — symlink, hardlink, distinct mknod node, bind mount — collapses
    to a single lock (F2). A symlink alias yields the identical key as its canonical name."""
    import pty

    master, slave = pty.openpty()
    name = os.ttyname(slave)
    try:
        expected = f"rdev:{os.stat(name).st_rdev}"
        assert SerialLocalTransport._source_lock_key(name) == expected
        alias = tmp_path / "ttyAlias"
        os.symlink(name, alias)
        assert SerialLocalTransport._source_lock_key(str(alias)) == expected
    finally:
        os.close(master)
        os.close(slave)


def test_source_lock_key_falls_back_for_non_char_and_missing_paths(tmp_path):
    """Non-char devices (a remote-terminal-server placeholder) and paths that do not exist yet
    have no device number, so the key falls back to the canonical path, never an rdev: key (F2)."""
    regular = tmp_path / "regular.txt"
    regular.write_text("not a device")
    missing = tmp_path / "does-not-exist"
    assert SerialLocalTransport._source_lock_key(str(regular)) == os.path.realpath(str(regular))
    assert SerialLocalTransport._source_lock_key(str(missing)) == os.path.realpath(str(missing))


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
