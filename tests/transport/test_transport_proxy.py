import socket
import subprocess
import sys
import threading
import time

import pytest

from kdive.seams.process_identity import ProcessIdentity, ProcProcessIdentityProbe
from kdive.transport.backends.proxy import (
    AgentProxyBackend,
    LocalDeviceSource,
    ProxyHandle,
    ProxyIdentityError,
    RemoteTerminalServerSource,
)
from kdive.transport.core.bounded import Deadline


class _FakeProc:
    """Stand-in Popen: records lifecycle calls; `wait` raises TimeoutExpired while
    returncode is None so reap escalates terminate→kill like a real child."""

    def __init__(self, pid, *, dies_on_term=True):
        self.pid = pid
        self.returncode = None
        self._dies_on_term = dies_on_term
        self.events: list[str] = []

    def terminate(self):
        self.events.append("terminate")
        if self._dies_on_term:
            self.returncode = 0

    def kill(self):
        self.events.append("kill")
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(cmd="agent-proxy", timeout=timeout)
        return self.returncode

    def poll(self):
        self.events.append("poll")
        return self.returncode


class _FakeSpawner:
    """Records argv; returns a _FakeProc per call (tracked in self.procs). If `_pids` is an
    iterator, hands out a distinct pid per call (retry tests), else the fixed `pid`."""

    def __init__(self, pid: int = 5000):
        self.calls: list[list[str]] = []
        self.pid = pid
        self._pids = None
        self.procs: list[_FakeProc] = []

    def __call__(self, argv, *, deadline, cancel, **kwargs):
        self.calls.append(list(argv))
        pid = next(self._pids) if self._pids is not None else self.pid
        proc = _FakeProc(pid=pid, dies_on_term=True)
        self.procs.append(proc)
        return proc


def _ok_probe(start_time="t"):
    class _P:
        def identity(self, pid):
            return ProcessIdentity(pid=pid, start_time=start_time, argv0="agent-proxy")

        def is_alive(self, pid):
            return True

        def looks_like(self, pid, name_substr):
            return True

        def owns_listener(self, pid, host, port):
            return True

    return _P()


def test_local_device_argv_includes_s003_when_no_uart_break():
    spawner = _FakeSpawner()
    backend = AgentProxyBackend(spawner=spawner, identity_probe=_ok_probe())
    partials: list[tuple[str, object]] = []
    backend.start(
        LocalDeviceSource(device="/dev/ttyS0", baud=115200),
        supports_uart_break=False,
        cancel=threading.Event(),
        deadline=Deadline.after(2.0),
        on_partial=lambda kind, value: partials.append((kind, value)),
        _verify=False,  # identity verification covered in Task 5
    )
    argv = spawner.calls[0]
    assert argv[0] == "agent-proxy"
    assert "-s003" in argv
    assert "0" in argv and "/dev/ttyS0,115200" in argv
    # Ports are loopback-bind-pinned so agent-proxy does not listen on 0.0.0.0 (F1).
    assert argv[1].startswith("127.0.0.1:") and "^127.0.0.1:" in argv[1]
    # cleanup authority is published atomically as pid + start-time fingerprint (F1, round 5)
    assert partials == [("backend_process", {"pid": 5000, "start_time": "t"})]


def test_local_device_argv_omits_s003_when_uart_break_supported():
    spawner = _FakeSpawner()
    backend = AgentProxyBackend(spawner=spawner, identity_probe=_ok_probe())
    backend.start(
        LocalDeviceSource(device="/dev/ttyS0", baud=115200),
        supports_uart_break=True,
        cancel=threading.Event(),
        deadline=Deadline.after(2.0),
        on_partial=lambda *_: None,
        _verify=False,
    )
    assert "-s003" not in spawner.calls[0]


def test_remote_terminal_server_argv_uses_ip_and_port():
    spawner = _FakeSpawner()
    backend = AgentProxyBackend(spawner=spawner, identity_probe=_ok_probe())
    backend.start(
        RemoteTerminalServerSource(host="10.0.0.5", port=4001),
        supports_uart_break=True,
        cancel=threading.Event(),
        deadline=Deadline.after(2.0),
        on_partial=lambda *_: None,
        _verify=False,
    )
    argv = spawner.calls[0]
    assert "10.0.0.5" in argv and "4001" in argv


class _Probe:
    """Configurable identity probe. `owns` may be a bool or a callable(pid, port)->bool|None.
    `is_alive` consults `killed` so stop() returns promptly once SIGTERM is recorded."""

    def __init__(self, *, start_time="t", looks=True, owns=True, killed=None):
        self.start_time = start_time
        self._looks = looks
        self._owns = owns
        self._killed = killed if killed is not None else set()

    def identity(self, pid):
        return ProcessIdentity(pid=pid, start_time=self.start_time, argv0="agent-proxy")

    def is_alive(self, pid):
        return pid not in self._killed

    def looks_like(self, pid, name_substr):
        return self._looks

    def owns_listener(self, pid, host, port):
        return self._owns(pid, host, port) if callable(self._owns) else self._owns


def _live_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    return sock, sock.getsockname()[1]


def test_verify_rejects_a_foreign_owner_and_does_not_kill_anything(monkeypatch):
    """A real listener answers TCP, but our child does NOT own it (owns_listener False).
    _verify_identity raises and signals nothing — killing is start()'s job, on OUR child."""
    killed = []
    monkeypatch.setattr("os.kill", lambda pid, sig: killed.append(pid))
    listener, port = _live_listener()
    backend = AgentProxyBackend(spawner=_FakeSpawner(pid=6000), identity_probe=_Probe(owns=False))
    handle = ProxyHandle(process=object(), backend_pid=6000, backend_start_time="t", console_port=port, gdb_port=port)
    try:
        with pytest.raises(ProxyIdentityError):
            backend._verify_identity(handle, deadline=Deadline.after(0.5), cancel=threading.Event())
        assert killed == []
    finally:
        listener.close()


def test_verify_fails_closed_when_ownership_is_unknown_even_with_a_live_listener():
    """owns_listener None (e.g. /proc unreadable) while a listener answers and our child
    is alive+named: verification must REJECT (fail closed), not pass (round-2 review F2)."""
    listener, port = _live_listener()
    backend = AgentProxyBackend(
        spawner=_FakeSpawner(pid=6000), identity_probe=_Probe(owns=lambda pid, host, port: None)
    )
    handle = ProxyHandle(process=object(), backend_pid=6000, backend_start_time="t", console_port=port, gdb_port=port)
    try:
        with pytest.raises(ProxyIdentityError):
            backend._verify_identity(handle, deadline=Deadline.after(0.5), cancel=threading.Event())
    finally:
        listener.close()


def test_verify_waits_for_a_listener_that_comes_up_after_spawn():
    """agent-proxy's bind+listen happens AFTER fork+exec returns — on a slow host the parent's
    immediate connect_tcp loses that race and gets ECONNREFUSED before the child has reached
    setup_local_port's listen(). _verify_identity must poll for the listener within the
    deadline rather than fail closed on the first refusal; otherwise start()'s respawn loop
    just hits the same race on every attempt (gated CI failure on ubuntu-24.04, round-7+)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # release the port — connect_tcp gets ECONNREFUSED until the thread re-binds

    listener_holder: list[socket.socket] = []

    def _bind_after_delay():
        time.sleep(0.3)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(5)
        listener_holder.append(s)

    t = threading.Thread(target=_bind_after_delay, daemon=True)
    t.start()
    backend = AgentProxyBackend(spawner=_FakeSpawner(pid=6000), identity_probe=_Probe())
    handle = ProxyHandle(process=object(), backend_pid=6000, backend_start_time="t", console_port=port, gdb_port=port)
    try:
        backend._verify_identity(handle, deadline=Deadline.after(3.0), cancel=threading.Event())
    finally:
        t.join(timeout=2.0)
        if listener_holder:
            listener_holder[0].close()


def test_verify_still_fails_closed_when_the_listener_never_comes_up():
    """The polling fix must remain bounded: if no listener appears before the deadline
    expires, _verify_identity must raise ProxyIdentityError rather than block forever."""
    # Pick a port nobody is listening on — bind+close to find a free port, never re-listen.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    backend = AgentProxyBackend(spawner=_FakeSpawner(pid=6000), identity_probe=_Probe())
    handle = ProxyHandle(process=object(), backend_pid=6000, backend_start_time="t", console_port=port, gdb_port=port)
    with pytest.raises(ProxyIdentityError):
        backend._verify_identity(handle, deadline=Deadline.after(0.3), cancel=threading.Event())


def test_start_retries_after_a_foreign_bind_and_reaps_only_our_own_child(monkeypatch):
    """First attempt loses the bind race (verify raises); start() reaps OUR first child via
    its owned Popen, reallocates, and the second attempt verifies. We only ever act on our
    own _FakeProc objects, so a foreign listener's owner can never be signalled."""
    spawner = _FakeSpawner()
    spawner._pids = iter([6000, 6001])  # distinct pid per attempt

    calls = {"n": 0}

    def _verify(handle, *, deadline, cancel):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ProxyIdentityError("foreign bind on first attempt")

    backend = AgentProxyBackend(spawner=spawner, identity_probe=_Probe())
    monkeypatch.setattr(backend, "_verify_identity", _verify)
    handle = backend.start(
        LocalDeviceSource(device="/dev/ttyS0"),
        supports_uart_break=True,
        cancel=threading.Event(),
        deadline=Deadline.after(5.0),
        on_partial=lambda *_: None,
    )
    assert handle.backend_pid == 6001
    assert "terminate" in spawner.procs[0].events  # first child reaped
    assert "terminate" not in spawner.procs[1].events  # second child kept


def test_start_fails_closed_and_reaps_when_no_start_time_fingerprint():
    """identity()/start_time is None ⇒ the handle would be unreapable later (F2). start()
    must reject and reap the spawned child rather than return an unreapable handle."""

    class _NoFingerprint:
        def identity(self, pid):
            return None  # no start-time fingerprint

        def is_alive(self, pid):
            return True

        def looks_like(self, pid, name_substr):
            return True

        def owns_listener(self, pid, host, port):
            return True

    proc = _FakeProc(pid=8100, dies_on_term=True)
    backend = AgentProxyBackend(spawner=lambda *a, **k: proc, identity_probe=_NoFingerprint())
    with pytest.raises(ProxyIdentityError):
        backend.start(
            LocalDeviceSource(device="/dev/ttyS0"),
            supports_uart_break=True,
            cancel=threading.Event(),
            deadline=Deadline.after(1.0),
            on_partial=lambda *_: None,
        )
    assert "terminate" in proc.events  # reaped despite the missing fingerprint


def test_start_reaps_the_spawned_child_when_verification_is_cancelled(monkeypatch):
    """cancel during verification raises BoundedIOCancelled out of _verify_identity; start()
    must reap the already-spawned child before propagating (round-3 review F1)."""
    from kdive.transport.core.bounded import BoundedIOCancelled

    proc = _FakeProc(pid=8000, dies_on_term=True)
    backend = AgentProxyBackend(spawner=lambda *a, **k: proc, identity_probe=_Probe(start_time="t"))

    def _cancelled(handle, *, deadline, cancel):
        raise BoundedIOCancelled("cancelled mid-verify")

    monkeypatch.setattr(backend, "_verify_identity", _cancelled)
    with pytest.raises(BoundedIOCancelled):
        backend.start(
            LocalDeviceSource(device="/dev/ttyS0"),
            supports_uart_break=True,
            cancel=threading.Event(),
            deadline=Deadline.after(5.0),
            on_partial=lambda *_: None,
        )
    assert "terminate" in proc.events  # spawned child reaped, not leaked


def test_stop_terminates_and_reaps_our_child():
    proc = _FakeProc(pid=7000, dies_on_term=True)
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="77"))
    handle = ProxyHandle(process=proc, backend_pid=7000, backend_start_time="77", console_port=1, gdb_port=2)
    backend.stop(handle)
    assert "terminate" in proc.events
    assert proc.returncode is not None  # actually reaped, not a zombie


def test_stop_escalates_to_kill_when_terminate_does_not_reap():
    proc = _FakeProc(pid=7000, dies_on_term=False)
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="77"))
    handle = ProxyHandle(process=proc, backend_pid=7000, backend_start_time="77", console_port=1, gdb_port=2)
    backend.stop(handle)
    assert proc.events[0] == "terminate" and "kill" in proc.events


def test_stop_does_not_signal_a_pid_whose_start_time_no_longer_matches():
    """pid reuse: a different process now holds backend_pid; start-time mismatch ⇒ never
    terminate/kill — only poll() to reap our own exited child."""
    proc = _FakeProc(pid=7000)
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="DIFFERENT"))
    handle = ProxyHandle(process=proc, backend_pid=7000, backend_start_time="77", console_port=1, gdb_port=2)
    backend.stop(handle)
    assert "terminate" not in proc.events and "kill" not in proc.events


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="default /proc identity probe")
def test_stop_reaps_a_real_subprocess():
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    probe = ProcProcessIdentityProbe()
    identity = probe.identity(proc.pid)
    backend = AgentProxyBackend()  # default ProcProcessIdentityProbe
    handle = ProxyHandle(
        process=proc, backend_pid=proc.pid, backend_start_time=identity.start_time, console_port=1, gdb_port=2
    )
    backend.stop(handle)
    assert proc.poll() is not None  # the real child was reaped


def test_stop_by_identity_signals_only_on_a_fingerprint_match(monkeypatch):
    """Crash-recovery reaper (no Popen): signals by pid only when the live start-time
    matches the durable record (round-6 F1)."""
    signalled = []
    monkeypatch.setattr("os.kill", lambda pid, sig: signalled.append(pid))
    # is_alive False for 9000 so the post-SIGTERM wait loop returns promptly.
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="77", killed={9000}))
    backend.stop_by_identity(9000, "77")
    assert 9000 in signalled


def test_stop_by_identity_refuses_without_or_on_mismatched_fingerprint(monkeypatch):
    signalled = []
    monkeypatch.setattr("os.kill", lambda pid, sig: signalled.append(pid))
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="DIFFERENT"))
    backend.stop_by_identity(9000, None)  # no fingerprint → unfenceable → refuse
    backend.stop_by_identity(9000, "77")  # live start_time "DIFFERENT" ≠ recorded "77"
    assert signalled == []


def test_spawn_reaps_the_child_if_on_partial_raises():
    """on_partial may fsync the durable record (Layer 4) and fail; the just-spawned child
    must be reaped before the error propagates (round-8 F1)."""
    proc = _FakeProc(pid=8200, dies_on_term=True)

    def _boom(kind, value):
        raise RuntimeError("durable record fsync failed")

    backend = AgentProxyBackend(spawner=lambda *a, **k: proc, identity_probe=_Probe(start_time="t"))
    with pytest.raises(RuntimeError):
        backend.start(
            LocalDeviceSource(device="/dev/ttyS0"),
            supports_uart_break=True,
            cancel=threading.Event(),
            deadline=Deadline.after(2.0),
            on_partial=_boom,
        )
    assert "terminate" in proc.events


def test_spawn_reaps_the_child_if_identity_raises():
    """An identity-probe failure after spawn must also reap the child (round-8 F1)."""
    proc = _FakeProc(pid=8300, dies_on_term=True)

    class _BoomProbe:
        def identity(self, pid):
            raise RuntimeError("identity probe failed")

        def is_alive(self, pid):
            return True

        def looks_like(self, pid, name_substr):
            return True

        def owns_listener(self, pid, host, port):
            return True

    backend = AgentProxyBackend(spawner=lambda *a, **k: proc, identity_probe=_BoomProbe())
    with pytest.raises(RuntimeError):
        backend.start(
            LocalDeviceSource(device="/dev/ttyS0"),
            supports_uart_break=True,
            cancel=threading.Event(),
            deadline=Deadline.after(2.0),
            on_partial=lambda *_: None,
        )
    assert "terminate" in proc.events


def test_health_is_degraded_when_a_foreign_process_owns_the_port():
    """The child is alive but no longer owns the loopback port (a foreign process bound it);
    health must report degraded, not bless the stolen endpoint (round-8 F2)."""
    listener, port = _live_listener()
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="t", owns=False))
    handle = ProxyHandle(
        process=_FakeProc(pid=9500), backend_pid=9500, backend_start_time="t", console_port=port, gdb_port=port
    )
    try:
        assert backend.health(handle) == "degraded"
    finally:
        listener.close()


def test_break_escape_is_the_pinned_telnet_iac_break():
    from kdive.transport.backends.proxy import _BREAK_ESCAPE

    assert _BREAK_ESCAPE == b"\xff\xf3"  # agent-proxy.c defaultBrkStr {0xff,0xf3}


def test_send_break_writes_the_pinned_escape_to_the_console_port():
    from kdive.transport.backends.proxy import _BREAK_ESCAPE

    listener, port = _live_listener()
    received = []
    done = threading.Event()

    def _accept():
        conn, _ = listener.accept()
        received.append(conn.recv(64))
        conn.close()
        done.set()

    threading.Thread(target=_accept, daemon=True).start()
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe())
    handle = ProxyHandle(process=object(), backend_pid=1, backend_start_time="t", console_port=port, gdb_port=port)
    backend.send_break(handle)
    done.wait(timeout=2.0)
    listener.close()
    assert received and _BREAK_ESCAPE in received[0]


def test_send_break_rechecks_ownership_after_connect_and_writes_nothing():
    """The port can be stolen in the window between the pre-connect ownership check and the
    write (F2). send_break must re-verify ownership AFTER connect, immediately before the
    write, and refuse — writing no BREAK bytes to the now-foreign listener."""
    from kdive.transport.backends.proxy import _BREAK_ESCAPE

    class _OwnsThenLoses:
        def __init__(self):
            self.owns_calls = 0

        def identity(self, pid):
            return ProcessIdentity(pid=pid, start_time="t", argv0="agent-proxy")

        def is_alive(self, pid):
            return True

        def looks_like(self, pid, name_substr):
            return True

        def owns_listener(self, pid, host, port):
            self.owns_calls += 1
            return self.owns_calls == 1  # owned pre-connect, stolen by the post-connect re-check

    listener, port = _live_listener()
    received = []
    accepted = threading.Event()

    def _accept():
        conn, _ = listener.accept()
        accepted.set()
        received.append(conn.recv(64))
        conn.close()

    threading.Thread(target=_accept, daemon=True).start()
    probe = _OwnsThenLoses()
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=probe)
    handle = ProxyHandle(
        process=_FakeProc(pid=1), backend_pid=1, backend_start_time="t", console_port=port, gdb_port=port
    )
    try:
        with pytest.raises(ProxyIdentityError):
            backend.send_break(handle)
        assert probe.owns_calls == 2  # ownership was re-checked after connect
        accepted.wait(timeout=2.0)
        assert all(_BREAK_ESCAPE not in chunk for chunk in received)  # no BREAK bytes written
    finally:
        listener.close()


def test_send_break_refuses_when_child_no_longer_owns_the_console_port():
    """A live listener answers, but our child no longer owns the port (owns_listener False):
    send_break must refuse rather than write BREAK bytes to a foreign listener (round-9 F1)."""
    listener, port = _live_listener()
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="t", owns=False))
    handle = ProxyHandle(
        process=_FakeProc(pid=1), backend_pid=1, backend_start_time="t", console_port=port, gdb_port=port
    )
    try:
        with pytest.raises(ProxyIdentityError):
            backend.send_break(handle)
    finally:
        listener.close()
