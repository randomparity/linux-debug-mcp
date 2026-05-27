import subprocess
import threading

from linux_debug_mcp.seams.process_identity import ProcessIdentity
from linux_debug_mcp.transport.bounded import Deadline
from linux_debug_mcp.transport.proxy import (
    AgentProxyBackend,
    LocalDeviceSource,
    RemoteTerminalServerSource,
)


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
