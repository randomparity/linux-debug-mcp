from __future__ import annotations

from pathlib import Path

import pytest

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.providers.gdb_mi import (
    RSP_REMOTE_TIMEOUT_SEC,
    GdbMiEngine,
    GdbMiError,
)
from linux_debug_mcp.transport.base import TcpEndpoint

_DONE: list[dict[str, object]] = [{"type": "result", "message": "done", "payload": None, "token": None}]
_CONNECTED: list[dict[str, object]] = [{"type": "result", "message": "connected", "payload": None, "token": None}]
_CONNECT_ERROR: list[dict[str, object]] = [
    {"type": "result", "message": "error", "payload": {"msg": "Connection refused."}, "token": None}
]
# attach() issues five non-connect commands (confirm/pagination/mi-async/file-exec/remotetimeout) then
# the connect; each non-connect command answers ^done.
_PRE_CONNECT = [_DONE, _DONE, _DONE, _DONE, _DONE]


class RecordingController:
    """Scripted MiController recording every command and whether exit() ran. write() pops the next
    scripted response (a list of raw dicts, or an Exception to raise)."""

    def __init__(self, writes: list[object]) -> None:
        self._writes = list(writes)
        self.commands: list[str] = []
        self.exited = False

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]:
        self.commands.append(command)
        item = self._writes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]

    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        return []

    def exit(self) -> None:
        self.exited = True


def _attach(tmp_path: Path, controller: RecordingController, sleeps: list[float]):
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    engine = GdbMiEngine(
        controller_factory=lambda command: controller,
        gdb_path_finder=lambda _: "/usr/bin/gdb",
        sleep=sleeps.append,
    )
    return engine.attach(
        rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=5551),
        vmlinux_path=vmlinux,
        transcript_path=tmp_path / "mi.log",
    )


def _connect_index(commands: list[str]) -> int:
    return next(i for i, c in enumerate(commands) if c.startswith("-target-select remote"))


def test_attach_sets_remotetimeout_before_target_select(tmp_path: Path) -> None:
    controller = RecordingController([*_PRE_CONNECT, _CONNECTED])
    _attach(tmp_path, controller, [])
    remotetimeout = f"-gdb-set remotetimeout {RSP_REMOTE_TIMEOUT_SEC}"
    assert remotetimeout in controller.commands
    assert controller.commands.index(remotetimeout) < _connect_index(controller.commands)


def test_connect_retries_transient_error_then_succeeds(tmp_path: Path) -> None:
    controller = RecordingController([*_PRE_CONNECT, _CONNECT_ERROR, _CONNECTED])
    sleeps: list[float] = []
    _attach(tmp_path, controller, sleeps)
    connects = [c for c in controller.commands if c.startswith("-target-select remote")]
    assert len(connects) == 2  # one retry
    assert len(sleeps) == 1  # one backoff between the two attempts
    assert controller.exited is False  # attach succeeded, engine kept


def test_connect_exhausts_retries_then_fails_attach(tmp_path: Path) -> None:
    controller = RecordingController([*_PRE_CONNECT, _CONNECT_ERROR, _CONNECT_ERROR, _CONNECT_ERROR])
    sleeps: list[float] = []
    with pytest.raises(GdbMiError) as exc:
        _attach(tmp_path, controller, sleeps)
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    connects = [c for c in controller.commands if c.startswith("-target-select remote")]
    assert len(connects) == 3  # _CONNECT_RETRY_COUNT attempts
    assert len(sleeps) == 2  # backoff between attempts, not after the last
    assert controller.exited is True  # failed attach tears the engine down
