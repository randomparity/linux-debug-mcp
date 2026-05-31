from __future__ import annotations

from pathlib import Path

import pytest

from kdive.domain import ErrorCategory
from kdive.providers.local.debug.gdb_mi import (
    RSP_REMOTE_TIMEOUT_SEC,
    GdbMiEngine,
    GdbMiError,
    _timeout_error,
)
from kdive.transport.base import TcpEndpoint

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

    def __init__(self, writes: list[object], reads: list[object] | None = None) -> None:
        self._writes = list(writes)
        self._reads = list(reads or [])
        self.commands: list[str] = []
        self.exited = False

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]:
        self.commands.append(command)
        item = self._writes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]

    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        if not self._reads:
            return []
        item = self._reads.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]

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


def _attach_engine(tmp_path: Path, controller: RecordingController):
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    engine = GdbMiEngine(
        controller_factory=lambda command: controller,
        gdb_path_finder=lambda _: "/usr/bin/gdb",
        sleep=lambda _seconds: None,
    )
    attachment = engine.attach(
        rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=5551),
        vmlinux_path=vmlinux,
        transcript_path=tmp_path / "mi.log",
    )
    return engine, attachment


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


# --- Task 2: transport_stall tagging (write-path + silence-path) -----------------------------------

_RUNNING: list[dict[str, object]] = [{"type": "result", "message": "running", "payload": None, "token": None}]


def _stopped(reason: str) -> list[dict[str, object]]:
    return [{"type": "notify", "message": "stopped", "payload": {"reason": reason}, "token": None}]


def test_timeout_error_is_transport_stall() -> None:
    exc = _timeout_error("-data-read-memory-bytes 0x0 4", 10.0)
    assert exc.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert exc.details.get("code") == "transport_stall"


def test_per_op_write_timeout_propagates_transport_stall(tmp_path: Path) -> None:
    # After a clean attach, the next per-op MI write times out -> the engine surfaces transport_stall.
    stall = _timeout_error("-data-list-register-names", 10.0)
    controller = RecordingController([*_PRE_CONNECT, _CONNECTED, stall])
    engine, attachment = _attach_engine(tmp_path, controller)
    with pytest.raises(GdbMiError) as exc:
        engine.read_registers(attachment, ["pc"])
    assert exc.value.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert exc.value.details.get("code") == "transport_stall"


def test_attach_phase_timeout_is_attach_failure_not_stall(tmp_path: Path) -> None:
    # A connect-phase timeout is an attach failure, not a mid-session stall (established = per-op only).
    stall = _timeout_error("-target-select remote 127.0.0.1:5551", 10.0)
    controller = RecordingController([*_PRE_CONNECT, stall, stall, stall])
    with pytest.raises(GdbMiError) as exc:
        _attach_engine(tmp_path, controller)
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert exc.value.details.get("code") != "transport_stall"


def test_resume_silence_after_accepted_interrupt_is_transport_stall(tmp_path: Path) -> None:
    # continue -> ^running; the link goes silent (no *stopped); the fallback interrupt write is
    # accepted but no SIGINT stop ever arrives -> a reachable kernel cannot ignore SIGINT -> stall.
    done: list[dict[str, object]] = [{"type": "result", "message": "done", "payload": None, "token": None}]
    # Every read returns [] (the link is silent): the continue wait times out AND the interrupt wait
    # sees no SIGINT stop -> stall.
    controller = RecordingController([*_PRE_CONNECT, _CONNECTED, _RUNNING, done], reads=[])
    engine, attachment = _attach_engine(tmp_path, controller)
    with pytest.raises(GdbMiError) as exc:
        engine.resume(attachment, "-exec-continue", timeout_sec=1)
    assert exc.value.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert exc.value.details.get("code") == "transport_stall"


def test_resume_timeout_with_sigint_stop_is_benign_timed_out(tmp_path: Path) -> None:
    # No breakpoint hit, but the fallback interrupt yields a SIGINT *stopped -> benign timed_out, NOT
    # a stall: the session stays usable (Phase-C behaviour preserved).
    done: list[dict[str, object]] = [{"type": "result", "message": "done", "payload": None, "token": None}]
    # The SIGINT stop arrives only after the continue wait's 3 read slices (timeout_sec=1), so the
    # interrupt wait observes it -> benign timed_out, not a stall.
    controller = RecordingController(
        [*_PRE_CONNECT, _CONNECTED, _RUNNING, done], reads=[[], [], [], _stopped("signal-received")]
    )
    engine, attachment = _attach_engine(tmp_path, controller)
    stop = engine.resume(attachment, "-exec-continue", timeout_sec=1)
    assert stop.timed_out is True
    assert stop.reason == "signal-received"
