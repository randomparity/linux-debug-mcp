from __future__ import annotations

from pathlib import Path

import pytest

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.providers.gdb_mi import GdbMiEngine, GdbMiError, MiController, MiRecord
from linux_debug_mcp.transport.base import TcpEndpoint


class FakeController:
    """Injectable MiController: each write() pops the next scripted response (a list of raw pygdbmi
    dicts) or raises the scripted exception. Records every command for assertions."""

    def __init__(self, scripted: list[object]) -> None:
        self._scripted = list(scripted)
        self.commands: list[str] = []
        self.exited = False

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]:
        self.commands.append(command)
        item = self._scripted.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]

    def exit(self) -> None:
        self.exited = True


def test_fakecontroller_satisfies_protocol() -> None:
    controller = FakeController([[{"type": "result", "message": "done", "payload": None, "token": None}]])
    assert isinstance(controller, MiController)


def test_gdb_mi_error_carries_category() -> None:
    err = GdbMiError("boom", category=ErrorCategory.DEBUG_ATTACH_FAILURE, details={"k": "v"})
    assert err.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert err.details == {"k": "v"}


_DONE: list[dict[str, object]] = [{"type": "result", "message": "done", "payload": None, "token": None}]
_CONNECTED: list[dict[str, object]] = [{"type": "result", "message": "connected", "payload": None, "token": None}]
# With mi-async on, `-exec-continue` returns `^running` immediately (no terminal stop follows).
_RUNNING: list[dict[str, object]] = [{"type": "result", "message": "running", "payload": None, "token": None}]
# The attach sequence is 4 setup commands (confirm/pagination/mi-async/file) + target-select.
_ATTACH_OK = [_DONE, _DONE, _DONE, _DONE, _CONNECTED]


def _endpoint() -> TcpEndpoint:
    return TcpEndpoint(host="127.0.0.1", port=5551)


def _engine(controller: FakeController) -> GdbMiEngine:
    return GdbMiEngine(controller_factory=lambda command: controller, gdb_path_finder=lambda _: "/usr/bin/gdb")


def test_attach_loads_symbols_selects_remote_and_sets_async(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = FakeController(list(_ATTACH_OK))
    engine = _engine(controller)
    attachment = engine.attach(
        rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "debug" / "mi.log"
    )
    assert "-gdb-set mi-async on" in controller.commands
    assert any(cmd.startswith("-file-exec-and-symbols") for cmd in controller.commands)
    assert "-target-select remote 127.0.0.1:5551" in controller.commands
    assert any(r.type == "result" and r.message == "connected" for r in attachment.records)
    assert (tmp_path / "debug" / "mi.log").is_file()  # transcript persisted


def test_attach_rejects_endpoint_that_is_not_a_tcp_endpoint(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    engine = _engine(FakeController([]))
    # A None rsp_endpoint (transport never produced a TCP RSP path) is a CONFIGURATION_ERROR via the
    # public attach() boundary; TcpEndpoint already pins loopback at its own schema, so a
    # non-loopback TcpEndpoint cannot be constructed to test.
    with pytest.raises(GdbMiError) as exc:
        engine.attach(rsp_endpoint=None, vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_attach_missing_gdb_raises_missing_dependency(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    engine = GdbMiEngine(controller_factory=lambda command: FakeController([]), gdb_path_finder=lambda _: None)
    with pytest.raises(GdbMiError) as exc:
        engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    assert exc.value.category == ErrorCategory.MISSING_DEPENDENCY


def test_attach_missing_vmlinux_raises_configuration_error(tmp_path: Path) -> None:
    engine = _engine(FakeController([]))
    with pytest.raises(GdbMiError) as exc:
        engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=tmp_path / "absent", transcript_path=tmp_path / "mi.log")
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_attach_raises_on_error_record_and_exits(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    error = [{"type": "result", "message": "error", "payload": {"msg": "boom"}, "token": None}]
    controller = FakeController([_DONE, _DONE, _DONE, _DONE, error])  # target-select errors
    engine = _engine(controller)
    with pytest.raises(GdbMiError) as exc:
        engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert controller.exited is True  # a failed attach must not leak the gdb process


def test_probe_read_returns_the_connected_attach_proof(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = FakeController(list(_ATTACH_OK))
    engine = _engine(controller)
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    record = engine.probe_read(attachment)
    assert isinstance(record, MiRecord)
    assert record.type == "result" and record.message == "connected"
    # probe_read issues NO new MI command; it returns the connect proof already captured at attach.
    assert controller.commands[-1] == "-target-select remote 127.0.0.1:5551"


def test_probe_read_without_connected_record_raises(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    # target-select returns ^done instead of ^connected (stub answered but did not connect).
    controller = FakeController([_DONE, _DONE, _DONE, _DONE, _DONE])
    engine = _engine(controller)
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    with pytest.raises(GdbMiError) as exc:
        engine.probe_read(attachment)
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE


def test_resume_and_detach_continues_disconnects_then_exits(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    # async continue returns ^running immediately; disconnect returns ^done.
    controller = FakeController([*_ATTACH_OK, _RUNNING, _DONE])
    engine = _engine(controller)
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    confirmed = engine.resume_and_detach(attachment)
    assert confirmed is True
    assert controller.exited is True
    assert "-exec-continue" in controller.commands
    assert "-target-disconnect" in controller.commands
    # CI-checkable anti-hang proxy: mi-async MUST be set before the continue, else a real sync
    # `-exec-continue` would block until a stop a free-running kernel never emits.
    assert controller.commands.index("-gdb-set mi-async on") < controller.commands.index("-exec-continue")


def test_force_resume_swallows_errors_and_kills(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    # continue raises, disconnect raises; force_resume must still exit() and report resume confirmed
    # because killing the controller disconnects RSP, which resumes QEMU.
    controller = FakeController([*_ATTACH_OK, RuntimeError("continue failed"), RuntimeError("disconnect failed")])
    engine = _engine(controller)
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    confirmed = engine.force_resume(attachment)
    assert confirmed is True
    assert controller.exited is True
