from __future__ import annotations

from pathlib import Path

import pytest

from kdive.domain import ErrorCategory
from kdive.providers.gdb_mi import (
    CANONICAL_PROBE_SYMBOL,
    GdbMiEngine,
    GdbMiError,
    MiController,
    MiRecord,
    ResolvedSymbol,
)
from kdive.transport.base import TcpEndpoint


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

    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        return []

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
# The attach sequence is 5 setup commands (confirm/pagination/mi-async/file/remotetimeout) +
# target-select.
_ATTACH_OK = [_DONE, _DONE, _DONE, _DONE, _DONE, _CONNECTED]


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
    # 5 setup commands answer ^done; the connect is retried 3 times (ADR 0023), each ^error.
    controller = FakeController([_DONE, _DONE, _DONE, _DONE, _DONE, error, error, error])
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
    # target-select returns ^done instead of ^connected (stub answered but did not connect). ^done is
    # not an error, so the connect is not retried; 5 setup ^done + the connect ^done.
    controller = FakeController([_DONE, _DONE, _DONE, _DONE, _DONE, _DONE])
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


# A -data-evaluate-expression "&linux_banner" success: ^done with a value field.
_EVAL_OK: list[dict[str, object]] = [
    {"type": "result", "message": "done", "payload": {"value": "0x1234 <linux_banner>"}, "token": None}
]


def test_resolve_symbol_returns_typed_value(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = FakeController([*_ATTACH_OK, _EVAL_OK])
    engine = _engine(controller)
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    resolved = engine.resolve_symbol(attachment, CANONICAL_PROBE_SYMBOL)
    assert isinstance(resolved, ResolvedSymbol)
    assert resolved.name == CANONICAL_PROBE_SYMBOL
    assert resolved.value == "0x1234 <linux_banner>"
    # the address-of a bare identifier is sent, quoted, as a single MI argument
    assert controller.commands[-1] == '-data-evaluate-expression "&linux_banner"'


def test_resolve_symbol_rejects_non_identifier_name_without_touching_gdb(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = FakeController(list(_ATTACH_OK))  # no eval response scripted
    engine = _engine(controller)
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    commands_before = list(controller.commands)
    with pytest.raises(GdbMiError) as exc:
        engine.resolve_symbol(attachment, "linux_banner; call system")
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert controller.commands == commands_before  # gdb was never asked


def test_resolve_symbol_raises_debug_attach_failure_on_error_record(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    error = [{"type": "result", "message": "error", "payload": {"msg": 'No symbol "linux_banner"'}, "token": None}]
    controller = FakeController([*_ATTACH_OK, error])
    engine = _engine(controller)
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    with pytest.raises(GdbMiError) as exc:
        engine.resolve_symbol(attachment, CANONICAL_PROBE_SYMBOL)
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE


def test_resolve_symbol_raises_when_done_has_no_value(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    no_value = [{"type": "result", "message": "done", "payload": None, "token": None}]
    controller = FakeController([*_ATTACH_OK, no_value])
    engine = _engine(controller)
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    with pytest.raises(GdbMiError) as exc:
        engine.resolve_symbol(attachment, CANONICAL_PROBE_SYMBOL)
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE


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
