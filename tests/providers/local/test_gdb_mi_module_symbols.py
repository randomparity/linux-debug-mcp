from __future__ import annotations

from pathlib import Path

import pytest

from kdive.domain import ErrorCategory
from kdive.providers.local.gdb_mi import GdbMiEngine, GdbMiError, LoadedModule
from kdive.transport.base import TcpEndpoint

_DONE: list[dict[str, object]] = [{"type": "result", "message": "done", "payload": None, "token": None}]
_CONNECTED: list[dict[str, object]] = [{"type": "result", "message": "connected", "payload": None, "token": None}]
# confirm/pagination/mi-async/file-exec/remotetimeout (^done) then connect (^connected).
_ATTACH_OK = [_DONE, _DONE, _DONE, _DONE, _DONE, _CONNECTED]


class RecordingController:
    def __init__(self, writes: list[object]) -> None:
        self._writes = list(writes)
        self.commands: list[str] = []

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]:
        self.commands.append(command)
        item = self._writes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]

    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        return []

    def exit(self) -> None:
        return None


def _attached(tmp_path: Path, writes: list[object]):
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = RecordingController([*_ATTACH_OK, *writes])
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
    return engine, controller, attachment


def test_load_module_symbols_issues_add_symbol_file(tmp_path: Path) -> None:
    ko = tmp_path / "foo.ko"
    ko.write_text("elf", encoding="utf-8")
    engine, controller, attachment = _attached(tmp_path, writes=[_DONE])
    loaded = engine.load_module_symbols(
        attachment,
        name="foo",
        ko_path=ko,
        sections={".text": "0xffffffffc0000000", ".data": "0xffffffffc0010000"},
    )
    assert isinstance(loaded, LoadedModule)
    assert loaded.name == "foo"
    assert loaded.sections[".text"] == "0xffffffffc0000000"
    # .text is the positional address; other sections follow as `-s <name> <addr>` (deterministic).
    assert (
        controller.commands[-1]
        == f'-interpreter-exec console "add-symbol-file {ko} 0xffffffffc0000000 -s .data 0xffffffffc0010000"'
    )


def test_load_module_symbols_rejects_non_hex_address(tmp_path: Path) -> None:
    ko = tmp_path / "foo.ko"
    ko.write_text("elf", encoding="utf-8")
    engine, controller, attachment = _attached(tmp_path, writes=[])
    before = list(controller.commands)
    with pytest.raises(GdbMiError) as exc:
        engine.load_module_symbols(attachment, name="foo", ko_path=ko, sections={".text": "0xZZ; quit"})
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert controller.commands == before  # validated before any MI command


def test_load_module_symbols_requires_text_section(tmp_path: Path) -> None:
    ko = tmp_path / "foo.ko"
    ko.write_text("elf", encoding="utf-8")
    engine, controller, attachment = _attached(tmp_path, writes=[])
    with pytest.raises(GdbMiError) as exc:
        engine.load_module_symbols(attachment, name="foo", ko_path=ko, sections={".data": "0xffffffffc0010000"})
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_load_module_symbols_rejects_ko_with_whitespace(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[])
    with pytest.raises(GdbMiError) as exc:
        engine.load_module_symbols(
            attachment, name="foo", ko_path=Path("/build/bad path/foo.ko"), sections={".text": "0xffffffffc0000000"}
        )
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_load_module_symbols_error_record_is_attach_failure(tmp_path: Path) -> None:
    ko = tmp_path / "foo.ko"
    ko.write_text("elf", encoding="utf-8")
    error = [{"type": "result", "message": "error", "payload": {"msg": "cannot read .ko"}, "token": None}]
    engine, controller, attachment = _attached(tmp_path, writes=[error])
    with pytest.raises(GdbMiError) as exc:
        engine.load_module_symbols(attachment, name="foo", ko_path=ko, sections={".text": "0xffffffffc0000000"})
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE
