"""Phase D (#82): debug.load_module_symbols handler — sysfs section sourcing over SSH, .ko
resolution under the build tree, and the idempotent loaded_modules ledger."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from test_server_debug_core_ops import (
    RUN_ID,
    FakeMiEngine,
    _build_transaction,
    _create_debug_ready_run,
    _make_registry,
    _profiles,
    _start,
)

from kdive.config import DebugProfile
from kdive.domain import ErrorCategory
from kdive.providers.gdb_mi import GdbMiSessionRegistry, LoadedModule
from kdive.server import debug_load_module_symbols_handler


@dataclass
class _SshResult:
    exit_status: int
    stdout: str = ""
    stderr: str = ""
    stdout_snippet: str = ""
    stderr_snippet: str = ""
    timed_out: bool = False
    cancelled: bool = False
    stdin_failed: bool = False
    oversized_output: bool = False


class FakeSshRunner:
    """Returns a canned section-read result; records whether it was invoked."""

    def __init__(self, result: _SshResult) -> None:
        self._result = result
        self.ran = False

    def which(self, command: str) -> str | None:
        return "/usr/bin/ssh"

    def run(self, argv, *, timeout, stdout_path, stderr_path, **kwargs) -> _SshResult:
        self.ran = True
        return self._result


class _LoaderEngine(FakeMiEngine):
    def __init__(self) -> None:
        super().__init__()
        self.loaded: list[tuple[str, str, dict[str, str]]] = []

    def load_module_symbols(self, attachment, *, name, ko_path, sections) -> LoadedModule:
        self.loaded.append((name, str(ko_path), dict(sections)))
        return LoadedModule(name=name, sections=sections)


def _started(tmp_path: Path):
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = _LoaderEngine()
    sessions = GdbMiSessionRegistry()
    start = _start(artifact_root, registry=registry, txn=txn, admission=admission, engine=engine, sessions=sessions)
    assert start.ok is True, start
    return artifact_root, registry, txn, admission, engine, sessions, start.data["debug_session_id"]


def _ko_in_build_tree(artifact_root: Path, name: str = "foo") -> Path:
    ko = artifact_root / RUN_ID / "build" / f"{name}.ko"
    ko.write_text("elf", encoding="utf-8")
    return ko


def _call(artifact_root, registry, txn, admission, engine, sessions, session_id, **overrides):
    kwargs = dict(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        module="foo",
        debug_session_id=session_id,
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )
    kwargs.update(overrides)
    return debug_load_module_symbols_handler(**kwargs)


def test_reads_sysfs_sections_and_loads(tmp_path: Path) -> None:
    artifact_root, registry, txn, admission, engine, sessions, sid = _started(tmp_path)
    ko = _ko_in_build_tree(artifact_root)
    ssh = FakeSshRunner(_SshResult(0, stdout=".text 0xffffffffc0000000\n.data 0xffffffffc0010000\n"))
    response = _call(
        artifact_root,
        registry,
        txn,
        admission,
        engine,
        sessions,
        sid,
        ssh_runner=ssh,
        module_ko_finder=lambda build_tree, module: ko,
    )
    assert response.ok is True, response
    assert ssh.ran is True
    assert engine.loaded == [("foo", str(ko), {".text": "0xffffffffc0000000", ".data": "0xffffffffc0010000"})]
    assert response.data["loaded_module"]["sections"][".text"] == "0xffffffffc0000000"


def test_text_unreadable_reports_section_addresses_unreadable(tmp_path: Path) -> None:
    artifact_root, registry, txn, admission, engine, sessions, sid = _started(tmp_path)
    _ko_in_build_tree(artifact_root)
    ssh = FakeSshRunner(_SshResult(0, stdout=".data 0xffffffffc0010000\n"))  # .text missing/unreadable
    response = _call(
        artifact_root,
        registry,
        txn,
        admission,
        engine,
        sessions,
        sid,
        ssh_runner=ssh,
        module_ko_finder=lambda build_tree, module: artifact_root / RUN_ID / "build" / "foo.ko",
    )
    assert response.ok is False
    assert response.error.category is ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details.get("code") == "section_addresses_unreadable"
    assert engine.loaded == []


def test_module_not_loaded_when_sysfs_dir_absent(tmp_path: Path) -> None:
    artifact_root, registry, txn, admission, engine, sessions, sid = _started(tmp_path)
    ssh = FakeSshRunner(_SshResult(0, stdout="__NO_MODULE__\n"))
    response = _call(
        artifact_root,
        registry,
        txn,
        admission,
        engine,
        sessions,
        sid,
        ssh_runner=ssh,
        module_ko_finder=lambda build_tree, module: artifact_root / RUN_ID / "build" / "foo.ko",
    )
    assert response.ok is False
    assert response.error.details.get("code") == "module_not_loaded"


def test_ko_not_found_reports_with_spellings(tmp_path: Path) -> None:
    artifact_root, registry, txn, admission, engine, sessions, sid = _started(tmp_path)
    ssh = FakeSshRunner(_SshResult(0, stdout=".text 0xffffffffc0000000\n"))
    response = _call(
        artifact_root,
        registry,
        txn,
        admission,
        engine,
        sessions,
        sid,
        ssh_runner=ssh,
        module_ko_finder=lambda build_tree, module: None,
    )
    assert response.ok is False
    assert response.error.details.get("code") == "module_object_not_found"


def test_explicit_sections_override_skips_ssh(tmp_path: Path) -> None:
    artifact_root, registry, txn, admission, engine, sessions, sid = _started(tmp_path)
    ko = _ko_in_build_tree(artifact_root)
    ssh = FakeSshRunner(_SshResult(0, stdout="should-not-be-read"))
    response = _call(
        artifact_root,
        registry,
        txn,
        admission,
        engine,
        sessions,
        sid,
        sections={".text": "0xffffffffc0000000"},
        ssh_runner=ssh,
        module_ko_finder=lambda build_tree, module: ko,
    )
    assert response.ok is True, response
    assert ssh.ran is False  # explicit map -> no SSH
    assert engine.loaded[0][2] == {".text": "0xffffffffc0000000"}


def test_ssh_unreachable_reports_ssh_unreachable(tmp_path: Path) -> None:
    artifact_root, registry, txn, admission, engine, sessions, sid = _started(tmp_path)
    _ko_in_build_tree(artifact_root)
    # SSH times out with no output (guest has no usable SSH path) -> ssh_unreachable, not a hang.
    ssh = FakeSshRunner(_SshResult(255, stdout="", timed_out=True))
    response = _call(
        artifact_root,
        registry,
        txn,
        admission,
        engine,
        sessions,
        sid,
        ssh_runner=ssh,
        module_ko_finder=lambda build_tree, module: artifact_root / RUN_ID / "build" / "foo.ko",
    )
    assert response.ok is False
    assert response.error.details.get("code") == "ssh_unreachable"


def test_idempotent_reload_same_address_is_noop(tmp_path: Path) -> None:
    artifact_root, registry, txn, admission, engine, sessions, sid = _started(tmp_path)
    ko = _ko_in_build_tree(artifact_root)
    ssh = FakeSshRunner(_SshResult(0, stdout=".text 0xffffffffc0000000\n"))
    first = _call(
        artifact_root,
        registry,
        txn,
        admission,
        engine,
        sessions,
        sid,
        ssh_runner=ssh,
        module_ko_finder=lambda build_tree, module: ko,
    )
    assert first.ok is True, first
    second = _call(
        artifact_root,
        registry,
        txn,
        admission,
        engine,
        sessions,
        sid,
        ssh_runner=FakeSshRunner(_SshResult(0, stdout=".text 0xffffffffc0000000\n")),
        module_ko_finder=lambda build_tree, module: ko,
    )
    assert second.ok is True, second
    assert len(engine.loaded) == 1  # the second call was a no-op (already loaded at the same address)


def test_reload_changed_address_is_error(tmp_path: Path) -> None:
    artifact_root, registry, txn, admission, engine, sessions, sid = _started(tmp_path)
    ko = _ko_in_build_tree(artifact_root)
    first = _call(
        artifact_root,
        registry,
        txn,
        admission,
        engine,
        sessions,
        sid,
        ssh_runner=FakeSshRunner(_SshResult(0, stdout=".text 0xffffffffc0000000\n")),
        module_ko_finder=lambda build_tree, module: ko,
    )
    assert first.ok is True, first
    second = _call(
        artifact_root,
        registry,
        txn,
        admission,
        engine,
        sessions,
        sid,
        ssh_runner=FakeSshRunner(_SshResult(0, stdout=".text 0xffffffffc0009999\n")),
        module_ko_finder=lambda build_tree, module: ko,
    )
    assert second.ok is False
    assert second.error.details.get("code") == "module_address_changed"


def test_module_name_rejects_non_identifier(tmp_path: Path) -> None:
    artifact_root, registry, txn, admission, engine, sessions, sid = _started(tmp_path)
    ssh = FakeSshRunner(_SshResult(0, stdout=".text 0x1\n"))
    response = _call(
        artifact_root,
        registry,
        txn,
        admission,
        engine,
        sessions,
        sid,
        module="foo; rm -rf /",
        ssh_runner=ssh,
        module_ko_finder=lambda build_tree, module: None,
    )
    assert response.ok is False
    assert response.error.category is ErrorCategory.CONFIGURATION_ERROR
    assert ssh.ran is False


def test_op_gated_by_enabled_operations(tmp_path: Path) -> None:
    artifact_root, registry, txn, admission, engine, sessions, sid = _started(tmp_path)
    ko = _ko_in_build_tree(artifact_root)
    narrowed = {
        "qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default", enabled_operations=["debug.continue"])
    }
    ssh = FakeSshRunner(_SshResult(0, stdout=".text 0xffffffffc0000000\n"))
    response = _call(
        artifact_root,
        registry,
        txn,
        admission,
        engine,
        sessions,
        sid,
        debug_profiles=narrowed,
        ssh_runner=ssh,
        module_ko_finder=lambda build_tree, module: ko,
    )
    assert response.ok is False
    assert ssh.ran is False  # refused before any SSH/gdb work
    assert engine.loaded == []
