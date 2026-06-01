from __future__ import annotations

from pathlib import Path

import pytest

from kdive.artifacts.store import ArtifactStore
from kdive.domain import (
    ErrorCategory,
    RunRequest,
    StepStatus,
)
from kdive.postmortem.crash_handler import debug_postmortem_crash_handler
from kdive.postmortem.models import DebugPostmortemCrashRequest
from kdive.providers.local.test.local_ssh_tests import SshCommandResult

GOOD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


def test_postmortem_vmcore_context_resolver_is_shared() -> None:
    import kdive.postmortem.crash_handler as crash_handler
    import kdive.postmortem.handlers as postmortem_handlers

    assert hasattr(crash_handler, "PostmortemVmcoreContext")
    assert hasattr(crash_handler, "resolve_postmortem_vmcore_context")
    assert postmortem_handlers.resolve_postmortem_vmcore_context is crash_handler.resolve_postmortem_vmcore_context


def test_postmortem_vmcore_resolver_has_concrete_request_and_manifest_types() -> None:
    from typing import get_type_hints

    import kdive.postmortem.crash_handler as crash_handler
    from kdive.artifacts.manifest import RunManifest

    context_hints = get_type_hints(crash_handler.PostmortemVmcoreContext)
    resolver_hints = get_type_hints(crash_handler.resolve_postmortem_vmcore_context)

    assert context_hints["manifest"] is RunManifest
    assert resolver_hints["request"] is crash_handler.PostmortemVmcoreRequest
    assert set(crash_handler.PostmortemVmcoreRequest.__annotations__) == {
        "run_id",
        "vmcore_ref",
        "vmlinux_ref",
        "modules_ref",
        "timeout_seconds",
    }


def test_postmortem_crash_handler_uses_named_execution_phases() -> None:
    source = (Path(__file__).parents[2] / "src" / "kdive" / "postmortem" / "crash_handler.py").read_text(
        encoding="utf-8"
    )
    handler_source = source.split("def debug_postmortem_crash_handler(", 1)[1].split("\ndef _finalize_crash_call(", 1)[
        0
    ]

    for helper in (
        "_prepare_crash_call_workspace",
        "_run_crash_batch",
        "_record_crash_runner_exception",
    ):
        assert f"def {helper}(" in source
        assert f"{helper}(" in handler_source

    assert "active_runner.run(" not in handler_source
    assert 'exception_type": type(exc).__name__' not in handler_source


def _run(tmp_path: Path) -> ArtifactStore:
    store = ArtifactStore(artifact_root=tmp_path)
    store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/s",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    rd = store.run_dir("r1")
    (rd / "inputs").mkdir(exist_ok=True)
    (rd / "build").mkdir(exist_ok=True)
    (rd / "inputs" / "vmcore").write_bytes(b"core")
    (rd / "build" / "vmlinux").write_bytes(b"elf")
    return store


class _FakeRunner:
    """Writes a cmd-NNNN.out per command by parsing the redirect targets out of
    the stdin script, then returns a clean exit."""

    def __init__(self, *, outputs: dict[int, str], exit_status: int = 0, **flags) -> None:
        self.outputs = outputs
        self.exit_status = exit_status
        self.flags = flags
        self.calls = 0

    def run(
        self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None, max_stdout_bytes=None
    ) -> SshCommandResult:
        self.calls += 1
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        for line in (stdin or "").splitlines():
            if " > " not in line or not line.split(" > ")[0].strip():
                continue
            target = Path(line.split(" > ", 1)[1])
            if target.name.startswith("cmd-"):
                idx = int(target.stem.split("-")[1])
                if idx in self.outputs:
                    target.write_text(self.outputs[idx], encoding="utf-8")
        return SshCommandResult(exit_status=self.exit_status, **self.flags)


class _RaisingRunner:
    def run(self, *args, **kwargs):
        raise OSError("crash unavailable")


def test_happy_path_keys_results_by_command(tmp_path) -> None:
    store = _run(tmp_path)
    runner = _FakeRunner(outputs={0: "KERNEL: vmlinux\nRELEASE: 6.1.0\n", 1: "raw text"})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["sys", "vtop 0x0"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert resp.data["results"]["sys"]["system"]["RELEASE"] == "6.1.0"
    assert resp.data["results"]["vtop 0x0"]["parsed"] is False
    assert any(name.startswith("postmortem.crash:") for name in store.load_manifest("r1").step_results)


def test_runner_exception_records_failed_crash_step(tmp_path) -> None:
    store = _run(tmp_path)
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["sys"],
        ),
        artifact_root=tmp_path,
        runner=_RaisingRunner(),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )

    assert resp.ok is False
    assert resp.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "postmortem_crash_failed"
    assert resp.error.details["exception_type"] == "OSError"
    result = next(
        result
        for name, result in store.load_manifest("r1").step_results.items()
        if name.startswith("postmortem.crash:")
    )
    assert result.status is StepStatus.FAILED
    assert result.details["code"] == "postmortem_crash_failed"


def test_raw_output_files_are_mode_0600(tmp_path) -> None:
    store = _run(tmp_path)
    runner = _FakeRunner(outputs={0: "RELEASE: 6.1.0\n"})
    debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["sys"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    crash_dir = store.run_dir("r1") / "sensitive" / "debug" / "postmortem" / "crash"
    call_dir = next(crash_dir.iterdir())
    raw_files = list(call_dir.glob("cmd-*.out")) + [call_dir / "stdout.raw", call_dir / "stderr.raw"]
    assert raw_files
    for raw in raw_files:
        assert raw.stat().st_mode & 0o777 == 0o600, raw


def test_build_id_mismatch_fails_loud_no_run(tmp_path) -> None:
    _run(tmp_path)
    runner = _FakeRunner(outputs={})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: "a" * 40,
        vmlinux_build_id_reader=lambda _p: "b" * 40,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_mismatch"
    assert runner.calls == 0


def _raising_reader(exc: Exception):
    def _reader(_path):
        raise exc

    return _reader


@pytest.mark.parametrize(
    "exc_name, expected_code",
    [
        ("VmcoreFormatUnsupported", "vmcore_format_unsupported"),
        ("VmcoreBuildIdAbsent", "provenance_unverifiable"),
        ("VmcoreBuildIdError", "vmcore_build_id_unreadable"),
    ],
)
def test_vmcore_reader_failures_fail_loud(tmp_path, exc_name, expected_code) -> None:
    from kdive.symbols.vmcore_build_id import VmcoreBuildIdAbsent, VmcoreBuildIdError, VmcoreFormatUnsupported

    _run(tmp_path)
    runner = _FakeRunner(outputs={})
    exceptions = {
        "VmcoreFormatUnsupported": VmcoreFormatUnsupported,
        "VmcoreBuildIdAbsent": VmcoreBuildIdAbsent,
        "VmcoreBuildIdError": VmcoreBuildIdError,
    }
    exc = exceptions[exc_name]("crafted")
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=_raising_reader(exc),
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == expected_code
    assert runner.calls == 0


def test_vmlinux_build_id_unreadable_fails_loud(tmp_path) -> None:
    from kdive.symbols.build_id import BuildIdReadError

    _run(tmp_path)
    runner = _FakeRunner(outputs={})

    def _raise(_p):
        raise BuildIdReadError("not an ELF")

    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=_raise,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "vmlinux_build_id_unreadable"
    assert runner.calls == 0


def test_crash_open_failure_no_output_nonzero_exit(tmp_path) -> None:
    _run(tmp_path)
    runner = _FakeRunner(outputs={}, exit_status=1)  # no cmd-*.out written, clean nonzero exit
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "crash_open_failure"


@pytest.mark.parametrize(
    "kwargs, code",
    [
        ({"commands": ["bt"], "timeout_seconds": 4}, "invalid_timeout"),
        ({"commands": ["bt", "bt"]}, "invalid_commands"),
        ({"commands": []}, "invalid_commands"),
    ],
)
def test_input_validation_codes(tmp_path, kwargs, code) -> None:
    _run(tmp_path)
    runner = _FakeRunner(outputs={})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            **kwargs,
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == code
    assert runner.calls == 0


def test_disallowed_command_rejected_no_run(tmp_path) -> None:
    _run(tmp_path)
    runner = _FakeRunner(outputs={})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["bt | sh"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "command_not_permitted"
    assert runner.calls == 0


def test_lifecycle_independent_no_admission_injected(tmp_path) -> None:
    # No admission service parameter exists on the handler at all — calling it
    # proves the gate is not in the path (AC).
    _run(tmp_path)
    runner = _FakeRunner(outputs={0: 'PID: 0  TASK: ff  CPU: 0   COMMAND: "x"\n'})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True


def test_timeout_beats_partial_files(tmp_path) -> None:
    _run(tmp_path)
    runner = _FakeRunner(outputs={0: "PID: 0\n"}, exit_status=124, timed_out=True)
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["bt", "ps"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "crash_timeout"


def test_redaction_masks_secret_in_output(tmp_path) -> None:
    _run(tmp_path)
    # The default Redactor (src/kdive/safety/redaction.py) masks
    # `key=value` pairs whose key matches password|passwd|token|api_key|secret.
    secret_value = "hunter2trustno1xyz"  # pragma: allowlist secret
    runner = _FakeRunner(outputs={0: f"[ 0.1] db_password={secret_value} loaded\n"})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["log"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    blob = repr(resp.data["results"])
    assert secret_value not in blob
    assert "[REDACTED]" in blob
    rd = ArtifactStore(artifact_root=tmp_path).run_dir("r1")
    parsed_on_disk = (rd / "debug" / "postmortem" / "crash").glob("*/parsed.json")
    assert all(secret_value not in p.read_text(encoding="utf-8") for p in parsed_on_disk)


def test_argv_carries_prlimit_disk_bound(tmp_path) -> None:
    from kdive.config import CRASH_PER_CMD_CAP

    _run(tmp_path)

    class _ArgvCapturingRunner(_FakeRunner):
        def run(self, argv, **kwargs):  # type: ignore[override]
            self.argv = argv
            return super().run(argv, **kwargs)

    runner = _ArgvCapturingRunner(outputs={0: "PID: 0\n"})
    debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert runner.argv[:2] == ["prlimit", f"--fsize={CRASH_PER_CMD_CAP}"]
    assert "crash" in runner.argv and "-s" in runner.argv


def test_modules_path_unsafe_rejected_no_run(tmp_path, monkeypatch) -> None:
    import kdive.postmortem.crash_handler as crash_handler_module
    from kdive.symbols.resolve import ResolvedSymbols

    store = _run(tmp_path)
    rd = store.run_dir("r1")
    (rd / "build" / "mods").mkdir(parents=True, exist_ok=True)

    def _fake_resolve(_prov, *, run_dir):
        return ResolvedSymbols(
            vmlinux_path=run_dir / "build" / "vmlinux",
            modules_path=run_dir / "build" / "mo ds",  # space -> unsafe
            warnings=[],
        )

    monkeypatch.setattr(crash_handler_module, "resolve_symbols", _fake_resolve)
    runner = _FakeRunner(outputs={})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            modules_ref="build/mods",
            commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "modules_path_unsafe"
    assert runner.calls == 0


def test_module_symbols_status_reported(tmp_path, monkeypatch) -> None:
    import kdive.postmortem.crash_handler as crash_handler_module
    from kdive.symbols.resolve import ResolvedSymbols

    store = _run(tmp_path)
    rd = store.run_dir("r1")
    (rd / "build" / "mods").mkdir(parents=True, exist_ok=True)

    def _fake_resolve(_prov, *, run_dir):
        return ResolvedSymbols(
            vmlinux_path=run_dir / "build" / "vmlinux",
            modules_path=run_dir / "build" / "mods",
            warnings=[],
        )

    monkeypatch.setattr(crash_handler_module, "resolve_symbols", _fake_resolve)

    class _ModRunner(_FakeRunner):
        def run(self, argv, *, stdin=None, **kwargs):  # type: ignore[override]
            for line in (stdin or "").splitlines():
                if " > " not in line:
                    continue
                target = Path(line.split(" > ", 1)[1])
                if target.name == "mod-load.out":
                    target.write_text("MODULE  NAME  loaded\n", encoding="utf-8")
            return super().run(argv, stdin=stdin, **kwargs)

    runner = _ModRunner(outputs={0: "PID: 0\n"})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            modules_ref="build/mods",
            commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert resp.data["module_symbols"]["status"] == "loaded"


def test_module_symbols_load_failed(tmp_path, monkeypatch) -> None:
    import kdive.postmortem.crash_handler as crash_handler_module
    from kdive.symbols.resolve import ResolvedSymbols

    store = _run(tmp_path)
    rd = store.run_dir("r1")
    (rd / "build" / "mods").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        crash_handler_module,
        "resolve_symbols",
        lambda _prov, *, run_dir: ResolvedSymbols(
            vmlinux_path=run_dir / "build" / "vmlinux",
            modules_path=run_dir / "build" / "mods",
            warnings=[],
        ),
    )

    class _BadModRunner(_FakeRunner):
        def run(self, argv, *, stdin=None, **kwargs):  # type: ignore[override]
            for line in (stdin or "").splitlines():
                if " > " in line and line.split(" > ", 1)[1].endswith("mod-load.out"):
                    Path(line.split(" > ", 1)[1]).write_text("mod: cannot find module debuginfo\n", encoding="utf-8")
            return super().run(argv, stdin=stdin, **kwargs)

    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            modules_ref="build/mods",
            commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=_BadModRunner(outputs={0: "PID: 0\n"}),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert resp.data["module_symbols"]["status"] == "load_failed"
