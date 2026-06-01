from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from kdive.artifacts.store import ArtifactStore
from kdive.domain import (
    ErrorCategory,
    RunRequest,
    StepStatus,
)
from kdive.postmortem.crash.handler import debug_postmortem_crash_handler
from kdive.postmortem.models import DebugPostmortemCrashRequest
from kdive.postmortem.probes import assemble_kdump_probe_response, validated_dump_dir
from kdive.postmortem.tools import PostmortemToolRuntime
from kdive.providers.local.test.local_ssh_tests import SshCommandResult
from kdive.safety.redaction import Redactor
from kdive.target.probes import ProbeContext

GOOD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


def test_postmortem_vmcore_context_resolver_is_shared() -> None:
    import kdive.postmortem.crash.handler as crash_handler

    assert hasattr(crash_handler, "PostmortemVmcoreContext")
    assert hasattr(crash_handler, "resolve_postmortem_vmcore_context")


def test_postmortem_vmcore_resolver_has_concrete_request_and_manifest_types() -> None:
    from typing import get_type_hints

    import kdive.postmortem.crash.handler as crash_handler
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


def test_postmortem_crash_handler_uses_request_artifact_root_contract() -> None:
    signature = inspect.signature(debug_postmortem_crash_handler)

    assert list(signature.parameters) == ["request", "runtime"]


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


def _probe_context(tmp_path: Path) -> ProbeContext:
    from kdive.config import RootfsProfile

    return ProbeContext(
        store=ArtifactStore(tmp_path),
        run_id="r1",
        rootfs=RootfsProfile(
            name="minimal",
            source="/rootfs.qcow2",
            access_method="ssh",
            ssh_host="127.0.0.1",
            ssh_user="root",
        ),
        host_build_id=None,
        redactor=Redactor(),
    )


def _probe_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    agent_dir = tmp_path / "agent"
    sensitive_dir = tmp_path / "sensitive"
    agent_dir.mkdir()
    sensitive_dir.mkdir()
    return agent_dir, sensitive_dir / "stdout.raw", sensitive_dir / "stderr.raw"


class _DumpDirRequest:
    def __init__(self, dump_dir: str | None) -> None:
        self.dump_dir = dump_dir


def test_kdump_probe_timeout_failure_propagates(tmp_path: Path) -> None:
    agent_dir, stdout_path, stderr_path = _probe_paths(tmp_path)
    stdout_path.write_text("{}", encoding="utf-8")

    response = assemble_kdump_probe_response(
        _probe_context(tmp_path),
        ssh_result=SshCommandResult(exit_status=124, timed_out=True),
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        agent_dir=agent_dir,
        probe_id="probe-1",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details["code"] == "ssh_failure"


def test_kdump_probe_success_returns_data_and_report_artifact(tmp_path: Path) -> None:
    agent_dir, stdout_path, stderr_path = _probe_paths(tmp_path)
    stdout_path.write_text(
        """
        {
          "cmdline_has_crashkernel": true,
          "kexec_crash_size": 4096,
          "fadump_enabled": 0,
          "fadump_registered": 0,
          "service_active": true,
          "service_units": {"kdump.service": "active"},
          "dump_target_directive": "path",
          "dump_dir": "/var/crash",
          "dump_dir_exists": true,
          "dump_dir_writable": true
        }
        """,
        encoding="utf-8",
    )

    response = assemble_kdump_probe_response(
        _probe_context(tmp_path),
        ssh_result=SshCommandResult(exit_status=0),
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        agent_dir=agent_dir,
        probe_id="probe-1",
    )

    assert response.ok is True
    assert response.data["kdump_ready"] is True
    assert response.data["mechanism"] == "kdump"
    assert (agent_dir / "probe.json").is_file()
    assert any(artifact.kind == "probe-report" for artifact in response.artifacts)


def test_validated_dump_dir_accepts_default_and_absolute_path() -> None:
    default_dir, default_failure = validated_dump_dir(_DumpDirRequest(None), "r1")
    explicit_dir, explicit_failure = validated_dump_dir(_DumpDirRequest("/tmp/crashes"), "r1")

    assert default_failure is None
    assert default_dir == "/var/crash"
    assert explicit_failure is None
    assert explicit_dir == "/tmp/crashes"


def test_validated_dump_dir_rejects_relative_path() -> None:
    dump_dir, failure = validated_dump_dir(_DumpDirRequest("relative/crashes"), "r1")

    assert dump_dir is None
    assert failure is not None
    assert failure.error is not None
    assert failure.error.category is ErrorCategory.CONFIGURATION_ERROR
    assert failure.error.details["code"] == "invalid_dump_dir"


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


def _runtime(
    tmp_path: Path,
    *,
    runner=None,
    vmcore_build_id_reader=None,
    vmlinux_build_id_reader=None,
    clock=None,
) -> PostmortemToolRuntime:
    return PostmortemToolRuntime(
        artifact_root=tmp_path,
        ssh_runner=runner,
        vmcore_build_id_reader=vmcore_build_id_reader or (lambda _p: GOOD_ID),
        vmlinux_build_id_reader=vmlinux_build_id_reader or (lambda _p: GOOD_ID),
        clock=clock,
    )


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
        runtime=_runtime(tmp_path, runner=runner),
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
        runtime=_runtime(tmp_path, runner=_RaisingRunner()),
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
        runtime=_runtime(tmp_path, runner=runner),
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
        runtime=_runtime(
            tmp_path,
            runner=runner,
            vmcore_build_id_reader=lambda _p: "a" * 40,
            vmlinux_build_id_reader=lambda _p: "b" * 40,
        ),
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
        runtime=_runtime(tmp_path, runner=runner, vmcore_build_id_reader=_raising_reader(exc)),
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
        runtime=_runtime(tmp_path, runner=runner, vmlinux_build_id_reader=_raise),
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
        runtime=_runtime(tmp_path, runner=runner),
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
        runtime=_runtime(tmp_path, runner=runner),
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
        runtime=_runtime(tmp_path, runner=runner),
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
        runtime=_runtime(tmp_path, runner=runner),
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
        runtime=_runtime(tmp_path, runner=runner),
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
        runtime=_runtime(tmp_path, runner=runner),
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
        runtime=_runtime(tmp_path, runner=runner),
    )
    assert runner.argv[:2] == ["prlimit", f"--fsize={CRASH_PER_CMD_CAP}"]
    assert "crash" in runner.argv and "-s" in runner.argv


def test_modules_path_unsafe_rejected_no_run(tmp_path, monkeypatch) -> None:
    import kdive.postmortem.crash.handler as crash_handler_module
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
        runtime=_runtime(tmp_path, runner=runner),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "modules_path_unsafe"
    assert runner.calls == 0


def test_module_symbols_status_reported(tmp_path, monkeypatch) -> None:
    import kdive.postmortem.crash.handler as crash_handler_module
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
        runtime=_runtime(tmp_path, runner=runner),
    )
    assert resp.ok is True
    assert resp.data["module_symbols"]["status"] == "loaded"


def test_module_symbols_load_failed(tmp_path, monkeypatch) -> None:
    import kdive.postmortem.crash.handler as crash_handler_module
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
        runtime=_runtime(tmp_path, runner=_BadModRunner(outputs={0: "PID: 0\n"})),
    )
    assert resp.ok is True
    assert resp.data["module_symbols"]["status"] == "load_failed"
