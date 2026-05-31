from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import kdive.server as server_module
from kdive.artifacts.store import ArtifactStore
from kdive.domain import (
    DebugIntrospectFromVmcoreHelperRequest,
    DebugIntrospectFromVmcoreRequest,
    ErrorCategory,
    RunRequest,
    StepStatus,
)
from kdive.introspect import handlers as introspect_handlers
from kdive.providers.local.local_ssh_tests import SshCommandResult
from kdive.server import (
    debug_introspect_from_vmcore_handler,
    debug_introspect_from_vmcore_helper_handler,
)
from kdive.symbols.build_id import BuildIdReadError

VALID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# Task 4: request models
# ---------------------------------------------------------------------------


def test_request_defaults() -> None:
    r = DebugIntrospectFromVmcoreRequest(
        run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", script="pass"
    )
    assert r.modules_ref is None
    assert r.timeout_seconds == 30
    assert r.allow_write is False
    assert r.args == {}


def test_request_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        DebugIntrospectFromVmcoreRequest(run_id="r1", vmcore_ref="c", vmlinux_ref="v", script="pass", target_ref="nope")


def test_helper_request_shape() -> None:
    r = DebugIntrospectFromVmcoreHelperRequest(run_id="r1", vmcore_ref="c", vmlinux_ref="v", name="sysinfo")
    assert r.args == {}
    assert r.timeout_seconds == 30


def test_vmcore_handlers_live_in_introspect_package() -> None:
    assert introspect_handlers.debug_introspect_from_vmcore_handler.__module__ == "kdive.introspect.handlers"
    assert (
        server_module.debug_introspect_from_vmcore_handler is introspect_handlers.debug_introspect_from_vmcore_handler
    )
    assert (
        server_module.debug_introspect_from_vmcore_helper_handler
        is introspect_handlers.debug_introspect_from_vmcore_helper_handler
    )


# ---------------------------------------------------------------------------
# Shared handler-test fixtures (Tasks 6-9)
# ---------------------------------------------------------------------------


class FakeRunner:
    """Local subprocess runner stand-in: records the call, writes the canned
    stdout/stderr to the requested paths, returns the canned SshCommandResult.
    """

    def __init__(self, results: list[SshCommandResult] | None = None) -> None:
        self.results = results or []
        self.calls: list[dict] = []

    def run(
        self,
        argv,
        *,
        timeout,
        stdout_path,
        stderr_path,
        cancel=None,
        stdin=None,
        max_stdout_bytes=None,
    ) -> SshCommandResult:
        self.calls.append({"argv": argv, "timeout": timeout, "stdin": stdin})
        result = self.results.pop(0) if self.results else SshCommandResult(exit_status=0, stdout="{}", stderr="")
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        return result


class RaisingRunner:
    def run(self, *args, **kwargs):
        raise OSError("disk full")


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


def test_from_vmcore_runner_exception_records_failed_step(tmp_path: Path) -> None:
    store = _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        DebugIntrospectFromVmcoreRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            script="print(1)",
        ),
        artifact_root=tmp_path,
        runner=RaisingRunner(),
        build_id_reader=lambda _p: VALID,
    )

    assert resp.ok is False
    assert resp.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "offline_introspect_failed"
    assert resp.error.details["exception_type"] == "OSError"
    result = next(
        result for name, result in store.load_manifest("r1").step_results.items() if name.startswith("introspect:")
    )
    assert result.status is StepStatus.FAILED
    assert result.details["code"] == "offline_introspect_failed"


def _wrapper_json(build_id: str | None = VALID, status: str = "ok", emits=None, user_stdout: str = "") -> dict:
    return {
        "call_id": "0" * 32,
        "build_id": build_id,
        "outcome": {"status": status},
        "emits": emits if emits is not None else [{"k": 1}],
        "user_stdout": user_stdout,
        "prelude_ms": 1,
        "truncated": {
            "emits": False,
            "user_stdout": False,
            "traceback": False,
            "total_json": False,
            "per_emit_size": False,
            "error_message": False,
        },
    }


def _req(**kw) -> DebugIntrospectFromVmcoreRequest:
    base = dict(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", script="emit({'k':1})")
    base.update(kw)
    return DebugIntrospectFromVmcoreRequest(**base)


def _ok_runner() -> FakeRunner:
    return FakeRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(_wrapper_json()), stderr="")])


# ---------------------------------------------------------------------------
# Task 6: debug.introspect.from_vmcore handler
# ---------------------------------------------------------------------------


def test_happy_path_succeeds(tmp_path: Path) -> None:
    store = _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        _req(), artifact_root=tmp_path, runner=_ok_runner(), build_id_reader=lambda p: VALID
    )
    assert resp.status == StepStatus.SUCCEEDED
    assert resp.data["emits"] == [{"k": 1}]
    assert resp.suggested_next_actions == ["artifacts.get_manifest", "debug.introspect.from_vmcore"]
    manifest = store.load_manifest("r1")
    step = next(s for n, s in manifest.step_results.items() if n.startswith("introspect:"))
    assert step.status == StepStatus.SUCCEEDED
    assert "ssh_user" not in step.details


def test_no_admission_no_boot_still_works(tmp_path: Path) -> None:
    # AC#3: lifecycle independence — no admission service exists in the call path.
    _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        _req(), artifact_root=tmp_path, runner=_ok_runner(), build_id_reader=lambda p: VALID
    )
    assert resp.status == StepStatus.SUCCEEDED


def test_host_verify_catches_build_id_mismatch(tmp_path: Path) -> None:
    # AC#2: wrapper reports ok but build_id disagrees with read_elf_build_id.
    _run(tmp_path)
    runner = FakeRunner(
        results=[SshCommandResult(exit_status=6, stdout=json.dumps(_wrapper_json(build_id="f" * 40)), stderr="")]
    )
    resp = debug_introspect_from_vmcore_handler(
        _req(), artifact_root=tmp_path, runner=runner, build_id_reader=lambda p: VALID
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_mismatch"


def test_wrapper_self_abort_provenance_unverifiable(tmp_path: Path) -> None:
    _run(tmp_path)
    body = _wrapper_json(build_id=None, status="provenance_unverifiable")
    runner = FakeRunner(results=[SshCommandResult(exit_status=4, stdout=json.dumps(body), stderr="")])
    resp = debug_introspect_from_vmcore_handler(
        _req(), artifact_root=tmp_path, runner=runner, build_id_reader=lambda p: VALID
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_unverifiable"


def test_missing_run(tmp_path: Path) -> None:
    resp = debug_introspect_from_vmcore_handler(
        _req(), artifact_root=tmp_path, runner=FakeRunner(), build_id_reader=lambda p: VALID
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_missing_vmcore(tmp_path: Path) -> None:
    _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        _req(vmcore_ref="inputs/nope"), artifact_root=tmp_path, runner=FakeRunner(), build_id_reader=lambda p: VALID
    )
    assert resp.error.details["code"] == "vmcore_not_found"


def test_escaping_vmcore_ref(tmp_path: Path) -> None:
    _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        _req(vmcore_ref="../../etc/passwd"),
        artifact_root=tmp_path,
        runner=FakeRunner(),
        build_id_reader=lambda p: VALID,
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "vmcore_not_found"


def test_unreadable_vmlinux_is_config_error(tmp_path: Path) -> None:
    _run(tmp_path)

    def _boom(p: Path) -> str:
        raise BuildIdReadError("not elf")

    resp = debug_introspect_from_vmcore_handler(
        _req(), artifact_root=tmp_path, runner=FakeRunner(), build_id_reader=_boom
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "vmlinux_build_id_unreadable"


def test_allow_write_not_applicable(tmp_path: Path) -> None:
    _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        _req(allow_write=True), artifact_root=tmp_path, runner=FakeRunner(), build_id_reader=lambda p: VALID
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "write_mode_not_applicable"


def test_bad_timeout(tmp_path: Path) -> None:
    _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        _req(timeout_seconds=1), artifact_root=tmp_path, runner=FakeRunner(), build_id_reader=lambda p: VALID
    )
    assert resp.error.details["code"] == "invalid_timeout"


def test_empty_script_rejected(tmp_path: Path) -> None:
    _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        _req(script=""), artifact_root=tmp_path, runner=FakeRunner(), build_id_reader=lambda p: VALID
    )
    assert resp.error.details["code"] == "invalid_script"


def test_timeout_exit_124(tmp_path: Path) -> None:
    _run(tmp_path)
    runner = FakeRunner(results=[SshCommandResult(exit_status=124, stdout="", stderr="")])
    resp = debug_introspect_from_vmcore_handler(
        _req(), artifact_root=tmp_path, runner=runner, build_id_reader=lambda p: VALID
    )
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "introspect_timeout"


def test_unparseable_stdout(tmp_path: Path) -> None:
    _run(tmp_path)
    runner = FakeRunner(results=[SshCommandResult(exit_status=0, stdout="garbage not json", stderr="")])
    resp = debug_introspect_from_vmcore_handler(
        _req(), artifact_root=tmp_path, runner=runner, build_id_reader=lambda p: VALID
    )
    assert resp.error.details["code"] == "wrapper_crash"


def test_redaction_masks_secret(tmp_path: Path) -> None:
    _run(tmp_path)
    body = _wrapper_json(user_stdout="api_key=SuperSecretValue123")
    runner = FakeRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")])
    resp = debug_introspect_from_vmcore_handler(
        _req(), artifact_root=tmp_path, runner=runner, build_id_reader=lambda p: VALID
    )
    assert "SuperSecretValue123" not in json.dumps(resp.data)
    rd = ArtifactStore(artifact_root=tmp_path).run_dir("r1")
    call_dirs = list((rd / "debug" / "introspect").iterdir())
    stdout_json = (call_dirs[0] / "stdout.json").read_text(encoding="utf-8")
    assert "SuperSecretValue123" not in stdout_json


# ---------------------------------------------------------------------------
# Task 7: debug.introspect.from_vmcore_helper handler
# ---------------------------------------------------------------------------


def test_helper_unknown_name(tmp_path: Path) -> None:
    _run(tmp_path)
    req = DebugIntrospectFromVmcoreHelperRequest(
        run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", name="nope"
    )
    resp = debug_introspect_from_vmcore_helper_handler(
        req, artifact_root=tmp_path, runner=FakeRunner(), build_id_reader=lambda p: VALID
    )
    assert resp.error.details["code"] == "unknown_helper"


def test_helper_happy_path(tmp_path: Path) -> None:
    # One concrete helper (sysinfo) with a hand-written valid emit matching its
    # output_model exactly — no generic schema synthesis.
    _run(tmp_path)
    sysinfo_emit = {
        "release": "6.1.0",
        "version": "#1 SMP",
        "machine": "x86_64",
        "nodename": "vm",
        "boot_cmdline": "ro quiet",
        "cpus_online": 4,
        "mem_total_pages": 1048576,
    }
    body = {
        "call_id": "0" * 32,
        "build_id": VALID,
        "outcome": {"status": "ok"},
        "emits": [sysinfo_emit],
        "user_stdout": "",
        "prelude_ms": 1,
        "truncated": {
            "emits": False,
            "user_stdout": False,
            "traceback": False,
            "total_json": False,
            "per_emit_size": False,
            "error_message": False,
        },
    }
    runner = FakeRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")])
    req = DebugIntrospectFromVmcoreHelperRequest(
        run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", name="sysinfo"
    )
    resp = debug_introspect_from_vmcore_helper_handler(
        req, artifact_root=tmp_path, runner=runner, build_id_reader=lambda p: VALID
    )
    assert resp.status == StepStatus.SUCCEEDED
    assert resp.data["helper"] == "sysinfo"
    assert resp.data["result"]["cpus_online"] == 4
    assert resp.suggested_next_actions == ["artifacts.get_manifest", "debug.introspect.from_vmcore_helper"]


# ---------------------------------------------------------------------------
# Task 8: allowlist + capability advertising
# ---------------------------------------------------------------------------


def test_operations_in_allowlist() -> None:
    from kdive.config import ALLOWED_DEBUG_OPERATIONS

    assert "debug.introspect.from_vmcore" in ALLOWED_DEBUG_OPERATIONS
    assert "debug.introspect.from_vmcore_helper" in ALLOWED_DEBUG_OPERATIONS


def test_capability_advertises_vmcore_ops_concurrent_safe() -> None:
    from kdive.providers.local.local_drgn_introspect import local_drgn_introspect_capability

    cap = local_drgn_introspect_capability()
    assert "debug.introspect.from_vmcore" in cap.operations
    assert "debug.introspect.from_vmcore_helper" in cap.operations
    by_op = {c.operation: c for c in cap.operation_capabilities}
    assert by_op["debug.introspect.from_vmcore"].semantics.concurrent_safe is True
    assert by_op["debug.introspect.from_vmcore_helper"].semantics.concurrent_safe is True
    assert by_op["debug.introspect.run"].semantics.concurrent_safe is False


# ---------------------------------------------------------------------------
# Task 9: MCP tool registration
# ---------------------------------------------------------------------------


def test_tools_registered() -> None:
    from kdive.server import create_app

    names = set(create_app()._tool_manager._tools)
    assert "debug.introspect.from_vmcore" in names
    assert "debug.introspect.from_vmcore_helper" in names
