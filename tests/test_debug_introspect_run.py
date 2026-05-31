"""Tests for `debug.introspect.run` (spec §9.1).

Task 2 of the implementation plan adds only the mode-0700 contract; the
remaining §9.1 matrix is filled in by Task 11.
"""

import json
import os
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

import kdive.server as server_module
from kdive.artifacts.store import ArtifactStore
from kdive.config import DebugProfile, RootfsProfile, TargetProfile
from kdive.coordination.admission import (
    AdmissionError,
    TargetSnapshot,
)
from kdive.domain import (
    DebugIntrospectRunRequest,
    ErrorCategory,
    RunRequest,
    StepResult,
    StepStatus,
    ToolResponse,
)
from kdive.providers.local.local_ssh_tests import SshCommandResult
from kdive.seams.target import ConsoleKind, PlatformMetadata, TargetState
from kdive.server import RUN_STDOUT_CAP, debug_introspect_run_handler

VALID_BUILD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


def test_execute_introspect_call_keeps_ssh_phase_in_helper() -> None:
    assert callable(server_module._run_introspect_ssh_with_cancellation)
    assert "_run_introspect_ssh_with_cancellation" in server_module._execute_introspect_call.__code__.co_names
    assert "threading" not in server_module._execute_introspect_call.__code__.co_names


def test_execute_introspect_call_keeps_preflight_and_admission_phases_in_helpers() -> None:
    assert callable(server_module._run_introspect_sudo_preflight)
    assert callable(server_module._admit_introspect_call)
    assert "_run_introspect_sudo_preflight" in server_module._execute_introspect_call.__code__.co_names
    assert "_admit_introspect_call" in server_module._execute_introspect_call.__code__.co_names
    assert "admit_ssh_tier" not in server_module._execute_introspect_call.__code__.co_names


def test_finalize_introspect_call_keeps_success_persistence_and_response_in_helpers() -> None:
    assert callable(server_module._persist_introspect_success_artifacts)
    assert callable(server_module._build_introspect_success_response)
    assert "_persist_introspect_success_artifacts" in server_module._finalize_introspect_call.__code__.co_names
    assert "_build_introspect_success_response" in server_module._finalize_introspect_call.__code__.co_names
    assert "ArtifactRef" not in server_module._finalize_introspect_call.__code__.co_names


def _make_run(tmp_path: Path) -> Path:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    return store.run_dir(manifest.run_id)


def test_sensitive_run_subdir_is_mode_0700(tmp_path: Path) -> None:
    # Spec §9.1: ArtifactStore.create_run must produce <run>/sensitive/ at
    # mode 0700 regardless of process umask. The 0600 file mode on wrapper.py
    # (spec §6.1) is only load-bearing if the parent directory is 0700;
    # otherwise other local users can read the file.
    old_umask = os.umask(0o022)
    try:
        run_dir = _make_run(tmp_path)
    finally:
        os.umask(old_umask)
    sensitive = run_dir / "sensitive"
    assert sensitive.is_dir()
    mode = sensitive.stat().st_mode & 0o777
    assert mode == 0o700, f"expected 0700, got {oct(mode)}"


# ---------------------------------------------------------------------------
# Task 11: spec §9.1 handler matrix
# ---------------------------------------------------------------------------


@dataclass
class FakeSshRunner:
    available: bool = True
    results: list[SshCommandResult] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}" if self.available else None

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
        self.calls.append(
            {
                "argv": argv,
                "timeout": timeout,
                "stdout_path": stdout_path,
                "stderr_path": stderr_path,
                "stdin": stdin,
                "cancel": cancel,
            }
        )
        result = self.results.pop(0) if self.results else SshCommandResult(exit_status=0, stdout="{}", stderr="")
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        return result


@dataclass
class FakeAdmissionHandle:
    cancel_event: threading.Event = field(default_factory=threading.Event)

    def wait_cancelled(self, timeout=None):
        return self.cancel_event.wait(timeout)


@dataclass
class FakeAdmissionService:
    snapshot: Any = None
    admit_raises: BaseException | None = None
    complete_raises: BaseException | None = None
    handle: FakeAdmissionHandle = field(default_factory=FakeAdmissionHandle)
    rollback_calls: list[FakeAdmissionHandle] = field(default_factory=list)

    def current_snapshot(self, target_key):
        return self.snapshot

    def admit_ssh_tier(self, target_key, generation, platform, *, lease=None, execution_proof=None):
        if self.admit_raises is not None:
            raise self.admit_raises
        return self.handle

    def complete(self, handle):
        if self.complete_raises is not None:
            raise self.complete_raises

    def rollback(self, handle) -> None:
        # R6-F3: real AdmissionService.rollback() deregisters the admitted
        # ssh-tier handle; the fake records the call so tests can assert it.
        self.rollback_calls.append(handle)

    def current_execution_epoch(self, target_key):
        return 0


class FakeSessionRegistry:
    """Minimal stand-in for SessionRegistry. probe_execution_state reads
    `read_record(target_key)`; returning None keeps the probe in UNKNOWN
    state, which the ssh-tier admission path tolerates.
    """

    def read_record(self, target_key):
        return None

    def sessions(self, target_key):
        return []

    def execution_state_for(self, *args, **kwargs):
        return None


def _make_snapshot(run_id: str) -> TargetSnapshot:
    return TargetSnapshot(
        generation=1,
        transports=(),
        platform=PlatformMetadata(
            console_kind=ConsoleKind.UART,
            console_count=1,
            dedicated_debug_line=False,
            ssh_reachable=True,
        ),
        state=TargetState.READY,
        lease=None,
    )


def _profiles():
    return (
        {"local-qemu": TargetProfile(name="local-qemu", architecture="x86_64", managed_domain=False)},
        {
            "minimal": RootfsProfile(
                name="minimal",
                source="/var/lib/kdive/rootfs/minimal.qcow2",
                access_method="ssh_and_serial",
                ssh_host="127.0.0.1",
                ssh_port=22,
                ssh_user="root",
                readiness_marker="ready",
            )
        },
        {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )


def _make_request(run_id: str, **overrides) -> DebugIntrospectRunRequest:
    base = {
        "run_id": run_id,
        "target_ref": "local-qemu",
        "script": "emit({'pid': 1})",
        "timeout_seconds": 30,
        "allow_write": False,
    }
    base.update(overrides)
    return DebugIntrospectRunRequest(**base)


def _bootstrap_run_with_build(tmp_path: Path) -> tuple[ArtifactStore, str, str]:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="build ok",
            artifacts=[],
            details={"build_id": VALID_BUILD_ID},
        ),
    )
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary="boot ok",
            artifacts=[],
            details={
                "kernel_provenance": {
                    "build_id": VALID_BUILD_ID,
                    "release": "6.9.0-test",
                    "vmlinux_ref": "build/vmlinux",
                    "modules_ref": None,
                    "cmdline": "root=/dev/vda console=ttyS0",
                    "config_ref": "build/.config",
                }
            },
        ),
    )
    return store, manifest.run_id, VALID_BUILD_ID


def _happy_ssh_result() -> SshCommandResult:
    body = {
        "call_id": "0" * 32,
        "build_id": VALID_BUILD_ID,
        "outcome": {"status": "ok"},
        "emits": [{"pid": 1}],
        "user_stdout": "",
        "prelude_ms": 5,
        "truncated": {
            "emits": False,
            "user_stdout": False,
            "traceback": False,
            "total_json": False,
            "per_emit_size": False,
            "error_message": False,
        },
    }
    return SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")


# ---------------------------------------------------------------------------
# Pre-SSH validation
# ---------------------------------------------------------------------------


_WRITE_PERMS = ["mutate live kernel state via drgn write APIs"]


def test_run_tool_exposes_acknowledged_permissions() -> None:
    import inspect

    from kdive.server import create_app

    app = create_app()
    tool = app._tool_manager._tools["debug.introspect.run"]
    params = inspect.signature(tool.fn).parameters
    assert "acknowledged_permissions" in params


def test_run_tool_forwards_args_to_request(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, DebugIntrospectRunRequest] = {}

    def fake_handler(request: DebugIntrospectRunRequest, **_kwargs: Any) -> ToolResponse:
        captured["request"] = request
        return ToolResponse.success(summary="ok")

    monkeypatch.setattr(server_module, "debug_introspect_run_handler", fake_handler)
    app = server_module.create_app()

    raw = app._tool_manager._tools["debug.introspect.run"].fn(
        run_id="r1",
        target_ref="local-qemu",
        script="print(1)",
        args={"limit": 3},
    )

    assert raw["ok"] is True
    assert captured["request"].args == {"limit": 3}


def test_allow_write_requires_profile_op(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, _ = _profiles()
    profile = DebugProfile(name="qemu-gdbstub-default", enabled_operations=["debug.introspect.run"])
    response = debug_introspect_run_handler(
        _make_request(run_id, allow_write=True, acknowledged_permissions=_WRITE_PERMS),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles={"qemu-gdbstub-default": profile},
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "operation_disabled"


def test_allow_write_requires_ack(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id, allow_write=True, acknowledged_permissions=[]),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "permission_required"
    assert response.error.details["required_permissions"] == _WRITE_PERMS


def test_allow_write_admitted_records_flag_and_perms(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    response = debug_introspect_run_handler(
        _make_request(run_id, allow_write=True, acknowledged_permissions=[*_WRITE_PERMS, "extra"]),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is True
    manifest = store.load_manifest(run_id)
    step = next(v for k, v in manifest.step_results.items() if k.startswith("introspect:"))
    assert step.details["allow_write"] is True
    # Only the satisfied required perms are recorded, not the caller's "extra".
    assert step.details["acknowledged_permissions"] == _WRITE_PERMS


def test_read_only_call_skips_gates_and_ignores_ack(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, _ = _profiles()
    profile = DebugProfile(name="qemu-gdbstub-default", enabled_operations=["debug.introspect.run"])
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    response = debug_introspect_run_handler(
        _make_request(run_id, allow_write=False, acknowledged_permissions=["ignored"]),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles={"qemu-gdbstub-default": profile},
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is True
    manifest = store.load_manifest(run_id)
    step = next(v for k, v in manifest.step_results.items() if k.startswith("introspect:"))
    assert step.details["allow_write"] is False
    assert "acknowledged_permissions" not in step.details


def test_write_mode_audit_log_line(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    with caplog.at_level("WARNING"):
        debug_introspect_run_handler(
            _make_request(run_id, allow_write=True, acknowledged_permissions=_WRITE_PERMS),
            artifact_root=tmp_path,
            target_profiles=targets,
            rootfs_profiles=rootfs,
            debug_profiles=debug,
            ssh_runner=ssh,
            admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
            session_registry=FakeSessionRegistry(),
        )
    audit_lines = [r for r in caplog.records if "write-mode invocation" in r.getMessage()]
    assert len(audit_lines) == 1


def test_read_only_call_emits_no_audit_line(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    with caplog.at_level("WARNING"):
        debug_introspect_run_handler(
            _make_request(run_id),
            artifact_root=tmp_path,
            target_profiles=targets,
            rootfs_profiles=rootfs,
            debug_profiles=debug,
            ssh_runner=ssh,
            admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
            session_registry=FakeSessionRegistry(),
        )
    assert not [r for r in caplog.records if "write-mode invocation" in r.getMessage()]


def test_allow_write_failed_call_records_flag_via_failure_recorder(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    # A drgn_open_failure outcome routes through _fail -> _record_introspect_failure
    # (a genuinely FAILED step), exercising the failure recorder's allow_write path.
    # NB: outcome.status="error" would NOT work here — it is the SUCCESS path
    # (status="script_error", SUCCEEDED step) and never reaches _record_introspect_failure.
    body = {
        "call_id": "0" * 32,
        "build_id": None,
        "outcome": {"status": "drgn_open_failure", "error_type": "OSError", "error_message": "x"},
        "emits": [],
        "user_stdout": "",
        "prelude_ms": 1,
        "truncated": {
            k: False for k in ("emits", "user_stdout", "traceback", "total_json", "per_emit_size", "error_message")
        },
    }
    ssh = FakeSshRunner(results=[SshCommandResult(exit_status=3, stdout=json.dumps(body), stderr="")])
    debug_introspect_run_handler(
        _make_request(run_id, allow_write=True, acknowledged_permissions=_WRITE_PERMS),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    manifest = store.load_manifest(run_id)
    step = next(v for k, v in manifest.step_results.items() if k.startswith("introspect:"))
    assert step.status == StepStatus.FAILED
    assert step.details["allow_write"] is True
    assert step.details["acknowledged_permissions"] == _WRITE_PERMS


def test_write_mode_disabled_outcome_rejected(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    body = {
        "call_id": "0" * 32,
        "build_id": VALID_BUILD_ID,
        "outcome": {"status": "write_mode_disabled", "error_message": "blocked"},
        "emits": [],
        "user_stdout": "",
        "prelude_ms": 1,
        "truncated": {
            k: False for k in ("emits", "user_stdout", "traceback", "total_json", "per_emit_size", "error_message")
        },
    }
    ssh = FakeSshRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "write_mode_disabled"
    manifest = store.load_manifest(run_id)
    step = next(v for k, v in manifest.step_results.items() if k.startswith("introspect:"))
    assert step.status == StepStatus.FAILED


def test_invalid_timeout_rejected(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id, timeout_seconds=4),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "invalid_timeout"


def test_invalid_script_rejected_when_empty(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id, script=""),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "invalid_script"


def test_invalid_script_rejected_when_oversized(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id, script="x" * (300 * 1024)),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "invalid_script"


def test_operation_disabled_in_profile(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, _ = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default", enabled_operations=[])},
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "operation_disabled"


def test_provenance_missing_when_boot_lacks_provenance(tmp_path: Path) -> None:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    # A SUCCEEDED boot step whose details carry neither kernel_provenance nor a
    # kernel_provenance_capture_error.
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary="boot ok",
            artifacts=[],
            details={},
        ),
    )
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(manifest.run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "provenance_missing"
    # Design §4: the recovery action is now re-running target.boot, which is
    # what captures provenance on a SUCCEEDED boot.
    assert "target.boot" in response.error.message


def test_malformed_build_id_rejected_as_provenance_corrupt(tmp_path: Path) -> None:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    # Design §4: build_id is sourced from the boot-recorded kernel_provenance,
    # so the malformed id must live there (the build step is no longer read).
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary="x",
            artifacts=[],
            details={
                "kernel_provenance": {
                    "build_id": "not-hex!",
                    "release": "x",
                    "vmlinux_ref": "build/vmlinux",
                    "cmdline": "",
                    "config_ref": None,
                    "modules_ref": None,
                }
            },
        ),
    )
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner()
    response = debug_introspect_run_handler(
        _make_request(manifest.run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(),
        session_registry=FakeSessionRegistry(),
    )
    assert response.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details["code"] == "provenance_corrupt"
    assert ssh.calls == []


def test_call_budget_exhausted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("kdive.server.MAX_INTROSPECT_CALLS_PER_RUN", 4)
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    for _ in range(4):
        store.record_step_result(
            run_id,
            StepResult(
                step_name=f"introspect:{uuid.uuid4().hex}",
                status=StepStatus.SUCCEEDED,
                summary="ok",
                artifacts=[],
                details={},
            ),
            append=True,
        )
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner()
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(),
        session_registry=FakeSessionRegistry(),
    )
    assert response.error.details["code"] == "manifest_call_budget_exhausted"
    assert ssh.calls == []


def test_legacy_sensitive_dir_rejected(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    sensitive_dir = store.run_dir(run_id) / "sensitive"
    sensitive_dir.chmod(0o755)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "sensitive_dir_too_permissive"


# ---------------------------------------------------------------------------
# Admission gating
# ---------------------------------------------------------------------------


def test_admission_no_snapshot_returns_snapshot_missing(tmp_path: Path) -> None:
    # Iter-1 finding 7: "no snapshot exists" is a distinct precondition from
    # "admission service unwired" — align with `_require_snapshot` and the
    # rest of the debug.* handlers (snapshot_missing vs admission_service_
    # unavailable).
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(snapshot=None),
        session_registry=FakeSessionRegistry(),
    )
    assert response.error.details["code"] == "snapshot_missing"


def test_admission_service_unavailable_returns_distinct_code(tmp_path: Path) -> None:
    # Iter-1 finding 7: surface "admission/session_registry not wired" as
    # its own code so operators can distinguish a missing snapshot from a
    # missing service.
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=None,
        session_registry=None,
    )
    assert response.error.details["code"] == "admission_service_unavailable"


def test_admit_rejects_halted(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    admission = FakeAdmissionService(
        snapshot=_make_snapshot(run_id),
        admit_raises=AdmissionError(
            "target halted",
            code="target_halted",
            category=ErrorCategory.READINESS_FAILURE,
        ),
    )
    ssh = FakeSshRunner()
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=admission,
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "target_halted"
    assert ssh.calls == []


# ---------------------------------------------------------------------------
# Happy path + wrapper outcome discrimination
# ---------------------------------------------------------------------------


def test_happy_path_records_step_and_returns_emits(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is True
    assert response.data["emits"] == [{"pid": 1}]
    assert response.data["status"] == "ok"
    # The rendered wrapper was piped on stdin.
    assert ssh.calls[0]["stdin"] is not None and "drgn" in ssh.calls[0]["stdin"]
    # introspect:<call_id> StepResult exists.
    manifest = store.load_manifest(run_id)
    introspect_steps = [n for n in manifest.step_results if n.startswith("introspect:")]
    assert len(introspect_steps) == 1
    assert manifest.step_results[introspect_steps[0]].status == StepStatus.SUCCEEDED


def test_introspect_surfaces_capture_error_code(tmp_path: Path) -> None:
    # Boot recorded a kernel_provenance_capture_error instead of provenance;
    # the handler surfaces that captured code verbatim under provenance_missing.
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary="boot ok",
            artifacts=[],
            details={
                "kernel_provenance_capture_error": {
                    "code": "build_id_unavailable",
                    "message": "build recorded no build_id",
                }
            },
        ),
    )
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner()
    response = debug_introspect_run_handler(
        _make_request(manifest.run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "provenance_missing"
    assert response.error.details["capture_error"] == "build_id_unavailable"
    assert ssh.calls == []


def test_introspect_host_wrapper_divergence_fails_loud(tmp_path: Path) -> None:
    # Wrapper reports outcome=ok but a build_id differing from the recorded one
    # (a truncation/normalization fault). The host verify must fail loud.
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    body = json.loads(_happy_ssh_result().stdout)
    body["build_id"] = "b" * 40
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    # Forensic outcome_status records provenance_inconsistent; agent-facing code
    # is provenance_mismatch.
    assert response.error.details["code"] == "provenance_mismatch"


def test_introspect_ok_outcome_without_build_id_fails_loud(tmp_path: Path) -> None:
    # An "ok" wrapper payload that omits build_id must NOT pass the host verify
    # silently. Synthetic fault injection: a real ok payload always carries it.
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    body = json.loads(_happy_ssh_result().stdout)
    del body["build_id"]
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "provenance_mismatch"


def test_wrapper_exit_4_provenance_mismatch(tmp_path: Path) -> None:
    body = {
        "call_id": "0" * 32,
        "build_id": "ff" * 20,
        "outcome": {"status": "provenance_mismatch", "expected": VALID_BUILD_ID, "actual": "ff" * 20},
        "emits": [],
        "user_stdout": "",
        "prelude_ms": 5,
        "truncated": {
            "emits": False,
            "user_stdout": False,
            "traceback": False,
            "total_json": False,
            "per_emit_size": False,
            "error_message": False,
        },
    }
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[SshCommandResult(exit_status=4, stdout=json.dumps(body), stderr="")])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.error.details["code"] == "provenance_mismatch"
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_wrapper_exit_124_introspect_timeout(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[SshCommandResult(exit_status=124, stdout="", stderr="")])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.error.details["code"] == "introspect_timeout"


def test_wrapper_crash_no_json(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout="garbage not json", stderr="")])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.error.details["code"] == "wrapper_crash"
    # Spec §6.1 R3-F2: non-JSON stdout is parked under sensitive/.
    manifest = store.load_manifest(run_id)
    introspect_steps = [n for n in manifest.step_results if n.startswith("introspect:")]
    call_id = introspect_steps[0].split(":", 1)[1]
    sensitive_raw = store.run_dir(run_id) / "sensitive" / "debug" / "introspect" / call_id / "stdout.raw"
    assert sensitive_raw.exists()


def test_ssh_timeout_propagates(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[SshCommandResult(exit_status=-1, stdout="", stderr="", timed_out=True)])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.error.details["code"] == "ssh_timeout"


def test_run_oversized_stdout_streaming_cap_is_infrastructure_failure(tmp_path: Path) -> None:
    # Iter-2 finding (run-path Finding 2): the SSH runner's streaming cap kills
    # a hostile target that floods stdout. The runner signals this with
    # oversized_output=True; the handler must surface it as a distinct
    # INFRASTRUCTURE_FAILURE / oversized_output, not fall through to wrapper_crash.
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[SshCommandResult(exit_status=-1, stdout="", stderr="", oversized_output=True)])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details["code"] == "oversized_output"


def test_run_oversized_stdout_backstop_is_infrastructure_failure(tmp_path: Path) -> None:
    # Post-hoc backstop: a direct-write path (test fake / future runner without
    # the streaming kill) leaves an oversized stdout.raw on disk with
    # oversized_output=False. `_read_capped` returns None for the oversized read
    # and the handler still classifies it as INFRASTRUCTURE_FAILURE / oversized_output.
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(
        results=[SshCommandResult(exit_status=0, stdout="x" * (RUN_STDOUT_CAP + 10), stderr="", oversized_output=False)]
    )
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details["code"] == "oversized_output"


def test_wrapper_py_written_under_sensitive_with_0600(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is True
    manifest = store.load_manifest(run_id)
    introspect_steps = [n for n in manifest.step_results if n.startswith("introspect:")]
    call_id = introspect_steps[0].split(":", 1)[1]
    wrapper_path = store.run_dir(run_id) / "sensitive" / "debug" / "introspect" / call_id / "wrapper.py"
    assert wrapper_path.exists()
    assert wrapper_path.stat().st_mode & 0o777 == 0o600


def test_response_artifacts_omit_wrapper_py(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is True
    public_paths = {a.path for a in response.artifacts}
    assert any("wrapper.skeleton.py" in p for p in public_paths)
    assert not any(p.endswith("/wrapper.py") for p in public_paths)


def test_no_orphan_artifacts_on_admission_failure(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    admission = FakeAdmissionService(
        snapshot=_make_snapshot(run_id),
        admit_raises=AdmissionError("halted", code="target_halted", category=ErrorCategory.READINESS_FAILURE),
    )
    debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=admission,
        session_registry=FakeSessionRegistry(),
    )
    intro_root = Path(tmp_path) / "r1" / "debug" / "introspect"
    if intro_root.exists():
        assert list(intro_root.iterdir()) == []


def test_redactor_applied_to_emits(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, _rootfs, debug = _profiles()
    rootfs_with_secret = {
        "minimal": RootfsProfile(
            name="minimal",
            source="/var/lib/kdive/rootfs/minimal.qcow2",
            access_method="ssh_and_serial",
            ssh_host="127.0.0.1",
            ssh_port=22,
            ssh_user="root",
            ssh_key_ref="supersecret",
            readiness_marker="ready",
        )
    }
    body = {
        "call_id": "0" * 32,
        "build_id": VALID_BUILD_ID,
        "outcome": {"status": "ok"},
        "emits": [{"leak": "supersecret value here"}],
        "user_stdout": "",
        "prelude_ms": 5,
        "truncated": {
            "emits": False,
            "user_stdout": False,
            "traceback": False,
            "total_json": False,
            "per_emit_size": False,
            "error_message": False,
        },
    }
    ssh = FakeSshRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs_with_secret,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is True
    flattened = json.dumps(response.model_dump(mode="json"))
    assert "supersecret" not in flattened


# ---------------------------------------------------------------------------
# R6-F3 companion test
# ---------------------------------------------------------------------------


def test_wrapper_render_error_rolls_back_admission(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # R6-F3: the WrapperRenderError arm in Step 9.5 must (a) release the
    # admission handle, (b) clean up the orphan agent_dir + sensitive_dir,
    # and (c) leave a forensic FAILED StepResult under introspect:<call_id>
    # so the operator can trace via `artifacts.get_manifest`.
    from kdive.providers.local.local_drgn_introspect import WrapperRenderError

    def _boom(**_kwargs):
        raise WrapperRenderError("test forced render failure")

    monkeypatch.setattr("kdive.server.render_wrapper", _boom)

    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    admission = FakeAdmissionService(snapshot=_make_snapshot(run_id))
    ssh = FakeSshRunner()
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=admission,
        session_registry=FakeSessionRegistry(),
    )

    # (a) Admission handle rolled back.
    assert admission.rollback_calls == [admission.handle]

    # (b) Orphan directories removed.
    intro_root = store.run_dir(run_id) / "debug" / "introspect"
    sensitive_intro_root = store.run_dir(run_id) / "sensitive" / "debug" / "introspect"
    if intro_root.exists():
        assert list(intro_root.iterdir()) == []
    if sensitive_intro_root.exists():
        assert list(sensitive_intro_root.iterdir()) == []

    # (c) Forensic FAILED StepResult under introspect:<call_id>.
    manifest = store.load_manifest(run_id)
    introspect_steps = {
        name: result for name, result in manifest.step_results.items() if name.startswith("introspect:")
    }
    assert len(introspect_steps) == 1
    name, step = next(iter(introspect_steps.items()))
    assert step.status == StepStatus.FAILED
    assert step.details["code"] == "wrapper_render_error"
    call_id_in_step_name = name[len("introspect:") :]
    assert step.details["call_id"] == call_id_in_step_name
    assert response.error.details["code"] == "wrapper_render_error"
    assert response.error.details["call_id"] == call_id_in_step_name
    # The wrapper never ran on the target — SSH must not have been called.
    assert ssh.calls == []


# ---------------------------------------------------------------------------
# Iter-1 findings 1, 3: manifest-immutability invariants
# ---------------------------------------------------------------------------


def test_target_profile_mismatch_returns_configuration_error(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id, target_profile="other"),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "manifest_profile_mismatch"
    assert response.error.details["requested_profile"] == "other"


def test_rootfs_profile_mismatch_returns_configuration_error(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id, rootfs_profile="other"),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "manifest_profile_mismatch"
    assert response.error.details["requested_profile"] == "other"


def test_debug_profile_mismatch_returns_configuration_error(tmp_path: Path) -> None:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
            debug_profile="qemu-gdbstub-default",
        )
    )
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="build ok",
            artifacts=[],
            details={"build_id": VALID_BUILD_ID},
        ),
    )
    targets, rootfs, debug = _profiles()
    debug["other"] = DebugProfile(name="other")
    response = debug_introspect_run_handler(
        _make_request(manifest.run_id, debug_profile="other"),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(snapshot=_make_snapshot(manifest.run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "manifest_profile_mismatch"
    assert response.error.details["requested_profile"] == "other"


def test_target_ref_mismatch_returns_configuration_error(tmp_path: Path) -> None:
    # Iter-1 finding 3: target_ref previously was silently ignored. Per spec
    # §3.1 it names the target profile, so a divergent value is a contract
    # violation.
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id, target_ref="some-other-target"),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "manifest_profile_mismatch"
    assert response.error.details["requested_target_profile"] == "some-other-target"


# ---------------------------------------------------------------------------
# Iter-1 finding 2: admission.complete() failure path must roll back +
# persist a FAILED introspect:<call_id> StepResult
# ---------------------------------------------------------------------------


def test_complete_raises_records_failed_step_and_rolls_back(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    admission = FakeAdmissionService(
        snapshot=_make_snapshot(run_id),
        complete_raises=AdmissionError(
            "ssh-tier op spanned an execution-state transition (halt) since admission",
            code="execution_state_changed",
            category=ErrorCategory.READINESS_FAILURE,
        ),
    )
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=admission,
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "execution_state_changed"
    # Handle is rolled back so admission._bindings does not leak.
    assert admission.rollback_calls == [admission.handle]
    # Manifest now carries a FAILED introspect:<call_id> record matching the
    # on-disk artifacts SSH already wrote.
    manifest = store.load_manifest(run_id)
    introspect_steps = {
        name: result for name, result in manifest.step_results.items() if name.startswith("introspect:")
    }
    assert len(introspect_steps) == 1
    step = next(iter(introspect_steps.values()))
    assert step.status == StepStatus.FAILED
    assert step.details["code"] == "execution_state_changed"


# ---------------------------------------------------------------------------
# Iter-1 finding 5: request.json must not embed the plaintext script
# ---------------------------------------------------------------------------


def test_request_json_replaces_script_with_sha256_pointer(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    secret_script = "MY_CRED = 'leaked-plaintext-credential'\nemit({'ok': True})"
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    debug_introspect_run_handler(
        _make_request(run_id, script=secret_script),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    manifest = store.load_manifest(run_id)
    introspect_steps = [n for n in manifest.step_results if n.startswith("introspect:")]
    call_id = introspect_steps[0].split(":", 1)[1]
    request_json_path = store.run_dir(run_id) / "debug" / "introspect" / call_id / "request.json"
    request_body = request_json_path.read_text(encoding="utf-8")
    assert "leaked-plaintext-credential" not in request_body
    assert "sha256:" in request_body
    # Defense-in-depth — the sensitive wrapper.py still has the rendered script.
    wrapper_path = store.run_dir(run_id) / "sensitive" / "debug" / "introspect" / call_id / "wrapper.py"
    assert wrapper_path.exists()


# ---------------------------------------------------------------------------
# Iter-1 finding 6: ssh_user=root must skip sudo in the remote invocation
# ---------------------------------------------------------------------------


def test_chmod_survives_missing_raw_file_race(tmp_path: Path) -> None:
    # Iter-3 finding 2: a concurrent delete between SSH-write and our
    # chmod 0600 must not crash the handler with FileNotFoundError.
    # Simulate by having the FakeSshRunner produce a result, then unlink
    # the raw files before the handler reaches its chmod loop. Without
    # the fix the handler would raise FileNotFoundError into the outer
    # `except Exception` envelope and drop the manifest record.
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()

    class _DeletingFakeSsh(FakeSshRunner):
        def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None, max_stdout_bytes=None):
            result = super().run(
                argv,
                timeout=timeout,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                cancel=cancel,
                stdin=stdin,
            )
            stdout_path.unlink(missing_ok=True)
            stderr_path.unlink(missing_ok=True)
            return result

    ssh = _DeletingFakeSsh(results=[_happy_ssh_result()])
    # No exception escapes the handler — the response is a structured
    # ToolResponse, not a Python crash. (The call ends up reporting
    # wrapper_crash because stdout was deleted, but the manifest still
    # gets an introspect:<call_id> entry rather than being abandoned.)
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "wrapper_crash"
    manifest = store.load_manifest(run_id)
    introspect_steps = [n for n in manifest.step_results if n.startswith("introspect:")]
    assert len(introspect_steps) == 1
    assert manifest.step_results[introspect_steps[0]].status == StepStatus.FAILED


def test_raw_stdout_and_stderr_are_sensitive_artifacts(tmp_path: Path) -> None:
    # Iter-2 finding 2: SSH stdout/stderr are now routed directly to
    # `<sensitive>/stdout.raw` and `<sensitive>/stderr.raw` (mode 0600)
    # and registered as sensitive=True ArtifactRefs. The agent's
    # response.artifacts must NOT contain them; the manifest's
    # introspect:<call_id> step MUST.
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is True
    public_paths = {a.path for a in response.artifacts}
    # No agent-visible path under <run>/debug/introspect/ ends in `.tmp`.
    assert not any(p.endswith(".tmp") for p in public_paths)
    # Raw files live in sensitive/ and are absent from the public list.
    manifest = store.load_manifest(run_id)
    introspect_steps = [n for n in manifest.step_results if n.startswith("introspect:")]
    call_id = introspect_steps[0].split(":", 1)[1]
    sensitive_dir = store.run_dir(run_id) / "sensitive" / "debug" / "introspect" / call_id
    raw_stdout = sensitive_dir / "stdout.raw"
    raw_stderr = sensitive_dir / "stderr.raw"
    assert raw_stdout.exists()
    assert raw_stderr.exists()
    # Both are 0600 (defense-in-depth on top of the 0700 dir).
    assert raw_stdout.stat().st_mode & 0o777 == 0o600
    assert raw_stderr.stat().st_mode & 0o777 == 0o600
    # Public response artifacts don't expose the raw files.
    assert str(raw_stdout) not in public_paths
    assert str(raw_stderr) not in public_paths
    # Manifest records them as sensitive=True so artifacts.collect can pick
    # them up (when the operator opts in to sensitive collection).
    step_artifacts = manifest.step_results[introspect_steps[0]].artifacts
    sensitive_paths = {a.path for a in step_artifacts if a.sensitive}
    assert str(raw_stdout) in sensitive_paths
    assert str(raw_stderr) in sensitive_paths
    # No `.tmp` lingers in the agent-visible directory.
    agent_dir = store.run_dir(run_id) / "debug" / "introspect" / call_id
    assert list(agent_dir.glob("*.tmp")) == []


def test_root_ssh_user_omits_sudo_from_remote_argv(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is True
    # Exactly one SSH call (the wrapper invocation) — no sudo preflight.
    assert len(ssh.calls) == 1
    wrapper_call = ssh.calls[0]
    # Remote command is the last element of the SSH argv (after `--` and
    # user@host). Assert the `sudo` token does NOT appear in it.
    remote_cmd = wrapper_call["argv"][-1]
    assert "sudo" not in remote_cmd.split()
    assert "python3" in remote_cmd


# ---------------------------------------------------------------------------
# Characterization test: render_wrapper receives caps/args_json from run handler
# ---------------------------------------------------------------------------


def test_run_uses_runner_default_caps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import kdive.server as server

    captured: dict = {}
    orig = server.render_wrapper

    def spy(**kwargs):
        captured.update(kwargs)
        return orig(**kwargs)

    monkeypatch.setattr(server, "render_wrapper", spy)

    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(results=[_happy_ssh_result()]),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is True, response.error
    assert captured["caps"] is None  # run opts into no override → runner defaults
    assert captured["args_json"] == "{}"  # run passes empty args


# ---------------------------------------------------------------------------
# Step F: debug.introspect.helper handler tests
# ---------------------------------------------------------------------------


def _helper_ssh_result(emit_obj: dict) -> SshCommandResult:
    """Build a wrapper-stdout envelope shaped like _happy_ssh_result() but with
    a caller-supplied emit.  Copies the full envelope so tests see realistic JSON."""
    body = {
        "call_id": "0" * 32,
        "build_id": VALID_BUILD_ID,
        "outcome": {"status": "ok"},
        "emits": [emit_obj],
        "user_stdout": "",
        "prelude_ms": 5,
        "truncated": {
            "emits": False,
            "user_stdout": False,
            "traceback": False,
            "total_json": False,
            "per_emit_size": False,
            "error_message": False,
        },
    }
    return SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")


def _helper_script_error_ssh_result() -> SshCommandResult:
    """Wrapper envelope for a curated drgn script that RAISED on the target:
    outcome.status="error" carrying error_type/error_message, empty emits."""
    body = {
        "call_id": "0" * 32,
        "build_id": VALID_BUILD_ID,
        "outcome": {
            "status": "error",
            "error_type": "KeyError",
            "error_message": "'__num_online_cpus'",
            "traceback": "Traceback (most recent call last): ...",
        },
        "emits": [],
        "user_stdout": "",
        "prelude_ms": 5,
        "truncated": {
            "emits": False,
            "user_stdout": False,
            "traceback": False,
            "total_json": False,
            "per_emit_size": False,
            "error_message": False,
        },
    }
    return SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")


def test_helper_success_returns_typed_result(tmp_path: Path) -> None:
    from kdive.domain import DebugIntrospectHelperRequest
    from kdive.server import debug_introspect_helper_handler

    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    emit = {
        "release": "6.8",
        "version": "#1",
        "machine": "x86_64",
        "nodename": "vm",
        "boot_cmdline": "ro",
        "cpus_online": 2,
        "mem_total_pages": 100,
    }
    resp = debug_introspect_helper_handler(
        DebugIntrospectHelperRequest(run_id=run_id, target_ref="local-qemu", name="sysinfo"),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(results=[_helper_ssh_result(emit)]),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert resp.ok is True, resp.error
    assert resp.data["helper"] == "sysinfo"
    assert resp.data["result"]["release"] == "6.8"
    assert "emits" not in resp.data
    steps = store.load_manifest(run_id).step_results
    assert any(n.startswith("introspect:") and s.status.name == "SUCCEEDED" for n, s in steps.items())


def test_helper_malformed_emit_records_failed_step(tmp_path: Path) -> None:
    from kdive.domain import DebugIntrospectHelperRequest
    from kdive.server import debug_introspect_helper_handler

    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    resp = debug_introspect_helper_handler(
        DebugIntrospectHelperRequest(run_id=run_id, target_ref="local-qemu", name="sysinfo"),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(results=[_helper_ssh_result({"wrong": "shape"})]),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "helper_schema_drift"
    steps = store.load_manifest(run_id).step_results
    assert any(n.startswith("introspect:") and s.status.name == "FAILED" for n, s in steps.items())


def test_helper_script_error_records_failed_step(tmp_path: Path) -> None:
    from kdive.domain import DebugIntrospectHelperRequest
    from kdive.server import debug_introspect_helper_handler

    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    resp = debug_introspect_helper_handler(
        DebugIntrospectHelperRequest(run_id=run_id, target_ref="local-qemu", name="sysinfo"),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(results=[_helper_script_error_ssh_result()]),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "helper_script_error"
    steps = store.load_manifest(run_id).step_results
    assert any(n.startswith("introspect:") and s.status.name == "FAILED" for n, s in steps.items())


def test_helper_gating_enforced(tmp_path: Path) -> None:
    from kdive.config import DebugProfile
    from kdive.domain import DebugIntrospectHelperRequest
    from kdive.server import debug_introspect_helper_handler

    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, _ = _profiles()
    resp = debug_introspect_helper_handler(
        DebugIntrospectHelperRequest(run_id=run_id, target_ref="local-qemu", name="sysinfo"),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default", enabled_operations=[])},
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "operation_disabled"


def test_helper_unknown_name(tmp_path: Path) -> None:
    from kdive.domain import DebugIntrospectHelperRequest
    from kdive.server import debug_introspect_helper_handler

    resp = debug_introspect_helper_handler(
        DebugIntrospectHelperRequest(run_id="missing", target_ref="t", name="nope"),
        artifact_root=tmp_path,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "unknown_helper"


def test_helper_args_invalid(tmp_path: Path) -> None:
    from kdive.domain import DebugIntrospectHelperRequest
    from kdive.server import debug_introspect_helper_handler

    resp = debug_introspect_helper_handler(
        DebugIntrospectHelperRequest(run_id="missing", target_ref="t", name="tasks", args={"limit": "lots"}),
        artifact_root=tmp_path,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "helper_args_invalid"


def test_helper_passes_cap_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import kdive.server as server
    from kdive.domain import DebugIntrospectHelperRequest
    from kdive.server import debug_introspect_helper_handler

    captured: dict = {}
    orig = server.render_wrapper

    def spy(**kwargs):
        captured.update(kwargs)
        return orig(**kwargs)

    monkeypatch.setattr(server, "render_wrapper", spy)

    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    emit = {
        "release": "6.8",
        "version": "#1",
        "machine": "x86_64",
        "nodename": "vm",
        "boot_cmdline": "ro",
        "cpus_online": 2,
        "mem_total_pages": 100,
    }
    resp = debug_introspect_helper_handler(
        DebugIntrospectHelperRequest(run_id=run_id, target_ref="local-qemu", name="sysinfo"),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(results=[_helper_ssh_result(emit)]),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert resp.ok is True, resp.error
    assert captured["caps"] == server.HELPER_CAP_PROFILE


def test_helper_redacts_secret_in_emit(tmp_path: Path) -> None:
    from kdive.domain import DebugIntrospectHelperRequest
    from kdive.safety.redaction import REDACTION
    from kdive.server import debug_introspect_helper_handler

    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, _rootfs, debug = _profiles()
    rootfs_with_secret = {
        "minimal": RootfsProfile(
            name="minimal",
            source="/var/lib/kdive/rootfs/minimal.qcow2",
            access_method="ssh_and_serial",
            ssh_host="127.0.0.1",
            ssh_port=22,
            ssh_user="root",
            ssh_key_ref="supersecret",
            readiness_marker="ready",
        )
    }
    emit = {
        "release": "6.8",
        "version": "#1",
        "machine": "x86_64",
        "nodename": "vm",
        "boot_cmdline": "ro quiet supersecret extra",
        "cpus_online": 2,
        "mem_total_pages": 100,
    }
    ssh = FakeSshRunner(results=[_helper_ssh_result(emit)])
    resp = debug_introspect_helper_handler(
        DebugIntrospectHelperRequest(run_id=run_id, target_ref="local-qemu", name="sysinfo"),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs_with_secret,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert resp.ok is True, resp.error
    assert "supersecret" not in resp.data["result"]["boot_cmdline"]
    assert REDACTION in resp.data["result"]["boot_cmdline"]
