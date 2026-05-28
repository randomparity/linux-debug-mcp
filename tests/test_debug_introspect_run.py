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

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile, RootfsProfile, TargetProfile
from linux_debug_mcp.coordination.admission import (
    AdmissionError,
    TargetSnapshot,
)
from linux_debug_mcp.domain import (
    DebugIntrospectRunRequest,
    ErrorCategory,
    RunRequest,
    StepResult,
    StepStatus,
)
from linux_debug_mcp.providers.local_ssh_tests import SshCommandResult
from linux_debug_mcp.seams.target import ConsoleKind, PlatformMetadata, TargetState
from linux_debug_mcp.server import debug_introspect_run_handler

VALID_BUILD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


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
                source="/var/lib/linux-debug-mcp/rootfs/minimal.qcow2",
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


def test_allow_write_rejected(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id, allow_write=True),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "allow_write_not_supported"


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


def test_provenance_missing_when_manifest_lacks_build_id(tmp_path: Path) -> None:
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
    # Plan review finding 3 (R6-F1 refinement): the diagnostic must direct the
    # operator at `kernel.create_run` as the recovery action. The explanatory
    # mention of `force_rebuild` in the message body is intentional.
    assert "kernel.create_run" in response.error.message


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
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="x",
            artifacts=[],
            details={"build_id": "not-hex!"},
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
    monkeypatch.setattr("linux_debug_mcp.server.MAX_INTROSPECT_CALLS_PER_RUN", 4)
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


def test_admission_no_snapshot_returns_target_not_ready(tmp_path: Path) -> None:
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
    assert response.error.details["code"] == "target_not_ready"


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
            source="/var/lib/linux-debug-mcp/rootfs/minimal.qcow2",
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
    from linux_debug_mcp.providers.local_drgn_introspect import WrapperRenderError

    def _boom(**_kwargs):
        raise WrapperRenderError("test forced render failure")

    monkeypatch.setattr("linux_debug_mcp.server.render_wrapper", _boom)

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
