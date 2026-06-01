from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from typing import Any

import pytest
from pydantic import ValidationError

from kdive.artifacts.store import ArtifactStore
from kdive.config import RootfsProfile
from kdive.domain import (
    ErrorCategory,
    RunRequest,
    StepResult,
    StepStatus,
)
from kdive.postmortem.handlers import debug_postmortem_check_prereqs_handler
from kdive.postmortem.models import DebugPostmortemCheckPrereqsRequest
from kdive.providers.local.test.local_ssh_tests import SshCommandResult
from kdive.target.probes import reject_if_target_halted
from kdive.transport.core.base import ExecutionState


def test_request_defaults_and_fields() -> None:
    req = DebugPostmortemCheckPrereqsRequest(run_id="r1", manifest_target_profile="x86_64-default")
    assert req.timeout_seconds == 20
    assert req.debug_profile is None


def test_request_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        DebugPostmortemCheckPrereqsRequest(run_id="r1", manifest_target_profile="x", bogus=1)


def test_request_rejects_deprecated_target_ref_alias() -> None:
    with pytest.raises(ValidationError):
        DebugPostmortemCheckPrereqsRequest(run_id="r1", target_ref="local-qemu")


class _FakeSnapshot:
    generation = 1
    platform = None


class _FakeAdmission:
    def current_snapshot(self, target_key):  # noqa: ANN001
        return _FakeSnapshot()

    def current_execution_epoch(self, target_key):  # noqa: ANN001
        return 0


class _FakeRecord:
    def __init__(self, state: ExecutionState) -> None:
        self.execution_state = state


class _FakeRegistry:
    def __init__(self, state: ExecutionState) -> None:
        self._state = state

    def read_record(self, target_key):  # noqa: ANN001
        return _FakeRecord(self._state)


def test_halted_target_is_fast_rejected() -> None:
    resp = reject_if_target_halted(
        run_id="r1",
        admission=_FakeAdmission(),
        session_registry=_FakeRegistry(ExecutionState.HALTED),
    )
    assert resp is not None
    assert resp.ok is False
    assert resp.error is not None
    assert resp.error.category == ErrorCategory.READINESS_FAILURE
    assert resp.error.details["code"] == "target_halted"


def test_executing_target_proceeds() -> None:
    assert (
        reject_if_target_halted(
            run_id="r1",
            admission=_FakeAdmission(),
            session_registry=_FakeRegistry(ExecutionState.EXECUTING),
        )
        is None
    )


def test_inert_gate_when_admission_absent() -> None:
    assert reject_if_target_halted(run_id="r1", admission=None, session_registry=None) is None


SECRET_KEY_REF = "s3cr3t-key"  # pragma: allowlist secret


def _rootfs(**over) -> dict[str, RootfsProfile]:
    base = {
        "name": "minimal",
        "source": "/img.qcow2",
        "access_method": "ssh",
        "ssh_host": "127.0.0.1",
        "ssh_user": "root",
        "ssh_key_ref": SECRET_KEY_REF,
    }
    base.update(over)
    return {"minimal": RootfsProfile(**base)}


def _booted_run(tmp_path, *, booted: bool = True) -> str:
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
        StepResult(step_name="build", status=StepStatus.SUCCEEDED, summary="build ok", artifacts=[]),
    )
    if booted:
        store.record_step_result(
            manifest.run_id,
            StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="boot ok", artifacts=[]),
        )
    return manifest.run_id


def _req(run_id: str, **over) -> DebugPostmortemCheckPrereqsRequest:
    base = {"run_id": run_id, "manifest_target_profile": "local-qemu"}
    base.update(over)
    return DebugPostmortemCheckPrereqsRequest(**base)


@dataclass
class _FakeRunner:
    results: list[SshCommandResult] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}"

    def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None, max_stdout_bytes=None):
        self.calls.append({"argv": argv, "stdin": stdin})
        result = self.results.pop(0) if self.results else SshCommandResult(exit_status=0, stdout="{}")
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        return result


def _ready_facts(**over) -> dict[str, Any]:
    doc = {
        "arch": "x86_64",
        "cmdline_has_crashkernel": True,
        "kexec_crash_size": 268435456,
        "fadump_enabled": None,
        "fadump_registered": None,
        "service_active": True,
        "service_units": {"kdump": "active"},
        "dump_target_directive": None,
        "dump_dir": None,
        "dump_dir_exists": True,
        "dump_dir_writable": True,
        "dump_dir_write_error": None,
    }
    doc.update(over)
    return doc


def _runner(facts: dict[str, Any] | None = None, *, exit_status: int = 0, stdout: str | None = None) -> _FakeRunner:
    payload = stdout if stdout is not None else _json.dumps(facts if facts is not None else _ready_facts())
    return _FakeRunner(results=[SshCommandResult(exit_status=exit_status, stdout=payload)])


def test_handler_success_three_checks(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_check_prereqs_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=_runner()
    )
    assert resp.ok is True
    assert resp.data["kdump_ready"] is True
    assert resp.data["mechanism"] == "kdump"
    assert len(resp.data["checks"]) == 3
    assert resp.suggested_next_actions == ["artifacts.get_manifest"]


def test_handler_run_not_found(tmp_path) -> None:
    resp = debug_postmortem_check_prereqs_handler(
        _req("nope"), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=_runner()
    )
    assert resp.ok is False
    assert resp.error is not None
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_handler_not_booted_is_readiness_failure(tmp_path) -> None:
    run_id = _booted_run(tmp_path, booted=False)
    resp = debug_postmortem_check_prereqs_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=_runner()
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "target_not_booted"


def test_handler_bad_timeout_is_configuration_error(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_check_prereqs_handler(
        _req(run_id, timeout_seconds=1), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=_runner()
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "invalid_timeout"


def test_handler_non_ssh_rootfs_is_configuration_error(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_check_prereqs_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(access_method="serial"), ssh_runner=_runner()
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_handler_python_absent(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_check_prereqs_handler(
        _req(run_id),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(),
        ssh_runner=_runner(stdout="", exit_status=127),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "probe_no_python"


def test_handler_unparseable(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_check_prereqs_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=_runner(stdout="not json")
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "probe_unparseable"


def test_handler_halted_fast_reject(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_check_prereqs_handler(
        _req(run_id),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(),
        ssh_runner=_runner(),
        admission=_FakeAdmission(),
        session_registry=_FakeRegistry(ExecutionState.HALTED),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "target_halted"


def test_handler_redacts_secret_in_probe(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    facts = _ready_facts(service_units={"kdump": f"active {SECRET_KEY_REF}"})
    resp = debug_postmortem_check_prereqs_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=_runner(facts)
    )
    assert resp.ok is True
    assert SECRET_KEY_REF not in _json.dumps(resp.data)


def test_handler_fadump_target_ready(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    facts = _ready_facts(
        arch="ppc64le", cmdline_has_crashkernel=False, kexec_crash_size=0, fadump_enabled=1, fadump_registered=1
    )
    resp = debug_postmortem_check_prereqs_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=_runner(facts)
    )
    assert resp.ok is True
    assert resp.data["mechanism"] == "fadump"
    assert resp.data["kdump_ready"] is True
