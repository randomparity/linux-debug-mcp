"""Tests for debug.introspect.check_prerequisites (spec §3-§9)."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from kdive.artifacts.store import ArtifactStore
from kdive.config import RootfsProfile
from kdive.domain import ErrorCategory, RunRequest, StepResult, StepStatus
from kdive.introspect.handlers import debug_introspect_check_prerequisites_handler
from kdive.introspect.models import DebugIntrospectCheckPrerequisitesRequest
from kdive.providers.local.test.local_ssh_tests import SshCommandResult
from kdive.seams.probes import PROBE_STDOUT_CAP
from kdive.server import create_app
from kdive.transport.core.base import ExecutionState

VALID_BUILD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


def _rootfs(**over) -> dict[str, RootfsProfile]:
    base = {
        "name": "minimal",
        "source": "/img.qcow2",
        "access_method": "ssh",
        "ssh_host": "127.0.0.1",
        "ssh_user": "root",
    }
    base.update(over)
    return {"minimal": RootfsProfile(**base)}


def _booted_run(tmp_path: Path, *, with_build_id: bool = True, booted: bool = True) -> str:
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
            details={"build_id": VALID_BUILD_ID} if with_build_id else {},
        ),
    )
    if booted:
        store.record_step_result(
            manifest.run_id,
            StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="boot ok", artifacts=[]),
        )
    return manifest.run_id


def _req(run_id: str, **over):
    base = {"run_id": run_id, "manifest_target_profile": "local-qemu"}
    base.update(over)
    return DebugIntrospectCheckPrerequisitesRequest(**base)


def test_request_defaults_and_extra_forbidden() -> None:
    req = DebugIntrospectCheckPrerequisitesRequest(run_id="r1", manifest_target_profile="local-qemu")
    assert req.timeout_seconds == 20
    assert req.debug_profile is None
    with pytest.raises(ValidationError):
        DebugIntrospectCheckPrerequisitesRequest(run_id="r1", manifest_target_profile="t", bogus=1)


def test_run_not_found_is_configuration_error(tmp_path: Path) -> None:
    resp = debug_introspect_check_prerequisites_handler(_req("nope"), artifact_root=tmp_path, rootfs_profiles=_rootfs())
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_not_booted_is_readiness_failure(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path, booted=False)
    resp = debug_introspect_check_prerequisites_handler(_req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs())
    assert resp.error.category == ErrorCategory.READINESS_FAILURE
    assert resp.suggested_next_actions == ["target.boot"]


def test_timeout_out_of_band_is_configuration_error(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id, timeout_seconds=999), artifact_root=tmp_path, rootfs_profiles=_rootfs()
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_non_ssh_access_method_is_configuration_error(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(access_method="serial")
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_missing_ssh_host_is_configuration_error(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(ssh_host=None)
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["field"] == "ssh_host"


def test_rootfs_profile_mismatch_is_configuration_error(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id, rootfs_profile="other"), artifact_root=tmp_path, rootfs_profiles=_rootfs()
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "manifest_profile_mismatch"


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


def test_halted_target_is_fast_rejected_before_introspect_prereq_probe(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=_probe_json())])

    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(),
        ssh_runner=runner,
        admission=_FakeAdmission(),
        session_registry=_FakeRegistry(ExecutionState.HALTED),
    )

    assert resp.ok is False
    assert resp.error is not None
    assert resp.error.category == ErrorCategory.READINESS_FAILURE
    assert resp.error.details["code"] == "target_halted"
    assert "probing introspect prerequisites" in resp.error.message
    assert runner.calls == []


# ---------------------------------------------------------------------------
# Task 8: SSH body tests
# ---------------------------------------------------------------------------

HOST = VALID_BUILD_ID


@dataclass
class FakeSshRunner:
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


def _probe_json(**over) -> str:
    doc = {
        "python_version": "3.11.2",
        "python_executable": "/usr/bin/python3",
        "drgn_present": True,
        "drgn_version": "0.0.27",
        "distro_id": "fedora",
        "distro_version": "39",
        "kernel_release": "6.7.0",
        "running_build_id": HOST,
        "vmlinux_debuginfo": {
            "candidates": [{"path": "/usr/lib/debug/boot/vmlinux-6.7.0", "file_build_id": HOST}],
            "btf": True,
            "module_debuginfo": True,
            "module_path": "/usr/lib/debug/lib/modules/6.7.0/kernel",
        },
    }
    doc.update(over)
    return json.dumps(doc)


def test_usable_target(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=_probe_json())])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
    )
    assert resp.ok is True
    assert resp.data["introspect_usable"] == "usable"
    assert resp.suggested_next_actions == ["debug.introspect.run"]
    assert runner.calls[0]["stdin"] is not None and "import json" in runner.calls[0]["stdin"]


def test_probe_uses_sudo_for_non_root(tmp_path: Path) -> None:
    """Spec §4: the probe's remote argv must carry the same sudo prefix the
    runner uses for a non-root SSH login, and must omit it for root."""
    run_id = _booted_run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=_probe_json())])
    debug_introspect_check_prerequisites_handler(
        _req(run_id),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(ssh_user="debug"),
        ssh_runner=runner,
    )
    # build_ssh_argv folds the remote argv into the trailing shell-command
    # string, so the sudo prefix surfaces in the last ssh_argv element.
    assert "sudo python3 -" in runner.calls[0]["argv"][-1]

    root_runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=_probe_json())])
    debug_introspect_check_prerequisites_handler(
        _req(run_id),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(ssh_user="root"),
        ssh_runner=root_runner,
    )
    assert "sudo" not in root_runner.calls[0]["argv"][-1]


def test_drgn_missing_reports_unusable(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    body = _probe_json(drgn_present=False, drgn_version=None)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=body)])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
    )
    assert resp.ok is True
    assert resp.data["introspect_usable"] == "unusable"
    assert resp.suggested_next_actions == ["host.check_prerequisites"]


def test_python3_missing_exit_127(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=127, stdout="", stderr="python3: not found")])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
    )
    assert resp.ok is True
    by = {c["check_id"]: c for c in resp.data["checks"]}
    assert by["target.python3"]["status"] == "failed"
    assert by["target.drgn"]["status"] == "skipped"
    assert resp.data["introspect_usable"] == "unusable"


def test_garbage_stdout_is_infrastructure_failure(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout="not json", stderr="boom")])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
    )
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE


def test_oversized_stdout_is_infrastructure_failure(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    huge = "x" * (PROBE_STDOUT_CAP + 10)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=huge)])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
    )
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "oversized_output"


def test_ssh_timeout_is_infrastructure_failure(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=-1, stdout="", timed_out=True)])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
    )
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE


def test_runner_raises_is_infrastructure_failure(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)

    @dataclass
    class RaisingSshRunner(FakeSshRunner):
        def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None, max_stdout_bytes=None):
            raise OSError("transport broke")

    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=RaisingSshRunner()
    )
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "ssh_failure"


def test_redaction_hides_ssh_key_ref(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    secret = "/secret/id_ed25519"  # pragma: allowlist secret
    # python_executable surfaces in resp.data["checks"] as details["executable"]
    # on both target.python3 and target.drgn, so the secret reaches the response.
    body = _probe_json(python_executable=secret)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=body)])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(ssh_key_ref=secret),
        ssh_runner=runner,
    )
    assert secret not in json.dumps(resp.model_dump(mode="json"))
    by = {c["check_id"]: c for c in resp.data["checks"]}
    executable = by["target.python3"]["details"]["executable"]
    assert executable
    assert executable != secret


def test_concurrent_probes_get_distinct_dirs(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    ids = set()
    for _ in range(2):
        runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=_probe_json())])
        resp = debug_introspect_check_prerequisites_handler(
            _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
        )
        ids.add(resp.data["probe_id"])
    assert len(ids) == 2


def test_ssh_connect_failure_exit_255(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    secret = "/secret/id_ed25519"  # pragma: allowlist secret
    runner = FakeSshRunner(
        results=[
            SshCommandResult(
                exit_status=255,
                stdout="",
                stderr_snippet=f"ssh: connect using key {secret}: Connection refused",
            )
        ]
    )
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(ssh_key_ref=secret),
        ssh_runner=runner,
    )
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "ssh_connect_failure"
    assert "Connection refused" in resp.error.details["stderr"]
    assert secret not in json.dumps(resp.model_dump(mode="json"))


def test_tool_is_registered() -> None:
    # Project idiom for enumerating registered tools (tests/test_server.py:40).
    names = set(create_app()._tool_manager._tools)
    assert "debug.introspect.check_prerequisites" in names
