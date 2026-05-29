"""Tests for debug.introspect.check_prerequisites (spec §3-§9)."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import RootfsProfile
from linux_debug_mcp.domain import (
    DebugIntrospectCheckPrerequisitesRequest,
    ErrorCategory,
    RunRequest,
    StepResult,
    StepStatus,
)
from linux_debug_mcp.server import debug_introspect_check_prerequisites_handler

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
    base = {"run_id": run_id, "target_ref": "local-qemu"}
    base.update(over)
    return DebugIntrospectCheckPrerequisitesRequest(**base)


def test_request_defaults_and_extra_forbidden() -> None:
    req = DebugIntrospectCheckPrerequisitesRequest(run_id="r1", target_ref="local-qemu")
    assert req.timeout_seconds == 20
    assert req.debug_profile is None
    with pytest.raises(ValidationError):
        DebugIntrospectCheckPrerequisitesRequest(run_id="r1", target_ref="t", bogus=1)


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
