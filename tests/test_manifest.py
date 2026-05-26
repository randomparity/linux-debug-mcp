from linux_debug_mcp.artifacts.manifest import BootAttempt, RunManifest
from linux_debug_mcp.config import RootfsProfile, TargetProfile
from linux_debug_mcp.domain import RunRequest, StepStatus


def _request():
    return RunRequest(source_path="/src", build_profile="b", target_profile="t", rootfs_profile="r")


def _attempt(n):
    return BootAttempt(
        attempt=n,
        resolved_target_profile=TargetProfile(name="t", architecture="x86_64"),
        resolved_rootfs_profile=RootfsProfile(name="r", source="/img.qcow2"),
        status=StepStatus.SUCCEEDED,
    )


def test_schema_version_is_2():
    manifest = RunManifest.create(run_id="run-1", request=_request())
    assert manifest.schema_version == 2
    assert manifest.boot_attempts == []
    assert manifest.resolved_build_profile is None


def test_with_boot_attempt_appends_without_mutating():
    manifest = RunManifest.create(run_id="run-1", request=_request())
    updated = manifest.with_boot_attempt(_attempt(1))
    assert manifest.boot_attempts == []  # original unchanged
    assert [a.attempt for a in updated.boot_attempts] == [1]
    updated2 = updated.with_boot_attempt(_attempt(2))
    assert [a.attempt for a in updated2.boot_attempts] == [1, 2]


def test_schema_version_1_manifest_still_loads():
    payload = (
        '{"schema_version": 1, "writer_version": "0.0.0", "run_id": "old-1",'
        ' "created_at": "2026-01-01T00:00:00Z",'
        ' "request": {"source_path": "/src", "build_profile": "b",'
        ' "target_profile": "t", "rootfs_profile": "r"},'
        ' "steps": [], "step_results": {}, "cleanup_state": "not_started"}'
    )
    manifest = RunManifest.model_validate_json(payload)
    assert manifest.schema_version == 1
    assert manifest.boot_attempts == []
    assert manifest.resolved_build_profile is None
