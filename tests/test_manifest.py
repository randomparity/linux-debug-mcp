import pytest

from linux_debug_mcp.artifacts.manifest import BootAttempt, RunManifest
from linux_debug_mcp.config import RootfsProfile, TargetProfile
from linux_debug_mcp.domain import RunRequest, StepResult, StepStatus


def _request():
    return RunRequest(source_path="/src", build_profile="b", target_profile="t", rootfs_profile="r")


def _attempt(n):
    return BootAttempt(
        attempt=n,
        resolved_target_profile=TargetProfile(name="t", architecture="x86_64"),
        resolved_rootfs_profile=RootfsProfile(name="r", source="/img.qcow2"),
        status=StepStatus.SUCCEEDED,
    )


def test_schema_version_is_3():
    manifest = RunManifest.create(run_id="run-1", request=_request())
    assert manifest.schema_version == 3
    assert manifest.boot_attempts == []
    assert manifest.resolved_build_profile is None
    assert manifest.resolved_target_profile is None
    assert manifest.resolved_rootfs_profile is None


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


def _make_manifest() -> RunManifest:
    return RunManifest.create(run_id="run-1", request=_request())


def test_append_step_result_grows_step_results() -> None:
    manifest = _make_manifest()
    first = StepResult(
        step_name="introspect:abc",
        status=StepStatus.SUCCEEDED,
        summary="ok",
        details={},
        artifacts=[],
    )
    second = StepResult(
        step_name="introspect:def",
        status=StepStatus.SUCCEEDED,
        summary="ok",
        details={},
        artifacts=[],
    )
    updated = manifest.append_step_result(first).append_step_result(second)
    assert set(updated.step_results.keys()) == {"introspect:abc", "introspect:def"}


def test_append_step_result_leaves_steps_unchanged() -> None:
    # Plan review finding 1: `RunManifest.steps` is the *planned* list seeded by
    # `RunManifest.create` — exactly 6 entries. `append_step_result` may only grow
    # `step_results`; mutating `steps` would conflate planned-vs-executed.
    manifest = _make_manifest()
    original_steps = list(manifest.steps)
    result = StepResult(
        step_name="introspect:abc",
        status=StepStatus.SUCCEEDED,
        summary="ok",
        details={},
        artifacts=[],
    )
    updated = manifest.append_step_result(result)
    assert updated.steps == original_steps
    assert "introspect:abc" in updated.step_results


def test_append_step_result_rejects_existing_name() -> None:
    manifest = _make_manifest()
    first = StepResult(
        step_name="introspect:abc",
        status=StepStatus.SUCCEEDED,
        summary="ok",
        details={},
        artifacts=[],
    )
    second = StepResult(
        step_name="introspect:abc",
        status=StepStatus.SUCCEEDED,
        summary="dup",
        details={},
        artifacts=[],
    )
    updated = manifest.append_step_result(first)
    with pytest.raises(ValueError, match="step name already recorded"):
        updated.append_step_result(second)
