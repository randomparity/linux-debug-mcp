import pytest

from kdive.artifacts import store as store_module
from kdive.artifacts.manifest import BootAttempt
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import BuildProfile, RootfsProfile, TargetProfile
from kdive.domain import ErrorCategory, RunRequest, StepResult, StepStatus


def _store(tmp_path) -> ArtifactStore:
    return ArtifactStore(tmp_path / "runs")


def _request():
    return RunRequest(source_path="/src", build_profile="b", target_profile="t", rootfs_profile="r")


def test_create_run_freezes_resolved_build_profile(tmp_path):
    store = _store(tmp_path)
    resolved = BuildProfile(name="b", architecture="x86_64", make_variables={"CC": "clang"})
    manifest = store.create_run(_request(), resolved_build_profile=resolved)
    reloaded = store.load_manifest(manifest.run_id)
    assert reloaded.resolved_build_profile.make_variables == {"CC": "clang"}


def test_record_boot_attempt_appends_and_repoints_boot(tmp_path):
    store = _store(tmp_path)
    manifest = store.create_run(_request())
    attempt = BootAttempt(
        attempt=1,
        resolved_target_profile=TargetProfile(name="t", architecture="x86_64"),
        resolved_rootfs_profile=RootfsProfile(name="r", source="/img.qcow2"),
        status=StepStatus.SUCCEEDED,
    )
    boot_result = StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="booted")
    store.record_boot_attempt(manifest.run_id, attempt=attempt, boot_result=boot_result)

    reloaded = store.load_manifest(manifest.run_id)
    assert [a.attempt for a in reloaded.boot_attempts] == [1]
    assert reloaded.step_results["boot"].status == StepStatus.SUCCEEDED


def test_record_boot_attempt_replaces_succeeded_boot(tmp_path):
    store = _store(tmp_path)
    manifest = store.create_run(_request())
    first = StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="boot-1")
    store.record_step_result(manifest.run_id, first)
    attempt2 = BootAttempt(
        attempt=2,
        resolved_target_profile=TargetProfile(name="t", architecture="x86_64"),
        resolved_rootfs_profile=RootfsProfile(name="r", source="/img.qcow2"),
        status=StepStatus.SUCCEEDED,
    )
    second = StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="boot-2")
    store.record_boot_attempt(manifest.run_id, attempt=attempt2, boot_result=second)
    reloaded = store.load_manifest(manifest.run_id)
    assert reloaded.step_results["boot"].summary == "boot-2"
    assert [a.attempt for a in reloaded.boot_attempts] == [2]


def test_record_step_result_append_true_grows_results(tmp_path):
    store = _store(tmp_path)
    manifest = store.create_run(_request())
    first = StepResult(
        step_name="introspect:aaa",
        status=StepStatus.SUCCEEDED,
        summary="ok",
        details={},
        artifacts=[],
    )
    second = StepResult(
        step_name="introspect:bbb",
        status=StepStatus.SUCCEEDED,
        summary="ok",
        details={},
        artifacts=[],
    )
    store.record_step_result(manifest.run_id, first, append=True)
    final = store.record_step_result(manifest.run_id, second, append=True)
    assert set(final.step_results.keys()) == {"introspect:aaa", "introspect:bbb"}


def test_record_step_result_append_true_rejects_collision(tmp_path):
    store = _store(tmp_path)
    manifest = store.create_run(_request())
    first = StepResult(
        step_name="introspect:aaa",
        status=StepStatus.SUCCEEDED,
        summary="ok",
        details={},
        artifacts=[],
    )
    store.record_step_result(manifest.run_id, first, append=True)
    with pytest.raises(ManifestStateError):
        store.record_step_result(manifest.run_id, first, append=True)


def test_manifest_write_oserror_raises_manifest_state_error(tmp_path, monkeypatch):
    store = _store(tmp_path)
    manifest = store.create_run(_request())
    result = StepResult(step_name="build", status=StepStatus.SUCCEEDED, summary="built")

    def fail_replace(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(store_module.os, "replace", fail_replace)

    with pytest.raises(ManifestStateError) as exc_info:
        store.record_step_result(manifest.run_id, result)

    assert exc_info.value.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert manifest.run_id in str(exc_info.value)
    assert "manifest.json" in str(exc_info.value)
    assert "disk full" in str(exc_info.value)
