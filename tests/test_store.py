from linux_debug_mcp.artifacts.manifest import BootAttempt
from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import BuildProfile, RootfsProfile, TargetProfile
from linux_debug_mcp.domain import RunRequest, StepResult, StepStatus


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
