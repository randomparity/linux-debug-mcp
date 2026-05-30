import threading
from pathlib import Path

import pytest
from conftest import (
    FakeBootProvider,
    Plan,
    create_run,
    profiles,
    record_build,
    rootfs_profile,
    target_profile,
)

from kdive.artifacts.store import ArtifactStore
from kdive.config import BootOverrides, RootfsOverrides, RootfsProfile, TargetProfile
from kdive.coordination.admission import AdmissionService, SnapshotStore
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus
from kdive.providers.libvirt_qemu import BootExecutionResult, ProviderBootError
from kdive.seams.target import TargetKey
from kdive.server import target_boot_handler


def boot(
    artifact_root: Path,
    tmp_path: Path,
    *,
    run_id: str = "run-abc123",
    provider: FakeBootProvider | None = None,
    target: TargetProfile | None = None,
    **kwargs: object,
):
    return target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider or FakeBootProvider(),
        **profiles(tmp_path, target=target),
        **kwargs,
    )


def test_target_boot_missing_run_is_configuration_error(tmp_path: Path) -> None:
    response = target_boot_handler(
        artifact_root=tmp_path / "runs",
        run_id="run-missing",
        provider=FakeBootProvider(),
        **profiles(tmp_path),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "run not found" in response.error.message


def test_target_boot_requires_succeeded_build(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)

    response = boot(artifact_root, tmp_path)

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "succeeded build" in response.error.message


def test_target_boot_rejects_succeeded_build_without_kernel_image(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root, include_kernel_image=False)

    response = boot(artifact_root, tmp_path)

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "kernel-image" in response.error.message


def test_target_boot_rejects_build_target_architecture_mismatch(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root, architecture="arm64")

    response = boot(artifact_root, tmp_path)

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "architecture" in response.error.message


def test_target_boot_public_defaults_resolve_manifest_profile_names(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    provider = FakeBootProvider()

    # The default `minimal` rootfs is source_kind="builder" pointing at an image the test
    # host does not have, so it gates before plan_boot. Inject a resolvable local_path
    # rootfs while leaving the target profile to resolve from the default registry — this
    # still exercises manifest-name resolution for both profiles.
    response = target_boot_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs_profile(tmp_path)},
    )

    assert response.ok is True
    assert provider.plans[0]["target_profile"].name == "local-qemu"
    assert provider.plans[0]["rootfs_profile"].name == "minimal"


def test_target_boot_records_debug_endpoint_in_manifest(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    run_id = "run-abc123"
    record_build(artifact_root, run_id)
    provider = FakeBootProvider()
    response = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        target_profiles={
            "local-qemu": TargetProfile(
                name="local-qemu",
                architecture="x86_64",
                target_ref="debug-vm",
                libvirt_uri="qemu:///system",
                managed_domain=True,
                debug_gdbstub=True,
                gdbstub_endpoint="127.0.0.1:1234",
            )
        },
        rootfs_profiles={"minimal": rootfs_profile(tmp_path)},
    )

    assert response.ok is True
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest(run_id)
    boot = manifest.step_results["boot"]
    assert boot.details["debug_boot"] is True
    assert boot.details["gdbstub_endpoint"] == {"host": "127.0.0.1", "port": 1234}
    assert boot.details["nokaslr_source"] == "provider_added"
    assert boot.details["kernel_image_path"].endswith("/run-abc123/build/arch/x86/boot/bzImage")


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"target_profile": "other-target"}, "target_profile must match"),
        ({"rootfs_profile": "other-rootfs"}, "rootfs_profile must match"),
    ],
)
def test_target_boot_rejects_profile_mismatch_arguments(
    tmp_path: Path,
    kwargs: dict[str, str],
    message: str,
) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)

    response = boot(artifact_root, tmp_path, **kwargs)

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert message in response.error.message


def test_target_boot_repeat_success_returns_recorded_result_without_provider(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    provider = FakeBootProvider()

    first = boot(artifact_root, tmp_path, provider=provider)
    second = boot(artifact_root, tmp_path, provider=provider)

    assert first.ok is True
    assert second.ok is True
    assert second.data == first.data
    assert len(provider.executions) == 1
    assert len(provider.plans) == 1


def test_target_boot_running_state_returns_failure_while_lock_active(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    provider = FakeBootProvider()
    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(
        "run-abc123",
        StepResult(
            step_name="boot",
            status=StepStatus.RUNNING,
            summary="target boot running",
            details={"domain": "kdive-dev"},
        ),
    )

    with store.boot_lock("run-abc123"):
        response = boot(artifact_root, tmp_path, provider=provider)

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert response.error.details["domain"] == "kdive-dev"
    assert provider.plans == []


def test_target_boot_lock_failure_reloads_recorded_running_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    store = ArtifactStore(artifact_root, create_root=False)
    initial_manifest = store.load_manifest("run-abc123")
    store.record_step_result(
        "run-abc123",
        StepResult(
            step_name="boot",
            status=StepStatus.RUNNING,
            summary="fresh running",
            details={"domain": "fresh-domain", "boot_log_path": "fresh.log"},
        ),
    )
    provider = FakeBootProvider()
    original_load_manifest = ArtifactStore.load_manifest
    calls = 0

    def load_manifest_once_stale(self: ArtifactStore, loaded_run_id: str):
        nonlocal calls
        calls += 1
        if calls == 1:
            return initial_manifest
        return original_load_manifest(self, loaded_run_id)

    monkeypatch.setattr(ArtifactStore, "load_manifest", load_manifest_once_stale)

    with store.boot_lock("run-abc123"):
        response = boot(artifact_root, tmp_path, provider=provider)

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert response.error.details["domain"] == "fresh-domain"
    assert response.error.details["boot_log_path"] == "fresh.log"
    assert provider.plans == []


def test_target_boot_force_reboot_invokes_provider_and_replaces_success(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    provider = FakeBootProvider(summary="first")
    assert boot(artifact_root, tmp_path, provider=provider).ok is True
    provider.summary = "replacement"

    response = boot(artifact_root, tmp_path, provider=provider, force_reboot=True)

    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert response.ok is True
    assert response.summary == "replacement"
    assert manifest.step_results["boot"].summary == "replacement"
    assert [execution["force_reboot"] for execution in provider.executions] == [False, True]


def test_target_boot_failed_boot_retries_after_failure(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(
        "run-abc123",
        StepResult(step_name="boot", status=StepStatus.FAILED, summary="old failure"),
    )
    provider = FakeBootProvider()

    response = boot(artifact_root, tmp_path, provider=provider)

    assert response.ok is True
    assert provider.executions[0]["retrying_after_failure"] is True


def test_target_boot_provider_planning_error_is_recorded_and_mapped(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    provider = FakeBootProvider(
        raise_on_plan=ProviderBootError(
            "unsupported boot plan",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"field": "rootfs"},
            artifacts=[ArtifactRef(path=str(artifact_root / "run-abc123" / "logs" / "boot.log"), kind="boot-log")],
        )
    )

    response = boot(artifact_root, tmp_path, provider=provider)

    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert response.error.details == {"field": "rootfs"}
    assert manifest.step_results["boot"].status == StepStatus.FAILED
    assert manifest.step_results["boot"].summary == "unsupported boot plan"
    assert manifest.step_results["boot"].details == {"field": "rootfs"}


def test_target_boot_unexpected_execute_exception_records_infrastructure_failure(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    provider = FakeBootProvider(raise_on_execute=RuntimeError("boom"))

    response = boot(artifact_root, tmp_path, provider=provider)

    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert response.error.details["exception_type"] == "RuntimeError"
    assert manifest.step_results["boot"].status == StepStatus.FAILED
    assert manifest.step_results["boot"].summary == "unexpected boot provider failure"


def test_target_boot_execute_exception_records_failed_attempt_and_retry_uses_next_attempt(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)

    failing = boot(artifact_root, tmp_path, provider=FakeBootProvider(raise_on_execute=RuntimeError("boom")))
    assert failing.ok is False
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    # the failed attempt is recorded atomically, so it occupies attempt-1 ...
    assert [attempt.attempt for attempt in manifest.boot_attempts] == [1]
    assert manifest.boot_attempts[0].status == StepStatus.FAILED

    # ... and a retry advances to attempt-2 instead of overwriting attempt-1
    retry = boot(artifact_root, tmp_path, provider=FakeBootProvider())
    assert retry.ok is True
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert [attempt.attempt for attempt in manifest.boot_attempts] == [1, 2]
    assert manifest.boot_attempts[1].status == StepStatus.SUCCEEDED


def test_target_boot_failed_execution_result_propagates_error_category(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    provider = FakeBootProvider(
        status=StepStatus.FAILED,
        summary="target boot timed out",
        error_category=ErrorCategory.BOOT_TIMEOUT,
    )

    response = boot(artifact_root, tmp_path, provider=provider)

    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "boot_timeout"
    assert response.error.details["diagnostic"] == "diagnostic"
    assert manifest.step_results["boot"].status == StepStatus.FAILED
    assert manifest.step_results["boot"].summary == "target boot timed out"


def test_target_boot_concurrent_calls_use_boot_lock(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    provider = FakeBootProvider(block=True)
    responses = []
    first = threading.Thread(target=lambda: responses.append(boot(artifact_root, tmp_path, provider=provider)))
    first.start()
    assert provider.started.wait(timeout=5)

    second = boot(artifact_root, tmp_path, provider=provider)
    provider.release.set()
    first.join(timeout=5)

    assert not first.is_alive()
    assert len(provider.executions) == 1
    assert len(provider.plans) == 1
    assert {response.ok for response in [*responses, second]} == {True, False}
    assert second.error is not None
    assert "previous boot is still recorded as running" in second.error.message


def test_target_boot_same_target_ref_across_runs_uses_target_lock(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path, run_id="run-one")
    create_run(tmp_path, run_id="run-two")
    record_build(artifact_root, run_id="run-one")
    record_build(artifact_root, run_id="run-two")
    provider = FakeBootProvider(block=True)
    responses = []
    first = threading.Thread(
        target=lambda: responses.append(boot(artifact_root, tmp_path, run_id="run-one", provider=provider))
    )
    first.start()
    assert provider.started.wait(timeout=5)

    second = boot(artifact_root, tmp_path, run_id="run-two", provider=provider)
    provider.release.set()
    first.join(timeout=5)

    assert not first.is_alive()
    assert len(provider.executions) == 1
    assert len(provider.plans) == 1
    assert second.ok is False
    assert second.error is not None
    assert "target domain is locked" in second.error.message


def test_target_boot_stale_running_is_failed_and_retried_only_when_locks_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(
        "run-abc123",
        StepResult(step_name="boot", status=StepStatus.RUNNING, summary="old running", details={"old": True}),
    )
    recorded: list[StepResult] = []
    original_record = ArtifactStore.record_step_result

    def capture_record(self: ArtifactStore, run_id: str, result: StepResult, *, replace_succeeded: bool = False):
        if result.step_name == "boot":
            recorded.append(result)
        return original_record(self, run_id, result, replace_succeeded=replace_succeeded)

    monkeypatch.setattr(ArtifactStore, "record_step_result", capture_record)

    response = boot(artifact_root, tmp_path)

    assert response.ok is True
    assert any(
        result.status == StepStatus.FAILED and result.details.get("stale_running_recovered") is True
        for result in recorded
    )


def test_target_boot_stale_running_is_not_marked_failed_when_target_lock_unavailable(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    store = ArtifactStore(artifact_root, create_root=False)
    old_running = StepResult(
        step_name="boot",
        status=StepStatus.RUNNING,
        summary="old running",
        details={"old": True},
    )
    store.record_step_result("run-abc123", old_running)

    with store.target_lock("kdive-dev"):
        response = boot(artifact_root, tmp_path)

    manifest = store.load_manifest("run-abc123")
    assert response.ok is False
    assert response.error is not None
    assert "target domain is locked" in response.error.message
    assert manifest.step_results["boot"] == old_running


def test_second_boot_with_new_kernel_args_opens_attempt_2(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    provider = FakeBootProvider()

    first = boot(artifact_root, tmp_path, provider=provider)
    assert first.ok is True

    second = boot(
        artifact_root,
        tmp_path,
        provider=provider,
        boot_overrides=BootOverrides(kernel_args=["dhash_entries=1"]),
    )

    assert second.ok is True
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert [attempt.attempt for attempt in manifest.boot_attempts] == [1, 2]
    assert "dhash_entries=1" in manifest.boot_attempts[-1].resolved_target_profile.kernel_args


class LeakyBootProvider(FakeBootProvider):
    def execute_boot(
        self,
        plan: Plan,
        *,
        force_reboot: bool = False,
        retrying_after_failure: bool = False,
    ) -> BootExecutionResult:
        result = super().execute_boot(
            plan,
            force_reboot=force_reboot,
            retrying_after_failure=retrying_after_failure,
        )
        return BootExecutionResult(
            status=result.status,
            summary=result.summary,
            details={**result.details, "leaked": "x=token=supersecret"},
            artifacts=result.artifacts,
            error_category=result.error_category,
            diagnostic=result.diagnostic,
        )


def test_boot_response_is_redacted(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    provider = LeakyBootProvider()

    response = boot(artifact_root, tmp_path, provider=provider)

    assert response.ok is True
    assert "supersecret" not in str(response.data)


def test_boot_rootfs_source_override_overlapping_sensitive_path_is_rejected(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    sensitive_dir = tmp_path / "secrets"
    sensitive_dir.mkdir()
    override_rootfs = sensitive_dir / "override.qcow2"
    override_rootfs.write_text("disk image", encoding="utf-8")

    response = boot(
        artifact_root,
        tmp_path,
        boot_overrides=BootOverrides(rootfs_source=str(override_rootfs)),
        sensitive_paths=[sensitive_dir],
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "sensitive" in response.error.message


def test_boot_applies_rootfs_field_overrides_to_resolved_profile(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    provider = FakeBootProvider()

    response = boot(
        artifact_root,
        tmp_path,
        provider=provider,
        boot_overrides=BootOverrides(rootfs=RootfsOverrides(mutability="mutable", ssh_user="debugger", ssh_port=2222)),
    )

    assert response.ok is True
    planned_rootfs = provider.plans[0]["rootfs_profile"]
    assert planned_rootfs.mutability == "mutable"
    assert planned_rootfs.ssh_user == "debugger"
    assert planned_rootfs.ssh_port == 2222


def test_boot_rootfs_source_override_allowed_without_sensitive_paths(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    override_rootfs = tmp_path / "elsewhere" / "override.qcow2"
    override_rootfs.parent.mkdir()
    override_rootfs.write_text("disk image", encoding="utf-8")

    response = boot(
        artifact_root,
        tmp_path,
        boot_overrides=BootOverrides(rootfs_source=str(override_rootfs)),
        sensitive_paths=[],
    )

    assert response.ok is True


def _booted_run_with_rootfs(tmp_path: Path, rootfs: RootfsProfile):
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    return target_boot_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=FakeBootProvider(),
        target_profiles={"local-qemu": target_profile()},
        rootfs_profiles={"minimal": rootfs},
    ), artifact_root


def test_boot_builder_missing_image_returns_configuration_error(tmp_path: Path) -> None:
    rootfs = RootfsProfile(
        name="minimal",
        source=str(tmp_path / "absent.qcow2"),
        source_kind="builder",
        mutability="copy_on_write",
        readiness_marker="ready",
    )
    response, artifact_root = _booted_run_with_rootfs(tmp_path, rootfs)
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert "just rootfs" in response.error.details["suggested_fix"]
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert manifest.step_results["boot"].status == StepStatus.FAILED


def test_boot_prebuilt_kind_returns_not_implemented(tmp_path: Path) -> None:
    image = tmp_path / "minimal.qcow2"
    image.write_text("qcow2\n", encoding="utf-8")
    rootfs = RootfsProfile(
        name="minimal",
        source=str(image),
        source_kind="prebuilt",
        mutability="read_only",
        readiness_marker="ready",
    )
    response, _ = _booted_run_with_rootfs(tmp_path, rootfs)
    assert response.ok is False
    assert response.error.category == ErrorCategory.NOT_IMPLEMENTED
    assert "#106" in response.error.message


def test_target_boot_frozen_override_yields_debug_next_action(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    debug_target = target_profile().model_copy(update={"debug_gdbstub": True})
    provider = FakeBootProvider(details={"console_status": "frozen"})

    response = boot(
        artifact_root,
        tmp_path,
        provider=provider,
        target=debug_target,
        boot_overrides=BootOverrides(wait_for_debugger=True),
    )

    assert response.ok is True
    assert response.data["console_status"] == "frozen"
    assert response.suggested_next_actions == ["debug.start_session"]
    assert provider.plans[-1]["target_profile"].wait_for_debugger is True


def test_target_boot_frozen_short_circuit_preserves_debug_next_action(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    debug_target = target_profile().model_copy(update={"debug_gdbstub": True})
    provider = FakeBootProvider(details={"console_status": "frozen"})

    first = boot(
        artifact_root,
        tmp_path,
        provider=provider,
        target=debug_target,
        boot_overrides=BootOverrides(wait_for_debugger=True),
    )
    # Re-invoke without force/override: short-circuits on the recorded SUCCEEDED frozen boot.
    second = boot(artifact_root, tmp_path, provider=provider, target=debug_target)

    assert first.suggested_next_actions == ["debug.start_session"]
    assert second.suggested_next_actions == ["debug.start_session"]
    assert len(provider.executions) == 1


def test_frozen_boot_stays_on_success_path_for_provenance_capture(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    debug_target = target_profile().model_copy(update={"debug_gdbstub": True})
    provider = FakeBootProvider(details={"console_status": "frozen"})

    boot(
        artifact_root,
        tmp_path,
        provider=provider,
        target=debug_target,
        boot_overrides=BootOverrides(wait_for_debugger=True),
    )

    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    boot_details = manifest.step_results["boot"].details
    # record_build records no build_id, so capture records the error variant -- but it RAN,
    # which proves the frozen boot stayed on the handler's SUCCEEDED path (server.py:1884).
    assert "kernel_provenance" in boot_details or "kernel_provenance_capture_error" in boot_details


def test_frozen_boot_publishes_admission_snapshot(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    debug_target = target_profile().model_copy(update={"debug_gdbstub": True})
    # Hold our own SnapshotStore reference -- AdmissionService keeps it private, so assert
    # on the store we constructed, not on the service.
    snapshots = SnapshotStore()
    admission = AdmissionService(snapshots)
    provider = FakeBootProvider(details={"console_status": "frozen"})

    response = boot(
        artifact_root,
        tmp_path,
        provider=provider,
        target=debug_target,
        boot_overrides=BootOverrides(wait_for_debugger=True),
        admission=admission,
    )

    assert response.ok is True
    # The published snapshot is what debug.start_session/run_tests resolve via _require_snapshot.
    target_key = TargetKey(provisioner="local-qemu", target_id="run-abc123")
    assert snapshots.get(target_key) is not None
