import threading
from dataclasses import dataclass
from pathlib import Path

import pytest

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import BootOverrides, RootfsProfile, TargetProfile
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus
from linux_debug_mcp.providers.libvirt_qemu import BootExecutionResult, ProviderBootError
from linux_debug_mcp.server import create_run_handler, target_boot_handler


@dataclass
class Plan:
    run_id: str
    domain_name: str
    boot_log_path: Path
    boot_plan_path: Path
    boot_summary_path: Path
    debug_gdbstub: bool = False
    gdbstub_endpoint: dict[str, object] | None = None
    nokaslr_source: str = "not_applicable"


class FakeBootProvider:
    name = "local-libvirt-qemu"

    def __init__(
        self,
        *,
        status: StepStatus = StepStatus.SUCCEEDED,
        summary: str = "target booted",
        error_category: ErrorCategory | None = None,
        block: bool = False,
        raise_on_plan: ProviderBootError | None = None,
        raise_on_execute: Exception | None = None,
    ) -> None:
        self.status = status
        self.summary = summary
        self.error_category = error_category
        self.block = block
        self.raise_on_plan = raise_on_plan
        self.raise_on_execute = raise_on_execute
        self.plans: list[dict[str, object]] = []
        self.executions: list[dict[str, object]] = []
        self.started = threading.Event()
        self.release = threading.Event()

    def plan_boot(
        self,
        *,
        run_id: str,
        run_dir: Path,
        kernel_image_path: Path,
        target_profile: TargetProfile,
        rootfs_profile: RootfsProfile,
        attempt: int = 1,
    ) -> Plan:
        if self.raise_on_plan is not None:
            raise self.raise_on_plan
        self.plans.append(
            {
                "run_id": run_id,
                "run_dir": run_dir,
                "kernel_image_path": kernel_image_path,
                "target_profile": target_profile,
                "rootfs_profile": rootfs_profile,
                "attempt": attempt,
            }
        )
        return Plan(
            run_id=run_id,
            domain_name=target_profile.target_ref or target_profile.name,
            boot_log_path=run_dir / "boot" / f"attempt-{attempt}" / "boot.log",
            boot_plan_path=run_dir / "boot" / f"attempt-{attempt}" / "boot-plan.json",
            boot_summary_path=run_dir / "boot" / f"attempt-{attempt}" / "boot-summary.json",
            debug_gdbstub=target_profile.debug_gdbstub,
            gdbstub_endpoint={"host": "127.0.0.1", "port": 1234} if target_profile.debug_gdbstub else None,
            nokaslr_source="provider_added" if target_profile.debug_gdbstub else "not_applicable",
        )

    def execute_boot(
        self,
        plan: Plan,
        *,
        force_reboot: bool = False,
        retrying_after_failure: bool = False,
    ) -> BootExecutionResult:
        self.executions.append(
            {
                "run_id": plan.run_id,
                "force_reboot": force_reboot,
                "retrying_after_failure": retrying_after_failure,
            }
        )
        self.started.set()
        if self.block:
            self.release.wait(timeout=5)
        if self.raise_on_execute is not None:
            raise self.raise_on_execute
        plan.boot_log_path.parent.mkdir(parents=True, exist_ok=True)
        plan.boot_log_path.write_text("boot log\n", encoding="utf-8")
        plan.boot_plan_path.parent.mkdir(parents=True, exist_ok=True)
        plan.boot_plan_path.write_text("{}\n", encoding="utf-8")
        plan.boot_summary_path.parent.mkdir(parents=True, exist_ok=True)
        plan.boot_summary_path.write_text("{}\n", encoding="utf-8")
        return BootExecutionResult(
            status=self.status,
            summary=self.summary,
            details={
                "domain": plan.domain_name,
                "provider_call": len(self.executions),
                "debug_boot": plan.debug_gdbstub,
                "gdbstub_endpoint": plan.gdbstub_endpoint,
                "nokaslr_source": plan.nokaslr_source,
            },
            artifacts=[ArtifactRef(path=str(plan.boot_log_path), kind="boot-log")],
            error_category=self.error_category,
            diagnostic="diagnostic" if self.status == StepStatus.FAILED else None,
        )


def make_source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "linux"
    source.mkdir(parents=True)
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    return source


def target_profile(
    *,
    name: str = "local-qemu",
    architecture: str = "x86_64",
    target_ref: str = "mcp-linux-debug-dev",
) -> TargetProfile:
    return TargetProfile(
        name=name,
        architecture=architecture,
        target_ref=target_ref,
        managed_domain=True,
        managed_domain_prefix="mcp-linux-debug-",
        libvirt_uri="qemu:///system",
    )


def rootfs_profile(tmp_path: Path, *, name: str = "minimal") -> RootfsProfile:
    rootfs = tmp_path / f"{name}.img"
    rootfs.write_text("rootfs\n", encoding="utf-8")
    return RootfsProfile(name=name, source=str(rootfs), mutability="read_only", readiness_marker="ready")


def create_run(
    tmp_path: Path,
    *,
    run_id: str = "run-abc123",
    target_profile_name: str = "local-qemu",
    rootfs_profile_name: str = "minimal",
) -> Path:
    source = make_source_tree(tmp_path / run_id)
    artifact_root = tmp_path / "runs"
    response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile=target_profile_name,
        rootfs_profile=rootfs_profile_name,
        run_id=run_id,
    )
    assert response.ok is True
    return artifact_root


def record_build(
    artifact_root: Path,
    run_id: str = "run-abc123",
    *,
    status: StepStatus = StepStatus.SUCCEEDED,
    architecture: str = "x86_64",
    include_kernel_image: bool = True,
) -> Path:
    build_dir = artifact_root / run_id / "build"
    kernel = build_dir / "arch" / "x86" / "boot" / "bzImage"
    kernel.parent.mkdir(parents=True, exist_ok=True)
    kernel.write_text("kernel\n", encoding="utf-8")
    artifacts = [ArtifactRef(path=str(kernel), kind="kernel-image")] if include_kernel_image else []
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        run_id,
        StepResult(
            step_name="build",
            status=status,
            summary="build result",
            artifacts=artifacts,
            details={"architecture": architecture, "output_path": str(build_dir)},
        ),
    )
    return kernel


def profiles(tmp_path: Path, *, target: TargetProfile | None = None) -> dict[str, dict[str, object]]:
    target = target or target_profile()
    rootfs = rootfs_profile(tmp_path)
    return {"target_profiles": {target.name: target}, "rootfs_profiles": {rootfs.name: rootfs}}


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

    response = target_boot_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
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
            details={"domain": "mcp-linux-debug-dev"},
        ),
    )

    with store.boot_lock("run-abc123"):
        response = boot(artifact_root, tmp_path, provider=provider)

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert response.error.details["domain"] == "mcp-linux-debug-dev"
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

    with store.target_lock("mcp-linux-debug-dev"):
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
