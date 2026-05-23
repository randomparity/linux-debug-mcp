from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from linux_debug_mcp.artifacts.manifest import RunManifest
from linux_debug_mcp.artifacts.store import ArtifactStore, ManifestStateError
from linux_debug_mcp.config import (
    BuildProfile,
    DebugProfile,
    RootfsProfile,
    TargetProfile,
    TestCommand,
    TestSuiteProfile,
)
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus, ToolResponse
from linux_debug_mcp.logging import configure_logging
from linux_debug_mcp.prereqs.checks import check_prerequisites
from linux_debug_mcp.providers.libvirt_qemu import LibvirtQemuProvider, ProviderBootError
from linux_debug_mcp.providers.local_kernel_build import LocalKernelBuildProvider
from linux_debug_mcp.providers.local_ssh_tests import LocalSshTestProvider
from linux_debug_mcp.providers.qemu_gdbstub import ProviderDebugError, QemuGdbstubProvider
from linux_debug_mcp.providers.registry import ProviderRegistry
from linux_debug_mcp.safety.paths import PathSafetyError, validate_source_path
from linux_debug_mcp.safety.redaction import Redactor

DEFAULT_ARTIFACT_ROOT = Path(".linux-debug-mcp/runs")
DEFAULT_BUILD_PROFILES = {
    "x86_64-default": BuildProfile(name="x86_64-default", architecture="x86_64"),
}
DEFAULT_TARGET_PROFILES = {
    "local-qemu": TargetProfile(
        name="local-qemu",
        architecture="x86_64",
        target_ref="mcp-linux-debug-dev",
        managed_domain=True,
        managed_domain_prefix="mcp-linux-debug-",
        libvirt_uri="qemu:///system",
    ),
}
DEFAULT_ROOTFS_PROFILES = {
    "minimal": RootfsProfile(
        name="minimal",
        source="/var/lib/linux-debug-mcp/rootfs/minimal.qcow2",
        mutability="read_only",
        readiness_marker="linux-debug-mcp-ready",
        ssh_host="127.0.0.1",
        ssh_port=22,
        ssh_user="root",
    ),
}
DEFAULT_TEST_SUITES = {
    "smoke-basic": TestSuiteProfile(
        name="smoke-basic",
        timeout_seconds=30,
        stop_on_failure=True,
        collect_dmesg=True,
        commands=[
            TestCommand(name="uname", argv=["uname", "-a"]),
            TestCommand(name="proc-version", argv=["test", "-r", "/proc/version"]),
            TestCommand(name="proc-cmdline", argv=["cat", "/proc/cmdline"]),
        ],
    )
}
DEFAULT_DEBUG_PROFILES = {
    "qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default"),
}
RUNNING_BUILD_MESSAGE = (
    "previous build is still recorded as running; inspect logs and create a new run or manually clean stale build state"
)
RUNNING_BOOT_MESSAGE = "previous boot is still recorded as running"
RUNNING_TESTS_MESSAGE = "previous test run is still recorded as running"


def _recorded_build_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.success(
        summary=result.summary,
        run_id=run_id,
        data=result.details,
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _running_build_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=RUNNING_BUILD_MESSAGE,
        run_id=run_id,
        details=result.details,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _build_profile_from_manifest(profile_name: str) -> BuildProfile:
    try:
        return DEFAULT_BUILD_PROFILES[profile_name]
    except KeyError as exc:
        raise ValueError(f"unknown build profile: {profile_name}") from exc


def _record_terminal_build_result(
    store: ArtifactStore,
    run_id: str,
    result: StepResult,
    *,
    attempts: int = 5,
    initial_delay_seconds: float = 0.01,
) -> None:
    delay_seconds = initial_delay_seconds
    for attempt in range(attempts):
        try:
            store.record_step_result(run_id, result)
            return
        except ManifestStateError as exc:
            if "manifest is locked" not in str(exc) or attempt == attempts - 1:
                raise
            time.sleep(delay_seconds)
            delay_seconds *= 2


def _recorded_boot_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.success(
        summary=result.summary,
        run_id=run_id,
        data=result.details,
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _recorded_test_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    redactor = Redactor()
    return ToolResponse.success(
        summary=redactor.redact_text(result.summary),
        run_id=run_id,
        data=redactor.redact_value(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.collect"],
    )


def _redacted_artifacts(artifacts: list[ArtifactRef], redactor: Redactor | None = None) -> list[ArtifactRef]:
    redactor = redactor or Redactor()
    return [
        ArtifactRef.model_validate(redactor.redact_value(artifact.model_dump(mode="json"))) for artifact in artifacts
    ]


def _recorded_collect_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    redactor = Redactor()
    return ToolResponse.success(
        summary=redactor.redact_text(result.summary),
        run_id=run_id,
        data=redactor.redact_value(result.details),
        artifacts=_redacted_artifacts(result.artifacts, redactor),
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _running_boot_response(*, run_id: str, result: StepResult, message: str = RUNNING_BOOT_MESSAGE) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=message,
        run_id=run_id,
        details=result.details,
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _running_tests_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=RUNNING_TESTS_MESSAGE,
        run_id=run_id,
        details=Redactor().redact_value(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _configuration_failure(*, run_id: str, message: str, details: dict[str, Any] | None = None) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
    )


def _find_kernel_image(build_result: StepResult) -> ArtifactRef | None:
    for artifact in build_result.artifacts:
        if artifact.kind == "kernel-image":
            return artifact
    return None


def _find_artifact(result: StepResult, kind: str) -> ArtifactRef | None:
    for artifact in result.artifacts:
        if artifact.kind == kind:
            return artifact
    return None


def _active_debug_session_from_result(result: StepResult) -> dict[str, Any] | None:
    if result.status != StepStatus.SUCCEEDED:
        return None
    if result.details.get("current_execution_state") == "ended":
        return None
    return result.details


def _debug_build_metadata(
    build_result: StepResult, *, kernel_image: ArtifactRef, vmlinux: ArtifactRef
) -> dict[str, Any]:
    return {
        **build_result.details,
        "kernel_image_path": str(kernel_image.path),
        "vmlinux_path": str(vmlinux.path),
    }


def _debug_boot_metadata(boot_result: StepResult, *, kernel_image: ArtifactRef) -> dict[str, Any]:
    return {
        **boot_result.details,
        "kernel_image_path": str(boot_result.details.get("kernel_image_path") or kernel_image.path),
    }


def _next_test_attempt(run_dir: Path) -> int:
    attempts = []
    tests_dir = run_dir / "tests"
    if tests_dir.exists():
        for path in tests_dir.glob("attempt-*"):
            try:
                attempts.append(int(path.name.removeprefix("attempt-")))
            except ValueError:
                continue
    return max(attempts, default=0) + 1


def _validate_adhoc_commands(commands: list[list[str]] | None) -> list[TestCommand]:
    validated: list[TestCommand] = []
    for index, argv in enumerate(commands or [], start=1):
        validated.append(TestCommand(name=f"adhoc-{index:03d}", argv=argv, required=True))
    return validated


def create_run_handler(
    *,
    artifact_root: Path,
    source_path: str,
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    run_id: str | None = None,
    debug_profile: str | None = None,
    test_suite: str | None = None,
) -> ToolResponse:
    try:
        resolved_source_path = validate_source_path(Path(source_path))
    except PathSafetyError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
            details={"source_path": source_path},
        )
    request = RunRequest(
        source_path=str(resolved_source_path),
        build_profile=build_profile,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        debug_profile=debug_profile,
        test_suite=test_suite,
        run_id=run_id,
    )
    try:
        store = ArtifactStore(artifact_root, source_paths=[resolved_source_path])
        manifest = store.create_run(request)
    except ManifestStateError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=str(exc),
            details={"artifact_root": str(artifact_root)},
        )
    manifest_path = artifact_root.expanduser().resolve() / manifest.run_id / "manifest.json"
    return ToolResponse.success(
        summary=f"created run {manifest.run_id}",
        run_id=manifest.run_id,
        data={"manifest": manifest.model_dump(mode="json"), "manifest_path": str(manifest_path)},
        artifacts=[ArtifactRef(path=str(manifest_path), kind="manifest")],
        suggested_next_actions=["kernel.build"],
    )


def get_manifest_handler(*, artifact_root: Path, run_id: str) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    return ToolResponse.success(
        summary=f"loaded manifest for {run_id}",
        run_id=run_id,
        data={"manifest": Redactor().redact_value(manifest.model_dump(mode="json"))},
        artifacts=[
            ArtifactRef(path=str(artifact_root.expanduser().resolve() / run_id / "manifest.json"), kind="manifest")
        ],
    )


def prerequisites_handler(
    *,
    artifact_root: Path,
    source_path: str | None,
    enable_libvirt_check: bool = False,
) -> ToolResponse:
    checks = check_prerequisites(
        artifact_root=artifact_root,
        source_path=Path(source_path) if source_path else None,
        enable_libvirt_check=enable_libvirt_check,
    )
    failed = [check for check in checks if check.status == "failed"]
    return ToolResponse.success(
        summary=f"{len(failed)} prerequisite checks failed",
        data={"checks": [check.model_dump(mode="json") for check in checks]},
        suggested_next_actions=["Fix failed checks", "kernel.create_run"],
    )


def list_providers_handler() -> ToolResponse:
    registry = ProviderRegistry.with_defaults()
    return ToolResponse.success(
        summary="listed provider capabilities",
        data={"providers": [provider.model_dump(mode="json") for provider in registry.list_capabilities()]},
    )


def kernel_build_handler(
    *,
    artifact_root: Path,
    run_id: str,
    build_profile: str | None = None,
    force_rebuild: bool = False,
    provider: LocalKernelBuildProvider | None = None,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                message=f"run not found: {run_id}",
                run_id=run_id,
            )
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    if force_rebuild:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="force_rebuild=true is not supported until rebuild cleanup policy is implemented",
            run_id=run_id,
        )
    requested_profile = build_profile or manifest.request.build_profile
    if requested_profile != manifest.request.build_profile:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="build_profile must match the immutable run manifest request",
            run_id=run_id,
            details={"requested_profile": requested_profile, "manifest_profile": manifest.request.build_profile},
        )
    existing = manifest.step_results.get("build")
    if existing and existing.status == StepStatus.SUCCEEDED:
        return _recorded_build_success_response(run_id=run_id, result=existing)
    if existing and existing.status == StepStatus.RUNNING:
        try:
            with store.build_lock(run_id):
                return _running_build_response(run_id=run_id, result=existing)
        except ManifestStateError as exc:
            return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    try:
        source_path = validate_source_path(Path(manifest.request.source_path))
        store = ArtifactStore(artifact_root, source_paths=[source_path], create_root=False)
        profile = _build_profile_from_manifest(requested_profile)
        provider = provider or LocalKernelBuildProvider()
        run_dir = store.run_dir(run_id)
        plan = provider.plan_build(source_path=source_path, output_path=run_dir / "build", profile=profile)
    except (PathSafetyError, ValueError, ManifestStateError) as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
            run_id=run_id,
        )
    log_path = store.run_dir(run_id) / "logs" / "build.log"
    summary_path = store.run_dir(run_id) / "summaries" / "build-summary.json"
    try:
        with store.build_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("build")
            if existing and existing.status == StepStatus.SUCCEEDED:
                return _recorded_build_success_response(run_id=run_id, result=existing)
            if existing and existing.status == StepStatus.RUNNING:
                return _running_build_response(run_id=run_id, result=existing)
            running = StepResult(
                step_name="build",
                status=StepStatus.RUNNING,
                summary="kernel build running",
                details={"argv": plan.argv, "log_path": str(log_path), "provider": provider.name},
                artifacts=[ArtifactRef(path=str(log_path), kind="build-log")],
            )
            store.record_step_result(run_id, running)
            try:
                execution = provider.execute_build(plan=plan, log_path=log_path, summary_path=summary_path)
            except Exception as exc:
                result = StepResult(
                    step_name="build",
                    status=StepStatus.FAILED,
                    summary="unexpected build provider failure",
                    artifacts=[ArtifactRef(path=str(log_path), kind="build-log")],
                    details={
                        "argv": plan.argv,
                        "log_path": str(log_path),
                        "provider": provider.name,
                        "exception_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )
                _record_terminal_build_result(store, run_id, result)
                return ToolResponse.failure(
                    category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                    message=result.summary,
                    run_id=run_id,
                    details=result.details,
                    artifacts=result.artifacts,
                    suggested_next_actions=["artifacts.get_manifest"],
                )
            result = StepResult(
                step_name="build",
                status=execution.status,
                summary=execution.summary,
                artifacts=execution.artifacts,
                details=execution.details,
            )
            _record_terminal_build_result(store, run_id, result)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    if execution.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=execution.summary,
            run_id=run_id,
            data=execution.details,
            artifacts=execution.artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    return ToolResponse.failure(
        category=execution.error_category or ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=execution.summary,
        run_id=run_id,
        details={**execution.details, "diagnostic": execution.diagnostic},
        artifacts=execution.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def target_boot_handler(
    *,
    artifact_root: Path,
    run_id: str,
    target_profile: str | None = None,
    rootfs_profile: str | None = None,
    force_reboot: bool = False,
    provider: LibvirtQemuProvider | None = None,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    default_libvirt_uri: str | None = None,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    requested_target_profile = target_profile or manifest.request.target_profile
    requested_rootfs_profile = rootfs_profile or manifest.request.rootfs_profile
    if requested_target_profile != manifest.request.target_profile:
        return _configuration_failure(
            run_id=run_id,
            message="target_profile must match the immutable run manifest request",
            details={
                "requested_profile": requested_target_profile,
                "manifest_profile": manifest.request.target_profile,
            },
        )
    if requested_rootfs_profile != manifest.request.rootfs_profile:
        return _configuration_failure(
            run_id=run_id,
            message="rootfs_profile must match the immutable run manifest request",
            details={
                "requested_profile": requested_rootfs_profile,
                "manifest_profile": manifest.request.rootfs_profile,
            },
        )

    target_profiles = target_profiles if target_profiles is not None else DEFAULT_TARGET_PROFILES
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    try:
        resolved_target_profile = target_profiles[requested_target_profile]
    except KeyError:
        return _configuration_failure(run_id=run_id, message=f"unknown target profile: {requested_target_profile}")
    try:
        resolved_rootfs_profile = rootfs_profiles[requested_rootfs_profile]
    except KeyError:
        return _configuration_failure(run_id=run_id, message=f"unknown rootfs profile: {requested_rootfs_profile}")
    if resolved_target_profile.libvirt_uri is None and default_libvirt_uri is not None:
        resolved_target_profile = resolved_target_profile.model_copy(update={"libvirt_uri": default_libvirt_uri})
    if resolved_target_profile.target_ref is None:
        return _configuration_failure(run_id=run_id, message="target profile target_ref is required")

    build_result = manifest.step_results.get("build")
    if build_result is None or build_result.status != StepStatus.SUCCEEDED:
        return _configuration_failure(run_id=run_id, message="target boot requires a succeeded build")
    kernel_image = _find_kernel_image(build_result)
    if kernel_image is None:
        return _configuration_failure(run_id=run_id, message="succeeded build did not record a kernel-image artifact")
    build_architecture = build_result.details.get("architecture")
    if build_architecture is not None and build_architecture != resolved_target_profile.architecture:
        return _configuration_failure(
            run_id=run_id,
            message="build architecture does not match target profile architecture",
            details={
                "build_architecture": build_architecture,
                "target_architecture": resolved_target_profile.architecture,
            },
        )

    existing = manifest.step_results.get("boot")
    if existing and existing.status == StepStatus.SUCCEEDED and not force_reboot:
        return _recorded_boot_success_response(run_id=run_id, result=existing)

    provider = provider or LibvirtQemuProvider()

    def execute_boot(*, plan: Any, retrying_after_failure: bool, replace_succeeded: bool) -> ToolResponse:
        plan_gdbstub_endpoint = getattr(plan, "gdbstub_endpoint", None)
        if plan_gdbstub_endpoint is not None and hasattr(plan_gdbstub_endpoint, "as_dict"):
            plan_gdbstub_endpoint = plan_gdbstub_endpoint.as_dict()
        running = StepResult(
            step_name="boot",
            status=StepStatus.RUNNING,
            summary="target boot running",
            details={
                "provider": provider.name,
                "domain": plan.domain_name,
                "target_profile": resolved_target_profile.name,
                "rootfs_profile": resolved_rootfs_profile.name,
                "kernel_image_path": str(kernel_image.path),
                "boot_log_path": str(plan.boot_log_path),
                "boot_plan_path": str(plan.boot_plan_path),
                "debug_boot": getattr(plan, "debug_gdbstub", False),
                "gdbstub_endpoint": plan_gdbstub_endpoint,
                "nokaslr_source": getattr(plan, "nokaslr_source", "not_applicable"),
            },
            artifacts=[ArtifactRef(path=str(plan.boot_log_path), kind="boot-log")],
        )
        store.record_step_result(run_id, running, replace_succeeded=replace_succeeded)
        try:
            execution = provider.execute_boot(
                plan,
                force_reboot=force_reboot,
                retrying_after_failure=retrying_after_failure,
            )
        except ProviderBootError as exc:
            failed = StepResult(
                step_name="boot",
                status=StepStatus.FAILED,
                summary=str(exc),
                artifacts=exc.artifacts,
                details=exc.details,
            )
            store.record_step_result(run_id, failed, replace_succeeded=replace_succeeded)
            return ToolResponse.failure(
                category=exc.category,
                message=str(exc),
                run_id=run_id,
                details=exc.details,
                artifacts=exc.artifacts,
                suggested_next_actions=["artifacts.get_manifest"],
            )
        except Exception as exc:
            failed = StepResult(
                step_name="boot",
                status=StepStatus.FAILED,
                summary="unexpected boot provider failure",
                artifacts=[ArtifactRef(path=str(plan.boot_log_path), kind="boot-log")],
                details={
                    "provider": provider.name,
                    "domain": plan.domain_name,
                    "exception_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
            store.record_step_result(run_id, failed, replace_succeeded=replace_succeeded)
            return ToolResponse.failure(
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                message=failed.summary,
                run_id=run_id,
                details=failed.details,
                artifacts=failed.artifacts,
                suggested_next_actions=["artifacts.get_manifest"],
            )
        terminal = StepResult(
            step_name="boot",
            status=execution.status,
            summary=execution.summary,
            artifacts=execution.artifacts,
            details={**execution.details, "kernel_image_path": str(kernel_image.path)},
        )
        store.record_step_result(run_id, terminal, replace_succeeded=replace_succeeded)
        if execution.status == StepStatus.SUCCEEDED:
            return ToolResponse.success(
                summary=execution.summary,
                run_id=run_id,
                data=terminal.details,
                artifacts=execution.artifacts,
                suggested_next_actions=["artifacts.get_manifest"],
            )
        return ToolResponse.failure(
            category=execution.error_category or ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=execution.summary,
            run_id=run_id,
            details={**execution.details, "diagnostic": execution.diagnostic},
            artifacts=execution.artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )

    try:
        with store.boot_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            locked_existing = locked_manifest.step_results.get("boot")
            if locked_existing and locked_existing.status == StepStatus.SUCCEEDED and not force_reboot:
                return _recorded_boot_success_response(run_id=run_id, result=locked_existing)
            retrying_after_failure = bool(locked_existing and locked_existing.status == StepStatus.FAILED)
            replace_succeeded = bool(locked_existing and locked_existing.status == StepStatus.SUCCEEDED)
            with store.target_lock(resolved_target_profile.target_ref):
                if locked_existing and locked_existing.status == StepStatus.RUNNING:
                    stale_failed = StepResult(
                        step_name="boot",
                        status=StepStatus.FAILED,
                        summary=locked_existing.summary,
                        artifacts=locked_existing.artifacts,
                        details={**locked_existing.details, "stale_running_recovered": True},
                    )
                    store.record_step_result(run_id, stale_failed)
                    retrying_after_failure = True
                try:
                    plan = provider.plan_boot(
                        run_id=run_id,
                        run_dir=store.run_dir(run_id),
                        kernel_image_path=Path(kernel_image.path),
                        target_profile=resolved_target_profile,
                        rootfs_profile=resolved_rootfs_profile,
                    )
                except ProviderBootError as exc:
                    failed = StepResult(
                        step_name="boot",
                        status=StepStatus.FAILED,
                        summary=str(exc),
                        artifacts=exc.artifacts,
                        details=exc.details,
                    )
                    store.record_step_result(run_id, failed, replace_succeeded=replace_succeeded or force_reboot)
                    return ToolResponse.failure(
                        category=exc.category,
                        message=str(exc),
                        run_id=run_id,
                        details=exc.details,
                        artifacts=exc.artifacts,
                        suggested_next_actions=["artifacts.get_manifest"],
                    )
                except (ManifestStateError, OSError, ValueError) as exc:
                    return _configuration_failure(run_id=run_id, message=str(exc))
                return execute_boot(
                    plan=plan,
                    retrying_after_failure=retrying_after_failure,
                    replace_succeeded=replace_succeeded or force_reboot,
                )
    except ManifestStateError as exc:
        if "boot is locked" in str(exc):
            try:
                refreshed = store.load_manifest(run_id).step_results.get("boot")
            except ManifestStateError:
                refreshed = None
            if refreshed and refreshed.status == StepStatus.RUNNING:
                return _running_boot_response(run_id=run_id, result=refreshed)
            if existing and existing.status == StepStatus.RUNNING:
                return _running_boot_response(run_id=run_id, result=existing)
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)


def target_run_tests_handler(
    *,
    artifact_root: Path,
    run_id: str,
    test_suite: str | None = None,
    commands: list[list[str]] | None = None,
    force_rerun: bool = False,
    provider: LocalSshTestProvider | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    test_suites: dict[str, TestSuiteProfile] | None = None,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    boot_result = manifest.step_results.get("boot")
    if boot_result is None or boot_result.status != StepStatus.SUCCEEDED:
        return _configuration_failure(run_id=run_id, message="target run tests requires a succeeded boot")

    try:
        adhoc_commands = _validate_adhoc_commands(commands)
    except ValueError as exc:
        return _configuration_failure(run_id=run_id, message=str(exc))

    requested_suite = test_suite or manifest.request.test_suite
    if manifest.request.test_suite is not None and requested_suite != manifest.request.test_suite:
        return _configuration_failure(
            run_id=run_id,
            message="test_suite must match the immutable run manifest request",
            details={"requested_suite": requested_suite, "manifest_suite": manifest.request.test_suite},
        )
    if requested_suite is None and not adhoc_commands:
        requested_suite = "smoke-basic"

    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    test_suites = test_suites if test_suites is not None else DEFAULT_TEST_SUITES
    try:
        resolved_rootfs_profile = rootfs_profiles[manifest.request.rootfs_profile]
    except KeyError:
        return _configuration_failure(
            run_id=run_id,
            message=f"unknown rootfs profile: {manifest.request.rootfs_profile}",
        )
    try:
        suite_profile = test_suites[requested_suite] if requested_suite is not None else None
    except KeyError:
        return _configuration_failure(run_id=run_id, message=f"unknown test suite: {requested_suite}")

    existing = manifest.step_results.get("run_tests")
    if existing and existing.status == StepStatus.SUCCEEDED and not force_rerun:
        return _recorded_test_success_response(run_id=run_id, result=existing)

    provider = provider or LocalSshTestProvider()
    try:
        with store.tests_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("run_tests")
            if existing and existing.status == StepStatus.SUCCEEDED and not force_rerun:
                return _recorded_test_success_response(run_id=run_id, result=existing)
            if existing and existing.status == StepStatus.RUNNING:
                stale_failed = StepResult(
                    step_name="run_tests",
                    status=StepStatus.FAILED,
                    summary=existing.summary,
                    artifacts=existing.artifacts,
                    details={**existing.details, "stale_running_recovered": True},
                )
                store.record_step_result(run_id, stale_failed)

            attempt = _next_test_attempt(store.run_dir(run_id))
            try:
                plan = provider.plan_tests(
                    run_id=run_id,
                    run_dir=store.run_dir(run_id),
                    rootfs_profile=resolved_rootfs_profile,
                    suite=suite_profile,
                    adhoc_commands=adhoc_commands,
                    attempt=attempt,
                )
            except ValueError as exc:
                return _configuration_failure(run_id=run_id, message=str(exc))
            running = StepResult(
                step_name="run_tests",
                status=StepStatus.RUNNING,
                summary="target tests running",
                details={
                    "provider": provider.name,
                    "suite": suite_profile.name if suite_profile is not None else "adhoc",
                    "attempt": attempt,
                },
            )
            store.record_step_result(run_id, running, replace_succeeded=force_rerun)
            try:
                execution = provider.execute_tests(plan)
            except Exception as exc:
                terminal = StepResult(
                    step_name="run_tests",
                    status=StepStatus.FAILED,
                    summary="unexpected test provider failure",
                    details={"provider": provider.name, "exception_type": type(exc).__name__, "error": str(exc)},
                )
                store.record_step_result(run_id, terminal, replace_succeeded=force_rerun)
                return ToolResponse.failure(
                    category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                    message=terminal.summary,
                    run_id=run_id,
                    details=Redactor().redact_value(terminal.details),
                    suggested_next_actions=["artifacts.collect"],
                )
            redactor = Redactor()
            safe_details = redactor.redact_value(execution.details)
            safe_summary = redactor.redact_text(execution.summary)
            safe_diagnostic = redactor.redact_text(execution.diagnostic or "")
            safe_artifacts = _redacted_artifacts(execution.artifacts, redactor)
            terminal = StepResult(
                step_name="run_tests",
                status=execution.status,
                summary=safe_summary,
                artifacts=safe_artifacts,
                details=safe_details,
            )
            store.record_step_result(run_id, terminal, replace_succeeded=force_rerun)
    except ManifestStateError as exc:
        if "tests are locked" in str(exc):
            try:
                refreshed = store.load_manifest(run_id).step_results.get("run_tests")
            except ManifestStateError:
                refreshed = None
            if refreshed and refreshed.status == StepStatus.RUNNING:
                return _running_tests_response(run_id=run_id, result=refreshed)
            if existing and existing.status == StepStatus.RUNNING:
                return _running_tests_response(run_id=run_id, result=existing)
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    if execution.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=safe_summary,
            run_id=run_id,
            data=safe_details,
            artifacts=safe_artifacts,
            suggested_next_actions=["artifacts.collect"],
        )
    return ToolResponse.failure(
        category=execution.error_category or ErrorCategory.TEST_FAILURE,
        message=safe_summary,
        run_id=run_id,
        details={
            **safe_details,
            "diagnostic": safe_diagnostic,
        },
        artifacts=safe_artifacts,
        suggested_next_actions=["artifacts.collect"],
    )


def debug_start_session_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_profile: str | None = None,
    new_session: bool = False,
    provider: QemuGdbstubProvider | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    build_result = manifest.step_results.get("build")
    if build_result is None or build_result.status != StepStatus.SUCCEEDED:
        return _configuration_failure(run_id=run_id, message="debug start session requires a succeeded build")
    boot_result = manifest.step_results.get("boot")
    if boot_result is None or boot_result.status != StepStatus.SUCCEEDED:
        return _configuration_failure(run_id=run_id, message="debug start session requires a succeeded boot")
    if boot_result.details.get("debug_boot") is not True:
        return _configuration_failure(run_id=run_id, message="debug start session requires a debug boot")
    vmlinux = _find_artifact(build_result, "vmlinux")
    if vmlinux is None:
        return _configuration_failure(run_id=run_id, message="succeeded build did not record a vmlinux artifact")
    kernel_image = _find_artifact(build_result, "kernel-image")
    if kernel_image is None:
        return _configuration_failure(run_id=run_id, message="succeeded build did not record a kernel-image artifact")
    gdbstub_endpoint = boot_result.details.get("gdbstub_endpoint")
    if not isinstance(gdbstub_endpoint, dict):
        return _configuration_failure(run_id=run_id, message="succeeded debug boot did not record a gdbstub endpoint")
    build_metadata = _debug_build_metadata(build_result, kernel_image=kernel_image, vmlinux=vmlinux)
    boot_metadata = _debug_boot_metadata(boot_result, kernel_image=kernel_image)

    requested_profile = debug_profile or manifest.request.debug_profile or "qemu-gdbstub-default"
    if (
        manifest.request.debug_profile is not None
        and debug_profile is not None
        and debug_profile != manifest.request.debug_profile
    ):
        return _configuration_failure(
            run_id=run_id,
            message="debug_profile must match the immutable run manifest request",
            details={"requested_profile": debug_profile, "manifest_profile": manifest.request.debug_profile},
        )
    profiles = debug_profiles if debug_profiles is not None else DEFAULT_DEBUG_PROFILES
    try:
        resolved_debug_profile = profiles[requested_profile]
    except KeyError:
        return _configuration_failure(run_id=run_id, message=f"unknown debug profile: {requested_profile}")

    provider = provider or QemuGdbstubProvider()
    redactor = Redactor()
    try:
        with store.debug_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("debug")
            if existing and not new_session:
                active_session = _active_debug_session_from_result(existing)
                if active_session is not None:
                    return ToolResponse.success(
                        summary=redactor.redact_text(existing.summary),
                        run_id=run_id,
                        data=redactor.redact_value(active_session),
                        artifacts=_redacted_artifacts(existing.artifacts, redactor),
                        suggested_next_actions=["debug.interrupt", "debug.read_registers", "artifacts.get_manifest"],
                    )
            try:
                result = provider.start_session(
                    run_id=run_id,
                    run_dir=store.run_dir(run_id),
                    vmlinux_path=Path(vmlinux.path),
                    gdbstub_endpoint=gdbstub_endpoint,
                    debug_profile=resolved_debug_profile,
                    build_metadata=build_metadata,
                    boot_metadata=boot_metadata,
                )
            except ProviderDebugError as exc:
                failed = StepResult(
                    step_name="debug",
                    status=StepStatus.FAILED,
                    summary=str(exc),
                    artifacts=exc.artifacts,
                    details=exc.details,
                )
                store.record_step_result(run_id, failed, replace_succeeded=new_session)
                return ToolResponse.failure(
                    category=exc.category,
                    message=redactor.redact_text(str(exc)),
                    run_id=run_id,
                    details=redactor.redact_value(exc.details),
                    artifacts=_redacted_artifacts(exc.artifacts, redactor),
                    suggested_next_actions=["artifacts.get_manifest"],
                )
            details = {
                "debug_session_id": result.session.session_id,
                "session_path": str(store.run_dir(run_id) / "debug" / "sessions" / f"{result.session.session_id}.json"),
                "current_execution_state": result.session.current_execution_state,
                "gdbstub_endpoint": result.session.gdbstub_endpoint,
                "transcript_path": result.session.transcript_path,
                "command_metadata_path": result.session.command_metadata_path,
                "latest_summary_path": result.session.latest_summary_path,
                "symbol_identity_validation": result.session.symbol_identity_validation,
            }
            terminal = StepResult(
                step_name="debug",
                status=result.status,
                summary=result.summary,
                artifacts=result.artifacts,
                details=details,
            )
            store.record_step_result(run_id, terminal, replace_succeeded=new_session)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    safe_details = redactor.redact_value(details)
    safe_artifacts = _redacted_artifacts(result.artifacts, redactor)
    safe_summary = redactor.redact_text(result.summary)
    if result.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=safe_summary,
            run_id=run_id,
            data=safe_details,
            artifacts=safe_artifacts,
            suggested_next_actions=["debug.interrupt", "debug.read_registers", "artifacts.get_manifest"],
        )
    return ToolResponse.failure(
        category=result.error_category or ErrorCategory.DEBUG_ATTACH_FAILURE,
        message=safe_summary,
        run_id=run_id,
        details=safe_details,
        artifacts=safe_artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _bundle_for_manifest(
    *,
    manifest: RunManifest,
    run_dir: Path,
    bundle_path: Path,
) -> tuple[dict[str, Any], list[ArtifactRef], list[dict[str, Any]], list[dict[str, Any]]]:
    required_kinds_by_step = {
        "build": {"build-log", "kernel-config", "kernel-image"},
        "boot": {"domain-xml", "boot-plan", "console-log", "boot-log"},
        "run_tests": {"test-summary"},
    }
    optional_kinds_by_step = {"build": {"vmlinux"}}
    grouped: dict[str, list[dict[str, Any]]] = {}
    missing_required: list[dict[str, Any]] = []
    missing_optional: list[dict[str, Any]] = []
    collected_refs: list[ArtifactRef] = []
    for step in manifest.steps:
        result = manifest.step_results.get(step.name)
        grouped[step.name] = []
        if result is None:
            continue
        present_kinds = {artifact.kind for artifact in result.artifacts}
        if result.status == StepStatus.SUCCEEDED:
            for kind in sorted(required_kinds_by_step.get(step.name, set()) - present_kinds):
                missing_required.append(
                    {"step": step.name, "kind": kind, "reason": "required artifact kind was not recorded"}
                )
            for kind in sorted(optional_kinds_by_step.get(step.name, set()) - present_kinds):
                missing_optional.append(
                    {"step": step.name, "kind": kind, "reason": "optional artifact kind was not recorded"}
                )
        for artifact in result.artifacts:
            exists = Path(artifact.path).is_file()
            item = {**artifact.model_dump(mode="json"), "exists": exists}
            grouped[step.name].append(item)
            if exists:
                collected_refs.append(artifact)
            elif result.status == StepStatus.SUCCEEDED and artifact.kind not in optional_kinds_by_step.get(
                step.name, set()
            ):
                missing_required.append({"step": step.name, "artifact": artifact.model_dump(mode="json")})
            else:
                missing_optional.append({"step": step.name, "artifact": artifact.model_dump(mode="json")})
    bundle_ref = ArtifactRef(path=str(bundle_path), kind="artifact-bundle")
    bundle = {
        "run_id": manifest.run_id,
        "run_dir": str(run_dir),
        "collected_at": datetime.now(UTC).isoformat(),
        "selected_profiles": manifest.request.model_dump(mode="json"),
        "steps": {step.name: step.status for step in manifest.steps},
        "summaries": {
            name: {"status": result.status, "summary": result.summary} for name, result in manifest.step_results.items()
        },
        "artifacts_by_step": grouped,
        "missing_expected_artifacts": missing_required,
        "missing_optional_artifacts": missing_optional,
        "cleanup_state": manifest.cleanup_state,
        "rollup": {
            "ok": not missing_required,
            "missing_required": len(missing_required),
            "missing_optional": len(missing_optional),
        },
    }
    return bundle, [*collected_refs, bundle_ref], missing_required, missing_optional


def artifacts_collect_handler(
    *,
    artifact_root: Path,
    run_id: str,
    force_recollect: bool = False,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    existing = manifest.step_results.get("collect_artifacts")
    if existing and existing.status == StepStatus.SUCCEEDED and not force_recollect:
        return _recorded_collect_success_response(run_id=run_id, result=existing)
    try:
        with store.collect_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("collect_artifacts")
            if existing and existing.status == StepStatus.SUCCEEDED and not force_recollect:
                return _recorded_collect_success_response(run_id=run_id, result=existing)
            bundle_path = store.run_dir(run_id) / "summaries" / "artifact-bundle.json"
            bundle, artifacts, missing_required, missing_optional = _bundle_for_manifest(
                manifest=locked_manifest,
                run_dir=store.run_dir(run_id),
                bundle_path=bundle_path,
            )
            bundle_path.parent.mkdir(parents=True, exist_ok=True)
            bundle_path.write_text(
                json.dumps(Redactor().redact_value(bundle), indent=2, default=str),
                encoding="utf-8",
            )
            status = StepStatus.FAILED if missing_required else StepStatus.SUCCEEDED
            result = StepResult(
                step_name="collect_artifacts",
                status=status,
                summary=(
                    "artifact collection succeeded"
                    if status == StepStatus.SUCCEEDED
                    else "artifact collection found missing required artifacts"
                ),
                artifacts=artifacts,
                details={"bundle": bundle, "rollup": bundle["rollup"]},
            )
            store.record_step_result(run_id, result, replace_succeeded=force_recollect)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    redactor = Redactor()
    safe_bundle = redactor.redact_value(bundle)
    safe_artifacts = _redacted_artifacts(artifacts, redactor)
    if missing_required:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=redactor.redact_text(result.summary),
            run_id=run_id,
            details={
                "bundle": safe_bundle,
                "rollup": safe_bundle["rollup"],
                "missing_required": redactor.redact_value(missing_required),
                "missing_optional": redactor.redact_value(missing_optional),
            },
            artifacts=safe_artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    return ToolResponse.success(
        summary=redactor.redact_text(result.summary),
        run_id=run_id,
        data={"bundle": safe_bundle, "rollup": safe_bundle["rollup"]},
        artifacts=safe_artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _workflow_failure_response(
    *,
    run_id: str | None,
    failing_step: str,
    latest_successful_step: str | None,
    response: ToolResponse,
    collect_response: ToolResponse | None,
) -> ToolResponse:
    details = {
        "failing_step": failing_step,
        "latest_successful_step": latest_successful_step,
        "failed_response": response.model_dump(mode="json"),
        "collect_response": collect_response.model_dump(mode="json") if collect_response else None,
    }
    category = response.error.category if response.error else ErrorCategory.INFRASTRUCTURE_FAILURE
    message = response.error.message if response.error else response.summary or f"{failing_step} failed"
    return ToolResponse.failure(
        category=category,
        message=message,
        run_id=run_id,
        details=details,
        artifacts=[*(response.artifacts or []), *((collect_response.artifacts if collect_response else []) or [])],
        suggested_next_actions=["artifacts.get_manifest", "Inspect artifact bundle"],
    )


def workflow_build_boot_test_handler(
    *,
    artifact_root: Path,
    source_path: str,
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    run_id: str | None = None,
    test_suite: str | None = None,
    commands: list[list[str]] | None = None,
    force_rebuild: bool = False,
    force_reboot: bool = False,
    force_rerun_tests: bool = False,
    force_recollect: bool = False,
) -> ToolResponse:
    if run_id is not None:
        try:
            store = ArtifactStore(artifact_root, create_root=False)
            manifest_path = store.run_dir(run_id) / "manifest.json"
            if manifest_path.is_file():
                manifest = store.load_manifest(run_id)
                resolved_test_suite = test_suite if test_suite is not None else manifest.request.test_suite
                try:
                    resolved_source_path = str(validate_source_path(Path(source_path)))
                except PathSafetyError as exc:
                    return ToolResponse.failure(
                        category=ErrorCategory.CONFIGURATION_ERROR,
                        message=str(exc),
                        run_id=run_id,
                        details={"source_path": source_path},
                    )
                expected = {
                    "source_path": resolved_source_path,
                    "build_profile": build_profile,
                    "target_profile": target_profile,
                    "rootfs_profile": rootfs_profile,
                    "test_suite": resolved_test_suite,
                }
                actual = {
                    "source_path": manifest.request.source_path,
                    "build_profile": manifest.request.build_profile,
                    "target_profile": manifest.request.target_profile,
                    "rootfs_profile": manifest.request.rootfs_profile,
                    "test_suite": manifest.request.test_suite,
                }
                mismatches = {
                    key: {"requested": expected[key], "manifest": actual[key]}
                    for key in expected
                    if expected[key] != actual[key]
                }
                if mismatches:
                    return ToolResponse.failure(
                        category=ErrorCategory.CONFIGURATION_ERROR,
                        message="immutable run manifest request mismatch",
                        run_id=run_id,
                        details={"mismatches": mismatches},
                    )
                test_suite = resolved_test_suite
        except ManifestStateError as exc:
            return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    if run_id is None or not (artifact_root / run_id / "manifest.json").is_file():
        create_response = create_run_handler(
            artifact_root=artifact_root,
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            test_suite=test_suite,
        )
        if not create_response.ok:
            return create_response
        run_id = create_response.run_id

    build_response = kernel_build_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        build_profile=build_profile,
        force_rebuild=force_rebuild,
    )
    if not build_response.ok:
        collect_response = artifacts_collect_handler(
            artifact_root=artifact_root,
            run_id=run_id,
            force_recollect=force_recollect,
        )
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="build",
            latest_successful_step=None,
            response=build_response,
            collect_response=collect_response,
        )

    boot_response = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        force_reboot=force_reboot,
    )
    if not boot_response.ok:
        collect_response = artifacts_collect_handler(
            artifact_root=artifact_root,
            run_id=run_id,
            force_recollect=force_recollect,
        )
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="boot",
            latest_successful_step="build",
            response=boot_response,
            collect_response=collect_response,
        )

    test_response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        test_suite=test_suite,
        commands=commands,
        force_rerun=force_rerun_tests,
    )
    collect_response = artifacts_collect_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        force_recollect=force_recollect,
    )
    if not test_response.ok:
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="run_tests",
            latest_successful_step="boot",
            response=test_response,
            collect_response=collect_response,
        )
    if not collect_response.ok:
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="collect_artifacts",
            latest_successful_step="run_tests",
            response=collect_response,
            collect_response=collect_response,
        )
    return ToolResponse.success(
        summary="build, boot, test workflow succeeded",
        run_id=run_id,
        data={
            "steps": {
                "build": build_response.model_dump(mode="json"),
                "boot": boot_response.model_dump(mode="json"),
                "run_tests": test_response.model_dump(mode="json"),
                "collect_artifacts": collect_response.model_dump(mode="json"),
            },
            "latest_successful_step": "collect_artifacts",
            "artifact_bundle": next(
                (
                    artifact.model_dump(mode="json")
                    for artifact in collect_response.artifacts
                    if artifact.kind == "artifact-bundle"
                ),
                None,
            ),
        },
        artifacts=collect_response.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def not_implemented_handler(tool_name: str, *, run_id: str | None = None) -> ToolResponse:
    sprint_by_prefix = {
        "kernel.build": "Sprint 1",
        "target.boot": "Sprint 2",
        "target.run_tests": "Sprint 3",
        "artifacts.collect": "Sprint 3",
        "workflow.build_boot_test": "Sprint 3",
        "workflow.build_boot_debug": "Sprint 4",
        "debug.": "Sprint 4",
    }
    sprint = "a later sprint"
    for prefix, value in sprint_by_prefix.items():
        if tool_name.startswith(prefix):
            sprint = value
            break
    return ToolResponse.failure(
        category=ErrorCategory.NOT_IMPLEMENTED,
        message=f"{tool_name} is implemented in {sprint}",
        run_id=run_id,
        details={"tool": tool_name, "sprint": sprint},
        suggested_next_actions=["Use host.check_prerequisites", "Use kernel.create_run"],
    )


def create_app() -> FastMCP:
    app = FastMCP("linux-debug-mcp")

    @app.tool(name="host.check_prerequisites")
    def host_check_prerequisites(
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        source_path: str | None = None,
        enable_libvirt_check: bool = False,
    ) -> dict[str, Any]:
        return prerequisites_handler(
            artifact_root=Path(artifact_root),
            source_path=source_path,
            enable_libvirt_check=enable_libvirt_check,
        ).model_dump(mode="json")

    @app.tool(name="kernel.create_run")
    def kernel_create_run(
        source_path: str,
        build_profile: str,
        target_profile: str,
        rootfs_profile: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        run_id: str | None = None,
        debug_profile: str | None = None,
        test_suite: str | None = None,
    ) -> dict[str, Any]:
        return create_run_handler(
            artifact_root=Path(artifact_root),
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            debug_profile=debug_profile,
            test_suite=test_suite,
        ).model_dump(mode="json")

    @app.tool(name="providers.list")
    def providers_list() -> dict[str, Any]:
        return list_providers_handler().model_dump(mode="json")

    @app.tool(name="artifacts.get_manifest")
    def artifacts_get_manifest(run_id: str, artifact_root: str = str(DEFAULT_ARTIFACT_ROOT)) -> dict[str, Any]:
        return get_manifest_handler(artifact_root=Path(artifact_root), run_id=run_id).model_dump(mode="json")

    @app.tool(name="kernel.build")
    def kernel_build(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        build_profile: str | None = None,
        force_rebuild: bool = False,
    ) -> dict[str, Any]:
        return kernel_build_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            build_profile=build_profile,
            force_rebuild=force_rebuild,
        ).model_dump(mode="json")

    @app.tool(name="target.boot")
    def target_boot(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
        force_reboot: bool = False,
    ) -> dict[str, Any]:
        return target_boot_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            force_reboot=force_reboot,
        ).model_dump(mode="json")

    @app.tool(name="target.run_tests")
    def target_run_tests(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        test_suite: str | None = None,
        commands: list[list[str]] | None = None,
        force_rerun: bool = False,
    ) -> dict[str, Any]:
        return target_run_tests_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            test_suite=test_suite,
            commands=commands,
            force_rerun=force_rerun,
        ).model_dump(mode="json")

    @app.tool(name="artifacts.collect")
    def artifacts_collect(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        force_recollect: bool = False,
    ) -> dict[str, Any]:
        return artifacts_collect_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            force_recollect=force_recollect,
        ).model_dump(mode="json")

    @app.tool(name="debug.start_session")
    def debug_start_session(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_profile: str | None = None,
        new_session: bool = False,
    ) -> dict[str, Any]:
        return debug_start_session_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_profile=debug_profile,
            new_session=new_session,
        ).model_dump(mode="json")

    @app.tool(name="workflow.build_boot_test")
    def workflow_build_boot_test(
        source_path: str,
        build_profile: str,
        target_profile: str,
        rootfs_profile: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        run_id: str | None = None,
        test_suite: str | None = None,
        commands: list[list[str]] | None = None,
        force_rebuild: bool = False,
        force_reboot: bool = False,
        force_rerun_tests: bool = False,
        force_recollect: bool = False,
    ) -> dict[str, Any]:
        return workflow_build_boot_test_handler(
            artifact_root=Path(artifact_root),
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            test_suite=test_suite,
            commands=commands,
            force_rebuild=force_rebuild,
            force_reboot=force_reboot,
            force_rerun_tests=force_rerun_tests,
            force_recollect=force_recollect,
        ).model_dump(mode="json")

    def make_stub(bound_tool_name: str):
        def stub(run_id: str | None = None) -> dict[str, Any]:
            return not_implemented_handler(bound_tool_name, run_id=run_id).model_dump(mode="json")

        return stub

    for tool_name in [
        "workflow.build_boot_debug",
        "debug.interrupt",
        "debug.continue",
        "debug.set_breakpoint",
        "debug.clear_breakpoint",
        "debug.list_breakpoints",
        "debug.read_registers",
        "debug.read_symbol",
        "debug.read_memory",
        "debug.evaluate",
        "debug.end_session",
    ]:
        app.tool(name=tool_name)(make_stub(tool_name))

    return app


def main() -> None:
    configure_logging()
    create_app().run()
