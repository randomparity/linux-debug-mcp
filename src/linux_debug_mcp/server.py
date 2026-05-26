from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from linux_debug_mcp.artifacts.manifest import BootAttempt, RunManifest
from linux_debug_mcp.artifacts.store import ArtifactStore, ManifestStateError
from linux_debug_mcp.config import (
    SPRINT_4_DEBUG_OPERATIONS,
    BootOverrides,
    BuildOverrides,
    BuildProfile,
    DebugProfile,
    RootfsProfile,
    TargetProfile,
    TestCommand,
    TestSuiteProfile,
    merge_kernel_args,
)
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus, ToolResponse
from linux_debug_mcp.logging import configure_logging
from linux_debug_mcp.prereqs.checks import check_prerequisites
from linux_debug_mcp.providers.contracts import (
    ConsoleReadRequest,
    ConsoleSessionRequest,
    ConsoleWriteRequest,
    HardwareControlRequest,
    ProviderRequest,
    ProvisioningRequest,
    RealBootRequest,
    RemoteArtifactSyncRequest,
    RemoteBuildRequest,
    ReservationReleaseRequest,
    ReservationRequest,
    ReserveProvisionBootRequest,
)
from linux_debug_mcp.providers.libvirt_qemu import LibvirtQemuProvider, ProviderBootError
from linux_debug_mcp.providers.local_kernel_build import LocalKernelBuildProvider
from linux_debug_mcp.providers.local_ssh_tests import LocalSshTestProvider
from linux_debug_mcp.providers.qemu_gdbstub import (
    DebugProviderResult,
    DebugSession,
    ProviderDebugError,
    QemuGdbstubProvider,
)
from linux_debug_mcp.providers.registry import ProviderRegistry
from linux_debug_mcp.providers.stubs import (
    future_not_implemented_response,
    select_future_provider,
)
from linux_debug_mcp.safety.paths import PathSafetyError, validate_rootfs_source, validate_source_path
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
    "local-qemu-debug": TargetProfile(
        name="local-qemu-debug",
        architecture="x86_64",
        target_ref="mcp-linux-debug-dev-debug",
        managed_domain=True,
        managed_domain_prefix="mcp-linux-debug-",
        libvirt_uri="qemu:///system",
        debug_gdbstub=True,
        gdbstub_endpoint="127.0.0.1:1234",
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
DEBUG_METHOD_OPERATIONS = {
    "read_registers": "debug.read_registers",
    "read_symbol": "debug.read_symbol",
    "read_memory": "debug.read_memory",
    "evaluate": "debug.evaluate",
    "set_breakpoint": "debug.set_breakpoint",
    "clear_breakpoint": "debug.clear_breakpoint",
    "list_breakpoints": "debug.list_breakpoints",
    "continue_execution": "debug.continue",
    "interrupt": "debug.interrupt",
    "end_session": "debug.end_session",
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


def _build_profile_from_manifest(manifest: RunManifest) -> BuildProfile:
    if manifest.resolved_build_profile is not None:
        return manifest.resolved_build_profile
    profile_name = manifest.request.build_profile
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


def _redacted_boot_data(data: dict[str, Any]) -> dict[str, Any]:
    return Redactor().redact_value(data)


def _recorded_boot_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.success(
        summary=result.summary,
        run_id=run_id,
        data=_redacted_boot_data(result.details),
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
        details=_redacted_boot_data(result.details),
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


def _debug_session_details_from_result(result: StepResult, *, allow_ended: bool = False) -> dict[str, Any] | None:
    if result.status != StepStatus.SUCCEEDED:
        return None
    if not allow_ended and result.details.get("current_execution_state") == "ended":
        return None
    return result.details


def _debug_session_manifest_details(*, store: ArtifactStore, run_id: str, session: DebugSession) -> dict[str, Any]:
    details: dict[str, Any] = {
        "debug_session_id": session.session_id,
        "session_path": str(store.run_dir(run_id) / "debug" / "sessions" / f"{session.session_id}.json"),
        "current_execution_state": session.current_execution_state,
        "gdbstub_endpoint": session.gdbstub_endpoint,
        "transcript_path": session.transcript_path,
        "command_metadata_path": session.command_metadata_path,
        "latest_summary_path": session.latest_summary_path,
        "symbol_identity_validation": session.symbol_identity_validation,
        "breakpoints": session.breakpoints,
        "controller_mode": session.controller_mode,
        "active_controller_pid": session.active_controller_pid,
        "controller_last_observed_state": session.controller_last_observed_state,
    }
    if session.ended_at is not None:
        details["ended_at"] = session.ended_at
    return details


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


def _ensure_debug_operation_enabled(profile: DebugProfile, operation: str) -> None:
    if operation not in set(SPRINT_4_DEBUG_OPERATIONS):
        raise ProviderDebugError(
            "unsupported debug operation",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"operation": operation},
        )
    if operation not in profile.enabled_operations:
        raise ProviderDebugError(
            "debug operation is disabled by selected profile",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"debug_profile": profile.name, "operation": operation},
        )


def _resolve_debug_profile(
    *,
    profile_name: str,
    debug_profiles: dict[str, DebugProfile] | None,
) -> DebugProfile:
    profiles = debug_profiles if debug_profiles is not None else DEFAULT_DEBUG_PROFILES
    try:
        return profiles[profile_name]
    except KeyError as exc:
        raise ProviderDebugError(
            "unknown debug profile",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"debug_profile": profile_name},
        ) from exc


def _require_run_debug_path(path: Path, *, run_dir: Path, description: str) -> Path:
    try:
        resolved = path.expanduser().resolve()
        debug_dir = (run_dir / "debug").expanduser().resolve()
    except OSError as exc:
        raise ProviderDebugError(
            f"{description} is invalid",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"path": str(path), "error": str(exc)},
        ) from exc
    if not resolved.is_relative_to(debug_dir):
        raise ProviderDebugError(
            f"{description} must be inside the run debug directory",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"path": str(path), "debug_dir": str(debug_dir)},
        )
    return resolved


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


def _resolve_initial_profiles(
    *,
    source_path: Path,
    sensitive_paths: list[Path],
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    build_overrides: BuildOverrides | None,
    boot_overrides: BootOverrides | None,
) -> tuple[BuildProfile, TargetProfile, RootfsProfile]:
    base_build = DEFAULT_BUILD_PROFILES[build_profile]
    base_target = DEFAULT_TARGET_PROFILES[target_profile]
    base_rootfs = DEFAULT_ROOTFS_PROFILES[rootfs_profile]

    resolved_build = base_build
    if build_overrides is not None and build_overrides.make_variables:
        resolved_build = base_build.model_copy(
            update={"make_variables": {**base_build.make_variables, **build_overrides.make_variables}}
        )

    resolved_target = base_target
    resolved_rootfs = base_rootfs
    if boot_overrides is not None:
        if boot_overrides.kernel_args:
            resolved_target = base_target.model_copy(
                update={"kernel_args": merge_kernel_args(base_target.kernel_args, boot_overrides.kernel_args)}
            )
        if boot_overrides.rootfs_source is not None:
            validated = validate_rootfs_source(
                Path(boot_overrides.rootfs_source),
                source_paths=[source_path],
                sensitive_paths=sensitive_paths,
            )
            resolved_rootfs = base_rootfs.model_copy(update={"source": str(validated)})
    return resolved_build, resolved_target, resolved_rootfs


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
    build_overrides: BuildOverrides | None = None,
    boot_overrides: BootOverrides | None = None,
) -> ToolResponse:
    try:
        resolved_source_path = validate_source_path(Path(source_path))
    except PathSafetyError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
            details={"source_path": source_path},
        )
    for name, mapping in (
        (build_profile, DEFAULT_BUILD_PROFILES),
        (target_profile, DEFAULT_TARGET_PROFILES),
        (rootfs_profile, DEFAULT_ROOTFS_PROFILES),
    ):
        if name not in mapping:
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                message=f"unknown profile: {name}",
            )
    try:
        resolved_build, _resolved_target, _resolved_rootfs = _resolve_initial_profiles(
            source_path=Path(resolved_source_path),
            sensitive_paths=[],
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            build_overrides=build_overrides,
            boot_overrides=boot_overrides,
        )
    except (PathSafetyError, ValueError) as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
        )
    request = RunRequest(
        source_path=str(resolved_source_path),
        build_profile=build_profile,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        debug_profile=debug_profile,
        test_suite=test_suite,
        run_id=run_id,
        build_overrides=build_overrides,
        boot_overrides=boot_overrides,
    )
    try:
        store = ArtifactStore(artifact_root, source_paths=[resolved_source_path])
        manifest = store.create_run(request, resolved_build_profile=resolved_build)
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
    providers = []
    for provider in registry.list_capabilities():
        provider_payload = provider.model_dump(mode="json")
        plugin_metadata = registry.provider_plugin_metadata(provider.provider_name)
        if plugin_metadata is not None:
            provider_payload["plugin"] = plugin_metadata.model_dump(mode="json")
            provider_payload["documentation_paths"] = list(plugin_metadata.documentation_paths)
        providers.append(provider_payload)
    return ToolResponse.success(
        summary="listed provider capabilities",
        data={"providers": providers},
    )


def _validation_error_details(exc: ValidationError) -> dict[str, Any]:
    return {
        "validation_errors": [
            {
                "field": ".".join(str(part) for part in error.get("loc", ())),
                "type": error.get("type", "validation_error"),
            }
            for error in exc.errors(include_input=False)
        ]
    }


def _future_stub_handler(
    *,
    contract: type[ProviderRequest],
    operation: str,
    payload: dict[str, Any],
    registry: ProviderRegistry | None = None,
) -> ToolResponse:
    redactor = Redactor()
    try:
        request = contract(**payload)
    except ValidationError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="future provider request failed validation",
            details=redactor.redact_value(_validation_error_details(exc)),
            suggested_next_actions=["providers.list"],
        )

    registry = registry or ProviderRegistry.with_defaults()
    provider = select_future_provider(
        registry,
        operation=operation,
        architecture=request.architecture,
        provider_name=request.provider_name,
    )
    if isinstance(provider, ToolResponse):
        return provider

    plugin_metadata = registry.provider_plugin_metadata(provider.provider_name)
    documentation_paths = (
        list(plugin_metadata.documentation_paths) if plugin_metadata is not None else list(provider.documentation_paths)
    )
    return future_not_implemented_response(
        provider=provider,
        operation=operation,
        architecture=request.architecture,
        documentation_paths=documentation_paths,
    )


def remote_build_kernel_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=RemoteBuildRequest,
        operation="remote.build_kernel",
        payload=kwargs,
        registry=registry,
    )


def remote_sync_artifacts_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=RemoteArtifactSyncRequest,
        operation="remote.sync_artifacts",
        payload=kwargs,
        registry=registry,
    )


def reservation_request_host_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ReservationRequest,
        operation="reservation.request_host",
        payload=kwargs,
        registry=registry,
    )


def reservation_release_host_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ReservationReleaseRequest,
        operation="reservation.release_host",
        payload=kwargs,
        registry=registry,
    )


def provision_prepare_target_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ProvisioningRequest,
        operation="provision.prepare_target",
        payload=kwargs,
        registry=registry,
    )


def hardware_power_control_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=HardwareControlRequest,
        operation="hardware.power_control",
        payload=kwargs,
        registry=registry,
    )


def hardware_boot_kernel_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=RealBootRequest,
        operation="hardware.boot_kernel",
        payload=kwargs,
        registry=registry,
    )


def console_open_session_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ConsoleSessionRequest,
        operation="console.open_session",
        payload=kwargs,
        registry=registry,
    )


def console_read_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ConsoleReadRequest,
        operation="console.read",
        payload=kwargs,
        registry=registry,
    )


def console_write_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ConsoleWriteRequest,
        operation="console.write",
        payload=kwargs,
        registry=registry,
    )


def workflow_reserve_provision_boot_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ReserveProvisionBootRequest,
        operation="workflow.reserve_provision_boot",
        payload=kwargs,
        registry=registry,
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
        profile = _build_profile_from_manifest(manifest)
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
    boot_overrides: BootOverrides | None = None,
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

    effective_boot_overrides = boot_overrides
    if effective_boot_overrides is None and not manifest.boot_attempts:
        effective_boot_overrides = manifest.request.boot_overrides
    if effective_boot_overrides is not None:
        try:
            if effective_boot_overrides.kernel_args:
                resolved_target_profile = resolved_target_profile.model_copy(
                    update={
                        "kernel_args": merge_kernel_args(
                            resolved_target_profile.kernel_args, effective_boot_overrides.kernel_args
                        )
                    }
                )
            if effective_boot_overrides.rootfs_source is not None:
                validated = validate_rootfs_source(
                    Path(effective_boot_overrides.rootfs_source),
                    source_paths=[Path(manifest.request.source_path)],
                    sensitive_paths=[],
                )
                resolved_rootfs_profile = resolved_rootfs_profile.model_copy(update={"source": str(validated)})
        except (PathSafetyError, ValueError) as exc:
            return _configuration_failure(run_id=run_id, message=str(exc))

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

    has_new_boot_overrides = boot_overrides is not None and (
        bool(boot_overrides.kernel_args) or boot_overrides.rootfs_source is not None
    )

    existing = manifest.step_results.get("boot")
    if existing and existing.status == StepStatus.SUCCEEDED and not force_reboot and not has_new_boot_overrides:
        return _recorded_boot_success_response(run_id=run_id, result=existing)

    provider = provider or LibvirtQemuProvider()

    def execute_boot(*, plan: Any, retrying_after_failure: bool, replace_succeeded: bool, attempt: int) -> ToolResponse:
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
                details=_redacted_boot_data(exc.details),
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
                details=_redacted_boot_data(failed.details),
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
        attempt_record = BootAttempt(
            attempt=attempt,
            resolved_target_profile=resolved_target_profile,
            resolved_rootfs_profile=resolved_rootfs_profile,
            status=execution.status,
        )
        store.record_boot_attempt(run_id, attempt=attempt_record, boot_result=terminal)
        if execution.status == StepStatus.SUCCEEDED:
            return ToolResponse.success(
                summary=execution.summary,
                run_id=run_id,
                data=_redacted_boot_data(terminal.details),
                artifacts=execution.artifacts,
                suggested_next_actions=["artifacts.get_manifest"],
            )
        return ToolResponse.failure(
            category=execution.error_category or ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=execution.summary,
            run_id=run_id,
            details=_redacted_boot_data({**execution.details, "diagnostic": execution.diagnostic}),
            artifacts=execution.artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )

    try:
        with store.boot_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            locked_existing = locked_manifest.step_results.get("boot")
            if (
                locked_existing
                and locked_existing.status == StepStatus.SUCCEEDED
                and not force_reboot
                and not has_new_boot_overrides
            ):
                return _recorded_boot_success_response(run_id=run_id, result=locked_existing)
            next_attempt = len(locked_manifest.boot_attempts) + 1
            retrying_after_failure = bool(locked_existing and locked_existing.status == StepStatus.FAILED)
            replace_succeeded = (
                bool(locked_existing and locked_existing.status == StepStatus.SUCCEEDED) or has_new_boot_overrides
            )
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
                        attempt=next_attempt,
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
                        details=_redacted_boot_data(exc.details),
                        artifacts=exc.artifacts,
                        suggested_next_actions=["artifacts.get_manifest"],
                    )
                except (ManifestStateError, OSError, ValueError) as exc:
                    return _configuration_failure(run_id=run_id, message=str(exc))
                return execute_boot(
                    plan=plan,
                    retrying_after_failure=retrying_after_failure,
                    replace_succeeded=replace_succeeded or force_reboot,
                    attempt=next_attempt,
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
    try:
        resolved_debug_profile = _resolve_debug_profile(
            profile_name=requested_profile,
            debug_profiles=debug_profiles,
        )
        _ensure_debug_operation_enabled(resolved_debug_profile, "debug.start_session")
    except ProviderDebugError as exc:
        return _configuration_failure(run_id=run_id, message=str(exc), details=exc.details)

    provider = provider or QemuGdbstubProvider()
    redactor = Redactor()
    try:
        with store.debug_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("debug")
            replace_existing_debug = new_session
            if existing and not new_session:
                active_session = _debug_session_details_from_result(existing)
                if active_session is not None:
                    return ToolResponse.success(
                        summary=redactor.redact_text(existing.summary),
                        run_id=run_id,
                        data=redactor.redact_value(active_session),
                        artifacts=_redacted_artifacts(existing.artifacts, redactor),
                        suggested_next_actions=["debug.interrupt", "debug.read_registers", "artifacts.get_manifest"],
                    )
                replace_existing_debug = existing.status == StepStatus.SUCCEEDED
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
                    details=redactor.redact_value(exc.details),
                )
                store.record_step_result(run_id, failed, replace_succeeded=replace_existing_debug)
                return ToolResponse.failure(
                    category=exc.category,
                    message=redactor.redact_text(str(exc)),
                    run_id=run_id,
                    details=redactor.redact_value(exc.details),
                    artifacts=_redacted_artifacts(exc.artifacts, redactor),
                    suggested_next_actions=["artifacts.get_manifest"],
                )
            details = _debug_session_manifest_details(store=store, run_id=run_id, session=result.session)
            terminal = StepResult(
                step_name="debug",
                status=result.status,
                summary=result.summary,
                artifacts=result.artifacts,
                details=details,
            )
            store.record_step_result(run_id, terminal, replace_succeeded=replace_existing_debug)
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


def _load_active_debug_session(
    store: ArtifactStore,
    run_id: str,
    debug_session_id: str | None = None,
    *,
    allow_ended: bool = False,
) -> DebugSession:
    manifest = store.load_manifest(run_id)
    debug_result = manifest.step_results.get("debug")
    if debug_result is None:
        raise ProviderDebugError(
            "active debug session required",
            category=ErrorCategory.CONFIGURATION_ERROR,
        )
    active_details = _debug_session_details_from_result(debug_result, allow_ended=allow_ended)
    if active_details is None:
        raise ProviderDebugError(
            "active debug session required",
            category=ErrorCategory.CONFIGURATION_ERROR,
        )
    active_session_id = active_details.get("debug_session_id")
    if debug_session_id is not None and active_session_id != debug_session_id:
        raise ProviderDebugError(
            "requested debug session is not active",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"requested_debug_session_id": debug_session_id, "active_debug_session_id": active_session_id},
        )
    session_path_value = active_details.get("session_path")
    if type(session_path_value) is not str:
        raise ProviderDebugError(
            "active debug session did not record a session path",
            category=ErrorCategory.CONFIGURATION_ERROR,
        )
    run_dir = store.run_dir(run_id)
    session_path = _require_run_debug_path(Path(session_path_value), run_dir=run_dir, description="session path")
    try:
        session = DebugSession.model_validate_json(session_path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise ProviderDebugError(
            "failed to load active debug session",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"session_path": str(session_path), "error": str(exc)},
        ) from exc
    if session.run_id != run_id or session.provider_name != "local-qemu-gdbstub":
        raise ProviderDebugError(
            "active debug session file does not match run",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={
                "session_path": str(session_path),
                "session_run_id": session.run_id,
                "provider_name": session.provider_name,
            },
        )
    for description, path_value in [
        ("transcript path", session.transcript_path),
        ("command metadata path", session.command_metadata_path),
        ("summary path", session.latest_summary_path),
    ]:
        _require_run_debug_path(Path(path_value), run_dir=run_dir, description=description)
    if session.session_id != active_session_id:
        raise ProviderDebugError(
            "active debug session file does not match manifest",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"session_path": str(session_path), "session_id": session.session_id},
        )
    if (not allow_ended and session.current_execution_state == "ended") or session.attach_status != "attached":
        raise ProviderDebugError(
            "active debug session required",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"debug_session_id": session.session_id},
        )
    return session


def _debug_operation_response(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    provider: QemuGdbstubProvider | None,
    method_name: str,
    kwargs: dict[str, object],
    persist_manifest: bool,
    allow_ended: bool = False,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    provider = provider or QemuGdbstubProvider()
    redactor = Redactor()
    try:
        with store.debug_lock(run_id):
            session = _load_active_debug_session(store, run_id, debug_session_id, allow_ended=allow_ended)
            profile = _resolve_debug_profile(
                profile_name=session.selected_debug_profile,
                debug_profiles=debug_profiles,
            )
            _ensure_debug_operation_enabled(profile, DEBUG_METHOD_OPERATIONS[method_name])
            result: DebugProviderResult = getattr(provider, method_name)(
                run_dir=store.run_dir(run_id),
                session=session,
                **kwargs,
            )
            details = result.details
            if persist_manifest:
                details = {
                    **_debug_session_manifest_details(store=store, run_id=run_id, session=result.session),
                    **result.details,
                }
                terminal = StepResult(
                    step_name="debug",
                    status=result.status,
                    summary=result.summary,
                    artifacts=result.artifacts,
                    details=details,
                )
                store.record_step_result(run_id, terminal, replace_succeeded=True)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    except ProviderDebugError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value(exc.details),
            artifacts=_redacted_artifacts(exc.artifacts, redactor),
            suggested_next_actions=["debug.start_session", "artifacts.get_manifest"],
        )

    safe_details = redactor.redact_value(result.details)
    safe_artifacts = _redacted_artifacts(result.artifacts, redactor)
    safe_summary = redactor.redact_text(result.summary)
    if result.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=safe_summary,
            run_id=run_id,
            data=safe_details,
            artifacts=safe_artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    return ToolResponse.failure(
        category=result.error_category or ErrorCategory.DEBUG_ATTACH_FAILURE,
        message=safe_summary,
        run_id=run_id,
        details={
            **safe_details,
            "diagnostic": redactor.redact_text(result.diagnostic or ""),
        },
        artifacts=safe_artifacts,
        suggested_next_actions=["debug.start_session", "artifacts.get_manifest"],
    )


def _debug_read_response(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    provider: QemuGdbstubProvider | None,
    method_name: str,
    kwargs: dict[str, object],
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    return _debug_operation_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        provider=provider,
        method_name=method_name,
        kwargs=kwargs,
        persist_manifest=False,
        debug_profiles=debug_profiles,
    )


def debug_read_registers_handler(
    *,
    artifact_root: Path,
    run_id: str,
    registers: list[str],
    debug_session_id: str | None = None,
    provider: QemuGdbstubProvider | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    return _debug_read_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        provider=provider,
        method_name="read_registers",
        kwargs={"registers": registers},
        debug_profiles=debug_profiles,
    )


def debug_read_symbol_handler(
    *,
    artifact_root: Path,
    run_id: str,
    symbol: str,
    debug_session_id: str | None = None,
    provider: QemuGdbstubProvider | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    return _debug_read_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        provider=provider,
        method_name="read_symbol",
        kwargs={"symbol": symbol},
        debug_profiles=debug_profiles,
    )


def debug_read_memory_handler(
    *,
    artifact_root: Path,
    run_id: str,
    address: int,
    byte_count: int,
    debug_session_id: str | None = None,
    provider: QemuGdbstubProvider | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    return _debug_read_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        provider=provider,
        method_name="read_memory",
        kwargs={"address": address, "byte_count": byte_count},
        debug_profiles=debug_profiles,
    )


def debug_evaluate_handler(
    *,
    artifact_root: Path,
    run_id: str,
    inspector: str,
    arguments: dict[str, object] | None = None,
    debug_session_id: str | None = None,
    provider: QemuGdbstubProvider | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    return _debug_read_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        provider=provider,
        method_name="evaluate",
        kwargs={"inspector": inspector, "arguments": arguments or {}},
        debug_profiles=debug_profiles,
    )


def _debug_stateful_response(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    provider: QemuGdbstubProvider | None,
    method_name: str,
    kwargs: dict[str, object],
    allow_ended: bool = False,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    return _debug_operation_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        provider=provider,
        method_name=method_name,
        kwargs=kwargs,
        persist_manifest=True,
        allow_ended=allow_ended,
        debug_profiles=debug_profiles,
    )


def debug_set_breakpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    symbol: str,
    debug_session_id: str | None = None,
    provider: QemuGdbstubProvider | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        provider=provider,
        method_name="set_breakpoint",
        kwargs={"symbol": symbol},
        debug_profiles=debug_profiles,
    )


def debug_clear_breakpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    breakpoint_id: str,
    debug_session_id: str | None = None,
    provider: QemuGdbstubProvider | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        provider=provider,
        method_name="clear_breakpoint",
        kwargs={"breakpoint_id": breakpoint_id},
        debug_profiles=debug_profiles,
    )


def debug_list_breakpoints_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None = None,
    provider: QemuGdbstubProvider | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        provider=provider,
        method_name="list_breakpoints",
        kwargs={},
        debug_profiles=debug_profiles,
    )


def debug_continue_handler(
    *,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None = None,
    debug_session_id: str | None = None,
    provider: QemuGdbstubProvider | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        provider=provider,
        method_name="continue_execution",
        kwargs={"timeout_seconds": timeout_seconds},
        debug_profiles=debug_profiles,
    )


def debug_interrupt_handler(
    *,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None = None,
    debug_session_id: str | None = None,
    provider: QemuGdbstubProvider | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        provider=provider,
        method_name="interrupt",
        kwargs={"timeout_seconds": timeout_seconds},
        debug_profiles=debug_profiles,
    )


def debug_end_session_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None = None,
    provider: QemuGdbstubProvider | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        provider=provider,
        method_name="end_session",
        kwargs={},
        allow_ended=True,
        debug_profiles=debug_profiles,
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
        "debug": {"debug-command-metadata", "debug-session", "debug-summary", "debug-transcript"},
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


def _collection_covers_manifest(*, manifest: RunManifest, collect_result: StepResult) -> bool:
    collected = {
        (artifact.path, artifact.kind) for artifact in collect_result.artifacts if artifact.kind != "artifact-bundle"
    }
    current = {
        (artifact.path, artifact.kind)
        for step_name, result in manifest.step_results.items()
        if step_name != "collect_artifacts"
        for artifact in result.artifacts
    }
    return current.issubset(collected)


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
    if (
        existing
        and existing.status == StepStatus.SUCCEEDED
        and not force_recollect
        and _collection_covers_manifest(manifest=manifest, collect_result=existing)
    ):
        return _recorded_collect_success_response(run_id=run_id, result=existing)
    try:
        with store.collect_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("collect_artifacts")
            replace_succeeded = force_recollect or bool(existing and existing.status == StepStatus.SUCCEEDED)
            if (
                existing
                and existing.status == StepStatus.SUCCEEDED
                and not force_recollect
                and _collection_covers_manifest(manifest=locked_manifest, collect_result=existing)
            ):
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
            store.record_step_result(run_id, result, replace_succeeded=replace_succeeded)
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
    failure_response = ToolResponse.failure(
        category=category,
        message=message,
        run_id=run_id,
        details=details,
        artifacts=[*(response.artifacts or []), *((collect_response.artifacts if collect_response else []) or [])],
        suggested_next_actions=["artifacts.get_manifest", "Inspect artifact bundle"],
    )
    failure_response.data = details
    return failure_response


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


def workflow_build_boot_debug_handler(
    *,
    artifact_root: Path,
    source_path: str,
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    run_id: str | None = None,
    debug_profile: str | None = None,
    force_rebuild: bool = False,
    force_reboot: bool = False,
    new_session: bool = False,
) -> ToolResponse:
    if run_id is not None:
        try:
            store = ArtifactStore(artifact_root, create_root=False)
            manifest_path = store.run_dir(run_id) / "manifest.json"
            if manifest_path.is_file():
                manifest = store.load_manifest(run_id)
                resolved_debug_profile = debug_profile if debug_profile is not None else manifest.request.debug_profile
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
                    **({"debug_profile": resolved_debug_profile} if manifest.request.debug_profile is not None else {}),
                }
                actual = {
                    "source_path": manifest.request.source_path,
                    "build_profile": manifest.request.build_profile,
                    "target_profile": manifest.request.target_profile,
                    "rootfs_profile": manifest.request.rootfs_profile,
                    **(
                        {"debug_profile": manifest.request.debug_profile}
                        if manifest.request.debug_profile is not None
                        else {}
                    ),
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
                if manifest.request.debug_profile is not None or debug_profile is None:
                    debug_profile = resolved_debug_profile
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
            debug_profile=debug_profile,
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
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="build",
            latest_successful_step=None,
            response=build_response,
            collect_response=None,
        )

    boot_response = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        force_reboot=force_reboot,
    )
    if not boot_response.ok:
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="boot",
            latest_successful_step="build",
            response=boot_response,
            collect_response=None,
        )

    debug_response = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profile=debug_profile,
        new_session=new_session,
    )
    if not debug_response.ok:
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="debug",
            latest_successful_step="boot",
            response=debug_response,
            collect_response=None,
        )

    return ToolResponse.success(
        summary="build, boot, debug workflow succeeded",
        run_id=run_id,
        data={
            "steps": {
                "build": build_response.model_dump(mode="json"),
                "boot": boot_response.model_dump(mode="json"),
                "debug": debug_response.model_dump(mode="json"),
            },
            "latest_successful_step": "debug",
        },
        artifacts=debug_response.artifacts,
        suggested_next_actions=["debug.read_registers", "debug.evaluate", "debug.end_session"],
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

    @app.tool(name="remote.build_kernel")
    def remote_build_kernel(
        architecture: str,
        source_ref: str,
        build_profile: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        output_artifact_ref: str | None = None,
    ) -> dict[str, Any]:
        return remote_build_kernel_handler(
            architecture=architecture,
            source_ref=source_ref,
            build_profile=build_profile,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            output_artifact_ref=output_artifact_ref,
        ).model_dump(mode="json")

    @app.tool(name="remote.sync_artifacts")
    def remote_sync_artifacts(
        architecture: str,
        external_artifact_ref: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        destination_artifact_ref: str | None = None,
    ) -> dict[str, Any]:
        return remote_sync_artifacts_handler(
            architecture=architecture,
            external_artifact_ref=external_artifact_ref,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            destination_artifact_ref=destination_artifact_ref,
        ).model_dump(mode="json")

    @app.tool(name="reservation.request_host")
    def reservation_request_host(
        architecture: str,
        reservation_pool: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        reservation_token_ref: str | None = None,
    ) -> dict[str, Any]:
        return reservation_request_host_handler(
            architecture=architecture,
            reservation_pool=reservation_pool,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            reservation_token_ref=reservation_token_ref,
        ).model_dump(mode="json")

    @app.tool(name="reservation.release_host")
    def reservation_release_host(
        architecture: str,
        reservation_id: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        return reservation_release_host_handler(
            architecture=architecture,
            reservation_id=reservation_id,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
        ).model_dump(mode="json")

    @app.tool(name="provision.prepare_target")
    def provision_prepare_target(
        architecture: str,
        target_name: str,
        provisioning_profile: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        reservation_id: str | None = None,
        credential_ref: str | None = None,
    ) -> dict[str, Any]:
        return provision_prepare_target_handler(
            architecture=architecture,
            target_name=target_name,
            provisioning_profile=provisioning_profile,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            reservation_id=reservation_id,
            credential_ref=credential_ref,
        ).model_dump(mode="json")

    @app.tool(name="hardware.power_control")
    def hardware_power_control(
        architecture: str,
        target_name: str,
        action: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        bmc_credential_ref: str | None = None,
    ) -> dict[str, Any]:
        return hardware_power_control_handler(
            architecture=architecture,
            target_name=target_name,
            action=action,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            bmc_credential_ref=bmc_credential_ref,
        ).model_dump(mode="json")

    @app.tool(name="hardware.boot_kernel")
    def hardware_boot_kernel(
        architecture: str,
        target_name: str,
        kernel_artifact_ref: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        boot_profile: str | None = None,
        reservation_id: str | None = None,
    ) -> dict[str, Any]:
        return hardware_boot_kernel_handler(
            architecture=architecture,
            target_name=target_name,
            kernel_artifact_ref=kernel_artifact_ref,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            boot_profile=boot_profile,
            reservation_id=reservation_id,
        ).model_dump(mode="json")

    @app.tool(name="console.open_session")
    def console_open_session(
        architecture: str,
        target_name: str,
        access_method: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        credential_ref: str | None = None,
    ) -> dict[str, Any]:
        return console_open_session_handler(
            architecture=architecture,
            target_name=target_name,
            access_method=access_method,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            credential_ref=credential_ref,
        ).model_dump(mode="json")

    @app.tool(name="console.read")
    def console_read(
        architecture: str,
        console_session_id: str,
        max_bytes: int = 4096,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        return console_read_handler(
            architecture=architecture,
            console_session_id=console_session_id,
            max_bytes=max_bytes,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
        ).model_dump(mode="json")

    @app.tool(name="console.write")
    def console_write(
        architecture: str,
        console_session_id: str,
        data: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        return console_write_handler(
            architecture=architecture,
            console_session_id=console_session_id,
            data=data,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
        ).model_dump(mode="json")

    @app.tool(name="workflow.reserve_provision_boot")
    def workflow_reserve_provision_boot(
        architecture: str,
        reservation_pool: str,
        target_name: str,
        provisioning_profile: str,
        kernel_artifact_ref: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        reservation_token_ref: str | None = None,
        credential_ref: str | None = None,
        bmc_credential_ref: str | None = None,
    ) -> dict[str, Any]:
        return workflow_reserve_provision_boot_handler(
            architecture=architecture,
            reservation_pool=reservation_pool,
            target_name=target_name,
            provisioning_profile=provisioning_profile,
            kernel_artifact_ref=kernel_artifact_ref,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            reservation_token_ref=reservation_token_ref,
            credential_ref=credential_ref,
            bmc_credential_ref=bmc_credential_ref,
        ).model_dump(mode="json")

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

    @app.tool(name="debug.read_registers")
    def debug_read_registers(
        run_id: str,
        registers: list[str],
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_read_registers_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            registers=registers,
            debug_session_id=debug_session_id,
        ).model_dump(mode="json")

    @app.tool(name="debug.read_symbol")
    def debug_read_symbol(
        run_id: str,
        symbol: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_read_symbol_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            symbol=symbol,
            debug_session_id=debug_session_id,
        ).model_dump(mode="json")

    @app.tool(name="debug.read_memory")
    def debug_read_memory(
        run_id: str,
        address: int,
        byte_count: int,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_read_memory_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            address=address,
            byte_count=byte_count,
            debug_session_id=debug_session_id,
        ).model_dump(mode="json")

    @app.tool(name="debug.evaluate")
    def debug_evaluate(
        run_id: str,
        inspector: str,
        arguments: dict[str, object] | None = None,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_evaluate_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            inspector=inspector,
            arguments=arguments,
            debug_session_id=debug_session_id,
        ).model_dump(mode="json")

    @app.tool(name="debug.set_breakpoint")
    def debug_set_breakpoint(
        run_id: str,
        symbol: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_set_breakpoint_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            symbol=symbol,
            debug_session_id=debug_session_id,
        ).model_dump(mode="json")

    @app.tool(name="debug.clear_breakpoint")
    def debug_clear_breakpoint(
        run_id: str,
        breakpoint_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_clear_breakpoint_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            breakpoint_id=breakpoint_id,
            debug_session_id=debug_session_id,
        ).model_dump(mode="json")

    @app.tool(name="debug.list_breakpoints")
    def debug_list_breakpoints(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_list_breakpoints_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
        ).model_dump(mode="json")

    @app.tool(name="debug.continue")
    def debug_continue(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return debug_continue_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
            timeout_seconds=timeout_seconds,
        ).model_dump(mode="json")

    @app.tool(name="debug.interrupt")
    def debug_interrupt(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return debug_interrupt_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
            timeout_seconds=timeout_seconds,
        ).model_dump(mode="json")

    @app.tool(name="debug.end_session")
    def debug_end_session(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_end_session_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
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

    @app.tool(name="workflow.build_boot_debug")
    def workflow_build_boot_debug(
        source_path: str,
        build_profile: str,
        target_profile: str,
        rootfs_profile: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        run_id: str | None = None,
        debug_profile: str | None = None,
        force_rebuild: bool = False,
        force_reboot: bool = False,
        new_session: bool = False,
    ) -> dict[str, Any]:
        return workflow_build_boot_debug_handler(
            artifact_root=Path(artifact_root),
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            debug_profile=debug_profile,
            force_rebuild=force_rebuild,
            force_reboot=force_reboot,
            new_session=new_session,
        ).model_dump(mode="json")

    return app


def main() -> None:
    configure_logging()
    create_app().run()
