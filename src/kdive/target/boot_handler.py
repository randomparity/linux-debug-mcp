from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kdive.artifacts.manifest import BootAttempt, RunManifest
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import (
    TARGET_DESTRUCTIVE_PERMISSIONS,
    BootOverrides,
    RootfsProfile,
    TargetProfile,
    merge_kernel_args,
    missing_destructive_permissions,
)
from kdive.coordination.admission import AdmissionService, publish_ready_snapshot
from kdive.default_profiles import DEFAULT_ROOTFS_PROFILES, DEFAULT_TARGET_PROFILES
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.providers.local.target.libvirt_qemu import LibvirtQemuProvider, ProviderBootError
from kdive.rootfs.sources import RootfsSourceError, resolve_rootfs_source
from kdive.safety.paths import PathSafetyError, validate_rootfs_source
from kdive.safety.redaction import Redactor
from kdive.seams.target import BreakHint, ConsoleKind, KernelProvenance, PlatformMetadata, TargetKey
from kdive.target.common import (
    _configuration_failure,
    _configuration_handler_failure,
    _HandlerFailure,
    _tool_response_from_handler_failure,
)
from kdive.target.tools import TargetBootHandlerRequest, TargetToolRuntime
from kdive.transport.core.base import LineRole, TransportRef

logger = logging.getLogger(__name__)

RUNNING_BOOT_MESSAGE = "previous boot is still recorded as running"


def _redacted_boot_data(data: dict[str, Any]) -> dict[str, Any]:
    return Redactor().redact_value(data)


def _boot_success_next_actions(details: dict[str, Any]) -> list[str]:
    if details.get("console_status") == "frozen":
        return ["debug.start_session"]
    return ["artifacts.get_manifest"]


def _recorded_boot_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.success(
        summary=result.summary,
        run_id=run_id,
        data=_redacted_boot_data(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=_boot_success_next_actions(result.details),
    )


def _running_boot_response(*, run_id: str, result: StepResult, message: str = RUNNING_BOOT_MESSAGE) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=message,
        run_id=run_id,
        status=StepStatus.RUNNING,
        details=_redacted_boot_data(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
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


def _artifact_run_relative_ref(artifact: ArtifactRef | None, *, run_root: Path) -> tuple[str | None, str | None]:
    if artifact is None:
        return None, None
    try:
        return str(Path(artifact.path).resolve().relative_to(run_root)), None
    except ValueError:
        return None, "artifact_path_unexpected"


def _capture_kernel_provenance(
    *,
    build_step: StepResult | None,
    boot_details: dict[str, Any],
    run_dir: Path,
) -> dict[str, Any]:
    if build_step is None:
        return {
            "kernel_provenance_capture_error": {"code": "build_id_unavailable", "message": "no build step recorded"}
        }
    build_id = build_step.details.get("build_id")
    if not isinstance(build_id, str):
        return {
            "kernel_provenance_capture_error": {"code": "build_id_unavailable", "message": "build recorded no build_id"}
        }
    release = build_step.details.get("kernel_release")
    if not isinstance(release, str):
        return {
            "kernel_provenance_capture_error": {
                "code": "release_unavailable",
                "message": "build recorded no kernel_release",
            }
        }

    run_root = run_dir.resolve()
    notes: list[str] = []
    config_artifact = _find_artifact(build_step, "kernel-config")
    config_ref, config_err = _artifact_run_relative_ref(config_artifact, run_root=run_root)
    if config_err is not None:
        return {
            "kernel_provenance_capture_error": {
                "code": config_err,
                "message": "kernel-config artifact is outside the run directory",
            }
        }
    if config_artifact is None:
        notes.append("config_artifact_missing")

    vmlinux_artifact = _find_artifact(build_step, "vmlinux")
    if vmlinux_artifact is not None:
        vmlinux_ref, vmlinux_err = _artifact_run_relative_ref(vmlinux_artifact, run_root=run_root)
        if vmlinux_err is not None:
            return {
                "kernel_provenance_capture_error": {
                    "code": vmlinux_err,
                    "message": "vmlinux artifact is outside the run directory",
                }
            }
    else:
        vmlinux_ref = "build/vmlinux"
        notes.append("vmlinux_artifact_missing")

    kernel_args = boot_details.get("kernel_args")
    cmdline = " ".join(kernel_args) if isinstance(kernel_args, list) else ""

    provenance = KernelProvenance(
        build_id=build_id,
        release=release,
        vmlinux_ref=vmlinux_ref or "build/vmlinux",
        modules_ref=None,
        cmdline=cmdline,
        config_ref=config_ref,
    )
    result: dict[str, Any] = {"kernel_provenance": provenance.model_dump(mode="json")}
    if notes:
        result["kernel_provenance_capture_notes"] = notes
    return result


def _publish_boot_ready_snapshot(
    admission: AdmissionService,
    *,
    run_id: str,
    generation: int,
    gdbstub_endpoint: dict[str, Any] | None,
    rootfs_profile: RootfsProfile,
) -> None:
    transports: list[TransportRef] = []
    if gdbstub_endpoint is not None:
        transports.append(
            TransportRef(
                provider="qemu-gdbstub",
                channel_id="rsp0",
                line_role=LineRole.RSP,
                caps=("rsp",),
                target_ref=gdbstub_endpoint,
            )
        )
    platform = PlatformMetadata(
        console_kind=ConsoleKind.UART,
        console_count=1,
        dedicated_debug_line=False,
        ssh_reachable=rootfs_profile.ssh_host is not None,
        break_hints=[BreakHint.GDBSTUB_NATIVE],
    )
    publish_ready_snapshot(
        admission,
        target_key=TargetKey(provisioner="local-qemu", target_id=run_id),
        generation=generation,
        transports=transports,
        platform=platform,
    )


def _short_circuit_boot_success(
    *,
    run_id: str,
    result: StepResult,
    admission: AdmissionService | None,
    manifest: RunManifest,
    rootfs_profile: RootfsProfile,
) -> ToolResponse:
    if admission is not None:
        details = result.details if isinstance(result.details, dict) else {}
        gdbstub_endpoint = details.get("gdbstub_endpoint") if isinstance(details, dict) else None
        if gdbstub_endpoint is not None and not isinstance(gdbstub_endpoint, dict):
            gdbstub_endpoint = None
        attempt = manifest.boot_attempts[-1].attempt if manifest.boot_attempts else 1
        _publish_boot_ready_snapshot(
            admission,
            run_id=run_id,
            generation=attempt,
            gdbstub_endpoint=gdbstub_endpoint,
            rootfs_profile=rootfs_profile,
        )
    return _recorded_boot_success_response(run_id=run_id, result=result)


def _finalize_boot_execution(
    execution: Any,
    *,
    store: ArtifactStore,
    run_id: str,
    attempt: int,
    manifest: RunManifest,
    kernel_image: ArtifactRef,
    resolved_target_profile: TargetProfile,
    resolved_rootfs_profile: RootfsProfile,
    admission: AdmissionService | None,
    plan_gdbstub_endpoint: dict[str, Any] | None,
) -> ToolResponse:
    terminal_details: dict[str, Any] = {**execution.details, "kernel_image_path": str(kernel_image.path)}
    if execution.status == StepStatus.SUCCEEDED:
        try:
            terminal_details.update(
                _capture_kernel_provenance(
                    build_step=manifest.step_results.get("build"),
                    boot_details=execution.details,
                    run_dir=store.run_dir(run_id),
                )
            )
        except Exception as capture_exc:
            logger.warning("kernel provenance capture failed: %s", capture_exc, exc_info=True)
            terminal_details["kernel_provenance_capture_error"] = {
                "code": "capture_unexpected_error",
                "message": f"{type(capture_exc).__name__}: {capture_exc}",
            }
    terminal = StepResult(
        step_name="boot",
        status=execution.status,
        summary=execution.summary,
        artifacts=execution.artifacts,
        details=terminal_details,
    )
    attempt_record = BootAttempt(
        attempt=attempt,
        resolved_target_profile=resolved_target_profile,
        resolved_rootfs_profile=resolved_rootfs_profile,
        status=execution.status,
    )
    store.record_boot_attempt(run_id, attempt=attempt_record, boot_result=terminal)
    if execution.status == StepStatus.SUCCEEDED and admission is not None:
        _publish_boot_ready_snapshot(
            admission,
            run_id=run_id,
            generation=attempt,
            gdbstub_endpoint=plan_gdbstub_endpoint,
            rootfs_profile=resolved_rootfs_profile,
        )
    if execution.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=execution.summary,
            run_id=run_id,
            data=_redacted_boot_data(terminal.details),
            artifacts=execution.artifacts,
            suggested_next_actions=_boot_success_next_actions(terminal.details),
        )
    return ToolResponse.failure(
        category=execution.error_category or ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=execution.summary,
        run_id=run_id,
        details=_redacted_boot_data({**execution.details, "diagnostic": execution.diagnostic}),
        artifacts=execution.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _record_boot_attempt_failure(
    *,
    store: ArtifactStore,
    run_id: str,
    attempt_record: BootAttempt,
    failed: StepResult,
    category: ErrorCategory,
) -> ToolResponse:
    store.record_boot_attempt(run_id, attempt=attempt_record, boot_result=failed)
    return ToolResponse.failure(
        category=category,
        message=failed.summary,
        run_id=run_id,
        details=_redacted_boot_data(failed.details),
        artifacts=failed.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _execute_boot_attempt(
    *,
    plan: Any,
    retrying_after_failure: bool,
    replace_succeeded: bool,
    attempt: int,
    manifest: RunManifest,
    provider: LibvirtQemuProvider,
    store: ArtifactStore,
    run_id: str,
    resolved_target_profile: TargetProfile,
    resolved_rootfs_profile: RootfsProfile,
    kernel_image: ArtifactRef,
    force_reboot: bool,
    admission: AdmissionService | None,
) -> ToolResponse:
    def _failed_attempt_record() -> BootAttempt:
        return BootAttempt(
            attempt=attempt,
            resolved_target_profile=resolved_target_profile,
            resolved_rootfs_profile=resolved_rootfs_profile,
            status=StepStatus.FAILED,
        )

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
            step_name="boot", status=StepStatus.FAILED, summary=str(exc), artifacts=exc.artifacts, details=exc.details
        )
        return _record_boot_attempt_failure(
            store=store, run_id=run_id, attempt_record=_failed_attempt_record(), failed=failed, category=exc.category
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
        return _record_boot_attempt_failure(
            store=store,
            run_id=run_id,
            attempt_record=_failed_attempt_record(),
            failed=failed,
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        )
    return _finalize_boot_execution(
        execution,
        store=store,
        run_id=run_id,
        attempt=attempt,
        manifest=manifest,
        kernel_image=kernel_image,
        resolved_target_profile=resolved_target_profile,
        resolved_rootfs_profile=resolved_rootfs_profile,
        admission=admission,
        plan_gdbstub_endpoint=plan_gdbstub_endpoint,
    )


def _assert_profile_matches_manifest(
    *, kind: str, requested: str | None, manifest_value: str | None, run_id: str
) -> _HandlerFailure | None:
    if requested == manifest_value:
        return None
    return _configuration_handler_failure(
        run_id=run_id,
        message=f"{kind}_profile must match the immutable run manifest request",
        details={"requested_profile": requested, "manifest_profile": manifest_value},
    )


def _apply_boot_overrides(
    *,
    resolved_target_profile: TargetProfile,
    resolved_rootfs_profile: RootfsProfile,
    overrides: BootOverrides,
    manifest: RunManifest,
    sensitive_paths: list[Path] | None,
    run_id: str,
) -> tuple[TargetProfile, RootfsProfile] | _HandlerFailure:
    try:
        if overrides.kernel_args:
            resolved_target_profile = resolved_target_profile.model_copy(
                update={"kernel_args": merge_kernel_args(resolved_target_profile.kernel_args, overrides.kernel_args)}
            )
        if overrides.wait_for_debugger is not None:
            resolved_target_profile = resolved_target_profile.model_copy(
                update={"wait_for_debugger": overrides.wait_for_debugger}
            )
        rootfs_update: dict[str, object] = {}
        if overrides.rootfs_source is not None:
            validated = validate_rootfs_source(
                Path(overrides.rootfs_source),
                source_paths=[Path(manifest.request.source_path)],
                sensitive_paths=sensitive_paths or [],
            )
            rootfs_update["source"] = str(validated)
        if overrides.rootfs is not None:
            rootfs_update.update(overrides.rootfs.as_profile_update())
        if rootfs_update:
            resolved_rootfs_profile = resolved_rootfs_profile.model_copy(update=rootfs_update)
    except (PathSafetyError, ValueError) as exc:
        return _configuration_handler_failure(run_id=run_id, message=str(exc))
    return resolved_target_profile, resolved_rootfs_profile


@dataclass(frozen=True)
class _ResolvedBootInputs:
    resolved_target_profile: TargetProfile
    resolved_rootfs_profile: RootfsProfile
    target_ref: str
    kernel_image: ArtifactRef


def _resolve_boot_inputs(
    *,
    manifest: RunManifest,
    run_id: str,
    target_profile: str | None,
    rootfs_profile: str | None,
    target_profiles: Mapping[str, TargetProfile] | None,
    rootfs_profiles: Mapping[str, RootfsProfile] | None,
    default_libvirt_uri: str | None,
    boot_overrides: BootOverrides | None,
    sensitive_paths: list[Path] | None,
) -> _ResolvedBootInputs | _HandlerFailure:
    requested_target_profile = target_profile or manifest.request.target_profile
    requested_rootfs_profile = rootfs_profile or manifest.request.rootfs_profile
    for kind, requested, manifest_value in (
        ("target", requested_target_profile, manifest.request.target_profile),
        ("rootfs", requested_rootfs_profile, manifest.request.rootfs_profile),
    ):
        mismatch = _assert_profile_matches_manifest(
            kind=kind, requested=requested, manifest_value=manifest_value, run_id=run_id
        )
        if mismatch is not None:
            return mismatch

    target_profiles = target_profiles if target_profiles is not None else DEFAULT_TARGET_PROFILES
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    if manifest.resolved_target_profile is not None:
        resolved_target_profile = manifest.resolved_target_profile
    else:
        try:
            resolved_target_profile = target_profiles[requested_target_profile]
        except KeyError:
            return _configuration_handler_failure(
                run_id=run_id, message=f"unknown target profile: {requested_target_profile}"
            )
    if manifest.resolved_rootfs_profile is not None:
        resolved_rootfs_profile = manifest.resolved_rootfs_profile
    else:
        try:
            resolved_rootfs_profile = rootfs_profiles[requested_rootfs_profile]
        except KeyError:
            return _configuration_handler_failure(
                run_id=run_id, message=f"unknown rootfs profile: {requested_rootfs_profile}"
            )
    if resolved_target_profile.libvirt_uri is None and default_libvirt_uri is not None:
        resolved_target_profile = resolved_target_profile.model_copy(update={"libvirt_uri": default_libvirt_uri})
    if resolved_target_profile.target_ref is None:
        return _configuration_handler_failure(run_id=run_id, message="target profile target_ref is required")
    target_ref = resolved_target_profile.target_ref

    effective_boot_overrides = boot_overrides
    if effective_boot_overrides is None and not manifest.boot_attempts:
        effective_boot_overrides = manifest.request.boot_overrides
    if effective_boot_overrides is not None:
        merged = _apply_boot_overrides(
            resolved_target_profile=resolved_target_profile,
            resolved_rootfs_profile=resolved_rootfs_profile,
            overrides=effective_boot_overrides,
            manifest=manifest,
            sensitive_paths=sensitive_paths,
            run_id=run_id,
        )
        if isinstance(merged, _HandlerFailure):
            return merged
        resolved_target_profile, resolved_rootfs_profile = merged

    build_result = manifest.step_results.get("build")
    if build_result is None or build_result.status != StepStatus.SUCCEEDED:
        return _configuration_handler_failure(run_id=run_id, message="target boot requires a succeeded build")
    kernel_image = _find_kernel_image(build_result)
    if kernel_image is None:
        return _configuration_handler_failure(
            run_id=run_id, message="succeeded build did not record a kernel-image artifact"
        )
    build_architecture = build_result.details.get("architecture")
    if build_architecture is not None and build_architecture != resolved_target_profile.architecture:
        return _configuration_handler_failure(
            run_id=run_id,
            message="build architecture does not match target profile architecture",
            details={
                "build_architecture": build_architecture,
                "target_architecture": resolved_target_profile.architecture,
            },
        )

    return _ResolvedBootInputs(
        resolved_target_profile=resolved_target_profile,
        resolved_rootfs_profile=resolved_rootfs_profile,
        target_ref=target_ref,
        kernel_image=kernel_image,
    )


def _plan_boot_or_failure(
    *,
    provider: LibvirtQemuProvider,
    store: ArtifactStore,
    run_id: str,
    kernel_image: ArtifactRef,
    resolved_target_profile: TargetProfile,
    resolved_rootfs_profile: RootfsProfile,
    next_attempt: int,
    replace_succeeded: bool,
    force_reboot: bool,
) -> Any:
    try:
        resolve_rootfs_source(resolved_rootfs_profile)
        plan = provider.plan_boot(
            run_id=run_id,
            run_dir=store.run_dir(run_id),
            kernel_image_path=Path(kernel_image.path),
            target_profile=resolved_target_profile,
            rootfs_profile=resolved_rootfs_profile,
            attempt=next_attempt,
        )
    except RootfsSourceError as exc:
        fix_details = {"suggested_fix": exc.suggested_fix} if exc.suggested_fix else {}
        failed = StepResult(
            step_name="boot",
            status=StepStatus.FAILED,
            summary=str(exc),
            details=fix_details,
        )
        store.record_step_result(run_id, failed, replace_succeeded=replace_succeeded or force_reboot)
        return ToolResponse.failure(
            category=exc.category,
            message=str(exc),
            run_id=run_id,
            details=fix_details,
            suggested_next_actions=["artifacts.get_manifest"],
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
    return plan


def _boot_under_locks(
    *,
    store: ArtifactStore,
    run_id: str,
    target_ref: str,
    resolved_target_profile: TargetProfile,
    resolved_rootfs_profile: RootfsProfile,
    kernel_image: ArtifactRef,
    force_reboot: bool,
    has_new_boot_overrides: bool,
    existing: StepResult | None,
    provider: LibvirtQemuProvider,
    admission: AdmissionService | None,
) -> ToolResponse:
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
                return _short_circuit_boot_success(
                    run_id=run_id,
                    result=locked_existing,
                    admission=admission,
                    manifest=locked_manifest,
                    rootfs_profile=resolved_rootfs_profile,
                )
            next_attempt = len(locked_manifest.boot_attempts) + 1
            retrying_after_failure = bool(locked_existing and locked_existing.status == StepStatus.FAILED)
            replace_succeeded = (
                bool(locked_existing and locked_existing.status == StepStatus.SUCCEEDED) or has_new_boot_overrides
            )
            with store.target_lock(target_ref):
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
                plan = _plan_boot_or_failure(
                    provider=provider,
                    store=store,
                    run_id=run_id,
                    kernel_image=kernel_image,
                    resolved_target_profile=resolved_target_profile,
                    resolved_rootfs_profile=resolved_rootfs_profile,
                    next_attempt=next_attempt,
                    replace_succeeded=replace_succeeded,
                    force_reboot=force_reboot,
                )
                if isinstance(plan, ToolResponse):
                    return plan
                return _execute_boot_attempt(
                    plan=plan,
                    retrying_after_failure=retrying_after_failure,
                    replace_succeeded=replace_succeeded or force_reboot,
                    attempt=next_attempt,
                    manifest=locked_manifest,
                    provider=provider,
                    store=store,
                    run_id=run_id,
                    resolved_target_profile=resolved_target_profile,
                    resolved_rootfs_profile=resolved_rootfs_profile,
                    kernel_image=kernel_image,
                    force_reboot=force_reboot,
                    admission=admission,
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


def target_boot_handler(
    *,
    request: TargetBootHandlerRequest,
    runtime: TargetToolRuntime,
) -> ToolResponse:
    artifact_root = request.artifact_root
    run_id = request.run_id
    boot_overrides = request.boot_overrides
    force_reboot = request.force_reboot
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    resolved_inputs = _resolve_boot_inputs(
        manifest=manifest,
        run_id=run_id,
        target_profile=request.target_profile,
        rootfs_profile=request.rootfs_profile,
        target_profiles=runtime.target_profiles,
        rootfs_profiles=runtime.rootfs_profiles,
        default_libvirt_uri=runtime.default_libvirt_uri,
        boot_overrides=boot_overrides,
        sensitive_paths=runtime.sensitive_paths,
    )
    if isinstance(resolved_inputs, _HandlerFailure):
        return _tool_response_from_handler_failure(resolved_inputs)
    resolved_target_profile = resolved_inputs.resolved_target_profile
    resolved_rootfs_profile = resolved_inputs.resolved_rootfs_profile
    target_ref = resolved_inputs.target_ref
    kernel_image = resolved_inputs.kernel_image

    has_new_boot_overrides = boot_overrides is not None and (
        bool(boot_overrides.kernel_args)
        or boot_overrides.rootfs_source is not None
        or boot_overrides.has_rootfs_field_overrides()
        or boot_overrides.wait_for_debugger is not None
    )

    existing = manifest.step_results.get("boot")
    if existing and existing.status == StepStatus.SUCCEEDED and not force_reboot and not has_new_boot_overrides:
        return _short_circuit_boot_success(
            run_id=run_id,
            result=existing,
            admission=runtime.admission,
            manifest=manifest,
            rootfs_profile=resolved_rootfs_profile,
        )

    missing = missing_destructive_permissions(
        "target.boot",
        request.acknowledged_permissions or [],
        registry=TARGET_DESTRUCTIVE_PERMISSIONS,
    )
    if missing:
        return _configuration_failure(
            run_id=run_id,
            message="target.boot requires acknowledged destructive permissions before booting",
            details={"code": "permission_required", "required_permissions": missing},
        )

    provider = runtime.boot_provider or LibvirtQemuProvider()

    return _boot_under_locks(
        store=store,
        run_id=run_id,
        target_ref=target_ref,
        resolved_target_profile=resolved_target_profile,
        resolved_rootfs_profile=resolved_rootfs_profile,
        kernel_image=kernel_image,
        force_reboot=force_reboot,
        has_new_boot_overrides=has_new_boot_overrides,
        existing=existing,
        provider=provider,
        admission=runtime.admission,
    )
