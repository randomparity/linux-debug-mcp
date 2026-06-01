from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from kdive.artifacts.manifest import RunManifest
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import (
    INTROSPECT_DESTRUCTIVE_PERMISSIONS,
    MAX_INTROSPECT_CALLS_PER_RUN,
    DebugProfile,
    RootfsProfile,
    TargetProfile,
    missing_destructive_permissions,
)
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.debug.policy import ensure_debug_operation_enabled, resolve_debug_profile
from kdive.domain import ErrorCategory, ToolResponse
from kdive.handlers.shared import configuration_failure_response as _configuration_failure
from kdive.introspect.models import DebugIntrospectRunRequest
from kdive.introspect.wrappers import SCRIPT_BYTE_CAP
from kdive.providers.debug import ProviderDebugError
from kdive.providers.ssh import SshRunner
from kdive.safety.redaction import Redactor
from kdive.symbols.verify import BUILD_ID_RE


def _require_value(value: Any | None, message: str) -> Any:
    if value is None:
        raise RuntimeError(message)
    return value


_INTROSPECT_STEP_NAME_RE = re.compile(r"^introspect:")


def _count_introspect_calls(manifest: RunManifest) -> int:
    """Spec §5.2 step 4a / R3-F5. Named so tests can monkey-patch it."""
    return sum(1 for name in manifest.step_results if _INTROSPECT_STEP_NAME_RE.match(name))


@dataclass(frozen=True)
class LiveIntrospectRuntime:
    artifact_root: Path
    target_profiles: Mapping[str, TargetProfile] | None = None
    rootfs_profiles: Mapping[str, RootfsProfile] | None = None
    debug_profiles: Mapping[str, DebugProfile] | None = None
    ssh_runner: SshRunner | None = None
    admission: AdmissionService | None = None
    session_registry: SessionRegistry | None = None
    clock: Callable[[], datetime] | None = None


@dataclass(frozen=True)
class _LiveManifestContext:
    store: ArtifactStore
    manifest: RunManifest


@dataclass(frozen=True)
class _LiveIntrospectContext:
    store: ArtifactStore
    manifest: RunManifest
    resolved_rootfs: RootfsProfile
    resolved_debug: DebugProfile
    redactor: Redactor
    build_id: str


@dataclass(frozen=True)
class _LiveIntrospectPolicy:
    write_mode_permissions: list[str]
    use_sudo: bool


@dataclass(frozen=True)
class _LiveIntrospectPreAdmissionContext:
    store: ArtifactStore
    resolved_rootfs: RootfsProfile
    redactor: Redactor
    build_id: str
    write_mode_permissions: list[str]
    use_sudo: bool


def _load_validate_manifest_context(
    *, artifact_root: Path, run_id: str
) -> tuple[_LiveManifestContext | None, ToolResponse | None]:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return None, _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return None, ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    return _LiveManifestContext(store=store, manifest=manifest), None


def _manifest_profile_mismatch_response(
    *,
    run_id: str,
    profile_kind: str,
    requested_profile: str | None,
    manifest_profile: str | None,
) -> ToolResponse:
    return _configuration_failure(
        run_id=run_id,
        message=f"{profile_kind}_profile must match the immutable run manifest request",
        details={
            "requested_profile": requested_profile,
            "manifest_profile": manifest_profile,
            "code": "manifest_profile_mismatch",
        },
    )


def _validate_live_introspect_manifest_binding(
    *, request: DebugIntrospectRunRequest, manifest: RunManifest
) -> ToolResponse | None:
    run_id = request.run_id
    if request.target_profile is not None and request.target_profile != manifest.request.target_profile:
        return _manifest_profile_mismatch_response(
            run_id=run_id,
            profile_kind="target",
            requested_profile=request.target_profile,
            manifest_profile=manifest.request.target_profile,
        )
    if request.rootfs_profile is not None and request.rootfs_profile != manifest.request.rootfs_profile:
        return _manifest_profile_mismatch_response(
            run_id=run_id,
            profile_kind="rootfs",
            requested_profile=request.rootfs_profile,
            manifest_profile=manifest.request.rootfs_profile,
        )
    if (
        manifest.request.debug_profile is not None
        and request.debug_profile is not None
        and request.debug_profile != manifest.request.debug_profile
    ):
        return _manifest_profile_mismatch_response(
            run_id=run_id,
            profile_kind="debug",
            requested_profile=request.debug_profile,
            manifest_profile=manifest.request.debug_profile,
        )
    if request.manifest_target_profile != manifest.request.target_profile:
        return _configuration_failure(
            run_id=run_id,
            message="manifest_target_profile must match the immutable run manifest target_profile",
            details={
                "requested_target_profile": request.manifest_target_profile,
                "manifest_target_profile": manifest.request.target_profile,
                "code": "manifest_profile_mismatch",
            },
        )
    return None


def _build_id_from_boot_provenance(*, run_id: str, manifest: RunManifest) -> tuple[str | None, ToolResponse | None]:
    boot_step = manifest.step_results.get("boot")
    provenance = boot_step.details.get("kernel_provenance") if boot_step is not None else None
    if not isinstance(provenance, dict):
        capture_error = boot_step.details.get("kernel_provenance_capture_error") if boot_step is not None else None
        if isinstance(capture_error, dict):
            return None, ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                run_id=run_id,
                message=(f"boot did not record a KernelProvenance: {capture_error.get('message', 'capture failed')}"),
                details={
                    "code": "provenance_missing",
                    "capture_error": capture_error.get("code"),
                },
            )
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(
                "boot for this run did not record a KernelProvenance (it predates "
                "provenance capture). Re-run target.boot with force_reboot=true; a "
                "plain re-run short-circuits the recorded SUCCEEDED boot and will "
                "not re-capture provenance."
            ),
            details={"code": "provenance_missing"},
        )
    build_id = provenance.get("build_id")
    if not isinstance(build_id, str) or not BUILD_ID_RE.match(build_id):
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="recorded build_id is malformed",
            details={"code": "provenance_corrupt", "recorded": str(build_id)},
        )
    return build_id, None


def _resolve_live_introspect_context(
    *,
    request: DebugIntrospectRunRequest,
    manifest_context: _LiveManifestContext,
    rootfs_profiles: Mapping[str, RootfsProfile],
    debug_profiles: Mapping[str, DebugProfile],
) -> tuple[_LiveIntrospectContext | None, ToolResponse | None]:
    manifest = manifest_context.manifest
    run_id = request.run_id
    binding_failure = _validate_live_introspect_manifest_binding(request=request, manifest=manifest)
    if binding_failure is not None:
        return None, binding_failure

    rootfs_name = request.rootfs_profile or manifest.request.rootfs_profile
    try:
        resolved_rootfs = rootfs_profiles[rootfs_name]
    except KeyError:
        return None, _configuration_failure(run_id=run_id, message=f"unknown rootfs profile: {rootfs_name}")

    debug_name = request.debug_profile or manifest.request.debug_profile or "qemu-gdbstub-default"
    try:
        resolved_debug = resolve_debug_profile(profile_name=debug_name, debug_profiles=debug_profiles)
    except ProviderDebugError as exc:
        return None, ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id, details=exc.details)

    redactor = Redactor(secret_values=[resolved_rootfs.ssh_key_ref] if resolved_rootfs.ssh_key_ref else [])
    build_id, build_id_failure = _build_id_from_boot_provenance(run_id=run_id, manifest=manifest)
    if build_id_failure is not None:
        return None, build_id_failure
    return (
        _LiveIntrospectContext(
            store=manifest_context.store,
            manifest=manifest,
            resolved_rootfs=resolved_rootfs,
            resolved_debug=resolved_debug,
            redactor=redactor,
            build_id=_require_value(build_id, "build_id missing after successful provenance resolution"),
        ),
        None,
    )


def _enforce_live_introspect_policy(
    *,
    request: DebugIntrospectRunRequest,
    context: _LiveIntrospectContext,
    operation_name: str,
) -> tuple[_LiveIntrospectPolicy | None, ToolResponse | None]:
    run_id = request.run_id
    try:
        ensure_debug_operation_enabled(context.resolved_debug, operation_name)
    except ProviderDebugError as exc:
        return None, ToolResponse.failure(
            category=exc.category,
            message=str(exc),
            run_id=run_id,
            details={**exc.details, "code": "operation_disabled"},
        )

    if request.allow_write:
        try:
            ensure_debug_operation_enabled(context.resolved_debug, "debug.introspect.write")
        except ProviderDebugError as exc:
            return None, ToolResponse.failure(
                category=exc.category,
                message=str(exc),
                run_id=run_id,
                details={**exc.details, "code": "operation_disabled"},
            )
        missing = missing_destructive_permissions(
            operation_name,
            request.acknowledged_permissions,
            registry=INTROSPECT_DESTRUCTIVE_PERMISSIONS,
        )
        if missing:
            return None, ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                run_id=run_id,
                message=(
                    "debug.introspect.run write mode is destructive; acknowledge its required permissions to proceed"
                ),
                details={"code": "permission_required", "required_permissions": missing},
            )
    write_mode_permissions = (
        list(INTROSPECT_DESTRUCTIVE_PERMISSIONS.get(operation_name, [])) if request.allow_write else []
    )
    if not (5 <= request.timeout_seconds <= 300):
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"timeout_seconds must be in [5, 300]; got {request.timeout_seconds}",
            details={"code": "invalid_timeout"},
        )
    script_bytes = request.script.encode("utf-8")
    if not script_bytes:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message="script must not be empty",
            details={"code": "invalid_script"},
        )
    if len(script_bytes) > SCRIPT_BYTE_CAP:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"script exceeds {SCRIPT_BYTE_CAP} bytes",
            details={"code": "invalid_script"},
        )
    if _count_introspect_calls(context.manifest) >= MAX_INTROSPECT_CALLS_PER_RUN:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(
                f"introspect call budget exhausted (>= {MAX_INTROSPECT_CALLS_PER_RUN}); "
                "start a new run via kernel.create_run"
            ),
            details={"code": "manifest_call_budget_exhausted"},
        )
    sensitive_dir = context.store.run_dir(run_id) / "sensitive"
    try:
        mode = sensitive_dir.stat().st_mode & 0o777
    except FileNotFoundError:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(f"{sensitive_dir} is missing; re-run kernel.create_run to recreate the run layout."),
            details={"code": "sensitive_dir_missing"},
        )
    if mode & 0o077:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(
                f"{sensitive_dir} mode is {oct(mode)}; expected 0o700. "
                "Re-run kernel.create_run, or chmod 0700 the directory."
            ),
            details={"code": "sensitive_dir_too_permissive", "actual_mode": oct(mode)},
        )
    return (
        _LiveIntrospectPolicy(
            write_mode_permissions=write_mode_permissions,
            use_sudo=context.resolved_rootfs.ssh_user != "root",
        ),
        None,
    )


def _resolve_pre_admission_introspect_context(
    *,
    request: DebugIntrospectRunRequest,
    artifact_root: Path,
    rootfs_profiles: Mapping[str, RootfsProfile],
    debug_profiles: Mapping[str, DebugProfile],
    operation_name: str,
) -> tuple[_LiveIntrospectPreAdmissionContext | None, ToolResponse | None]:
    manifest_context, manifest_failure = _load_validate_manifest_context(
        artifact_root=artifact_root, run_id=request.run_id
    )
    if manifest_failure is not None:
        return None, manifest_failure

    context, context_failure = _resolve_live_introspect_context(
        request=request,
        manifest_context=_require_value(manifest_context, "manifest context missing after successful load"),
        rootfs_profiles=rootfs_profiles,
        debug_profiles=debug_profiles,
    )
    if context_failure is not None:
        return None, context_failure
    context = _require_value(context, "live introspect context missing after successful resolution")

    policy, policy_failure = _enforce_live_introspect_policy(
        request=request,
        context=context,
        operation_name=operation_name,
    )
    if policy_failure is not None:
        return None, policy_failure
    policy = _require_value(policy, "live introspect policy missing after successful enforcement")

    return (
        _LiveIntrospectPreAdmissionContext(
            store=context.store,
            resolved_rootfs=context.resolved_rootfs,
            redactor=context.redactor,
            build_id=context.build_id,
            write_mode_permissions=policy.write_mode_permissions,
            use_sudo=policy.use_sudo,
        ),
        None,
    )
