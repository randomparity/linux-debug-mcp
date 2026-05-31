from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from kdive.config import DebugProfile, RootfsProfile, TargetProfile
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.domain import DebugIntrospectHelperRequest, DebugIntrospectRunRequest, ErrorCategory, ToolResponse
from kdive.introspect.execution import (
    HELPER_CAP_PROFILE,
    IntrospectPostValidator,
    _execute_introspect_call,
    _make_helper_post_validator,
    _redact_and_truncate,
)
from kdive.introspect_helpers import get_helper_registry
from kdive.providers.local.local_ssh_tests import SshRunner
from kdive.safety.redaction import Redactor


def _execute_live_introspect_call(
    request: DebugIntrospectRunRequest,
    *,
    artifact_root: Path,
    target_profiles: dict[str, TargetProfile] | None,
    rootfs_profiles: dict[str, RootfsProfile] | None,
    debug_profiles: dict[str, DebugProfile] | None,
    ssh_runner: SshRunner | None,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
    clock: Callable[[], datetime] | None,
    operation_name: str,
    caps: dict[str, int] | None,
    post_validator: IntrospectPostValidator | None,
) -> ToolResponse:
    return _execute_introspect_call(
        request,
        artifact_root=artifact_root,
        target_profiles=target_profiles,
        rootfs_profiles=rootfs_profiles,
        debug_profiles=debug_profiles,
        ssh_runner=ssh_runner,
        admission=admission,
        session_registry=session_registry,
        clock=clock,
        operation_name=operation_name,
        caps=caps,
        post_validator=post_validator,
    )


def debug_introspect_run_handler(
    request: DebugIntrospectRunRequest,
    *,
    artifact_root: Path,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    return _execute_live_introspect_call(
        request,
        artifact_root=artifact_root,
        target_profiles=target_profiles,
        rootfs_profiles=rootfs_profiles,
        debug_profiles=debug_profiles,
        ssh_runner=ssh_runner,
        admission=admission,
        session_registry=session_registry,
        clock=clock,
        operation_name="debug.introspect.run",
        caps=None,
        post_validator=None,
    )


def debug_introspect_helper_handler(
    request: DebugIntrospectHelperRequest,
    *,
    artifact_root: Path,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    helper_registry = get_helper_registry()
    spec = helper_registry.get(request.name)
    if spec is None:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=request.run_id,
            message=f"unknown helper {request.name!r}; valid: {sorted(helper_registry)}",
            details={"code": "unknown_helper", "valid": sorted(helper_registry)},
            suggested_next_actions=["debug.introspect.helper"],
        )
    try:
        validated_args = spec.args_model.model_validate(request.args)
    except ValidationError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=request.run_id,
            message=_redact_and_truncate(Redactor(), str(exc), cap=512),
            details={"code": "helper_args_invalid"},
            suggested_next_actions=["debug.introspect.helper"],
        )
    run_request = DebugIntrospectRunRequest(
        run_id=request.run_id,
        manifest_target_profile=request.manifest_target_profile,
        script=spec.script,
        timeout_seconds=request.timeout_seconds,
        allow_write=False,
        debug_profile=request.debug_profile,
        target_profile=request.target_profile,
        rootfs_profile=request.rootfs_profile,
        args=validated_args.model_dump(mode="json"),
    )
    return _execute_live_introspect_call(
        run_request,
        artifact_root=artifact_root,
        target_profiles=target_profiles,
        rootfs_profiles=rootfs_profiles,
        debug_profiles=debug_profiles,
        ssh_runner=ssh_runner,
        admission=admission,
        session_registry=session_registry,
        clock=clock,
        operation_name="debug.introspect.helper",
        caps=HELPER_CAP_PROFILE,
        post_validator=_make_helper_post_validator(spec),
    )
