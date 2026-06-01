from __future__ import annotations

from datetime import UTC, datetime

from kdive.default_profiles import DEFAULT_DEBUG_PROFILES, DEFAULT_ROOTFS_PROFILES
from kdive.domain import ToolResponse
from kdive.introspect.context import (
    LiveIntrospectRuntime,
)
from kdive.introspect.context import (
    _require_value as _require_introspect_value,
)
from kdive.introspect.context import (
    _resolve_pre_admission_introspect_context as _resolve_pre_admission,
)
from kdive.introspect.models import DebugIntrospectRunRequest
from kdive.introspect.result import (
    IntrospectPostValidator,
)
from kdive.introspect.runner import (
    _admit_introspect_call as _admit_call,
)
from kdive.introspect.runner import (
    _execute_admitted_introspect_ssh as _execute_admitted_ssh,
)
from kdive.introspect.runner import (
    _run_introspect_sudo_preflight as _run_sudo_preflight,
)
from kdive.providers.ssh import SshRunner, SubprocessSshRunner


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _execute_introspect_call(
    request: DebugIntrospectRunRequest,
    *,
    runtime: LiveIntrospectRuntime,
    operation_name: str = "debug.introspect.run",
    caps: dict[str, int] | None = None,
    post_validator: IntrospectPostValidator | None = None,
) -> ToolResponse:
    """Shared core for `debug.introspect.run` (§5.2) and `debug.introspect.helper`
    (§6). Execute a user-supplied drgn Python script over SSH against a live
    target VM and return structured JSON.
    """
    run_id = request.run_id
    now = runtime.clock or _utcnow

    rootfs_profiles = runtime.rootfs_profiles if runtime.rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    debug_profiles = runtime.debug_profiles if runtime.debug_profiles is not None else DEFAULT_DEBUG_PROFILES

    pre_admission, pre_admission_failure = _resolve_pre_admission(
        request=request,
        artifact_root=runtime.artifact_root,
        rootfs_profiles=rootfs_profiles,
        debug_profiles=debug_profiles,
        operation_name=operation_name,
    )
    if pre_admission_failure is not None:
        return pre_admission_failure
    pre_admission = _require_introspect_value(
        pre_admission, "pre-admission context missing after successful resolution"
    )

    runner: SshRunner = runtime.ssh_runner or SubprocessSshRunner()

    # Spec §5.2 step 5: sudo preflight (only when sudo is needed).
    if pre_admission.use_sudo:
        preflight_failure = _run_sudo_preflight(
            runner=runner,
            store=pre_admission.store,
            run_id=run_id,
            resolved_rootfs=pre_admission.resolved_rootfs,
            redactor=pre_admission.redactor,
        )
        if preflight_failure is not None:
            return preflight_failure

    # Spec §5.2 step 6: admission gate.
    introspect_admission, admission_failure = _admit_call(
        admission=runtime.admission,
        session_registry=runtime.session_registry,
        run_id=run_id,
    )
    if admission_failure is not None:
        return admission_failure
    admission = _require_introspect_value(runtime.admission, "admission service missing after successful admission")
    introspect_admission = _require_introspect_value(
        introspect_admission, "admission handle missing after successful admission"
    )

    return _execute_admitted_ssh(
        request=request,
        pre_admission=pre_admission,
        runner=runner,
        admission=admission,
        introspect_admission=introspect_admission,
        now=now,
        operation_name=operation_name,
        caps=caps,
        post_validator=post_validator,
    )


__all__ = (
    "LiveIntrospectRuntime",
    "_execute_introspect_call",
)
