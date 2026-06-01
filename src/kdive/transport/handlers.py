from __future__ import annotations

from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import missing_destructive_permissions
from kdive.coordination.admission import AdmissionError, AdmissionService, require_target_snapshot
from kdive.coordination.endpoint_safety import EndpointSafetyError
from kdive.coordination.registry import SessionRegistry
from kdive.debug.policy import ensure_debug_operation_enabled, halt_debug_transport, resolve_debug_profile
from kdive.domain import ErrorCategory, ToolResponse
from kdive.handlers.shared import configuration_failure_response as _configuration_failure
from kdive.providers.debug import ProviderDebugError
from kdive.safety.redaction import Redactor
from kdive.seams.guard import GuardConflict
from kdive.seams.target import TargetKey
from kdive.transport.core.base import ExecutionState, LineRole, OpenRequest, TransportSession
from kdive.transport.core.break_inject import InjectBreakError
from kdive.transport.tools import (
    TransportCloseHandlerRequest,
    TransportInjectBreakHandlerRequest,
    TransportOpenHandlerRequest,
    TransportToolContext,
)


def _transport_disabled_failure(*, run_id: str) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message="transport coordination is not available on this server instance",
        run_id=run_id,
        details={"code": "transport_unavailable"},
    )


def _transaction_exception_failure(
    *,
    run_id: str,
    exc: Exception,
    code: str,
    redactor: Redactor,
) -> ToolResponse:
    category = exc.category if isinstance(exc, ProviderDebugError) else ErrorCategory.INFRASTRUCTURE_FAILURE
    details = dict(exc.details) if isinstance(exc, ProviderDebugError) else {}
    details.update({"code": code, "exception_type": type(exc).__name__})
    return ToolResponse.failure(
        category=category,
        message=redactor.redact_text(str(exc)),
        run_id=run_id,
        details=redactor.redact_value(details),
        suggested_next_actions=["providers.list"],
    )


def _transport_open_request(*, run_id: str, admission: AdmissionService) -> OpenRequest:
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = require_target_snapshot(admission, target_key)
    rsp_channel = next((ref for ref in snapshot.transports if ref.line_role is LineRole.RSP), None)
    if rsp_channel is None:
        raise AdmissionError(
            "authoritative snapshot exposes no RSP channel for a stop-capable open",
            category=ErrorCategory.READINESS_FAILURE,
            code="no_rsp_channel",
        )
    return OpenRequest(
        target_key=target_key,
        generation=snapshot.generation,
        transport_ref=rsp_channel,
        required_caps=["rsp"],
        platform=snapshot.platform,
    )


def transport_open_handler(
    *,
    request: TransportOpenHandlerRequest,
    runtime: TransportToolContext,
) -> ToolResponse:
    run_id = request.run_id
    transaction = runtime.transaction
    admission = runtime.admission
    session_registry = runtime.session_registry
    if transaction is None or admission is None or session_registry is None:
        return _transport_disabled_failure(run_id=run_id)
    redactor = Redactor()
    try:
        open_request = _transport_open_request(run_id=run_id, admission=admission)
        session = transaction.open(open_request, recovery=request.recovery)
    except KeyError:
        return _configuration_failure(
            run_id=run_id,
            message=redactor.redact_text(
                f"no transport provider registered for {open_request.transport_ref.provider!r}"
            ),
            details=redactor.redact_value({"code": "unknown_transport_provider"}),
        )
    except (GuardConflict, EndpointSafetyError) as exc:
        return ToolResponse.failure(
            category=ErrorCategory.TRANSPORT_CONFLICT,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value({"code": getattr(exc, "code", "stop_capable_conflict")}),
            suggested_next_actions=["providers.list"],
        )
    except AdmissionError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value({"code": exc.code}),
            suggested_next_actions=["providers.list"],
        )
    except ProviderDebugError as exc:
        return _transaction_exception_failure(
            run_id=run_id,
            exc=exc,
            code="transport_open_failed",
            redactor=redactor,
        )
    except Exception as exc:
        return _transaction_exception_failure(
            run_id=run_id,
            exc=exc,
            code="transport_open_failed",
            redactor=redactor,
        )
    return ToolResponse.success(
        summary=f"transport session {session.session_id} open",
        run_id=run_id,
        data={
            "session_id": session.session_id,
            "provider": session.provider,
            "channel_id": session.channel_id,
            "generation": session.generation,
            "rsp_endpoint": session.rsp_endpoint.model_dump(mode="json") if session.rsp_endpoint else None,
            "console_endpoint": session.console_endpoint.model_dump(mode="json") if session.console_endpoint else None,
        },
        suggested_next_actions=["debug.start_session"],
    )


def _resolve_session_for_run(
    *,
    session_registry: SessionRegistry,
    session_id: str,
    run_id: str,
) -> TransportSession | None:
    record = next((r for r in session_registry.list_records() if r.session_id == session_id), None)
    if record is None:
        return None
    target_key = record.target_key
    if target_key.provisioner != "local-qemu" or target_key.target_id != run_id:
        raise _SessionRunMismatch(
            f"session {session_id!r} belongs to target {target_key.provisioner}/{target_key.target_id}, "
            f"not run {run_id!r}"
        )
    return record


class _SessionRunMismatch(ValueError):
    pass


def _transport_inject_break_profile_gate(
    *,
    request: TransportInjectBreakHandlerRequest,
    runtime: TransportToolContext,
) -> ToolResponse | None:
    run_id = request.run_id
    missing = missing_destructive_permissions("transport.inject_break", request.acknowledged_permissions or [])
    if missing:
        return _configuration_failure(
            run_id=run_id,
            message="transport.inject_break is destructive; acknowledge its required permissions to proceed",
            details={"code": "permission_required", "required_permissions": missing},
        )

    requested_profile = "qemu-gdbstub-default"
    if request.artifact_root is not None:
        try:
            store = ArtifactStore(request.artifact_root, create_root=False)
            requested_profile = store.load_manifest(run_id).request.debug_profile or "qemu-gdbstub-default"
        except (ManifestStateError, OSError) as exc:
            return _configuration_failure(
                run_id=run_id,
                message=f"failed to load run manifest for transport.inject_break: {exc}",
                details={"code": "manifest_load_failed"},
            )
    try:
        resolved_profile = resolve_debug_profile(profile_name=requested_profile, debug_profiles=runtime.debug_profiles)
        ensure_debug_operation_enabled(resolved_profile, "transport.inject_break")
    except ProviderDebugError as exc:
        return _configuration_failure(run_id=run_id, message=str(exc), details=exc.details)
    return None


def _break_unconfirmed_failure(
    *,
    run_id: str,
    category: ErrorCategory,
    message: str,
    redactor: Redactor,
    extra_details: dict[str, object] | None = None,
) -> ToolResponse:
    details = {
        **(extra_details or {}),
        "code": "break_unconfirmed",
        "execution_state": ExecutionState.UNKNOWN.value,
    }
    return ToolResponse.failure(
        category=category,
        message=redactor.redact_text(message),
        run_id=run_id,
        details=redactor.redact_value(details),
        suggested_next_actions=["providers.list"],
    )


def _probe_injected_break(
    *,
    runtime: TransportToolContext,
    record: TransportSession,
    redactor: Redactor,
) -> tuple[bool, dict[str, object]]:
    try:
        return runtime.probe_halted(record), {}
    except Exception as exc:
        return False, {
            "probe_code": "probe_failed",
            "exception_type": type(exc).__name__,
            "exception_message": redactor.redact_text(str(exc)),
        }


def transport_close_handler(
    *,
    request: TransportCloseHandlerRequest,
    runtime: TransportToolContext,
) -> ToolResponse:
    run_id = request.run_id
    session_id = request.session_id
    transaction = runtime.transaction
    session_registry = runtime.session_registry
    if transaction is None or session_registry is None:
        return _transport_disabled_failure(run_id=run_id)
    try:
        record = _resolve_session_for_run(session_registry=session_registry, session_id=session_id, run_id=run_id)
    except _SessionRunMismatch as exc:
        return _configuration_failure(
            run_id=run_id,
            message=str(exc),
            details={"code": "session_run_mismatch"},
        )
    if record is None:
        return ToolResponse.success(
            summary=f"transport session {session_id} already closed",
            run_id=run_id,
            data={"session_id": session_id, "already_closed": True},
            suggested_next_actions=["transport.open"],
        )
    redactor = Redactor()
    try:
        transaction.close(session_id)
    except ProviderDebugError as exc:
        return _transaction_exception_failure(
            run_id=run_id,
            exc=exc,
            code="transport_close_failed",
            redactor=redactor,
        )
    except Exception as exc:
        return _transaction_exception_failure(
            run_id=run_id,
            exc=exc,
            code="transport_close_failed",
            redactor=redactor,
        )
    return ToolResponse.success(
        summary=f"transport session {session_id} closed",
        run_id=run_id,
        data={"session_id": session_id, "already_closed": False},
        suggested_next_actions=["transport.open"],
    )


def transport_inject_break_handler(
    *,
    request: TransportInjectBreakHandlerRequest,
    runtime: TransportToolContext,
) -> ToolResponse:
    run_id = request.run_id
    session_id = request.session_id
    transaction = runtime.transaction
    admission = runtime.admission
    session_registry = runtime.session_registry
    if transaction is None or admission is None or session_registry is None:
        return _transport_disabled_failure(run_id=run_id)
    profile_failure = _transport_inject_break_profile_gate(request=request, runtime=runtime)
    if profile_failure is not None:
        return profile_failure
    try:
        record = _resolve_session_for_run(
            session_registry=session_registry,
            session_id=session_id,
            run_id=run_id,
        )
    except _SessionRunMismatch as exc:
        return _configuration_failure(
            run_id=run_id,
            message=str(exc),
            details={"code": "session_run_mismatch"},
        )
    if record is None:
        return _configuration_failure(
            run_id=run_id,
            message=f"no open transport session for break injection: {session_id}",
            details={"code": "unknown_session"},
        )
    halt_debug_transport(session=record, admission=admission, session_registry=session_registry)
    redactor = Redactor()
    try:
        if runtime.break_mechanism is None:
            transaction.inject_break_for_session(session_id, "auto")
        else:
            runtime.break_mechanism(method="auto", break_plan=record.break_plan)
    except InjectBreakError as exc:
        session_registry.write_record(record.model_copy(update={"execution_state": ExecutionState.UNKNOWN}))
        return _break_unconfirmed_failure(
            run_id=run_id,
            category=exc.category,
            message=str(exc),
            redactor=redactor,
            extra_details=dict(getattr(exc, "details", {}) or {}),
        )
    except Exception as exc:
        session_registry.write_record(record.model_copy(update={"execution_state": ExecutionState.UNKNOWN}))
        return _break_unconfirmed_failure(
            run_id=run_id,
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=f"break mechanism failed unexpectedly: {exc}",
            redactor=redactor,
        )

    halted_observed, probe_failure_details = _probe_injected_break(
        runtime=runtime,
        record=record,
        redactor=redactor,
    )
    if not halted_observed:
        session_registry.write_record(record.model_copy(update={"execution_state": ExecutionState.UNKNOWN}))
        return _break_unconfirmed_failure(
            run_id=run_id,
            category=ErrorCategory.DEBUG_ATTACH_FAILURE,
            message="inject_break: post-probe did not confirm HALTED",
            redactor=redactor,
            extra_details={
                "probe_observed": ExecutionState.UNKNOWN.value,
                **probe_failure_details,
            },
        )
    return ToolResponse.success(
        summary=f"break injected on transport session {session_id}; target halted",
        run_id=run_id,
        data={"session_id": session_id, "execution_state": ExecutionState.HALTED.value},
        suggested_next_actions=["debug.start_session"],
    )
