from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import ALLOWED_DEBUG_OPERATIONS, DebugProfile, missing_destructive_permissions
from kdive.coordination.admission import AdmissionError, AdmissionService
from kdive.coordination.endpoint_safety import EndpointSafetyError
from kdive.coordination.exec_probe import probe_rsp_halted
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.default_profiles import DEFAULT_DEBUG_PROFILES
from kdive.domain import ErrorCategory, ToolResponse
from kdive.providers.debug import ProviderDebugError
from kdive.safety.redaction import Redactor
from kdive.seams.guard import GuardConflict
from kdive.seams.target import TargetKey
from kdive.transport.core.base import BreakPlan, ExecutionState, LineRole, OpenRequest, TransportSession
from kdive.transport.core.break_inject import BreakRequestMethod, InjectBreakError


def _configuration_failure(*, run_id: str, message: str, details: dict[str, Any] | None = None) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
    )


def _ensure_debug_operation_enabled(profile: DebugProfile, operation: str) -> None:
    if operation not in set(ALLOWED_DEBUG_OPERATIONS):
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


def _require_snapshot(admission: AdmissionService, target_key: TargetKey):
    snapshot = admission.current_snapshot(target_key)
    if snapshot is None:
        raise AdmissionError(
            "no authoritative snapshot for target; boot must publish a READY snapshot first",
            category=ErrorCategory.READINESS_FAILURE,
            code="snapshot_missing",
        )
    return snapshot


def _halt_debug_transport(
    *,
    session: TransportSession,
    admission: AdmissionService,
    session_registry: SessionRegistry,
) -> None:
    session_registry.write_record(session.model_copy(update={"execution_state": ExecutionState.HALTED}))
    halt_epoch = admission.note_execution_transition(session.target_key, session.generation)
    admission.cancel_ssh_tier(session.target_key, session.generation, halt_epoch=halt_epoch)


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
    snapshot = _require_snapshot(admission, target_key)
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
    run_id: str,
    recovery: bool = False,
    transaction: TransportTransaction | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
) -> ToolResponse:
    if transaction is None or admission is None or session_registry is None:
        return _transport_disabled_failure(run_id=run_id)
    redactor = Redactor()
    try:
        request = _transport_open_request(run_id=run_id, admission=admission)
        session = transaction.open(request, recovery=recovery)
    except KeyError:
        return _configuration_failure(
            run_id=run_id,
            message=redactor.redact_text(f"no transport provider registered for {request.transport_ref.provider!r}"),
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


class BreakMechanism(Protocol):
    def __call__(self, *, method: BreakRequestMethod, break_plan: BreakPlan | None) -> None: ...


def transport_close_handler(
    *,
    run_id: str,
    session_id: str,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
) -> ToolResponse:
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
    run_id: str,
    session_id: str,
    acknowledged_permissions: list[str] | None = None,
    artifact_root: Path | None = None,
    transaction: TransportTransaction | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    break_mechanism: BreakMechanism | None = None,
    probe_halted: Callable[[TransportSession], bool] = probe_rsp_halted,
) -> ToolResponse:
    if transaction is None or admission is None or session_registry is None:
        return _transport_disabled_failure(run_id=run_id)
    missing = missing_destructive_permissions("transport.inject_break", acknowledged_permissions or [])
    if missing:
        return _configuration_failure(
            run_id=run_id,
            message="transport.inject_break is destructive; acknowledge its required permissions to proceed",
            details={"code": "permission_required", "required_permissions": missing},
        )
    requested_profile = "qemu-gdbstub-default"
    if artifact_root is not None:
        try:
            store = ArtifactStore(artifact_root, create_root=False)
            requested_profile = store.load_manifest(run_id).request.debug_profile or "qemu-gdbstub-default"
        except (ManifestStateError, OSError) as exc:
            return _configuration_failure(
                run_id=run_id,
                message=f"failed to load run manifest for transport.inject_break: {exc}",
                details={"code": "manifest_load_failed"},
            )
    try:
        resolved_profile = _resolve_debug_profile(profile_name=requested_profile, debug_profiles=debug_profiles)
        _ensure_debug_operation_enabled(resolved_profile, "transport.inject_break")
    except ProviderDebugError as exc:
        return _configuration_failure(run_id=run_id, message=str(exc), details=exc.details)
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
    _halt_debug_transport(session=record, admission=admission, session_registry=session_registry)
    redactor = Redactor()
    try:
        if break_mechanism is None:
            transaction.inject_break_for_session(session_id, "auto")
        else:
            break_mechanism(method="auto", break_plan=record.break_plan)
    except InjectBreakError as exc:
        session_registry.write_record(record.model_copy(update={"execution_state": ExecutionState.UNKNOWN}))
        exc_details = dict(getattr(exc, "details", {}) or {})
        details = redactor.redact_value(
            {
                **exc_details,
                "code": "break_unconfirmed",
                "execution_state": ExecutionState.UNKNOWN.value,
            }
        )
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=details,
            suggested_next_actions=["providers.list"],
        )
    except Exception as exc:
        session_registry.write_record(record.model_copy(update={"execution_state": ExecutionState.UNKNOWN}))
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=redactor.redact_text(f"break mechanism failed unexpectedly: {exc}"),
            run_id=run_id,
            details=redactor.redact_value(
                {"code": "break_unconfirmed", "execution_state": ExecutionState.UNKNOWN.value}
            ),
            suggested_next_actions=["providers.list"],
        )
    probe_failure_details: dict[str, object] = {}
    try:
        halted_observed = probe_halted(record)
    except Exception as exc:
        halted_observed = False
        probe_failure_details = {
            "probe_code": "probe_failed",
            "exception_type": type(exc).__name__,
            "exception_message": redactor.redact_text(str(exc)),
        }
    if not halted_observed:
        session_registry.write_record(record.model_copy(update={"execution_state": ExecutionState.UNKNOWN}))
        return ToolResponse.failure(
            category=ErrorCategory.DEBUG_ATTACH_FAILURE,
            message="inject_break: post-probe did not confirm HALTED",
            run_id=run_id,
            details=redactor.redact_value(
                {
                    "code": "break_unconfirmed",
                    "execution_state": ExecutionState.UNKNOWN.value,
                    "probe_observed": ExecutionState.UNKNOWN.value,
                    **probe_failure_details,
                }
            ),
            suggested_next_actions=["providers.list"],
        )
    return ToolResponse.success(
        summary=f"break injected on transport session {session_id}; target halted",
        run_id=run_id,
        data={"session_id": session_id, "execution_state": ExecutionState.HALTED.value},
        suggested_next_actions=["debug.start_session"],
    )
