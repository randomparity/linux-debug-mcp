from __future__ import annotations

import contextlib
from dataclasses import dataclass
from pathlib import Path

from kdive.artifacts.redaction import redacted_artifacts
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.contracts import (
    DebugBacktraceRequest,
    DebugClearBreakpointRequest,
    DebugClearWatchpointRequest,
    DebugContinueRequest,
    DebugEvaluateRequest,
    DebugFinishRequest,
    DebugInterruptRequest,
    DebugListBreakpointsRequest,
    DebugListVariablesRequest,
    DebugNextRequest,
    DebugOperationRequest,
    DebugReadMemoryRequest,
    DebugReadRegistersRequest,
    DebugReadSymbolRequest,
    DebugRuntime,
    DebugSetBreakpointRequest,
    DebugSetWatchpointRequest,
    DebugStepRequest,
)
from kdive.debug.policy import ensure_debug_operation_enabled, resolve_debug_profile
from kdive.debug.session_state import (
    debug_session_manifest_details,
    enforce_debug_ownership_fence,
    load_active_debug_session,
    mi_session_artifacts,
    persist_mi_debug_session,
    preserved_debug_step_details,
    recorded_transport_session_id,
    teardown_stalled_debug_session,
)
from kdive.domain import ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.handlers.shared import configuration_failure_response as _configuration_failure
from kdive.providers.debug import (
    MAX_INTERACTIVE_WAIT_SEC,
    MAX_MEMORY_READ_BYTES,
    DebugSession,
    DebugSessionState,
    GdbMiAttachment,
    GdbMiEngine,
    GdbMiError,
    GdbMiSessionRegistry,
    ProviderDebugError,
)
from kdive.safety.redaction import Redactor
from kdive.seams.guard import SessionGuard
from kdive.seams.transport_state import BreakMethod, TransportSession
from kdive.transport.core.break_inject import InjectBreakError


@dataclass(frozen=True)
class _DebugOpSuccess:
    data: dict[str, object]
    session: DebugSession


@dataclass(frozen=True)
class _DebugOpFailure:
    category: ErrorCategory
    message: str
    details: dict[str, object]
    suggested_next_actions: list[str]

    def to_tool_response(self, *, run_id: str, redactor: Redactor) -> ToolResponse:
        return ToolResponse.failure(
            category=self.category,
            message=redactor.redact_text(self.message),
            run_id=run_id,
            details=redactor.redact_value(self.details),
            suggested_next_actions=self.suggested_next_actions,
        )


_BREAKPOINT_MUTATOR_TYPES = (
    DebugSetBreakpointRequest,
    DebugSetWatchpointRequest,
    DebugClearBreakpointRequest,
    DebugClearWatchpointRequest,
)


def _execution_timeout(timeout_seconds: int | None) -> int:
    return timeout_seconds if timeout_seconds is not None else MAX_INTERACTIVE_WAIT_SEC


def _engine_op_data(
    *, engine: GdbMiEngine, attachment: GdbMiAttachment, request: DebugOperationRequest
) -> dict[str, object]:
    """Dispatch one typed debug.* request onto the live gdb/MI attachment and return redacted JSON data.

    ``end_session`` has a dedicated reap path and is not routed through this function.
    """
    if isinstance(request, DebugReadRegistersRequest):
        return engine.read_registers(attachment, [str(name) for name in request.registers])
    if isinstance(request, DebugReadSymbolRequest):
        return engine.read_symbol(attachment, request.symbol)
    if isinstance(request, DebugReadMemoryRequest):
        if request.address < 0:
            raise GdbMiError(
                f"address must be non-negative, got {request.address}",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        if not 0 < request.byte_count <= MAX_MEMORY_READ_BYTES:
            raise GdbMiError(
                f"byte_count must be in 1..{MAX_MEMORY_READ_BYTES}, got {request.byte_count}",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        return engine.read_memory(attachment, address=request.address, byte_count=request.byte_count)
    if isinstance(request, DebugEvaluateRequest):
        evaluate_args = {str(key): value for key, value in request.arguments.items()}
        return engine.evaluate_inspector(attachment, inspector=request.inspector, arguments=evaluate_args)
    if isinstance(request, DebugSetBreakpointRequest):
        return {"breakpoint": engine.set_breakpoint(attachment, request.symbol).model_dump(mode="json")}
    if isinstance(request, DebugSetWatchpointRequest):
        return {"breakpoint": engine.set_watchpoint(attachment, request.symbol).model_dump(mode="json")}
    if isinstance(request, DebugClearBreakpointRequest):
        engine.clear_breakpoint(attachment, request.breakpoint_id)
        return {}
    if isinstance(request, DebugClearWatchpointRequest):
        engine.clear_watchpoint(attachment, request.breakpoint_id)
        return {}
    if isinstance(request, DebugListBreakpointsRequest):
        return {"breakpoints": [ref.model_dump(mode="json") for ref in engine.list_breakpoints(attachment)]}
    if isinstance(request, DebugBacktraceRequest):
        return {"frames": [frame.model_dump(mode="json") for frame in engine.backtrace(attachment)]}
    if isinstance(request, DebugListVariablesRequest):
        return {"variables": [var.model_dump(mode="json") for var in engine.list_variables(attachment)]}
    if isinstance(request, DebugContinueRequest):
        stop = engine.continue_(attachment, timeout_sec=_execution_timeout(request.timeout_seconds))
        return {"stop": stop.model_dump(mode="json"), "current_execution_state": DebugSessionState.STOPPED.value}
    if isinstance(request, DebugStepRequest):
        stop = engine.step(attachment, timeout_sec=_execution_timeout(request.timeout_seconds))
        return {"stop": stop.model_dump(mode="json"), "current_execution_state": DebugSessionState.STOPPED.value}
    if isinstance(request, DebugNextRequest):
        stop = engine.next(attachment, timeout_sec=_execution_timeout(request.timeout_seconds))
        return {"stop": stop.model_dump(mode="json"), "current_execution_state": DebugSessionState.STOPPED.value}
    if isinstance(request, DebugFinishRequest):
        stop = engine.finish(attachment, timeout_sec=_execution_timeout(request.timeout_seconds))
        return {"stop": stop.model_dump(mode="json"), "current_execution_state": DebugSessionState.STOPPED.value}
    raise GdbMiError(
        "unsupported debug operation",
        category=ErrorCategory.CONFIGURATION_ERROR,
        details={"operation": request.profile_operation},
    )


_INJECT_BREAK_STOP_TIMEOUT_SEC = 10.0


def _break_entry_method(transport_session: TransportSession | None) -> BreakMethod:
    """ADR 0024 decision 1: the break-entry method is whatever admission recorded in the session's
    ``break_plan`` — the tier never chooses or hardcodes it. Absent a record or a plan, default to
    the gdbstub's native interrupt (the loopback x86_64/QEMU path), which needs no injection."""
    if transport_session is None or transport_session.break_plan is None:
        return BreakMethod.GDBSTUB_NATIVE
    return transport_session.break_plan.method


def _lookup_transport_session(
    *,
    session_registry: SessionRegistry | None,
    artifact_root: Path,
    run_id: str,
    transaction: TransportTransaction | None,
) -> TransportSession | None:
    """Resolve the live ``TransportSession`` backing this debug run: read the bound
    ``transport_session_id`` start_session persisted into the debug step, then look the durable
    record up in the registry. None when the registry/transaction is unwired or no transport
    session was bound — the caller then defaults to the gdbstub-native interrupt."""
    if session_registry is None or transaction is None:
        return None
    transport_session_id = recorded_transport_session_id(artifact_root=artifact_root, run_id=run_id)
    if transport_session_id is None:
        return None
    return next((r for r in session_registry.list_records() if r.session_id == transport_session_id), None)


def _interrupt_op_data(
    *,
    engine: GdbMiEngine,
    attachment: GdbMiAttachment,
    transport_session: TransportSession | None,
    transaction: TransportTransaction | None,
) -> dict[str, object]:
    """Route ``debug.interrupt`` off the admitted break plan (ADR 0024). A gdbstub-native plan (or
    an absent record / unwired transaction) interrupts the inferior directly through the engine; any
    other admitted method is injected over the console via the transaction, then the engine waits the
    bounded window for the resulting stop. ``inject_break_for_session`` raises
    ``break_inject_unavailable`` when the transport exposes no break handle — never a silent no-op."""
    method = _break_entry_method(transport_session)
    if method is BreakMethod.GDBSTUB_NATIVE or transaction is None or transport_session is None:
        stop = engine.interrupt(attachment)
    else:
        transaction.inject_break_for_session(transport_session.session_id, method)
        stop = engine.wait_for_stop(attachment, timeout_sec=_INJECT_BREAK_STOP_TIMEOUT_SEC)
    # No stop within the window means the break is unconfirmed — report `unknown`, never an
    # optimistic `stopped`. An out-of-band break over a lossy console can be silently dropped, so
    # claiming HALTED would mislead the agent (matching the fail-closed posture of the dedicated
    # transport.inject_break tool, which post-probes and reports UNKNOWN when unconfirmed).
    if stop is None:
        return {"stop": None, "current_execution_state": DebugSessionState.UNKNOWN.value}
    return {"stop": stop.model_dump(mode="json"), "current_execution_state": DebugSessionState.STOPPED.value}


def _run_debug_engine_op(
    *,
    engine: GdbMiEngine,
    gdb_mi_sessions: GdbMiSessionRegistry,
    attachment: GdbMiAttachment,
    session: DebugSession,
    request: DebugOperationRequest,
    artifact_root: Path,
    run_id: str,
    transaction: TransportTransaction | None,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
    session_guard: SessionGuard | None,
) -> _DebugOpSuccess | _DebugOpFailure:
    """Run one debug.* op on the live attachment and rebuild the breakpoint ledger after a mutator
    (TD-09 — extracted from ``_debug_operation_response`` so the handler stays under the size limit).

    Returns a domain result object, not a public ``ToolResponse``. Benign typed exceptions are
    re-raised for the caller's outer handler; failures that require local teardown are returned as
    ``_DebugOpFailure`` and translated at the response boundary."""
    try:
        if isinstance(request, DebugInterruptRequest):
            data = _interrupt_op_data(
                engine=engine,
                attachment=attachment,
                transport_session=_lookup_transport_session(
                    session_registry=session_registry,
                    artifact_root=artifact_root,
                    run_id=run_id,
                    transaction=transaction,
                ),
                transaction=transaction,
            )
        else:
            data = _engine_op_data(engine=engine, attachment=attachment, request=request)
        updated_session = session
        if isinstance(request, _BREAKPOINT_MUTATOR_TYPES):
            ledger = {ref.number: ref.model_dump(mode="json") for ref in engine.list_breakpoints(attachment)}
            updated_session = session.model_copy(update={"breakpoints": ledger})
        return _DebugOpSuccess(data=data, session=updated_session)
    except GdbMiError as exc:
        if exc.details.get("code") == "transport_stall":
            reaped = gdb_mi_sessions.reap(session.session_id)
            if reaped is not None:
                with contextlib.suppress(Exception):
                    engine.force_resume(reaped)
            teardown_stalled_debug_session(
                run_id=run_id,
                admission=admission,
                session_registry=session_registry,
                transaction=transaction,
                session_guard=session_guard,
            )
            return _DebugOpFailure(
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                message=str(exc),
                details={"code": "transport_stall"},
                suggested_next_actions=["debug.start_session", "debug.kdb", "debug.introspect.run"],
            )
        raise
    except InjectBreakError as exc:
        return _DebugOpFailure(
            category=exc.category,
            message=str(exc),
            details=exc.details,
            suggested_next_actions=["debug.kdb", "debug.introspect.run", "artifacts.get_manifest"],
        )
    except ProviderDebugError:
        raise
    except Exception as exc:
        reaped = gdb_mi_sessions.reap(session.session_id)
        if reaped is not None:
            with contextlib.suppress(Exception):
                engine.force_resume(reaped)
        return _DebugOpFailure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=f"the gdb/MI engine faulted during debug.{request.summary_name}: {exc}",
            details={"code": "debug_engine_faulted"},
            suggested_next_actions=["debug.end_session", "artifacts.get_manifest"],
        )


def _persist_debug_op_details(
    *, store: ArtifactStore, run_id: str, request: DebugOperationRequest, session: DebugSession, data: dict[str, object]
) -> dict[str, object]:
    """Persist the post-op DebugSession + a SUCCEEDED ``debug`` step, returning the merged details
    (manifest details + preserved step details + op data). Extracted from _debug_operation_response
    (TD-09)."""
    persist_mi_debug_session(store=store, run_id=run_id, session=session)
    details = {
        **debug_session_manifest_details(store=store, run_id=run_id, session=session),
        **preserved_debug_step_details(store, run_id),
        **data,
    }
    terminal = StepResult(
        step_name="debug",
        status=StepStatus.SUCCEEDED,
        summary=f"debug.{request.summary_name} succeeded",
        artifacts=mi_session_artifacts(store=store, run_id=run_id, session=session),
        details=details,
    )
    store.record_step_result(run_id, terminal, replace_succeeded=True)
    return details


def _map_debug_op_exception(
    exc: Exception, *, run_id: str, request: DebugOperationRequest, redactor: Redactor
) -> ToolResponse:
    """Map the terminal exceptions of _debug_operation_response's op block to a structured failure
    (TD-09), preserving the original per-type handling order."""
    if isinstance(exc, ManifestStateError):
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    if isinstance(exc, ProviderDebugError):
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value(exc.details),
            artifacts=redacted_artifacts(exc.artifacts, redactor),
            suggested_next_actions=["debug.start_session", "artifacts.get_manifest"],
        )
    if isinstance(exc, GdbMiError):
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value(exc.details),
            suggested_next_actions=["debug.start_session", "artifacts.get_manifest"],
        )
    # OSError: the engine op already ran (live session healthy); only persist/record bookkeeping
    # faulted. Surface a structured failure WITHOUT reaping — the caller can retry the op.
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=redactor.redact_text(f"failed to record debug.{request.summary_name}: {exc}"),
        run_id=run_id,
        details={"code": "debug_session_op_record_failed"},
        suggested_next_actions=["debug.end_session", "artifacts.get_manifest"],
    )


def _debug_operation_response(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    request: DebugOperationRequest,
    runtime: DebugRuntime,
    allow_ended: bool = False,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    if runtime.gdb_mi_engine is None or runtime.gdb_mi_sessions is None:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message="the gdb/MI engine is not available on this server instance",
            run_id=run_id,
            details={"code": "debug_engine_unavailable"},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    redactor = Redactor()
    try:
        with store.debug_lock(run_id):
            session = load_active_debug_session(store, run_id, debug_session_id, allow_ended=allow_ended)
            admission = runtime.admission if request.requires_admission_fence else None
            # Operation metadata decides whether the legacy-session fence may tombstone the target.
            # Pure read operations still assert Layer-4 ownership through the registry, while
            # mutating/control operations use admission to mark recovery_required on legacy state.
            enforce_debug_ownership_fence(
                run_id=run_id,
                admission=admission,
                session_registry=runtime.session_registry,
            )
            profile = resolve_debug_profile(
                profile_name=session.selected_debug_profile,
                debug_profiles=runtime.debug_profiles,
            )
            ensure_debug_operation_enabled(profile, request.profile_operation)
            attachment = runtime.gdb_mi_sessions.require(session.session_id)
            # Every engine interaction for this op — the op itself AND the post-mutator ledger rebuild
            # (-break-list) — shares one guard (inside debug_lock, no concurrent op can require() a
            # stalled attachment). _run_debug_engine_op returns an internal success/failure result;
            # a benign GdbMiError/ProviderDebugError propagates to the outer handler below.
            op_result = _run_debug_engine_op(
                engine=runtime.gdb_mi_engine,
                gdb_mi_sessions=runtime.gdb_mi_sessions,
                attachment=attachment,
                session=session,
                request=request,
                artifact_root=artifact_root,
                run_id=run_id,
                transaction=runtime.transaction,
                admission=admission,
                session_registry=runtime.session_registry,
                session_guard=runtime.session_guard,
            )
            if isinstance(op_result, _DebugOpFailure):
                return op_result.to_tool_response(run_id=run_id, redactor=redactor)
            data = op_result.data
            updated_session = op_result.session
            if request.persist_manifest:
                details = _persist_debug_op_details(
                    store=store, run_id=run_id, request=request, session=updated_session, data=data
                )
            else:
                details = data
    except (ManifestStateError, ProviderDebugError, GdbMiError, OSError) as exc:
        return _map_debug_op_exception(exc, run_id=run_id, request=request, redactor=redactor)

    op_artifacts = mi_session_artifacts(store=store, run_id=run_id, session=updated_session)
    return ToolResponse.success(
        summary=f"debug.{request.summary_name} succeeded",
        run_id=run_id,
        data=redactor.redact_value(details),
        artifacts=redacted_artifacts(op_artifacts, redactor),
        suggested_next_actions=["artifacts.get_manifest"],
    )
