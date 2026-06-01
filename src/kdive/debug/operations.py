from __future__ import annotations

import contextlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from kdive.artifacts.redaction import redacted_artifacts
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import RecoveryTombstone, SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.handlers import (
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
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.providers.debug import (
    MAX_INTERACTIVE_WAIT_SEC,
    MAX_MEMORY_READ_BYTES,
    DebugAttachStatus,
    DebugSession,
    DebugSessionState,
    GdbMiAttachment,
    GdbMiEngine,
    GdbMiError,
    GdbMiSessionRegistry,
    ProviderDebugError,
)
from kdive.safety.redaction import Redactor
from kdive.seams.guard import SessionGuard, SessionGuardContext
from kdive.seams.target import TargetKey
from kdive.transport.core.base import BreakMethod, ExecutionState, TransportSession
from kdive.transport.core.break_inject import InjectBreakError
from kdive.transport.handlers import _ensure_debug_operation_enabled, _resolve_debug_profile


def _configuration_failure(*, run_id: str, message: str, details: dict[str, Any] | None = None) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
    )


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


def _debug_session_details_from_result(result: StepResult, *, allow_ended: bool = False) -> dict[str, Any] | None:
    if result.status != StepStatus.SUCCEEDED:
        return None
    if not allow_ended and result.details.get("current_execution_state") == DebugSessionState.ENDED.value:
        return None
    return result.details


def _debug_session_manifest_details(*, store: ArtifactStore, run_id: str, session: DebugSession) -> dict[str, Any]:
    details: dict[str, Any] = {
        "debug_session_id": session.session_id,
        "session_path": str(store.run_dir(run_id) / "debug" / "sessions" / f"{session.session_id}.json"),
        "current_execution_state": session.current_execution_state.value,
        "gdbstub_endpoint": session.gdbstub_endpoint,
        "transcript_path": session.transcript_path,
        "command_metadata_path": session.command_metadata_path,
        "latest_summary_path": session.latest_summary_path,
        "symbol_identity_validation": session.symbol_identity_validation,
        "breakpoints": session.breakpoints,
    }
    if session.ended_at is not None:
        details["ended_at"] = session.ended_at
    return details


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


def _persist_mi_debug_session(*, store: ArtifactStore, run_id: str, session: DebugSession) -> Path:
    """Write the DebugSession JSON to ``<run>/debug/sessions/<session_id>.json`` (the path
    ``_debug_session_manifest_details`` records and ``_load_active_debug_session`` reads back) and
    ensure its transcript/metadata directory exists. Returns the session-file path."""
    session_path = store.run_dir(run_id) / "debug" / "sessions" / f"{session.session_id}.json"
    session_path.parent.mkdir(parents=True, exist_ok=True)
    Path(session.transcript_path).parent.mkdir(parents=True, exist_ok=True)
    session_path.write_text(session.model_dump_json(indent=2), encoding="utf-8")
    return session_path


def _resume_debug_transport(
    *,
    session: TransportSession,
    admission: AdmissionService,
    session_registry: SessionRegistry,
) -> None:
    """Inverse of `_halt_debug_transport` for the guaranteed-resume path: once the MI engine confirms
    the kernel is EXECUTING again (best-effort continue + RSP disconnect), persist HALTED->EXECUTING
    and bump the execution epoch so a fresh ssh-tier proof at the new epoch is accepted. Writing the
    durable record EXECUTING also makes a subsequent transaction.close() leave NO closed_while_halted
    recovery tombstone, so a fresh ssh-tier operation succeeds with the target back in EXECUTING
    (interface-contracts §5.6)."""
    session_registry.write_record(session.model_copy(update={"execution_state": ExecutionState.EXECUTING}))
    admission.note_execution_transition(session.target_key, session.generation)


def _teardown_debug_transport(
    *,
    transport_session: TransportSession,
    transaction: TransportTransaction,
    session_registry: SessionRegistry | None,
    session_guard: SessionGuard | None,
) -> None:
    """Tear down an open transport session after a failed attach: SessionGuard-supervised close when
    the guard is wired, else a guarded transaction.close(force=False). Shared by the legacy batch
    attach-failure path and the Phase-A MI probe-failure path."""
    sid = transport_session.session_id
    tkey = transport_session.target_key
    if session_guard is not None and session_registry is not None:
        session_guard.teardown(
            SessionGuardContext(
                target_key=tkey, generation=transport_session.generation, session_id=sid, reason="attach_error"
            ),
            close=lambda: transaction.close(sid, force=False),
            read_record=lambda: session_registry.read_record(tkey),
            force_reap=lambda: transaction.force_release(sid),
        )
    else:
        with contextlib.suppress(Exception):
            transaction.close(sid, force=False)


def _teardown_stalled_debug_session(
    *,
    run_id: str,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
    transaction: TransportTransaction | None,
    session_guard: SessionGuard | None,
) -> None:
    """Full transport teardown after a `transport_stall` on an established session (ADR 0023). The
    caller has already reaped the live attachment and `force_resume`d the guest; this writes the
    durable record back to EXECUTING (when admission is wired — the stateful path) and closes the
    transport, releasing the StopCapableGuard so target.run_tests is ungated and re-attach starts
    clean. Degrades gracefully: with no transaction/record wired it is a no-op; on the read path
    (no admission) it skips the durable-EXECUTING write and leaves the conservative
    closed-while-halted recovery tombstone. Best-effort throughout — teardown must not raise."""
    if transaction is None or session_registry is None:
        return
    tkey = TargetKey(provisioner="local-qemu", target_id=run_id)
    record = session_registry.read_record(tkey)
    if record is None:
        return
    if admission is not None:
        with contextlib.suppress(Exception):
            _resume_debug_transport(session=record, admission=admission, session_registry=session_registry)
    with contextlib.suppress(Exception):
        _teardown_debug_transport(
            transport_session=record,
            transaction=transaction,
            session_registry=session_registry,
            session_guard=session_guard,
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
    ended_state_refused = not allow_ended and session.current_execution_state is DebugSessionState.ENDED
    if ended_state_refused or session.attach_status is not DebugAttachStatus.ATTACHED:
        raise ProviderDebugError(
            "active debug session required",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"debug_session_id": session.session_id},
        )
    return session


def _mark_legacy_session_recovery_required(
    *, run_id: str, admission: AdmissionService, session_registry: SessionRegistry
) -> None:
    """Mark an unmanaged debug session's target recovery-required in both durable and admission state.

    The tombstone generation is the current authoritative snapshot generation when available. With
    no snapshot, generation 0 is fail-closed because admission treats a tombstone that is not older
    than the snapshot as live.
    """
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = admission.current_snapshot(target_key)
    generation = snapshot.generation if snapshot is not None else 0
    session_registry.write_tombstone(
        RecoveryTombstone(target_key=target_key, generation=generation, reason="legacy_session_no_ownership")
    )
    admission.mark_recovery_required(target_key, generation)


def _assert_layer4_ownership(
    *,
    run_id: str,
    session_registry: SessionRegistry | None,
) -> None:
    """Assert that the run has a durable transport ownership record when a registry is wired.

    Read-only debug paths use this non-mutating check: they refuse unmanaged sessions but do not
    write recovery tombstones. Servers without a wired registry run ungated because they have no
    durable ownership model to consult.
    """
    if session_registry is None:
        return
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    if session_registry.read_record(target_key) is not None:
        return  # Layer-4-owned session; the durable record governs it.
    raise ProviderDebugError(
        "legacy debug session predates the transport-ownership model and has no durable record; "
        "it cannot be silently resumed.",
        category=ErrorCategory.DEBUG_ATTACH_FAILURE,
        details={"code": "legacy_session_no_ownership", "debug_session_id": None},
    )


def _is_legacy_debug_session(
    *,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
    transport_session_id: str | None,
    run_id: str,
) -> bool:
    """Return True for an unmanaged debug session on a fully wired server.

    A managed session has both a persisted ``transport_session_id`` and a durable
    ``SessionRegistry`` ownership record. ``debug.end_session`` uses this predicate to decide
    whether a successful detach must write the recovery tombstone after force-ending the session.
    """
    return (
        admission is not None
        and session_registry is not None
        and transport_session_id is None
        and session_registry.read_record(TargetKey(provisioner="local-qemu", target_id=run_id)) is None
    )


def _fence_legacy_debug_session(
    *,
    run_id: str,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
) -> None:
    """Fail closed for unmanaged sessions before stateful mutating debug operations.

    On a server with admission and session registry wiring, a run without a durable ownership record
    is unmanaged. Mutating debug operations refuse that session and write a recovery-required
    tombstone so later SSH/test work cannot proceed against a target whose execution state is
    unknown to the transport layer. ``debug.end_session`` is the only stateful exception: it detaches
    first, then writes the same tombstone after a successful detach.
    """
    if admission is None or session_registry is None:
        return
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    if session_registry.read_record(target_key) is not None:
        return  # Layer-4-owned session; the durable record governs it.
    _mark_legacy_session_recovery_required(run_id=run_id, admission=admission, session_registry=session_registry)
    raise ProviderDebugError(
        "legacy debug session predates the transport-ownership model and has no durable record; "
        "it cannot be silently resumed. The target is now recovery_required.",
        category=ErrorCategory.DEBUG_ATTACH_FAILURE,
        details={"code": "legacy_session_no_ownership", "debug_session_id": None},
    )


def _enforce_debug_ownership_fence(
    *,
    run_id: str,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
) -> None:
    """Enforce the ownership rule for every debug path that may connect gdb.

    Mutating paths with admission wiring write the recovery tombstone and refuse unmanaged sessions.
    Read/probe paths without admission wiring run the non-mutating ownership assertion. Both paths
    raise ``ProviderDebugError`` when a wired registry has no durable ownership record for the run.
    """
    if admission is not None:
        _fence_legacy_debug_session(run_id=run_id, admission=admission, session_registry=session_registry)
    else:
        _assert_layer4_ownership(run_id=run_id, session_registry=session_registry)


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
    transport_session_id = _recorded_transport_session_id(artifact_root=artifact_root, run_id=run_id)
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


def _mi_session_artifacts(*, store: ArtifactStore, run_id: str, session: DebugSession) -> list[ArtifactRef]:
    """The debug step's artifacts for the live session: the session JSON and its transcript. Rebuilt
    on each persisted op so a stateful re-record keeps the same artifact set start_session minted."""
    session_path = store.run_dir(run_id) / "debug" / "sessions" / f"{session.session_id}.json"
    return [
        ArtifactRef(path=str(session_path), kind="debug-session"),
        ArtifactRef(path=session.transcript_path, kind="debug-transcript", sensitive=True),
    ]


def _preserved_debug_step_details(store: ArtifactStore, run_id: str) -> dict[str, object]:
    """The start_session bindings a stateful re-record must carry forward (else a later end_session
    could not close the transport, and the MI probe record would be lost): transport_session_id and
    the typed mi_probe block."""
    try:
        existing = store.load_manifest(run_id).step_results.get("debug")
    except ManifestStateError:
        return {}
    if existing is None:
        return {}
    return {key: existing.details[key] for key in ("transport_session_id", "mi_probe") if key in existing.details}


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
            _teardown_stalled_debug_session(
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
    _persist_mi_debug_session(store=store, run_id=run_id, session=session)
    details = {
        **_debug_session_manifest_details(store=store, run_id=run_id, session=session),
        **_preserved_debug_step_details(store, run_id),
        **data,
    }
    terminal = StepResult(
        step_name="debug",
        status=StepStatus.SUCCEEDED,
        summary=f"debug.{request.summary_name} succeeded",
        artifacts=_mi_session_artifacts(store=store, run_id=run_id, session=session),
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
            session = _load_active_debug_session(store, run_id, debug_session_id, allow_ended=allow_ended)
            # Mutating-op fence (tombstones the legacy session) when BOTH admission + registry are
            # wired; pure-read assertion (no tombstone — reads are non-destructive) when only the
            # registry is wired. Every debug.* path that connects gdb gets at least the ownership
            # assertion, so a legacy session can never silently halt the kernel as a side effect of
            # `target remote` against a run target.run_tests is unaware of. This runs BEFORE the
            # live-attachment lookup (ADR 0021 fence-then-lookup).
            _enforce_debug_ownership_fence(
                run_id=run_id,
                admission=runtime.admission,
                session_registry=runtime.session_registry,
            )
            profile = _resolve_debug_profile(
                profile_name=session.selected_debug_profile,
                debug_profiles=runtime.debug_profiles,
            )
            _ensure_debug_operation_enabled(profile, request.profile_operation)
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
                admission=runtime.admission,
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

    op_artifacts = _mi_session_artifacts(store=store, run_id=run_id, session=updated_session)
    return ToolResponse.success(
        summary=f"debug.{request.summary_name} succeeded",
        run_id=run_id,
        data=redactor.redact_value(details),
        artifacts=redacted_artifacts(op_artifacts, redactor),
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _recorded_transport_session_id(*, artifact_root: Path, run_id: str) -> str | None:
    """Read the transport-ownership binding `debug.start_session` persisted into the debug step
    details (set only on the transaction-backed path). None when the run/manifest/step is absent or
    no transport session was bound — the legacy ungated path records nothing, so close() is skipped."""
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        if not (store.run_dir(run_id) / "manifest.json").is_file():
            return None
        debug_result = store.load_manifest(run_id).step_results.get("debug")
    except ManifestStateError:
        return None
    if debug_result is None:
        return None
    transport_session_id = debug_result.details.get("transport_session_id")
    return transport_session_id if isinstance(transport_session_id, str) else None
