from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

from kdive.artifacts.redaction import redacted_artifacts
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import DebugProfile
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.operations import (
    _configuration_failure,
    _debug_session_manifest_details,
    _is_legacy_debug_session,
    _load_active_debug_session,
    _mark_legacy_session_recovery_required,
    _mi_session_artifacts,
    _persist_mi_debug_session,
    _preserved_debug_step_details,
    _recorded_transport_session_id,
)
from kdive.domain import ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.providers.debug import DebugSessionState, GdbMiEngine, GdbMiSessionRegistry, ProviderDebugError
from kdive.safety.redaction import Redactor
from kdive.seams.guard import SessionGuard, SessionGuardContext
from kdive.seams.target import TargetKey
from kdive.transport.handlers import _ensure_debug_operation_enabled, _resolve_debug_profile

_RequiredT = TypeVar("_RequiredT")


def _require_value(value: _RequiredT | None, message: str) -> _RequiredT:
    if value is None:
        raise RuntimeError(message)
    return value


def _end_mi_debug_session(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    debug_profiles: dict[str, DebugProfile] | None,
    gdb_mi_engine: GdbMiEngine | None,
    gdb_mi_sessions: GdbMiSessionRegistry | None,
) -> ToolResponse:
    """Reap the live gdb/MI attachment and durably record the session ENDED."""
    store = ArtifactStore(artifact_root, create_root=False)
    if not (store.run_dir(run_id) / "manifest.json").is_file():
        return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
    redactor = Redactor()
    try:
        with store.debug_lock(run_id):
            session = _load_active_debug_session(store, run_id, debug_session_id, allow_ended=True)
            profile = _resolve_debug_profile(profile_name=session.selected_debug_profile, debug_profiles=debug_profiles)
            _ensure_debug_operation_enabled(profile, "debug.end_session")
            ended = session.model_copy(
                update={"current_execution_state": DebugSessionState.ENDED, "ended_at": datetime.now(UTC).isoformat()}
            )
            _persist_mi_debug_session(store=store, run_id=run_id, session=ended)
            details = {
                **_debug_session_manifest_details(store=store, run_id=run_id, session=ended),
                **_preserved_debug_step_details(store, run_id),
            }
            terminal = StepResult(
                step_name="debug",
                status=StepStatus.SUCCEEDED,
                summary="debug.end_session succeeded",
                artifacts=_mi_session_artifacts(store=store, run_id=run_id, session=ended),
                details=details,
            )
            store.record_step_result(run_id, terminal, replace_succeeded=True)
            if gdb_mi_sessions is not None:
                reaped = gdb_mi_sessions.reap(session.session_id)
                if reaped is not None and gdb_mi_engine is not None:
                    with contextlib.suppress(Exception):
                        gdb_mi_engine.force_resume(reaped)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    except OSError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=redactor.redact_text(f"failed to record debug.end_session: {exc}"),
            run_id=run_id,
            details={"code": "debug_session_end_record_failed"},
            suggested_next_actions=["debug.end_session", "artifacts.get_manifest"],
        )
    except ProviderDebugError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value(exc.details),
            suggested_next_actions=["debug.start_session", "artifacts.get_manifest"],
        )
    return ToolResponse.success(
        summary="debug.end_session succeeded",
        run_id=run_id,
        data=redactor.redact_value(details),
        artifacts=redacted_artifacts(_mi_session_artifacts(store=store, run_id=run_id, session=ended), redactor),
        suggested_next_actions=["artifacts.get_manifest"],
    )


def debug_end_session_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    transaction: TransportTransaction | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    transport_session_id = (
        _recorded_transport_session_id(artifact_root=artifact_root, run_id=run_id) if transaction is not None else None
    )
    is_legacy_session = _is_legacy_debug_session(
        admission=admission,
        session_registry=session_registry,
        transport_session_id=transport_session_id,
        run_id=run_id,
    )
    response = _end_mi_debug_session(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )
    if response.ok and transaction is not None and transport_session_id is not None:
        if session_guard is not None and session_registry is not None:
            tkey = TargetKey(provisioner="local-qemu", target_id=run_id)
            ended_record = session_registry.read_record(tkey)
            ended_generation = ended_record.generation if ended_record is not None else 0
            session_guard.teardown(
                SessionGuardContext(
                    target_key=tkey,
                    generation=ended_generation,
                    session_id=transport_session_id,
                    reason="ended",
                ),
                close=lambda: transaction.close(transport_session_id, force=True),
                read_record=lambda: session_registry.read_record(tkey),
                force_reap=lambda: transaction.force_release(transport_session_id),
            )
        else:
            transaction.close(transport_session_id, force=True)
    if response.ok and is_legacy_session:
        admission = _require_value(admission, "admission service missing for legacy session recovery marker")
        session_registry = _require_value(
            session_registry,
            "session registry missing for legacy session recovery marker",
        )
        _mark_legacy_session_recovery_required(run_id=run_id, admission=admission, session_registry=session_registry)
    return response
