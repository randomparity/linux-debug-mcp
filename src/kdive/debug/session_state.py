from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import RecoveryTombstone, SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus
from kdive.providers.debug import DebugAttachStatus, DebugSession, DebugSessionState, ProviderDebugError
from kdive.seams.guard import SessionGuard, SessionGuardContext
from kdive.seams.target import TargetKey
from kdive.seams.transport_state import ExecutionState, TransportSession


def debug_session_details_from_result(result: StepResult, *, allow_ended: bool = False) -> dict[str, Any] | None:
    if result.status != StepStatus.SUCCEEDED:
        return None
    if not allow_ended and result.details.get("current_execution_state") == DebugSessionState.ENDED.value:
        return None
    return result.details


def debug_session_manifest_details(*, store: ArtifactStore, run_id: str, session: DebugSession) -> dict[str, Any]:
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


def persist_mi_debug_session(*, store: ArtifactStore, run_id: str, session: DebugSession) -> Path:
    """Write the DebugSession JSON and ensure its transcript/metadata directory exists."""
    session_path = store.run_dir(run_id) / "debug" / "sessions" / f"{session.session_id}.json"
    session_path.parent.mkdir(parents=True, exist_ok=True)
    Path(session.transcript_path).parent.mkdir(parents=True, exist_ok=True)
    session_path.write_text(session.model_dump_json(indent=2), encoding="utf-8")
    return session_path


def resume_debug_transport(
    *,
    session: TransportSession,
    admission: AdmissionService,
    session_registry: SessionRegistry,
) -> None:
    session_registry.write_record(session.model_copy(update={"execution_state": ExecutionState.EXECUTING}))
    admission.note_execution_transition(session.target_key, session.generation)


def teardown_debug_transport(
    *,
    transport_session: TransportSession,
    transaction: TransportTransaction,
    session_registry: SessionRegistry | None,
    session_guard: SessionGuard | None,
) -> None:
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


def teardown_stalled_debug_session(
    *,
    run_id: str,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
    transaction: TransportTransaction | None,
    session_guard: SessionGuard | None,
) -> None:
    if transaction is None or session_registry is None:
        return
    tkey = TargetKey(provisioner="local-qemu", target_id=run_id)
    record = session_registry.read_record(tkey)
    if record is None:
        return
    if admission is not None:
        with contextlib.suppress(Exception):
            resume_debug_transport(session=record, admission=admission, session_registry=session_registry)
    with contextlib.suppress(Exception):
        teardown_debug_transport(
            transport_session=record,
            transaction=transaction,
            session_registry=session_registry,
            session_guard=session_guard,
        )


def load_active_debug_session(
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
    active_details = debug_session_details_from_result(debug_result, allow_ended=allow_ended)
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


def mark_legacy_session_recovery_required(
    *, run_id: str, admission: AdmissionService, session_registry: SessionRegistry
) -> None:
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
    if session_registry is None:
        return
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    if session_registry.read_record(target_key) is not None:
        return
    raise ProviderDebugError(
        "legacy debug session predates the transport-ownership model and has no durable record; "
        "it cannot be silently resumed.",
        category=ErrorCategory.DEBUG_ATTACH_FAILURE,
        details={"code": "legacy_session_no_ownership", "debug_session_id": None},
    )


def is_legacy_debug_session(
    *,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
    transport_session_id: str | None,
    run_id: str,
) -> bool:
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
    if admission is None or session_registry is None:
        return
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    if session_registry.read_record(target_key) is not None:
        return
    mark_legacy_session_recovery_required(run_id=run_id, admission=admission, session_registry=session_registry)
    raise ProviderDebugError(
        "legacy debug session predates the transport-ownership model and has no durable record; "
        "it cannot be silently resumed. The target is now recovery_required.",
        category=ErrorCategory.DEBUG_ATTACH_FAILURE,
        details={"code": "legacy_session_no_ownership", "debug_session_id": None},
    )


def enforce_debug_ownership_fence(
    *,
    run_id: str,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
) -> None:
    if admission is not None:
        _fence_legacy_debug_session(run_id=run_id, admission=admission, session_registry=session_registry)
    else:
        _assert_layer4_ownership(run_id=run_id, session_registry=session_registry)


def mi_session_artifacts(*, store: ArtifactStore, run_id: str, session: DebugSession) -> list[ArtifactRef]:
    session_path = store.run_dir(run_id) / "debug" / "sessions" / f"{session.session_id}.json"
    return [
        ArtifactRef(path=str(session_path), kind="debug-session"),
        ArtifactRef(path=session.transcript_path, kind="debug-transcript", sensitive=True),
    ]


def preserved_debug_step_details(store: ArtifactStore, run_id: str) -> dict[str, object]:
    try:
        existing = store.load_manifest(run_id).step_results.get("debug")
    except ManifestStateError:
        return {}
    if existing is None:
        return {}
    return {key: existing.details[key] for key in ("transport_session_id", "mi_probe") if key in existing.details}


def recorded_transport_session_id(*, artifact_root: Path, run_id: str) -> str | None:
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
