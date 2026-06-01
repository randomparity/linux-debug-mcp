from __future__ import annotations

import contextlib
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kdive.artifacts.manifest import RunManifest
from kdive.artifacts.redaction import redacted_artifacts
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import DebugProfile
from kdive.coordination.admission import AdmissionError, AdmissionService, require_target_snapshot
from kdive.coordination.endpoint_safety import EndpointSafetyError
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.policy import ensure_debug_operation_enabled, halt_debug_transport, resolve_debug_profile
from kdive.debug.session_state import (
    debug_session_details_from_result,
    debug_session_manifest_details,
    persist_mi_debug_session,
    resume_debug_transport,
    teardown_debug_transport,
)
from kdive.debug.tools import DebugStartSessionRequest, DebugToolContext
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.handlers.shared import _require_value
from kdive.handlers.shared import configuration_failure_response as _configuration_failure
from kdive.providers.debug import (
    DebugAttachStatus,
    DebugSession,
    DebugSessionState,
    GdbMiEngine,
    GdbMiError,
    GdbMiSessionRegistry,
    ProviderDebugError,
)
from kdive.providers.local.debug.gdb_mi import CANONICAL_PROBE_SYMBOL
from kdive.safety.redaction import Redactor
from kdive.seams.guard import GuardConflict, PreconditionError, SessionGuard, SessionGuardContext
from kdive.seams.target import ConsoleKind, TargetKey
from kdive.seams.transport_state import LineRole, OpenRequest, TransportRef, TransportSession
from kdive.symbols.build_id import BuildIdReadError, read_elf_build_id
from kdive.symbols.verify import BUILD_ID_RE, ProvenanceMismatch, verify_vmlinux_provenance


def _find_artifact(result: StepResult, kind: str) -> ArtifactRef | None:
    return next((artifact for artifact in result.artifacts if artifact.kind == kind), None)


def _debug_open_request(*, run_id: str, gdbstub_endpoint: dict[str, Any], admission: AdmissionService) -> OpenRequest:
    """Build the §4.3 transport.open request for the recorded gdbstub endpoint, reading
    `generation`/`platform` from the authoritative snapshot the boot step published (never
    re-deriving them — ADR 0007). The RSP channel mirrors the boot snapshot producer."""
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = require_target_snapshot(admission, target_key)
    return OpenRequest(
        target_key=target_key,
        generation=snapshot.generation,
        transport_ref=TransportRef(
            provider="qemu-gdbstub",
            channel_id="rsp0",
            line_role=LineRole.RSP,
            caps=("rsp",),
            target_ref=gdbstub_endpoint,
            # The qemu-gdbstub transport reads the RSP host/port from opts (transport.qemu_gdbstub),
            # so the endpoint must be in opts, not only target_ref, or attach raises KeyError: 'port'.
            opts=gdbstub_endpoint,
        ),
        required_caps=["rsp"],
        platform=snapshot.platform,
    )


def _mi_probe_transcript_path(run_dir: Path) -> Path:
    """The live gdb/MI session's transcript. ADR 0021: this is the session-of-record transcript the
    persisted DebugSession references (it is the same file the attach probe writes into)."""
    return run_dir / "debug" / "mi-probe.log"


def _run_mi_attach_probe(
    *,
    engine: GdbMiEngine,
    transport_session: TransportSession,
    vmlinux_path: Path,
    run_dir: Path,
    run_id: str,
    session_id: str,
    gdb_mi_sessions: GdbMiSessionRegistry,
    transaction: TransportTransaction,
    admission: AdmissionService,
    session_registry: SessionRegistry,
    session_guard: SessionGuard | None,
    redactor: Redactor,
) -> tuple[ToolResponse | None, dict[str, object]]:
    """Attach the persistent gdb/MI engine over the guard-protected TransportSession.rsp_endpoint,
    read one MI record as typed JSON, resolve the canonical probe symbol, and — on success — REGISTER
    the live attachment under ``session_id`` and leave it ATTACHED (ADR 0021 decision 1). Returns
    ``(None, {"mi_probe": ...})`` on success (the typed record is merged into the debug step details),
    or ``(failure_response, {})`` after a guaranteed-resume teardown that never leaves the kernel
    HALTED and reaps any partial registration. The live session is the sole session-of-record; there
    is no batch attach behind it."""
    transcript_path = _mi_probe_transcript_path(run_dir)
    attachment = None
    try:
        attachment = engine.attach(
            rsp_endpoint=transport_session.rsp_endpoint, vmlinux_path=vmlinux_path, transcript_path=transcript_path
        )
        record = engine.probe_read(attachment)
        symbol = engine.resolve_symbol(attachment, CANONICAL_PROBE_SYMBOL)
        # Keep the engine attached and hold the live attachment across MCP calls under the minted
        # session id (ADR 0021) — the per-op handlers look it up to issue MI verbs. NO detach here.
        gdb_mi_sessions.register(session_id, attachment)
        mi_probe: dict[str, object] = {
            "mi_probe": redactor.redact_value(
                {
                    "record": record.model_dump(mode="json"),
                    "symbol": symbol.model_dump(mode="json"),
                    "transcript_path": str(transcript_path),
                }
            )
        }
        return None, mi_probe
    except Exception as exc:  # noqa: BLE001 - the guaranteed-resume invariant is unconditional
        # The invariant is "the target is NEVER left HALTED on a tool error" (engine crash, RSP
        # timeout, AND a raised tool exception). So this catch is intentionally broad: a non-GdbMiError
        # (e.g. an unwrapped pygdbmi error) must still trigger resume + teardown, not escape and strand
        # the kernel HALTED with the guard held. KeyboardInterrupt/SystemExit (BaseException, not
        # Exception) still propagate. The error is re-reported as a failure response, never swallowed.
        category = exc.category if isinstance(exc, GdbMiError) else ErrorCategory.INFRASTRUCTURE_FAILURE
        base_details = exc.details if isinstance(exc, GdbMiError) else {}
        # If attach failed before connecting (bad endpoint / missing gdb / missing vmlinux), no RSP
        # connection was made, so the engine never halted the target -> treat resume as confirmed so
        # the durable record is un-halted and no recovery tombstone is left. Otherwise run the
        # guaranteed-resume (best-effort continue + disconnect + kill).
        resume_confirmed = engine.force_resume(attachment) if attachment is not None else True
        # Reap any registration (idempotent no-op when the fault preceded register()) so a failed
        # attach never leaves a dangling live attachment behind the freed durable record.
        gdb_mi_sessions.reap(session_id)
        if resume_confirmed:
            # Best-effort: the un-halt is a durable write that could raise (e.g. OSError on a full
            # disk). It MUST NOT be able to skip the teardown below, or the guaranteed-resume
            # invariant would be defeated (guard left held, kernel left HALTED). If the EXECUTING
            # write fails, teardown's close(force=False) then leaves a closed_while_halted recovery
            # tombstone -- the conservative fallback -- and still releases the guard.
            with contextlib.suppress(Exception):
                resume_debug_transport(
                    session=transport_session, admission=admission, session_registry=session_registry
                )
        teardown_debug_transport(
            transport_session=transport_session,
            transaction=transaction,
            session_registry=session_registry,
            session_guard=session_guard,
        )
        details = redactor.redact_value({**base_details, "transport_session_id": transport_session.session_id})
        failure = ToolResponse.failure(
            category=category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=details,
            suggested_next_actions=["host.check_prerequisites", "artifacts.get_manifest"],
        )
        return failure, {}


_LOSSY_OUT_OF_BAND_CONSOLES = frozenset({ConsoleKind.HVC, ConsoleKind.VIRTIO})
_TRANSPORT_QUALITY_WARNING = (
    "gdb/MI RSP is riding a lossy out-of-band console ({console_kind}); break-in and live"
    " transcripts may be dropped or corrupted. Prefer the in-guest/postmortem tiers for"
    " reliable inspection."
)
_LOSSY_TRANSPORT_NEXT_ACTIONS = ("debug.kdb", "debug.introspect.run")


def is_lossy_out_of_band(console_kind: ConsoleKind) -> bool:
    """True when the RSP travels over a console whose framing can silently drop or corrupt bytes
    (paravirtual HVC, virtio-console) rather than a dedicated UART line. ADR 0024 decision 2: the
    warning is keyed on console framing quality, never on the selected line's role."""
    return console_kind in _LOSSY_OUT_OF_BAND_CONSOLES


def _build_mi_debug_session(
    *,
    session_id: str,
    run_id: str,
    vmlinux_path: Path,
    gdbstub_endpoint: dict[str, object],
    profile_name: str,
    transcript_path: Path,
    started_at: str,
) -> DebugSession:
    """Build the persisted DebugSession for the live gdb/MI attach (ADR 0021). The id is minted once
    in the handler BEFORE the probe and threaded here, so the registry key and the persisted id are
    identical. Symbol-identity validation is empty: the #70 build-id version-lock gate ran before the
    attach and is authoritative (ADR 0021 decision 2b) — there is no live-banner scrape."""
    attempt_dir = transcript_path.parent
    return DebugSession(
        session_id=session_id,
        run_id=run_id,
        provider_name="local-qemu-gdbstub",
        gdbstub_endpoint=gdbstub_endpoint,
        vmlinux_path=str(vmlinux_path),
        selected_debug_profile=profile_name,
        attach_status=DebugAttachStatus.ATTACHED,
        started_at=started_at,
        ended_at=None,
        current_execution_state=DebugSessionState.STOPPED,
        breakpoints={},
        transcript_path=str(transcript_path),
        command_metadata_path=str(attempt_dir / "commands.jsonl"),
        latest_summary_path=str(attempt_dir / "debug-summary.json"),
        symbol_identity_validation={},
    )


def _verify_gdb_symbol_version_lock(
    *,
    boot_result: StepResult,
    vmlinux_path: Path,
    run_id: str,
    build_id_reader: Callable[[Path], str],
) -> ToolResponse | None:
    """#70 / ADR 0017: verify the on-disk vmlinux ELF build-id equals the
    boot-recorded §4.2 KernelProvenance.build_id. Returns a failure ToolResponse to
    abort the attach, or None to proceed. Unconditional (independent of
    symbol_identity_required) -- a detected mismatch is bogus symbols.

    *vmlinux_path* is the manifest-recorded build artifact (trusted: the artifact
    root is the trust boundary), read read-only for its ELF build-id note; the gdb
    provider performs the authoritative under-run-dir path confinement at attach.
    """
    provenance = boot_result.details.get("kernel_provenance")
    if not isinstance(provenance, dict):
        capture_error = boot_result.details.get("kernel_provenance_capture_error")
        details: dict[str, Any] = {"code": "provenance_missing"}
        if isinstance(capture_error, dict):
            message = f"boot did not record a KernelProvenance: {capture_error.get('message', 'capture failed')}"
            details["capture_error"] = capture_error.get("code")
        else:
            message = (
                "boot for this run did not record a KernelProvenance (it predates "
                "provenance capture). Re-run target.boot with force_reboot=true to capture it."
            )
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=message,
            details=details,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    expected_build_id = provenance.get("build_id")
    if not isinstance(expected_build_id, str) or not BUILD_ID_RE.match(expected_build_id):
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="recorded build_id is malformed",
            details={"code": "provenance_corrupt", "recorded": str(expected_build_id)},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    try:
        verify_vmlinux_provenance(
            expected_build_id=expected_build_id,
            vmlinux_path=vmlinux_path,
            build_id_reader=build_id_reader,
        )
    except BuildIdReadError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"could not read a GNU build-id from the vmlinux to verify symbols: {exc}",
            details={"code": "vmlinux_build_id_unreadable"},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    except ProvenanceMismatch as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(
                f"vmlinux build-id {exc.observed!r} does not match the booted kernel's recorded "
                f"build-id {exc.expected!r}; rebuild or re-boot so the booted kernel and the "
                "vmlinux on disk share a build-id"
            ),
            details={"code": "provenance_mismatch", "expected": exc.expected, "observed": exc.observed},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    return None


@dataclass(frozen=True)
class _DebugStartPreflight:
    store: ArtifactStore
    manifest: RunManifest
    build_result: StepResult
    boot_result: StepResult
    vmlinux: ArtifactRef
    kernel_image: ArtifactRef
    gdbstub_endpoint: dict[str, object]
    resolved_debug_profile: DebugProfile
    redactor: Redactor
    started_at: str


@dataclass(frozen=True)
class _DebugStartAttach:
    target_key: TargetKey
    transport_session: TransportSession
    session_id: str
    mi_probe_details: dict[str, object]
    replace_existing_debug: bool
    runtime: _DebugStartRuntime


@dataclass(frozen=True)
class _DebugStartRuntime:
    transaction: TransportTransaction
    admission: AdmissionService
    session_registry: SessionRegistry
    gdb_mi_engine: GdbMiEngine
    gdb_mi_sessions: GdbMiSessionRegistry


@dataclass(frozen=True)
class _DebugStartDependencies:
    transaction: TransportTransaction | None
    admission: AdmissionService | None
    session_registry: SessionRegistry | None
    session_guard: SessionGuard | None
    gdb_mi_engine: GdbMiEngine | None
    gdb_mi_sessions: GdbMiSessionRegistry | None


@dataclass(frozen=True)
class _DebugStartReadiness:
    runtime: _DebugStartRuntime
    replace_existing_debug: bool


@dataclass(frozen=True)
class _DebugStartPersisted:
    artifacts: list[ArtifactRef]
    details: dict[str, Any]


def _debug_start_session_preflight(
    *,
    artifact_root: Path,
    run_id: str,
    debug_profile: str | None,
    debug_profiles: Mapping[str, DebugProfile] | None,
) -> tuple[_DebugStartPreflight | None, ToolResponse | None]:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return None, _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return None, ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    build_result = manifest.step_results.get("build")
    if build_result is None or build_result.status != StepStatus.SUCCEEDED:
        return None, _configuration_failure(run_id=run_id, message="debug start session requires a succeeded build")
    boot_result = manifest.step_results.get("boot")
    if boot_result is None or boot_result.status != StepStatus.SUCCEEDED:
        return None, _configuration_failure(run_id=run_id, message="debug start session requires a succeeded boot")
    if boot_result.details.get("debug_boot") is not True:
        return None, _configuration_failure(run_id=run_id, message="debug start session requires a debug boot")
    vmlinux = _find_artifact(build_result, "vmlinux")
    if vmlinux is None:
        return None, _configuration_failure(run_id=run_id, message="succeeded build did not record a vmlinux artifact")
    kernel_image = _find_artifact(build_result, "kernel-image")
    if kernel_image is None:
        return None, _configuration_failure(
            run_id=run_id, message="succeeded build did not record a kernel-image artifact"
        )
    gdbstub_endpoint = boot_result.details.get("gdbstub_endpoint")
    if not isinstance(gdbstub_endpoint, dict):
        return None, _configuration_failure(
            run_id=run_id, message="succeeded debug boot did not record a gdbstub endpoint"
        )

    requested_profile = debug_profile or manifest.request.debug_profile or "qemu-gdbstub-default"
    if (
        manifest.request.debug_profile is not None
        and debug_profile is not None
        and debug_profile != manifest.request.debug_profile
    ):
        return None, _configuration_failure(
            run_id=run_id,
            message="debug_profile must match the immutable run manifest request",
            details={"requested_profile": debug_profile, "manifest_profile": manifest.request.debug_profile},
        )
    try:
        resolved_debug_profile = resolve_debug_profile(
            profile_name=requested_profile,
            debug_profiles=debug_profiles,
        )
        ensure_debug_operation_enabled(resolved_debug_profile, "debug.start_session")
    except ProviderDebugError as exc:
        return None, _configuration_failure(run_id=run_id, message=str(exc), details=exc.details)

    return (
        _DebugStartPreflight(
            store=store,
            manifest=manifest,
            build_result=build_result,
            boot_result=boot_result,
            vmlinux=vmlinux,
            kernel_image=kernel_image,
            gdbstub_endpoint=gdbstub_endpoint,
            resolved_debug_profile=resolved_debug_profile,
            redactor=Redactor(),
            started_at=datetime.now(UTC).isoformat(),
        ),
        None,
    )


def _debug_start_session_engine_missing(
    *,
    run_id: str,
    dependencies: _DebugStartDependencies,
) -> ToolResponse | None:
    if (
        dependencies.transaction is not None
        and dependencies.admission is not None
        and dependencies.session_registry is not None
        and dependencies.gdb_mi_engine is not None
        and dependencies.gdb_mi_sessions is not None
    ):
        return None
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message="debug.start_session requires the transport machinery and the gdb/MI engine",
        run_id=run_id,
        details={"code": "debug_engine_unavailable"},
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _cleanup_debug_start_session_attach(
    *,
    exc: Exception,
    run_id: str,
    session_id: str,
    transport_session: TransportSession,
    transaction: TransportTransaction,
    admission: AdmissionService,
    session_registry: SessionRegistry,
    session_guard: SessionGuard | None,
    gdb_mi_engine: GdbMiEngine,
    gdb_mi_sessions: GdbMiSessionRegistry,
    redactor: Redactor,
) -> ToolResponse:
    reaped = gdb_mi_sessions.reap(session_id)
    if reaped is not None:
        with contextlib.suppress(Exception):
            gdb_mi_engine.force_resume(reaped)
    with contextlib.suppress(Exception):
        resume_debug_transport(session=transport_session, admission=admission, session_registry=session_registry)
    teardown_debug_transport(
        transport_session=transport_session,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
    )
    category = exc.category if isinstance(exc, ManifestStateError) else ErrorCategory.INFRASTRUCTURE_FAILURE
    return ToolResponse.failure(
        category=category,
        message=redactor.redact_text(str(exc)),
        run_id=run_id,
        details=redactor.redact_value(
            {
                "code": "debug_session_persist_failed",
                "exception_type": type(exc).__name__,
                "error": str(exc),
            }
        ),
        suggested_next_actions=["host.check_prerequisites", "artifacts.get_manifest"],
    )


def _debug_start_session_reuse_or_readiness(
    *,
    run_id: str,
    preflight: _DebugStartPreflight,
    new_session: bool,
    build_id_reader: Callable[[Path], str],
    dependencies: _DebugStartDependencies,
) -> tuple[_DebugStartReadiness | None, ToolResponse | None]:
    store = preflight.store
    redactor = preflight.redactor
    locked_manifest = store.load_manifest(run_id)
    existing = locked_manifest.step_results.get("debug")
    replace_existing_debug = new_session
    if existing and not new_session:
        active_session = debug_session_details_from_result(existing)
        if active_session is not None:
            return (
                None,
                ToolResponse.success(
                    summary=redactor.redact_text(existing.summary),
                    run_id=run_id,
                    data=redactor.redact_value(active_session),
                    artifacts=redacted_artifacts(existing.artifacts, redactor),
                    suggested_next_actions=["debug.interrupt", "debug.read_registers", "artifacts.get_manifest"],
                ),
            )
        replace_existing_debug = existing.status == StepStatus.SUCCEEDED

    version_lock_failure = _verify_gdb_symbol_version_lock(
        boot_result=preflight.boot_result,
        vmlinux_path=Path(preflight.vmlinux.path),
        run_id=run_id,
        build_id_reader=build_id_reader,
    )
    if version_lock_failure is not None:
        return None, version_lock_failure

    engine_failure = _debug_start_session_engine_missing(
        run_id=run_id,
        dependencies=dependencies,
    )
    if engine_failure is not None:
        return None, engine_failure
    transaction = _require_value(dependencies.transaction, "debug transaction missing after availability check")
    admission = _require_value(dependencies.admission, "debug admission missing after availability check")
    session_registry = _require_value(
        dependencies.session_registry,
        "debug session registry missing after availability check",
    )
    gdb_mi_engine = _require_value(dependencies.gdb_mi_engine, "debug gdb/MI engine missing after availability check")
    gdb_mi_sessions = _require_value(
        dependencies.gdb_mi_sessions,
        "debug gdb/MI registry missing after availability check",
    )
    return (
        _DebugStartReadiness(
            runtime=_DebugStartRuntime(
                transaction=transaction,
                admission=admission,
                session_registry=session_registry,
                gdb_mi_engine=gdb_mi_engine,
                gdb_mi_sessions=gdb_mi_sessions,
            ),
            replace_existing_debug=replace_existing_debug,
        ),
        None,
    )


def _debug_start_session_open_and_probe(
    *,
    run_id: str,
    preflight: _DebugStartPreflight,
    readiness: _DebugStartReadiness,
    recovery: bool,
    dependencies: _DebugStartDependencies,
) -> tuple[_DebugStartAttach | None, ToolResponse | None]:
    runtime = readiness.runtime
    session_guard = dependencies.session_guard
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    if session_guard is not None:
        try:
            session_guard.enter(
                SessionGuardContext(target_key=target_key, generation=0, session_id=None, reason="attach_error")
            )
        except PreconditionError as exc:
            return (
                None,
                ToolResponse.failure(
                    category=ErrorCategory.READINESS_FAILURE,
                    message=str(exc),
                    run_id=run_id,
                    details={"code": "precondition_failed", "precondition": exc.name},
                    suggested_next_actions=["artifacts.get_manifest"],
                ),
            )
    try:
        request = _debug_open_request(
            run_id=run_id,
            gdbstub_endpoint=preflight.gdbstub_endpoint,
            admission=runtime.admission,
        )
        transport_session = runtime.transaction.open(request, recovery=recovery)
    except (GuardConflict, EndpointSafetyError) as exc:
        return (
            None,
            ToolResponse.failure(
                category=ErrorCategory.TRANSPORT_CONFLICT,
                message=str(exc),
                run_id=run_id,
                details={"code": getattr(exc, "code", "stop_capable_conflict")},
                suggested_next_actions=["artifacts.get_manifest"],
            ),
        )
    except AdmissionError as exc:
        return (
            None,
            ToolResponse.failure(
                category=exc.category,
                message=str(exc),
                run_id=run_id,
                details={"code": exc.code},
                suggested_next_actions=["artifacts.get_manifest"],
            ),
        )

    halt_debug_transport(
        session=transport_session,
        admission=runtime.admission,
        session_registry=runtime.session_registry,
    )
    session_id = f"debug-{uuid.uuid4().hex}"
    probe_failure, mi_probe_details = _run_mi_attach_probe(
        engine=runtime.gdb_mi_engine,
        transport_session=transport_session,
        vmlinux_path=Path(preflight.vmlinux.path),
        run_dir=preflight.store.run_dir(run_id),
        run_id=run_id,
        session_id=session_id,
        gdb_mi_sessions=runtime.gdb_mi_sessions,
        transaction=runtime.transaction,
        admission=runtime.admission,
        session_registry=runtime.session_registry,
        session_guard=session_guard,
        redactor=preflight.redactor,
    )
    if probe_failure is not None:
        return None, probe_failure
    return (
        _DebugStartAttach(
            target_key=target_key,
            transport_session=transport_session,
            session_id=session_id,
            mi_probe_details=mi_probe_details,
            replace_existing_debug=readiness.replace_existing_debug,
            runtime=runtime,
        ),
        None,
    )


def _debug_start_session_persist_success(
    *,
    run_id: str,
    preflight: _DebugStartPreflight,
    attach: _DebugStartAttach,
    session_guard: SessionGuard | None,
) -> _DebugStartPersisted:
    store = preflight.store
    runtime = attach.runtime
    session = _build_mi_debug_session(
        session_id=attach.session_id,
        run_id=run_id,
        vmlinux_path=Path(preflight.vmlinux.path),
        gdbstub_endpoint=preflight.gdbstub_endpoint,
        profile_name=preflight.resolved_debug_profile.name,
        transcript_path=_mi_probe_transcript_path(store.run_dir(run_id)),
        started_at=preflight.started_at,
    )
    session_path = persist_mi_debug_session(store=store, run_id=run_id, session=session)
    artifacts = [
        ArtifactRef(path=str(session_path), kind="debug-session"),
        ArtifactRef(path=session.transcript_path, kind="debug-transcript", sensitive=True),
    ]
    details = debug_session_manifest_details(store=store, run_id=run_id, session=session)
    details.update(attach.mi_probe_details)
    details["transport_session_id"] = attach.transport_session.session_id
    if session_guard is not None:
        sid = attach.transport_session.session_id
        tkey = attach.transport_session.target_key
        post_ctx = SessionGuardContext(
            target_key=tkey, generation=attach.transport_session.generation, session_id=sid, reason="attach_error"
        )
        try:
            session_guard.verify_attached(post_ctx, attach.transport_session)
        except PreconditionError as exc:
            reaped = runtime.gdb_mi_sessions.reap(attach.session_id)
            if reaped is not None:
                with contextlib.suppress(Exception):
                    runtime.gdb_mi_engine.force_resume(reaped)
            session_guard.teardown(
                post_ctx,
                close=lambda: runtime.transaction.close(sid, force=False),
                read_record=lambda: runtime.session_registry.read_record(tkey),
                force_reap=lambda: runtime.transaction.force_release(sid),
            )
            raise exc
    terminal = StepResult(
        step_name="debug",
        status=StepStatus.SUCCEEDED,
        summary="gdb/MI debug session started",
        artifacts=artifacts,
        details=details,
    )
    store.record_step_result(run_id, terminal, replace_succeeded=attach.replace_existing_debug)
    return _DebugStartPersisted(artifacts=artifacts, details=details)


def _debug_start_session_success_response(
    *,
    run_id: str,
    target_key: TargetKey,
    details: dict[str, Any],
    artifacts: list[ArtifactRef],
    admission: AdmissionService,
    redactor: Redactor,
) -> ToolResponse:
    next_actions = ["debug.interrupt", "debug.read_registers", "artifacts.get_manifest"]
    snapshot = admission.current_snapshot(target_key)
    if snapshot is not None and is_lossy_out_of_band(snapshot.platform.console_kind):
        details["transport_quality_warning"] = _TRANSPORT_QUALITY_WARNING.format(
            console_kind=snapshot.platform.console_kind.value
        )
        next_actions = [*_LOSSY_TRANSPORT_NEXT_ACTIONS, *next_actions]
    return ToolResponse.success(
        summary="gdb/MI debug session started",
        run_id=run_id,
        data=redactor.redact_value(details),
        artifacts=redacted_artifacts(artifacts, redactor),
        suggested_next_actions=next_actions,
    )


def _start_session(
    *,
    artifact_root: Path,
    run_id: str,
    debug_profile: str | None = None,
    new_session: bool = False,
    debug_profiles: Mapping[str, DebugProfile] | None = None,
    transaction: TransportTransaction | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    recovery: bool = False,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    preflight, preflight_failure = _debug_start_session_preflight(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profile=debug_profile,
        debug_profiles=debug_profiles,
    )
    if preflight_failure is not None:
        return preflight_failure
    preflight = _require_value(preflight, "debug preflight missing without failure")
    dependencies = _DebugStartDependencies(
        transaction=transaction,
        admission=admission,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )

    attach: _DebugStartAttach | None = None
    persisted: _DebugStartPersisted | None = None
    try:
        with preflight.store.debug_lock(run_id):
            readiness, readiness_failure = _debug_start_session_reuse_or_readiness(
                run_id=run_id,
                preflight=preflight,
                new_session=new_session,
                build_id_reader=build_id_reader,
                dependencies=dependencies,
            )
            if readiness_failure is not None:
                return readiness_failure
            readiness = _require_value(readiness, "debug readiness missing without failure")
            attach, attach_failure = _debug_start_session_open_and_probe(
                run_id=run_id,
                preflight=preflight,
                readiness=readiness,
                recovery=recovery,
                dependencies=dependencies,
            )
            if attach_failure is not None:
                return attach_failure
            attach = _require_value(attach, "debug attach missing without failure")

            try:
                persisted = _debug_start_session_persist_success(
                    run_id=run_id,
                    preflight=preflight,
                    attach=attach,
                    session_guard=session_guard,
                )
            except PreconditionError as exc:
                return ToolResponse.failure(
                    category=ErrorCategory.READINESS_FAILURE,
                    message=str(exc),
                    run_id=run_id,
                    details={"code": "precondition_failed", "precondition": exc.name},
                    suggested_next_actions=["artifacts.get_manifest"],
                )
            except Exception as exc:  # noqa: BLE001 - guaranteed-resume is unconditional after register
                return _cleanup_debug_start_session_attach(
                    exc=exc,
                    run_id=run_id,
                    session_id=attach.session_id,
                    transport_session=attach.transport_session,
                    transaction=attach.runtime.transaction,
                    admission=attach.runtime.admission,
                    session_registry=attach.runtime.session_registry,
                    session_guard=session_guard,
                    gdb_mi_engine=attach.runtime.gdb_mi_engine,
                    gdb_mi_sessions=attach.runtime.gdb_mi_sessions,
                    redactor=preflight.redactor,
                )
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    attach = _require_value(attach, "debug attach missing before success response")
    persisted = _require_value(persisted, "debug persistence result missing before success response")
    return _debug_start_session_success_response(
        run_id=run_id,
        target_key=attach.target_key,
        details=persisted.details,
        artifacts=persisted.artifacts,
        admission=attach.runtime.admission,
        redactor=preflight.redactor,
    )


def debug_start_session_handler(*, request: DebugStartSessionRequest, runtime: DebugToolContext) -> ToolResponse:
    return _start_session(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        debug_profile=request.debug_profile,
        new_session=request.new_session,
        transaction=runtime.transaction,
        admission=runtime.admission,
        session_registry=runtime.session_registry,
        session_guard=runtime.session_guard,
        gdb_mi_engine=runtime.gdb_mi_engine,
        gdb_mi_sessions=runtime.gdb_mi_sessions,
    )
