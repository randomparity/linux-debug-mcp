from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from kdive.artifacts.steps import record_append_only_terminal_step
from kdive.artifacts.store import ArtifactStore
from kdive.config import (
    TRIAGE_CRASH_COMMANDS,
    TRIAGE_DMESG_HELPER,
    TRIAGE_MODULES_HELPER,
)
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.postmortem.crash.handler import resolve_postmortem_vmcore_context
from kdive.postmortem.models import (
    DebugPostmortemCrashRequest,
    DebugPostmortemTriageReport,
    DebugPostmortemTriageRequest,
)
from kdive.postmortem.tools import DrgnHelperRequest, PostmortemToolRuntime
from kdive.postmortem.triage import CrashOutcome, DrgnOutcome, any_section_ok, assemble_report
from kdive.safety.files import atomic_write_text
from kdive.safety.redaction import Redactor
from kdive.symbols.build_id import read_elf_build_id
from kdive.symbols.vmcore_build_id import read_vmcore_build_id


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class _TriageSourceResponses:
    crash: ToolResponse
    dmesg: ToolResponse
    modules: ToolResponse


@dataclass(frozen=True)
class _TriageReportState:
    report: DebugPostmortemTriageReport
    sub_call_ids: dict[str, str | None]
    started_at: datetime
    finished_at: datetime
    duration_ms: int


def _triage_subcall_id(resp: ToolResponse) -> str | None:
    """The sub-call's own call_id, on success (data) or failure (error.details)."""
    cid = resp.data.get("call_id") if resp.ok else (resp.error.details if resp.error else {}).get("call_id")
    return cid if isinstance(cid, str) else None


def _triage_reason(resp: ToolResponse) -> str:
    """A failed sub-call's stable error code, defensively (details may be empty)."""
    details = resp.error.details if resp.error else {}
    code = details.get("code")
    return code if isinstance(code, str) and code else "sub_call_failed"


def _triage_subcall_failure(*, run_id: str, code: str, exc: Exception) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        run_id=run_id,
        message="postmortem triage subcall failed before returning a tool response",
        details={"code": code, "exception_type": type(exc).__name__},
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _run_triage_sources(
    request: DebugPostmortemTriageRequest,
    *,
    runtime: PostmortemToolRuntime,
) -> _TriageSourceResponses:
    run_id = request.run_id
    crash_handler = runtime.crash_handler
    drgn_helper_handler = runtime.drgn_helper_handler
    if crash_handler is None or drgn_helper_handler is None:
        raise TypeError("postmortem triage runtime requires crash and drgn helper handlers")
    try:
        crash_resp = crash_handler(
            request=DebugPostmortemCrashRequest(
                run_id=run_id,
                vmcore_ref=request.vmcore_ref,
                vmlinux_ref=request.vmlinux_ref,
                modules_ref=request.modules_ref,
                commands=list(TRIAGE_CRASH_COMMANDS),
                timeout_seconds=request.timeout_seconds,
            ),
            runtime=runtime,
        )
    except Exception as exc:  # noqa: BLE001 - triage boundary normalizes subcall exceptions
        crash_resp = _triage_subcall_failure(run_id=run_id, code="postmortem_crash_failed", exc=exc)

    def drgn(name: str) -> ToolResponse:
        try:
            return drgn_helper_handler(
                request=DrgnHelperRequest(
                    run_id=run_id,
                    vmcore_ref=request.vmcore_ref,
                    vmlinux_ref=request.vmlinux_ref,
                    modules_ref=None,
                    name=name,
                    timeout_seconds=request.timeout_seconds,
                ),
                runtime=runtime,
            )
        except Exception as exc:  # noqa: BLE001 - triage boundary normalizes subcall exceptions
            return _triage_subcall_failure(run_id=run_id, code="offline_introspect_failed", exc=exc)

    return _TriageSourceResponses(
        crash=crash_resp,
        dmesg=drgn(TRIAGE_DMESG_HELPER),
        modules=drgn(TRIAGE_MODULES_HELPER),
    )


def _build_triage_report_state(
    *,
    vmcore_build_id: str,
    sources: _TriageSourceResponses,
    started_at: datetime,
    finished_at: datetime,
    duration_ms: int,
) -> _TriageReportState:
    return _TriageReportState(
        report=assemble_report(
            vmcore_build_id=vmcore_build_id,
            crash=_triage_crash_outcome(sources.crash),
            dmesg=_triage_drgn_outcome(sources.dmesg),
            modules=_triage_drgn_outcome(sources.modules),
        ),
        sub_call_ids={
            "crash": _triage_subcall_id(sources.crash),
            "dmesg": _triage_subcall_id(sources.dmesg),
            "modules": _triage_subcall_id(sources.modules),
        },
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
    )


def _triage_crash_outcome(response: ToolResponse) -> CrashOutcome:
    return CrashOutcome(
        ok=response.ok,
        reason=None if response.ok else _triage_reason(response),
        results=response.data.get("results", {}) if response.ok else {},
    )


def _triage_drgn_outcome(response: ToolResponse) -> DrgnOutcome:
    return DrgnOutcome(
        ok=response.ok,
        reason=None if response.ok else _triage_reason(response),
        result=response.data.get("result", {}) if response.ok else {},
    )


def _record_failed_triage(
    *,
    store: ArtifactStore,
    run_id: str,
    state: _TriageReportState,
    redactor: Redactor,
) -> ToolResponse:
    section_reasons = {
        "panic_reason": state.report.panic_reason.reason,
        "faulting_task": state.report.faulting_task.reason,
        "backtrace": state.report.backtrace.reason,
        "recent_dmesg": state.report.recent_dmesg.reason,
        "modules": state.report.modules.reason,
    }
    details = redactor.redact_value(
        {
            "code": "triage_all_sources_failed",
            "sub_call_ids": state.sub_call_ids,
            "section_reasons": section_reasons,
        }
    )
    record_append_only_terminal_step(
        store,
        run_id,
        StepResult(
            step_name=f"postmortem.triage:{uuid.uuid4().hex}",
            status=StepStatus.FAILED,
            summary="triage: all sources failed",
            artifacts=[],
            details={"code": "triage_all_sources_failed", "duration_ms": state.duration_ms},
        ),
    )
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        run_id=run_id,
        message="triage produced no usable section; both crash and drgn sources failed",
        details=details,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _persist_successful_triage_report(
    *,
    store: ArtifactStore,
    run_id: str,
    run_dir: Path,
    vmcore_build_id: str,
    state: _TriageReportState,
    redactor: Redactor,
) -> ToolResponse:
    call_id = uuid.uuid4().hex
    redacted_report = redactor.redact_value(state.report.model_dump(mode="json"))
    agent_dir = run_dir / "debug" / "postmortem" / "triage" / call_id
    agent_dir.mkdir(parents=True, mode=0o700)
    report_path = agent_dir / "report.json"
    atomic_write_text(report_path, json.dumps(redacted_report))
    artifact = ArtifactRef(path=str(report_path.relative_to(run_dir)), kind="triage_report_json")
    partial = not all(
        section["status"] == "ok"
        for section in (
            redacted_report["panic_reason"],
            redacted_report["faulting_task"],
            redacted_report["backtrace"],
            redacted_report["recent_dmesg"],
            redacted_report["modules"],
        )
    )
    record_append_only_terminal_step(
        store,
        run_id,
        StepResult(
            step_name=f"postmortem.triage:{call_id}",
            status=StepStatus.SUCCEEDED,
            summary=f"triage report (partial={partial})",
            artifacts=[artifact],
            details={
                "call_id": call_id,
                "vmcore_build_id": vmcore_build_id,
                "partial": partial,
                "duration_ms": state.duration_ms,
            },
        ),
    )
    return ToolResponse.success(
        summary=f"triage report (partial={partial})",
        run_id=run_id,
        data={
            "call_id": call_id,
            "report": redacted_report,
            "partial": partial,
            "vmcore_build_id": vmcore_build_id,
            "sub_call_ids": state.sub_call_ids,
            "started_at": state.started_at.isoformat(),
            "finished_at": state.finished_at.isoformat(),
            "duration_ms": state.duration_ms,
        },
        artifacts=[artifact],
        suggested_next_actions=[
            "debug.postmortem.crash",
            "debug.introspect.from_vmcore_helper",
            "artifacts.get_manifest",
        ],
    )


def debug_postmortem_triage_handler(
    request: DebugPostmortemTriageRequest,
    *,
    runtime: PostmortemToolRuntime,
) -> ToolResponse:
    """Spec §4 / ADR 0027. Compose the crash + drgn offline tiers into one report; no admission gate."""
    if runtime.drgn_helper_handler is None:
        raise TypeError("drgn_helper_handler is required")
    run_id = request.run_id
    now = runtime.clock or _utcnow
    ctx, failure = resolve_postmortem_vmcore_context(
        request,
        artifact_root=runtime.artifact_root,
        vmcore_build_id_reader=runtime.vmcore_build_id_reader or read_vmcore_build_id,
        vmlinux_build_id_reader=runtime.vmlinux_build_id_reader or read_elf_build_id,
    )
    if failure is not None:
        return failure
    if ctx is None:
        raise RuntimeError("postmortem vmcore context missing after successful resolution")
    store = ctx.store
    run_dir = ctx.run_dir
    vmcore_build_id = ctx.vmcore_build_id

    started_at = now()
    started_monotonic = time.monotonic()
    sources = _run_triage_sources(
        request,
        runtime=runtime,
    )
    duration_ms = int((time.monotonic() - started_monotonic) * 1000)
    state = _build_triage_report_state(
        vmcore_build_id=vmcore_build_id,
        sources=sources,
        started_at=started_at,
        finished_at=now(),
        duration_ms=duration_ms,
    )
    redactor = Redactor(secret_values=[])

    if not any_section_ok(state.report):
        return _record_failed_triage(store=store, run_id=run_id, state=state, redactor=redactor)

    return _persist_successful_triage_report(
        store=store,
        run_id=run_id,
        run_dir=run_dir,
        vmcore_build_id=vmcore_build_id,
        state=state,
        redactor=redactor,
    )
