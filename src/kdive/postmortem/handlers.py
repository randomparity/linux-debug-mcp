from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import TRIAGE_CRASH_COMMANDS, TRIAGE_DMESG_HELPER, TRIAGE_MODULES_HELPER
from kdive.domain import (
    ArtifactRef,
    DebugIntrospectFromVmcoreHelperRequest,
    ErrorCategory,
    StepResult,
    StepStatus,
    ToolResponse,
)
from kdive.introspect.execution import _record_terminal_introspect_result, _utcnow
from kdive.introspect.handlers import debug_introspect_from_vmcore_helper_handler
from kdive.postmortem.crash_commands import validate_modules_path
from kdive.postmortem.crash_handler import (
    _crash_build_id_fail_loud,
    _crash_config_failure,
    debug_postmortem_crash_handler,
)
from kdive.postmortem.models import DebugPostmortemCrashRequest, DebugPostmortemTriageRequest
from kdive.postmortem.triage import CrashOutcome, DrgnOutcome, any_section_ok, assemble_report
from kdive.providers.ssh import SshRunner
from kdive.safety.paths import PathSafetyError, confine_run_relative
from kdive.safety.redaction import Redactor
from kdive.seams.target import KernelProvenance
from kdive.symbols.build_id import read_elf_build_id
from kdive.symbols.resolve import SymbolResolutionError, resolve_symbols
from kdive.symbols.vmcore_build_id import read_vmcore_build_id


def _triage_subcall_id(resp: ToolResponse) -> str | None:
    """The sub-call's own call_id, on success (data) or failure (error.details)."""
    cid = resp.data.get("call_id") if resp.ok else (resp.error.details if resp.error else {}).get("call_id")
    return cid if isinstance(cid, str) else None


def _triage_reason(resp: ToolResponse) -> str:
    """A failed sub-call's stable error code, defensively (details may be empty)."""
    details = resp.error.details if resp.error else {}
    code = details.get("code")
    return code if isinstance(code, str) and code else "sub_call_failed"


def debug_postmortem_triage_handler(
    request: DebugPostmortemTriageRequest,
    *,
    artifact_root: Path,
    runner: SshRunner | None = None,
    vmcore_build_id_reader: Callable[[Path], str] = read_vmcore_build_id,
    vmlinux_build_id_reader: Callable[[Path], str] = read_elf_build_id,
    clock: Callable[[], datetime] | None = None,
    crash_handler: Callable[..., ToolResponse] = debug_postmortem_crash_handler,
    drgn_helper_handler: Callable[..., ToolResponse] = debug_introspect_from_vmcore_helper_handler,
) -> ToolResponse:
    """Spec §4 / ADR 0027. Compose the crash + drgn offline tiers into one report; no admission gate."""
    run_id = request.run_id
    now = clock or _utcnow
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        if not (store.run_dir(run_id) / "manifest.json").is_file():
            return _crash_config_failure(run_id, "run_not_found", f"run not found: {run_id}")
        store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    if not (5 <= request.timeout_seconds <= 300):
        return _crash_config_failure(
            run_id, "invalid_timeout", f"timeout_seconds must be in [5, 300]; got {request.timeout_seconds}"
        )

    run_dir = store.run_dir(run_id)
    provenance_shell = KernelProvenance(
        build_id="",
        release="",
        vmlinux_ref=request.vmlinux_ref,
        modules_ref=request.modules_ref,
        cmdline="",
        config_ref=None,
    )
    try:
        resolved = resolve_symbols(provenance_shell, run_dir=run_dir)
    except SymbolResolutionError as exc:
        return _crash_config_failure(run_id, "symbol_resolution_failed", str(exc))
    try:
        vmcore_path = confine_run_relative(request.vmcore_ref, run_dir=run_dir)
    except PathSafetyError as exc:
        return _crash_config_failure(run_id, "vmcore_not_found", str(exc))
    if not vmcore_path.is_file():
        return _crash_config_failure(run_id, "vmcore_not_found", f"vmcore not found at {request.vmcore_ref!r}")
    if resolved.modules_path is not None and not validate_modules_path(str(resolved.modules_path)):
        return _crash_config_failure(run_id, "modules_path_unsafe", "resolved modules path has unsafe characters")

    vmcore_build_id, failure = _crash_build_id_fail_loud(
        run_id, vmcore_path, resolved.vmlinux_path, vmcore_build_id_reader, vmlinux_build_id_reader
    )
    if failure is not None:
        return failure

    started_at = now()
    started_monotonic = time.monotonic()

    crash_resp = crash_handler(
        DebugPostmortemCrashRequest(
            run_id=run_id,
            vmcore_ref=request.vmcore_ref,
            vmlinux_ref=request.vmlinux_ref,
            modules_ref=request.modules_ref,
            commands=list(TRIAGE_CRASH_COMMANDS),
            timeout_seconds=request.timeout_seconds,
        ),
        artifact_root=artifact_root,
        runner=runner,
        vmcore_build_id_reader=vmcore_build_id_reader,
        vmlinux_build_id_reader=vmlinux_build_id_reader,
        clock=clock,
    )

    def drgn(name: str) -> ToolResponse:
        return drgn_helper_handler(
            DebugIntrospectFromVmcoreHelperRequest(
                run_id=run_id,
                vmcore_ref=request.vmcore_ref,
                vmlinux_ref=request.vmlinux_ref,
                modules_ref=None,
                name=name,
                timeout_seconds=request.timeout_seconds,
            ),
            artifact_root=artifact_root,
            runner=runner,
            build_id_reader=vmlinux_build_id_reader,
            clock=clock,
        )

    dmesg_resp = drgn(TRIAGE_DMESG_HELPER)
    modules_resp = drgn(TRIAGE_MODULES_HELPER)

    crash_outcome = CrashOutcome(
        ok=crash_resp.ok,
        reason=None if crash_resp.ok else _triage_reason(crash_resp),
        results=crash_resp.data.get("results", {}) if crash_resp.ok else {},
    )
    dmesg_outcome = DrgnOutcome(
        ok=dmesg_resp.ok,
        reason=None if dmesg_resp.ok else _triage_reason(dmesg_resp),
        result=dmesg_resp.data.get("result", {}) if dmesg_resp.ok else {},
    )
    modules_outcome = DrgnOutcome(
        ok=modules_resp.ok,
        reason=None if modules_resp.ok else _triage_reason(modules_resp),
        result=modules_resp.data.get("result", {}) if modules_resp.ok else {},
    )

    report = assemble_report(
        vmcore_build_id=vmcore_build_id,
        crash=crash_outcome,
        dmesg=dmesg_outcome,
        modules=modules_outcome,
    )
    sub_call_ids = {
        "crash": _triage_subcall_id(crash_resp),
        "dmesg": _triage_subcall_id(dmesg_resp),
        "modules": _triage_subcall_id(modules_resp),
    }
    redactor = Redactor(secret_values=[])
    duration_ms = int((time.monotonic() - started_monotonic) * 1000)
    finished_at = now()

    if not any_section_ok(report):
        section_reasons = {
            "panic_reason": report.panic_reason.reason,
            "faulting_task": report.faulting_task.reason,
            "backtrace": report.backtrace.reason,
            "recent_dmesg": report.recent_dmesg.reason,
            "modules": report.modules.reason,
        }
        details = redactor.redact_value(
            {"code": "triage_all_sources_failed", "sub_call_ids": sub_call_ids, "section_reasons": section_reasons}
        )
        _record_terminal_introspect_result(
            store,
            run_id,
            StepResult(
                step_name=f"postmortem.triage:{uuid.uuid4().hex}",
                status=StepStatus.FAILED,
                summary="triage: all sources failed",
                artifacts=[],
                details={"code": "triage_all_sources_failed", "duration_ms": duration_ms},
            ),
        )
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="triage produced no usable section; both crash and drgn sources failed",
            details=details,
            suggested_next_actions=["artifacts.get_manifest"],
        )

    call_id = uuid.uuid4().hex
    redacted_report = redactor.redact_value(report.model_dump(mode="json"))
    agent_dir = run_dir / "debug" / "postmortem" / "triage" / call_id
    agent_dir.mkdir(parents=True, mode=0o700)
    report_path = agent_dir / "report.json"
    report_path.write_text(json.dumps(redacted_report), encoding="utf-8")
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
    _record_terminal_introspect_result(
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
                "duration_ms": duration_ms,
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
            "sub_call_ids": sub_call_ids,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_ms": duration_ms,
        },
        artifacts=[artifact],
        suggested_next_actions=[
            "debug.postmortem.crash",
            "debug.introspect.from_vmcore_helper",
            "artifacts.get_manifest",
        ],
    )
