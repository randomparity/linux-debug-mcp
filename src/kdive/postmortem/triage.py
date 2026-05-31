"""Pure section assembly for debug.postmortem.triage. Spec §4 / ADR 0027.

No I/O, no redaction (the handler redacts). Composes the crash and drgn sub-call
outputs into a DebugPostmortemTriageReport.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from kdive.postmortem.models import (
    BacktraceSection,
    DebugPostmortemTriageReport,
    FaultingTaskSection,
    ModulesSection,
    PanicReasonSection,
    RecentDmesgSection,
)

# Ordered; first match wins. Kept narrow and kernel-specific (ADR 0027 decision 2a).
_PANIC_SIGNATURES: tuple[str, ...] = (
    "Kernel panic - not syncing",
    "Kernel panic",
    "Unable to handle kernel",
    "general protection fault",
    "kernel BUG at",
    "BUG:",
    "Oops",
)


def select_panic_reason(log_lines: list[Mapping[str, Any]]) -> str | None:
    """Return the first log line matching the highest-priority panic signature.

    Selection over the crash ``log`` parser's already-redacted structured lines — not a
    new parser. Pure and total; never raises. A non-panic core returns ``None``.
    """
    for signature in _PANIC_SIGNATURES:
        for line in log_lines:
            text = line.get("text") or ""
            if signature in text:
                return text
    return None


@dataclass(frozen=True)
class CrashOutcome:
    """Distilled crash sub-call result. ``results`` is the redacted command→parsed map
    when ``ok``; ``reason`` is the sub-call's stable error code when not ``ok``."""

    ok: bool
    reason: str | None
    results: dict[str, Any]


@dataclass(frozen=True)
class DrgnOutcome:
    """Distilled drgn helper sub-call result. ``result`` is the redacted helper output
    (``{"entries"/"modules": ...}``) when ``ok``; ``reason`` is the error code otherwise."""

    ok: bool
    reason: str | None
    result: dict[str, Any]


def _crash_sections(crash: CrashOutcome) -> tuple[PanicReasonSection, FaultingTaskSection, BacktraceSection]:
    if not crash.ok:
        reason = crash.reason or "sub_call_failed"
        return (
            PanicReasonSection(status="failed", reason=reason),
            FaultingTaskSection(status="failed", reason=reason),
            BacktraceSection(status="failed", reason=reason),
        )
    log = crash.results.get("log")
    if isinstance(log, Mapping) and log.get("parsed"):
        panic = PanicReasonSection(status="ok", text=select_panic_reason(list(log.get("lines") or [])))
    else:
        panic_reason = (log.get("reason") if isinstance(log, Mapping) else None) or "log_missing"
        panic = PanicReasonSection(status="failed", reason=panic_reason)
    bt = crash.results.get("bt")
    if isinstance(bt, Mapping) and bt.get("parsed"):
        faulting = FaultingTaskSection(status="ok", pid=bt.get("pid"), command=bt.get("command"))
        backtrace = BacktraceSection(status="ok", frames=list(bt.get("frames") or []))
    else:
        bt_reason = (bt.get("reason") if isinstance(bt, Mapping) else None) or "bt_missing"
        faulting = FaultingTaskSection(status="failed", reason=bt_reason)
        backtrace = BacktraceSection(status="failed", reason=bt_reason)
    return panic, faulting, backtrace


def _dmesg_section(dmesg: DrgnOutcome) -> RecentDmesgSection:
    if dmesg.ok:
        return RecentDmesgSection(
            status="ok",
            entries=list(dmesg.result.get("entries") or []),
            truncated=bool(dmesg.result.get("truncated", False)),
        )
    return RecentDmesgSection(status="failed", reason=dmesg.reason or "sub_call_failed")


def _modules_section(modules: DrgnOutcome) -> ModulesSection:
    if modules.ok:
        return ModulesSection(
            status="ok",
            modules=list(modules.result.get("modules") or []),
            decode_errors=int(modules.result.get("decode_errors", 0)),
        )
    return ModulesSection(status="failed", reason=modules.reason or "sub_call_failed")


def assemble_report(
    *,
    vmcore_build_id: str,
    crash: CrashOutcome,
    dmesg: DrgnOutcome,
    modules: DrgnOutcome,
) -> DebugPostmortemTriageReport:
    """Compose the five sections into one report. Pure; the handler redacts/persists."""
    panic, faulting, backtrace = _crash_sections(crash)
    return DebugPostmortemTriageReport(
        vmcore_build_id=vmcore_build_id,
        panic_reason=panic,
        faulting_task=faulting,
        backtrace=backtrace,
        recent_dmesg=_dmesg_section(dmesg),
        modules=_modules_section(modules),
    )


def any_section_ok(report: DebugPostmortemTriageReport) -> bool:
    """True iff at least one section is ``ok`` (the partial-success boundary; ADR 0027
    decision 3). False → triage hard-fails with ``triage_all_sources_failed``."""
    return any(
        section.status == "ok"
        for section in (
            report.panic_reason,
            report.faulting_task,
            report.backtrace,
            report.recent_dmesg,
            report.modules,
        )
    )
