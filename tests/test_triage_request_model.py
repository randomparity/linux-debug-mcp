from __future__ import annotations

import pytest
from pydantic import ValidationError

from kdive.domain import (
    BacktraceSection,
    DebugPostmortemTriageReport,
    DebugPostmortemTriageRequest,
    FaultingTaskSection,
    ModulesSection,
    PanicReasonSection,
    RecentDmesgSection,
)


def test_request_defaults_and_forbids_extra() -> None:
    req = DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux")
    assert req.modules_ref is None
    assert req.timeout_seconds == 60
    with pytest.raises(ValidationError):
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="a", vmlinux_ref="b", bogus=1)


def test_report_sections_carry_source_and_status() -> None:
    report = DebugPostmortemTriageReport(
        vmcore_build_id="ab" * 20,
        panic_reason=PanicReasonSection(status="ok", text="Kernel panic - not syncing: x"),
        faulting_task=FaultingTaskSection(status="ok", pid=7, command="kworker"),
        backtrace=BacktraceSection(status="ok", frames=[{"level": 0, "symbol": "panic"}]),
        recent_dmesg=RecentDmesgSection(status="failed", reason="crash_timeout"),
        modules=ModulesSection(status="ok", modules=[{"name": "ext4"}], decode_errors=0),
    )
    assert report.panic_reason.source == "crash"
    assert report.recent_dmesg.source == "drgn"
    assert report.recent_dmesg.status == "failed"
    assert report.modules.decode_errors == 0


def test_section_status_is_constrained() -> None:
    with pytest.raises(ValidationError):
        PanicReasonSection(status="bogus")
