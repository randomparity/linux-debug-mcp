from __future__ import annotations

from kdive.postmortem.models import DebugPostmortemTriageReport
from kdive.postmortem.triage import (
    CrashOutcome,
    DrgnOutcome,
    any_section_ok,
    assemble_report,
    select_panic_reason,
)


def test_selects_highest_priority_signature() -> None:
    lines = [
        {"ts": 1.0, "text": "BUG: unable to handle kernel paging request"},
        {"ts": 2.0, "text": "Kernel panic - not syncing: Fatal exception"},
    ]
    # "Kernel panic - not syncing" outranks "BUG:" despite appearing later.
    assert select_panic_reason(lines) == "Kernel panic - not syncing: Fatal exception"


def test_falls_back_to_lower_signature() -> None:
    lines = [{"ts": 1.0, "text": "BUG: spinlock bad magic"}]
    assert select_panic_reason(lines) == "BUG: spinlock bad magic"


def test_no_match_returns_none() -> None:
    assert select_panic_reason([{"ts": 1.0, "text": "eth0: link up"}]) is None


def test_empty_list_returns_none() -> None:
    assert select_panic_reason([]) is None


def test_missing_text_key_does_not_raise() -> None:
    assert select_panic_reason([{"ts": 1.0}]) is None


_BID = "ab" * 20


def _crash_ok() -> CrashOutcome:
    return CrashOutcome(
        ok=True,
        reason=None,
        results={
            "log": {"parsed": True, "lines": [{"ts": 1.0, "text": "Kernel panic - not syncing: x"}]},
            "bt": {"parsed": True, "pid": 7, "command": "kworker", "frames": [{"level": 0, "symbol": "panic"}]},
        },
    )


def test_happy_path_all_ok() -> None:
    report = assemble_report(
        vmcore_build_id=_BID,
        crash=_crash_ok(),
        dmesg=DrgnOutcome(ok=True, reason=None, result={"entries": [{"text": "boot"}], "truncated": False}),
        modules=DrgnOutcome(ok=True, reason=None, result={"modules": [{"name": "ext4"}], "decode_errors": 0}),
    )
    assert isinstance(report, DebugPostmortemTriageReport)
    assert report.panic_reason.status == "ok"
    assert report.panic_reason.text == "Kernel panic - not syncing: x"
    assert report.faulting_task.pid == 7 and report.faulting_task.command == "kworker"
    assert report.backtrace.frames == [{"level": 0, "symbol": "panic"}]
    assert report.recent_dmesg.entries == [{"text": "boot"}]
    assert report.modules.modules == [{"name": "ext4"}]
    assert all(
        s.status == "ok"
        for s in (report.panic_reason, report.faulting_task, report.backtrace, report.recent_dmesg, report.modules)
    )


def test_crash_source_down_fails_three_sections() -> None:
    report = assemble_report(
        vmcore_build_id=_BID,
        crash=CrashOutcome(ok=False, reason="crash_open_failure", results={}),
        dmesg=DrgnOutcome(ok=True, reason=None, result={"entries": [], "truncated": False}),
        modules=DrgnOutcome(ok=True, reason=None, result={"modules": [], "decode_errors": 0}),
    )
    assert report.panic_reason.status == "failed" and report.panic_reason.reason == "crash_open_failure"
    assert report.faulting_task.status == "failed" and report.backtrace.status == "failed"
    assert report.recent_dmesg.status == "ok" and report.modules.status == "ok"


def test_within_crash_bt_not_captured_log_ok() -> None:
    report = assemble_report(
        vmcore_build_id=_BID,
        crash=CrashOutcome(
            ok=True,
            reason=None,
            results={
                "log": {"parsed": True, "lines": [{"ts": 1.0, "text": "ok no panic"}]},
                "bt": {"parsed": False, "reason": "not_captured", "raw": None},
            },
        ),
        dmesg=DrgnOutcome(ok=False, reason="helper_script_error", result={}),
        modules=DrgnOutcome(ok=False, reason="helper_script_error", result={}),
    )
    assert report.panic_reason.status == "ok" and report.panic_reason.text is None
    assert report.backtrace.status == "failed" and report.backtrace.reason == "not_captured"
    assert report.faulting_task.status == "failed" and report.faulting_task.reason == "not_captured"


def test_bt_missing_from_results() -> None:
    report = assemble_report(
        vmcore_build_id=_BID,
        crash=CrashOutcome(ok=True, reason=None, results={"log": {"parsed": True, "lines": []}}),
        dmesg=DrgnOutcome(ok=True, reason=None, result={"entries": [], "truncated": False}),
        modules=DrgnOutcome(ok=True, reason=None, result={"modules": [], "decode_errors": 0}),
    )
    assert report.backtrace.status == "failed" and report.backtrace.reason == "bt_missing"


def test_any_section_ok_helper() -> None:
    none_ok = assemble_report(
        vmcore_build_id=_BID,
        crash=CrashOutcome(ok=False, reason="crash_open_failure", results={}),
        dmesg=DrgnOutcome(ok=False, reason="helper_script_error", result={}),
        modules=DrgnOutcome(ok=False, reason="helper_script_error", result={}),
    )
    assert any_section_ok(none_ok) is False

    one_ok = assemble_report(
        vmcore_build_id=_BID,
        crash=_crash_ok(),
        dmesg=DrgnOutcome(ok=False, reason="helper_script_error", result={}),
        modules=DrgnOutcome(ok=False, reason="helper_script_error", result={}),
    )
    assert any_section_ok(one_ok) is True
