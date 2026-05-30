# `debug.postmortem.triage` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `debug.postmortem.triage` MCP tool that composes the existing crash (#92) and drgn (#54/#55) offline tiers into one typed `DebugPostmortemTriageReport` (panic reason, faulting task, backtrace, recent dmesg, modules) with a single up-front build-id gate and a per-section partial-failure contract.

**Architecture:** A thin orchestrator handler (`debug_postmortem_triage_handler` in `server.py`) runs one host-authoritative build-id gate over the shared refs, then calls the existing `debug_postmortem_crash_handler` once (`commands=["log","bt"]`) and `debug_introspect_from_vmcore_helper_handler` twice (`dmesg`, `modules`) as injectable in-process seams. A pure module (`postmortem/triage.py`) assembles the five report sections and selects the panic line; the handler redacts and persists the composed report. No new analysis mechanism, no admission gate (ADR 0027).

**Tech Stack:** Python 3.11+, Pydantic v2 (`Model` base, `extra="forbid"`), FastMCP tool registration, pytest. Lint/format `ruff`; types `ty`.

**Reference docs:** spec `docs/superpowers/specs/2026-05-30-debug-postmortem-triage-design.md`; ADR `docs/adr/0027-postmortem-triage-composition.md`. Read both before starting.

---

## File structure

- `src/linux_debug_mcp/domain.py` — **modify**: add `DebugPostmortemTriageRequest`, the five section models, and `DebugPostmortemTriageReport`.
- `src/linux_debug_mcp/config.py` — **modify**: add `"debug.postmortem.triage"` to `ALLOWED_DEBUG_OPERATIONS`; add `TRIAGE_CRASH_COMMANDS`, `TRIAGE_DMESG_HELPER`, `TRIAGE_MODULES_HELPER`.
- `src/linux_debug_mcp/postmortem/triage.py` — **create**: pure `select_panic_reason()` + `assemble_report()` (+ two small input dataclasses). No I/O, no redaction.
- `src/linux_debug_mcp/server.py` — **modify**: `debug_postmortem_triage_handler()` orchestrator + `@app.tool("debug.postmortem.triage")` wrapper.
- `src/linux_debug_mcp/providers/local_crash_postmortem.py` — **modify**: add `"debug.postmortem.triage"` to `operations`.
- `docs/debug-postmortem.md` — **modify**: add a `triage` section.
- Tests: `tests/test_triage_assemble.py`, `tests/test_debug_postmortem_triage.py`, `tests/test_triage_config.py`, `tests/test_postmortem_triage_integration.py`.

---

## Task 1: Domain models — request, sections, report

**Files:**
- Modify: `src/linux_debug_mcp/domain.py` (add after `DebugPostmortemCrashRequest`, near line 208)
- Test: `tests/test_triage_request_model.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_triage_request_model.py
from __future__ import annotations

import pytest
from pydantic import ValidationError

from linux_debug_mcp.domain import (
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_triage_request_model.py -q`
Expected: FAIL with `ImportError` (models not defined).

- [ ] **Step 3: Add the models**

In `src/linux_debug_mcp/domain.py`, add `Literal` to the typing import at the top (change `from typing import Any` to `from typing import Any, Literal`), then insert after the `DebugPostmortemCrashRequest` class (after line ~208):

```python
class DebugPostmortemTriageRequest(Model):
    """Request payload for ``debug.postmortem.triage``. Spec §3.1.

    Composes the crash (#92) and drgn (#54/#55) offline tiers into one report.
    No ``commands``/``helpers`` (fixed helper set) and no ``target_ref``/``*_profile``
    (offline, never gated). ``timeout_seconds`` is handler-bounded to ``[5, 300]`` and
    applied to EACH sub-call; ``modules_ref`` is validated up front and threaded to the
    crash sub-call only.
    """

    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    timeout_seconds: int = 60


class _TriageSectionBase(Model):
    """Shared per-section status. Spec §3.3 / ADR 0027 decision 3."""

    status: Literal["ok", "failed"]
    reason: str | None = None  # the sub-call's stable error code, set iff status == "failed"


class PanicReasonSection(_TriageSectionBase):
    source: Literal["crash"] = "crash"
    text: str | None = None  # selected panic line; None when none matched (status may still be "ok")


class FaultingTaskSection(_TriageSectionBase):
    source: Literal["crash"] = "crash"
    pid: int | None = None
    command: str | None = None


class BacktraceSection(_TriageSectionBase):
    source: Literal["crash"] = "crash"
    frames: list[dict[str, Any]] = Field(default_factory=list)


class RecentDmesgSection(_TriageSectionBase):
    source: Literal["drgn"] = "drgn"
    entries: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool = False


class ModulesSection(_TriageSectionBase):
    source: Literal["drgn"] = "drgn"
    modules: list[dict[str, Any]] = Field(default_factory=list)
    decode_errors: int = 0


class DebugPostmortemTriageReport(Model):
    """Composite triage report. Spec §3.3. All section payloads are pass-through of the
    already-typed-and-redacted upstream shapes (ADR 0027 decision 8)."""

    vmcore_build_id: str
    panic_reason: PanicReasonSection
    faulting_task: FaultingTaskSection
    backtrace: BacktraceSection
    recent_dmesg: RecentDmesgSection
    modules: ModulesSection
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_triage_request_model.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check src/linux_debug_mcp/domain.py tests/test_triage_request_model.py
uv run ruff format src/linux_debug_mcp/domain.py tests/test_triage_request_model.py
uv run ty check src
git add src/linux_debug_mcp/domain.py tests/test_triage_request_model.py
git commit -m "feat(postmortem): add triage request + report domain models

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

Expected: ruff clean, `ty` no new errors, commit succeeds.

---

## Task 2: `select_panic_reason` (pure panic-line selection)

**Files:**
- Create: `src/linux_debug_mcp/postmortem/triage.py`
- Test: `tests/test_triage_assemble.py` (create — also used by Task 3)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_triage_assemble.py
from __future__ import annotations

from linux_debug_mcp.postmortem.triage import select_panic_reason


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_triage_assemble.py -q`
Expected: FAIL with `ModuleNotFoundError: linux_debug_mcp.postmortem.triage`.

- [ ] **Step 3: Create `triage.py` with `select_panic_reason`**

```python
# src/linux_debug_mcp/postmortem/triage.py
"""Pure section assembly for debug.postmortem.triage. Spec §4 / ADR 0027.

No I/O, no redaction (the handler redacts). Composes the crash and drgn sub-call
outputs into a DebugPostmortemTriageReport.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_triage_assemble.py -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check src/linux_debug_mcp/postmortem/triage.py tests/test_triage_assemble.py
uv run ruff format src/linux_debug_mcp/postmortem/triage.py tests/test_triage_assemble.py
uv run ty check src
git add src/linux_debug_mcp/postmortem/triage.py tests/test_triage_assemble.py
git commit -m "feat(postmortem): add select_panic_reason for triage

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `assemble_report` (pure section assembly)

**Files:**
- Modify: `src/linux_debug_mcp/postmortem/triage.py`
- Test: `tests/test_triage_assemble.py` (append)

`assemble_report` takes three small outcome objects (built by the handler from the
sub-call `ToolResponse`s) plus the verified `vmcore_build_id`, and returns a
`DebugPostmortemTriageReport`. Keeping it free of `ToolResponse` keeps it pure-testable.

- [ ] **Step 1: Write the failing test (append to `tests/test_triage_assemble.py`)**

```python
from linux_debug_mcp.domain import DebugPostmortemTriageReport
from linux_debug_mcp.postmortem.triage import CrashOutcome, DrgnOutcome, assemble_report

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


def test_all_sections_ok_helper() -> None:
    from linux_debug_mcp.postmortem.triage import any_section_ok

    report = assemble_report(
        vmcore_build_id=_BID,
        crash=CrashOutcome(ok=False, reason="crash_open_failure", results={}),
        dmesg=DrgnOutcome(ok=False, reason="helper_script_error", result={}),
        modules=DrgnOutcome(ok=False, reason="helper_script_error", result={}),
    )
    assert any_section_ok(report) is False

    report2 = _crash_ok()
    full = assemble_report(
        vmcore_build_id=_BID,
        crash=report2,
        dmesg=DrgnOutcome(ok=False, reason="helper_script_error", result={}),
        modules=DrgnOutcome(ok=False, reason="helper_script_error", result={}),
    )
    assert any_section_ok(full) is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_triage_assemble.py -q`
Expected: FAIL with `ImportError` (`CrashOutcome`/`DrgnOutcome`/`assemble_report`/`any_section_ok` not defined).

- [ ] **Step 3: Add outcomes + `assemble_report` + `any_section_ok` to `triage.py`**

Append to `src/linux_debug_mcp/postmortem/triage.py` (the `from` imports at the top already cover `dataclass`, `Any`, `Mapping`; add the domain import):

```python
from linux_debug_mcp.domain import (
    BacktraceSection,
    DebugPostmortemTriageReport,
    FaultingTaskSection,
    ModulesSection,
    PanicReasonSection,
    RecentDmesgSection,
)


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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_triage_assemble.py -q`
Expected: PASS (10 tests total).

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check src/linux_debug_mcp/postmortem/triage.py tests/test_triage_assemble.py
uv run ruff format src/linux_debug_mcp/postmortem/triage.py tests/test_triage_assemble.py
uv run ty check src
git add src/linux_debug_mcp/postmortem/triage.py tests/test_triage_assemble.py
git commit -m "feat(postmortem): add assemble_report section composition

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Config constants + allowlist

**Files:**
- Modify: `src/linux_debug_mcp/config.py` (`ALLOWED_DEBUG_OPERATIONS` near line 132; add constants near the crash bounds at line 149)
- Test: `tests/test_triage_config.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_triage_config.py
from __future__ import annotations

from linux_debug_mcp.config import (
    ALLOWED_DEBUG_OPERATIONS,
    TRIAGE_CRASH_COMMANDS,
    TRIAGE_DMESG_HELPER,
    TRIAGE_MODULES_HELPER,
)


def test_triage_operation_is_allowlisted() -> None:
    assert "debug.postmortem.triage" in ALLOWED_DEBUG_OPERATIONS


def test_fixed_helper_set_constants() -> None:
    assert TRIAGE_CRASH_COMMANDS == ("log", "bt")
    assert TRIAGE_DMESG_HELPER == "dmesg"
    assert TRIAGE_MODULES_HELPER == "modules"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_triage_config.py -q`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Add the constants + allowlist entry**

In `src/linux_debug_mcp/config.py`, add to `ALLOWED_DEBUG_OPERATIONS` right after the `"debug.postmortem.crash"` entry (line ~132):

```python
    # Composite triage (#93). Listed for enumerability; never gated (§5.6 rule 3) —
    # composes the crash + drgn offline tiers, no DebugProfile in the request.
    "debug.postmortem.triage",
```

Then add, immediately after the `CRASH_COMMAND_ALLOWLIST` block (after its closing `}`):

```python
# debug.postmortem.triage fixed helper set (#93 / spec §7). Reviewable in one place.
TRIAGE_CRASH_COMMANDS: tuple[str, ...] = ("log", "bt")
TRIAGE_DMESG_HELPER = "dmesg"
TRIAGE_MODULES_HELPER = "modules"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_triage_config.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check src/linux_debug_mcp/config.py tests/test_triage_config.py
uv run ruff format src/linux_debug_mcp/config.py tests/test_triage_config.py
uv run ty check src
git add src/linux_debug_mcp/config.py tests/test_triage_config.py
git commit -m "feat(postmortem): allowlist triage op + fixed helper-set constants

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: The orchestrator handler

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (add `debug_postmortem_triage_handler` after `_finalize_crash_call`, near line 4279; add imports to the `domain` and `postmortem.triage` import blocks)
- Test: `tests/test_debug_postmortem_triage.py` (create)

The handler mirrors `debug_postmortem_crash_handler`'s up-front structure (manifest load,
timeout check, confine vmcore, resolve symbols, `validate_modules_path`,
`_crash_buildid_failloud`), then calls the injected sub-handlers and `assemble_report`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_debug_postmortem_triage.py
from __future__ import annotations

from pathlib import Path

import pytest

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import (
    DebugPostmortemTriageRequest,
    ErrorCategory,
    RunRequest,
    StepStatus,
    ToolResponse,
)
from linux_debug_mcp.server import debug_postmortem_triage_handler

GOOD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


def _run(tmp_path: Path) -> ArtifactStore:
    store = ArtifactStore(artifact_root=tmp_path)
    store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/s",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    rd = store.run_dir("r1")
    (rd / "inputs").mkdir(exist_ok=True)
    (rd / "build").mkdir(exist_ok=True)
    (rd / "inputs" / "vmcore").write_bytes(b"core")
    (rd / "build" / "vmlinux").write_bytes(b"elf")
    return store


class _Recorder:
    """Counts sub-handler invocations and returns a canned ToolResponse."""

    def __init__(self, response: ToolResponse) -> None:
        self.response = response
        self.calls: list[dict] = []

    def __call__(self, request, **kwargs):
        self.calls.append({"request": request, "kwargs": kwargs})
        return self.response


def _crash_ok() -> ToolResponse:
    return ToolResponse.success(
        summary="crash",
        run_id="r1",
        data={
            "call_id": "crash1",
            "results": {
                "log": {"parsed": True, "lines": [{"ts": 1.0, "text": "Kernel panic - not syncing: boom"}]},
                "bt": {"parsed": True, "pid": 7, "command": "kworker", "frames": [{"level": 0, "symbol": "panic"}]},
            },
        },
    )


def _drgn_ok(payload: dict) -> ToolResponse:
    return ToolResponse.success(summary="drgn", run_id="r1", data={"call_id": "d", "result": payload})


def _common(**overrides):
    base = dict(
        artifact_root=None,  # set per-call
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    base.update(overrides)
    return base


def test_happy_path_full_report(tmp_path) -> None:
    store = _run(tmp_path)
    crash = _Recorder(_crash_ok())
    dmesg = _Recorder(_drgn_ok({"entries": [{"text": "boot"}], "truncated": False}))
    modules = _Recorder(_drgn_ok({"modules": [{"name": "ext4"}], "decode_errors": 0}))
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=lambda req, **kw: (dmesg if req.name == "dmesg" else modules)(req, **kw),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert resp.data["partial"] is False
    report = resp.data["report"]
    assert report["panic_reason"]["text"] == "Kernel panic - not syncing: boom"
    assert report["faulting_task"]["pid"] == 7
    assert report["recent_dmesg"]["entries"] == [{"text": "boot"}]
    assert report["modules"]["modules"] == [{"name": "ext4"}]
    assert resp.data["sub_call_ids"]["crash"] == "crash1"
    # report.json persisted under debug/
    rd = store.run_dir("r1")
    assert any((rd / "debug" / "postmortem" / "triage").glob("*/report.json"))
    assert any(n.startswith("postmortem.triage:") for n in store.load_manifest("r1").step_results)


def test_partial_crash_down(tmp_path) -> None:
    _run(tmp_path)
    crash = _Recorder(ToolResponse.failure(category=ErrorCategory.INFRASTRUCTURE_FAILURE, message="no crash", run_id="r1", details={"code": "crash_open_failure"}))
    dmesg = _Recorder(_drgn_ok({"entries": [{"text": "boot"}], "truncated": False}))
    modules = _Recorder(_drgn_ok({"modules": [], "decode_errors": 0}))
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=lambda req, **kw: (dmesg if req.name == "dmesg" else modules)(req, **kw),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert resp.data["partial"] is True
    report = resp.data["report"]
    assert report["panic_reason"]["status"] == "failed"
    assert report["panic_reason"]["reason"] == "crash_open_failure"
    assert report["recent_dmesg"]["status"] == "ok"


def test_build_id_mismatch_no_subcall(tmp_path) -> None:
    _run(tmp_path)
    crash = _Recorder(_crash_ok())
    drgn = _Recorder(_drgn_ok({"entries": []}))
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=drgn,
        vmcore_build_id_reader=lambda _p: "a" * 40,
        vmlinux_build_id_reader=lambda _p: "b" * 40,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_mismatch"
    assert crash.calls == [] and drgn.calls == []


def test_all_sources_down_hard_fail(tmp_path) -> None:
    _run(tmp_path)
    crash = _Recorder(ToolResponse.failure(category=ErrorCategory.INFRASTRUCTURE_FAILURE, message="x", run_id="r1", details={"code": "crash_open_failure", "call_id": "crashX"}))
    drgn = _Recorder(ToolResponse.failure(category=ErrorCategory.INFRASTRUCTURE_FAILURE, message="y", run_id="r1", details={"code": "helper_script_error"}))
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=drgn,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "triage_all_sources_failed"
    assert resp.error.details["sub_call_ids"]["crash"] == "crashX"


def test_detail_less_failure_does_not_raise(tmp_path) -> None:
    _run(tmp_path)
    # A sub-handler failure with NO details (e.g. a ManifestStateError branch).
    crash = _Recorder(ToolResponse.failure(category=ErrorCategory.INFRASTRUCTURE_FAILURE, message="bare", run_id="r1"))
    dmesg = _Recorder(_drgn_ok({"entries": [{"text": "x"}], "truncated": False}))
    modules = _Recorder(_drgn_ok({"modules": [], "decode_errors": 0}))
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=lambda req, **kw: (dmesg if req.name == "dmesg" else modules)(req, **kw),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert resp.data["report"]["panic_reason"]["reason"] == "sub_call_failed"
    assert resp.data["sub_call_ids"]["crash"] is None


def test_drgn_subcalls_get_modules_ref_none(tmp_path) -> None:
    _run(tmp_path)
    (tmp_path / "r1" / "build" / "mods").mkdir(parents=True, exist_ok=True)
    seen = {}

    def _drgn(req, **kw):
        seen[req.name] = req.modules_ref
        return _drgn_ok({"entries": [], "truncated": False} if req.name == "dmesg" else {"modules": [], "decode_errors": 0})

    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", modules_ref="build/mods"),
        artifact_root=tmp_path,
        crash_handler=_Recorder(_crash_ok()),
        drgn_helper_handler=_drgn,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert seen == {"dmesg": None, "modules": None}


def test_invalid_timeout_no_subcall(tmp_path) -> None:
    _run(tmp_path)
    crash = _Recorder(_crash_ok())
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", timeout_seconds=4),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=_Recorder(_drgn_ok({})),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "invalid_timeout"
    assert crash.calls == []


def test_redaction_masks_secret_in_report(tmp_path) -> None:
    store = _run(tmp_path)
    secret = "hunter2trustno1xyz"  # pragma: allowlist secret
    crash = _Recorder(
        ToolResponse.success(
            summary="crash",
            run_id="r1",
            data={"call_id": "c", "results": {"log": {"parsed": True, "lines": [{"ts": 1.0, "text": f"db_password={secret} boom"}]}, "bt": {"parsed": False, "reason": "not_captured"}}},
        )
    )
    dmesg = _Recorder(_drgn_ok({"entries": [], "truncated": False}))
    modules = _Recorder(_drgn_ok({"modules": [], "decode_errors": 0}))
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=lambda req, **kw: (dmesg if req.name == "dmesg" else modules)(req, **kw),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert secret not in repr(resp.data["report"])
    rd = store.run_dir("r1")
    for p in (rd / "debug" / "postmortem" / "triage").glob("*/report.json"):
        assert secret not in p.read_text(encoding="utf-8")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_debug_postmortem_triage.py -q`
Expected: FAIL with `ImportError` (`debug_postmortem_triage_handler` undefined).

- [ ] **Step 3: Add imports + the handler**

In `src/linux_debug_mcp/server.py`, extend the `domain` import block (line 62) with **`DebugPostmortemTriageRequest` only** (the handler never names `DebugPostmortemTriageReport` — it receives the report from `assemble_report()` and calls `.model_dump()`; importing the unused `DebugPostmortemTriageReport` here would trip ruff `F401` and fail this task's guardrail). Add the `postmortem.triage` import (new line after line 82):

```python
from linux_debug_mcp.postmortem.triage import (
    CrashOutcome,
    DrgnOutcome,
    any_section_ok,
    assemble_report,
)
```

Also add to the `config` import block (line 25) `TRIAGE_CRASH_COMMANDS`, `TRIAGE_DMESG_HELPER`, `TRIAGE_MODULES_HELPER`.

Then insert after `_finalize_crash_call` (after line 4279):

```python
def _triage_subcall_id(resp: ToolResponse) -> str | None:
    """The sub-call's own call_id, on success (data) or failure (error.details)."""
    if resp.ok:
        cid = resp.data.get("call_id")
    else:
        cid = (resp.error.details if resp.error else {}).get("call_id")
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
    """Spec §4 / ADR 0027. Compose the crash + drgn offline tiers into one report; no
    admission gate. One up-front build-id gate over the shared refs, then three sub-calls,
    then per-section assembly with a partial-vs-hard failure contract."""
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
    # Up-front gate over the shared refs (spec §4 step 2): resolve vmlinux + modules,
    # confine vmcore, charset-check modules_path, then the host build-id fail-loud — all
    # before any sub-call, so a caller-input ref error hard-fails (never a partial).
    provenance_shell = KernelProvenance(
        build_id="", release="", vmlinux_ref=request.vmlinux_ref, modules_ref=request.modules_ref, cmdline="", config_ref=None
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

    vmcore_build_id, failure = _crash_buildid_failloud(
        run_id, vmcore_path, resolved.vmlinux_path, vmcore_build_id_reader, vmlinux_build_id_reader
    )
    if failure is not None:
        return failure

    started_at = now()
    started_monotonic = time.monotonic()

    # Sub-calls (sequential): crash once (log+bt), then dmesg + modules. modules_ref rides
    # on the crash sub-call only; the drgn helpers get modules_ref=None (spec §3.1).
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

    def _drgn(name: str) -> ToolResponse:
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

    dmesg_resp = _drgn(TRIAGE_DMESG_HELPER)
    modules_resp = _drgn(TRIAGE_MODULES_HELPER)

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
        s["status"] == "ok"
        for s in (
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
            details={"call_id": call_id, "vmcore_build_id": vmcore_build_id, "partial": partial, "duration_ms": duration_ms},
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
        suggested_next_actions=["debug.postmortem.crash", "debug.introspect.from_vmcore_helper", "artifacts.get_manifest"],
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_debug_postmortem_triage.py -q`
Expected: PASS (8 tests).

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check src/linux_debug_mcp/server.py tests/test_debug_postmortem_triage.py
uv run ruff format src/linux_debug_mcp/server.py tests/test_debug_postmortem_triage.py
uv run ty check src
git add src/linux_debug_mcp/server.py tests/test_debug_postmortem_triage.py
git commit -m "feat(postmortem): add debug.postmortem.triage handler

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Tool registration

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (add `@app.tool` wrapper after the `debug.postmortem.crash` wrapper, near line 8124)
- Test: `tests/test_debug_postmortem_triage.py` (append a registration smoke test)

- [ ] **Step 1: Write the failing test (append)**

```python
def test_tool_is_registered() -> None:
    from linux_debug_mcp.server import create_app

    app = create_app()
    # FastMCP exposes registered tools; the triage tool must be present.
    import asyncio

    tools = asyncio.run(app.list_tools())
    assert any(t.name == "debug.postmortem.triage" for t in tools)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_debug_postmortem_triage.py::test_tool_is_registered -q`
Expected: FAIL (tool not registered).

- [ ] **Step 3: Add the registration wrapper**

In `src/linux_debug_mcp/server.py`, immediately after the `debug_postmortem_crash` tool wrapper (after line 8124):

```python
    @app.tool(name="debug.postmortem.triage")
    def debug_postmortem_triage(
        run_id: str,
        vmcore_ref: str,
        vmlinux_ref: str,
        modules_ref: str | None = None,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        request = DebugPostmortemTriageRequest(
            run_id=run_id,
            vmcore_ref=vmcore_ref,
            vmlinux_ref=vmlinux_ref,
            modules_ref=modules_ref,
            timeout_seconds=timeout_seconds,
        )
        return debug_postmortem_triage_handler(
            request,
            artifact_root=Path(artifact_root),
        ).model_dump(mode="json")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_debug_postmortem_triage.py::test_tool_is_registered -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check src/linux_debug_mcp/server.py
uv run ty check src
git add src/linux_debug_mcp/server.py tests/test_debug_postmortem_triage.py
git commit -m "feat(postmortem): register debug.postmortem.triage MCP tool

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Advertise the operation on the capability

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_crash_postmortem.py:33`
- Test: `tests/test_triage_capability.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_triage_capability.py
from __future__ import annotations

from linux_debug_mcp.providers.local_crash_postmortem import local_crash_postmortem_capability


def test_capability_advertises_triage() -> None:
    cap = local_crash_postmortem_capability()
    assert "debug.postmortem.triage" in cap.operations
    assert "debug.postmortem.crash" in cap.operations  # unchanged
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_triage_capability.py -q`
Expected: FAIL (`debug.postmortem.triage` not in operations).

- [ ] **Step 3: Add the operation**

In `src/linux_debug_mcp/providers/local_crash_postmortem.py`, change line 33:

```python
        operations=["debug.postmortem.crash", "debug.postmortem.triage"],
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_triage_capability.py -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check src/linux_debug_mcp/providers/local_crash_postmortem.py tests/test_triage_capability.py
uv run ty check src
git add src/linux_debug_mcp/providers/local_crash_postmortem.py tests/test_triage_capability.py
git commit -m "feat(postmortem): advertise triage op on local-crash-postmortem

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: Env-gated integration test (AC#4)

**Files:**
- Create: `tests/test_postmortem_triage_integration.py`

Mirrors the gating of `tests/test_postmortem_crash_integration.py`. Asserts the
fixture-agnostic invariants from spec §8: build-id provenance agreement, crash-side
well-formedness, drgn-side well-formedness.

- [ ] **Step 1: Write the test (it skips without the env)**

```python
# tests/test_postmortem_triage_integration.py
from __future__ import annotations

import importlib.util
import os
import shutil
from pathlib import Path

import pytest

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import (
    DebugIntrospectFromVmcoreRequest,
    DebugPostmortemTriageRequest,
    RunRequest,
)
from linux_debug_mcp.server import (
    debug_introspect_from_vmcore_handler,
    debug_postmortem_triage_handler,
)

_VMCORE = os.environ.get("LDM_VMCORE")
_VMLINUX = os.environ.get("LDM_VMLINUX")
_HAS_DRGN = importlib.util.find_spec("drgn") is not None
pytestmark = pytest.mark.skipif(
    not (_VMCORE and _VMLINUX and shutil.which("crash") and _HAS_DRGN),
    reason="set LDM_VMCORE + LDM_VMLINUX and install crash AND drgn to run (triage exercises both tiers)",
)


def _stage(tmp_path: Path) -> ArtifactStore:
    store = ArtifactStore(artifact_root=tmp_path)
    store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/s",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    rd = store.run_dir("r1")
    (rd / "inputs").mkdir(exist_ok=True)
    (rd / "build").mkdir(exist_ok=True)
    shutil.copy(_VMCORE, rd / "inputs" / "vmcore")
    shutil.copy(_VMLINUX, rd / "build" / "vmlinux")
    return store


def test_triage_real_core_consistency(tmp_path) -> None:
    _stage(tmp_path)
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
    )
    assert resp.ok is True, resp.error
    report = resp.data["report"]

    # Invariant 1: same-core provenance agreement (crash-verified id == drgn-reported id).
    drgn = debug_introspect_from_vmcore_handler(
        DebugIntrospectFromVmcoreRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            script='emit({"build_id": prog.main_module().build_id.hex()})',
        ),
        artifact_root=tmp_path,
    )
    assert drgn.ok is True, drgn.error
    assert drgn.data["build_id"] == report["vmcore_build_id"]

    # Invariant 2: crash side well-formed.
    assert report["faulting_task"]["status"] == "ok"
    assert isinstance(report["faulting_task"]["pid"], int) and report["faulting_task"]["pid"] >= 0
    assert report["backtrace"]["frames"]

    # Invariant 3: drgn side well-formed (fixture-agnostic).
    assert report["modules"]["status"] == "ok"
    assert report["modules"]["decode_errors"] == 0
    assert report["recent_dmesg"]["status"] == "ok"
    assert report["recent_dmesg"]["entries"]

    # Optional: a known-modular fixture asserts a non-empty module list.
    if os.environ.get("LDM_VMCORE_MODULAR") == "1":
        assert report["modules"]["modules"]
```

- [ ] **Step 2: Run the test (expect skip)**

Run: `uv run python -m pytest tests/test_postmortem_triage_integration.py -q`
Expected: SKIPPED (no `LDM_VMCORE`/`crash`).

- [ ] **Step 3: Guardrails + commit**

```bash
uv run ruff check tests/test_postmortem_triage_integration.py
uv run ruff format tests/test_postmortem_triage_integration.py
git add tests/test_postmortem_triage_integration.py
git commit -m "test(postmortem): env-gated real-core triage consistency test

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 9: Docs

**Files:**
- Modify: `docs/debug-postmortem.md` (append a `triage` section)

- [ ] **Step 1: Append the section**

Add at the end of `docs/debug-postmortem.md`:

```markdown

---

# `debug.postmortem.triage` — composite triage report

`debug.postmortem.triage` is the **one call** for an agent handed a crash, and the
recommended first reaction to the `target.crashed` lifecycle event. It composes the
crash and drgn offline tiers into a single typed report against one `(vmcore, vmlinux)`
pair. It is offline and **never gated**, like the rest of this tier.

Design: [spec](superpowers/specs/2026-05-30-debug-postmortem-triage-design.md) ·
[ADR 0027](adr/0027-postmortem-triage-composition.md).

## Request

| Field | Type | Notes |
|---|---|---|
| `run_id` | str | Existing run (`kernel.create_run`). |
| `vmcore_ref` | str | Run-relative path to the captured vmcore. |
| `vmlinux_ref` | str | Run-relative path to the uncompressed ELF vmlinux with symbols. |
| `modules_ref` | str \| null | Optional run-relative `*.ko[.debug]` dir; used by the crash sub-call only. |
| `timeout_seconds` | int | Handler-bounded to `[5, 300]` (default 60), applied to **each** sub-call. |

The three sub-calls run **sequentially**, so worst-case wall-clock is ≈ 3 ×
`timeout_seconds`; `duration_ms` reports the true elapsed time.

## What it composes

| Report section | Source | Sub-call |
|---|---|---|
| `panic_reason` | crash | `debug.postmortem.crash` `log` (panic line selected from the parsed log) |
| `faulting_task` | crash | `debug.postmortem.crash` `bt` (header pid/command) |
| `backtrace` | crash | `debug.postmortem.crash` `bt` (frames) |
| `recent_dmesg` | drgn | `debug.introspect.from_vmcore_helper` `dmesg` |
| `modules` | drgn | `debug.introspect.from_vmcore_helper` `modules` |

## Partial-report semantics

Each section is tagged `source` (`crash`/`drgn`), `status` (`ok`/`failed`), and — when
failed — a `reason` (the sub-call's stable error code). A failure in **one** source
fails only its sections; the report is returned with `partial: true` as long as at least
one section is `ok`. Only when **every** section failed does triage hard-fail with
`triage_all_sources_failed` (whose `details` carry `sub_call_ids` so a sub-call that
*ran* stays reachable). `sub_call_ids` also lets an agent pull a sub-call's own
transcript/artifacts.

## Build-id fail-loud

Before any sub-call, triage runs the host-authoritative build-id gate **once**
(`read_vmcore_build_id` vs `read_elf_build_id`). A mismatch / unreadable vmlinux /
unverifiable-or-unsupported vmcore is a `configuration_error` and **no sub-call runs** —
the whole triage fails loud, never a degraded report.

## Redaction

The composed report and the persisted `report.json` under
`<run>/debug/postmortem/triage/<call-id>/` pass through `Redactor()`; the
`triage_all_sources_failed` failure `details` are redacted too. Each sub-call's own raw
outputs stay under its own `sensitive/` tree (the sub-tiers' contract).
```

- [ ] **Step 2: Verify the doc guard**

Run: `just check-docs`
Expected: PASS (no "sprint" tokens).

- [ ] **Step 3: Commit**

```bash
git add docs/debug-postmortem.md
git commit -m "docs(postmortem): document debug.postmortem.triage

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 10: Full-suite guardrail sweep

- [ ] **Step 1: Run the whole suite + all guardrails**

```bash
uv run ruff check
uv run ruff format --check
uv run ty check src
uv run python -m pytest -q
```

Expected: ruff clean, format clean, `ty` reports no NEW errors vs `main`, all tests pass (triage integration test SKIPPED).

- [ ] **Step 2: If anything fails, fix and re-run before proceeding.** No commit needed if clean.

---

## Self-review notes (spec coverage)

- AC#1 (one structured report): Tasks 1, 3, 5 (`test_happy_path_full_report`).
- AC#2 (partial on one-source failure): Task 5 (`test_partial_crash_down`, `test_within_crash_bt_not_captured_log_ok` via Task 3).
- AC#3 (build-id mismatch hard-fails before any sub-call): Task 5 (`test_build_id_mismatch_no_subcall`).
- AC#4 (crash/drgn consistency on a real core): Task 8.
- AC#5 (redaction of report + persisted artifact): Task 5 (`test_redaction_masks_secret_in_report`).
- Up-front modules_ref validation + crash-only threading: Task 5 (`test_drgn_subcalls_get_modules_ref_none`).
- Defensive reason/sub_call_ids extraction: Task 5 (`test_detail_less_failure_does_not_raise`, `test_all_sources_down_hard_fail`).
- No-separate-budget / step record: Task 5 (manifest `postmortem.triage:` step assertion).
- Capability/config enumerability: Tasks 4, 7.
- Docs: Task 9.
