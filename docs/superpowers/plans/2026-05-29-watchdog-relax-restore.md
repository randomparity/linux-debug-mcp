# Watchdog relax/restore helper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `seams/watchdog.py` helper that captures and relaxes kernel lockup watchdogs before an interactive stop and restores their prior values on teardown, hooked into the `SessionGuard` exit slot, shipped inert (no live channel) and proven by seam-level tests.

**Architecture:** A stateful `WatchdogPolicy` keyed on `session_id` reads-then-relaxes an arch-specific ordered list of `WatchdogKnob`s through an injected `WatchdogControl` channel, and restores the captured values idempotently. Only the restore is a `SessionGuard` `TeardownStep` (`WatchdogRestoreStep`); relax is a post-acquire `policy.relax(ctx)` call the live tier places after `transaction.open()` commits. `create_app` is unchanged — the helper is exercised only in tests with a fake channel.

**Tech Stack:** Python 3.11+, `dataclasses`, `enum.StrEnum`, `threading.Lock`, `typing.Protocol`/`runtime_checkable`; pytest. Lint/format `ruff`, types `ty`. Mirrors `seams/guard.py` and `tests/test_session_guard.py`.

**Spec:** `docs/superpowers/specs/2026-05-29-watchdog-relax-restore-design.md` · **ADR:** `docs/adr/0016-watchdog-relax-restore-helper.md`

---

## File structure

- Create: `src/linux_debug_mcp/seams/watchdog.py` — all of: `WatchdogArch`, `WatchdogKnob`, `WriteOutcome`, `WatchdogControl` (Protocol), `RelaxReport`, `RestoreReport`, `CapturedState`, `WatchdogPolicy`, `WatchdogRestoreStep`, `WatchdogRestoreError`, `x86_64_knobs()`, `ppc64le_knobs()`, `knobs_for_arch()`.
- Create: `tests/test_seams_watchdog.py` — seam-level tests with a `FakeWatchdogControl`.
- No other files change. `create_app` (`server.py`) is intentionally untouched (spec §1.2).

The module is small and single-responsibility (watchdog relax/restore policy + its one SessionGuard adapter). It imports only `SessionGuardContext` from `seams/guard.py` and stdlib.

---

## Task 1: Knob model and architecture variants

**Files:**
- Create: `src/linux_debug_mcp/seams/watchdog.py`
- Test: `tests/test_seams_watchdog.py`

- [ ] **Step 1: Write the failing test**

```python
"""Unit tests for the watchdog relax/restore seam (issue #69).

Covers the arch knob lists, capture/relax/restore round-trip, capture-once baseline
preservation, session_id keying, and restore-on-error/timeout via SessionGuard.teardown.
See docs/superpowers/specs/2026-05-29-watchdog-relax-restore-design.md / docs/adr/0016-*.
"""

from linux_debug_mcp.seams.watchdog import (
    WatchdogArch,
    knobs_for_arch,
)


def test_x86_knob_list_is_the_five_generic_detectors():
    names = [k.name for k in knobs_for_arch(WatchdogArch.X86_64)]
    assert names == [
        "kernel.nmi_watchdog",
        "kernel.watchdog",
        "kernel.watchdog_thresh",
        "kernel.softlockup_panic",
        "kernel.hardlockup_panic",
    ]
    assert all(not k.out_of_band for k in knobs_for_arch(WatchdogArch.X86_64))


def test_ppc64le_adds_out_of_band_phyp_knob():
    knobs = knobs_for_arch(WatchdogArch.PPC64LE)
    names = [k.name for k in knobs]
    assert names[:5] == [
        "kernel.nmi_watchdog",
        "kernel.watchdog",
        "kernel.watchdog_thresh",
        "kernel.softlockup_panic",
        "kernel.hardlockup_panic",
    ]
    assert names[5] == "phyp_partition_watchdog"
    phyp = knobs[5]
    assert phyp.out_of_band is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_seams_watchdog.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.seams.watchdog'`.

- [ ] **Step 3: Write minimal implementation**

Create `src/linux_debug_mcp/seams/watchdog.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class WatchdogArch(StrEnum):
    X86_64 = "x86_64"
    PPC64LE = "ppc64le"


@dataclass(frozen=True)
class WatchdogKnob:
    """One watchdog control. `relaxed_value` is the transient override written before
    an interactive stop; restore puts the captured prior value back. `out_of_band`
    knobs are not reachable over the in-band (sysctl) channel."""

    name: str
    relaxed_value: str
    out_of_band: bool = False


_GENERIC_LOCKUP_KNOBS: tuple[WatchdogKnob, ...] = (
    WatchdogKnob("kernel.nmi_watchdog", "0"),
    WatchdogKnob("kernel.watchdog", "0"),
    WatchdogKnob("kernel.watchdog_thresh", "0"),
    WatchdogKnob("kernel.softlockup_panic", "0"),
    WatchdogKnob("kernel.hardlockup_panic", "0"),
)


def knobs_for_arch(arch: WatchdogArch) -> tuple[WatchdogKnob, ...]:
    """The ordered knob list for an architecture. x86_64 and ppc64le share the
    arch-independent lockup detectors; ppc64le adds the out-of-band PHYP/PowerVM
    partition watchdog, which has no in-band sysctl and is recorded skipped."""
    if arch is WatchdogArch.PPC64LE:
        return (*_GENERIC_LOCKUP_KNOBS, WatchdogKnob("phyp_partition_watchdog", "disabled", out_of_band=True))
    return _GENERIC_LOCKUP_KNOBS
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_seams_watchdog.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/watchdog.py tests/test_seams_watchdog.py
git commit -m "feat(watchdog): arch knob lists for relax/restore

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Channel Protocol, reports, and outcomes

**Files:**
- Modify: `src/linux_debug_mcp/seams/watchdog.py`
- Test: `tests/test_seams_watchdog.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_seams_watchdog.py`:

```python
from linux_debug_mcp.seams.watchdog import (
    KnobOutcome,
    RelaxReport,
    RestoreReport,
    WriteOutcome,
)


class FakeWatchdogControl:
    """Records ordered (op, name, value) calls; serves scripted reads and write failures."""

    def __init__(self, *, values: dict[str, str] | None = None, fail_writes: set[str] | None = None) -> None:
        self._values = dict(values or {})
        self._fail_writes = set(fail_writes or set())
        self.calls: list[tuple[str, str, str | None]] = []

    def read_knob(self, name: str) -> str | None:
        self.calls.append(("read", name, None))
        return self._values.get(name)

    def write_knob(self, name: str, value: str) -> WriteOutcome:
        self.calls.append(("write", name, value))
        if name in self._fail_writes:
            return WriteOutcome(ok=False, detail=f"write {name} failed")
        self._values[name] = value
        return WriteOutcome(ok=True)


def test_write_outcome_defaults_to_empty_detail():
    assert WriteOutcome(ok=True).detail == ""


def test_reports_are_constructible():
    relax = RelaxReport(outcomes={"kernel.watchdog": KnobOutcome.RELAXED})
    restore = RestoreReport(restored={}, noop=True)
    assert relax.outcomes["kernel.watchdog"] is KnobOutcome.RELAXED
    assert restore.noop is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_seams_watchdog.py -q`
Expected: FAIL — `ImportError: cannot import name 'KnobOutcome'`.

- [ ] **Step 3: Write minimal implementation**

Add to `src/linux_debug_mcp/seams/watchdog.py` (after the imports, extend them; add below `knobs_for_arch`):

```python
# extend the top-of-file imports to:
# from dataclasses import dataclass, field
# from enum import StrEnum
# from typing import Protocol, runtime_checkable


class KnobOutcome(StrEnum):
    RELAXED = "relaxed"          # read captured + relax write ok
    ABSENT = "absent"            # read_knob returned None (knob not present)
    SKIPPED = "skipped"          # out_of_band knob, no in-band channel
    WRITE_FAILED = "write_failed"  # relax (or restore) write_knob failed / raised


@dataclass(frozen=True)
class WriteOutcome:
    ok: bool
    detail: str = ""             # redacted; empty on success


@dataclass(frozen=True)
class RelaxReport:
    outcomes: dict[str, KnobOutcome] = field(default_factory=dict)


@dataclass(frozen=True)
class RestoreReport:
    restored: dict[str, bool] = field(default_factory=dict)  # knob -> restore write ok
    noop: bool = False                                       # no capture existed for the session

    @property
    def failures(self) -> dict[str, bool]:
        return {name: ok for name, ok in self.restored.items() if not ok}


@runtime_checkable
class WatchdogControl(Protocol):
    def read_knob(self, name: str) -> str | None:
        """Return the knob's current value, or None if it cannot be read. Never raises
        for an absent knob."""
        ...

    def write_knob(self, name: str, value: str) -> WriteOutcome:
        """Set the knob. Returns WriteOutcome(ok=False, ...) on failure; MUST NOT raise."""
        ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_seams_watchdog.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/watchdog.py tests/test_seams_watchdog.py
git commit -m "feat(watchdog): channel Protocol, outcomes, and reports

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `WatchdogPolicy.relax` — capture-then-relax, once per session

**Files:**
- Modify: `src/linux_debug_mcp/seams/watchdog.py`
- Test: `tests/test_seams_watchdog.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_seams_watchdog.py`:

```python
import pytest

from linux_debug_mcp.seams.guard import SessionGuardContext
from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.seams.watchdog import WatchdogPolicy


def _ctx(*, session_id: str | None = "sess-1", generation: int = 7) -> SessionGuardContext:
    return SessionGuardContext(
        target_key=TargetKey(provisioner="local-qemu", target_id="run-1"),
        generation=generation,
        session_id=session_id,
        reason="ended",
    )


def _x86_policy(channel: object) -> WatchdogPolicy:
    return WatchdogPolicy(arch=WatchdogArch.X86_64, channel=channel)  # type: ignore[arg-type]


def test_relax_reads_then_writes_each_knob_in_declared_order():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    report = _x86_policy(channel).relax(_ctx())
    # read then write per knob, in declared order
    assert channel.calls == [
        ("read", "kernel.nmi_watchdog", None),
        ("write", "kernel.nmi_watchdog", "0"),
        ("read", "kernel.watchdog", None),
        ("write", "kernel.watchdog", "0"),
        ("read", "kernel.watchdog_thresh", None),
        ("write", "kernel.watchdog_thresh", "0"),
        ("read", "kernel.softlockup_panic", None),
        ("write", "kernel.softlockup_panic", "0"),
        ("read", "kernel.hardlockup_panic", None),
        ("write", "kernel.hardlockup_panic", "0"),
    ]
    assert all(o is KnobOutcome.RELAXED for o in report.outcomes.values())


def test_relax_requires_session_id():
    with pytest.raises(ValueError, match="session_id"):
        _x86_policy(FakeWatchdogControl()).relax(_ctx(session_id=None))


def test_relax_records_absent_knob_and_skips_its_write():
    channel = FakeWatchdogControl(values={"kernel.watchdog": "1"})  # others absent
    report = _x86_policy(channel).relax(_ctx())
    assert report.outcomes["kernel.nmi_watchdog"] is KnobOutcome.ABSENT
    assert ("write", "kernel.nmi_watchdog", "0") not in channel.calls
    assert report.outcomes["kernel.watchdog"] is KnobOutcome.RELAXED


def test_relax_records_write_failed_when_write_fails():
    channel = FakeWatchdogControl(
        values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)},
        fail_writes={"kernel.nmi_watchdog"},
    )
    report = _x86_policy(channel).relax(_ctx())
    assert report.outcomes["kernel.nmi_watchdog"] is KnobOutcome.WRITE_FAILED


def test_relax_records_out_of_band_knob_skipped_without_touching_channel():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.PPC64LE) if not k.out_of_band})
    report = WatchdogPolicy(arch=WatchdogArch.PPC64LE, channel=channel).relax(_ctx())
    assert report.outcomes["phyp_partition_watchdog"] is KnobOutcome.SKIPPED
    assert all(name != "phyp_partition_watchdog" for _op, name, _v in channel.calls)


def test_relax_is_capture_once_second_relax_does_not_reread():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    reads_after_first = [c for c in channel.calls if c[0] == "read"]
    channel.calls.clear()
    policy.relax(_ctx())  # second relax, same session
    assert [c for c in channel.calls if c[0] == "read"] == []  # no re-read
    assert len(reads_after_first) == 5
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_seams_watchdog.py -q`
Expected: FAIL — `ImportError: cannot import name 'WatchdogPolicy'`.

- [ ] **Step 3: Write minimal implementation**

Add to `src/linux_debug_mcp/seams/watchdog.py` (add `import threading` and `from collections.abc import Sequence` to the imports):

```python
@dataclass
class _CapturedState:
    """Per-session capture. `prior` is the value read at relax time (the operator
    baseline to restore); `relaxed` records whether the relax write itself succeeded
    (a knob whose relax write failed is not restored — nothing was changed)."""

    prior: dict[str, str] = field(default_factory=dict)   # in-band knob -> baseline value
    relaxed: dict[str, bool] = field(default_factory=dict)  # in-band knob -> relax write ok


class WatchdogPolicy:
    """Stateful watchdog relax/restore policy (spec §3.3). Captures the operator
    baseline on the first relax for a session_id, writes the relaxed values, and
    restores the baseline idempotently on teardown. All target I/O goes through the
    injected WatchdogControl channel; no concrete channel ships in #69."""

    def __init__(
        self,
        *,
        arch: WatchdogArch,
        channel: WatchdogControl,
        knobs: Sequence[WatchdogKnob] | None = None,
    ) -> None:
        self._knobs = tuple(knobs) if knobs is not None else knobs_for_arch(arch)
        self._channel = channel
        self._lock = threading.Lock()
        self._captures: dict[str, _CapturedState] = {}

    def relax(self, ctx: SessionGuardContext) -> RelaxReport:
        if ctx.session_id is None:
            raise ValueError("watchdog relax requires a committed session_id (run it post-acquire)")
        with self._lock:
            existing = self._captures.get(ctx.session_id)
        if existing is not None:
            return self._reissue_relax(existing)
        return self._first_relax(ctx.session_id)

    def _first_relax(self, session_id: str) -> RelaxReport:
        capture = _CapturedState()
        outcomes: dict[str, KnobOutcome] = {}
        for knob in self._knobs:
            if knob.out_of_band:
                outcomes[knob.name] = KnobOutcome.SKIPPED
                continue
            prior = self._safe_read(knob.name)
            if prior is None:
                outcomes[knob.name] = KnobOutcome.ABSENT
                continue
            capture.prior[knob.name] = prior
            ok = self._safe_write(knob.name, knob.relaxed_value)
            capture.relaxed[knob.name] = ok
            outcomes[knob.name] = KnobOutcome.RELAXED if ok else KnobOutcome.WRITE_FAILED
        with self._lock:
            self._captures[session_id] = capture
        return RelaxReport(outcomes=outcomes)

    def _reissue_relax(self, capture: _CapturedState) -> RelaxReport:
        # Capture-once: do NOT re-read (that would capture already-relaxed values and
        # destroy the baseline — spec §4.1). Re-issue the relax writes for knobs we
        # captured a baseline for.
        outcomes: dict[str, KnobOutcome] = {}
        for knob in self._knobs:
            if knob.out_of_band:
                outcomes[knob.name] = KnobOutcome.SKIPPED
                continue
            if knob.name not in capture.prior:
                outcomes[knob.name] = KnobOutcome.ABSENT
                continue
            ok = self._safe_write(knob.name, knob.relaxed_value)
            capture.relaxed[knob.name] = capture.relaxed.get(knob.name, False) or ok
            outcomes[knob.name] = KnobOutcome.RELAXED if ok else KnobOutcome.WRITE_FAILED
        return RelaxReport(outcomes=outcomes)

    def _safe_read(self, name: str) -> str | None:
        try:
            return self._channel.read_knob(name)
        except Exception:  # noqa: BLE001 - a channel error is data, never control flow
            return None

    def _safe_write(self, name: str, value: str) -> bool:
        try:
            return self._channel.write_knob(name, value).ok
        except Exception:  # noqa: BLE001 - a channel error is recorded, never raised
            return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_seams_watchdog.py -q`
Expected: PASS (all relax tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/watchdog.py tests/test_seams_watchdog.py
git commit -m "feat(watchdog): capture-once relax keyed on session_id

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `WatchdogPolicy.restore` — idempotent reverse-order restore

**Files:**
- Modify: `src/linux_debug_mcp/seams/watchdog.py`
- Test: `tests/test_seams_watchdog.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_seams_watchdog.py`:

```python
def test_restore_round_trips_captured_values_in_reverse_order():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    channel.calls.clear()
    report = policy.restore(_ctx())
    assert channel.calls == [
        ("write", "kernel.hardlockup_panic", "1"),
        ("write", "kernel.softlockup_panic", "1"),
        ("write", "kernel.watchdog_thresh", "1"),
        ("write", "kernel.watchdog", "1"),
        ("write", "kernel.nmi_watchdog", "1"),
    ]
    assert report.noop is False
    assert all(report.restored.values())


def test_restore_without_prior_relax_is_noop():
    channel = FakeWatchdogControl()
    report = _x86_policy(channel).restore(_ctx())
    assert report.noop is True
    assert channel.calls == []


def test_second_restore_is_noop_after_capture_cleared():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    policy.restore(_ctx())
    channel.calls.clear()
    second = policy.restore(_ctx())
    assert second.noop is True
    assert channel.calls == []


def test_restore_clears_capture_even_when_a_write_fails():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    channel._fail_writes.add("kernel.watchdog")  # restore write will fail for one knob
    report = policy.restore(_ctx())
    assert report.failures == {"kernel.watchdog": False}
    # other knobs still restored
    assert report.restored["kernel.nmi_watchdog"] is True
    # capture cleared regardless -> second restore is noop
    assert policy.restore(_ctx()).noop is True


def test_restore_does_not_rewrite_absent_or_write_failed_knobs():
    channel = FakeWatchdogControl(values={"kernel.watchdog": "1"})  # only this knob present
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    channel.calls.clear()
    policy.restore(_ctx())
    written = [name for op, name, _v in channel.calls if op == "write"]
    assert written == ["kernel.watchdog"]  # absent knobs not restored


def test_distinct_sessions_capture_and_restore_independently():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx(session_id="s-A"))
    policy.relax(_ctx(session_id="s-B"))
    # restoring A leaves B's capture intact
    assert policy.restore(_ctx(session_id="s-A")).noop is False
    assert policy.restore(_ctx(session_id="s-A")).noop is True
    assert policy.restore(_ctx(session_id="s-B")).noop is False


def test_capture_once_preserves_baseline_across_re_relax():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx())   # captures "1", writes "0"
    policy.relax(_ctx())   # re-relax: must NOT recapture "0"
    channel.calls.clear()
    policy.restore(_ctx())
    # every restore write puts the ORIGINAL "1" back, never the relaxed "0"
    assert all(value == "1" for op, _name, value in channel.calls if op == "write")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_seams_watchdog.py -q`
Expected: FAIL — `AttributeError: 'WatchdogPolicy' object has no attribute 'restore'`.

- [ ] **Step 3: Write minimal implementation**

Add the `restore` method to `WatchdogPolicy` in `src/linux_debug_mcp/seams/watchdog.py`:

```python
    def restore(self, ctx: SessionGuardContext) -> RestoreReport:
        if ctx.session_id is None:
            return RestoreReport(noop=True)
        with self._lock:
            capture = self._captures.pop(ctx.session_id, None)  # clear unconditionally
        if capture is None:
            return RestoreReport(noop=True)
        restored: dict[str, bool] = {}
        for knob in reversed(self._knobs):
            if knob.out_of_band or not capture.relaxed.get(knob.name, False):
                continue  # never relaxed -> nothing to put back
            prior = capture.prior[knob.name]
            restored[knob.name] = self._safe_write(knob.name, prior)
        return RestoreReport(restored=restored, noop=False)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_seams_watchdog.py -q`
Expected: PASS (all relax + restore tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/watchdog.py tests/test_seams_watchdog.py
git commit -m "feat(watchdog): idempotent reverse-order restore, clear after one pass

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `WatchdogRestoreStep` TeardownStep adapter

**Files:**
- Modify: `src/linux_debug_mcp/seams/watchdog.py`
- Test: `tests/test_seams_watchdog.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_seams_watchdog.py`:

```python
from linux_debug_mcp.seams.guard import TeardownStep
from linux_debug_mcp.seams.watchdog import WatchdogRestoreError, WatchdogRestoreStep


def test_restore_step_is_a_teardown_step():
    step = WatchdogRestoreStep(_x86_policy(FakeWatchdogControl()))
    assert isinstance(step, TeardownStep)
    assert step.name == "watchdog-restore"


def test_restore_step_teardown_restores_and_does_not_raise_on_success():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    WatchdogRestoreStep(policy).teardown(_ctx())  # no raise
    assert channel._values["kernel.nmi_watchdog"] == "1"


def test_restore_step_teardown_raises_on_restore_write_failure():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    channel._fail_writes.add("kernel.watchdog")
    with pytest.raises(WatchdogRestoreError):
        WatchdogRestoreStep(policy).teardown(_ctx())


def test_restore_step_teardown_is_silent_on_noop():
    WatchdogRestoreStep(_x86_policy(FakeWatchdogControl())).teardown(_ctx())  # no relax -> noop, no raise
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_seams_watchdog.py -q`
Expected: FAIL — `ImportError: cannot import name 'WatchdogRestoreStep'`.

- [ ] **Step 3: Write minimal implementation**

Add to `src/linux_debug_mcp/seams/watchdog.py`:

```python
class WatchdogRestoreError(RuntimeError):
    """Raised by WatchdogRestoreStep.teardown when one or more restore writes failed,
    so SessionGuard.teardown aggregates it into TeardownReport.step_errors. It never
    aborts teardown (the guard suppresses+records it) — the resume + reap invariant
    holds regardless (ADR 0013)."""

    def __init__(self, report: RestoreReport) -> None:
        super().__init__(f"watchdog restore failed for knobs: {sorted(report.failures)}")
        self.report = report


class WatchdogRestoreStep:
    """SessionGuard TeardownStep (the exit slot) that restores the captured watchdog
    baseline. Raises WatchdogRestoreError only on a restore-write failure so the
    failure lands in TeardownReport.step_errors; silent on a noop restore."""

    name = "watchdog-restore"

    def __init__(self, policy: WatchdogPolicy) -> None:
        self._policy = policy

    def teardown(self, ctx: SessionGuardContext) -> None:
        report = self._policy.restore(ctx)
        if report.failures:
            raise WatchdogRestoreError(report)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_seams_watchdog.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/watchdog.py tests/test_seams_watchdog.py
git commit -m "feat(watchdog): WatchdogRestoreStep teardown adapter

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: restore-on-error / restore-on-timeout through SessionGuard.teardown

**Files:**
- Modify: `tests/test_seams_watchdog.py`

This task adds no production code — it proves the spec §5 behavior by driving the real
`SessionGuard.teardown` with the restore step, mirroring `tests/test_session_guard.py`'s
teardown harness (`close`/`read_record`/`force_reap` fakes).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_seams_watchdog.py`:

```python
from linux_debug_mcp.seams.guard import SessionGuard


def _run_teardown(policy: WatchdogPolicy, *, reason: str):
    """Drive SessionGuard.teardown with the restore step + minimal clean-resume fakes
    (record already gone -> resume_ok True), as the attach-error/clean-end handler does."""
    guard = SessionGuard(teardown_steps=[WatchdogRestoreStep(policy)])
    closed: list[bool] = []
    return guard.teardown(
        _ctx(reason=reason),
        close=lambda: closed.append(True),
        read_record=lambda: None,         # record deleted -> resume_ok holds
        force_reap=lambda: None,
    ), closed


def test_restore_on_error_reachable_channel():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    report, closed = _run_teardown(policy, reason="attach_error")
    assert closed == [True]                          # close still ran
    assert report.resume_ok is True
    assert "watchdog-restore" not in report.step_errors  # restore succeeded
    assert channel._values["kernel.nmi_watchdog"] == "1"


def test_restore_on_error_unreachable_channel_is_recorded_not_fatal():
    knob_names = {k.name for k in knobs_for_arch(WatchdogArch.X86_64)}
    channel = FakeWatchdogControl(values={n: "1" for n in knob_names}, fail_writes=knob_names)
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    report, closed = _run_teardown(policy, reason="attach_error")
    assert closed == [True]                           # close still ran despite restore failing
    assert report.resume_ok is True
    assert "watchdog-restore" in report.step_errors   # failure recorded, not raised out
    # capture cleared -> a retry teardown is a clean noop
    second, _ = _run_teardown(policy, reason="attach_error")
    assert "watchdog-restore" not in second.step_errors


def test_restore_on_timeout_runs_on_same_attach_error_path():
    # A start_session timeout surfaces as attach_error teardown (spec §5); the restore
    # step runs identically. Here we assert restore is attempted on that path.
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    report, _ = _run_teardown(policy, reason="attach_error")
    assert report.resume_ok is True
    assert channel._values["kernel.watchdog"] == "1"  # restored
```

- [ ] **Step 2: Run test to verify it fails, then passes**

Run: `uv run python -m pytest tests/test_seams_watchdog.py -q`
Expected: PASS (no new production code needed — these exercise existing Task 4/5 code through `SessionGuard`). If any fails, fix the test against the real `TeardownReport` field names (`step_errors`, `resume_ok`) — do not change production code.

- [ ] **Step 3: Commit**

```bash
git add tests/test_seams_watchdog.py
git commit -m "test(watchdog): restore-on-error/timeout via SessionGuard.teardown

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Guardrails + module docstring + final sweep

**Files:**
- Modify: `src/linux_debug_mcp/seams/watchdog.py` (module docstring only)

- [ ] **Step 1: Add a module docstring**

Prepend to `src/linux_debug_mcp/seams/watchdog.py` (above `from __future__`):

```python
"""Watchdog relax/restore helper for interactive stops (issue #69).

Relaxes kernel lockup detectors (and, on POWER, declares the out-of-band PHYP
watchdog) before an interactive stop and restores the captured operator baseline on
teardown. Stateful, keyed on session_id, capture-once. The restore is a SessionGuard
TeardownStep; relax is a post-acquire call. Shipped inert (no concrete WatchdogControl
channel) — see docs/superpowers/specs/2026-05-29-watchdog-relax-restore-design.md and
docs/adr/0016-watchdog-relax-restore-helper.md.
"""
```

- [ ] **Step 2: Run lint, format, types**

Run: `uv run ruff check src/linux_debug_mcp/seams/watchdog.py tests/test_seams_watchdog.py && uv run ruff format --check src/linux_debug_mcp/seams/watchdog.py tests/test_seams_watchdog.py && uv run ty check src`
Expected: all clean. If `ruff format --check` reports a diff, run `uv run ruff format <files>` and re-check. Fix any `ty` errors (e.g. add precise type hints) before proceeding.

- [ ] **Step 3: Run the full test suite**

Run: `uv run python -m pytest -q`
Expected: all pass (existing suite + new `tests/test_seams_watchdog.py`). The libvirt/gdb/drgn integration tests stay skipped without those tools.

- [ ] **Step 4: Doc guard**

Run: `just check-docs`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/watchdog.py
git commit -m "docs(watchdog): module docstring; finalize seam

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-review notes (spec coverage)

- §3.1 arch knobs → Task 1. §3.2 channel/outcomes/reports → Task 2. §3.3 relax capture-once + §4.1 baseline preservation → Task 3 (+ `test_capture_once_preserves_baseline_across_re_relax` in Task 4). §3.3 restore + §4.3 clear-after-one-pass → Task 4. §3.4 `WatchdogRestoreStep` → Task 5. §5 restore-on-error (reachable + unreachable) / restore-on-timeout → Task 6. §3.2 redaction: knob values are not secret and no concrete channel ships, so redaction is the live channel's responsibility (spec §3.2) — no #69 code surfaces guest text into a persisted/returned `ToolResponse`; nothing to redact in the inert helper.
- §1.2 inert wiring: `create_app` deliberately unchanged — no task modifies `server.py`.
- §7 "dispatcher path has no restore obligation": #69 wires nothing into the dispatcher, so there is no code to test against; this is asserted structurally (the restore step is constructed only in tests, never registered with `InProcessLifecycleDispatcher`). No standalone test — the absence is guaranteed by `create_app` being untouched.
- §7 "x86 vs ppc64le variance" → Task 1 + Task 3 (`test_relax_records_out_of_band_knob_skipped_without_touching_channel`).
