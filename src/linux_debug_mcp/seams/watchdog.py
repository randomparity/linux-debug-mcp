from __future__ import annotations

import logging
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from linux_debug_mcp.seams.guard import SessionGuardContext

logger = logging.getLogger(__name__)


class WatchdogArch(StrEnum):
    X86_64 = "x86_64"
    PPC64LE = "ppc64le"


class KnobOutcome(StrEnum):
    RELAXED = "relaxed"  # read captured + relax write ok
    ABSENT = "absent"  # read_knob returned None (knob not present)
    SKIPPED = "skipped"  # out_of_band knob, no in-band channel
    WRITE_FAILED = "write_failed"  # relax (or restore) write_knob failed / raised


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


@dataclass(frozen=True)
class WriteOutcome:
    ok: bool
    detail: str = ""  # redacted; empty on success


@dataclass(frozen=True)
class RelaxReport:
    outcomes: dict[str, KnobOutcome] = field(default_factory=dict)


@dataclass(frozen=True)
class RestoreReport:
    restored: dict[str, bool] = field(default_factory=dict)  # knob -> restore write ok
    noop: bool = False  # no capture existed for the session

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


@dataclass
class _CapturedState:
    """Per-session capture. `prior` is the value read at relax time (the operator
    baseline to restore); `relaxed` records whether the relax write itself succeeded
    (a knob whose relax write failed is not restored — nothing was changed)."""

    prior: dict[str, str] = field(default_factory=dict)  # in-band knob -> baseline value
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
        # Claim-the-slot under the lock so only ONE caller ever runs the read-pass for a
        # session_id. A naive "check existence, release lock, then read+write+store" gap
        # would let two concurrent same-session relaxes both read — the second reading the
        # already-relaxed values and overwriting the baseline (the corruption capture-once
        # exists to prevent, spec §4.1). The owner populates the claimed capture in place;
        # a racing non-owner takes the reissue path (no re-read). I/O stays OUTSIDE the lock
        # so distinct sessions relax concurrently (spec §3.3).
        with self._lock:
            capture = self._captures.get(ctx.session_id)
            is_owner = capture is None
            if is_owner:
                capture = _CapturedState()
                self._captures[ctx.session_id] = capture  # claim before releasing the lock
        assert capture is not None
        return self._first_relax(capture) if is_owner else self._reissue_relax(capture)

    def _first_relax(self, capture: _CapturedState) -> RelaxReport:
        # Populates the already-claimed capture object in place (it is the dict entry).
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

    def _safe_read(self, name: str) -> str | None:
        try:
            return self._channel.read_knob(name)
        except Exception as exc:  # noqa: BLE001 - a channel error is data, never control flow
            logger.warning("watchdog: read_knob(%s) raised: %r", name, exc)
            return None

    def _safe_write(self, name: str, value: str) -> bool:
        try:
            return self._channel.write_knob(name, value).ok
        except Exception as exc:  # noqa: BLE001 - a channel error is recorded, never raised
            logger.warning("watchdog: write_knob(%s) raised: %r", name, exc)
            return False
