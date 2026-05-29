from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable


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
