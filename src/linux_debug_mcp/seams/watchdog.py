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
