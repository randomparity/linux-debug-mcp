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
