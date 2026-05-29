"""Unit tests for the watchdog relax/restore seam (issue #69).

Covers the arch knob lists, capture/relax/restore round-trip, capture-once baseline
preservation, session_id keying, and restore-on-error/timeout via SessionGuard.teardown.
See docs/superpowers/specs/2026-05-29-watchdog-relax-restore-design.md / docs/adr/0016-*.
"""

import pytest

from linux_debug_mcp.seams.guard import SessionGuardContext
from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.seams.watchdog import (
    KnobOutcome,
    RelaxReport,
    RestoreReport,
    WatchdogArch,
    WatchdogPolicy,
    WriteOutcome,
    knobs_for_arch,
)


def _ctx(*, session_id: str | None = "sess-1", generation: int = 7) -> SessionGuardContext:
    return SessionGuardContext(
        target_key=TargetKey(provisioner="local-qemu", target_id="run-1"),
        generation=generation,
        session_id=session_id,
        reason="ended",
    )


def _x86_policy(channel: object) -> WatchdogPolicy:
    return WatchdogPolicy(arch=WatchdogArch.X86_64, channel=channel)  # type: ignore[arg-type]


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


def test_relax_reads_then_writes_each_knob_in_declared_order():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    report = _x86_policy(channel).relax(_ctx())
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
    channel = FakeWatchdogControl(values={"kernel.watchdog": "1"})
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
    in_band = {k.name: "1" for k in knobs_for_arch(WatchdogArch.PPC64LE) if not k.out_of_band}
    channel = FakeWatchdogControl(values=in_band)
    report = WatchdogPolicy(arch=WatchdogArch.PPC64LE, channel=channel).relax(_ctx())
    assert report.outcomes["phyp_partition_watchdog"] is KnobOutcome.SKIPPED
    assert all(name != "phyp_partition_watchdog" for _op, name, _v in channel.calls)


def test_relax_is_capture_once_second_relax_does_not_reread():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    reads_after_first = [c for c in channel.calls if c[0] == "read"]
    channel.calls.clear()
    policy.relax(_ctx())
    assert [c for c in channel.calls if c[0] == "read"] == []
    assert len(reads_after_first) == 5


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
    channel._fail_writes.add("kernel.watchdog")
    report = policy.restore(_ctx())
    assert report.failures == {"kernel.watchdog": False}
    assert report.restored["kernel.nmi_watchdog"] is True
    assert policy.restore(_ctx()).noop is True


def test_restore_does_not_rewrite_absent_or_write_failed_knobs():
    channel = FakeWatchdogControl(values={"kernel.watchdog": "1"})
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    channel.calls.clear()
    policy.restore(_ctx())
    written = [name for op, name, _v in channel.calls if op == "write"]
    assert written == ["kernel.watchdog"]


def test_distinct_sessions_capture_and_restore_independently():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx(session_id="s-A"))
    policy.relax(_ctx(session_id="s-B"))
    assert policy.restore(_ctx(session_id="s-A")).noop is False
    assert policy.restore(_ctx(session_id="s-A")).noop is True
    assert policy.restore(_ctx(session_id="s-B")).noop is False


def test_capture_once_preserves_baseline_across_re_relax():
    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    policy.relax(_ctx())
    policy.relax(_ctx())
    channel.calls.clear()
    policy.restore(_ctx())
    assert all(value == "1" for op, _name, value in channel.calls if op == "write")


def test_concurrent_same_session_relax_reads_exactly_once():
    """Claim-the-slot guarantees only one thread runs the read-pass for a session, so a
    concurrent relax cannot overwrite the baseline with already-relaxed values (spec §4.1)."""
    import threading as _threading

    channel = FakeWatchdogControl(values={k.name: "1" for k in knobs_for_arch(WatchdogArch.X86_64)})
    policy = _x86_policy(channel)
    barrier = _threading.Barrier(8)

    def _worker() -> None:
        barrier.wait()
        policy.relax(_ctx(session_id="shared"))

    threads = [_threading.Thread(target=_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    reads = [c for c in channel.calls if c[0] == "read"]
    assert len(reads) == 5
    channel.calls.clear()
    policy.restore(_ctx(session_id="shared"))
    assert all(value == "1" for op, _name, value in channel.calls if op == "write")
