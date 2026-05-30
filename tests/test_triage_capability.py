from __future__ import annotations

from kdive.providers.local_crash_postmortem import local_crash_postmortem_capability


def test_capability_advertises_triage() -> None:
    cap = local_crash_postmortem_capability()
    assert "debug.postmortem.triage" in cap.operations
    assert "debug.postmortem.crash" in cap.operations  # unchanged
