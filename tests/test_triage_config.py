from __future__ import annotations

from kdive.config import (
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
