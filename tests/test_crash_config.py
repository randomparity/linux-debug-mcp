from __future__ import annotations

from kdive.config import (
    ALLOWED_DEBUG_OPERATIONS,
    CRASH_COMMAND_ALLOWLIST,
    CRASH_PER_CMD_CAP,
    CRASH_SCRIPT_BYTE_CAP,
    CRASH_STDOUT_CAP,
    MAX_CRASH_COMMANDS,
    MAX_POSTMORTEM_CRASH_CALLS_PER_RUN,
)


def test_operation_registered() -> None:
    assert "debug.postmortem.crash" in ALLOWED_DEBUG_OPERATIONS


def test_allowlist_has_read_only_verbs() -> None:
    assert {"bt", "ps", "log", "kmem", "sys", "mod"} <= CRASH_COMMAND_ALLOWLIST


def test_caps_are_sane() -> None:
    assert 0 < CRASH_PER_CMD_CAP <= CRASH_STDOUT_CAP
    assert MAX_CRASH_COMMANDS > 0
    assert MAX_POSTMORTEM_CRASH_CALLS_PER_RUN > 0
    assert CRASH_SCRIPT_BYTE_CAP > 0
