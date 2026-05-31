from __future__ import annotations

import pytest

from kdive.postmortem.crash_commands import (
    crash_command_rejection_reason,
    validate_modules_path,
)

ALLOW = {"bt", "ps", "log", "kmem", "sys", "mod"}


@pytest.mark.parametrize("cmd", ["bt", "ps -A", "kmem -i", "sys", "log"])
def test_allowed_commands_pass(cmd: str) -> None:
    assert crash_command_rejection_reason(cmd, ALLOW) is None


@pytest.mark.parametrize(
    "cmd",
    [
        "!cat /etc/shadow",
        "bt | sh",
        "sys > /tmp/x",
        "log < /etc/passwd",
        "ps; quit",
        "bt && rm -rf /",
        "p `id`",
        "p $(id)",
    ],
)
def test_shell_reaching_commands_rejected(cmd: str) -> None:
    assert crash_command_rejection_reason(cmd, ALLOW) is not None


def test_embedded_newline_rejected() -> None:
    assert crash_command_rejection_reason("bt\nps", ALLOW) is not None


def test_non_allowlisted_verb_rejected() -> None:
    reason = crash_command_rejection_reason("gdb foo", ALLOW)
    assert reason is not None and "allowlist" in reason


def test_empty_command_rejected() -> None:
    assert crash_command_rejection_reason("   ", ALLOW) is not None


@pytest.mark.parametrize("path", ["/run/r1/target/mods", "build/mods_v2.1", "a/b-c/d.e"])
def test_safe_modules_path(path: str) -> None:
    assert validate_modules_path(path) is True


@pytest.mark.parametrize("path", ["/run/r1/m od", "/run/r1/m\nod", "/run/r1/m;od", "a b"])
def test_unsafe_modules_path(path: str) -> None:
    assert validate_modules_path(path) is False
