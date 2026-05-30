"""Validation of caller crash command strings. ADR 0026 decision 2a / spec §3.4.

This is the load-bearing security control: the path is never gated, so every
command is sanitised (deny shell-reaching metacharacters/newlines) and checked
against an allowlist of read-only verbs before any crash invocation.
"""

from __future__ import annotations

import re

# Pipe-to-shell, redirection, command substitution, chaining, backgrounding.
_DENY_CHARS = ("|", ">", "<", "`", "$(", ";", "&")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MODULES_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def validate_crash_command(command: str, allowlist: set[str]) -> str | None:
    """Return ``None`` if the command is permitted, else a human-readable reason.

    Two layers (spec §3.4): a security-critical denylist (newline/control chars,
    leading ``!`` shell escape, and the ``_DENY_CHARS`` metacharacters) and an
    allowlist of read-only leading verbs.
    """
    stripped = command.strip()
    if not stripped:
        return "empty command"
    if _CONTROL.search(command):
        return "command contains a newline or control character"
    if stripped[0] == "!":
        return "shell escape ('!') is not permitted"
    for token in _DENY_CHARS:
        if token in command:
            return f"disallowed metacharacter {token!r}"
    verb = stripped.split()[0].lower()
    if verb not in allowlist:
        return f"verb {verb!r} is not in the crash command allowlist"
    return None


def validate_modules_path(path: str) -> bool:
    """True iff ``path`` is safe to interpolate into a crash ``mod -S`` command
    line (no whitespace/newline/metacharacters). Spec §6 step 8."""
    return bool(_MODULES_PATH_RE.match(path))
