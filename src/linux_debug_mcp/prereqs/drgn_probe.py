"""Host-side core for debug.introspect.check_prerequisites (spec §4-§5).

Pure, SSH-free decision logic so the verdict matrix is unit-testable. The
on-target probe (PROBE_SCRIPT, added in a later task) emits raw facts; this
module turns them into PrerequisiteCheck objects + a tri-state verdict.
"""

from __future__ import annotations

import re
from typing import Any

from linux_debug_mcp.domain import PrerequisiteCheck, PrerequisiteStatus

# Tri-state verdict values (spec §5).
USABLE = "usable"
UNKNOWN = "unknown"
UNUSABLE = "unusable"

_NON_HEX = re.compile(r"[^0-9a-fA-F]")
_HEX_PREFIX = re.compile(r"^0x", re.IGNORECASE)


def normalize_build_id(value: Any) -> str | None:
    """Lowercase hex, separators/whitespace stripped (spec §5 normalization).

    Strips a leading ``0x``/``0X`` prefix before removing non-hex characters,
    so that ``"0xDEAD"`` normalises to ``"dead"`` rather than ``"0dead"``.
    """
    if not isinstance(value, str):
        return None
    without_prefix = _HEX_PREFIX.sub("", value)
    cleaned = _NON_HEX.sub("", without_prefix).lower()
    return cleaned or None


def install_hint(distro_id: str | None) -> str:
    """drgn install remediation by distro family (spec §5)."""
    distro = (distro_id or "").lower()
    if distro == "fedora":
        return "sudo dnf install drgn"
    if distro in {"rhel", "centos", "rocky", "almalinux"}:
        return "sudo dnf install python3-drgn  (requires EPEL)"
    if distro in {"debian", "ubuntu"}:
        return "sudo apt install python3-drgn  (or the drgn PPA)"
    return "python3 -m pip install drgn"


def python_missing_checks() -> tuple[list[PrerequisiteCheck], str]:
    """Synthesized report when target has no python3 (spec §6: ssh exit 127)."""
    checks = [
        PrerequisiteCheck(
            check_id="target.python3",
            status=PrerequisiteStatus.FAILED,
            message="python3 is not available on the target",
            suggested_fix="Install python3 on the target.",
        ),
        PrerequisiteCheck(
            check_id="target.drgn",
            status=PrerequisiteStatus.SKIPPED,
            message="skipped: python3 unavailable",
        ),
        PrerequisiteCheck(
            check_id="target.vmlinux_debuginfo",
            status=PrerequisiteStatus.SKIPPED,
            message="skipped: python3 unavailable",
        ),
    ]
    return checks, UNUSABLE
