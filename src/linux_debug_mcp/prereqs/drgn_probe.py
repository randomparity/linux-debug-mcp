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
    """Synthesized report when target has no python3 (spec §6: ssh exit 127).

    Intentionally emits only the 3 checks relevant when python3 is absent
    (``target.python3`` FAILED, ``target.drgn``/``target.vmlinux_debuginfo``
    SKIPPED); the ``target.kernel_buildid`` and ``target.module_debuginfo``
    checks are omitted by design on this path because the probe never ran.
    """
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


def _verdict(
    *,
    drgn_present: bool,
    found: bool,
    btf: bool,
    running: str | None,
    host: str | None,
    build_id_verified: bool,
    wrong_debuginfo: bool,
) -> str:
    """Spec §5 tri-state. Only proven contradictions / hard-missing prereqs
    are UNUSABLE; unconfirmable cases are UNKNOWN (never a false UNUSABLE)."""
    if not drgn_present:
        return UNUSABLE
    if not found and not btf:
        return UNUSABLE
    if running is not None and host is not None and running != host:
        return UNUSABLE
    if wrong_debuginfo:
        return UNUSABLE
    if found and build_id_verified and running is not None and host is not None and running == host:
        return USABLE
    return UNKNOWN


def _python_check(probe: dict[str, Any]) -> PrerequisiteCheck:
    version = probe.get("python_version")
    executable = probe.get("python_executable")
    return PrerequisiteCheck(
        check_id="target.python3",
        status=PrerequisiteStatus.PASSED if version else PrerequisiteStatus.FAILED,
        message=f"python3 {version}" if version else "python3 not available on target",
        details={"version": version, "executable": executable},
        suggested_fix=None if version else "Install python3 on the target.",
    )


def _drgn_check(probe: dict[str, Any]) -> PrerequisiteCheck:
    present = bool(probe.get("drgn_present"))
    version = probe.get("drgn_version")
    return PrerequisiteCheck(
        check_id="target.drgn",
        status=PrerequisiteStatus.PASSED if present else PrerequisiteStatus.FAILED,
        message=f"drgn {version}" if present else "drgn is not importable under the target interpreter",
        details={"version": version, "executable": probe.get("python_executable")},
        suggested_fix=None if present else install_hint(probe.get("distro_id")),
    )


def _vmlinux_check(
    *,
    candidates: list[tuple[Any, str | None]],
    btf: bool,
    build_id_verified: bool,
    file_matches_host: bool,
    chosen_path: Any,
    chosen_id: str | None,
) -> PrerequisiteCheck:
    details = {
        "path": chosen_path,
        "file_build_id": chosen_id,
        "build_id_verified": build_id_verified,
        "file_matches_host": file_matches_host,
        "btf": btf,
        "candidates": [{"path": p, "file_build_id": f} for p, f in candidates],
    }
    if not candidates:
        status = PrerequisiteStatus.WARNING if btf else PrerequisiteStatus.FAILED
        message = (
            "no DWARF vmlinux found; BTF present (drgn may attach with reduced coverage)"
            if btf
            else "no vmlinux DWARF debuginfo found in drgn's default search paths"
        )
        fix = None if btf else "Install kernel debuginfo (e.g. kernel-debuginfo / linux-image-*-dbg)."
    elif build_id_verified:
        status = PrerequisiteStatus.PASSED
        message = f"vmlinux debuginfo matches the running kernel at {chosen_path}"
        fix = None
    else:
        status = PrerequisiteStatus.WARNING
        message = "vmlinux debuginfo found but its build-id is not confirmed against the running kernel"
        fix = None
    return PrerequisiteCheck(
        check_id="target.vmlinux_debuginfo",
        status=status,
        message=message,
        details=details,
        suggested_fix=fix,
    )


def _kernel_buildid_check(running: str | None, host: str | None) -> PrerequisiteCheck:
    if running is None or host is None:
        status = PrerequisiteStatus.SKIPPED
        message = (
            "host build-id unknown — provenance not checked"
            if host is None
            else "running build-id unavailable (e.g. /sys/kernel/notes unreadable)"
        )
    elif running == host:
        status = PrerequisiteStatus.PASSED
        message = "running kernel build-id matches the host build"
    else:
        status = PrerequisiteStatus.WARNING
        message = "running kernel build-id does not match the host build"
    return PrerequisiteCheck(
        check_id="target.kernel_buildid",
        status=status,
        message=message,
        details={"running": running, "expected": host},
    )


def _module_debuginfo_check(vmlinux: dict[str, Any]) -> PrerequisiteCheck:
    present = bool(vmlinux.get("module_debuginfo"))
    return PrerequisiteCheck(
        check_id="target.module_debuginfo",
        status=PrerequisiteStatus.PASSED if present else PrerequisiteStatus.WARNING,
        message=(
            "module debuginfo present"
            if present
            else "module debuginfo not found (core-kernel introspection still works)"
        ),
        details={"path": vmlinux.get("module_path")},
    )


def build_probe_checks(probe: dict[str, Any], *, host_build_id: Any) -> tuple[list[PrerequisiteCheck], str]:
    """Spec §4-§5: turn raw probe JSON into checks + tri-state verdict.

    ``build_id_verified`` and ``file_matches_host`` are computed here (the
    target cannot know the host build-id ``H``).
    """
    host = normalize_build_id(host_build_id)
    running = normalize_build_id(probe.get("running_build_id"))
    vmlinux = probe.get("vmlinux_debuginfo") or {}
    candidates = [
        (c.get("path"), normalize_build_id(c.get("file_build_id")))
        for c in (vmlinux.get("candidates") or [])
        if isinstance(c, dict)
    ]

    found = bool(candidates)
    match_running = next((p for p, f in candidates if running is not None and f == running), None)
    match_host = next((p for p, f in candidates if host is not None and f == host), None)
    build_id_verified = match_running is not None
    file_matches_host = match_host is not None
    chosen_path = match_running or match_host or (candidates[0][0] if candidates else None)
    chosen_id = next((f for p, f in candidates if p == chosen_path), None)
    btf = bool(vmlinux.get("btf"))
    parsed_any = any(f is not None for _, f in candidates)
    wrong_debuginfo = running is not None and parsed_any and match_running is None

    checks = [
        _python_check(probe),
        _drgn_check(probe),
        _vmlinux_check(
            candidates=candidates,
            btf=btf,
            build_id_verified=build_id_verified,
            file_matches_host=file_matches_host,
            chosen_path=chosen_path,
            chosen_id=chosen_id,
        ),
        _kernel_buildid_check(running, host),
        _module_debuginfo_check(vmlinux),
    ]

    verdict = _verdict(
        drgn_present=bool(probe.get("drgn_present")),
        found=found,
        btf=btf,
        running=running,
        host=host,
        build_id_verified=build_id_verified,
        wrong_debuginfo=wrong_debuginfo,
    )
    return checks, verdict
