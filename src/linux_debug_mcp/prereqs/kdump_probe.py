"""Host-side core for debug.postmortem.check_prereqs (#94 / ADR 0028).

Pure, SSH-free decision logic so the kdump-readiness verdict matrix is
unit-testable. The on-target probe (``KDUMP_PROBE_SCRIPT_TEMPLATE``) emits one JSON
facts object; this module turns it into three independent ``PrerequisiteCheck``s plus
the detected crash-capture mechanism. The target emits facts; the host decides
PASS/FAIL (the trust boundary mirrors ``prereqs/drgn_probe.py``).
"""

from __future__ import annotations

from typing import Any

from linux_debug_mcp.domain import PrerequisiteCheck, PrerequisiteStatus

KDUMP = "kdump"
FADUMP = "fadump"
NONE = "none"

# kdump service unit names probed, in order. Fedora/RHEL/SUSE: kdump; Debian/Ubuntu:
# kdump-tools. Both are queried in ONE `systemctl is-active` call (one bounded
# subprocess) so a stalled systemctl cannot overrun the call budget (ADR 0028 dec 2).
SERVICE_UNITS = ("kdump", "kdump-tools")

# makedumpfile dump-target directive keywords. When /etc/kdump.conf names one of
# these, the dump `path` is relative to that target's mount (not the rootfs), so a
# local write-probe is meaningless — the dump-path check degrades to WARNING
# (ADR 0028 decision 5).
DUMP_TARGET_DIRECTIVES = (
    "raw",
    "ext2",
    "ext3",
    "ext4",
    "xfs",
    "btrfs",
    "minix",
    "nfs",
    "ssh",
    "nvme",
    "virtiofs",
)

DEFAULT_DUMP_DIR = "/var/crash"


def _as_int(value: Any) -> int:
    return value if isinstance(value, int) else 0


def resolve_mechanism(probe: dict[str, Any]) -> str:
    """fadump if firmware-assisted dump is enabled; else kdump if crashkernel
    memory is reserved; else none (ADR 0028 decision 4)."""
    if probe.get("fadump_enabled") == 1:
        return FADUMP
    if probe.get("cmdline_has_crashkernel") and _as_int(probe.get("kexec_crash_size")) > 0:
        return KDUMP
    return NONE


def _crashkernel_check(probe: dict[str, Any], mechanism: str) -> PrerequisiteCheck:
    if mechanism == FADUMP:
        return PrerequisiteCheck(
            check_id="kdump.crashkernel_reserved",
            status=PrerequisiteStatus.PASSED,
            message="firmware-assisted dump (fadump) is the active POWER crash-capture mechanism",
            details={"mechanism": FADUMP, "fadump_registered": probe.get("fadump_registered")},
        )
    size = _as_int(probe.get("kexec_crash_size"))
    has_cmdline = bool(probe.get("cmdline_has_crashkernel"))
    details = {"cmdline_has_crashkernel": has_cmdline, "kexec_crash_size": probe.get("kexec_crash_size")}
    if has_cmdline and size > 0:
        return PrerequisiteCheck(
            check_id="kdump.crashkernel_reserved",
            status=PrerequisiteStatus.PASSED,
            message=f"crashkernel memory is reserved ({size} bytes)",
            details=details,
        )
    if not has_cmdline:
        message = "no crashkernel= reservation on the kernel command line"
        fix = "add a crashkernel= reservation to the kernel command line and reboot"
    else:
        message = "crashkernel= is set but reserved 0 bytes (/sys/kernel/kexec_crash_size is 0)"
        fix = "crashkernel= reserved 0 bytes; choose a value that fits available RAM (e.g. crashkernel=256M) and reboot"
    return PrerequisiteCheck(
        check_id="kdump.crashkernel_reserved",
        status=PrerequisiteStatus.FAILED,
        message=message,
        details=details,
        suggested_fix=fix,
    )


def _service_check(probe: dict[str, Any]) -> PrerequisiteCheck:
    units = probe.get("service_units") or {}
    if probe.get("service_active") is True:
        return PrerequisiteCheck(
            check_id="kdump.service_active",
            status=PrerequisiteStatus.PASSED,
            message="a kdump service unit is active",
            details={"units": units},
        )
    return PrerequisiteCheck(
        check_id="kdump.service_active",
        status=PrerequisiteStatus.FAILED,
        message=f"no kdump service unit is active (checked: {', '.join(SERVICE_UNITS)})",
        details={"units": units},
        suggested_fix=(
            "enable and start the kdump service (e.g. `systemctl enable --now kdump`); "
            "this tool reports state only and never starts it"
        ),
    )


def _dump_path_check(probe: dict[str, Any]) -> PrerequisiteCheck:
    dump_dir = probe.get("dump_dir") or DEFAULT_DUMP_DIR
    directive = probe.get("dump_target_directive")
    if directive:
        return PrerequisiteCheck(
            check_id="kdump.dump_path_writable",
            status=PrerequisiteStatus.WARNING,
            message=(
                f"dump target is a separate '{directive}' device/share; local writability "
                f"not assessed (x86_64 local {DEFAULT_DUMP_DIR} is the tested path)"
            ),
            details={"dump_dir": dump_dir, "dump_target_directive": directive},
        )
    details = {"dump_dir": dump_dir, "source": "kdump.conf" if probe.get("dump_dir") else "default"}
    if not probe.get("dump_dir_exists"):
        return PrerequisiteCheck(
            check_id="kdump.dump_path_writable",
            status=PrerequisiteStatus.FAILED,
            message=f"dump directory {dump_dir} does not exist",
            details=details,
            suggested_fix=f"create {dump_dir} (it must be writable by the root capture kernel)",
        )
    if probe.get("dump_dir_writable"):
        return PrerequisiteCheck(
            check_id="kdump.dump_path_writable",
            status=PrerequisiteStatus.PASSED,
            message=f"dump directory {dump_dir} is writable",
            details=details,
        )
    err = probe.get("dump_dir_write_error") or "write failed"
    return PrerequisiteCheck(
        check_id="kdump.dump_path_writable",
        status=PrerequisiteStatus.FAILED,
        message=f"dump directory {dump_dir} is not writable by the capture kernel: {err}",
        details={**details, "write_error": err},
        suggested_fix="fix the mount (read-only?), free space (ENOSPC), or ownership/permissions",
    )


def build_kdump_checks(probe: dict[str, Any]) -> tuple[list[PrerequisiteCheck], str]:
    """Turn the raw probe JSON into three independent checks + the mechanism string.

    The three checks are built from one already-collected facts object, so one
    probe's failure never masks another (the independence invariant, AC#2).
    """
    mechanism = resolve_mechanism(probe)
    checks = [
        _crashkernel_check(probe, mechanism),
        _service_check(probe),
        _dump_path_check(probe),
    ]
    return checks, mechanism
