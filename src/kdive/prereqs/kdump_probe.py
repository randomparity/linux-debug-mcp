"""Host-side core for debug.postmortem.check_prereqs (#94 / ADR 0028).

Pure, SSH-free decision logic so the kdump-readiness verdict matrix is
unit-testable. The on-target probe (``KDUMP_PROBE_SCRIPT_TEMPLATE``) emits one JSON
facts object; this module turns it into three independent ``PrerequisiteCheck``s plus
the detected crash-capture mechanism. The target emits facts; the host decides
PASS/FAIL (the trust boundary mirrors ``prereqs/drgn_probe.py``).
"""

from __future__ import annotations

from string import Template
from typing import Any

from kdive.domain import PrerequisiteCheck, PrerequisiteStatus

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
    details = {
        "dump_dir": dump_dir,
        "source": "kdump.conf" if probe.get("dump_dir") else "default",
        "kdump_conf_error": probe.get("kdump_conf_error"),
    }
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


# On-target probe. stdlib-only python3 reading stdin, emitting ONE JSON facts object
# on stdout. The host (build_kdump_checks) decides verdicts. `$systemctl_timeout` and
# `$units` / `$targets` are substituted by render_kdump_probe_script: the systemctl
# timeout is derived from the call budget so the single systemctl call is provably
# under the outer `timeout Ns` bound (ADR 0028 decision 2). The probe runs as root
# (sudo prefix for non-root logins), so the dump-dir writability fact is a transient
# mkstemp write probe, NOT os.access(W_OK) (root bypasses mode bits — ADR 0028 dec 5).
# Self-cleaning except on an outer-timeout SIGKILL, which skips the finally and may
# leave one ".kdive-writecheck-*" temp file in the dump dir.
KDUMP_PROBE_SCRIPT_TEMPLATE = Template(
    r"""import errno, json, os, subprocess, sys, tempfile

UNITS = list($units)
TARGETS = set($targets)


def _error(exc):
    return {"type": type(exc).__name__, "message": str(exc)[:160]}


def _read_int(path):
    try:
        with open(path) as fh:
            return int(fh.read().strip())
    except Exception:
        return None


def _cmdline_has_crashkernel():
    try:
        with open("/proc/cmdline") as fh:
            return "crashkernel=" in fh.read()
    except Exception:
        return None


def _service_states():
    states = {}
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", *UNITS],
            capture_output=True,
            text=True,
            timeout=$systemctl_timeout,
        )
        lines = proc.stdout.splitlines()
        for i, unit in enumerate(UNITS):
            states[unit] = lines[i].strip() if i < len(lines) else "unknown"
        return any(s == "active" for s in states.values()), states
    except Exception as exc:
        return None, {"error": type(exc).__name__}


def _kdump_conf():
    directive = None
    dump_dir = None
    try:
        with open("/etc/kdump.conf") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                kw = parts[0]
                if kw in TARGETS and directive is None:
                    directive = kw
                elif kw == "path" and len(parts) > 1:
                    dump_dir = parts[1].strip()
    except Exception as exc:
        return directive, dump_dir, _error(exc)
    return directive, dump_dir, None


def _writable(d):
    if not os.path.isdir(d):
        return None, None
    fd = None
    path = None
    try:
        fd, path = tempfile.mkstemp(dir=d, prefix=".kdive-writecheck-")
        return True, None
    except OSError as exc:
        return False, errno.errorcode.get(exc.errno, str(exc.errno))
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        if path is not None:
            try:
                os.unlink(path)
            except Exception:
                pass


directive, conf_dir, conf_error = _kdump_conf()
dump_dir = conf_dir or "/var/crash"
service_active, service_units = _service_states()
writable, write_error = _writable(dump_dir)
try:
    arch = os.uname().machine
except Exception:
    arch = None

result = {
    "arch": arch,
    "cmdline_has_crashkernel": _cmdline_has_crashkernel(),
    "kexec_crash_size": _read_int("/sys/kernel/kexec_crash_size"),
    "fadump_enabled": _read_int("/sys/kernel/fadump_enabled"),
    "fadump_registered": _read_int("/sys/kernel/fadump_registered"),
    "service_active": service_active,
    "service_units": service_units,
    "dump_target_directive": directive,
    "dump_dir": conf_dir,
    "kdump_conf_error": conf_error,
    "dump_dir_exists": os.path.isdir(dump_dir),
    "dump_dir_writable": writable,
    "dump_dir_write_error": write_error,
}
sys.stdout.write(json.dumps(result))
"""
)


def render_kdump_probe_script(*, systemctl_timeout: int) -> str:
    """Render the on-target probe with the budget-derived systemctl timeout and the
    canonical unit / dump-target lists (one source of truth — ADR 0028 dec 2)."""
    return KDUMP_PROBE_SCRIPT_TEMPLATE.substitute(
        systemctl_timeout=systemctl_timeout,
        units=repr(list(SERVICE_UNITS)),
        targets=repr(list(DUMP_TARGET_DIRECTIVES)),
    )
