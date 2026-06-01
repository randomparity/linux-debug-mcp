from __future__ import annotations

import json
import subprocess
import sys

from kdive.domain import PrerequisiteStatus
from kdive.prereqs.kdump_probe import build_kdump_checks, render_kdump_probe_script


def _by_id(checks):
    return {c.check_id: c for c in checks}


READY = {
    "arch": "x86_64",
    "cmdline_has_crashkernel": True,
    "kexec_crash_size": 268435456,
    "fadump_enabled": None,
    "fadump_registered": None,
    "service_active": True,
    "service_units": {"kdump": "active", "kdump-tools": "inactive"},
    "dump_target_directive": None,
    "dump_dir": None,
    "kdump_conf_error": None,
    "dump_dir_exists": True,
    "dump_dir_writable": True,
    "dump_dir_write_error": None,
}


def test_ready_target_all_pass() -> None:
    checks, mechanism = build_kdump_checks(READY)
    assert mechanism == "kdump"
    by_id = _by_id(checks)
    assert {c.status for c in checks} == {PrerequisiteStatus.PASSED}
    assert set(by_id) == {
        "kdump.crashkernel_reserved",
        "kdump.service_active",
        "kdump.dump_path_writable",
    }


def test_three_faults_are_independent() -> None:
    probe = dict(
        READY,
        cmdline_has_crashkernel=False,
        kexec_crash_size=0,
        service_active=False,
        dump_dir_exists=False,
        dump_dir_writable=None,
    )
    checks, mechanism = build_kdump_checks(probe)
    assert mechanism == "none"
    assert all(c.status == PrerequisiteStatus.FAILED for c in checks)
    assert all(c.suggested_fix for c in checks)


def test_crashkernel_present_but_zero_bytes_fails_with_distinct_fix() -> None:
    probe = dict(READY, cmdline_has_crashkernel=True, kexec_crash_size=0)
    checks, _ = build_kdump_checks(probe)
    chk = _by_id(checks)["kdump.crashkernel_reserved"]
    assert chk.status == PrerequisiteStatus.FAILED
    assert "0 bytes" in chk.message


def test_crashkernel_absent_has_add_fix() -> None:
    probe = dict(READY, cmdline_has_crashkernel=False, kexec_crash_size=0)
    checks, _ = build_kdump_checks(probe)
    chk = _by_id(checks)["kdump.crashkernel_reserved"]
    assert chk.status == PrerequisiteStatus.FAILED
    assert "command line" in (chk.suggested_fix or "")


def test_fadump_enabled_reports_fadump_not_a_kdump_failure() -> None:
    probe = dict(
        READY,
        arch="ppc64le",
        cmdline_has_crashkernel=False,
        kexec_crash_size=0,
        fadump_enabled=1,
        fadump_registered=1,
    )
    checks, mechanism = build_kdump_checks(probe)
    assert mechanism == "fadump"
    chk = _by_id(checks)["kdump.crashkernel_reserved"]
    assert chk.status == PrerequisiteStatus.PASSED
    assert "fadump" in chk.message.lower()


def test_service_fact_missing_does_not_mask_other_checks() -> None:
    probe = dict(READY, service_active=None, service_units={"error": "TimeoutExpired"})
    checks, _ = build_kdump_checks(probe)
    by_id = _by_id(checks)
    assert by_id["kdump.service_active"].status == PrerequisiteStatus.FAILED
    assert by_id["kdump.crashkernel_reserved"].status == PrerequisiteStatus.PASSED
    assert by_id["kdump.dump_path_writable"].status == PrerequisiteStatus.PASSED


def test_unwritable_dump_dir_fails_with_errno() -> None:
    probe = dict(READY, dump_dir_writable=False, dump_dir_write_error="EROFS")
    checks, _ = build_kdump_checks(probe)
    chk = _by_id(checks)["kdump.dump_path_writable"]
    assert chk.status == PrerequisiteStatus.FAILED
    assert "EROFS" in chk.message


def test_missing_dump_dir_fails_with_create_fix() -> None:
    probe = dict(READY, dump_dir=None, dump_dir_exists=False, dump_dir_writable=None)
    checks, _ = build_kdump_checks(probe)
    chk = _by_id(checks)["kdump.dump_path_writable"]
    assert chk.status == PrerequisiteStatus.FAILED
    assert "create" in (chk.suggested_fix or "").lower()


def test_kdump_conf_error_is_preserved_in_dump_path_details() -> None:
    conf_error = {"type": "PermissionError", "message": "permission denied"}
    probe = dict(READY, dump_dir=None, kdump_conf_error=conf_error)

    checks, _ = build_kdump_checks(probe)
    chk = _by_id(checks)["kdump.dump_path_writable"]

    assert chk.details["kdump_conf_error"] == conf_error


def test_separate_dump_device_is_warning_not_false_fail() -> None:
    probe = dict(
        READY,
        dump_target_directive="ext4",
        dump_dir="/crash",
        dump_dir_exists=False,
        dump_dir_writable=None,
    )
    checks, _ = build_kdump_checks(probe)
    chk = _by_id(checks)["kdump.dump_path_writable"]
    assert chk.status == PrerequisiteStatus.WARNING
    assert "ext4" in chk.message


def test_render_substitutes_systemctl_timeout() -> None:
    script = render_kdump_probe_script(systemctl_timeout=3)
    assert "timeout=3" in script
    assert "$systemctl_timeout" not in script


def test_probe_script_runs_on_host_and_emits_expected_keys() -> None:
    # The script is stdlib-only and must run without crashing on any Linux host,
    # emitting one JSON object with the full fact set (values may be null here).
    script = render_kdump_probe_script(systemctl_timeout=3)
    proc = subprocess.run([sys.executable, "-"], input=script, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    facts = json.loads(proc.stdout)
    for key in (
        "arch",
        "cmdline_has_crashkernel",
        "kexec_crash_size",
        "fadump_enabled",
        "fadump_registered",
        "service_active",
        "service_units",
        "dump_target_directive",
        "dump_dir",
        "kdump_conf_error",
        "dump_dir_exists",
        "dump_dir_writable",
        "dump_dir_write_error",
    ):
        assert key in facts
