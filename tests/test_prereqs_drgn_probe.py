"""Unit tests for the host-side drgn-probe core (spec §4-§5)."""

import json
import subprocess
import sys
from typing import Any

from kdive.domain import PrerequisiteCheck, PrerequisiteStatus
from kdive.prereqs.drgn_probe import (
    PROBE_SCRIPT,
    UNKNOWN,
    UNUSABLE,
    USABLE,
    build_probe_checks,
    install_hint,
    normalize_build_id,
    python_missing_checks,
)
from kdive.providers.local_drgn_introspect import TARGET_PYTHON_ARGV, local_drgn_introspect_capability


def test_target_python_argv_is_shared_constant() -> None:
    # Spec §4: probe and runner must use the same interpreter invocation.
    assert TARGET_PYTHON_ARGV == ["python3", "-"]


def test_normalize_build_id() -> None:
    assert normalize_build_id("AB:CD ef\n") == "abcdef"
    assert normalize_build_id("0xDEAD") == "dead"
    assert normalize_build_id("") is None
    assert normalize_build_id(None) is None
    assert normalize_build_id(123) is None


def test_install_hint_by_distro() -> None:
    assert "dnf install drgn" in install_hint("fedora")
    assert "python3-drgn" in install_hint("rhel")
    assert "apt install python3-drgn" in install_hint("ubuntu")
    assert "pip install drgn" in install_hint(None)
    assert "pip install drgn" in install_hint("plan9")


def test_python_missing_checks() -> None:
    checks, verdict = python_missing_checks()
    by_id = {c.check_id: c for c in checks}
    assert by_id["target.python3"].status == PrerequisiteStatus.FAILED
    assert by_id["target.drgn"].status == PrerequisiteStatus.SKIPPED
    assert by_id["target.vmlinux_debuginfo"].status == PrerequisiteStatus.SKIPPED
    assert verdict == UNUSABLE


HOST = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret
OTHER = "ffffffffffffffffffffffffffffffffffffffff"  # pragma: allowlist secret


def _probe(**over: object) -> dict[str, Any]:
    base: dict[str, Any] = {
        "python_version": "3.11.2",
        "python_executable": "/usr/bin/python3",
        "drgn_present": True,
        "drgn_version": "0.0.27",
        "distro_id": "fedora",
        "distro_version": "39",
        "kernel_release": "6.7.0",
        "running_build_id": HOST,
        "vmlinux_debuginfo": {
            "candidates": [{"path": "/usr/lib/debug/boot/vmlinux-6.7.0", "file_build_id": HOST}],
            "btf": True,
            "module_debuginfo": True,
            "module_path": "/usr/lib/debug/lib/modules/6.7.0/kernel",
        },
    }
    base.update(over)
    return base


def _ids(checks: list[PrerequisiteCheck]) -> dict[str, PrerequisiteCheck]:
    return {c.check_id: c for c in checks}


def test_verdict_usable_when_all_agree() -> None:
    checks, verdict = build_probe_checks(_probe(), host_build_id=HOST)
    assert verdict == USABLE
    by = _ids(checks)
    assert by["target.vmlinux_debuginfo"].status == PrerequisiteStatus.PASSED
    assert by["target.vmlinux_debuginfo"].details["build_id_verified"] is True
    assert by["target.kernel_buildid"].status == PrerequisiteStatus.PASSED


def test_drgn_missing_is_unusable_with_hint() -> None:
    checks, verdict = build_probe_checks(_probe(drgn_present=False, drgn_version=None), host_build_id=HOST)
    by = _ids(checks)
    assert by["target.drgn"].status == PrerequisiteStatus.FAILED
    assert "dnf install drgn" in by["target.drgn"].suggested_fix
    assert by["target.drgn"].details["executable"] == "/usr/bin/python3"
    assert verdict == UNUSABLE


def test_proven_provenance_mismatch_is_unusable() -> None:
    probe = _probe(running_build_id=OTHER)
    probe["vmlinux_debuginfo"]["candidates"] = [{"path": "/boot/vmlinux-6.7.0", "file_build_id": OTHER}]
    checks, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert _ids(checks)["target.kernel_buildid"].status == PrerequisiteStatus.WARNING
    assert verdict == UNUSABLE


def test_wrong_debuginfo_no_btf_is_unusable() -> None:
    probe = _probe()
    probe["vmlinux_debuginfo"]["candidates"] = [{"path": "/boot/vmlinux-6.7.0", "file_build_id": OTHER}]
    probe["vmlinux_debuginfo"]["btf"] = False
    _, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert verdict == UNUSABLE


def test_wrong_debuginfo_with_btf_is_unknown() -> None:
    # A present-but-wrong DWARF alongside BTF is unconfirmable: drgn may fall
    # back to BTF, so the honest verdict is UNKNOWN, never a false UNUSABLE.
    probe = _probe()
    probe["vmlinux_debuginfo"]["candidates"] = [{"path": "/boot/vmlinux-6.7.0", "file_build_id": OTHER}]
    probe["vmlinux_debuginfo"]["btf"] = True
    _, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert verdict == UNKNOWN


def test_set_based_match_avoids_false_unusable() -> None:
    probe = _probe()
    probe["vmlinux_debuginfo"]["candidates"] = [
        {"path": "/usr/lib/debug/boot/vmlinux-6.7.0", "file_build_id": OTHER},
        {"path": "/lib/modules/6.7.0/build/vmlinux", "file_build_id": HOST},
    ]
    checks, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert verdict == USABLE
    assert _ids(checks)["target.vmlinux_debuginfo"].details["path"] == "/lib/modules/6.7.0/build/vmlinux"


def test_running_build_id_null_is_unknown_and_buildid_skipped() -> None:
    probe = _probe(running_build_id=None)
    probe["vmlinux_debuginfo"]["candidates"] = [{"path": "/boot/vmlinux-6.7.0", "file_build_id": HOST}]
    checks, verdict = build_probe_checks(probe, host_build_id=HOST)
    by = _ids(checks)
    assert by["target.kernel_buildid"].status == PrerequisiteStatus.SKIPPED
    assert by["target.vmlinux_debuginfo"].status == PrerequisiteStatus.WARNING
    assert by["target.vmlinux_debuginfo"].details["file_matches_host"] is True
    assert verdict == UNKNOWN


def test_host_build_id_absent_is_unknown() -> None:
    checks, verdict = build_probe_checks(_probe(), host_build_id=None)
    assert _ids(checks)["target.kernel_buildid"].status == PrerequisiteStatus.SKIPPED
    assert verdict == UNKNOWN


def test_no_dwarf_but_btf_is_unknown_warning() -> None:
    probe = _probe()
    probe["vmlinux_debuginfo"]["candidates"] = []
    checks, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert _ids(checks)["target.vmlinux_debuginfo"].status == PrerequisiteStatus.WARNING
    assert verdict == UNKNOWN


def test_no_dwarf_no_btf_is_unusable_failed() -> None:
    probe = _probe()
    probe["vmlinux_debuginfo"] = {"candidates": [], "btf": False}
    checks, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert _ids(checks)["target.vmlinux_debuginfo"].status == PrerequisiteStatus.FAILED
    assert verdict == UNUSABLE


def test_module_debuginfo_absent_is_warning_only() -> None:
    probe = _probe()
    probe["vmlinux_debuginfo"]["module_debuginfo"] = False
    checks, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert _ids(checks)["target.module_debuginfo"].status == PrerequisiteStatus.WARNING
    assert verdict == USABLE


def test_probe_script_compiles() -> None:
    compile(PROBE_SCRIPT, "<probe>", "exec")


def test_probe_script_runs_and_emits_valid_json() -> None:
    # Runs on the test host; sub-steps that can't read /sys degrade to null
    # rather than crashing, so this is portable (incl. minimal CI containers).
    proc = subprocess.run(
        [sys.executable, "-"],
        input=PROBE_SCRIPT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    for key in (
        "python_version",
        "python_executable",
        "drgn_present",
        "kernel_release",
        "running_build_id",
        "vmlinux_debuginfo",
    ):
        assert key in doc
    assert isinstance(doc["vmlinux_debuginfo"]["candidates"], list)


def test_capability_advertises_check_prerequisites() -> None:
    cap = local_drgn_introspect_capability()
    assert "debug.introspect.check_prerequisites" in cap.operations
    assert "debug.introspect.run" in cap.operations
