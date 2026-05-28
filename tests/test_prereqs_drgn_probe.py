"""Unit tests for the host-side drgn-probe core (spec §4-§5)."""

from linux_debug_mcp.domain import PrerequisiteStatus
from linux_debug_mcp.prereqs.drgn_probe import (
    UNUSABLE,
    install_hint,
    normalize_build_id,
    python_missing_checks,
)
from linux_debug_mcp.providers.local_drgn_introspect import TARGET_PYTHON_ARGV


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
