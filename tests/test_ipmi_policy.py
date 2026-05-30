from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from kdive.safety.ipmi import (
    IPMI_ALLOWED_CIPHER_SUITES,
    IPMI_DEFAULT_CIPHER_SUITE,
    IPMI_FORBIDDEN_CIPHER_SUITE,
    IPMI_INTERFACE,
    IpmiPolicyError,
    check_ipmi_cipher_value,
    validate_ipmi_cipher_suite,
)


def test_policy_constants() -> None:
    assert IPMI_INTERFACE == "lanplus"
    assert IPMI_FORBIDDEN_CIPHER_SUITE == 0
    assert IPMI_DEFAULT_CIPHER_SUITE == 3
    assert 3 in IPMI_ALLOWED_CIPHER_SUITES
    assert len(IPMI_ALLOWED_CIPHER_SUITES) == 1
    assert IPMI_FORBIDDEN_CIPHER_SUITE not in IPMI_ALLOWED_CIPHER_SUITES


def test_none_normalizes_to_default() -> None:
    assert validate_ipmi_cipher_suite(None) == IPMI_DEFAULT_CIPHER_SUITE


def test_allowed_suite_passes() -> None:
    assert validate_ipmi_cipher_suite(3) == 3
    assert check_ipmi_cipher_value(3) == 3


def test_cipher_zero_rejected() -> None:
    with pytest.raises(IpmiPolicyError) as exc:
        validate_ipmi_cipher_suite(0)
    assert "0" in str(exc.value)
    with pytest.raises(IpmiPolicyError):
        check_ipmi_cipher_value(0)


@pytest.mark.parametrize("suite", [1, 2, 17, -1, 999])
def test_non_allowlisted_suites_rejected(suite: int) -> None:
    with pytest.raises(IpmiPolicyError):
        validate_ipmi_cipher_suite(suite)
    with pytest.raises(IpmiPolicyError):
        check_ipmi_cipher_value(suite)


def test_ipmi_policy_error_is_value_error() -> None:
    assert issubclass(IpmiPolicyError, ValueError)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_check_ipmi() -> subprocess.CompletedProcess[str]:
    just = shutil.which("just")
    if just is None:
        pytest.skip("just is not installed")
    return subprocess.run(
        [just, "check-ipmi"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_check_ipmi_passes_on_clean_tree() -> None:
    result = _run_check_ipmi()
    assert result.returncode == 0, result.stdout + result.stderr


def test_guard_pattern_flags_forbidden_and_passes_compliant(tmp_path: Path) -> None:
    pattern = r"-I lan\b|-C *0\b"
    sample = tmp_path / "sample.txt"
    sample.write_text(
        "ipmitool -I lanplus -C 3 sol activate\n"
        "ipmitool -I lanplus -C 30 raw\n"
        "ipmitool -I lan -U admin\n"
        "ipmitool -C 0 chassis\n"
        "ipmitool -C0 power\n"
    )
    rg = shutil.which("rg")
    if rg is None:
        pytest.skip("ripgrep is not installed")
    proc = subprocess.run(
        [rg, "-n", "-e", pattern, str(sample)],
        capture_output=True,
        text=True,
        check=False,
    )
    matched_lines = {line.split(":", 1)[0] for line in proc.stdout.splitlines()}
    assert matched_lines == {"3", "4", "5"}
