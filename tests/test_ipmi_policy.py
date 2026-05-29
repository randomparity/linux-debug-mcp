from __future__ import annotations

import pytest

from linux_debug_mcp.safety.ipmi import (
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
