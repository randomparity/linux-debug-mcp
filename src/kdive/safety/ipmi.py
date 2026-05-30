"""IPMI cipher-suite policy chokepoint.

Single source of truth for the IPMI hardening invariant (issue #67): IPMI must
use the ``lanplus`` interface with an authenticated cipher suite, and cipher
suite 0 (no authentication) is always refused. This module owns the allowlist
and opens no resources; the ``ipmi-sol`` provider (#15) must validate through
``validate_ipmi_cipher_suite`` rather than re-deriving the rule.
"""

from __future__ import annotations

IPMI_INTERFACE = "lanplus"
IPMI_FORBIDDEN_CIPHER_SUITE = 0
IPMI_DEFAULT_CIPHER_SUITE = 3
IPMI_ALLOWED_CIPHER_SUITES: frozenset[int] = frozenset({3})


class IpmiPolicyError(ValueError):
    """Raised when an IPMI configuration violates the cipher-suite policy."""


def check_ipmi_cipher_value(value: int) -> int:
    """Validate a concrete (non-``None``) IPMI cipher suite against the policy.

    Used by field-level validators so the rejection is attributed to the
    offending field. Cipher suite 0 and any suite outside
    ``IPMI_ALLOWED_CIPHER_SUITES`` raise ``IpmiPolicyError``.

    Args:
        value: The requested cipher suite.

    Returns:
        The approved cipher suite integer (unchanged).

    Raises:
        IpmiPolicyError: If the suite is 0 or not in the allowlist.
    """
    if value == IPMI_FORBIDDEN_CIPHER_SUITE:
        raise IpmiPolicyError(
            "IPMI cipher suite 0 disables authentication and is refused; "
            f"use cipher suite {IPMI_DEFAULT_CIPHER_SUITE} (lanplus)"
        )
    if value not in IPMI_ALLOWED_CIPHER_SUITES:
        allowed = ", ".join(str(suite) for suite in sorted(IPMI_ALLOWED_CIPHER_SUITES))
        raise IpmiPolicyError(f"IPMI cipher suite must be one of {{{allowed}}}; got {value}")
    return value


def validate_ipmi_cipher_suite(value: int | None) -> int:
    """Return a policy-approved IPMI cipher suite, taking the default for ``None``.

    The chokepoint the ``ipmi-sol`` provider (#15) calls to resolve an effective
    suite. ``None`` normalizes to ``IPMI_DEFAULT_CIPHER_SUITE``; otherwise the
    value is checked via :func:`check_ipmi_cipher_value`.

    Args:
        value: Requested cipher suite, or ``None`` to take the mandated default.

    Returns:
        The approved cipher suite integer.

    Raises:
        IpmiPolicyError: If the suite is 0 or not in the allowlist.
    """
    if value is None:
        return IPMI_DEFAULT_CIPHER_SUITE
    return check_ipmi_cipher_value(value)
