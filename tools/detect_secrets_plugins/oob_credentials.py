from __future__ import annotations

import re

from detect_secrets.plugins.base import RegexBasedDetector


class OobCredentialDetector(RegexBasedDetector):
    """Flag hardcoded out-of-band management credentials (BMC/HMC/NovaLink/IPMI) assigned
    to a concrete value. Matches ``<keyword> = "value"`` / ``<keyword>: value`` — an
    assignment to a non-empty value — NOT a bare keyword mention, so design docs that name
    these systems in prose are not flagged."""

    secret_type = "Out-of-band management credential"  # pragma: allowlist secret

    denylist = (
        re.compile(
            r"(?i)\b(?:bmc|hmc|novalink|ipmi)[ _-]?(?:password|passwd|pass|secret|token|key)\b"
            r"\s*[=:]\s*['\"]?\S+"
        ),
    )
