from __future__ import annotations

import re

BUILD_ID_RE = re.compile(r"^[0-9a-f]{8,}$")


class ProvenanceMismatch(Exception):
    """Raised when an observed build_id does not equal the expected build_id.

    Both ids are opaque lower-case hex and safe to surface to callers.
    """

    def __init__(self, *, expected: str, observed: str) -> None:
        super().__init__(f"build_id mismatch: expected {expected!r}, observed {observed!r}")
        self.expected = expected
        self.observed = observed


def verify_build_id(*, expected: str, observed: str) -> None:
    """Raise :class:`ProvenanceMismatch` if *observed* != *expected*.

    Both MUST be the full canonical lower-case build-id (never a prefix).
    Shape validation is the caller's job (see :data:`BUILD_ID_RE`); this
    function decides equality only -- the one rule both the live and offline
    callers share.
    """
    if observed != expected:
        raise ProvenanceMismatch(expected=expected, observed=observed)
