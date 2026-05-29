from __future__ import annotations

import pytest

from linux_debug_mcp.symbols.verify import (
    BUILD_ID_RE,
    ProvenanceMismatch,
    verify_build_id,
)

FULL = "a" * 40


def test_equal_ids_do_not_raise():
    verify_build_id(expected=FULL, observed=FULL)


def test_mismatch_raises_carrying_both_ids():
    other = "b" * 40
    with pytest.raises(ProvenanceMismatch) as excinfo:
        verify_build_id(expected=FULL, observed=other)
    assert excinfo.value.expected == FULL
    assert excinfo.value.observed == other


def test_prefix_of_same_build_is_a_mismatch():
    # The no-truncation contract: a prefix of the same build_id is NOT equal.
    with pytest.raises(ProvenanceMismatch):
        verify_build_id(expected=FULL, observed=FULL[:16])


@pytest.mark.parametrize("bad", ["", "abc", "A" * 40, "g" * 40, "12 34"])
def test_build_id_re_rejects_malformed(bad):
    assert BUILD_ID_RE.match(bad) is None


@pytest.mark.parametrize("good", ["a" * 8, "0123456789abcdef", "f" * 64])
def test_build_id_re_accepts_canonical(good):
    assert BUILD_ID_RE.match(good) is not None
