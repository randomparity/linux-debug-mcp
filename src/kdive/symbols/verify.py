from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from kdive.symbols.build_id import read_elf_build_id

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


def verify_vmlinux_provenance(
    *,
    expected_build_id: str,
    vmlinux_path: Path,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
) -> str:
    """Read the vmlinux ELF build-id and verify it equals *expected_build_id*.

    Returns the observed build-id on success. Raises
    :class:`kdive.symbols.build_id.BuildIdReadError` when the file is
    unreadable / not an ELF / carries no GNU build-id note, and
    :class:`ProvenanceMismatch` when the observed id differs from *expected_build_id*.

    The caller MUST have validated *expected_build_id*'s shape (the recorded §4.2
    value); ``read_elf_build_id`` already returns canonical lower-case hex, so the
    observed side needs no separate shape check. This is the §4.2 consumable
    verification entry point (interface-contracts §4.2).
    """
    observed = build_id_reader(vmlinux_path)
    verify_build_id(expected=expected_build_id, observed=observed)
    return observed
