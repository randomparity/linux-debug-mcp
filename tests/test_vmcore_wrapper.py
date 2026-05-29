from __future__ import annotations

from pathlib import Path

from linux_debug_mcp.providers.local_drgn_introspect import WRAPPER_TEMPLATE

GOLDEN = Path(__file__).parent / "golden" / "live_wrapper_template.txt"


def test_live_wrapper_template_byte_identical_after_split() -> None:
    # ADR 0010: the prologue/body split must not change the live wrapper text.
    assert WRAPPER_TEMPLATE.template == GOLDEN.read_text(encoding="utf-8")
