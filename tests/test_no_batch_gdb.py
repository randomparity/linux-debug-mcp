from __future__ import annotations

from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "linux_debug_mcp"


def test_no_batch_gdb_invocation_remains() -> None:
    """ADR 0021 decision 4 / acceptance: one engine, no batch. No source file may
    construct a `-batch` gdb argv or keep the batch runner after Phase C."""
    offenders: list[str] = []
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if '"-batch"' in text or "'-batch'" in text or "run_batch" in text or "SubprocessGdbRunner" in text:
            offenders.append(str(path.relative_to(SRC)))
    assert offenders == [], f"batch gdb paths still present in: {offenders}"
