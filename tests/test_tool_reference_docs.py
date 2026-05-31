from __future__ import annotations

import re
from pathlib import Path

from kdive.server import create_app


def test_tool_reference_inventory_matches_runtime_tools() -> None:
    docs = Path("docs/tool-reference.md").read_text(encoding="utf-8")
    section = docs.split("## Registered MCP Tool Inventory", maxsplit=1)[1].split("\n## ", maxsplit=1)[0]
    documented = set(re.findall(r"^- `([^`]+)`$", section, flags=re.MULTILINE))
    runtime = set(create_app()._tool_manager._tools)

    assert documented == runtime
