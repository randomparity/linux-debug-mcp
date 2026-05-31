from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_extracted_handler_modules_do_not_import_server_module() -> None:
    handler_sources = [
        path
        for path in (ROOT / "src" / "kdive").rglob("*.py")
        if path.name in {"handlers.py", "session_handlers.py", "crash_handler.py"}
    ]

    offenders = [
        path.relative_to(ROOT) for path in handler_sources if "kdive.server" in path.read_text(encoding="utf-8")
    ]

    assert offenders == []
