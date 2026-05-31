from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]
SERVER_SOURCE = ROOT / "src" / "kdive" / "server.py"
INTROSPECT_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "introspect" / "handlers.py"
INTROSPECT_EXECUTION_SOURCE = ROOT / "src" / "kdive" / "introspect" / "execution.py"


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


def test_server_does_not_own_shared_probe_helpers() -> None:
    server_source = SERVER_SOURCE.read_text(encoding="utf-8")

    assert "PROBE_STDOUT_CAP =" not in server_source

    duplicated_helpers = [
        "_resolve_probe_context",
        "_reject_if_target_halted",
        "_prepare_probe_dirs",
        "_parse_probe_stdout",
        "_no_json_response",
        "_assemble_probe_response",
        "_probe_success",
        "_assemble_kdump_response",
    ]

    assert [helper for helper in duplicated_helpers if f"def {helper}(" in server_source] == []


def test_live_introspection_does_not_keep_passthrough_wrappers() -> None:
    handler_source = INTROSPECT_HANDLERS_SOURCE.read_text(encoding="utf-8")
    execution_source = INTROSPECT_EXECUTION_SOURCE.read_text(encoding="utf-8")

    assert "def _execute_live_introspect_call(" not in handler_source
    assert "def _prepare_live_wrapper(" not in execution_source
