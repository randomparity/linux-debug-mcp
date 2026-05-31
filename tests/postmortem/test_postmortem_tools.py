from __future__ import annotations

from pathlib import Path

from kdive.server import create_app


def test_postmortem_handlers_do_not_import_server_privates() -> None:
    source = (Path(__file__).parents[2] / "src" / "kdive" / "postmortem" / "handlers.py").read_text(encoding="utf-8")

    assert "from kdive.server import" not in source


def test_create_app_registers_postmortem_tools_through_package_module() -> None:
    app = create_app()

    assert app._tool_manager._tools["debug.postmortem.crash"].fn.__module__ == "kdive.postmortem.tools"
    assert app._tool_manager._tools["debug.postmortem.triage"].fn.__module__ == "kdive.postmortem.tools"


def test_create_app_still_exposes_postmortem_tools() -> None:
    names = set(create_app()._tool_manager._tools)

    assert {
        "debug.postmortem.crash",
        "debug.postmortem.triage",
        "debug.postmortem.check_prereqs",
        "debug.postmortem.list_dumps",
        "debug.postmortem.fetch",
    } <= names
