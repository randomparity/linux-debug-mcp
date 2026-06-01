from __future__ import annotations

from pathlib import Path

POSTMORTEM_ROOT = Path(__file__).resolve().parents[1] / "src" / "kdive" / "postmortem"


def test_postmortem_workflows_are_split_into_focused_packages() -> None:
    root_modules = {
        "crash_batch.py",
        "crash_commands.py",
        "crash_handler.py",
        "crash_parsers.py",
        "dumps.py",
        "triage.py",
    }

    assert not any((POSTMORTEM_ROOT / module).exists() for module in root_modules)
    assert (POSTMORTEM_ROOT / "crash" / "__init__.py").is_file()
    assert (POSTMORTEM_ROOT / "dumps" / "__init__.py").is_file()
    assert (POSTMORTEM_ROOT / "triage" / "__init__.py").is_file()


def test_crash_package_exports_only_handler_boundary_symbols() -> None:
    import kdive.postmortem.crash as crash

    assert crash.__all__ == (
        "debug_postmortem_crash_handler",
        "resolve_postmortem_vmcore_context",
    )
