from __future__ import annotations

from pathlib import Path

from linux_debug_mcp.domain import PrerequisiteStatus
from linux_debug_mcp.prereqs.checks import check_prerequisites


class _FakeRunner:
    def __init__(self, present: bool) -> None:
        self._present = present

    def which(self, command: str) -> str | None:
        if command == "crash":
            return "/usr/bin/crash" if self._present else None
        return "/usr/bin/" + command  # everything else present

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        return (0, "", "")


def _crash_check(present: bool):
    checks = check_prerequisites(
        artifact_root=Path("/tmp"),
        source_path=None,
        enable_libvirt_check=False,
        runner=_FakeRunner(present),
    )
    return next(c for c in checks if c.check_id == "tool.crash")


def test_crash_present_passes() -> None:
    assert _crash_check(True).status == PrerequisiteStatus.PASSED


def test_crash_absent_fails() -> None:
    check = _crash_check(False)
    assert check.status == PrerequisiteStatus.FAILED
    assert check.suggested_fix is not None
