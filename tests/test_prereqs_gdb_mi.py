from __future__ import annotations

from pathlib import Path

from linux_debug_mcp.prereqs.checks import check_prerequisites

_VERSION_ARGV = ["gdb", "--version"]
_MI_ARGV = ["gdb", "-nx", "-q", "-ex", 'interpreter-exec mi3 "-list-features"', "-ex", "quit"]


class FakeRunner:
    def __init__(self, *, present: bool, version_out: str, mi_out: str, mi_code: int = 0) -> None:
        self._present = present
        self._version_out = version_out
        self._mi_out = mi_out
        self._mi_code = mi_code

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}" if self._present else None

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        if command == _VERSION_ARGV:
            return (0, self._version_out, "")
        if command == _MI_ARGV:
            return (self._mi_code, self._mi_out, "")
        return (0, "", "")


def _check(runner: FakeRunner, tmp_path: Path):
    checks = check_prerequisites(
        artifact_root=tmp_path / "runs", source_path=None, enable_libvirt_check=False, runner=runner
    )
    return {check.check_id: check for check in checks}["tool.gdb_mi"]


def test_gdb_mi_probe_passes_on_modern_gdb(tmp_path: Path) -> None:
    runner = FakeRunner(present=True, version_out="GNU gdb (GDB) 12.1\n", mi_out="^done,features=[]\n(gdb)\n")
    check = _check(runner, tmp_path)
    assert check.status == "passed"
    assert "12.1" in check.message


def test_gdb_mi_probe_fails_on_old_gdb_naming_versions(tmp_path: Path) -> None:
    runner = FakeRunner(present=True, version_out="GNU gdb (GDB) 8.3.1\n", mi_out="^done\n(gdb)\n")
    check = _check(runner, tmp_path)
    assert check.status == "failed"
    assert "8.3" in check.message and "9.1" in check.message  # names detected + required


def test_gdb_mi_probe_fails_when_no_done_record(tmp_path: Path) -> None:
    # gdb accepts the mi3 name but yields no usable ^done record
    runner = FakeRunner(present=True, version_out="GNU gdb (GDB) 12.1\n", mi_out="garbage\n", mi_code=1)
    check = _check(runner, tmp_path)
    assert check.status == "failed"
    assert "mi3" in check.message.lower()


def test_gdb_mi_probe_fails_when_gdb_absent(tmp_path: Path) -> None:
    runner = FakeRunner(present=False, version_out="", mi_out="")
    check = _check(runner, tmp_path)
    assert check.status == "failed"
    assert "9.1" in check.message


def test_gdb_mi_probe_uses_gdb_version_not_distro_packaging_token(tmp_path: Path) -> None:
    # gdb's own version (12.1) is the last token; the parenthetical packaging token (8.0.1) must not
    # be mistaken for it.
    runner = FakeRunner(present=True, version_out="GNU gdb (Ubuntu 8.0.1-1ubuntu1) 12.1\n", mi_out="^done\n(gdb)\n")
    check = _check(runner, tmp_path)
    assert check.status == "passed"
    assert "12.1" in check.message
