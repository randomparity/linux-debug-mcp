import subprocess
from pathlib import Path

from linux_debug_mcp.prereqs.checks import check_prerequisites


class FakeRunner:
    def __init__(self, available: set[str]) -> None:
        self.available = available

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}" if command in self.available else None

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        if command == ["virsh", "uri"]:
            return (0, "qemu:///system\n", "")
        return (1, "", "unsupported")


class TimeoutRunner(FakeRunner):
    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        raise subprocess.TimeoutExpired(command, timeout)


def test_prereq_checks_report_missing_tools(tmp_path: Path) -> None:
    checks = check_prerequisites(
        artifact_root=tmp_path,
        source_path=None,
        enable_libvirt_check=False,
        runner=FakeRunner({"make", "bash", "git"}),
    )

    by_id = {check.check_id: check for check in checks}

    assert by_id["python.version"].status == "passed"
    assert by_id["python.package.mcp"].status in {"passed", "failed"}
    assert by_id["tool.make"].status == "passed"
    assert by_id["tool.gdb"].status == "failed"
    assert by_id["compiler.c"].status == "failed"
    assert by_id["libvirt.uri"].status == "skipped"


def test_prereq_checks_accept_clang_when_gcc_is_missing(tmp_path: Path) -> None:
    checks = check_prerequisites(
        artifact_root=tmp_path,
        source_path=None,
        enable_libvirt_check=False,
        runner=FakeRunner({"make", "clang", "bash", "git", "qemu-system-x86_64", "virsh", "gdb"}),
    )

    by_id = {check.check_id: check for check in checks}

    assert by_id["compiler.c"].status == "passed"
    assert by_id["compiler.c"].details["command"] == "clang"


def test_prereq_checks_validate_source_tree(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")

    checks = check_prerequisites(
        artifact_root=tmp_path / "runs",
        source_path=source,
        enable_libvirt_check=True,
        runner=FakeRunner({"make", "gcc", "bash", "git", "qemu-system-x86_64", "virsh", "gdb"}),
    )

    by_id = {check.check_id: check for check in checks}

    assert by_id["artifact_root.writable"].status == "passed"
    assert by_id["source.linux_tree"].status == "passed"
    assert by_id["libvirt.uri"].status == "passed"


def test_prereq_checks_report_libvirt_timeout(tmp_path: Path) -> None:
    checks = check_prerequisites(
        artifact_root=tmp_path,
        source_path=None,
        enable_libvirt_check=True,
        runner=TimeoutRunner({"virsh"}),
    )

    by_id = {check.check_id: check for check in checks}

    assert by_id["libvirt.uri"].status == "failed"
    assert "timed out" in by_id["libvirt.uri"].message
