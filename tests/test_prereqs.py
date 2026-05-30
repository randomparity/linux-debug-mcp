import subprocess
from pathlib import Path

from linux_debug_mcp.config import BuildProfile, RootfsProfile, TargetProfile
from linux_debug_mcp.prereqs.checks import (
    PortProbeResult,
    check_gdbstub_port,
    check_kernel_config,
    check_prerequisites,
    check_rootfs_image,
)


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


def test_kernel_config_skipped_without_build_profile() -> None:
    check = check_kernel_config(None, None)
    assert check.check_id == "kernel.config"
    assert check.status == "skipped"


def test_kernel_config_passes_when_base_config_derivable() -> None:
    build = BuildProfile(name="b", architecture="x86_64", base_config=["defconfig"])
    check = check_kernel_config(None, build)
    assert check.status == "passed"
    assert "defconfig" in check.message


def test_kernel_config_skipped_when_empty_base_config_and_no_source() -> None:
    build = BuildProfile(name="b", architecture="x86_64")
    check = check_kernel_config(None, build)
    assert check.status == "skipped"


def test_kernel_config_passes_when_source_config_present(tmp_path: Path) -> None:
    (tmp_path / ".config").write_text("CONFIG_X=y\n", encoding="utf-8")
    build = BuildProfile(name="b", architecture="x86_64")
    check = check_kernel_config(tmp_path, build)
    assert check.status == "passed"
    assert "present" in check.message


def test_kernel_config_fails_when_no_config_and_no_base_config(tmp_path: Path) -> None:
    build = BuildProfile(name="b", architecture="x86_64")
    check = check_kernel_config(tmp_path, build)
    assert check.status == "failed"
    assert check.suggested_fix is not None
    assert "base_config" in check.suggested_fix


def test_rootfs_image_skipped_without_profile() -> None:
    check = check_rootfs_image(None)
    assert check.check_id == "rootfs.image"
    assert check.status == "skipped"


def test_rootfs_image_passes_when_local_path_exists(tmp_path: Path) -> None:
    image = tmp_path / "disk.qcow2"
    image.write_bytes(b"qcow")
    profile = RootfsProfile(name="r", source=str(image), source_kind="local_path")
    check = check_rootfs_image(profile)
    assert check.status == "passed"
    assert check.details["path"] == str(image)


def test_rootfs_image_fails_when_local_path_missing(tmp_path: Path) -> None:
    profile = RootfsProfile(name="r", source=str(tmp_path / "absent.qcow2"), source_kind="local_path")
    check = check_rootfs_image(profile)
    assert check.status == "failed"
    assert "not found" in check.message


def test_rootfs_image_fails_with_builder_fix_when_builder_image_missing(tmp_path: Path) -> None:
    profile = RootfsProfile(name="r", source=str(tmp_path / "minimal.qcow2"), source_kind="builder")
    check = check_rootfs_image(profile)
    assert check.status == "failed"
    assert "just rootfs" in (check.suggested_fix or "")


def test_rootfs_image_fails_for_not_implemented_kind() -> None:
    profile = RootfsProfile(name="r", source="catalog-name", source_kind="prebuilt")
    check = check_rootfs_image(profile)
    assert check.status == "failed"
    assert "local_path" in (check.suggested_fix or "")


def test_gdbstub_port_skipped_without_profile() -> None:
    check = check_gdbstub_port(None)
    assert check.check_id == "gdbstub.port"
    assert check.status == "skipped"


def test_gdbstub_port_skipped_when_not_debug_gdbstub() -> None:
    target = TargetProfile(name="t", architecture="x86_64")
    check = check_gdbstub_port(target)
    assert check.status == "skipped"


def test_gdbstub_port_passes_when_free() -> None:
    target = TargetProfile(name="t", architecture="x86_64", debug_gdbstub=True)
    check = check_gdbstub_port(target, port_probe=lambda h, p: PortProbeResult("free"))
    assert check.status == "passed"
    assert check.details == {"host": "127.0.0.1", "port": 1234}


def test_gdbstub_port_fails_when_in_use() -> None:
    target = TargetProfile(name="t", architecture="x86_64", debug_gdbstub=True)
    check = check_gdbstub_port(target, port_probe=lambda h, p: PortProbeResult("in_use"))
    assert check.status == "failed"
    assert "in use" in check.message
    assert "127.0.0.1:1234" in check.message


def test_gdbstub_port_fails_with_bind_error_detail() -> None:
    target = TargetProfile(name="t", architecture="x86_64", debug_gdbstub=True)
    check = check_gdbstub_port(target, port_probe=lambda h, p: PortProbeResult("error", "Permission denied"))
    assert check.status == "failed"
    assert "could not bind" in check.message
    assert "Permission denied" in check.message


def test_gdbstub_port_fails_on_unparseable_endpoint() -> None:
    target = TargetProfile(name="t", architecture="x86_64", debug_gdbstub=True, gdbstub_endpoint="garbage")
    probed: list[tuple[str, int]] = []

    def probe(host: str, port: int) -> PortProbeResult:
        probed.append((host, port))
        return PortProbeResult("free")

    check = check_gdbstub_port(target, port_probe=probe)
    assert check.status == "failed"
    assert "could not parse" in check.message
    assert probed == []
