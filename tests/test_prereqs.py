import subprocess
from pathlib import Path

from kdive.config import BuildProfile, RootfsProfile, TargetProfile
from kdive.prereqs.checks import (
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


class LibvirtCapabilitiesRunner(FakeRunner):
    def __init__(self, available: set[str], *, code: int, stderr: str = "") -> None:
        super().__init__(available)
        self._code = code
        self._stderr = stderr
        self.last_command: list[str] | None = None

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        self.last_command = command
        return (self._code, "<capabilities/>" if self._code == 0 else "", self._stderr)


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


def _make_linux_tree(root: Path) -> Path:
    root.mkdir(exist_ok=True)
    (root / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (root / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    return root


def test_kernel_config_passes_when_source_config_present(tmp_path: Path) -> None:
    source = _make_linux_tree(tmp_path / "linux")
    (source / ".config").write_text("CONFIG_X=y\n", encoding="utf-8")
    build = BuildProfile(name="b", architecture="x86_64")
    check = check_kernel_config(source, build)
    assert check.status == "passed"
    assert "present" in check.message


def test_kernel_config_fails_when_no_config_and_no_base_config(tmp_path: Path) -> None:
    source = _make_linux_tree(tmp_path / "linux")
    build = BuildProfile(name="b", architecture="x86_64")
    check = check_kernel_config(source, build)
    assert check.status == "failed"
    assert check.suggested_fix is not None
    assert "base_config" in check.suggested_fix


def test_kernel_config_skipped_when_source_is_not_a_linux_tree(tmp_path: Path) -> None:
    not_a_tree = tmp_path / "empty"
    not_a_tree.mkdir()
    build = BuildProfile(name="b", architecture="x86_64")
    check = check_kernel_config(not_a_tree, build)
    assert check.status == "skipped"
    assert "source.linux_tree" in check.message


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


def test_rootfs_builder_passes_when_toolchain_present() -> None:
    from kdive.prereqs.checks import check_rootfs_builder

    check = check_rootfs_builder(runner=FakeRunner({"virt-builder", "qemu-img"}))
    assert check.check_id == "rootfs.builder"
    assert check.status == "passed"


def test_rootfs_builder_fails_naming_libguestfs_tools_when_virt_builder_missing() -> None:
    from kdive.prereqs.checks import check_rootfs_builder

    check = check_rootfs_builder(runner=FakeRunner({"qemu-img"}))
    assert check.status == "failed"
    assert "libguestfs-tools" in (check.suggested_fix or "")


def test_rootfs_builder_fails_when_qemu_img_missing() -> None:
    from kdive.prereqs.checks import check_rootfs_builder

    check = check_rootfs_builder(runner=FakeRunner({"virt-builder"}))
    assert check.status == "failed"


def test_kvm_access_passes_when_device_usable() -> None:
    from kdive.prereqs.checks import check_kvm_access

    check = check_kvm_access(kvm_probe=lambda: True)
    assert check.check_id == "kvm.access"
    assert check.status == "passed"


def test_kvm_access_warns_when_device_unusable() -> None:
    from kdive.prereqs.checks import check_kvm_access

    check = check_kvm_access(kvm_probe=lambda: False)
    assert check.status == "warning"
    assert "kvm" in (check.suggested_fix or "").lower()
    assert "TCG" in (check.message or "")


def test_libvirt_connect_skipped_without_profile() -> None:
    from kdive.prereqs.checks import check_libvirt_connect

    check = check_libvirt_connect(None)
    assert check.check_id == "libvirt.connect"
    assert check.status == "skipped"


def test_libvirt_connect_passes_and_uses_profile_uri() -> None:
    from kdive.prereqs.checks import check_libvirt_connect

    target = TargetProfile(name="t", architecture="x86_64", libvirt_uri="qemu:///session")
    runner = LibvirtCapabilitiesRunner({"virsh"}, code=0)
    check = check_libvirt_connect(target, runner=runner)
    assert check.status == "passed"
    assert runner.last_command == ["virsh", "-c", "qemu:///session", "capabilities"]


def test_libvirt_connect_defaults_uri_when_profile_unset() -> None:
    from kdive.prereqs.checks import check_libvirt_connect

    target = TargetProfile(name="t", architecture="x86_64", libvirt_uri=None)
    runner = LibvirtCapabilitiesRunner({"virsh"}, code=0)
    check_libvirt_connect(target, runner=runner)
    assert runner.last_command == ["virsh", "-c", "qemu:///system", "capabilities"]


def test_libvirt_connect_fails_distinguishes_system_and_session() -> None:
    from kdive.prereqs.checks import check_libvirt_connect

    system_target = TargetProfile(name="t", architecture="x86_64", libvirt_uri="qemu:///system")
    system = check_libvirt_connect(
        system_target, runner=LibvirtCapabilitiesRunner({"virsh"}, code=1, stderr="polkit denied")
    )
    assert system.status == "failed"
    assert "polkit" in (system.suggested_fix or "").lower()

    session_target = TargetProfile(name="t", architecture="x86_64", libvirt_uri="qemu:///session")
    session = check_libvirt_connect(
        session_target, runner=LibvirtCapabilitiesRunner({"virsh"}, code=1, stderr="failed to connect")
    )
    assert session.status == "failed"
    assert "virtqemud" in (session.suggested_fix or "")


def test_libvirt_connect_fails_when_virsh_missing() -> None:
    from kdive.prereqs.checks import check_libvirt_connect

    target = TargetProfile(name="t", architecture="x86_64", libvirt_uri="qemu:///system")
    check = check_libvirt_connect(target, runner=LibvirtCapabilitiesRunner(set(), code=0))
    assert check.status == "failed"
