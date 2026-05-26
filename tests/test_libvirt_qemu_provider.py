import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree

import pytest

from linux_debug_mcp.config import RootfsProfile, TargetProfile
from linux_debug_mcp.domain import ErrorCategory, StepStatus
from linux_debug_mcp.providers.libvirt_qemu import (
    CommandResult,
    ConsoleResult,
    LibvirtQemuProvider,
    ProviderBootError,
    SubprocessLibvirtRunner,
)

MCP_METADATA_NS = "urn:linux-debug-mcp:domain"


def make_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    kernel = tmp_path / "build" / "arch" / "x86" / "boot" / "bzImage"
    rootfs = tmp_path / "images" / "rootfs.qcow2"
    run_dir = tmp_path / "runs" / "run-abc123"
    kernel.parent.mkdir(parents=True, exist_ok=True)
    rootfs.parent.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    kernel.write_bytes(b"kernel")
    rootfs.write_bytes(b"rootfs")
    return kernel, rootfs, run_dir


def rootfs_profile(
    rootfs: Path,
    *,
    mutability: str = "read_only",
    source_type: str = "disk_image",
    readiness_marker: str | None = "linux-debug-mcp-ready",
) -> RootfsProfile:
    return RootfsProfile(
        name="minimal",
        source=str(rootfs),
        source_type=source_type,
        mutability=mutability,
        readiness_marker=readiness_marker,
    )


def target_profile(**overrides: object) -> TargetProfile:
    values = {
        "name": "local-qemu",
        "architecture": "x86_64",
        "target_ref": "debug-vm",
        "libvirt_uri": "qemu:///system",
        "managed_domain": True,
        "kernel_args": ["panic=1"],
        "timeout_seconds": 180,
        "cleanup_policy": "preserve_on_failure",
    }
    values.update(overrides)
    return TargetProfile(**values)


def assert_configuration_error(exc_info: pytest.ExceptionInfo[ProviderBootError]) -> None:
    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


def make_plan(
    tmp_path: Path,
    *,
    mutability: str = "read_only",
    run_id: str = "run-abc123",
    cleanup_policy: str = "preserve_on_failure",
):
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider()
    return provider.plan_boot(
        run_id=run_id,
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(cleanup_policy=cleanup_policy),
        rootfs_profile=rootfs_profile(rootfs, mutability=mutability),
    )


@pytest.mark.parametrize("mutability", ["read_only", "mutable"])
def test_plan_boot_accepts_existing_disk_image_for_supported_mutability(tmp_path: Path, mutability: str) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider()

    plan = provider.plan_boot(
        run_id="run-abc123",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(),
        rootfs_profile=rootfs_profile(rootfs, mutability=mutability),
    )

    assert plan.rootfs_path == rootfs.resolve(strict=True)
    assert plan.rootfs_mutability == mutability


def test_plan_boot_generates_complete_boot_plan(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider()

    plan = provider.plan_boot(
        run_id="run-abc123",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(kernel_args=["panic=1", "quiet"]),
        rootfs_profile=rootfs_profile(rootfs),
    )

    assert plan.run_id == "run-abc123"
    assert plan.provider_name == "local-libvirt-qemu"
    assert plan.target_profile_name == "local-qemu"
    assert plan.rootfs_profile_name == "minimal"
    assert plan.domain_name == "debug-vm"
    assert plan.libvirt_uri == "qemu:///system"
    assert plan.kernel_image_path == kernel.resolve(strict=True)
    assert plan.rootfs_path == rootfs.resolve(strict=True)
    assert plan.root_device == "/dev/vda"
    assert plan.serial_device == "ttyS0"
    assert plan.kernel_args == ["panic=1", "quiet", "root=/dev/vda", "console=ttyS0"]
    assert plan.timeout_seconds == 180
    assert plan.readiness_marker == "linux-debug-mcp-ready"
    assert plan.domain_xml_path == run_dir / "boot" / "attempt-1" / "domain.xml"
    assert plan.console_log_path == run_dir / "boot" / "attempt-1" / "console.log"
    assert plan.boot_log_path == run_dir / "boot" / "attempt-1" / "boot.log"
    assert plan.boot_plan_path == run_dir / "boot" / "attempt-1" / "boot-plan.json"
    assert plan.boot_summary_path == run_dir / "boot" / "attempt-1" / "boot-summary.json"
    assert plan.ownership == {
        "provider": "local-libvirt-qemu",
        "run_id": "run-abc123",
        "target_profile": "local-qemu",
        "rootfs_profile": "minimal",
    }
    assert plan.define_argv == ["virsh", "-c", "qemu:///system", "define", str(plan.domain_xml_path)]
    assert plan.start_argv == ["virsh", "-c", "qemu:///system", "start", "debug-vm"]
    assert plan.destroy_argv == ["virsh", "-c", "qemu:///system", "destroy", "debug-vm"]
    assert plan.dumpxml_argv == ["virsh", "-c", "qemu:///system", "dumpxml", "debug-vm"]


class PortCheckingRunner:
    def __init__(self, *, port_available: bool = True) -> None:
        self.port_available = port_available

    def which(self, command: str) -> str | None:
        return "/usr/bin/virsh" if command == "virsh" else None

    def run(self, argv: list[str], *, timeout: int, log_path: Path | None = None) -> CommandResult:
        return CommandResult(argv=argv, exit_status=0, stdout="")

    def stream_console(
        self,
        domain: str,
        *,
        libvirt_uri: str,
        output_path: Path,
        timeout: int,
        readiness_marker: str,
    ) -> ConsoleResult:
        return ConsoleResult(
            status="ready",
            matched_marker=readiness_marker,
            snippet=readiness_marker,
            started_at=datetime.now(UTC),
            ended_at=datetime.now(UTC),
        )

    def is_tcp_port_available(self, host: str, port: int) -> bool:
        return self.port_available


def test_debug_boot_adds_gdbstub_endpoint_and_nokaslr(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner())

    plan = provider.plan_boot(
        run_id="run-debug",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(debug_gdbstub=True, gdbstub_endpoint="127.0.0.1:1234"),
        rootfs_profile=rootfs_profile(rootfs),
    )
    xml_text = provider.render_domain_xml(plan)
    root = ElementTree.fromstring(xml_text)

    assert plan.debug_gdbstub is True
    assert plan.gdbstub_endpoint is not None
    assert plan.gdbstub_endpoint.as_dict() == {"host": "127.0.0.1", "port": 1234}
    assert plan.nokaslr_source == "provider_added"
    assert "nokaslr" in plan.kernel_args
    qemu_args = root.findall(".//{http://libvirt.org/schemas/domain/qemu/1.0}arg")
    values = [item.attrib["value"] for item in qemu_args]
    assert "-gdb" in values
    assert "tcp:127.0.0.1:1234,server=on,wait=off" in values


@pytest.mark.parametrize(
    "endpoint",
    [
        "0.0.0.0:1234",
        "192.168.122.1:1234",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:1234/path",
        "127.0.0.1:1234?x=1",
        "127.0.0.1:12 34",
        "::1:1234",
        "<bad>:1234",
    ],
)
def test_debug_boot_rejects_unsafe_gdbstub_endpoints(tmp_path: Path, endpoint: str) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner())

    with pytest.raises(ProviderBootError) as exc_info:
        provider.plan_boot(
            run_id="run-debug",
            run_dir=run_dir,
            kernel_image_path=kernel,
            target_profile=target_profile(debug_gdbstub=True, gdbstub_endpoint=endpoint),
            rootfs_profile=rootfs_profile(rootfs),
        )

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_debug_boot_rejects_occupied_gdbstub_port(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner(port_available=False))

    with pytest.raises(ProviderBootError, match="gdbstub endpoint is already in use") as exc_info:
        provider.plan_boot(
            run_id="run-debug",
            run_dir=run_dir,
            kernel_image_path=kernel,
            target_profile=target_profile(debug_gdbstub=True, gdbstub_endpoint="127.0.0.1:1234"),
            rootfs_profile=rootfs_profile(rootfs),
        )

    assert exc_info.value.category == ErrorCategory.INFRASTRUCTURE_FAILURE


@pytest.mark.parametrize(
    ("target_overrides", "rootfs_overrides", "message"),
    [
        ({}, {"source_type": "directory"}, "directory rootfs sources are not supported"),
        ({}, {"mutability": "copy_on_write"}, "copy_on_write rootfs mutability is not supported"),
        ({"provider_name": "remote-libvirt-qemu"}, {}, "unsupported target provider"),
        ({"target_ref": None}, {}, "target_ref is required"),
        ({"managed_domain": False}, {}, "managed_domain=True is required"),
        ({"target_ref": "prod-vm", "managed_domain_prefix": "debug-"}, {}, "target_ref must start with"),
        ({"libvirt_uri": None}, {}, "libvirt_uri is required"),
        ({"architecture": "arm64"}, {}, "unsupported architecture"),
        ({"kernel_args": ["root=/dev/sda"]}, {}, "conflicting root="),
        ({"kernel_args": ["console=ttyS1"]}, {}, "conflicting console="),
        ({}, {"readiness_marker": None}, "readiness_marker is required"),
    ],
)
def test_plan_boot_rejects_unsupported_configuration(
    tmp_path: Path,
    target_overrides: dict[str, object],
    rootfs_overrides: dict[str, object],
    message: str,
) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider()

    with pytest.raises(ProviderBootError, match=message) as exc_info:
        provider.plan_boot(
            run_id="run-abc123",
            run_dir=run_dir,
            kernel_image_path=kernel,
            target_profile=target_profile(**target_overrides),
            rootfs_profile=rootfs_profile(rootfs, **rootfs_overrides),
        )

    assert_configuration_error(exc_info)


@pytest.mark.parametrize(
    ("missing_path", "message"),
    [
        ("kernel", "kernel image path does not exist"),
        ("rootfs", "rootfs source path does not exist"),
        ("run_dir", "run directory does not exist"),
    ],
)
def test_plan_boot_normalizes_missing_paths_to_configuration_error(
    tmp_path: Path,
    missing_path: str,
    message: str,
) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider()
    if missing_path == "kernel":
        kernel = tmp_path / "missing" / "bzImage"
    elif missing_path == "rootfs":
        rootfs = tmp_path / "missing" / "rootfs.qcow2"
    else:
        run_dir = tmp_path / "missing" / "run-abc123"

    with pytest.raises(ProviderBootError, match=message) as exc_info:
        provider.plan_boot(
            run_id="run-abc123",
            run_dir=run_dir,
            kernel_image_path=kernel,
            target_profile=target_profile(),
            rootfs_profile=rootfs_profile(rootfs),
        )

    assert_configuration_error(exc_info)


def test_plan_boot_attempt_parameter_relocates_all_artifact_paths(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider()

    plan = provider.plan_boot(
        run_id="run-abc123",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(),
        rootfs_profile=rootfs_profile(rootfs),
        attempt=2,
    )

    assert plan.domain_xml_path == run_dir / "boot" / "attempt-2" / "domain.xml"
    assert plan.console_log_path == run_dir / "boot" / "attempt-2" / "console.log"
    assert plan.boot_log_path == run_dir / "boot" / "attempt-2" / "boot.log"
    assert plan.boot_plan_path == run_dir / "boot" / "attempt-2" / "boot-plan.json"
    assert plan.boot_summary_path == run_dir / "boot" / "attempt-2" / "boot-summary.json"


def test_render_domain_xml_includes_direct_kernel_boot_devices_and_metadata(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    provider = LibvirtQemuProvider()

    xml_text = provider.render_domain_xml(plan)
    root = ElementTree.fromstring(xml_text)

    assert root.tag == "domain"
    assert root.attrib["type"] == "kvm"
    assert root.findtext("name") == "debug-vm"
    assert root.find("memory").attrib == {"unit": "MiB"}
    assert root.findtext("memory") == "1024"
    assert root.findtext("vcpu") == "1"
    assert root.findtext("os/kernel") == str(plan.kernel_image_path)
    assert root.findtext("os/cmdline") == " ".join(plan.kernel_args)
    disk = root.find("./devices/disk[@device='disk']")
    assert disk is not None
    assert disk.find("source").attrib["file"] == str(plan.rootfs_path)
    assert disk.find("target").attrib == {"dev": "vda", "bus": "virtio"}
    assert root.find("./devices/serial[@type='pty']") is not None
    assert root.find("./devices/console[@type='pty']") is not None
    metadata = root.find(f"metadata/{{{MCP_METADATA_NS}}}linux-debug-mcp")
    assert metadata is not None
    assert metadata.findtext(f"{{{MCP_METADATA_NS}}}provider") == "local-libvirt-qemu"
    assert metadata.findtext(f"{{{MCP_METADATA_NS}}}domain") == "debug-vm"
    assert metadata.findtext(f"{{{MCP_METADATA_NS}}}target_profile") == "local-qemu"
    assert metadata.findtext(f"{{{MCP_METADATA_NS}}}run_id") == "run-abc123"


@pytest.mark.parametrize(
    ("mutability", "expect_readonly"),
    [
        ("read_only", True),
        ("mutable", False),
    ],
)
def test_render_domain_xml_sets_readonly_disk_marker_by_rootfs_mutability(
    tmp_path: Path,
    mutability: str,
    expect_readonly: bool,
) -> None:
    plan = make_plan(tmp_path, mutability=mutability)
    provider = LibvirtQemuProvider()

    disk = ElementTree.fromstring(provider.render_domain_xml(plan)).find("./devices/disk[@device='disk']")

    assert disk is not None
    assert (disk.find("readonly") is not None) is expect_readonly


class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}"

    def run(self, argv: list[str], *, timeout: int, log_path: Path | None = None):
        self.commands.append(argv)
        raise AssertionError("ownership validation must not run virsh commands")

    def stream_console(
        self,
        domain: str,
        *,
        libvirt_uri: str,
        output_path: Path,
        timeout: int,
        readiness_marker: str,
    ):
        raise AssertionError("ownership validation must not stream console")


def test_validate_existing_domain_ownership_rejects_unowned_domain_before_mutation(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    runner = RecordingRunner()
    provider = LibvirtQemuProvider(runner=runner)
    existing_xml = """
    <domain type="kvm">
      <name>debug-vm</name>
      <metadata>
        <ldmcp:linux-debug-mcp xmlns:ldmcp="urn:linux-debug-mcp:domain">
          <ldmcp:provider>other-provider</ldmcp:provider>
          <ldmcp:domain>debug-vm</ldmcp:domain>
          <ldmcp:target_profile>local-qemu</ldmcp:target_profile>
        </ldmcp:linux-debug-mcp>
      </metadata>
    </domain>
    """

    with pytest.raises(ProviderBootError, match="existing domain is not owned") as exc_info:
        provider.validate_existing_domain_ownership(plan, existing_xml)

    assert_configuration_error(exc_info)
    assert runner.commands == []


def test_validate_existing_domain_ownership_allows_matching_owner_across_run_ids(tmp_path: Path) -> None:
    original_plan = make_plan(tmp_path, run_id="run-abc123")
    reuse_plan = make_plan(tmp_path, run_id="run-def456")
    provider = LibvirtQemuProvider()
    existing_xml = provider.render_domain_xml(original_plan)

    provider.validate_existing_domain_ownership(reuse_plan, existing_xml)


def test_execute_boot_maps_missing_virsh_to_missing_dependency(tmp_path: Path) -> None:
    class MissingVirshRunner:
        def which(self, command: str) -> str | None:
            assert command == "virsh"
            return None

        def run(self, argv: list[str], *, timeout: int, log_path: Path | None = None) -> CommandResult:
            raise AssertionError("missing virsh must stop before commands run")

        def stream_console(
            self,
            domain: str,
            *,
            libvirt_uri: str,
            output_path: Path,
            timeout: int,
            readiness_marker: str,
        ) -> ConsoleResult:
            raise AssertionError("missing virsh must stop before console streaming")

    plan = make_plan(tmp_path)
    result = LibvirtQemuProvider(runner=MissingVirshRunner()).execute_boot(plan)

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.MISSING_DEPENDENCY
    assert result.summary == "missing required libvirt tools"


def test_default_runner_run_uses_subprocess_without_shell_and_appends_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append({"argv": argv, **kwargs})
        return subprocess.CompletedProcess(argv, 7, stdout="out\n", stderr="err\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    log_path = tmp_path / "virsh.log"
    log_path.write_text("existing\n", encoding="utf-8")

    result = SubprocessLibvirtRunner().run(["virsh", "list"], timeout=12, log_path=log_path)

    assert result == CommandResult(argv=["virsh", "list"], exit_status=7, stdout="out\n", stderr="err\n")
    assert calls == [
        {
            "argv": ["virsh", "list"],
            "check": False,
            "capture_output": True,
            "text": True,
            "timeout": 12,
        }
    ]
    assert log_path.read_text(encoding="utf-8") == "existing\n$ virsh list\nout\nerr\n"


def test_default_runner_run_maps_timeout_to_command_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(argv, timeout=3, output="partial\n", stderr="late\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    log_path = tmp_path / "virsh.log"

    result = SubprocessLibvirtRunner().run(["virsh", "start", "vm"], timeout=3, log_path=log_path)

    assert result.timed_out is True
    assert result.exit_status == -1
    assert result.stdout == "partial\n"
    assert result.stderr == "late\n"
    assert "timed out after 3s" in log_path.read_text(encoding="utf-8")


def test_default_runner_stream_console_detects_marker_and_writes_bounded_snippet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    popen_calls: list[dict[str, object]] = []

    class FakeStdout:
        def __init__(self) -> None:
            self.lines = iter(["booting\n", "x" * 5000 + "\n", "linux-debug-mcp-ready\n"])

        def readline(self) -> str:
            return next(self.lines, "")

    class FakePopen:
        def __init__(self, argv: list[str], **kwargs: object) -> None:
            popen_calls.append({"argv": argv, **kwargs})
            self.stdout = FakeStdout()
            self.terminated = False

        def poll(self) -> int | None:
            return None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: int | None = None) -> int:
            return 0

        def kill(self) -> None:
            raise AssertionError("ready console should terminate cleanly")

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    console_log = tmp_path / "console.log"

    result = SubprocessLibvirtRunner(snippet_limit=128).stream_console(
        "debug-vm",
        libvirt_uri="qemu:///system",
        output_path=console_log,
        timeout=5,
        readiness_marker="linux-debug-mcp-ready",
    )

    assert popen_calls[0]["argv"] == ["virsh", "-c", "qemu:///system", "console", "--force", "debug-vm"]
    assert popen_calls[0]["shell"] is False
    assert result.status == "ready"
    assert result.matched_marker == "linux-debug-mcp-ready"
    assert len(result.snippet) <= 128
    assert "linux-debug-mcp-ready" in console_log.read_text(encoding="utf-8")


def test_default_runner_stream_console_times_out_and_terminates_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instances: list[object] = []

    class FakeStdout:
        def readline(self) -> str:
            return ""

    class FakePopen:
        def __init__(self, argv: list[str], **kwargs: object) -> None:
            self.stdout = FakeStdout()
            self.terminated = False
            instances.append(self)

        def poll(self) -> int | None:
            return None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: int | None = None) -> int:
            return 0

        def kill(self) -> None:
            raise AssertionError("terminate should be enough in this fake")

    monkeypatch.setattr(subprocess, "Popen", FakePopen)

    result = SubprocessLibvirtRunner().stream_console(
        "debug-vm",
        libvirt_uri="qemu:///system",
        output_path=tmp_path / "console.log",
        timeout=0,
        readiness_marker="ready",
    )

    assert result.status == "timeout"
    assert instances[0].terminated is True


def test_default_runner_stream_console_reports_early_exit_and_terminates_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instances: list[object] = []

    class FakeStdout:
        def __init__(self) -> None:
            self.lines = iter(["booting\n", ""])

        def readline(self) -> str:
            return next(self.lines, "")

    class FakePopen:
        def __init__(self, argv: list[str], **kwargs: object) -> None:
            self.stdout = FakeStdout()
            self.terminated = False
            self.polls = 0
            instances.append(self)

        def poll(self) -> int | None:
            self.polls += 1
            return 0 if self.polls > 1 else None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: int | None = None) -> int:
            return 0

        def kill(self) -> None:
            raise AssertionError("early exit should terminate cleanly")

    monkeypatch.setattr(subprocess, "Popen", FakePopen)

    result = SubprocessLibvirtRunner().stream_console(
        "debug-vm",
        libvirt_uri="qemu:///system",
        output_path=tmp_path / "console.log",
        timeout=5,
        readiness_marker="ready",
    )

    assert result.status == "exited"
    assert instances[0].terminated is True


def test_default_runner_stream_console_reads_partial_output_without_newline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeStdout:
        def __init__(self) -> None:
            self.payload = b"partial linux-debug-mcp-ready"

        def fileno(self) -> int:
            return 123

        def readline(self) -> str:
            raise AssertionError("partial console output must not use blocking readline after readiness")

    class FakeSelector:
        def register(self, file_number: int, event: int) -> None:
            assert file_number == 123

        def select(self, timeout: float) -> list[tuple[object, int]]:
            return [(object(), 1)]

        def close(self) -> None:
            pass

    class FakePopen:
        def __init__(self, argv: list[str], **kwargs: object) -> None:
            self.stdout = FakeStdout()
            self.terminated = False

        def poll(self) -> int | None:
            return None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: int | None = None) -> int:
            return 0

        def kill(self) -> None:
            raise AssertionError("marker detection should terminate cleanly")

    def fake_os_read(file_number: int, size: int) -> bytes:
        assert file_number == 123
        assert size > 0
        return b"partial linux-debug-mcp-ready"

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    monkeypatch.setattr("linux_debug_mcp.providers.libvirt_qemu.selectors.DefaultSelector", FakeSelector)
    monkeypatch.setattr("linux_debug_mcp.providers.libvirt_qemu.os.read", fake_os_read)

    result = SubprocessLibvirtRunner().stream_console(
        "debug-vm",
        libvirt_uri="qemu:///system",
        output_path=tmp_path / "console.log",
        timeout=5,
        readiness_marker="linux-debug-mcp-ready",
    )

    assert result.status == "ready"
    assert result.matched_marker == "linux-debug-mcp-ready"
    assert (tmp_path / "console.log").read_text(encoding="utf-8") == "partial linux-debug-mcp-ready"


class FakeLibvirtRunner:
    def __init__(
        self,
        *,
        tools: dict[str, str] | None = None,
        dumpxml: CommandResult | None = None,
        define: CommandResult | None = None,
        start: CommandResult | None = None,
        destroy: CommandResult | None = None,
        console: ConsoleResult | None = None,
    ) -> None:
        self.tools = {"virsh": "/usr/bin/virsh"} if tools is None else tools
        self.dumpxml = dumpxml or CommandResult(["virsh", "dumpxml"], 1, stderr="Domain not found: debug-vm\n")
        self.define = define or CommandResult(["virsh", "define"], 0, stdout="defined\n")
        self.start = start or CommandResult(["virsh", "start"], 0, stdout="started\n")
        self.destroy = destroy or CommandResult(["virsh", "destroy"], 0, stdout="destroyed\n")
        self.console = console or ConsoleResult(
            status="ready",
            matched_marker="linux-debug-mcp-ready",
            snippet="linux-debug-mcp-ready\n",
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            ended_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        self.commands: list[list[str]] = []
        self.console_calls: list[dict[str, object]] = []

    def which(self, command: str) -> str | None:
        return self.tools.get(command)

    def run(self, argv: list[str], *, timeout: int, log_path: Path | None = None) -> CommandResult:
        self.commands.append(argv)
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(f"$ {' '.join(argv)}\n")
        action = argv[3]
        if action == "dumpxml":
            return CommandResult(
                argv,
                self.dumpxml.exit_status,
                self.dumpxml.stdout,
                self.dumpxml.stderr,
                self.dumpxml.timed_out,
            )
        if action == "define":
            return CommandResult(
                argv,
                self.define.exit_status,
                self.define.stdout,
                self.define.stderr,
                self.define.timed_out,
            )
        if action == "start":
            return CommandResult(
                argv,
                self.start.exit_status,
                self.start.stdout,
                self.start.stderr,
                self.start.timed_out,
            )
        if action == "destroy":
            return CommandResult(
                argv,
                self.destroy.exit_status,
                self.destroy.stdout,
                self.destroy.stderr,
                self.destroy.timed_out,
            )
        raise AssertionError(f"unexpected command: {argv}")

    def stream_console(
        self,
        domain: str,
        *,
        libvirt_uri: str,
        output_path: Path,
        timeout: int,
        readiness_marker: str,
    ) -> ConsoleResult:
        self.console_calls.append(
            {
                "domain": domain,
                "libvirt_uri": libvirt_uri,
                "output_path": output_path,
                "timeout": timeout,
                "readiness_marker": readiness_marker,
            }
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.console.snippet, encoding="utf-8")
        return self.console


def test_execute_boot_first_boot_domain_absent_defines_starts_and_writes_artifacts(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    runner = FakeLibvirtRunner()
    provider = LibvirtQemuProvider(runner=runner)

    result = provider.execute_boot(plan)

    assert result.status == StepStatus.SUCCEEDED
    assert runner.commands == [plan.dumpxml_argv, plan.define_argv, plan.start_argv]
    assert runner.console_calls[0]["domain"] == "debug-vm"
    assert plan.domain_xml_path.is_file()
    assert plan.boot_plan_path.is_file()
    assert plan.console_log_path.read_text(encoding="utf-8") == "linux-debug-mcp-ready\n"
    assert plan.boot_log_path.is_file()
    assert plan.boot_summary_path.is_file()
    assert {artifact.kind for artifact in result.artifacts} == {
        "domain-xml",
        "boot-plan",
        "console-log",
        "boot-log",
        "boot-summary",
    }


def test_execute_boot_dumpxml_non_absent_failure_maps_to_infrastructure_failure(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    runner = FakeLibvirtRunner(dumpxml=CommandResult(plan.dumpxml_argv, 2, stderr="libvirt unavailable\n"))

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert runner.commands == [plan.dumpxml_argv]


@pytest.mark.parametrize(
    "dumpxml",
    [
        CommandResult(["virsh", "dumpxml"], 1, stderr="Domain not found: debug-vm\n", timed_out=True),
        CommandResult(["virsh", "dumpxml"], 1, stderr="error: failed to get domain 'debug-vm'\n"),
    ],
)
def test_execute_boot_dumpxml_only_specific_domain_not_found_is_absent(
    tmp_path: Path,
    dumpxml: CommandResult,
) -> None:
    plan = make_plan(tmp_path)
    runner = FakeLibvirtRunner(dumpxml=dumpxml)

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert runner.commands == [plan.dumpxml_argv]


def test_execute_boot_retry_stops_matching_domain_before_define_start(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    existing_xml = LibvirtQemuProvider().render_domain_xml(plan)
    runner = FakeLibvirtRunner(dumpxml=CommandResult(plan.dumpxml_argv, 0, stdout=existing_xml))

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan, retrying_after_failure=True)

    assert result.status == StepStatus.SUCCEEDED
    assert runner.commands == [plan.dumpxml_argv, plan.destroy_argv, plan.define_argv, plan.start_argv]


def test_execute_boot_stops_existing_matching_domain_before_fresh_run_start(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    existing_xml = LibvirtQemuProvider().render_domain_xml(plan)
    runner = FakeLibvirtRunner(dumpxml=CommandResult(plan.dumpxml_argv, 0, stdout=existing_xml))

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)

    assert result.status == StepStatus.SUCCEEDED
    assert runner.commands == [plan.dumpxml_argv, plan.destroy_argv, plan.define_argv, plan.start_argv]


def test_execute_boot_continues_when_existing_matching_domain_is_already_inactive(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    existing_xml = LibvirtQemuProvider().render_domain_xml(plan)
    runner = FakeLibvirtRunner(
        dumpxml=CommandResult(plan.dumpxml_argv, 0, stdout=existing_xml),
        destroy=CommandResult(plan.destroy_argv, 1, stderr="domain is not running\n"),
    )

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)

    assert result.status == StepStatus.SUCCEEDED
    assert runner.commands == [plan.dumpxml_argv, plan.destroy_argv, plan.define_argv, plan.start_argv]


def test_execute_boot_console_timeout_maps_to_boot_timeout_and_preserves_artifacts(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    console = ConsoleResult(
        status="timeout",
        matched_marker=None,
        snippet="booting\n",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        ended_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    runner = FakeLibvirtRunner(console=console)

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.BOOT_TIMEOUT
    assert plan.console_log_path.is_file()
    assert any(artifact.path == str(plan.console_log_path) for artifact in result.artifacts)


def test_execute_boot_console_early_exit_maps_to_readiness_failure(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    console = ConsoleResult(
        status="exited",
        matched_marker=None,
        snippet="boot stopped\n",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        ended_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    runner = FakeLibvirtRunner(console=console)

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.READINESS_FAILURE


def test_execute_boot_command_failure_maps_to_infrastructure_failure(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    runner = FakeLibvirtRunner(define=CommandResult(plan.define_argv, 1, stderr="define failed\n"))

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert runner.commands == [plan.dumpxml_argv, plan.define_argv]


def test_execute_boot_debug_start_failure_preserves_debug_details(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    plan = LibvirtQemuProvider(runner=PortCheckingRunner()).plan_boot(
        run_id="run-debug",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(debug_gdbstub=True, gdbstub_endpoint="127.0.0.1:1234"),
        rootfs_profile=rootfs_profile(rootfs),
    )
    runner = FakeLibvirtRunner(start=CommandResult(plan.start_argv, 1, stderr="start failed\n"))

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert result.details["debug_boot"] is True
    assert result.details["gdbstub_endpoint"] == {"host": "127.0.0.1", "port": 1234}
    assert result.details["nokaslr_source"] == "provider_added"


@pytest.mark.parametrize(
    "start_result",
    [
        CommandResult(["virsh", "start"], 1, stderr="start failed\n"),
        CommandResult(["virsh", "start"], -1, stderr="partial start\n", timed_out=True),
    ],
)
def test_execute_boot_stop_on_failure_destroys_after_start_failure(
    tmp_path: Path,
    start_result: CommandResult,
) -> None:
    plan = make_plan(tmp_path, cleanup_policy="stop_on_failure")
    runner = FakeLibvirtRunner(start=start_result)

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert runner.commands == [plan.dumpxml_argv, plan.define_argv, plan.start_argv, plan.destroy_argv]
    assert result.details["cleanup"]["argv"] == plan.destroy_argv
    assert result.details["cleanup"]["exit_status"] == 0


def test_execute_boot_stop_on_failure_destroys_after_console_evidence(tmp_path: Path) -> None:
    plan = make_plan(tmp_path, cleanup_policy="stop_on_failure")
    console = ConsoleResult(
        status="timeout",
        matched_marker=None,
        snippet="still booting\n",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        ended_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    runner = FakeLibvirtRunner(console=console)

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)

    assert result.error_category == ErrorCategory.BOOT_TIMEOUT
    assert plan.console_log_path.read_text(encoding="utf-8") == "still booting\n"
    assert runner.commands == [plan.dumpxml_argv, plan.define_argv, plan.start_argv, plan.destroy_argv]


def test_execute_boot_preserve_on_failure_leaves_domain_running(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    console = ConsoleResult(
        status="timeout",
        matched_marker=None,
        snippet="still booting\n",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        ended_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    runner = FakeLibvirtRunner(console=console)

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)

    assert result.error_category == ErrorCategory.BOOT_TIMEOUT
    assert runner.commands == [plan.dumpxml_argv, plan.define_argv, plan.start_argv]


def test_execute_boot_rotates_existing_console_log_on_rerun(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    plan.console_log_path.parent.mkdir(parents=True, exist_ok=True)
    plan.console_log_path.write_text("previous\n", encoding="utf-8")
    runner = FakeLibvirtRunner()

    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)

    assert result.status == StepStatus.SUCCEEDED
    summary = json.loads(plan.boot_summary_path.read_text(encoding="utf-8"))
    assert any(artifact["kind"] == "boot-summary" for artifact in summary["artifacts"])
    rotated = list(plan.console_log_path.parent.glob("console.*.log"))
    assert len(rotated) == 1
    assert rotated[0].read_text(encoding="utf-8") == "previous\n"
    assert plan.console_log_path.read_text(encoding="utf-8") == "linux-debug-mcp-ready\n"
    rotated_artifacts = [
        artifact for artifact in result.artifacts if artifact.path == str(rotated[0]) and artifact.kind == "console-log"
    ]
    assert len(rotated_artifacts) == 1
    assert rotated_artifacts[0].description == "previous console log"
