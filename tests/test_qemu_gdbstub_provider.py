from pathlib import Path

import pytest

from linux_debug_mcp.config import DebugProfile
from linux_debug_mcp.domain import ErrorCategory, StepStatus
from linux_debug_mcp.providers.qemu_gdbstub import (
    GdbCommandResult,
    ProviderDebugError,
    QemuGdbstubProvider,
    SubprocessGdbRunner,
)


class FakeGdbRunner:
    def __init__(self, *, gdb_path: str | None = "/usr/bin/gdb") -> None:
        self.gdb_path = gdb_path
        self.batches: list[tuple[list[str], list[str], int, Path]] = []

    def which(self, command: str) -> str | None:
        return self.gdb_path if command == "gdb" else None

    def run_batch(
        self,
        argv: list[str],
        commands: list[str],
        *,
        timeout: int,
        transcript_path: Path,
    ) -> GdbCommandResult:
        self.batches.append((argv, commands, timeout, transcript_path))
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path.write_text("\n".join(commands), encoding="utf-8")
        return GdbCommandResult(exit_status=0, stdout='$1 = "Linux version 6.9.0-test (builder)\\n"', stderr="")


class MismatchedBannerGdbRunner(FakeGdbRunner):
    def run_batch(
        self,
        argv: list[str],
        commands: list[str],
        *,
        timeout: int,
        transcript_path: Path,
    ) -> GdbCommandResult:
        self.batches.append((argv, commands, timeout, transcript_path))
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path.write_text("\n".join(commands), encoding="utf-8")
        return GdbCommandResult(exit_status=0, stdout='$1 = "Linux version 6.8.0-other (builder)\\n"', stderr="")


class OverlappingBannerGdbRunner(FakeGdbRunner):
    def run_batch(
        self,
        argv: list[str],
        commands: list[str],
        *,
        timeout: int,
        transcript_path: Path,
    ) -> GdbCommandResult:
        self.batches.append((argv, commands, timeout, transcript_path))
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path.write_text("\n".join(commands), encoding="utf-8")
        return GdbCommandResult(exit_status=0, stdout='$1 = "Linux version 6.9.0-other (builder)\\n"', stderr="")


class ExplodingGdbRunner(FakeGdbRunner):
    def run_batch(
        self,
        argv: list[str],
        commands: list[str],
        *,
        timeout: int,
        transcript_path: Path,
    ) -> GdbCommandResult:
        raise OSError("gdb exploded")


def write_vmlinux(tmp_path: Path) -> Path:
    vmlinux = tmp_path / "build" / "vmlinux"
    vmlinux.parent.mkdir(parents=True)
    vmlinux.write_text("fake vmlinux", encoding="utf-8")
    return vmlinux


def write_vmlinux_with_space(tmp_path: Path) -> Path:
    vmlinux = tmp_path / "build with space" / "vmlinux"
    vmlinux.parent.mkdir(parents=True)
    vmlinux.write_text("fake vmlinux", encoding="utf-8")
    return vmlinux


def test_start_session_records_files_and_uses_constrained_attach_batch(tmp_path: Path) -> None:
    vmlinux = write_vmlinux(tmp_path)
    runner = FakeGdbRunner()
    provider = QemuGdbstubProvider(runner=runner)

    result = provider.start_session(
        run_id="run-debug",
        run_dir=tmp_path,
        vmlinux_path=vmlinux,
        gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
        debug_profile=DebugProfile(name="qemu-gdbstub-default"),
        build_metadata={
            "kernel_release": "6.9.0-test",
            "kernel_image_path": str(tmp_path / "bzImage"),
            "vmlinux_path": str(vmlinux),
        },
        boot_metadata={"debug_boot": True, "kernel_image_path": str(tmp_path / "bzImage")},
    )

    assert result.status == StepStatus.SUCCEEDED
    assert result.session.session_id.startswith("debug-")
    assert result.session.current_execution_state == "stopped"
    assert result.session.controller_mode == "batch"
    assert Path(result.session.transcript_path).is_file()
    assert Path(result.session.command_metadata_path).is_file()
    assert Path(result.session.latest_summary_path).is_file()
    assert result.artifacts_by_kind["debug-transcript"].is_file()
    transcript_artifact = next(artifact for artifact in result.artifacts if artifact.kind == "debug-transcript")
    assert transcript_artifact.sensitive is True
    assert len(runner.batches) == 1
    argv, commands, timeout, transcript_path = runner.batches[0]
    assert argv[:4] == ["/usr/bin/gdb", "-nx", "-batch", "-q"]
    assert commands == [
        "set pagination off",
        "set confirm off",
        f"file {vmlinux.resolve()}",
        "target remote 127.0.0.1:1234",
        "p linux_banner",
    ]
    assert timeout == 30
    assert transcript_path == Path(result.session.transcript_path)


def test_start_session_requires_same_run_linkage_and_live_banner(tmp_path: Path) -> None:
    vmlinux = write_vmlinux(tmp_path)
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    result = provider.start_session(
        run_id="run-debug",
        run_dir=tmp_path,
        vmlinux_path=vmlinux,
        gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
        debug_profile=DebugProfile(name="qemu-gdbstub-default"),
        build_metadata={
            "kernel_release": "6.9.0-test",
            "kernel_image_path": str(tmp_path / "build" / "bzImage"),
            "vmlinux_path": str(vmlinux),
        },
        boot_metadata={
            "debug_boot": True,
            "kernel_image_path": str(tmp_path / "build" / "bzImage"),
        },
    )

    assert result.session.symbol_identity_validation["same_run_artifact_linkage"] is True
    assert result.session.symbol_identity_validation["live_banner_match"] is True
    assert result.session.symbol_identity_validation["build_kernel_release"] == "6.9.0-test"


def test_start_session_fails_when_same_run_linkage_is_missing(tmp_path: Path) -> None:
    vmlinux = write_vmlinux(tmp_path)
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.start_session(
            run_id="run-debug",
            run_dir=tmp_path,
            vmlinux_path=vmlinux,
            gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
            debug_profile=DebugProfile(name="qemu-gdbstub-default"),
            build_metadata={"kernel_release": "6.9.0-test", "kernel_image_path": str(tmp_path / "a")},
            boot_metadata={"debug_boot": True, "kernel_image_path": str(tmp_path / "b")},
        )

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert exc_info.value.details["symbol_identity_validation"]["same_run_artifact_linkage"] is False


def test_start_session_fails_when_live_banner_mismatches(tmp_path: Path) -> None:
    vmlinux = write_vmlinux(tmp_path)
    provider = QemuGdbstubProvider(runner=MismatchedBannerGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.start_session(
            run_id="run-debug",
            run_dir=tmp_path,
            vmlinux_path=vmlinux,
            gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
            debug_profile=DebugProfile(name="qemu-gdbstub-default"),
            build_metadata={
                "kernel_release": "6.9.0-test",
                "kernel_image_path": str(tmp_path / "build" / "bzImage"),
                "vmlinux_path": str(vmlinux),
            },
            boot_metadata={
                "debug_boot": True,
                "kernel_image_path": str(tmp_path / "build" / "bzImage"),
            },
        )

    assert exc_info.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert exc_info.value.details["symbol_identity_validation"]["live_banner_match"] is False
    assert "6.8.0-other" in exc_info.value.details["diagnostic"]
    artifact_kinds = {artifact.kind for artifact in exc_info.value.artifacts}
    assert {"debug-transcript", "debug-command-metadata", "debug-summary", "debug-session"} <= artifact_kinds
    for artifact in exc_info.value.artifacts:
        assert Path(artifact.path).is_file()


def test_start_session_requires_exact_live_banner_release(tmp_path: Path) -> None:
    vmlinux = write_vmlinux(tmp_path)
    provider = QemuGdbstubProvider(runner=OverlappingBannerGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.start_session(
            run_id="run-debug",
            run_dir=tmp_path,
            vmlinux_path=vmlinux,
            gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
            debug_profile=DebugProfile(name="qemu-gdbstub-default"),
            build_metadata={
                "kernel_release": "6.9.0",
                "kernel_image_path": str(tmp_path / "build" / "bzImage"),
                "vmlinux_path": str(vmlinux),
            },
            boot_metadata={
                "debug_boot": True,
                "kernel_image_path": str(tmp_path / "build" / "bzImage"),
            },
        )

    assert exc_info.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert exc_info.value.details["symbol_identity_validation"]["live_banner_match"] is False


def test_start_session_converts_artifact_write_failure_to_provider_error(tmp_path: Path) -> None:
    vmlinux = write_vmlinux(tmp_path)
    (tmp_path / "debug").write_text("not a directory", encoding="utf-8")
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.start_session(
            run_id="run-debug",
            run_dir=tmp_path,
            vmlinux_path=vmlinux,
            gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
            debug_profile=DebugProfile(name="qemu-gdbstub-default"),
            build_metadata={
                "kernel_release": "6.9.0-test",
                "kernel_image_path": str(tmp_path / "build" / "bzImage"),
                "vmlinux_path": str(vmlinux),
            },
            boot_metadata={
                "debug_boot": True,
                "kernel_image_path": str(tmp_path / "build" / "bzImage"),
            },
        )

    assert exc_info.value.category == ErrorCategory.INFRASTRUCTURE_FAILURE


def test_start_session_escapes_spaces_in_gdb_file_command(tmp_path: Path) -> None:
    vmlinux = write_vmlinux_with_space(tmp_path)
    runner = FakeGdbRunner()
    provider = QemuGdbstubProvider(runner=runner)

    provider.start_session(
        run_id="run-debug",
        run_dir=tmp_path,
        vmlinux_path=vmlinux,
        gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
        debug_profile=DebugProfile(name="qemu-gdbstub-default", symbol_identity_required=False),
        build_metadata={},
        boot_metadata={"debug_boot": True},
    )

    _argv, commands, _timeout, _transcript_path = runner.batches[0]
    escaped_vmlinux = str(vmlinux.resolve()).replace(" ", "\\ ")
    assert f"file {escaped_vmlinux}" in commands


def test_start_session_rejects_directory_vmlinux_path(tmp_path: Path) -> None:
    vmlinux_dir = tmp_path / "build" / "vmlinux"
    vmlinux_dir.mkdir(parents=True)
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.start_session(
            run_id="run-debug",
            run_dir=tmp_path,
            vmlinux_path=vmlinux_dir,
            gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
            debug_profile=DebugProfile(name="qemu-gdbstub-default"),
            build_metadata={},
            boot_metadata={"debug_boot": True},
        )

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_start_session_rejects_vmlinux_outside_run_dir(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    outside_vmlinux = tmp_path / "outside" / "vmlinux"
    outside_vmlinux.parent.mkdir()
    outside_vmlinux.write_text("fake vmlinux", encoding="utf-8")
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.start_session(
            run_id="run-debug",
            run_dir=run_dir,
            vmlinux_path=outside_vmlinux,
            gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
            debug_profile=DebugProfile(name="qemu-gdbstub-default"),
            build_metadata={},
            boot_metadata={"debug_boot": True},
        )

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_gdb_path_rejects_control_whitespace(tmp_path: Path) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider._gdb_path(Path("bad\tpath/vmlinux"))

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_start_session_allocates_next_attempt_paths(tmp_path: Path) -> None:
    vmlinux = write_vmlinux(tmp_path)
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    first = provider.start_session(
        run_id="run-debug",
        run_dir=tmp_path,
        vmlinux_path=vmlinux,
        gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
        debug_profile=DebugProfile(name="qemu-gdbstub-default", symbol_identity_required=False),
        build_metadata={},
        boot_metadata={"debug_boot": True},
    )
    second = provider.start_session(
        run_id="run-debug",
        run_dir=tmp_path,
        vmlinux_path=vmlinux,
        gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
        debug_profile=DebugProfile(name="qemu-gdbstub-default", symbol_identity_required=False),
        build_metadata={},
        boot_metadata={"debug_boot": True},
    )

    assert first.session.transcript_path != second.session.transcript_path
    assert first.session.command_metadata_path != second.session.command_metadata_path
    assert first.session.latest_summary_path != second.session.latest_summary_path
    for path in [
        first.session.transcript_path,
        first.session.command_metadata_path,
        first.session.latest_summary_path,
        second.session.transcript_path,
        second.session.command_metadata_path,
        second.session.latest_summary_path,
    ]:
        assert Path(path).is_file()


def test_start_session_converts_runner_failure_to_failed_result_with_artifacts(tmp_path: Path) -> None:
    vmlinux = write_vmlinux(tmp_path)
    provider = QemuGdbstubProvider(runner=ExplodingGdbRunner())

    result = provider.start_session(
        run_id="run-debug",
        run_dir=tmp_path,
        vmlinux_path=vmlinux,
        gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
        debug_profile=DebugProfile(name="qemu-gdbstub-default", symbol_identity_required=False),
        build_metadata={},
        boot_metadata={"debug_boot": True},
    )

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert Path(result.session.latest_summary_path).is_file()
    assert result.artifacts_by_kind["debug-session"].is_file()
    assert result.artifacts_by_kind["debug-summary"].is_file()


def test_subprocess_runner_transcript_records_non_timeout_status(tmp_path: Path) -> None:
    transcript_path = tmp_path / "debug" / "attempt-001" / "transcript.txt"
    transcript_path.parent.mkdir(parents=True)
    runner = SubprocessGdbRunner()

    runner._append_transcript(
        transcript_path=transcript_path,
        argv=["gdb", "-batch"],
        commands=["set pagination off"],
        timeout=30,
        result=GdbCommandResult(exit_status=0, stdout="ok\n", stderr="", timed_out=False),
    )

    transcript = transcript_path.read_text(encoding="utf-8")
    assert "timed_out: false\n" in transcript
    assert "timed out after 30s" not in transcript


@pytest.mark.parametrize("symbol", ["", "bad-name", "bad;name", "bad name", "bad/name"])
def test_symbol_validation_rejects_unsafe_names(tmp_path: Path, symbol: str) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.validate_symbol_name(symbol)

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


@pytest.mark.parametrize("symbol", [None, 1234, True])
def test_symbol_validation_rejects_non_string_values(tmp_path: Path, symbol: object) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.validate_symbol_name(symbol)  # type: ignore[arg-type]

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_register_validation_accepts_safe_name(tmp_path: Path) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    assert provider.validate_register_name("rax") == "rax"


@pytest.mark.parametrize("register", ["", "bad-name", "bad name", "bad/name"])
def test_register_validation_rejects_unsafe_names(tmp_path: Path, register: str) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.validate_register_name(register)

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


@pytest.mark.parametrize("register", [None, 1234, True])
def test_register_validation_rejects_non_string_values(tmp_path: Path, register: object) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.validate_register_name(register)  # type: ignore[arg-type]

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


@pytest.mark.parametrize("port", [True, False, "1234"])
def test_endpoint_validation_rejects_non_integer_ports(tmp_path: Path, port: object) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider._validated_endpoint({"host": "127.0.0.1", "port": port})

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


@pytest.mark.parametrize("endpoint", [None, True, [], "127.0.0.1:1234"])
def test_endpoint_validation_rejects_non_object_values(tmp_path: Path, endpoint: object) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider._validated_endpoint(endpoint)  # type: ignore[arg-type]

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


@pytest.mark.parametrize("byte_count", [-1, 0, 4097])
def test_memory_validation_rejects_invalid_byte_counts(tmp_path: Path, byte_count: int) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.validate_memory_read(address=0x1000, byte_count=byte_count)

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


@pytest.mark.parametrize(
    ("address", "byte_count"),
    [
        ("0x1000", 8),
        (0x1000, True),
    ],
)
def test_memory_validation_rejects_non_integer_values(tmp_path: Path, address: object, byte_count: object) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.validate_memory_read(address=address, byte_count=byte_count)  # type: ignore[arg-type]

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_read_registers_parses_fake_gdb_output(tmp_path: Path) -> None:
    runner = FakeGdbRunner()
    runner.run_batch = lambda argv, commands, timeout, transcript_path: GdbCommandResult(  # type: ignore[method-assign]
        exit_status=0,
        stdout="rax            0x1\nrip            0xffffffff81000000\n",
        stderr="",
    )
    provider = QemuGdbstubProvider(runner=runner)
    session = provider.write_session_for_test(tmp_path, state="stopped")

    result = provider.read_registers(run_dir=tmp_path, session=session, registers=["rax", "rip"])

    assert result.details["registers"] == {"rax": "0x1", "rip": "0xffffffff81000000"}


def test_read_registers_redacts_failure_diagnostic(tmp_path: Path) -> None:
    runner = FakeGdbRunner()
    runner.run_batch = lambda argv, commands, timeout, transcript_path: GdbCommandResult(  # type: ignore[method-assign]
        exit_status=1,
        stdout="",
        stderr="token=secret\n",
    )
    provider = QemuGdbstubProvider(runner=runner)
    session = provider.write_session_for_test(tmp_path, state="stopped")

    result = provider.read_registers(run_dir=tmp_path, session=session, registers=["rax"])

    assert result.status == StepStatus.FAILED
    assert result.details["stderr_snippet"] == "token=[REDACTED]\n"
    assert result.diagnostic == "token=[REDACTED]\n"


def test_read_memory_enforces_4096_byte_limit(tmp_path: Path) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())
    session = provider.write_session_for_test(tmp_path, state="stopped")

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.read_memory(run_dir=tmp_path, session=session, address=0x1000, byte_count=4097)

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_evaluate_rejects_unknown_inspector(tmp_path: Path) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())
    session = provider.write_session_for_test(tmp_path, state="stopped")

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.evaluate(run_dir=tmp_path, session=session, inspector="raw", arguments={})

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR
