from pathlib import Path

import pytest

from linux_debug_mcp.config import DebugProfile
from linux_debug_mcp.domain import ErrorCategory, StepStatus
from linux_debug_mcp.providers.qemu_gdbstub import (
    GdbCommandResult,
    ProviderDebugError,
    QemuGdbstubProvider,
)


class FakeGdbRunner:
    def __init__(self, *, gdb_path: str | None = "/usr/bin/gdb") -> None:
        self.gdb_path = gdb_path
        self.batches: list[tuple[list[str], list[str]]] = []

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
        self.batches.append((argv, commands))
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path.write_text("\n".join(commands), encoding="utf-8")
        return GdbCommandResult(exit_status=0, stdout="$1 = 0xffffffff81000000", stderr="")


def write_vmlinux(tmp_path: Path) -> Path:
    vmlinux = tmp_path / "build" / "vmlinux"
    vmlinux.parent.mkdir(parents=True)
    vmlinux.write_text("fake vmlinux", encoding="utf-8")
    return vmlinux


def test_start_session_records_files_and_uses_constrained_attach_batch(tmp_path: Path) -> None:
    vmlinux = write_vmlinux(tmp_path)
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    result = provider.start_session(
        run_id="run-debug",
        run_dir=tmp_path,
        vmlinux_path=vmlinux,
        gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
        debug_profile=DebugProfile(name="qemu-gdbstub-default"),
        build_metadata={"kernel_release": "6.9.0-test"},
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


@pytest.mark.parametrize("symbol", ["", "bad-name", "bad;name", "bad name", "bad/name"])
def test_symbol_validation_rejects_unsafe_names(tmp_path: Path, symbol: str) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.validate_symbol_name(symbol)

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


@pytest.mark.parametrize("byte_count", [-1, 0, 4097])
def test_memory_validation_rejects_invalid_byte_counts(tmp_path: Path, byte_count: int) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.validate_memory_read(address=0x1000, byte_count=byte_count)

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR
