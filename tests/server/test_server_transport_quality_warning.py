"""Phase D (#82), ADR 0024 decision 2: when the gdb/MI RSP rides a lossy out-of-band console
(HVC / VIRTIO) the start_session success surfaces a transport-quality warning and points the
agent at the postmortem/in-guest tiers. A plain QEMU UART carries no such warning."""

from __future__ import annotations

from pathlib import Path

from test_server_debug_core_ops import (
    FakeMiEngine,
    _build_transaction,
    _create_debug_ready_run,
    _make_registry,
    _start,
)

from kdive.providers.local.debug.gdb_mi import GdbMiSessionRegistry
from kdive.seams.target import BreakHint, ConsoleKind, PlatformMetadata
from kdive.server import is_lossy_out_of_band

PLATFORM_HVC = PlatformMetadata(
    console_kind=ConsoleKind.HVC,
    console_count=1,
    dedicated_debug_line=False,
    ssh_reachable=True,
    break_hints=[BreakHint.GDBSTUB_NATIVE],
)
PLATFORM_VIRTIO = PlatformMetadata(
    console_kind=ConsoleKind.VIRTIO,
    console_count=1,
    dedicated_debug_line=False,
    ssh_reachable=True,
    break_hints=[BreakHint.GDBSTUB_NATIVE],
)
PLATFORM_UART = PlatformMetadata(
    console_kind=ConsoleKind.UART,
    console_count=1,
    dedicated_debug_line=False,
    ssh_reachable=True,
    break_hints=[BreakHint.GDBSTUB_NATIVE],
)


def test_is_lossy_out_of_band_predicate() -> None:
    assert is_lossy_out_of_band(PLATFORM_HVC.console_kind) is True
    assert is_lossy_out_of_band(PLATFORM_VIRTIO.console_kind) is True
    assert is_lossy_out_of_band(PLATFORM_UART.console_kind) is False


def _start_over(tmp_path: Path, platform: PlatformMetadata):
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry, platform=platform)
    engine = FakeMiEngine()
    sessions = GdbMiSessionRegistry()
    return _start(artifact_root, registry=registry, txn=txn, admission=admission, engine=engine, sessions=sessions)


def test_start_session_over_hvc_emits_warning(tmp_path: Path) -> None:
    response = _start_over(tmp_path, PLATFORM_HVC)
    assert response.ok is True, response
    warning = response.data.get("transport_quality_warning")
    assert isinstance(warning, str) and warning
    assert "debug.kdb" in response.suggested_next_actions
    assert "debug.introspect.run" in response.suggested_next_actions


def test_start_session_over_qemu_uart_no_warning(tmp_path: Path) -> None:
    response = _start_over(tmp_path, PLATFORM_UART)
    assert response.ok is True, response
    assert "transport_quality_warning" not in response.data
    assert response.suggested_next_actions == [
        "debug.interrupt",
        "debug.read_registers",
        "artifacts.get_manifest",
    ]
