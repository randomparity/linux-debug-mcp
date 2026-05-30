import os
from pathlib import Path

import pytest

from linux_debug_mcp import server
from linux_debug_mcp.config import RootfsProfile, TargetProfile
from linux_debug_mcp.providers.gdb_mi import GdbMiEngine, GdbMiSessionRegistry
from linux_debug_mcp.server import workflow_build_boot_debug_handler

MANAGED_DOMAIN_PREFIX = "mcp-linux-debug-"
REQUIRED_ENV = [
    "LINUX_DEBUG_MCP_LIVE_GDBSTUB",
    "LINUX_DEBUG_MCP_SOURCE",
    "LINUX_DEBUG_MCP_ROOTFS",
    "LINUX_DEBUG_MCP_DOMAIN",
    "LINUX_DEBUG_MCP_LIBVIRT_URI",
    "LINUX_DEBUG_MCP_READINESS_MARKER",
]


def require_live_gdbstub_env() -> dict[str, str]:
    values = {name: value for name in REQUIRED_ENV if (value := os.environ.get(name))}
    missing = [name for name in REQUIRED_ENV if name not in values]
    if "LINUX_DEBUG_MCP_LIVE_GDBSTUB" in values and values["LINUX_DEBUG_MCP_LIVE_GDBSTUB"] != "1":
        missing.append("LINUX_DEBUG_MCP_LIVE_GDBSTUB=1")
    if missing:
        pytest.skip(
            "live gdbstub integration test skipped; set "
            f"{', '.join(missing)} to run it. Example: "
            "LINUX_DEBUG_MCP_LIVE_GDBSTUB=1 "
            "LINUX_DEBUG_MCP_SOURCE=/path/to/linux "
            "LINUX_DEBUG_MCP_ROOTFS=/var/lib/linux-debug-mcp/rootfs/minimal.qcow2 "
            "LINUX_DEBUG_MCP_DOMAIN=mcp-linux-debug-dev-debug "
            "LINUX_DEBUG_MCP_LIBVIRT_URI=qemu:///system "
            "LINUX_DEBUG_MCP_READINESS_MARKER=linux-debug-mcp-ready "
            "pytest tests/test_qemu_gdbstub_integration.py -q"
        )
    return values


def test_live_build_boot_debug_workflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = require_live_gdbstub_env()
    source = Path(env["LINUX_DEBUG_MCP_SOURCE"]).expanduser()
    rootfs = Path(env["LINUX_DEBUG_MCP_ROOTFS"]).expanduser()
    kernel_image = source / "arch" / "x86" / "boot" / "bzImage"
    vmlinux = source / "vmlinux"
    gdbstub_endpoint = os.environ.get("LINUX_DEBUG_MCP_GDBSTUB_ENDPOINT", "127.0.0.1:1234")

    assert source.is_dir(), f"LINUX_DEBUG_MCP_SOURCE must be a Linux source directory: {source}"
    assert rootfs.is_file(), f"LINUX_DEBUG_MCP_ROOTFS must be a disk image file: {rootfs}"
    assert kernel_image.is_file(), f"built kernel image is required at {kernel_image}"
    assert vmlinux.is_file(), f"unstripped vmlinux is required at {vmlinux}"
    assert env["LINUX_DEBUG_MCP_DOMAIN"].startswith(MANAGED_DOMAIN_PREFIX), (
        "LINUX_DEBUG_MCP_DOMAIN must be a dedicated managed domain starting with "
        f"{MANAGED_DOMAIN_PREFIX!r}: {env['LINUX_DEBUG_MCP_DOMAIN']}"
    )

    monkeypatch.setitem(
        server.DEFAULT_TARGET_PROFILES,
        "live-qemu-debug",
        TargetProfile(
            name="live-qemu-debug",
            architecture="x86_64",
            target_ref=env["LINUX_DEBUG_MCP_DOMAIN"],
            managed_domain=True,
            managed_domain_prefix=MANAGED_DOMAIN_PREFIX,
            libvirt_uri=env["LINUX_DEBUG_MCP_LIBVIRT_URI"],
            timeout_seconds=300,
            debug_gdbstub=True,
            gdbstub_endpoint=gdbstub_endpoint,
        ),
    )
    monkeypatch.setitem(
        server.DEFAULT_ROOTFS_PROFILES,
        "live-rootfs",
        RootfsProfile(
            name="live-rootfs",
            source=str(rootfs),
            source_type="disk_image",
            mutability="read_only",
            readiness_marker=env["LINUX_DEBUG_MCP_READINESS_MARKER"],
        ),
    )

    # The live debug attach drives the persistent gdb/MI engine over the guard-protected transport,
    # exactly as create_app wires it: build the Layer-4 machinery and a real engine + live-session
    # registry and thread them through the workflow.
    machinery = server._build_transport_machinery(session_registry=None, transport_registry=None)
    response = workflow_build_boot_debug_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="live-qemu-debug",
        rootfs_profile="live-rootfs",
        debug_profile="qemu-gdbstub-default",
        force_rebuild=True,
        force_reboot=True,
        new_session=True,
        admission=machinery.admission,
        session_registry=machinery.session_registry,
        transaction=machinery.transaction,
        session_guard=machinery.session_guard,
        gdb_mi_engine=GdbMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
    )

    assert response.ok is True, response.model_dump(mode="json")
    assert response.data["steps"]["build"]["ok"] is True
    assert response.data["steps"]["boot"]["ok"] is True
    assert response.data["steps"]["debug"]["ok"] is True


def test_live_frozen_boot_hits_early_breakpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Acceptance for #104: wait_for_debugger freezes the boot at the reset vector so a
    breakpoint set before the debugger releases the CPU is hit deterministically in early init.

    Gated behind the same live-gdbstub env guard as test_live_build_boot_debug_workflow; skipped
    in CI. Requires a real QEMU+KVM guest, a built kernel, and a managed debug domain.
    """
    from linux_debug_mcp.config import BootOverrides
    from linux_debug_mcp.server import (
        create_run_handler,
        debug_continue_handler,
        debug_read_symbol_handler,
        debug_set_breakpoint_handler,
        debug_start_session_handler,
        kernel_build_handler,
        target_boot_handler,
    )

    env = require_live_gdbstub_env()
    source = Path(env["LINUX_DEBUG_MCP_SOURCE"]).expanduser()
    rootfs = Path(env["LINUX_DEBUG_MCP_ROOTFS"]).expanduser()
    vmlinux = source / "vmlinux"
    gdbstub_endpoint = os.environ.get("LINUX_DEBUG_MCP_GDBSTUB_ENDPOINT", "127.0.0.1:1234")
    early_symbol = os.environ.get("LINUX_DEBUG_MCP_EARLY_SYMBOL", "start_kernel")

    assert source.is_dir(), f"LINUX_DEBUG_MCP_SOURCE must be a Linux source directory: {source}"
    assert rootfs.is_file(), f"LINUX_DEBUG_MCP_ROOTFS must be a disk image file: {rootfs}"
    assert vmlinux.is_file(), f"unstripped vmlinux is required at {vmlinux}"
    assert env["LINUX_DEBUG_MCP_DOMAIN"].startswith(MANAGED_DOMAIN_PREFIX)

    monkeypatch.setitem(
        server.DEFAULT_TARGET_PROFILES,
        "live-qemu-debug",
        TargetProfile(
            name="live-qemu-debug",
            architecture="x86_64",
            target_ref=env["LINUX_DEBUG_MCP_DOMAIN"],
            managed_domain=True,
            managed_domain_prefix=MANAGED_DOMAIN_PREFIX,
            libvirt_uri=env["LINUX_DEBUG_MCP_LIBVIRT_URI"],
            timeout_seconds=300,
            debug_gdbstub=True,
            gdbstub_endpoint=gdbstub_endpoint,
        ),
    )
    monkeypatch.setitem(
        server.DEFAULT_ROOTFS_PROFILES,
        "live-rootfs",
        RootfsProfile(
            name="live-rootfs",
            source=str(rootfs),
            source_type="disk_image",
            mutability="read_only",
            readiness_marker=env["LINUX_DEBUG_MCP_READINESS_MARKER"],
        ),
    )

    artifact_root = tmp_path / "runs"
    machinery = server._build_transport_machinery(session_registry=None, transport_registry=None)
    engine = GdbMiEngine()
    sessions = GdbMiSessionRegistry()

    # Freeze the boot via a create-time boot override (becomes the manifest request override).
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="live-qemu-debug",
        rootfs_profile="live-rootfs",
        debug_profile="qemu-gdbstub-default",
        boot_overrides=BootOverrides(wait_for_debugger=True),
    )
    assert created.ok is True, created.model_dump(mode="json")
    run_id = created.data["run_id"]

    built = kernel_build_handler(artifact_root=artifact_root, run_id=run_id, force_rebuild=True)
    assert built.ok is True, built.model_dump(mode="json")

    boot_resp = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        force_reboot=True,
        admission=machinery.admission,
    )
    assert boot_resp.ok is True, boot_resp.model_dump(mode="json")
    # The frozen boot returns SUCCEEDED without a readiness wait and steers to the debugger.
    assert boot_resp.data["console_status"] == "frozen"
    assert boot_resp.data["wait_for_debugger"] is True
    assert boot_resp.suggested_next_actions == ["debug.start_session"]

    session_resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        new_session=True,
        admission=machinery.admission,
        session_registry=machinery.session_registry,
        transaction=machinery.transaction,
        session_guard=machinery.session_guard,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )
    assert session_resp.ok is True, session_resp.model_dump(mode="json")
    session_id = session_resp.data["debug_session_id"]

    debug_kwargs = {
        "artifact_root": artifact_root,
        "run_id": run_id,
        "debug_session_id": session_id,
        "transaction": machinery.transaction,
        "session_registry": machinery.session_registry,
        "session_guard": machinery.session_guard,
        "gdb_mi_engine": engine,
        "gdb_mi_sessions": sessions,
    }

    bp_resp = debug_set_breakpoint_handler(symbol=early_symbol, admission=machinery.admission, **debug_kwargs)
    assert bp_resp.ok is True, bp_resp.model_dump(mode="json")

    cont_resp = debug_continue_handler(admission=machinery.admission, **debug_kwargs)
    assert cont_resp.ok is True, cont_resp.model_dump(mode="json")

    # The CPU ran from the reset vector into the early-init breakpoint; the symbol is inspectable.
    read_resp = debug_read_symbol_handler(symbol=early_symbol, **debug_kwargs)
    assert read_resp.ok is True, read_resp.model_dump(mode="json")
