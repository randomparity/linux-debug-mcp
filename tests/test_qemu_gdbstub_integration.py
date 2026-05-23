import os
from pathlib import Path

import pytest

from linux_debug_mcp import server
from linux_debug_mcp.config import RootfsProfile, TargetProfile
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
    )

    assert response.ok is True, response.model_dump(mode="json")
    assert response.data["steps"]["build"]["ok"] is True
    assert response.data["steps"]["boot"]["ok"] is True
    assert response.data["steps"]["debug"]["ok"] is True
