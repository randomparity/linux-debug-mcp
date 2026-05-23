import os
from pathlib import Path

import pytest

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import RootfsProfile, TargetProfile
from linux_debug_mcp.domain import ArtifactRef, StepResult, StepStatus
from linux_debug_mcp.server import create_run_handler, target_boot_handler

MANAGED_DOMAIN_PREFIX = "mcp-linux-debug-"
REQUIRED_ENV = [
    "LINUX_DEBUG_MCP_LIBVIRT_TEST",
    "LINUX_DEBUG_MCP_ROOTFS",
    "LINUX_DEBUG_MCP_SOURCE",
    "LINUX_DEBUG_MCP_DOMAIN",
    "LINUX_DEBUG_MCP_LIBVIRT_URI",
    "LINUX_DEBUG_MCP_READINESS_MARKER",
]


def require_libvirt_integration_env() -> dict[str, str]:
    values = {name: value for name in REQUIRED_ENV if (value := os.environ.get(name))}
    missing = [name for name in REQUIRED_ENV if name not in values]
    if "LINUX_DEBUG_MCP_LIBVIRT_TEST" in values and values["LINUX_DEBUG_MCP_LIBVIRT_TEST"] != "1":
        missing.append("LINUX_DEBUG_MCP_LIBVIRT_TEST=1")
    if missing:
        pytest.skip(
            "libvirt boot integration test skipped; set "
            f"{', '.join(missing)} to run it. Example: "
            "LINUX_DEBUG_MCP_LIBVIRT_TEST=1 "
            "LINUX_DEBUG_MCP_ROOTFS=/var/lib/linux-debug-mcp/rootfs/minimal.qcow2 "
            "LINUX_DEBUG_MCP_SOURCE=/path/to/linux "
            "LINUX_DEBUG_MCP_DOMAIN=mcp-linux-debug-dev "
            "LINUX_DEBUG_MCP_LIBVIRT_URI=qemu:///system "
            "LINUX_DEBUG_MCP_READINESS_MARKER=linux-debug-mcp-ready "
            "pytest tests/test_libvirt_boot_integration.py -q"
        )
    return values


def test_target_boot_smoke_path_against_opted_in_libvirt_host(
    tmp_path: Path,
) -> None:
    env = require_libvirt_integration_env()
    source = Path(env["LINUX_DEBUG_MCP_SOURCE"]).expanduser()
    rootfs = Path(env["LINUX_DEBUG_MCP_ROOTFS"]).expanduser()
    kernel_image = source / "arch" / "x86" / "boot" / "bzImage"
    artifact_root = tmp_path / "runs"
    run_id = "run-libvirt-boot-integration"

    assert source.is_dir(), f"LINUX_DEBUG_MCP_SOURCE must be a Linux source directory: {source}"
    assert rootfs.is_file(), f"LINUX_DEBUG_MCP_ROOTFS must be a disk image file: {rootfs}"
    assert env["LINUX_DEBUG_MCP_DOMAIN"].startswith(MANAGED_DOMAIN_PREFIX), (
        "LINUX_DEBUG_MCP_DOMAIN must be a dedicated managed domain starting with "
        f"{MANAGED_DOMAIN_PREFIX!r}: {env['LINUX_DEBUG_MCP_DOMAIN']}"
    )
    assert kernel_image.is_file(), (
        "LINUX_DEBUG_MCP_SOURCE must contain a built x86_64 kernel image at "
        f"{kernel_image}; build bzImage before running this integration test"
    )

    create_response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="pilot-libvirt",
        rootfs_profile="pilot-rootfs",
        run_id=run_id,
    )
    assert create_response.ok is True, create_response.model_dump(mode="json")

    ArtifactStore(artifact_root, create_root=False).record_step_result(
        run_id,
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="seeded integration build result",
            artifacts=[ArtifactRef(path=str(kernel_image), kind="kernel-image")],
            details={"architecture": "x86_64", "output_path": str(kernel_image.parent)},
        ),
    )

    boot_response = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        force_reboot=True,
        target_profiles={
            "pilot-libvirt": TargetProfile(
                name="pilot-libvirt",
                architecture="x86_64",
                target_ref=env["LINUX_DEBUG_MCP_DOMAIN"],
                managed_domain=True,
                managed_domain_prefix=MANAGED_DOMAIN_PREFIX,
                libvirt_uri=env["LINUX_DEBUG_MCP_LIBVIRT_URI"],
                timeout_seconds=300,
            )
        },
        rootfs_profiles={
            "pilot-rootfs": RootfsProfile(
                name="pilot-rootfs",
                source=str(rootfs),
                source_type="disk_image",
                mutability="read_only",
                readiness_marker=env["LINUX_DEBUG_MCP_READINESS_MARKER"],
            )
        },
    )

    assert boot_response.ok is True, boot_response.model_dump(mode="json")
    assert boot_response.data["domain"] == env["LINUX_DEBUG_MCP_DOMAIN"]
    assert boot_response.data["matched_marker"] == env["LINUX_DEBUG_MCP_READINESS_MARKER"]
