import os
from pathlib import Path

import pytest
from handler_call_helpers import target_boot_handler

from kdive.artifacts.handlers import create_run_handler
from kdive.artifacts.store import ArtifactStore
from kdive.config import RootfsProfile, TargetProfile
from kdive.domain import ArtifactRef, StepResult, StepStatus

MANAGED_DOMAIN_PREFIX = "kdive-"
REQUIRED_ENV = [
    "KDIVE_LIBVIRT_TEST",
    "KDIVE_ROOTFS",
    "KDIVE_SOURCE",
    "KDIVE_DOMAIN",
    "KDIVE_LIBVIRT_URI",
    "KDIVE_READINESS_MARKER",
]


def require_libvirt_integration_env() -> dict[str, str]:
    values = {name: value for name in REQUIRED_ENV if (value := os.environ.get(name))}
    missing = [name for name in REQUIRED_ENV if name not in values]
    if "KDIVE_LIBVIRT_TEST" in values and values["KDIVE_LIBVIRT_TEST"] != "1":
        missing.append("KDIVE_LIBVIRT_TEST=1")
    if missing:
        pytest.skip(
            "libvirt boot integration test skipped; set "
            f"{', '.join(missing)} to run it. Example: "
            "KDIVE_LIBVIRT_TEST=1 "
            "KDIVE_ROOTFS=/var/lib/kdive/rootfs/minimal.qcow2 "
            "KDIVE_SOURCE=/path/to/linux "
            "KDIVE_DOMAIN=kdive-dev "
            "KDIVE_LIBVIRT_URI=qemu:///system "
            "KDIVE_READINESS_MARKER=kdive-ready "
            "pytest tests/test_libvirt_boot_integration.py -q"
        )
    return values


def test_target_boot_smoke_path_against_opted_in_libvirt_host(
    tmp_path: Path,
) -> None:
    env = require_libvirt_integration_env()
    source = Path(env["KDIVE_SOURCE"]).expanduser()
    rootfs = Path(env["KDIVE_ROOTFS"]).expanduser()
    kernel_image = source / "arch" / "x86" / "boot" / "bzImage"
    artifact_root = tmp_path / "runs"
    run_id = "run-libvirt-boot-integration"

    assert source.is_dir(), f"KDIVE_SOURCE must be a Linux source directory: {source}"
    assert rootfs.is_file(), f"KDIVE_ROOTFS must be a disk image file: {rootfs}"
    assert env["KDIVE_DOMAIN"].startswith(MANAGED_DOMAIN_PREFIX), (
        "KDIVE_DOMAIN must be a dedicated managed domain starting with "
        f"{MANAGED_DOMAIN_PREFIX!r}: {env['KDIVE_DOMAIN']}"
    )
    assert kernel_image.is_file(), (
        "KDIVE_SOURCE must contain a built x86_64 kernel image at "
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
                target_ref=env["KDIVE_DOMAIN"],
                managed_domain=True,
                managed_domain_prefix=MANAGED_DOMAIN_PREFIX,
                libvirt_uri=env["KDIVE_LIBVIRT_URI"],
                timeout_seconds=300,
            )
        },
        rootfs_profiles={
            "pilot-rootfs": RootfsProfile(
                name="pilot-rootfs",
                source=str(rootfs),
                source_type="disk_image",
                mutability="read_only",
                readiness_marker=env["KDIVE_READINESS_MARKER"],
            )
        },
    )

    assert boot_response.ok is True, boot_response.model_dump(mode="json")
    assert boot_response.data["domain"] == env["KDIVE_DOMAIN"]
    assert boot_response.data["matched_marker"] == env["KDIVE_READINESS_MARKER"]
