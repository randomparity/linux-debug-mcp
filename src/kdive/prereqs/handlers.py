from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from kdive.config import BuildProfile, RootfsProfile, TargetProfile
from kdive.default_profiles import DEFAULT_BUILD_PROFILES, DEFAULT_ROOTFS_PROFILES, DEFAULT_TARGET_PROFILES
from kdive.domain import PrerequisiteCheck, PrerequisiteStatus, ToolResponse
from kdive.prereqs.checks import (
    PortProbeResult,
    PrerequisiteRunner,
    SubprocessPrerequisiteRunner,
    check_gdbstub_port,
    check_kernel_config,
    check_kvm_access,
    check_libvirt_connect,
    check_prerequisites,
    check_rootfs_builder,
    check_rootfs_image,
)

_READINESS_CHECK_IDS = {"build": "kernel.config", "target": "gdbstub.port", "rootfs": "rootfs.image"}


def _resolve_readiness_profile(
    kind: str, name: str | None, registry: dict[str, Any]
) -> tuple[Any, PrerequisiteCheck | None]:
    """Resolve a readiness profile name to its object, or to a FAILED check for an unknown name."""
    if name is None:
        return None, None
    if name not in registry:
        known = ", ".join(sorted(registry)) or "(none configured)"
        return None, PrerequisiteCheck(
            check_id=_READINESS_CHECK_IDS[kind],
            status=PrerequisiteStatus.FAILED,
            message=f"unknown {kind} profile: {name}",
            suggested_fix=f"Select a known {kind} profile: {known}.",
        )
    return registry[name], None


def prerequisites_handler(
    *,
    artifact_root: Path,
    source_path: str | None,
    enable_libvirt_check: bool = False,
    build_profile: str | None = None,
    target_profile: str | None = None,
    rootfs_profile: str | None = None,
    build_profiles: dict[str, BuildProfile] | None = None,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    port_probe: Callable[[str, int], PortProbeResult] | None = None,
    runner: PrerequisiteRunner | None = None,
    kvm_probe: Callable[[], bool] | None = None,
) -> ToolResponse:
    build_profiles = build_profiles if build_profiles is not None else DEFAULT_BUILD_PROFILES
    target_profiles = target_profiles if target_profiles is not None else DEFAULT_TARGET_PROFILES
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    source = Path(source_path) if source_path else None
    runner = runner or SubprocessPrerequisiteRunner()
    checks = check_prerequisites(
        artifact_root=artifact_root,
        source_path=source,
        enable_libvirt_check=enable_libvirt_check,
        runner=runner,
    )
    build_obj, build_err = _resolve_readiness_profile("build", build_profile, build_profiles)
    rootfs_obj, rootfs_err = _resolve_readiness_profile("rootfs", rootfs_profile, rootfs_profiles)
    target_obj, target_err = _resolve_readiness_profile("target", target_profile, target_profiles)
    checks.append(build_err or check_kernel_config(source, build_obj))
    checks.append(rootfs_err or check_rootfs_image(rootfs_obj))
    checks.append(target_err or check_gdbstub_port(target_obj, port_probe=port_probe))
    checks.append(check_kvm_access(kvm_probe=kvm_probe))
    checks.append(check_rootfs_builder(runner=runner))
    checks.append(
        target_err or check_libvirt_connect(target_obj, runner=runner, enable_libvirt_check=enable_libvirt_check)
    )
    failed = [check for check in checks if check.status is PrerequisiteStatus.FAILED]
    return ToolResponse.success(
        summary=f"{len(failed)} prerequisite checks failed",
        data={"checks": [check.model_dump(mode="json") for check in checks]},
        suggested_next_actions=["Fix failed checks", "kernel.create_run"],
    )
