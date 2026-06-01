from __future__ import annotations

from pathlib import Path

from kdive.config import BootOverrides, RootfsProfile, TargetProfile, TestSuiteProfile
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.kernel.handlers import kernel_build_handler as _kernel_build_handler
from kdive.kernel.tools import KernelBuildHandlerRequest, KernelToolRuntime
from kdive.providers.local.build.local_kernel_build import LocalKernelBuildProvider
from kdive.providers.local.target.libvirt_qemu import LibvirtQemuProvider
from kdive.providers.local.test.local_ssh_tests import LocalSshTestProvider
from kdive.target.handlers import target_boot_handler as _target_boot_handler
from kdive.target.handlers import target_run_tests_handler as _target_run_tests_handler
from kdive.target.tools import TargetBootHandlerRequest, TargetRunTestsHandlerRequest, TargetToolRuntime


def kernel_build_handler(
    *,
    artifact_root: Path,
    run_id: str,
    build_profile: str | None = None,
    force_rebuild: bool = False,
    provider: LocalKernelBuildProvider | None = None,
):
    return _kernel_build_handler(
        request=KernelBuildHandlerRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            build_profile=build_profile,
            force_rebuild=force_rebuild,
        ),
        runtime=KernelToolRuntime(sensitive_paths=[], build_provider=provider),
    )


def target_boot_handler(
    *,
    artifact_root: Path,
    run_id: str,
    target_profile: str | None = None,
    rootfs_profile: str | None = None,
    force_reboot: bool = False,
    provider: LibvirtQemuProvider | None = None,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    default_libvirt_uri: str | None = None,
    boot_overrides: BootOverrides | None = None,
    acknowledged_permissions: list[str] | None = None,
    sensitive_paths: list[Path] | None = None,
    admission: AdmissionService | None = None,
):
    return _target_boot_handler(
        request=TargetBootHandlerRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            force_reboot=force_reboot,
            boot_overrides=boot_overrides,
            acknowledged_permissions=acknowledged_permissions,
        ),
        runtime=TargetToolRuntime(
            sensitive_paths=sensitive_paths or [],
            admission=admission,
            session_registry=None,
            boot_provider=provider,
            target_profiles=target_profiles,
            rootfs_profiles=rootfs_profiles,
            default_libvirt_uri=default_libvirt_uri,
        ),
    )


def target_run_tests_handler(
    *,
    artifact_root: Path,
    run_id: str,
    test_suite: str | None = None,
    commands: list[list[str]] | None = None,
    force_rerun: bool = False,
    attempt: int | None = None,
    acknowledged_permissions: list[str] | None = None,
    provider: LocalSshTestProvider | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    test_suites: dict[str, TestSuiteProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
):
    return _target_run_tests_handler(
        request=TargetRunTestsHandlerRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            test_suite=test_suite,
            commands=commands,
            force_rerun=force_rerun,
            attempt=attempt,
            acknowledged_permissions=acknowledged_permissions,
        ),
        runtime=TargetToolRuntime(
            sensitive_paths=[],
            admission=admission,
            session_registry=session_registry,
            test_provider=provider,
            rootfs_profiles=rootfs_profiles,
            test_suites=test_suites,
        ),
    )
