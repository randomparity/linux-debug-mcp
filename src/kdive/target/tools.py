from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from kdive.config import BootOverrides
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.domain import ToolResponse
from kdive.model import Model
from kdive.tools.adapter_boundary import adapter_validation_failure, model_arg, optional_model_arg

if TYPE_CHECKING:
    from kdive.config import RootfsProfile, TargetProfile, TestSuiteProfile
    from kdive.providers.local.target.libvirt_qemu import LibvirtQemuProvider
    from kdive.providers.local.test.local_ssh_tests import LocalSshTestProvider


class TargetBootHandler(Protocol):
    def __call__(self, *, request: TargetBootHandlerRequest, runtime: TargetToolRuntime) -> ToolResponse: ...


class TargetRunTestsHandler(Protocol):
    def __call__(self, *, request: TargetRunTestsHandlerRequest, runtime: TargetToolRuntime) -> ToolResponse: ...


@dataclass(frozen=True)
class TargetToolRuntime:
    sensitive_paths: list[Path]
    admission: AdmissionService | None
    session_registry: SessionRegistry | None
    boot_provider: LibvirtQemuProvider | None = None
    test_provider: LocalSshTestProvider | None = None
    target_profiles: dict[str, TargetProfile] | None = None
    rootfs_profiles: dict[str, RootfsProfile] | None = None
    test_suites: dict[str, TestSuiteProfile] | None = None
    default_libvirt_uri: str | None = None


@dataclass(frozen=True)
class TargetBootHandlerRequest:
    artifact_root: Path
    run_id: str
    target_profile: str | None
    rootfs_profile: str | None
    force_reboot: bool
    boot_overrides: BootOverrides | None
    acknowledged_permissions: list[str] | None


@dataclass(frozen=True)
class TargetRunTestsHandlerRequest:
    artifact_root: Path
    run_id: str
    test_suite: str | None
    commands: list[list[str]] | None
    force_rerun: bool
    attempt: int | None
    acknowledged_permissions: list[str] | None


class TargetBootContext(Model):
    run_id: str
    artifact_root: str | None = None


class TargetBootProfiles(Model):
    target_profile: str | None = None
    rootfs_profile: str | None = None


class TargetBootOptions(Model):
    force_reboot: bool = False
    boot_overrides: dict[str, Any] | None = None
    acknowledged_permissions: list[str] | None = None


class TargetRunContext(Model):
    run_id: str
    artifact_root: str | None = None


class TargetRunOptions(Model):
    test_suite: str | None = None
    commands: list[list[str]] | None = None
    force_rerun: bool = False
    attempt: int | None = None
    acknowledged_permissions: list[str] | None = None


def register_target_tools(
    app: FastMCP,
    *,
    default_artifact_root: Path,
    sensitive_paths: list[Path],
    admission: AdmissionService,
    session_registry: SessionRegistry,
    target_boot_handler: TargetBootHandler,
    target_run_tests_handler: TargetRunTestsHandler,
) -> None:
    default_artifact_root_text = str(default_artifact_root)
    runtime = TargetToolRuntime(
        sensitive_paths=sensitive_paths,
        admission=admission,
        session_registry=session_registry,
    )

    @app.tool(name="target.boot")
    def target_boot(
        context: TargetBootContext | dict[str, Any],
        profiles: TargetBootProfiles | dict[str, Any] | None = None,
        options: TargetBootOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            context_model = model_arg(context, TargetBootContext)
            profiles_model = optional_model_arg(profiles, TargetBootProfiles)
            options_model = optional_model_arg(options, TargetBootOptions)
            resolved_boot_overrides = (
                BootOverrides(**options_model.boot_overrides) if options_model.boot_overrides else None
            )
        except (TypeError, ValueError, ValidationError) as exc:
            return adapter_validation_failure(exc)
        return target_boot_handler(
            request=TargetBootHandlerRequest(
                artifact_root=Path(context_model.artifact_root or default_artifact_root_text),
                run_id=context_model.run_id,
                target_profile=profiles_model.target_profile,
                rootfs_profile=profiles_model.rootfs_profile,
                force_reboot=options_model.force_reboot,
                boot_overrides=resolved_boot_overrides,
                acknowledged_permissions=options_model.acknowledged_permissions,
            ),
            runtime=runtime,
        ).model_dump(mode="json")

    @app.tool(name="target.run_tests")
    def target_run_tests(
        context: TargetRunContext | dict[str, Any],
        options: TargetRunOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            context_model = model_arg(context, TargetRunContext)
            options_model = optional_model_arg(options, TargetRunOptions)
        except (TypeError, ValueError, ValidationError) as exc:
            return adapter_validation_failure(exc)
        return target_run_tests_handler(
            request=TargetRunTestsHandlerRequest(
                artifact_root=Path(context_model.artifact_root or default_artifact_root_text),
                run_id=context_model.run_id,
                test_suite=options_model.test_suite,
                commands=options_model.commands,
                force_rerun=options_model.force_rerun,
                attempt=options_model.attempt,
                acknowledged_permissions=options_model.acknowledged_permissions,
            ),
            runtime=runtime,
        ).model_dump(mode="json")
