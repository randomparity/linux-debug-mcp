from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from kdive.config import BootOverrides
from kdive.coordination.admission import AdmissionService
from kdive.domain import ToolResponse
from kdive.model import Model
from kdive.tools.adapter_boundary import adapter_validation_failure, model_arg, optional_model_arg


class TargetBootHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        target_profile: str | None,
        rootfs_profile: str | None,
        force_reboot: bool,
        boot_overrides: BootOverrides | None,
        acknowledged_permissions: list[str] | None,
        sensitive_paths: list[Path] | None,
        admission: AdmissionService | None,
    ) -> ToolResponse: ...


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


def register_target_tools(
    app: FastMCP,
    *,
    default_artifact_root: Path,
    sensitive_paths: list[Path],
    admission: AdmissionService,
    target_boot_handler: TargetBootHandler,
) -> None:
    default_artifact_root_text = str(default_artifact_root)

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
            artifact_root=Path(context_model.artifact_root or default_artifact_root_text),
            run_id=context_model.run_id,
            target_profile=profiles_model.target_profile,
            rootfs_profile=profiles_model.rootfs_profile,
            force_reboot=options_model.force_reboot,
            boot_overrides=resolved_boot_overrides,
            acknowledged_permissions=options_model.acknowledged_permissions,
            sensitive_paths=sensitive_paths,
            admission=admission,
        ).model_dump(mode="json")
