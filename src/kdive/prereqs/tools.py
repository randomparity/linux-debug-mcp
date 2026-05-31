from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from kdive.domain import ToolResponse
from kdive.model import Model
from kdive.tools.adapter_boundary import adapter_validation_failure, optional_model_arg


class HostPrerequisitesHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        source_path: str | None,
        enable_libvirt_check: bool,
        build_profile: str | None,
        target_profile: str | None,
        rootfs_profile: str | None,
    ) -> ToolResponse: ...


class HostPrerequisitesContext(Model):
    artifact_root: str | None = None


class HostPrerequisitesProfiles(Model):
    build_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class HostPrerequisitesOptions(Model):
    source_path: str | None = None
    enable_libvirt_check: bool = False


def register_prereq_tools(
    app: FastMCP,
    *,
    default_artifact_root: Path,
    prerequisites_handler: HostPrerequisitesHandler,
) -> None:
    default_artifact_root_text = str(default_artifact_root)

    @app.tool(name="host.check_prerequisites")
    def host_check_prerequisites(
        context: HostPrerequisitesContext | dict[str, Any] | None = None,
        profiles: HostPrerequisitesProfiles | dict[str, Any] | None = None,
        options: HostPrerequisitesOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            context_model = optional_model_arg(context, HostPrerequisitesContext)
            profiles_model = optional_model_arg(profiles, HostPrerequisitesProfiles)
            options_model = optional_model_arg(options, HostPrerequisitesOptions)
        except (TypeError, ValueError, ValidationError) as exc:
            return adapter_validation_failure(exc)
        return prerequisites_handler(
            artifact_root=Path(context_model.artifact_root or default_artifact_root_text),
            source_path=options_model.source_path,
            enable_libvirt_check=options_model.enable_libvirt_check,
            build_profile=profiles_model.build_profile,
            target_profile=profiles_model.target_profile,
            rootfs_profile=profiles_model.rootfs_profile,
        ).model_dump(mode="json")
