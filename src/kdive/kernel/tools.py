from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from kdive.config import BootOverrides, BuildOverrides
from kdive.domain import ToolResponse
from kdive.model import Model
from kdive.tools.adapter_boundary import adapter_validation_failure, model_arg, optional_model_arg


class CreateRunHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        source_path: str,
        build_profile: str | None,
        target_profile: str | None,
        rootfs_profile: str | None,
        run_id: str | None,
        debug_profile: str | None,
        test_suite: str | None,
        build_overrides: BuildOverrides | None,
        boot_overrides: BootOverrides | None,
        sensitive_paths: list[Path] | None,
        build_profile_spec: dict[str, Any] | None,
        target_profile_spec: dict[str, Any] | None,
        rootfs_profile_spec: dict[str, Any] | None,
    ) -> ToolResponse: ...


class CreateRunProfiles(Model):
    source_path: str
    build_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class CreateRunContext(Model):
    artifact_root: str | None = None
    run_id: str | None = None


class CreateRunOptions(Model):
    debug_profile: str | None = None
    test_suite: str | None = None
    build_overrides: dict[str, Any] | None = None
    boot_overrides: dict[str, Any] | None = None
    profile_specs: dict[str, dict[str, Any]] | None = None


CreateRunToolShapes = tuple[
    BuildOverrides | None,
    BootOverrides | None,
    dict[str, Any] | None,
    dict[str, Any] | None,
    dict[str, Any] | None,
]


def create_run_shapes_from_tool_args(
    *,
    build_overrides: dict[str, Any] | None,
    boot_overrides: dict[str, Any] | None,
    profile_specs: dict[str, dict[str, Any]] | None,
) -> CreateRunToolShapes:
    specs = profile_specs or {}
    unknown_specs = set(specs) - {"build", "target", "rootfs"}
    if unknown_specs:
        raise ValueError(f"unknown profile_specs keys: {', '.join(sorted(unknown_specs))}")
    return (
        BuildOverrides(**build_overrides) if build_overrides else None,
        BootOverrides(**boot_overrides) if boot_overrides else None,
        specs.get("build"),
        specs.get("target"),
        specs.get("rootfs"),
    )


def register_kernel_tools(
    app: FastMCP,
    *,
    default_artifact_root: Path,
    sensitive_paths: list[Path],
    create_run_handler: CreateRunHandler,
) -> None:
    default_artifact_root_text = str(default_artifact_root)

    @app.tool(name="kernel.create_run")
    def kernel_create_run(
        profiles: CreateRunProfiles | dict[str, Any],
        context: CreateRunContext | dict[str, Any] | None = None,
        options: CreateRunOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            profiles_model = model_arg(profiles, CreateRunProfiles)
            context_model = optional_model_arg(context, CreateRunContext)
            options_model = optional_model_arg(options, CreateRunOptions)
            resolved_build_overrides, resolved_boot_overrides, build_spec, target_spec, rootfs_spec = (
                create_run_shapes_from_tool_args(
                    build_overrides=options_model.build_overrides,
                    boot_overrides=options_model.boot_overrides,
                    profile_specs=options_model.profile_specs,
                )
            )
        except (TypeError, ValueError, ValidationError) as exc:
            return adapter_validation_failure(exc)
        return create_run_handler(
            artifact_root=Path(context_model.artifact_root or default_artifact_root_text),
            source_path=profiles_model.source_path,
            build_profile=profiles_model.build_profile,
            target_profile=profiles_model.target_profile,
            rootfs_profile=profiles_model.rootfs_profile,
            run_id=context_model.run_id,
            debug_profile=options_model.debug_profile,
            test_suite=options_model.test_suite,
            build_overrides=resolved_build_overrides,
            boot_overrides=resolved_boot_overrides,
            sensitive_paths=sensitive_paths,
            build_profile_spec=build_spec,
            target_profile_spec=target_spec,
            rootfs_profile_spec=rootfs_spec,
        ).model_dump(mode="json")
