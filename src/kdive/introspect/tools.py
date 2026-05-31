from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.domain import (
    DebugIntrospectCheckPrerequisitesRequest,
    DebugIntrospectFromVmcoreHelperRequest,
    DebugIntrospectFromVmcoreRequest,
    DebugIntrospectHelperRequest,
    DebugIntrospectRunRequest,
    ToolResponse,
)

IntrospectHandler = Callable[..., ToolResponse]


def register_introspect_tools(
    app: FastMCP,
    *,
    default_artifact_root: Path,
    admission: AdmissionService,
    session_registry: SessionRegistry,
    run_handler: IntrospectHandler,
    helper_handler: IntrospectHandler,
    check_prereqs_handler: IntrospectHandler,
    from_vmcore_handler: IntrospectHandler,
    from_vmcore_helper_handler: IntrospectHandler,
) -> None:
    default_artifact_root_text = str(default_artifact_root)

    @app.tool(name="debug.introspect.run")
    def debug_introspect_run(
        run_id: str,
        target_ref: str,
        script: str,
        artifact_root: str = default_artifact_root_text,
        timeout_seconds: int = 30,
        allow_write: bool = False,
        acknowledged_permissions: list[str] | None = None,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
        args: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        request = DebugIntrospectRunRequest(
            run_id=run_id,
            manifest_target_profile=target_ref,
            script=script,
            timeout_seconds=timeout_seconds,
            allow_write=allow_write,
            acknowledged_permissions=acknowledged_permissions or [],
            debug_profile=debug_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            args=args or {},
        )
        return run_handler(
            request,
            artifact_root=Path(artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.helper")
    def debug_introspect_helper(
        run_id: str,
        target_ref: str,
        name: str,
        args: dict[str, Any] | None = None,
        artifact_root: str = default_artifact_root_text,
        timeout_seconds: int = 30,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugIntrospectHelperRequest(
            run_id=run_id,
            manifest_target_profile=target_ref,
            name=name,
            args=args or {},
            timeout_seconds=timeout_seconds,
            debug_profile=debug_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
        )
        return helper_handler(
            request,
            artifact_root=Path(artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.check_prerequisites")
    def debug_introspect_check_prerequisites(
        run_id: str,
        target_ref: str,
        artifact_root: str = default_artifact_root_text,
        timeout_seconds: int = 20,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugIntrospectCheckPrerequisitesRequest(
            run_id=run_id,
            manifest_target_profile=target_ref,
            timeout_seconds=timeout_seconds,
            debug_profile=debug_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
        )
        return check_prereqs_handler(
            request,
            artifact_root=Path(artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.from_vmcore")
    def debug_introspect_from_vmcore(
        run_id: str,
        vmcore_ref: str,
        vmlinux_ref: str,
        script: str,
        modules_ref: str | None = None,
        artifact_root: str = default_artifact_root_text,
        timeout_seconds: int = 30,
        allow_write: bool = False,
        args: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        request = DebugIntrospectFromVmcoreRequest(
            run_id=run_id,
            vmcore_ref=vmcore_ref,
            vmlinux_ref=vmlinux_ref,
            script=script,
            modules_ref=modules_ref,
            timeout_seconds=timeout_seconds,
            allow_write=allow_write,
            args=args or {},
        )
        return from_vmcore_handler(
            request,
            artifact_root=Path(artifact_root),
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.from_vmcore_helper")
    def debug_introspect_from_vmcore_helper(
        run_id: str,
        vmcore_ref: str,
        vmlinux_ref: str,
        name: str,
        modules_ref: str | None = None,
        args: dict[str, Any] | None = None,
        artifact_root: str = default_artifact_root_text,
        timeout_seconds: int = 30,
    ) -> dict[str, Any]:
        request = DebugIntrospectFromVmcoreHelperRequest(
            run_id=run_id,
            vmcore_ref=vmcore_ref,
            vmlinux_ref=vmlinux_ref,
            name=name,
            modules_ref=modules_ref,
            args=args or {},
            timeout_seconds=timeout_seconds,
        )
        return from_vmcore_helper_handler(
            request,
            artifact_root=Path(artifact_root),
        ).model_dump(mode="json")
