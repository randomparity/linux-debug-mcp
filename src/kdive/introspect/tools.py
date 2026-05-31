from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

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
from kdive.model import Model


class IntrospectTargetContext(Model):
    target_ref: str
    artifact_root: str | None = None
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class IntrospectRunOptions(Model):
    timeout_seconds: int = 30
    allow_write: bool = False
    acknowledged_permissions: list[str] | None = None
    args: dict[str, Any] | None = None


class IntrospectHelperOptions(Model):
    timeout_seconds: int = 30
    args: dict[str, Any] | None = None


class IntrospectProbeOptions(Model):
    timeout_seconds: int = 20


class VmcoreIntrospectInputs(Model):
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    artifact_root: str | None = None


class VmcoreIntrospectRunOptions(Model):
    timeout_seconds: int = 30
    allow_write: bool = False
    args: dict[str, Any] | None = None


class VmcoreIntrospectHelperOptions(Model):
    timeout_seconds: int = 30
    args: dict[str, Any] | None = None


class IntrospectRunHandler(Protocol):
    def __call__(
        self,
        request: DebugIntrospectRunRequest,
        *,
        artifact_root: Path,
        admission: AdmissionService,
        session_registry: SessionRegistry,
    ) -> ToolResponse: ...


class IntrospectHelperHandler(Protocol):
    def __call__(
        self,
        request: DebugIntrospectHelperRequest,
        *,
        artifact_root: Path,
        admission: AdmissionService,
        session_registry: SessionRegistry,
    ) -> ToolResponse: ...


class IntrospectCheckPrereqsHandler(Protocol):
    def __call__(
        self,
        request: DebugIntrospectCheckPrerequisitesRequest,
        *,
        artifact_root: Path,
        admission: AdmissionService,
        session_registry: SessionRegistry,
    ) -> ToolResponse: ...


class VmcoreIntrospectRunHandler(Protocol):
    def __call__(
        self,
        request: DebugIntrospectFromVmcoreRequest,
        *,
        artifact_root: Path,
    ) -> ToolResponse: ...


class VmcoreIntrospectHelperHandler(Protocol):
    def __call__(
        self,
        request: DebugIntrospectFromVmcoreHelperRequest,
        *,
        artifact_root: Path,
    ) -> ToolResponse: ...


def register_introspect_tools(
    app: FastMCP,
    *,
    default_artifact_root: Path,
    admission: AdmissionService,
    session_registry: SessionRegistry,
    run_handler: IntrospectRunHandler,
    helper_handler: IntrospectHelperHandler,
    check_prereqs_handler: IntrospectCheckPrereqsHandler,
    from_vmcore_handler: VmcoreIntrospectRunHandler,
    from_vmcore_helper_handler: VmcoreIntrospectHelperHandler,
) -> None:
    default_artifact_root_text = str(default_artifact_root)

    def artifact_root_path(value: str | None) -> Path:
        return Path(value or default_artifact_root_text)

    @app.tool(name="debug.introspect.run")
    def debug_introspect_run(
        run_id: str,
        target: IntrospectTargetContext,
        script: str,
        options: IntrospectRunOptions | None = None,
    ) -> dict[str, Any]:
        options = options or IntrospectRunOptions()
        request = DebugIntrospectRunRequest(
            run_id=run_id,
            manifest_target_profile=target.target_ref,
            script=script,
            timeout_seconds=options.timeout_seconds,
            allow_write=options.allow_write,
            acknowledged_permissions=options.acknowledged_permissions or [],
            debug_profile=target.debug_profile,
            target_profile=target.target_profile,
            rootfs_profile=target.rootfs_profile,
            args=options.args or {},
        )
        return run_handler(
            request,
            artifact_root=artifact_root_path(target.artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.helper")
    def debug_introspect_helper(
        run_id: str,
        target: IntrospectTargetContext,
        name: str,
        options: IntrospectHelperOptions | None = None,
    ) -> dict[str, Any]:
        options = options or IntrospectHelperOptions()
        request = DebugIntrospectHelperRequest(
            run_id=run_id,
            manifest_target_profile=target.target_ref,
            name=name,
            args=options.args or {},
            timeout_seconds=options.timeout_seconds,
            debug_profile=target.debug_profile,
            target_profile=target.target_profile,
            rootfs_profile=target.rootfs_profile,
        )
        return helper_handler(
            request,
            artifact_root=artifact_root_path(target.artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.check_prerequisites")
    def debug_introspect_check_prerequisites(
        run_id: str,
        target: IntrospectTargetContext,
        options: IntrospectProbeOptions | None = None,
    ) -> dict[str, Any]:
        options = options or IntrospectProbeOptions()
        request = DebugIntrospectCheckPrerequisitesRequest(
            run_id=run_id,
            manifest_target_profile=target.target_ref,
            timeout_seconds=options.timeout_seconds,
            debug_profile=target.debug_profile,
            target_profile=target.target_profile,
            rootfs_profile=target.rootfs_profile,
        )
        return check_prereqs_handler(
            request,
            artifact_root=artifact_root_path(target.artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.from_vmcore")
    def debug_introspect_from_vmcore(
        run_id: str,
        vmcore: VmcoreIntrospectInputs,
        script: str,
        options: VmcoreIntrospectRunOptions | None = None,
    ) -> dict[str, Any]:
        options = options or VmcoreIntrospectRunOptions()
        request = DebugIntrospectFromVmcoreRequest(
            run_id=run_id,
            vmcore_ref=vmcore.vmcore_ref,
            vmlinux_ref=vmcore.vmlinux_ref,
            script=script,
            modules_ref=vmcore.modules_ref,
            timeout_seconds=options.timeout_seconds,
            allow_write=options.allow_write,
            args=options.args or {},
        )
        return from_vmcore_handler(
            request,
            artifact_root=artifact_root_path(vmcore.artifact_root),
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.from_vmcore_helper")
    def debug_introspect_from_vmcore_helper(
        run_id: str,
        vmcore: VmcoreIntrospectInputs,
        name: str,
        options: VmcoreIntrospectHelperOptions | None = None,
    ) -> dict[str, Any]:
        options = options or VmcoreIntrospectHelperOptions()
        request = DebugIntrospectFromVmcoreHelperRequest(
            run_id=run_id,
            vmcore_ref=vmcore.vmcore_ref,
            vmlinux_ref=vmcore.vmlinux_ref,
            name=name,
            modules_ref=vmcore.modules_ref,
            args=options.args or {},
            timeout_seconds=options.timeout_seconds,
        )
        return from_vmcore_helper_handler(
            request,
            artifact_root=artifact_root_path(vmcore.artifact_root),
        ).model_dump(mode="json")
