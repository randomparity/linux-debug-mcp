from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP

from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.domain import ToolResponse
from kdive.introspect.execution import LiveIntrospectRuntime
from kdive.introspect.models import (
    DebugIntrospectCheckPrerequisitesRequest,
    DebugIntrospectFromVmcoreHelperRequest,
    DebugIntrospectFromVmcoreRequest,
    DebugIntrospectHelperRequest,
    DebugIntrospectRunRequest,
)
from kdive.model import Model
from kdive.tools.adapter_boundary import adapter_validation_failure, model_arg, optional_model_arg


class IntrospectTargetContext(Model):
    run_id: str
    manifest_target_profile: str
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
    run_id: str
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
        runtime: LiveIntrospectRuntime,
    ) -> ToolResponse: ...


class IntrospectHelperHandler(Protocol):
    def __call__(
        self,
        request: DebugIntrospectHelperRequest,
        *,
        runtime: LiveIntrospectRuntime,
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

    def live_runtime(value: str | None) -> LiveIntrospectRuntime:
        return LiveIntrospectRuntime(
            artifact_root=artifact_root_path(value),
            admission=admission,
            session_registry=session_registry,
        )

    @app.tool(name="debug.introspect.run")
    def debug_introspect_run(
        target: IntrospectTargetContext | dict[str, Any],
        script: str,
        options: IntrospectRunOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            target_model = model_arg(target, IntrospectTargetContext)
            options_model = optional_model_arg(options, IntrospectRunOptions)
            request = DebugIntrospectRunRequest(
                run_id=target_model.run_id,
                manifest_target_profile=target_model.manifest_target_profile,
                script=script,
                timeout_seconds=options_model.timeout_seconds,
                allow_write=options_model.allow_write,
                acknowledged_permissions=options_model.acknowledged_permissions or [],
                debug_profile=target_model.debug_profile,
                target_profile=target_model.target_profile,
                rootfs_profile=target_model.rootfs_profile,
                args=options_model.args or {},
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return run_handler(
            request,
            runtime=live_runtime(target_model.artifact_root),
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.helper")
    def debug_introspect_helper(
        target: IntrospectTargetContext | dict[str, Any],
        name: str,
        options: IntrospectHelperOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            target_model = model_arg(target, IntrospectTargetContext)
            options_model = optional_model_arg(options, IntrospectHelperOptions)
            request = DebugIntrospectHelperRequest(
                run_id=target_model.run_id,
                manifest_target_profile=target_model.manifest_target_profile,
                name=name,
                args=options_model.args or {},
                timeout_seconds=options_model.timeout_seconds,
                debug_profile=target_model.debug_profile,
                target_profile=target_model.target_profile,
                rootfs_profile=target_model.rootfs_profile,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return helper_handler(
            request,
            runtime=live_runtime(target_model.artifact_root),
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.check_prerequisites")
    def debug_introspect_check_prerequisites(
        target: IntrospectTargetContext | dict[str, Any],
        options: IntrospectProbeOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            target_model = model_arg(target, IntrospectTargetContext)
            options_model = optional_model_arg(options, IntrospectProbeOptions)
            request = DebugIntrospectCheckPrerequisitesRequest(
                run_id=target_model.run_id,
                manifest_target_profile=target_model.manifest_target_profile,
                timeout_seconds=options_model.timeout_seconds,
                debug_profile=target_model.debug_profile,
                target_profile=target_model.target_profile,
                rootfs_profile=target_model.rootfs_profile,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return check_prereqs_handler(
            request,
            artifact_root=artifact_root_path(target_model.artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.from_vmcore")
    def debug_introspect_from_vmcore(
        vmcore: VmcoreIntrospectInputs | dict[str, Any],
        script: str,
        options: VmcoreIntrospectRunOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            vmcore_model = model_arg(vmcore, VmcoreIntrospectInputs)
            options_model = optional_model_arg(options, VmcoreIntrospectRunOptions)
            request = DebugIntrospectFromVmcoreRequest(
                run_id=vmcore_model.run_id,
                vmcore_ref=vmcore_model.vmcore_ref,
                vmlinux_ref=vmcore_model.vmlinux_ref,
                script=script,
                modules_ref=vmcore_model.modules_ref,
                timeout_seconds=options_model.timeout_seconds,
                allow_write=options_model.allow_write,
                args=options_model.args or {},
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return from_vmcore_handler(
            request,
            artifact_root=artifact_root_path(vmcore_model.artifact_root),
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.from_vmcore_helper")
    def debug_introspect_from_vmcore_helper(
        vmcore: VmcoreIntrospectInputs | dict[str, Any],
        name: str,
        options: VmcoreIntrospectHelperOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            vmcore_model = model_arg(vmcore, VmcoreIntrospectInputs)
            options_model = optional_model_arg(options, VmcoreIntrospectHelperOptions)
            request = DebugIntrospectFromVmcoreHelperRequest(
                run_id=vmcore_model.run_id,
                vmcore_ref=vmcore_model.vmcore_ref,
                vmlinux_ref=vmcore_model.vmlinux_ref,
                name=name,
                modules_ref=vmcore_model.modules_ref,
                args=options_model.args or {},
                timeout_seconds=options_model.timeout_seconds,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return from_vmcore_helper_handler(
            request,
            artifact_root=artifact_root_path(vmcore_model.artifact_root),
        ).model_dump(mode="json")
