from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP

from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ToolResponse
from kdive.model import Model
from kdive.providers.debug import GdbMiEngine, GdbMiSessionRegistry
from kdive.seams.guard import SessionGuard
from kdive.tools.adapter_boundary import adapter_validation_failure, model_arg, optional_model_arg
from kdive.workflow.handlers import WorkflowHandlerDependencies


class BuildBootTestHandler(Protocol):
    def __call__(
        self, *, request: WorkflowBuildBootTestHandlerRequest, runtime: WorkflowToolRuntime
    ) -> ToolResponse: ...


class BuildBootDebugHandler(Protocol):
    def __call__(
        self, *, request: WorkflowBuildBootDebugHandlerRequest, runtime: WorkflowToolRuntime
    ) -> ToolResponse: ...


@dataclass(frozen=True)
class WorkflowToolRuntime:
    admission: AdmissionService
    session_registry: SessionRegistry
    transaction: TransportTransaction
    session_guard: SessionGuard
    gdb_mi_engine: GdbMiEngine
    gdb_mi_sessions: GdbMiSessionRegistry
    dependencies: WorkflowHandlerDependencies


@dataclass(frozen=True)
class WorkflowBuildBootTestHandlerRequest:
    artifact_root: Path
    source_path: str
    build_profile: str
    target_profile: str
    rootfs_profile: str
    run_id: str | None
    test_suite: str | None
    commands: list[list[str]] | None
    force_rebuild: bool
    force_reboot: bool
    force_rerun_tests: bool
    force_recollect: bool
    acknowledged_permissions: list[str] | None


@dataclass(frozen=True)
class WorkflowBuildBootDebugHandlerRequest:
    artifact_root: Path
    source_path: str
    build_profile: str
    target_profile: str
    rootfs_profile: str
    run_id: str | None
    debug_profile: str | None
    force_rebuild: bool
    force_reboot: bool
    new_session: bool
    acknowledged_permissions: list[str] | None


class WorkflowRunContext(Model):
    artifact_root: str | None = None
    run_id: str | None = None


class WorkflowProfileInputs(Model):
    source_path: str
    build_profile: str
    target_profile: str
    rootfs_profile: str


class WorkflowBuildBootTestOptions(Model):
    test_suite: str | None = None
    commands: list[list[str]] | None = None
    force_rebuild: bool = False
    force_reboot: bool = False
    force_rerun_tests: bool = False
    force_recollect: bool = False
    acknowledged_permissions: list[str] | None = None


class WorkflowBuildBootDebugOptions(Model):
    debug_profile: str | None = None
    force_rebuild: bool = False
    force_reboot: bool = False
    new_session: bool = False
    acknowledged_permissions: list[str] | None = None


def register_workflow_tools(
    app: FastMCP,
    *,
    default_artifact_root: Path,
    admission: AdmissionService,
    session_registry: SessionRegistry,
    transaction: TransportTransaction,
    session_guard: SessionGuard,
    gdb_mi_engine: GdbMiEngine,
    gdb_mi_sessions: GdbMiSessionRegistry,
    dependencies: WorkflowHandlerDependencies,
    build_boot_test_handler: BuildBootTestHandler,
    build_boot_debug_handler: BuildBootDebugHandler,
) -> None:
    default_artifact_root_text = str(default_artifact_root)
    runtime = WorkflowToolRuntime(
        admission=admission,
        session_registry=session_registry,
        transaction=transaction,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
        dependencies=dependencies,
    )

    @app.tool(name="workflow.build_boot_test")
    def workflow_build_boot_test(
        context: WorkflowRunContext | dict[str, Any] | None = None,
        profiles: WorkflowProfileInputs | dict[str, Any] | None = None,
        options: WorkflowBuildBootTestOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            profiles_model = model_arg(profiles, WorkflowProfileInputs)
            context_model = optional_model_arg(context, WorkflowRunContext)
            options_model = optional_model_arg(options, WorkflowBuildBootTestOptions)
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return build_boot_test_handler(
            request=WorkflowBuildBootTestHandlerRequest(
                artifact_root=Path(context_model.artifact_root or default_artifact_root_text),
                source_path=profiles_model.source_path,
                build_profile=profiles_model.build_profile,
                target_profile=profiles_model.target_profile,
                rootfs_profile=profiles_model.rootfs_profile,
                run_id=context_model.run_id,
                test_suite=options_model.test_suite,
                commands=options_model.commands,
                force_rebuild=options_model.force_rebuild,
                force_reboot=options_model.force_reboot,
                force_rerun_tests=options_model.force_rerun_tests,
                force_recollect=options_model.force_recollect,
                acknowledged_permissions=options_model.acknowledged_permissions,
            ),
            runtime=runtime,
        ).model_dump(mode="json")

    @app.tool(name="workflow.build_boot_debug")
    def workflow_build_boot_debug(
        context: WorkflowRunContext | dict[str, Any] | None = None,
        profiles: WorkflowProfileInputs | dict[str, Any] | None = None,
        options: WorkflowBuildBootDebugOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            profiles_model = model_arg(profiles, WorkflowProfileInputs)
            context_model = optional_model_arg(context, WorkflowRunContext)
            options_model = optional_model_arg(options, WorkflowBuildBootDebugOptions)
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return build_boot_debug_handler(
            request=WorkflowBuildBootDebugHandlerRequest(
                artifact_root=Path(context_model.artifact_root or default_artifact_root_text),
                source_path=profiles_model.source_path,
                build_profile=profiles_model.build_profile,
                target_profile=profiles_model.target_profile,
                rootfs_profile=profiles_model.rootfs_profile,
                run_id=context_model.run_id,
                debug_profile=options_model.debug_profile,
                force_rebuild=options_model.force_rebuild,
                force_reboot=options_model.force_reboot,
                new_session=options_model.new_session,
                acknowledged_permissions=options_model.acknowledged_permissions,
            ),
            runtime=runtime,
        ).model_dump(mode="json")
