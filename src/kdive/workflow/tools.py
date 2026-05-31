from __future__ import annotations

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


class BuildBootTestHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        source_path: str,
        build_profile: str,
        target_profile: str,
        rootfs_profile: str,
        run_id: str | None,
        test_suite: str | None,
        commands: list[list[str]] | None,
        force_rebuild: bool,
        force_reboot: bool,
        force_rerun_tests: bool,
        force_recollect: bool,
        acknowledged_permissions: list[str] | None,
        admission: AdmissionService,
        session_registry: SessionRegistry,
    ) -> ToolResponse: ...


class BuildBootDebugHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        source_path: str,
        build_profile: str,
        target_profile: str,
        rootfs_profile: str,
        run_id: str | None,
        debug_profile: str | None,
        force_rebuild: bool,
        force_reboot: bool,
        new_session: bool,
        acknowledged_permissions: list[str] | None,
        admission: AdmissionService,
        session_registry: SessionRegistry,
        transaction: TransportTransaction,
        session_guard: SessionGuard,
        gdb_mi_engine: GdbMiEngine,
        gdb_mi_sessions: GdbMiSessionRegistry,
    ) -> ToolResponse: ...


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
    build_boot_test_handler: BuildBootTestHandler,
    build_boot_debug_handler: BuildBootDebugHandler,
) -> None:
    default_artifact_root_text = str(default_artifact_root)

    @app.tool(name="workflow.build_boot_test")
    def workflow_build_boot_test(
        profiles: WorkflowProfileInputs,
        context: WorkflowRunContext | None = None,
        options: WorkflowBuildBootTestOptions | None = None,
    ) -> dict[str, Any]:
        context = context or WorkflowRunContext()
        options = options or WorkflowBuildBootTestOptions()
        return build_boot_test_handler(
            artifact_root=Path(context.artifact_root or default_artifact_root_text),
            source_path=profiles.source_path,
            build_profile=profiles.build_profile,
            target_profile=profiles.target_profile,
            rootfs_profile=profiles.rootfs_profile,
            run_id=context.run_id,
            test_suite=options.test_suite,
            commands=options.commands,
            force_rebuild=options.force_rebuild,
            force_reboot=options.force_reboot,
            force_rerun_tests=options.force_rerun_tests,
            force_recollect=options.force_recollect,
            acknowledged_permissions=options.acknowledged_permissions,
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")

    @app.tool(name="workflow.build_boot_debug")
    def workflow_build_boot_debug(
        profiles: WorkflowProfileInputs,
        context: WorkflowRunContext | None = None,
        options: WorkflowBuildBootDebugOptions | None = None,
    ) -> dict[str, Any]:
        context = context or WorkflowRunContext()
        options = options or WorkflowBuildBootDebugOptions()
        return build_boot_debug_handler(
            artifact_root=Path(context.artifact_root or default_artifact_root_text),
            source_path=profiles.source_path,
            build_profile=profiles.build_profile,
            target_profile=profiles.target_profile,
            rootfs_profile=profiles.rootfs_profile,
            run_id=context.run_id,
            debug_profile=options.debug_profile,
            force_rebuild=options.force_rebuild,
            force_reboot=options.force_reboot,
            new_session=options.new_session,
            acknowledged_permissions=options.acknowledged_permissions,
            admission=admission,
            session_registry=session_registry,
            transaction=transaction,
            session_guard=session_guard,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")
