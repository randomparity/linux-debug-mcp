from __future__ import annotations

from pathlib import Path
from typing import Any

from kdive.domain import ToolResponse
from kdive.workflow.handlers import WorkflowHandlerDependencies
from kdive.workflow.tools import (
    WorkflowBuildBootDebugHandlerRequest,
    WorkflowBuildBootTestHandlerRequest,
    WorkflowToolRuntime,
)


def workflow_runtime(
    *,
    dependencies: WorkflowHandlerDependencies,
    sensitive_paths: list[Path] | None = None,
    admission: object | None = None,
    session_registry: object | None = None,
    transaction: object | None = None,
    session_guard: object | None = None,
    gdb_mi_engine: object | None = None,
    gdb_mi_sessions: object | None = None,
) -> WorkflowToolRuntime:
    return WorkflowToolRuntime(
        sensitive_paths=sensitive_paths or [],
        admission=admission,
        session_registry=session_registry,
        transaction=transaction,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
        dependencies=dependencies,
    )


def build_boot_test_request(
    *,
    artifact_root: Path,
    source_path: str,
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    run_id: str | None = None,
    test_suite: str | None = None,
    commands: list[list[str]] | None = None,
    force_rebuild: bool = False,
    force_reboot: bool = False,
    force_rerun_tests: bool = False,
    force_recollect: bool = False,
    build_overrides: Any | None = None,
    boot_overrides: Any | None = None,
    build_profile_spec: dict[str, Any] | None = None,
    target_profile_spec: dict[str, Any] | None = None,
    rootfs_profile_spec: dict[str, Any] | None = None,
    acknowledged_permissions: list[str] | None = None,
) -> WorkflowBuildBootTestHandlerRequest:
    return WorkflowBuildBootTestHandlerRequest(
        artifact_root=artifact_root,
        source_path=source_path,
        build_profile=build_profile,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        run_id=run_id,
        test_suite=test_suite,
        commands=commands,
        force_rebuild=force_rebuild,
        force_reboot=force_reboot,
        force_rerun_tests=force_rerun_tests,
        force_recollect=force_recollect,
        build_overrides=build_overrides,
        boot_overrides=boot_overrides,
        build_profile_spec=build_profile_spec,
        target_profile_spec=target_profile_spec,
        rootfs_profile_spec=rootfs_profile_spec,
        acknowledged_permissions=acknowledged_permissions,
    )


def build_boot_debug_request(
    *,
    artifact_root: Path,
    source_path: str,
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    run_id: str | None = None,
    debug_profile: str | None = None,
    force_rebuild: bool = False,
    force_reboot: bool = False,
    new_session: bool = False,
    build_overrides: Any | None = None,
    boot_overrides: Any | None = None,
    build_profile_spec: dict[str, Any] | None = None,
    target_profile_spec: dict[str, Any] | None = None,
    rootfs_profile_spec: dict[str, Any] | None = None,
    acknowledged_permissions: list[str] | None = None,
) -> WorkflowBuildBootDebugHandlerRequest:
    return WorkflowBuildBootDebugHandlerRequest(
        artifact_root=artifact_root,
        source_path=source_path,
        build_profile=build_profile,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        run_id=run_id,
        debug_profile=debug_profile,
        force_rebuild=force_rebuild,
        force_reboot=force_reboot,
        new_session=new_session,
        build_overrides=build_overrides,
        boot_overrides=boot_overrides,
        build_profile_spec=build_profile_spec,
        target_profile_spec=target_profile_spec,
        rootfs_profile_spec=rootfs_profile_spec,
        acknowledged_permissions=acknowledged_permissions,
    )


def call_workflow_build_boot_test_handler(handler, **kwargs: Any) -> ToolResponse:
    dependencies = kwargs.pop("dependencies")
    runtime = workflow_runtime(
        dependencies=dependencies,
        sensitive_paths=kwargs.pop("sensitive_paths", None),
        admission=kwargs.pop("admission", None),
        session_registry=kwargs.pop("session_registry", None),
    )
    return handler(request=build_boot_test_request(**kwargs), runtime=runtime)


def call_workflow_build_boot_debug_handler(handler, **kwargs: Any) -> ToolResponse:
    dependencies = kwargs.pop("dependencies")
    runtime = workflow_runtime(
        dependencies=dependencies,
        sensitive_paths=kwargs.pop("sensitive_paths", None),
        admission=kwargs.pop("admission", None),
        session_registry=kwargs.pop("session_registry", None),
        transaction=kwargs.pop("transaction", None),
        session_guard=kwargs.pop("session_guard", None),
        gdb_mi_engine=kwargs.pop("gdb_mi_engine", None),
        gdb_mi_sessions=kwargs.pop("gdb_mi_sessions", None),
    )
    return handler(request=build_boot_debug_request(**kwargs), runtime=runtime)
