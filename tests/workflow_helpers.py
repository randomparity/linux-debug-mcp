from __future__ import annotations

from pathlib import Path
from typing import Any

from kdive.debug.tools import DebugStartSessionRequest
from kdive.domain import ToolResponse
from kdive.kernel.tools import CreateRunHandlerRequest, KernelBuildHandlerRequest
from kdive.target.tools import TargetBootHandlerRequest, TargetRunTestsHandlerRequest
from kdive.workflow.contracts import (
    WorkflowBuildBootDebugHandlerRequest,
    WorkflowBuildBootTestHandlerRequest,
    WorkflowHandlerDependencies,
    WorkflowToolRuntime,
)


def direct_workflow_dependencies(
    *,
    create_run,
    kernel_build,
    target_boot,
    target_run_tests,
    debug_start,
    artifacts_collect,
) -> WorkflowHandlerDependencies:
    def create_run_call(*, request: CreateRunHandlerRequest, runtime: Any) -> ToolResponse:
        return create_run(
            artifact_root=request.artifact_root,
            source_path=request.source_path,
            build_profile=request.build_profile,
            target_profile=request.target_profile,
            rootfs_profile=request.rootfs_profile,
            run_id=request.run_id,
            debug_profile=request.debug_profile,
            test_suite=request.test_suite,
            build_overrides=request.build_overrides,
            boot_overrides=request.boot_overrides,
            sensitive_paths=runtime.sensitive_paths,
            build_profile_spec=request.build_profile_spec,
            target_profile_spec=request.target_profile_spec,
            rootfs_profile_spec=request.rootfs_profile_spec,
        )

    def kernel_build_call(*, request: KernelBuildHandlerRequest, runtime: Any) -> ToolResponse:
        return kernel_build(
            artifact_root=request.artifact_root,
            run_id=request.run_id,
            build_profile=request.build_profile,
            force_rebuild=request.force_rebuild,
        )

    def target_boot_call(*, request: TargetBootHandlerRequest, runtime: Any) -> ToolResponse:
        return target_boot(
            artifact_root=request.artifact_root,
            run_id=request.run_id,
            target_profile=request.target_profile,
            rootfs_profile=request.rootfs_profile,
            force_reboot=request.force_reboot,
            boot_overrides=request.boot_overrides,
            acknowledged_permissions=request.acknowledged_permissions,
            sensitive_paths=runtime.sensitive_paths,
            admission=runtime.admission,
        )

    def target_run_tests_call(*, request: TargetRunTestsHandlerRequest, runtime: Any) -> ToolResponse:
        return target_run_tests(
            artifact_root=request.artifact_root,
            run_id=request.run_id,
            test_suite=request.test_suite,
            commands=request.commands,
            force_rerun=request.force_rerun,
            attempt=request.attempt,
            acknowledged_permissions=request.acknowledged_permissions,
            admission=runtime.admission,
            session_registry=runtime.session_registry,
        )

    def debug_start_call(*, request: DebugStartSessionRequest, runtime: Any) -> ToolResponse:
        return debug_start(
            artifact_root=request.artifact_root,
            run_id=request.run_id,
            debug_profile=request.debug_profile,
            new_session=request.new_session,
            transaction=runtime.transaction,
            admission=runtime.admission,
            session_registry=runtime.session_registry,
            session_guard=runtime.session_guard,
            gdb_mi_engine=runtime.gdb_mi_engine,
            gdb_mi_sessions=runtime.gdb_mi_sessions,
        )

    return WorkflowHandlerDependencies(
        create_run_handler=create_run_call,
        kernel_build_handler=kernel_build_call,
        target_boot_handler=target_boot_call,
        target_run_tests_handler=target_run_tests_call,
        debug_start_session_handler=debug_start_call,
        artifacts_collect_handler=artifacts_collect,
    )


def workflow_runtime(
    *,
    dependencies: WorkflowHandlerDependencies,
    sensitive_paths: list[Path] | None = None,
    admission: Any = None,
    session_registry: Any = None,
    transaction: Any = None,
    session_guard: Any = None,
    gdb_mi_engine: Any = None,
    gdb_mi_sessions: Any = None,
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
