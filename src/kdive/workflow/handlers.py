from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from kdive.artifacts.manifest import RunManifest
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ErrorCategory, ToolResponse
from kdive.providers.debug import GdbMiEngine, GdbMiSessionRegistry
from kdive.safety.paths import PathSafetyError, validate_source_path
from kdive.seams.guard import SessionGuard


class CreateRunHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        source_path: str,
        build_profile: str,
        target_profile: str,
        rootfs_profile: str,
        run_id: str | None = None,
        debug_profile: str | None = None,
        test_suite: str | None = None,
    ) -> ToolResponse: ...


class KernelBuildHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        build_profile: str | None = None,
        force_rebuild: bool = False,
    ) -> ToolResponse: ...


class TargetBootHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
        force_reboot: bool = False,
        acknowledged_permissions: list[str] | None = None,
        admission: AdmissionService | None = None,
    ) -> ToolResponse: ...


class TargetRunTestsHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        test_suite: str | None = None,
        commands: list[list[str]] | None = None,
        force_rerun: bool = False,
        admission: AdmissionService | None = None,
        session_registry: SessionRegistry | None = None,
    ) -> ToolResponse: ...


class DebugStartSessionHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        debug_profile: str | None = None,
        new_session: bool = False,
        transaction: TransportTransaction | None = None,
        admission: AdmissionService | None = None,
        session_registry: SessionRegistry | None = None,
        session_guard: SessionGuard | None = None,
        gdb_mi_engine: GdbMiEngine | None = None,
        gdb_mi_sessions: GdbMiSessionRegistry | None = None,
    ) -> ToolResponse: ...


class ArtifactsCollectHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        force_recollect: bool = False,
    ) -> ToolResponse: ...


@dataclass(frozen=True)
class WorkflowHandlerDependencies:
    create_run_handler: CreateRunHandler
    kernel_build_handler: KernelBuildHandler
    target_boot_handler: TargetBootHandler
    target_run_tests_handler: TargetRunTestsHandler
    debug_start_session_handler: DebugStartSessionHandler
    artifacts_collect_handler: ArtifactsCollectHandler


@dataclass(frozen=True)
class _ExistingWorkflowRunValidation:
    manifest: RunManifest
    resolved_optional: str | None


@dataclass(frozen=True)
class _BuildBootWorkflowResult:
    run_id: str
    resolved_optional: str | None
    build_response: ToolResponse
    boot_response: ToolResponse


_WORKFLOW_DEPENDENCIES: WorkflowHandlerDependencies | None = None


def configure_workflow_dependencies(dependencies: WorkflowHandlerDependencies) -> None:
    global _WORKFLOW_DEPENDENCIES
    _WORKFLOW_DEPENDENCIES = dependencies


def configure_workflow_handlers(
    *,
    create_run_handler: CreateRunHandler,
    kernel_build_handler: KernelBuildHandler,
    target_boot_handler: TargetBootHandler,
    target_run_tests_handler: TargetRunTestsHandler,
    debug_start_session_handler: DebugStartSessionHandler,
    artifacts_collect_handler: ArtifactsCollectHandler,
) -> None:
    configure_workflow_dependencies(
        WorkflowHandlerDependencies(
            create_run_handler=create_run_handler,
            kernel_build_handler=kernel_build_handler,
            target_boot_handler=target_boot_handler,
            target_run_tests_handler=target_run_tests_handler,
            debug_start_session_handler=debug_start_session_handler,
            artifacts_collect_handler=artifacts_collect_handler,
        )
    )


def _workflow_dependencies() -> WorkflowHandlerDependencies:
    if _WORKFLOW_DEPENDENCIES is None:
        raise RuntimeError("workflow handler dependencies have not been configured")
    return _WORKFLOW_DEPENDENCIES


def _validate_existing_workflow_run_request(
    *,
    artifact_root: Path,
    run_id: str,
    source_path: str,
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    optional_field: Literal["test_suite", "debug_profile"],
    requested_optional: str | None,
    optional_policy: Literal["always", "when_manifest_set"],
) -> tuple[_ExistingWorkflowRunValidation | None, ToolResponse | None]:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return None, None
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return None, ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    manifest_optional = getattr(manifest.request, optional_field)
    resolved_optional = requested_optional if requested_optional is not None else manifest_optional
    try:
        resolved_source_path = str(validate_source_path(Path(source_path)))
    except PathSafetyError as exc:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
            run_id=run_id,
            details={"source_path": source_path},
        )

    expected = {
        "source_path": resolved_source_path,
        "build_profile": build_profile,
        "target_profile": target_profile,
        "rootfs_profile": rootfs_profile,
    }
    actual = {
        "source_path": manifest.request.source_path,
        "build_profile": manifest.request.build_profile,
        "target_profile": manifest.request.target_profile,
        "rootfs_profile": manifest.request.rootfs_profile,
    }
    include_optional = optional_policy == "always" or manifest_optional is not None
    if include_optional:
        expected[optional_field] = resolved_optional
        actual[optional_field] = manifest_optional

    mismatches = {
        key: {"requested": expected[key], "manifest": actual[key]} for key in expected if expected[key] != actual[key]
    }
    if mismatches:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="immutable run manifest request mismatch",
            run_id=run_id,
            details={"mismatches": mismatches},
        )
    return _ExistingWorkflowRunValidation(manifest=manifest, resolved_optional=resolved_optional), None


def _workflow_failure_response(
    *,
    run_id: str | None,
    failing_step: str,
    latest_successful_step: str | None,
    response: ToolResponse,
    collect_response: ToolResponse | None,
) -> ToolResponse:
    details = {
        "failing_step": failing_step,
        "latest_successful_step": latest_successful_step,
        "failed_response": response.model_dump(mode="json"),
        "collect_response": collect_response.model_dump(mode="json") if collect_response else None,
    }
    category = response.error.category if response.error else ErrorCategory.INFRASTRUCTURE_FAILURE
    message = response.error.message if response.error else response.summary or f"{failing_step} failed"
    failure_response = ToolResponse.failure(
        category=category,
        message=message,
        run_id=run_id,
        details=details,
        artifacts=[*(response.artifacts or []), *((collect_response.artifacts if collect_response else []) or [])],
        suggested_next_actions=["artifacts.get_manifest", "Inspect artifact bundle"],
    )
    failure_response.data = details
    return failure_response


def _pipeline_failure_collect_response(
    *,
    dependencies: WorkflowHandlerDependencies,
    artifact_root: Path,
    run_id: str,
    force_recollect: bool,
    collect_pipeline_failures: bool,
) -> ToolResponse | None:
    if not collect_pipeline_failures:
        return None
    return dependencies.artifacts_collect_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        force_recollect=force_recollect,
    )


def _require_pipeline(pipeline: _BuildBootWorkflowResult | None) -> _BuildBootWorkflowResult:
    if pipeline is None:
        raise RuntimeError("build/boot workflow returned neither result nor failure")
    return pipeline


def _run_build_boot_workflow(
    *,
    workflow_name: str,
    artifact_root: Path,
    source_path: str,
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    run_id: str | None,
    optional_field: Literal["test_suite", "debug_profile"],
    requested_optional: str | None,
    optional_policy: Literal["always", "when_manifest_set"],
    force_rebuild: bool,
    force_reboot: bool,
    force_recollect: bool,
    collect_pipeline_failures: bool,
    acknowledged_permissions: list[str] | None,
    admission: AdmissionService | None,
    dependencies: WorkflowHandlerDependencies,
) -> tuple[_BuildBootWorkflowResult | None, ToolResponse | None]:
    if run_id is not None:
        validation, validation_failure = _validate_existing_workflow_run_request(
            artifact_root=artifact_root,
            run_id=run_id,
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            optional_field=optional_field,
            requested_optional=requested_optional,
            optional_policy=optional_policy,
        )
        if validation_failure is not None:
            return None, validation_failure
        if validation is not None and (
            optional_field == "test_suite"
            or validation.manifest.request.debug_profile is not None
            or requested_optional is None
        ):
            requested_optional = validation.resolved_optional

    if run_id is None or not (artifact_root / run_id / "manifest.json").is_file():
        create_kwargs = {optional_field: requested_optional}
        create_response = dependencies.create_run_handler(
            artifact_root=artifact_root,
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            **create_kwargs,
        )
        if not create_response.ok:
            return None, create_response
        run_id = create_response.run_id
    if run_id is None:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=f"{workflow_name} could not establish a run_id",
        )

    build_response = dependencies.kernel_build_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        build_profile=build_profile,
        force_rebuild=force_rebuild,
    )
    if not build_response.ok:
        collect_response = _pipeline_failure_collect_response(
            dependencies=dependencies,
            artifact_root=artifact_root,
            run_id=run_id,
            force_recollect=force_recollect,
            collect_pipeline_failures=collect_pipeline_failures,
        )
        return None, _workflow_failure_response(
            run_id=run_id,
            failing_step="build",
            latest_successful_step=None,
            response=build_response,
            collect_response=collect_response,
        )

    boot_response = dependencies.target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        force_reboot=force_reboot,
        acknowledged_permissions=acknowledged_permissions,
        admission=admission,
    )
    if not boot_response.ok:
        collect_response = _pipeline_failure_collect_response(
            dependencies=dependencies,
            artifact_root=artifact_root,
            run_id=run_id,
            force_recollect=force_recollect,
            collect_pipeline_failures=collect_pipeline_failures,
        )
        return None, _workflow_failure_response(
            run_id=run_id,
            failing_step="boot",
            latest_successful_step="build",
            response=boot_response,
            collect_response=collect_response,
        )

    return (
        _BuildBootWorkflowResult(
            run_id=run_id,
            resolved_optional=requested_optional,
            build_response=build_response,
            boot_response=boot_response,
        ),
        None,
    )


def workflow_build_boot_test_handler(
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
    acknowledged_permissions: list[str] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    dependencies: WorkflowHandlerDependencies | None = None,
) -> ToolResponse:
    dependencies = dependencies or _workflow_dependencies()
    pipeline, pipeline_failure = _run_build_boot_workflow(
        workflow_name="workflow.build_boot_test",
        artifact_root=artifact_root,
        source_path=source_path,
        build_profile=build_profile,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        run_id=run_id,
        optional_field="test_suite",
        requested_optional=test_suite,
        optional_policy="always",
        force_rebuild=force_rebuild,
        force_reboot=force_reboot,
        force_recollect=force_recollect,
        collect_pipeline_failures=True,
        acknowledged_permissions=acknowledged_permissions,
        admission=admission,
        dependencies=dependencies,
    )
    if pipeline_failure is not None:
        return pipeline_failure
    pipeline = _require_pipeline(pipeline)
    run_id = pipeline.run_id
    test_suite = pipeline.resolved_optional
    build_response = pipeline.build_response
    boot_response = pipeline.boot_response

    test_response = dependencies.target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        test_suite=test_suite,
        commands=commands,
        force_rerun=force_rerun_tests,
        admission=admission,
        session_registry=session_registry,
    )
    collect_response = dependencies.artifacts_collect_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        force_recollect=force_recollect,
    )
    if not test_response.ok:
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="run_tests",
            latest_successful_step="boot",
            response=test_response,
            collect_response=collect_response,
        )
    if not collect_response.ok:
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="collect_artifacts",
            latest_successful_step="run_tests",
            response=collect_response,
            collect_response=collect_response,
        )
    return ToolResponse.success(
        summary="build, boot, test workflow succeeded",
        run_id=run_id,
        data={
            "steps": {
                "build": build_response.model_dump(mode="json"),
                "boot": boot_response.model_dump(mode="json"),
                "run_tests": test_response.model_dump(mode="json"),
                "collect_artifacts": collect_response.model_dump(mode="json"),
            },
            "latest_successful_step": "collect_artifacts",
            "artifact_bundle": next(
                (
                    artifact.model_dump(mode="json")
                    for artifact in collect_response.artifacts
                    if artifact.kind == "artifact-bundle"
                ),
                None,
            ),
        },
        artifacts=collect_response.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def workflow_build_boot_debug_handler(
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
    acknowledged_permissions: list[str] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    transaction: TransportTransaction | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
    dependencies: WorkflowHandlerDependencies | None = None,
) -> ToolResponse:
    dependencies = dependencies or _workflow_dependencies()
    pipeline, pipeline_failure = _run_build_boot_workflow(
        workflow_name="workflow.build_boot_debug",
        artifact_root=artifact_root,
        source_path=source_path,
        build_profile=build_profile,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        run_id=run_id,
        optional_field="debug_profile",
        requested_optional=debug_profile,
        optional_policy="when_manifest_set",
        force_rebuild=force_rebuild,
        force_reboot=force_reboot,
        force_recollect=False,
        collect_pipeline_failures=False,
        acknowledged_permissions=acknowledged_permissions,
        admission=admission,
        dependencies=dependencies,
    )
    if pipeline_failure is not None:
        return pipeline_failure
    pipeline = _require_pipeline(pipeline)
    run_id = pipeline.run_id
    debug_profile = pipeline.resolved_optional
    build_response = pipeline.build_response
    boot_response = pipeline.boot_response

    debug_response = dependencies.debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profile=debug_profile,
        new_session=new_session,
        transaction=transaction,
        admission=admission,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )
    if not debug_response.ok:
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="debug",
            latest_successful_step="boot",
            response=debug_response,
            collect_response=None,
        )

    return ToolResponse.success(
        summary="build, boot, debug workflow succeeded",
        run_id=run_id,
        data={
            "steps": {
                "build": build_response.model_dump(mode="json"),
                "boot": boot_response.model_dump(mode="json"),
                "debug": debug_response.model_dump(mode="json"),
            },
            "latest_successful_step": "debug",
        },
        artifacts=debug_response.artifacts,
        suggested_next_actions=["debug.read_registers", "debug.evaluate", "debug.end_session"],
    )
