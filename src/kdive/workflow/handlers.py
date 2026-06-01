from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol

from kdive.artifacts.manifest import RunManifest
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import BootOverrides, BuildOverrides
from kdive.coordination.admission import AdmissionService
from kdive.debug.tools import DebugStartSessionRequest, DebugToolContext
from kdive.domain import ErrorCategory, ToolResponse
from kdive.kernel.tools import (
    CreateRunHandler,
    CreateRunHandlerRequest,
    KernelBuildHandler,
    KernelBuildHandlerRequest,
    KernelToolRuntime,
)
from kdive.safety.paths import PathSafetyError, validate_source_path
from kdive.target.tools import (
    TargetBootHandler,
    TargetBootHandlerRequest,
    TargetRunTestsHandler,
    TargetRunTestsHandlerRequest,
    TargetToolRuntime,
)

if TYPE_CHECKING:
    from kdive.workflow.tools import (
        WorkflowBuildBootDebugHandlerRequest,
        WorkflowBuildBootTestHandlerRequest,
        WorkflowToolRuntime,
    )


class DebugStartSessionHandler(Protocol):
    def __call__(self, *, request: DebugStartSessionRequest, runtime: DebugToolContext) -> ToolResponse: ...


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
class BuildBootWorkflowRequest:
    artifact_root: Path
    source_path: str
    build_profile: str
    target_profile: str
    rootfs_profile: str
    run_id: str | None = None
    force_rebuild: bool = False
    force_reboot: bool = False
    force_recollect: bool = False
    build_overrides: BuildOverrides | None = None
    boot_overrides: BootOverrides | None = None
    sensitive_paths: list[Path] | None = None
    build_profile_spec: dict[str, object] | None = None
    target_profile_spec: dict[str, object] | None = None
    rootfs_profile_spec: dict[str, object] | None = None
    acknowledged_permissions: list[str] | None = None
    admission: AdmissionService | None = None


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
    request: BuildBootWorkflowRequest,
    optional_field: Literal["test_suite", "debug_profile"],
    requested_optional: str | None,
    optional_policy: Literal["always", "when_manifest_set"],
    collect_pipeline_failures: bool,
    dependencies: WorkflowHandlerDependencies,
) -> tuple[_BuildBootWorkflowResult | None, ToolResponse | None]:
    run_id = request.run_id
    if run_id is not None:
        validation, validation_failure = _validate_existing_workflow_run_request(
            artifact_root=request.artifact_root,
            run_id=run_id,
            source_path=request.source_path,
            build_profile=request.build_profile,
            target_profile=request.target_profile,
            rootfs_profile=request.rootfs_profile,
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

    if run_id is None or not (request.artifact_root / run_id / "manifest.json").is_file():
        create_response = dependencies.create_run_handler(
            request=CreateRunHandlerRequest(
                artifact_root=request.artifact_root,
                source_path=request.source_path,
                build_profile=request.build_profile,
                target_profile=request.target_profile,
                rootfs_profile=request.rootfs_profile,
                run_id=run_id,
                debug_profile=requested_optional if optional_field == "debug_profile" else None,
                test_suite=requested_optional if optional_field == "test_suite" else None,
                build_overrides=request.build_overrides,
                boot_overrides=request.boot_overrides,
                build_profile_spec=request.build_profile_spec,
                target_profile_spec=request.target_profile_spec,
                rootfs_profile_spec=request.rootfs_profile_spec,
            ),
            runtime=KernelToolRuntime(sensitive_paths=request.sensitive_paths or []),
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
        request=KernelBuildHandlerRequest(
            artifact_root=request.artifact_root,
            run_id=run_id,
            build_profile=request.build_profile,
            force_rebuild=request.force_rebuild,
        ),
        runtime=KernelToolRuntime(sensitive_paths=request.sensitive_paths or []),
    )
    if not build_response.ok:
        collect_response = _pipeline_failure_collect_response(
            dependencies=dependencies,
            artifact_root=request.artifact_root,
            run_id=run_id,
            force_recollect=request.force_recollect,
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
        request=TargetBootHandlerRequest(
            artifact_root=request.artifact_root,
            run_id=run_id,
            target_profile=request.target_profile,
            rootfs_profile=request.rootfs_profile,
            force_reboot=request.force_reboot,
            boot_overrides=request.boot_overrides,
            acknowledged_permissions=request.acknowledged_permissions,
        ),
        runtime=TargetToolRuntime(
            sensitive_paths=request.sensitive_paths or [],
            admission=request.admission,
            session_registry=None,
        ),
    )
    if not boot_response.ok:
        collect_response = _pipeline_failure_collect_response(
            dependencies=dependencies,
            artifact_root=request.artifact_root,
            run_id=run_id,
            force_recollect=request.force_recollect,
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
    *, request: WorkflowBuildBootTestHandlerRequest, runtime: WorkflowToolRuntime
) -> ToolResponse:
    dependencies = runtime.dependencies
    pipeline, pipeline_failure = _run_build_boot_workflow(
        workflow_name="workflow.build_boot_test",
        request=BuildBootWorkflowRequest(
            artifact_root=request.artifact_root,
            source_path=request.source_path,
            build_profile=request.build_profile,
            target_profile=request.target_profile,
            rootfs_profile=request.rootfs_profile,
            run_id=request.run_id,
            force_rebuild=request.force_rebuild,
            force_reboot=request.force_reboot,
            force_recollect=request.force_recollect,
            build_overrides=request.build_overrides,
            boot_overrides=request.boot_overrides,
            sensitive_paths=runtime.sensitive_paths,
            build_profile_spec=request.build_profile_spec,
            target_profile_spec=request.target_profile_spec,
            rootfs_profile_spec=request.rootfs_profile_spec,
            acknowledged_permissions=request.acknowledged_permissions,
            admission=runtime.admission,
        ),
        optional_field="test_suite",
        requested_optional=request.test_suite,
        optional_policy="always",
        collect_pipeline_failures=True,
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
        request=TargetRunTestsHandlerRequest(
            artifact_root=request.artifact_root,
            run_id=run_id,
            test_suite=test_suite,
            commands=request.commands,
            force_rerun=request.force_rerun_tests,
            attempt=None,
            acknowledged_permissions=request.acknowledged_permissions,
        ),
        runtime=TargetToolRuntime(
            sensitive_paths=runtime.sensitive_paths,
            admission=runtime.admission,
            session_registry=runtime.session_registry,
        ),
    )
    collect_response = dependencies.artifacts_collect_handler(
        artifact_root=request.artifact_root,
        run_id=run_id,
        force_recollect=request.force_recollect,
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
    *, request: WorkflowBuildBootDebugHandlerRequest, runtime: WorkflowToolRuntime
) -> ToolResponse:
    dependencies = runtime.dependencies
    pipeline, pipeline_failure = _run_build_boot_workflow(
        workflow_name="workflow.build_boot_debug",
        request=BuildBootWorkflowRequest(
            artifact_root=request.artifact_root,
            source_path=request.source_path,
            build_profile=request.build_profile,
            target_profile=request.target_profile,
            rootfs_profile=request.rootfs_profile,
            run_id=request.run_id,
            force_rebuild=request.force_rebuild,
            force_reboot=request.force_reboot,
            build_overrides=request.build_overrides,
            boot_overrides=request.boot_overrides,
            sensitive_paths=runtime.sensitive_paths,
            build_profile_spec=request.build_profile_spec,
            target_profile_spec=request.target_profile_spec,
            rootfs_profile_spec=request.rootfs_profile_spec,
            acknowledged_permissions=request.acknowledged_permissions,
            admission=runtime.admission,
        ),
        optional_field="debug_profile",
        requested_optional=request.debug_profile,
        optional_policy="when_manifest_set",
        collect_pipeline_failures=False,
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
        request=DebugStartSessionRequest(
            artifact_root=request.artifact_root,
            run_id=run_id,
            debug_session_id=None,
            debug_profile=debug_profile,
            new_session=request.new_session,
        ),
        runtime=DebugToolContext(
            default_artifact_root=request.artifact_root,
            transaction=runtime.transaction,
            admission=runtime.admission,
            session_registry=runtime.session_registry,
            session_guard=runtime.session_guard,
            gdb_mi_engine=runtime.gdb_mi_engine,
            gdb_mi_sessions=runtime.gdb_mi_sessions,
        ),
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
