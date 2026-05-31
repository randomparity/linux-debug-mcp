from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from kdive.artifacts.manifest import RunManifest
from kdive.artifacts.store import ArtifactStore, ManifestStateError, record_step_with_retry
from kdive.config import BuildProfile
from kdive.default_profiles import DEFAULT_BUILD_PROFILES
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.providers.local.build.local_kernel_build import (
    BuildExecutionResult,
    BuildIdMissing,
    BuildPlan,
    LocalKernelBuildProvider,
    ReadelfUnavailable,
)
from kdive.safety.paths import PathSafetyError, validate_source_path
from kdive.safety.redaction import Redactor

RUNNING_BUILD_MESSAGE = (
    "previous build is still recorded as running; inspect logs and create a new run or manually clean stale build state"
)


def _recorded_build_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.success(
        summary=result.summary,
        run_id=run_id,
        data=Redactor().redact_value(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _running_build_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=RUNNING_BUILD_MESSAGE,
        run_id=run_id,
        details=Redactor().redact_value(result.details),
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _build_profile_from_manifest(manifest: RunManifest) -> BuildProfile:
    if manifest.resolved_build_profile is not None:
        return manifest.resolved_build_profile
    profile_name = manifest.request.build_profile
    try:
        return DEFAULT_BUILD_PROFILES[profile_name]
    except KeyError as exc:
        raise ValueError(f"unknown build profile: {profile_name}") from exc


def _record_terminal_build_result(store: ArtifactStore, run_id: str, result: StepResult) -> None:
    record_step_with_retry(store, run_id, result)


@dataclass(frozen=True)
class _KernelBuildContext:
    store: ArtifactStore
    run_id: str
    provider: LocalKernelBuildProvider
    plan: BuildPlan
    log_path: Path
    summary_path: Path


def kernel_build_handler(
    *,
    artifact_root: Path,
    run_id: str,
    build_profile: str | None = None,
    force_rebuild: bool = False,
    provider: LocalKernelBuildProvider | None = None,
) -> ToolResponse:
    context, response = _resolve_kernel_build_request(
        artifact_root=artifact_root,
        run_id=run_id,
        build_profile=build_profile,
        force_rebuild=force_rebuild,
        provider=provider,
    )
    if response is not None:
        return response
    context = _require_kernel_build_context(context)
    execution, response = _execute_kernel_build_under_lock(context)
    if response is not None:
        return response
    execution = _require_build_execution(execution)
    return _build_execution_response(run_id=run_id, execution=execution)


def _resolve_kernel_build_request(
    *,
    artifact_root: Path,
    run_id: str,
    build_profile: str | None,
    force_rebuild: bool,
    provider: LocalKernelBuildProvider | None,
) -> tuple[_KernelBuildContext | None, ToolResponse | None]:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return None, ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                message=f"run not found: {run_id}",
                run_id=run_id,
            )
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return None, ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    if force_rebuild:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="force_rebuild=true is not supported until rebuild cleanup policy is implemented",
            run_id=run_id,
        )
    requested_profile = build_profile or manifest.request.build_profile
    if requested_profile != manifest.request.build_profile:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="build_profile must match the immutable run manifest request",
            run_id=run_id,
            details={"requested_profile": requested_profile, "manifest_profile": manifest.request.build_profile},
        )
    existing = manifest.step_results.get("build")
    if existing and existing.status == StepStatus.SUCCEEDED:
        return None, _recorded_build_success_response(run_id=run_id, result=existing)
    if existing and existing.status == StepStatus.RUNNING:
        try:
            with store.build_lock(run_id):
                return None, _running_build_response(run_id=run_id, result=existing)
        except ManifestStateError as exc:
            return None, ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    try:
        source_path = validate_source_path(Path(manifest.request.source_path))
        store = ArtifactStore(artifact_root, source_paths=[source_path], create_root=False)
        profile = _build_profile_from_manifest(manifest)
        provider = provider or LocalKernelBuildProvider()
        run_dir = store.run_dir(run_id)
        plan = provider.plan_build(source_path=source_path, output_path=run_dir / "build", profile=profile)
    except (PathSafetyError, ValueError, ManifestStateError) as exc:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
            run_id=run_id,
        )
    log_path = store.run_dir(run_id) / "logs" / "build.log"
    summary_path = store.run_dir(run_id) / "summaries" / "build-summary.json"
    return (
        _KernelBuildContext(
            store=store,
            run_id=run_id,
            provider=provider,
            plan=plan,
            log_path=log_path,
            summary_path=summary_path,
        ),
        None,
    )


def _execute_kernel_build_under_lock(
    context: _KernelBuildContext,
) -> tuple[BuildExecutionResult | None, ToolResponse | None]:
    store = context.store
    run_id = context.run_id
    provider = context.provider
    plan = context.plan
    log_path = context.log_path
    summary_path = context.summary_path
    try:
        with store.build_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("build")
            if existing and existing.status == StepStatus.SUCCEEDED:
                return None, _recorded_build_success_response(run_id=run_id, result=existing)
            if existing and existing.status == StepStatus.RUNNING:
                return None, _running_build_response(run_id=run_id, result=existing)
            running = StepResult(
                step_name="build",
                status=StepStatus.RUNNING,
                summary="kernel build running",
                details={"argv": plan.argv, "log_path": str(log_path), "provider": provider.name},
                artifacts=[ArtifactRef(path=str(log_path), kind="build-log")],
            )
            store.record_step_result(run_id, running)
            try:
                execution = provider.execute_build(plan=plan, log_path=log_path, summary_path=summary_path)
            except ReadelfUnavailable as exc:
                return None, _readelf_unavailable_response(context, exc)
            except BuildIdMissing as exc:
                return None, _build_id_missing_response(context, exc)
            except Exception as exc:
                result = StepResult(
                    step_name="build",
                    status=StepStatus.FAILED,
                    summary="unexpected build provider failure",
                    artifacts=[ArtifactRef(path=str(log_path), kind="build-log")],
                    details={
                        "argv": plan.argv,
                        "log_path": str(log_path),
                        "provider": provider.name,
                        "exception_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )
                _record_terminal_build_result(store, run_id, result)
                return None, ToolResponse.failure(
                    category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                    message=result.summary,
                    run_id=run_id,
                    details=Redactor().redact_value(result.details),
                    artifacts=result.artifacts,
                    suggested_next_actions=["artifacts.get_manifest"],
                )
            result = StepResult(
                step_name="build",
                status=execution.status,
                summary=execution.summary,
                artifacts=execution.artifacts,
                details=execution.details,
            )
            _record_terminal_build_result(store, run_id, result)
    except ManifestStateError as exc:
        return None, ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    return execution, None


def _readelf_unavailable_response(context: _KernelBuildContext, exc: ReadelfUnavailable) -> ToolResponse:
    failed = StepResult(
        step_name="build",
        status=StepStatus.FAILED,
        summary="readelf unavailable while extracting build_id",
        artifacts=exc.artifacts,
        details={"code": "readelf_unavailable", "error": str(exc), "provider": context.provider.name},
    )
    _record_terminal_build_result(context.store, context.run_id, failed)
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=(
            "readelf unavailable while extracting build_id; "
            "the recorded FAILED build step retains vmlinux and the build log "
            "for forensic inspection"
        ),
        run_id=context.run_id,
        details={"code": "readelf_unavailable"},
        artifacts=exc.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _build_id_missing_response(context: _KernelBuildContext, exc: BuildIdMissing) -> ToolResponse:
    failed = StepResult(
        step_name="build",
        status=StepStatus.FAILED,
        summary="vmlinux has no .note.gnu.build-id",
        artifacts=exc.artifacts,
        details={"code": "build_id_missing", "error": str(exc), "provider": context.provider.name},
    )
    _record_terminal_build_result(context.store, context.run_id, failed)
    return ToolResponse.failure(
        category=ErrorCategory.BUILD_FAILURE,
        message=(
            "vmlinux has no .note.gnu.build-id; rebuild with LD_BUILD_ID=sha1 "
            "or equivalent (spec §7). The FAILED build step retains vmlinux "
            "and the build log so the failure can be diagnosed without "
            "re-running the build."
        ),
        run_id=context.run_id,
        details={"code": "build_id_missing"},
        artifacts=exc.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _build_execution_response(*, run_id: str, execution: BuildExecutionResult) -> ToolResponse:
    if execution.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=execution.summary,
            run_id=run_id,
            data=Redactor().redact_value(execution.details),
            artifacts=execution.artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    return ToolResponse.failure(
        category=execution.error_category or ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=execution.summary,
        run_id=run_id,
        details=Redactor().redact_value({**execution.details, "diagnostic": execution.diagnostic}),
        artifacts=execution.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _require_kernel_build_context(context: _KernelBuildContext | None) -> _KernelBuildContext:
    if context is None:
        raise RuntimeError("kernel build context missing after successful resolution")
    return context


def _require_build_execution(execution: BuildExecutionResult | None) -> BuildExecutionResult:
    if execution is None:
        raise RuntimeError("kernel build execution missing after successful locked phase")
    return execution
