from __future__ import annotations

import time
from pathlib import Path

from kdive.artifacts.manifest import RunManifest
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import BuildProfile
from kdive.default_profiles import DEFAULT_BUILD_PROFILES
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.providers.local.build.local_kernel_build import (
    BuildIdMissing,
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


def _record_step_with_retry(
    store: ArtifactStore,
    run_id: str,
    result: StepResult,
    *,
    append: bool = False,
    replace_succeeded: bool = False,
    attempts: int = 5,
    initial_delay_seconds: float = 0.01,
) -> None:
    """Retry transient manifest-lock failures while recording a terminal step."""
    delay_seconds = initial_delay_seconds
    for attempt in range(attempts):
        try:
            store.record_step_result(run_id, result, append=append, replace_succeeded=replace_succeeded)
            return
        except ManifestStateError as exc:
            if "manifest is locked" not in str(exc) or attempt == attempts - 1:
                raise
            time.sleep(delay_seconds)
            delay_seconds *= 2


def _record_terminal_build_result(store: ArtifactStore, run_id: str, result: StepResult) -> None:
    _record_step_with_retry(store, run_id, result)


def kernel_build_handler(
    *,
    artifact_root: Path,
    run_id: str,
    build_profile: str | None = None,
    force_rebuild: bool = False,
    provider: LocalKernelBuildProvider | None = None,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                message=f"run not found: {run_id}",
                run_id=run_id,
            )
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    if force_rebuild:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="force_rebuild=true is not supported until rebuild cleanup policy is implemented",
            run_id=run_id,
        )
    requested_profile = build_profile or manifest.request.build_profile
    if requested_profile != manifest.request.build_profile:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="build_profile must match the immutable run manifest request",
            run_id=run_id,
            details={"requested_profile": requested_profile, "manifest_profile": manifest.request.build_profile},
        )
    existing = manifest.step_results.get("build")
    if existing and existing.status == StepStatus.SUCCEEDED:
        return _recorded_build_success_response(run_id=run_id, result=existing)
    if existing and existing.status == StepStatus.RUNNING:
        try:
            with store.build_lock(run_id):
                return _running_build_response(run_id=run_id, result=existing)
        except ManifestStateError as exc:
            return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    try:
        source_path = validate_source_path(Path(manifest.request.source_path))
        store = ArtifactStore(artifact_root, source_paths=[source_path], create_root=False)
        profile = _build_profile_from_manifest(manifest)
        provider = provider or LocalKernelBuildProvider()
        run_dir = store.run_dir(run_id)
        plan = provider.plan_build(source_path=source_path, output_path=run_dir / "build", profile=profile)
    except (PathSafetyError, ValueError, ManifestStateError) as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
            run_id=run_id,
        )
    log_path = store.run_dir(run_id) / "logs" / "build.log"
    summary_path = store.run_dir(run_id) / "summaries" / "build-summary.json"
    try:
        with store.build_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("build")
            if existing and existing.status == StepStatus.SUCCEEDED:
                return _recorded_build_success_response(run_id=run_id, result=existing)
            if existing and existing.status == StepStatus.RUNNING:
                return _running_build_response(run_id=run_id, result=existing)
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
                failed = StepResult(
                    step_name="build",
                    status=StepStatus.FAILED,
                    summary="readelf unavailable while extracting build_id",
                    artifacts=exc.artifacts,
                    details={"code": "readelf_unavailable", "error": str(exc), "provider": provider.name},
                )
                _record_terminal_build_result(store, run_id, failed)
                return ToolResponse.failure(
                    category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                    message=(
                        "readelf unavailable while extracting build_id; "
                        "the recorded FAILED build step retains vmlinux and the build log "
                        "for forensic inspection"
                    ),
                    run_id=run_id,
                    details={"code": "readelf_unavailable"},
                    artifacts=exc.artifacts,
                    suggested_next_actions=["artifacts.get_manifest"],
                )
            except BuildIdMissing as exc:
                failed = StepResult(
                    step_name="build",
                    status=StepStatus.FAILED,
                    summary="vmlinux has no .note.gnu.build-id",
                    artifacts=exc.artifacts,
                    details={"code": "build_id_missing", "error": str(exc), "provider": provider.name},
                )
                _record_terminal_build_result(store, run_id, failed)
                return ToolResponse.failure(
                    category=ErrorCategory.BUILD_FAILURE,
                    message=(
                        "vmlinux has no .note.gnu.build-id; rebuild with LD_BUILD_ID=sha1 "
                        "or equivalent (spec §7). The FAILED build step retains vmlinux "
                        "and the build log so the failure can be diagnosed without "
                        "re-running the build."
                    ),
                    run_id=run_id,
                    details={"code": "build_id_missing"},
                    artifacts=exc.artifacts,
                    suggested_next_actions=["artifacts.get_manifest"],
                )
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
                return ToolResponse.failure(
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
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
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
