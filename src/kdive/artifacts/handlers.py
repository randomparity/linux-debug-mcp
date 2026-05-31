from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from kdive.artifacts.manifest import RunManifest
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.safety.redaction import Redactor


class ConfigurationFailure(Protocol):
    def __call__(self, *, run_id: str, message: str, details: dict[str, Any] | None = None) -> ToolResponse: ...


class BundleForManifest(Protocol):
    def __call__(
        self,
        *,
        manifest: RunManifest,
        run_dir: Path,
        bundle_path: Path,
    ) -> tuple[dict[str, Any], list[ArtifactRef], list[dict[str, Any]], list[dict[str, Any]]]: ...


class CollectionCoversManifest(Protocol):
    def __call__(self, *, manifest: RunManifest, collect_result: StepResult) -> bool: ...


class RecordedCollectSuccessResponse(Protocol):
    def __call__(self, *, run_id: str, result: StepResult) -> ToolResponse: ...


class RedactedArtifacts(Protocol):
    def __call__(self, artifacts: list[ArtifactRef], redactor: Redactor) -> list[ArtifactRef]: ...


@dataclass(frozen=True)
class ArtifactHandlerDependencies:
    bundle_for_manifest: BundleForManifest
    collection_covers_manifest: CollectionCoversManifest
    configuration_failure: ConfigurationFailure
    recorded_collect_success_response: RecordedCollectSuccessResponse
    redacted_artifacts: RedactedArtifacts


_DEPENDENCIES: ArtifactHandlerDependencies | None = None


def configure_artifact_handler_dependencies(dependencies: ArtifactHandlerDependencies) -> None:
    global _DEPENDENCIES
    _DEPENDENCIES = dependencies


def _dependencies() -> ArtifactHandlerDependencies:
    if _DEPENDENCIES is None:
        raise RuntimeError("artifact handler dependencies have not been configured")
    return _DEPENDENCIES


def artifacts_collect_handler(
    *,
    artifact_root: Path,
    run_id: str,
    force_recollect: bool = False,
) -> ToolResponse:
    dependencies = _dependencies()
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return dependencies.configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    existing = manifest.step_results.get("collect_artifacts")
    if (
        existing
        and existing.status == StepStatus.SUCCEEDED
        and not force_recollect
        and dependencies.collection_covers_manifest(manifest=manifest, collect_result=existing)
    ):
        return dependencies.recorded_collect_success_response(run_id=run_id, result=existing)
    try:
        with store.collect_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("collect_artifacts")
            replace_succeeded = force_recollect or bool(existing and existing.status == StepStatus.SUCCEEDED)
            if (
                existing
                and existing.status == StepStatus.SUCCEEDED
                and not force_recollect
                and dependencies.collection_covers_manifest(manifest=locked_manifest, collect_result=existing)
            ):
                return dependencies.recorded_collect_success_response(run_id=run_id, result=existing)
            bundle_path = store.run_dir(run_id) / "summaries" / "artifact-bundle.json"
            bundle, artifacts, missing_required, missing_optional = dependencies.bundle_for_manifest(
                manifest=locked_manifest,
                run_dir=store.run_dir(run_id),
                bundle_path=bundle_path,
            )
            bundle_path.parent.mkdir(parents=True, exist_ok=True)
            bundle_path.write_text(
                json.dumps(Redactor().redact_value(bundle), indent=2, default=str),
                encoding="utf-8",
            )
            status = StepStatus.FAILED if missing_required else StepStatus.SUCCEEDED
            result = StepResult(
                step_name="collect_artifacts",
                status=status,
                summary=(
                    "artifact collection succeeded"
                    if status == StepStatus.SUCCEEDED
                    else "artifact collection found missing required artifacts"
                ),
                artifacts=artifacts,
                details={"bundle": bundle, "rollup": bundle["rollup"]},
            )
            store.record_step_result(run_id, result, replace_succeeded=replace_succeeded)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    redactor = Redactor()
    safe_bundle = redactor.redact_value(bundle)
    safe_artifacts = dependencies.redacted_artifacts(artifacts, redactor)
    if missing_required:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=redactor.redact_text(result.summary),
            run_id=run_id,
            details={
                "bundle": safe_bundle,
                "rollup": safe_bundle["rollup"],
                "missing_required": redactor.redact_value(missing_required),
                "missing_optional": redactor.redact_value(missing_optional),
            },
            artifacts=safe_artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    return ToolResponse.success(
        summary=redactor.redact_text(result.summary),
        run_id=run_id,
        data={"bundle": safe_bundle, "rollup": safe_bundle["rollup"]},
        artifacts=safe_artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )
