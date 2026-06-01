from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from pydantic import ValidationError

from kdive.artifacts.manifest import RunManifest
from kdive.artifacts.redaction import redacted_artifacts
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import (
    BootOverrides,
    BuildOverrides,
    BuildProfile,
    RootfsProfile,
    TargetProfile,
    merge_config_lines,
)
from kdive.default_profiles import DEFAULT_BUILD_PROFILES, DEFAULT_ROOTFS_PROFILES, DEFAULT_TARGET_PROFILES
from kdive.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus, ToolResponse
from kdive.safety.paths import PathSafetyError, validate_rootfs_source, validate_source_path
from kdive.safety.redaction import Redactor


def _configuration_failure(*, run_id: str, message: str, details: dict[str, Any] | None = None) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
    )


def _recorded_collect_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    redactor = Redactor()
    return ToolResponse.success(
        summary=redactor.redact_text(result.summary),
        run_id=run_id,
        data=redactor.redact_value(result.details),
        artifacts=redacted_artifacts(result.artifacts, redactor),
        suggested_next_actions=["artifacts.get_manifest"],
    )


@dataclass(frozen=True)
class _ResolvedProfiles:
    build: BuildProfile
    target: TargetProfile
    rootfs: RootfsProfile


_ProfileT = TypeVar("_ProfileT", BuildProfile, TargetProfile, RootfsProfile)


def _resolve_base_profile(
    kind: str,
    *,
    name: str | None,
    spec: dict[str, Any] | None,
    registry: dict[str, _ProfileT],
    model: type[_ProfileT],
) -> _ProfileT:
    if name is not None and spec is not None:
        raise ValueError(f"provide either {kind}_profile or {kind}_profile_spec, not both")
    if name is None and spec is None:
        raise ValueError(f"{kind}_profile or {kind}_profile_spec is required")
    if spec is not None:
        try:
            return model.model_validate(spec)
        except ValidationError as exc:
            raise ValueError(f"invalid {kind}_profile_spec: {exc.error_count()} validation error(s)") from exc
    if name not in registry:
        raise ValueError(f"unknown profile: {name}")
    return registry[name]


def _resolve_initial_profiles(
    *,
    source_path: Path,
    sensitive_paths: list[Path],
    build_profile: str | None,
    build_profile_spec: dict[str, Any] | None,
    target_profile: str | None,
    target_profile_spec: dict[str, Any] | None,
    rootfs_profile: str | None,
    rootfs_profile_spec: dict[str, Any] | None,
    build_overrides: BuildOverrides | None,
    boot_overrides: BootOverrides | None,
) -> _ResolvedProfiles:
    base_build = _resolve_base_profile(
        "build", name=build_profile, spec=build_profile_spec, registry=DEFAULT_BUILD_PROFILES, model=BuildProfile
    )
    base_target = _resolve_base_profile(
        "target", name=target_profile, spec=target_profile_spec, registry=DEFAULT_TARGET_PROFILES, model=TargetProfile
    )
    base_rootfs = _resolve_base_profile(
        "rootfs", name=rootfs_profile, spec=rootfs_profile_spec, registry=DEFAULT_ROOTFS_PROFILES, model=RootfsProfile
    )

    resolved_build = base_build
    if build_overrides is not None:
        build_update: dict[str, object] = {}
        if build_overrides.make_variables:
            build_update["make_variables"] = {**base_build.make_variables, **build_overrides.make_variables}
        if build_overrides.config_lines:
            build_update["config_lines"] = merge_config_lines(base_build.config_lines, build_overrides.config_lines)
        if build_overrides.base_config:
            build_update["base_config"] = list(build_overrides.base_config)
        if build_update:
            resolved_build = base_build.model_copy(update=build_update)

    if rootfs_profile_spec is not None:
        validated_source = validate_rootfs_source(
            Path(base_rootfs.source),
            source_paths=[source_path],
            sensitive_paths=sensitive_paths,
        )
        base_rootfs = base_rootfs.model_copy(update={"source": str(validated_source)})

    if boot_overrides is not None and boot_overrides.rootfs_source is not None:
        validate_rootfs_source(
            Path(boot_overrides.rootfs_source),
            source_paths=[source_path],
            sensitive_paths=sensitive_paths,
        )
    return _ResolvedProfiles(build=resolved_build, target=base_target, rootfs=base_rootfs)


def create_run_handler(
    *,
    artifact_root: Path,
    source_path: str,
    build_profile: str | None = None,
    target_profile: str | None = None,
    rootfs_profile: str | None = None,
    run_id: str | None = None,
    debug_profile: str | None = None,
    test_suite: str | None = None,
    build_overrides: BuildOverrides | None = None,
    boot_overrides: BootOverrides | None = None,
    sensitive_paths: list[Path] | None = None,
    build_profile_spec: dict[str, Any] | None = None,
    target_profile_spec: dict[str, Any] | None = None,
    rootfs_profile_spec: dict[str, Any] | None = None,
) -> ToolResponse:
    try:
        resolved_source_path = validate_source_path(Path(source_path))
    except PathSafetyError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
            details={"source_path": source_path},
        )
    try:
        resolved = _resolve_initial_profiles(
            source_path=Path(resolved_source_path),
            sensitive_paths=sensitive_paths or [],
            build_profile=build_profile,
            build_profile_spec=build_profile_spec,
            target_profile=target_profile,
            target_profile_spec=target_profile_spec,
            rootfs_profile=rootfs_profile,
            rootfs_profile_spec=rootfs_profile_spec,
            build_overrides=build_overrides,
            boot_overrides=boot_overrides,
        )
    except (PathSafetyError, ValueError) as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
        )
    request = RunRequest(
        source_path=str(resolved_source_path),
        build_profile=resolved.build.name,
        target_profile=resolved.target.name,
        rootfs_profile=resolved.rootfs.name,
        debug_profile=debug_profile,
        test_suite=test_suite,
        run_id=run_id,
        build_overrides=build_overrides,
        boot_overrides=boot_overrides,
    )
    try:
        store = ArtifactStore(artifact_root, source_paths=[resolved_source_path])
        manifest = store.create_run(
            request,
            resolved_build_profile=resolved.build,
            resolved_target_profile=resolved.target if target_profile_spec is not None else None,
            resolved_rootfs_profile=resolved.rootfs if rootfs_profile_spec is not None else None,
        )
    except ManifestStateError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=str(exc),
            details={"artifact_root": str(artifact_root)},
        )
    manifest_path = artifact_root.expanduser().resolve() / manifest.run_id / "manifest.json"
    return ToolResponse.success(
        summary=f"created run {manifest.run_id}",
        run_id=manifest.run_id,
        data={
            "manifest": Redactor().redact_value(manifest.model_dump(mode="json")),
            "manifest_path": str(manifest_path),
        },
        artifacts=[ArtifactRef(path=str(manifest_path), kind="manifest")],
        suggested_next_actions=["kernel.build"],
    )


def get_manifest_handler(*, artifact_root: Path, run_id: str) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    return ToolResponse.success(
        summary=f"loaded manifest for {run_id}",
        run_id=run_id,
        data={"manifest": Redactor().redact_value(manifest.model_dump(mode="json"))},
        artifacts=[
            ArtifactRef(path=str(artifact_root.expanduser().resolve() / run_id / "manifest.json"), kind="manifest")
        ],
    )


def _bundle_for_manifest(
    *,
    manifest: RunManifest,
    run_dir: Path,
    bundle_path: Path,
) -> tuple[dict[str, Any], list[ArtifactRef], list[dict[str, Any]], list[dict[str, Any]]]:
    required_kinds_by_step = {
        "build": {"build-log", "kernel-config", "kernel-image"},
        "boot": {"domain-xml", "boot-plan", "console-log", "boot-log"},
        "debug": {"debug-command-metadata", "debug-session", "debug-summary", "debug-transcript"},
        "run_tests": {"test-summary"},
    }
    optional_kinds_by_step = {"build": {"vmlinux"}}
    grouped: dict[str, list[dict[str, Any]]] = {}
    missing_required: list[dict[str, Any]] = []
    missing_optional: list[dict[str, Any]] = []
    collected_refs: list[ArtifactRef] = []
    for step in manifest.steps:
        result = manifest.step_results.get(step.name)
        grouped[step.name] = []
        if result is None:
            continue
        present_kinds = {artifact.kind for artifact in result.artifacts}
        if result.status == StepStatus.SUCCEEDED:
            for kind in sorted(required_kinds_by_step.get(step.name, set()) - present_kinds):
                missing_required.append(
                    {"step": step.name, "kind": kind, "reason": "required artifact kind was not recorded"}
                )
            for kind in sorted(optional_kinds_by_step.get(step.name, set()) - present_kinds):
                missing_optional.append(
                    {"step": step.name, "kind": kind, "reason": "optional artifact kind was not recorded"}
                )
        for artifact in result.artifacts:
            exists = Path(artifact.path).is_file()
            item = {**artifact.model_dump(mode="json"), "exists": exists}
            grouped[step.name].append(item)
            if exists:
                collected_refs.append(artifact)
            elif result.status == StepStatus.SUCCEEDED and artifact.kind not in optional_kinds_by_step.get(
                step.name, set()
            ):
                missing_required.append({"step": step.name, "artifact": artifact.model_dump(mode="json")})
            else:
                missing_optional.append({"step": step.name, "artifact": artifact.model_dump(mode="json")})

    fixed_step_names = {step.name for step in manifest.steps}
    for step_name, result in manifest.step_results.items():
        if step_name in fixed_step_names:
            continue
        grouped[step_name] = []
        for artifact in result.artifacts:
            exists = Path(artifact.path).is_file()
            item = {**artifact.model_dump(mode="json"), "exists": exists}
            grouped[step_name].append(item)
            if exists:
                collected_refs.append(artifact)
            elif result.status == StepStatus.SUCCEEDED:
                missing_required.append({"step": step_name, "artifact": artifact.model_dump(mode="json")})
            else:
                missing_optional.append({"step": step_name, "artifact": artifact.model_dump(mode="json")})
    bundle_ref = ArtifactRef(path=str(bundle_path), kind="artifact-bundle")
    bundle = {
        "run_id": manifest.run_id,
        "run_dir": str(run_dir),
        "collected_at": datetime.now(UTC).isoformat(),
        "selected_profiles": manifest.request.model_dump(mode="json"),
        "steps": {step.name: step.status for step in manifest.steps},
        "summaries": {
            name: {"status": result.status, "summary": result.summary} for name, result in manifest.step_results.items()
        },
        "artifacts_by_step": grouped,
        "missing_expected_artifacts": missing_required,
        "missing_optional_artifacts": missing_optional,
        "cleanup_state": manifest.cleanup_state,
        "rollup": {
            "ok": not missing_required,
            "missing_required": len(missing_required),
            "missing_optional": len(missing_optional),
        },
    }
    return bundle, [*collected_refs, bundle_ref], missing_required, missing_optional


def _collection_covers_manifest(*, manifest: RunManifest, collect_result: StepResult) -> bool:
    collected = {
        (artifact.path, artifact.kind) for artifact in collect_result.artifacts if artifact.kind != "artifact-bundle"
    }
    current = {
        (artifact.path, artifact.kind)
        for step_name, result in manifest.step_results.items()
        if step_name != "collect_artifacts"
        for artifact in result.artifacts
    }
    return current.issubset(collected)


def artifacts_collect_handler(
    *,
    artifact_root: Path,
    run_id: str,
    force_recollect: bool = False,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    existing = manifest.step_results.get("collect_artifacts")
    if (
        existing
        and existing.status == StepStatus.SUCCEEDED
        and not force_recollect
        and _collection_covers_manifest(manifest=manifest, collect_result=existing)
    ):
        return _recorded_collect_success_response(run_id=run_id, result=existing)
    try:
        with store.collect_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("collect_artifacts")
            replace_succeeded = force_recollect or bool(existing and existing.status == StepStatus.SUCCEEDED)
            if (
                existing
                and existing.status == StepStatus.SUCCEEDED
                and not force_recollect
                and _collection_covers_manifest(manifest=locked_manifest, collect_result=existing)
            ):
                return _recorded_collect_success_response(run_id=run_id, result=existing)
            bundle_path = store.run_dir(run_id) / "summaries" / "artifact-bundle.json"
            bundle, artifacts, missing_required, missing_optional = _bundle_for_manifest(
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
    safe_artifacts = redacted_artifacts(artifacts, redactor)
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
