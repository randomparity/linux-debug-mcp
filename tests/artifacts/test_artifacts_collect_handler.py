import json
from pathlib import Path

from conftest import make_source_tree
from handler_call_helpers import create_run_handler

from kdive.artifacts.store import ArtifactStore
from kdive.domain import ArtifactRef, StepResult, StepStatus
from kdive.server import artifacts_collect_handler


def test_artifacts_collect_handler_lives_in_artifacts_package() -> None:
    assert artifacts_collect_handler.__module__ == "kdive.artifacts.handlers"


def create_run(tmp_path: Path) -> Path:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"
    response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )
    assert response.ok is True
    return artifact_root


def test_collect_artifacts_writes_bundle_for_existing_manifest_refs(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    build_log = artifact_root / "run-abc123" / "logs" / "build.log"
    kernel_config = artifact_root / "run-abc123" / "build" / ".config"
    kernel_image = artifact_root / "run-abc123" / "build" / "arch" / "x86" / "boot" / "bzImage"
    build_log.write_text("build\n", encoding="utf-8")
    kernel_config.parent.mkdir(parents=True, exist_ok=True)
    kernel_config.write_text("CONFIG_TEST=y\n", encoding="utf-8")
    kernel_image.parent.mkdir(parents=True, exist_ok=True)
    kernel_image.write_text("kernel\n", encoding="utf-8")
    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(
        "run-abc123",
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="build ok",
            artifacts=[
                ArtifactRef(path=str(build_log), kind="build-log"),
                ArtifactRef(path=str(kernel_config), kind="kernel-config"),
                ArtifactRef(path=str(kernel_image), kind="kernel-image"),
            ],
        ),
    )

    response = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is True
    bundle_path = artifact_root / "run-abc123" / "summaries" / "artifact-bundle.json"
    assert bundle_path.is_file()
    assert any(artifact.kind == "artifact-bundle" for artifact in response.artifacts)
    assert response.data["rollup"]["missing_required"] == 0


def test_collect_artifacts_fails_when_succeeded_step_reference_is_missing(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    missing = artifact_root / "run-abc123" / "logs" / "missing-build.log"
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        "run-abc123",
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="build ok",
            artifacts=[ArtifactRef(path=str(missing), kind="build-log")],
        ),
    )

    response = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert any(artifact.kind == "artifact-bundle" for artifact in response.artifacts)
    assert response.error.details["rollup"]["missing_required"] >= 1


def test_collect_artifacts_fails_when_succeeded_build_omits_required_artifact_kind(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    build_log = artifact_root / "run-abc123" / "logs" / "build.log"
    build_log.write_text("build\n", encoding="utf-8")
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        "run-abc123",
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="build ok",
            artifacts=[ArtifactRef(path=str(build_log), kind="build-log")],
        ),
    )

    response = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert "kernel-config" in str(response.error.details)
    assert "kernel-image" in str(response.error.details)


def test_collect_artifacts_returns_recorded_success_without_force_recollect(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    first = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")
    second = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert first.ok is True
    assert second.ok is True
    assert second.summary == first.summary


def test_collect_artifacts_force_recollect_rewrites_bundle(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    first = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")
    bundle_path = artifact_root / "run-abc123" / "summaries" / "artifact-bundle.json"
    old_text = bundle_path.read_text(encoding="utf-8")
    bundle_path.write_text('{"stale": true}', encoding="utf-8")

    second = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123", force_recollect=True)

    assert first.ok is True
    assert second.ok is True
    assert bundle_path.read_text(encoding="utf-8") != '{"stale": true}'
    assert bundle_path.read_text(encoding="utf-8") == old_text or "collected_at" in bundle_path.read_text(
        encoding="utf-8"
    )


def test_collect_artifacts_redacts_sensitive_artifact_paths_in_response(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    sensitive_log = artifact_root / "run-abc123" / "sensitive" / "serial.log"
    sensitive_log.write_text("token=secret-token-value\n", encoding="utf-8")
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        "run-abc123",
        StepResult(
            step_name="debug",
            status=StepStatus.FAILED,
            summary="debug failed",
            artifacts=[ArtifactRef(path=str(sensitive_log), kind="serial-log", sensitive=True)],
        ),
    )

    response = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")

    payload = response.model_dump(mode="json")
    assert response.ok is True
    assert str(sensitive_log) not in str(payload)
    assert "[REDACTED]" in str(payload)


def test_collect_artifacts_includes_succeeded_debug_artifacts(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    run_dir = artifact_root / "run-abc123"
    session_path = run_dir / "debug" / "sessions" / "debug-test.json"
    transcript_path = run_dir / "debug" / "attempt-001" / "transcript.txt"
    command_metadata_path = run_dir / "debug" / "attempt-001" / "commands.jsonl"
    summary_path = run_dir / "debug" / "attempt-001" / "debug-summary.json"
    session_path.parent.mkdir(parents=True, exist_ok=True)
    transcript_path.parent.mkdir(parents=True, exist_ok=True)
    session_path.write_text('{"session_id":"debug-test"}\n', encoding="utf-8")
    transcript_path.write_text("token=secret-token-value\n", encoding="utf-8")
    command_metadata_path.write_text('{"command":"info registers"}\n', encoding="utf-8")
    summary_path.write_text('{"summary":"debug ok"}\n', encoding="utf-8")
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        "run-abc123",
        StepResult(
            step_name="debug",
            status=StepStatus.SUCCEEDED,
            summary="debug ok",
            artifacts=[
                ArtifactRef(path=str(session_path), kind="debug-session"),
                ArtifactRef(path=str(transcript_path), kind="debug-transcript", sensitive=True),
                ArtifactRef(path=str(command_metadata_path), kind="debug-command-metadata"),
                ArtifactRef(path=str(summary_path), kind="debug-summary"),
            ],
        ),
    )

    response = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")

    bundle_path = run_dir / "summaries" / "artifact-bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    debug_artifacts = bundle["artifacts_by_step"]["debug"]
    assert response.ok is True
    assert {artifact["kind"] for artifact in debug_artifacts} == {
        "debug-session",
        "debug-transcript",
        "debug-command-metadata",
        "debug-summary",
    }
    assert all(artifact["exists"] for artifact in debug_artifacts)
    assert str(transcript_path) not in bundle_path.read_text(encoding="utf-8")
    assert response.data["rollup"]["missing_required"] == 0


def test_collect_artifacts_recollects_when_debug_artifacts_are_added_after_success(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    run_id = "run-abc123"
    first = artifacts_collect_handler(artifact_root=artifact_root, run_id=run_id)
    assert first.ok is True
    run_dir = artifact_root / run_id
    session_path = run_dir / "debug" / "sessions" / "debug-test.json"
    transcript_path = run_dir / "debug" / "attempt-001" / "transcript.txt"
    command_metadata_path = run_dir / "debug" / "attempt-001" / "commands.jsonl"
    summary_path = run_dir / "debug" / "attempt-001" / "debug-summary.json"
    session_path.parent.mkdir(parents=True, exist_ok=True)
    transcript_path.parent.mkdir(parents=True, exist_ok=True)
    for path in [session_path, transcript_path, command_metadata_path, summary_path]:
        path.write_text("debug artifact\n", encoding="utf-8")
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        run_id,
        StepResult(
            step_name="debug",
            status=StepStatus.SUCCEEDED,
            summary="debug ok",
            artifacts=[
                ArtifactRef(path=str(session_path), kind="debug-session"),
                ArtifactRef(path=str(transcript_path), kind="debug-transcript", sensitive=True),
                ArtifactRef(path=str(command_metadata_path), kind="debug-command-metadata"),
                ArtifactRef(path=str(summary_path), kind="debug-summary"),
            ],
        ),
    )

    second = artifacts_collect_handler(artifact_root=artifact_root, run_id=run_id)

    assert second.ok is True
    kinds = {artifact.kind for artifact in second.artifacts}
    assert {"debug-session", "debug-transcript", "debug-command-metadata", "debug-summary"} <= kinds
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest(run_id)
    recorded_collect = manifest.step_results["collect_artifacts"]
    recorded_kinds = {artifact.kind for artifact in recorded_collect.artifacts}
    assert {"debug-session", "debug-transcript", "debug-command-metadata", "debug-summary"} <= recorded_kinds


def test_collect_artifacts_bundles_dynamic_introspect_step_results(tmp_path: Path) -> None:
    # Iter-2 finding 1: introspect:<call_id> step results live in
    # `manifest.step_results` but NOT in the fixed `manifest.steps` list,
    # so the bundler used to drop them silently — leaving forensic exports
    # without any record of executed introspect calls.
    artifact_root = create_run(tmp_path)
    run_id = "run-abc123"
    run_dir = artifact_root / run_id
    introspect_dir = run_dir / "debug" / "introspect" / "deadbeefdeadbeefdeadbeefdeadbeef"
    introspect_dir.mkdir(parents=True, exist_ok=True)
    stdout_json = introspect_dir / "stdout.json"
    request_json = introspect_dir / "request.json"
    stdout_json.write_text('{"emits": []}\n', encoding="utf-8")
    request_json.write_text('{"script": "sha256:abc"}\n', encoding="utf-8")
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        run_id,
        StepResult(
            step_name="introspect:deadbeefdeadbeefdeadbeefdeadbeef",
            status=StepStatus.SUCCEEDED,
            summary="introspect call deadbeef ok",
            artifacts=[
                ArtifactRef(path=str(stdout_json), kind="application/json"),
                ArtifactRef(path=str(request_json), kind="application/json"),
            ],
        ),
        append=True,
    )

    response = artifacts_collect_handler(artifact_root=artifact_root, run_id=run_id)

    assert response.ok is True
    bundle_path = run_dir / "summaries" / "artifact-bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    dynamic_step_name = "introspect:deadbeefdeadbeefdeadbeefdeadbeef"
    assert dynamic_step_name in bundle["artifacts_by_step"]
    artifacts = bundle["artifacts_by_step"][dynamic_step_name]
    assert {a["kind"] for a in artifacts} == {"application/json"}
    assert all(a["exists"] for a in artifacts)
    # Bundle's artifact list (returned to the agent) now includes the
    # introspect call's artifacts.
    collected_paths = {a.path for a in response.artifacts}
    assert str(stdout_json) in collected_paths
    assert str(request_json) in collected_paths


def test_collect_introspect_succeeded_artifact_missing_is_reported(tmp_path: Path) -> None:
    # Iter-2 finding 1: a SUCCEEDED introspect step that references a
    # nonexistent artifact must be reported as missing_required, mirroring
    # how the bundler treats SUCCEEDED fixed-step entries.
    artifact_root = create_run(tmp_path)
    run_id = "run-abc123"
    missing_path = artifact_root / run_id / "debug" / "introspect" / "ghost" / "stdout.json"
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        run_id,
        StepResult(
            step_name="introspect:ghost",
            status=StepStatus.SUCCEEDED,
            summary="introspect call ghost ok",
            artifacts=[ArtifactRef(path=str(missing_path), kind="application/json")],
        ),
        append=True,
    )

    response = artifacts_collect_handler(artifact_root=artifact_root, run_id=run_id)

    assert response.ok is False
    assert response.error is not None
    assert response.error.details["rollup"]["missing_required"] >= 1
