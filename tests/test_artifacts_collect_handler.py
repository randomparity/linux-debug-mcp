from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import ArtifactRef, StepResult, StepStatus
from linux_debug_mcp.server import artifacts_collect_handler, create_run_handler


def make_source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "linux"
    source.mkdir(parents=True)
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    return source


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
