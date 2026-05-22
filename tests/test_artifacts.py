from pathlib import Path

import pytest

from linux_debug_mcp.artifacts.store import ArtifactStore, ManifestStateError
from linux_debug_mcp.domain import RunRequest, StepResult, StepStatus


def request(run_id: str | None = None) -> RunRequest:
    return RunRequest(
        source_path="/src/linux",
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id=run_id,
    )


def make_source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    return source


def test_create_run_workspace_and_manifest(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])

    manifest = store.create_run(request(run_id="run-abc123"))

    run_dir = tmp_path / "runs" / "run-abc123"
    assert manifest.run_id == "run-abc123"
    assert (run_dir / "manifest.json").exists()
    for name in ["inputs", "logs", "build", "target", "tests", "debug", "summaries", "sensitive"]:
        assert (run_dir / name).is_dir()


def test_create_run_refuses_duplicate_run_id(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    with pytest.raises(ManifestStateError, match="already exists"):
        store.create_run(request(run_id="run-abc123"))


def test_create_run_cleans_partial_workspace_on_creation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    run_dir = tmp_path / "runs" / "run-abc123"
    target_dir = run_dir / "target"
    original_mkdir = Path.mkdir

    def fail_for_target_subdir(self: Path, *args: object, **kwargs: object) -> None:
        if self == target_dir:
            raise PermissionError("permission denied")
        original_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_for_target_subdir)

    with pytest.raises(ManifestStateError, match="failed to create run"):
        store.create_run(request(run_id="run-abc123"))

    assert not run_dir.exists()


def test_artifact_store_rejects_source_checkout_as_root(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)

    with pytest.raises(ManifestStateError, match="artifact root overlaps source path"):
        ArtifactStore(source, source_paths=[source])


def test_artifact_store_wraps_artifact_root_creation_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"
    original_mkdir = Path.mkdir

    def fail_for_artifact_root(self: Path, *args: object, **kwargs: object) -> None:
        if self == artifact_root:
            raise PermissionError("permission denied")
        original_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_for_artifact_root)

    with pytest.raises(ManifestStateError, match="failed to create artifact root"):
        ArtifactStore(artifact_root, source_paths=[source])


def test_manifest_round_trips_and_records_schema_version(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    created = store.create_run(request(run_id="run-abc123"))

    loaded = store.load_manifest("run-abc123")

    assert loaded == created
    assert loaded.schema_version == 1
    assert loaded.writer_version == "0.1.0"


def test_completed_step_result_is_not_overwritten(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))
    result = StepResult(step_name="create_run", status=StepStatus.SUCCEEDED, summary="created")

    updated = store.record_step_result("run-abc123", result)
    repeated = store.record_step_result(
        "run-abc123",
        StepResult(step_name="create_run", status=StepStatus.SUCCEEDED, summary="changed"),
    )

    assert updated.step_results["create_run"].summary == "created"
    assert repeated.step_results["create_run"].summary == "created"


def test_existing_manifest_lock_returns_structured_state_error(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))
    lock_path = tmp_path / "runs" / "run-abc123" / ".manifest.lock"
    lock_path.write_text("12345", encoding="utf-8")

    with pytest.raises(ManifestStateError, match="manifest is locked"):
        store.record_step_result(
            "run-abc123",
            StepResult(step_name="create_run", status=StepStatus.SUCCEEDED, summary="created"),
        )


def test_record_step_result_for_missing_run_returns_state_error(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])

    with pytest.raises(ManifestStateError, match="failed to lock manifest"):
        store.record_step_result(
            "run-abc123",
            StepResult(step_name="create_run", status=StepStatus.SUCCEEDED, summary="created"),
        )


def test_load_manifest_rejects_unsafe_run_id_as_state_error(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])

    with pytest.raises(ManifestStateError, match="unsafe"):
        store.load_manifest("../run-abc123")
