import os
from pathlib import Path

import pytest
from conftest import make_source_tree

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
    assert loaded.schema_version == 3
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


def test_run_dir_returns_validated_run_path(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    assert store.run_dir("run-abc123") == tmp_path / "runs" / "run-abc123"


def test_build_lock_excludes_concurrent_builds(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    with (
        store.build_lock("run-abc123"),
        pytest.raises(ManifestStateError, match="build is locked"),
        store.build_lock("run-abc123"),
    ):
        pass


def test_boot_lock_excludes_concurrent_boots(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    with (
        store.boot_lock("run-abc123"),
        pytest.raises(ManifestStateError, match="boot is locked"),
        store.boot_lock("run-abc123"),
    ):
        pass


def test_tests_lock_excludes_concurrent_test_runs(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    with (
        store.tests_lock("run-abc123"),
        pytest.raises(ManifestStateError, match="tests are locked"),
        store.tests_lock("run-abc123"),
    ):
        pass


def test_collect_lock_excludes_concurrent_collection(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    with (
        store.collect_lock("run-abc123"),
        pytest.raises(ManifestStateError, match="artifact collection is locked"),
        store.collect_lock("run-abc123"),
    ):
        pass


def test_debug_lock_serializes_per_run(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    manifest = store.create_run(
        RunRequest(
            source_path=str(tmp_path),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
            run_id="run-debug-lock",
        )
    )

    with (
        store.debug_lock(manifest.run_id),
        pytest.raises(ManifestStateError, match="debug is locked"),
        store.debug_lock(manifest.run_id),
    ):
        pass


def test_running_build_result_can_be_replaced_by_success(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    store.record_step_result(
        "run-abc123",
        StepResult(step_name="build", status=StepStatus.RUNNING, summary="build running"),
    )
    manifest = store.record_step_result(
        "run-abc123",
        StepResult(step_name="build", status=StepStatus.SUCCEEDED, summary="build succeeded"),
    )

    assert manifest.step_results["build"].summary == "build succeeded"
    assert manifest.step_results["build"].status == StepStatus.SUCCEEDED


def test_succeeded_boot_result_can_be_replaced_when_explicit(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    store.record_step_result("run-abc123", StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="old"))
    manifest = store.record_step_result(
        "run-abc123",
        StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="new"),
        replace_succeeded=True,
    )

    assert manifest.step_results["boot"].summary == "new"


def test_target_lock_excludes_concurrent_domain_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = make_source_tree(tmp_path)
    store_a = ArtifactStore(tmp_path / "runs-a", source_paths=[source])
    store_b = ArtifactStore(tmp_path / "runs-b", source_paths=[source])
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))

    with (
        store_a.target_lock("mcp-linux-debug-dev"),
        pytest.raises(ManifestStateError, match="target domain is locked"),
        store_b.target_lock("mcp-linux-debug-dev"),
    ):
        pass


def test_target_lock_fallback_creates_private_lock_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr("linux_debug_mcp.artifacts.store.tempfile.gettempdir", lambda: str(tmp_path))

    with store.target_lock("mcp-linux-debug-dev"):
        pass

    lock_dir = next(tmp_path.glob("linux-debug-mcp-*/locks"))
    assert lock_dir.stat().st_mode & 0o777 == 0o700


def test_target_lock_rejects_unsafe_fallback_lock_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr("linux_debug_mcp.artifacts.store.tempfile.gettempdir", lambda: str(tmp_path))
    lock_dir = tmp_path / f"linux-debug-mcp-{os.getuid()}" / "locks"
    lock_dir.mkdir(parents=True)
    lock_dir.chmod(0o777)

    with (
        pytest.raises(ManifestStateError, match="unsafe target lock directory"),
        store.target_lock("mcp-linux-debug-dev"),
    ):
        pass


def test_target_lock_rejects_symlink_fallback_lock_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr("linux_debug_mcp.artifacts.store.tempfile.gettempdir", lambda: str(tmp_path))
    symlink_target = tmp_path / "symlink-target"
    symlink_target.mkdir()
    (tmp_path / f"linux-debug-mcp-{os.getuid()}").symlink_to(symlink_target, target_is_directory=True)

    with (
        pytest.raises(ManifestStateError, match="unsafe target lock directory"),
        store.target_lock("mcp-linux-debug-dev"),
    ):
        pass
