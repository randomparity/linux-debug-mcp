import threading
from pathlib import Path

from linux_debug_mcp.providers.local_kernel_build import LocalKernelBuildProvider
from linux_debug_mcp.server import create_run_handler, kernel_build_handler


class NoopRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}"

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        self.commands.append(argv)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("ok\n", encoding="utf-8")
        return 0


class BlockingRunner(NoopRunner):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        self.commands.append(argv)
        self.started.set()
        self.release.wait(timeout=5)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("ok\n", encoding="utf-8")
        return 0


class RaisingRunner(NoopRunner):
    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        self.commands.append(argv)
        raise RuntimeError("boom")


class FailingRunner(NoopRunner):
    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        self.commands.append(argv)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("build failed\n", encoding="utf-8")
        return 2


class TransientManifestLockRunner(NoopRunner):
    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        result = super().run(argv, timeout=timeout, log_path=log_path, env=env, cwd=cwd)
        lock_path = log_path.parents[1] / ".manifest.lock"
        lock_path.write_text("transient", encoding="utf-8")

        def release_lock() -> None:
            lock_path.unlink(missing_ok=True)

        threading.Timer(0.02, release_lock).start()
        return result


def make_source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    return source


def create_run(tmp_path: Path, *, build_profile: str = "x86_64-default") -> tuple[Path, Path]:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"
    create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile=build_profile,
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )
    return source, artifact_root


def test_kernel_build_rejects_force_rebuild_true(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", force_rebuild=True)

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "force_rebuild=true" in response.error.message


def test_kernel_build_rejects_profile_mismatch(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path, build_profile="x86_64-default")

    response = kernel_build_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        build_profile="clang",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_kernel_build_rejects_missing_manifest_profile(tmp_path: Path) -> None:
    # create_run_handler now rejects an unknown base profile fail-fast (covered by
    # test_create_run_rejects_unknown_base_profile). The build-time guard still
    # protects a legacy/v1 manifest whose recorded build profile is unknown and
    # carries no resolved_build_profile, so build that scenario via the store.
    from linux_debug_mcp.artifacts.store import ArtifactStore
    from linux_debug_mcp.domain import RunRequest

    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"
    store = ArtifactStore(artifact_root, source_paths=[source])
    store.create_run(
        RunRequest(
            source_path=str(source),
            build_profile="unknown-profile",
            target_profile="local-qemu",
            rootfs_profile="minimal",
            run_id="run-abc123",
        )
    )

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "unknown build profile" in response.error.message


def test_kernel_build_missing_run_is_configuration_error(tmp_path: Path) -> None:
    artifact_root = tmp_path / "runs"
    artifact_root.mkdir()

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-missing")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "run not found" in response.error.message


def test_kernel_build_fails_without_developer_config(tmp_path: Path) -> None:
    source, artifact_root = create_run(tmp_path)
    (source / ".config").unlink()
    from linux_debug_mcp.artifacts.store import ArtifactStore
    from linux_debug_mcp.domain import StepStatus

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert manifest.step_results["build"].status == StepStatus.FAILED


def test_kernel_build_failure_response_includes_artifacts(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    provider = LocalKernelBuildProvider(runner=FailingRunner())

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)

    assert response.ok is False
    assert {artifact.kind for artifact in response.artifacts} == {"build-log", "build-summary"}


def test_kernel_build_response_redacts_secret_make_variable(tmp_path: Path) -> None:
    from linux_debug_mcp.config import BuildOverrides

    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        build_overrides=BuildOverrides(make_variables={"API_TOKEN": "supersecret"}),
    )
    assert created.ok is True
    build_dir = artifact_root / "run-abc123" / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")

    response = kernel_build_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=LocalKernelBuildProvider(runner=NoopRunner()),
    )

    assert response.ok is True
    flattened = str(response.data)
    # the secret-shaped make variable reaches the build argv but must not leak unredacted
    assert "supersecret" not in flattened
    assert "API_TOKEN=[REDACTED]" in flattened

    # the repeat-build path (_recorded_build_success_response) must redact too
    repeat = kernel_build_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=LocalKernelBuildProvider(runner=NoopRunner()),
    )
    assert repeat.ok is True
    assert "supersecret" not in str(repeat.data)


def test_kernel_build_repeat_success_returns_recorded_result(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    build_dir = artifact_root / "run-abc123" / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    runner = NoopRunner()
    provider = LocalKernelBuildProvider(runner=runner)

    first = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)
    second = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)

    assert first.ok is True
    assert second.ok is True
    assert second.summary == first.summary
    assert second.data["output_path"] == first.data["output_path"]
    assert len(runner.commands) == 1


def test_kernel_build_existing_running_state_fails_without_rerun(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    from linux_debug_mcp.artifacts.store import ArtifactStore
    from linux_debug_mcp.domain import StepResult, StepStatus

    runner = NoopRunner()
    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(
        "run-abc123",
        StepResult(step_name="build", status=StepStatus.RUNNING, summary="kernel build running"),
    )

    response = kernel_build_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=LocalKernelBuildProvider(runner=runner),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert "previous build is still recorded as running" in response.error.message
    assert runner.commands == []


def test_kernel_build_existing_running_state_takes_precedence_over_missing_source(tmp_path: Path) -> None:
    source, artifact_root = create_run(tmp_path)
    from linux_debug_mcp.artifacts.store import ArtifactStore
    from linux_debug_mcp.domain import StepResult, StepStatus

    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(
        "run-abc123",
        StepResult(step_name="build", status=StepStatus.RUNNING, summary="kernel build running"),
    )
    (source / "Kconfig").unlink()

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert "previous build is still recorded as running" in response.error.message


def test_kernel_build_existing_build_lock_returns_failure(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    from linux_debug_mcp.artifacts.store import ArtifactStore

    store = ArtifactStore(artifact_root, create_root=False)
    with store.build_lock("run-abc123"):
        response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert "build is locked" in response.error.message


def test_kernel_build_unexpected_provider_exception_records_failed_result(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    from linux_debug_mcp.artifacts.store import ArtifactStore
    from linux_debug_mcp.domain import StepStatus

    runner = RaisingRunner()
    provider = LocalKernelBuildProvider(runner=runner)

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert "unexpected build provider failure" in response.error.message
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert manifest.step_results["build"].status == StepStatus.FAILED
    assert manifest.step_results["build"].summary == "unexpected build provider failure"


def test_kernel_build_retries_terminal_result_write_after_transient_manifest_lock(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    from linux_debug_mcp.artifacts.store import ArtifactStore
    from linux_debug_mcp.domain import StepStatus

    build_dir = artifact_root / "run-abc123" / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=TransientManifestLockRunner())

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)

    assert response.ok is True
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert manifest.step_results["build"].status == StepStatus.SUCCEEDED


def test_kernel_build_concurrent_calls_only_start_one_subprocess(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    build_dir = artifact_root / "run-abc123" / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    runner = BlockingRunner()
    provider = LocalKernelBuildProvider(runner=runner)
    responses = []

    first = threading.Thread(
        target=lambda: responses.append(
            kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)
        )
    )
    first.start()
    assert runner.started.wait(timeout=5)

    second = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)
    runner.release.set()
    first.join(timeout=5)

    assert not first.is_alive()
    assert len(runner.commands) == 1
    assert {response.ok for response in [*responses, second]} == {True, False}
    assert second.ok is False
    assert second.error is not None
    assert second.error.category == "infrastructure_failure"
    assert "build is locked" in second.error.message
