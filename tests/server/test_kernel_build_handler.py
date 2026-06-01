import inspect
import subprocess
import threading
from pathlib import Path
from unittest.mock import patch

from conftest import NoopBuildRunner as NoopRunner
from conftest import add_merge_config_script, make_source_tree
from handler_call_helpers import kernel_build_handler

from kdive.artifacts.handlers import create_run_handler
from kdive.kernel import handlers as kernel_handlers
from kdive.providers.local.build.local_kernel_build import (
    LocalKernelBuildProvider,
)
from kdive.providers.local.build.local_kernel_build import (
    _extract_build_id as _REAL_EXTRACT_BUILD_ID,
)

# Task 4 R2-F6: the build success path now extracts and records build_id by
# running readelf against vmlinux. Most handler/workflow tests in this suite
# do not produce a real vmlinux (runners are faked), so conftest.py installs
# an autouse fixture that stubs `_extract_build_id` to a constant. Tests
# that need the real body re-patch via _REAL_EXTRACT_BUILD_ID (captured at
# module-load time, before the autouse fixture runs).


def test_kernel_build_handler_uses_request_runtime_contract() -> None:
    signature = inspect.signature(kernel_handlers.kernel_build_handler)

    assert set(signature.parameters) == {"request", "runtime"}
    assert all(parameter.kind is inspect.Parameter.KEYWORD_ONLY for parameter in signature.parameters.values())


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


def create_run(tmp_path: Path, *, build_profile: str = "x86_64-default") -> tuple[Path, Path]:
    source = make_source_tree(tmp_path, with_config=True)
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
    from kdive.artifacts.store import ArtifactStore
    from kdive.domain import RunRequest

    source = make_source_tree(tmp_path, with_config=True)
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


def test_default_build_profile_uses_defconfig_base_config() -> None:
    from kdive.server import DEFAULT_BUILD_PROFILES

    assert DEFAULT_BUILD_PROFILES["x86_64-default"].base_config == ["defconfig"]


def test_default_build_profiles_include_x86_64_debug() -> None:
    from kdive.server import DEFAULT_BUILD_PROFILES

    profile = DEFAULT_BUILD_PROFILES["x86_64-debug"]
    assert profile.base_config == ["defconfig"]
    assert profile.config_lines == [
        "CONFIG_VIRTIO=y",
        "CONFIG_VIRTIO_PCI=y",
        "CONFIG_VIRTIO_BLK=y",
        "CONFIG_VIRTIO_NET=y",
        "CONFIG_VIRTIO_CONSOLE=y",
        "CONFIG_SERIAL_8250=y",
        "CONFIG_SERIAL_8250_CONSOLE=y",
        "CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y",
        "# CONFIG_RANDOMIZE_BASE is not set",
    ]


def test_build_overrides_base_config_replaces_profile_value(tmp_path: Path) -> None:
    from kdive.artifacts.store import ArtifactStore
    from kdive.config import BuildOverrides

    source = make_source_tree(tmp_path, with_config=True)
    artifact_root = tmp_path / "runs"
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        build_overrides=BuildOverrides(base_config=["tinyconfig"]),
    )

    assert created.ok is True
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert manifest.resolved_build_profile is not None
    # Replacement, not a merge with the profile's ["defconfig"].
    assert manifest.resolved_build_profile.base_config == ["tinyconfig"]


def test_kernel_build_without_config_or_base_config_returns_suggested_fix(tmp_path: Path) -> None:
    from kdive.artifacts.store import ArtifactStore
    from kdive.domain import StepStatus

    source = make_source_tree(tmp_path)  # no developer .config
    artifact_root = tmp_path / "runs"
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile_spec={"name": "no-base", "architecture": "x86_64", "base_config": []},
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )
    assert created.ok is True

    # No provider injected: rung 4 raises before any make/runner call, so the real provider is safe.
    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "base_config" in response.error.details["suggested_fix"]
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert manifest.step_results["build"].status == StepStatus.FAILED


def test_kernel_build_failure_response_includes_artifacts(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    provider = LocalKernelBuildProvider(runner=FailingRunner())

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)

    assert response.ok is False
    assert {artifact.kind for artifact in response.artifacts} == {"build-log", "build-summary"}


def test_kernel_build_response_redacts_secret_make_variable(tmp_path: Path) -> None:
    from kdive.config import BuildOverrides

    source = make_source_tree(tmp_path, with_config=True)
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
    from kdive.artifacts.store import ArtifactStore
    from kdive.domain import StepResult, StepStatus

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
    assert response.status == StepStatus.RUNNING
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert "previous build is still recorded as running" in response.error.message
    assert runner.commands == []


def test_kernel_build_existing_running_state_takes_precedence_over_missing_source(tmp_path: Path) -> None:
    source, artifact_root = create_run(tmp_path)
    from kdive.artifacts.store import ArtifactStore
    from kdive.domain import StepResult, StepStatus

    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(
        "run-abc123",
        StepResult(step_name="build", status=StepStatus.RUNNING, summary="kernel build running"),
    )
    (source / "Kconfig").unlink()

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.status == StepStatus.RUNNING
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert "previous build is still recorded as running" in response.error.message


def test_kernel_build_existing_build_lock_returns_failure(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    from kdive.artifacts.store import ArtifactStore

    store = ArtifactStore(artifact_root, create_root=False)
    with store.build_lock("run-abc123"):
        response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert "build is locked" in response.error.message


def test_kernel_build_unexpected_provider_exception_records_failed_result(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    from kdive.artifacts.store import ArtifactStore
    from kdive.domain import StepStatus

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
    from kdive.artifacts.store import ArtifactStore
    from kdive.domain import StepStatus

    build_dir = artifact_root / "run-abc123" / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=TransientManifestLockRunner())

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)

    assert response.ok is True
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert manifest.step_results["build"].status == StepStatus.SUCCEEDED


def test_build_applies_config_lines_before_main_make(tmp_path: Path) -> None:
    from kdive.config import BuildOverrides

    source = make_source_tree(tmp_path, with_config=True)
    add_merge_config_script(source)
    artifact_root = tmp_path / "runs"
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        build_overrides=BuildOverrides(config_lines=["CONFIG_DEBUG_INFO=y"]),
    )
    assert created.ok is True
    build_dir = artifact_root / "run-abc123" / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")

    runner = NoopRunner()
    response = kernel_build_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=LocalKernelBuildProvider(runner=runner),
    )

    assert response.ok is True
    assert len(runner.commands) == 3
    assert runner.commands[0][0].endswith("merge_config.sh")
    assert runner.commands[1][-1] == "olddefconfig"
    assert runner.commands[2][-1] == "bzImage"
    override = (build_dir.parent / "inputs" / "override.config").read_text(encoding="utf-8")
    assert override == "CONFIG_DEBUG_INFO=y\n"


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


def test_readelf_unavailable_fails_build(tmp_path: Path) -> None:
    # Spec §9.1 / §7 R2-F6: ReadelfUnavailable -> step FAILED;
    # ErrorCategory.INFRASTRUCTURE_FAILURE; code=readelf_unavailable.
    from kdive.artifacts.store import ArtifactStore
    from kdive.domain import StepStatus
    from kdive.providers.local.build.local_kernel_build import ReadelfUnavailable

    _, artifact_root = create_run(tmp_path)
    build_dir = artifact_root / "run-abc123" / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")

    with patch(
        "kdive.providers.local.build.local_kernel_build._extract_build_id",
        side_effect=ReadelfUnavailable("readelf not found"),
    ):
        response = kernel_build_handler(
            artifact_root=artifact_root,
            run_id="run-abc123",
            provider=LocalKernelBuildProvider(runner=NoopRunner()),
        )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert response.error.details["code"] == "readelf_unavailable"
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert manifest.step_results["build"].status == StepStatus.FAILED


def test_build_id_missing_fails_build(tmp_path: Path) -> None:
    # Spec §9.1 / §7 R2-F6: BuildIdMissing -> step FAILED;
    # ErrorCategory.BUILD_FAILURE; code=build_id_missing.
    from kdive.artifacts.store import ArtifactStore
    from kdive.domain import StepStatus
    from kdive.providers.local.build.local_kernel_build import BuildIdMissing

    _, artifact_root = create_run(tmp_path)
    build_dir = artifact_root / "run-abc123" / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")

    with patch(
        "kdive.providers.local.build.local_kernel_build._extract_build_id",
        side_effect=BuildIdMissing("no Build ID note"),
    ):
        response = kernel_build_handler(
            artifact_root=artifact_root,
            run_id="run-abc123",
            provider=LocalKernelBuildProvider(runner=NoopRunner()),
        )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "build_failure"
    assert response.error.details["code"] == "build_id_missing"
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert manifest.step_results["build"].status == StepStatus.FAILED


def test_build_id_missing_failure_preserves_vmlinux_artifact(tmp_path: Path) -> None:
    # Plan review finding 6 (R6-F2 rewrite): build artifacts MUST survive a
    # build_id extraction failure so operators can diagnose why readelf came up
    # empty without re-running the build. Round-6 review caught that patching
    # `_extract_build_id` with `side_effect=BuildIdMissing(..., artifacts=...)`
    # was inert because the provider's catch arm re-wraps with
    # `artifacts=self._detect_artifacts(...)` — the injected payload was
    # unconditionally overwritten.
    #
    # This test exercises the FULL provider hoist + handler consume path:
    # restore the real `_extract_build_id` (overriding the module's autouse
    # stub), mock at the deepest seam (`subprocess.run`) so readelf returns
    # cleanly with no Build ID note, and pre-create the artifacts that
    # `_detect_artifacts` discovers on disk (paths per local_kernel_build.py).
    from kdive.artifacts.store import ArtifactStore

    _, artifact_root = create_run(tmp_path)
    build_dir = artifact_root / "run-abc123" / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    # Pre-create vmlinux on disk so `_detect_artifacts` lists it.
    (build_dir / "vmlinux").write_text("symbols", encoding="utf-8")

    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout="no notes here\n", stderr="")
    # Restore the real `_extract_build_id` (the module's autouse fixture stubs
    # it) so the provider invokes the real readelf-running body, and mock the
    # `subprocess.run` seam underneath so readelf returns "no Build ID note".
    with (
        patch(
            "kdive.providers.local.build.local_kernel_build._extract_build_id",
            _REAL_EXTRACT_BUILD_ID,
        ),
        patch(
            "kdive.providers.local.build.local_kernel_build.subprocess.run",
            return_value=fake,
        ),
    ):
        response = kernel_build_handler(
            artifact_root=artifact_root,
            run_id="run-abc123",
            provider=LocalKernelBuildProvider(runner=NoopRunner()),
        )

    assert response.ok is False
    assert response.error.details["code"] == "build_id_missing"
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    artifact_kinds = {a.kind for a in manifest.step_results["build"].artifacts}
    assert "vmlinux" in artifact_kinds
    assert "build-log" in artifact_kinds
