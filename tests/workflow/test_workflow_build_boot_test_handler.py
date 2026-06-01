from dataclasses import dataclass
from pathlib import Path

import pytest
from conftest import NoopBuildRunner as _NoopBuildRunner
from conftest import make_source_tree

import kdive.server as server_module
from kdive.artifacts.store import ArtifactStore
from kdive.config import (
    TARGET_DESTRUCTIVE_PERMISSIONS,
    BootOverrides,
    BuildOverrides,
    RootfsProfile,
    TargetProfile,
)
from kdive.config import (
    TestCommand as _TestCommand,
)
from kdive.config import (
    TestSuiteProfile as _TestSuiteProfile,
)
from kdive.debug.session_handlers import debug_start_session_handler
from kdive.domain import ArtifactRef, ErrorCategory, StepStatus, ToolResponse
from kdive.providers.local.build.local_kernel_build import LocalKernelBuildProvider
from kdive.providers.local.target.libvirt_qemu import BootExecutionResult
from kdive.providers.local.test.local_ssh_tests import TestExecutionResult as _TestExecutionResult
from kdive.server import (
    create_run_handler,
    kernel_build_handler,
    target_boot_handler,
    target_run_tests_handler,
    workflow_build_boot_test_handler,
)
from kdive.workflow import handlers as workflow_handlers
from kdive.workflow.handlers import WorkflowHandlerDependencies


def success(summary: str, *, run_id: str = "run-abc123") -> ToolResponse:
    return ToolResponse.success(summary=summary, run_id=run_id, data={"summary": summary})


def failure(category: ErrorCategory, message: str, *, run_id: str = "run-abc123") -> ToolResponse:
    return ToolResponse.failure(category=category, message=message, run_id=run_id)


def test_workflow_handlers_require_explicit_dependencies(tmp_path: Path) -> None:
    assert not hasattr(workflow_handlers, "configure_workflow_dependencies")
    assert not hasattr(workflow_handlers, "configure_workflow_handlers")
    assert not hasattr(workflow_handlers, "_WORKFLOW_DEPENDENCIES")

    with pytest.raises(TypeError, match="dependencies"):
        workflow_build_boot_test_handler(
            artifact_root=tmp_path / "runs",
            source_path=str(tmp_path),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )


def _install_workflow_dependencies(
    *,
    create_run=create_run_handler,
    kernel_build=server_module.kernel_build_handler,
    target_boot=server_module.target_boot_handler,
    target_run_tests=server_module.target_run_tests_handler,
    artifacts_collect=server_module.artifacts_collect_handler,
) -> WorkflowHandlerDependencies:
    dependencies = WorkflowHandlerDependencies(
        create_run_handler=create_run,
        kernel_build_handler=kernel_build,
        target_boot_handler=target_boot,
        target_run_tests_handler=target_run_tests,
        debug_start_session_handler=debug_start_session_handler,
        artifacts_collect_handler=artifacts_collect,
    )
    return dependencies


def test_workflow_runs_build_boot_tests_and_collects(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    dependencies = _install_workflow_dependencies(
        create_run=lambda **kwargs: success("created"),
        kernel_build=lambda **kwargs: calls.append("build") or success("built"),
        target_boot=lambda **kwargs: calls.append("boot") or success("booted"),
        target_run_tests=lambda **kwargs: calls.append("tests") or success("tested"),
        artifacts_collect=lambda **kwargs: calls.append("collect") or success("collected"),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        dependencies=dependencies,
    )

    assert response.ok is True
    assert calls == ["build", "boot", "tests", "collect"]
    assert response.data["latest_successful_step"] == "collect_artifacts"


def test_workflow_threads_safety_overrides_into_create_and_boot(tmp_path: Path) -> None:
    build_overrides = BuildOverrides(make_variables={"KCFLAGS": "-O2"})
    boot_overrides = BootOverrides(kernel_args=["panic=1"])
    sensitive_paths = [tmp_path / "sensitive"]
    build_profile_spec = {"name": "inline-build"}
    target_profile_spec = {"name": "inline-target"}
    rootfs_profile_spec = {"name": "inline-rootfs"}
    captured: dict[str, dict[str, object]] = {}

    dependencies = _install_workflow_dependencies(
        create_run=lambda **kwargs: captured.setdefault("create", kwargs) and success("created"),
        kernel_build=lambda **kwargs: success("built"),
        target_boot=lambda **kwargs: captured.setdefault("boot", kwargs) and success("booted"),
        target_run_tests=lambda **kwargs: success("tested"),
        artifacts_collect=lambda **kwargs: success("collected"),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        build_overrides=build_overrides,
        boot_overrides=boot_overrides,
        sensitive_paths=sensitive_paths,
        build_profile_spec=build_profile_spec,
        target_profile_spec=target_profile_spec,
        rootfs_profile_spec=rootfs_profile_spec,
        dependencies=dependencies,
    )

    assert response.ok is True
    assert captured["create"]["build_overrides"] == build_overrides
    assert captured["create"]["boot_overrides"] == boot_overrides
    assert captured["create"]["sensitive_paths"] == sensitive_paths
    assert captured["create"]["build_profile_spec"] == build_profile_spec
    assert captured["create"]["target_profile_spec"] == target_profile_spec
    assert captured["create"]["rootfs_profile_spec"] == rootfs_profile_spec
    assert captured["boot"]["boot_overrides"] == boot_overrides
    assert captured["boot"]["sensitive_paths"] == sensitive_paths


def test_workflow_accepts_explicit_dependencies_without_global_configuration(tmp_path: Path) -> None:
    calls: list[str] = []
    dependencies = WorkflowHandlerDependencies(
        create_run_handler=lambda **kwargs: success("created"),
        kernel_build_handler=lambda **kwargs: calls.append("build") or success("built"),
        target_boot_handler=lambda **kwargs: calls.append("boot") or success("booted"),
        target_run_tests_handler=lambda **kwargs: calls.append("tests") or success("tested"),
        debug_start_session_handler=debug_start_session_handler,
        artifacts_collect_handler=lambda **kwargs: calls.append("collect") or success("collected"),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        dependencies=dependencies,
    )

    assert response.ok is True
    assert calls == ["build", "boot", "tests", "collect"]


def test_workflow_collects_and_returns_build_failure(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    dependencies = _install_workflow_dependencies(
        create_run=lambda **kwargs: success("created"),
        kernel_build=lambda **kwargs: calls.append("build") or failure(ErrorCategory.BUILD_FAILURE, "build failed"),
        artifacts_collect=lambda **kwargs: calls.append("collect") or success("collected"),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        dependencies=dependencies,
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "build_failure"
    assert response.error.details["failing_step"] == "build"
    assert calls == ["build", "collect"]


def test_workflow_collects_after_test_failure(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    dependencies = _install_workflow_dependencies(
        create_run=lambda **kwargs: success("created"),
        kernel_build=lambda **kwargs: calls.append("build") or success("built"),
        target_boot=lambda **kwargs: calls.append("boot") or success("booted"),
        target_run_tests=lambda **kwargs: calls.append("tests") or failure(ErrorCategory.TEST_FAILURE, "tests failed"),
        artifacts_collect=lambda **kwargs: calls.append("collect") or success("collected"),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        dependencies=dependencies,
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.details["failing_step"] == "run_tests"
    assert calls == ["build", "boot", "tests", "collect"]


def test_workflow_rejects_existing_run_request_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    artifact_root = tmp_path / "runs"
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        test_suite="smoke-basic",
    )
    assert created.ok is True

    response = workflow_build_boot_test_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="other-build-profile",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        test_suite="smoke-basic",
        dependencies=WorkflowHandlerDependencies(
            create_run_handler=create_run_handler,
            kernel_build_handler=server_module.kernel_build_handler,
            target_boot_handler=server_module.target_boot_handler,
            target_run_tests_handler=server_module.target_run_tests_handler,
            debug_start_session_handler=debug_start_session_handler,
            artifacts_collect_handler=server_module.artifacts_collect_handler,
        ),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "immutable run manifest request" in response.error.message


def test_workflow_existing_run_uses_manifest_test_suite_when_omitted(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    artifact_root = tmp_path / "runs"
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        test_suite="smoke-basic",
    )
    assert created.ok is True

    captured_tests: dict[str, object] = {}

    def fake_run_tests(**kwargs: object) -> ToolResponse:
        captured_tests.update(kwargs)
        return success("tested")

    dependencies = _install_workflow_dependencies(
        kernel_build=lambda **kwargs: success("built"),
        target_boot=lambda **kwargs: success("booted"),
        target_run_tests=fake_run_tests,
        artifacts_collect=lambda **kwargs: success("collected"),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        dependencies=dependencies,
    )

    assert response.ok is True
    assert captured_tests["test_suite"] == "smoke-basic"


def test_workflow_forwards_acknowledged_permissions_to_run_tests(tmp_path: Path) -> None:
    captured_tests: dict[str, object] = {}

    def fake_run_tests(**kwargs: object) -> ToolResponse:
        captured_tests.update(kwargs)
        return success("tested")

    dependencies = _install_workflow_dependencies(
        create_run=lambda **kwargs: success("created"),
        kernel_build=lambda **kwargs: success("built"),
        target_boot=lambda **kwargs: success("booted"),
        target_run_tests=fake_run_tests,
        artifacts_collect=lambda **kwargs: success("collected"),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        commands=[["uname", "-a"]],
        acknowledged_permissions=TARGET_DESTRUCTIVE_PERMISSIONS["target.run_tests"],
        dependencies=dependencies,
    )

    assert response.ok is True
    assert captured_tests["acknowledged_permissions"] == TARGET_DESTRUCTIVE_PERMISSIONS["target.run_tests"]


def test_workflow_creates_missing_supplied_run_id_exactly(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}
    calls: list[str] = []

    def fake_create_run(**kwargs: object) -> ToolResponse:
        captured.update(kwargs)
        return success("created", run_id=str(kwargs["run_id"]))

    dependencies = _install_workflow_dependencies(
        create_run=fake_create_run,
        kernel_build=lambda **kwargs: calls.append("build") or success("built", run_id="run-explicit"),
        target_boot=lambda **kwargs: calls.append("boot") or success("booted", run_id="run-explicit"),
        target_run_tests=lambda **kwargs: calls.append("tests") or success("tested", run_id="run-explicit"),
        artifacts_collect=lambda **kwargs: calls.append("collect") or success("collected", run_id="run-explicit"),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-explicit",
        dependencies=dependencies,
    )

    assert response.ok is True
    assert captured["run_id"] == "run-explicit"
    assert calls == ["build", "boot", "tests", "collect"]


# ---------------------------------------------------------------------------
# End-to-end override flow helpers (no monkeypatching; real handlers + fakes)
# ---------------------------------------------------------------------------


@dataclass
class _FakeBootPlan:
    run_id: str
    domain_name: str
    boot_log_path: Path
    boot_plan_path: Path
    boot_summary_path: Path
    debug_gdbstub: bool = False
    gdbstub_endpoint: dict[str, object] | None = None
    nokaslr_source: str = "not_applicable"


class _FakeBootProvider:
    name = "local-libvirt-qemu"

    def __init__(self) -> None:
        self.plans: list[dict[str, object]] = []
        self.executions: list[dict[str, object]] = []

    def plan_boot(
        self,
        *,
        run_id: str,
        run_dir: Path,
        kernel_image_path: Path,
        target_profile: TargetProfile,
        rootfs_profile: RootfsProfile,
        attempt: int = 1,
    ) -> _FakeBootPlan:
        self.plans.append(
            {
                "run_id": run_id,
                "target_profile": target_profile,
                "rootfs_profile": rootfs_profile,
                "attempt": attempt,
            }
        )
        return _FakeBootPlan(
            run_id=run_id,
            domain_name=target_profile.target_ref or target_profile.name,
            boot_log_path=run_dir / "boot" / f"attempt-{attempt}" / "boot.log",
            boot_plan_path=run_dir / "boot" / f"attempt-{attempt}" / "boot-plan.json",
            boot_summary_path=run_dir / "boot" / f"attempt-{attempt}" / "boot-summary.json",
        )

    def execute_boot(
        self,
        plan: _FakeBootPlan,
        *,
        force_reboot: bool = False,
        retrying_after_failure: bool = False,
    ) -> BootExecutionResult:
        self.executions.append({"run_id": plan.run_id, "attempt": len(self.executions) + 1})
        plan.boot_log_path.parent.mkdir(parents=True, exist_ok=True)
        plan.boot_log_path.write_text("boot log\n", encoding="utf-8")
        plan.boot_plan_path.write_text("{}\n", encoding="utf-8")
        plan.boot_summary_path.write_text("{}\n", encoding="utf-8")
        return BootExecutionResult(
            status=StepStatus.SUCCEEDED,
            summary="target booted",
            details={"domain": plan.domain_name, "debug_boot": False, "gdbstub_endpoint": None},
            artifacts=[ArtifactRef(path=str(plan.boot_log_path), kind="boot-log")],
        )


class _FakeTestProvider:
    name = "local-ssh-tests"

    def __init__(self) -> None:
        self.executions = 0

    def plan_tests(self, **kwargs: object) -> object:
        return {"plan": kwargs}

    def execute_tests(self, plan: object) -> _TestExecutionResult:
        self.executions += 1
        return _TestExecutionResult(
            status=StepStatus.SUCCEEDED,
            summary="test suite smoke-basic passed: 1 passed, 0 failed",
            artifacts=[],
            details={"counts": {"passed": 1, "failed": 0}, "commands": []},
        )


def _make_e2e_profiles(
    tmp_path: Path,
) -> tuple[
    dict[str, TargetProfile],
    dict[str, RootfsProfile],
    dict[str, _TestSuiteProfile],
]:
    rootfs_img = tmp_path / "minimal.img"
    rootfs_img.write_text("rootfs\n", encoding="utf-8")
    target = TargetProfile(
        name="local-qemu",
        architecture="x86_64",
        target_ref="kdive-dev",
        managed_domain=True,
        managed_domain_prefix="kdive-",
        libvirt_uri="qemu:///system",
    )
    rootfs = RootfsProfile(
        name="minimal",
        source=str(rootfs_img),
        mutability="read_only",
        readiness_marker="ready",
        ssh_host="127.0.0.1",
        ssh_user="root",
    )
    suite = _TestSuiteProfile(
        name="smoke-basic",
        commands=[_TestCommand(name="uname", argv=["uname", "-a"])],
    )
    return (
        {target.name: target},
        {rootfs.name: rootfs},
        {suite.name: suite},
    )


def test_override_flow_end_to_end(tmp_path: Path) -> None:
    """End-to-end: create_run overrides → attempt 1 → attempt 2 (no accumulation) → build reused → run_tests ok."""
    run_id = "run-override-e2e"
    source = make_source_tree(tmp_path, with_config=True)
    artifact_root = tmp_path / "runs"
    target_profiles, rootfs_profiles, test_suites = _make_e2e_profiles(tmp_path)

    # Step 1: create_run with build and boot overrides.
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id=run_id,
        build_overrides=BuildOverrides(make_variables={"CC": "clang"}),
        boot_overrides=BootOverrides(kernel_args=["dhash_entries=1"]),
    )
    assert created.ok is True

    # Verify the resolved build profile was frozen with CC=clang.
    store = ArtifactStore(artifact_root, create_root=False)
    manifest = store.load_manifest(run_id)
    assert manifest.resolved_build_profile is not None
    assert manifest.resolved_build_profile.make_variables == {"CC": "clang"}

    # Step 2: kernel_build_handler with a NoopRunner — pre-create bzImage so detection succeeds.
    build_dir = artifact_root / run_id / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel\n", encoding="utf-8")
    noop_runner = _NoopBuildRunner()
    build_response = kernel_build_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=LocalKernelBuildProvider(runner=noop_runner),
    )
    assert build_response.ok is True

    # build_argv must include CC=clang (resolved profile reaches the provider plan).
    assert any("CC=clang" in arg for arg in noop_runner.commands[0])

    # Step 3: first boot — applies create_run boot_overrides (dhash_entries=1) as attempt 1.
    boot_provider = _FakeBootProvider()
    boot1 = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=boot_provider,
        target_profiles=target_profiles,
        rootfs_profiles=rootfs_profiles,
        acknowledged_permissions=TARGET_DESTRUCTIVE_PERMISSIONS["target.boot"],
    )
    assert boot1.ok is True
    manifest = store.load_manifest(run_id)
    assert [a.attempt for a in manifest.boot_attempts] == [1]
    assert "dhash_entries=1" in manifest.boot_attempts[0].resolved_target_profile.kernel_args

    # Step 4: second boot with NEW overrides (dhash_entries=2) → attempt 2; no accumulation; build not re-run.
    boot2 = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=boot_provider,
        boot_overrides=BootOverrides(kernel_args=["dhash_entries=2"]),
        target_profiles=target_profiles,
        rootfs_profiles=rootfs_profiles,
        acknowledged_permissions=TARGET_DESTRUCTIVE_PERMISSIONS["target.boot"],
    )
    assert boot2.ok is True
    manifest = store.load_manifest(run_id)
    assert [a.attempt for a in manifest.boot_attempts] == [1, 2]
    attempt2_args = manifest.boot_attempts[1].resolved_target_profile.kernel_args
    assert "dhash_entries=2" in attempt2_args
    assert "dhash_entries=1" not in attempt2_args  # no accumulation across attempts

    # Build was NOT re-run (runner was only called once, for the build step).
    assert len(noop_runner.commands) == 1

    # Step 5: run_tests succeeds and binds to attempt 2's rootfs.
    test_provider = _FakeTestProvider()
    tests_response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=test_provider,
        rootfs_profiles=rootfs_profiles,
        test_suites=test_suites,
    )
    assert tests_response.ok is True
    assert test_provider.executions == 1
