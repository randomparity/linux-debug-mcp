from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import RootfsProfile, TargetProfile
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus
from linux_debug_mcp.providers.libvirt_qemu import BootExecutionResult, ProviderBootError
from linux_debug_mcp.providers.local_ssh_tests import TestExecutionResult
from linux_debug_mcp.server import create_run_handler


def make_source_tree(base: Path, *, with_config: bool = False) -> Path:
    """Create a minimal Linux source tree (``Kconfig`` + ``Makefile``) under ``base/linux``.

    With ``with_config=True`` also writes a developer ``.config`` so prepare_config succeeds.
    """
    source = base / "linux"
    source.mkdir(parents=True)
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    if with_config:
        (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    return source


def add_merge_config_script(source: Path) -> Path:
    """Add ``scripts/kconfig/merge_config.sh`` to an existing source tree for config-merge tests."""
    script = source / "scripts" / "kconfig" / "merge_config.sh"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    return script


class NoopBuildRunner:
    """BuildRunner fake: reports every tool present, records commands, writes the log, returns 0."""

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


# ---------------------------------------------------------------------------
# Shared boot-handler fakes (from test_target_boot_handler)
# ---------------------------------------------------------------------------


@dataclass
class Plan:
    run_id: str
    domain_name: str
    boot_log_path: Path
    boot_plan_path: Path
    boot_summary_path: Path
    debug_gdbstub: bool = False
    gdbstub_endpoint: dict[str, object] | None = None
    nokaslr_source: str = "not_applicable"


class FakeBootProvider:
    name = "local-libvirt-qemu"

    def __init__(
        self,
        *,
        status: StepStatus = StepStatus.SUCCEEDED,
        summary: str = "target booted",
        error_category: ErrorCategory | None = None,
        block: bool = False,
        raise_on_plan: ProviderBootError | None = None,
        raise_on_execute: Exception | None = None,
    ) -> None:
        self.status = status
        self.summary = summary
        self.error_category = error_category
        self.block = block
        self.raise_on_plan = raise_on_plan
        self.raise_on_execute = raise_on_execute
        self.plans: list[dict[str, object]] = []
        self.executions: list[dict[str, object]] = []
        self.started = threading.Event()
        self.release = threading.Event()

    def plan_boot(
        self,
        *,
        run_id: str,
        run_dir: Path,
        kernel_image_path: Path,
        target_profile: TargetProfile,
        rootfs_profile: RootfsProfile,
        attempt: int = 1,
    ) -> Plan:
        if self.raise_on_plan is not None:
            raise self.raise_on_plan
        self.plans.append(
            {
                "run_id": run_id,
                "run_dir": run_dir,
                "kernel_image_path": kernel_image_path,
                "target_profile": target_profile,
                "rootfs_profile": rootfs_profile,
                "attempt": attempt,
            }
        )
        return Plan(
            run_id=run_id,
            domain_name=target_profile.target_ref or target_profile.name,
            boot_log_path=run_dir / "boot" / f"attempt-{attempt}" / "boot.log",
            boot_plan_path=run_dir / "boot" / f"attempt-{attempt}" / "boot-plan.json",
            boot_summary_path=run_dir / "boot" / f"attempt-{attempt}" / "boot-summary.json",
            debug_gdbstub=target_profile.debug_gdbstub,
            gdbstub_endpoint={"host": "127.0.0.1", "port": 1234} if target_profile.debug_gdbstub else None,
            nokaslr_source="provider_added" if target_profile.debug_gdbstub else "not_applicable",
        )

    def execute_boot(
        self,
        plan: Plan,
        *,
        force_reboot: bool = False,
        retrying_after_failure: bool = False,
    ) -> BootExecutionResult:
        self.executions.append(
            {
                "run_id": plan.run_id,
                "force_reboot": force_reboot,
                "retrying_after_failure": retrying_after_failure,
            }
        )
        self.started.set()
        if self.block:
            self.release.wait(timeout=5)
        if self.raise_on_execute is not None:
            raise self.raise_on_execute
        plan.boot_log_path.parent.mkdir(parents=True, exist_ok=True)
        plan.boot_log_path.write_text("boot log\n", encoding="utf-8")
        plan.boot_plan_path.parent.mkdir(parents=True, exist_ok=True)
        plan.boot_plan_path.write_text("{}\n", encoding="utf-8")
        plan.boot_summary_path.parent.mkdir(parents=True, exist_ok=True)
        plan.boot_summary_path.write_text("{}\n", encoding="utf-8")
        return BootExecutionResult(
            status=self.status,
            summary=self.summary,
            details={
                "domain": plan.domain_name,
                "provider_call": len(self.executions),
                "debug_boot": plan.debug_gdbstub,
                "gdbstub_endpoint": plan.gdbstub_endpoint,
                "nokaslr_source": plan.nokaslr_source,
            },
            artifacts=[ArtifactRef(path=str(plan.boot_log_path), kind="boot-log")],
            error_category=self.error_category,
            diagnostic="diagnostic" if self.status == StepStatus.FAILED else None,
        )


def target_profile(
    *,
    name: str = "local-qemu",
    architecture: str = "x86_64",
    target_ref: str = "mcp-linux-debug-dev",
) -> TargetProfile:
    return TargetProfile(
        name=name,
        architecture=architecture,
        target_ref=target_ref,
        managed_domain=True,
        managed_domain_prefix="mcp-linux-debug-",
        libvirt_uri="qemu:///system",
    )


def rootfs_profile(tmp_path: Path, *, name: str = "minimal") -> RootfsProfile:
    rootfs = tmp_path / f"{name}.img"
    rootfs.write_text("rootfs\n", encoding="utf-8")
    return RootfsProfile(name=name, source=str(rootfs), mutability="read_only", readiness_marker="ready")


def create_run(
    tmp_path: Path,
    *,
    run_id: str = "run-abc123",
    target_profile_name: str = "local-qemu",
    rootfs_profile_name: str = "minimal",
) -> Path:
    source = make_source_tree(tmp_path / run_id)
    artifact_root = tmp_path / "runs"
    response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile=target_profile_name,
        rootfs_profile=rootfs_profile_name,
        run_id=run_id,
    )
    assert response.ok is True
    return artifact_root


def record_build(
    artifact_root: Path,
    run_id: str = "run-abc123",
    *,
    status: StepStatus = StepStatus.SUCCEEDED,
    architecture: str = "x86_64",
    include_kernel_image: bool = True,
) -> Path:
    build_dir = artifact_root / run_id / "build"
    kernel = build_dir / "arch" / "x86" / "boot" / "bzImage"
    kernel.parent.mkdir(parents=True, exist_ok=True)
    kernel.write_text("kernel\n", encoding="utf-8")
    artifacts = [ArtifactRef(path=str(kernel), kind="kernel-image")] if include_kernel_image else []
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        run_id,
        StepResult(
            step_name="build",
            status=status,
            summary="build result",
            artifacts=artifacts,
            details={"architecture": architecture, "output_path": str(build_dir)},
        ),
    )
    return kernel


def profiles(tmp_path: Path, *, target: TargetProfile | None = None) -> dict[str, dict[str, object]]:
    target = target or target_profile()
    rootfs = rootfs_profile(tmp_path)
    return {"target_profiles": {target.name: target}, "rootfs_profiles": {rootfs.name: rootfs}}


# ---------------------------------------------------------------------------
# Shared run-tests-handler fakes (from test_target_run_tests_handler)
# ---------------------------------------------------------------------------


class FakeTestProvider:
    name = "local-ssh-tests"

    def __init__(self, *, result: TestExecutionResult | None = None) -> None:
        self.result = result or TestExecutionResult(
            status=StepStatus.SUCCEEDED,
            summary="test suite smoke-basic passed: 1 passed, 0 failed",
            artifacts=[],
            details={"counts": {"passed": 1, "failed": 0}, "commands": []},
        )
        self.plans: list[dict[str, object]] = []
        self.executions = 0
        self.planned_rootfs: RootfsProfile | None = None

    def plan_tests(self, **kwargs: object) -> object:
        self.plans.append(kwargs)
        self.planned_rootfs = kwargs.get("rootfs_profile")  # type: ignore[assignment]
        return {"plan": kwargs}

    def execute_tests(self, plan: object, *, cancel: object = None) -> TestExecutionResult:
        self.executions += 1
        return self.result


def create_booted_run(tmp_path: Path, *, run_id: str = "run-abc123", test_suite: str | None = None) -> Path:
    source = make_source_tree(tmp_path / run_id)
    artifact_root = tmp_path / "runs"
    response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id=run_id,
        test_suite=test_suite,
    )
    assert response.ok is True
    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(run_id, StepResult(step_name="build", status=StepStatus.SUCCEEDED, summary="build ok"))
    store.record_step_result(run_id, StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="boot ok"))
    return artifact_root


def rootfs(tmp_path: Path) -> RootfsProfile:
    return RootfsProfile(
        name="minimal",
        source=str(tmp_path / "rootfs.qcow2"),
        access_method="ssh_and_serial",
        ssh_host="127.0.0.1",
        ssh_user="root",
    )
