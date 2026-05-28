from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile, RootfsProfile, TargetProfile
from linux_debug_mcp.coordination.admission import AdmissionService
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.coordination.transaction import TransportTransaction
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.providers.libvirt_qemu import BootExecutionResult, ProviderBootError
from linux_debug_mcp.providers.local_ssh_tests import TestExecutionResult
from linux_debug_mcp.providers.qemu_gdbstub import DebugSession
from linux_debug_mcp.seams.target import (
    BreakHint,
    ConsoleKind,
    PlatformMetadata,
    TargetKey,
    publish_ready_snapshot,
)
from linux_debug_mcp.server import create_run_handler
from linux_debug_mcp.transport.base import LineRole, TransportRef


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


class CancelAwareTestProvider(FakeTestProvider):
    """FakeTestProvider that blocks in execute_tests until the watcher fires the cancel fence —
    the shared harness used by every halt-cancel conformance test. cancel_observed is set when the
    provider returns through the cancelled branch, so a test can assert the fence reached this far
    rather than the response shape alone (which the run_tests handler shapes on its own)."""

    def __init__(self, *, result: TestExecutionResult | None = None) -> None:
        super().__init__(result=result)
        self.cancel_observed = threading.Event()

    def execute_tests(self, plan: object, *, cancel: object = None) -> TestExecutionResult:
        self.executions += 1
        if cancel is not None and cancel.wait(5) and cancel.is_set():
            self.cancel_observed.set()
            return TestExecutionResult(
                status=StepStatus.FAILED, summary="cancelled", artifacts=[], details={"cancelled": True}
            )
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


# ---------------------------------------------------------------------------
# Shared legacy-fence helpers (from test_server_legacy_session_fence)
#
# These seed a pre-Layer-4 DebugSession (raw gdbstub_endpoint, NO durable SessionRegistry
# ownership record) and build the Layer-4 transaction/admission trio against it. Lifted here
# so the dedicated B7 fence tests AND the §10.2 conformance suite share one source — a
# contract change touches this file, not a test-to-test-module import.
# ---------------------------------------------------------------------------


LEGACY_FENCE_RUN_ID = "run-1"
LEGACY_FENCE_KEY = TargetKey(provisioner="local-qemu", target_id=LEGACY_FENCE_RUN_ID)
LEGACY_FENCE_GDBSTUB_ENDPOINT = {"host": "127.0.0.1", "port": 1234}
LEGACY_FENCE_RSP_CHANNEL = TransportRef(
    provider="qemu-gdbstub",
    channel_id="rsp0",
    line_role=LineRole.RSP,
    caps=("rsp",),
    target_ref=LEGACY_FENCE_GDBSTUB_ENDPOINT,
)
LEGACY_FENCE_PLATFORM_WITH_SSH = PlatformMetadata(
    console_kind=ConsoleKind.UART,
    console_count=1,
    dedicated_debug_line=False,
    ssh_reachable=True,
    break_hints=[BreakHint.GDBSTUB_NATIVE],
)


def legacy_fence_profiles() -> dict[str, DebugProfile]:
    return {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")}


def legacy_fence_make_registry(tmp_path: Path) -> SessionRegistry:
    directory = tmp_path / "reg"
    directory.mkdir(parents=True, exist_ok=True)
    return SessionRegistry(directory=directory)


def legacy_fence_build_transaction(
    *,
    registry: SessionRegistry,
    generation: int = 1,
) -> tuple[TransportTransaction, AdmissionService]:
    # Imported lazily so conftest stays decoupled from the _layer4_fakes test harness at module
    # load (conftest already loads for every test; _layer4_fakes only when a Layer-4 test needs it).
    from _layer4_fakes import FakeQemuTransport, build_txn  # noqa: PLC0415

    txn, admission = build_txn(FakeQemuTransport(), registry=registry, generation=generation)
    publish_ready_snapshot(
        admission,
        target_key=LEGACY_FENCE_KEY,
        generation=generation,
        transports=[LEGACY_FENCE_RSP_CHANNEL],
        platform=LEGACY_FENCE_PLATFORM_WITH_SSH,
    )
    return txn, admission


def seed_legacy_debug_session(tmp_path: Path) -> Path:
    """Create a run whose manifest records an ATTACHED, HALTED ('stopped') DebugSession with a raw
    gdbstub_endpoint and NO matching SessionRegistry ownership record — the pre-Layer-4 shape."""
    artifact_root = tmp_path / "runs"
    source = tmp_path / "source"
    source.mkdir()
    store = ArtifactStore(artifact_root, source_paths=[source])
    manifest = store.create_run(
        RunRequest(
            source_path=str(source),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
            debug_profile="qemu-gdbstub-default",
            run_id=LEGACY_FENCE_RUN_ID,
        )
    )
    run_dir = store.run_dir(manifest.run_id)
    vmlinux = run_dir / "build" / "vmlinux"
    kernel = run_dir / "build" / "bzImage"
    vmlinux.write_text("vmlinux", encoding="utf-8")
    kernel.write_text("kernel", encoding="utf-8")
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="built",
            artifacts=[
                ArtifactRef(path=str(kernel), kind="kernel-image"),
                ArtifactRef(path=str(vmlinux), kind="vmlinux"),
            ],
            details={"kernel_release": "6.9.0-test"},
        ),
    )
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary="booted",
            details={"debug_boot": True, "gdbstub_endpoint": LEGACY_FENCE_GDBSTUB_ENDPOINT},
        ),
    )

    session_path = run_dir / "debug" / "sessions" / "debug-1.json"
    transcript_path = run_dir / "debug" / "attempt-001" / "transcript.txt"
    commands_path = run_dir / "debug" / "attempt-001" / "commands.jsonl"
    summary_path = run_dir / "debug" / "attempt-001" / "debug-summary.json"
    for path in [session_path, transcript_path, commands_path, summary_path]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    session = DebugSession(
        session_id="debug-1",
        run_id=manifest.run_id,
        provider_name="local-qemu-gdbstub",
        gdbstub_endpoint=LEGACY_FENCE_GDBSTUB_ENDPOINT,
        vmlinux_path=str(vmlinux),
        selected_debug_profile="qemu-gdbstub-default",
        attach_status="attached",
        started_at="2026-05-20T00:00:00+00:00",
        current_execution_state="stopped",
        transcript_path=str(transcript_path),
        command_metadata_path=str(commands_path),
        latest_summary_path=str(summary_path),
        symbol_identity_validation={"same_run_artifact_linkage": True, "live_banner_match": True},
    )
    session_path.write_text(session.model_dump_json(indent=2), encoding="utf-8")
    # Record the debug step pointing at the legacy session file — NO transport_session_id, the
    # hallmark of a pre-Layer-4 session (no ownership binding).
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="debug",
            status=StepStatus.SUCCEEDED,
            summary="debug session started",
            artifacts=[ArtifactRef(path=str(session_path), kind="debug-session")],
            details={"debug_session_id": "debug-1", "session_path": str(session_path)},
        ),
    )
    return artifact_root
