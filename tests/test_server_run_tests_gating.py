import threading
import time
from datetime import UTC, datetime

from conftest import FakeTestProvider, create_booted_run, rootfs

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.coordination.admission import AdmissionService, SnapshotStore
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.domain import ErrorCategory, StepResult, StepStatus
from linux_debug_mcp.providers.local_ssh_tests import TestExecutionResult
from linux_debug_mcp.seams.target import (
    BreakHint,
    ConsoleKind,
    PlatformMetadata,
    TargetKey,
    publish_ready_snapshot,
)
from linux_debug_mcp.server import target_run_tests_handler
from linux_debug_mcp.transport.base import (
    ExecutionState,
    LineRole,
    RecordState,
    TransportRef,
    TransportSession,
    new_session_id,
)

RUN_ID = "run-abc123"
KEY = TargetKey(provisioner="local-qemu", target_id=RUN_ID)
PLATFORM = PlatformMetadata(
    console_kind=ConsoleKind.UART,
    console_count=1,
    dedicated_debug_line=False,
    ssh_reachable=True,
    break_hints=[BreakHint.GDBSTUB_NATIVE],
)
CHANNEL = TransportRef(provider="qemu-gdbstub", channel_id="rsp0", line_role=LineRole.RSP, caps=("rsp",))


def _seed_admission(generation: int = 1) -> AdmissionService:
    admission = AdmissionService(SnapshotStore())
    publish_ready_snapshot(admission, target_key=KEY, generation=generation, transports=[CHANNEL], platform=PLATFORM)
    return admission


def _make_registry(tmp_path) -> SessionRegistry:
    directory = tmp_path / "reg"
    directory.mkdir(parents=True, exist_ok=True)
    return SessionRegistry(directory=directory)


def _record(reg: SessionRegistry, state: ExecutionState, generation: int = 1) -> None:
    reg.write_record(
        TransportSession(
            session_id=new_session_id(),
            target_key=KEY,
            generation=generation,
            provider="qemu-gdbstub",
            channel_id="rsp0",
            record_state=RecordState.READY,
            execution_state=state,
            created_at=datetime.now(UTC),
        )
    )


def test_fresh_run_rejected_while_halted(tmp_path):
    artifact_root = create_booted_run(tmp_path)
    reg = _make_registry(tmp_path)
    _record(reg, ExecutionState.HALTED)
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=_seed_admission(),
        session_registry=reg,
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.READINESS_FAILURE
    assert response.error.details["code"] == "target_halted"


def test_cached_succeeded_served_while_halted(tmp_path):
    artifact_root = create_booted_run(tmp_path)
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        RUN_ID, StepResult(step_name="run_tests", status=StepStatus.SUCCEEDED, summary="cached pass")
    )
    reg = _make_registry(tmp_path)
    _record(reg, ExecutionState.HALTED)

    class SpyAdmission(AdmissionService):
        ssh_tier_calls = 0

        def admit_ssh_tier(self, *a, **k):  # noqa: ANN001
            type(self).ssh_tier_calls += 1
            return super().admit_ssh_tier(*a, **k)

    admission = SpyAdmission(SnapshotStore())
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission,
        session_registry=reg,
    )
    assert response.ok is True
    assert SpyAdmission.ssh_tier_calls == 0


def test_admitted_then_halted_run_is_cancelled(tmp_path):
    artifact_root = create_booted_run(tmp_path)
    reg = _make_registry(tmp_path)
    _record(reg, ExecutionState.EXECUTING)
    admission = _seed_admission()

    class CancelAwareProvider(FakeTestProvider):
        def __init__(self):
            super().__init__()
            self.cancel_observed = threading.Event()

        def execute_tests(self, plan, *, cancel=None):
            self.executions += 1
            if cancel is not None and cancel.wait(5) and cancel.is_set():
                self.cancel_observed.set()
                return TestExecutionResult(
                    status=StepStatus.FAILED, summary="cancelled", artifacts=[], details={"cancelled": True}
                )
            return self.result

    provider = CancelAwareProvider()

    def _halt():
        time.sleep(0.2)
        halt_epoch = admission.note_execution_transition(KEY, 1)
        admission.cancel_ssh_tier(KEY, 1, halt_epoch=halt_epoch)

    live_before = set(threading.enumerate())
    timer = threading.Thread(target=_halt, daemon=True)
    timer.start()
    start = time.monotonic()
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission,
        session_registry=reg,
    )
    elapsed = time.monotonic() - start
    timer.join(timeout=2)
    assert provider.cancel_observed.is_set()
    assert response.ok is False
    assert elapsed < 5
    leftover = [t for t in threading.enumerate() if t.is_alive() and t not in live_before and t is not timer]
    assert leftover == []
    step = ArtifactStore(artifact_root, create_root=False).load_manifest(RUN_ID).step_results.get("run_tests")
    assert step is not None and step.status == StepStatus.FAILED


def test_clean_run_leaves_no_watcher_thread(tmp_path):
    artifact_root = create_booted_run(tmp_path)
    reg = _make_registry(tmp_path)
    _record(reg, ExecutionState.EXECUTING)
    admission = _seed_admission()
    live_before = set(threading.enumerate())
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission,
        session_registry=reg,
    )
    assert response.ok is True
    leftover = [t for t in threading.enumerate() if t.is_alive() and t not in live_before]
    assert leftover == []
