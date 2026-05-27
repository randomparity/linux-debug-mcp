from datetime import UTC, datetime

from linux_debug_mcp.coordination.admission import AdmissionService, SnapshotStore, TargetSnapshot
from linux_debug_mcp.coordination.exec_probe import probe_execution_state
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.seams.target import ConsoleKind, PlatformMetadata, TargetKey, TargetState
from linux_debug_mcp.transport.base import ExecutionState, RecordState, TransportSession, new_session_id


def _platform() -> PlatformMetadata:
    return PlatformMetadata(
        console_kind=ConsoleKind.UART, console_count=1, dedicated_debug_line=False, ssh_reachable=True
    )


def _seed(store: SnapshotStore, key: TargetKey, gen: int = 3) -> None:
    store.put(key, TargetSnapshot(generation=gen, transports=(), platform=_platform(), state=TargetState.DEBUGGING))


def _rec(key: TargetKey, state: ExecutionState, gen: int = 3) -> TransportSession:
    return TransportSession(
        session_id=new_session_id(),
        target_key=key,
        generation=gen,
        provider="qemu-gdbstub",
        channel_id="rsp0",
        record_state=RecordState.READY,
        execution_state=state,
        created_at=datetime.now(UTC),
    )


def test_probe_reports_executing(tmp_path):
    key = TargetKey(provisioner="local-qemu", target_id="r1")
    store = SnapshotStore()
    _seed(store, key)
    admission = AdmissionService(store)
    reg = SessionRegistry(directory=tmp_path)
    reg.write_record(_rec(key, ExecutionState.EXECUTING))
    proof = probe_execution_state(registry=reg, admission=admission, target_key=key, generation=3)
    assert proof.state is ExecutionState.EXECUTING
    assert proof.generation == 3 and proof.epoch == admission.current_execution_epoch(key)


def test_probe_reports_halted(tmp_path):
    key = TargetKey(provisioner="local-qemu", target_id="r2")
    store = SnapshotStore()
    _seed(store, key)
    admission = AdmissionService(store)
    reg = SessionRegistry(directory=tmp_path)
    reg.write_record(_rec(key, ExecutionState.HALTED))
    proof = probe_execution_state(registry=reg, admission=admission, target_key=key, generation=3)
    assert proof.state is ExecutionState.HALTED


def test_probe_unknown_when_no_record(tmp_path):
    key = TargetKey(provisioner="local-qemu", target_id="r3")
    store = SnapshotStore()
    _seed(store, key)
    admission = AdmissionService(store)
    reg = SessionRegistry(directory=tmp_path)
    proof = probe_execution_state(registry=reg, admission=admission, target_key=key, generation=3)
    assert proof.state is ExecutionState.UNKNOWN
