import socket
import threading
from datetime import UTC, datetime

from kdive.coordination.admission import AdmissionService, SnapshotStore, TargetSnapshot
from kdive.coordination.exec_probe import probe_execution_state, probe_rsp_halted
from kdive.coordination.registry import SessionRegistry
from kdive.seams.target import ConsoleKind, PlatformMetadata, TargetKey, TargetState
from kdive.transport.core.base import (
    ExecutionState,
    RecordState,
    TcpEndpoint,
    TransportSession,
    new_session_id,
)
from kdive.transport.core.rsp_probe import rsp_frame


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


# ---------------------------------------------------------------------------
# Findings F2/F5 — bounded RSP `?` post-break confirmation probe
# ---------------------------------------------------------------------------


def _serve_once(handler) -> tuple[socket.socket, int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _run():
        conn, _ = listener.accept()
        try:
            handler(conn)
        finally:
            conn.close()

    threading.Thread(target=_run, daemon=True).start()
    return listener, port


def _session_with_endpoint(port: int) -> TransportSession:
    return TransportSession(
        session_id=new_session_id(),
        target_key=TargetKey(provisioner="local-qemu", target_id="r-probe"),
        generation=1,
        provider="qemu-gdbstub",
        channel_id="rsp0",
        record_state=RecordState.READY,
        execution_state=ExecutionState.HALTED,
        created_at=datetime.now(UTC),
        rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=port),
    )


def test_probe_rsp_halted_returns_true_on_stop_reply():
    """F2: a peer that answers `?` with a `T..` or `S..` stop reply is reported HALTED. This is
    the success-path confirmation `transport.inject_break` relies on — it is NOT a cached-flag
    read; it is a live RSP exchange (see ADR 0001 amended)."""
    listener, port = _serve_once(lambda conn: conn.sendall(b"+" + rsp_frame("T05")))
    try:
        session = _session_with_endpoint(port)
        assert probe_rsp_halted(session, deadline_s=2.0) is True
    finally:
        listener.close()


def test_probe_rsp_halted_returns_true_on_signal_stop_reply():
    """A `S..` (signal-only) stop reply is also a valid halt indication."""
    listener, port = _serve_once(lambda conn: conn.sendall(b"+" + rsp_frame("S0b")))
    try:
        session = _session_with_endpoint(port)
        assert probe_rsp_halted(session, deadline_s=2.0) is True
    finally:
        listener.close()


def test_probe_rsp_halted_returns_false_on_timeout():
    """F2: a peer that connects but never speaks must return False within the bounded deadline
    — fail closed so `break_unconfirmed` fires against a silent-no-op break mechanism."""
    listener, port = _serve_once(lambda conn: None)  # accepts, says nothing
    try:
        session = _session_with_endpoint(port)
        assert probe_rsp_halted(session, deadline_s=0.4) is False
    finally:
        listener.close()


def test_probe_rsp_halted_returns_false_when_nothing_listens():
    """A dead/closed gdbstub port returns False — never a positive halt confirmation."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    session = _session_with_endpoint(dead_port)
    assert probe_rsp_halted(session, deadline_s=0.3) is False


def test_probe_rsp_halted_rejects_non_stop_reply():
    """A frame with a non-stop-reply payload (e.g. an `O..` console output packet) is NOT a halt
    confirmation — F2's posture is positive `T`/`S` reply only, fail closed otherwise."""
    listener, port = _serve_once(lambda conn: conn.sendall(b"+" + rsp_frame("O68656c6c6f")))
    try:
        session = _session_with_endpoint(port)
        assert probe_rsp_halted(session, deadline_s=0.6) is False
    finally:
        listener.close()


def test_probe_rsp_halted_returns_false_when_no_rsp_endpoint():
    """A session without an `rsp_endpoint` cannot be probed — fail closed."""
    session = TransportSession(
        session_id=new_session_id(),
        target_key=TargetKey(provisioner="local-qemu", target_id="r-noendpoint"),
        generation=1,
        provider="qemu-gdbstub",
        channel_id="rsp0",
        record_state=RecordState.READY,
        execution_state=ExecutionState.HALTED,
        created_at=datetime.now(UTC),
        rsp_endpoint=None,
    )
    assert probe_rsp_halted(session, deadline_s=0.1) is False
