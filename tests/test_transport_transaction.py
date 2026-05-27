import pytest
from _layer4_fakes import (
    KEY,
    FakeBrokeredTransport,
    FakeQemuTransport,
    build_txn,
    make_request,
)

from linux_debug_mcp.coordination.endpoint_safety import EndpointSafetyError
from linux_debug_mcp.coordination.lease import ConsoleLeaseManager, LeaseOwner
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.seams.guard import GuardConflict, InProcessStopCapableGuard
from linux_debug_mcp.transport.base import RecordState, TcpEndpoint


def test_open_happy_path_returns_loopback_session(tmp_path):
    txn, admission = build_txn(FakeQemuTransport(), registry=SessionRegistry(directory=tmp_path))
    session = txn.open(make_request())
    assert session.record_state is RecordState.READY
    assert isinstance(session.rsp_endpoint, TcpEndpoint) and session.rsp_endpoint.host == "127.0.0.1"
    assert session.stop_guard_token is not None
    # promoted: a second open on the same target is refused by the guard
    with pytest.raises(GuardConflict):
        txn.open(make_request())


def test_brokered_required_refused_before_any_acquisition(tmp_path):
    guard, leases = InProcessStopCapableGuard(), ConsoleLeaseManager()
    txn, _ = build_txn(
        FakeBrokeredTransport(), guard=guard, leases=leases, registry=SessionRegistry(directory=tmp_path)
    )
    with pytest.raises(EndpointSafetyError) as exc:
        txn.open(make_request(provider="redfish-sol"))
    assert exc.value.code == "endpoint_unsafe"
    # no guard acquired, no lease, no record written
    assert leases.snapshot(KEY)[0] is LeaseOwner.FREE
    assert SessionRegistry(directory=tmp_path).read_record(KEY) is None


def test_attach_failure_rolls_back_everything(tmp_path):
    guard, leases = InProcessStopCapableGuard(), ConsoleLeaseManager()
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(crash=True), guard=guard, leases=leases, registry=reg)
    with pytest.raises(RuntimeError, match="attach blew up"):
        txn.open(make_request())
    assert reg.read_record(KEY) is None  # write-ahead record deleted
    assert leases.snapshot(KEY)[0] is LeaseOwner.FREE  # no lease leaked
    # guard freed via the FENCED release → a fresh open can now acquire
    txn_ok, _ = build_txn(FakeQemuTransport(), guard=guard, leases=leases, registry=reg)
    assert txn_ok.open(make_request()).record_state is RecordState.READY


def test_on_partial_writes_backend_pid_through_before_ready(tmp_path):
    # Finding #1: the backend pid must be in the durable OPENING record the instant the
    # backend_process partial fires — before attach() returns — so a death before READY is
    # reapable. A transport that reads its own record mid-attach proves the write-through ordering.
    reg = SessionRegistry(directory=tmp_path)

    class ReadsOwnRecordAtAttach(FakeQemuTransport):
        def attach(self, request, *, cancel, deadline, on_partial):
            attachment = super().attach(request, cancel=cancel, deadline=deadline, on_partial=on_partial)
            self.seen = reg.read_record(KEY)  # after the backend_process partial wrote through
            return attachment

    transport = ReadsOwnRecordAtAttach(backend_pid=4321, backend_start_time="999")
    txn, _ = build_txn(transport, registry=reg)
    txn.open(make_request())
    assert transport.seen is not None and transport.seen.backend_pid == 4321
    assert transport.seen.record_state is RecordState.OPENING


def test_close_reaps_and_clears(tmp_path):
    transport = FakeQemuTransport()
    reg = SessionRegistry(directory=tmp_path)
    txn, _ = build_txn(transport, registry=reg)
    session = txn.open(make_request())
    txn.close(session.session_id)
    assert transport.closed == [session.session_id]
    assert reg.read_record(KEY) is None
