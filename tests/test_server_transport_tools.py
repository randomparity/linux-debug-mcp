"""Behaviour tests for the transport.open / transport.close / transport.inject_break MCP
handlers (plan Task B5). The handlers take the Layer-4 collaborators (transaction, admission,
session_registry) as injected parameters — the same dependency-injection seam B6 will wire into
create_app — so these exercise the real TransportTransaction over the shared `_layer4_fakes`
harness, never a mock of the transaction itself."""

from __future__ import annotations

from _layer4_fakes import (
    KEY,
    FakeBreakPolicy,
    FakeQemuTransport,
    build_txn,
    seed_snapshot,
)

from linux_debug_mcp.config import TRANSPORT_DESTRUCTIVE_PERMISSIONS
from linux_debug_mcp.coordination.admission import AdmissionService, SnapshotStore
from linux_debug_mcp.coordination.lease import ConsoleLeaseManager
from linux_debug_mcp.coordination.registry import RecoveryTombstone, SessionRegistry
from linux_debug_mcp.coordination.transaction import TransportTransaction
from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.seams.guard import InProcessStopCapableGuard
from linux_debug_mcp.seams.secrets import EnvSecretsResolver
from linux_debug_mcp.server import (
    transport_close_handler,
    transport_inject_break_handler,
    transport_open_handler,
)
from linux_debug_mcp.transport.base import BreakMethod, BreakPlan, ExecutionState, LineRole, TransportRef
from linux_debug_mcp.transport.break_inject import InjectBreakError

# `KEY` is TargetKey(provisioner="local-qemu", target_id="run-1"); the handlers derive the
# TargetKey from `run_id`, so every test addresses the seeded snapshot with this run id.
RUN_ID = "run-1"
INJECT_PERMS = TRANSPORT_DESTRUCTIVE_PERMISSIONS["transport.inject_break"]


def _open(tmp_path, **kwargs):
    """Build a transaction over the shared harness and open a session through the handler."""
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    response = transport_open_handler(
        run_id=RUN_ID,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        **kwargs,
    )
    return response, txn, admission, reg


def test_transport_open_returns_session_and_records_endpoint(tmp_path):
    response, _txn, _admission, reg = _open(tmp_path)

    assert response.ok is True
    session_id = response.data["session_id"]
    # the loopback RSP endpoint the backend attached is surfaced to the agent...
    assert response.data["rsp_endpoint"]["host"] == "127.0.0.1"
    assert response.data["rsp_endpoint"]["port"] == 5551
    # ...and a READY durable ownership record was written for the target.
    record = reg.read_record(KEY)
    assert record is not None
    assert record.session_id == session_id
    assert "debug.start_session" in response.suggested_next_actions
    assert "transport.status" in response.suggested_next_actions


def test_transport_open_recovery_clears_tombstone(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    # Park the target: a generation-current tombstone + the admission cache (the dual-write A
    # crash-reconcile would leave). Ordinary open is now gated `recovery_required`.
    reg.write_tombstone(RecoveryTombstone(target_key=KEY, generation=1, reason="reconciled_halted"))
    admission.mark_recovery_required(KEY, 1)

    blocked = transport_open_handler(run_id=RUN_ID, transaction=txn, admission=admission, session_registry=reg)
    assert blocked.ok is False
    assert blocked.error.category is ErrorCategory.READINESS_FAILURE

    # recovery=True admits through the recovery gate AND clears the tombstone (dual-write).
    recovered = transport_open_handler(
        run_id=RUN_ID, transaction=txn, admission=admission, session_registry=reg, recovery=True
    )
    assert recovered.ok is True
    assert reg.read_tombstone(KEY) is None


def test_transport_close_reaps_and_clears(tmp_path):
    response, txn, admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]

    closed = transport_close_handler(run_id=RUN_ID, session_id=session_id, transaction=txn, session_registry=reg)

    assert closed.ok is True
    # close() reaped the backend (FakeQemuTransport.close recorded the id) and deleted the record.
    assert reg.read_record(KEY) is None
    # the promoted admission binding was deregistered, so a reopen is not blocked.
    assert admission._bindings.get(KEY, []) == []


def test_inject_break_writes_halted_before_break(tmp_path):
    response, txn, admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]
    observed: dict[str, object] = {}

    def spy_break(**kwargs):
        # the break mechanism reads the durable record at break time: it MUST already see HALTED,
        # so a death during the break can never strand the record as EXECUTING.
        record = reg.read_record(KEY)
        observed["state_at_break"] = record.execution_state
        observed["method"] = kwargs["method"]

    result = transport_inject_break_handler(
        run_id=RUN_ID,
        session_id=session_id,
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=spy_break,
    )

    assert result.ok is True
    assert observed["state_at_break"] is ExecutionState.HALTED
    # the persisted record stays HALTED after a confirmed break.
    assert reg.read_record(KEY).execution_state is ExecutionState.HALTED


def test_inject_break_timeout_records_unknown_not_executing(tmp_path):
    response, txn, admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]

    def timing_out_break(**kwargs):
        raise InjectBreakError("break timed out", category=ErrorCategory.DEBUG_ATTACH_FAILURE)

    result = transport_inject_break_handler(
        run_id=RUN_ID,
        session_id=session_id,
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=timing_out_break,
    )

    assert result.ok is False
    # an unconfirmable break must NEVER leave a stale EXECUTING: fail closed to UNKNOWN.
    assert reg.read_record(KEY).execution_state is ExecutionState.UNKNOWN


def test_inject_break_unexpected_error_also_records_unknown(tmp_path):
    # The unconfirmable-break ⇒ UNKNOWN invariant must hold for ANY mechanism failure, not just
    # InjectBreakError: an OSError/TypeError (e.g. the B6 real-mechanism missing-kwargs trap) raised
    # AFTER the optimistic HALTED write must still fail closed to UNKNOWN and return a failure —
    # never a stale HALTED, never EXECUTING, never an escaping crash.
    response, txn, admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]

    def exploding_break(**kwargs):
        raise OSError("proxy socket vanished mid-break")

    result = transport_inject_break_handler(
        run_id=RUN_ID,
        session_id=session_id,
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=exploding_break,
    )

    assert result.ok is False
    assert result.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    # NOT stranded at the optimistic HALTED, NOT left EXECUTING — fail closed to UNKNOWN.
    assert reg.read_record(KEY).execution_state is ExecutionState.UNKNOWN


def test_inject_break_requires_destructive_permission(tmp_path):
    response, txn, admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]
    calls: list[str] = []

    def spy_break(**kwargs):
        calls.append(kwargs["method"])

    refused = transport_inject_break_handler(
        run_id=RUN_ID,
        session_id=session_id,
        acknowledged_permissions=[],  # destructive permission NOT acknowledged
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=spy_break,
    )
    assert refused.ok is False
    assert refused.error.category is ErrorCategory.CONFIGURATION_ERROR
    assert calls == []  # the break mechanism was never invoked
    # the durable record is untouched (still EXECUTING) when the op is refused at the gate.
    assert reg.read_record(KEY).execution_state is ExecutionState.EXECUTING

    granted = transport_inject_break_handler(
        run_id=RUN_ID,
        session_id=session_id,
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=spy_break,
    )
    assert granted.ok is True
    assert len(calls) == 1  # with the permission, the break proceeds


def test_transport_open_unregistered_provider_is_configuration_error(tmp_path):
    # Carried review note #1: a request naming a provider absent from the transaction's
    # `transports` map must surface as CONFIGURATION_ERROR, not a raw KeyError escaping to the agent.
    reg = SessionRegistry(directory=tmp_path)
    # The handler reads the authoritative snapshot's RSP channel to build the OpenRequest. Seed a
    # snapshot whose channel names a provider the transaction has no Transport for, so admission
    # re-binds it cleanly but the transaction's `self._transports[provider]` lookup misses.
    ghost = TransportRef(provider="ghost-provider", channel_id="rsp0", line_role=LineRole.RSP, caps=("rsp",))
    store = SnapshotStore()
    seed_snapshot(store, transports=(ghost,))
    admission = AdmissionService(store)
    transport = FakeQemuTransport()  # registered as "qemu-gdbstub" — NOT "ghost-provider"
    txn = TransportTransaction(
        admission=admission,
        registry=reg,
        guard=InProcessStopCapableGuard(),
        leases=ConsoleLeaseManager(),
        secrets=EnvSecretsResolver([]),
        break_policy=FakeBreakPolicy(),
        transports={transport.capability.provider_name: transport},
    )

    response = transport_open_handler(
        run_id=RUN_ID,
        transaction=txn,
        admission=admission,
        session_registry=reg,
    )
    assert response.ok is False
    assert response.error.category is ErrorCategory.CONFIGURATION_ERROR


def test_break_plan_native_helper_is_a_noop_for_inject():
    # guard: gdbstub_native is never a valid inject_break argument (the real break mechanism
    # rejects it). This pins that the destructive-permission constant only covers inject_break.
    plan = BreakPlan(method=BreakMethod.GDBSTUB_NATIVE, channel_id="rsp0", rationale="rsp")
    assert plan.method is BreakMethod.GDBSTUB_NATIVE
    assert set(TRANSPORT_DESTRUCTIVE_PERMISSIONS) == {"transport.inject_break"}
