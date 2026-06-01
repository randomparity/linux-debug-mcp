from _layer4_fakes import (
    KEY,
    FakeBrokeredTransport,
    FakeQemuTransport,
    build_txn,
)
from _secrets_helpers import make_env_secrets as EnvSecretsResolver
from handler_call_helpers import transport_open_handler

from kdive.coordination.lease import ConsoleLeaseManager
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ErrorCategory
from kdive.seams.guard import InProcessStopCapableGuard


def test_stale_handle_category_value():
    assert ErrorCategory.STALE_HANDLE == "stale_handle"


def test_transport_conflict_category_value():
    assert ErrorCategory.TRANSPORT_CONFLICT == "transport_conflict"


def test_new_categories_are_distinct_members():
    values = {member.value for member in ErrorCategory}
    assert {"stale_handle", "transport_conflict"} <= values


# ---------------------------------------------------------------------------
# Finding F13 — guard/endpoint conflicts route through TRANSPORT_CONFLICT, not DEBUG_ATTACH_FAILURE
# ---------------------------------------------------------------------------


def test_guard_conflict_maps_to_transport_conflict(tmp_path):
    """F13: a second transport.open against the same target whose guard is already held must
    surface as TRANSPORT_CONFLICT (the dedicated, agent-facing category for transport-resource
    conflicts) — not as the gdb-attach-specific DEBUG_ATTACH_FAILURE that previously masked it."""
    transport = FakeQemuTransport()
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(transport, registry=reg)
    first = transport_open_handler(run_id="run-1", transaction=txn, admission=admission, session_registry=reg)
    assert first.ok is True

    second = transport_open_handler(run_id="run-1", transaction=txn, admission=admission, session_registry=reg)
    assert second.ok is False
    assert second.error.category is ErrorCategory.TRANSPORT_CONFLICT


def test_endpoint_unsafe_maps_to_transport_conflict(tmp_path):
    """F13: a brokered_required transport refusing pre-attach must also route through
    TRANSPORT_CONFLICT — same agent-facing taxonomy, different sub-cause from a guard race."""
    # Build a transaction that holds ONLY the brokered transport, then ask the handler to open
    # against a snapshot whose channel happens to be the qemu-gdbstub one. Simpler: rebuild the
    # txn with the brokered transport's provider name to ensure refuse_unsafe_exposure fires.
    transport = FakeBrokeredTransport()
    reg = SessionRegistry(directory=tmp_path)
    # Build txn with broker transport; we register snapshot using its provider name so handler picks it.
    from _layer4_fakes import CHANNEL, PLATFORM

    from kdive.coordination.admission import AdmissionService, SnapshotStore, TargetSnapshot
    from kdive.seams.target import TargetState
    from kdive.transport.core.base import LineRole, TransportRef

    store = SnapshotStore()
    broker_channel = TransportRef(
        provider=transport.capability.provider_name,
        channel_id=CHANNEL.channel_id,
        line_role=LineRole.RSP,
        caps=CHANNEL.caps,
    )
    store.put(
        KEY,
        TargetSnapshot(generation=1, transports=(broker_channel,), platform=PLATFORM, state=TargetState.READY),
    )
    admission = AdmissionService(store)
    txn = TransportTransaction(
        admission=admission,
        registry=reg,
        guard=InProcessStopCapableGuard(),
        leases=ConsoleLeaseManager(),
        secrets=EnvSecretsResolver([]),
        break_policy=__import__("_layer4_fakes", fromlist=["FakeBreakPolicy"]).FakeBreakPolicy(),
        transports={transport.capability.provider_name: transport},
    )

    response = transport_open_handler(run_id="run-1", transaction=txn, admission=admission, session_registry=reg)
    assert response.ok is False
    assert response.error.category is ErrorCategory.TRANSPORT_CONFLICT
