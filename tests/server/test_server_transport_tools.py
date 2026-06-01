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
from _secrets_helpers import make_env_secrets as EnvSecretsResolver

from kdive.config import TRANSPORT_DESTRUCTIVE_PERMISSIONS
from kdive.coordination.admission import AdmissionService, SnapshotStore
from kdive.coordination.lease import ConsoleLeaseManager
from kdive.coordination.registry import RecoveryTombstone, SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ErrorCategory
from kdive.providers.debug import ProviderDebugError
from kdive.seams.guard import InProcessStopCapableGuard
from kdive.server import (
    transport_close_handler,
    transport_inject_break_handler,
    transport_open_handler,
)
from kdive.transport.core.base import BreakMethod, BreakPlan, ExecutionState, LineRole, TransportRef
from kdive.transport.core.break_inject import InjectBreakError

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
    assert transport_open_handler.__module__ == "kdive.transport.handlers"

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
    # transport.status is Layer 5 and not yet registered; the suggestion must point only at
    # currently registered tools (no phantom features).
    assert "transport.status" not in response.suggested_next_actions


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


def test_transport_open_maps_provider_debug_error(monkeypatch, tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)

    def fail_open(*_args, **_kwargs):
        raise ProviderDebugError(
            "provider refused open",
            category=ErrorCategory.DEBUG_ATTACH_FAILURE,
            details={"provider_code": "rsp_refused"},
        )

    monkeypatch.setattr(txn, "open", fail_open)

    response = transport_open_handler(run_id=RUN_ID, transaction=txn, admission=admission, session_registry=reg)

    assert response.ok is False
    assert response.error.category is ErrorCategory.DEBUG_ATTACH_FAILURE
    assert response.error.details["code"] == "transport_open_failed"
    assert response.error.details["provider_code"] == "rsp_refused"
    assert response.error.details["exception_type"] == "ProviderDebugError"


def test_transport_open_maps_unexpected_transaction_error(monkeypatch, tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)

    def fail_open(*_args, **_kwargs):
        raise RuntimeError("raw open failure")

    monkeypatch.setattr(txn, "open", fail_open)

    response = transport_open_handler(run_id=RUN_ID, transaction=txn, admission=admission, session_registry=reg)

    assert response.ok is False
    assert response.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details == {"code": "transport_open_failed", "exception_type": "RuntimeError"}


def test_transport_close_reaps_and_clears(tmp_path):
    response, txn, admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]

    closed = transport_close_handler(run_id=RUN_ID, session_id=session_id, transaction=txn, session_registry=reg)

    assert closed.ok is True
    # Live close: the response distinguishes "I closed it" from "it was already gone".
    assert closed.data["already_closed"] is False
    # close() reaped the backend (FakeQemuTransport.close recorded the id) and deleted the record.
    assert reg.read_record(KEY) is None
    # the promoted admission binding was deregistered, so a reopen is not blocked.
    assert admission._bindings.get(KEY, []) == []


def test_transport_close_maps_unexpected_transaction_error(monkeypatch, tmp_path):
    response, txn, _admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]

    def fail_close(*_args, **_kwargs):
        raise RuntimeError("raw close failure")

    monkeypatch.setattr(txn, "close", fail_close)

    closed = transport_close_handler(run_id=RUN_ID, session_id=session_id, transaction=txn, session_registry=reg)

    assert closed.ok is False
    assert closed.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    assert closed.error.details == {"code": "transport_close_failed", "exception_type": "RuntimeError"}
    assert reg.read_record(KEY) is not None


def test_transport_close_signals_already_closed_when_record_reaped(tmp_path):
    """A `transport.close` arriving after the record was reaped out-of-band (e.g. by
    `reconcile()` on restart, or by a CRASHED lifecycle event driving force_drop) returns success
    AND `data["already_closed"] is True` — distinguishing it from a close that actually tore the
    session down. Mirrors `transport.inject_break`'s explicit `unknown_session` outcome and stops
    the handler from misleadingly logging "transport session X closed" when the reaper got there
    first."""
    response, txn, _admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]
    # Out-of-band reap: simulate reconcile()/lifecycle force_drop deleting the durable record
    # before the close call arrives. The handler should still return success but flag the state.
    reg.delete_record(KEY)
    assert reg.read_record(KEY) is None

    closed = transport_close_handler(run_id=RUN_ID, session_id=session_id, transaction=txn, session_registry=reg)

    assert closed.ok is True
    assert closed.data["already_closed"] is True
    assert closed.data["session_id"] == session_id
    assert "already closed" in closed.summary


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
        probe_halted=lambda _session: True,  # F2: RSP `?` observes a stop reply
    )

    assert result.ok is True
    assert observed["state_at_break"] is ExecutionState.HALTED
    # the persisted record stays HALTED after a confirmed break.
    assert reg.read_record(KEY).execution_state is ExecutionState.HALTED


def test_inject_break_default_uses_transaction_session_break(monkeypatch, tmp_path):
    response, txn, admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]
    calls: list[tuple[str, str]] = []

    def inject_break_for_session(session_id_arg: str, requested_method: str) -> None:
        calls.append((session_id_arg, requested_method))

    monkeypatch.setattr(txn, "inject_break_for_session", inject_break_for_session)

    result = transport_inject_break_handler(
        run_id=RUN_ID,
        session_id=session_id,
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        probe_halted=lambda _session: True,
    )

    assert result.ok is True
    assert calls == [(session_id, "auto")]


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
        probe_halted=lambda _session: True,
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


# ---------------------------------------------------------------------------
# Finding F2 — inject_break post-probe rejects when kernel did not actually halt
# ---------------------------------------------------------------------------


def test_inject_break_post_probe_rejects_when_kernel_did_not_halt(tmp_path):
    """F2: when the break mechanism returns success but the bounded RSP `?` probe does NOT
    observe a stop reply, the handler MUST dual-write UNKNOWN and return DEBUG_ATTACH_FAILURE/
    break_unconfirmed. The prior cached-flag implementation was unreachable here because
    `halt_debug_transport` writes HALTED to the flag the probe would have read."""
    response, txn, admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]

    def silent_break(**_kwargs):
        return None

    result = transport_inject_break_handler(
        run_id=RUN_ID,
        session_id=session_id,
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=silent_break,
        probe_halted=lambda _session: False,  # RSP `?` produced no stop reply
    )

    assert result.ok is False
    assert result.error.category is ErrorCategory.DEBUG_ATTACH_FAILURE
    assert result.error.details["code"] == "break_unconfirmed"
    assert reg.read_record(KEY).execution_state is ExecutionState.UNKNOWN


# ---------------------------------------------------------------------------
# Finding F7 — session_id ↔ run_id validation
# ---------------------------------------------------------------------------


def test_inject_break_rejects_session_from_different_run(tmp_path):
    """F7: a caller cannot halt run-B's kernel by passing its session_id under run_id=run-A.
    Refused as session_run_mismatch BEFORE `halt_debug_transport` writes HALTED, so the
    other run's durable record stays EXECUTING."""
    response, txn, admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]
    other_run = "different-run"

    result = transport_inject_break_handler(
        run_id=other_run,
        session_id=session_id,
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        probe_halted=lambda _session: True,  # would otherwise succeed
    )

    assert result.ok is False
    assert result.error.category is ErrorCategory.CONFIGURATION_ERROR
    assert result.error.details["code"] == "session_run_mismatch"
    # the durable record stays untouched for run-1 — never halted on behalf of "different-run"
    assert reg.read_record(KEY).execution_state is ExecutionState.EXECUTING


def test_close_rejects_session_from_different_run(tmp_path):
    """F7: same fence for `transport.close` — never tear down some OTHER run's session."""
    response, txn, _admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]

    result = transport_close_handler(
        run_id="different-run",
        session_id=session_id,
        transaction=txn,
        session_registry=reg,
    )

    assert result.ok is False
    assert result.error.category is ErrorCategory.CONFIGURATION_ERROR
    assert result.error.details["code"] == "session_run_mismatch"
    # the durable record (and so the live session) survives — run-1 is intact.
    assert reg.read_record(KEY) is not None


# ---------------------------------------------------------------------------
# Finding F14 — inject_break gated by DebugProfile.enabled_operations
# ---------------------------------------------------------------------------


def test_inject_break_refused_when_profile_does_not_enable_it(tmp_path):
    """F14: inject_break is destructive — a `DebugProfile` whose `enabled_operations` omits
    `transport.inject_break` MUST refuse the call before the break mechanism runs, before the
    durable record is updated. The kernel stays EXECUTING."""
    from kdive.config import DebugProfile

    response, txn, admission, reg = _open(tmp_path)
    session_id = response.data["session_id"]
    called: list[str] = []

    def spy_break(**kwargs):
        called.append(kwargs["method"])

    read_only_profiles = {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default", enabled_operations=[])}

    result = transport_inject_break_handler(
        run_id=RUN_ID,
        session_id=session_id,
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        debug_profiles=read_only_profiles,
        break_mechanism=spy_break,
        probe_halted=lambda _session: True,
    )

    assert result.ok is False
    assert result.error.category is ErrorCategory.CONFIGURATION_ERROR
    # the break mechanism was never invoked and the durable record stays EXECUTING.
    assert called == []
    assert reg.read_record(KEY).execution_state is ExecutionState.EXECUTING


def test_inject_break_reports_manifest_load_error_when_artifact_root_supplied(tmp_path):
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir()
    response, txn, admission, reg = _open(registry_dir)
    session_id = response.data["session_id"]
    artifact_root = tmp_path / "runs"
    manifest_path = artifact_root / RUN_ID / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text("{not-json", encoding="utf-8")
    called: list[str] = []

    def spy_break(**kwargs):
        called.append(kwargs["method"])

    result = transport_inject_break_handler(
        run_id=RUN_ID,
        session_id=session_id,
        acknowledged_permissions=INJECT_PERMS,
        artifact_root=artifact_root,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=spy_break,
        probe_halted=lambda _session: True,
    )

    assert result.ok is False
    assert result.error.category is ErrorCategory.CONFIGURATION_ERROR
    assert result.error.details["code"] == "manifest_load_failed"
    assert called == []
    assert reg.read_record(KEY).execution_state is ExecutionState.EXECUTING
