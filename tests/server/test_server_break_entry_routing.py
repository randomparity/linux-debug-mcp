"""Phase D (#82), ADR 0024 decision 1: break entry routes off the admitted ``break_plan.method``.
A gdbstub-native plan (or an absent record) uses the engine's direct ``interrupt()``; any other
admitted method is injected through ``TransportTransaction.inject_break_for_session``. The tier
never chooses or hardcodes the method, and a transport with no resolvable break handle fails with
``break_inject_unavailable`` rather than silently no-op'ing."""

from __future__ import annotations

from datetime import UTC, datetime

from kdive.coordination.transaction import TransportTransaction
from kdive.debug.operations import _break_entry_method, _interrupt_op_data
from kdive.providers.local.debug.gdb_mi import StopRecord
from kdive.seams.target import TargetKey
from kdive.transport.base import BreakMethod, BreakPlan, TransportSession
from kdive.transport.break_inject import InjectBreakError

KEY = TargetKey(provisioner="local-qemu", target_id="run-xyz")


def _record(method: BreakMethod | None) -> TransportSession:
    plan = None if method is None else BreakPlan(method=method, channel_id="rsp0", rationale="test")
    return TransportSession(
        session_id="transport-" + "0" * 32,
        target_key=KEY,
        generation=1,
        provider="qemu-gdbstub",
        channel_id="rsp0",
        break_plan=plan,
        created_at=datetime.now(UTC),
    )


class _RecordingEngine:
    def __init__(self) -> None:
        self.interrupted = False
        self.waited = False

    def interrupt(self, attachment) -> StopRecord | None:
        self.interrupted = True
        return StopRecord(reason="signal-received")

    def wait_for_stop(self, attachment, *, timeout_sec: float) -> StopRecord | None:
        self.waited = True
        return StopRecord(reason="signal-received")


class _NoStopEngine:
    """Models a break that produced no MI stop within the window (interrupt / wait_for_stop time out
    and return None) — the lossy out-of-band case this whole tier warns about."""

    def interrupt(self, attachment) -> StopRecord | None:
        return None

    def wait_for_stop(self, attachment, *, timeout_sec: float) -> StopRecord | None:
        return None


class _RecordingTransaction:
    def __init__(self) -> None:
        self.injected: list[tuple[str, str]] = []

    def inject_break_for_session(self, session_id: str, requested_method: str) -> None:
        self.injected.append((session_id, requested_method))


def test_break_entry_method_native_for_gdbstub_native_and_absent() -> None:
    assert _break_entry_method(_record(BreakMethod.GDBSTUB_NATIVE)) is BreakMethod.GDBSTUB_NATIVE
    assert _break_entry_method(_record(None)) is BreakMethod.GDBSTUB_NATIVE
    assert _break_entry_method(None) is BreakMethod.GDBSTUB_NATIVE


def test_router_native_calls_engine_interrupt() -> None:
    engine = _RecordingEngine()
    txn = _RecordingTransaction()
    data = _interrupt_op_data(
        engine=engine, attachment=object(), transport_session=_record(BreakMethod.GDBSTUB_NATIVE), transaction=txn
    )
    assert engine.interrupted is True
    assert engine.waited is False
    assert txn.injected == []
    assert data["current_execution_state"] == "stopped"


def test_router_inject_for_serial_method_calls_inject_break_for_session() -> None:
    engine = _RecordingEngine()
    txn = _RecordingTransaction()
    record = _record(BreakMethod.AGENT_PROXY_BREAK)
    data = _interrupt_op_data(engine=engine, attachment=object(), transport_session=record, transaction=txn)
    assert txn.injected == [(record.session_id, "agent_proxy_break")]
    assert engine.interrupted is False
    assert engine.waited is True
    assert data["current_execution_state"] == "stopped"


def test_router_inject_no_stop_reports_unknown_not_stopped() -> None:
    # The break was injected but no MI stop arrived within the window — report unknown, never an
    # optimistic "stopped" (the lossy-console fail-open the dedicated inject_break tool guards too).
    txn = _RecordingTransaction()
    record = _record(BreakMethod.AGENT_PROXY_BREAK)
    data = _interrupt_op_data(engine=_NoStopEngine(), attachment=object(), transport_session=record, transaction=txn)
    assert data["stop"] is None
    assert data["current_execution_state"] == "unknown"


def test_router_native_no_stop_reports_unknown_not_stopped() -> None:
    txn = _RecordingTransaction()
    data = _interrupt_op_data(
        engine=_NoStopEngine(),
        attachment=object(),
        transport_session=_record(BreakMethod.GDBSTUB_NATIVE),
        transaction=txn,
    )
    assert data["stop"] is None
    assert data["current_execution_state"] == "unknown"


class _NoHandleTransport:
    def break_resources(self, session):
        return None


class _FakeRegistry:
    def __init__(self, records: list[TransportSession]) -> None:
        self._records = records

    def list_records(self) -> list[TransportSession]:
        return list(self._records)


def _bare_transaction(records, transports) -> TransportTransaction:
    txn = object.__new__(TransportTransaction)
    txn._registry = _FakeRegistry(records)  # type: ignore[attr-defined]
    txn._transports = transports  # type: ignore[attr-defined]
    return txn


def test_inject_break_for_session_missing_handle_raises_unavailable() -> None:
    record = _record(BreakMethod.AGENT_PROXY_BREAK)
    txn = _bare_transaction([record], {"qemu-gdbstub": _NoHandleTransport()})
    try:
        txn.inject_break_for_session(record.session_id, "agent_proxy_break")
    except InjectBreakError as exc:
        assert exc.details.get("code") == "break_inject_unavailable"
    else:
        raise AssertionError("expected InjectBreakError for a transport with no break handle")


def test_inject_break_for_session_unknown_session_raises_unavailable() -> None:
    txn = _bare_transaction([], {})
    try:
        txn.inject_break_for_session("transport-" + "f" * 32, "agent_proxy_break")
    except InjectBreakError as exc:
        assert exc.details.get("code") == "break_inject_unavailable"
    else:
        raise AssertionError("expected InjectBreakError for an unknown session")
