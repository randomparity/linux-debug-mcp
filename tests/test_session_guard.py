"""Unit tests for the SessionGuard seam (issue #66).

Covers the precondition/teardown protocol surface, enter/verify_attached phases, and the
idempotent teardown invariant (steps -> close -> resume verify -> force_reap remediation).
See docs/superpowers/specs/2026-05-29-session-guard-design.md / docs/adr/0013-*.
"""

import pytest

from kdive.seams.guard import (
    PostAttachPrecondition,
    PreAttachPrecondition,
    PreconditionError,
    SessionGuard,
    SessionGuardContext,
    TeardownReport,
    TeardownStep,
)
from kdive.seams.target import TargetKey
from kdive.transport.core.base import ExecutionState


def _ctx(reason: str = "ended", session_id: str | None = "sess-1") -> SessionGuardContext:
    return SessionGuardContext(
        target_key=TargetKey(provisioner="local-qemu", target_id="run-1"),
        generation=1,
        session_id=session_id,
        reason=reason,
    )


def test_context_is_frozen():
    ctx = _ctx()
    with pytest.raises((AttributeError, TypeError)):
        ctx.reason = "attach_error"  # type: ignore[misc]


def test_precondition_error_is_raisable():
    with pytest.raises(PreconditionError):
        raise PreconditionError("symbol mismatch", name="symbol-lock")


def test_empty_guard_protocols_importable():
    guard = SessionGuard()
    assert isinstance(guard, SessionGuard)
    # Protocols are importable and runtime-checkable.
    assert PreAttachPrecondition is not None
    assert PostAttachPrecondition is not None
    assert TeardownStep is not None
    assert TeardownReport is not None


class _RecordingPre:
    def __init__(self, name: str, calls: list[str], *, fail: bool = False) -> None:
        self.name = name
        self._calls = calls
        self._fail = fail

    def check(self, ctx: SessionGuardContext) -> None:
        self._calls.append(self.name)
        if self._fail:
            raise PreconditionError(f"{self.name} failed", name=self.name)


class _RecordingPost:
    def __init__(self, name: str, calls: list[str], *, fail: bool = False) -> None:
        self.name = name
        self._calls = calls
        self._fail = fail

    def check(self, ctx: SessionGuardContext, session: object) -> None:
        self._calls.append(self.name)
        if self._fail:
            raise PreconditionError(f"{self.name} failed", name=self.name)


def test_enter_runs_preconditions_in_order():
    calls: list[str] = []
    guard = SessionGuard(pre_attach=[_RecordingPre("a", calls), _RecordingPre("b", calls)])
    guard.enter(_ctx(reason="ended", session_id=None))
    assert calls == ["a", "b"]


def test_enter_first_failure_aborts_no_later_precondition():
    calls: list[str] = []
    guard = SessionGuard(pre_attach=[_RecordingPre("a", calls, fail=True), _RecordingPre("b", calls)])
    with pytest.raises(PreconditionError) as exc:
        guard.enter(_ctx(reason="ended", session_id=None))
    assert exc.value.name == "a"
    assert calls == ["a"]


def test_verify_attached_runs_post_preconditions_in_order():
    calls: list[str] = []
    guard = SessionGuard(post_attach=[_RecordingPost("p", calls), _RecordingPost("q", calls)])
    guard.verify_attached(_ctx(), session=object())
    assert calls == ["p", "q"]


def test_verify_attached_first_failure_raises():
    calls: list[str] = []
    guard = SessionGuard(post_attach=[_RecordingPost("p", calls, fail=True), _RecordingPost("q", calls)])
    with pytest.raises(PreconditionError) as exc:
        guard.verify_attached(_ctx(), session=object())
    assert exc.value.name == "p"
    assert calls == ["p"]


class _RecordingStep:
    def __init__(self, name: str, calls: list[str], *, fail: bool = False) -> None:
        self.name = name
        self._calls = calls
        self._fail = fail

    def teardown(self, ctx: SessionGuardContext) -> None:
        self._calls.append(self.name)
        if self._fail:
            raise RuntimeError(f"{self.name} boom")


class _FakeHaltedRecord:
    """Stand-in whose execution_state mimics a still-HALTED TransportSession."""

    def __init__(self) -> None:
        self.execution_state = ExecutionState.HALTED


def _ended_teardown(guard, *, record_after_close):
    state = {"closed": False, "force_reaped": False}

    def close() -> None:
        state["closed"] = True

    def read_record():
        return record_after_close(state)

    def force_reap() -> None:
        state["force_reaped"] = True

    report = guard.teardown(_ctx(reason="ended"), close=close, read_record=read_record, force_reap=force_reap)
    return report, state


def test_teardown_steps_run_in_reverse_then_close():
    calls: list[str] = []
    guard = SessionGuard(teardown_steps=[_RecordingStep("first", calls), _RecordingStep("second", calls)])
    report, state = _ended_teardown(guard, record_after_close=lambda s: None)
    assert calls == ["second", "first"]
    assert state["closed"] is True
    assert report.resume_ok is True
    assert state["force_reaped"] is False


def test_teardown_step_failure_is_suppressed_and_aggregated():
    calls: list[str] = []
    guard = SessionGuard(teardown_steps=[_RecordingStep("ok", calls), _RecordingStep("bad", calls, fail=True)])
    report, state = _ended_teardown(guard, record_after_close=lambda s: None)
    assert calls == ["bad", "ok"]
    assert state["closed"] is True
    assert "bad" in report.step_errors
    assert report.resume_ok is True


def test_teardown_resume_ok_true_when_record_deleted():
    guard = SessionGuard()
    report, _ = _ended_teardown(guard, record_after_close=lambda s: None)
    assert report.resume_ok is True
    assert report.close_error is None


def test_teardown_close_raises_then_force_reap_clears():
    state = {"force_reaped": False}

    def close() -> None:
        raise RuntimeError("transport.close wedged")

    reads = [_FakeHaltedRecord(), None]

    def read_record():
        return reads.pop(0)

    def force_reap() -> None:
        state["force_reaped"] = True

    guard = SessionGuard()
    report = guard.teardown(_ctx(reason="ended"), close=close, read_record=read_record, force_reap=force_reap)
    assert report.close_error is not None
    assert state["force_reaped"] is True
    assert report.resume_ok is True


def test_teardown_resume_false_when_force_reap_also_fails():
    def close() -> None:
        raise RuntimeError("wedged")

    def read_record():
        return _FakeHaltedRecord()

    def force_reap() -> None:
        return None

    guard = SessionGuard()
    report = guard.teardown(_ctx(reason="ended"), close=close, read_record=read_record, force_reap=force_reap)
    assert report.resume_ok is False
    assert report.resume_detail


def test_teardown_idempotent_over_shared_state():
    shared = {"record": _FakeHaltedRecord(), "closes": 0, "force_reaps": 0}

    def close() -> None:
        shared["closes"] += 1
        shared["record"] = None

    def read_record():
        return shared["record"]

    def force_reap() -> None:
        shared["force_reaps"] += 1

    guard = SessionGuard()
    first = guard.teardown(_ctx(reason="ended"), close=close, read_record=read_record, force_reap=force_reap)
    second = guard.teardown(_ctx(reason="ended"), close=close, read_record=read_record, force_reap=force_reap)
    assert first.resume_ok is True and second.resume_ok is True
    assert shared["closes"] == 2
    assert shared["force_reaps"] == 0
