from __future__ import annotations

import pytest
from pydantic import ValidationError

from linux_debug_mcp.domain import DebugPostmortemCheckPrereqsRequest, ErrorCategory
from linux_debug_mcp.server import _reject_if_target_halted
from linux_debug_mcp.transport.base import ExecutionState


def test_request_defaults_and_fields() -> None:
    req = DebugPostmortemCheckPrereqsRequest(run_id="r1", target_ref="x86_64-default")
    assert req.timeout_seconds == 20
    assert req.debug_profile is None


def test_request_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        DebugPostmortemCheckPrereqsRequest(run_id="r1", target_ref="x", bogus=1)


class _FakeSnapshot:
    generation = 1
    platform = None


class _FakeAdmission:
    def current_snapshot(self, target_key):  # noqa: ANN001
        return _FakeSnapshot()

    def current_execution_epoch(self, target_key):  # noqa: ANN001
        return 0


class _FakeRecord:
    def __init__(self, state: ExecutionState) -> None:
        self.execution_state = state


class _FakeRegistry:
    def __init__(self, state: ExecutionState) -> None:
        self._state = state

    def read_record(self, target_key):  # noqa: ANN001
        return _FakeRecord(self._state)


def test_halted_target_is_fast_rejected() -> None:
    resp = _reject_if_target_halted(
        run_id="r1",
        admission=_FakeAdmission(),
        session_registry=_FakeRegistry(ExecutionState.HALTED),
    )
    assert resp is not None
    assert resp.ok is False
    assert resp.error is not None
    assert resp.error.category == ErrorCategory.READINESS_FAILURE
    assert resp.error.details["code"] == "target_halted"


def test_executing_target_proceeds() -> None:
    assert (
        _reject_if_target_halted(
            run_id="r1",
            admission=_FakeAdmission(),
            session_registry=_FakeRegistry(ExecutionState.EXECUTING),
        )
        is None
    )


def test_inert_gate_when_admission_absent() -> None:
    assert _reject_if_target_halted(run_id="r1", admission=None, session_registry=None) is None
