from __future__ import annotations

from typing import Any

from kdive.coordination.admission import AdmissionOp
from kdive.seams.target import TargetKey


def assert_no_admission_binding(admission: Any, target_key: TargetKey) -> None:
    """Observe the admission binding table in tests that lack a public binding query."""
    assert admission._bindings.get(target_key, []) == []


def assert_admission_binding_exists(admission: Any, target_key: TargetKey) -> None:
    """Observe admission ownership without scattering private storage details across tests."""
    assert admission._bindings.get(target_key, []) != []


def assert_no_admission_binding_for_op(admission: Any, target_key: TargetKey, operation: AdmissionOp) -> None:
    """Observe that a specific admission operation has no live binding."""
    assert [handle for handle in admission._bindings.get(target_key, ()) if handle.op is operation] == []


def assert_no_recovery_required(admission: Any, target_key: TargetKey) -> None:
    """Observe that recovery-required admission cache has no entry for a target."""
    assert admission._recovery_required.get(target_key) is None


def assert_recovery_required(
    admission: Any,
    target_key: TargetKey,
    *,
    generation: int | None = None,
) -> None:
    """Observe recovery-required admission cache state without exposing its storage layout."""
    actual_generation = admission._recovery_required.get(target_key)
    if generation is None:
        assert actual_generation is not None
    else:
        assert actual_generation == generation


def assert_admission_open(admission: Any, target_key: TargetKey) -> None:
    """Observe that admission is not closed for a target."""
    assert target_key not in admission._closed_at


def assert_admission_closed_at(admission: Any, target_key: TargetKey, generation: int) -> None:
    """Observe the generation at which admission was closed for a target."""
    assert admission._closed_at.get(target_key) == generation


def assert_stop_guard_released(transaction: Any, target_key: TargetKey) -> None:
    """Confirm a target-wide stop guard can be reacquired after cleanup."""
    token = transaction._guard.acquire(target_key)
    assert transaction._guard.release(target_key, token) is True


def assert_lifecycle_unsubscribed(dispatcher: Any, target_key: TargetKey) -> None:
    """Observe lifecycle subscriber cleanup in tests that validate dispatcher wiring."""
    assert dispatcher._subscribers.get(target_key, {}) == {}


def assert_lifecycle_subscribed(dispatcher: Any, target_key: TargetKey, session_id: str) -> None:
    """Observe lifecycle subscriber registration in tests that validate dispatcher wiring."""
    assert session_id in dispatcher._subscribers.get(target_key, {})
