from __future__ import annotations

from typing import Any

from kdive.seams.target import TargetKey


def assert_no_admission_binding(admission: Any, target_key: TargetKey) -> None:
    """Observe the admission binding table in tests that lack a public binding query."""
    assert admission._bindings.get(target_key, []) == []


def assert_admission_binding_exists(admission: Any, target_key: TargetKey) -> None:
    """Observe admission ownership without scattering private storage details across tests."""
    assert admission._bindings.get(target_key, []) != []


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
