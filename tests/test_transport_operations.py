import pytest

from kdive.config import (
    TRANSPORT_DESTRUCTIVE_PERMISSIONS,
    TRANSPORT_OPERATIONS,
    validate_transport_operation,
)


def test_allowlist_contents():
    assert TRANSPORT_OPERATIONS == [
        "transport.open",
        "transport.status",
        "transport.health",
        "transport.inject_break",
        "transport.close",
    ]


def test_validate_accepts_allowed_operation():
    # Returns the op unchanged on success.
    assert validate_transport_operation("transport.open") == "transport.open"


def test_validate_rejects_unknown_operation():
    with pytest.raises(ValueError):
        validate_transport_operation("transport.nuke")


def test_inject_break_carries_destructive_permission():
    perms = TRANSPORT_DESTRUCTIVE_PERMISSIONS["transport.inject_break"]
    assert perms == ["drop target kernel into the debugger"]


def test_only_inject_break_is_destructive():
    assert set(TRANSPORT_DESTRUCTIVE_PERMISSIONS) == {"transport.inject_break"}
