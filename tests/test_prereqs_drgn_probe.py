"""Unit tests for the host-side drgn-probe core (spec §4-§5)."""

from linux_debug_mcp.providers.local_drgn_introspect import TARGET_PYTHON_ARGV


def test_target_python_argv_is_shared_constant() -> None:
    # Spec §4: probe and runner must use the same interpreter invocation.
    assert TARGET_PYTHON_ARGV == ["python3", "-"]
