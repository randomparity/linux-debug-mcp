from linux_debug_mcp.introspect_helpers import HELPER_REGISTRY, built_in_helper_specs
from linux_debug_mcp.introspect_helpers.base import HelperSpec


def test_registry_names_are_unique_and_expected() -> None:
    names = [spec.name for spec in built_in_helper_specs()]
    assert len(names) == len(set(names))  # unique
    assert set(names) == {"sysinfo", "tasks", "dmesg", "modules", "slab", "irq"}


def test_registry_maps_name_to_spec() -> None:
    assert isinstance(HELPER_REGISTRY["sysinfo"], HelperSpec)
    assert HELPER_REGISTRY["sysinfo"].version >= 1


def test_every_spec_script_calls_emit() -> None:
    for spec in built_in_helper_specs():
        assert "emit(" in spec.script, spec.name
