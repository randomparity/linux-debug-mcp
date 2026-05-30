"""Tests for the provider plugin registry."""

from kdive.providers.plugins import local_provider_plugin_specs


def test_local_drgn_introspect_capability_is_registered() -> None:
    specs = local_provider_plugin_specs()
    cap_names = {
        cap.provider_name for spec in specs for cap in (factory() for factory in spec.provider_capability_factories)
    }
    assert "local-drgn-introspect" in cap_names


def test_local_drgn_introspect_advertises_introspect_run_operation() -> None:
    specs = local_provider_plugin_specs()
    for spec in specs:
        for factory in spec.provider_capability_factories:
            cap = factory()
            if cap.provider_name == "local-drgn-introspect":
                assert "debug.introspect.run" in cap.operations
                return
    raise AssertionError("local-drgn-introspect capability not registered")
