from __future__ import annotations

from linux_debug_mcp.providers.local_crash_postmortem import local_crash_postmortem_capability
from linux_debug_mcp.providers.plugins import local_provider_plugin_specs


def test_capability_advertises_operation() -> None:
    cap = local_crash_postmortem_capability()
    assert cap.provider_name == "local-crash-postmortem"
    assert cap.operations == ["debug.postmortem.crash"]
    assert "crash" in cap.required_host_tools
    assert cap.semantics.concurrent_safe is True


def test_capability_registered_in_local_specs() -> None:
    names = {
        cap().provider_name for spec in local_provider_plugin_specs() for cap in spec.provider_capability_factories
    }
    assert "local-crash-postmortem" in names
