from __future__ import annotations

from linux_debug_mcp.providers.local_vmcore_retrieval import local_vmcore_retrieval_capability
from linux_debug_mcp.providers.plugins import built_in_provider_plugin_specs


def test_capability_shape() -> None:
    cap = local_vmcore_retrieval_capability()
    assert cap.provider_name == "local-vmcore-retrieval"
    assert "debug.postmortem.list_dumps" in cap.operations
    assert "debug.postmortem.fetch" in cap.operations
    assert "ssh" in cap.required_host_tools
    assert "scp" in cap.required_host_tools
    assert cap.transports == ["ssh"]


def test_capability_registered_in_plugins() -> None:
    names = {
        cap().provider_name for spec in built_in_provider_plugin_specs() for cap in spec.provider_capability_factories
    }
    assert "local-vmcore-retrieval" in names
