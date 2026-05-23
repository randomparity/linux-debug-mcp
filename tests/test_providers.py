import pytest

from linux_debug_mcp.domain import OperationSemantics, ProviderCapability, TargetKind
from linux_debug_mcp.providers.registry import ProviderRegistry


def capability(name: str) -> ProviderCapability:
    return ProviderCapability(
        provider_name=name,
        provider_version="0.1.0",
        architectures=["x86_64"],
        target_kinds=[TargetKind.LOCAL],
        operations=["host.check_prerequisites"],
        required_host_tools=[],
        destructive_permissions=[],
        access_methods=["filesystem"],
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=False,
            cancelable=False,
            concurrent_safe=True,
        ),
    )


def test_registry_lists_registered_capabilities() -> None:
    registry = ProviderRegistry()
    registry.register(capability("local-artifacts"))

    assert registry.list_capabilities()[0].provider_name == "local-artifacts"
    assert registry.get("local-artifacts").operations == ["host.check_prerequisites"]


def test_registry_rejects_duplicate_names() -> None:
    registry = ProviderRegistry()
    registry.register(capability("local-artifacts"))

    with pytest.raises(ValueError, match="already registered"):
        registry.register(capability("local-artifacts"))


def test_default_registry_exposes_sprint_1_providers() -> None:
    registry = ProviderRegistry.with_defaults()

    providers = {provider.provider_name: provider for provider in registry.list_capabilities()}

    assert set(providers) == {"local-artifacts", "local-prereqs", "local-kernel-build", "stub-workflows"}
    assert "kernel.build" in providers["local-kernel-build"].operations
    assert "kernel.build" not in providers["stub-workflows"].operations
    assert "make" in providers["local-kernel-build"].required_host_tools
