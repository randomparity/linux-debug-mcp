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

    assert set(providers) == {
        "local-artifacts",
        "local-prereqs",
        "local-kernel-build",
        "local-libvirt-qemu",
        "local-ssh-tests",
        "stub-workflows",
    }
    assert "kernel.build" in providers["local-kernel-build"].operations
    assert "kernel.build" not in providers["stub-workflows"].operations
    assert "make" in providers["local-kernel-build"].required_host_tools

    libvirt_qemu = providers["local-libvirt-qemu"]
    assert libvirt_qemu.operations == ["target.boot"]
    assert "target.boot" not in providers["stub-workflows"].operations
    assert libvirt_qemu.required_host_tools == ["virsh"]
    assert libvirt_qemu.target_kinds == [TargetKind.VIRTUAL]
    assert libvirt_qemu.access_methods == ["libvirt", "serial-console", "filesystem"]
    assert libvirt_qemu.destructive_permissions == [
        "define MCP-owned libvirt domains",
        "update MCP-owned libvirt domains",
        "start MCP-owned libvirt domains",
        "stop MCP-owned libvirt domains",
        "destroy MCP-owned libvirt domains",
    ]
    assert libvirt_qemu.semantics.idempotent is True
    assert libvirt_qemu.semantics.retryable is True
    assert libvirt_qemu.semantics.destructive is True
    assert libvirt_qemu.semantics.cancelable is False
    assert libvirt_qemu.semantics.concurrent_safe is False

    ssh_tests = providers["local-ssh-tests"]
    assert ssh_tests.operations == ["target.run_tests"]
    assert "target.run_tests" not in providers["stub-workflows"].operations
    assert ssh_tests.required_host_tools == ["ssh"]
    assert ssh_tests.target_kinds == [TargetKind.VIRTUAL]
