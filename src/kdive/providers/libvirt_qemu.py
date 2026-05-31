"""Deprecated compatibility facade for ``kdive.providers.local.libvirt_qemu``.

New code should import from ``kdive.providers.local.libvirt_qemu`` directly.
This facade is kept only for existing external imports and should be removed
before the 0.2.0 release.
"""

from kdive.providers.local.libvirt_qemu import (
    MCP_METADATA_NS,
    QEMU_DOMAIN_MEMORY_MIB,
    QEMU_DOMAIN_VCPU_COUNT,
    QEMU_NS,
    BootExecutionResult,
    BootPlan,
    CommandResult,
    ConsoleResult,
    GdbstubEndpoint,
    LibvirtQemuProvider,
    LibvirtRunner,
    ProviderBootError,
    SubprocessLibvirtRunner,
    local_libvirt_qemu_capability,
    parse_domifaddr_ipv4,
)

__all__ = [
    "MCP_METADATA_NS",
    "QEMU_DOMAIN_MEMORY_MIB",
    "QEMU_DOMAIN_VCPU_COUNT",
    "QEMU_NS",
    "BootExecutionResult",
    "BootPlan",
    "CommandResult",
    "ConsoleResult",
    "GdbstubEndpoint",
    "LibvirtQemuProvider",
    "LibvirtRunner",
    "ProviderBootError",
    "SubprocessLibvirtRunner",
    "local_libvirt_qemu_capability",
    "parse_domifaddr_ipv4",
]
