"""Deprecated provider import compatibility boundary.

Concrete provider implementations live under ``kdive.providers.local``. The
root-level modules listed here are legacy import aliases kept only until the
documented 0.2.0 removal point.
"""

from __future__ import annotations

from types import MappingProxyType

LEGACY_PROVIDER_MODULES = MappingProxyType(
    {
        "kdive.providers.drgn_vmcore_wrapper": "kdive.providers.local.drgn_vmcore_wrapper",
        "kdive.providers.drgn_wrapper_common": "kdive.providers.local.drgn_wrapper_common",
        "kdive.providers.gdb_mi": "kdive.providers.local.gdb_mi",
        "kdive.providers.libvirt_qemu": "kdive.providers.local.libvirt_qemu",
        "kdive.providers.local_crash_postmortem": "kdive.providers.local.local_crash_postmortem",
        "kdive.providers.local_drgn_introspect": "kdive.providers.local.local_drgn_introspect",
        "kdive.providers.local_kernel_build": "kdive.providers.local.local_kernel_build",
        "kdive.providers.local_ssh_tests": "kdive.providers.local.local_ssh_tests",
        "kdive.providers.local_vmcore_retrieval": "kdive.providers.local.local_vmcore_retrieval",
        "kdive.providers.qemu_gdbstub": "kdive.providers.local.qemu_gdbstub",
    }
)

__all__ = ["LEGACY_PROVIDER_MODULES"]
