"""Deprecated compatibility facade for ``kdive.providers.local.qemu_gdbstub``.

New code should import from ``kdive.providers.local.qemu_gdbstub`` directly.
This facade is kept only for existing external imports and should be removed
before the 0.2.0 release.
"""

from kdive.providers.local.qemu_gdbstub import (
    QEMU_GDBSTUB_OPERATIONS,
    DebugSession,
    ProviderDebugError,
    local_qemu_gdbstub_capability,
)

__all__ = [
    "QEMU_GDBSTUB_OPERATIONS",
    "DebugSession",
    "ProviderDebugError",
    "local_qemu_gdbstub_capability",
]
