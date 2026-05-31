"""Deprecated compatibility facade for ``kdive.providers.local.local_drgn_introspect``.

New code should import from ``kdive.providers.local.local_drgn_introspect`` directly.
This facade is kept only for existing external imports and should be removed
before the 0.2.0 release.
"""

from kdive.providers.local.local_drgn_introspect import (
    SCRIPT_BYTE_CAP,
    TARGET_PYTHON_ARGV,
    LocalDrgnIntrospectProvider,
    local_drgn_introspect_capability,
)

__all__ = [
    "SCRIPT_BYTE_CAP",
    "TARGET_PYTHON_ARGV",
    "LocalDrgnIntrospectProvider",
    "local_drgn_introspect_capability",
]
