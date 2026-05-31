"""Deprecated compatibility facade for ``kdive.providers.local.drgn_vmcore_wrapper``.

New code should import from ``kdive.providers.local.drgn_vmcore_wrapper`` directly.
This facade is kept only for existing external imports and should be removed
before the 0.2.0 release.
"""

from kdive.providers.local.drgn_vmcore_wrapper import (
    VMCORE_WRAPPER_TEMPLATE,
    render_vmcore_wrapper,
    render_vmcore_wrapper_skeleton,
)

__all__ = ["VMCORE_WRAPPER_TEMPLATE", "render_vmcore_wrapper", "render_vmcore_wrapper_skeleton"]
