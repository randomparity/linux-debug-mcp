"""Deprecated compatibility facade for ``kdive.providers.local.drgn_wrapper_common``.

New code should import from ``kdive.providers.local.drgn_wrapper_common`` directly.
This facade is kept only for existing external imports and should be removed
before the 0.2.0 release.
"""

from kdive.providers.local.drgn_wrapper_common import RUNNER_DEFAULT_CAPS, WrapperRenderError, user_script_sha256

__all__ = ["RUNNER_DEFAULT_CAPS", "WrapperRenderError", "user_script_sha256"]
