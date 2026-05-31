"""Deprecated compatibility facade for ``kdive.providers.local.local_crash_postmortem``.

New code should import from ``kdive.providers.local.local_crash_postmortem`` directly.
This facade is kept only for existing external imports and should be removed
before the 0.2.0 release.
"""

from kdive.providers.local.local_crash_postmortem import local_crash_postmortem_capability

__all__ = ["local_crash_postmortem_capability"]
