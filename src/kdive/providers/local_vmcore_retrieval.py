"""Deprecated compatibility facade for ``kdive.providers.local.local_vmcore_retrieval``.

New code should import from ``kdive.providers.local.local_vmcore_retrieval`` directly.
This facade is kept only for existing external imports and should be removed
before the 0.2.0 release.
"""

from kdive.providers.local.local_vmcore_retrieval import local_vmcore_retrieval_capability

__all__ = ["local_vmcore_retrieval_capability"]
