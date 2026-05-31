"""Deprecated compatibility facade for ``kdive.providers.local.local_kernel_build``.

New code should import from ``kdive.providers.local.local_kernel_build`` directly.
This facade is kept only for existing external imports and should be removed
before the 0.2.0 release.
"""

from kdive.providers.local.local_kernel_build import (
    READELF_TIMEOUT_SECONDS,
    BuildExecutionResult,
    BuildIdMissing,
    BuildPlan,
    BuildRunner,
    ConfigGenerationError,
    ConfigMergeError,
    LocalKernelBuildProvider,
    MissingConfigError,
    ReadelfUnavailable,
    SubprocessBuildRunner,
    local_kernel_build_capability,
)

__all__ = [
    "READELF_TIMEOUT_SECONDS",
    "BuildExecutionResult",
    "BuildIdMissing",
    "BuildPlan",
    "BuildRunner",
    "ConfigGenerationError",
    "ConfigMergeError",
    "LocalKernelBuildProvider",
    "MissingConfigError",
    "ReadelfUnavailable",
    "SubprocessBuildRunner",
    "local_kernel_build_capability",
]
