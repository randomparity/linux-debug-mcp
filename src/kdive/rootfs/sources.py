"""Resolve a RootfsProfile's source_kind to a concrete on-disk image path.

Phase 1 (issue #102) implements ``local_path`` and ``builder``. ``prebuilt`` (#106)
and ``url`` (#107) are accepted by the model but report ``NOT_IMPLEMENTED`` here. The
resolver performs no privileged provisioning: the only filesystem access is a
``Path.exists()`` check for the ``builder`` kind.
"""

from pathlib import Path

from kdive.config import RootfsProfile
from kdive.domain import ErrorCategory

_BUILDER_FIX = (
    "Run `just rootfs` to build the default rootfs image at the configured path, "
    "or set the rootfs profile's source to an existing disk image."
)
_UNIMPLEMENTED_ISSUE = {"prebuilt": "#106", "url": "#107"}


class RootfsSourceError(Exception):
    """A rootfs source_kind could not be resolved to a usable image."""

    def __init__(self, message: str, *, category: ErrorCategory, suggested_fix: str = "") -> None:
        super().__init__(message)
        self.category = category
        self.suggested_fix = suggested_fix


def resolve_rootfs_source(profile: RootfsProfile) -> Path:
    """Map ``profile.source_kind`` to a concrete image path or raise RootfsSourceError.

    For ``local_path`` the path is returned without an existence check (the provider's
    own resolution reports the generic missing-path error). For ``builder`` a missing
    image raises a CONFIGURATION_ERROR naming ``just rootfs``. ``prebuilt``/``url``
    raise NOT_IMPLEMENTED naming their tracking issue.
    """
    source = Path(profile.source)
    kind = profile.source_kind
    if kind == "local_path":
        return source
    if kind == "builder":
        if source.exists():
            return source
        raise RootfsSourceError(
            f"builder rootfs image not found: {source}",
            category=ErrorCategory.CONFIGURATION_ERROR,
            suggested_fix=_BUILDER_FIX,
        )
    issue = _UNIMPLEMENTED_ISSUE[kind]
    raise RootfsSourceError(
        f"rootfs source_kind '{kind}' is not implemented yet (tracked in {issue})",
        category=ErrorCategory.NOT_IMPLEMENTED,
    )
