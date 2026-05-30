from pathlib import Path

import pytest

from kdive.config import RootfsProfile
from kdive.domain import ErrorCategory
from kdive.rootfs.sources import RootfsSourceError, resolve_rootfs_source


def _profile(tmp_path: Path, *, source_kind: str, exists: bool = True) -> RootfsProfile:
    image = tmp_path / "minimal.qcow2"
    if exists:
        image.write_bytes(b"qcow2")
    return RootfsProfile(name="minimal", source=str(image), source_kind=source_kind)


def test_local_path_returns_source_without_existence_check(tmp_path: Path) -> None:
    profile = _profile(tmp_path, source_kind="local_path", exists=False)
    assert resolve_rootfs_source(profile) == Path(profile.source)


def test_builder_present_returns_path(tmp_path: Path) -> None:
    profile = _profile(tmp_path, source_kind="builder", exists=True)
    assert resolve_rootfs_source(profile) == Path(profile.source)


def test_builder_missing_raises_configuration_error_with_just_rootfs(tmp_path: Path) -> None:
    profile = _profile(tmp_path, source_kind="builder", exists=False)
    with pytest.raises(RootfsSourceError) as exc:
        resolve_rootfs_source(profile)
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert "just rootfs" in exc.value.suggested_fix


@pytest.mark.parametrize(("kind", "issue"), [("prebuilt", "#106"), ("url", "#107")])
def test_unimplemented_kinds_raise_not_implemented(tmp_path: Path, kind: str, issue: str) -> None:
    profile = _profile(tmp_path, source_kind=kind, exists=True)
    with pytest.raises(RootfsSourceError) as exc:
        resolve_rootfs_source(profile)
    assert exc.value.category == ErrorCategory.NOT_IMPLEMENTED
    assert issue in str(exc.value)
