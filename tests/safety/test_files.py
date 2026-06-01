from __future__ import annotations

import os
from pathlib import Path

import pytest

from kdive.safety.files import atomic_write_text


def test_atomic_write_text_replaces_file_through_sibling_temp(tmp_path: Path) -> None:
    path = tmp_path / "result.json"
    path.write_text("old", encoding="utf-8")

    atomic_write_text(path, "new")

    assert path.read_text(encoding="utf-8") == "new"
    assert list(tmp_path.glob(".*.tmp")) == []
    assert path.stat().st_mode & 0o777 == 0o600


def test_atomic_write_text_removes_temp_file_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "result.json"

    def fail_replace(source: str | bytes | os.PathLike[str], destination: str | bytes | os.PathLike[str]) -> None:
        raise PermissionError(f"cannot replace {source} -> {destination}")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(PermissionError):
        atomic_write_text(path, "new")

    assert not path.exists()
    assert list(tmp_path.glob(".*.tmp")) == []
