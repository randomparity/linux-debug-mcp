import hashlib
import os
from pathlib import Path

import pytest

from linux_debug_mcp.safety.runtime_locks import (
    RuntimeLockError,
    device_lock_filename,
    private_runtime_lock_dir,
    private_runtime_registry_dir,
)


def test_prefers_xdg_runtime_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))

    lock_dir = private_runtime_lock_dir(base=tmp_path / "unused")

    assert lock_dir == xdg / "linux-debug-mcp" / "locks"
    assert lock_dir.is_dir()


def test_validates_xdg_runtime_subdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A safety-critical device lock now depends on the XDG-derived dir, so it must get the
    same symlink/ownership/0700 validation the fallback branch enforces — not a bare mkdir."""
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    subdir = xdg / "linux-debug-mcp"
    subdir.mkdir()
    subdir.chmod(0o777)

    with pytest.raises(RuntimeLockError):
        private_runtime_lock_dir()


def test_falls_back_to_private_uid_dir_under_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)

    lock_dir = private_runtime_lock_dir(base=tmp_path)

    assert lock_dir == tmp_path / f"linux-debug-mcp-{os.getuid()}" / "locks"
    assert lock_dir.stat().st_mode & 0o777 == 0o700


def test_rejects_symlinked_fallback_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / f"linux-debug-mcp-{os.getuid()}").symlink_to(real, target_is_directory=True)

    with pytest.raises(RuntimeLockError):
        private_runtime_lock_dir(base=tmp_path)


def test_rejects_world_writable_fallback_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    lock_dir = tmp_path / f"linux-debug-mcp-{os.getuid()}" / "locks"
    lock_dir.mkdir(parents=True)
    lock_dir.chmod(0o777)

    with pytest.raises(RuntimeLockError):
        private_runtime_lock_dir(base=tmp_path)


def test_registry_dir_prefers_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    result = private_runtime_registry_dir()
    assert result == tmp_path / "linux-debug-mcp" / "registry"
    assert result.is_dir()
    assert (result.stat().st_mode & 0o777) == 0o700


def test_registry_dir_fallback_when_no_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    result = private_runtime_registry_dir(base=tmp_path)
    assert result == tmp_path / f"linux-debug-mcp-{os.getuid()}" / "registry"
    assert result.is_dir()


def test_registry_dir_rejects_symlink(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    base = tmp_path / "linux-debug-mcp"
    base.mkdir(parents=True)
    (base / "registry").symlink_to(tmp_path)
    with pytest.raises(RuntimeLockError):
        private_runtime_registry_dir()


def test_device_lock_filename_is_sha256_namespaced() -> None:
    device = "/dev/ttyUSB0"
    digest = hashlib.sha256(device.encode()).hexdigest()

    assert device_lock_filename(device) == f"device-{digest}.lock"
