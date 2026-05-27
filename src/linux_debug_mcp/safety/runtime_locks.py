from __future__ import annotations

import os
import tempfile
from hashlib import sha256
from pathlib import Path


class RuntimeLockError(RuntimeError):
    """Resolving or validating the host-global runtime lock directory failed.

    Raised with a generic "runtime lock directory" noun so each caller can map it
    to its own error taxonomy and message wording.
    """


def private_runtime_lock_dir(*, base: Path | None = None) -> Path:
    """Resolve the host-global, uid-isolated lock directory.

    Prefers ``$XDG_RUNTIME_DIR/linux-debug-mcp/locks`` (already private to the
    session). Otherwise falls back to ``<base>/linux-debug-mcp-<uid>/locks`` with
    symlink, ownership, and ``0700`` validation. ``base`` defaults to the system
    temp dir; callers inject it so the resolution can be tested in isolation.
    """
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir:
        lock_dir = Path(runtime_dir) / "linux-debug-mcp" / "locks"
        try:
            lock_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RuntimeLockError(f"failed to create runtime lock directory: {exc}") from exc
        return lock_dir
    root = base if base is not None else Path(tempfile.gettempdir())
    base_dir = root / f"linux-debug-mcp-{os.getuid()}"
    _ensure_private(base_dir)
    lock_dir = base_dir / "locks"
    _ensure_private(lock_dir)
    return lock_dir


def device_lock_filename(device: str) -> str:
    """Return the host-global source-exclusivity lock filename for ``device``.

    Hashed so an arbitrary device path becomes a single safe path component, and
    namespaced (``device-``) so it never collides with target locks in the same dir.
    """
    return f"device-{sha256(device.encode()).hexdigest()}.lock"


def _ensure_private(lock_dir: Path) -> None:
    if lock_dir.is_symlink():
        raise RuntimeLockError("unsafe runtime lock directory")
    existed = lock_dir.exists()
    try:
        lock_dir.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise RuntimeLockError(f"failed to create runtime lock directory: {exc}") from exc
    if lock_dir.is_symlink():
        raise RuntimeLockError("unsafe runtime lock directory")
    if not existed:
        try:
            lock_dir.chmod(0o700)
        except OSError as exc:
            raise RuntimeLockError(f"failed to create runtime lock directory: {exc}") from exc
    try:
        stat_result = lock_dir.stat()
    except OSError as exc:
        raise RuntimeLockError(f"failed to inspect runtime lock directory: {exc}") from exc
    if stat_result.st_uid != os.getuid() or stat_result.st_mode & 0o022:
        raise RuntimeLockError("unsafe runtime lock directory")
