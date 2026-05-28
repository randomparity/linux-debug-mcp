"""Tests for `debug.introspect.run` (spec §9.1).

Task 2 of the implementation plan adds only the mode-0700 contract; the
remaining §9.1 matrix is filled in by Task 11.
"""

import os
from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import RunRequest


def _make_run(tmp_path: Path) -> Path:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    return store.run_dir(manifest.run_id)


def test_sensitive_run_subdir_is_mode_0700(tmp_path: Path) -> None:
    # Spec §9.1: ArtifactStore.create_run must produce <run>/sensitive/ at
    # mode 0700 regardless of process umask. The 0600 file mode on wrapper.py
    # (spec §6.1) is only load-bearing if the parent directory is 0700;
    # otherwise other local users can read the file.
    old_umask = os.umask(0o022)
    try:
        run_dir = _make_run(tmp_path)
    finally:
        os.umask(old_umask)
    sensitive = run_dir / "sensitive"
    assert sensitive.is_dir()
    mode = sensitive.stat().st_mode & 0o777
    assert mode == 0o700, f"expected 0700, got {oct(mode)}"
