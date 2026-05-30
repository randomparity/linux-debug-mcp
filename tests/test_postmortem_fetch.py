from __future__ import annotations

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import RunRequest


def _store_with_run(tmp_path):
    store = ArtifactStore(artifact_root=tmp_path)
    store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    return store


def test_postmortem_fetch_lock_is_reentrant_safe(tmp_path) -> None:
    store = _store_with_run(tmp_path)
    with store.postmortem_fetch_lock("r1"):
        pass  # acquires and releases without error
    with store.postmortem_fetch_lock("r1"):
        pass
