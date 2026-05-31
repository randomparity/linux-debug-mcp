from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from kdive.artifacts.store import ArtifactStore
from kdive.domain import RunRequest
from kdive.postmortem.models import DebugPostmortemCrashRequest
from kdive.server import debug_postmortem_crash_handler

pytestmark = pytest.mark.skipif(
    shutil.which("crash") is None or not os.environ.get("KDIVE_VMCORE") or not os.environ.get("KDIVE_VMLINUX"),
    reason="requires crash + KDIVE_VMCORE + KDIVE_VMLINUX",
)


def test_real_crash_batch(tmp_path: Path) -> None:
    store = ArtifactStore(artifact_root=tmp_path)
    store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/s",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    rd = store.run_dir("r1")
    (rd / "inputs").mkdir(exist_ok=True)
    (rd / "build").mkdir(exist_ok=True)
    shutil.copy(os.environ["KDIVE_VMCORE"], rd / "inputs" / "vmcore")
    shutil.copy(os.environ["KDIVE_VMLINUX"], rd / "build" / "vmlinux")
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            commands=["sys", "log", "bt"],
            timeout_seconds=120,
        ),
        artifact_root=tmp_path,
    )
    assert resp.ok is True, resp.error
    assert resp.data["vmcore_build_id"]
    assert resp.data["results"]["sys"]["system"].get("RELEASE")
    # Framing held: each command produced its own output file.
    for cmd in ("sys", "log", "bt"):
        assert cmd in resp.data["results"]
