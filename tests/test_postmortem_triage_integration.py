from __future__ import annotations

import importlib.util
import os
import shutil
from pathlib import Path

import pytest

from kdive.artifacts.store import ArtifactStore
from kdive.domain import (
    DebugIntrospectFromVmcoreRequest,
    DebugPostmortemTriageRequest,
    RunRequest,
)
from kdive.server import (
    debug_introspect_from_vmcore_handler,
    debug_postmortem_triage_handler,
)

_VMCORE = os.environ.get("KDIVE_VMCORE")
_VMLINUX = os.environ.get("KDIVE_VMLINUX")
_HAS_DRGN = importlib.util.find_spec("drgn") is not None
pytestmark = pytest.mark.skipif(
    not (_VMCORE and _VMLINUX and shutil.which("crash") and _HAS_DRGN),
    reason="set KDIVE_VMCORE + KDIVE_VMLINUX and install crash AND drgn to run (triage exercises both tiers)",
)


def _stage(tmp_path: Path) -> ArtifactStore:
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
    shutil.copy(_VMCORE, rd / "inputs" / "vmcore")
    shutil.copy(_VMLINUX, rd / "build" / "vmlinux")
    return store


def test_triage_real_core_consistency(tmp_path) -> None:
    _stage(tmp_path)
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
    )
    assert resp.ok is True, resp.error
    report = resp.data["report"]

    # Invariant 1: same-core provenance agreement (crash-verified id == drgn-reported id).
    drgn = debug_introspect_from_vmcore_handler(
        DebugIntrospectFromVmcoreRequest(
            run_id="r1",
            vmcore_ref="inputs/vmcore",
            vmlinux_ref="build/vmlinux",
            script='emit({"build_id": prog.main_module().build_id.hex()})',
        ),
        artifact_root=tmp_path,
    )
    assert drgn.ok is True, drgn.error
    assert drgn.data["build_id"] == report["vmcore_build_id"]

    # Invariant 2: crash side well-formed.
    assert report["faulting_task"]["status"] == "ok"
    assert isinstance(report["faulting_task"]["pid"], int) and report["faulting_task"]["pid"] >= 0
    assert report["backtrace"]["frames"]

    # Invariant 3: drgn side well-formed (fixture-agnostic).
    assert report["modules"]["status"] == "ok"
    assert report["modules"]["decode_errors"] == 0
    assert report["recent_dmesg"]["status"] == "ok"
    assert report["recent_dmesg"]["entries"]

    # Optional: a known-modular fixture asserts a non-empty module list.
    if os.environ.get("KDIVE_VMCORE_MODULAR") == "1":
        assert report["modules"]["modules"]
