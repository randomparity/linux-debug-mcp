"""Integration tests for debug.introspect.from_vmcore. Spec §12 (AC#1).

Env-gated, skipped in CI like the libvirt/gdb suites. Requires:
  - ``drgn`` importable on the host
  - ``KDIVE_VMCORE``  — path to a captured vmcore file
  - ``KDIVE_VMLINUX`` — path to the matching uncompressed ELF vmlinux+DWARF

The vmcore + vmlinux are staged into a fresh run directory (the handler confines
both refs to the run dir), then a fixed drgn script is run via the real local
``python3`` subprocess + ``read_elf_build_id``. This exercises the full offline
path end-to-end: build-id fail-loud, symbol load, emit() framing, redaction, and
the manifest step — with no live target.

The full live-vs-offline equivalence (``test_from_vmcore_matches_live``) further
requires a booted target (the libvirt gate) and asserts equal ``emits`` for the
same script run via ``debug.introspect.run`` and ``debug.introspect.from_vmcore``;
it is intentionally not implemented here until a captured-core fixture exists.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from kdive.artifacts.store import ArtifactStore
from kdive.domain import RunRequest, StepStatus
from kdive.introspect.handlers import debug_introspect_from_vmcore_handler

pytest.importorskip("drgn")
VMCORE = os.environ.get("KDIVE_VMCORE")
VMLINUX = os.environ.get("KDIVE_VMLINUX")

pytestmark = pytest.mark.skipif(
    not (VMCORE and VMLINUX),
    reason="set KDIVE_VMCORE and KDIVE_VMLINUX (and install host drgn) to run the vmcore integration test",
)


def _staged_run(tmp_path: Path) -> tuple[ArtifactStore, str, str]:
    store = ArtifactStore(artifact_root=tmp_path)
    store.create_run(
        RunRequest(
            run_id="vmcore-it",
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    rd = store.run_dir("vmcore-it")
    (rd / "inputs").mkdir(exist_ok=True)
    (rd / "build").mkdir(exist_ok=True)
    assert VMCORE is not None and VMLINUX is not None
    shutil.copy(VMCORE, rd / "inputs" / "vmcore")
    shutil.copy(VMLINUX, rd / "build" / "vmlinux")
    return store, "inputs/vmcore", "build/vmlinux"


def test_from_vmcore_runs_script_against_real_core(tmp_path: Path) -> None:
    from kdive.introspect.models import DebugIntrospectFromVmcoreRequest

    _store, vmcore_ref, vmlinux_ref = _staged_run(tmp_path)
    request = DebugIntrospectFromVmcoreRequest(
        run_id="vmcore-it",
        vmcore_ref=vmcore_ref,
        vmlinux_ref=vmlinux_ref,
        script="emit({'comm': prog['init_task'].comm.string_().decode()})",
        timeout_seconds=120,
    )
    resp = debug_introspect_from_vmcore_handler(request, artifact_root=tmp_path)
    assert resp.status == StepStatus.SUCCEEDED, resp.model_dump(mode="json")
    assert resp.data["emits"], "expected at least one emit from the real core"
    assert resp.data["build_id"]
