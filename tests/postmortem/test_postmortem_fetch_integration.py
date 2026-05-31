"""Env-gated live-SSH/scp vmcore retrieval against a managed libvirt guest.

Skipped unless ``KDIVE_LIBVIRT_TEST=1`` (plus the source/rootfs/domain env)
is set and virsh/qemu are present — identical gating to
``tests/test_kdump_prereqs_integration.py``, whose bootstrap helpers this reuses.
Never un-gated in CI. The CI-runnable pure-function cross-checks live in
``tests/test_postmortem_dumps.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kdive.postmortem.handlers import (
    debug_postmortem_fetch_handler,
    debug_postmortem_list_dumps_handler,
)
from kdive.postmortem.models import DebugPostmortemFetchRequest, DebugPostmortemListDumpsRequest
from kdive.providers.local.local_ssh_tests import SubprocessSshRunner
from tests.introspect.test_drgn_introspect_integration import _bootstrap_booted_run, _require_integration_env


def test_real_target_list_then_fetch(tmp_path: Path) -> None:
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)

    listed = debug_postmortem_list_dumps_handler(
        DebugPostmortemListDumpsRequest(run_id=ctx.run_id, manifest_target_profile="pilot-libvirt"),
        artifact_root=tmp_path / "runs",
        rootfs_profiles=ctx.rootfs_profiles,
        ssh_runner=SubprocessSshRunner(),
        admission=ctx.admission,
        session_registry=ctx.session_registry,
    )
    assert listed.ok is True, listed.model_dump(mode="json")
    if not listed.data["dumps"]:
        pytest.skip("no captured dumps on the live target")

    dump_ref = listed.data["dumps"][0]["path"]
    fetched = debug_postmortem_fetch_handler(
        DebugPostmortemFetchRequest(run_id=ctx.run_id, manifest_target_profile="pilot-libvirt", dump_ref=dump_ref),
        artifact_root=tmp_path / "runs",
        rootfs_profiles=ctx.rootfs_profiles,
        ssh_runner=SubprocessSshRunner(),
        admission=ctx.admission,
        session_registry=ctx.session_registry,
    )
    assert fetched.ok is True, fetched.model_dump(mode="json")
    assert fetched.data["vmcore_ref"].endswith("/vmcore")
    vmcore_file = next(f for f in fetched.data["files"] if f["name"] == "vmcore")
    assert len(vmcore_file["sha256"]) == 64
    assert vmcore_file["size_bytes"] > 0
