"""Env-gated live-SSH kdump readiness probe against a managed libvirt guest.

Skipped unless ``KDIVE_LIBVIRT_TEST=1`` (plus the source/rootfs/domain env)
is set and virsh/qemu are present — identical gating to
``tests/test_drgn_introspect_integration.py``, whose bootstrap helpers this reuses.
Never un-gated in CI. The CI-runnable script-structure cross-check lives in
``tests/test_prereqs_kdump_probe.py`` (``test_probe_script_runs_on_host_*``).
"""

from __future__ import annotations

from pathlib import Path

from kdive.domain import PrerequisiteStatus
from kdive.postmortem.models import DebugPostmortemCheckPrereqsRequest
from kdive.providers.local.local_ssh_tests import SubprocessSshRunner
from kdive.server import debug_postmortem_check_prereqs_handler
from tests.introspect.test_drgn_introspect_integration import _bootstrap_booted_run, _require_integration_env


def test_real_target_reports_consistent_kdump_readiness(tmp_path: Path) -> None:
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)

    resp = debug_postmortem_check_prereqs_handler(
        DebugPostmortemCheckPrereqsRequest(run_id=ctx.run_id, target_ref="pilot-libvirt"),
        artifact_root=tmp_path / "runs",
        rootfs_profiles=ctx.rootfs_profiles,
        ssh_runner=SubprocessSshRunner(),
        admission=ctx.admission,
        session_registry=ctx.session_registry,
    )

    assert resp.ok is True, resp.model_dump(mode="json")
    assert resp.data["mechanism"] in {"kdump", "fadump", "none"}
    checks = resp.data["checks"]
    assert len(checks) == 3
    ids = {c["check_id"] for c in checks}
    assert ids == {
        "kdump.crashkernel_reserved",
        "kdump.service_active",
        "kdump.dump_path_writable",
    }
    # kdump_ready is true iff no check FAILED.
    assert resp.data["kdump_ready"] == all(c["status"] != PrerequisiteStatus.FAILED.value for c in checks)
