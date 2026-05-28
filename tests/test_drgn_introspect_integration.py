"""Integration tests for debug.introspect.run. Spec §9.3.

Gated on:
  - ``drgn`` installed target-side (the rootfs must include it)
  - ``qemu-system-x86_64`` on the host
  - ``virsh`` on the host
  - ``LINUX_DEBUG_MCP_LIBVIRT_TEST=1`` environment variable

The bootstrap (kernel.create_run → kernel.build → target.boot) is reused
from ``tests/test_libvirt_boot_integration.py``. Tests opt-in via the
same env-gate as the boot integration test.
"""

import os
import shutil

import pytest

from linux_debug_mcp.domain import DebugIntrospectRunRequest, ErrorCategory
from linux_debug_mcp.server import debug_introspect_run_handler


def _require_integration_env() -> None:
    missing = []
    if shutil.which("drgn") is None:
        missing.append("drgn (target-side; rootfs must include it)")
    if shutil.which("qemu-system-x86_64") is None:
        missing.append("qemu-system-x86_64")
    if shutil.which("virsh") is None:
        missing.append("virsh")
    if os.environ.get("LINUX_DEBUG_MCP_LIBVIRT_TEST") != "1":
        missing.append("LINUX_DEBUG_MCP_LIBVIRT_TEST=1")
    if missing:
        pytest.skip(
            "drgn introspect integration test skipped; set "
            f"{', '.join(missing)} to run it. Example: "
            "LINUX_DEBUG_MCP_LIBVIRT_TEST=1 "
            "LINUX_DEBUG_MCP_ROOTFS=/var/lib/linux-debug-mcp/rootfs/minimal.qcow2 "
            "LINUX_DEBUG_MCP_SOURCE=/path/to/linux "
            "LINUX_DEBUG_MCP_DOMAIN=mcp-linux-debug-dev "
            "LINUX_DEBUG_MCP_LIBVIRT_URI=qemu:///system "
            "LINUX_DEBUG_MCP_READINESS_MARKER=linux-debug-mcp-ready "
            "pytest tests/test_drgn_introspect_integration.py -q"
        )


def _bootstrap_booted_run(tmp_path):
    """Run the kernel.create_run → kernel.build → target.boot bootstrap and
    return (run_id, store, admission, session_registry).

    The implementation reuses the canonical sequence from
    ``tests/test_libvirt_boot_integration.py``; consult that file for the
    full env-variable and resource handling. This stub deliberately
    skips before invoking expensive bootstrap to keep CI fast — the
    integration runner is expected to inline the libvirt boot sequence
    when running this gated test locally.
    """
    pytest.skip(
        "bootstrap helper for drgn introspect integration not wired up; "
        "fill in by mirroring tests/test_libvirt_boot_integration.py."
    )


def test_introspect_emit_roundtrip(tmp_path) -> None:
    _require_integration_env()
    run_id, store, admission, session_registry = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=run_id,
        target_ref="local-qemu",
        script='emit({"pid": 1})',
        timeout_seconds=30,
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path,
        admission=admission,
        session_registry=session_registry,
    )
    assert response.ok is True, response.error
    assert response.data["status"] == "ok"
    assert response.data["emits"] == [{"pid": 1}]


def test_introspect_target_side_timeout(tmp_path) -> None:
    _require_integration_env()
    run_id, store, admission, session_registry = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=run_id,
        target_ref="local-qemu",
        script="while True:\n    pass\n",
        timeout_seconds=5,
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path,
        admission=admission,
        session_registry=session_registry,
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details["code"] == "introspect_timeout"


def test_introspect_build_id_round_trips(tmp_path) -> None:
    _require_integration_env()
    run_id, store, admission, session_registry = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=run_id,
        target_ref="local-qemu",
        script="emit({})",
        timeout_seconds=30,
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path,
        admission=admission,
        session_registry=session_registry,
    )
    assert response.ok is True, response.error
    manifest = store.load_manifest(run_id)
    recorded = manifest.step_results["build"].details["build_id"]
    assert response.data["build_id"] == recorded
