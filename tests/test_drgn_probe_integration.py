"""Gated cross-check: PROBE_SCRIPT vs a real drgn (spec §9).

Skipped without importable drgn + a readable running-kernel build-id, exactly
like tests/test_qemu_gdbstub_integration.py is skipped without virsh/gdb.
"""

import json
import subprocess
import sys

import pytest

from linux_debug_mcp.prereqs.drgn_probe import (
    PROBE_SCRIPT,
    USABLE,
    build_probe_checks,
    normalize_build_id,
)

drgn = pytest.importorskip("drgn")


def _run_probe() -> dict:
    proc = subprocess.run([sys.executable, "-"], input=PROBE_SCRIPT, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_probe_running_build_id_matches_drgn() -> None:
    doc = _run_probe()
    if doc["running_build_id"] is None:
        pytest.skip("/sys/kernel/notes not readable in this environment")
    try:
        prog = drgn.Program()
        prog.set_kernel()
        prog.load_default_debug_info()
        drgn_bid = prog.main_module().build_id.hex()
    except Exception as exc:  # noqa: BLE001 - environment-dependent skip
        pytest.skip(f"drgn could not attach to the live kernel: {exc}")
    assert normalize_build_id(doc["running_build_id"]) == normalize_build_id(drgn_bid)
    checks, verdict = build_probe_checks(doc, host_build_id=drgn_bid)
    by = {c.check_id: c for c in checks}
    # drgn may attach via debuginfod or BTF — sources PROBE_SCRIPT does not
    # enumerate. Only cross-check DWARF agreement when the probe found a local
    # vmlinux whose build-id matches the running kernel; otherwise there is no
    # shared local artifact for the probe and drgn to agree on.
    running = normalize_build_id(doc["running_build_id"])
    local_match = any(
        normalize_build_id(c.get("file_build_id")) == running for c in doc["vmlinux_debuginfo"]["candidates"]
    )
    if not local_match:
        pytest.skip("no local DWARF vmlinux matching the running kernel (drgn used debuginfod/BTF)")
    assert by["target.vmlinux_debuginfo"].details["build_id_verified"] is True
    assert verdict == USABLE
