"""Golden integration tests for debug.introspect.helper. Spec §6.

Gated identically to ``tests/test_drgn_introspect_integration.py``:
  - ``drgn`` installed target-side (the rootfs must include it)
  - ``qemu-system-x86_64`` on the host
  - ``virsh`` on the host
  - ``LINUX_DEBUG_MCP_LIBVIRT_TEST=1`` environment variable

Runs require a configured libvirt VM host with the env vars set; they SKIP
cleanly without them.  Every test asserts ``resp.ok is True`` first so any
handler failure surfaces the full error details.

NOTE: Real-VM behavior is unverifiable without a configured libvirt host.
These tests were authored to be structurally correct (import, collect, skip)
but their live assertions have NOT been confirmed against a running VM.
They must be validated on a VM host before being declared fully green.
"""

import contextlib
import time

# Re-use the shared gate, bootstrap helper, and _guest_ssh from the drgn
# introspect integration module.  Cross-test imports work here because pytest
# adds the tests/ directory to sys.path via the rootdir discovery mechanism
# (conftest.py is at repo root/tests/ so the tests/ package root is importable).
from test_drgn_introspect_integration import (
    BootstrapResult,
    _bootstrap_booted_run,
    _guest_ssh,
    _require_integration_env,
)

from linux_debug_mcp.domain import DebugIntrospectHelperRequest
from linux_debug_mcp.server import debug_introspect_helper_handler


def _call_helper(
    ctx: BootstrapResult,
    name: str,
    args: dict,
    timeout_seconds: int = 30,
) -> object:
    """Invoke debug_introspect_helper_handler and return the ToolResponse."""
    request = DebugIntrospectHelperRequest(
        run_id=ctx.run_id,
        target_ref="pilot-libvirt",
        name=name,
        args=args,
        timeout_seconds=timeout_seconds,
    )
    artifact_root = ctx.store.artifact_root
    return debug_introspect_helper_handler(
        request,
        artifact_root=artifact_root,
        target_profiles=ctx.target_profiles,
        rootfs_profiles=ctx.rootfs_profiles,
        admission=ctx.admission,
        session_registry=ctx.session_registry,
    )


def test_sysinfo_invariants(tmp_path) -> None:
    """sysinfo: release is truthy, cpus_online >= 1."""
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)
    resp = _call_helper(ctx, "sysinfo", {})
    assert resp.ok is True, resp.error
    result = resp.data["result"]
    assert result["release"], "sysinfo.release must be a non-empty string"
    assert result["cpus_online"] >= 1, f"cpus_online must be >= 1, got {result['cpus_online']}"


def test_tasks_includes_pid1(tmp_path) -> None:
    """tasks helper: some task with pid==1 has comm in {init, systemd}."""
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)
    resp = _call_helper(ctx, "tasks", {"states": [], "limit": 500})
    assert resp.ok is True, resp.error
    tasks = resp.data["result"]["tasks"]
    pid1_tasks = [t for t in tasks if t["pid"] == 1]
    assert pid1_tasks, "no task with pid==1 in tasks helper output"
    pid1_comm = pid1_tasks[0]["comm"]
    assert pid1_comm in {"init", "systemd"}, f"pid 1 comm expected 'init' or 'systemd', got {pid1_comm!r}"


def test_dmesg_nonempty(tmp_path) -> None:
    """dmesg helper: entries list is non-empty."""
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)
    resp = _call_helper(ctx, "dmesg", {})
    assert resp.ok is True, resp.error
    entries = resp.data["result"]["entries"]
    assert entries, "dmesg helper returned no entries"


def test_modules_nonempty(tmp_path) -> None:
    """modules helper: at least one module loaded."""
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)
    resp = _call_helper(ctx, "modules", {})
    assert resp.ok is True, resp.error
    modules = resp.data["result"]["modules"]
    assert modules, "modules helper returned no modules"


def test_slab_has_kmalloc(tmp_path) -> None:
    """slab helper: at least one cache name starts with 'kmalloc'."""
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)
    resp = _call_helper(ctx, "slab", {})
    assert resp.ok is True, resp.error
    caches = resp.data["result"]["caches"]
    kmalloc_caches = [c for c in caches if c["name"].startswith("kmalloc")]
    assert kmalloc_caches, "no kmalloc-* cache found in slab helper output"


def test_irq_counts_length_matches_cpus(tmp_path) -> None:
    """irq counts_per_cpu length == sysinfo cpus_online for every IRQ."""
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)

    sysinfo_resp = _call_helper(ctx, "sysinfo", {})
    assert sysinfo_resp.ok is True, sysinfo_resp.error
    cpus_online = sysinfo_resp.data["result"]["cpus_online"]

    irq_resp = _call_helper(ctx, "irq", {})
    assert irq_resp.ok is True, irq_resp.error
    irqs = irq_resp.data["result"]["irqs"]

    assert irqs, "irq helper returned no IRQs"
    for entry in irqs:
        counts = entry["counts_per_cpu"]
        assert len(counts) == cpus_online, (
            f"IRQ {entry['irq']}: counts_per_cpu length {len(counts)} != cpus_online {cpus_online}"
        )


def test_tasks_dstate_blocker(tmp_path) -> None:
    """tasks with states=['D']: a deterministic D-state blocker has a non-empty kernel_stack.

    The blocker is started via SSH: ``dd if=/dev/vda of=/dev/null bs=1M`` on a
    background nohup.  The exact block device must exist on the guest; /dev/vda
    is conventional for virtio-blk.  The dd runs in uninterruptible sleep while
    reading the block device.  This is intentionally self-clearing (dd exits
    when the device is exhausted or when the process is killed on guest reboot).

    NOTE: The exact mechanism is the VM author's choice and must be
    deterministic/self-clearing.  Adjust the device path if your rootfs uses a
    different block device (e.g. /dev/sda, /dev/vdb).
    """
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)

    # Start an uninterruptible-sleep process on the guest.
    _guest_ssh(
        ctx.run_id,
        ctx.store,
        ctx.rootfs_profile,
        ["sh", "-c", "nohup dd if=/dev/vda of=/dev/null bs=1M >/dev/null 2>&1 &"],
    )
    # Give the process time to enter D state.
    time.sleep(0.5)

    resp = _call_helper(ctx, "tasks", {"states": ["D"], "limit": 100})
    assert resp.ok is True, resp.error
    d_tasks = resp.data["result"]["tasks"]
    assert d_tasks, "no D-state tasks found; is the blocker running and entering D state?"
    has_stack = [t for t in d_tasks if t.get("kernel_stack")]
    assert has_stack, "no D-state task has a non-empty kernel_stack"


def test_sysinfo_no_stop_the_world(tmp_path) -> None:
    """sysinfo does not pause the guest for a detectable duration.

    A heartbeat loop writes timestamps at 0.05s intervals.  The sysinfo helper
    runs during the heartbeat.  After, we read the heartbeat file and assert the
    maximum inter-sample gap is < 0.5s (~10x the heartbeat interval).  A
    real stop-the-world pause of several hundred milliseconds would exceed this
    threshold; normal scheduling jitter on a lightly-loaded VM does not.
    """
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)

    # Start heartbeat loop on the guest.
    _guest_ssh(
        ctx.run_id,
        ctx.store,
        ctx.rootfs_profile,
        ["sh", "-c", "nohup sh -c 'while :; do date +%s.%N >>/tmp/hb; sleep 0.05; done' >/dev/null 2>&1 &"],
    )

    # Let the heartbeat accumulate samples before we run sysinfo.
    time.sleep(0.5)

    sysinfo_resp = _call_helper(ctx, "sysinfo", {})
    assert sysinfo_resp.ok is True, sysinfo_resp.error

    # Let the heartbeat accumulate more samples after sysinfo.
    time.sleep(0.5)

    hb_text = _guest_ssh(ctx.run_id, ctx.store, ctx.rootfs_profile, ["cat", "/tmp/hb"])
    samples = []
    for line in hb_text.splitlines():
        line = line.strip()
        if line:
            with contextlib.suppress(ValueError):
                samples.append(float(line))

    assert len(samples) >= 4, (
        f"heartbeat produced only {len(samples)} samples; expected several from the ~1 second window"
    )

    samples.sort()
    gaps = [samples[i + 1] - samples[i] for i in range(len(samples) - 1)]
    max_gap = max(gaps)
    # Threshold is ~10× the 0.05s heartbeat interval.  A multi-hundred-ms
    # stop-the-world pause would clearly exceed 0.5s; scheduling jitter alone
    # on a lightly-loaded VM does not.
    assert max_gap < 0.5, (
        f"max inter-heartbeat gap {max_gap:.3f}s >= 0.5s threshold; sysinfo may have caused a detectable VM pause"
    )
