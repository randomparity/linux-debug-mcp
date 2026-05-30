# `debug.postmortem.check_prereqs` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a live-target `debug.postmortem.check_prereqs` MCP tool that probes a booted target over SSH and reports kdump readiness (crashkernel reserved, kdump service active, dump path writable) as three independent `PrerequisiteCheck`s, with POWER fadump detection and a HALTED fast-reject.

**Architecture:** A pure host-side check builder (`prereqs/kdump_probe.py`) turns one JSON facts object — emitted by a stdlib-only on-target probe script — into three independent checks plus a mechanism string. The handler in `server.py` reuses the #84 introspect SSH-probe machinery (`_resolve_probe_context`, `_target_python_remote_argv`, `build_ssh_argv`, the capped/bounded `SshRunner` round-trip, `_prepare_probe_dirs`, `_read_capped`, `Redactor`) and adds a proof-only HALTED gate. See `docs/superpowers/specs/2026-05-30-debug-postmortem-check-prereqs-design.md` and `docs/adr/0028-postmortem-check-prereqs-kdump-readiness.md`.

**Tech Stack:** Python 3.11+, Pydantic v2, FastMCP, pytest. Lint/format `ruff`, types `ty` (hard-gating).

---

## File structure

- `src/linux_debug_mcp/prereqs/kdump_probe.py` — **new.** `KDUMP_PROBE_SCRIPT_TEMPLATE` (string.Template) + `render_kdump_probe_script(systemctl_timeout)` + pure `build_kdump_checks(probe) -> (checks, mechanism)`. The unit-test surface.
- `src/linux_debug_mcp/domain.py` — **modify.** Add `DebugPostmortemCheckPrereqsRequest`.
- `src/linux_debug_mcp/server.py` — **modify.** Generalize `_resolve_probe_context` param to a `Protocol`; parametrize `_prepare_probe_dirs`; add `_reject_if_target_halted`, `debug_postmortem_check_prereqs_handler`, and the tool registration.
- `src/linux_debug_mcp/config.py` — **modify.** Add `debug.postmortem.check_prereqs` to `ALLOWED_DEBUG_OPERATIONS`.
- `src/linux_debug_mcp/providers/local_drgn_introspect.py` — **modify.** Add the op to `local_drgn_introspect_capability().operations`.
- `tests/test_prereqs_kdump_probe.py` — **new.** Pure builder + script-smoke tests.
- `tests/test_postmortem_check_prereqs.py` — **new.** Handler tests with injected fakes.
- `tests/test_kdump_prereqs_capability.py` — **new.** Capability + config enumeration.
- `tests/test_kdump_prereqs_integration.py` — **new.** Env-gated real-SSH test.

---

## Task 1: Generalize `_resolve_probe_context` to a `Protocol`

This is a prerequisite: the new handler reuses `_resolve_probe_context`, which is typed for the introspect request model, and `ty` is hard-gating.

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (near `class _ProbeContext` at line 2123 and `def _resolve_probe_context` at line 2131)

- [ ] **Step 1: Add the Protocol above `_resolve_probe_context`**

Insert immediately before `class _ProbeContext` (line 2123). `Protocol` is already importable from `typing`; confirm `from typing import ... Protocol` is present near the top of `server.py` and add `Protocol` to that import if missing.

```python
class _SupportsProbeRequest(Protocol):
    """Structural type for the run-scoped fields `_resolve_probe_context` reads.

    Lets both `DebugIntrospectCheckPrerequisitesRequest` and
    `DebugPostmortemCheckPrereqsRequest` (field-identical, distinct tools) share the
    resolver without `ty` rejecting the second model (it does not duck-type Pydantic
    models by structure unless the parameter is a Protocol). See ADR 0028 decision 8.
    """

    run_id: str
    target_ref: str
    timeout_seconds: int
    debug_profile: str | None
    target_profile: str | None
    rootfs_profile: str | None
```

- [ ] **Step 2: Change the resolver's parameter type**

In `def _resolve_probe_context(` (line 2131), change the annotation:

```python
def _resolve_probe_context(
    request: _SupportsProbeRequest,
    *,
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile],
) -> tuple[_ProbeContext | None, ToolResponse | None]:
```

- [ ] **Step 3: Verify guardrails stay green (no behavior change)**

Run: `uv run ty check src && uv run ruff check && uv run python -m pytest tests/test_prereqs_drgn_probe.py -q`
Expected: ty PASS (the introspect call site still satisfies the Protocol), ruff clean, introspect prereq tests still pass.

If `ty` rejects the Protocol (attribute-variance), fall back to a shared base model: add `class _ProbeRequestBase(Model)` in `domain.py` carrying the six fields, make `DebugIntrospectCheckPrerequisitesRequest` inherit it, and annotate the resolver with `_ProbeRequestBase`. Re-run guardrails.

- [ ] **Step 4: Commit**

```bash
git add src/linux_debug_mcp/server.py
git commit -m "refactor(server): generalize _resolve_probe_context to a Protocol"
```

---

## Task 2: Pure check builder `build_kdump_checks`

**Files:**
- Create: `src/linux_debug_mcp/prereqs/kdump_probe.py`
- Test: `tests/test_prereqs_kdump_probe.py`

- [ ] **Step 1: Write the failing tests for `build_kdump_checks`**

Create `tests/test_prereqs_kdump_probe.py`:

```python
from __future__ import annotations

from linux_debug_mcp.domain import PrerequisiteStatus
from linux_debug_mcp.prereqs.kdump_probe import build_kdump_checks


def _by_id(checks):
    return {c.check_id: c for c in checks}


READY = {
    "arch": "x86_64",
    "cmdline_has_crashkernel": True,
    "kexec_crash_size": 268435456,
    "fadump_enabled": None,
    "fadump_registered": None,
    "service_active": True,
    "service_units": {"kdump": "active", "kdump-tools": "inactive"},
    "dump_target_directive": None,
    "dump_dir": "/var/crash",
    "dump_dir_exists": True,
    "dump_dir_writable": True,
    "dump_dir_write_error": None,
}


def test_ready_target_all_pass() -> None:
    checks, mechanism = build_kdump_checks(READY)
    assert mechanism == "kdump"
    by_id = _by_id(checks)
    assert {c.status for c in checks} == {PrerequisiteStatus.PASSED}
    assert set(by_id) == {
        "kdump.crashkernel_reserved",
        "kdump.service_active",
        "kdump.dump_path_writable",
    }


def test_three_faults_are_independent() -> None:
    probe = dict(
        READY,
        cmdline_has_crashkernel=False,
        kexec_crash_size=0,
        service_active=False,
        dump_dir_exists=False,
        dump_dir_writable=None,
    )
    checks, mechanism = build_kdump_checks(probe)
    assert mechanism == "none"
    assert all(c.status == PrerequisiteStatus.FAILED for c in checks)
    assert all(c.suggested_fix for c in checks)


def test_crashkernel_present_but_zero_bytes_fails_with_distinct_fix() -> None:
    probe = dict(READY, cmdline_has_crashkernel=True, kexec_crash_size=0)
    checks, _ = build_kdump_checks(probe)
    chk = _by_id(checks)["kdump.crashkernel_reserved"]
    assert chk.status == PrerequisiteStatus.FAILED
    assert "0 bytes" in chk.message


def test_fadump_enabled_reports_fadump_not_a_kdump_failure() -> None:
    probe = dict(
        READY,
        arch="ppc64le",
        cmdline_has_crashkernel=False,
        kexec_crash_size=0,
        fadump_enabled=1,
        fadump_registered=1,
    )
    checks, mechanism = build_kdump_checks(probe)
    assert mechanism == "fadump"
    chk = _by_id(checks)["kdump.crashkernel_reserved"]
    assert chk.status == PrerequisiteStatus.PASSED
    assert "fadump" in chk.message.lower()


def test_service_fact_missing_does_not_mask_other_checks() -> None:
    probe = dict(READY, service_active=None, service_units={"error": "TimeoutExpired"})
    checks, _ = build_kdump_checks(probe)
    by_id = _by_id(checks)
    assert by_id["kdump.service_active"].status == PrerequisiteStatus.FAILED
    assert by_id["kdump.crashkernel_reserved"].status == PrerequisiteStatus.PASSED
    assert by_id["kdump.dump_path_writable"].status == PrerequisiteStatus.PASSED


def test_unwritable_dump_dir_fails_with_errno() -> None:
    probe = dict(READY, dump_dir_writable=False, dump_dir_write_error="EROFS")
    checks, _ = build_kdump_checks(probe)
    chk = _by_id(checks)["kdump.dump_path_writable"]
    assert chk.status == PrerequisiteStatus.FAILED
    assert "EROFS" in chk.message


def test_missing_dump_dir_fails_with_create_fix() -> None:
    probe = dict(READY, dump_dir="/var/crash", dump_dir_exists=False, dump_dir_writable=None)
    checks, _ = build_kdump_checks(probe)
    chk = _by_id(checks)["kdump.dump_path_writable"]
    assert chk.status == PrerequisiteStatus.FAILED
    assert "create" in (chk.suggested_fix or "").lower()


def test_separate_dump_device_is_warning_not_false_fail() -> None:
    probe = dict(
        READY,
        dump_target_directive="ext4",
        dump_dir="/crash",
        dump_dir_exists=False,
        dump_dir_writable=None,
    )
    checks, _ = build_kdump_checks(probe)
    chk = _by_id(checks)["kdump.dump_path_writable"]
    assert chk.status == PrerequisiteStatus.WARNING
    assert "ext4" in chk.message
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_prereqs_kdump_probe.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.prereqs.kdump_probe'`.

- [ ] **Step 3: Implement `build_kdump_checks`**

Create `src/linux_debug_mcp/prereqs/kdump_probe.py`:

```python
"""Host-side core for debug.postmortem.check_prereqs (#94 / ADR 0028).

Pure, SSH-free decision logic so the kdump-readiness verdict matrix is
unit-testable. The on-target probe (KDUMP_PROBE_SCRIPT_TEMPLATE) emits one JSON
facts object; this module turns it into three independent PrerequisiteChecks plus
the detected crash-capture mechanism. The target emits facts; the host decides
PASS/FAIL (the trust boundary mirrors prereqs/drgn_probe.py).
"""

from __future__ import annotations

from string import Template
from typing import Any

from linux_debug_mcp.domain import PrerequisiteCheck, PrerequisiteStatus

KDUMP = "kdump"
FADUMP = "fadump"
NONE = "none"

# kdump service unit names probed, in order. Fedora/RHEL/SUSE: kdump; Debian/Ubuntu:
# kdump-tools. Both are queried in ONE `systemctl is-active` call (one bounded
# subprocess) so a stalled systemctl cannot overrun the call budget (ADR 0028 dec 2).
SERVICE_UNITS = ("kdump", "kdump-tools")

# makedumpfile dump-target directive keywords. When /etc/kdump.conf names one of
# these, the dump `path` is relative to that target's mount (not the rootfs), so a
# local write-probe is meaningless — the dump-path check degrades to WARNING
# (ADR 0028 decision 5).
DUMP_TARGET_DIRECTIVES = (
    "raw",
    "ext2",
    "ext3",
    "ext4",
    "xfs",
    "btrfs",
    "minix",
    "nfs",
    "ssh",
    "nvme",
    "virtiofs",
)

DEFAULT_DUMP_DIR = "/var/crash"


def _as_int(value: Any) -> int:
    return value if isinstance(value, int) else 0


def resolve_mechanism(probe: dict[str, Any]) -> str:
    """fadump if firmware-assisted dump is enabled; else kdump if crashkernel
    memory is reserved; else none (ADR 0028 decision 4)."""
    if probe.get("fadump_enabled") == 1:
        return FADUMP
    if probe.get("cmdline_has_crashkernel") and _as_int(probe.get("kexec_crash_size")) > 0:
        return KDUMP
    return NONE


def _crashkernel_check(probe: dict[str, Any], mechanism: str) -> PrerequisiteCheck:
    if mechanism == FADUMP:
        return PrerequisiteCheck(
            check_id="kdump.crashkernel_reserved",
            status=PrerequisiteStatus.PASSED,
            message="firmware-assisted dump (fadump) is the active POWER crash-capture mechanism",
            details={"mechanism": FADUMP, "fadump_registered": probe.get("fadump_registered")},
        )
    size = _as_int(probe.get("kexec_crash_size"))
    has_cmdline = bool(probe.get("cmdline_has_crashkernel"))
    details = {"cmdline_has_crashkernel": has_cmdline, "kexec_crash_size": probe.get("kexec_crash_size")}
    if has_cmdline and size > 0:
        return PrerequisiteCheck(
            check_id="kdump.crashkernel_reserved",
            status=PrerequisiteStatus.PASSED,
            message=f"crashkernel memory is reserved ({size} bytes)",
            details=details,
        )
    if not has_cmdline:
        message = "no crashkernel= reservation on the kernel command line"
        fix = "add a crashkernel= reservation to the kernel command line and reboot"
    else:
        message = "crashkernel= is set but /sys/kernel/kexec_crash_size is 0 (no memory reserved)"
        fix = "crashkernel= reserved 0 bytes; choose a value that fits available RAM (e.g. crashkernel=256M) and reboot"
    return PrerequisiteCheck(
        check_id="kdump.crashkernel_reserved",
        status=PrerequisiteStatus.FAILED,
        message=message,
        details=details,
        suggested_fix=fix,
    )


def _service_check(probe: dict[str, Any]) -> PrerequisiteCheck:
    units = probe.get("service_units") or {}
    if probe.get("service_active") is True:
        return PrerequisiteCheck(
            check_id="kdump.service_active",
            status=PrerequisiteStatus.PASSED,
            message="a kdump service unit is active",
            details={"units": units},
        )
    return PrerequisiteCheck(
        check_id="kdump.service_active",
        status=PrerequisiteStatus.FAILED,
        message=f"no kdump service unit is active (checked: {', '.join(SERVICE_UNITS)})",
        details={"units": units},
        suggested_fix=(
            "enable and start the kdump service (e.g. `systemctl enable --now kdump`); "
            "this tool reports state only and never starts it"
        ),
    )


def _dump_path_check(probe: dict[str, Any]) -> PrerequisiteCheck:
    dump_dir = probe.get("dump_dir") or DEFAULT_DUMP_DIR
    directive = probe.get("dump_target_directive")
    if directive:
        return PrerequisiteCheck(
            check_id="kdump.dump_path_writable",
            status=PrerequisiteStatus.WARNING,
            message=(
                f"dump target is a separate '{directive}' device/share; local writability "
                f"not assessed (x86_64 local {DEFAULT_DUMP_DIR} is the tested path)"
            ),
            details={"dump_dir": dump_dir, "dump_target_directive": directive},
        )
    details = {"dump_dir": dump_dir, "source": "kdump.conf" if probe.get("dump_dir") else "default"}
    if not probe.get("dump_dir_exists"):
        return PrerequisiteCheck(
            check_id="kdump.dump_path_writable",
            status=PrerequisiteStatus.FAILED,
            message=f"dump directory {dump_dir} does not exist",
            details=details,
            suggested_fix=f"create {dump_dir} (it must be writable by the root capture kernel)",
        )
    if probe.get("dump_dir_writable"):
        return PrerequisiteCheck(
            check_id="kdump.dump_path_writable",
            status=PrerequisiteStatus.PASSED,
            message=f"dump directory {dump_dir} is writable",
            details=details,
        )
    err = probe.get("dump_dir_write_error") or "write failed"
    return PrerequisiteCheck(
        check_id="kdump.dump_path_writable",
        status=PrerequisiteStatus.FAILED,
        message=f"dump directory {dump_dir} is not writable by the capture kernel: {err}",
        details={**details, "write_error": err},
        suggested_fix="fix the mount (read-only?), free space (ENOSPC), or ownership/permissions",
    )


def build_kdump_checks(probe: dict[str, Any]) -> tuple[list[PrerequisiteCheck], str]:
    """Turn the raw probe JSON into three independent checks + the mechanism string.

    The three checks are built from one already-collected facts object, so one
    probe's failure never masks another (the independence invariant, AC#2).
    """
    mechanism = resolve_mechanism(probe)
    checks = [
        _crashkernel_check(probe, mechanism),
        _service_check(probe),
        _dump_path_check(probe),
    ]
    return checks, mechanism
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_prereqs_kdump_probe.py -q`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/prereqs/kdump_probe.py tests/test_prereqs_kdump_probe.py
git commit -m "feat(prereqs): pure kdump readiness check builder"
```

---

## Task 3: On-target probe script + renderer

**Files:**
- Modify: `src/linux_debug_mcp/prereqs/kdump_probe.py`
- Test: `tests/test_prereqs_kdump_probe.py`

- [ ] **Step 1: Write the failing script-smoke test**

Append to `tests/test_prereqs_kdump_probe.py`:

```python
import json
import subprocess
import sys

from linux_debug_mcp.prereqs.kdump_probe import render_kdump_probe_script


def test_render_substitutes_systemctl_timeout() -> None:
    script = render_kdump_probe_script(systemctl_timeout=3)
    assert "timeout=3" in script
    assert "$systemctl_timeout" not in script


def test_probe_script_runs_on_host_and_emits_expected_keys() -> None:
    # The script is stdlib-only and must run without crashing on any Linux host,
    # emitting one JSON object with the full fact set (values may be null here).
    script = render_kdump_probe_script(systemctl_timeout=3)
    proc = subprocess.run(
        [sys.executable, "-"], input=script, capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    facts = json.loads(proc.stdout)
    for key in (
        "arch",
        "cmdline_has_crashkernel",
        "kexec_crash_size",
        "fadump_enabled",
        "fadump_registered",
        "service_active",
        "service_units",
        "dump_target_directive",
        "dump_dir",
        "dump_dir_exists",
        "dump_dir_writable",
        "dump_dir_write_error",
    ):
        assert key in facts
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_prereqs_kdump_probe.py -k probe_script -q`
Expected: FAIL — `ImportError: cannot import name 'render_kdump_probe_script'`.

- [ ] **Step 3: Add the script template + renderer**

Append to `src/linux_debug_mcp/prereqs/kdump_probe.py`:

```python
# On-target probe. stdlib-only python3 reading stdin, emitting ONE JSON facts object
# on stdout. The host (build_kdump_checks) decides verdicts. `$systemctl_timeout` is
# substituted by render_kdump_probe_script with a value derived from the call budget
# so the single systemctl call is provably under the outer `timeout Ns` bound
# (ADR 0028 decision 2). It runs as root (sudo prefix for non-root logins), so the
# dump-dir writability fact is a transient mkstemp write probe, NOT os.access(W_OK)
# (root bypasses mode bits — ADR 0028 decision 5).
KDUMP_PROBE_SCRIPT_TEMPLATE = Template(
    r"""import errno, json, os, subprocess, sys, tempfile

UNITS = ["kdump", "kdump-tools"]
TARGETS = ("raw", "ext2", "ext3", "ext4", "xfs", "btrfs", "minix", "nfs", "ssh", "nvme", "virtiofs")


def _read_int(path):
    try:
        with open(path) as fh:
            return int(fh.read().strip())
    except Exception:
        return None


def _cmdline_has_crashkernel():
    try:
        with open("/proc/cmdline") as fh:
            return "crashkernel=" in fh.read()
    except Exception:
        return None


def _service_states():
    states = {}
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", *UNITS],
            capture_output=True,
            text=True,
            timeout=$systemctl_timeout,
        )
        lines = proc.stdout.splitlines()
        for i, unit in enumerate(UNITS):
            states[unit] = lines[i].strip() if i < len(lines) else "unknown"
        return any(s == "active" for s in states.values()), states
    except Exception as exc:
        return None, {"error": type(exc).__name__}


def _kdump_conf():
    directive = None
    dump_dir = None
    try:
        with open("/etc/kdump.conf") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                kw = parts[0]
                if kw in TARGETS and directive is None:
                    directive = kw
                elif kw == "path" and len(parts) > 1:
                    dump_dir = parts[1].strip()
    except Exception:
        pass
    return directive, dump_dir


def _writable(d):
    if not os.path.isdir(d):
        return None, None
    fd = None
    path = None
    try:
        fd, path = tempfile.mkstemp(dir=d, prefix=".ldm-writecheck-")
        return True, None
    except OSError as exc:
        return False, errno.errorcode.get(exc.errno, str(exc.errno))
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        if path is not None:
            try:
                os.unlink(path)
            except Exception:
                pass


directive, conf_dir = _kdump_conf()
dump_dir = conf_dir or "/var/crash"
service_active, service_units = _service_states()
writable, write_error = _writable(dump_dir)
try:
    arch = os.uname().machine
except Exception:
    arch = None

result = {
    "arch": arch,
    "cmdline_has_crashkernel": _cmdline_has_crashkernel(),
    "kexec_crash_size": _read_int("/sys/kernel/kexec_crash_size"),
    "fadump_enabled": _read_int("/sys/kernel/fadump_enabled"),
    "fadump_registered": _read_int("/sys/kernel/fadump_registered"),
    "service_active": service_active,
    "service_units": service_units,
    "dump_target_directive": directive,
    "dump_dir": conf_dir,
    "dump_dir_exists": os.path.isdir(dump_dir),
    "dump_dir_writable": writable,
    "dump_dir_write_error": write_error,
}
sys.stdout.write(json.dumps(result))
"""
)


def render_kdump_probe_script(*, systemctl_timeout: int) -> str:
    """Substitute the in-script systemctl timeout (ADR 0028 decision 2)."""
    return KDUMP_PROBE_SCRIPT_TEMPLATE.substitute(systemctl_timeout=systemctl_timeout)
```

Note: `_kdump_conf` returns `conf_dir` (the raw `path` directive value or `None`); `result["dump_dir"]` carries `conf_dir` so the host `_dump_path_check` can tell "came from kdump.conf" (truthy) from "default" (None). The write probe and `dump_dir_exists` use the resolved `dump_dir` (`conf_dir or "/var/crash"`).

- [ ] **Step 4: Run to verify pass**

Run: `uv run python -m pytest tests/test_prereqs_kdump_probe.py -q`
Expected: PASS (10 tests). The script-smoke test exercises the real script on the dev host.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/prereqs/kdump_probe.py tests/test_prereqs_kdump_probe.py
git commit -m "feat(prereqs): on-target kdump probe script + renderer"
```

---

## Task 4: Request model `DebugPostmortemCheckPrereqsRequest`

**Files:**
- Modify: `src/linux_debug_mcp/domain.py` (after `DebugIntrospectCheckPrerequisitesRequest`, ~line 134)
- Test: `tests/test_postmortem_check_prereqs.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_postmortem_check_prereqs.py`:

```python
from __future__ import annotations

import pytest
from pydantic import ValidationError

from linux_debug_mcp.domain import DebugPostmortemCheckPrereqsRequest


def test_request_defaults_and_fields() -> None:
    req = DebugPostmortemCheckPrereqsRequest(run_id="r1", target_ref="x86_64-default")
    assert req.timeout_seconds == 20
    assert req.debug_profile is None


def test_request_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        DebugPostmortemCheckPrereqsRequest(run_id="r1", target_ref="x", bogus=1)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_postmortem_check_prereqs.py -q`
Expected: FAIL — `ImportError: cannot import name 'DebugPostmortemCheckPrereqsRequest'`.

- [ ] **Step 3: Add the model**

Insert in `src/linux_debug_mcp/domain.py` after `DebugIntrospectCheckPrerequisitesRequest` (line 134):

```python
class DebugPostmortemCheckPrereqsRequest(Model):
    """Request payload for ``debug.postmortem.check_prereqs``. #94 / ADR 0028.

    Run-scoped, live-target kdump-readiness probe. Field-identical to
    ``DebugIntrospectCheckPrerequisitesRequest`` (a distinct tool gets a distinct
    model). ``timeout_seconds`` defaults to 20 and is handler-bounded to [5, 60] so
    an out-of-range value surfaces as ``ToolResponse.failure(CONFIGURATION_ERROR)``.
    """

    run_id: str
    target_ref: str
    timeout_seconds: int = 20
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run python -m pytest tests/test_postmortem_check_prereqs.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/domain.py tests/test_postmortem_check_prereqs.py
git commit -m "feat(domain): add DebugPostmortemCheckPrereqsRequest"
```

---

## Task 5: Parametrize `_prepare_probe_dirs`

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`def _prepare_probe_dirs` at line 2301)

- [ ] **Step 1: Replace the body with a category-parametrized version**

Replace the whole function (lines 2301-2313):

```python
def _prepare_probe_dirs(
    store: ArtifactStore,
    run_id: str,
    probe_id: str,
    *,
    category: tuple[str, ...] = ("debug", "checkprereq"),
) -> tuple[Path, Path]:
    """Create the agent-visible and sensitive probe directories with 0o700.

    ``category`` is the path under the run dir (and under ``sensitive/``) the probe
    writes to; defaults to the introspect ``debug/checkprereq`` layout. Postmortem
    passes ``("debug", "postmortem", "check_prereqs")``. Returns ``(agent_dir,
    sensitive_dir)``.
    """
    run_dir = store.run_dir(run_id)
    agent_dir = run_dir.joinpath(*category, probe_id)
    sensitive_dir = run_dir.joinpath("sensitive", *category, probe_id)
    agent_dir.mkdir(parents=True, mode=0o700)
    sensitive_dir.mkdir(parents=True, mode=0o700)
    sensitive_root = run_dir / "sensitive"
    current = sensitive_dir
    while current != sensitive_root and current != run_dir:
        with contextlib.suppress(FileNotFoundError):
            current.chmod(0o700)
        current = current.parent
    return agent_dir, sensitive_dir
```

- [ ] **Step 2: Verify the introspect path is unchanged**

Run: `uv run ty check src && uv run python -m pytest tests/test_prereqs_drgn_probe.py tests/ -k "check_prereq or introspect" -q`
Expected: PASS (the default `category` reproduces the prior `debug/checkprereq` layout and chmod set).

- [ ] **Step 3: Commit**

```bash
git add src/linux_debug_mcp/server.py
git commit -m "refactor(server): parametrize _prepare_probe_dirs category"
```

---

## Task 6: HALTED fast-reject helper

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (add near `_admit_run_tests_ssh_tier`, after line 589)
- Test: `tests/test_postmortem_check_prereqs.py`

- [ ] **Step 1: Add `_reject_if_target_halted`**

Insert after `_admit_run_tests_ssh_tier` (after line 589):

```python
def _reject_if_target_halted(
    *,
    run_id: str,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
) -> ToolResponse | None:
    """§5.6 rule 2 proof-only fast-reject for the read-only kdump prereq probe.

    Returns a READINESS_FAILURE/target_halted response when the target is HALTED,
    else None (proceed). Inert when admission/registry are absent (handler-test and
    legacy callers run ungated). Unlike `_admit_run_tests_ssh_tier` it does NOT
    promote the ssh tier — a bounded single-shot read-only probe only needs the
    immediate rejection; the SSH command timeout bounds the residual TOCTOU window
    (ADR 0028 decision 3). May raise AdmissionError(snapshot_missing); the caller
    maps it to its carried category/code.
    """
    if admission is None or session_registry is None:
        return None
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = _require_snapshot(admission, target_key)
    proof = probe_execution_state(
        registry=session_registry, admission=admission, target_key=target_key, generation=snapshot.generation
    )
    if proof.state is ExecutionState.HALTED:
        return ToolResponse.failure(
            category=ErrorCategory.READINESS_FAILURE,
            run_id=run_id,
            message="target halted in debugger; resume or detach before probing kdump prerequisites",
            details={"code": "target_halted"},
            suggested_next_actions=["debug.continue", "debug.end_session"],
        )
    return None
```

- [ ] **Step 2: Write the failing HALTED test**

Append to `tests/test_postmortem_check_prereqs.py` (helpers used by later tasks too):

```python
from pathlib import Path

from linux_debug_mcp.domain import ErrorCategory, StepStatus
from linux_debug_mcp.server import _reject_if_target_halted
from linux_debug_mcp.transport.base import ExecutionState


class _FakeSnapshot:
    generation = 1
    platform = None


class _FakeAdmission:
    def current_snapshot(self, target_key):  # noqa: ANN001
        return _FakeSnapshot()

    def current_execution_epoch(self, target_key):  # noqa: ANN001
        return 0


class _FakeRecord:
    def __init__(self, state: ExecutionState) -> None:
        self.execution_state = state


class _FakeRegistry:
    def __init__(self, state: ExecutionState) -> None:
        self._state = state

    def read_record(self, target_key):  # noqa: ANN001
        return _FakeRecord(self._state)


def test_halted_target_is_fast_rejected() -> None:
    resp = _reject_if_target_halted(
        run_id="r1",
        admission=_FakeAdmission(),
        session_registry=_FakeRegistry(ExecutionState.HALTED),
    )
    assert resp is not None
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.READINESS_FAILURE
    assert resp.error.details["code"] == "target_halted"


def test_executing_target_proceeds() -> None:
    assert (
        _reject_if_target_halted(
            run_id="r1",
            admission=_FakeAdmission(),
            session_registry=_FakeRegistry(ExecutionState.EXECUTING),
        )
        is None
    )


def test_inert_gate_when_admission_absent() -> None:
    assert _reject_if_target_halted(run_id="r1", admission=None, session_registry=None) is None
```

Confirm the actual attribute names on `ToolResponse` for the error payload (`resp.error.category` / `resp.error.details`) by reading `domain.py:ToolResponse` / `ErrorInfo`; adjust the assertions to match (the model uses an `ErrorInfo` with `category` and `details`).

- [ ] **Step 3: Run to verify pass**

Run: `uv run python -m pytest tests/test_postmortem_check_prereqs.py -k "halted or executing or inert" -q`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_postmortem_check_prereqs.py
git commit -m "feat(server): proof-only HALTED fast-reject for ssh prereq probes"
```

---

## Task 7: The handler `debug_postmortem_check_prereqs_handler`

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (add after `_probe_success`, ~line 2457; add imports for `build_kdump_checks`, `render_kdump_probe_script`)
- Test: `tests/test_postmortem_check_prereqs.py`

- [ ] **Step 1: Add the import**

Near the existing `from linux_debug_mcp.prereqs.drgn_probe import (...)` (line 94), add:

```python
from linux_debug_mcp.prereqs.kdump_probe import build_kdump_checks, render_kdump_probe_script
```

- [ ] **Step 2: Write the handler**

Insert after `_probe_success` (after line 2457):

```python
def _kdump_probe_dirs(store: ArtifactStore, run_id: str, probe_id: str) -> tuple[Path, Path]:
    return _prepare_probe_dirs(store, run_id, probe_id, category=("debug", "postmortem", "check_prereqs"))


def debug_postmortem_check_prereqs_handler(
    request: DebugPostmortemCheckPrereqsRequest,
    *,
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
) -> ToolResponse:
    """#94 / ADR 0028: live-target kdump readiness probe over SSH."""
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    _ctx, failure = _resolve_probe_context(request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles)
    if failure is not None:
        return failure
    assert _ctx is not None
    ctx = _ctx
    run_id = ctx.run_id

    try:
        halted = _reject_if_target_halted(run_id=run_id, admission=admission, session_registry=session_registry)
    except AdmissionError as exc:
        return ToolResponse.failure(
            category=exc.category, run_id=run_id, message=str(exc), details={"code": exc.code}
        )
    if halted is not None:
        return halted

    runner: SshRunner = ssh_runner or SubprocessSshRunner()
    probe_id = uuid.uuid4().hex
    agent_dir, sensitive_dir = _kdump_probe_dirs(ctx.store, run_id, probe_id)

    use_sudo = ctx.rootfs.ssh_user != "root"
    remote_argv = _target_python_remote_argv(timeout_seconds=request.timeout_seconds, use_sudo=use_sudo)
    script = render_kdump_probe_script(systemctl_timeout=max(2, request.timeout_seconds // 2))
    try:
        ssh_argv = build_ssh_argv(
            rootfs_profile=ctx.rootfs,
            known_hosts_path=ctx.store.run_dir(run_id) / "sensitive" / "known_hosts",
            command=remote_argv,
            command_timeout=request.timeout_seconds + 10,
        )
    except ValueError as exc:
        return _configuration_failure(
            run_id=run_id,
            message=_redact_and_truncate(ctx.redactor, str(exc), cap=256),
            details={"code": "invalid_ssh_options"},
        )

    stdout_path = sensitive_dir / "stdout.raw"
    stderr_path = sensitive_dir / "stderr.raw"
    try:
        ssh_result = runner.run(
            ssh_argv,
            timeout=request.timeout_seconds + 10,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            stdin=script,
            max_stdout_bytes=PROBE_STDOUT_CAP,
        )
    except Exception as exc:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=_redact_and_truncate(ctx.redactor, f"ssh probe raised: {exc}", cap=256),
            details={"code": "ssh_failure"},
        )
    for _path in (stdout_path, stderr_path):
        with contextlib.suppress(FileNotFoundError):
            _path.chmod(0o600)

    return _assemble_kdump_response(
        ctx,
        ssh_result=ssh_result,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        agent_dir=agent_dir,
        probe_id=probe_id,
    )


def _assemble_kdump_response(
    ctx: _ProbeContext,
    *,
    ssh_result: SshCommandResult,
    stdout_path: Path,
    stderr_path: Path,
    agent_dir: Path,
    probe_id: str,
) -> ToolResponse:
    run_id = ctx.run_id
    if ssh_result.oversized_output:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=f"probe stdout exceeded {PROBE_STDOUT_CAP} bytes",
            details={"code": "oversized_output"},
        )
    raw_stdout = _read_capped(stdout_path, PROBE_STDOUT_CAP)
    if raw_stdout is None:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=f"probe stdout exceeded {PROBE_STDOUT_CAP} bytes",
            details={"code": "oversized_output"},
        )
    if ssh_result.cancelled or ssh_result.timed_out or ssh_result.stdin_failed:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="probe ssh round trip failed",
            details={"code": "ssh_failure"},
        )
    if ssh_result.exit_status == 255:
        snippet = _redact_and_truncate(ctx.redactor, ssh_result.stderr_snippet or "", cap=256)
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="probe ssh transport failed before the target ran",
            details={"code": "ssh_connect_failure", "stderr": snippet},
        )
    if ssh_result.exit_status == 127:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="python3 is not available on the target; cannot probe kdump readiness",
            details={"code": "probe_no_python"},
        )
    try:
        parsed = json.loads(raw_stdout) if raw_stdout else None
    except json.JSONDecodeError:
        parsed = None
    if not isinstance(parsed, dict):
        snippet = _redact_and_truncate(ctx.redactor, ssh_result.stderr_snippet or "", cap=256)
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=f"probe did not return parseable JSON (exit {ssh_result.exit_status})",
            details={"code": "probe_unparseable", "stderr": snippet},
        )

    checks, mechanism = build_kdump_checks(parsed)
    kdump_ready = not any(c.status == PrerequisiteStatus.FAILED for c in checks)
    report_path = agent_dir / "probe.json"
    report_path.write_text(json.dumps(ctx.redactor.redact_value(parsed)), encoding="utf-8")
    artifacts = [
        ArtifactRef(path=str(stdout_path), kind="probe-stdout", sensitive=True),
        ArtifactRef(path=str(stderr_path), kind="probe-stderr", sensitive=True),
        ArtifactRef(path=str(report_path), kind="probe-report", sensitive=False),
    ]
    failed = sum(1 for c in checks if c.status == PrerequisiteStatus.FAILED)
    return ToolResponse.success(
        summary=f"kdump prerequisites: {'ready' if kdump_ready else 'not ready'} ({mechanism}, {failed} failed)",
        run_id=run_id,
        data={
            "kdump_ready": kdump_ready,
            "mechanism": mechanism,
            "probe_id": probe_id,
            "checks": ctx.redactor.redact_value([c.model_dump(mode="json") for c in checks]),
        },
        artifacts=artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )
```

- [ ] **Step 3: Write the handler tests (fake runner, errors, redaction)**

Append to `tests/test_postmortem_check_prereqs.py`. First read an existing handler test (e.g. `tests/test_prereqs_drgn_probe.py` or a `*check_prerequisites*` test) to copy the run-fixture helper that creates a manifest with a SUCCEEDED boot step and an ssh rootfs profile; reuse that exact construction here (do not invent a new manifest shape). Sketch:

```python
import json as _json
from dataclasses import dataclass

from linux_debug_mcp.config import RootfsProfile
from linux_debug_mcp.providers.local_ssh_tests import SshCommandResult
from linux_debug_mcp.server import debug_postmortem_check_prereqs_handler


@dataclass
class _FakeRunner:
    payload: str
    exit_status: int = 0

    def which(self, command):  # noqa: ANN001
        return "/usr/bin/ssh"

    def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None, max_stdout_bytes=None):  # noqa: ANN001
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(self.payload, encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        return SshCommandResult(exit_status=self.exit_status, stdout=self.payload)


READY_PAYLOAD = _json.dumps(
    {
        "arch": "x86_64",
        "cmdline_has_crashkernel": True,
        "kexec_crash_size": 268435456,
        "fadump_enabled": None,
        "fadump_registered": None,
        "service_active": True,
        "service_units": {"kdump": "active"},
        "dump_target_directive": None,
        "dump_dir": None,
        "dump_dir_exists": True,
        "dump_dir_writable": True,
        "dump_dir_write_error": None,
    }
)


def _ready_run(tmp_path):  # build a run dir with a SUCCEEDED boot step + ssh rootfs
    ...  # mirror the existing introspect check_prereqs handler test's fixture


def test_handler_success_three_checks(tmp_path):
    artifact_root, request, rootfs_profiles = _ready_run(tmp_path)
    resp = debug_postmortem_check_prereqs_handler(
        request,
        artifact_root=artifact_root,
        rootfs_profiles=rootfs_profiles,
        ssh_runner=_FakeRunner(READY_PAYLOAD),
    )
    assert resp.ok is True
    assert resp.data["kdump_ready"] is True
    assert resp.data["mechanism"] == "kdump"
    assert len(resp.data["checks"]) == 3


def test_handler_run_not_found(tmp_path):
    ...  # request for a nonexistent run_id → CONFIGURATION_ERROR


def test_handler_bad_timeout(tmp_path):
    ...  # timeout_seconds=1 → CONFIGURATION_ERROR / invalid_timeout


def test_handler_python_absent(tmp_path):
    artifact_root, request, rootfs_profiles = _ready_run(tmp_path)
    resp = debug_postmortem_check_prereqs_handler(
        request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles,
        ssh_runner=_FakeRunner("", exit_status=127),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "probe_no_python"


def test_handler_unparseable(tmp_path):
    artifact_root, request, rootfs_profiles = _ready_run(tmp_path)
    resp = debug_postmortem_check_prereqs_handler(
        request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles,
        ssh_runner=_FakeRunner("not json"),
    )
    assert resp.error.details["code"] == "probe_unparseable"


def test_handler_redacts_secret_in_probe(tmp_path):
    artifact_root, request, rootfs_profiles = _ready_run(tmp_path)
    # the rootfs profile in _ready_run carries ssh_key_ref="s3cr3t-key"; embed it in a fact
    payload = _json.loads(READY_PAYLOAD)
    payload["service_units"] = {"kdump": "active s3cr3t-key"}
    resp = debug_postmortem_check_prereqs_handler(
        request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles,
        ssh_runner=_FakeRunner(_json.dumps(payload)),
    )
    assert "s3cr3t-key" not in _json.dumps(resp.data)
```

Fill the `...` fixtures by copying the introspect `check_prerequisites` handler test's run-creation helper verbatim and changing only the request type to `DebugPostmortemCheckPrereqsRequest`. For the redaction test, make `_ready_run` set `ssh_key_ref="s3cr3t-key"` on the rootfs profile so the `Redactor` is seeded with it.

- [ ] **Step 4: Run to verify pass**

Run: `uv run python -m pytest tests/test_postmortem_check_prereqs.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_postmortem_check_prereqs.py
git commit -m "feat(server): debug.postmortem.check_prereqs handler"
```

---

## Task 8: Register op in config + provider capability

**Files:**
- Modify: `src/linux_debug_mcp/config.py` (`ALLOWED_DEBUG_OPERATIONS`, line 135)
- Modify: `src/linux_debug_mcp/providers/local_drgn_introspect.py` (`operations`, line 650)
- Test: `tests/test_kdump_prereqs_capability.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_kdump_prereqs_capability.py`:

```python
from linux_debug_mcp.config import ALLOWED_DEBUG_OPERATIONS
from linux_debug_mcp.providers.local_drgn_introspect import local_drgn_introspect_capability


def test_op_in_allowed_debug_operations() -> None:
    assert "debug.postmortem.check_prereqs" in ALLOWED_DEBUG_OPERATIONS


def test_op_advertised_by_ssh_capability() -> None:
    cap = local_drgn_introspect_capability()
    assert "debug.postmortem.check_prereqs" in cap.operations
    assert "debug.introspect.check_prerequisites" in cap.operations  # unchanged
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_kdump_prereqs_capability.py -q`
Expected: FAIL (assertions).

- [ ] **Step 3: Add the op to both lists**

In `src/linux_debug_mcp/config.py`, after the `debug.postmortem.triage` entry (line 135), add:

```python
    # Live-target kdump readiness probe (#94 / ADR 0028). An ssh-tier diagnostic;
    # gated only by the §5.6 HALTED fast-reject, not by DebugProfile.enabled_operations
    # (like debug.introspect.check_prerequisites). Listed for enumerability.
    "debug.postmortem.check_prereqs",
```

In `src/linux_debug_mcp/providers/local_drgn_introspect.py`, add to the `operations` list (line 650):

```python
        "debug.postmortem.check_prereqs",
```

(Append it after `"debug.introspect.check_prerequisites"`. It uses `live_semantics` — it is not in `vmcore_ops`, so the existing `operation_capabilities` comprehension assigns `live_semantics` automatically.)

- [ ] **Step 4: Run to verify pass + no other capability assertion broke**

Run: `uv run python -m pytest tests/test_kdump_prereqs_capability.py tests/test_prereqs_drgn_probe.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/config.py src/linux_debug_mcp/providers/local_drgn_introspect.py tests/test_kdump_prereqs_capability.py
git commit -m "feat(config): enumerate debug.postmortem.check_prereqs op + capability"
```

---

## Task 9: MCP tool registration

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (after the `debug.postmortem.triage` registration, line 8385)
- Test: `tests/test_kdump_prereqs_capability.py`

- [ ] **Step 1: Write the failing registration test**

Append to `tests/test_kdump_prereqs_capability.py`:

```python
import asyncio

from linux_debug_mcp.server import create_app


def test_tool_registered() -> None:
    app = create_app()
    names = {t.name for t in asyncio.run(app.list_tools())}
    assert "debug.postmortem.check_prereqs" in names
```

Confirm the `create_app().list_tools()` access pattern against an existing server test (e.g. a test that enumerates registered tool names); use that project's exact idiom if it differs.

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_kdump_prereqs_capability.py -k registered -q`
Expected: FAIL (tool absent).

- [ ] **Step 3: Add the registration**

Insert after the `debug.postmortem.triage` tool block (after line 8384, before `@app.tool(name="artifacts.collect")`):

```python
    @app.tool(name="debug.postmortem.check_prereqs")
    def debug_postmortem_check_prereqs(
        run_id: str,
        target_ref: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        timeout_seconds: int = 20,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugPostmortemCheckPrereqsRequest(
            run_id=run_id,
            target_ref=target_ref,
            timeout_seconds=timeout_seconds,
            debug_profile=debug_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
        )
        return debug_postmortem_check_prereqs_handler(
            request,
            artifact_root=Path(artifact_root),
            admission=admission_service,
            session_registry=durable_registry,
        ).model_dump(mode="json")
```

Add `DebugPostmortemCheckPrereqsRequest` to the `from linux_debug_mcp.domain import (...)` block at the top of `server.py`. Confirm the closure variable for the session registry is named `durable_registry` (it is what `target.run_tests` passes — line 8203); if it differs, match the run_tests registration exactly.

- [ ] **Step 4: Run to verify pass**

Run: `uv run python -m pytest tests/test_kdump_prereqs_capability.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_kdump_prereqs_capability.py
git commit -m "feat(server): register debug.postmortem.check_prereqs MCP tool"
```

---

## Task 10: Env-gated live-target integration test

The CI-runnable script-structure cross-check is already covered by Task 3's
`test_probe_script_runs_on_host_and_emits_expected_keys` (it runs the real probe
against the local host). Task 10 is the **human-run live-SSH-to-a-guest** test for
AC#6. It must join the project's existing live-libvirt gated group — gated by
`LINUX_DEBUG_MCP_LIBVIRT_TEST=1` plus the source/rootfs/domain env, exactly like
`tests/test_drgn_introspect_integration.py` (the true live-SSH analog). Do **not**
invent a new env var, and do not model it on `tests/test_drgn_probe_integration.py`
(that is a local-host cross-check, not a live-SSH test).

**Files:**
- Create: `tests/test_kdump_prereqs_integration.py`

- [ ] **Step 1: Write the gated test reusing the established live-libvirt bring-up**

Read `tests/test_drgn_introspect_integration.py` and reuse its `_require_integration_env()`
gate and its run bring-up (`create_run_handler` → `target_boot_handler`) verbatim,
changing only the final call to the kdump handler. Create
`tests/test_kdump_prereqs_integration.py`:

```python
"""Env-gated live-SSH kdump readiness probe against a managed libvirt guest.

Skipped unless LINUX_DEBUG_MCP_LIBVIRT_TEST=1 (plus the source/rootfs/domain env)
is set and virsh/qemu are present — identical gating to
tests/test_drgn_introspect_integration.py. Never un-gated in CI. The CI-runnable
script-structure cross-check lives in tests/test_prereqs_kdump_probe.py
(test_probe_script_runs_on_host_and_emits_expected_keys).
"""

from __future__ import annotations

import os
import shutil

import pytest

from linux_debug_mcp.providers.local_ssh_tests import SubprocessSshRunner


def _require_integration_env() -> None:
    missing = []
    if shutil.which("qemu-system-x86_64") is None:
        missing.append("qemu-system-x86_64")
    if shutil.which("virsh") is None:
        missing.append("virsh")
    if os.environ.get("LINUX_DEBUG_MCP_LIBVIRT_TEST") != "1":
        missing.append("LINUX_DEBUG_MCP_LIBVIRT_TEST=1")
    if missing:
        pytest.skip(
            "kdump prereq integration test skipped; set "
            f"{', '.join(missing)} (+ LINUX_DEBUG_MCP_SOURCE / _ROOTFS / _DOMAIN / "
            "_LIBVIRT_URI / _READINESS_MARKER) to run it"
        )


def test_real_target_reports_consistent_kdump_readiness() -> None:
    _require_integration_env()
    # Bring up the guest exactly as tests/test_drgn_introspect_integration.py does
    # (create_run_handler then target_boot_handler with the _SOURCE/_ROOTFS/_DOMAIN/
    # _LIBVIRT_URI env), then run the real probe over SSH:
    #   resp = debug_postmortem_check_prereqs_handler(
    #       DebugPostmortemCheckPrereqsRequest(run_id=run_id, target_ref=domain),
    #       artifact_root=..., rootfs_profiles=..., ssh_runner=SubprocessSshRunner())
    # Assert: resp.ok is True; resp.data["mechanism"] in {"kdump","fadump","none"};
    # exactly three checks; and on a known kdump-ready guest, all three PASSED.
    ...
```

Fill the bring-up by copying the run-creation + boot block from
`test_drgn_introspect_integration.py` verbatim (same env vars, same handlers), so
this test joins the same gated group and shares its setup contract.

- [ ] **Step 2: Verify it skips cleanly without the live env**

Run: `uv run python -m pytest tests/test_kdump_prereqs_integration.py -q`
Expected: 1 skipped (reason names `LINUX_DEBUG_MCP_LIBVIRT_TEST=1`).

- [ ] **Step 3: Commit**

```bash
git add tests/test_kdump_prereqs_integration.py
git commit -m "test(postmortem): env-gated live-SSH kdump prereq integration test"
```

---

## Task 11: Full guardrails + tool-reference doc

**Files:**
- Modify (if it enumerates tools): `docs/tool-reference.md`

- [ ] **Step 1: Check whether `docs/tool-reference.md` lists per-tool entries and, if so, add `debug.postmortem.check_prereqs`**

Run: `rg -n "debug.postmortem|debug.introspect.check_prerequisites" docs/tool-reference.md`
If the file enumerates the postmortem tools, add a `debug.postmortem.check_prereqs` row/section mirroring the `debug.postmortem.triage` entry and pointing at `docs/debug-postmortem.md`. If it does not enumerate them, skip (the `debug-postmortem.md` section already added in the spec phase is the canonical doc).

- [ ] **Step 2: Run the full guardrail suite**

Run: `uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q && just check-docs`
Expected: all clean; integration tests skipped.

- [ ] **Step 3: Commit any doc change**

```bash
git add docs/tool-reference.md
git commit -m "docs(tool-reference): list debug.postmortem.check_prereqs"
```

(Skip the commit if Step 1 found nothing to change.)

---

## Self-review checklist (run before handing off)

- **Spec coverage:** crashkernel/service/dump-path checks (Task 2), fadump mechanism (Task 2), independence + service-fact-missing (Task 2), HALTED fast-reject (Task 6), redaction (Task 7), python3-absent/unparseable/oversize/ssh-failure contract (Task 7), enumeration + capability (Task 8), registration with admission wiring (Task 9), docs (spec phase + Task 11). AC#6 (env-gated live test) is split: the CI-runnable on-host script-structure cross-check is Task 3's `test_probe_script_runs_on_host_and_emits_expected_keys`, and the human-run live-SSH-to-a-guest test is Task 10 (gated on `LINUX_DEBUG_MCP_LIBVIRT_TEST=1`). All AC rows in the spec §4 map to a task.
- **Placeholder scan:** the only `...` are in test fixtures explicitly instructed to be copied from the existing introspect check_prereqs handler test — replace them with the real fixture during execution; no production code has placeholders.
- **Type consistency:** `build_kdump_checks(probe) -> (list[PrerequisiteCheck], str)`, `render_kdump_probe_script(*, systemctl_timeout: int) -> str`, `_reject_if_target_halted(*, run_id, admission, session_registry) -> ToolResponse | None`, `debug_postmortem_check_prereqs_handler(request, *, artifact_root, rootfs_profiles=, ssh_runner=, admission=, session_registry=)` are used identically wherever referenced. `kdump_ready = not any FAILED` matches §3.2.
