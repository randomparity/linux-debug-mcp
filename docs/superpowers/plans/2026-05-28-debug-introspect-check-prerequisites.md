# `debug.introspect.check_prerequisites` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a run-scoped, read-only MCP tool `debug.introspect.check_prerequisites` that SSHes into a booted target, probes for drgn/python/debuginfo, and returns a `PrerequisiteCheck` list plus a tri-state `introspect_usable` verdict — so an agent learns up front whether `debug.introspect.run` will work.

**Architecture:** A pure on-target `python3` probe script (no drgn-to-kernel attach) is piped over SSH via the existing `build_ssh_argv()` + `SubprocessSshRunner` transport. All decision logic (build-id matching, verdict, remediation hints) lives host-side in a new testable module `prereqs/drgn_probe.py`; the `server.py` handler only orchestrates manifest/profile resolution, SSH, redaction, and artifact persistence. The probe is **not** admission-gated and **not** step-recorded (prerequisite state is mutable).

**Tech Stack:** Python 3.11, Pydantic v2 (`domain.py` models), FastMCP (`@app.tool`), `uv`/`pytest`/`ruff`/`ty`. Spec: `docs/superpowers/specs/2026-05-28-debug-introspect-check-prerequisites-design.md`.

---

## File Structure

**Create:**
- `src/linux_debug_mcp/prereqs/drgn_probe.py` — the testable core: `PROBE_SCRIPT` (on-target script), `build_probe_checks()`, `python_missing_checks()`, `install_hint()`, `normalize_build_id()`, verdict constants.
- `tests/test_prereqs_drgn_probe.py` — unit tests for the pure core (no SSH).
- `tests/test_debug_introspect_check_prereqs.py` — handler tests with a fake `SshRunner`.
- `tests/test_drgn_probe_integration.py` — gated real-drgn cross-check.

**Modify:**
- `src/linux_debug_mcp/domain.py` — add `DebugIntrospectCheckPrerequisitesRequest`.
- `src/linux_debug_mcp/providers/local_drgn_introspect.py` — add `TARGET_PYTHON_ARGV` constant; add op to `local_drgn_introspect_capability()`.
- `src/linux_debug_mcp/server.py` — refactor runner to use `TARGET_PYTHON_ARGV`; add `debug_introspect_check_prerequisites_handler` (+ helpers); register `@app.tool`.

**Design refinements vs spec (grounded in code, note in commit messages):**
- `file_matches_host` / `build_id_verified` are computed **host-side** in `build_probe_checks()` (the target does not know the host `build_id` `H`); the on-target script emits only raw `candidates: [{path, file_build_id}]` + `running_build_id`.
- Required SSH fields are `ssh_host` and `ssh_user` only (`ssh_key_ref` is optional — the default `minimal` rootfs profile in `server.py:174` has no key). The spec §6 row named the trio; `ssh_host`/`ssh_user` are what `build_ssh_argv` (`local_ssh_tests.py:217`) actually requires.

---

## Task 1: Request model `DebugIntrospectCheckPrerequisitesRequest`

**Files:**
- Modify: `src/linux_debug_mcp/domain.py` (after `DebugIntrospectRunRequest`, ~line 115)
- Test: `tests/test_debug_introspect_check_prereqs.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_debug_introspect_check_prereqs.py`:

```python
"""Tests for debug.introspect.check_prerequisites (spec §3-§9)."""

from pathlib import Path

import pytest

from linux_debug_mcp.domain import DebugIntrospectCheckPrerequisitesRequest


def test_request_defaults_and_extra_forbidden() -> None:
    req = DebugIntrospectCheckPrerequisitesRequest(run_id="r1", target_ref="local-qemu")
    assert req.timeout_seconds == 20
    assert req.debug_profile is None
    with pytest.raises(Exception):
        DebugIntrospectCheckPrerequisitesRequest(run_id="r1", target_ref="t", bogus=1)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_debug_introspect_check_prereqs.py::test_request_defaults_and_extra_forbidden -q`
Expected: FAIL — `ImportError: cannot import name 'DebugIntrospectCheckPrerequisitesRequest'`.

- [ ] **Step 3: Add the model**

In `src/linux_debug_mcp/domain.py`, immediately after the `DebugIntrospectRunRequest` class:

```python
class DebugIntrospectCheckPrerequisitesRequest(Model):
    """Request payload for ``debug.introspect.check_prerequisites``. Spec §3.

    Run-scoped, read-only target probe. ``timeout_seconds`` defaults to 20 and
    is bounded to [5, 60] by the handler (not Pydantic) so an out-of-range
    value surfaces as ``ToolResponse.failure(CONFIGURATION_ERROR)`` per §6.
    """

    run_id: str
    target_ref: str
    timeout_seconds: int = 20
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_debug_introspect_check_prereqs.py::test_request_defaults_and_extra_forbidden -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/domain.py tests/test_debug_introspect_check_prereqs.py
git commit -m "feat(domain): add DebugIntrospectCheckPrerequisitesRequest (#52)"
```

---

## Task 2: Shared-interpreter constant `TARGET_PYTHON_ARGV`

Spec §4 "shared-interpreter invariant": the probe and `debug.introspect.run` must invoke the same interpreter. Factor the literal into one constant both consume.

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_drgn_introspect.py` (add constant near top, after imports)
- Modify: `src/linux_debug_mcp/server.py:2305` (runner uses the constant)
- Test: `tests/test_prereqs_drgn_probe.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_prereqs_drgn_probe.py`:

```python
"""Unit tests for the host-side drgn-probe core (spec §4-§5)."""

from linux_debug_mcp.providers.local_drgn_introspect import TARGET_PYTHON_ARGV


def test_target_python_argv_is_shared_constant() -> None:
    # Spec §4: probe and runner must use the same interpreter invocation.
    assert TARGET_PYTHON_ARGV == ["python3", "-"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_prereqs_drgn_probe.py::test_target_python_argv_is_shared_constant -q`
Expected: FAIL — `ImportError: cannot import name 'TARGET_PYTHON_ARGV'`.

- [ ] **Step 3: Add the constant and refactor the runner**

In `src/linux_debug_mcp/providers/local_drgn_introspect.py`, after the existing imports (before `WRAPPER_TEMPLATE`):

```python
# Spec §4 (shared-interpreter invariant): the single interpreter invocation
# consumed by BOTH debug.introspect.run (server.debug_introspect_run_handler)
# and debug.introspect.check_prerequisites (the probe). drgn installed for an
# interpreter other than this one is reported missing by design, because the
# runner would equally fail to import it.
TARGET_PYTHON_ARGV = ["python3", "-"]
```

In `src/linux_debug_mcp/server.py`, find the import line that pulls from `providers.local_drgn_introspect` (search `from linux_debug_mcp.providers.local_drgn_introspect import`) and add `TARGET_PYTHON_ARGV` to it. Then replace line ~2305:

```python
        remote_argv.extend(["python3", "-"])
```

with:

```python
        remote_argv.extend(TARGET_PYTHON_ARGV)
```

- [ ] **Step 4: Run tests to verify pass + no runner regression**

Run: `uv run python -m pytest tests/test_prereqs_drgn_probe.py::test_target_python_argv_is_shared_constant tests/test_debug_introspect_run.py -q`
Expected: PASS (the new test and the full existing introspect suite).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/local_drgn_introspect.py src/linux_debug_mcp/server.py tests/test_prereqs_drgn_probe.py
git commit -m "refactor: share TARGET_PYTHON_ARGV between introspect runner and probe (#52)"
```

---

## Task 3: Pure helpers `normalize_build_id`, `install_hint`, `python_missing_checks`

**Files:**
- Create: `src/linux_debug_mcp/prereqs/drgn_probe.py`
- Test: `tests/test_prereqs_drgn_probe.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_prereqs_drgn_probe.py`:

```python
from linux_debug_mcp.domain import PrerequisiteStatus
from linux_debug_mcp.prereqs.drgn_probe import (
    UNUSABLE,
    install_hint,
    normalize_build_id,
    python_missing_checks,
)


def test_normalize_build_id() -> None:
    assert normalize_build_id("AB:CD ef\n") == "abcdef"
    assert normalize_build_id("0xDEAD") == "dead"
    assert normalize_build_id("") is None
    assert normalize_build_id(None) is None
    assert normalize_build_id(123) is None


def test_install_hint_by_distro() -> None:
    assert "dnf install drgn" in install_hint("fedora")
    assert "python3-drgn" in install_hint("rhel")
    assert "apt install python3-drgn" in install_hint("ubuntu")
    assert "pip install drgn" in install_hint(None)
    assert "pip install drgn" in install_hint("plan9")


def test_python_missing_checks() -> None:
    checks, verdict = python_missing_checks()
    by_id = {c.check_id: c for c in checks}
    assert by_id["target.python3"].status == PrerequisiteStatus.FAILED
    assert by_id["target.drgn"].status == PrerequisiteStatus.SKIPPED
    assert by_id["target.vmlinux_debuginfo"].status == PrerequisiteStatus.SKIPPED
    assert verdict == UNUSABLE
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_prereqs_drgn_probe.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.prereqs.drgn_probe'`.

- [ ] **Step 3: Create the module with the helpers**

Create `src/linux_debug_mcp/prereqs/drgn_probe.py`:

```python
"""Host-side core for debug.introspect.check_prerequisites (spec §4-§5).

Pure, SSH-free decision logic so the verdict matrix is unit-testable. The
on-target probe (PROBE_SCRIPT, added in a later task) emits raw facts; this
module turns them into PrerequisiteCheck objects + a tri-state verdict.
"""

from __future__ import annotations

import re
from typing import Any

from linux_debug_mcp.domain import PrerequisiteCheck, PrerequisiteStatus

# Tri-state verdict values (spec §5).
USABLE = "usable"
UNKNOWN = "unknown"
UNUSABLE = "unusable"

_NON_HEX = re.compile(r"[^0-9a-fA-F]")


def normalize_build_id(value: Any) -> str | None:
    """Lowercase hex, separators/whitespace stripped (spec §5 normalization)."""
    if not isinstance(value, str):
        return None
    cleaned = _NON_HEX.sub("", value).lower()
    return cleaned or None


def install_hint(distro_id: str | None) -> str:
    """drgn install remediation by distro family (spec §5)."""
    distro = (distro_id or "").lower()
    if distro == "fedora":
        return "sudo dnf install drgn"
    if distro in {"rhel", "centos", "rocky", "almalinux"}:
        return "sudo dnf install python3-drgn  (requires EPEL)"
    if distro in {"debian", "ubuntu"}:
        return "sudo apt install python3-drgn  (or the drgn PPA)"
    return "python3 -m pip install drgn"


def python_missing_checks() -> tuple[list[PrerequisiteCheck], str]:
    """Synthesized report when target has no python3 (spec §6: ssh exit 127)."""
    checks = [
        PrerequisiteCheck(
            check_id="target.python3",
            status=PrerequisiteStatus.FAILED,
            message="python3 is not available on the target",
            suggested_fix="Install python3 on the target.",
        ),
        PrerequisiteCheck(
            check_id="target.drgn",
            status=PrerequisiteStatus.SKIPPED,
            message="skipped: python3 unavailable",
        ),
        PrerequisiteCheck(
            check_id="target.vmlinux_debuginfo",
            status=PrerequisiteStatus.SKIPPED,
            message="skipped: python3 unavailable",
        ),
    ]
    return checks, UNUSABLE
```

- [ ] **Step 4: Run tests to verify pass**

Run: `uv run python -m pytest tests/test_prereqs_drgn_probe.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/prereqs/drgn_probe.py tests/test_prereqs_drgn_probe.py
git commit -m "feat(prereqs): drgn-probe build-id/distro/python-missing helpers (#52)"
```

---

## Task 4: Verdict + checks core `build_probe_checks`

The heart of the design — the §5 verdict matrix, set-based build-id matching, BTF fallback.

**Files:**
- Modify: `src/linux_debug_mcp/prereqs/drgn_probe.py`
- Test: `tests/test_prereqs_drgn_probe.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_prereqs_drgn_probe.py`:

```python
from linux_debug_mcp.prereqs.drgn_probe import USABLE, UNKNOWN, build_probe_checks

HOST = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret
OTHER = "ffffffffffffffffffffffffffffffffffffffff"  # pragma: allowlist secret


def _probe(**over: object) -> dict:
    base: dict = {
        "python_version": "3.11.2",
        "python_executable": "/usr/bin/python3",
        "drgn_present": True,
        "drgn_version": "0.0.27",
        "distro_id": "fedora",
        "distro_version": "39",
        "kernel_release": "6.7.0",
        "running_build_id": HOST,
        "vmlinux_debuginfo": {
            "candidates": [{"path": "/usr/lib/debug/boot/vmlinux-6.7.0", "file_build_id": HOST}],
            "btf": True,
            "module_debuginfo": True,
            "module_path": "/usr/lib/debug/lib/modules/6.7.0/kernel",
        },
    }
    base.update(over)
    return base


def _ids(checks):
    return {c.check_id: c for c in checks}


def test_verdict_usable_when_all_agree() -> None:
    checks, verdict = build_probe_checks(_probe(), host_build_id=HOST)
    assert verdict == USABLE
    by = _ids(checks)
    assert by["target.vmlinux_debuginfo"].status == PrerequisiteStatus.PASSED
    assert by["target.vmlinux_debuginfo"].details["build_id_verified"] is True
    assert by["target.kernel_buildid"].status == PrerequisiteStatus.PASSED


def test_drgn_missing_is_unusable_with_hint() -> None:
    checks, verdict = build_probe_checks(
        _probe(drgn_present=False, drgn_version=None), host_build_id=HOST
    )
    by = _ids(checks)
    assert by["target.drgn"].status == PrerequisiteStatus.FAILED
    assert "dnf install drgn" in by["target.drgn"].suggested_fix
    assert by["target.drgn"].details["executable"] == "/usr/bin/python3"
    assert verdict == UNUSABLE


def test_proven_provenance_mismatch_is_unusable() -> None:
    probe = _probe(running_build_id=OTHER)
    probe["vmlinux_debuginfo"]["candidates"] = [
        {"path": "/boot/vmlinux-6.7.0", "file_build_id": OTHER}
    ]
    checks, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert _ids(checks)["target.kernel_buildid"].status == PrerequisiteStatus.WARNING
    assert verdict == UNUSABLE


def test_wrong_debuginfo_is_unusable() -> None:
    probe = _probe()
    probe["vmlinux_debuginfo"]["candidates"] = [
        {"path": "/boot/vmlinux-6.7.0", "file_build_id": OTHER}
    ]
    _, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert verdict == UNUSABLE


def test_set_based_match_avoids_false_unusable() -> None:
    # Stale vmlinux first, correct one later -> usable, chosen path is the match.
    probe = _probe()
    probe["vmlinux_debuginfo"]["candidates"] = [
        {"path": "/usr/lib/debug/boot/vmlinux-6.7.0", "file_build_id": OTHER},
        {"path": "/lib/modules/6.7.0/build/vmlinux", "file_build_id": HOST},
    ]
    checks, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert verdict == USABLE
    assert _ids(checks)["target.vmlinux_debuginfo"].details["path"] == "/lib/modules/6.7.0/build/vmlinux"


def test_running_build_id_null_is_unknown_and_buildid_skipped() -> None:
    probe = _probe(running_build_id=None)
    probe["vmlinux_debuginfo"]["candidates"] = [
        {"path": "/boot/vmlinux-6.7.0", "file_build_id": HOST}
    ]
    checks, verdict = build_probe_checks(probe, host_build_id=HOST)
    by = _ids(checks)
    assert by["target.kernel_buildid"].status == PrerequisiteStatus.SKIPPED
    assert by["target.vmlinux_debuginfo"].status == PrerequisiteStatus.WARNING
    assert by["target.vmlinux_debuginfo"].details["file_matches_host"] is True
    assert verdict == UNKNOWN


def test_host_build_id_absent_is_unknown() -> None:
    checks, verdict = build_probe_checks(_probe(), host_build_id=None)
    assert _ids(checks)["target.kernel_buildid"].status == PrerequisiteStatus.SKIPPED
    assert verdict == UNKNOWN


def test_no_dwarf_but_btf_is_unknown_warning() -> None:
    probe = _probe()
    probe["vmlinux_debuginfo"]["candidates"] = []
    checks, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert _ids(checks)["target.vmlinux_debuginfo"].status == PrerequisiteStatus.WARNING
    assert verdict == UNKNOWN


def test_no_dwarf_no_btf_is_unusable_failed() -> None:
    probe = _probe()
    probe["vmlinux_debuginfo"] = {"candidates": [], "btf": False}
    checks, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert _ids(checks)["target.vmlinux_debuginfo"].status == PrerequisiteStatus.FAILED
    assert verdict == UNUSABLE


def test_module_debuginfo_absent_is_warning_only() -> None:
    probe = _probe()
    probe["vmlinux_debuginfo"]["module_debuginfo"] = False
    checks, verdict = build_probe_checks(probe, host_build_id=HOST)
    assert _ids(checks)["target.module_debuginfo"].status == PrerequisiteStatus.WARNING
    assert verdict == USABLE
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_prereqs_drgn_probe.py -q`
Expected: FAIL — `ImportError: cannot import name 'build_probe_checks'`.

- [ ] **Step 3: Implement `build_probe_checks` + `_verdict`**

Append to `src/linux_debug_mcp/prereqs/drgn_probe.py`:

```python
def _verdict(
    *,
    drgn_present: bool,
    found: bool,
    btf: bool,
    running: str | None,
    host: str | None,
    build_id_verified: bool,
    wrong_debuginfo: bool,
) -> str:
    """Spec §5 tri-state. Only proven contradictions / hard-missing prereqs
    are UNUSABLE; unconfirmable cases are UNKNOWN (never a false UNUSABLE)."""
    if not drgn_present:
        return UNUSABLE
    if not found and not btf:
        return UNUSABLE
    if running is not None and host is not None and running != host:
        return UNUSABLE
    if wrong_debuginfo:
        return UNUSABLE
    if found and build_id_verified and running is not None and host is not None and running == host:
        return USABLE
    return UNKNOWN


def _python_check(probe: dict[str, Any]) -> PrerequisiteCheck:
    version = probe.get("python_version")
    executable = probe.get("python_executable")
    return PrerequisiteCheck(
        check_id="target.python3",
        status=PrerequisiteStatus.PASSED if version else PrerequisiteStatus.FAILED,
        message=f"python3 {version}" if version else "python3 not available on target",
        details={"version": version, "executable": executable},
        suggested_fix=None if version else "Install python3 on the target.",
    )


def _drgn_check(probe: dict[str, Any]) -> PrerequisiteCheck:
    present = bool(probe.get("drgn_present"))
    version = probe.get("drgn_version")
    return PrerequisiteCheck(
        check_id="target.drgn",
        status=PrerequisiteStatus.PASSED if present else PrerequisiteStatus.FAILED,
        message=f"drgn {version}" if present else "drgn is not importable under the target interpreter",
        details={"version": version, "executable": probe.get("python_executable")},
        suggested_fix=None if present else install_hint(probe.get("distro_id")),
    )


def build_probe_checks(
    probe: dict[str, Any], *, host_build_id: Any
) -> tuple[list[PrerequisiteCheck], str]:
    """Spec §4-§5: turn raw probe JSON into checks + tri-state verdict.

    ``build_id_verified`` and ``file_matches_host`` are computed here (the
    target cannot know the host build-id ``H``).
    """
    host = normalize_build_id(host_build_id)
    running = normalize_build_id(probe.get("running_build_id"))
    vmlinux = probe.get("vmlinux_debuginfo") or {}
    candidates = [
        (c.get("path"), normalize_build_id(c.get("file_build_id")))
        for c in (vmlinux.get("candidates") or [])
        if isinstance(c, dict)
    ]

    found = bool(candidates)
    match_running = next((p for p, f in candidates if running is not None and f == running), None)
    match_host = next((p for p, f in candidates if host is not None and f == host), None)
    build_id_verified = match_running is not None
    file_matches_host = match_host is not None
    chosen_path = match_running or match_host or (candidates[0][0] if candidates else None)
    chosen_id = next((f for p, f in candidates if p == chosen_path), None)
    btf = bool(vmlinux.get("btf"))
    parsed_any = any(f is not None for _, f in candidates)
    wrong_debuginfo = running is not None and parsed_any and match_running is None

    checks = [_python_check(probe), _drgn_check(probe)]

    vm_details = {
        "path": chosen_path,
        "file_build_id": chosen_id,
        "build_id_verified": build_id_verified,
        "file_matches_host": file_matches_host,
        "btf": btf,
        "candidates": [{"path": p, "file_build_id": f} for p, f in candidates],
    }
    if not found:
        vm_status = PrerequisiteStatus.WARNING if btf else PrerequisiteStatus.FAILED
        vm_message = (
            "no DWARF vmlinux found; BTF present (drgn may attach with reduced coverage)"
            if btf
            else "no vmlinux DWARF debuginfo found in drgn's default search paths"
        )
        vm_fix = None if btf else "Install kernel debuginfo (e.g. kernel-debuginfo / linux-image-*-dbg)."
    elif build_id_verified:
        vm_status = PrerequisiteStatus.PASSED
        vm_message = f"vmlinux debuginfo matches the running kernel at {chosen_path}"
        vm_fix = None
    else:
        vm_status = PrerequisiteStatus.WARNING
        vm_message = "vmlinux debuginfo found but its build-id is not confirmed against the running kernel"
        vm_fix = None
    checks.append(
        PrerequisiteCheck(
            check_id="target.vmlinux_debuginfo",
            status=vm_status,
            message=vm_message,
            details=vm_details,
            suggested_fix=vm_fix,
        )
    )

    if running is None or host is None:
        kb_status = PrerequisiteStatus.SKIPPED
        kb_message = (
            "host build-id unknown — provenance not checked"
            if host is None
            else "running build-id unavailable (e.g. /sys/kernel/notes unreadable)"
        )
    elif running == host:
        kb_status = PrerequisiteStatus.PASSED
        kb_message = "running kernel build-id matches the host build"
    else:
        kb_status = PrerequisiteStatus.WARNING
        kb_message = "running kernel build-id does not match the host build"
    checks.append(
        PrerequisiteCheck(
            check_id="target.kernel_buildid",
            status=kb_status,
            message=kb_message,
            details={"running": running, "expected": host},
        )
    )

    module_present = bool(vmlinux.get("module_debuginfo"))
    checks.append(
        PrerequisiteCheck(
            check_id="target.module_debuginfo",
            status=PrerequisiteStatus.PASSED if module_present else PrerequisiteStatus.WARNING,
            message=(
                "module debuginfo present"
                if module_present
                else "module debuginfo not found (core-kernel introspection still works)"
            ),
            details={"path": vmlinux.get("module_path")},
        )
    )

    verdict = _verdict(
        drgn_present=bool(probe.get("drgn_present")),
        found=found,
        btf=btf,
        running=running,
        host=host,
        build_id_verified=build_id_verified,
        wrong_debuginfo=wrong_debuginfo,
    )
    return checks, verdict
```

- [ ] **Step 4: Run tests to verify pass**

Run: `uv run python -m pytest tests/test_prereqs_drgn_probe.py -q`
Expected: PASS (all matrix tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/prereqs/drgn_probe.py tests/test_prereqs_drgn_probe.py
git commit -m "feat(prereqs): drgn-probe verdict matrix and check builder (#52)"
```

---

## Task 5: On-target `PROBE_SCRIPT`

Self-contained stdlib-only python3 that emits one JSON object. No drgn-to-kernel attach.

**Files:**
- Modify: `src/linux_debug_mcp/prereqs/drgn_probe.py`
- Test: `tests/test_prereqs_drgn_probe.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_prereqs_drgn_probe.py`:

```python
import json
import subprocess
import sys

from linux_debug_mcp.prereqs.drgn_probe import PROBE_SCRIPT


def test_probe_script_compiles() -> None:
    compile(PROBE_SCRIPT, "<probe>", "exec")


def test_probe_script_runs_and_emits_valid_json() -> None:
    # Runs on the test host; sub-steps that can't read /sys degrade to null
    # rather than crashing, so this is portable (incl. minimal CI containers).
    proc = subprocess.run(
        [sys.executable, "-"],
        input=PROBE_SCRIPT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    for key in (
        "python_version",
        "python_executable",
        "drgn_present",
        "kernel_release",
        "running_build_id",
        "vmlinux_debuginfo",
    ):
        assert key in doc
    assert isinstance(doc["vmlinux_debuginfo"]["candidates"], list)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_prereqs_drgn_probe.py::test_probe_script_compiles -q`
Expected: FAIL — `ImportError: cannot import name 'PROBE_SCRIPT'`.

- [ ] **Step 3: Add the probe script**

Append to `src/linux_debug_mcp/prereqs/drgn_probe.py`:

```python
# Spec §4. On-target probe: stdlib-only python3, emits one JSON object on
# stdout. Never imports drgn to open the kernel (only to read its version).
# Debuginfo search order is pinned to drgn's default kernel search; review
# this list when the runner's drgn pin changes (see the gated cross-check in
# tests/test_drgn_probe_integration.py).
PROBE_SCRIPT = r'''import json, os, struct, sys


def _safe(fn):
    try:
        return fn()
    except Exception:
        return None


def _os_release():
    data = {}
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "=" in line:
                    k, _, v = line.partition("=")
                    data[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return data


def _parse_notes(blob):
    off, n = 0, len(blob)
    while off + 12 <= n:
        namesz, descsz, ntype = struct.unpack_from("<III", blob, off)
        off += 12
        name = blob[off:off + namesz]
        off += (namesz + 3) & ~3
        desc = blob[off:off + descsz]
        off += (descsz + 3) & ~3
        if ntype == 3 and name.rstrip(b"\x00") == b"GNU":
            return desc.hex()
    return None


def _running_build_id():
    try:
        with open("/sys/kernel/notes", "rb") as fh:
            return _parse_notes(fh.read())
    except Exception:
        return None


def _elf_build_id(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
            if head[:4] != b"\x7fELF":
                return None
            is64 = head[4] == 2
            end = "<" if head[5] == 1 else ">"
            if is64:
                e_phoff = struct.unpack_from(end + "Q", head, 32)[0]
                e_phentsize = struct.unpack_from(end + "H", head, 54)[0]
                e_phnum = struct.unpack_from(end + "H", head, 56)[0]
            else:
                e_phoff = struct.unpack_from(end + "I", head, 28)[0]
                e_phentsize = struct.unpack_from(end + "H", head, 42)[0]
                e_phnum = struct.unpack_from(end + "H", head, 44)[0]
            for i in range(e_phnum):
                fh.seek(e_phoff + i * e_phentsize)
                ph = fh.read(e_phentsize)
                if is64:
                    p_type, _flags, p_off, _va, _pa, p_filesz = struct.unpack_from(end + "IIQQQQ", ph, 0)
                else:
                    p_type, p_off, _va, _pa, p_filesz = struct.unpack_from(end + "IIIII", ph, 0)
                if p_type != 4:
                    continue
                fh.seek(p_off)
                bid = _parse_notes(fh.read(p_filesz))
                if bid:
                    return bid
    except Exception:
        return None
    return None


def _candidates(rel, rbid):
    paths = []
    if rbid:
        paths.append("/usr/lib/debug/.build-id/%s/%s.debug" % (rbid[:2], rbid[2:]))
    paths += [
        "/usr/lib/debug/boot/vmlinux-%s" % rel,
        "/usr/lib/debug/lib/modules/%s/vmlinux" % rel,
        "/lib/modules/%s/build/vmlinux" % rel,
        "/lib/modules/%s/vmlinux" % rel,
        "/boot/vmlinux-%s" % rel,
    ]
    out = []
    for p in paths:
        if os.path.exists(p):
            out.append({"path": p, "file_build_id": _elf_build_id(p)})
    return out


rel = _safe(lambda: os.uname().release) or ""
rbid = _running_build_id()
osr = _os_release()

drgn_present = False
drgn_version = None
try:
    import drgn
    drgn_present = True
    drgn_version = _safe(lambda: getattr(drgn, "__version__", None))
except Exception:
    pass

module_dir = "/usr/lib/debug/lib/modules/%s/kernel" % rel
result = {
    "python_version": "%d.%d.%d" % (sys.version_info[0], sys.version_info[1], sys.version_info[2]),
    "python_executable": sys.executable,
    "drgn_present": drgn_present,
    "drgn_version": drgn_version,
    "distro_id": osr.get("ID"),
    "distro_version": osr.get("VERSION_ID"),
    "kernel_release": rel,
    "running_build_id": rbid,
    "vmlinux_debuginfo": {
        "candidates": _candidates(rel, rbid),
        "btf": os.path.exists("/sys/kernel/btf/vmlinux"),
        "module_debuginfo": _safe(lambda: bool(os.path.isdir(module_dir) and os.listdir(module_dir))) or False,
        "module_path": module_dir,
    },
}
sys.stdout.write(json.dumps(result))
'''
```

- [ ] **Step 4: Run tests to verify pass**

Run: `uv run python -m pytest tests/test_prereqs_drgn_probe.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/prereqs/drgn_probe.py tests/test_prereqs_drgn_probe.py
git commit -m "feat(prereqs): on-target drgn PROBE_SCRIPT (#52)"
```

---

## Task 6: Advertise the operation on the capability

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_drgn_introspect.py:301`
- Test: `tests/test_prereqs_drgn_probe.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_prereqs_drgn_probe.py`:

```python
from linux_debug_mcp.providers.local_drgn_introspect import local_drgn_introspect_capability


def test_capability_advertises_check_prerequisites() -> None:
    cap = local_drgn_introspect_capability()
    assert "debug.introspect.check_prerequisites" in cap.operations
    assert "debug.introspect.run" in cap.operations
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_prereqs_drgn_probe.py::test_capability_advertises_check_prerequisites -q`
Expected: FAIL — assertion error (op not present).

- [ ] **Step 3: Add the operation**

In `src/linux_debug_mcp/providers/local_drgn_introspect.py`, change:

```python
        operations=["debug.introspect.run"],
```

to:

```python
        operations=["debug.introspect.run", "debug.introspect.check_prerequisites"],
```

- [ ] **Step 4: Run test to verify it passes + provider suite green**

Run: `uv run python -m pytest tests/test_prereqs_drgn_probe.py::test_capability_advertises_check_prerequisites -q && uv run python -m pytest -q -k "provider or capabilit"`
Expected: PASS (and no `operations`/`operation_capabilities` length mismatch from `ProviderCapability`).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/local_drgn_introspect.py tests/test_prereqs_drgn_probe.py
git commit -m "feat(providers): advertise debug.introspect.check_prerequisites (#52)"
```

---

## Task 7: Pre-SSH resolution helper `_resolve_probe_context`

All failure paths that must short-circuit before SSH (spec §6).

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (add near `debug_introspect_run_handler`, ~line 1900)
- Test: `tests/test_debug_introspect_check_prereqs.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_debug_introspect_check_prereqs.py`:

```python
from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import RootfsProfile
from linux_debug_mcp.domain import ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.server import debug_introspect_check_prerequisites_handler

VALID_BUILD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


def _rootfs(**over) -> dict[str, RootfsProfile]:
    base = {
        "name": "minimal",
        "source": "/img.qcow2",
        "access_method": "ssh",
        "ssh_host": "127.0.0.1",
        "ssh_user": "root",
    }
    base.update(over)
    return {"minimal": RootfsProfile(**base)}


def _booted_run(tmp_path: Path, *, with_build_id: bool = True, booted: bool = True) -> str:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="build ok",
            artifacts=[],
            details={"build_id": VALID_BUILD_ID} if with_build_id else {},
        ),
    )
    if booted:
        store.record_step_result(
            manifest.run_id,
            StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="boot ok", artifacts=[]),
        )
    return manifest.run_id


def _req(run_id: str, **over):
    from linux_debug_mcp.domain import DebugIntrospectCheckPrerequisitesRequest

    base = {"run_id": run_id, "target_ref": "local-qemu"}
    base.update(over)
    return DebugIntrospectCheckPrerequisitesRequest(**base)


def test_run_not_found_is_configuration_error(tmp_path: Path) -> None:
    resp = debug_introspect_check_prerequisites_handler(
        _req("nope"), artifact_root=tmp_path, rootfs_profiles=_rootfs()
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_not_booted_is_readiness_failure(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path, booted=False)
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs()
    )
    assert resp.error.category == ErrorCategory.READINESS_FAILURE
    assert resp.suggested_next_actions == ["target.boot"]


def test_timeout_out_of_band_is_configuration_error(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id, timeout_seconds=999), artifact_root=tmp_path, rootfs_profiles=_rootfs()
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_non_ssh_access_method_is_configuration_error(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(access_method="serial")
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_missing_ssh_host_is_configuration_error(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(ssh_host=None)
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["field"] == "ssh_host"


def test_rootfs_profile_mismatch_is_configuration_error(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id, rootfs_profile="other"), artifact_root=tmp_path, rootfs_profiles=_rootfs()
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "manifest_profile_mismatch"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_debug_introspect_check_prereqs.py -q -k "not_found or not_booted or timeout_out or access_method or ssh_host or profile_mismatch"`
Expected: FAIL — `ImportError: cannot import name 'debug_introspect_check_prerequisites_handler'`.

- [ ] **Step 3: Add the context dataclass + resolution helper**

In `src/linux_debug_mcp/server.py`, just above `def debug_introspect_run_handler(`:

```python
@dataclass(frozen=True)
class _ProbeContext:
    store: ArtifactStore
    run_id: str
    rootfs: RootfsProfile
    host_build_id: str | None
    redactor: Redactor


def _resolve_probe_context(
    request: DebugIntrospectCheckPrerequisitesRequest,
    *,
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile],
) -> tuple[_ProbeContext | None, ToolResponse | None]:
    """Spec §6: all pre-SSH validation. Returns (context, None) on success or
    (None, failure-response) on any short-circuit."""
    run_id = request.run_id
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        if not (store.run_dir(run_id) / "manifest.json").is_file():
            return None, _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return None, ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    for field_name, requested, recorded in (
        ("target_profile", request.target_profile, manifest.request.target_profile),
        ("rootfs_profile", request.rootfs_profile, manifest.request.rootfs_profile),
        ("debug_profile", request.debug_profile, manifest.request.debug_profile),
    ):
        if requested is not None and recorded is not None and requested != recorded:
            return None, _configuration_failure(
                run_id=run_id,
                message=f"{field_name} must match the immutable run manifest request",
                details={"requested_profile": requested, "manifest_profile": recorded,
                         "code": "manifest_profile_mismatch"},
            )
    if request.target_ref != manifest.request.target_profile:
        return None, _configuration_failure(
            run_id=run_id,
            message="target_ref must match the immutable run manifest target_profile",
            details={"requested_target_ref": request.target_ref,
                     "manifest_target_profile": manifest.request.target_profile,
                     "code": "manifest_profile_mismatch"},
        )
    if not (5 <= request.timeout_seconds <= 60):
        return None, _configuration_failure(
            run_id=run_id,
            message=f"timeout_seconds must be in [5, 60]; got {request.timeout_seconds}",
            details={"code": "invalid_timeout"},
        )

    boot = manifest.step_results.get("boot")
    if boot is None or boot.status != StepStatus.SUCCEEDED:
        return None, ToolResponse.failure(
            category=ErrorCategory.READINESS_FAILURE,
            run_id=run_id,
            message="target has not booted; boot it before probing prerequisites",
            details={"code": "target_not_booted"},
            suggested_next_actions=["target.boot"],
        )

    rootfs_name = request.rootfs_profile or manifest.request.rootfs_profile
    try:
        rootfs = rootfs_profiles[rootfs_name]
    except KeyError:
        return None, _configuration_failure(run_id=run_id, message=f"unknown rootfs profile: {rootfs_name}")
    if rootfs.access_method not in {"ssh", "ssh_and_serial"}:
        return None, _configuration_failure(
            run_id=run_id,
            message=f"rootfs access_method must be ssh; got {rootfs.access_method}",
            details={"code": "unsupported_access_method"},
        )
    for field_name, value in (("ssh_host", rootfs.ssh_host), ("ssh_user", rootfs.ssh_user)):
        if not value:
            return None, _configuration_failure(
                run_id=run_id,
                message=f"rootfs profile is missing required SSH field: {field_name}",
                details={"code": "missing_ssh_field", "field": field_name},
            )

    build = manifest.step_results.get("build")
    host_build_id = build.details.get("build_id") if build is not None else None
    redactor = Redactor(secret_values=[rootfs.ssh_key_ref] if rootfs.ssh_key_ref else [])
    return (
        _ProbeContext(store=store, run_id=run_id, rootfs=rootfs,
                      host_build_id=host_build_id, redactor=redactor),
        None,
    )
```

Then add a minimal handler stub so the tests can import + exercise the pre-SSH paths (the SSH body is filled in Task 8):

```python
def debug_introspect_check_prerequisites_handler(
    request: DebugIntrospectCheckPrerequisitesRequest,
    *,
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    ssh_runner: SshRunner | None = None,
) -> ToolResponse:
    """Spec §3-§7: target-side drgn prerequisite probe."""
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    _ctx, failure = _resolve_probe_context(
        request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles
    )
    if failure is not None:
        return failure
    raise NotImplementedError("SSH body added in Task 8")
```

Add `DebugIntrospectCheckPrerequisitesRequest` to the existing `from linux_debug_mcp.domain import (...)` group in `server.py`. (`dataclass` is already imported at `server.py:14`; `RootfsProfile`, `Redactor`, `ArtifactStore`, `ManifestStateError`, `SshRunner`, `StepStatus`, `ErrorCategory`, `DEFAULT_ROOTFS_PROFILES` are already imported.)

- [ ] **Step 4: Run tests to verify pre-SSH paths pass**

Run: `uv run python -m pytest tests/test_debug_introspect_check_prereqs.py -q -k "not_found or not_booted or timeout_out or access_method or ssh_host or profile_mismatch"`
Expected: PASS (these tests never reach the `NotImplementedError`).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_debug_introspect_check_prereqs.py
git commit -m "feat(server): probe context resolution + pre-SSH validation (#52)"
```

---

## Task 8: Handler SSH body — execute, parse, assemble

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (replace the `NotImplementedError` body; add `_read_capped`, `_assemble_probe_response`, `_probe_success`)
- Test: `tests/test_debug_introspect_check_prereqs.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_debug_introspect_check_prereqs.py`:

```python
import json
from dataclasses import dataclass, field
from typing import Any

from linux_debug_mcp.providers.local_ssh_tests import SshCommandResult

HOST = VALID_BUILD_ID


@dataclass
class FakeSshRunner:
    results: list[SshCommandResult] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}"

    def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None):
        self.calls.append({"argv": argv, "stdin": stdin})
        result = self.results.pop(0) if self.results else SshCommandResult(exit_status=0, stdout="{}")
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        return result


def _probe_json(**over) -> str:
    doc = {
        "python_version": "3.11.2",
        "python_executable": "/usr/bin/python3",
        "drgn_present": True,
        "drgn_version": "0.0.27",
        "distro_id": "fedora",
        "distro_version": "39",
        "kernel_release": "6.7.0",
        "running_build_id": HOST,
        "vmlinux_debuginfo": {
            "candidates": [{"path": "/usr/lib/debug/boot/vmlinux-6.7.0", "file_build_id": HOST}],
            "btf": True,
            "module_debuginfo": True,
            "module_path": "/usr/lib/debug/lib/modules/6.7.0/kernel",
        },
    }
    doc.update(over)
    return json.dumps(doc)


def test_usable_target(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=_probe_json())])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
    )
    assert resp.ok is True
    assert resp.data["introspect_usable"] == "usable"
    assert resp.suggested_next_actions == ["debug.introspect.run"]
    # The probe was sent over stdin (not as an argv member).
    assert runner.calls[0]["stdin"] is not None and "import json" in runner.calls[0]["stdin"]


def test_drgn_missing_reports_unusable(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    body = _probe_json(drgn_present=False, drgn_version=None)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=body)])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
    )
    assert resp.ok is True
    assert resp.data["introspect_usable"] == "unusable"
    assert resp.suggested_next_actions == ["host.check_prerequisites"]


def test_python3_missing_exit_127(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=127, stdout="", stderr="python3: not found")])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
    )
    assert resp.ok is True
    by = {c["check_id"]: c for c in resp.data["checks"]}
    assert by["target.python3"]["status"] == "failed"
    assert by["target.drgn"]["status"] == "skipped"
    assert resp.data["introspect_usable"] == "unusable"


def test_garbage_stdout_is_infrastructure_failure(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout="not json", stderr="boom")])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
    )
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE


def test_oversized_stdout_is_infrastructure_failure(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    huge = "x" * (256 * 1024 + 10)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=huge)])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
    )
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "oversized_output"


def test_ssh_timeout_is_infrastructure_failure(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=-1, stdout="", timed_out=True)])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
    )
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE


def test_redaction_hides_ssh_key_ref(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    secret = "/secret/id_ed25519"  # pragma: allowlist secret
    body = _probe_json(distro_version=secret)  # secret leaks into probe output
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=body)])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(ssh_key_ref=secret),
        ssh_runner=runner,
    )
    assert secret not in json.dumps(resp.model_dump(mode="json"))


def test_concurrent_probes_get_distinct_dirs(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    ids = set()
    for _ in range(2):
        runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout=_probe_json())])
        resp = debug_introspect_check_prerequisites_handler(
            _req(run_id), artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner
        )
        ids.add(resp.data["probe_id"])
    assert len(ids) == 2


def test_ssh_connect_failure_exit_255(tmp_path: Path) -> None:
    run_id = _booted_run(tmp_path)
    secret = "/secret/id_ed25519"  # pragma: allowlist secret
    runner = FakeSshRunner(results=[SshCommandResult(
        exit_status=255, stdout="",
        stderr_snippet=f"ssh: connect using key {secret}: Connection refused",
    )])
    resp = debug_introspect_check_prerequisites_handler(
        _req(run_id),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(ssh_key_ref=secret),
        ssh_runner=runner,
    )
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "ssh_connect_failure"
    assert "Connection refused" in resp.error.details["stderr"]
    assert secret not in json.dumps(resp.model_dump(mode="json"))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_debug_introspect_check_prereqs.py -q -k "usable or drgn_missing or python3_missing or garbage or oversized or ssh_timeout or ssh_connect or redaction or concurrent"`
Expected: FAIL — `NotImplementedError: SSH body added in Task 8`.

- [ ] **Step 3: Implement the SSH body + assembly helpers**

In `src/linux_debug_mcp/server.py`, add the module-level cap constant near the other introspect constants (e.g. below `MAX_INTROSPECT_CALLS_PER_RUN`):

```python
# Spec §6/§7: cap the probe stdout read so a noisy/hostile target cannot
# balloon handler memory before json.loads. Mirrors the runner's output caps.
PROBE_STDOUT_CAP = 256 * 1024
```

Add the new imports to the existing `from linux_debug_mcp.prereqs.drgn_probe import ...` group (create the import if absent):

```python
from linux_debug_mcp.prereqs.drgn_probe import (
    PROBE_SCRIPT,
    USABLE,
    UNKNOWN,
    build_probe_checks,
    python_missing_checks,
)
```

Replace the `raise NotImplementedError(...)` line in `debug_introspect_check_prerequisites_handler` with:

```python
    assert _ctx is not None
    ctx = _ctx
    run_id = ctx.run_id

    runner: SshRunner = ssh_runner or SubprocessSshRunner()
    probe_id = uuid.uuid4().hex
    agent_dir = ctx.store.run_dir(run_id) / "debug" / "checkprereq" / probe_id
    sensitive_dir = ctx.store.run_dir(run_id) / "sensitive" / "debug" / "checkprereq" / probe_id
    agent_dir.mkdir(parents=True, mode=0o700)
    sensitive_dir.mkdir(parents=True, mode=0o700)
    for _dir in (sensitive_dir, sensitive_dir.parent, sensitive_dir.parent.parent):
        with contextlib.suppress(FileNotFoundError):
            _dir.chmod(0o700)

    remote_argv = ["timeout", "--kill-after=2s", f"{request.timeout_seconds}s", *TARGET_PYTHON_ARGV]
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
            stdin=PROBE_SCRIPT,
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

    return _assemble_probe_response(
        ctx,
        ssh_result=ssh_result,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        agent_dir=agent_dir,
        probe_id=probe_id,
    )
```

Add the three helper functions immediately after the handler:

```python
def _read_capped(path: Path, cap: int) -> str | None:
    """Read the file iff its byte size is within *cap*; None if oversized."""
    if not path.exists():
        return ""
    if path.stat().st_size > cap:
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def _assemble_probe_response(
    ctx: _ProbeContext,
    *,
    ssh_result: SshCommandResult,
    stdout_path: Path,
    stderr_path: Path,
    agent_dir: Path,
    probe_id: str,
) -> ToolResponse:
    run_id = ctx.run_id
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
    try:
        parsed = json.loads(raw_stdout) if raw_stdout else None
    except json.JSONDecodeError:
        parsed = None

    if parsed is None and ssh_result.exit_status == 127:
        checks, verdict = python_missing_checks()
        return _probe_success(
            ctx,
            agent_dir=agent_dir,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            probe_id=probe_id,
            checks=checks,
            verdict=verdict,
            parsed=None,
        )
    if parsed is None and ssh_result.exit_status == 255:
        snippet = _redact_and_truncate(ctx.redactor, ssh_result.stderr_snippet or "", cap=256)
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="probe ssh transport failed before the target ran",
            details={"code": "ssh_connect_failure", "stderr": snippet},
        )
    if not isinstance(parsed, dict):
        snippet = _redact_and_truncate(ctx.redactor, ssh_result.stderr_snippet or "", cap=256)
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=f"probe did not return parseable JSON (exit {ssh_result.exit_status})",
            details={"code": "probe_unparseable", "stderr": snippet},
        )

    checks, verdict = build_probe_checks(parsed, host_build_id=ctx.host_build_id)
    return _probe_success(
        ctx,
        agent_dir=agent_dir,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        probe_id=probe_id,
        checks=checks,
        verdict=verdict,
        parsed=parsed,
    )


def _probe_success(
    ctx: _ProbeContext,
    *,
    agent_dir: Path,
    stdout_path: Path,
    stderr_path: Path,
    probe_id: str,
    checks: list[PrerequisiteCheck],
    verdict: str,
    parsed: dict[str, Any] | None,
) -> ToolResponse:
    artifacts = [
        ArtifactRef(path=str(stdout_path), kind="probe-stdout", sensitive=True),
        ArtifactRef(path=str(stderr_path), kind="probe-stderr", sensitive=True),
    ]
    if parsed is not None:
        report_path = agent_dir / "probe.json"
        report_path.write_text(json.dumps(ctx.redactor.redact_value(parsed)), encoding="utf-8")
        artifacts.append(ArtifactRef(path=str(report_path), kind="probe-report", sensitive=False))
    failed = sum(1 for c in checks if c.status == PrerequisiteStatus.FAILED)
    next_actions = ["debug.introspect.run"] if verdict in {USABLE, UNKNOWN} else ["host.check_prerequisites"]
    return ToolResponse.success(
        summary=f"introspect prerequisites: {verdict} ({failed} failed checks)",
        run_id=ctx.run_id,
        data={
            "introspect_usable": verdict,
            "probe_id": probe_id,
            "checks": [c.model_dump(mode="json") for c in checks],
        },
        artifacts=artifacts,
        suggested_next_actions=next_actions,
    )
```

Confirm these symbols are imported in `server.py` (most already are): `uuid`, `json`, `contextlib`, `Path`, `Any`, `ArtifactRef`, `PrerequisiteCheck`, `PrerequisiteStatus`, `build_ssh_argv`, `SubprocessSshRunner`, `SshCommandResult`, `TARGET_PYTHON_ARGV`. Add any missing to the existing import groups.

- [ ] **Step 4: Run the full handler suite**

Run: `uv run python -m pytest tests/test_debug_introspect_check_prereqs.py -q`
Expected: PASS (all pre-SSH + SSH-body tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_debug_introspect_check_prereqs.py
git commit -m "feat(server): debug.introspect.check_prerequisites handler SSH body (#52)"
```

---

## Task 9: Register the MCP tool

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (inside `create_app()`, next to the `debug.introspect.run` registration ~line 5027)
- Test: `tests/test_debug_introspect_check_prereqs.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_debug_introspect_check_prereqs.py`:

```python
from linux_debug_mcp.server import create_app


def test_tool_is_registered() -> None:
    # Project idiom for enumerating registered tools (tests/test_server.py:40).
    names = set(create_app()._tool_manager._tools)
    assert "debug.introspect.check_prerequisites" in names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_debug_introspect_check_prereqs.py::test_tool_is_registered -q`
Expected: FAIL — name not in the registered set.

- [ ] **Step 3: Register the tool**

In `src/linux_debug_mcp/server.py`, inside `create_app()` immediately after the `debug_introspect_run` registration block:

```python
    @app.tool(name="debug.introspect.check_prerequisites")
    def debug_introspect_check_prerequisites(
        run_id: str,
        target_ref: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        timeout_seconds: int = 20,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugIntrospectCheckPrerequisitesRequest(
            run_id=run_id,
            target_ref=target_ref,
            timeout_seconds=timeout_seconds,
            debug_profile=debug_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
        )
        return debug_introspect_check_prerequisites_handler(
            request,
            artifact_root=Path(artifact_root),
        ).model_dump(mode="json")
```

- [ ] **Step 4: Run test + stdio smoke**

Run: `uv run python -m pytest tests/test_debug_introspect_check_prereqs.py::test_tool_is_registered -q`
Expected: PASS.
Run: `timeout 2 uv run linux-debug-mcp || test $? -eq 124`
Expected: exits via timeout (124) — the server boots and registers tools without error.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_debug_introspect_check_prereqs.py
git commit -m "feat(server): register debug.introspect.check_prerequisites tool (#52)"
```

---

## Task 10: Gated real-drgn cross-check (spec §9)

Validates that `PROBE_SCRIPT`'s debuginfo search + build-id parse agree with a real drgn on the test host. Skipped when drgn or a readable kernel is unavailable.

**Files:**
- Create: `tests/test_drgn_probe_integration.py`

- [ ] **Step 1: Write the gated test**

Create `tests/test_drgn_probe_integration.py`:

```python
"""Gated cross-check: PROBE_SCRIPT vs a real drgn (spec §9).

Skipped without importable drgn + a readable running-kernel build-id, exactly
like tests/test_qemu_gdbstub_integration.py is skipped without virsh/gdb.
"""

import json
import subprocess
import sys

import pytest

from linux_debug_mcp.prereqs.drgn_probe import (
    USABLE,
    PROBE_SCRIPT,
    build_probe_checks,
    normalize_build_id,
)

drgn = pytest.importorskip("drgn")


def _run_probe() -> dict:
    proc = subprocess.run(
        [sys.executable, "-"], input=PROBE_SCRIPT, capture_output=True, text=True, timeout=60
    )
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
        normalize_build_id(c.get("file_build_id")) == running
        for c in doc["vmlinux_debuginfo"]["candidates"]
    )
    if not local_match:
        pytest.skip("no local DWARF vmlinux matching the running kernel (drgn used debuginfod/BTF)")
    assert by["target.vmlinux_debuginfo"].details["build_id_verified"] is True
    assert verdict == USABLE
```

- [ ] **Step 2: Run it (skips cleanly if drgn/kernel unavailable)**

Run: `uv run python -m pytest tests/test_drgn_probe_integration.py -q`
Expected: PASS on a host with drgn + readable kernel debuginfo, otherwise SKIPPED — never FAIL on an unequipped host/CI.

- [ ] **Step 3: Commit**

```bash
git add tests/test_drgn_probe_integration.py
git commit -m "test: gated real-drgn cross-check for probe (#52)"
```

---

## Task 11: Final verification

- [ ] **Step 1: Full test suite**

Run: `uv run python -m pytest -q`
Expected: all green (new tests + no regressions in introspect/provider suites).

- [ ] **Step 2: Lint + format + types**

Run: `just lint` (or `uv run ruff check src tests && uv run ruff format --check src tests && uv run ty check src`)
Expected: clean — zero warnings/errors (per project zero-warnings policy).

- [ ] **Step 3: Docs guard**

Run: `just check-docs`
Expected: PASS (no "sprint" in README/docs).

- [ ] **Step 4: Commit any fixes, then open the PR**

```bash
git add -A && git commit -m "chore: lint/type fixes for check_prerequisites (#52)"  # only if needed
git push -u origin feat/introspect-check-prereqs
gh pr create --fill --base main
```

---

## Self-Review

**Spec coverage:**
- §3 tool surface & run-scoped/immutability → Tasks 1, 7, 9.
- §3 not gated by `enabled_operations` → Task 8 handler omits `_ensure_debug_operation_enabled` (by construction; no test needed beyond the passing `usable` path which never gates).
- §4 probe script, shared-interpreter invariant, build-id parse, candidate set → Tasks 2, 5; cross-checked in Task 10.
- §5 tri-state verdict, distro hints, normalization, BTF fallback, host-`build_id`-absent → Tasks 3, 4.
- §6 error handling (run-not-found, not-booted, access_method, missing ssh field, timeout bound, oversized/garbage stdout, python3-missing, ssh failure) → Tasks 7, 8.
- §7 redaction, `sensitive/` placement, per-probe_id isolation → Task 8 (`_probe_success`, `sensitive_dir`, `redactor`; tests `test_redaction_*`, `test_concurrent_*`).
- §8 capability wiring → Task 6.
- §9 testing matrix + gated real-drgn → Tasks 4, 7, 8, 10. The Task 10 gated cross-check always asserts the probe's `running_build_id` matches drgn's. The stronger DWARF agreement assert (`build_id_verified` + `USABLE`) is **conditional on the probe finding a local vmlinux whose build-id matches the running kernel** — the one case where the probe and drgn share a local artifact to agree on; it skips when drgn resolves debuginfo via debuginfod/BTF (sources `PROBE_SCRIPT` does not enumerate), preserving §5's "BTF-only ⇒ UNKNOWN, never a false verdict" semantics. The dedicated SSH connect-failure row (exit 255 → `ssh_connect_failure`) is covered by `test_ssh_connect_failure_exit_255` in Task 8, which also asserts the redactor strips the configured `ssh_key_ref` from the connect-failure path.

**Param-limit compliance:** `_assemble_probe_response` and `_probe_success` take `ctx` positionally and make every remaining parameter keyword-only (leading `*`), so each has exactly one positional param — within CLAUDE.md "Hard limits" §2 (≤5), which `just lint` does not enforce (ruff omits `PLR0913`).

**Placeholder scan:** No TBD/TODO; every code step shows full code. The Task 7 handler intentionally raises `NotImplementedError` only as an explicit TDD intermediate, replaced in Task 8 Step 3.

**Type/name consistency:** `_ProbeContext`, `_resolve_probe_context`, `_assemble_probe_response`, `_probe_success`, `_read_capped`, `build_probe_checks`, `python_missing_checks`, `PROBE_SCRIPT`, `TARGET_PYTHON_ARGV`, verdict constants `USABLE`/`UNKNOWN`/`UNUSABLE` are used identically across tasks. `data["introspect_usable"]` carries the tri-state string in §5, handler, and tests. `build_probe_checks(probe, *, host_build_id=...)` signature matches all call sites.
