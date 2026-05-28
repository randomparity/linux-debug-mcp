# `debug.introspect.run` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the foundation tier of Epic #9's structured-debug surface: a `debug.introspect.run` MCP tool that runs a user-supplied drgn Python script over SSH against a live target VM, returning structured JSON with redaction, caps, cancellation, and provenance fencing.

**Architecture:** Reuses the existing ssh-tier seams. A new `LocalDrgnIntrospectProvider` advertises the `local-drgn-introspect` capability. A per-call Python wrapper rendered from a `string.Template` is piped over SSH stdin to `timeout(1) sudo python3 -`; the wrapper `import drgn`s, loads kernel debug info, fences against `build_id`, `exec`s the user script with `prog`/`emit` injected, and emits one JSON document on stdout. The host parses, redacts, records a `StepResult` named `introspect:<call_id>` into the manifest, and bridges admission-cancel into an SSH cancel event.

**Tech Stack:** Python 3.11, FastMCP (`mcp>=1.9`), Pydantic v2 (`extra="forbid"`, `validate_assignment=True`), `string.Template`, `threading.Event`, `subprocess` for `readelf`, on-target drgn ≥ recent (only the `Program.set_kernel` / `load_default_debug_info` / `main_module().build_id` surface is used). Ruff (`line-length=120`, selects `E,F,I,UP,B,SIM`), `ty check` as the hard-gating type checker. No new runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-05-28-debug-introspect-run-design.md` (907 lines, 4 rounds of `/challenge` adversarial review). When this plan says "spec §X", read that section verbatim — the spec is authoritative on contracts and the plan is authoritative on order/granularity.

**Issue:** #51 (foundation of Epic #9). Out of scope by design: #52 (prereq probe), #53 (full `KernelProvenance`), #54 (curated helpers), #55 (vmcore), #56 (write-mode opt-in).

---

## File structure

| File | Action | Responsibility |
|---|---|---|
| `src/linux_debug_mcp/config.py` | Modify | Rename `SPRINT_4_DEBUG_OPERATIONS` → `ALLOWED_DEBUG_OPERATIONS`, append `"debug.introspect.run"`, add `MAX_INTROSPECT_CALLS_PER_RUN` and `PRELUDE_WARNING_FRACTION_PCT` constants. |
| `src/linux_debug_mcp/domain.py` | Modify | Add `DebugIntrospectRunRequest` wire model. |
| `src/linux_debug_mcp/artifacts/manifest.py` | Modify | Add `RunManifest.append_step_result`. |
| `src/linux_debug_mcp/artifacts/store.py` | Modify | `create_run`: chmod `<run>/sensitive/` to `0700` (R2-F4). `record_step_result`: add `append: bool = False` kwarg routing to `append_step_result`. |
| `src/linux_debug_mcp/providers/local_kernel_build.py` | Modify | Add `ReadelfUnavailable`/`BuildIdMissing` exception classes; `_extract_build_id(vmlinux: Path) -> str`; wire into the success path to populate `details["build_id"]`. |
| `src/linux_debug_mcp/providers/local_drgn_introspect.py` | **Create** | `LocalDrgnIntrospectProvider` class, the `string.Template` wrapper string, `local_drgn_introspect_capability()` factory, helper `render_wrapper(...)` that calls `Template.substitute(...)` with the §3.1 pre-substitution regex checks. |
| `src/linux_debug_mcp/providers/plugins.py` | Modify | Register `local_drgn_introspect_capability` in `local_provider_plugin_specs()`. |
| `src/linux_debug_mcp/providers/local_ssh_tests.py` | Modify | Extend `SshRunner` protocol and `SubprocessSshRunner` with a `stdin: str \| None = None` parameter (Task 8.5). |
| `tests/_layer4_fakes.py`, `tests/test_local_ssh_tests_provider.py`, `tests/test_break_inject.py` | Modify | Add the new `stdin` kwarg to each `SshRunner` fake; also add the pre-existing-missing `cancel` kwarg to `tests/test_break_inject.py:20` (Task 8.5). |
| `src/linux_debug_mcp/server.py` | Modify | Rename internal references to the constant. Map `kernel.build` `ReadelfUnavailable` / `BuildIdMissing` to `INFRASTRUCTURE_FAILURE`/`readelf_unavailable` and `BUILD_FAILURE`/`build_id_missing` respectively (R2-F6). Add `debug_introspect_run_handler` + `_count_introspect_calls`. Add the `@app.tool(name="debug.introspect.run")` registration. Extend `DEFAULT_DEBUG_PROFILES["qemu-gdbstub-default"]` only if needed — the `DebugProfile` default factory already pulls from the (renamed) allowlist, so adding `"debug.introspect.run"` to the allowlist makes it default-enabled automatically; verify before touching defaults. |
| `tests/test_local_kernel_build.py` | Modify | Add `test_readelf_unavailable_fails_build` and `test_build_id_missing_fails_build` (R2-F6). |
| `tests/test_debug_introspect_run.py` | **Create** | Handler unit tests — full matrix from spec §9.1. |
| `tests/test_introspect_wrapper.py` | **Create** | Wrapper-only unit tests — exec the rendered wrapper in-process against a stub `drgn` module, spec §9.2. |
| `tests/test_drgn_introspect_integration.py` | **Create** | End-to-end test against the smoke VM; gated on `which drgn` + `which qemu-system-x86_64`, spec §9.3. |

**Files NOT created:** No new `ErrorCategory` enum values (spec §8.5). No new ADR — the design fits ADR 0006 and 0007 (spec §12). No new top-level `safety/` modules — reuse `Redactor`. No new lock context — manifest serialization handles ordering (spec §5.3).

**Why this split:**
- The wrapper template lives with its provider so render-time substitution and the exit-code contract stay co-located. Wrapper tests exec the rendered string in-process so they can directly assert on `exec` outcomes without an SSH round trip.
- The handler stays in `server.py` next to its peers (`target_run_tests_handler`, `kernel_build_handler`) so the manifest-lock retry pattern (`_record_terminal_build_result`) and `_redacted_artifacts` are accessible without import churn.
- `domain.py` owns wire types; the request model goes there.
- `manifest.py` / `store.py` get one well-defined extension each (`append_step_result`, `record_step_result(append=…)`).

---

## How to use this plan

1. Each task lists every file to create/modify with line-anchored references where they exist today.
2. Steps inside a task are 2–5 minute units. Run-the-test → confirm-fail → write-code → confirm-pass → commit.
3. **All hard gates must pass between tasks:** `uv run ruff check src tests && uv run ruff format --check src tests && uv run ty check src && uv run python -m pytest -q`. Don't proceed past a failing check.
4. The spec's challenge-round fixes (R2-F1 … R4-F6) are cited inline where they shape implementation. When you see one, re-read that paragraph of the spec before coding.
5. Pre-commit (`pre-commit run --files <changed>`) runs `ruff`, `detect-secrets`, plus repo hygiene hooks. The branch's `ty check` job is hard-gating in CI.

---

## Task 1: Allowlist rename + new caps in `config.py`

**Goal:** Land the constant rename and the two new numeric caps before any code references them. This unblocks Tasks 5–12.

**Files:**
- Modify: `src/linux_debug_mcp/config.py:95-110` (the `SPRINT_4_DEBUG_OPERATIONS` list, append after it)
- Modify: `src/linux_debug_mcp/config.py:375-395` (the `DebugProfile.validate_enabled_operations` validator — uses the renamed name)
- Modify: `src/linux_debug_mcp/server.py:456-470` (`_ensure_debug_operation_enabled` references the constant)
- Modify any other file that imports `SPRINT_4_DEBUG_OPERATIONS` (verify with grep below)
- Test: `tests/test_config.py` (extend existing tests; do not create a new file)

- [ ] **Step 1.1: Inventory the rename surface**

Run:
```bash
rg -n 'SPRINT_4_DEBUG_OPERATIONS' src tests
```

Expected: hits in `src/linux_debug_mcp/config.py`, `src/linux_debug_mcp/server.py`, and possibly tests. The internal `docs/superpowers/` planning artifacts and CLAUDE.md mention the name in historical context — leave those alone (spec §8.6 explicitly permits docs to keep the old name where historical).

- [ ] **Step 1.2: Write the failing test asserting allowlist contains `debug.introspect.run` and rename is in place**

Add to `tests/test_config.py`:
```python
from linux_debug_mcp.config import (
    ALLOWED_DEBUG_OPERATIONS,
    MAX_INTROSPECT_CALLS_PER_RUN,
    PRELUDE_WARNING_FRACTION_PCT,
)


def test_allowed_debug_operations_includes_introspect_run() -> None:
    assert "debug.introspect.run" in ALLOWED_DEBUG_OPERATIONS


def test_max_introspect_calls_per_run_default() -> None:
    # Spec §5.2 step 4a defines the default as 1000.
    assert MAX_INTROSPECT_CALLS_PER_RUN == 1000


def test_prelude_warning_fraction_pct_default() -> None:
    # Spec §11 open risk 4a defines the default as 40 (percent).
    assert PRELUDE_WARNING_FRACTION_PCT == 40
```

Run: `uv run python -m pytest tests/test_config.py::test_allowed_debug_operations_includes_introspect_run tests/test_config.py::test_max_introspect_calls_per_run_default tests/test_config.py::test_prelude_warning_fraction_pct_default -v`

Expected: `ImportError: cannot import name 'ALLOWED_DEBUG_OPERATIONS' …`

- [ ] **Step 1.3: Perform the rename in `config.py` and add the caps**

Edit `src/linux_debug_mcp/config.py`. Replace:
```python
SPRINT_4_DEBUG_OPERATIONS = [
```
with:
```python
ALLOWED_DEBUG_OPERATIONS = [
```

In the list body, append `"debug.introspect.run"` as the last entry. Below the closing `]`, add:
```python
# Spec §5.2 step 4a: soft cap on introspect step records per run. The handler enforces this
# once, without holding the manifest lock — see spec §5.3 "Soft-cap semantics".
MAX_INTROSPECT_CALLS_PER_RUN = 1000

# Spec §11 open risk 4a: integer-percent threshold for the host-side prelude-cost warning;
# fires when `prelude_ms * 100 >= PRELUDE_WARNING_FRACTION_PCT * timeout_seconds * 1000`.
PRELUDE_WARNING_FRACTION_PCT = 40
```

In `DebugProfile.validate_enabled_operations`, replace the `SPRINT_4_DEBUG_OPERATIONS` reference with `ALLOWED_DEBUG_OPERATIONS`. In the `enabled_operations` field default, replace the same reference.

- [ ] **Step 1.4: Update the server-side callsite**

Edit `src/linux_debug_mcp/server.py:456-470` so `_ensure_debug_operation_enabled` reads `ALLOWED_DEBUG_OPERATIONS`. Add a top-of-file import: `from linux_debug_mcp.config import ALLOWED_DEBUG_OPERATIONS` (replace any existing `SPRINT_4_DEBUG_OPERATIONS` import).

- [ ] **Step 1.5: Update any remaining callsites**

Repeat the rg from step 1.1 — every remaining hit outside `docs/superpowers/` should be touched. Update tests that referenced the old name verbatim (e.g. `from linux_debug_mcp.config import SPRINT_4_DEBUG_OPERATIONS`).

- [ ] **Step 1.6: Run tests and gates**

Run:
```bash
uv run python -m pytest tests/test_config.py -q
uv run ruff check src tests
uv run ty check src
```

Expected: all green. Then run the full test suite to verify no test referenced the old name:
```bash
uv run python -m pytest -q
```

Expected: all green.

- [ ] **Step 1.7: Commit**

```bash
git add src/linux_debug_mcp/config.py src/linux_debug_mcp/server.py tests/test_config.py
git commit -m "config: rename SPRINT_4_DEBUG_OPERATIONS -> ALLOWED_DEBUG_OPERATIONS; add introspect caps"
```

---

## Task 2: Harden `<run>/sensitive/` to mode 0700 in `ArtifactStore.create_run` (R2-F4)

**Goal:** Make the `0700` parent-mode contract that spec §6.1 / §6.1a / step 4b depends on actually hold for newly created runs. Without this, the `0600` mode on `wrapper.py` is ineffective against any local user.

**Files:**
- Modify: `src/linux_debug_mcp/artifacts/store.py:53-95` (`create_run`)
- Test: `tests/test_debug_introspect_run.py` (test goes in the *introspect* test file per spec §9.1 — even though the change is in `ArtifactStore`, the test exists in service of the introspect contract)

- [ ] **Step 2.1: Write the failing test**

Create `tests/test_debug_introspect_run.py` with the imports and this single test (the rest of the file is written in Task 11):
```python
import os
from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import RunRequest


def _make_run(tmp_path: Path) -> Path:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(RunRequest(run_id="r1"))
    return store.run_dir(manifest.run_id)


def test_sensitive_run_subdir_is_mode_0700(tmp_path: Path) -> None:
    # Spec §9.1: assert ArtifactStore.create_run produces <run>/sensitive/
    # at mode 0700 regardless of process umask.
    old_umask = os.umask(0o022)
    try:
        run_dir = _make_run(tmp_path)
    finally:
        os.umask(old_umask)
    sensitive = run_dir / "sensitive"
    assert sensitive.is_dir()
    mode = sensitive.stat().st_mode & 0o777
    assert mode == 0o700, f"expected 0700, got {oct(mode)}"
```

Run: `uv run python -m pytest tests/test_debug_introspect_run.py::test_sensitive_run_subdir_is_mode_0700 -v`

Expected: FAIL — mode is `0o755` (or whatever the umask permits) because today's `create_run` calls `(run_dir / subdir).mkdir()` without forcing a mode for `sensitive/`.

- [ ] **Step 2.2: Implement the mode hardening**

Edit `src/linux_debug_mcp/artifacts/store.py`. After the loop that creates the subdirs in `create_run`, add the explicit chmod. The current loop is around line 71:
```python
for subdir in self.SUBDIRS:
    (run_dir / subdir).mkdir()
```
Replace that block with:
```python
for subdir in self.SUBDIRS:
    (run_dir / subdir).mkdir()
# Spec §6.1 R2-F4: <run>/sensitive/ must be 0700 so the 0600 file mode on
# wrapper.py (spec §6.1) is load-bearing against other local users. mkdir's
# `mode=` arg is masked by umask on POSIX; an explicit chmod after the fact
# is the only portable guarantee.
(run_dir / "sensitive").chmod(0o700)
```

- [ ] **Step 2.3: Run the test, confirm pass, then run the full store test module**

Run:
```bash
uv run python -m pytest tests/test_debug_introspect_run.py::test_sensitive_run_subdir_is_mode_0700 -v
uv run python -m pytest tests/test_artifacts_store.py -q
uv run python -m pytest -q
```

Expected: all green. Pay special attention to any existing test that asserts on the mode of `sensitive/`; none is expected.

- [ ] **Step 2.4: Commit**

```bash
git add src/linux_debug_mcp/artifacts/store.py tests/test_debug_introspect_run.py
git commit -m "artifacts: chmod <run>/sensitive to 0700 in create_run"
```

---

## Task 3: `RunManifest.append_step_result` + `record_step_result(append=True)`

**Goal:** Add the append-mode helper the spec §5.2 step 13 requires. Default `append=False` preserves today's replace-on-`force_*` semantics for the singleton named steps (`build`, `boot`, `run_tests`, `debug`). `append=True` is what introspect uses to grow `step_results` without ever replacing.

**Files:**
- Modify: `src/linux_debug_mcp/artifacts/manifest.py:60-75` (the `with_step_result` method block — add `append_step_result` immediately after it)
- Modify: `src/linux_debug_mcp/artifacts/store.py:99-110` (`record_step_result`)
- Test: `tests/test_artifacts_manifest.py` (extend; do not create) and `tests/test_artifacts_store.py` (extend; do not create)

- [ ] **Step 3.1: Write the failing manifest-level test**

Add to `tests/test_artifacts_manifest.py`:
```python
def test_append_step_result_grows_step_results() -> None:
    manifest = _make_manifest()  # use the existing helper in this test module
    first = StepResult(step_name="introspect:abc", status=StepStatus.SUCCEEDED,
                       summary="ok", details={}, artifacts=[])
    second = StepResult(step_name="introspect:def", status=StepStatus.SUCCEEDED,
                        summary="ok", details={}, artifacts=[])
    updated = manifest.append_step_result(first).append_step_result(second)
    assert set(updated.step_results.keys()) == {"introspect:abc", "introspect:def"}


def test_append_step_result_leaves_steps_unchanged() -> None:
    # Plan review finding 1: `RunManifest.steps` is the *planned* list seeded by
    # `RunManifest.create` (manifest.py:50-58) — exactly 6 entries: create_run,
    # build, boot, run_tests, collect_artifacts, debug. `append_step_result` may
    # only grow `step_results`; mutating `steps` would conflate planned-vs-
    # executed and break consumers that iterate the plan.
    manifest = _make_manifest()
    original_steps = list(manifest.steps)
    result = StepResult(step_name="introspect:abc", status=StepStatus.SUCCEEDED,
                        summary="ok", details={}, artifacts=[])
    updated = manifest.append_step_result(result)
    assert updated.steps == original_steps
    assert "introspect:abc" in updated.step_results


def test_append_step_result_rejects_existing_name() -> None:
    manifest = _make_manifest()
    first = StepResult(step_name="introspect:abc", status=StepStatus.SUCCEEDED,
                       summary="ok", details={}, artifacts=[])
    second = StepResult(step_name="introspect:abc", status=StepStatus.SUCCEEDED,
                        summary="dup", details={}, artifacts=[])
    updated = manifest.append_step_result(first)
    with pytest.raises(ValueError, match="step name already recorded"):
        updated.append_step_result(second)
```

If the test module lacks a `_make_manifest()` helper, look for an existing fixture/helper that builds a `RunManifest` with a synthetic `RunRequest`; copy that. Do not invent a new helper if one exists.

Run: `uv run python -m pytest tests/test_artifacts_manifest.py -v -k append_step_result`

Expected: `AttributeError: 'RunManifest' object has no attribute 'append_step_result'`.

- [ ] **Step 3.2: Implement `RunManifest.append_step_result`**

Edit `src/linux_debug_mcp/artifacts/manifest.py`. After `with_step_result` (currently lines 60–73), add:
```python
def append_step_result(self, result: StepResult) -> RunManifest:
    """Append a new step result. Unlike `with_step_result`, this never replaces an
    existing entry and never short-circuits — duplicate `step_name` raises. Spec
    §5.2 step 13 uses this for `introspect:<call_id>` records, where every call
    is a fresh entry and collisions are an internal bug (UUIDv4).

    NOTE: `self.steps` is intentionally untouched. Per `RunManifest.create`
    (`manifest.py:50-58`), `steps` is the fixed *planned* list of six well-known
    workflow steps (create_run, build, boot, run_tests, collect_artifacts,
    debug). It is a static plan, not a per-call ledger; `with_step_result`
    likewise only updates the matching planned entry's status in place
    (`manifest.py:60-70`), never appends. Introspect calls are dynamic — they
    grow `step_results` under `introspect:<call_id>` keys but stay out of
    `steps`. Plan review finding 1.
    """
    if result.step_name in self.step_results:
        raise ValueError(f"step name already recorded: {result.step_name}")
    clone = self.model_copy(deep=True)
    clone.step_results[result.step_name] = result
    return clone
```

`RunStep` import is **not** required for this helper — the implementation only
touches `step_results`. (If a later helper needs `RunStep`, check
`manifest.py:1-19` first before adding the import.)

- [ ] **Step 3.3: Run the manifest tests**

Run: `uv run python -m pytest tests/test_artifacts_manifest.py -v -k append_step_result`

Expected: PASS.

- [ ] **Step 3.4: Write the failing store-level test**

Add to `tests/test_artifacts_store.py`:
```python
def test_record_step_result_append_true_grows_results(tmp_path: Path) -> None:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(RunRequest(run_id="r1"))
    first = StepResult(step_name="introspect:aaa", status=StepStatus.SUCCEEDED,
                       summary="ok", details={}, artifacts=[])
    second = StepResult(step_name="introspect:bbb", status=StepStatus.SUCCEEDED,
                        summary="ok", details={}, artifacts=[])
    store.record_step_result(manifest.run_id, first, append=True)
    final = store.record_step_result(manifest.run_id, second, append=True)
    assert set(final.step_results.keys()) == {"introspect:aaa", "introspect:bbb"}


def test_record_step_result_append_true_rejects_collision(tmp_path: Path) -> None:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(RunRequest(run_id="r1"))
    first = StepResult(step_name="introspect:aaa", status=StepStatus.SUCCEEDED,
                       summary="ok", details={}, artifacts=[])
    store.record_step_result(manifest.run_id, first, append=True)
    with pytest.raises(ManifestStateError):
        store.record_step_result(manifest.run_id, first, append=True)
```

Run: `uv run python -m pytest tests/test_artifacts_store.py -v -k append`

Expected: `TypeError: record_step_result() got an unexpected keyword argument 'append'`.

- [ ] **Step 3.5: Implement `record_step_result(append=...)`**

Edit `src/linux_debug_mcp/artifacts/store.py:99-110`. Replace the existing method with:
```python
def record_step_result(
    self,
    run_id: str,
    result: StepResult,
    *,
    replace_succeeded: bool = False,
    append: bool = False,
) -> RunManifest:
    """Record `result` into the manifest under the manifest lock.

    `append=False` (default): `replace_succeeded` controls the
    `with_step_result` semantics — used by the singleton named steps
    (`build`, `boot`, `run_tests`, `debug`) where a re-invocation
    after `force_*` overwrites a SUCCEEDED entry.

    `append=True` (spec §5.2 step 13): use `RunManifest.append_step_result`,
    which never replaces and raises on `step_name` collision. Used for
    `introspect:<call_id>` records. `replace_succeeded` is ignored when
    `append=True` and is rejected to surface caller bugs early.
    """
    if append and replace_succeeded:
        raise ValueError("append=True is incompatible with replace_succeeded=True")
    run_id = self._validate_run_id(run_id)
    run_dir = self._run_dir(run_id)
    with self._manifest_lock(run_dir):
        manifest = self.load_manifest(run_id)
        if append:
            try:
                updated = manifest.append_step_result(result)
            except ValueError as exc:
                raise ManifestStateError(
                    str(exc), ErrorCategory.INFRASTRUCTURE_FAILURE
                ) from exc
        else:
            updated = manifest.with_step_result(
                result, replace_succeeded=replace_succeeded
            )
        if updated != manifest:
            self._write_manifest(run_dir, updated)
        return updated
```

Make sure `ErrorCategory` is imported at the top of `store.py` (it already is — see line ~7).

- [ ] **Step 3.6: Run the store tests + full suite**

```bash
uv run python -m pytest tests/test_artifacts_store.py -v -k append
uv run python -m pytest -q
uv run ruff check src tests && uv run ty check src
```

Expected: all green.

- [ ] **Step 3.7: Commit**

```bash
git add src/linux_debug_mcp/artifacts/manifest.py src/linux_debug_mcp/artifacts/store.py \
        tests/test_artifacts_manifest.py tests/test_artifacts_store.py
git commit -m "artifacts: add append_step_result + record_step_result(append=...)"
```

---

## Task 4: Build-id extraction in `local_kernel_build` (R2-F6)

**Goal:** Add the two distinct exception classes, the `_extract_build_id(vmlinux)` helper, and the wiring that maps each failure mode to its own `(ErrorCategory, code)` in the build handler. The introspect handler depends on `manifest.steps["build"].details["build_id"]`.

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_kernel_build.py` (top-of-file imports; add the two exceptions and `_extract_build_id`; call it from the success path)
- Modify: `src/linux_debug_mcp/server.py:922-…` (`kernel_build_handler` — catch the two exception types around the provider call and map each to its own failure response)
- Test: `tests/test_local_kernel_build.py` (extend)

- [ ] **Step 4.1: Read the current build success path**

Run:
```bash
rg -n '_finalize_build_result|build_result\.details|def kernel_build_handler' \
   src/linux_debug_mcp/providers/local_kernel_build.py src/linux_debug_mcp/server.py
```

The success path inside `LocalKernelBuildProvider` builds a `StepResult` via `_finalize_build_result` and writes `details` containing build artifacts. The new `build_id` belongs in that `details` dict. The exception types live in `local_kernel_build.py` so they can be raised by the provider and caught either there (mapped to a `StepResult` with `status=FAILED`) or in the server handler — the spec §7 phrasing implies catching at the provider level so the build step record carries the failure shape directly. Confirm by reading the existing failure paths (`_record_terminal_build_result`-bound code in `server.py:217`).

- [ ] **Step 4.2: Write the failing tests**

Add to `tests/test_local_kernel_build.py`:
```python
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from linux_debug_mcp.providers.local_kernel_build import (
    BuildIdMissing,
    ReadelfUnavailable,
    _extract_build_id,
)


def test_extract_build_id_returns_hex_on_success(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"")  # contents irrelevant; readelf is mocked
    fake = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout="    Owner          Data size  Description\n"
               "    GNU            0x14       NT_GNU_BUILD_ID (unique build ID bitstring)\n"
               "    Build ID: 0123456789abcdef0123456789abcdef01234567\n",
        stderr="",
    )
    with patch("linux_debug_mcp.providers.local_kernel_build.subprocess.run",
               return_value=fake):
        assert _extract_build_id(vmlinux) == "0123456789abcdef0123456789abcdef01234567"


def test_extract_build_id_raises_readelf_unavailable_on_missing_binary(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"")
    with patch("linux_debug_mcp.providers.local_kernel_build.subprocess.run",
               side_effect=FileNotFoundError("readelf")):
        with pytest.raises(ReadelfUnavailable):
            _extract_build_id(vmlinux)


def test_extract_build_id_raises_readelf_unavailable_on_nonzero_exit(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"")
    fake = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error")
    with patch("linux_debug_mcp.providers.local_kernel_build.subprocess.run",
               return_value=fake):
        with pytest.raises(ReadelfUnavailable):
            _extract_build_id(vmlinux)


def test_extract_build_id_raises_readelf_unavailable_on_timeout(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"")
    with patch(
        "linux_debug_mcp.providers.local_kernel_build.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["readelf"], timeout=10),
    ):
        with pytest.raises(ReadelfUnavailable):
            _extract_build_id(vmlinux)


def test_extract_build_id_raises_build_id_missing_when_no_note(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"")
    fake = subprocess.CompletedProcess(args=[], returncode=0,
                                       stdout="no notes here\n", stderr="")
    with patch("linux_debug_mcp.providers.local_kernel_build.subprocess.run",
               return_value=fake):
        with pytest.raises(BuildIdMissing):
            _extract_build_id(vmlinux)
```

Run: `uv run python -m pytest tests/test_local_kernel_build.py -v -k extract_build_id`

Expected: `ImportError: cannot import name 'ReadelfUnavailable' …`.

- [ ] **Step 4.3: Implement the exceptions and `_extract_build_id`**

Edit `src/linux_debug_mcp/providers/local_kernel_build.py`. Near the top of the file (after existing imports), add:
```python
import re
import subprocess
```
(Verify which are already imported and skip duplicates.)

Add immediately after the imports (or in a logical location near other helpers):
```python
class ReadelfUnavailable(Exception):
    """`readelf` failed — binary missing, non-zero exit, or timed out.

    Spec §7 R2-F6: distinct from `BuildIdMissing` so the caller can map each
    to its own `(ErrorCategory, code)` without inspecting auxiliary state.

    The optional `artifacts` payload carries the build artifacts that DID get
    produced (vmlinux may be present, .config and build log certainly are) so
    the handler can attach them to the FAILED `StepResult` for forensic
    recovery. Plan review finding 6 — without this the operator sees a build
    failure with zero artifacts even though the kernel built fine; build_id
    extraction is the *only* thing that failed.
    """

    def __init__(self, message: str, *,
                 artifacts: list[ArtifactRef] | None = None) -> None:
        super().__init__(message)
        self.artifacts: list[ArtifactRef] = artifacts or []


class BuildIdMissing(Exception):
    """`readelf` ran cleanly but the vmlinux carries no `.note.gnu.build-id`.

    Same `artifacts` contract as `ReadelfUnavailable` — see that docstring.
    Plan review finding 6.
    """

    def __init__(self, message: str, *,
                 artifacts: list[ArtifactRef] | None = None) -> None:
        super().__init__(message)
        self.artifacts: list[ArtifactRef] = artifacts or []


_BUILD_ID_LINE = re.compile(r"\s*Build ID:\s*([0-9a-fA-F]+)")


def _extract_build_id(vmlinux: Path) -> str:
    """Return the lower-case hex `.note.gnu.build-id` of *vmlinux*.

    Spec §7. Raises `ReadelfUnavailable` when the binary cannot be invoked /
    returns non-zero / times out. Raises `BuildIdMissing` when `readelf`
    succeeded but the note is absent.
    """
    try:
        proc = subprocess.run(
            ["readelf", "-n", str(vmlinux)],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ReadelfUnavailable(str(exc)) from exc
    if proc.returncode != 0:
        raise ReadelfUnavailable(
            f"readelf exit={proc.returncode}: {proc.stderr[:200]}"
        )
    for line in proc.stdout.splitlines():
        match = _BUILD_ID_LINE.match(line)
        if match:
            return match.group(1).lower()
    raise BuildIdMissing(f"no Build ID note in {vmlinux}")
```

- [ ] **Step 4.4: Confirm the extractor tests pass**

```bash
uv run python -m pytest tests/test_local_kernel_build.py -v -k extract_build_id
```

Expected: PASS.

- [ ] **Step 4.5: Wire the extractor into the success path**

In `LocalKernelBuildProvider`, find the success path (the place that calls `_finalize_build_result(..., status=StepStatus.SUCCEEDED, ...)`; see the report at `local_kernel_build.py:~324`). The build artifacts must be gathered FIRST (the kernel build succeeded — vmlinux, .config, build-log all exist) and attached to any extraction exception so the FAILED step record carries them. Plan review finding 6.

```python
# Collect candidate artifacts BEFORE attempting build_id extraction.
# `_detect_artifacts` already returns the full success-artifact list
# (`local_kernel_build.py:334-342`). If extraction fails, we re-raise the
# exception with these artifacts attached so the handler can persist them
# in the FAILED StepResult — operators need vmlinux + build-log to diagnose
# why readelf came up empty.
build_artifacts = self._detect_artifacts(
    plan=plan, log_path=log_path, summary_path=summary_path,
)
try:
    details["build_id"] = _extract_build_id(plan.output_path / "vmlinux")
except ReadelfUnavailable as exc:
    # Re-wrap with artifacts payload. The handler in server.py maps each
    # type to a distinct (ErrorCategory, code). Spec §7 R2-F6.
    raise ReadelfUnavailable(str(exc), artifacts=build_artifacts) from exc
except BuildIdMissing as exc:
    raise BuildIdMissing(str(exc), artifacts=build_artifacts) from exc
```

The re-wrap (rather than bare re-raise) is what makes the catch load-bearing: the new exception instance carries the artifacts the original did not. The handler in `server.py` reads `exc.artifacts` to build the FAILED `StepResult`.

- [ ] **Step 4.6: Write the failing handler-level tests**

Add to `tests/test_local_kernel_build.py` (these exercise `kernel_build_handler`, not the helper). Read the file first to find the existing handler-test scaffolding — there will be a fake/stub `LocalKernelBuildProvider` already, plus a fixture that creates a run dir with `inputs/.config` etc. Reuse all of it.

```python
from unittest.mock import patch

from linux_debug_mcp.providers.local_kernel_build import (
    BuildIdMissing,
    ReadelfUnavailable,
)


def test_readelf_unavailable_fails_build(tmp_path: Path,
                                          stub_build_provider) -> None:
    # Spec §9.1 / §7 R2-F6: ReadelfUnavailable -> step FAILED;
    # ErrorCategory.INFRASTRUCTURE_FAILURE; code=readelf_unavailable.
    # `stub_build_provider` is the fixture/helper that already lives in this
    # test module and returns a working LocalKernelBuildProvider. Wire its
    # downstream `_extract_build_id` call to raise.
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(RunRequest(run_id="r1"))
    with patch(
        "linux_debug_mcp.providers.local_kernel_build._extract_build_id",
        side_effect=ReadelfUnavailable("readelf not found"),
    ):
        response = kernel_build_handler(
            artifact_root=tmp_path, run_id=manifest.run_id,
            provider=stub_build_provider,
        )
    assert response.ok is False
    assert response.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details["code"] == "readelf_unavailable"
    final_manifest = store.load_manifest(manifest.run_id)
    assert final_manifest.step_results["build"].status == StepStatus.FAILED


def test_build_id_missing_fails_build(tmp_path: Path,
                                       stub_build_provider) -> None:
    # Spec §9.1 / §7 R2-F6: BuildIdMissing -> step FAILED;
    # ErrorCategory.BUILD_FAILURE; code=build_id_missing.
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(RunRequest(run_id="r1"))
    with patch(
        "linux_debug_mcp.providers.local_kernel_build._extract_build_id",
        side_effect=BuildIdMissing("no Build ID note"),
    ):
        response = kernel_build_handler(
            artifact_root=tmp_path, run_id=manifest.run_id,
            provider=stub_build_provider,
        )
    assert response.ok is False
    assert response.error.category == ErrorCategory.BUILD_FAILURE
    assert response.error.details["code"] == "build_id_missing"
    final_manifest = store.load_manifest(manifest.run_id)
    assert final_manifest.step_results["build"].status == StepStatus.FAILED


def test_build_id_missing_failure_preserves_vmlinux_artifact(
    tmp_path: Path, stub_build_provider,
) -> None:
    # Plan review finding 6: build artifacts MUST survive a build_id extraction
    # failure so operators can diagnose why readelf came up empty without
    # re-running the build. The provider hoists `_detect_artifacts` before the
    # extraction call and re-raises with the artifacts attached; the handler
    # threads `exc.artifacts` into the FAILED StepResult.
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(RunRequest(run_id="r1"))
    fake_artifacts = [
        ArtifactRef(path="/tmp/vmlinux", kind="vmlinux"),
        ArtifactRef(path="/tmp/build.log", kind="build-log"),
    ]
    with patch(
        "linux_debug_mcp.providers.local_kernel_build._extract_build_id",
        side_effect=BuildIdMissing("no Build ID note", artifacts=fake_artifacts),
    ):
        response = kernel_build_handler(
            artifact_root=tmp_path, run_id=manifest.run_id,
            provider=stub_build_provider,
        )
    assert response.ok is False
    final = store.load_manifest(manifest.run_id)
    artifact_kinds = {a.kind for a in final.step_results["build"].artifacts}
    assert "vmlinux" in artifact_kinds
    assert "build-log" in artifact_kinds
```

If `ArtifactRef` is not yet imported in this test module, add it from
`linux_debug_mcp.domain`. If no `stub_build_provider` fixture/helper exists in this file today, look at how the rest of `tests/test_local_kernel_build.py` exercises `kernel_build_handler` and copy that scaffolding — it most likely uses a `FakeKernelBuildProvider` defined at module scope. Match the existing convention; do not invent a new fake unless none exists.

Note on the test's patch shape: patching `_extract_build_id` directly bypasses the provider-side `_detect_artifacts` hoist (Step 4.5). The test instead constructs `BuildIdMissing(..., artifacts=fake_artifacts)` to simulate what Step 4.5 would have done — the assertion validates that the *handler* (Step 4.7) consumes `exc.artifacts`. A separate provider-integration test (e.g. an existing build-success test extended with a malformed vmlinux fixture) would exercise the Step 4.5 hoist directly; add one if the existing fixtures support it.

Run: `uv run python -m pytest tests/test_local_kernel_build.py::test_readelf_unavailable_fails_build tests/test_local_kernel_build.py::test_build_id_missing_fails_build -v`

Expected: FAIL — the handler doesn't yet catch the new exception types.

- [ ] **Step 4.7: Map the exceptions in `kernel_build_handler`**

Edit `src/linux_debug_mcp/server.py` around line 922 (`kernel_build_handler`). Around the provider call (the place that invokes the provider's run/build method), wrap with:
```python
try:
    build_result = provider.run(...)   # name as it appears today
except ReadelfUnavailable as exc:
    # Plan review finding 6: exc.artifacts carries the build artifacts the
    # provider already produced (vmlinux, .config, build-log). Persist them in
    # the FAILED StepResult so operators can inspect why readelf came up empty
    # without re-running the build.
    failed = StepResult(
        step_name="build",
        status=StepStatus.FAILED,
        summary="readelf unavailable while extracting build_id",
        details={"code": "readelf_unavailable", "error": str(exc)},
        artifacts=exc.artifacts,
    )
    _record_terminal_build_result(store, run_id, failed)
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=(
            "readelf unavailable while extracting build_id; "
            "the recorded FAILED build step retains vmlinux and the build log "
            "for forensic inspection"
        ),
        run_id=run_id,
        details={"code": "readelf_unavailable"},
    )
except BuildIdMissing as exc:
    # Plan review finding 6: same artifact-preservation rationale as
    # ReadelfUnavailable above.
    failed = StepResult(
        step_name="build",
        status=StepStatus.FAILED,
        summary="vmlinux has no .note.gnu.build-id",
        details={"code": "build_id_missing", "error": str(exc)},
        artifacts=exc.artifacts,
    )
    _record_terminal_build_result(store, run_id, failed)
    return ToolResponse.failure(
        category=ErrorCategory.BUILD_FAILURE,
        message=(
            "vmlinux has no .note.gnu.build-id; rebuild with LD_BUILD_ID=sha1 "
            "or equivalent (spec §7). The FAILED build step retains vmlinux "
            "and the build log so the failure can be diagnosed without "
            "re-running the build."
        ),
        run_id=run_id,
        details={"code": "build_id_missing"},
    )
```

Imports: at the top of `server.py`, ensure `from linux_debug_mcp.providers.local_kernel_build import ReadelfUnavailable, BuildIdMissing` is present.

- [ ] **Step 4.8: Confirm tests pass**

```bash
uv run python -m pytest tests/test_local_kernel_build.py -q
uv run python -m pytest -q
uv run ruff check src tests && uv run ty check src
```

Expected: all green.

- [ ] **Step 4.9: Commit**

```bash
git add src/linux_debug_mcp/providers/local_kernel_build.py src/linux_debug_mcp/server.py \
        tests/test_local_kernel_build.py
git commit -m "kernel.build: record build_id; fail loudly on readelf_unavailable / build_id_missing"
```

---

## Task 5: `DebugIntrospectRunRequest` domain model

**Goal:** Land the wire-level Pydantic model the handler signature requires.

**Files:**
- Modify: `src/linux_debug_mcp/domain.py` (add the new model near the other request models)
- Test: `tests/test_domain.py` (extend; do not create)

- [ ] **Step 5.1: Write the failing test**

Add to `tests/test_domain.py`:
```python
from pydantic import ValidationError

from linux_debug_mcp.domain import DebugIntrospectRunRequest


def test_debug_introspect_run_request_minimal() -> None:
    req = DebugIntrospectRunRequest(run_id="r1", target_ref="local-qemu",
                                    script="print(1)")
    assert req.timeout_seconds == 30
    assert req.allow_write is False
    assert req.debug_profile is None


def test_debug_introspect_run_request_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        DebugIntrospectRunRequest(run_id="r1", target_ref="t", script="s", unknown=1)
```

Run: `uv run python -m pytest tests/test_domain.py -v -k debug_introspect_run_request`

Expected: `ImportError`.

- [ ] **Step 5.2: Add the model**

Edit `src/linux_debug_mcp/domain.py`. Add (near the bottom or with the other wire models):
```python
class DebugIntrospectRunRequest(Model):
    """Request payload for `debug.introspect.run`. Spec §3.1.

    `script` is the user-supplied drgn Python source. The handler base64-encodes
    it for transport and substitutes it into a `string.Template`-rendered wrapper
    on the target (spec §4.2). `call_id` is server-minted, not in the request.
    """

    run_id: str
    target_ref: str
    script: str
    timeout_seconds: int = 30
    allow_write: bool = False
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None
```

`Model` already pins `extra="forbid"` and `validate_assignment=True` (see `domain.py:54`).

The handler — not Pydantic — enforces the `[5, 300]` timeout band and the script-non-empty / ≤256 KiB invariants. They're handler-level errors (`CONFIGURATION_ERROR` / `invalid_*`) rather than Pydantic-level so they surface as `ToolResponse.failure(...)` with the spec's exact codes from §3.3.

- [ ] **Step 5.3: Run tests**

```bash
uv run python -m pytest tests/test_domain.py -v -k debug_introspect_run_request
uv run python -m pytest -q
uv run ruff check src tests && uv run ty check src
```

Expected: all green.

- [ ] **Step 5.4: Commit**

```bash
git add src/linux_debug_mcp/domain.py tests/test_domain.py
git commit -m "domain: add DebugIntrospectRunRequest"
```

---

## Task 6: Provider scaffold — `LocalDrgnIntrospectProvider` + wrapper template

**Goal:** Land the new provider module, including the full wrapper template, the rendering helper, the provider class, and the capability factory. Tests follow in Task 8; Task 7 wires the capability into the plugin registry.

**Files:**
- Create: `src/linux_debug_mcp/providers/local_drgn_introspect.py`

- [ ] **Step 6.1: Create the module skeleton**

Create the file with the following structure. The wrapper template is verbatim from spec §4.2 — do not summarize or paraphrase.

```python
"""local-drgn-introspect: live drgn-over-SSH introspection provider.

Spec: docs/superpowers/specs/2026-05-28-debug-introspect-run-design.md
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from string import Template

from linux_debug_mcp.providers.contracts import (
    ProviderCapability,
    ImplementationState,
)

# Spec §3.1 pre-substitution validators. EXPECTED_BUILD_ID is host-validated
# hex from manifest.steps["build"].details["build_id"]. CALL_ID is a server-
# minted UUIDv4 hex.
_BUILD_ID_RE = re.compile(r"^[0-9a-f]{8,}$")
_CALL_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# Spec §3.1: 256 KiB script cap.
SCRIPT_BYTE_CAP = 256 * 1024


class WrapperRenderError(ValueError):
    """Raised when a non-user template input fails its host-side pre-substitution
    regex check. The user `script` field cannot trigger this because it is
    base64-encoded into a pure-ASCII literal before substitution (spec §3.1).
    """


# Spec §4.2 — exact wrapper template. Three placeholders:
#   ${USER_SCRIPT_B64}      pure-ASCII base64 of the decoded user script bytes
#   ${EXPECTED_BUILD_ID}    lower-case hex, validated by _BUILD_ID_RE
#   ${CALL_ID}              UUIDv4 hex, validated by _CALL_ID_RE
WRAPPER_TEMPLATE = Template(r"""<paste spec §4.2 wrapper body verbatim>""")


def render_wrapper(*, user_script: str, expected_build_id: str, call_id: str) -> str:
    """Render the on-target wrapper.

    Spec §3.1: host validates the non-user values BEFORE substitution. A
    failing regex on `expected_build_id` is `INFRASTRUCTURE_FAILURE` /
    `provenance_corrupt` at the handler layer (manifest carries malformed
    hex). A failing regex on `call_id` is an internal bug — should never
    happen because the caller mints UUIDv4 hex.

    `user_script` is base64-encoded and substituted into a pure-ASCII literal,
    so triple quotes, NUL bytes, and `${...}` sigils inside the user script
    cannot escape their enclosing string.
    """
    if not _BUILD_ID_RE.match(expected_build_id):
        raise WrapperRenderError(
            f"expected_build_id must match {_BUILD_ID_RE.pattern}; got {expected_build_id!r}"
        )
    if not _CALL_ID_RE.match(call_id):
        raise WrapperRenderError(
            f"call_id must match {_CALL_ID_RE.pattern}; got {call_id!r}"
        )
    encoded = base64.b64encode(user_script.encode("utf-8")).decode("ascii")
    # `substitute` (not `safe_substitute`) raises KeyError on unknown
    # placeholders — defensive against future template churn.
    return WRAPPER_TEMPLATE.substitute(
        USER_SCRIPT_B64=encoded,
        EXPECTED_BUILD_ID=expected_build_id,
        CALL_ID=call_id,
    )


def user_script_sha256(user_script: str) -> str:
    """Spec §6.3 R2-F7: sha256 of the *decoded user script bytes*, NOT of the
    rendered wrapper. Used in the agent-visible `wrapper.skeleton.py` placeholder.
    """
    return hashlib.sha256(user_script.encode("utf-8")).hexdigest()


def render_wrapper_skeleton(*, expected_build_id: str, call_id: str,
                             user_script_sha256_hex: str) -> str:
    """Render the agent-visible companion to wrapper.py (spec §6.1, §6.3).

    Same template, same regex-validated header values, but the user-script body
    is replaced by a sha256 reference. The skeleton carries no plaintext from
    the script and is safe to surface in the response's `artifacts` list.
    """
    placeholder = (
        f"# <user script: sha256:{user_script_sha256_hex}; "
        f"full source under sensitive/debug/introspect/{call_id}/wrapper.py>"
    )
    # Encoding the placeholder via base64 keeps the rendered template's shape
    # identical to wrapper.py so skeleton diffing in #54 and beyond stays
    # mechanical. The decoded body in the skeleton is the placeholder comment.
    encoded = base64.b64encode(placeholder.encode("utf-8")).decode("ascii")
    if not _BUILD_ID_RE.match(expected_build_id):
        raise WrapperRenderError(
            f"expected_build_id must match {_BUILD_ID_RE.pattern}; got {expected_build_id!r}"
        )
    if not _CALL_ID_RE.match(call_id):
        raise WrapperRenderError(
            f"call_id must match {_CALL_ID_RE.pattern}; got {call_id!r}"
        )
    return WRAPPER_TEMPLATE.substitute(
        USER_SCRIPT_B64=encoded,
        EXPECTED_BUILD_ID=expected_build_id,
        CALL_ID=call_id,
    )


@dataclass(frozen=True)
class LocalDrgnIntrospectProvider:
    """Marker for the local drgn-introspect capability.

    The actual SSH invocation, wrapper render, and result parsing live in the
    handler (`server.debug_introspect_run_handler`) so they can share the
    `_record_terminal_build_result`-style manifest-lock retry pattern and the
    redaction helpers. This provider object exists so the registry can declare
    `local-drgn-introspect` as a capability without bundling logic the handler
    already owns.
    """

    name: str = "local-drgn-introspect"


def local_drgn_introspect_capability() -> ProviderCapability:
    """Factory used by `providers/plugins.py`. Spec §3.4 / §2."""
    return ProviderCapability(
        name="local-drgn-introspect",
        implementation_state=ImplementationState.IMPLEMENTED,
        operations=["debug.introspect.run"],
    )
```

**Important:** at "<paste spec §4.2 wrapper body verbatim>", paste the wrapper template from spec §4.2 lines 222–463 character-for-character. The wrapper relies on:
- `_li_`-prefixed names for every wrapper-private global (R2-F8, R4-F4)
- the pre-seeded `_li_pre_helpers` snapshot containing both itself and `_li_drgn_helper_names` (R3-F1)
- `prelude_ms` initialized to `0` so it's present on every early-exit path (R2-F9)
- the tail `try/except/finally` recovery path that emits a minimal-JSON `outcome.status="wrapper_internal_error"` doc when serialization fails (R2-F2)
- exit code `6` for `wrapper_complete` (the agent-visible mapping in spec §4.3)

When pasting, use a raw triple-quoted string `r"""..."""` because the template contains `${...}` `string.Template` sigils that must remain literal. Confirm the rendered Python parses by running `python -c "compile(open('....').read(), '<x>', 'exec')"` against a rendered output in Task 8.

If `ProviderCapability` accepts an `operation_capabilities` parameter and the existing providers use it, mirror that shape exactly — see `providers/local_ssh_tests.py` `local_ssh_tests_capability()`.

- [ ] **Step 6.2: Run quick gates**

```bash
uv run ruff check src/linux_debug_mcp/providers/local_drgn_introspect.py
uv run ty check src
```

No test coverage yet — Task 8 adds wrapper tests.

- [ ] **Step 6.3: Commit**

```bash
git add src/linux_debug_mcp/providers/local_drgn_introspect.py
git commit -m "providers: add local_drgn_introspect (wrapper template + capability factory)"
```

---

## Task 7: Register `local-drgn-introspect` in the plugin spec

**Goal:** Make `providers.list` advertise the new capability.

**Files:**
- Modify: `src/linux_debug_mcp/providers/plugins.py:32-…` (`local_provider_plugin_specs()`)
- Test: `tests/test_providers_plugins.py` (extend; if missing, create with a single test)

- [ ] **Step 7.1: Write the failing test**

If `tests/test_providers_plugins.py` exists, extend it; otherwise create. Add:
```python
def test_local_drgn_introspect_capability_is_registered() -> None:
    specs = local_provider_plugin_specs()
    cap_names = {
        cap.name
        for spec in specs
        for cap in (factory() for factory in spec.provider_capability_factories)
    }
    assert "local-drgn-introspect" in cap_names


def test_local_drgn_introspect_advertises_introspect_run_operation() -> None:
    specs = local_provider_plugin_specs()
    for spec in specs:
        for factory in spec.provider_capability_factories:
            cap = factory()
            if cap.name == "local-drgn-introspect":
                assert "debug.introspect.run" in cap.operations
                return
    raise AssertionError("local-drgn-introspect capability not registered")
```

Run: `uv run python -m pytest tests/test_providers_plugins.py -v`

Expected: FAIL — `local-drgn-introspect` not registered.

- [ ] **Step 7.2: Register the factory**

Edit `src/linux_debug_mcp/providers/plugins.py`. At the top, add:
```python
from linux_debug_mcp.providers.local_drgn_introspect import local_drgn_introspect_capability
```
Inside `local_provider_plugin_specs()`, append `local_drgn_introspect_capability` to the `provider_capability_factories` list — alongside `local_ssh_tests_capability`.

- [ ] **Step 7.3: Run tests + gates**

```bash
uv run python -m pytest tests/test_providers_plugins.py -v
uv run python -m pytest -q
uv run ruff check src tests && uv run ty check src
```

Expected: all green.

- [ ] **Step 7.4: Commit**

```bash
git add src/linux_debug_mcp/providers/plugins.py tests/test_providers_plugins.py
git commit -m "providers: register local-drgn-introspect plugin"
```

---

## Task 8: Wrapper unit tests — `tests/test_introspect_wrapper.py`

**Goal:** Cover spec §9.2 — every test case that asserts on rendered-wrapper behavior. The wrapper is `exec`'d in-process against a stub `drgn` module so no SSH or kernel is involved.

**Files:**
- Create: `tests/test_introspect_wrapper.py`

- [ ] **Step 8.1: Write the test module skeleton**

Create `tests/test_introspect_wrapper.py`:
```python
"""Spec §9.2 — wrapper unit tests.

The rendered wrapper is `exec`'d in-process against a stub `drgn` module. Each
test exercises one path through the wrapper and asserts on:
  * stdout (must always be a single valid JSON document when the wrapper exits
    with code 6; per spec §4.3 the host parses JSON first, exit code second)
  * the system exit code (raised through `SystemExit`)
  * fields inside the parsed JSON (outcome.status, truncated.*, emits, build_id)
"""

import json
import sys
import types
from contextlib import redirect_stdout, suppress
from io import StringIO
from types import SimpleNamespace

import pytest

from linux_debug_mcp.providers.local_drgn_introspect import (
    render_wrapper,
    user_script_sha256,
)

EXPECTED_BUILD_ID = "0123456789abcdef0123456789abcdef01234567"
CALL_ID = "0" * 32  # 32 hex chars — passes _CALL_ID_RE


def _install_stub_drgn(monkeypatch: pytest.MonkeyPatch,
                       *, helpers: dict | None = None,
                       main_module_build_id: bytes | None = None,
                       open_raises: BaseException | None = None) -> None:
    """Install a minimal stub `drgn` + `drgn.helpers.linux` into sys.modules."""
    drgn_module = types.ModuleType("drgn")

    class _StubProg:
        def set_kernel(self): ...
        def load_default_debug_info(self):
            if open_raises is not None:
                raise open_raises
        def main_module(self):
            if main_module_build_id is None:
                raise AttributeError("main_module().build_id unavailable")
            return SimpleNamespace(build_id=main_module_build_id)

    def _make_program(*a, **k):
        return _StubProg()

    drgn_module.Program = _make_program

    helpers_pkg = types.ModuleType("drgn.helpers")
    helpers_linux = types.ModuleType("drgn.helpers.linux")
    for name, fn in (helpers or {
        "list_for_each_entry": lambda *a, **k: [],
        "for_each_task": lambda *a, **k: [],
        "dmesg": lambda *a, **k: "",
    }).items():
        setattr(helpers_linux, name, fn)
    helpers_pkg.linux = helpers_linux

    monkeypatch.setitem(sys.modules, "drgn", drgn_module)
    monkeypatch.setitem(sys.modules, "drgn.helpers", helpers_pkg)
    monkeypatch.setitem(sys.modules, "drgn.helpers.linux", helpers_linux)


def _exec_wrapper(script: str, *,
                  expected_build_id: str = EXPECTED_BUILD_ID) -> tuple[str, int]:
    """Render the wrapper, exec it in-process under capture, return
    (stdout, exit_code)."""
    rendered = render_wrapper(user_script=script,
                              expected_build_id=expected_build_id,
                              call_id=CALL_ID)
    buf = StringIO()
    exit_code = 0
    with redirect_stdout(buf):
        try:
            exec(compile(rendered, "<wrapper>", "exec"), {"__name__": "__wrapper__"})
        except SystemExit as exc:
            exit_code = exc.code or 0
    return buf.getvalue(), exit_code
```

- [ ] **Step 8.2: Add the §9.2 happy-path tests**

Add each test from spec §9.2 in order. For each: install the stub drgn (with `main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID)` for the happy path), exec the wrapper, parse the JSON, and assert.

Representative example:
```python
def test_wrapper_emit_roundtrips_json(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch,
                       main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    stdout, exit_code = _exec_wrapper('emit({"pid": 1})')
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["emits"] == [{"pid": 1}]
    assert payload["outcome"] == {"status": "ok"}
    assert payload["build_id"] == EXPECTED_BUILD_ID
    assert payload["truncated"] == {
        "emits": False, "user_stdout": False, "traceback": False,
        "total_json": False, "per_emit_size": False, "error_message": False,
    }


def test_wrapper_provenance_mismatch_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    # Stub reports a different build_id than EXPECTED.
    different = bytes.fromhex("ff" * 20)
    _install_stub_drgn(monkeypatch, main_module_build_id=different)
    stdout, exit_code = _exec_wrapper("pass")
    assert exit_code == 4
    payload = json.loads(stdout)
    assert payload["outcome"]["status"] == "provenance_mismatch"


def test_wrapper_drgn_import_failure_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force drgn import to raise.
    monkeypatch.setitem(sys.modules, "drgn",
                        None)  # `import drgn` will raise ImportError
    stdout, exit_code = _exec_wrapper("pass")
    assert exit_code == 3
    payload = json.loads(stdout)
    assert payload["outcome"]["status"] == "drgn_open_failure"


def test_wrapper_drgn_version_skew_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    # Spec §9.2 F8: prog.main_module().build_id raises.
    _install_stub_drgn(monkeypatch, main_module_build_id=None)
    stdout, exit_code = _exec_wrapper("pass")
    assert exit_code == 3
    payload = json.loads(stdout)
    assert payload["outcome"]["status"] == "drgn_version_skew"
    assert payload["outcome"]["error_type"] == "AttributeError"


def test_wrapper_syntax_error_exits_5(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch,
                       main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    stdout, exit_code = _exec_wrapper("def (: bad syntax")
    assert exit_code == 5
    payload = json.loads(stdout)
    assert payload["outcome"]["status"] == "script_compile_error"
    assert payload["outcome"]["error_type"] == "SyntaxError"
```

Add equivalent test functions for each of the remaining §9.2 cases, including:
- `test_wrapper_truncates_user_stdout`
- `test_wrapper_truncates_emits`
- `test_wrapper_truncates_traceback`
- `test_wrapper_truncates_error_message` (R2-F3 / R3-F3 — 32 KiB exception message)
- `test_wrapper_total_json_cap_drops_from_tail_not_all`
- `test_wrapper_total_json_cap_falls_back_to_clearing_user_stdout`
- `test_wrapper_per_emit_byte_cap_inserts_placeholder`
- `test_wrapper_user_script_exception_captures_traceback`
- `test_wrapper_stdout_only_contains_json` (asserts that script `print("noise")` lands in `user_stdout`, not on the wrapper stdout)
- `test_wrapper_round_trips_script_containing_triple_quotes_and_template_sigils`
- `test_wrapper_emit_unserializable_replaced_with_placeholder`
- `test_wrapper_helper_namespace_contains_expected_subset` (R2-F8 + R4-F4: assert all wrapper-private `_li_*` names are absent from the user namespace)
- `test_wrapper_handles_drgn_helper_shadowing_wrapper_private_name` (R2-F8 — stub a helper named `result` and assert wrapper still emits a valid doc with `outcome.status="ok"`)
- `test_user_script_sys_exit_does_not_spoof_timeout` (R2-F1 — script `sys.exit(124)` results in exit 6, outcome.error_type=SystemExit)
- `test_wrapper_always_emits_json_on_happy_path`
- `test_wrapper_tail_serialization_failure_emits_minimal_json` (R2-F2, R4-F3)
- `test_wrapper_tail_pipe_failure_falls_through_to_silent_crash` (R3-F2)

Each test follows the same shape: install stub drgn, exec, assert JSON parses, assert specific fields. **Do not skip any test from §9.2** — they collectively prove the wrapper meets the contract.

For the R2-F2 / R3-F2 tests, you'll need to inject a controlled `_li_json` reference. Two approaches:
1. After `compile()`, monkey-patch the resulting namespace before `exec` to swap `_li_json.dumps`.
2. Render a test-only wrapper variant. Approach 1 is simpler. The exec namespace is the dict you pass in; you can pre-populate `_li_json` (and `_li_sys.stdout` for the pipe test) before exec.

Actually, the wrapper does its imports under `import` — the simplest way is to monkey-patch `json.dumps` globally via `monkeypatch.setattr(json, "dumps", ...)`, but only for the *tail* dumps. Since the wrapper aliases `import json as _li_json` early, the attribute on the underlying `json` module is shared. Patch `json.dumps` to a counter that succeeds for early calls (the wrapper calls `json.dump` in early exits but not on the happy path — re-read §4.2) and fails for the tail call.

The cleanest approach is to patch `json.dumps` to a wrapped function that succeeds normally for all callers other than the in-progress wrapper exec. Since the only call to `json.dumps` on the happy path is the tail (the early-exit paths use `json.dump` to stdout), patching `json.dumps` to raise once is sufficient. Then patch back, allowing the inner-except `_li_json.dumps({...})` recovery call to succeed.

For `test_wrapper_tail_pipe_failure_falls_through_to_silent_crash`, replace the captured stdout buffer with one whose `write` raises `BrokenPipeError`:
```python
class _BrokenStdout:
    def write(self, _: str) -> int:
        raise BrokenPipeError("pipe closed")
```

- [ ] **Step 8.3: Run the wrapper tests**

```bash
uv run python -m pytest tests/test_introspect_wrapper.py -v
```

Expected: all green. Expect to iterate: the wrapper is dense and the first run will likely surface a mismatch between the rendered template and the assumed in-process exec semantics (e.g. `sys.exit` raising `SystemExit` rather than terminating the process). Adjust the *tests*, not the wrapper — the wrapper exit-code contract is fixed by the spec.

- [ ] **Step 8.4: Commit**

```bash
git add tests/test_introspect_wrapper.py
git commit -m "tests: introspect wrapper unit tests (spec §9.2)"
```

---

## Task 8.5: `SshRunner` Protocol — add `stdin` and audit implementers

**Goal:** The introspect handler in Task 9 pipes the rendered wrapper to `ssh` on stdin (`ssh_runner.run(..., stdin=wrapper)`). Today's `SshRunner` Protocol (`src/linux_debug_mcp/providers/local_ssh_tests.py:78`) has no `stdin` parameter. Land that Protocol change — plus the production implementer and every existing fake — as its own isolated commit, **before** Task 9. Doing so means the handler change in Task 9 is mechanical and bisectable; if a future regression appears, `git bisect` will attribute it to either "the transport widened" or "the handler grew", not both. Plan review finding 4.

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_ssh_tests.py:78-105` — `SshRunner` Protocol and `SubprocessSshRunner` production class
- Modify: `tests/_layer4_fakes.py:148` — `FakeSshRunner`
- Modify: `tests/test_local_ssh_tests_provider.py:19` — `FakeSshRunner`
- Modify: `tests/test_break_inject.py:20` — `_RecordingSsh` (also fix the pre-existing missing `cancel` kwarg surfaced by the audit)

- [ ] **Step 8.5.1: Inventory implementers**

```bash
rg -n 'class .*SshRunner|def run\(self, argv' src tests
```

Confirm the implementer set is exactly:
1. `SshRunner` protocol — `src/linux_debug_mcp/providers/local_ssh_tests.py:78`
2. `SubprocessSshRunner` — `src/linux_debug_mcp/providers/local_ssh_tests.py:94` (production)
3. `FakeSshRunner` — `tests/_layer4_fakes.py:148`
4. `FakeSshRunner` — `tests/test_local_ssh_tests_provider.py:19`
5. `_RecordingSsh` — `tests/test_break_inject.py:20`

The `libvirt_qemu_provider` tests (`tests/test_libvirt_qemu_provider.py`) define `Cmd.run(self, argv, *, timeout, log_path=None)` — these are *not* `SshRunner` implementations (they don't satisfy `SshRunner.which`), so they are not in scope. Confirm by checking the function signature.

If the inventory above has grown since this plan was written, add the new implementer to the same edit. Do not skip any — `ty check` will refuse to type-check `server.py` if even one implementer is missing the new parameter.

- [ ] **Step 8.5.2: Extend the Protocol**

In `src/linux_debug_mcp/providers/local_ssh_tests.py:78-91`, add `stdin: str | None = None` to `SshRunner.run`:
```python
class SshRunner(Protocol):
    def which(self, command: str) -> str | None:
        raise NotImplementedError

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        stdout_path: Path,
        stderr_path: Path,
        cancel: threading.Event | None = None,
        stdin: str | None = None,            # Spec §4.1: wrapper piped on stdin
    ) -> SshCommandResult:
        raise NotImplementedError
```

- [ ] **Step 8.5.3: Extend the production implementer**

In `src/linux_debug_mcp/providers/local_ssh_tests.py:94-105+`, add `stdin: str | None = None` to `SubprocessSshRunner.run` and route it to the underlying `subprocess.Popen`/`subprocess.run`. Read the current body first — it is a `Popen` loop with `stdout_file`/`stderr_file` handles and a `cancel` check, not a one-shot `subprocess.run`. The minimal change is to pass `stdin=subprocess.PIPE` and call `proc.communicate(input=stdin)` when `stdin is not None`; otherwise fall through to today's behavior. Confirm by reading the existing `Popen` invocation and matching its IO semantics.

```python
def run(
    self,
    argv: list[str],
    *,
    timeout: int,
    stdout_path: Path,
    stderr_path: Path,
    cancel: threading.Event | None = None,
    stdin: str | None = None,
) -> SshCommandResult:
    # (existing setup block — keep unchanged)
    proc = subprocess.Popen(
        argv,
        stdout=stdout_file,
        stderr=stderr_file,
        stdin=subprocess.PIPE if stdin is not None else None,
        text=True,
        # (existing Popen kwargs — keep unchanged)
    )
    if stdin is not None:
        # Write the wrapper on stdin and close it so the remote can EOF.
        # `communicate` blocks for the process — the existing cancel loop
        # must be reconciled with this. Read the current body before
        # blindly substituting `communicate`; the cleanest path is a
        # short writer thread that closes stdin and lets the existing
        # poll/cancel loop finish unchanged.
        pass  # ← engineer: integrate per the comment above
```

The `pass` placeholder in the body is an integration note, not a literal: read the existing `SubprocessSshRunner.run` body and pick the integration that preserves the cancel-and-timeout behavior. Keep the change small.

- [ ] **Step 8.5.4: Update every fake**

Each of the three fakes implements `SshRunner.run` with an explicit signature (no `**kwargs`), so `ty check` will reject the protocol after Step 8.5.2 until every fake also accepts `stdin`.

`tests/_layer4_fakes.py:157`:
```python
def run(self, argv, *, timeout, stdout_path, stderr_path,
        cancel=None, stdin=None):
    # (existing body — keep unchanged)
```

`tests/test_local_ssh_tests_provider.py:19+`:
```python
def run(self, argv, *, timeout, stdout_path, stderr_path,
        cancel=None, stdin=None):
    # (existing body — keep unchanged)
```

`tests/test_break_inject.py:20`:
```python
def run(self, argv, *, timeout, stdout_path, stderr_path,
        cancel=None, stdin=None):
    # Plan review finding 4: this fake was already missing the `cancel`
    # parameter required by SshRunner.run — a pre-existing protocol
    # mismatch surfaced by the audit. Adding `stdin` lets us fix both at
    # once, since `ty check` will refuse the file until both are present.
    self.argv = argv

    class _R:
        returncode = 0

    return _R()
```

Note the `_RecordingSsh` body is unchanged except for the signature — it doesn't write to stdout/stderr files in today's test, and the introspect handler isn't exercised by `test_break_inject.py`. The new `stdin` kwarg is accepted and ignored.

- [ ] **Step 8.5.5: `ty check` gate**

```bash
uv run ty check src
uv run python -m pytest -q
```

Both must be green before moving on to Task 9. Specifically:
- `ty check src` is the load-bearing gate — if any `SshRunner` implementer is missing the new kwarg, the typechecker rejects the assignment in `server.py` where the protocol is consumed.
- The full pytest suite verifies that no test relied on the old signature shape (e.g. by `**kwargs` forwarding).

If `ty check` flags an implementer not in the Step 8.5.1 inventory, extend the inventory and add the same `stdin: str | None = None` parameter there. Do not relax the type check.

- [ ] **Step 8.5.6: Commit as a single, isolated change**

```bash
git add src/linux_debug_mcp/providers/local_ssh_tests.py \
        tests/_layer4_fakes.py \
        tests/test_local_ssh_tests_provider.py \
        tests/test_break_inject.py
git commit -m "transport: extend SshRunner.run protocol with stdin (+ fix test_break_inject fake)"
```

Keep this commit separate from Task 9's handler change so a future `git bisect` can attribute regressions cleanly (transport widening vs. handler logic).

---

## Task 9: Handler implementation — `debug_introspect_run_handler`

**Goal:** Implement the 14-step handler from spec §5.2 inside `server.py`, alongside its peers. This is the largest task; sub-tests in Task 11 verify each branch.

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (add the handler and the `_count_introspect_calls` helper)

- [ ] **Step 9.1: Add the helpers and signatures**

In `server.py`, near the other private helpers (after `_record_terminal_build_result`), add:
```python
_INTROSPECT_STEP_NAME_RE = re.compile(r"^introspect:")


def _count_introspect_calls(manifest: RunManifest) -> int:
    """Spec §5.2 step 4a / R3-F5. Named so tests can monkey-patch it to
    exercise the soft-cap concurrency property without thread races.
    """
    return sum(1 for name in manifest.step_results
               if _INTROSPECT_STEP_NAME_RE.match(name))


def _redact_and_truncate(redactor: Redactor, text: str, cap: int = 256) -> str:
    """Spec §5.2 step 5, step 9, §6.3 — redact BEFORE truncate. The order
    matters: `Redactor.redact_text` does literal substring replacement against
    `secret_values`, so truncating first could split an `ssh_key_ref` mid-secret
    and leave an unmatched prefix in the diagnostic (R2-F3).
    """
    redacted = redactor.redact_text(text)
    return redacted[:cap]
```

Make sure `import re` is present at the top of `server.py` (it is — verify with `rg '^import re' src/linux_debug_mcp/server.py`).

- [ ] **Step 9.2: Add the handler signature**

Add the function signature from spec §5.1:
```python
def debug_introspect_run_handler(
    request: DebugIntrospectRunRequest,
    *,
    artifact_root: Path,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    provider: LocalDrgnIntrospectProvider | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    """Spec §5.2. See file-level docstring for the contract."""
```

Imports at the top of `server.py`:
```python
from linux_debug_mcp.domain import DebugIntrospectRunRequest
from linux_debug_mcp.providers.local_drgn_introspect import (
    LocalDrgnIntrospectProvider,
    WrapperRenderError,
    render_wrapper,
    render_wrapper_skeleton,
    user_script_sha256,
    SCRIPT_BYTE_CAP,
)
from linux_debug_mcp.config import (
    MAX_INTROSPECT_CALLS_PER_RUN,
    PRELUDE_WARNING_FRACTION_PCT,
)
```

- [ ] **Step 9.3: Implement spec §5.2 steps 1–5 — pre-admission validation**

Spec §5.2's step numbering (1, 2, 3, 4, 4a, 4b, 5) is the source of truth. The list below uses the same numbers — do not renumber.

**Spec step 1 — Resolve profiles + load manifest.** Mirror `target_run_tests_handler` (`server.py:1462`). Construct the per-call `Redactor` immediately after the rootfs profile is resolved (spec §5.2 prologue):
```python
redactor = Redactor(
    secret_values=[resolved_rootfs.ssh_key_ref] if resolved_rootfs.ssh_key_ref else []
)
```

**Spec step 2 — Operation gating.** Wrap `_ensure_debug_operation_enabled(resolved_debug, "debug.introspect.run")` with `try/except ProviderDebugError` and convert to `ToolResponse.failure(category=CONFIGURATION_ERROR, message=..., details={"code": "operation_disabled"})`.

**Spec step 3 — Request invariants.** `allow_write=True` rejected (`code="allow_write_not_supported"`); `timeout_seconds` in `[5, 300]` (`code="invalid_timeout"`); `script` non-empty and ≤ `SCRIPT_BYTE_CAP` bytes when UTF-8 encoded (`code="invalid_script"`). For each, return `ToolResponse.failure(category=CONFIGURATION_ERROR, run_id=run_id, details={"code": "<exact code from §3.3>"}, ...)`. No `call_id` in any response body yet.

**Spec step 4 — Build_id from manifest:**
```python
build_step = manifest.step_results.get("build")
if build_step is None or "build_id" not in build_step.details:
    # Plan review finding 3: do NOT tell the operator to "rerun kernel.build".
    # `kernel.build` is idempotent on SUCCEEDED (server.py:957) and
    # `force_rebuild=true` is rejected outright with CONFIGURATION_ERROR
    # (server.py:942-947). A re-run of the same run_id is a no-op. The
    # operator must start a fresh run via `kernel.create_run`; that run's
    # build will populate `build_id` via the Task 4 extractor.
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        run_id=run_id,
        message=(
            "kernel.build for this run did not record a build_id. Start a "
            "fresh run via kernel.create_run (kernel.build is idempotent on "
            "SUCCEEDED and force_rebuild is not yet supported — see "
            "kernel_build_handler at server.py:942-947). The fresh build "
            "will populate build_id."
        ),
        details={"code": "provenance_missing"},
    )
build_id = build_step.details["build_id"]
if not _BUILD_ID_RE.match(build_id):  # imported from local_drgn_introspect
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        run_id=run_id,
        message="recorded build_id is malformed",
        details={"code": "provenance_corrupt", "recorded": build_id},
    )
```

**Spec step 4a — Manifest call budget:**
```python
if _count_introspect_calls(manifest) >= MAX_INTROSPECT_CALLS_PER_RUN:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        run_id=run_id,
        message=(
            f"introspect call budget exhausted (>= {MAX_INTROSPECT_CALLS_PER_RUN}); "
            "start a new run via kernel.create_run"
        ),
        details={"code": "manifest_call_budget_exhausted"},
    )
```

**Spec step 4b — `sensitive/` parent-mode preflight (R4-F1):**
```python
sensitive_dir = store.run_dir(run_id) / "sensitive"
mode = sensitive_dir.stat().st_mode & 0o777
if mode & 0o077:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        run_id=run_id,
        message=(
            f"{sensitive_dir} mode is {oct(mode)}; expected 0o700. "
            "Re-run kernel.create_run, or `chmod 0700` the directory."
        ),
        details={"code": "sensitive_dir_too_permissive",
                 "actual_mode": oct(mode)},
    )
```

**Spec step 5 — Sudo preflight** (skip when `resolved_rootfs.ssh_user == "root"`):
```python
if resolved_rootfs.ssh_user != "root":
    sudo_argv = _build_sudo_preflight_argv(resolved_rootfs)  # reuse existing
    preflight_stdout = store.run_dir(run_id) / "logs" / "sudo_preflight.stdout"
    preflight_stderr = store.run_dir(run_id) / "logs" / "sudo_preflight.stderr"
    preflight_stdout.parent.mkdir(parents=True, exist_ok=True)
    result = ssh_runner.run(
        sudo_argv, timeout=5,
        stdout_path=preflight_stdout, stderr_path=preflight_stderr,
    )
    if result.exit_status != 0:
        message = _redact_and_truncate(redactor, result.stderr, cap=256)
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"sudo -n true failed: {message}",
            details={"code": "sudo_requires_password"},
        )
```
   If a `_build_sudo_preflight_argv`-style helper doesn't exist in `local_ssh_tests.py`, build the argv inline:
   ```python
   sudo_argv = [
       "ssh", *resolved_rootfs.ssh_args(),  # however the existing code constructs args
       f"{resolved_rootfs.ssh_user}@{resolved_rootfs.ssh_host}",
       "sudo", "-n", "true",
   ]
   ```
   Match whatever pattern `target_run_tests_handler` uses today.

The plain code listing above is dense — review §5.2 again to ensure no step is skipped. The order is load-bearing (preflight cost is paid only after cheap checks succeed).

- [ ] **Step 9.4: Implement step 6 — admission gate**

Per spec §5.2 step 6:
```python
target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
snapshot = admission.current_snapshot(target_key)
if snapshot is None:
    return ToolResponse.failure(
        category=ErrorCategory.READINESS_FAILURE,
        run_id=run_id, message="target not ready",
        details={"code": "target_not_ready"},
    )
proof = probe_execution_state(
    registry=session_registry, admission=admission,
    target_key=target_key, generation=snapshot.generation,
)
try:
    handle = admission.admit_ssh_tier(
        target_key, snapshot.generation, snapshot.platform,
        lease=snapshot.lease, execution_proof=proof,
    )
except AdmissionError as exc:
    return _admission_error_to_failure(exc, run_id=run_id)
```

Reuse `_admission_error_to_failure` if it exists in `server.py`; otherwise inline a mapping over `exc.code` (`target_halted`, `execution_state_unknown`, `stale_handle`) to the §3.3 row. Look at how `target_run_tests_handler` maps admission errors (`server.py:~1560`).

- [ ] **Step 9.5: Implement steps 7–8 — mint `call_id`, render wrapper, persist artifacts**

Per spec §5.2 steps 7–8:
```python
call_id = uuid.uuid4().hex
agent_dir = store.run_dir(run_id) / "debug" / "introspect" / call_id
sensitive_dir = (store.run_dir(run_id) / "sensitive"
                 / "debug" / "introspect" / call_id)
agent_dir.mkdir(parents=True, mode=0o700)
sensitive_dir.mkdir(parents=True, mode=0o700)
# Defensive chmod — parent-of-parent under sensitive/ may have inherited
# umask if the intermediate `debug/` dir was created here for the first time.
sensitive_dir.chmod(0o700)
sensitive_dir.parent.chmod(0o700)
sensitive_dir.parent.parent.chmod(0o700)

try:
    wrapper = render_wrapper(
        user_script=request.script,
        expected_build_id=build_id,
        call_id=call_id,
    )
    skeleton = render_wrapper_skeleton(
        expected_build_id=build_id,
        call_id=call_id,
        user_script_sha256_hex=user_script_sha256(request.script),
    )
except WrapperRenderError as exc:
    # provenance_corrupt is already caught at step 4; reaching here implies
    # a programmer error (call_id regex). Surface as INFRASTRUCTURE_FAILURE.
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        run_id=run_id, message=f"wrapper render error: {exc}",
        details={"code": "wrapper_crash"},
    )

(sensitive_dir / "wrapper.py").write_text(wrapper, encoding="utf-8")
(sensitive_dir / "wrapper.py").chmod(0o600)
(agent_dir / "wrapper.skeleton.py").write_text(skeleton, encoding="utf-8")

redacted_request = redactor.redact_value(request.model_dump(mode="json"))
(agent_dir / "request.json").write_text(json.dumps(redacted_request), encoding="utf-8")
```

- [ ] **Step 9.6: Implement steps 9–10 — SSH invocation + cancellation watcher**

Per spec §5.2 steps 9–10 (cancellation watcher is **verbatim** from `_run_admitted` in `target.run_tests`):
```python
user_timeout = request.timeout_seconds
ssh_argv = [
    "ssh", *resolved_rootfs.ssh_argv(),
    f"{resolved_rootfs.ssh_user}@{resolved_rootfs.ssh_host}",
    "--", f"timeout --kill-after=2s {user_timeout}s sudo python3 -",
]
stdout_path = agent_dir / "stdout.raw.tmp"
stderr_path = agent_dir / "stderr.raw.tmp"

cancel_event = threading.Event()
stop_watcher = threading.Event()

def watcher() -> None:
    while not stop_watcher.is_set():
        if handle.wait_cancelled(0.1):
            cancel_event.set()
            return

thread = threading.Thread(target=watcher, daemon=True)
thread.start()
try:
    ssh_result = ssh_runner.run(
        ssh_argv,
        timeout=user_timeout + 10,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        cancel=cancel_event,
        stdin=wrapper,                       # match SshRunner's stdin API
    )
finally:
    stop_watcher.set()
    thread.join()

try:
    admission.complete(handle)
except AdmissionError as exc:
    return _admission_error_to_failure(exc, run_id=run_id, with_call_id=call_id)
```

`stdin` is already supported on `SshRunner.run` per Task 8.5 — pass `stdin=wrapper` to `ssh_runner.run(...)` and the production `SubprocessSshRunner` will write it to the remote process's stdin. No transport-layer changes belong in this task.

- [ ] **Step 9.7: Implement step 11 — exit-code-and-JSON parsing**

Per spec §4.3 contract. The host parses JSON first; the exit code is advisory unless JSON is absent/invalid. Define a local helper that records the FAILED `StepResult` (with `details.outcome_status` for forensics per §6.2) and returns the agent-facing `ToolResponse.failure(...)`:

```python
def _record_introspect_failure(
    *, store: ArtifactStore, run_id: str, call_id: str,
    category: ErrorCategory, code: str, message: str,
    agent_dir: Path, sensitive_dir: Path,
    redactor: Redactor, raw_stderr: str,
    started_at: datetime, finished_at: datetime,
    ssh_exit: int,
    request_timeout_seconds: int,
    duration_ms: int,
    ssh_user: str,
    outcome_status_for_forensics: str | None,
    include_stdout_json: bool = False,
    redacted_payload: dict[str, object] | None = None,
) -> ToolResponse:
    """Persist artifacts, record the FAILED step, return ToolResponse.failure.

    Plan review findings 2 & 5:
    - `request_timeout_seconds` is the caller's *budget* (spec §6.2 — it is the
      same value the success path records in step.details["timeout_seconds"]).
      Do NOT use elapsed wall-clock here.
    - `duration_ms` is the measured wall-clock duration in milliseconds — the
      same field the success path records in step.details["duration_ms"].
      Keeping success and failure record shapes symmetric lets forensic tooling
      treat the two paths uniformly.
    - `ssh_user` is required (no "unknown" placeholder) so the failure record
      is always actionable. The previous `extra_details` escape hatch has been
      removed — every field every caller writes now lives in the signature.
    """
    (agent_dir / "stderr.log").write_text(
        redactor.redact_text(raw_stderr), encoding="utf-8"
    )
    if include_stdout_json and redacted_payload is not None:
        (agent_dir / "stdout.json").write_text(
            json.dumps(redacted_payload), encoding="utf-8"
        )
    artifacts: list[ArtifactRef] = [
        ArtifactRef(path=str(agent_dir / "request.json"), kind="application/json"),
        ArtifactRef(path=str(agent_dir / "wrapper.skeleton.py"),
                    kind="text/x-python"),
        ArtifactRef(path=str(sensitive_dir / "wrapper.py"),
                    kind="text/x-python", sensitive=True),
        ArtifactRef(path=str(agent_dir / "stderr.log"), kind="text/plain"),
    ]
    if include_stdout_json:
        artifacts.append(ArtifactRef(
            path=str(agent_dir / "stdout.json"), kind="application/json"))
    if (sensitive_dir / "stdout.raw").exists():
        artifacts.append(ArtifactRef(
            path=str(sensitive_dir / "stdout.raw"),
            kind="application/octet-stream", sensitive=True))
    details: dict[str, object] = {
        "call_id": call_id,
        "timeout_seconds": request_timeout_seconds,
        "duration_ms": duration_ms,
        "wrapper_exit_code": ssh_exit,
        "ssh_user": ssh_user,
        "outcome_status": outcome_status_for_forensics,
        "code": code,
    }
    step = StepResult(
        step_name=f"introspect:{call_id}",
        status=StepStatus.FAILED,
        summary=message,
        artifacts=artifacts,
        details=details,
    )
    _record_terminal_introspect_result(store, run_id, step)
    public = [a for a in artifacts if not a.sensitive]
    return ToolResponse.failure(
        category=category, run_id=run_id, message=message,
        details={"code": code, "call_id": call_id,
                 "outcome_status": outcome_status_for_forensics},
        artifacts=public,
        suggested_next_actions=["artifacts.get_manifest"],
    )
```

Then the parsing block:
```python
raw_stdout = stdout_path.read_text(encoding="utf-8", errors="replace")
raw_stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
finished_at = (clock or _utcnow)()
# Plan review finding 2: measure duration ONCE at the top of the block so it is
# consistent across every failure-record path. `timeout_seconds` is the request
# budget (recorded verbatim from `request.timeout_seconds`); `duration_ms` is
# the wall-clock elapsed time. The success path (Step 9.9) records the same two
# fields with the same semantics.
duration_ms = int((finished_at - started_at).total_seconds() * 1000)

parsed: dict[str, object] | None
try:
    parsed = json.loads(raw_stdout) if raw_stdout else None
except json.JSONDecodeError:
    parsed = None

ssh_exit = ssh_result.exit_status
# `common` is threaded into every `_record_introspect_failure(...)` call.
# Plan review findings 2 & 5: every required field on the helper signature
# (including `ssh_user`) MUST be present here so no failure path is missing it.
common = dict(
    store=store, run_id=run_id, call_id=call_id,
    agent_dir=agent_dir, sensitive_dir=sensitive_dir,
    redactor=redactor, raw_stderr=raw_stderr,
    started_at=started_at, finished_at=finished_at, ssh_exit=ssh_exit,
    request_timeout_seconds=request.timeout_seconds,
    duration_ms=duration_ms,
    ssh_user=resolved_rootfs.ssh_user,
)

if ssh_result.timed_out:
    return _record_introspect_failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        code="ssh_timeout",
        message="ssh round trip exceeded host-side timeout margin",
        outcome_status_for_forensics=None, **common)

if ssh_exit == 124 and parsed is None:
    return _record_introspect_failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        code="introspect_timeout",
        message="target-side timeout(1) fired",
        outcome_status_for_forensics=None, **common)

if parsed is None:
    # Spec §6.1 R3-F2: stdout was non-empty but not JSON -> move to
    # sensitive/stdout.raw and persist stderr-only on the agent side.
    if raw_stdout:
        (sensitive_dir / "stdout.raw").write_text(raw_stdout, encoding="utf-8")
        (sensitive_dir / "stdout.raw").chmod(0o600)
    return _record_introspect_failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        code="wrapper_crash",
        message=f"wrapper exited {ssh_exit} without a parseable JSON document",
        outcome_status_for_forensics=None, **common)

# JSON parsed. Discriminate on outcome.status — exit code is advisory (§4.3).
redacted_payload = redactor.redact_value(parsed)
outcome_status = redacted_payload.get("outcome", {}).get("status")
common_json = dict(common,
                   include_stdout_json=True, redacted_payload=redacted_payload)

if outcome_status == "drgn_open_failure":
    return _record_introspect_failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE, code="drgn_open_failure",
        message="drgn could not attach to the live target",
        outcome_status_for_forensics=outcome_status, **common_json)
if outcome_status == "drgn_version_skew":
    return _record_introspect_failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE, code="drgn_version_skew",
        message="drgn on target lacks main_module().build_id (version skew)",
        outcome_status_for_forensics=outcome_status, **common_json)
if outcome_status == "provenance_mismatch":
    return _record_introspect_failure(
        category=ErrorCategory.CONFIGURATION_ERROR, code="provenance_mismatch",
        message="target build_id does not match the recorded build_id",
        outcome_status_for_forensics=outcome_status, **common_json)
if outcome_status == "script_compile_error":
    return _record_introspect_failure(
        category=ErrorCategory.CONFIGURATION_ERROR, code="script_compile_error",
        message="user script failed to compile on the target",
        outcome_status_for_forensics=outcome_status, **common_json)
if outcome_status == "wrapper_internal_error":
    # R4-F3: forensic-only on disk; agent-facing collapses to wrapper_crash.
    return _record_introspect_failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE, code="wrapper_crash",
        message="wrapper exited 6 with a minimal-recovery JSON document",
        outcome_status_for_forensics="wrapper_internal_error", **common_json)
# Happy path branches: outcome.status in {"ok", "error"} -> proceed to step 12.
```

The two helper symbols (`_record_introspect_failure`, `_utcnow`) live in `server.py`; `_utcnow = lambda: datetime.now(UTC)` if no existing helper. If the test sentinel uses `clock`, route it through `(clock or _utcnow)()` to keep tests deterministic.

- [ ] **Step 9.8: Implement step 12 — redaction post-processing for the happy path**

```python
# Spec §6.3: stdout.json is the parsed-then-redacted-then-reserialized doc.
redacted_payload = redactor.redact_value(parsed)
(agent_dir / "stdout.json").write_text(
    json.dumps(redacted_payload), encoding="utf-8"
)
(agent_dir / "stderr.log").write_text(
    redactor.redact_text(raw_stderr), encoding="utf-8"
)

# Build the response.
emits = redacted_payload.get("emits", [])
user_stdout = redacted_payload.get("user_stdout", "")
truncated = redacted_payload.get("truncated", {})
prelude_ms = redacted_payload.get("prelude_ms", 0)

# Spec §11 open risk 4a: integer-only soft warning.
diagnostic = None
if (prelude_ms * 100
        >= PRELUDE_WARNING_FRACTION_PCT * request.timeout_seconds * 1000):
    diagnostic = (
        f"prelude ({prelude_ms} ms) consumed >= "
        f"{PRELUDE_WARNING_FRACTION_PCT}% of timeout_seconds "
        f"({request.timeout_seconds} s); consider raising timeout_seconds."
    )

status = "script_error" if outcome_status == "error" else "ok"
outcome = (
    {"status": "error", **redacted_payload["outcome"]}
    if status == "script_error"
    else {"status": "ok"}
)

# Snippets — head 2 KiB + tail 2 KiB. Spec §3.2.
user_stdout_snippet = _head_tail(user_stdout, head=2048, tail=2048)
drgn_stderr_snippet = _head_tail(redactor.redact_text(raw_stderr),
                                 head=2048, tail=2048)
```

Implement `_head_tail(s, head, tail)` as a private helper inside `server.py` (no `re` needed):
```python
def _head_tail(s: str, *, head: int, tail: int) -> str:
    if len(s) <= head + tail:
        return s
    return f"{s[:head]}\n…[truncated]…\n{s[-tail:]}"
```

- [ ] **Step 9.9: Implement step 13 — manifest record under the lock**

Per spec §5.2 step 13:
```python
artifacts: list[ArtifactRef] = [
    ArtifactRef(path=str(agent_dir / "request.json"), kind="application/json"),
    ArtifactRef(path=str(agent_dir / "wrapper.skeleton.py"), kind="text/x-python"),
    ArtifactRef(
        path=str(sensitive_dir / "wrapper.py"), kind="text/x-python",
        sensitive=True,
    ),
    ArtifactRef(path=str(agent_dir / "stdout.json"), kind="application/json"),
    ArtifactRef(path=str(agent_dir / "stderr.log"), kind="text/plain"),
]
if (sensitive_dir / "stdout.raw").exists():
    artifacts.append(ArtifactRef(
        path=str(sensitive_dir / "stdout.raw"),
        kind="application/octet-stream", sensitive=True,
    ))

step = StepResult(
    step_name=f"introspect:{call_id}",
    status=StepStatus.SUCCEEDED,
    summary=f"introspect call {call_id[:8]} ok",
    artifacts=artifacts,
    details={
        "call_id": call_id,
        "build_id": redacted_payload.get("build_id"),
        "timeout_seconds": request.timeout_seconds,
        "wrapper_exit_code": ssh_result.exit_status,
        "duration_ms": duration_ms,
        "prelude_ms": prelude_ms,
        "truncated": truncated,
        "ssh_user": resolved_rootfs.ssh_user,
        "outcome_status": outcome_status,  # R4-F3: forensic value
    },
)
_record_terminal_introspect_result(store, run_id, step)
# Now build and return ToolResponse.success(...) per spec §3.2.
```

`_record_terminal_introspect_result` is a small clone of `_record_terminal_build_result` that uses `append=True`:
```python
def _record_terminal_introspect_result(
    store: ArtifactStore, run_id: str, result: StepResult,
    *, attempts: int = 5, initial_delay_seconds: float = 0.01,
) -> None:
    delay = initial_delay_seconds
    for attempt in range(attempts):
        try:
            store.record_step_result(run_id, result, append=True)
            return
        except ManifestStateError as exc:
            if "manifest is locked" not in str(exc) or attempt == attempts - 1:
                raise
            time.sleep(delay)
            delay *= 2
```

- [ ] **Step 9.10: Build the success `ToolResponse`**

Final piece:
```python
public_artifacts = [a for a in artifacts if not a.sensitive]
return ToolResponse.success(
    summary=f"introspect call {call_id[:8]} ok",
    run_id=run_id,
    status=StepStatus.SUCCEEDED,
    artifacts=public_artifacts,
    suggested_next_actions=["artifacts.get_manifest", "debug.introspect.run"],
    data={
        "call_id": call_id,
        "status": status,
        "outcome": outcome,
        "emits": emits,
        "user_stdout_snippet": user_stdout_snippet,
        "drgn_stderr_snippet": drgn_stderr_snippet,
        "build_id": redacted_payload.get("build_id"),
        "truncated": truncated,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_ms": duration_ms,
        "prelude_ms": prelude_ms,
        "artifacts": [a.model_dump(mode="json") for a in public_artifacts],
        "diagnostic": diagnostic,
    },
)
```

Verify `ToolResponse.success` accepts a `data` dict on inspection of `domain.py:209` — it does. The `data` dict is the agent-facing payload.

- [ ] **Step 9.11: Lint, type-check, commit**

```bash
uv run ruff check src tests
uv run ty check src
uv run python -m pytest -q
```

The full test suite should still be green — no introspect tests exist yet beyond the wrapper tests and the mode-0700 test, neither of which the handler should regress.

```bash
git add src/linux_debug_mcp/server.py
git commit -m "server: implement debug_introspect_run_handler"
```

---

## Task 10: Tool registration

**Goal:** Wire the handler into the FastMCP app.

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (inside `create_app`, alongside the other `@app.tool(...)` registrations)

- [ ] **Step 10.1: Write the failing test**

Add to `tests/test_server.py` (extend; do not create):
```python
def test_introspect_tool_is_registered() -> None:
    app = create_app()
    names = {tool.name for tool in app.list_tools()}  # or however the test
                                                       # module discovers tools
    assert "debug.introspect.run" in names
```

Use the same pattern the existing test file uses to discover registered tool names. If a helper exists (e.g. `_registered_tool_names(app)`), use it.

Run: `uv run python -m pytest tests/test_server.py -v -k introspect_tool_is_registered`

Expected: FAIL.

- [ ] **Step 10.2: Register the tool**

Inside `create_app` (server.py:3586 region), alongside the other tool registrations, add:
```python
@app.tool(name="debug.introspect.run")
def debug_introspect_run(
    run_id: str,
    target_ref: str,
    script: str,
    timeout_seconds: int = 30,
    allow_write: bool = False,
    debug_profile: str | None = None,
    target_profile: str | None = None,
    rootfs_profile: str | None = None,
) -> dict[str, object]:
    request = DebugIntrospectRunRequest(
        run_id=run_id, target_ref=target_ref, script=script,
        timeout_seconds=timeout_seconds, allow_write=allow_write,
        debug_profile=debug_profile, target_profile=target_profile,
        rootfs_profile=rootfs_profile,
    )
    return debug_introspect_run_handler(
        request,
        artifact_root=config.artifact_root,
        target_profiles=DEFAULT_TARGET_PROFILES,
        rootfs_profiles=DEFAULT_ROOTFS_PROFILES,
        debug_profiles=DEFAULT_DEBUG_PROFILES,
        admission=admission_service,
        session_registry=session_registry,
    ).model_dump(mode="json")
```

Match whatever symbol names this file uses for the live AdmissionService and session registry; the existing `target.run_tests` registration shows the pattern.

- [ ] **Step 10.3: Run tests**

```bash
uv run python -m pytest tests/test_server.py -v -k introspect_tool_is_registered
uv run python -m pytest -q
```

Expected: all green.

- [ ] **Step 10.4: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server.py
git commit -m "server: register debug.introspect.run tool"
```

---

## Task 11: Handler unit tests — `tests/test_debug_introspect_run.py`

**Goal:** Cover spec §9.1 — every handler test case. The mode-0700 test was added in Task 2; the rest are added here.

**Files:**
- Modify: `tests/test_debug_introspect_run.py` (append to the file created in Task 2)

- [ ] **Step 11.1: Add the fakes and shared fixtures**

At the top of the file (below the existing test from Task 2):
```python
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import (
    ALLOWED_DEBUG_OPERATIONS,
    MAX_INTROSPECT_CALLS_PER_RUN,
    PRELUDE_WARNING_FRACTION_PCT,
    DebugProfile,
)
from linux_debug_mcp.domain import (
    ArtifactRef,
    DebugIntrospectRunRequest,
    ErrorCategory,
    RootfsProfile,
    RunRequest,
    StepResult,
    StepStatus,
    TargetProfile,
    ToolResponse,
)
from linux_debug_mcp.providers.local_ssh_tests import SshCommandResult
from linux_debug_mcp.server import (
    _count_introspect_calls,
    debug_introspect_run_handler,
)


@dataclass
class FakeSshRunner:
    """Mirrors tests/test_local_ssh_tests_provider.py FakeSshRunner. Records
    every call's argv/stdin/timeout for assertion. Returns caller-controlled
    SshCommandResult instances."""
    available: bool = True
    results: list[SshCommandResult] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}" if self.available else None

    def run(self, argv, *, timeout, stdout_path, stderr_path,
            cancel=None, stdin=None) -> SshCommandResult:
        self.calls.append({
            "argv": argv, "timeout": timeout,
            "stdout_path": stdout_path, "stderr_path": stderr_path,
            "stdin": stdin,
        })
        result = (self.results.pop(0) if self.results
                  else SshCommandResult(exit_status=0, stdout="{}", stderr=""))
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        return result


@dataclass
class FakeAdmissionHandle:
    cancel_event: threading.Event = field(default_factory=threading.Event)

    def wait_cancelled(self, timeout: float | None = None) -> bool:
        return self.cancel_event.wait(timeout)


@dataclass
class FakeAdmissionService:
    snapshot: Any = None     # whatever TargetSnapshot shape the real one uses
    admit_raises: BaseException | None = None
    complete_raises: BaseException | None = None
    handle: FakeAdmissionHandle = field(default_factory=FakeAdmissionHandle)

    def current_snapshot(self, target_key):
        return self.snapshot

    def admit_ssh_tier(self, target_key, generation, platform, *,
                       lease=None, execution_proof=None):
        if self.admit_raises is not None:
            raise self.admit_raises
        return self.handle

    def complete(self, handle):
        if self.complete_raises is not None:
            raise self.complete_raises


def _make_request(run_id: str, **overrides) -> DebugIntrospectRunRequest:
    base = {
        "run_id": run_id, "target_ref": "local-qemu",
        "script": "emit({'pid': 1})",
        "timeout_seconds": 30, "allow_write": False,
    }
    base.update(overrides)
    return DebugIntrospectRunRequest(**base)


def _bootstrap_run_with_build(tmp_path: Path) -> tuple[ArtifactStore, str, str]:
    """Create a run and pre-record a SUCCEEDED build step carrying build_id."""
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(RunRequest(run_id="r1"))
    build_id = "0123456789abcdef0123456789abcdef01234567"
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="build", status=StepStatus.SUCCEEDED,
            summary="build ok", artifacts=[],
            details={"build_id": build_id},
        ),
    )
    return store, manifest.run_id, build_id


def _profiles() -> tuple[dict, dict, dict]:
    """Return (target_profiles, rootfs_profiles, debug_profiles) with a root
    ssh_user — bypasses the sudo preflight for the common-case tests."""
    return (
        {"local-qemu": TargetProfile(name="local-qemu", architecture="x86_64",
                                     target_ref="qemu", managed_domain=True,
                                     libvirt_uri="qemu:///system")},
        {"minimal": RootfsProfile(name="minimal", source="x",
                                  mutability="read_only",
                                  readiness_marker="ready",
                                  ssh_host="127.0.0.1", ssh_port=22,
                                  ssh_user="root")},
        {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )
```

Adjust the `RootfsProfile` / `TargetProfile` constructor calls to match the real field set (some may have additional required fields — check `config.py` `RootfsProfile`).

- [ ] **Step 11.2: Add the pre-SSH validation tests**

For each case in spec §9.1, add one focused test. Examples for the simplest cases:

```python
def test_allow_write_rejected(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id, allow_write=True),
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=FakeSshRunner(), admission=FakeAdmissionService(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "allow_write_not_supported"


def test_invalid_timeout_rejected(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id, timeout_seconds=4),  # below the min of 5
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=FakeSshRunner(), admission=FakeAdmissionService(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "invalid_timeout"


def test_provenance_missing_when_manifest_lacks_build_id(tmp_path: Path) -> None:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(RunRequest(run_id="r1"))
    # No build step recorded -> provenance_missing.
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(manifest.run_id),
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=FakeSshRunner(), admission=FakeAdmissionService(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "provenance_missing"
    # Plan review finding 3: the diagnostic must point at `kernel.create_run`,
    # NOT `force_rebuild` (which is rejected at server.py:942-947) and NOT
    # "rerun kernel.build" (which is a no-op on SUCCEEDED at server.py:957).
    assert "kernel.create_run" in response.error.message
    assert "force_rebuild" not in response.error.message


def test_malformed_build_id_in_manifest_rejected(tmp_path: Path) -> None:
    # Spec §9.1 F4: manifest's build_id is "not-hex!" -> provenance_corrupt.
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(RunRequest(run_id="r1"))
    store.record_step_result(
        manifest.run_id,
        StepResult(step_name="build", status=StepStatus.SUCCEEDED,
                   summary="x", artifacts=[],
                   details={"build_id": "not-hex!"}),
    )
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner()
    response = debug_introspect_run_handler(
        _make_request(manifest.run_id),
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=ssh, admission=FakeAdmissionService(),
    )
    assert response.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details["code"] == "provenance_corrupt"
    assert ssh.calls == []   # SSH never invoked.


def test_call_budget_exhausted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Spec §9.1 F5: pre-populate the budget; handler rejects when the
    # introspect-call count meets MAX.
    # Plan review finding 7: pre-populating 1000 entries makes this test O(N^2)
    # in manifest I/O (every record rewrites the manifest). Shrink the budget
    # to a small N via monkeypatch so the pre-population is fast.
    # Why server.* and not config.*: server.py imports the constant by name at
    # module load (`from linux_debug_mcp.config import MAX_INTROSPECT_CALLS_PER_RUN`),
    # so `monkeypatch.setattr` on `config.MAX_…` would NOT affect what
    # `debug_introspect_run_handler` actually sees. The handler's binding is
    # `linux_debug_mcp.server.MAX_INTROSPECT_CALLS_PER_RUN`.
    monkeypatch.setattr(
        "linux_debug_mcp.server.MAX_INTROSPECT_CALLS_PER_RUN", 4,
    )
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    for _ in range(4):
        store.record_step_result(
            run_id,
            StepResult(step_name=f"introspect:{uuid.uuid4().hex}",
                       status=StepStatus.SUCCEEDED, summary="ok",
                       artifacts=[], details={}),
            append=True,
        )
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner()
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=ssh, admission=FakeAdmissionService(),
    )
    assert response.error.details["code"] == "manifest_call_budget_exhausted"
    assert ssh.calls == []
    assert not (store.run_dir(run_id) / "debug" / "introspect").exists()


def test_legacy_sensitive_dir_rejected(tmp_path: Path) -> None:
    # Spec §9.1 R3-F4/R4-F1: a run with sensitive/ at 0755 is rejected.
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    (store.run_dir(run_id) / "sensitive").chmod(0o755)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner()
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=ssh, admission=FakeAdmissionService(),
    )
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "sensitive_dir_too_permissive"
    assert "0o755" in response.error.message or "0o755" in str(response.error.details)
    assert ssh.calls == []   # no SSH at all
    assert not (store.run_dir(run_id) / "debug" / "introspect").exists()
    sensitive_root = store.run_dir(run_id) / "sensitive" / "debug" / "introspect"
    assert not sensitive_root.exists()


def _happy_path_wrapper_json(call_id: str, build_id: str,
                              *, emits: list | None = None,
                              user_stdout: str = "",
                              prelude_ms: int = 35) -> str:
    """Builds the exact JSON shape the wrapper produces on the ok path.
    Used by tests that drive FakeSshRunner."""
    return json.dumps({
        "call_id": call_id, "build_id": build_id,
        "outcome": {"status": "ok"},
        "emits": emits or [], "user_stdout": user_stdout,
        "prelude_ms": prelude_ms,
        "truncated": {"emits": False, "user_stdout": False,
                      "traceback": False, "total_json": False,
                      "per_emit_size": False, "error_message": False},
    })


def test_legacy_sensitive_dir_at_0700_admitted(tmp_path: Path) -> None:
    # Companion to test_legacy_sensitive_dir_rejected: prove the check
    # discriminates exactly at the low-bits boundary (spec §9.1 final sentence
    # of test_legacy_sensitive_dir_rejected). A mode-0700 sensitive/ admits.
    store, run_id, build_id = _bootstrap_run_with_build(tmp_path)
    (store.run_dir(run_id) / "sensitive").chmod(0o700)
    targets, rootfs, debug = _profiles()
    # FakeSshRunner returns one happy-path JSON document; UUID gen is real but
    # we read the call_id out of the response after the fact.
    ssh = FakeSshRunner(results=[
        SshCommandResult(
            exit_status=6,
            stdout=_happy_path_wrapper_json("00" * 16, build_id),
            stderr="",
        ),
    ])
    admission = FakeAdmissionService(
        snapshot=_make_snapshot(run_id),   # helper defined below
    )
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=ssh, admission=admission,
    )
    assert response.ok is True
    assert response.data["status"] == "ok"
```

Add `_make_snapshot(run_id)` as a helper near the top of the test module. It returns whatever shape `AdmissionService.current_snapshot` returns today — read `coordination/admission.py` `TargetSnapshot` to match. The FakeAdmissionService just hands this back unchanged.

Add each of the remaining §9.1 tests with a full body. Below are concrete bodies for the three trickiest tests; the rest follow the same pattern (bootstrap, fakes, call, assert) and are mechanical from §9.1's prose.

```python
def test_prelude_warning_at_threshold_boundary(tmp_path: Path) -> None:
    """Spec §11 open risk 4a (R2-F1): integer-only soft warning fires when
    `prelude_ms * 100 >= PRELUDE_WARNING_FRACTION_PCT * timeout_seconds * 1000`.
    At default PCT=40 and timeout_seconds=10: threshold = 4000 ms.
    """
    store, run_id, build_id = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()

    # Case A: prelude_ms=4000, timeout=10 -> 400_000 >= 400_000 -> warns.
    ssh_warns = FakeSshRunner(results=[
        SshCommandResult(
            exit_status=6,
            stdout=_happy_path_wrapper_json("00" * 16, build_id, prelude_ms=4000),
            stderr="",
        ),
    ])
    warns = debug_introspect_run_handler(
        _make_request(run_id, timeout_seconds=10),
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=ssh_warns,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
    )
    assert warns.ok is True
    assert warns.data["diagnostic"] is not None
    assert "prelude" in warns.data["diagnostic"]

    # Case B: prelude_ms=3999, timeout=10 -> 399_900 >= 400_000 false -> silent.
    # Use a second run_id so the call budget / manifest is clean.
    store2 = ArtifactStore(artifact_root=tmp_path)
    manifest2 = store2.create_run(RunRequest(run_id="r2"))
    store2.record_step_result(
        manifest2.run_id,
        StepResult(step_name="build", status=StepStatus.SUCCEEDED, summary="ok",
                   artifacts=[], details={"build_id": build_id}),
    )
    ssh_silent = FakeSshRunner(results=[
        SshCommandResult(
            exit_status=6,
            stdout=_happy_path_wrapper_json("11" * 16, build_id, prelude_ms=3999),
            stderr="",
        ),
    ])
    silent = debug_introspect_run_handler(
        _make_request(manifest2.run_id, timeout_seconds=10),
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=ssh_silent,
        admission=FakeAdmissionService(snapshot=_make_snapshot(manifest2.run_id)),
    )
    assert silent.ok is True
    assert silent.data["diagnostic"] is None


def test_sudo_preflight_diagnostic_is_redacted(tmp_path: Path) -> None:
    """Spec §9.1 F7 + R2-F3: redact BEFORE truncate to 256 B. Two arrangements
    — secret contained inside the captured stderr, and secret straddling byte
    256 — both must end up with the secret fully replaced by `[REDACTED]`.
    """
    from linux_debug_mcp.safety.redaction import REDACTION

    # Sub-case 1: secret is contained well within 256 B.
    secret = "s3cret-key-material"  # pragma: allowlist secret
    rootfs = {"minimal": RootfsProfile(
        name="minimal", source="x", mutability="read_only",
        readiness_marker="ready", ssh_host="127.0.0.1", ssh_port=22,
        ssh_user="bob", ssh_key_ref=secret,
    )}
    targets, _, debug = _profiles()
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    ssh = FakeSshRunner(results=[
        # Preflight: non-zero with the secret embedded in stderr.
        SshCommandResult(exit_status=1, stdout="", stderr=f"sudo: a password is required for {secret}"),
    ])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=ssh, admission=FakeAdmissionService(),
    )
    assert response.error.details["code"] == "sudo_requires_password"
    assert secret not in response.error.message
    assert REDACTION in response.error.message

    # Sub-case 2 (boundary, R2-F3): secret straddles byte 256 — without
    # redact-before-truncate the diagnostic would carry a partial prefix.
    pad = "X" * (256 - len(secret) // 2)        # half of secret straddles cap
    long_stderr = pad + secret + "tail-suffix"
    ssh2 = FakeSshRunner(results=[
        SshCommandResult(exit_status=1, stdout="", stderr=long_stderr),
    ])
    store2 = ArtifactStore(artifact_root=tmp_path)
    manifest2 = store2.create_run(RunRequest(run_id="rs2"))
    store2.record_step_result(
        manifest2.run_id,
        StepResult(step_name="build", status=StepStatus.SUCCEEDED, summary="ok",
                   artifacts=[], details={"build_id": "0" * 40}),
    )
    response2 = debug_introspect_run_handler(
        _make_request(manifest2.run_id),
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=ssh2, admission=FakeAdmissionService(),
    )
    assert response2.error.details["code"] == "sudo_requires_password"
    # The full secret must not appear; no prefix-only fragment either.
    assert secret not in response2.error.message
    for window in range(4, len(secret)):
        assert secret[:window] not in response2.error.message, (
            f"redact-before-truncate violated: prefix {secret[:window]!r} leaked"
        )


def test_failure_record_preserves_request_timeout_and_measures_duration(
    tmp_path: Path,
) -> None:
    """Plan review findings 2 & 5: the FAILED step record must carry

    - `details.timeout_seconds` == the caller's *request budget*, NOT elapsed
      wall-clock time. Spec §6.2 says the success and failure record shapes are
      symmetric on this field.
    - `details.duration_ms` == the measured wall-clock duration in ms.
    - `details.ssh_user` == the resolved rootfs profile's ssh_user (never the
      literal string "unknown" — the previous placeholder leaked through every
      failure path that did not populate `extra_details`).
    """
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()  # rootfs ssh_user defaults to "root"
    ssh = FakeSshRunner(results=[
        # exit_status=124 with empty stdout drives the introspect_timeout branch
        # — one of the failure paths that previously fell through with
        # ssh_user="unknown".
        SshCommandResult(exit_status=124, stdout="", stderr=""),
    ])
    admission = FakeAdmissionService(snapshot=_make_snapshot(run_id))
    response = debug_introspect_run_handler(
        _make_request(run_id, timeout_seconds=30),
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=ssh, admission=admission,
    )
    assert response.ok is False
    assert response.error.details["code"] == "introspect_timeout"

    manifest = store.load_manifest(run_id)
    introspect_step = next(
        s for k, s in manifest.step_results.items()
        if k.startswith("introspect:")
    )
    # Finding 2: budget vs elapsed split.
    assert introspect_step.details["timeout_seconds"] == 30
    assert isinstance(introspect_step.details["duration_ms"], int)
    assert introspect_step.details["duration_ms"] >= 0
    # Finding 5: ssh_user is the resolved profile's user, never "unknown".
    assert introspect_step.details["ssh_user"] == "root"
    assert introspect_step.details["ssh_user"] != "unknown"


def test_budget_soft_cap_overshoot_under_concurrency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Spec §9.1 / R2-F5 / R3-F5: prove the soft-cap framing.

    Pre-populate MAX-1 entries. Monkey-patch `_count_introspect_calls` to
    return MAX-1 for its first TWO invocations (simulating two callers that
    raced the budget gate); both calls succeed and write, landing the manifest
    at MAX+1. A third call observes the real count >= MAX and is rejected.
    """
    import linux_debug_mcp.server as server_module

    # Plan review finding 7: pre-populating 999 entries makes this test O(N^2)
    # in manifest I/O (every record rewrites the manifest). Shrink the budget
    # to a small N via monkeypatch so the pre-population is fast.
    # Why server.* and not config.*: server.py imports the constant by name at
    # module load (`from linux_debug_mcp.config import MAX_INTROSPECT_CALLS_PER_RUN`),
    # so `monkeypatch.setattr` on `config.MAX_…` would NOT affect what
    # `debug_introspect_run_handler` actually sees. The handler's binding is
    # `linux_debug_mcp.server.MAX_INTROSPECT_CALLS_PER_RUN`.
    monkeypatch.setattr(server_module, "MAX_INTROSPECT_CALLS_PER_RUN", 4)
    budget = server_module.MAX_INTROSPECT_CALLS_PER_RUN   # = 4 after patch

    store, run_id, build_id = _bootstrap_run_with_build(tmp_path)
    for _ in range(budget - 1):
        store.record_step_result(
            run_id,
            StepResult(step_name=f"introspect:{uuid.uuid4().hex}",
                       status=StepStatus.SUCCEEDED, summary="ok",
                       artifacts=[], details={}),
            append=True,
        )

    targets, rootfs, debug = _profiles()
    real_count = server_module._count_introspect_calls
    call_log = {"n": 0}

    def stubbed_count(manifest):
        call_log["n"] += 1
        if call_log["n"] <= 2:
            return budget - 1
        return real_count(manifest)

    monkeypatch.setattr(server_module, "_count_introspect_calls", stubbed_count)

    admission = FakeAdmissionService(snapshot=_make_snapshot(run_id))
    for i in range(2):
        ssh = FakeSshRunner(results=[
            SshCommandResult(
                exit_status=6,
                stdout=_happy_path_wrapper_json(f"{i:032x}", build_id),
                stderr="",
            ),
        ])
        response = debug_introspect_run_handler(
            _make_request(run_id),
            artifact_root=tmp_path,
            target_profiles=targets, rootfs_profiles=rootfs,
            debug_profiles=debug, ssh_runner=ssh, admission=admission,
        )
        assert response.ok is True, f"call {i} expected ok, got {response.error}"

    # Manifest has budget + 1 introspect entries (overshoot by 1).
    manifest = store.load_manifest(run_id)
    introspect_count = sum(
        1 for name in manifest.step_results if name.startswith("introspect:")
    )
    assert introspect_count == budget + 1

    # Third call, no monkey-patch trickery: real count is budget+1 >= budget -> reject.
    ssh3 = FakeSshRunner()
    response3 = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets, rootfs_profiles=rootfs, debug_profiles=debug,
        ssh_runner=ssh3, admission=admission,
    )
    assert response3.error.details["code"] == "manifest_call_budget_exhausted"
    assert ssh3.calls == []
```

Add the remaining §9.1 tests, each with a complete body. They are mechanical applications of the pattern (bootstrap → fakes → call → assert). The full list, with the FakeSshRunner / FakeAdmissionService configuration each one needs:

| Test name | FakeSshRunner / FakeAdmissionService setup | Assertion |
|---|---|---|
| `test_invalid_script_rejected` | n/a (rejected pre-SSH) | one assertion for empty `script=""`; one for `script="x"*300_000` (over `SCRIPT_BYTE_CAP`); both → `details["code"]=="invalid_script"` |
| `test_operation_disabled_in_profile` | n/a | pass `debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default", enabled_operations=[])}` → `details["code"]=="operation_disabled"` |
| `test_admit_rejects_halted` | `admission.admit_raises=AdmissionError("target_halted", code="target_halted")` | `< 100 ms`; `error.code=="target_halted"`; FakeSshRunner.calls=[] |
| `test_admission_complete_raises_execution_state_changed` | `admission.complete_raises=AdmissionError("execution_state_changed", code="execution_state_changed")` | response is failure; partial result discarded |
| `test_wrapper_exit_3_drgn_open_failure` | results=[SshCommandResult(exit_status=3, stdout=json with `outcome.status="drgn_open_failure"`)] | `details["code"]=="drgn_open_failure"` |
| `test_wrapper_exit_4_provenance_mismatch` | exit_status=4, outcome.status="provenance_mismatch" | `details["code"]=="provenance_mismatch"` |
| `test_wrapper_exit_5_script_compile_error` | exit_status=5, outcome.status="script_compile_error" | `details["code"]=="script_compile_error"` |
| `test_wrapper_exit_124_introspect_timeout` | exit_status=124, stdout="" | `details["code"]=="introspect_timeout"` |
| `test_wrapper_crash_no_json` | exit_status=0, stdout="garbage that is not JSON" | `details["code"]=="wrapper_crash"`; `<run>/sensitive/debug/introspect/<call_id>/stdout.raw` exists; agent-facing `stdout.json` does not |
| `test_ssh_timeout_propagates` | `SshCommandResult(timed_out=True)` | `details["code"]=="ssh_timeout"` |
| `test_timeout_propagates_to_runner` | inspect `ssh.calls[-1]["cancel"]`; set it; verify it propagated | the cancel Event was forwarded |
| `test_host_backstop_on_oversize_stdout` | `stdout="A" * (8 * 1024 * 1024)` | host-side max-bytes backstop triggers `wrapper_crash` (or rejects with a specific code if the handler implements a separate `stdout_too_large` code) |
| `test_redactor_applied_to_emits_and_snippets` | rootfs_profile.ssh_key_ref=secret; stdout includes `secret` inside `emits`, `user_stdout`, `outcome.error_message` | secret absent from response and `result.json` / `stdout.json` on disk |
| `test_step_result_recorded_with_introspect_call_id_name` | happy path | `manifest.step_results` keys include `introspect:<call_id>` exactly |
| `test_sudo_preflight_returns_actionable_error_on_password_prompt` | rootfs.ssh_user="bob"; ssh.results=[SshCommandResult(exit_status=1, stderr="sudo: a password is required")]  | `details["code"]=="sudo_requires_password"`; FakeSshRunner.calls has ONE entry (preflight only — wrapper not invoked) |
| `test_wrapper_py_written_under_sensitive_with_0600` | happy path | `<run>/sensitive/debug/introspect/<call_id>/wrapper.py` exists; mode `0o600` |
| `test_response_artifacts_omit_wrapper_py` | happy path | response.artifacts paths contain `wrapper.skeleton.py` and not `wrapper.py`; step record's `artifacts` includes a `sensitive=True` entry for `wrapper.py` |
| `test_no_orphan_artifacts_on_admission_failure` | `admission.admit_raises=AdmissionError("target_halted")` | no `<run>/debug/introspect/<call_id>/` or `<run>/sensitive/debug/introspect/<call_id>/`; `response.data` has no `call_id` key |

Every row is a separate `def test_…`. **No row may be skipped.** Each one is the spec's contract; missing one breaks the acceptance-criteria mapping in §10 of the spec.

- [ ] **Step 11.3: Run the handler tests**

```bash
uv run python -m pytest tests/test_debug_introspect_run.py -v
```

Iterate until all green. Expect to discover small mismatches between the spec and the handler — fix the handler when the spec is correct; surface a spec ambiguity in this plan's `## Open questions` block (add it; don't silently diverge).

- [ ] **Step 11.4: Final gates + commit**

```bash
uv run python -m pytest -q
uv run ruff check src tests && uv run ruff format --check src tests
uv run ty check src
just check-docs
```

All green.

```bash
git add tests/test_debug_introspect_run.py
git commit -m "tests: debug_introspect_run_handler unit tests (spec §9.1)"
```

---

## Task 12: Integration test — `tests/test_drgn_introspect_integration.py`

**Goal:** End-to-end coverage against a real boot. Gated like `test_libvirt_boot_integration.py` and `test_qemu_gdbstub_integration.py` so CI without QEMU + drgn + libvirt skips cleanly.

**Files:**
- Create: `tests/test_drgn_introspect_integration.py`

- [ ] **Step 12.1: Add the skip gate and shared fixtures**

```python
"""Integration tests for debug.introspect.run. Spec §9.3.

Gated on:
  - `which drgn` (target-side; this test SSHs into the smoke VM)
  - `which qemu-system-x86_64`
  - `which virsh`
  - LINUX_DEBUG_MCP_LIBVIRT_TEST=1 environment variable.
"""

import os
import shutil

import pytest

from linux_debug_mcp.domain import DebugIntrospectRunRequest
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
            f"{', '.join(missing)} to run it."
        )
```

- [ ] **Step 12.2: Add the three integration tests**

Each test reuses the existing `kernel.create_run` → `kernel.build` → `target.boot` bootstrap from `test_libvirt_boot_integration.py`. The bootstrap helper there builds a small kernel and boots the smoke VM with SSH wired up. Copy/extract whatever fixture/helper that file uses (`_bootstrap_booted_run(tmp_path)` or similar) — do not duplicate the boot logic inline. Once the smoke VM is up, calling `debug_introspect_run_handler` with the **real** `LocalDrgnIntrospectProvider`, real `SshRunner`, and the live `AdmissionService` exercises the end-to-end path.

```python
def test_introspect_emit_roundtrip(tmp_path: Path) -> None:
    _require_integration_env()
    run_id, store, admission, session_registry = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=run_id, target_ref="local-qemu",
        script='emit({"pid": 1})',
        timeout_seconds=30,
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path,
        target_profiles=DEFAULT_TARGET_PROFILES,
        rootfs_profiles=DEFAULT_ROOTFS_PROFILES,
        debug_profiles=DEFAULT_DEBUG_PROFILES,
        admission=admission,
        session_registry=session_registry,
    )
    assert response.ok is True, response.error
    assert response.data["status"] == "ok"
    assert response.data["emits"] == [{"pid": 1}]


def test_introspect_target_side_timeout(tmp_path: Path) -> None:
    _require_integration_env()
    run_id, store, admission, session_registry = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=run_id, target_ref="local-qemu",
        script="while True:\n    pass\n",
        timeout_seconds=5,
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path,
        target_profiles=DEFAULT_TARGET_PROFILES,
        rootfs_profiles=DEFAULT_ROOTFS_PROFILES,
        debug_profiles=DEFAULT_DEBUG_PROFILES,
        admission=admission,
        session_registry=session_registry,
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details["code"] == "introspect_timeout"


def test_introspect_build_id_round_trips(tmp_path: Path) -> None:
    _require_integration_env()
    run_id, store, admission, session_registry = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=run_id, target_ref="local-qemu",
        script="emit({})",
        timeout_seconds=30,
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path,
        target_profiles=DEFAULT_TARGET_PROFILES,
        rootfs_profiles=DEFAULT_ROOTFS_PROFILES,
        debug_profiles=DEFAULT_DEBUG_PROFILES,
        admission=admission,
        session_registry=session_registry,
    )
    assert response.ok is True, response.error
    manifest = store.load_manifest(run_id)
    recorded = manifest.step_results["build"].details["build_id"]
    assert response.data["build_id"] == recorded
```

Adjust the imports at the top of the file (`DEFAULT_TARGET_PROFILES`, `DEFAULT_ROOTFS_PROFILES`, etc.) to match what `server.py` actually exports — they may not be importable today; if not, mirror the constructor sequence from `_bootstrap_booted_run` to provide them inline.

- [ ] **Step 12.3: Run (will skip on CI without the gates)**

```bash
LINUX_DEBUG_MCP_LIBVIRT_TEST=1 uv run python -m pytest tests/test_drgn_introspect_integration.py -v
```

On a developer machine with the smoke VM and drgn installed, all three should pass. On bare CI, all three should `SKIPPED`.

- [ ] **Step 12.4: Commit**

```bash
git add tests/test_drgn_introspect_integration.py
git commit -m "tests: drgn introspect end-to-end integration (gated)"
```

---

## Task 13: Final verification & cleanup

**Goal:** Ratify the change — every gate green, tool surface live, docs honest.

- [ ] **Step 13.1: Run every gate from a clean state**

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run ty check src
uv run python -m pytest -q
just check-host          # informational; expected to surface readelf as present
just check-docs          # forbids "sprint*" in README.md / docs/ outside docs/superpowers/
pre-commit run --files $(git diff --name-only origin/main...HEAD)
```

All green.

- [ ] **Step 13.2: Stdio smoke**

```bash
timeout 2 uv run linux-debug-mcp || test $? -eq 124
```

Expected exit 124 (the server stays up until killed). If the server crashes on import or initial registration, fix it before continuing — most likely cause is a missing import inside server.py for the new symbols.

- [ ] **Step 13.3: Manual MCP-level smoke (optional, recommended)**

Verify `providers.list` advertises `local-drgn-introspect` and `debug.introspect.run` shows up in `tools.list`. Use the existing MCP smoke harness (see project docs for how the team exercises stdio + MCP locally).

- [ ] **Step 13.4: Check open-issue alignment**

Run:
```bash
gh issue view 51        # the introspect foundation issue
gh issue list --label epic-9
```

Confirm acceptance criteria on #51 map to the tests added in §10 of the spec; cross-check.

- [ ] **Step 13.5: Final commit (if any straggler changes) and create the PR**

```bash
git status
# If anything still uncommitted: make a single cleanup commit, then:
gh pr create --title "feat(debug): debug.introspect.run live drgn-over-SSH runner (#51)" \
             --body-file <(cat <<'EOF'
## Summary

Adds the foundation tier of Epic #9's structured-debug surface:
`debug.introspect.run`, a per-call drgn-over-SSH runner that fences against
the live target's `build_id`, redacts every diagnostic, and lands one
`introspect:<call_id>` StepResult per call.

## Test plan

- [x] `uv run python -m pytest -q`
- [x] `uv run ruff check src tests && uv run ty check src`
- [x] `just check-docs` (no `sprint*` outside `docs/superpowers/`)
- [x] `timeout 2 uv run linux-debug-mcp || test $? -eq 124`
- [ ] Integration gated on local QEMU + drgn: see `tests/test_drgn_introspect_integration.py`.

## Spec

`docs/superpowers/specs/2026-05-28-debug-introspect-run-design.md` (907 lines, 4 rounds of /challenge).
EOF
)
```

---

## Open questions / risks surfaced during implementation

(Append to this section as the implementation reveals spec ambiguities. If empty at the end, delete the section.)

- *placeholder*

---

## Acceptance criteria mapping

| Spec criterion | Plan task |
|---|---|
| `ALLOWED_DEBUG_OPERATIONS` includes `debug.introspect.run` | Task 1 |
| `<run>/sensitive/` is `0700` on every new run | Task 2 |
| Manifest can grow `introspect:<call_id>` entries without replacement | Task 3 |
| `manifest.steps["build"].details["build_id"]` populated; failure modes distinct | Task 4 |
| Wire model `DebugIntrospectRunRequest` (extra="forbid") | Task 5 |
| Wrapper template + render helpers + capability factory | Task 6 |
| `local-drgn-introspect` advertised via `providers.list` | Task 7 |
| Wrapper exit-code contract, R2-F2 / R3-F2 / R2-F8 / R4-F4 fixes | Task 8 |
| Handler implements every step in spec §5.2 | Task 9 |
| `debug.introspect.run` exposed via FastMCP | Task 10 |
| All 24 §9.1 test cases | Task 11 |
| All 3 §9.3 integration tests (gated) | Task 12 |
| All gates green; stdio smoke; PR open | Task 13 |
