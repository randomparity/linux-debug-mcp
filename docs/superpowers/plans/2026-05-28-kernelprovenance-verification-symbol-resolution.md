# KernelProvenance verification + symbol resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the shared build_id verifier + vmlinux/modules resolver seam, a local-qemu boot-capture adapter that records a `KernelProvenance` into the manifest, and a re-point of the live `debug.introspect.run` handler so its expected `build_id` flows from that authoritative boot record.

**Architecture:** A new pure host-side library `src/linux_debug_mcp/symbols/` holds two independent units — `verify.py` (a pure build_id equality check, the one rule both live and offline callers share) and `resolve.py` (a run-sandbox-confined vmlinux/modules locator for the offline path). Path confinement is added once to the existing leaf `safety/paths.py` as `confine_run_relative`. The boot-capture adapter stays in `server.py` next to the existing boot snapshot adapter, folding a synthesized `KernelProvenance` into the boot `StepResult.details` at construction time (single write, SUCCEEDED branch only). The live handler re-points its `EXPECTED_BUILD_ID` source from the build step to the boot-recorded provenance and adds a host-side `verify_build_id` call on the wrapper's returned id.

**Tech Stack:** Python 3.11+, pydantic v2 models (`domain.py`, `seams/target.py`), pytest, ruff, `ty`. No new dependencies.

**Source of truth:** `docs/superpowers/specs/2026-05-28-kernelprovenance-verification-symbol-resolution-design.md` (§ references below point into it). Interface contract: `docs/specs/interface-contracts.md` §4.2.

---

## Discrepancy this plan corrects (read before starting)

Design §3 sources `cmdline` from `boot details["kernel_args"]`. In the current code the libvirt provider's **success** boot details (`src/linux_debug_mcp/providers/libvirt_qemu.py:466-475`) do **not** include `kernel_args`; only the on-disk boot plan (`:665`) carries the assembled args. **Task 5** adds `kernel_args` to the success details so the capture adapter (Task 6) reads a real assembled cmdline. Do Task 5 before Task 6.

## Verified anchors (clean reads, current `HEAD`)

- `KernelProvenance` model: `src/linux_debug_mcp/seams/target.py:84-90` — fields `build_id, release, vmlinux_ref, modules_ref (opt), cmdline, config_ref (opt)`; inherits `Model` (`extra="forbid"`, `validate_assignment=True`).
- `_BUILD_ID_RE = re.compile(r"^[0-9a-f]{8,}$")`: defined at `src/linux_debug_mcp/providers/local_drgn_introspect.py:24`, used `:240`, `:271`; imported into `server.py:91` and used at `server.py:2441`.
- Live introspect build_id sourcing: `server.py:2421-2447` (reads `build_step.details["build_id"]`, emits `provenance_missing` / `provenance_corrupt`).
- Wrapper render call: `server.py:2604-2613` (`render_wrapper(..., expected_build_id=build_id, ...)`).
- Wrapper outcome discrimination: `server.py:2899-2950`; in-wrapper `provenance_mismatch` handled at `:2923`. Happy-path redacted payload + `stdout.json` write at `:2952-2953`; the wrapper-reported id is `redacted_payload["build_id"]` (`:3018`).
- Boot terminal StepResult construction: `server.py:1603-1609` (`details={**execution.details, "kernel_image_path": str(kernel_image.path)}`). `record_boot_attempt` at `:1616`; `_publish_boot_ready_snapshot` at `:1618` (runs AFTER the record — do not capture there).
- `_find_artifact(result, kind)`: `server.py:615-619`.
- Build records `details["kernel_release"]` (`local_kernel_build.py:348`), `details["build_id"]` (`:392`); artifacts `kernel-config`, `kernel-image`, `vmlinux` (`:417-425`). Build output dir is wired in `server.py:1182` as `output_path=run_dir / "build"`, so recorded artifact paths are absolute under `<run>/build/` (e.g. `<run>/build/vmlinux`, `<run>/build/.config`). The run dir comes from `ArtifactStore.run_dir(run_id)` (`artifacts/store.py:158`).
- `safety/paths.py`: `PathSafetyError`, `_is_relative_to`, `_resolve_existing_or_parent`, `validate_*` family — no `confine_run_relative` yet.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/linux_debug_mcp/safety/paths.py` (modify) | add `confine_run_relative(ref, *, run_dir) -> Path` — single canonical run-sandbox guard |
| `src/linux_debug_mcp/symbols/__init__.py` (create) | package marker; re-export public API |
| `src/linux_debug_mcp/symbols/verify.py` (create) | `BUILD_ID_RE`, `ProvenanceMismatch`, `verify_build_id` |
| `src/linux_debug_mcp/symbols/resolve.py` (create) | `ResolutionWarning`, `ResolvedSymbols`, `SymbolResolutionError`, `resolve_symbols` |
| `src/linux_debug_mcp/providers/local_drgn_introspect.py` (modify) | delete local `_BUILD_ID_RE`, import shared `BUILD_ID_RE` |
| `src/linux_debug_mcp/providers/libvirt_qemu.py` (modify) | record `kernel_args` in success boot details |
| `src/linux_debug_mcp/server.py` (modify) | delete imported `_BUILD_ID_RE` use → shared; add `_capture_kernel_provenance`; fold into boot details; re-point live handler + host-side verify |

Test files (create): `tests/test_confine_run_relative.py`, `tests/test_symbols_verify.py`, `tests/test_symbols_resolve.py`, `tests/test_kernel_provenance_capture.py`.
Existing test files extended: `tests/test_libvirt_qemu_provider.py` (Task 5, success-details `kernel_args`), and the introspect handler module re-pointed in Task 7 Step 0.

---

## Task 1: `confine_run_relative` in `safety/paths.py`

**Files:**
- Modify: `src/linux_debug_mcp/safety/paths.py`
- Test: `tests/test_confine_run_relative.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_confine_run_relative.py
from __future__ import annotations

import pytest

from linux_debug_mcp.safety.paths import PathSafetyError, confine_run_relative


def test_resolves_existing_relative_file(tmp_path):
    run_dir = tmp_path / "run"
    (run_dir / "build").mkdir(parents=True)
    target = run_dir / "build" / "vmlinux"
    target.write_text("elf", encoding="utf-8")
    resolved = confine_run_relative("build/vmlinux", run_dir=run_dir)
    assert resolved == target.resolve()


def test_missing_relative_file_still_confined(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    resolved = confine_run_relative("build/vmlinux", run_dir=run_dir)
    assert resolved == (run_dir / "build" / "vmlinux").resolve()


def test_dotdot_escape_rejected(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    with pytest.raises(PathSafetyError):
        confine_run_relative("../escape", run_dir=run_dir)


def test_absolute_override_rejected(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    with pytest.raises(PathSafetyError):
        confine_run_relative("/etc/passwd", run_dir=run_dir)


def test_symlink_escape_rejected(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    # The escaping component is the symlink `link` itself: resolve() collapses
    # it to `outside`, which is not under run_dir. Asserting on the resolved
    # parent makes the test fail for the right reason if resolve() semantics shift.
    (run_dir / "link").symlink_to(outside)
    assert (run_dir / "link").resolve() == outside.resolve()  # precondition
    with pytest.raises(PathSafetyError):
        confine_run_relative("link/secret", run_dir=run_dir)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_confine_run_relative.py -q`
Expected: FAIL with `ImportError: cannot import name 'confine_run_relative'`.

- [ ] **Step 3: Add the implementation**

Append to `src/linux_debug_mcp/safety/paths.py` (after `validate_secret_file_reference`):

```python
def confine_run_relative(ref: str, *, run_dir: Path) -> Path:
    """Resolve a run-relative *ref* and confine it under *run_dir*.

    Rejects absolute overrides, ``..`` traversal, and symlink escapes by
    resolving the joined path and requiring the result to stay under the
    resolved run directory. The path need not exist; existence is the
    caller's concern.
    """
    run_root = run_dir.resolve()
    resolved = (run_root / ref).resolve()
    if not _is_relative_to(resolved, run_root):
        raise PathSafetyError(f"path escapes run sandbox: {ref!r}")
    return resolved
```

**Safety model (state this in the implementation docstring / commit body).** The guard's safety rests entirely on `Path.resolve()` collapsing symlinks in path components *that exist on disk* — a symlink in an existing component is followed and the escaped target is caught by the `_is_relative_to` check. Two boundaries the caller must understand: (a) it is a **point-in-time** check — a TOCTOU window exists between confining a ref and using the resolved path, so callers that act on the path much later should re-confine or hold a lock (out of scope for this seam, which resolves-and-immediately-stats); (b) for a ref whose components do **not** yet exist, `resolve()` (non-strict on 3.11+) normalizes `..` lexically and cannot follow a symlink that isn't there yet. This matches the resolver's usage (`resolve_symbols` confines then immediately `is_file()`-checks, Task 4) and the boot adapter's usage (confines a path it just recorded). It is **not** a guard against an adversary who can plant symlinks inside `run_dir` between confine and use — the run sandbox is server-owned, so that is not in this seam's threat model.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_confine_run_relative.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Lint + types**

Run: `just lint && uv run ty check src`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/safety/paths.py tests/test_confine_run_relative.py
git commit -m "feat(safety): add confine_run_relative run-sandbox guard (#53)"
```

---

## Task 2: `symbols/verify.py` — shared build_id verifier

**Files:**
- Create: `src/linux_debug_mcp/symbols/__init__.py`
- Create: `src/linux_debug_mcp/symbols/verify.py`
- Test: `tests/test_symbols_verify.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_symbols_verify.py
from __future__ import annotations

import pytest

from linux_debug_mcp.symbols.verify import (
    BUILD_ID_RE,
    ProvenanceMismatch,
    verify_build_id,
)

FULL = "a" * 40


def test_equal_ids_do_not_raise():
    verify_build_id(expected=FULL, observed=FULL)


def test_mismatch_raises_carrying_both_ids():
    other = "b" * 40
    with pytest.raises(ProvenanceMismatch) as excinfo:
        verify_build_id(expected=FULL, observed=other)
    assert excinfo.value.expected == FULL
    assert excinfo.value.observed == other


def test_prefix_of_same_build_is_a_mismatch():
    # The no-truncation contract: a prefix of the same build_id is NOT equal.
    with pytest.raises(ProvenanceMismatch):
        verify_build_id(expected=FULL, observed=FULL[:16])


@pytest.mark.parametrize("bad", ["", "abc", "A" * 40, "g" * 40, "12 34"])
def test_build_id_re_rejects_malformed(bad):
    assert BUILD_ID_RE.match(bad) is None


@pytest.mark.parametrize("good", ["a" * 8, "0123456789abcdef", "f" * 64])
def test_build_id_re_accepts_canonical(good):
    assert BUILD_ID_RE.match(good) is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_symbols_verify.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'linux_debug_mcp.symbols'`.

- [ ] **Step 3: Create the package and verifier**

`src/linux_debug_mcp/symbols/__init__.py`:

```python
from __future__ import annotations

from linux_debug_mcp.symbols.verify import (
    BUILD_ID_RE,
    ProvenanceMismatch,
    verify_build_id,
)

__all__ = ["BUILD_ID_RE", "ProvenanceMismatch", "verify_build_id"]
```

`src/linux_debug_mcp/symbols/verify.py`:

```python
from __future__ import annotations

import re

BUILD_ID_RE = re.compile(r"^[0-9a-f]{8,}$")


class ProvenanceMismatch(Exception):
    """Raised when an observed build_id does not equal the expected build_id.

    Both ids are opaque lower-case hex and safe to surface to callers.
    """

    def __init__(self, *, expected: str, observed: str) -> None:
        super().__init__(f"build_id mismatch: expected {expected!r}, observed {observed!r}")
        self.expected = expected
        self.observed = observed


def verify_build_id(*, expected: str, observed: str) -> None:
    """Raise :class:`ProvenanceMismatch` if *observed* != *expected*.

    Both MUST be the full canonical lower-case build-id (never a prefix).
    Shape validation is the caller's job (see :data:`BUILD_ID_RE`); this
    function decides equality only — the one rule both the live and offline
    callers share.
    """
    if observed != expected:
        raise ProvenanceMismatch(expected=expected, observed=observed)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_symbols_verify.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + types**

Run: `just lint && uv run ty check src`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/symbols/__init__.py src/linux_debug_mcp/symbols/verify.py tests/test_symbols_verify.py
git commit -m "feat(symbols): add shared build_id verifier (#53)"
```

---

## Task 3: Collapse duplicate `_BUILD_ID_RE` onto the shared constant

Design §1: "One constant, not three." Replace the duplicate regexes in `local_drgn_introspect.py` and `server.py` with the shared `BUILD_ID_RE` from `symbols/verify.py`.

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_drgn_introspect.py:24,240,271`
- Modify: `src/linux_debug_mcp/server.py:91,2441`

- [ ] **Step 1: Re-point `local_drgn_introspect.py`**

Delete the line at `src/linux_debug_mcp/providers/local_drgn_introspect.py:24`:

```python
_BUILD_ID_RE = re.compile(r"^[0-9a-f]{8,}$")
```

Add an import near the top of the file's import block:

```python
from linux_debug_mcp.symbols.verify import BUILD_ID_RE
```

Then replace both usages (`:240`, `:271`) — change `_BUILD_ID_RE` to `BUILD_ID_RE`:

```python
    if not BUILD_ID_RE.match(expected_build_id):
        raise WrapperRenderError(f"expected_build_id must match {BUILD_ID_RE.pattern}; got {expected_build_id!r}")
```

If `re` is now unused in this module, remove the `import re`. Confirm with: `rg -n '\bre\.' src/linux_debug_mcp/providers/local_drgn_introspect.py`.

- [ ] **Step 2: Re-point `server.py`**

In `server.py`, the import block around `:91` currently imports `_BUILD_ID_RE` from `providers.local_drgn_introspect`. Remove `_BUILD_ID_RE` from that import list and add:

```python
from linux_debug_mcp.symbols.verify import BUILD_ID_RE
```

Change the usage at `server.py:2441`:

```python
    if not isinstance(build_id, str) or not BUILD_ID_RE.match(build_id):
```

- [ ] **Step 3: Confirm no stale references**

Run: `rg -n '_BUILD_ID_RE' src/`
Expected: no matches.

- [ ] **Step 4: Run the affected test suites**

Run: `uv run python -m pytest tests/test_symbols_verify.py -q && just lint && uv run ty check src`
Expected: PASS, no lint/type errors. (Full handler suites run in later tasks.)

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/local_drgn_introspect.py src/linux_debug_mcp/server.py
git commit -m "refactor(symbols): use one shared BUILD_ID_RE, delete duplicates (#53)"
```

---

## Task 4: `symbols/resolve.py` — vmlinux/modules resolver

**Files:**
- Create: `src/linux_debug_mcp/symbols/resolve.py`
- Modify: `src/linux_debug_mcp/symbols/__init__.py` (re-export)
- Test: `tests/test_symbols_resolve.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_symbols_resolve.py
from __future__ import annotations

import pytest

from linux_debug_mcp.seams.target import KernelProvenance
from linux_debug_mcp.symbols.resolve import (
    ResolvedSymbols,
    SymbolResolutionError,
    resolve_symbols,
)

FULL = "a" * 40


def _provenance(**overrides) -> KernelProvenance:
    base = dict(
        build_id=FULL,
        release="6.9.0-test",
        vmlinux_ref="build/vmlinux",
        modules_ref=None,
        cmdline="root=/dev/vda console=ttyS0",
        config_ref="build/.config",
    )
    base.update(overrides)
    return KernelProvenance(**base)


def _make_run(tmp_path):
    run_dir = tmp_path / "run"
    (run_dir / "build").mkdir(parents=True)
    return run_dir


def test_resolves_vmlinux_and_warns_on_missing_modules(tmp_path):
    run_dir = _make_run(tmp_path)
    (run_dir / "build" / "vmlinux").write_text("elf", encoding="utf-8")
    result = resolve_symbols(_provenance(), run_dir=run_dir)
    assert isinstance(result, ResolvedSymbols)
    assert result.vmlinux_path == (run_dir / "build" / "vmlinux").resolve()
    assert result.modules_path is None
    assert [w.code for w in result.warnings] == ["modules_debuginfo_missing"]


def test_missing_vmlinux_file_is_fatal(tmp_path):
    run_dir = _make_run(tmp_path)
    with pytest.raises(SymbolResolutionError) as excinfo:
        resolve_symbols(_provenance(), run_dir=run_dir)
    assert excinfo.value.code == "symbol_resolution_failed"


def test_vmlinux_escape_is_fatal(tmp_path):
    run_dir = _make_run(tmp_path)
    with pytest.raises(SymbolResolutionError) as excinfo:
        resolve_symbols(_provenance(vmlinux_ref="../../etc/passwd"), run_dir=run_dir)
    assert excinfo.value.code == "symbol_resolution_failed"


def test_present_modules_bundle_resolves_without_warning(tmp_path):
    run_dir = _make_run(tmp_path)
    (run_dir / "build" / "vmlinux").write_text("elf", encoding="utf-8")
    modules = run_dir / "build" / "modules-debug"
    modules.mkdir()
    result = resolve_symbols(
        _provenance(modules_ref="build/modules-debug"), run_dir=run_dir
    )
    assert result.modules_path == modules.resolve()
    assert result.warnings == []


def test_missing_modules_bundle_warns_once(tmp_path):
    run_dir = _make_run(tmp_path)
    (run_dir / "build" / "vmlinux").write_text("elf", encoding="utf-8")
    result = resolve_symbols(
        _provenance(modules_ref="build/modules-debug"), run_dir=run_dir
    )
    assert result.modules_path is None
    assert [w.code for w in result.warnings] == ["modules_debuginfo_missing"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_symbols_resolve.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'linux_debug_mcp.symbols.resolve'`.

- [ ] **Step 3: Create the resolver**

`src/linux_debug_mcp/symbols/resolve.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from linux_debug_mcp.safety.paths import PathSafetyError, confine_run_relative
from linux_debug_mcp.seams.target import KernelProvenance


@dataclass(frozen=True)
class ResolutionWarning:
    code: str
    detail: str


@dataclass(frozen=True)
class ResolvedSymbols:
    vmlinux_path: Path
    modules_path: Path | None
    warnings: list[ResolutionWarning]


class SymbolResolutionError(Exception):
    """A required symbol source could not be resolved inside the run sandbox."""

    def __init__(self, message: str, *, code: str = "symbol_resolution_failed") -> None:
        super().__init__(message)
        self.code = code


def resolve_symbols(provenance: KernelProvenance, *, run_dir: Path) -> ResolvedSymbols:
    """Resolve drgn-consumable paths from *provenance*, confined to *run_dir*.

    ``vmlinux_ref`` is required (missing/escaping/not-a-file is fatal).
    ``modules_ref`` is optional: absent or missing-bundle yields exactly one
    ``modules_debuginfo_missing`` warning, never a silent drop. This function
    does NOT verify build_id — that is :func:`linux_debug_mcp.symbols.verify.verify_build_id`.
    """
    try:
        vmlinux_path = confine_run_relative(provenance.vmlinux_ref, run_dir=run_dir)
    except PathSafetyError as exc:
        raise SymbolResolutionError(f"vmlinux_ref is unsafe: {exc}") from exc
    if not vmlinux_path.is_file():
        raise SymbolResolutionError(f"vmlinux not found at {provenance.vmlinux_ref!r}")

    warnings: list[ResolutionWarning] = []
    modules_path: Path | None = None
    if provenance.modules_ref is None:
        warnings.append(
            ResolutionWarning(code="modules_debuginfo_missing", detail="no modules_ref recorded")
        )
    else:
        try:
            candidate = confine_run_relative(provenance.modules_ref, run_dir=run_dir)
        except PathSafetyError as exc:
            raise SymbolResolutionError(f"modules_ref is unsafe: {exc}") from exc
        if candidate.exists():
            modules_path = candidate
        else:
            warnings.append(
                ResolutionWarning(
                    code="modules_debuginfo_missing",
                    detail=f"modules bundle absent at {provenance.modules_ref!r}",
                )
            )
    return ResolvedSymbols(vmlinux_path=vmlinux_path, modules_path=modules_path, warnings=warnings)
```

Extend `src/linux_debug_mcp/symbols/__init__.py`:

```python
from __future__ import annotations

from linux_debug_mcp.symbols.resolve import (
    ResolutionWarning,
    ResolvedSymbols,
    SymbolResolutionError,
    resolve_symbols,
)
from linux_debug_mcp.symbols.verify import (
    BUILD_ID_RE,
    ProvenanceMismatch,
    verify_build_id,
)

__all__ = [
    "BUILD_ID_RE",
    "ProvenanceMismatch",
    "ResolutionWarning",
    "ResolvedSymbols",
    "SymbolResolutionError",
    "resolve_symbols",
    "verify_build_id",
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_symbols_resolve.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + types**

Run: `just lint && uv run ty check src`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/symbols/resolve.py src/linux_debug_mcp/symbols/__init__.py tests/test_symbols_resolve.py
git commit -m "feat(symbols): add run-confined vmlinux/modules resolver (#53)"
```

---

## Task 5: Record `kernel_args` in libvirt success boot details

The capture adapter (Task 6) needs the assembled args the provider actually booted. They are present in the boot plan but not in the success `StepResult.details`. Add them.

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py:466-475`
- Test: add to the existing `tests/test_libvirt_qemu_provider.py` (reuses the in-file `FakeLibvirtRunner` + `make_plan` helpers that drive a real SUCCEEDED `execute_boot`, no virsh)

- [ ] **Step 1: Write the failing test**

The existing module already exercises the SUCCEEDED success path via `FakeLibvirtRunner` and `make_plan` (see `test_execute_boot_first_boot_domain_absent_defines_starts_and_writes_artifacts`, `tests/test_libvirt_qemu_provider.py:835`). Add a test that asserts the **success `result.details`** carries the assembled `kernel_args` — this exercises the real code change rather than re-deriving `_kernel_args`:

```python
def test_execute_boot_success_details_carry_assembled_kernel_args(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    provider = LibvirtQemuProvider(runner=FakeLibvirtRunner())

    result = provider.execute_boot(plan)

    assert result.status == StepStatus.SUCCEEDED
    # The default target_profile() uses kernel_args=["panic=1"]; the provider
    # assembles root=/console= onto it (libvirt_qemu.py:591-597).
    assert result.details["kernel_args"] == plan.kernel_args
    assert "root=/dev/vda" in result.details["kernel_args"]
    assert "console=ttyS0" in result.details["kernel_args"]
```

(`Path`, `StepStatus`, `LibvirtQemuProvider`, `FakeLibvirtRunner`, and `make_plan` are all already imported/defined in that module — confirm before adding.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py::test_execute_boot_success_details_carry_assembled_kernel_args -q`
Expected: FAIL with `KeyError: 'kernel_args'` (success details do not yet include it).

- [ ] **Step 3: Add `kernel_args` to the success details dict**

In `src/linux_debug_mcp/providers/libvirt_qemu.py`, the success-branch `details` dict built around `:466-475` (the one passed to `_boot_result` at the `console.status == "ready"` branch). Add one entry:

```python
            "kernel_args": plan.kernel_args,
```

Place it alongside `"nokaslr_source": plan.nokaslr_source,` so both success and the surrounding details carry the assembled args. `plan.kernel_args` is the assembled list (`BootPlan.kernel_args`, `:53`, set from `_debug_kernel_args` at `:327`).

- [ ] **Step 4: Run boot-related provider tests**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -q && just lint && uv run ty check src`
Expected: PASS (the new test plus the existing ones still green), no lint/type errors. (The gated `tests/test_libvirt_boot_integration.py` stays skipped without virsh — do not unskip it.)

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/libvirt_qemu.py tests/test_libvirt_qemu_provider.py
git commit -m "feat(boot): record assembled kernel_args in success boot details (#53)"
```

---

## Task 6: Boot-capture adapter (`_capture_kernel_provenance`)

Synthesize a `KernelProvenance` from the build + boot records and fold it into the boot terminal `StepResult.details` at construction (design §3). Single write, SUCCEEDED branch only. Capture failure is a typed `kernel_provenance_capture_error`, never a silent skip; boot still SUCCEEDS.

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (add `_capture_kernel_provenance` near `_find_artifact:615`; call at the terminal StepResult `:1603-1609`)
- Test: `tests/test_kernel_provenance_capture.py`

- [ ] **Step 1: Write the failing test (pure adapter unit tests)**

```python
# tests/test_kernel_provenance_capture.py
from __future__ import annotations

from linux_debug_mcp.domain import ArtifactRef, StepResult, StepStatus
from linux_debug_mcp.server import _capture_kernel_provenance

FULL = "a" * 40


def _build_step(tmp_path, *, with_vmlinux=True, build_id=FULL, release="6.9.0-test"):
    out = tmp_path / "build"
    out.mkdir(parents=True, exist_ok=True)
    (out / ".config").write_text("CONFIG_X=y", encoding="utf-8")
    artifacts = [ArtifactRef(path=str(out / ".config"), kind="kernel-config")]
    if with_vmlinux:
        (out / "vmlinux").write_text("elf", encoding="utf-8")
        artifacts.append(ArtifactRef(path=str(out / "vmlinux"), kind="vmlinux"))
    details = {}
    if build_id is not None:
        details["build_id"] = build_id
    if release is not None:
        details["kernel_release"] = release
    return StepResult(
        step_name="build",
        status=StepStatus.SUCCEEDED,
        summary="ok",
        details=details,
        artifacts=artifacts,
    )


def test_successful_capture_has_run_relative_refs_and_cmdline(tmp_path):
    build = _build_step(tmp_path)
    boot_details = {"kernel_args": ["root=/dev/vda", "console=ttyS0", "nokaslr"]}
    result = _capture_kernel_provenance(
        build_step=build, boot_details=boot_details, run_dir=tmp_path
    )
    prov = result["kernel_provenance"]
    assert prov["build_id"] == FULL
    assert prov["release"] == "6.9.0-test"
    assert prov["vmlinux_ref"] == "build/vmlinux"
    assert prov["config_ref"] == "build/.config"
    assert prov["cmdline"] == "root=/dev/vda console=ttyS0 nokaslr"
    assert prov["modules_ref"] is None
    assert "kernel_provenance_capture_error" not in result


def test_missing_vmlinux_records_conventional_ref_plus_note(tmp_path):
    build = _build_step(tmp_path, with_vmlinux=False)
    result = _capture_kernel_provenance(
        build_step=build, boot_details={"kernel_args": []}, run_dir=tmp_path
    )
    assert result["kernel_provenance"]["vmlinux_ref"] == "build/vmlinux"
    assert "vmlinux_artifact_missing" in result["kernel_provenance_capture_notes"]


def test_missing_build_id_is_typed_capture_error(tmp_path):
    build = _build_step(tmp_path, build_id=None)
    result = _capture_kernel_provenance(
        build_step=build, boot_details={"kernel_args": []}, run_dir=tmp_path
    )
    assert result["kernel_provenance_capture_error"]["code"] == "build_id_unavailable"
    assert "kernel_provenance" not in result


def test_missing_release_is_typed_capture_error(tmp_path):
    build = _build_step(tmp_path, release=None)
    result = _capture_kernel_provenance(
        build_step=build, boot_details={"kernel_args": []}, run_dir=tmp_path
    )
    assert result["kernel_provenance_capture_error"]["code"] == "release_unavailable"


def test_relocated_config_artifact_is_capture_error(tmp_path):
    build = _build_step(tmp_path)
    # Point the kernel-config artifact outside run_dir.
    outside = tmp_path.parent / "stray.config"
    outside.write_text("x", encoding="utf-8")
    build.artifacts = [
        ArtifactRef(path=str(outside), kind="kernel-config"),
        *[a for a in build.artifacts if a.kind != "kernel-config"],
    ]
    result = _capture_kernel_provenance(
        build_step=build, boot_details={"kernel_args": []}, run_dir=tmp_path
    )
    assert result["kernel_provenance_capture_error"]["code"] == "artifact_path_unexpected"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_kernel_provenance_capture.py -q`
Expected: FAIL with `ImportError: cannot import name '_capture_kernel_provenance'`.

- [ ] **Step 3: Add the adapter to `server.py`**

Insert after `_find_artifact` (`server.py:619`). Confirm `KernelProvenance` is imported in `server.py`; if not, add `from linux_debug_mcp.seams.target import KernelProvenance` to the existing seams import block.

```python
def _artifact_run_relative_ref(
    artifact: ArtifactRef | None, *, run_root: Path
) -> tuple[str | None, str | None]:
    """Return (run-relative ref, error-code). error-code is set only when a
    present artifact's path is not under run_root."""
    if artifact is None:
        return None, None
    try:
        return str(Path(artifact.path).resolve().relative_to(run_root)), None
    except ValueError:
        return None, "artifact_path_unexpected"


def _capture_kernel_provenance(
    *,
    build_step: StepResult | None,
    boot_details: dict[str, Any],
    run_dir: Path,
) -> dict[str, Any]:
    """Synthesize a KernelProvenance from the build + boot records (design §3).

    Returns one of:
      - {"kernel_provenance": <model_dump>, ["kernel_provenance_capture_notes": [...]]}
      - {"kernel_provenance_capture_error": {"code": ..., "message": ...}}
    Never raises; a missing required field is a typed capture error so an
    otherwise-good boot still SUCCEEDS.
    """
    if build_step is None:
        return {"kernel_provenance_capture_error": {"code": "build_id_unavailable", "message": "no build step recorded"}}
    build_id = build_step.details.get("build_id")
    if not isinstance(build_id, str):
        return {"kernel_provenance_capture_error": {"code": "build_id_unavailable", "message": "build recorded no build_id"}}
    release = build_step.details.get("kernel_release")
    if not isinstance(release, str):
        return {"kernel_provenance_capture_error": {"code": "release_unavailable", "message": "build recorded no kernel_release"}}

    run_root = run_dir.resolve()
    config_ref, config_err = _artifact_run_relative_ref(_find_artifact(build_step, "kernel-config"), run_root=run_root)
    if config_err is not None:
        return {"kernel_provenance_capture_error": {"code": config_err, "message": "kernel-config artifact is outside the run directory"}}

    notes: list[str] = []
    vmlinux_artifact = _find_artifact(build_step, "vmlinux")
    if vmlinux_artifact is not None:
        vmlinux_ref, vmlinux_err = _artifact_run_relative_ref(vmlinux_artifact, run_root=run_root)
        if vmlinux_err is not None:
            return {"kernel_provenance_capture_error": {"code": vmlinux_err, "message": "vmlinux artifact is outside the run directory"}}
    else:
        vmlinux_ref = "build/vmlinux"
        notes.append("vmlinux_artifact_missing")

    kernel_args = boot_details.get("kernel_args")
    cmdline = " ".join(kernel_args) if isinstance(kernel_args, list) else ""

    provenance = KernelProvenance(
        build_id=build_id,
        release=release,
        vmlinux_ref=vmlinux_ref or "build/vmlinux",
        modules_ref=None,
        cmdline=cmdline,
        config_ref=config_ref,
    )
    result: dict[str, Any] = {"kernel_provenance": provenance.model_dump(mode="json")}
    if notes:
        result["kernel_provenance_capture_notes"] = notes
    return result
```

- [ ] **Step 4: Fold the capture into the boot terminal StepResult**

At `server.py:1603-1609`, the SUCCEEDED-or-FAILED terminal StepResult is built. Capture provenance **only on SUCCEEDED** and fold it into the details literal. Replace:

```python
        terminal = StepResult(
            step_name="boot",
            status=execution.status,
            summary=execution.summary,
            artifacts=execution.artifacts,
            details={**execution.details, "kernel_image_path": str(kernel_image.path)},
        )
```

with:

```python
        terminal_details: dict[str, Any] = {**execution.details, "kernel_image_path": str(kernel_image.path)}
        if execution.status == StepStatus.SUCCEEDED:
            try:
                terminal_details.update(
                    _capture_kernel_provenance(
                        build_step=locked_manifest.step_results.get("build"),
                        boot_details=execution.details,
                        run_dir=store.run_dir(run_id),
                    )
                )
            except Exception as capture_exc:  # provenance capture must never fail an otherwise-good boot
                # Broad catch is deliberate (a good boot must not be lost to a
                # capture defect) but must NOT be silent: log with traceback so a
                # masked programming bug is observable, then record a typed error.
                logger.warning("kernel provenance capture failed: %s", capture_exc, exc_info=True)
                terminal_details["kernel_provenance_capture_error"] = {
                    "code": "capture_unexpected_error",
                    "message": f"{type(capture_exc).__name__}: {capture_exc}",
                }
        terminal = StepResult(
            step_name="boot",
            status=execution.status,
            summary=execution.summary,
            artifacts=execution.artifacts,
            details=terminal_details,
        )
```

**Reuse the in-scope manifest, do not re-read.** `execute_boot` is a closure defined inside `target_boot_handler`; by the time it runs, the handler has already loaded `locked_manifest` under the boot lock (`server.py:1644`) and the build step is terminal before boot. Read the build step from `locked_manifest.step_results.get("build")` — issuing a second `store.load_manifest(run_id)` here is a redundant disk read inside the lock and, worse, can raise `ManifestStateError` *after* the VM already booted, crashing an otherwise-successful boot. `_capture_kernel_provenance` is contractually no-raise, but the `try/except` is a belt-and-suspenders guard so any unexpected fault (e.g. a `model_dump` edge) degrades to a recorded capture error rather than failing the boot. `capture_unexpected_error` is surfaced by the Task 7 live re-point the same way as the other capture-error codes (it falls through the `isinstance(capture_error, dict)` branch).

**Closure-scope caveat for the implementer (verified def/binding/call order).** `execute_boot` is *defined* at `server.py:1527` — which is **above** the `locked_manifest` binding at `:1644`. This works only by Python's late binding of free variables: `locked_manifest` is resolved when the closure *runs*, not when it is defined, and the closure is *called* at `:1703`, inside the `with store.boot_lock(run_id):` block where `:1644` already bound the name. So the real fragility is **not** the position of the `def` — it is the position of the *call*: if a future refactor hoists the `execute_boot(...)` invocation out of that `with` block, `locked_manifest` is unbound and the closure raises `NameError`. The `logger` reference in the `except` is likewise a module-level free variable (`server.py:158`), resolved the same way. The robust fix that removes the hidden dependency entirely: thread the manifest through the signature — `def execute_boot(*, plan, ..., manifest)` and call `execute_boot(..., manifest=locked_manifest)` at `:1703` — so the data dependency is explicit rather than captured. Prefer that if touching `execute_boot`'s signature is acceptable; otherwise keep the closure capture and do not move the call site.

- [ ] **Step 5: Run the adapter unit tests + boot handler tests**

Run: `uv run python -m pytest tests/test_kernel_provenance_capture.py -q`
Expected: PASS.

Then the boot handler suite (locate it):

Run: `rg -l "target_boot_handler" tests/ | tr '\n' ' '`
Run the listed module(s): `uv run python -m pytest <those files> -q`
Expected: PASS (existing boot tests still green; provenance is additive on the SUCCEEDED path).

- [ ] **Step 6: Lint + types**

Run: `just lint && uv run ty check src`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_kernel_provenance_capture.py
git commit -m "feat(boot): capture KernelProvenance into boot step details (#53)"
```

---

## Task 7: Live re-point of `debug.introspect.run`

Move `EXPECTED_BUILD_ID` sourcing from the build step to the boot-recorded `kernel_provenance` (design §4), surface capture errors verbatim, and add a host-side `verify_build_id` on the wrapper's returned id with host-authoritative precedence.

**Files:**
- Modify: `src/linux_debug_mcp/server.py:2421-2447` (sourcing) and `:2952` (host-side verify)
- Test: re-point `tests/test_debug_introspect_run.py` (Step 0 confirms; Step 3 enumerates the edits) + add cases

- [ ] **Step 0: Confirm the existing introspect handler tests**

Run: `rg -l 'introspect.*handler|render_wrapper|expected_build_id|kernel_provenance' tests/ | sort -u`

The module is `tests/test_debug_introspect_run.py` (34 tests; verified at plan-authoring time). The shared seeder is `_bootstrap_run_with_build` (`:208-229`), which records a SUCCEEDED build step with `details={"build_id": VALID_BUILD_ID}` and **no boot step**. `VALID_BUILD_ID` is defined at `:34`. The two tests that encode build-step provenance semantics directly (not via the helper) are `test_provenance_missing_when_manifest_lacks_build_id` (`:343`) and `test_malformed_build_id_rejected_as_provenance_corrupt` (`:373`). Step 3 below enumerates exactly what changes in each. If `rg` surfaces an additional module, fold it in; otherwise this is the only handler test file.

- [ ] **Step 1: Re-point the build_id source (replace `server.py:2421-2447`)**

Replace the block from the `# Spec §5.2 step 4: build_id from manifest.` comment through the `provenance_corrupt` failure (ending at the current `:2447`) with:

```python
    # Design §4: build_id flows from the boot-recorded KernelProvenance, the
    # authoritative §4.2 record — not the build step.
    boot_step = manifest.step_results.get("boot")
    provenance = boot_step.details.get("kernel_provenance") if boot_step is not None else None
    if not isinstance(provenance, dict):
        capture_error = (
            boot_step.details.get("kernel_provenance_capture_error") if boot_step is not None else None
        )
        if isinstance(capture_error, dict):
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                run_id=run_id,
                message=(
                    "boot did not record a KernelProvenance: "
                    f"{capture_error.get('message', 'capture failed')}"
                ),
                details={
                    "code": "provenance_missing",
                    "capture_error": capture_error.get("code"),
                },
            )
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(
                "boot for this run did not record a KernelProvenance. Re-run "
                "target.boot for this run; provenance is captured on a SUCCEEDED boot."
            ),
            details={"code": "provenance_missing"},
        )
    build_id = provenance.get("build_id")
    if not isinstance(build_id, str) or not BUILD_ID_RE.match(build_id):
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="recorded build_id is malformed",
            details={"code": "provenance_corrupt", "recorded": str(build_id)},
        )
```

The downstream `render_wrapper(..., expected_build_id=build_id, ...)` at `:2604-2613` is unchanged — `build_id` now comes from provenance.

- [ ] **Step 2: Add host-side verify at the happy path (before `server.py:2952` stdout write)**

`verify_build_id` is already imported in Task 3's edit? No — Task 3 imported `BUILD_ID_RE` only. Add to the same import line: `from linux_debug_mcp.symbols.verify import BUILD_ID_RE, ProvenanceMismatch, verify_build_id`.

Immediately before the happy-path redaction write (`server.py:2952`, the `# Spec §5.2 step 12` comment / `(agent_dir / "stdout.json").write_text(...)`), insert:

```python
        # Design §4: host-authoritative provenance verify. The wrapper already
        # self-aborted on mismatch (outcome_status == "provenance_mismatch",
        # handled above); reaching here on an "ok" outcome with a disagreeing or
        # absent id is a truncation/normalization/wrapper fault — fail loud, never skip.
        observed_build_id = redacted_payload.get("build_id") if isinstance(redacted_payload, dict) else None
        if not isinstance(observed_build_id, str):
            # An "ok" outcome that omits build_id is itself a wrapper fault; a
            # missing observed id must NOT pass silently with symbols trusted.
            return _fail(
                category=ErrorCategory.CONFIGURATION_ERROR,
                code="provenance_mismatch",
                message="wrapper reported success without a build_id; cannot confirm provenance",
                outcome_status_for_forensics="provenance_inconsistent",
                include_stdout_json=True,
                redacted_payload=rp,
            )
        try:
            verify_build_id(expected=build_id, observed=observed_build_id)
        except ProvenanceMismatch:
            return _fail(
                category=ErrorCategory.CONFIGURATION_ERROR,
                code="provenance_mismatch",
                message="host build_id verify disagrees with the wrapper-reported id",
                outcome_status_for_forensics="provenance_inconsistent",
                include_stdout_json=True,
                redacted_payload=rp,
            )
```

`_fail`'s real signature (verified at `server.py`) is `def _fail(*, category, code, message, outcome_status_for_forensics: str | None, include_stdout_json: bool = False, redacted_payload: dict[str, Any] | None = None)` — the kwargs above match it verbatim. The forensic `outcome_status` records `provenance_inconsistent`; the agent-facing `code` is `provenance_mismatch`.

**Note on placement:** this block reads `redacted_payload`, `rp`, and `_fail`, all of which exist only *after* the JSON-parse + outcome-discrimination section (`server.py:2899-2950`). Insert it immediately after the last `outcome_status == ...` branch (`wrapper_internal_error`, ending `:2950`) and before the `# Spec §5.2 step 12` happy-path write (`:2952`). At that point `outcome_status` is neither an error sentinel nor `provenance_mismatch` (those returned already), so the only outcomes reaching here are `"ok"` and `"error"` (script_error) — both legitimately carry a `build_id` from a kernel that drgn attached to, so the verify applies to both.

- [ ] **Step 3: Re-point existing introspect tests + add new cases**

The target module is `tests/test_debug_introspect_run.py` (34 tests). It currently seeds provenance in the **build** step; the re-point breaks that. Make these three concrete edits before adding new cases — they are not optional, the suite will not pass otherwise:

**(a) `_bootstrap_run_with_build` helper (`tests/test_debug_introspect_run.py:208-229`).** Today it records only a SUCCEEDED **build** step with `details={"build_id": VALID_BUILD_ID}` and **no boot step**. Every matrix test that reaches the SSH/admission path (happy path `:537`, redaction `:765`, the profile-mismatch group `:877-955`, etc.) flows through this helper, so after the re-point they all hit the new `provenance_missing` branch and fail. Add a SUCCEEDED **boot** step to the helper whose `details["kernel_provenance"]` is a well-formed dict mirroring `_capture_kernel_provenance` output:

```python
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary="boot ok",
            artifacts=[],
            details={
                "kernel_provenance": {
                    "build_id": VALID_BUILD_ID,
                    "release": "6.9.0-test",
                    "vmlinux_ref": "build/vmlinux",
                    "modules_ref": None,
                    "cmdline": "root=/dev/vda console=ttyS0",
                    "config_ref": "build/.config",
                }
            },
        ),
    )
```

Keep the build-step record too (other call sites and the manifest invariant still expect a build step). The helper's `build_id` return value is unchanged (`VALID_BUILD_ID`), so callers that compare against it still work.

**(b) `test_provenance_missing_when_manifest_lacks_build_id` (`:343-370`).** Its premise shifts from "no build_id" to "no boot provenance," and its message assertion must change. Re-point it to create a run, record a SUCCEEDED **boot** step whose `details` lack `kernel_provenance` (and lack `kernel_provenance_capture_error`), then assert `response.error.details["code"] == "provenance_missing"` and `"target.boot" in response.error.message` (the new Step-1 message says "Re-run target.boot…", not "kernel.create_run"). Rename to `test_provenance_missing_when_boot_lacks_provenance` for accuracy.

**(c) `test_malformed_build_id_rejected_as_provenance_corrupt` (`:373-...`).** Today it seeds the malformed id in the **build** step (`:384-392`); the handler no longer reads it there. Move the malformed seed into the **boot** step: record a SUCCEEDED boot step with `details={"kernel_provenance": {"build_id": "not-hex!", "release": "x", "vmlinux_ref": "build/vmlinux", "cmdline": "", "config_ref": None, "modules_ref": None}}`. Keep the `provenance_corrupt` assertion. (A build step may still be recorded for realism but is no longer load-bearing.)

Then change the setup of the remaining matrix tests as needed so the **boot** step records a valid `kernel_provenance` (via the updated helper in (a)). Keep each existing assertion. Then add:

```python
def test_introspect_provenance_missing_when_boot_has_none(<existing fixtures>):
    # Boot step present but no kernel_provenance / capture-error recorded.
    response = <call introspect handler with a boot step whose details lack kernel_provenance>
    assert response.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.details["code"] == "provenance_missing"


def test_introspect_surfaces_capture_error_code(<existing fixtures>):
    # Boot recorded kernel_provenance_capture_error instead of provenance.
    response = <call handler with boot details {"kernel_provenance_capture_error": {"code": "build_id_unavailable", "message": "..."}}>
    assert response.details["code"] == "provenance_missing"
    assert response.details["capture_error"] == "build_id_unavailable"


def test_introspect_host_wrapper_divergence_fails_loud(<existing fixtures>):
    # Wrapper returns status ok but a build_id differing from the recorded one.
    # Seed boot provenance build_id = "a"*40; fake SSH stdout payload build_id = "b"*40.
    response = <call handler with that fake wrapper payload>
    assert response.category == ErrorCategory.CONFIGURATION_ERROR
    # forensic outcome_status records provenance_inconsistent; agent-facing code is provenance_mismatch.
    assert response.details["code"] == "provenance_mismatch"


def test_introspect_ok_outcome_without_build_id_fails_loud(<existing fixtures>):
    # Finding 3: an "ok" wrapper payload that omits build_id must NOT pass the
    # host verify silently. Seed boot provenance build_id = "a"*40; fake SSH
    # stdout payload = {"outcome": {"status": "ok"}, "emits": [], "user_stdout": ""}
    # (no build_id key).
    response = <call handler with that fake wrapper payload>
    assert response.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.details["code"] == "provenance_mismatch"
```

Fill the `<...>` placeholders against the module's existing fakes, which the matrix tests already use: `_profiles()` (returns `targets, rootfs, debug`), `FakeSshRunner(results=[...])`, `FakeAdmissionService()`, `FakeSessionRegistry()`, `_make_request(run_id)`, and `_happy_ssh_result()` (`:232`) as the payload template. For the divergence and missing-id cases, build the run via the updated `_bootstrap_run_with_build` (so boot provenance build_id = `VALID_BUILD_ID`) and pass a hand-built `SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")` where `body` is `_happy_ssh_result()`'s dict with `build_id` set to a *different* valid hex (divergence) or with the `build_id` key removed (missing-id). The wrapper sets `build_id` before the user script runs (`local_drgn_introspect.py:101`), so a real `"ok"` payload always carries it — the missing-id case is a synthetic fault injection that exercises the new guard. Both must reach the host verify, i.e. `outcome.status == "ok"` so the in-wrapper `provenance_mismatch` branch (`server.py:2923`) is not taken.

- [ ] **Step 4: Run the introspect handler suite**

Run: `uv run python -m pytest <introspect test module(s) from Step 0> -q`
Expected: PASS (re-pointed existing tests + 3 new cases). The gated real-drgn cross-check tests stay gated/skipped without drgn — do not unskip them.

- [ ] **Step 5: Full suite + lint + types**

Run: `just test && just lint && uv run ty check src`
Expected: all green, no warnings.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/
git commit -m "feat(introspect): source build_id from boot provenance + host-side verify (#53)"
```

---

## Task 8: ADR status, docs cross-link, self-review

**Files:**
- Create: `docs/adr/NNNN-symbols-package.md` (next sequential number; check `docs/adr/README.md`)
- Modify: `docs/adr/README.md` (index entry)
- Modify: the design doc's ADR `Status:` line (proposed → accepted) if you keep the ADR inline; otherwise extract it.

- [ ] **Step 1: Record the ADR**

The design already contains a fully-formed ADR ("a dedicated `symbols/` package") with Context / Decision / Consequences / Considered & rejected. Per project CLAUDE.md, ADRs live at `docs/adr/NNNN-short-title.md`. Either (a) move that ADR block into a new `docs/adr/NNNN-symbols-package.md` and flip its status to **accepted**, or (b) if the team keeps design-embedded ADRs, add a stub ADR pointing at the design §"ADR" section. Add the index line to `docs/adr/README.md`.

- [ ] **Step 2: Self-review against the design spec**

Walk each design section and confirm a task covers it:
- §1 verifier → Task 2; one-constant collapse → Task 3.
- §2 resolver + `confine_run_relative` → Tasks 1, 4.
- §3 boot capture (field sourcing, vmlinux-optional note, typed capture error) → Tasks 5, 6.
- §4 live re-point + host-side verify precedence → Task 7.
- §5 error taxonomy → asserted across Tasks 6 (`build_id_unavailable`/`release_unavailable`/`artifact_path_unexpected`, `vmlinux_artifact_missing`) and 7 (`provenance_missing`/`provenance_corrupt`/`provenance_mismatch`+`provenance_inconsistent`) and 4 (`symbol_resolution_failed`, `modules_debuginfo_missing`).
- §6 testing → each task's tests.
- §7 deferred (vmcore caller #55, external symbol roots, provisioning capture, real modules bundle) → intentionally not implemented; confirm no task accidentally adds them.

- [ ] **Step 3: Doc terminology guard**

Run: `just check-docs`
Expected: PASS (no "sprint" in README/docs outside `docs/superpowers/`).

- [ ] **Step 4: Final full verification**

Run: `just test && just lint && uv run ty check src`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add docs/
git commit -m "docs(adr): accept dedicated symbols package (#53)"
```

---

## Acceptance criteria mapping (from #53 / design)

- A live target whose `build_id` matches the boot-recorded `KernelProvenance.build_id` resolves and runs; host-side `verify_build_id` confirms the wrapper-reported id → Tasks 6, 7 (+ divergence test).
- A mismatched `build_id` fails with `CONFIGURATION_ERROR` / `provenance_mismatch`, no symbols loaded → wrapper branch (`server.py:2923`, unchanged) + host verify (Task 7).
- Missing module debuginfo surfaced as a typed `modules_debuginfo_missing` warning, not dropped → Task 4.
