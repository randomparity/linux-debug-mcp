# Symbol version-lock for the gdb tier — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an unconditional build-id version-lock to the live gdb debug tier (#13): before `debug.start_session` attaches gdb, verify the on-disk vmlinux ELF build-id equals the boot-recorded §4.2 `KernelProvenance.build_id`, failing loud on mismatch.

**Architecture:** A new `verify_vmlinux_provenance` entry point in `symbols/verify.py` composes the existing `read_elf_build_id` + `verify_build_id`. `debug_start_session_handler` gains a `build_id_reader` param and a pre-attach check (after the idempotent SUCCEEDED short-circuit, before the transport/attach), implemented in a small module-level helper. The #53 live and #14 vmcore tiers are untouched (they already verify build-id in the shared introspect finalizer).

**Tech Stack:** Python 3.11+, pytest, `uv run` for everything; `ruff`, `ty`.

**Spec:** `docs/superpowers/specs/2026-05-29-symbol-version-lock-design.md` · **ADR:** `docs/adr/0017-symbol-version-lock-gdb-tier.md`

---

## File structure

- `src/linux_debug_mcp/symbols/verify.py` — add `verify_vmlinux_provenance` (Task 1).
- `src/linux_debug_mcp/symbols/__init__.py` — export it (Task 1).
- `src/linux_debug_mcp/server.py` — add `_verify_gdb_symbol_version_lock` helper + wire into `debug_start_session_handler` + import (Tasks 3–4).
- `tests/test_symbols_verify.py` — unit tests for the primitive (Task 2).
- `tests/conftest.py` — shared `write_vmlinux_with_build_id` + `seed_kernel_provenance` helpers (Task 5).
- `tests/test_symbol_version_lock.py` (new) — gdb-tier behavior tests (Task 6).
- Existing gdb-handler test seeders (Task 7): `tests/test_debug_handlers.py`, `tests/test_session_guard_wiring.py`, `tests/test_server_debug_session_migration.py`, `tests/test_server_debug_reads_while_halted.py`, `tests/test_phase_b_integration_gaps.py`.

Not touched: `tests/test_workflow_build_boot_debug_handler.py` (monkeypatches the handler), `tests/test_transport_open_close_integration.py` (gated live test; its real build/boot produce a matching real vmlinux build-id), the gated gdb/libvirt integration tests.

---

## Task 1: The shared verification primitive

**Files:**
- Modify: `src/linux_debug_mcp/symbols/verify.py`
- Modify: `src/linux_debug_mcp/symbols/__init__.py`
- Test: `tests/test_symbols_verify.py` (Task 2)

- [ ] **Step 1: Add `verify_vmlinux_provenance` to `symbols/verify.py`**

Replace the top imports and append the function. The new file head:

```python
from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from linux_debug_mcp.symbols.build_id import read_elf_build_id

BUILD_ID_RE = re.compile(r"^[0-9a-f]{8,}$")
```

Append at end of file (after `verify_build_id`):

```python
def verify_vmlinux_provenance(
    *,
    expected_build_id: str,
    vmlinux_path: Path,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
) -> str:
    """Read the vmlinux ELF build-id and verify it equals *expected_build_id*.

    Returns the observed build-id on success. Raises
    :class:`linux_debug_mcp.symbols.build_id.BuildIdReadError` when the file is
    unreadable / not an ELF / carries no GNU build-id note, and
    :class:`ProvenanceMismatch` when the observed id differs from *expected_build_id*.

    The caller MUST have validated *expected_build_id*'s shape (the recorded §4.2
    value); ``read_elf_build_id`` already returns canonical lower-case hex, so the
    observed side needs no separate shape check. This is the §4.2 consumable
    verification entry point (interface-contracts §4.2).
    """
    observed = build_id_reader(vmlinux_path)
    verify_build_id(expected=expected_build_id, observed=observed)
    return observed
```

- [ ] **Step 2: Export it from `symbols/__init__.py`**

In `src/linux_debug_mcp/symbols/__init__.py`, extend the `verify` import and `__all__`:

```python
from linux_debug_mcp.symbols.verify import (
    BUILD_ID_RE,
    ProvenanceMismatch,
    verify_build_id,
    verify_vmlinux_provenance,
)
```

Add `"verify_vmlinux_provenance",` to `__all__` (keep it alphabetical-ish, beside `verify_build_id`).

- [ ] **Step 3: Run lint + type check**

Run: `uv run ruff check src/linux_debug_mcp/symbols && uv run ty check src`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add src/linux_debug_mcp/symbols/verify.py src/linux_debug_mcp/symbols/__init__.py
git commit -m "feat(symbols): add verify_vmlinux_provenance read+compare entry point"
```

---

## Task 2: Unit-test the primitive

**Files:**
- Modify: `tests/test_symbols_verify.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_symbols_verify.py`:

```python
import pytest

from linux_debug_mcp.symbols.build_id import BuildIdReadError
from linux_debug_mcp.symbols.verify import ProvenanceMismatch, verify_vmlinux_provenance

_FULL = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


def test_verify_vmlinux_provenance_returns_observed_on_match(tmp_path):
    observed = verify_vmlinux_provenance(
        expected_build_id=_FULL,
        vmlinux_path=tmp_path / "vmlinux",
        build_id_reader=lambda _p: _FULL,
    )
    assert observed == _FULL


def test_verify_vmlinux_provenance_raises_on_mismatch(tmp_path):
    other = "ffffffffffffffffffffffffffffffffffffffff"  # pragma: allowlist secret
    with pytest.raises(ProvenanceMismatch):
        verify_vmlinux_provenance(
            expected_build_id=_FULL,
            vmlinux_path=tmp_path / "vmlinux",
            build_id_reader=lambda _p: other,
        )


def test_verify_vmlinux_provenance_prefix_is_a_mismatch(tmp_path):
    with pytest.raises(ProvenanceMismatch):
        verify_vmlinux_provenance(
            expected_build_id=_FULL,
            vmlinux_path=tmp_path / "vmlinux",
            build_id_reader=lambda _p: _FULL[:16],
        )


def test_verify_vmlinux_provenance_propagates_read_error(tmp_path):
    def _boom(_p):
        raise BuildIdReadError("no NT_GNU_BUILD_ID note found")

    with pytest.raises(BuildIdReadError):
        verify_vmlinux_provenance(
            expected_build_id=_FULL,
            vmlinux_path=tmp_path / "vmlinux",
            build_id_reader=_boom,
        )
```

(If `tests/test_symbols_verify.py` already imports `pytest`, drop the duplicate import.)

- [ ] **Step 2: Run the tests**

Run: `uv run python -m pytest tests/test_symbols_verify.py -q`
Expected: PASS (4 new tests green).

- [ ] **Step 3: Commit**

```bash
git add tests/test_symbols_verify.py
git commit -m "test(symbols): cover verify_vmlinux_provenance match/mismatch/read-error"
```

---

## Task 3: The handler helper (failing test first)

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (import + new helper `_verify_gdb_symbol_version_lock`)
- Test: `tests/test_symbol_version_lock.py` (Task 6 holds the full suite; this task adds the helper the suite needs)

This task implements the helper but is verified end-to-end by Task 6's tests; here we add the code and rely on Task 1/2 plus a quick import smoke.

- [ ] **Step 1: Add the import**

In `src/linux_debug_mcp/server.py`, change the existing import line:

```python
from linux_debug_mcp.symbols.verify import BUILD_ID_RE, ProvenanceMismatch, verify_build_id
```

to:

```python
from linux_debug_mcp.symbols.verify import (
    BUILD_ID_RE,
    ProvenanceMismatch,
    verify_build_id,
    verify_vmlinux_provenance,
)
```

`read_elf_build_id` and `BuildIdReadError` are already imported from `linux_debug_mcp.symbols.build_id`. `verify_build_id` stays imported (still used by the introspect finalizer).

- [ ] **Step 2: Add the helper above `debug_start_session_handler`**

Insert this module-level function immediately before `def debug_start_session_handler(` (currently ~line 4008):

```python
def _verify_gdb_symbol_version_lock(
    *,
    boot_result: StepResult,
    vmlinux_path: Path,
    run_id: str,
    build_id_reader: Callable[[Path], str],
) -> ToolResponse | None:
    """#70 / ADR 0017: verify the on-disk vmlinux ELF build-id equals the
    boot-recorded §4.2 KernelProvenance.build_id. Returns a failure ToolResponse to
    abort the attach, or None to proceed. Unconditional (independent of
    symbol_identity_required) — a detected mismatch is bogus symbols.
    """
    provenance = boot_result.details.get("kernel_provenance")
    if not isinstance(provenance, dict):
        capture_error = boot_result.details.get("kernel_provenance_capture_error")
        details: dict[str, Any] = {"code": "provenance_missing"}
        if isinstance(capture_error, dict):
            message = f"boot did not record a KernelProvenance: {capture_error.get('message', 'capture failed')}"
            details["capture_error"] = capture_error.get("code")
        else:
            message = (
                "boot for this run did not record a KernelProvenance (it predates "
                "provenance capture). Re-run target.boot with force_reboot=true to capture it."
            )
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=message,
            details=details,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    expected_build_id = provenance.get("build_id")
    if not isinstance(expected_build_id, str) or not BUILD_ID_RE.match(expected_build_id):
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="recorded build_id is malformed",
            details={"code": "provenance_corrupt", "recorded": str(expected_build_id)},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    try:
        verify_vmlinux_provenance(
            expected_build_id=expected_build_id,
            vmlinux_path=vmlinux_path,
            build_id_reader=build_id_reader,
        )
    except BuildIdReadError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"could not read a GNU build-id from the vmlinux to verify symbols: {exc}",
            details={"code": "vmlinux_build_id_unreadable"},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    except ProvenanceMismatch as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(
                f"vmlinux build-id {exc.observed!r} does not match the booted kernel's recorded "
                f"build-id {exc.expected!r}; rebuild or re-boot so the booted kernel and the "
                "vmlinux on disk share a build-id"
            ),
            details={"code": "provenance_mismatch", "expected": exc.expected, "observed": exc.observed},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    return None
```

- [ ] **Step 3: Type check (the call site lands in Task 4; verify the helper compiles)**

Run: `uv run ruff check src/linux_debug_mcp/server.py && uv run ty check src`
Expected: no errors. (`Any`, `Callable`, `Path`, `StepResult`, `ToolResponse`, `ErrorCategory`, `BuildIdReadError` are all already imported in `server.py`.)

- [ ] **Step 4: Commit**

```bash
git add src/linux_debug_mcp/server.py
git commit -m "feat(debug): add gdb symbol version-lock helper (#70)"
```

---

## Task 4: Wire the check into `debug_start_session_handler`

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`debug_start_session_handler` signature + call site)

- [ ] **Step 1: Add the `build_id_reader` parameter**

In the `debug_start_session_handler` signature (currently ~line 4008–4021), add a parameter after `recovery: bool = False`:

```python
    recovery: bool = False,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
) -> ToolResponse:
```

- [ ] **Step 2: Insert the pre-attach call after the idempotent short-circuit**

In the `with store.debug_lock(run_id):` block, the existing code computes
`replace_existing_debug` (the line `replace_existing_debug = existing.status == StepStatus.SUCCEEDED`, ~line 4088), and the next line is `transport_enabled = transaction is not None and ...`. Insert between them:

```python
                replace_existing_debug = existing.status == StepStatus.SUCCEEDED
            # #70 / ADR 0017: symbol version-lock BEFORE any acquisition or attach.
            # Runs on every fresh attach (incl. new_session / replace / recovery), after the
            # idempotent SUCCEEDED short-circuit above so re-reading a healthy session never
            # re-gates. A failure returns with nothing acquired and no debug step recorded.
            version_lock_failure = _verify_gdb_symbol_version_lock(
                boot_result=boot_result,
                vmlinux_path=Path(vmlinux.path),
                run_id=run_id,
                build_id_reader=build_id_reader,
            )
            if version_lock_failure is not None:
                return version_lock_failure
            transport_enabled = transaction is not None and admission is not None and session_registry is not None
```

(The `boot_result` and `vmlinux` locals are already in scope from the top of the handler. Match the surrounding indentation: the inserted block is at the same indent as `transport_enabled`, inside the `with store.debug_lock` body but outside the `if existing and not new_session:` block.)

- [ ] **Step 3: Wire the tool wrapper to pass through (no behavior change for callers)**

No change needed in the `@app.tool("debug.start_session")` wrapper — the new parameter defaults to the real reader. Confirm the wrapper still type-checks.

- [ ] **Step 4: Lint + type check**

Run: `uv run ruff check src/linux_debug_mcp/server.py && uv run ty check src`
Expected: no errors.

- [ ] **Step 5: Run the existing gdb-handler tests to observe the expected breakage**

Run: `uv run python -m pytest tests/test_debug_handlers.py -q`
Expected: FAILures — the seeded runs have no `kernel_provenance` and a text vmlinux, so the new gate returns `provenance_missing` / `vmlinux_build_id_unreadable`. This confirms the gate is live. Task 7 fixes the fixtures.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/server.py
git commit -m "feat(debug): version-lock vmlinux build-id before gdb attach (#70)"
```

---

## Task 5: Shared test helpers (real-ELF vmlinux + provenance seeding)

**Files:**
- Modify: `tests/conftest.py`

- [ ] **Step 1: Add the helpers**

Append to `tests/conftest.py` (top-level functions; `struct`, `Path` are needed — `Path` is already imported, add `import struct` near the other stdlib imports):

```python
GDB_TEST_BUILD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


def write_vmlinux_with_build_id(path: Path, build_id_hex: str = GDB_TEST_BUILD_ID) -> None:
    """Write a minimal valid 64-bit LE ELF carrying an NT_GNU_BUILD_ID note, so the
    real read_elf_build_id() returns build_id_hex. Avoids per-test build_id_reader
    injection in the gdb-handler tests.
    """
    import struct

    desc = bytes.fromhex(build_id_hex)
    note = struct.pack("<III", 4, len(desc), 3) + b"GNU\x00" + desc
    if len(note) % 4:
        note += b"\x00" * (-len(note) % 4)
    phoff = 64
    note_off = phoff + 56
    ehdr = (
        b"\x7fELF"
        + bytes([2, 1, 1, 0])
        + b"\x00" * 8
        + struct.pack("<HHI", 2, 62, 1)
        + struct.pack("<QQQ", 0, phoff, 0)
        + struct.pack("<IHHHHHH", 0, 64, 56, 1, 0, 0, 0)
    )
    phdr = struct.pack("<IIQQQQQQ", 4, 0, note_off, 0, 0, len(note), len(note), 4)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(ehdr + phdr + note)


def kernel_provenance_details(build_id_hex: str = GDB_TEST_BUILD_ID, *, release: str = "6.9.0-test") -> dict:
    """A boot-step `kernel_provenance` dict matching write_vmlinux_with_build_id."""
    return {
        "build_id": build_id_hex,
        "release": release,
        "vmlinux_ref": "build/vmlinux",
        "modules_ref": None,
        "cmdline": "",
        "config_ref": None,
    }
```

(Place the `import struct` at module top with the other imports and drop the local `import struct` inside the function — shown inline only for clarity.)

- [ ] **Step 2: Smoke-test the ELF helper round-trips through the real reader**

Run:
```bash
uv run python -c "
import tempfile, pathlib
from tests.conftest import write_vmlinux_with_build_id, GDB_TEST_BUILD_ID
from linux_debug_mcp.symbols.build_id import read_elf_build_id
d=pathlib.Path(tempfile.mkdtemp())/'vmlinux'
write_vmlinux_with_build_id(d)
assert read_elf_build_id(d)==GDB_TEST_BUILD_ID, read_elf_build_id(d)
print('ok')
"
```
Expected: `ok`. (If `tests` is not importable this way, run the equivalent inside `uv run python -m pytest` via a temporary test; the Task 6 happy-path test also proves it.)

- [ ] **Step 3: Lint**

Run: `uv run ruff check tests/conftest.py`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add tests/conftest.py
git commit -m "test: add real-ELF vmlinux + kernel_provenance seeding helpers"
```

---

## Task 6: gdb-tier behavior tests

**Files:**
- Create: `tests/test_symbol_version_lock.py`

- [ ] **Step 1: Write the behavior tests**

Create `tests/test_symbol_version_lock.py`:

```python
from pathlib import Path

from conftest import GDB_TEST_BUILD_ID, kernel_provenance_details, write_vmlinux_with_build_id

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.symbols.build_id import BuildIdReadError
from tests.test_debug_handlers import FakeDebugProvider  # reuse the existing fake

from linux_debug_mcp.server import debug_start_session_handler


def _seed(tmp_path: Path, *, provenance: dict | None, real_elf: bool = True) -> tuple[Path, str]:
    artifact_root = tmp_path / "runs"
    source = tmp_path / "source"
    source.mkdir()
    store = ArtifactStore(artifact_root, source_paths=[source])
    manifest = store.create_run(
        RunRequest(
            source_path=str(source),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
            debug_profile="qemu-gdbstub-default",
            run_id="run-vlock",
        )
    )
    vmlinux = artifact_root / manifest.run_id / "build" / "vmlinux"
    kernel = artifact_root / manifest.run_id / "build" / "bzImage"
    if real_elf:
        write_vmlinux_with_build_id(vmlinux)
    else:
        vmlinux.parent.mkdir(parents=True, exist_ok=True)
        vmlinux.write_text("not-an-elf", encoding="utf-8")
    kernel.write_text("kernel", encoding="utf-8")
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="build", status=StepStatus.SUCCEEDED, summary="built",
            artifacts=[
                ArtifactRef(path=str(kernel), kind="kernel-image"),
                ArtifactRef(path=str(vmlinux), kind="vmlinux"),
            ],
            details={"kernel_release": "6.9.0-test"},
        ),
    )
    boot_details: dict = {"debug_boot": True, "gdbstub_endpoint": {"host": "127.0.0.1", "port": 1234}}
    if provenance is not None:
        boot_details["kernel_provenance"] = provenance
    store.record_step_result(
        manifest.run_id,
        StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="booted", details=boot_details),
    )
    return artifact_root, manifest.run_id


def _profiles(symbol_identity_required: bool = True) -> dict:
    return {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default", symbol_identity_required=symbol_identity_required)}


def test_matching_build_id_attaches(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details())
    provider = FakeDebugProvider()
    resp = debug_start_session_handler(
        artifact_root=artifact_root, run_id=run_id, provider=provider, debug_profiles=_profiles(),
    )
    assert resp.ok is True
    assert provider.calls == 1


def test_mismatched_build_id_fails_and_never_attaches(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details())
    provider = FakeDebugProvider()
    other = "ffffffffffffffffffffffffffffffffffffffff"  # pragma: allowlist secret
    resp = debug_start_session_handler(
        artifact_root=artifact_root, run_id=run_id, provider=provider, debug_profiles=_profiles(),
        build_id_reader=lambda _p: other,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_mismatch"
    assert resp.error.details["observed"] == other
    assert resp.error.details["expected"] == GDB_TEST_BUILD_ID
    assert provider.calls == 0
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest(run_id)
    assert "debug" not in manifest.step_results


def test_unreadable_vmlinux_fails(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details(), real_elf=False)
    provider = FakeDebugProvider()

    def _boom(_p):
        raise BuildIdReadError("not an ELF file (bad magic)")

    resp = debug_start_session_handler(
        artifact_root=artifact_root, run_id=run_id, provider=provider, debug_profiles=_profiles(),
        build_id_reader=_boom,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "vmlinux_build_id_unreadable"
    assert provider.calls == 0


def test_missing_provenance_fails(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=None)
    provider = FakeDebugProvider()
    resp = debug_start_session_handler(
        artifact_root=artifact_root, run_id=run_id, provider=provider, debug_profiles=_profiles(),
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_missing"
    assert provider.calls == 0


def test_corrupt_recorded_build_id_fails(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details("NOT-HEX"))
    provider = FakeDebugProvider()
    resp = debug_start_session_handler(
        artifact_root=artifact_root, run_id=run_id, provider=provider, debug_profiles=_profiles(),
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "provenance_corrupt"
    assert provider.calls == 0


def test_mismatch_fails_even_when_identity_not_required(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details())
    provider = FakeDebugProvider()
    other = "ffffffffffffffffffffffffffffffffffffffff"  # pragma: allowlist secret
    resp = debug_start_session_handler(
        artifact_root=artifact_root, run_id=run_id, provider=provider,
        debug_profiles=_profiles(symbol_identity_required=False),
        build_id_reader=lambda _p: other,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "provenance_mismatch"
    assert provider.calls == 0


def test_idempotent_reattach_skips_version_lock(tmp_path):
    # First attach with matching provenance + real ELF succeeds and records a SUCCEEDED debug step.
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details())
    provider = FakeDebugProvider()
    first = debug_start_session_handler(
        artifact_root=artifact_root, run_id=run_id, provider=provider, debug_profiles=_profiles(),
    )
    assert first.ok is True
    # Now corrupt the recorded provenance to prove the idempotent return does NOT re-gate.
    store = ArtifactStore(artifact_root, create_root=False)
    manifest = store.load_manifest(run_id)
    boot = manifest.step_results["boot"]
    store.record_step_result(
        run_id,
        StepResult(
            step_name="boot", status=StepStatus.SUCCEEDED, summary=boot.summary,
            details={k: v for k, v in boot.details.items() if k != "kernel_provenance"},
        ),
        replace_succeeded=True,
    )
    second = debug_start_session_handler(
        artifact_root=artifact_root, run_id=run_id, provider=FakeDebugProvider(), debug_profiles=_profiles(),
    )
    assert second.ok is True  # returned the existing session, no provenance_missing
    assert second.data["debug_session_id"] == "debug-1"
```

Notes for the implementer:
- `FakeDebugProvider` is imported from `tests/test_debug_handlers.py` to avoid duplicating the fake. If cross-module import is awkward in this layout, copy the small fake into this module instead.
- `ArtifactStore.record_step_result(..., replace_succeeded=True)` is the existing API used to overwrite a SUCCEEDED step (see `kernel_build_handler`). Verify the kwarg name against `store.py` before running; if it differs, use the actual name.

- [ ] **Step 2: Run the new suite**

Run: `uv run python -m pytest tests/test_symbol_version_lock.py -q`
Expected: PASS (7 tests).

- [ ] **Step 3: Commit**

```bash
git add tests/test_symbol_version_lock.py
git commit -m "test(debug): gdb-tier symbol version-lock behavior (#70)"
```

---

## Task 7: Migrate existing gdb-handler test seeders

Each of these files has a run-seeder that writes a text `vmlinux` and a boot step with **no** `kernel_provenance`. For each: (a) replace the `vmlinux.write_text("vmlinux", ...)` with `write_vmlinux_with_build_id(vmlinux)`, and (b) add `"kernel_provenance": kernel_provenance_details(),` to the boot step's `details`. Import both helpers from `conftest`.

**Files & exact edits:**

- [ ] **Step 1: `tests/test_debug_handlers.py`**

Add to imports: `from conftest import kernel_provenance_details, write_vmlinux_with_build_id`.
In `create_debug_ready_run` (~line 121–149): change `vmlinux.write_text("vmlinux", encoding="utf-8")` → `write_vmlinux_with_build_id(vmlinux)`; in the `boot` step `details` dict add `"kernel_provenance": kernel_provenance_details(),`.

- [ ] **Step 2: `tests/test_session_guard_wiring.py`**

In `_create_debug_ready_run` (~line 63–110): same two edits (`write_vmlinux_with_build_id` at ~line 80; add `kernel_provenance` to the boot `details` at ~line 98). Import the helpers from `conftest`.

- [ ] **Step 3: `tests/test_server_debug_session_migration.py`**

In `_create_debug_ready_run` (~line 171–215): same two edits (vmlinux ~line 188; boot `details` ~line 206). Import helpers.

- [ ] **Step 4: `tests/test_server_debug_reads_while_halted.py`**

In `_create_debug_ready_run` (~line 91–135): same two edits (vmlinux ~line 109; boot `details` ~line 127). Import helpers.

- [ ] **Step 5: `tests/test_phase_b_integration_gaps.py`**

In `_create_debug_ready_run` (~line 320–360): same two edits (vmlinux ~line 337; boot `details` ~line 355). Import helpers.

- [ ] **Step 6: Run each migrated file**

Run:
```bash
uv run python -m pytest tests/test_debug_handlers.py tests/test_session_guard_wiring.py \
  tests/test_server_debug_session_migration.py tests/test_server_debug_reads_while_halted.py \
  tests/test_phase_b_integration_gaps.py -q
```
Expected: PASS. If a test asserts on exact boot-step `details` equality (e.g. `test_debug_start_session_records_manifest_debug_step` checks `boot_metadata`), confirm those assertions read `boot_metadata` (which is derived, not the raw boot `details`) and are unaffected; if any asserts equality on the raw boot `details`, update it to include the new `kernel_provenance` key.

- [ ] **Step 7: Commit**

```bash
git add tests/test_debug_handlers.py tests/test_session_guard_wiring.py \
  tests/test_server_debug_session_migration.py tests/test_server_debug_reads_while_halted.py \
  tests/test_phase_b_integration_gaps.py
git commit -m "test: seed kernel_provenance + real-ELF vmlinux for gdb-handler tests (#70)"
```

---

## Task 8: Full guardrails + spec status

**Files:**
- Modify: `docs/superpowers/specs/2026-05-29-symbol-version-lock-design.md` (Status → accepted)

- [ ] **Step 1: Flip spec status**

Change the header `**Status:** proposed` → `**Status:** accepted`.

- [ ] **Step 2: Run the whole guardrail set**

Run:
```bash
uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q && just check-docs
```
Expected: all green, zero warnings.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-05-29-symbol-version-lock-design.md
git commit -m "docs(symbols): mark #70 version-lock spec accepted"
```

---

## Self-review checklist (run before handing off)

- Spec §3.1 primitive → Task 1. §3.2 handler consumption (extraction, unconditional, placement after short-circuit, recovery) → Tasks 3–4. §2 failure contract codes/categories → Task 3 helper + Task 6 assertions. §4 test plan (match/mismatch/unreadable/missing/corrupt/idempotent/unconditional) → Task 6; primitive unit tests → Task 2; opt-in seeding helper + unchanged shared fixtures → Tasks 5/7.
- No placeholders: every code step shows complete code.
- Type consistency: `verify_vmlinux_provenance(*, expected_build_id, vmlinux_path, build_id_reader)` used identically in Tasks 1, 3, 6; `_verify_gdb_symbol_version_lock(*, boot_result, vmlinux_path, run_id, build_id_reader)` defined in Task 3, called in Task 4; codes `provenance_missing` / `provenance_corrupt` / `vmlinux_build_id_unreadable` / `provenance_mismatch` consistent across Task 3 and Task 6.
