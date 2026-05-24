# Simplification Review Followups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce low-risk duplication and test-only surface introduced by the Phase 4 debug branch while preserving behavior.

**Architecture:** Keep the cleanup local to the existing provider and server modules. Consolidate only repeated helpers with identical behavior, remove test fixture code from production, and keep larger workflow orchestration extraction deferred because it crosses build, boot, test, and debug behavior.

**Tech Stack:** Python, Pydantic models, pytest, existing MCP server handlers.

---

## Review Scope

Target diff: `main..HEAD`.

Subagent review passes:
- Reuse reviewer
- Quality reviewer
- Efficiency reviewer

## Files

- Modify: `src/linux_debug_mcp/providers/qemu_gdbstub.py`
  - Derive provider operation list from `PHASE_4_DEBUG_OPERATIONS`.
  - Remove `write_session_for_test()` from production code.
  - Collapse failure transcript write/append helpers into one helper with explicit file mode.
  - Avoid repeated existing-artifact scans where practical.
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py`
  - Remove dict-aware `GdbstubEndpoint.__eq__`.
  - Reuse one selector during console streaming.
  - Remove per-chunk console log flush.
- Modify: `src/linux_debug_mcp/server.py`
  - Remove `_active_debug_session_from_result()` in favor of `_debug_session_details_from_result()`.
  - Consolidate debug read/stateful handler execution into a shared helper that optionally persists the manifest.
- Modify: `tests/test_qemu_gdbstub_provider.py`
  - Add a local `write_session_for_test()` fixture helper and update call sites.
- Modify: `tests/test_libvirt_qemu_provider.py`
  - Compare `GdbstubEndpoint.as_dict()` explicitly.
- Test: `tests/test_qemu_gdbstub_provider.py`
- Test: `tests/test_libvirt_qemu_provider.py`
- Test: `tests/test_debug_handlers.py`

## Deferred Findings

- Broad extraction of `workflow_build_boot_test_handler()` and `workflow_build_boot_debug_handler()` is deferred. It is a valid simplification target, but it spans immutable run request semantics, failure collection behavior, and terminal step differences. That should be a separate refactor with narrower tests.
- Shared endpoint parsing between boot-time string input and debug-time dict input is deferred. The current branch has different public input shapes and error messages; consolidating them safely requires an explicit compatibility pass.
- Moving `debug.start_session` manifest loading entirely under `debug_lock` is deferred because it can change error ordering for malformed runs with an active session.

## Tasks

### Task 1: Provider Constants and Test Fixture Cleanup

**Files:**
- Modify: `src/linux_debug_mcp/providers/qemu_gdbstub.py`
- Modify: `tests/test_qemu_gdbstub_provider.py`

- [ ] **Step 1: Add a local test helper**

Move the current `QemuGdbstubProvider.write_session_for_test()` body into `tests/test_qemu_gdbstub_provider.py` as `write_session_for_test(run_dir, *, state="stopped", controller_mode="batch", pid=None)`.

- [ ] **Step 2: Update test call sites**

Replace `provider.write_session_for_test(...)` with `write_session_for_test(...)`.

- [ ] **Step 3: Remove production helper**

Delete `QemuGdbstubProvider.write_session_for_test()` from `src/linux_debug_mcp/providers/qemu_gdbstub.py`.

- [ ] **Step 4: Derive operation constants**

Import `PHASE_4_DEBUG_OPERATIONS` from `linux_debug_mcp.config` and set:

```python
QEMU_GDBSTUB_OPERATIONS = ["workflow.build_boot_debug", *PHASE_4_DEBUG_OPERATIONS]
```

- [ ] **Step 5: Verify provider tests**

Run: `pytest tests/test_qemu_gdbstub_provider.py -q`

Expected: all tests pass.

### Task 2: Transcript and Artifact Helper Cleanup

**Files:**
- Modify: `src/linux_debug_mcp/providers/qemu_gdbstub.py`
- Test: `tests/test_qemu_gdbstub_provider.py`

- [ ] **Step 1: Replace duplicate failure transcript helpers**

Create one `_record_failure_transcript(..., mode: Literal["w", "a"])` helper with the current transcript body.

- [ ] **Step 2: Update call sites**

Use `mode="w"` in `start_session()` and `mode="a"` in `_run_read_operation()`.

- [ ] **Step 3: Reuse existing-artifact calculation**

Where artifacts are checked immediately after writes, compute `_existing_artifacts(artifacts)` once and reuse it for subsequent success or failure returns in the same block.

- [ ] **Step 4: Verify provider tests**

Run: `pytest tests/test_qemu_gdbstub_provider.py -q`

Expected: all tests pass.

### Task 3: Libvirt Provider Runtime Cleanup

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py`
- Modify: `tests/test_libvirt_qemu_provider.py`

- [ ] **Step 1: Remove custom equality**

Delete `GdbstubEndpoint.__eq__()`.

- [ ] **Step 2: Update endpoint assertion**

Change the debug boot test to assert `plan.gdbstub_endpoint is not None` and compare `plan.gdbstub_endpoint.as_dict()`.

- [ ] **Step 3: Reuse console selector**

Create/register one `selectors.DefaultSelector()` in `stream_console()` when `process.stdout` has a file descriptor. Pass the selector to `_read_console_line()`.

- [ ] **Step 4: Remove per-chunk flush**

Delete `output_file.flush()` inside the console read loop.

- [ ] **Step 5: Verify libvirt tests**

Run: `pytest tests/test_libvirt_qemu_provider.py -q`

Expected: all tests pass.

### Task 4: Server Debug Handler Consolidation

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Test: `tests/test_debug_handlers.py`

- [ ] **Step 1: Remove redundant active-session helper**

Delete `_active_debug_session_from_result()` and call `_debug_session_details_from_result(existing)` directly.

- [ ] **Step 2: Extract shared debug operation helper**

Replace `_debug_read_response()` and `_debug_stateful_response()` internals with a shared `_debug_operation_response()` that accepts:

```python
persist_manifest: bool
allow_ended: bool = False
```

For `persist_manifest=True`, merge `_debug_session_manifest_details()` with `result.details` and record the `debug` step result with `replace_succeeded=True`.

- [ ] **Step 3: Preserve response behavior**

Keep success suggested actions as `["artifacts.get_manifest"]`. Keep provider error suggested actions as `["debug.start_session", "artifacts.get_manifest"]`. Keep failed result diagnostics in `details["diagnostic"]`.

- [ ] **Step 4: Verify handler tests**

Run: `pytest tests/test_debug_handlers.py -q`

Expected: all tests pass.

### Task 5: Final Verification and Commit

**Files:**
- All modified files.

- [ ] **Step 1: Run focused test set**

Run:

```bash
pytest tests/test_qemu_gdbstub_provider.py tests/test_libvirt_qemu_provider.py tests/test_debug_handlers.py -q
```

Expected: all tests pass.

- [ ] **Step 2: Run full suite**

Run:

```bash
pytest -q
```

Expected: all tests pass.

- [ ] **Step 3: Inspect diff**

Run:

```bash
git diff --stat
git diff --check
```

Expected: scoped code cleanup, no whitespace errors.

- [ ] **Step 4: Commit**

Run:

```bash
git add docs/superpowers/plans/2026-05-23-simplification-review-followups.md src/linux_debug_mcp/providers/qemu_gdbstub.py src/linux_debug_mcp/providers/libvirt_qemu.py src/linux_debug_mcp/server.py tests/test_qemu_gdbstub_provider.py tests/test_libvirt_qemu_provider.py
git commit -m "refactor: address simplification review followups"
```
