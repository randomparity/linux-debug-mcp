# Simplification Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the lowest-risk simplification recommendations from the `main..HEAD` review while preserving Phase 3 smoke-test and artifact behavior.

**Architecture:** Keep provider-specific SSH validation in `LocalSshTestProvider`, keep response redaction in server helpers, and avoid loading full SSH command output into memory when artifacts already contain complete logs. Defer larger workflow-loop and artifact-bundling module moves because they touch broader observable control flow and can be handled in a separate refactor.

**Tech Stack:** Python 3.11, Pydantic 2, pytest, ruff.

---

### Task 1: Remove Duplicate Ad Hoc Command Validation

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Test: `tests/test_target_run_tests_handler.py`

- [ ] **Step 1: Add a failing test for Pydantic-backed ad hoc validation**

Add a test that sends an invalid ad hoc command and asserts the handler still returns a configuration error:

```python
def test_run_tests_rejects_empty_adhoc_argv_entry(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        commands=[[""]],
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
        provider=FakeTestProvider(),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "test command argv entries" in response.error.message
```

- [ ] **Step 2: Run the focused test**

Run: `pytest tests/test_target_run_tests_handler.py::test_run_tests_rejects_empty_adhoc_argv_entry -q`

Expected: FAIL until `_validate_adhoc_commands()` lets `TestCommand` own validation.

- [ ] **Step 3: Simplify `_validate_adhoc_commands()`**

Remove the manual `unicodedata` import and loop. Construct `TestCommand` directly and let its validators raise `ValueError` through Pydantic.

- [ ] **Step 4: Re-run the focused test**

Run: `pytest tests/test_target_run_tests_handler.py::test_run_tests_rejects_empty_adhoc_argv_entry -q`

Expected: PASS.

### Task 2: Let the SSH Test Provider Own SSH Capability Validation

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Test: `tests/test_target_run_tests_handler.py`

- [ ] **Step 1: Tighten the existing provider rejection test**

Update `test_run_tests_rejects_rootfs_missing_ssh_endpoint_as_configuration_error` to use the real `LocalSshTestProvider` path instead of a fake provider, proving the handler maps provider `ValueError` to configuration errors.

- [ ] **Step 2: Run the focused test**

Run: `pytest tests/test_target_run_tests_handler.py::test_run_tests_rejects_rootfs_missing_ssh_endpoint_as_configuration_error -q`

Expected: PASS before and after, guarding behavior while implementation shrinks.

- [ ] **Step 3: Remove duplicate handler checks**

Delete the handler-level `access_method`, `ssh_host`, and `ssh_user` checks. Keep rootfs lookup and existing `except ValueError` around `provider.plan_tests()`.

- [ ] **Step 4: Re-run the target handler tests**

Run: `pytest tests/test_target_run_tests_handler.py -q`

Expected: PASS.

### Task 3: Centralize Cached Artifact Collection Responses

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Test: `tests/test_artifacts_collect_handler.py`

- [ ] **Step 1: Add or rely on cached collect tests**

Use existing cached-success tests in `tests/test_artifacts_collect_handler.py` to guard behavior.

- [ ] **Step 2: Extract `_recorded_collect_success_response()`**

Create a helper that builds the cached successful artifact collection response once with the current redaction and `artifacts.get_manifest` suggested action.

- [ ] **Step 3: Replace both duplicated branches**

Use the helper before acquiring the collect lock and inside the lock.

- [ ] **Step 4: Run artifact collection tests**

Run: `pytest tests/test_artifacts_collect_handler.py -q`

Expected: PASS.

### Task 4: Avoid Full SSH Output Re-Reads for Snippets

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_ssh_tests.py`
- Test: `tests/test_local_ssh_tests_provider.py`

- [ ] **Step 1: Add a failing snippet truncation test**

Add a test with output longer than `_SNIPPET_LIMIT` and assert metadata snippets are truncated while `stdout.txt` keeps the full output.

- [ ] **Step 2: Run the focused test**

Run: `pytest tests/test_local_ssh_tests_provider.py::test_execute_truncates_snippets_but_preserves_full_stdout_artifact -q`

Expected: FAIL until command metadata reads bounded snippets from artifact files.

- [ ] **Step 3: Change `SshCommandResult` and subprocess runner**

Make `SshCommandResult` carry `stdout_snippet` and `stderr_snippet`. In `SubprocessSshRunner`, do not read whole stdout/stderr files after subprocess completion; read only `_SNIPPET_LIMIT` chars from each path.

- [ ] **Step 4: Update metadata and fake runner tests**

Have `_command_metadata()` use snippet fields, and update `FakeSshRunner` to fill snippets after writing artifacts.

- [ ] **Step 5: Run provider tests**

Run: `pytest tests/test_local_ssh_tests_provider.py -q`

Expected: PASS.

### Task 5: Verify and Commit

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Modify: `src/linux_debug_mcp/providers/local_ssh_tests.py`
- Modify: `tests/test_target_run_tests_handler.py`
- Modify: `tests/test_local_ssh_tests_provider.py`

- [ ] **Step 1: Run targeted tests**

Run: `pytest tests/test_target_run_tests_handler.py tests/test_artifacts_collect_handler.py tests/test_local_ssh_tests_provider.py -q`

Expected: PASS.

- [ ] **Step 2: Run full test suite**

Run: `pytest -q`

Expected: PASS.

- [ ] **Step 3: Run lint**

Run: `ruff check .`

Expected: PASS.

- [ ] **Step 4: Commit**

Run:

```bash
git add docs/superpowers/plans/2026-05-23-simplification-review-fixes.md src/linux_debug_mcp/server.py src/linux_debug_mcp/providers/local_ssh_tests.py tests/test_target_run_tests_handler.py tests/test_local_ssh_tests_provider.py
git commit -m "refactor: apply simplification review fixes"
```
