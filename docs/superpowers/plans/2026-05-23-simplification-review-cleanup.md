# Simplification Review Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce low-risk duplication and avoidable work found by the `main..HEAD` simplification review while preserving the Phase 1 kernel build behavior.

**Architecture:** Keep public tool behavior and data shapes unchanged. Extract private helpers only where current code repeats the same mechanics: file locks, existing build responses, and terminal build finalization. Keep broader profile registry ownership and test fixture consolidation out of this commit because those introduce more design churn than this cleanup needs.

**Tech Stack:** Python 3, Pydantic models, pytest, existing `ArtifactStore`, `ToolResponse`, and local kernel build provider abstractions.

---

### Task 1: Simplify Exclusive File Locks

**Files:**
- Modify: `src/linux_debug_mcp/artifacts/store.py`
- Test: `tests/test_artifacts.py`

- [ ] **Step 1: Run existing lock tests before editing**

Run:
```bash
pytest tests/test_artifacts.py::test_existing_manifest_lock_returns_structured_state_error tests/test_artifacts.py::test_build_lock_excludes_concurrent_builds -q
```

Expected: PASS. These tests already cover the behavior being preserved, so no new public behavior test is needed.

- [ ] **Step 2: Extract one private lock context manager**

In `src/linux_debug_mcp/artifacts/store.py`, add:
```python
    @contextmanager
    def _file_lock(self, lock_path: Path, *, locked_message: str, failure_prefix: str) -> Iterator[None]:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise ManifestStateError(locked_message, ErrorCategory.INFRASTRUCTURE_FAILURE) from exc
        except OSError as exc:
            raise ManifestStateError(f"{failure_prefix}: {exc}") from exc
        try:
            os.write(fd, str(os.getpid()).encode("ascii"))
            yield
        finally:
            os.close(fd)
            with suppress(FileNotFoundError):
                lock_path.unlink()
```

Replace `build_lock()` and `_manifest_lock()` bodies so they delegate to `_file_lock()` with the same filenames and error messages.

- [ ] **Step 3: Run lock tests**

Run:
```bash
pytest tests/test_artifacts.py::test_existing_manifest_lock_returns_structured_state_error tests/test_artifacts.py::test_build_lock_excludes_concurrent_builds -q
```

Expected: PASS.

### Task 2: Reuse Existing Build State Responses

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Test: `tests/test_kernel_build_handler.py`

- [ ] **Step 1: Run existing state tests before editing**

Run:
```bash
pytest tests/test_kernel_build_handler.py::test_kernel_build_repeat_success_returns_recorded_result tests/test_kernel_build_handler.py::test_kernel_build_existing_running_state_fails_without_rerun tests/test_kernel_build_handler.py::test_kernel_build_existing_running_state_takes_precedence_over_missing_source -q
```

Expected: PASS. These tests already pin success reuse, stale running state, and ordering before source validation.

- [ ] **Step 2: Add private response helpers**

In `src/linux_debug_mcp/server.py`, add helpers near `RUNNING_BUILD_MESSAGE`:
```python
def _recorded_build_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.success(
        summary=result.summary,
        run_id=run_id,
        data=result.details,
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _running_build_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=RUNNING_BUILD_MESSAGE,
        run_id=run_id,
        details=result.details,
        suggested_next_actions=["artifacts.get_manifest"],
    )
```

Replace duplicated response construction in `kernel_build_handler()` with these helpers. Keep both pre-lock and locked checks in place.

- [ ] **Step 3: Run handler state tests**

Run:
```bash
pytest tests/test_kernel_build_handler.py::test_kernel_build_repeat_success_returns_recorded_result tests/test_kernel_build_handler.py::test_kernel_build_existing_running_state_fails_without_rerun tests/test_kernel_build_handler.py::test_kernel_build_existing_running_state_takes_precedence_over_missing_source -q
```

Expected: PASS.

### Task 3: Centralize Build Result Finalization

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_kernel_build.py`
- Test: `tests/test_local_kernel_build.py`

- [ ] **Step 1: Add a targeted test for summary-write failure on nonzero builds**

Add this test to `tests/test_local_kernel_build.py`:
```python
def test_execute_nonzero_summary_write_failure_returns_infrastructure_failure(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "build"
    summary_parent = tmp_path / "summary-parent"
    source.mkdir()
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    summary_parent.write_text("not a directory", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=FakeRunner(returncode=2, output="failed\n"))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=tmp_path / "build.log",
        summary_path=summary_parent / "build-summary.json",
    )

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.INFRASTRUCTURE_FAILURE
```

- [ ] **Step 2: Run the new test and verify it passes before refactor**

Run:
```bash
pytest tests/test_local_kernel_build.py::test_execute_nonzero_summary_write_failure_returns_infrastructure_failure -q
```

Expected: PASS. This confirms existing behavior before centralizing finalization.

- [ ] **Step 3: Extract `_finalize_build_result()`**

In `LocalKernelBuildProvider`, add a helper that writes the summary once and returns either the intended `BuildExecutionResult` or `_infrastructure_failure()` if writing the summary raises `OSError`:
```python
    def _finalize_build_result(
        self,
        *,
        plan: BuildPlan,
        log_path: Path,
        summary_path: Path,
        details: dict[str, object],
        artifacts: list[ArtifactRef],
        status: StepStatus,
        summary: str,
        error_category: ErrorCategory | None = None,
        diagnostic: str | None = None,
    ) -> BuildExecutionResult:
        try:
            self._write_summary(summary_path=summary_path, details=details, artifacts=artifacts)
        except OSError as exc:
            return self._infrastructure_failure(exc=exc, plan=plan, log_path=log_path, details=details)
        return BuildExecutionResult(
            status=status,
            summary=summary,
            artifacts=artifacts,
            details=details,
            error_category=error_category,
            diagnostic=diagnostic,
        )
```

Update the nonzero exit, missing artifact, and success branches to use this helper.

- [ ] **Step 4: Run provider tests**

Run:
```bash
pytest tests/test_local_kernel_build.py -q
```

Expected: PASS.

### Task 4: Avoid Full Build Log Reads for Diagnostics

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_kernel_build.py`
- Test: `tests/test_local_kernel_build.py`

- [ ] **Step 1: Add a bounded tail behavior test**

Add this test to `tests/test_local_kernel_build.py`:
```python
def test_log_tail_reads_recent_suffix_and_redacts(tmp_path: Path) -> None:
    log_path = tmp_path / "build.log"
    log_path.write_text("a" * 5000 + " token=secret\n", encoding="utf-8")
    provider = LocalKernelBuildProvider()

    tail = provider._log_tail(log_path, limit=32)

    assert tail is not None
    assert len(tail) <= 64
    assert "token=[REDACTED]" in tail
```

- [ ] **Step 2: Run the new test and verify it passes before refactor**

Run:
```bash
pytest tests/test_local_kernel_build.py::test_log_tail_reads_recent_suffix_and_redacts -q
```

Expected: PASS. The test captures required output behavior before changing the implementation.

- [ ] **Step 3: Change `_log_tail()` to seek near EOF**

Implement `_log_tail()` with binary reads:
```python
    def _log_tail(self, log_path: Path, *, limit: int = 4000) -> str | None:
        if not log_path.is_file():
            return None
        with log_path.open("rb") as log_file:
            log_file.seek(0, os.SEEK_END)
            size = log_file.tell()
            log_file.seek(max(size - limit, 0))
            text = log_file.read().decode("utf-8", errors="replace")
        return self.redactor.redact_text(text)
```

- [ ] **Step 4: Run provider tests**

Run:
```bash
pytest tests/test_local_kernel_build.py -q
```

Expected: PASS.

### Task 5: Remove Redundant Target Validation Branch

**Files:**
- Modify: `src/linux_debug_mcp/config.py`
- Test: `tests/test_config.py`

- [ ] **Step 1: Run target validation tests before editing**

Run:
```bash
pytest tests/test_config.py -q
```

Expected: PASS.

- [ ] **Step 2: Make regex/checks non-overlapping**

In `BuildProfile.validate_targets()`, use one regex that expresses the whole target policy and remove the unreachable `if "=" in target or target.startswith("-")` branch:
```python
        target_pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./+-]*$")
        for target in value:
            if not target_pattern.match(target):
                raise ValueError(f"target {target!r} is not a simple make target")
        return value
```

- [ ] **Step 3: Run config tests**

Run:
```bash
pytest tests/test_config.py -q
```

Expected: PASS.

### Task 6: Final Verification and Commit

**Files:**
- Verify all modified files

- [ ] **Step 1: Run focused tests**

Run:
```bash
pytest tests/test_artifacts.py tests/test_config.py tests/test_kernel_build_handler.py tests/test_local_kernel_build.py -q
```

Expected: PASS.

- [ ] **Step 2: Run full test suite**

Run:
```bash
pytest -q
```

Expected: PASS.

- [ ] **Step 3: Review diff**

Run:
```bash
git diff --stat
git diff -- src/linux_debug_mcp/artifacts/store.py src/linux_debug_mcp/config.py src/linux_debug_mcp/providers/local_kernel_build.py src/linux_debug_mcp/server.py tests/test_local_kernel_build.py
```

Expected: diff only contains the planned simplifications and targeted tests.

- [ ] **Step 4: Commit**

Run:
```bash
git add docs/superpowers/plans/2026-05-23-simplification-review-cleanup.md src/linux_debug_mcp/artifacts/store.py src/linux_debug_mcp/config.py src/linux_debug_mcp/providers/local_kernel_build.py src/linux_debug_mcp/server.py tests/test_config.py tests/test_kernel_build_handler.py tests/test_local_kernel_build.py
git commit -m "refactor: simplify kernel build cleanup paths"
```

Expected: commit succeeds.
