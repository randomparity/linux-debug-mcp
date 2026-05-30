# gdb/MI prerequisite — behavioral-primary gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the mi3 `^done` behavioral probe the authoritative gdb prerequisite gate, demoting the gdb version string to advisory context, per ADR 0025 / issue #84.

**Architecture:** `_gdb_mi_capability_check` in `prereqs/checks.py` currently fails a host when `version < 9.1` *before* consulting the behavioral probe. This plan removes the version early-return, reorders so the `mi_code == 0 and "^done" in mi_out` behavioral check decides pass/fail, and records the version as advisory `details` (`version`, `mi3_documented_minimum`, `version_below_documented_minimum`). It also removes the now-dead duplicate `MIN_GDB_VERSION` constant in `providers/gdb_mi.py`.

**Tech Stack:** Python 3.11+, pytest, ruff, ty. Handler/probe-level tests with an injected `FakeRunner` (no real gdb).

---

## File Structure

- `src/linux_debug_mcp/prereqs/checks.py` — `_gdb_mi_capability_check` (the probe), `_MI_MIN_VERSION` (the one documented-minimum constant). All behavior change is local to this one function.
- `src/linux_debug_mcp/providers/gdb_mi.py` — remove the unused `MIN_GDB_VERSION = (9, 1)` constant (line 23-24, comment + assignment).
- `tests/test_prereqs_gdb_mi.py` — invert the old-gdb test, add advisory-flag assertions, add the unparseable-version-no-`^done` regression test and the `^done`-substring-with-nonzero-exit spoofing test.

No new files. No new dependencies.

---

## Task 1: Behavioral probe decides pass/fail; version becomes advisory

**Files:**
- Modify: `src/linux_debug_mcp/prereqs/checks.py:110-162` (`_gdb_mi_capability_check`)
- Test: `tests/test_prereqs_gdb_mi.py`

- [ ] **Step 1: Rewrite the existing old-gdb test to expect a pass with an advisory flag**

In `tests/test_prereqs_gdb_mi.py`, replace `test_gdb_mi_probe_fails_on_old_gdb_naming_versions` with:

```python
def test_gdb_mi_probe_passes_on_old_gdb_that_answers_mi3(tmp_path: Path) -> None:
    # A sub-9.1 gdb that emits a valid ^done is admitted on the behavioral signal (ADR 0025);
    # the below-minimum version rides along as advisory context, not a veto.
    runner = FakeRunner(present=True, version_out="GNU gdb (GDB) 8.3.1\n", mi_out="^done\n(gdb)\n")
    check = _check(runner, tmp_path)
    assert check.status == "passed"
    assert check.details["version"] == "8.3"
    assert check.details["mi3_documented_minimum"] == "9.1"
    assert check.details["version_below_documented_minimum"] is True
    assert "8.3" in check.message
```

- [ ] **Step 2: Add a clean-pass assertion that the advisory flag is False**

Append to `tests/test_prereqs_gdb_mi.py`:

```python
def test_gdb_mi_probe_pass_on_modern_gdb_sets_advisory_flag_false(tmp_path: Path) -> None:
    runner = FakeRunner(present=True, version_out="GNU gdb (GDB) 12.1\n", mi_out="^done,features=[]\n(gdb)\n")
    check = _check(runner, tmp_path)
    assert check.status == "passed"
    assert check.details["version"] == "12.1"
    assert check.details["version_below_documented_minimum"] is False
```

- [ ] **Step 3: Add the unparseable-version regression tests (pass and fail variants)**

Append to `tests/test_prereqs_gdb_mi.py`:

```python
def test_gdb_mi_probe_passes_when_version_unparseable_but_done_present(tmp_path: Path) -> None:
    # gdb present, --version unparseable, but the behavioral probe yields ^done -> pass on behavior.
    runner = FakeRunner(present=True, version_out="some gdb banner with no version\n", mi_out="^done\n(gdb)\n")
    check = _check(runner, tmp_path)
    assert check.status == "passed"
    assert check.details["version"] == "unknown"
    assert check.details["version_below_documented_minimum"] is True


def test_gdb_mi_probe_fails_with_unknown_version_and_no_done(tmp_path: Path) -> None:
    # The version early-return is gone, so this path is now reachable with version=None. It must
    # format the version as "unknown" and never index a None version (ADR 0025 decision 4).
    runner = FakeRunner(present=True, version_out="no version here\n", mi_out="garbage\n", mi_code=1)
    check = _check(runner, tmp_path)
    assert check.status == "failed"
    assert "unknown" in check.message
    assert "mi3" in check.message.lower()
```

- [ ] **Step 4: Add the `^done`-substring-with-nonzero-exit spoofing test**

Append to `tests/test_prereqs_gdb_mi.py`:

```python
def test_gdb_mi_probe_fails_when_done_present_but_exit_nonzero(tmp_path: Path) -> None:
    # mi_code == 0 is a required conjunct: a non-zero exit fails even if output contains ^done.
    runner = FakeRunner(present=True, version_out="GNU gdb (GDB) 12.1\n", mi_out="^done\n", mi_code=1)
    check = _check(runner, tmp_path)
    assert check.status == "failed"
    assert "mi3" in check.message.lower()
```

- [ ] **Step 5: Run the tests and confirm the new/changed ones fail**

Run: `uv run python -m pytest tests/test_prereqs_gdb_mi.py -q`
Expected: `test_gdb_mi_probe_passes_on_old_gdb_that_answers_mi3`, `..._advisory_flag_false`, `..._when_version_unparseable_but_done_present`, `..._fails_with_unknown_version_and_no_done` FAIL (the old code returns `failed` with a "too old" message for the 8.3 case, raises/KeyErrors on `details["version_below_documented_minimum"]`, and on the unparseable-no-`^done` case takes the version early-return path with a "too old" message). The `..._nonzero_exit` test already passes under old code (the version gate passes 12.1, then `mi_code != 0` fails) — that is fine; it pins behavior that must survive.

- [ ] **Step 6: Rewrite `_gdb_mi_capability_check` so the behavioral probe is primary**

In `src/linux_debug_mcp/prereqs/checks.py`, replace the version-gate block (lines 138-162, from `version = _parse_gdb_version(version_out)` through the final `return`) with:

```python
    version = _parse_gdb_version(version_out)
    detected = f"{version[0]}.{version[1]}" if version is not None else "unknown"
    if mi_code != 0 or "^done" not in mi_out:
        return PrerequisiteCheck(
            check_id="tool.gdb_mi",
            status=PrerequisiteStatus.FAILED,
            message=(
                f"gdb {detected} did not return a valid mi3 ^done record; the debug.gdb "
                f"tier requires a working mi3 interpreter"
            ),
            suggested_fix=f"Confirm a gdb with mi3 support (>= {required} documents it) is installed.",
        )
    below_minimum = version is None or version < _MI_MIN_VERSION
    message = f"gdb {detected} supports the mi3 machine interface"
    if below_minimum:
        message += (
            f" (admitted on the behavioral mi3 probe; reported version is below the documented "
            f"minimum {required})"
        )
    return PrerequisiteCheck(
        check_id="tool.gdb_mi",
        status=PrerequisiteStatus.PASSED,
        message=message,
        details={
            "version": detected,
            "mi3_documented_minimum": required,
            "version_below_documented_minimum": below_minimum,
        },
    )
```

- [ ] **Step 7: Update the function docstring to match the behavioral-primary contract**

In `src/linux_debug_mcp/prereqs/checks.py`, replace the `_gdb_mi_capability_check` docstring (lines 111-113) with:

```python
    """Verify gdb can drive the mi3 machine interface the debug.gdb tier requires. The behavioral
    probe is authoritative (ADR 0025): a host passes iff gdb is present, the probe runs, and it
    returns ``mi_code == 0`` with a ``^done`` record. The reported version is advisory only --
    recorded in ``details`` and named in messages, never a veto -- because the documented ``9.1``
    minimum is a manual statement, not the exact capability boundary."""
```

- [ ] **Step 8: Run the gdb-mi prereq tests and confirm all pass**

Run: `uv run python -m pytest tests/test_prereqs_gdb_mi.py -q`
Expected: PASS (all tests, including the unchanged `test_gdb_mi_probe_passes_on_modern_gdb`, `test_gdb_mi_probe_fails_when_no_done_record`, `test_gdb_mi_probe_fails_when_gdb_absent`, `test_gdb_mi_probe_uses_gdb_version_not_distro_packaging_token`).

- [ ] **Step 9: Commit**

```bash
git add src/linux_debug_mcp/prereqs/checks.py tests/test_prereqs_gdb_mi.py
git commit -m "fix(prereqs): make mi3 ^done probe the primary gdb gate (#84)"
```

---

## Task 2: Remove the dead duplicate version constant

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py:23-24`

- [ ] **Step 1: Confirm the constant is unused outside its own definition**

Run: `rg -n "MIN_GDB_VERSION" src/ tests/`
Expected: exactly one hit — the definition at `src/linux_debug_mcp/providers/gdb_mi.py:24`. (If any other reference exists, stop: it is not dead, and removing it is out of scope; revisit the ADR decision 5.)

- [ ] **Step 2: Delete the constant and its comment**

In `src/linux_debug_mcp/providers/gdb_mi.py`, remove these two lines (23-24):

```python
# Minimum gdb release that documents the mi3 interpreter (GDB manual "GDB/MI" chapter).
MIN_GDB_VERSION = (9, 1)
```

- [ ] **Step 3: Confirm the module still imports and the engine suite passes**

Run: `uv run python -m pytest tests/test_gdb_mi_engine.py tests/test_gdb_mi_core_ops.py -q`
Expected: PASS (no reference to the removed constant; import succeeds).

- [ ] **Step 4: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py
git commit -m "refactor(gdb-mi): drop unused MIN_GDB_VERSION constant (#84)"
```

---

## Task 3: Full guardrail sweep

**Files:** none (verification only)

- [ ] **Step 1: Lint, format, type-check, full test suite, docs guard**

Run:
```bash
uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q && just check-docs
```
Expected: ruff clean, format clean, ty clean (zero errors), pytest all pass (integration tests skipped as usual), check-docs passes.

- [ ] **Step 2: If anything is red, fix it before proceeding**

Zero-warnings policy: fix every warning or add a justified inline ignore. Do not advance with a red guardrail.

---

## Self-Review

**Spec coverage** (ADR 0025 decisions):
- Decision 1 (behavioral primary) → Task 1 Step 6 (behavioral check decides; version early-return removed).
- Decision 2 (version advisory, `details["version"]="unknown"` when unparseable) → Task 1 Step 6 (`detected`, `details`), Step 3 test.
- Decision 3 (machine-detectable advisory flag) → Task 1 Step 6 (`version_below_documented_minimum`), Steps 1-3 tests.
- Decision 4 (no `version[0]` deref on the now-reachable no-`^done` path) → Task 1 Step 6 (`detected` computed once, used in failure message), Step 3 regression test.
- Decision 5 (single source of truth; drop `MIN_GDB_VERSION`) → Task 2.
- Decision 6 (`mi_code == 0` + `^done` sole gate; spoofing negative test) → Task 1 Step 4 test.
- "no host that previously passed now fails" → covered by the unchanged passing tests in Step 8.

**Placeholder scan:** none — every code/test step shows the literal content.

**Type consistency:** `details` keys (`version`, `mi3_documented_minimum`, `version_below_documented_minimum`) match between the implementation (Step 6) and every test assertion (Steps 1-3). `detected`/`required`/`below_minimum` names are internal to one function. `PrerequisiteCheck`/`PrerequisiteStatus` are the existing domain types (unchanged). `FakeRunner`/`_check` are the existing test helpers (unchanged signatures).
