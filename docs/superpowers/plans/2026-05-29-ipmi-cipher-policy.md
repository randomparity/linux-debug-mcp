# IPMI cipher-suite policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce that IPMI sessions use `lanplus`/cipher-suite-3 and refuse cipher 0, via a contract-layer validator backed by a single policy chokepoint, plus a CI tripwire against hardcoded cipher-0/non-lanplus `ipmitool` literals.

**Architecture:** A new `safety/ipmi.py` owns the cipher allowlist + `validate_ipmi_cipher_suite`. `ConsoleSessionRequest` gains an `ipmi_cipher_suite` field and a model validator that calls the chokepoint for `ipmi-sol` and rejects the field for other methods. A `just check-ipmi` target (mirroring `check-docs`) plus a dedicated CI job greps `src/` for forbidden `ipmitool` literals. The `ipmi-sol` provider remains an unimplemented future stub.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, ripgrep (default Rust-regex engine), just, GitHub Actions. Lint/format `ruff`; types `ty`.

**Spec:** `docs/superpowers/specs/2026-05-29-ipmi-cipher-policy-design.md` · **ADR:** `docs/adr/0014-ipmi-cipher-suite-policy.md`

---

## File structure

- **Create** `src/linux_debug_mcp/safety/ipmi.py` — policy constants, `IpmiPolicyError`, `validate_ipmi_cipher_suite`. No I/O, no provider/server imports.
- **Modify** `src/linux_debug_mcp/providers/contracts.py` — add `ipmi_cipher_suite` field + `model_validator(mode="after")` to `ConsoleSessionRequest`; import from `safety.ipmi`.
- **Modify** `justfile` — add `check-ipmi` target.
- **Modify** `.github/workflows/ci.yml` — add an `ipmi-policy` job running `just check-ipmi`.
- **Create** `tests/test_ipmi_policy.py` — unit tests for the chokepoint and the guard target.
- **Modify** `tests/test_provider_contracts.py` — contract-level accept/reject tests for `ipmi_cipher_suite`.
- **Modify** `tests/test_future_stub_handlers.py` — handler-level `CONFIGURATION_ERROR`/`NOT_IMPLEMENTED` tests for the new field.

No JSON-schema snapshot exists for `ConsoleSessionRequest` (the `introspect_helpers/schemas/*.json` snapshots are unrelated), so none needs regenerating.

---

### Task 1: Policy chokepoint `safety/ipmi.py`

**Files:**
- Create: `src/linux_debug_mcp/safety/ipmi.py`
- Test: `tests/test_ipmi_policy.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_ipmi_policy.py`:

```python
from __future__ import annotations

import pytest

from linux_debug_mcp.safety.ipmi import (
    IPMI_ALLOWED_CIPHER_SUITES,
    IPMI_DEFAULT_CIPHER_SUITE,
    IPMI_FORBIDDEN_CIPHER_SUITE,
    IPMI_INTERFACE,
    IpmiPolicyError,
    check_ipmi_cipher_value,
    validate_ipmi_cipher_suite,
)


def test_policy_constants() -> None:
    assert IPMI_INTERFACE == "lanplus"
    assert IPMI_FORBIDDEN_CIPHER_SUITE == 0
    assert IPMI_DEFAULT_CIPHER_SUITE == 3
    assert IPMI_ALLOWED_CIPHER_SUITES == frozenset({3})
    assert IPMI_FORBIDDEN_CIPHER_SUITE not in IPMI_ALLOWED_CIPHER_SUITES


def test_none_normalizes_to_default() -> None:
    assert validate_ipmi_cipher_suite(None) == IPMI_DEFAULT_CIPHER_SUITE


def test_allowed_suite_passes() -> None:
    assert validate_ipmi_cipher_suite(3) == 3
    assert check_ipmi_cipher_value(3) == 3


def test_cipher_zero_rejected() -> None:
    with pytest.raises(IpmiPolicyError) as exc:
        validate_ipmi_cipher_suite(0)
    assert "0" in str(exc.value)
    with pytest.raises(IpmiPolicyError):
        check_ipmi_cipher_value(0)


@pytest.mark.parametrize("suite", [1, 2, 17, -1, 999])
def test_non_allowlisted_suites_rejected(suite: int) -> None:
    with pytest.raises(IpmiPolicyError):
        validate_ipmi_cipher_suite(suite)
    with pytest.raises(IpmiPolicyError):
        check_ipmi_cipher_value(suite)


def test_ipmi_policy_error_is_value_error() -> None:
    assert issubclass(IpmiPolicyError, ValueError)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_ipmi_policy.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'linux_debug_mcp.safety.ipmi'`.

- [ ] **Step 3: Write minimal implementation**

Create `src/linux_debug_mcp/safety/ipmi.py`:

```python
"""IPMI cipher-suite policy chokepoint.

Single source of truth for the IPMI hardening invariant (issue #67): IPMI must
use the ``lanplus`` interface with an authenticated cipher suite, and cipher
suite 0 (no authentication) is always refused. This module owns the allowlist
and opens no resources; the ``ipmi-sol`` provider (#15) must validate through
``validate_ipmi_cipher_suite`` rather than re-deriving the rule.
"""

from __future__ import annotations

IPMI_INTERFACE = "lanplus"
IPMI_FORBIDDEN_CIPHER_SUITE = 0
IPMI_DEFAULT_CIPHER_SUITE = 3
IPMI_ALLOWED_CIPHER_SUITES: frozenset[int] = frozenset({3})


class IpmiPolicyError(ValueError):
    """Raised when an IPMI configuration violates the cipher-suite policy."""


def check_ipmi_cipher_value(value: int) -> int:
    """Validate a concrete (non-``None``) IPMI cipher suite against the policy.

    Used by field-level validators so the rejection is attributed to the
    offending field. Cipher suite 0 and any suite outside
    ``IPMI_ALLOWED_CIPHER_SUITES`` raise ``IpmiPolicyError``.

    Args:
        value: The requested cipher suite.

    Returns:
        The approved cipher suite integer (unchanged).

    Raises:
        IpmiPolicyError: If the suite is 0 or not in the allowlist.
    """
    if value == IPMI_FORBIDDEN_CIPHER_SUITE:
        raise IpmiPolicyError(
            "IPMI cipher suite 0 disables authentication and is refused; "
            f"use cipher suite {IPMI_DEFAULT_CIPHER_SUITE} (lanplus)"
        )
    if value not in IPMI_ALLOWED_CIPHER_SUITES:
        allowed = ", ".join(str(suite) for suite in sorted(IPMI_ALLOWED_CIPHER_SUITES))
        raise IpmiPolicyError(f"IPMI cipher suite must be one of {{{allowed}}}; got {value}")
    return value


def validate_ipmi_cipher_suite(value: int | None) -> int:
    """Return a policy-approved IPMI cipher suite, taking the default for ``None``.

    The chokepoint the ``ipmi-sol`` provider (#15) calls to resolve an effective
    suite. ``None`` normalizes to ``IPMI_DEFAULT_CIPHER_SUITE``; otherwise the
    value is checked via :func:`check_ipmi_cipher_value`.

    Args:
        value: Requested cipher suite, or ``None`` to take the mandated default.

    Returns:
        The approved cipher suite integer.

    Raises:
        IpmiPolicyError: If the suite is 0 or not in the allowlist.
    """
    if value is None:
        return IPMI_DEFAULT_CIPHER_SUITE
    return check_ipmi_cipher_value(value)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_ipmi_policy.py -q`
Expected: PASS (all tests in the file).

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff check src/linux_debug_mcp/safety/ipmi.py tests/test_ipmi_policy.py
uv run ruff format src/linux_debug_mcp/safety/ipmi.py tests/test_ipmi_policy.py
uv run ty check src
git add src/linux_debug_mcp/safety/ipmi.py tests/test_ipmi_policy.py
git commit -m "feat(ipmi): add cipher-suite policy chokepoint"
```

---

### Task 2: Contract enforcement on `ConsoleSessionRequest`

**Files:**
- Modify: `src/linux_debug_mcp/providers/contracts.py:253-270` (`ConsoleSessionRequest`) and import block at top
- Test: `tests/test_provider_contracts.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_provider_contracts.py` (the file already imports `ConsoleSessionRequest`, `pytest`, `ValidationError`, and defines `assert_rejects`):

```python
def _ipmi_request(**overrides: object) -> dict:
    payload = {
        "architecture": "x86_64",
        "target_name": "vm-01",
        "access_method": "ipmi-sol",
    }
    payload.update(overrides)
    return payload


def test_ipmi_sol_defaults_cipher_to_three() -> None:
    request = ConsoleSessionRequest(**_ipmi_request())
    assert request.ipmi_cipher_suite == 3


def test_ipmi_sol_accepts_explicit_cipher_three() -> None:
    request = ConsoleSessionRequest(**_ipmi_request(ipmi_cipher_suite=3))
    assert request.ipmi_cipher_suite == 3


def test_ipmi_sol_rejects_cipher_zero() -> None:
    with pytest.raises(ValidationError) as exc:
        ConsoleSessionRequest(**_ipmi_request(ipmi_cipher_suite=0))
    assert "ipmi_cipher_suite" in str(exc.value)


@pytest.mark.parametrize("suite", [1, 2, 17])
def test_ipmi_sol_rejects_non_allowlisted_cipher(suite: int) -> None:
    assert_rejects(ConsoleSessionRequest, _ipmi_request(ipmi_cipher_suite=suite))


def test_cipher_rejected_for_non_ipmi_method() -> None:
    payload = {
        "architecture": "x86_64",
        "target_name": "vm-01",
        "access_method": "ssh",
        "ipmi_cipher_suite": 3,
    }
    assert_rejects(ConsoleSessionRequest, payload)


def test_serial_method_without_cipher_is_accepted() -> None:
    request = ConsoleSessionRequest(architecture="x86_64", target_name="vm-01", access_method="serial")
    assert request.ipmi_cipher_suite is None


def test_legacy_ipmi_access_method_rejected() -> None:
    payload = {"architecture": "x86_64", "target_name": "vm-01", "access_method": "ipmi"}
    assert_rejects(ConsoleSessionRequest, payload)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_provider_contracts.py -k ipmi -q`
Expected: FAIL — `test_ipmi_sol_defaults_cipher_to_three` errors with `AttributeError`/`extra fields not permitted` (the field does not exist yet), and the rejection tests fail because cipher 0 is currently accepted.

- [ ] **Step 3: Add the import**

In `src/linux_debug_mcp/providers/contracts.py`, add after the existing `from linux_debug_mcp.domain import Model` line (line 9):

```python
from linux_debug_mcp.safety.ipmi import IPMI_DEFAULT_CIPHER_SUITE, check_ipmi_cipher_value
```

- [ ] **Step 4: Add the field and validators**

Replace `ConsoleSessionRequest` (currently lines 253-270) with:

```python
class ConsoleSessionRequest(ProviderRequest):
    target_name: str
    access_method: str
    credential_ref: str | None = None
    ipmi_cipher_suite: int | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderRequest._safe_label_fields,
        "target_name",
        "access_method",
        "credential_ref",
    )

    @field_validator("access_method")
    @classmethod
    def validate_access_method(cls, value: str) -> str:
        if value not in _CONSOLE_ACCESS_METHODS:
            raise ValueError("console access method is not supported")
        return value

    @field_validator("ipmi_cipher_suite")
    @classmethod
    def validate_cipher_value(cls, value: int | None) -> int | None:
        if value is None:
            return value
        return check_ipmi_cipher_value(value)

    @model_validator(mode="after")
    def enforce_ipmi_cipher_policy(self) -> ConsoleSessionRequest:
        if self.access_method == "ipmi-sol":
            if self.ipmi_cipher_suite is None:
                object.__setattr__(self, "ipmi_cipher_suite", IPMI_DEFAULT_CIPHER_SUITE)
        elif self.ipmi_cipher_suite is not None:
            raise ValueError("ipmi_cipher_suite is only valid for access_method 'ipmi-sol'")
        return self
```

Notes for the engineer:
- **Why two validators.** The value-domain rejection (cipher 0 / non-allowlisted) lives
  in `validate_cipher_value`, a `field_validator`, so Pydantic attributes the error to
  `loc=("ipmi_cipher_suite",)`. A `model_validator(mode="after")` raise has `loc=()`
  (model-level), so the field name would be absent from `validation_errors` and AC1
  would be unmeetable. Verified empirically: field-validator error → `loc=('ipmi_cipher_suite',)`;
  after-model-validator error → `loc=()`. The cross-field rules (default `None→3` for
  `ipmi-sol`; require `None` for non-IPMI methods) genuinely need `access_method`, so
  they stay in the model validator.
- `object.__setattr__` is required for the `None → 3` normalization: a plain
  `self.ipmi_cipher_suite = ...` re-triggers validation under the model's
  `validate_assignment=True`, which re-runs this `mode="after"` validator and recurses.
  Bypassing assignment validation is safe here because the value is the approved default.
  Verified: `object.__setattr__` normalization yields `.ipmi_cipher_suite == 3` with no
  recursion.
- `check_ipmi_cipher_value` raises `IpmiPolicyError(ValueError)`, which Pydantic collects
  as a normal validation error — `_future_stub_handler` maps it to `CONFIGURATION_ERROR`.
- `model_validator` and `field_validator` are already imported in this file (line 7).
- A non-IPMI method with `ipmi_cipher_suite=0` is rejected by the field validator (loc =
  the field); a non-IPMI method with an allowlisted suite (e.g. `3`) passes the field
  validator and is then rejected by the model validator ("only valid for ipmi-sol").
  Both are `CONFIGURATION_ERROR`, satisfying AC4.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run python -m pytest tests/test_provider_contracts.py -k ipmi -q`
Expected: PASS (all 9 parametrized/individual ipmi cases).

- [ ] **Step 6: Run the full contract test module for regressions**

Run: `uv run python -m pytest tests/test_provider_contracts.py -q`
Expected: PASS — the existing `serial`-method `ConsoleSessionRequest` acceptance test (line ~115) still passes because `ipmi_cipher_suite` defaults to `None` and the validator allows `None` for non-ipmi methods.

- [ ] **Step 7: Lint, type-check, commit**

```bash
uv run ruff check src/linux_debug_mcp/providers/contracts.py tests/test_provider_contracts.py
uv run ruff format src/linux_debug_mcp/providers/contracts.py tests/test_provider_contracts.py
uv run ty check src
git add src/linux_debug_mcp/providers/contracts.py tests/test_provider_contracts.py
git commit -m "feat(ipmi): enforce cipher policy in ConsoleSessionRequest"
```

---

### Task 3: Handler-level failure-contract tests

**Files:**
- Test: `tests/test_future_stub_handlers.py`

This task adds no production code — it pins the end-to-end `ToolResponse` contract
(`CONFIGURATION_ERROR` vs `NOT_IMPLEMENTED`) through `console_open_session_handler`,
which is already imported in the test module.

- [ ] **Step 1: Write the failing/asserting tests**

Append to `tests/test_future_stub_handlers.py`:

```python
def test_console_open_ipmi_cipher_zero_is_configuration_error() -> None:
    response = console_open_session_handler(
        architecture="x86_64",
        target_name="host-01",
        access_method="ipmi-sol",
        ipmi_cipher_suite=0,
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    fields = [item["field"] for item in response.error.details["validation_errors"]]
    assert any("ipmi_cipher_suite" in field for field in fields)
    assert response.suggested_next_actions == ["providers.list"]


def test_console_open_ipmi_default_cipher_reaches_not_implemented() -> None:
    response = console_open_session_handler(
        architecture="x86_64",
        target_name="host-01",
        access_method="ipmi-sol",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "not_implemented"
    assert response.error.details["provider_name"] == "console-access-stub"
    assert response.error.details["operation"] == "console.open_session"


def test_console_open_cipher_on_ssh_is_configuration_error() -> None:
    response = console_open_session_handler(
        architecture="x86_64",
        target_name="host-01",
        access_method="ssh",
        ipmi_cipher_suite=3,
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
```

- [ ] **Step 2: Run tests**

Run: `uv run python -m pytest tests/test_future_stub_handlers.py -k "ipmi or cipher" -q`
Expected: PASS — Task 2 already implemented the enforcement, so these should pass immediately. `test_console_open_ipmi_default_cipher_reaches_not_implemented` reaches provider selection; `console.open_session` + `x86_64` resolves to exactly one candidate (`console-access-stub`) — verified against `ProviderRegistry.with_defaults().find_by_operation_and_architecture(...)`, which returns `['console-access-stub']` for both `x86_64` and `ppc64le` — so `select_future_provider` returns the stub (`not_implemented`), never the multi-candidate `configuration_error`.

- [ ] **Step 3: Run the full module for regressions**

Run: `uv run python -m pytest tests/test_future_stub_handlers.py -q`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/test_future_stub_handlers.py
git commit -m "test(ipmi): pin handler failure contract for cipher policy"
```

---

### Task 4: CI guard `just check-ipmi`

**Files:**
- Modify: `justfile` (add `check-ipmi` target after `check-docs`, lines 40-44)
- Test: `tests/test_ipmi_policy.py` (add guard-behavior tests)

- [ ] **Step 1: Write the failing guard tests**

Append to `tests/test_ipmi_policy.py`:

```python
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_check_ipmi() -> subprocess.CompletedProcess[str]:
    just = shutil.which("just")
    if just is None:
        pytest.skip("just is not installed")
    return subprocess.run(
        [just, "check-ipmi"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_check_ipmi_passes_on_clean_tree() -> None:
    result = _run_check_ipmi()
    assert result.returncode == 0, result.stdout + result.stderr


def test_guard_pattern_flags_forbidden_and_passes_compliant(tmp_path: Path) -> None:
    # Mirror the justfile pattern so the regex itself is covered without mutating src/.
    pattern = r"-I lan\b|-C *0\b"
    sample = tmp_path / "sample.txt"
    sample.write_text(
        "ipmitool -I lanplus -C 3 sol activate\n"  # compliant, must NOT match
        "ipmitool -I lanplus -C 30 raw\n"  # multi-digit, must NOT match
        "ipmitool -I lan -U admin\n"  # bare lan, MUST match
        "ipmitool -C 0 chassis\n"  # cipher 0, MUST match
        "ipmitool -C0 power\n"  # cipher 0 no space, MUST match
    )
    rg = shutil.which("rg")
    if rg is None:
        pytest.skip("ripgrep is not installed")
    proc = subprocess.run(
        [rg, "-n", "-e", pattern, str(sample)],
        capture_output=True,
        text=True,
        check=False,
    )
    matched_lines = {line.split(":", 1)[0] for line in proc.stdout.splitlines()}
    assert matched_lines == {"3", "4", "5"}
```

- [ ] **Step 2: Run tests to verify the clean-tree test fails**

Run: `uv run python -m pytest tests/test_ipmi_policy.py -k check_ipmi -q`
Expected: FAIL — `just check-ipmi` does not exist yet (`just` exits non-zero with "Justfile does not contain recipe `check-ipmi`").

- [ ] **Step 3: Add the `check-ipmi` target**

In `justfile`, immediately after the `check-docs` target (after line 44) add:

```makefile
check-ipmi:
    # IPMI hardening guard (issue #67): no hardcoded cipher-0 / non-lanplus
    # ipmitool invocations under src/. safety/ipmi.py is the one file allowed to
    # name the forbidden constant. Patterns are \b-anchored so -I lanplus and
    # -C 3 / -C 30 are not flagged. Default ripgrep engine (no PCRE2).
    ! rg -n -e '-I lan\b|-C *0\b' src -g '!src/linux_debug_mcp/safety/ipmi.py'
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -m pytest tests/test_ipmi_policy.py -k "check_ipmi or guard_pattern" -q`
Expected: PASS — clean tree returns 0; the pattern flags exactly lines 3,4,5.

- [ ] **Step 5: Manually verify the tripwire bites (end-to-end against real `src/`)**

The Step-1 `guard_pattern` unit test covers the regex in isolation; this step proves the
real `just check-ipmi` invocation fails on a planted `src/` literal. The `trap` guarantees
the probe is removed even if the step is interrupted, so it cannot pollute the tree or the
guard's own scan.

```bash
PROBE=src/linux_debug_mcp/_ipmi_guard_probe.py
trap 'trash "$PROBE" 2>/dev/null || rm -f "$PROBE"' EXIT
printf 'X = "ipmitool -C 0 -I lanplus"\n' > "$PROBE"
just check-ipmi; echo "exit=$?"   # expect exit=1 (guard bites)
trash "$PROBE" 2>/dev/null || rm -f "$PROBE"
trap - EXIT
just check-ipmi; echo "exit=$?"   # expect exit=0 (clean tree)
```
Expected: first `exit=1` (guard fails on the planted literal), second `exit=0` (clean).

- [ ] **Step 6: Commit**

```bash
git add justfile tests/test_ipmi_policy.py
git commit -m "ci(ipmi): add check-ipmi guard against cipher-0 literals"
```

---

### Task 5: Wire the guard into CI

**Files:**
- Modify: `.github/workflows/ci.yml` (add an `ipmi-policy` job after the `docs` job, ~line 96)

- [ ] **Step 1: Add the CI job**

In `.github/workflows/ci.yml`, after the `docs` job block (which ends at line 95) and before `workflow-hygiene`, add:

```yaml
  ipmi-policy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - run: |
          set -euo pipefail
          sudo apt-get update && sudo apt-get install -y --no-install-recommends ripgrep just
          just check-ipmi
```

Use the exact same `actions/checkout` SHA + version comment already used elsewhere in the file (line 89) so the pin stays consistent.

- [ ] **Step 2: Lint the workflow**

Run: `uv run --with 'zizmor==1.25.2' zizmor .github/workflows`
Expected: no new findings versus the existing `docs` job (same shape: pinned checkout, `persist-credentials: false`, pinned `apt-get` install).

Run: `uv run --with 'actionlint-py==1.7.12.24' actionlint`
Expected: PASS (no syntax errors).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(ipmi): run check-ipmi guard as a dedicated job"
```

---

### Task 6: Full guardrail sweep

- [ ] **Step 1: Run the complete guardrail set**

```bash
uv run ruff check
uv run ruff format --check .
uv run ty check src
uv run python -m pytest -q
uv run pre-commit run --all-files
just check-docs
just check-ipmi
```
Expected: all green, zero warnings. `pre-commit run --all-files` mirrors CI's hard-gating
`pre-commit` job (including `detect-secrets`); run it locally so a hook failure surfaces
before CI. The env-gated libvirt/gdb/drgn integration tests skip as usual.

- [ ] **Step 2: Confirm no unintended diffs**

Run: `git status` and `git diff --stat origin/main...HEAD`
Expected: only the files listed in the file-structure section, plus the spec/ADR committed earlier.

---

## Self-review notes

- **Spec coverage:** AC1→Task 3 (`cipher_zero` handler test) + Task 2 (`rejects_cipher_zero`); AC2→Task 3 (`default_cipher_reaches_not_implemented`) + Task 2 (`defaults_cipher_to_three`); AC3→Task 2 (`rejects_non_allowlisted_cipher[1]`); AC4→Task 2/Task 3 (`cipher_on_ssh`); AC5→Task 2 (`legacy_ipmi_access_method_rejected`); AC6→Task 1 (chokepoint tests); AC7→Task 4 (`check_ipmi_passes_on_clean_tree` + Step 5 manual bite); AC8→Task 4 (`guard_pattern_flags_forbidden_and_passes_compliant`).
- **Rollback:** every task is an isolated commit; reverting any single commit leaves the tree green except for the test it added. Task 2 must precede Task 3 (handler tests depend on the contract validator). Task 1 must precede Task 2 (import). Task 4 must precede Task 5 (CI runs the target Task 4 defines).
- **No placeholders:** all code and commands are concrete.
- **Type consistency:** `validate_ipmi_cipher_suite(value: int | None) -> int`, `IpmiPolicyError(ValueError)`, field `ipmi_cipher_suite: int | None` used consistently across Tasks 1–3.
