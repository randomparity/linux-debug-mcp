# `debug.introspect.helper` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `debug.introspect.helper(run_id, target_ref, name, args, timeout_seconds)` — a curated library of six versioned drgn scripts (`sysinfo`, `tasks`, `dmesg`, `modules`, `slab`, `irq`), each returning a Pydantic-typed JSON contract — reusing the #51 runner via a shared core executor.

**Architecture:** Extract the #51 run pipeline into a `_execute_introspect_call` core that takes a per-call cap profile and a post-validator callback. The shared on-target wrapper gains `${ARGS_B64}` and `${CAPS_JSON}` slots. Helpers are in-project modules (`introspect_helpers/`) declaring a drgn script, an args model, and an output model; the helper handler resolves the name, validates args, runs the script through the core under a raised cap profile, and the post-validator parses the single emit into the output model so the manifest step status matches the agent-visible outcome.

**Tech Stack:** Python 3.11+, Pydantic v2 (`Model` base, `extra="forbid"`), FastMCP `@app.tool`, drgn (on-target), pytest. Lint/format: `ruff`; types: `ty`.

**Spec:** `docs/superpowers/specs/2026-05-28-debug-introspect-helper-design.md`

---

## Working agreement

- Run all commands from the repo root with `uv run`.
- One logical change per commit; commit at the end of each task.
- After every task: `uv run ruff check src tests && uv run ruff format --check src tests && uv run ty check src`. Fix all findings before committing.
- The existing #51 suites are the executable spec for "behavior unchanged": `tests/test_introspect_wrapper.py`, `tests/test_debug_introspect_run.py`. They MUST stay green after the refactor tasks (Tasks 1–2).
- Integration tests (`*_integration.py`) are skipped without `virsh`/the smoke VM; keep that gating.

---

## File structure

**Create:**
- `src/linux_debug_mcp/introspect_helpers/__init__.py` — `built_in_helper_specs()`, `HELPER_REGISTRY`
- `src/linux_debug_mcp/introspect_helpers/base.py` — `HelperSpec` dataclass, `NoArgs` empty model, shared row sub-models
- `src/linux_debug_mcp/introspect_helpers/sysinfo.py` … `irq.py` — one module per helper
- `src/linux_debug_mcp/introspect_helpers/schemas/<name>.v<version>.json` — checked-in JSON-Schema snapshots
- `tests/test_introspect_helpers.py` — unit tests (registry, args, drift, redaction, cap fit, snapshot)
- `tests/test_introspect_helper_integration.py` — golden integration tests (VM-gated)
- `docs/adr/0009-introspect-helper-layer.md` — ADR

**Modify:**
- `src/linux_debug_mcp/providers/local_drgn_introspect.py` — `${ARGS_B64}`/`${CAPS_JSON}` slots, `RUNNER_DEFAULT_CAPS`, `_merge_and_validate_caps`, `render_wrapper`/`render_wrapper_skeleton` signatures, capability `operations`
- `src/linux_debug_mcp/server.py` — extract `_execute_introspect_call`, thin `debug_introspect_run_handler`, add `debug_introspect_helper_handler` + `@app.tool` registration
- `src/linux_debug_mcp/domain.py` — `DebugIntrospectHelperRequest`
- `src/linux_debug_mcp/config.py` — add `debug.introspect.helper` to `ALLOWED_DEBUG_OPERATIONS`
- `tests/test_introspect_wrapper.py` — cover new wrapper slots

---

## Task 1: Wrapper gains `${ARGS_B64}` + `${CAPS_JSON}` slots

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_drgn_introspect.py`
- Test: `tests/test_introspect_wrapper.py`

- [ ] **Step 1: Write failing tests for the new render parameters**

Add to `tests/test_introspect_wrapper.py`:

```python
def test_render_wrapper_injects_args_into_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    rendered = render_wrapper(
        user_script='emit({"got": args["limit"]})',
        expected_build_id=EXPECTED_BUILD_ID,
        call_id=CALL_ID,
        args_json='{"limit": 7}',
    )
    buf = StringIO()
    ns: dict[str, Any] = {"__name__": "__wrapper__", "__builtins__": builtins}
    with redirect_stdout(buf):
        try:
            exec(compile(rendered, "<wrapper>", "exec"), ns)
        except SystemExit:
            pass
    assert json.loads(buf.getvalue())["emits"] == [{"got": 7}]


def test_render_wrapper_default_caps_match_runner_defaults() -> None:
    from linux_debug_mcp.providers.local_drgn_introspect import RUNNER_DEFAULT_CAPS

    rendered = render_wrapper(user_script="pass", expected_build_id=EXPECTED_BUILD_ID, call_id=CALL_ID)
    assert f'"per_emit_bytes": {RUNNER_DEFAULT_CAPS["per_emit_bytes"]}' in rendered


def test_render_wrapper_caps_override_merges_onto_defaults() -> None:
    rendered = render_wrapper(
        user_script="pass",
        expected_build_id=EXPECTED_BUILD_ID,
        call_id=CALL_ID,
        caps={"per_emit_bytes": 4 * 1024 * 1024},
    )
    assert '"per_emit_bytes": 4194304' in rendered
    assert '"error_message": 4096' in rendered  # inherited


def test_render_wrapper_rejects_non_positive_cap() -> None:
    with pytest.raises(WrapperRenderError):
        render_wrapper(
            user_script="pass",
            expected_build_id=EXPECTED_BUILD_ID,
            call_id=CALL_ID,
            caps={"per_emit_bytes": 0},
        )


def test_render_wrapper_rejects_unknown_cap_key() -> None:
    with pytest.raises(WrapperRenderError):
        render_wrapper(
            user_script="pass",
            expected_build_id=EXPECTED_BUILD_ID,
            call_id=CALL_ID,
            caps={"bogus": 10},
        )
```

Ensure `WrapperRenderError` and `render_wrapper` are imported at the top of the test file (they already import `render_wrapper`; add `WrapperRenderError`).

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run python -m pytest tests/test_introspect_wrapper.py -k "render_wrapper_injects_args or caps" -q`
Expected: FAIL (`render_wrapper() got an unexpected keyword argument 'args_json'`).

- [ ] **Step 3: Add the caps constant + validator and edit the template**

In `src/linux_debug_mcp/providers/local_drgn_introspect.py`, add after the `_CALL_ID_RE` block:

```python
import json

# Spec §3.3: the runner-default cap profile. `_li_caps` in the wrapper is
# substituted from this (debug.introspect.run) or a merged override (helpers).
RUNNER_DEFAULT_CAPS: dict[str, int] = {
    "emits": 100,
    "user_stdout": 256 * 1024,
    "traceback": 16 * 1024,
    "total_json": 1 * 1024 * 1024,
    "per_emit_bytes": 32 * 1024,
    "error_message": 4096,
}


def _merge_and_validate_caps(caps: dict[str, int] | None) -> dict[str, int]:
    """Merge caller overrides onto the six-key runner defaults; reject unknown
    keys and non-positive ints. Spec §3.3: the wrapper indexes all six keys
    (incl. on early exception paths) so the rendered set must be complete.
    """
    merged = dict(RUNNER_DEFAULT_CAPS)
    for key, value in (caps or {}).items():
        if key not in RUNNER_DEFAULT_CAPS:
            raise WrapperRenderError(f"unknown cap key {key!r}; allowed: {sorted(RUNNER_DEFAULT_CAPS)}")
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise WrapperRenderError(f"cap {key!r} must be a positive int; got {value!r}")
        merged[key] = value
    return merged
```

In `WRAPPER_TEMPLATE`, replace the hardcoded caps literal:

```python
_li_caps = {"emits": 100, "user_stdout": 256 * 1024, "traceback": 16 * 1024,
            "total_json": 1 * 1024 * 1024, "per_emit_bytes": 32 * 1024,
            "error_message": 4096}
```

with:

```python
_li_caps = ${CAPS_JSON}
```

(`${CAPS_JSON}` is rendered from `json.dumps` of an all-int dict, which is valid Python literal syntax.)

In the same template, immediately after the `namespace = { ... }` block and its `for name in _li_drgn_helper_names:` loop (i.e. just before `import base64 as _li_base64`), add args injection — reuse the `_li_base64`/`_li_json` already in scope by importing base64 one line earlier:

```python
import base64 as _li_base64
namespace["args"] = _li_json.loads(_li_base64.b64decode("${ARGS_B64}").decode("utf-8"))
USER_SCRIPT_B64 = "${USER_SCRIPT_B64}"
```

(Delete the now-duplicate `import base64 as _li_base64` that previously preceded `USER_SCRIPT_B64`.)

- [ ] **Step 4: Update `render_wrapper` and `render_wrapper_skeleton` signatures**

```python
def render_wrapper(
    *,
    user_script: str,
    expected_build_id: str,
    call_id: str,
    args_json: str = "{}",
    caps: dict[str, int] | None = None,
) -> str:
    if not BUILD_ID_RE.match(expected_build_id):
        raise WrapperRenderError(f"expected_build_id must match {BUILD_ID_RE.pattern}; got {expected_build_id!r}")
    if not _CALL_ID_RE.match(call_id):
        raise WrapperRenderError(f"call_id must match {_CALL_ID_RE.pattern}; got {call_id!r}")
    merged_caps = _merge_and_validate_caps(caps)
    encoded = base64.b64encode(user_script.encode("utf-8")).decode("ascii")
    args_b64 = base64.b64encode(args_json.encode("utf-8")).decode("ascii")
    return WRAPPER_TEMPLATE.substitute(
        USER_SCRIPT_B64=encoded,
        EXPECTED_BUILD_ID=expected_build_id,
        CALL_ID=call_id,
        ARGS_B64=args_b64,
        CAPS_JSON=json.dumps(merged_caps),
    )
```

Apply the same new `args_json`/`caps` parameters and the same `ARGS_B64`/`CAPS_JSON` substitution to `render_wrapper_skeleton` (it already builds a placeholder body; thread `args_json`/`caps` through identically).

- [ ] **Step 5: Run the wrapper suite**

Run: `uv run python -m pytest tests/test_introspect_wrapper.py -q`
Expected: PASS (new tests + all existing tests — the default render is byte-equivalent in behavior because `RUNNER_DEFAULT_CAPS` matches the old literal and `args` defaults to `{}`).

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/providers/local_drgn_introspect.py tests/test_introspect_wrapper.py
git commit -m "feat(introspect): add args + per-call cap slots to the drgn wrapper"
```

---

## Task 2: Extract `_execute_introspect_call` core executor

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`debug_introspect_run_handler`, lines ~2392–~3215)
- Test: `tests/test_debug_introspect_run.py` (must stay green unchanged)

> This task is a behavior-preserving extraction. The existing `test_debug_introspect_run.py` suite is the executable spec — do not change its assertions. The transformation moves the existing body into a core function and threads two new parameters; it adds no new behavior to `run`.

- [ ] **Step 1: Add a characterization assertion that `run` passes default caps**

Add to `tests/test_debug_introspect_run.py` (near the other handler tests; reuse the file's existing fixtures/fakes for `ssh_runner`, profiles, and a booted manifest):

```python
def test_run_uses_runner_default_caps(monkeypatch, tmp_path):
    captured = {}
    import linux_debug_mcp.server as server

    orig = server.render_wrapper

    def spy(**kwargs):
        captured.update(kwargs)
        return orig(**kwargs)

    monkeypatch.setattr(server, "render_wrapper", spy)
    _run_introspect_ok(monkeypatch, tmp_path)  # existing helper that drives a successful run
    assert captured["caps"] is None  # run opts into no override → runner defaults
    assert captured["args_json"] == "{}"
```

If `test_debug_introspect_run.py` has no `_run_introspect_ok` helper, model this on the existing happy-path test in that file (call `debug_introspect_run_handler` with the file's fakes and assert a SUCCEEDED response first, then add the spy assertions).

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run python -m pytest tests/test_debug_introspect_run.py::test_run_uses_runner_default_caps -q`
Expected: FAIL (`render_wrapper` is currently called without `caps`/`args_json`).

- [ ] **Step 3: Define the core function signature and a result dataclass**

In `server.py`, add above `debug_introspect_run_handler`:

```python
from dataclasses import dataclass, field


@dataclass
class IntrospectCallResult:
    """Outcome of one core introspect execution (spec §5)."""

    response: ToolResponse
    redacted_payload: dict[str, Any] | None = None
    call_id: str | None = None
    outcome_status: str | None = None


IntrospectPostValidator = Callable[[dict[str, Any]], "PostValidatorVerdict | None"]


@dataclass
class PostValidatorVerdict:
    """Spec §5: lets a caller turn a wrapper-`ok` payload into a typed failure
    while keeping the manifest record and the response in agreement.
    """

    ok: bool
    failure_code: str | None = None
    failure_message: str | None = None
    failure_category: ErrorCategory | None = None
    extra_step_details: dict[str, Any] = field(default_factory=dict)
    extra_response_data: dict[str, Any] = field(default_factory=dict)
```

- [ ] **Step 4: Rename and reparameterize the handler into the core**

Rename `debug_introspect_run_handler` to `_execute_introspect_call` and add three keyword-only parameters after the existing ones:

```python
def _execute_introspect_call(
    request: DebugIntrospectRunRequest,
    *,
    artifact_root: Path,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    clock: Callable[[], datetime] | None = None,
    operation_name: str = "debug.introspect.run",
    caps: dict[str, int] | None = None,
    post_validator: IntrospectPostValidator | None = None,
) -> ToolResponse:
```

Make these edits inside the moved body:
1. Replace the literal `"debug.introspect.run"` in the `_ensure_debug_operation_enabled(resolved_debug, "debug.introspect.run")` call (line ~2494) with `operation_name`.
2. In the `render_wrapper(...)` call (line ~2725), pass `args_json=_introspect_args_json(request)` and `caps=caps`. Add a tiny helper near the top of the module:
   ```python
   def _introspect_args_json(request: object) -> str:
       """Helper requests expose `args`; run requests do not."""
       return json.dumps(getattr(request, "args", {}) or {})
   ```
   Apply the same `args_json`/`caps` to the `render_wrapper_skeleton(...)` call.
3. On the happy path (the `outcome_status in {"ok","error"}` branch, line ~3103+), **before** building the SUCCEEDED `StepResult` (line ~3162), invoke the post-validator:
   ```python
   verdict = post_validator(redacted_payload) if post_validator is not None else None
   step_status = StepStatus.SUCCEEDED
   step_failure_code = None
   if verdict is not None and not verdict.ok:
       step_status = StepStatus.FAILED
       step_failure_code = verdict.failure_code
   ```
   Use `step_status` in the `StepResult(...)` and merge `verdict.extra_step_details` (when present) into its `details`.
4. After `_record_terminal_introspect_result(store, run_id, step)`: if `verdict is not None and not verdict.ok`, return `ToolResponse.failure(category=verdict.failure_category, run_id=run_id, message=verdict.failure_message, details={"code": verdict.failure_code, "call_id": call_id}, suggested_next_actions=["artifacts.get_manifest"])`. Otherwise return the existing `ToolResponse.success(...)`, merging `verdict.extra_response_data` into its `data` when a verdict is present and ok.

- [ ] **Step 5: Add a thin `debug_introspect_run_handler` delegating to the core**

```python
def debug_introspect_run_handler(
    request: DebugIntrospectRunRequest,
    *,
    artifact_root: Path,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    """Spec §5.2. Thin wrapper over the shared core (spec §5). `run` opts into
    no cap override (runner defaults) and supplies no post-validator.
    """
    return _execute_introspect_call(
        request,
        artifact_root=artifact_root,
        target_profiles=target_profiles,
        rootfs_profiles=rootfs_profiles,
        debug_profiles=debug_profiles,
        ssh_runner=ssh_runner,
        admission=admission,
        session_registry=session_registry,
        clock=clock,
        operation_name="debug.introspect.run",
        caps=None,
        post_validator=None,
    )
```

- [ ] **Step 6: Run the full #51 suite + the new characterization test**

Run: `uv run python -m pytest tests/test_debug_introspect_run.py -q`
Expected: PASS (all existing tests + `test_run_uses_runner_default_caps`).

- [ ] **Step 7: Lint, type-check, commit**

```bash
uv run ruff check src tests && uv run ruff format src tests && uv run ty check src
git add src/linux_debug_mcp/server.py tests/test_debug_introspect_run.py
git commit -m "refactor(introspect): extract _execute_introspect_call core from run handler"
```

---

## Task 3: `HelperSpec`, `NoArgs`, and the registry scaffolding

**Files:**
- Create: `src/linux_debug_mcp/introspect_helpers/__init__.py`, `src/linux_debug_mcp/introspect_helpers/base.py`
- Test: `tests/test_introspect_helpers.py`

- [ ] **Step 1: Write failing registry tests**

Create `tests/test_introspect_helpers.py`:

```python
import pytest

from linux_debug_mcp.introspect_helpers import HELPER_REGISTRY, built_in_helper_specs
from linux_debug_mcp.introspect_helpers.base import HelperSpec


def test_registry_names_are_unique_and_expected() -> None:
    names = [spec.name for spec in built_in_helper_specs()]
    assert names == sorted(names) or len(names) == len(set(names))  # unique
    assert set(names) == {"sysinfo", "tasks", "dmesg", "modules", "slab", "irq"}


def test_registry_maps_name_to_spec() -> None:
    assert isinstance(HELPER_REGISTRY["sysinfo"], HelperSpec)
    assert HELPER_REGISTRY["sysinfo"].version >= 1


def test_every_spec_script_calls_emit() -> None:
    for spec in built_in_helper_specs():
        assert "emit(" in spec.script, spec.name
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -q`
Expected: FAIL (`ModuleNotFoundError: linux_debug_mcp.introspect_helpers`).

- [ ] **Step 3: Write `base.py`**

```python
"""Curated drgn introspection helpers. Spec §3."""

from __future__ import annotations

from dataclasses import dataclass

from linux_debug_mcp.domain import Model


class NoArgs(Model):
    """Empty args model for helpers that take no parameters."""


@dataclass(frozen=True)
class HelperSpec:
    name: str
    version: int
    script: str
    args_model: type[Model]
    output_model: type[Model]
```

- [ ] **Step 4: Write `__init__.py` (registry assembled in later tasks)**

```python
"""Helper registry. Spec §3.1."""

from __future__ import annotations

from linux_debug_mcp.introspect_helpers.base import HelperSpec


def built_in_helper_specs() -> list[HelperSpec]:
    # Imports are local so a syntax error in one helper module surfaces at call
    # time with a clear traceback rather than breaking package import.
    from linux_debug_mcp.introspect_helpers import dmesg, irq, modules, slab, sysinfo, tasks

    return [
        sysinfo.SPEC,
        tasks.SPEC,
        dmesg.SPEC,
        modules.SPEC,
        slab.SPEC,
        irq.SPEC,
    ]


HELPER_REGISTRY: dict[str, HelperSpec] = {spec.name: spec for spec in built_in_helper_specs()}
```

(This task's tests will fail until the six helper modules exist — Tasks 4–9 add them. To keep this task self-contained and green, temporarily stub the six modules in Step 5, then flesh each out in its own task.)

- [ ] **Step 5: Create six minimal stub modules so the registry imports**

For each of `sysinfo tasks dmesg modules slab irq`, create `src/linux_debug_mcp/introspect_helpers/<name>.py` with a placeholder (fleshed out in Tasks 4–9):

```python
from __future__ import annotations

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec, NoArgs


class Output(Model):
    placeholder: bool = True


SPEC = HelperSpec(
    name="sysinfo",  # <-- set per module
    version=1,
    script="emit({'placeholder': True})",
    args_model=NoArgs,
    output_model=Output,
)
```

- [ ] **Step 6: Run, verify green**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/linux_debug_mcp/introspect_helpers tests/test_introspect_helpers.py
git commit -m "feat(introspect): helper registry scaffolding + stub modules"
```

---

## Task 4: `sysinfo` helper

**Files:**
- Modify: `src/linux_debug_mcp/introspect_helpers/sysinfo.py`
- Create: `src/linux_debug_mcp/introspect_helpers/schemas/sysinfo.v1.json`
- Test: `tests/test_introspect_helpers.py`

- [ ] **Step 1: Write a failing model test**

Add to `tests/test_introspect_helpers.py`:

```python
def test_sysinfo_model_validates_sample() -> None:
    from linux_debug_mcp.introspect_helpers.sysinfo import Output

    Output.model_validate({
        "release": "6.8.0", "version": "#1 SMP", "machine": "x86_64",
        "nodename": "vm", "boot_cmdline": "ro quiet", "cpus_online": 4,
        "mem_total_pages": 1048576,
    })


def test_sysinfo_model_rejects_extra_field() -> None:
    from pydantic import ValidationError
    from linux_debug_mcp.introspect_helpers.sysinfo import Output

    with pytest.raises(ValidationError):
        Output.model_validate({"release": "x", "version": "y", "machine": "z",
                               "nodename": "n", "boot_cmdline": "", "cpus_online": 1,
                               "mem_total_pages": 1, "extra": 1})
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k sysinfo -q`
Expected: FAIL (placeholder `Output` has no `release`).

- [ ] **Step 3: Write the helper**

Replace `src/linux_debug_mcp/introspect_helpers/sysinfo.py`:

```python
"""sysinfo helper: uts fields, boot cmdline, basic counters. Spec §7."""

from __future__ import annotations

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec, NoArgs


class Output(Model):
    release: str
    version: str
    machine: str
    nodename: str
    boot_cmdline: str
    cpus_online: int
    mem_total_pages: int


SCRIPT = r"""
uts = prog["init_uts_ns"].name
def _s(field):
    return field.string_().decode("utf-8", "replace")
emit({
    "release": _s(uts.release),
    "version": _s(uts.version),
    "machine": _s(uts.machine),
    "nodename": _s(uts.nodename),
    "boot_cmdline": prog["saved_command_line"].string_().decode("utf-8", "replace"),
    "cpus_online": int(prog["__num_online_cpus"].counter.value_()),
    "mem_total_pages": int(prog["_totalram_pages"].counter.value_()),
})
"""

SPEC = HelperSpec(name="sysinfo", version=1, script=SCRIPT, args_model=NoArgs, output_model=Output)
```

> Note: the exact symbol names (`__num_online_cpus`, `_totalram_pages`) vary by kernel version; the golden integration test (Task 14) is what verifies the drgn against a live kernel. If a symbol is absent on the smoke VM, adjust to the equivalent (`drgn.helpers.linux.cpumask.num_online_cpus(prog)`, `prog["totalram_pages"]`) and re-run the integration test.

- [ ] **Step 4: Generate and check in the schema snapshot**

Run:
```bash
uv run python -c "import json; from linux_debug_mcp.introspect_helpers.sysinfo import Output, SPEC; \
import pathlib; p=pathlib.Path('src/linux_debug_mcp/introspect_helpers/schemas'); p.mkdir(parents=True, exist_ok=True); \
(p/f'sysinfo.v{SPEC.version}.json').write_text(json.dumps(Output.model_json_schema(), indent=2, sort_keys=True))"
```

- [ ] **Step 5: Run model tests**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k sysinfo -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/introspect_helpers/sysinfo.py src/linux_debug_mcp/introspect_helpers/schemas/sysinfo.v1.json tests/test_introspect_helpers.py
git commit -m "feat(introspect): sysinfo helper"
```

---

## Task 5: `tasks` helper (args + truncation)

**Files:**
- Modify: `src/linux_debug_mcp/introspect_helpers/tasks.py`
- Create: `src/linux_debug_mcp/introspect_helpers/schemas/tasks.v1.json`
- Test: `tests/test_introspect_helpers.py`

- [ ] **Step 1: Write failing tests for the args + output models**

```python
def test_tasks_args_defaults() -> None:
    from linux_debug_mcp.introspect_helpers.tasks import Args

    a = Args()
    assert a.states == ["D"]
    assert a.include_stack is True
    assert a.limit == 200


def test_tasks_output_validates_sample() -> None:
    from linux_debug_mcp.introspect_helpers.tasks import Output

    Output.model_validate({
        "tasks": [{"pid": 1, "tgid": 1, "comm": "systemd", "state": "S",
                   "kernel_stack": ["__schedule+0x1"]}],
        "truncated": False,
    })
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k tasks -q`
Expected: FAIL.

- [ ] **Step 3: Write the helper**

```python
"""tasks helper: process list + kernel stacks, focus on blocked/D-state. Spec §7."""

from __future__ import annotations

from pydantic import Field

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec


class Args(Model):
    states: list[str] = Field(default_factory=lambda: ["D"])
    include_stack: bool = True
    limit: int = 200


class Task(Model):
    pid: int
    tgid: int
    comm: str
    state: str
    kernel_stack: list[str] = Field(default_factory=list)


class Output(Model):
    tasks: list[Task]
    truncated: bool


SCRIPT = r"""
from drgn.helpers.linux.pid import for_each_task
from drgn import ProgramFlags

want = set(args.get("states", ["D"]))
include_stack = bool(args.get("include_stack", True))
limit = int(args.get("limit", 200))

def state_letter(task):
    # TASK_RUNNING=0 ... use task_state_to_char if available, else a small map.
    try:
        from drgn.helpers.linux.sched import task_state_to_char
        return task_state_to_char(task)
    except Exception:
        return "?"

rows = []
truncated = False
for task in for_each_task(prog):
    letter = state_letter(task)
    if want and letter not in want:
        continue
    if len(rows) >= limit:
        truncated = True
        break
    stack = []
    if include_stack:
        try:
            for frame in prog.stack_trace(task):
                stack.append(str(frame))
        except Exception as exc:
            stack = ["<stack unavailable: %s>" % type(exc).__name__]
    rows.append({
        "pid": int(task.pid.value_()),
        "tgid": int(task.tgid.value_()),
        "comm": task.comm.string_().decode("utf-8", "replace"),
        "state": letter,
        "kernel_stack": stack,
    })

emit({"tasks": rows, "truncated": truncated})
"""

SPEC = HelperSpec(name="tasks", version=1, script=SCRIPT, args_model=Args, output_model=Output)
```

- [ ] **Step 4: Generate the schema snapshot**

```bash
uv run python -c "import json,pathlib; from linux_debug_mcp.introspect_helpers.tasks import Output, SPEC; \
p=pathlib.Path('src/linux_debug_mcp/introspect_helpers/schemas'); \
(p/f'tasks.v{SPEC.version}.json').write_text(json.dumps(Output.model_json_schema(), indent=2, sort_keys=True))"
```

- [ ] **Step 5: Run, verify green**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k tasks -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/introspect_helpers/tasks.py src/linux_debug_mcp/introspect_helpers/schemas/tasks.v1.json tests/test_introspect_helpers.py
git commit -m "feat(introspect): tasks helper"
```

---

## Task 6: `dmesg` helper (args + redaction-targeted text)

**Files:**
- Modify: `src/linux_debug_mcp/introspect_helpers/dmesg.py`
- Create: `src/linux_debug_mcp/introspect_helpers/schemas/dmesg.v1.json`
- Test: `tests/test_introspect_helpers.py`

- [ ] **Step 1: Write failing tests**

```python
def test_dmesg_args_default() -> None:
    from linux_debug_mcp.introspect_helpers.dmesg import Args

    assert Args().max_entries == 1000


def test_dmesg_output_validates_sample() -> None:
    from linux_debug_mcp.introspect_helpers.dmesg import Output

    Output.model_validate({"entries": [{"ts_usec": 1, "level": 6, "text": "boot"}], "truncated": False})
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k dmesg -q`
Expected: FAIL.

- [ ] **Step 3: Write the helper**

```python
"""dmesg helper: printk ring buffer. text is redacted host-side (spec §5)."""

from __future__ import annotations

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec


class Args(Model):
    max_entries: int = 1000


class Entry(Model):
    ts_usec: int
    level: int
    text: str


class Output(Model):
    entries: list[Entry]
    truncated: bool


SCRIPT = r"""
from drgn.helpers.linux.printk import get_printk_records

max_entries = int(args.get("max_entries", 1000))
records = list(get_printk_records(prog))
truncated = len(records) > max_entries
rows = []
for rec in records[-max_entries:] if truncated else records:
    rows.append({
        "ts_usec": int(rec.timestamp) // 1000,
        "level": int(rec.level),
        "text": rec.text.decode("utf-8", "replace") if isinstance(rec.text, (bytes, bytearray)) else str(rec.text),
    })
emit({"entries": rows, "truncated": truncated})
"""

SPEC = HelperSpec(name="dmesg", version=1, script=SCRIPT, args_model=Args, output_model=Output)
```

- [ ] **Step 4: Generate the schema snapshot**

```bash
uv run python -c "import json,pathlib; from linux_debug_mcp.introspect_helpers.dmesg import Output, SPEC; \
p=pathlib.Path('src/linux_debug_mcp/introspect_helpers/schemas'); \
(p/f'dmesg.v{SPEC.version}.json').write_text(json.dumps(Output.model_json_schema(), indent=2, sort_keys=True))"
```

- [ ] **Step 5: Run, verify green**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k dmesg -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/introspect_helpers/dmesg.py src/linux_debug_mcp/introspect_helpers/schemas/dmesg.v1.json tests/test_introspect_helpers.py
git commit -m "feat(introspect): dmesg helper"
```

---

## Task 7: `modules` helper

**Files:**
- Modify: `src/linux_debug_mcp/introspect_helpers/modules.py`
- Create: `src/linux_debug_mcp/introspect_helpers/schemas/modules.v1.json`
- Test: `tests/test_introspect_helpers.py`

- [ ] **Step 1: Write a failing model test**

```python
def test_modules_output_validates_sample() -> None:
    from linux_debug_mcp.introspect_helpers.modules import Output

    Output.model_validate({"modules": [{"name": "ext4", "size": 1, "refcount": 2,
                                         "used_by": ["jbd2"], "state": "live"}]})
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k modules -q`
Expected: FAIL.

- [ ] **Step 3: Write the helper**

```python
"""modules helper: loaded modules + refcounts. Spec §7 (naturally bounded)."""

from __future__ import annotations

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec, NoArgs


class Module(Model):
    name: str
    size: int
    refcount: int
    used_by: list[str]
    state: str


class Output(Model):
    modules: list[Module]


SCRIPT = r"""
from drgn.helpers.linux.module import for_each_module

_STATE = {0: "live", 1: "coming", 2: "going", 3: "unformed"}
rows = []
for mod in for_each_module(prog):
    try:
        refcount = int(mod.refcnt.counter.value_())
    except Exception:
        refcount = -1
    used_by = []
    try:
        from drgn.helpers.linux.list import list_for_each_entry
        for use in list_for_each_entry("struct module_use", mod.source_list.address_of_(), "source_list"):
            used_by.append(use.source.name.string_().decode("utf-8", "replace"))
    except Exception:
        pass
    rows.append({
        "name": mod.name.string_().decode("utf-8", "replace"),
        "size": int(mod.core_layout.size.value_()) if hasattr(mod, "core_layout") else int(mod.mem[0].size.value_()),
        "refcount": refcount,
        "used_by": used_by,
        "state": _STATE.get(int(mod.state.value_()), "unknown"),
    })
emit({"modules": rows})
"""

SPEC = HelperSpec(name="modules", version=1, script=SCRIPT, args_model=NoArgs, output_model=Output)
```

- [ ] **Step 4: Generate the schema snapshot**

```bash
uv run python -c "import json,pathlib; from linux_debug_mcp.introspect_helpers.modules import Output, SPEC; \
p=pathlib.Path('src/linux_debug_mcp/introspect_helpers/schemas'); \
(p/f'modules.v{SPEC.version}.json').write_text(json.dumps(Output.model_json_schema(), indent=2, sort_keys=True))"
```

- [ ] **Step 5: Run, verify green**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k modules -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/introspect_helpers/modules.py src/linux_debug_mcp/introspect_helpers/schemas/modules.v1.json tests/test_introspect_helpers.py
git commit -m "feat(introspect): modules helper"
```

---

## Task 8: `slab` helper

**Files:**
- Modify: `src/linux_debug_mcp/introspect_helpers/slab.py`
- Create: `src/linux_debug_mcp/introspect_helpers/schemas/slab.v1.json`
- Test: `tests/test_introspect_helpers.py`

- [ ] **Step 1: Write a failing model test**

```python
def test_slab_output_validates_sample() -> None:
    from linux_debug_mcp.introspect_helpers.slab import Output

    Output.model_validate({"caches": [{"name": "kmalloc-64", "active_objs": 10,
                                        "num_objs": 20, "objsize": 64, "objs_per_slab": 64}]})
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k slab -q`
Expected: FAIL.

- [ ] **Step 3: Write the helper**

```python
"""slab helper: slab cache stats. Spec §7 (naturally bounded)."""

from __future__ import annotations

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec, NoArgs


class Cache(Model):
    name: str
    active_objs: int
    num_objs: int
    objsize: int
    objs_per_slab: int


class Output(Model):
    caches: list[Cache]


SCRIPT = r"""
from drgn.helpers.linux.slab import for_each_slab_cache

rows = []
for cache in for_each_slab_cache(prog):
    try:
        name = cache.name.string_().decode("utf-8", "replace")
        objsize = int(cache.object_size.value_())
        oo = int(cache.oo.x.value_())
        objs_per_slab = oo & ((1 << 16) - 1)
        rows.append({
            "name": name,
            "active_objs": -1,
            "num_objs": -1,
            "objsize": objsize,
            "objs_per_slab": objs_per_slab,
        })
    except Exception:
        continue
emit({"caches": rows})
"""

SPEC = HelperSpec(name="slab", version=1, script=SCRIPT, args_model=NoArgs, output_model=Output)
```

> Note: `active_objs`/`num_objs` require walking per-node slab lists, which is allocator-version-specific (SLUB vs SLAB). Ship v1 with the cheap fields (`-1` sentinels for the per-node counts) and let the golden test (Task 14) confirm the shape on the smoke VM; a follow-up may populate the counts and bump `version`.

- [ ] **Step 4: Generate the schema snapshot**

```bash
uv run python -c "import json,pathlib; from linux_debug_mcp.introspect_helpers.slab import Output, SPEC; \
p=pathlib.Path('src/linux_debug_mcp/introspect_helpers/schemas'); \
(p/f'slab.v{SPEC.version}.json').write_text(json.dumps(Output.model_json_schema(), indent=2, sort_keys=True))"
```

- [ ] **Step 5: Run, verify green**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k slab -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/introspect_helpers/slab.py src/linux_debug_mcp/introspect_helpers/schemas/slab.v1.json tests/test_introspect_helpers.py
git commit -m "feat(introspect): slab helper"
```

---

## Task 9: `irq` helper

**Files:**
- Modify: `src/linux_debug_mcp/introspect_helpers/irq.py`
- Create: `src/linux_debug_mcp/introspect_helpers/schemas/irq.v1.json`
- Test: `tests/test_introspect_helpers.py`

- [ ] **Step 1: Write a failing model test**

```python
def test_irq_output_validates_sample() -> None:
    from linux_debug_mcp.introspect_helpers.irq import Output

    Output.model_validate({"irqs": [{"irq": 0, "name": "timer",
                                      "counts_per_cpu": [10, 12], "affinity": [0, 1]}]})


def test_irq_name_nullable() -> None:
    from linux_debug_mcp.introspect_helpers.irq import Output

    Output.model_validate({"irqs": [{"irq": 1, "name": None,
                                     "counts_per_cpu": [0], "affinity": [0]}]})
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k irq -q`
Expected: FAIL.

- [ ] **Step 3: Write the helper**

```python
"""irq helper: per-CPU IRQ counts + affinity. Spec §7 (naturally bounded)."""

from __future__ import annotations

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec, NoArgs


class Irq(Model):
    irq: int
    name: str | None
    counts_per_cpu: list[int]
    affinity: list[int]


class Output(Model):
    irqs: list[Irq]


SCRIPT = r"""
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.percpu import per_cpu_ptr

online = list(for_each_online_cpu(prog))
rows = []
irq_descs = prog["irq_desc_tree"] if "irq_desc_tree" in prog else None

def iter_descs():
    # Prefer the radix-tree of irq_desc; fall back to nothing if unavailable.
    try:
        from drgn.helpers.linux.radixtree import radix_tree_for_each
        for index, entry in radix_tree_for_each(prog["irq_desc_tree"].address_of_()):
            yield int(index), drgn.Object(prog, "struct irq_desc *", value=entry.value_())
    except Exception:
        return

for irq_no, desc in iter_descs():
    try:
        counts = []
        kstat = desc.kstat_irqs
        for cpu in online:
            counts.append(int(per_cpu_ptr(kstat, cpu).value_()))
        name = None
        try:
            action = desc.action
            if action.value_():
                name = action.name.string_().decode("utf-8", "replace")
        except Exception:
            name = None
        affinity = list(online)  # affinity mask decode is version-specific; report online set as v1
        rows.append({"irq": irq_no, "name": name, "counts_per_cpu": counts, "affinity": affinity})
    except Exception:
        continue
emit({"irqs": rows})
"""

SPEC = HelperSpec(name="irq", version=1, script=SCRIPT, args_model=NoArgs, output_model=Output)
```

> Note: IRQ descriptor storage (`irq_desc_tree` radix tree vs sparse array) and affinity-mask layout are kernel-version-specific. v1 reports per-CPU counts over the online set and uses the online set as `affinity`; the golden test (Task 14) verifies shape and the `counts_per_cpu` length invariant on the smoke VM. A follow-up may decode real affinity and bump `version`.

- [ ] **Step 4: Generate the schema snapshot**

```bash
uv run python -c "import json,pathlib; from linux_debug_mcp.introspect_helpers.irq import Output, SPEC; \
p=pathlib.Path('src/linux_debug_mcp/introspect_helpers/schemas'); \
(p/f'irq.v{SPEC.version}.json').write_text(json.dumps(Output.model_json_schema(), indent=2, sort_keys=True))"
```

- [ ] **Step 5: Run, verify green**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k irq -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/introspect_helpers/irq.py src/linux_debug_mcp/introspect_helpers/schemas/irq.v1.json tests/test_introspect_helpers.py
git commit -m "feat(introspect): irq helper"
```

---

## Task 10: Schema-snapshot discipline test

**Files:**
- Test: `tests/test_introspect_helpers.py`

- [ ] **Step 1: Write the snapshot-diff test**

```python
def test_schema_snapshots_match_models() -> None:
    import json
    from pathlib import Path

    from linux_debug_mcp.introspect_helpers import built_in_helper_specs

    schema_dir = Path("src/linux_debug_mcp/introspect_helpers/schemas")
    for spec in built_in_helper_specs():
        snap = schema_dir / f"{spec.name}.v{spec.version}.json"
        assert snap.is_file(), f"missing snapshot for {spec.name} v{spec.version}"
        expected = json.dumps(spec.output_model.model_json_schema(), indent=2, sort_keys=True)
        assert snap.read_text() == expected, (
            f"{spec.name} model changed without a snapshot/version bump (spec §3.4)"
        )
```

- [ ] **Step 2: Run, verify green**

Run: `uv run python -m pytest tests/test_introspect_helpers.py::test_schema_snapshots_match_models -q`
Expected: PASS (all six snapshots match; if any fails, the snapshot was generated with different formatting — regenerate with the exact `indent=2, sort_keys=True` used here).

- [ ] **Step 3: Commit**

```bash
git add tests/test_introspect_helpers.py
git commit -m "test(introspect): enforce helper schema-snapshot discipline"
```

---

## Task 11: `DebugIntrospectHelperRequest` domain type

**Files:**
- Modify: `src/linux_debug_mcp/domain.py`
- Test: `tests/test_introspect_helpers.py`

- [ ] **Step 1: Write a failing test**

```python
def test_helper_request_defaults() -> None:
    from linux_debug_mcp.domain import DebugIntrospectHelperRequest

    r = DebugIntrospectHelperRequest(run_id="r", target_ref="t", name="sysinfo")
    assert r.args == {}
    assert r.timeout_seconds == 30


def test_helper_request_forbids_extra() -> None:
    from pydantic import ValidationError
    from linux_debug_mcp.domain import DebugIntrospectHelperRequest

    with pytest.raises(ValidationError):
        DebugIntrospectHelperRequest(run_id="r", target_ref="t", name="sysinfo", bogus=1)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k helper_request -q`
Expected: FAIL (`cannot import name 'DebugIntrospectHelperRequest'`).

- [ ] **Step 3: Add the model**

In `src/linux_debug_mcp/domain.py`, after `DebugIntrospectCheckPrerequisitesRequest`:

```python
class DebugIntrospectHelperRequest(Model):
    """Request payload for ``debug.introspect.helper``. Spec §6.1.

    ``args`` is validated against the resolved helper's ``args_model`` by the
    handler (not Pydantic) so an unknown helper / bad args surface as the
    spec's exact failure codes. The ``[5, 300]`` timeout band and
    manifest-immutability of profile fields are enforced by the handler.
    """

    run_id: str
    target_ref: str
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 30
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None
```

- [ ] **Step 4: Run, verify green**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k helper_request -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/domain.py tests/test_introspect_helpers.py
git commit -m "feat(introspect): DebugIntrospectHelperRequest domain type"
```

---

## Task 12: Allowlist + capability advertise `debug.introspect.helper`

**Files:**
- Modify: `src/linux_debug_mcp/config.py`, `src/linux_debug_mcp/providers/local_drgn_introspect.py`
- Test: `tests/test_introspect_helpers.py`

- [ ] **Step 1: Write failing tests**

```python
def test_helper_op_in_allowlist() -> None:
    from linux_debug_mcp.config import ALLOWED_DEBUG_OPERATIONS

    assert "debug.introspect.helper" in ALLOWED_DEBUG_OPERATIONS


def test_capability_advertises_helper_op() -> None:
    from linux_debug_mcp.providers.local_drgn_introspect import local_drgn_introspect_capability

    assert "debug.introspect.helper" in local_drgn_introspect_capability().operations
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k "allowlist or advertises" -q`
Expected: FAIL.

- [ ] **Step 3: Edit `config.py`**

In `ALLOWED_DEBUG_OPERATIONS`, add after `"debug.introspect.run",`:

```python
    "debug.introspect.helper",
```

- [ ] **Step 4: Edit the capability**

In `local_drgn_introspect_capability()`, change the `operations` list to:

```python
        operations=[
            "debug.introspect.run",
            "debug.introspect.check_prerequisites",
            "debug.introspect.helper",
        ],
```

- [ ] **Step 5: Run, verify green**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k "allowlist or advertises" -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/config.py src/linux_debug_mcp/providers/local_drgn_introspect.py tests/test_introspect_helpers.py
git commit -m "feat(introspect): allowlist + advertise debug.introspect.helper"
```

---

## Task 13: `debug_introspect_helper_handler` + post-validator + tool registration

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Test: `tests/test_introspect_helpers.py`

- [ ] **Step 1: Write failing handler tests (drift, unknown-name, args-invalid, redaction, success)**

These reuse the fakes from `tests/test_debug_introspect_run.py`. Import the existing helpers there or replicate the minimal fake SSH runner that returns a canned wrapper stdout JSON. Add to `tests/test_introspect_helpers.py`:

```python
def test_helper_unknown_name(tmp_path):
    from linux_debug_mcp.domain import DebugIntrospectHelperRequest
    from linux_debug_mcp.server import debug_introspect_helper_handler

    resp = debug_introspect_helper_handler(
        DebugIntrospectHelperRequest(run_id="missing", target_ref="t", name="nope"),
        artifact_root=tmp_path,
    )
    assert resp.error is not None
    assert resp.error.details.get("code") == "unknown_helper"


def test_helper_args_invalid(tmp_path):
    from linux_debug_mcp.domain import DebugIntrospectHelperRequest
    from linux_debug_mcp.server import debug_introspect_helper_handler

    resp = debug_introspect_helper_handler(
        DebugIntrospectHelperRequest(run_id="missing", target_ref="t", name="tasks", args={"limit": "lots"}),
        artifact_root=tmp_path,
    )
    assert resp.error is not None
    assert resp.error.details.get("code") == "helper_args_invalid"
```

> Resolution order matters: `unknown_helper` and `helper_args_invalid` must be checked **before** the run/manifest existence checks, so these two tests need only a `tmp_path` (no booted run). Assert that in the handler (Step 3).

Add a post-validator unit test that does not need SSH:

```python
def test_post_validator_drift_on_zero_emits():
    from linux_debug_mcp.server import _make_helper_post_validator
    from linux_debug_mcp.introspect_helpers import HELPER_REGISTRY

    v = _make_helper_post_validator(HELPER_REGISTRY["sysinfo"])
    verdict = v({"emits": []})
    assert verdict is not None and verdict.ok is False
    assert verdict.failure_code == "helper_schema_drift"


def test_post_validator_drift_on_two_emits():
    from linux_debug_mcp.server import _make_helper_post_validator
    from linux_debug_mcp.introspect_helpers import HELPER_REGISTRY

    v = _make_helper_post_validator(HELPER_REGISTRY["sysinfo"])
    assert v({"emits": [{}, {}]}).ok is False


def test_post_validator_ok_on_valid_single_emit():
    from linux_debug_mcp.server import _make_helper_post_validator
    from linux_debug_mcp.introspect_helpers import HELPER_REGISTRY

    v = _make_helper_post_validator(HELPER_REGISTRY["sysinfo"])
    good = {"emits": [{"release": "6.8", "version": "#1", "machine": "x86_64",
                       "nodename": "vm", "boot_cmdline": "", "cpus_online": 1,
                       "mem_total_pages": 1}]}
    verdict = v(good)
    assert verdict.ok is True
    assert verdict.extra_response_data["result"]["release"] == "6.8"


def test_post_validator_redacted_emit_still_validates():
    # The core redacts before the validator runs; a redacted str field stays a
    # str, so a redacted dmesg text still validates.
    from linux_debug_mcp.server import _make_helper_post_validator
    from linux_debug_mcp.introspect_helpers import HELPER_REGISTRY

    v = _make_helper_post_validator(HELPER_REGISTRY["dmesg"])
    payload = {"emits": [{"entries": [{"ts_usec": 1, "level": 6, "text": "[REDACTED]"}], "truncated": False}]}
    assert v(payload).ok is True
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -k "helper_unknown or helper_args or post_validator" -q`
Expected: FAIL (`cannot import name 'debug_introspect_helper_handler'`).

- [ ] **Step 3: Implement the post-validator factory**

In `server.py`, add:

```python
HELPER_CAP_PROFILE: dict[str, int] = {
    "per_emit_bytes": 4 * 1024 * 1024,
    "emits": 4,
    "total_json": 8 * 1024 * 1024,
}


def _make_helper_post_validator(spec: HelperSpec) -> IntrospectPostValidator:
    """Spec §3.3: validate the single redacted emit into the helper's
    output_model; turn drift into a typed failure verdict so the recorded
    manifest step matches the response.
    """

    def _validate(redacted_payload: dict[str, Any]) -> PostValidatorVerdict:
        emits = redacted_payload.get("emits") if isinstance(redacted_payload, dict) else None
        if not isinstance(emits, list) or len(emits) != 1:
            return PostValidatorVerdict(
                ok=False,
                failure_code="helper_schema_drift",
                failure_message=f"expected exactly one emit, got {0 if not isinstance(emits, list) else len(emits)}",
                failure_category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                extra_step_details={"helper": spec.name, "version": spec.version},
            )
        try:
            model = spec.output_model.model_validate(emits[0])
        except ValidationError as exc:
            return PostValidatorVerdict(
                ok=False,
                failure_code="helper_schema_drift",
                failure_message=_redact_and_truncate(Redactor(), str(exc), cap=512),
                failure_category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                extra_step_details={"helper": spec.name, "version": spec.version},
            )
        return PostValidatorVerdict(
            ok=True,
            extra_step_details={"helper": spec.name, "version": spec.version},
            extra_response_data={
                "helper": spec.name,
                "version": spec.version,
                "result": model.model_dump(mode="json"),
            },
        )

    return _validate
```

Add imports at the top of `server.py`: `from pydantic import ValidationError`, `from linux_debug_mcp.introspect_helpers import HELPER_REGISTRY`, `from linux_debug_mcp.introspect_helpers.base import HelperSpec`, and `from linux_debug_mcp.domain import DebugIntrospectHelperRequest`.

- [ ] **Step 4: Implement the handler**

```python
def debug_introspect_helper_handler(
    request: DebugIntrospectHelperRequest,
    *,
    artifact_root: Path,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    """Spec §6. Resolve a curated helper, validate its args, and run its drgn
    script through the shared core under the raised helper cap profile.
    """
    spec = HELPER_REGISTRY.get(request.name)
    if spec is None:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=request.run_id,
            message=f"unknown helper {request.name!r}; valid: {sorted(HELPER_REGISTRY)}",
            details={"code": "unknown_helper", "valid": sorted(HELPER_REGISTRY)},
        )
    try:
        spec.args_model.model_validate(request.args)
    except ValidationError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=request.run_id,
            message=_redact_and_truncate(Redactor(), str(exc), cap=512),
            details={"code": "helper_args_invalid"},
        )

    run_request = DebugIntrospectRunRequest(
        run_id=request.run_id,
        target_ref=request.target_ref,
        script=spec.script,
        timeout_seconds=request.timeout_seconds,
        allow_write=False,
        debug_profile=request.debug_profile,
        target_profile=request.target_profile,
        rootfs_profile=request.rootfs_profile,
        args=dict(request.args),  # requires the optional `args` field added below
    )

    return _execute_introspect_call(
        run_request,
        artifact_root=artifact_root,
        target_profiles=target_profiles,
        rootfs_profiles=rootfs_profiles,
        debug_profiles=debug_profiles,
        ssh_runner=ssh_runner,
        admission=admission,
        session_registry=session_registry,
        clock=clock,
        operation_name="debug.introspect.helper",
        caps=HELPER_CAP_PROFILE,
        post_validator=_make_helper_post_validator(spec),
    )
```

> **Required prerequisite edit (do this first in this step):** `DebugIntrospectRunRequest` has `extra="forbid"`, so passing `args=` only works once the field exists. Add an **optional** `args: dict[str, Any] = Field(default_factory=dict)` field to `DebugIntrospectRunRequest` in `domain.py`. It stays `{}` for `run` (run's tool registration does not expose it, so run's public contract and `request.json` are unchanged). `_introspect_args_json` (Task 2) already reads it via `getattr(request, "args", {})`, so no change there. The Task 2 characterization test (`args_json == "{}"`) still holds for `run`.

- [ ] **Step 5: Register the tool in `create_app()`**

Find the introspect tool registrations in `create_app()` (near the other `@app.tool` blocks). Add:

```python
    @app.tool(name="debug.introspect.helper")
    def debug_introspect_helper(
        run_id: str,
        target_ref: str,
        name: str,
        args: dict[str, Any] | None = None,
        timeout_seconds: int = 30,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugIntrospectHelperRequest(
            run_id=run_id,
            target_ref=target_ref,
            name=name,
            args=args or {},
            timeout_seconds=timeout_seconds,
            debug_profile=debug_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
        )
        return debug_introspect_helper_handler(request, artifact_root=artifact_root).model_dump(mode="json")
```

Match the exact wrapper style of the existing `debug.introspect.run` registration (same `artifact_root` capture, same `.model_dump(mode="json")`).

- [ ] **Step 6: Run the unit tests**

Run: `uv run python -m pytest tests/test_introspect_helpers.py -q`
Expected: PASS.

- [ ] **Step 7: Lint, type-check, commit**

```bash
uv run ruff check src tests && uv run ruff format src tests && uv run ty check src
git add src/linux_debug_mcp/server.py src/linux_debug_mcp/domain.py tests/test_introspect_helpers.py
git commit -m "feat(introspect): debug.introspect.helper handler + tool"
```

---

## Task 14: Cap-fit unit test (the §7 defaults serialize within the helper profile)

**Files:**
- Test: `tests/test_introspect_helpers.py`

- [ ] **Step 1: Write the cap-fit test**

```python
def test_default_list_helpers_fit_helper_cap_profile() -> None:
    import json

    from linux_debug_mcp.server import HELPER_CAP_PROFILE

    # tasks: 200 tasks × a deep stack
    deep_stack = [f"func_{i}+0x{i:x}/0x100" for i in range(64)]
    tasks_payload = {
        "tasks": [{"pid": i, "tgid": i, "comm": "kworker/u8:0", "state": "D",
                   "kernel_stack": deep_stack} for i in range(200)],
        "truncated": True,
    }
    encoded = json.dumps(tasks_payload)
    assert len(encoded) <= HELPER_CAP_PROFILE["per_emit_bytes"]
    assert len(encoded) <= HELPER_CAP_PROFILE["total_json"]

    # dmesg: 1000 entries
    dmesg_payload = {
        "entries": [{"ts_usec": i, "level": 6, "text": "x" * 80} for i in range(1000)],
        "truncated": True,
    }
    encoded = json.dumps(dmesg_payload)
    assert len(encoded) <= HELPER_CAP_PROFILE["per_emit_bytes"]
```

- [ ] **Step 2: Run, verify green**

Run: `uv run python -m pytest tests/test_introspect_helpers.py::test_default_list_helpers_fit_helper_cap_profile -q`
Expected: PASS. (If `tasks` overflows 4 MiB, lower the `tasks` default `limit` in Task 5 or raise `per_emit_bytes` in `HELPER_CAP_PROFILE`, then re-run — the test is the guardrail that keeps §7 defaults inside the profile.)

- [ ] **Step 3: Commit**

```bash
git add tests/test_introspect_helpers.py
git commit -m "test(introspect): assert §7 defaults fit the helper cap profile"
```

---

## Task 15: Golden integration tests (VM-gated)

**Files:**
- Create: `tests/test_introspect_helper_integration.py`
- Test: itself

- [ ] **Step 1: Write the gated integration module**

Model the skip-gating and VM bring-up on `tests/test_drgn_introspect_integration.py`. Reuse its fixtures for booting the smoke VM and obtaining an `artifact_root` + booted `run_id`.

```python
"""Golden integration tests for debug.introspect.helper (spec §8.2).

Skipped without virsh + the smoke VM, matching the other *_integration suites.
"""

from __future__ import annotations

import shutil

import pytest

pytestmark = pytest.mark.skipif(shutil.which("virsh") is None, reason="requires virsh + smoke VM")


def _run_helper(booted_run, name, args=None):
    from linux_debug_mcp.domain import DebugIntrospectHelperRequest
    from linux_debug_mcp.server import debug_introspect_helper_handler

    resp = debug_introspect_helper_handler(
        DebugIntrospectHelperRequest(
            run_id=booted_run.run_id, target_ref=booted_run.target_profile,
            name=name, args=args or {},
        ),
        artifact_root=booted_run.artifact_root,
    )
    assert resp.error is None, resp
    return resp.data["result"]


def test_sysinfo_invariants(booted_run):
    result = _run_helper(booted_run, "sysinfo")
    assert result["release"]
    assert result["cpus_online"] >= 1


def test_tasks_includes_pid1(booted_run):
    result = _run_helper(booted_run, "tasks", {"states": [], "limit": 500})
    comms = {t["comm"] for t in result["tasks"] if t["pid"] == 1}
    assert comms & {"init", "systemd"}


def test_dmesg_nonempty(booted_run):
    result = _run_helper(booted_run, "dmesg")
    assert result["entries"]


def test_modules_nonempty(booted_run):
    result = _run_helper(booted_run, "modules")
    assert result["modules"]


def test_slab_has_kmalloc(booted_run):
    result = _run_helper(booted_run, "slab")
    assert any(c["name"].startswith("kmalloc") for c in result["caches"])


def test_irq_counts_length_matches_cpus(booted_run):
    sysinfo = _run_helper(booted_run, "sysinfo")
    result = _run_helper(booted_run, "irq")
    assert result["irqs"]
    for entry in result["irqs"]:
        assert len(entry["counts_per_cpu"]) == sysinfo["cpus_online"]
```

- [ ] **Step 2: Write the D-state acceptance test**

```python
def test_tasks_dstate_blocker(booted_run):
    # Spec §8.2: spawn a kernel-side D-state blocker on the guest, then assert
    # tasks(states=["D"]) returns it with a non-empty stack. Use the booted_run
    # SSH channel to start a process blocked in uninterruptible sleep (e.g.
    # `vmtouch`/a `dd` on a stalled device, or `cat /proc/<self>/...`); the
    # integration fixture exposes a `guest_ssh(cmd)` helper — see
    # test_drgn_introspect_integration.py for the pattern.
    booted_run.guest_ssh("nohup dd if=/dev/sda of=/dev/null bs=1M &")  # adjust to a reliably-D device
    result = _run_helper(booted_run, "tasks", {"states": ["D"]})
    blocked = [t for t in result["tasks"] if t["kernel_stack"]]
    assert blocked, "expected at least one D-state task with a stack"
```

> If the smoke VM has no device that reliably parks a task in `D`, substitute a tiny out-of-tree kernel module that calls `set_current_state(TASK_UNINTERRUPTIBLE); schedule_timeout(...)`, or use a `fsfreeze`-style stall. The acceptance criterion is "a synthetic kernel-side blocker"; the exact mechanism is the integration author's choice — keep it deterministic and self-cleaning.

- [ ] **Step 3: Write the no-pause heartbeat test**

```python
def test_sysinfo_no_stop_the_world(booted_run):
    # Spec §8.2: a guest heartbeat must not gap across the helper call.
    booted_run.guest_ssh(
        "nohup sh -c 'while true; do date +%s.%N >> /tmp/hb; sleep 0.05; done' >/dev/null 2>&1 &"
    )
    import time
    time.sleep(0.5)
    _run_helper(booted_run, "sysinfo")
    time.sleep(0.5)
    samples = [float(x) for x in booted_run.guest_ssh("cat /tmp/hb").split()]
    gaps = [b - a for a, b in zip(samples, samples[1:])]
    assert max(gaps) < 0.5, f"heartbeat gap {max(gaps)}s suggests a stop-the-world pause"
```

- [ ] **Step 4: Run (will skip without a VM; run on a VM host to verify)**

Run: `uv run python -m pytest tests/test_introspect_helper_integration.py -q`
Expected: SKIPPED locally (no virsh); on a VM host, PASS. If a helper's drgn fails on the live kernel, fix the drgn in the corresponding helper module (Tasks 4–9) and re-run — this is where version-specific symbol issues surface.

- [ ] **Step 5: Commit**

```bash
git add tests/test_introspect_helper_integration.py
git commit -m "test(introspect): golden integration tests for helpers"
```

---

## Task 16: ADR 0009

**Files:**
- Create: `docs/adr/0009-introspect-helper-layer.md`
- Modify: `docs/adr/README.md` (index)

- [ ] **Step 1: Write the ADR**

Create `docs/adr/0009-introspect-helper-layer.md` following the project ADR format (Status · Context · Decision · Consequences · Considered & rejected). Populate the three decided points and their rejected alternatives verbatim from spec §9:
- Shared core executor (rejected: helper-delegates-to-run).
- Single-emit typed-result + raised helper cap profile (rejected: advisory validation; jsonschema runtime validator; runner caps for helpers; per-row streaming).
- `${ARGS_B64}` wrapper seam + single unit-gated operation (rejected: text-prepend args; defer args; per-helper operations).

Set Status to `accepted` and link the spec: `docs/superpowers/specs/2026-05-28-debug-introspect-helper-design.md`.

- [ ] **Step 2: Add the index line**

In `docs/adr/README.md`, add a row/line for `0009-introspect-helper-layer.md` matching the existing index style.

- [ ] **Step 3: Doc guard + commit**

```bash
just check-docs
git add docs/adr/0009-introspect-helper-layer.md docs/adr/README.md
git commit -m "docs(adr): accept introspect helper layer (#54)"
```

---

## Task 17: Full-suite green + final review

**Files:** none (verification)

- [ ] **Step 1: Run the whole suite**

Run: `uv run python -m pytest -q`
Expected: PASS (integration suites SKIPPED without a VM).

- [ ] **Step 2: Lint + format + types**

Run: `uv run ruff check src tests && uv run ruff format --check src tests && uv run ty check src`
Expected: clean.

- [ ] **Step 3: Stdio smoke**

Run: `timeout 2 uv run linux-debug-mcp || test $? -eq 124`
Expected: exit 124 (server started, timed out) — confirms `create_app()` registers the new tool without import errors.

- [ ] **Step 4: Acceptance-criteria checklist (spec §11)**

Confirm each box: helper returns typed JSON (Task 15 `test_sysinfo_invariants`); D-state (Task 15 `test_tasks_dstate_blocker`); dmesg redaction (Task 13 `test_post_validator_redacted_emit_still_validates` + live in Task 15); golden tests fail loud on schema drift (Task 10 + Task 15 model validation); gating via the single op (Task 12). If any is unmet, file the gap as a follow-up step here before closing.

---

## Self-review notes (author)

- **Spec coverage:** §3.1–3.4 → Tasks 3,4–9,10; §4 → Task 1; §5 → Task 2; §6.1 → Task 11; §6.2/6.3 → Task 13 (response data + failure codes); §6.4 → Task 12; §7 → Tasks 4–9; §8.1 → Tasks 3,4–10,13,14; §8.2 → Task 15; §9 → Task 16; §10 → Tasks 1,2,11,12,13; §11 → Task 17.
- **`args` threading:** resolved cleanly by adding an optional `args` field to `DebugIntrospectRunRequest` (Task 13 Step 4) rather than `object.__setattr__`, because `validate_assignment=True` would reject the hack. `run` keeps `args={}` and does not expose the field in its tool signature.
- **Cap completeness:** `HELPER_CAP_PROFILE` overrides only 3 keys; `_merge_and_validate_caps` (Task 1) backfills the other three from `RUNNER_DEFAULT_CAPS`, so the wrapper always gets all six.
- **Type consistency:** `HelperSpec`, `PostValidatorVerdict`, `IntrospectPostValidator`, `_make_helper_post_validator`, `HELPER_CAP_PROFILE`, `RUNNER_DEFAULT_CAPS`, `_merge_and_validate_caps` names are used identically across tasks.
