# Base kernel config generation Implementation Plan

> **For agentic workers:** Implement task-by-task with TDD — write the failing test, watch it fail, then the minimal code to pass. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `kernel.build` build a freshly cloned kernel tree by generating a base `.config` from an
ordered list of make config targets (`base_config`), with a precedence ladder that preserves the
existing developer-`.config` behavior, an actionable failure when no config can be produced, and a new
`x86_64-debug` profile that yields a DWARF, KASLR-disabled, virtio/serial guest kernel.

**Reference docs:** spec `docs/specs/2026-05-30-base-kernel-config-generation.md`; ADR
`docs/adr/0030-base-config-generation.md`. Read both before starting.

**Tech Stack:** Python 3.11+, Pydantic v2 (`ConfigModel`, `extra="forbid"`), pytest, injected fake
runners. Lint/format `ruff`; types `ty`.

---

## File structure

- `src/linux_debug_mcp/config.py` — **modify**: extract `validate_make_targets`; add `base_config` +
  validator to `BuildProfile` and `BuildOverrides`.
- `src/linux_debug_mcp/providers/local_kernel_build.py` — **modify**: `BuildPlan.base_config`;
  `plan_build` populates it; `ConfigGenerationError` + `MissingConfigError`; `_generate_base_config`;
  `prepare_config` precedence ladder (new signature `(plan, log_dir)`); `execute_build` error mapping +
  `config-log` artifact on generation failure.
- `src/linux_debug_mcp/server.py` — **modify**: `x86_64-default` gains `base_config=["defconfig"]`; add
  `x86_64-debug`; `_resolve_initial_profiles` replaces `base_config` from overrides.
- `CLAUDE.md` — **modify**: add `x86_64-debug` to the default-profiles list.
- Tests: extend `tests/test_config.py`, `tests/test_local_kernel_build.py`,
  `tests/test_kernel_build_handler.py`.

---

## Task 1: config-model `base_config` field + shared validator

**Files:** modify `src/linux_debug_mcp/config.py`; extend `tests/test_config.py`.

- [ ] **RED** — add tests: `BuildProfile(base_config=["defconfig","kvm_guest.config"])` accepted and
  round-trips; an invalid token (e.g. `"; rm -rf"`, `"-j8"`, `"a b"`) raises `ValidationError`; same for
  `BuildOverrides`; default `base_config == []`. Watch them fail (field absent).
- [ ] **GREEN** —
  - Add module-level `_MAKE_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./+-]*\Z")` and
    `validate_make_targets(value: list[str]) -> list[str]`.
  - Rewrite `BuildProfile.validate_targets` to delegate to `validate_make_targets`.
  - `BuildProfile`: add `base_config: list[str] = Field(default_factory=list)` + `@field_validator
    ("base_config")` delegating to `validate_make_targets`.
  - `BuildOverrides`: same field + validator.
- [ ] **REFACTOR / verify** — `ruff`, `ty`, run `tests/test_config.py`.

## Task 2: `BuildPlan.base_config` + `plan_build`

**Files:** modify `providers/local_kernel_build.py`; extend `tests/test_kernel_build_handler.py`
(plan_build tests live there).

- [ ] **RED** — `plan_build` with a profile carrying `base_config=["defconfig"]` sets
  `plan.base_config == ["defconfig"]`; default profile → `plan.base_config == []`. Fails (attr absent).
- [ ] **GREEN** — add `base_config: list[str] = field(default_factory=list)` to `BuildPlan`; in
  `plan_build` set `base_config=list(profile.base_config)`.
- [ ] verify.

## Task 3: `prepare_config` precedence ladder + generation

**Files:** modify `providers/local_kernel_build.py`; rewrite the `test_prepare_config_*` provider tests
and add new ones in `tests/test_local_kernel_build.py`.

Note: `prepare_config` signature changes to `(self, *, plan: BuildPlan, log_dir: Path) -> Path`. The
existing `test_prepare_config_*` tests call the old `(source_path, output_path)` signature and must be
rewritten to build a `BuildPlan` (via `plan_build`) and pass `plan`/`log_dir`.

- [ ] **RED** — tests against `prepare_config(plan=..., log_dir=...)`:
  - rung 1: output `.config` exists → returned unchanged, runner not called.
  - rung 2: source `.config` exists, no base_config → copied, runner not called.
  - rung 3: no `.config`, `base_config=["defconfig"]` → runner invoked with
    `["make","-C",src,f"O={out}","ARCH=x86_64","defconfig"]`; use a runner fake that *creates*
    `<out>/.config` on the defconfig call; returns the output `.config`.
  - rung 3 ordered: `base_config=["defconfig","kvm_guest.config"]` → two make calls in list order.
  - rung 3 no result: base_config runs but no `.config` appears → raises `ConfigGenerationError`.
  - rung 3 nonzero: a target returns nonzero → raises `ConfigGenerationError` with a diagnostic tail and
    a `log_path` pointing at `config-base-00-<target>.log`.
  - rung 4: no `.config`, empty base_config → raises `MissingConfigError` with `.suggested_fix`.
- [ ] **GREEN** —
  - Add `class ConfigGenerationError(Exception)` (carries `diagnostic`, `log_path`) and `class
    MissingConfigError(Exception)` (carries `suggested_fix`).
  - Add module-level `_sanitize_target(target) -> str` (`re.sub(r"[^A-Za-z0-9_.-]", "_", target)`).
  - Add `_generate_base_config(self, *, plan, log_dir)`: `log_dir.mkdir(parents=True, exist_ok=True)`;
    for `index, target` in `enumerate(plan.base_config)`, run
    `["make","-C",str(plan.source_path),f"O={plan.output_path}","ARCH=x86_64",target]` →
    `log_dir / f"config-base-{index:02d}-{_sanitize_target(target)}.log"`, `cwd=plan.output_path`,
    `env=plan.environment`, `timeout=plan.timeout_seconds`; nonzero → raise `ConfigGenerationError`
    with `diagnostic=self._log_tail(log_path)`, `log_path=log_path`.
  - Rewrite `prepare_config` to the 4-rung ladder (output → source → generate → `MissingConfigError`);
    after generation, if `output_config` absent raise `ConfigGenerationError("base config targets
    produced no .config")`.
- [ ] verify.

## Task 4: `execute_build` error mapping + `config-log` artifact

**Files:** modify `providers/local_kernel_build.py`; add tests to `tests/test_local_kernel_build.py`.

- [ ] **RED** —
  - `execute_build` on a clean tree with `base_config=["defconfig"]` (runner creates `.config` on
    defconfig) → SUCCEEDED; command order: defconfig → (merge if config_lines) → olddefconfig → main make.
  - generation nonzero → result `FAILED`, `CONFIGURATION_ERROR`, `diagnostic` carries redacted tail, and
    `artifacts` includes an `ArtifactRef(kind="config-log")` for the failing target's log.
  - no `.config` + empty base_config → `FAILED`, `CONFIGURATION_ERROR`,
    `details["suggested_fix"]` present.

  Test-construction notes (verified against the current provider):
  - The SUCCEEDED defconfig test must satisfy the existing required-artifacts gate
    (`_assemble_build_result` requires both `.config` and `bzImage`): pre-create `bzImage` (as
    `_make_run_dir` does) in addition to having the fake runner create `<out>/.config` on the
    defconfig call. The success path calls `_extract_build_id(vmlinux)`, which the conftest autouse
    `_stub_extract_build_id` fixture already neutralizes — no real `vmlinux` needed.
  - Command-ordering depends on whether `config_lines` are present. Assert the full
    `defconfig → merge_config.sh → olddefconfig → bzImage` sequence only against a profile that has
    **both** `base_config` and `config_lines` (the `x86_64-debug` shape). Against a `base_config`-only
    profile (e.g. `x86_64-default`), `_apply_config_lines` returns early, so the order is just
    `defconfig → bzImage` — assert that separately.
- [ ] **GREEN** —
  - Update the `prepare_config` call site: `self.prepare_config(plan=plan, log_dir=log_path.parent)`.
  - Add `except ConfigGenerationError` → `CONFIGURATION_ERROR`, `diagnostic=exc.diagnostic`,
    `artifacts=[ArtifactRef(path=str(exc.log_path), kind="config-log")]` when `exc.log_path` is a file.
  - Add `except MissingConfigError` → `CONFIGURATION_ERROR`,
    `details={..., "suggested_fix": exc.suggested_fix}`.
  - Remove the now-dead `except ValueError` arm (prepare_config no longer raises `ValueError`).
- [ ] verify.

## Task 5: default profiles + override replacement

**Files:** modify `server.py`, `CLAUDE.md`; extend `tests/test_config.py` and
`tests/test_kernel_build_handler.py`.

- [ ] **RED** —
  - `DEFAULT_BUILD_PROFILES["x86_64-default"].base_config == ["defconfig"]`.
  - `x86_64-debug` resolves with `base_config == ["defconfig"]` and the exact spec `config_lines`.
  - End-to-end: `create_run_handler(build_overrides=BuildOverrides(base_config=["tinyconfig"]))` then
    `_build_profile_from_manifest` (or build) shows `base_config == ["tinyconfig"]` (replacement, not
    merged with `["defconfig"]`).
  - Re-point `test_kernel_build_fails_without_developer_config`: the local `create_run` helper
    (`test_kernel_build_handler.py:99`) creates a source `.config` via `with_config=True`, which would
    stop the ladder at rung 2. The re-pointed test must therefore use a source tree with **no**
    `.config` **and** a `build_profile_spec` with `base_config=[]`, so the ladder reaches rung 4.
    Rung 4 raises `MissingConfigError` inside `prepare_config` *before* any runner/`make` call, so no
    provider injection and no real `make` is involved. Assert `CONFIGURATION_ERROR`, `suggested_fix` in
    the failure `details`, and the recorded build step is `FAILED`.
- [ ] **GREEN** —
  - `x86_64-default`: `base_config=["defconfig"]`.
  - Add `x86_64-debug` `BuildProfile(name="x86_64-debug", architecture="x86_64",
    base_config=["defconfig"], config_lines=[... 9 lines from the spec ...])`.
  - `_resolve_initial_profiles`: `if build_overrides.base_config: build_update["base_config"] =
    list(build_overrides.base_config)`; update the merge-comment to note base_config is replaced.
  - `CLAUDE.md`: add `x86_64-debug` to the default-profiles enumeration.
- [ ] verify.

## Task 6: full guardrails

- [ ] `uv run ruff check` + `uv run ruff format`, `uv run ty check src`, `uv run python -m pytest -q`.
- [ ] `just check-docs`.
- [ ] Confirm no JSON-schema snapshot regen needed (`introspect_helpers/schemas/` has no
  `BuildProfile`/`BuildOverrides` snapshot — verified absent).

---

## Risks / notes

- `prepare_config` signature change ripples to the `test_prepare_config_*` provider tests — rewrite them
  (legitimate: the contract changed), do not monkey-patch around it.
- `config_lines` still re-merge on every `execute_build` (rung-1 idempotent rebuild re-applies them);
  this is unchanged from today and `merge_config.sh -m` + `olddefconfig` are idempotent for the same
  symbols.
- Adding `x86_64-debug` must not break any test asserting the default-profile set — verified no
  exact-set assertion on `DEFAULT_BUILD_PROFILES` exists.
