# Dynamic Profile Overrides — Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an agent inject inline kernel-config fragment lines (`config_lines`) on a run, merged into the developer-prepared base `.config` at build time via `merge_config.sh`.

**Architecture:** `config_lines` ride the same frozen-resolved-profile path Phase 1 built. `BuildOverrides.config_lines` and `BuildProfile.config_lines` are layered + validated at `create_run` and frozen into `resolved_build_profile`. At build time the local provider writes the resolved lines to `inputs/override.config`, runs `scripts/kconfig/merge_config.sh -m -O <build> <base.config> <override.config>` then `make O=<build> olddefconfig` (both through the injectable runner, with `cwd` set to the writable build dir), before the main `make`.

**Tech Stack:** Python 3.11+, pydantic v2, pytest, `uv`/`ruff`. No new dependencies.

**Scope:** Phase 2 only (the `config_lines` config-fragment merge). Phase 1 (boot-time overrides, `make_variables`, boot-attempt model, resolved-profile freezing) is already merged on this branch and is the substrate this builds on. This plan implements design sections §1 (`config_lines` merge semantics), §2 (`config_lines` validator), §7 (build-provider fragment support), and the `config_lines` parts of §8 (tool surface), from `docs/superpowers/specs/2026-05-25-dynamic-profile-overrides-design.md`.

---

## Decisions locked in before implementation

These resolve the §7 "planning prerequisites" and two ambiguities the spec left open. They are settled — do not re-litigate them during implementation.

1. **`merge_config.sh` confirmed.** Present at `<source>/scripts/kconfig/merge_config.sh` in the supported tree (`/home/dave/src/linux`). Under `-m` it merges fragments without running make and does `cp -T "$TMP_FILE" "$KCONFIG_CONFIG"`; `-O <dir>` sets `KCONFIG_CONFIG=<dir>/.config`. So `merge_config.sh -m -O <build> <base.config> <override.config>` writes the merged config to `<build>/.config`. We then run `make O=<build> olddefconfig` to normalize. The first positional CONFIG arg is the base (it is `cat`'d to a temp file first); later fragments override it.

2. **`merge_config.sh` needs a writable cwd.** It creates `mktemp ./.tmp.config.XXXXXXXXXX` **relative to the current directory**. We therefore extend `BuildRunner.run` with an optional `cwd: Path | None = None` and invoke the merge (and the follow-up `olddefconfig`) with `cwd=<build dir>` (per-run, writable) so the temp file never lands in the source tree. The main `make` call is **deliberately left with no `cwd`** (inherits the process cwd): it uses `make -C <source> O=<build>` with no relative temp files, so it needs no override — do not "fix" that asymmetry. The `olddefconfig` argv hardcodes `ARCH=x86_64`, matching the existing main-make argv (`local_kernel_build.py:90`); the provider only supports x86_64 (enforced at `plan_build`, `:84`), so this is correct and intentionally mirrors the existing line rather than deriving from `plan.architecture`.

3. **`config_fragments` is removed, replaced by `config_lines`.** `BuildProfile.config_fragments: list[Path]` is a phantom field — defined but only ever *rejected* (`local_kernel_build.py:88`), never implemented. Per the project standard ("no phantom features", "replace, don't deprecate"), Phase 2 removes it entirely and replaces it with `config_lines: list[str]`, the inline mechanism the spec actually specifies. Its two test references are updated to the new field.

   **Manifest note:** `BuildProfile` is embedded in `RunManifest.resolved_build_profile`, and `ConfigModel` sets `extra="forbid"` (`config.py:77`). *Removing* a field is therefore non-additive (unlike the spec's §Migration additive bump): any manifest serialized locally during Phase-1 development with `"config_fragments": []` will fail `model_validate_json` after removal. There are no committed JSON fixtures carrying this field, and Phase 1 is freshly merged on this branch, so fresh trees and CI are unaffected — but if you have a local run dir created mid-Phase-1, discard it (delete the stale run's `manifest.json`); no migration code is warranted for a never-released field.

4. **`override.config` location.** Written to `<run_dir>/inputs/override.config`, derived inside the provider as `plan.output_path.parent / "inputs" / "override.config"`. Under the enforced `per_run` output policy `output_path` is always `<run_dir>/build`, so `.parent` is the run dir. The merge log goes to `<run_dir>/logs/config-merge.log` and the olddefconfig log to `<run_dir>/logs/config-olddefconfig.log` (siblings of `build.log`, derived from `log_path.parent`). These logs are written for debugging but are not registered in the artifact manifest in Phase 2.

---

## File structure

| File | Responsibility | Change |
|------|----------------|--------|
| `src/linux_debug_mcp/config.py` | Validators, merge helpers, profile/override models | Add `validate_config_line_tokens`, `merge_config_lines`; replace `BuildProfile.config_fragments` with `config_lines`; add `config_lines` to `BuildOverrides` |
| `src/linux_debug_mcp/providers/local_kernel_build.py` | Local kernel build provider | Remove fragment-rejection guard; add `cwd` to runner; add `config_lines` to `BuildPlan`; add `ConfigMergeError` + `_apply_config_lines` merge step |
| `src/linux_debug_mcp/server.py` | Handlers + tool surface | Merge `config_lines` in `_resolve_initial_profiles`; thread `config_lines` through `_overrides_from_tool_args` and the `kernel.create_run` tool |
| `docs/fedora-libvirt-user-guide.md` | User guide | Correct the "does not run `defconfig` or generate kernel configs" claim |
| `tests/test_config_overrides.py` | Override-model + helper tests | Add `config_lines` validator/merge tests |
| `tests/test_config.py` | Profile model tests | Update `config_fragments` reference to `config_lines` |
| `tests/test_local_kernel_build.py` | Provider tests | Update `FakeRunner` for `cwd`; replace the fragment-rejection test; add merge-step tests |
| `tests/test_kernel_build_handler.py` | Handler runner fakes | Add `cwd` to fake-runner `run` signatures |
| `tests/test_server.py` | End-to-end | Add `config_lines` create_run → build integration + redaction test |

---

## Task 1: `config_lines` validator and symbol-merge helper

**Files:**
- Modify: `src/linux_debug_mcp/config.py` (add after `merge_kernel_args`, around line 37)
- Test: `tests/test_config_overrides.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_config_overrides.py` already has `import pytest` and a `from linux_debug_mcp.config import (BootOverrides, BuildOverrides, TargetProfile, merge_kernel_args)` block. **Do not add new import statements** — merge `merge_config_lines` and `validate_config_line_tokens` into that existing block (keeping it sorted), so it reads:

```python
from linux_debug_mcp.config import (
    BootOverrides,
    BuildOverrides,
    TargetProfile,
    merge_config_lines,
    merge_kernel_args,
    validate_config_line_tokens,
)
```

Then add the test functions to `tests/test_config_overrides.py`:

```python
@pytest.mark.parametrize(
    "line",
    [
        "CONFIG_DEBUG_INFO=y",
        "CONFIG_FOO=m",
        "# CONFIG_BAR is not set",
        "CONFIG_NR_CPUS=8",
        "CONFIG_DELAY=-1",
        "CONFIG_BASE=0x1000",
        'CONFIG_CMDLINE="console=ttyS0 nokaslr"',
    ],
)
def test_validate_config_line_accepts_valid_grammar(line: str) -> None:
    assert validate_config_line_tokens([line]) == [line]


@pytest.mark.parametrize(
    "line",
    [
        "CONFIG_FOO",  # no value
        "CONFIG_FOO=maybe",  # not y/m/n/int/hex/string
        "CONFIG_foo=y",  # lowercase symbol
        "CONFIG_FOO=y; rm -rf /",  # shell injection
        "rm -rf /",  # not a config line
        "# CONFIG_FOO is unset",  # wrong "is not set" phrasing
        'CONFIG_X="bad\nnewline"',  # embedded newline
        "CONFIG_FOO=y\nCONFIG_BAR=y",  # multi-line single token
    ],
)
def test_validate_config_line_rejects_invalid_grammar(line: str) -> None:
    with pytest.raises(ValueError, match="invalid kernel config line"):
        validate_config_line_tokens([line])


def test_merge_config_lines_last_wins_by_symbol() -> None:
    base = ["CONFIG_A=y", "CONFIG_B=m"]
    override = ["CONFIG_B=n", "CONFIG_C=y"]
    assert merge_config_lines(base, override) == ["CONFIG_A=y", "CONFIG_B=n", "CONFIG_C=y"]


def test_merge_config_lines_override_can_unset_base_symbol() -> None:
    base = ["CONFIG_A=y"]
    override = ["# CONFIG_A is not set"]
    assert merge_config_lines(base, override) == ["# CONFIG_A is not set"]


def test_merge_config_lines_empty_override_returns_base() -> None:
    base = ["CONFIG_A=y"]
    assert merge_config_lines(base, []) == ["CONFIG_A=y"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && uv run python -m pytest tests/test_config_overrides.py -k "config_line" -v`
Expected: FAIL with `ImportError: cannot import name 'merge_config_lines'` / `'validate_config_line_tokens'`.

- [ ] **Step 3: Implement the validator and merge helper**

In `src/linux_debug_mcp/config.py`, add the pattern near the other module patterns (after line 14):

```python
_CONFIG_LINE_PATTERN = re.compile(
    r'^(?:CONFIG_[A-Z0-9_]+=(?:[ymn]|-?\d+|0x[0-9A-Fa-f]+|"[^"\n]*")'
    r"|# CONFIG_[A-Z0-9_]+ is not set)$"
)
```

Add these functions after `merge_kernel_args` (after line 36):

```python
def validate_config_line_tokens(value: list[str]) -> list[str]:
    for line in value:
        if not _CONFIG_LINE_PATTERN.match(line):
            raise ValueError(f"invalid kernel config line: {line!r}")
    return value


def _config_symbol(line: str) -> str:
    if line.startswith("# CONFIG_"):
        return line[len("# ") :].split(" ", 1)[0]
    return line.split("=", 1)[0]


def merge_config_lines(base: list[str], override: list[str]) -> list[str]:
    override_symbols = {_config_symbol(line) for line in override}
    merged = [line for line in base if _config_symbol(line) not in override_symbols]
    merged.extend(override)
    return merged
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && uv run python -m pytest tests/test_config_overrides.py -k "config_line" -v`
Expected: PASS (all parametrized cases green).

- [ ] **Step 5: Commit**

```bash
cd /home/dave/src/linux-debug-mcp-dynamic-profiles
git add src/linux_debug_mcp/config.py tests/test_config_overrides.py
git commit -m "feat: add config_lines validator and symbol-merge helper"
```

---

## Task 2: Replace `config_fragments` with `config_lines` on the profile models

**Files:**
- Modify: `src/linux_debug_mcp/config.py:90` (`BuildProfile`), `:218-224` (`BuildOverrides`)
- Modify: `tests/test_config.py:272`
- Test: `tests/test_config_overrides.py`

- [ ] **Step 1: Write the failing tests**

`BuildOverrides` is already imported in `tests/test_config_overrides.py`; add `BuildProfile` to the same existing `from linux_debug_mcp.config import (...)` block (do not add a standalone import line). Then add the test functions:

```python
def test_build_profile_has_config_lines_and_validates() -> None:
    profile = BuildProfile(name="x", architecture="x86_64", config_lines=["CONFIG_A=y"])
    assert profile.config_lines == ["CONFIG_A=y"]


def test_build_profile_rejects_invalid_config_line() -> None:
    with pytest.raises(ValueError, match="invalid kernel config line"):
        BuildProfile(name="x", architecture="x86_64", config_lines=["CONFIG_A=y; evil"])


def test_build_profile_no_longer_accepts_config_fragments() -> None:
    with pytest.raises(ValueError):
        BuildProfile(name="x", architecture="x86_64", config_fragments=["/tmp/frag"])


def test_build_overrides_config_lines_validated() -> None:
    overrides = BuildOverrides(config_lines=["# CONFIG_A is not set"])
    assert overrides.config_lines == ["# CONFIG_A is not set"]
    with pytest.raises(ValueError, match="invalid kernel config line"):
        BuildOverrides(config_lines=["not a config line"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && uv run python -m pytest tests/test_config_overrides.py -k "config_lines or config_fragments" -v`
Expected: FAIL — `BuildProfile` still accepts `config_fragments` and has no `config_lines`.

- [ ] **Step 3: Update the models**

In `src/linux_debug_mcp/config.py`, in `BuildProfile`, replace line 90:

```python
    config_fragments: list[Path] = Field(default_factory=list)
```

with:

```python
    config_lines: list[str] = Field(default_factory=list)
```

Add a validator to `BuildProfile` (next to `validate_make_variables`, after line 111):

```python
    @field_validator("config_lines")
    @classmethod
    def validate_config_lines(cls, value: list[str]) -> list[str]:
        return validate_config_line_tokens(value)
```

In `BuildOverrides` (lines 218-224), add the field and validator so the model becomes:

```python
class BuildOverrides(ConfigModel):
    make_variables: dict[str, str] = Field(default_factory=dict)
    config_lines: list[str] = Field(default_factory=list)

    @field_validator("make_variables")
    @classmethod
    def validate_make_variables(cls, value: dict[str, str]) -> dict[str, str]:
        return validate_make_variable_map(value)

    @field_validator("config_lines")
    @classmethod
    def validate_config_lines(cls, value: list[str]) -> list[str]:
        return validate_config_line_tokens(value)
```

- [ ] **Step 4: Update the existing `config_fragments` assertion**

In `tests/test_config.py`, change line 272 from:

```python
    assert profile.config_fragments == []
```

to:

```python
    assert profile.config_lines == []
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && uv run python -m pytest tests/test_config_overrides.py tests/test_config.py -v`
Expected: PASS. (`Path` is still imported — it is used by `ServerConfig`; do not remove the import.)

- [ ] **Step 6: Commit**

```bash
cd /home/dave/src/linux-debug-mcp-dynamic-profiles
git add src/linux_debug_mcp/config.py tests/test_config_overrides.py tests/test_config.py
git commit -m "feat: replace BuildProfile.config_fragments with config_lines"
```

---

## Task 3: Provider plumbing — remove guard, add runner `cwd`, thread `config_lines` into `BuildPlan`

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_kernel_build.py` (`BuildRunner`, `SubprocessBuildRunner`, `BuildPlan`, `plan_build`)
- Modify: `tests/test_local_kernel_build.py` (`FakeRunner`, replace fragment-rejection test)
- Modify: `tests/test_kernel_build_handler.py` (5 fake runner `run` signatures)
- Modify: `tests/test_workflow_build_boot_test_handler.py` (`_NoopBuildRunner.run` signature, ~line 263)

> Build-runner fakes (those whose `run` takes `env: dict[str, str]`) live in exactly three test files: `test_local_kernel_build.py` (`FakeRunner`), `test_kernel_build_handler.py` (`NoopRunner`, `BlockingRunner`, `RaisingRunner`, `FailingRunner`, `TransientManifestLockRunner`), and `test_workflow_build_boot_test_handler.py` (`_NoopBuildRunner`). The SSH/libvirt runners (`stdout_path`/`CommandResult` shape) are unrelated — do not touch them.

- [ ] **Step 1: Write/replace the failing tests**

In `tests/test_local_kernel_build.py`, **replace** `test_plan_build_rejects_config_fragments_until_supported` (lines 80-89) with:

```python
def test_plan_build_threads_config_lines_into_plan(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(
        name="frag",
        architecture="x86_64",
        config_lines=["CONFIG_DEBUG_INFO=y"],
    )

    plan = provider.plan_build(
        source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile
    )

    assert plan.config_lines == ["CONFIG_DEBUG_INFO=y"]
    # config_lines do not appear in the main make argv
    assert not any("CONFIG_DEBUG_INFO" in arg for arg in plan.argv)
```

Update `FakeRunner` (lines 92-108) to accept and record `cwd`:

```python
class FakeRunner:
    def __init__(self, *, tools: dict[str, str] | None = None, returncode: int = 0, output: str = "") -> None:
        self.tools = {"make": "/usr/bin/make"} if tools is None else tools
        self.returncode = returncode
        self.output = output
        self.commands: list[list[str]] = []
        self.environments: list[dict[str, str]] = []
        self.cwds: list[Path | None] = []

    def which(self, command: str) -> str | None:
        return self.tools.get(command)

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        self.commands.append(argv)
        self.environments.append(env)
        self.cwds.append(cwd)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(self.output, encoding="utf-8")
        return self.returncode
```

In `tests/test_kernel_build_handler.py` (the 5 fakes) and `tests/test_workflow_build_boot_test_handler.py` (`_NoopBuildRunner`), add `cwd: Path | None = None` to every fake-runner `run` signature. Keep each body exactly as it is — only the signature changes. Each becomes:

```python
    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        ...  # keep the existing body of THIS class unchanged
```

(Note: `TransientManifestLockRunner.run` calls `super().run(argv, timeout=timeout, log_path=log_path, env=env)` — leave that call as-is; the inherited `cwd` default applies.)

Confirm you caught them all: after editing,
`cd /home/dave/src/linux-debug-mcp-dynamic-profiles && rg -n "def run\(self, argv: list\[str\], \*, timeout: int, log_path: Path, env: dict\[str, str\]\) -> int" tests/`
should report **zero** lines (every build-runner `run` is now the multi-line `cwd` form).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && uv run python -m pytest tests/test_local_kernel_build.py::test_plan_build_threads_config_lines_into_plan -v`
Expected: FAIL — `BuildPlan` has no `config_lines` field (`TypeError`).

- [ ] **Step 3: Implement provider plumbing**

In `src/linux_debug_mcp/providers/local_kernel_build.py`:

Add `cwd` to the `BuildRunner` protocol (lines 41-42):

```python
    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        raise NotImplementedError
```

Add `cwd` to `SubprocessBuildRunner.run` (lines 49-60) and pass it through:

```python
    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        with log_path.open("w", encoding="utf-8") as log_file:
            completed = subprocess.run(
                argv,
                check=False,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=env,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
        return completed.returncode
```

Add `config_lines` to `BuildPlan` (after `environment`, line 34):

```python
    environment: dict[str, str]
    config_lines: list[str] = field(default_factory=list)
```

In `plan_build`, remove the rejection guard (lines 88-89):

```python
        if profile.config_fragments:
            raise ValueError("config fragments are not supported by the local Sprint 1 provider")
```

and set `config_lines` on the returned `BuildPlan` (add to the `BuildPlan(...)` constructor, after `environment=...`):

```python
            environment=self._sanitized_environment(),
            config_lines=list(profile.config_lines),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && uv run python -m pytest tests/test_local_kernel_build.py tests/test_kernel_build_handler.py -v`
Expected: PASS (the merge step itself is Task 4; `config_lines` default `[]` means `execute_build` behavior is unchanged so far).

- [ ] **Step 5: Commit**

```bash
cd /home/dave/src/linux-debug-mcp-dynamic-profiles
git add src/linux_debug_mcp/providers/local_kernel_build.py tests/test_local_kernel_build.py tests/test_kernel_build_handler.py
git commit -m "feat: thread config_lines into BuildPlan and add runner cwd"
```

---

## Task 4: Config-fragment merge step in `execute_build`

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_kernel_build.py` (add `ConfigMergeError`, `_apply_config_lines`; wire into `execute_build`)
- Test: `tests/test_local_kernel_build.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_local_kernel_build.py`:

```python
def _make_run_dir(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "linux"
    (source / "scripts" / "kconfig").mkdir(parents=True)
    (source / "scripts" / "kconfig" / "merge_config.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (source / ".config").write_text("CONFIG_BASE=y\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "run-1"
    output = run_dir / "build"
    (output / "arch" / "x86" / "boot").mkdir(parents=True)
    (output / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    return source, output


def test_execute_applies_config_lines_before_main_make(tmp_path: Path) -> None:
    source, output = _make_run_dir(tmp_path)
    runner = FakeRunner(output="ok\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(
        name="frag", architecture="x86_64", config_lines=["CONFIG_DEBUG_INFO=y", "# CONFIG_FOO is not set"]
    )
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "succeeded"
    # Three runner calls in order: merge_config.sh, olddefconfig, main make.
    assert runner.commands[0] == [
        str(source / "scripts" / "kconfig" / "merge_config.sh"),
        "-m",
        "-O",
        str(output),
        str(output / ".config"),
        str(output.parent / "inputs" / "override.config"),
    ]
    assert runner.commands[1] == ["make", "-C", str(source), f"O={output}", "ARCH=x86_64", "olddefconfig"]
    assert runner.commands[2] == plan.argv
    # merge_config.sh ran with the build dir as cwd (writable temp-file location).
    assert runner.cwds[0] == output
    # override.config holds exactly the resolved config_lines.
    override = (output.parent / "inputs" / "override.config").read_text(encoding="utf-8")
    assert override == "CONFIG_DEBUG_INFO=y\n# CONFIG_FOO is not set\n"


def test_execute_without_config_lines_runs_only_main_make(tmp_path: Path) -> None:
    source, output = _make_run_dir(tmp_path)
    runner = FakeRunner(output="ok\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "succeeded"
    assert runner.commands == [plan.argv]
    assert not (output.parent / "inputs" / "override.config").exists()


def test_execute_config_merge_nonzero_returns_configuration_error(tmp_path: Path) -> None:
    source, output = _make_run_dir(tmp_path)
    runner = FakeRunner(returncode=1, output="token=secret\nmerge boom\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(name="frag", architecture="x86_64", config_lines=["CONFIG_DEBUG_INFO=y"])
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.CONFIGURATION_ERROR
    assert "config merge failed" in result.summary
    assert "token=[REDACTED]" in result.diagnostic


def test_execute_config_lines_without_merge_script_fails(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / ".config").write_text("CONFIG_BASE=y\n", encoding="utf-8")
    output = tmp_path / "runs" / "run-1" / "build"
    (output / "arch" / "x86" / "boot").mkdir(parents=True)
    (output / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    runner = FakeRunner(output="ok\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(name="frag", architecture="x86_64", config_lines=["CONFIG_DEBUG_INFO=y"])
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.CONFIGURATION_ERROR
    assert "merge_config.sh not found" in result.summary
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && uv run python -m pytest tests/test_local_kernel_build.py -k "config_lines or config_merge" -v`
Expected: FAIL — no merge step yet, so only one runner call is recorded and `override.config` is never written.

- [ ] **Step 3: Implement `ConfigMergeError` and the merge step**

In `src/linux_debug_mcp/providers/local_kernel_build.py`, add the exception after the imports (before `BuildPlan`, around line 23):

```python
class ConfigMergeError(Exception):
    def __init__(self, message: str, *, diagnostic: str | None = None) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic
```

Add the `_apply_config_lines` method to `LocalKernelBuildProvider` (place it after `prepare_config`, before `detect_source_revision`):

```python
    def _apply_config_lines(self, *, plan: BuildPlan, base_config: Path, log_dir: Path) -> None:
        if not plan.config_lines:
            return
        merge_script = plan.source_path / "scripts" / "kconfig" / "merge_config.sh"
        if not merge_script.is_file():
            raise ConfigMergeError(f"merge_config.sh not found at {merge_script}")
        inputs_dir = plan.output_path.parent / "inputs"
        inputs_dir.mkdir(parents=True, exist_ok=True)
        override_config = inputs_dir / "override.config"
        override_config.write_text("\n".join(plan.config_lines) + "\n", encoding="utf-8")
        merge_log = log_dir / "config-merge.log"
        merge_status = self.runner.run(
            [str(merge_script), "-m", "-O", str(plan.output_path), str(base_config), str(override_config)],
            timeout=plan.timeout_seconds,
            log_path=merge_log,
            env=plan.environment,
            cwd=plan.output_path,
        )
        if merge_status != 0:
            raise ConfigMergeError(
                f"kernel config merge failed (exit status {merge_status})",
                diagnostic=self._log_tail(merge_log),
            )
        olddefconfig_log = log_dir / "config-olddefconfig.log"
        olddefconfig_status = self.runner.run(
            ["make", "-C", str(plan.source_path), f"O={plan.output_path}", "ARCH=x86_64", "olddefconfig"],
            timeout=plan.timeout_seconds,
            log_path=olddefconfig_log,
            env=plan.environment,
            cwd=plan.output_path,
        )
        if olddefconfig_status != 0:
            raise ConfigMergeError(
                f"olddefconfig failed (exit status {olddefconfig_status})",
                diagnostic=self._log_tail(olddefconfig_log),
            )
```

In `execute_build`, change the try-block (lines 157-168) to capture the base config, call the merge, and handle `ConfigMergeError` first:

```python
        try:
            base_config = self.prepare_config(source_path=plan.source_path, output_path=plan.output_path)
            self._apply_config_lines(plan=plan, base_config=base_config, log_dir=log_path.parent)
            exit_status = self.runner.run(
                plan.argv, timeout=plan.timeout_seconds, log_path=log_path, env=plan.environment
            )
        except ConfigMergeError as exc:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary=str(exc),
                error_category=ErrorCategory.CONFIGURATION_ERROR,
                details={"argv": plan.argv, "source_revision": source_revision},
                diagnostic=exc.diagnostic,
            )
        except ValueError as exc:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary=str(exc),
                error_category=ErrorCategory.CONFIGURATION_ERROR,
                details={"argv": plan.argv, "source_revision": source_revision},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary=f"build infrastructure failure: {exc}",
                error_category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                details={"argv": plan.argv, "source_revision": source_revision},
                diagnostic=self._log_tail(log_path),
            )
```

(The existing `ValueError`/`OSError` branches are unchanged except for the new `base_config` assignment and the merge call inside `try`. The `ConfigMergeError` branch must come **before** the `ValueError` branch — `ConfigMergeError` is not a `ValueError` subclass, so ordering is for readability/intent.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && uv run python -m pytest tests/test_local_kernel_build.py -v`
Expected: PASS (new merge tests green; pre-existing provider tests still green — they use no `config_lines`, so the merge is a no-op).

- [ ] **Step 5: Commit**

```bash
cd /home/dave/src/linux-debug-mcp-dynamic-profiles
git add src/linux_debug_mcp/providers/local_kernel_build.py tests/test_local_kernel_build.py
git commit -m "feat: apply config_lines via merge_config.sh before main build"
```

---

## Task 5: Merge `config_lines` in `_resolve_initial_profiles`

**Files:**
- Modify: `src/linux_debug_mcp/server.py:24` (import), `:399-403` (`_resolve_initial_profiles` build merge)
- Test: `tests/test_server.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_server.py`. It already imports `BuildOverrides` (line 5), `server`, and uses the module-level `make_source_tree` helper and the `ArtifactStore(..., create_root=False)` + `store.load_manifest(run_id)` pattern (see `test_create_run_freezes_merged_profiles`). Mirror that exactly:

```python
def test_create_run_freezes_merged_config_lines(tmp_path):
    source = make_source_tree(tmp_path)
    response = server.create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        build_overrides=BuildOverrides(config_lines=["CONFIG_DEBUG_INFO=y"]),
    )
    assert response.ok
    run_id = response.run_id
    store = server.ArtifactStore(tmp_path / "runs", create_root=False)
    manifest = store.load_manifest(run_id)
    assert manifest.resolved_build_profile is not None
    assert manifest.resolved_build_profile.config_lines == ["CONFIG_DEBUG_INFO=y"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && uv run python -m pytest tests/test_server.py::test_create_run_freezes_merged_config_lines -v`
Expected: FAIL — `resolved_build_profile.config_lines` is `[]` because the merge ignores `config_lines`.

- [ ] **Step 3: Implement the merge**

In `src/linux_debug_mcp/server.py`, extend the import at line 24 (the block importing from `linux_debug_mcp.config`) to include `merge_config_lines`:

```python
    merge_config_lines,
    merge_kernel_args,
```

Replace the build-override merge in `_resolve_initial_profiles` (lines 399-403):

```python
    resolved_build = base_build
    if build_overrides is not None and build_overrides.make_variables:
        resolved_build = base_build.model_copy(
            update={"make_variables": {**base_build.make_variables, **build_overrides.make_variables}}
        )
```

with:

```python
    resolved_build = base_build
    if build_overrides is not None:
        build_update: dict[str, object] = {}
        if build_overrides.make_variables:
            build_update["make_variables"] = {**base_build.make_variables, **build_overrides.make_variables}
        if build_overrides.config_lines:
            build_update["config_lines"] = merge_config_lines(
                base_build.config_lines, build_overrides.config_lines
            )
        if build_update:
            resolved_build = base_build.model_copy(update=build_update)
```

(The `model_copy(update=...)` safety note already in the comment above this block still applies: both base and override `config_lines` were validated at construction, and `merge_config_lines` only filters + concatenates pre-validated lines.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && uv run python -m pytest tests/test_server.py::test_create_run_freezes_merged_config_lines -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/dave/src/linux-debug-mcp-dynamic-profiles
git add src/linux_debug_mcp/server.py tests/test_server.py
git commit -m "feat: merge config_lines into resolved build profile at create_run"
```

---

## Task 6: Expose `config_lines` on the `kernel.create_run` tool

**Files:**
- Modify: `src/linux_debug_mcp/server.py:2350-2362` (`_overrides_from_tool_args`), `:2380-2413` (`kernel.create_run`), `:2690-2692` (`target.boot` call site)
- Test: `tests/test_server.py`

- [ ] **Step 1: Write the failing tests and update the existing one**

`_overrides_from_tool_args` gains a required keyword-only `config_lines` (matching the no-default style of its siblings). The existing `test_overrides_from_tool_args_builds_models` (test_server.py, ~line 433) calls it **without** `config_lines` at two call sites — it will raise `TypeError` after the signature change. Update both calls to pass `config_lines=None`:

```python
    build, boot = server._overrides_from_tool_args(
        kernel_args=["dhash_entries=1"], rootfs_source=None, make_variables={"CC": "clang"}, config_lines=None
    )
    ...
    none_build, none_boot = server._overrides_from_tool_args(
        kernel_args=None, rootfs_source=None, make_variables=None, config_lines=None
    )
```

Then add the new `config_lines` cases to `tests/test_server.py`:

```python
def test_overrides_from_tool_args_builds_config_lines():
    build_overrides, boot_overrides = server._overrides_from_tool_args(
        kernel_args=None,
        rootfs_source=None,
        make_variables=None,
        config_lines=["CONFIG_DEBUG_INFO=y"],
    )
    assert build_overrides is not None
    assert build_overrides.config_lines == ["CONFIG_DEBUG_INFO=y"]
    assert boot_overrides is None


def test_overrides_from_tool_args_none_when_no_build_overrides():
    build_overrides, _ = server._overrides_from_tool_args(
        kernel_args=["nokaslr"], rootfs_source=None, make_variables=None, config_lines=None
    )
    assert build_overrides is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && uv run python -m pytest tests/test_server.py -k "overrides_from_tool_args" -v`
Expected: FAIL — `_overrides_from_tool_args() got an unexpected keyword argument 'config_lines'`.

- [ ] **Step 3: Thread `config_lines` through the tool surface**

In `src/linux_debug_mcp/server.py`, update `_overrides_from_tool_args` (lines 2350-2362):

```python
def _overrides_from_tool_args(
    *,
    kernel_args: list[str] | None,
    rootfs_source: str | None,
    make_variables: dict[str, str] | None,
    config_lines: list[str] | None,
) -> tuple[BuildOverrides | None, BootOverrides | None]:
    build_overrides = (
        BuildOverrides(make_variables=make_variables or {}, config_lines=config_lines or [])
        if (make_variables or config_lines)
        else None
    )
    boot_overrides = (
        BootOverrides(kernel_args=kernel_args or [], rootfs_source=rootfs_source)
        if (kernel_args or rootfs_source)
        else None
    )
    return build_overrides, boot_overrides
```

Add the `config_lines` parameter to the `kernel.create_run` tool (after `make_variables`, line 2392) and pass it into `_overrides_from_tool_args`:

```python
        make_variables: dict[str, str] | None = None,
        config_lines: list[str] | None = None,
    ) -> dict[str, Any]:
        try:
            build_overrides, boot_overrides = _overrides_from_tool_args(
                kernel_args=kernel_args,
                rootfs_source=rootfs_source,
                make_variables=make_variables,
                config_lines=config_lines,
            )
```

Update the `target.boot` call site (lines 2690-2692) to pass `config_lines=None` (boot has no build-time overrides):

```python
            _build_overrides, boot_overrides = _overrides_from_tool_args(
                kernel_args=kernel_args, rootfs_source=rootfs_source, make_variables=None, config_lines=None
            )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && uv run python -m pytest tests/test_server.py -k "overrides_from_tool_args" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/dave/src/linux-debug-mcp-dynamic-profiles
git add src/linux_debug_mcp/server.py tests/test_server.py
git commit -m "feat: expose config_lines on kernel.create_run tool"
```

---

## Task 7: Correct the user-guide config claim

**Files:**
- Modify: `docs/fedora-libvirt-user-guide.md:170-171`

- [ ] **Step 1: Update the claim**

In `docs/fedora-libvirt-user-guide.md`, replace lines 170-171:

```markdown
The current provider does not run `defconfig` or generate kernel configs for
you. The source tree must already have whatever configuration you want to boot.
```

with:

```markdown
The provider does not run `defconfig`: the source tree must already have a base
`.config` (or one already staged in the run's build dir). It will, however,
apply inline `config_lines` overrides on top of that base — the run writes them
to `inputs/override.config` and merges them with `scripts/kconfig/merge_config.sh`
followed by `make olddefconfig`. `config_lines` augment an existing base config;
they cannot bootstrap one from nothing.
```

- [ ] **Step 2: Verify no other stale claim remains**

Run: `cd /home/dave/src/linux-debug-mcp-dynamic-profiles && rg -n "does not run .defconfig|generate kernel config" docs/fedora-libvirt-user-guide.md`
Expected: only the corrected passage above (no other text claiming fragments are unsupported). Note: a broader `does not run` search also matches the unrelated "It does not run SSH..." line near `:382` — that is expected and must not be touched.

- [ ] **Step 3: Commit**

```bash
cd /home/dave/src/linux-debug-mcp-dynamic-profiles
git add docs/fedora-libvirt-user-guide.md
git commit -m "docs: note config_lines fragment merge in user guide"
```

---

## Task 8: End-to-end `config_lines` merge flow + manifest redaction

These two tests characterize the integrated path. After Tasks 1-6 they pass with no new production code; if either reveals a wiring gap, fix it in the relevant earlier-task file.

**Files:**
- Test: `tests/test_kernel_build_handler.py` (merge flow — reuses `make_source_tree`, `create_run_handler`, `kernel_build_handler`, `NoopRunner`, `LocalKernelBuildProvider`, all already imported)
- Test: `tests/test_server.py` (manifest redaction — mirrors `test_create_run_response_redacts_secret_make_variable`)

- [ ] **Step 1: Write the merge-flow test**

Add to `tests/test_kernel_build_handler.py` (`NoopRunner.run` already records `argv` in `.commands`; it gains `cwd` in Task 3). The module's `make_source_tree` writes a base `.config` but no `merge_config.sh`, so the test adds the script file:

```python
def test_build_applies_config_lines_before_main_make(tmp_path: Path) -> None:
    from linux_debug_mcp.config import BuildOverrides

    source = make_source_tree(tmp_path)
    (source / "scripts" / "kconfig").mkdir(parents=True)
    (source / "scripts" / "kconfig" / "merge_config.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    artifact_root = tmp_path / "runs"
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        build_overrides=BuildOverrides(config_lines=["CONFIG_DEBUG_INFO=y"]),
    )
    assert created.ok is True
    build_dir = artifact_root / "run-abc123" / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")

    runner = NoopRunner()
    response = kernel_build_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=LocalKernelBuildProvider(runner=runner),
    )

    assert response.ok is True
    merge_idx = next(i for i, c in enumerate(runner.commands) if c[0].endswith("merge_config.sh"))
    olddefconfig_idx = next(i for i, c in enumerate(runner.commands) if c[-1] == "olddefconfig")
    main_make_idx = next(i for i, c in enumerate(runner.commands) if c[-1] == "bzImage")
    assert merge_idx < olddefconfig_idx < main_make_idx
    override = (build_dir.parent / "inputs" / "override.config").read_text(encoding="utf-8")
    assert override == "CONFIG_DEBUG_INFO=y\n"
```

- [ ] **Step 2: Write the redaction test**

Add to `tests/test_server.py` (mirrors `test_create_run_response_redacts_secret_make_variable`; the create_run response embeds the redacted manifest dump, which now carries `resolved_build_profile.config_lines`):

```python
def test_create_run_response_redacts_secret_shaped_config_line(tmp_path):
    source = make_source_tree(tmp_path)
    response = server.create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        build_overrides=BuildOverrides(config_lines=['CONFIG_CMDLINE="token=supersecret"']),
    )
    assert response.ok
    assert "supersecret" not in str(response.data)
    assert "[REDACTED]" in str(response.data)
```

- [ ] **Step 3: Run both tests to verify they pass**

Run:
```bash
cd /home/dave/src/linux-debug-mcp-dynamic-profiles
uv run python -m pytest \
  tests/test_kernel_build_handler.py::test_build_applies_config_lines_before_main_make \
  tests/test_server.py::test_create_run_response_redacts_secret_shaped_config_line -v
```
Expected: PASS. (If the merge-flow test fails because the merge step never runs, the gap is in Task 4/5; if redaction fails, confirm the create_run response routes the manifest dump through `Redactor` — Phase 1 wired this.)

- [ ] **Step 4: Run the full suite + linters**

Run:
```bash
cd /home/dave/src/linux-debug-mcp-dynamic-profiles
uv run python -m pytest -q
uv run ruff check src/ tests/
```
Expected: all tests pass (Phase 1's count plus the Phase 2 additions), `ruff` reports "All checks passed!".

- [ ] **Step 5: Commit**

```bash
cd /home/dave/src/linux-debug-mcp-dynamic-profiles
git add tests/test_kernel_build_handler.py tests/test_server.py
git commit -m "test: end-to-end config_lines merge flow and manifest redaction"
```

---

## Final verification (after all tasks)

- [ ] Full suite green: `uv run python -m pytest -q`
- [ ] Lint clean: `uv run ruff check src/ tests/`
- [ ] No `config_fragments` references remain **in code**: `rg -n "config_fragments" src/ tests/` returns nothing. (Do **not** grep `docs/` — the design spec and the Phase-0/Phase-1 plan/design docs legitimately retain historical `config_fragments` mentions; those are records of past decisions and must not be edited.)
- [ ] The Phase 2 boundary in the Phase 1 plan is now satisfied (the rejection guard is gone, `merge_config.sh` is wired). The note at `docs/superpowers/plans/2026-05-25-dynamic-profile-overrides-phase-1.md:11` referred to *Phase 1* scope and is left as historical record.
- [ ] Dispatch a final code-quality review of the whole Phase 2 change set, then use superpowers:finishing-a-development-branch.

---

## Spec coverage check

| Spec requirement | Task |
|------------------|------|
| §2 `config_lines` kconfig grammar validator | Task 1 |
| §1 `config_lines` last-wins merge by symbol | Task 1, Task 5 |
| `BuildOverrides.config_lines` (§1) | Task 2 |
| Remove fragment-rejection guard (§7) | Task 3 |
| Runner cwd for `merge_config.sh` temp file (prereq) | Task 3 |
| `merge_config.sh -m -O` + `olddefconfig` between `prepare_config` and main make (§7) | Task 4 |
| No-base-`.config` / merge-failure → `configuration_error` (Error handling, §7) | Task 4 |
| Freeze resolved `config_lines` into manifest (§3) | Task 5 |
| `config_lines` on `kernel.create_run` tool (§8) | Task 6 |
| Correct user-doc claim (§7 prereq) | Task 7 |
| Build-provider merge test: argv + `override.config` (Testing) | Task 4, Task 8 |
| `config_lines` grammar-violation tests (Testing) | Task 1, Task 2 |
| Redaction of secret-shaped `config_lines` in manifest view (§6, Testing) | Task 8 |
| End-to-end override flow (Testing) | Task 8 |
