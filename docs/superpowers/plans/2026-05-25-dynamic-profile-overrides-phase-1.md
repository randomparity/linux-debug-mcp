# Dynamic Profile Overrides — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an agent pass inline `kernel_args`, `rootfs_source`, and `make_variables` overrides on a named base profile, freeze the resolved profiles into the run manifest, and re-boot an existing build with new boot-time values as a recorded boot attempt.

**Architecture:** Overrides are validated free-form and merged onto a required named base profile at `create_run`. The resolved build profile and the first boot attempt (resolved target + rootfs) are frozen into the manifest (`schema_version` 1→2, additive). Build/boot/run_tests read the resolved profiles from the manifest instead of the module-global `DEFAULT_*` dicts. A second `target.boot` with new boot overrides appends a `BootAttempt` and re-points `step_results["boot"]` in one atomic locked write.

**Tech Stack:** Python 3.11+, pydantic v2 (`extra="forbid"`, `validate_assignment=True`), pytest, FastMCP. Tests inject fakes/monkeypatch — no real builds, VMs, or SSH. Run tests with `uv run python -m pytest`.

**Scope:** Phase 1 only. `config_lines` kernel-config fragment merge is **Phase 2** and is out of scope here — do not remove the `config_fragments` rejection guard in `local_kernel_build.py:88`.

**Source of truth:** `docs/superpowers/specs/2026-05-25-dynamic-profile-overrides-design.md`.

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `src/linux_debug_mcp/config.py` | profile models + new override models + validators + merge helpers | modify |
| `src/linux_debug_mcp/safety/paths.py` | `validate_rootfs_source` | modify |
| `src/linux_debug_mcp/domain.py` | `RunRequest` gains override fields | modify |
| `src/linux_debug_mcp/artifacts/manifest.py` | `BootAttempt`, manifest fields, `with_boot_attempt`, schema bump | modify |
| `src/linux_debug_mcp/artifacts/store.py` | `record_boot_attempt` atomic writer; thread resolved profiles through `create_run` | modify |
| `src/linux_debug_mcp/server.py` | resolve+merge+freeze at `create_run`; read resolved profiles in build/boot/run_tests; boot-attempt trigger; redact boot returns; tool surface | modify |
| `src/linux_debug_mcp/providers/libvirt_qemu.py` | `plan_boot` `attempt` param + per-attempt artifact paths | modify |
| `tests/test_config_overrides.py` | override models, validators, merge | create |
| `tests/test_paths.py` | `validate_rootfs_source` | modify |
| `tests/test_manifest.py` | `BootAttempt`, `with_boot_attempt`, v1 load | create |
| `tests/test_store.py` | `record_boot_attempt`, `create_run` freezing | create |
| `tests/test_domain.py` | `RunRequest` override fields | modify |
| `tests/test_server.py` | `create_run` freezing + build reads resolved profile | modify |
| `tests/test_target_boot_handler.py` | boot-attempt trigger + redaction | modify |
| `tests/test_target_run_tests_handler.py` | run_tests binds to boot attempt | modify |
| `tests/test_libvirt_qemu_provider.py` | per-attempt boot paths | modify |

---

## Task 1: Override models, kernel-arg validator, and merge helpers (`config.py`)

**Files:**
- Modify: `src/linux_debug_mcp/config.py`
- Test: `tests/test_config_overrides.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_config_overrides.py`:

```python
import pytest

from linux_debug_mcp.config import (
    BootOverrides,
    BuildOverrides,
    TargetProfile,
    merge_kernel_args,
)


def test_kernel_args_accepts_safe_tokens():
    overrides = BootOverrides(kernel_args=["dhash_entries=1", "nokaslr", "console=ttyS0,115200"])
    assert overrides.kernel_args == ["dhash_entries=1", "nokaslr", "console=ttyS0,115200"]


@pytest.mark.parametrize(
    "token",
    ["foo; rm -rf /", "a b", "x=$(id)", 'quote="bad"', "tab\tval", "pipe|x"],
)
def test_kernel_args_rejects_unsafe_tokens(token):
    with pytest.raises(ValueError):
        BootOverrides(kernel_args=[token])


def test_target_profile_kernel_args_validated():
    with pytest.raises(ValueError):
        TargetProfile(name="t", architecture="x86_64", kernel_args=["bad;arg"])


def test_build_overrides_make_variables_reuse_existing_rules():
    BuildOverrides(make_variables={"CC": "clang"})
    with pytest.raises(ValueError):
        BuildOverrides(make_variables={"O": "x"})  # reserved, provider-owned


def test_merge_kernel_args_dedups_by_key():
    base = ["console=ttyS0", "nokaslr", "dhash_entries=2"]
    override = ["dhash_entries=1", "quiet"]
    assert merge_kernel_args(base, override) == ["console=ttyS0", "nokaslr", "dhash_entries=1", "quiet"]


def test_merge_kernel_args_dedups_bare_flag():
    assert merge_kernel_args(["nokaslr", "ro"], ["nokaslr"]) == ["ro", "nokaslr"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_config_overrides.py -q`
Expected: FAIL with `ImportError: cannot import name 'BootOverrides'`.

- [ ] **Step 3: Implement the validator, merge helper, and models**

In `src/linux_debug_mcp/config.py`, add module-level helpers next to `_SAFE_LABEL_PATTERN` (after line 12). The `validate_make_variable_map` function is extracted so both `BuildProfile` and `BuildOverrides` share one implementation (DRY):

```python
_KERNEL_ARG_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:=,/-]*$")


def validate_kernel_arg_tokens(value: list[str]) -> list[str]:
    for token in value:
        if not _KERNEL_ARG_PATTERN.match(token):
            raise ValueError(f"unsafe kernel argument token: {token!r}")
    return value


def merge_kernel_args(base: list[str], override: list[str]) -> list[str]:
    def key_of(token: str) -> str:
        return token.split("=", 1)[0] if "=" in token else token

    override_keys = {key_of(token) for token in override}
    merged = [token for token in base if key_of(token) not in override_keys]
    merged.extend(override)
    return merged


def validate_make_variable_map(value: dict[str, str]) -> dict[str, str]:
    reserved = {"O", "ARCH", "KBUILD_OUTPUT"}
    name_pattern = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    for key, item in value.items():
        if key in reserved:
            raise ValueError(f"make variable {key} is provider-owned")
        if not name_pattern.match(key):
            raise ValueError(f"make variable {key} is not a simple make variable name")
        if any(unicodedata.category(char) == "Cc" for char in item):
            raise ValueError(f"make variable {key} contains a control character")
    return value
```

Refactor `BuildProfile.validate_make_variables` (lines 70-82) to delegate to the shared helper:

```python
    @field_validator("make_variables")
    @classmethod
    def validate_make_variables(cls, value: dict[str, str]) -> dict[str, str]:
        return validate_make_variable_map(value)
```

Add a `kernel_args` validator to `TargetProfile` (inside the class, after the existing fields, around line 182):

```python
    @field_validator("kernel_args")
    @classmethod
    def validate_kernel_args(cls, value: list[str]) -> list[str]:
        return validate_kernel_arg_tokens(value)
```

Add the two override models after `TargetProfile` (after line 182):

```python
class BuildOverrides(ConfigModel):
    make_variables: dict[str, str] = Field(default_factory=dict)

    @field_validator("make_variables")
    @classmethod
    def validate_make_variables(cls, value: dict[str, str]) -> dict[str, str]:
        return validate_make_variable_map(value)


class BootOverrides(ConfigModel):
    kernel_args: list[str] = Field(default_factory=list)
    rootfs_source: str | None = None

    @field_validator("kernel_args")
    @classmethod
    def validate_kernel_args(cls, value: list[str]) -> list[str]:
        return validate_kernel_arg_tokens(value)

    @field_validator("rootfs_source")
    @classmethod
    def validate_rootfs_source(cls, value: str | None) -> str | None:
        if value is not None and (not value or _has_control_character(value)):
            raise ValueError("rootfs_source must be non-empty and free of control characters")
        return value
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_config_overrides.py -q`
Expected: PASS (6 tests).

- [ ] **Step 5: Run the existing config tests for regressions**

Run: `uv run python -m pytest tests/test_config.py -q`
Expected: PASS (the new `TargetProfile.kernel_args` validator must not break existing default profiles — `DEFAULT_TARGET_PROFILES` use no kernel_args, so they pass).

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/config.py tests/test_config_overrides.py
git commit -m "feat: add override models, kernel-arg validator, and merge helper"
```

---

## Task 2: `validate_rootfs_source` path-safety (`safety/paths.py`)

**Files:**
- Modify: `src/linux_debug_mcp/safety/paths.py`
- Test: `tests/test_paths.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_paths.py`:

```python
from pathlib import Path

import pytest

from linux_debug_mcp.safety.paths import PathSafetyError, validate_rootfs_source


def test_validate_rootfs_source_accepts_regular_file(tmp_path):
    image = tmp_path / "rootfs.qcow2"
    image.write_bytes(b"x")
    resolved = validate_rootfs_source(image, source_paths=[], sensitive_paths=[])
    assert resolved == image.resolve()


def test_validate_rootfs_source_rejects_missing(tmp_path):
    with pytest.raises(PathSafetyError):
        validate_rootfs_source(tmp_path / "missing.qcow2", source_paths=[], sensitive_paths=[])


def test_validate_rootfs_source_rejects_directory(tmp_path):
    with pytest.raises(PathSafetyError):
        validate_rootfs_source(tmp_path, source_paths=[], sensitive_paths=[])


def test_validate_rootfs_source_rejects_source_overlap(tmp_path):
    src = tmp_path / "linux"
    src.mkdir()
    image = src / "rootfs.qcow2"
    image.write_bytes(b"x")
    with pytest.raises(PathSafetyError):
        validate_rootfs_source(image, source_paths=[src], sensitive_paths=[])


def test_validate_rootfs_source_rejects_shell_metacharacters(tmp_path):
    image = tmp_path / "rootfs.qcow2"
    image.write_bytes(b"x")
    with pytest.raises(PathSafetyError):
        validate_rootfs_source(Path(f"{image};rm"), source_paths=[], sensitive_paths=[])
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_paths.py -q -k rootfs_source`
Expected: FAIL with `ImportError: cannot import name 'validate_rootfs_source'`.

- [ ] **Step 3: Implement `validate_rootfs_source`**

Add to `src/linux_debug_mcp/safety/paths.py` after `validate_source_path` (after line 83):

```python
def validate_rootfs_source(
    rootfs_source: Path,
    *,
    source_paths: list[Path],
    sensitive_paths: list[Path],
) -> Path:
    if any(char in _SHELL_METACHARS for char in str(rootfs_source)) or any(
        ord(char) < 32 for char in str(rootfs_source)
    ):
        raise PathSafetyError("rootfs source contains unsafe characters")
    resolved = rootfs_source.expanduser().resolve()
    home = Path.home().resolve()
    if resolved in {Path("/"), home}:
        raise PathSafetyError("rootfs source is too broad")
    if not resolved.is_file():
        raise PathSafetyError("rootfs source is not a file")
    for source in source_paths:
        if _paths_overlap(resolved, _resolve_existing_or_parent(source)):
            raise PathSafetyError("rootfs source overlaps source path")
    for sensitive in sensitive_paths:
        if _paths_overlap(resolved, _resolve_existing_or_parent(sensitive)):
            raise PathSafetyError("rootfs source overlaps sensitive path")
    return resolved
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_paths.py -q`
Expected: PASS (all paths tests, including the 5 new ones).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/safety/paths.py tests/test_paths.py
git commit -m "feat: add validate_rootfs_source path-safety check"
```

---

## Task 3: `RunRequest` override fields (`domain.py`)

**Files:**
- Modify: `src/linux_debug_mcp/domain.py:79-86`
- Test: `tests/test_domain.py`

> **Type note:** `domain.py` must import `BootOverrides`/`BuildOverrides` from `config.py`. This is acyclic: `config.py` imports only `safety.secrets`, which has no internal imports.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_domain.py`:

```python
from linux_debug_mcp.config import BootOverrides, BuildOverrides
from linux_debug_mcp.domain import RunRequest


def test_run_request_overrides_default_none():
    request = RunRequest(
        source_path="/src",
        build_profile="b",
        target_profile="t",
        rootfs_profile="r",
    )
    assert request.build_overrides is None
    assert request.boot_overrides is None


def test_run_request_accepts_overrides_round_trip():
    request = RunRequest(
        source_path="/src",
        build_profile="b",
        target_profile="t",
        rootfs_profile="r",
        build_overrides=BuildOverrides(make_variables={"CC": "clang"}),
        boot_overrides=BootOverrides(kernel_args=["dhash_entries=1"]),
    )
    reparsed = RunRequest.model_validate_json(request.model_dump_json())
    assert reparsed.boot_overrides.kernel_args == ["dhash_entries=1"]
    assert reparsed.build_overrides.make_variables == {"CC": "clang"}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run python -m pytest tests/test_domain.py -q -k overrides`
Expected: FAIL — `RunRequest` rejects unknown fields (`extra="forbid"`).

- [ ] **Step 3: Add the fields to `RunRequest`**

In `src/linux_debug_mcp/domain.py`, add the import after line 6:

```python
from linux_debug_mcp.config import BootOverrides, BuildOverrides
```

Extend `RunRequest` (lines 79-86) with two optional fields:

```python
class RunRequest(Model):
    source_path: str
    build_profile: str
    target_profile: str
    rootfs_profile: str
    debug_profile: str | None = None
    test_suite: str | None = None
    run_id: str | None = None
    build_overrides: BuildOverrides | None = None
    boot_overrides: BootOverrides | None = None
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run python -m pytest tests/test_domain.py -q`
Expected: PASS.

- [ ] **Step 5: Check for import cycles**

Run: `uv run python -c "import linux_debug_mcp.domain, linux_debug_mcp.config, linux_debug_mcp.artifacts.manifest"`
Expected: no output, exit 0 (no `ImportError`/circular import).

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/domain.py tests/test_domain.py
git commit -m "feat: add override fields to RunRequest"
```

---

## Task 4: `BootAttempt`, manifest fields, `with_boot_attempt`, schema bump (`manifest.py`)

**Files:**
- Modify: `src/linux_debug_mcp/artifacts/manifest.py`
- Test: `tests/test_manifest.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_manifest.py`:

```python
from linux_debug_mcp.artifacts.manifest import BootAttempt, RunManifest
from linux_debug_mcp.config import RootfsProfile, TargetProfile
from linux_debug_mcp.domain import RunRequest, StepResult, StepStatus


def _request():
    return RunRequest(source_path="/src", build_profile="b", target_profile="t", rootfs_profile="r")


def _attempt(n):
    return BootAttempt(
        attempt=n,
        resolved_target_profile=TargetProfile(name="t", architecture="x86_64"),
        resolved_rootfs_profile=RootfsProfile(name="r", source="/img.qcow2"),
        status=StepStatus.SUCCEEDED,
    )


def test_schema_version_is_2():
    manifest = RunManifest.create(run_id="run-1", request=_request())
    assert manifest.schema_version == 2
    assert manifest.boot_attempts == []
    assert manifest.resolved_build_profile is None


def test_with_boot_attempt_appends_without_mutating():
    manifest = RunManifest.create(run_id="run-1", request=_request())
    updated = manifest.with_boot_attempt(_attempt(1))
    assert manifest.boot_attempts == []  # original unchanged
    assert [a.attempt for a in updated.boot_attempts] == [1]
    updated2 = updated.with_boot_attempt(_attempt(2))
    assert [a.attempt for a in updated2.boot_attempts] == [1, 2]


def test_schema_version_1_manifest_still_loads():
    payload = (
        '{"schema_version": 1, "writer_version": "0.0.0", "run_id": "old-1",'
        ' "created_at": "2026-01-01T00:00:00Z",'
        ' "request": {"source_path": "/src", "build_profile": "b",'
        ' "target_profile": "t", "rootfs_profile": "r"},'
        ' "steps": [], "step_results": {}, "cleanup_state": "not_started"}'
    )
    manifest = RunManifest.model_validate_json(payload)
    assert manifest.schema_version == 1
    assert manifest.boot_attempts == []
    assert manifest.resolved_build_profile is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_manifest.py -q`
Expected: FAIL with `ImportError: cannot import name 'BootAttempt'`.

- [ ] **Step 3: Implement the model changes**

Rewrite `src/linux_debug_mcp/artifacts/manifest.py`:

```python
from __future__ import annotations

from datetime import UTC, datetime

from pydantic import Field

from linux_debug_mcp import __version__
from linux_debug_mcp.config import BuildProfile, RootfsProfile, TargetProfile
from linux_debug_mcp.domain import Model, RunRequest, RunStep, StepResult, StepStatus


class BootAttempt(Model):
    attempt: int
    resolved_target_profile: TargetProfile
    resolved_rootfs_profile: RootfsProfile
    status: StepStatus
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RunManifest(Model):
    schema_version: int = 2
    writer_version: str = __version__
    run_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    request: RunRequest
    steps: list[RunStep] = Field(default_factory=list)
    step_results: dict[str, StepResult] = Field(default_factory=dict)
    cleanup_state: str = "not_started"
    resolved_build_profile: BuildProfile | None = None
    boot_attempts: list[BootAttempt] = Field(default_factory=list)

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        request: RunRequest,
        resolved_build_profile: BuildProfile | None = None,
        boot_attempts: list[BootAttempt] | None = None,
    ) -> RunManifest:
        return cls(
            run_id=run_id,
            request=request,
            resolved_build_profile=resolved_build_profile,
            boot_attempts=boot_attempts or [],
            steps=[
                RunStep(name="create_run", status=StepStatus.SUCCEEDED, provider="local-artifacts"),
                RunStep(name="build", status=StepStatus.PENDING),
                RunStep(name="boot", status=StepStatus.PENDING),
                RunStep(name="run_tests", status=StepStatus.PENDING),
                RunStep(name="collect_artifacts", status=StepStatus.PENDING),
                RunStep(name="debug", status=StepStatus.PENDING),
            ],
        )

    def with_step_result(self, result: StepResult, *, replace_succeeded: bool = False) -> RunManifest:
        if result.step_name in self.step_results:
            existing = self.step_results[result.step_name]
            if existing.status == StepStatus.SUCCEEDED and not replace_succeeded:
                return self
        clone = self.model_copy(deep=True)
        clone.step_results[result.step_name] = result
        for step in clone.steps:
            if step.name == result.step_name:
                step.status = result.status
        return clone

    def with_boot_attempt(self, attempt: BootAttempt) -> RunManifest:
        clone = self.model_copy(deep=True)
        clone.boot_attempts.append(attempt)
        return clone
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_manifest.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/artifacts/manifest.py tests/test_manifest.py
git commit -m "feat: add BootAttempt, resolved profiles, and with_boot_attempt to manifest"
```

---

## Task 5: `record_boot_attempt` atomic writer + thread resolved profiles through `create_run` (`store.py`)

**Files:**
- Modify: `src/linux_debug_mcp/artifacts/store.py:51-92`
- Test: `tests/test_store.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_store.py`:

```python
from pathlib import Path

from linux_debug_mcp.artifacts.manifest import BootAttempt
from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import BuildProfile, RootfsProfile, TargetProfile
from linux_debug_mcp.domain import RunRequest, StepResult, StepStatus


def _store(tmp_path) -> ArtifactStore:
    return ArtifactStore(tmp_path / "runs")


def _request():
    return RunRequest(source_path="/src", build_profile="b", target_profile="t", rootfs_profile="r")


def test_create_run_freezes_resolved_build_profile(tmp_path):
    store = _store(tmp_path)
    resolved = BuildProfile(name="b", architecture="x86_64", make_variables={"CC": "clang"})
    manifest = store.create_run(_request(), resolved_build_profile=resolved)
    reloaded = store.load_manifest(manifest.run_id)
    assert reloaded.resolved_build_profile.make_variables == {"CC": "clang"}


def test_record_boot_attempt_appends_and_repoints_boot(tmp_path):
    store = _store(tmp_path)
    manifest = store.create_run(_request())
    attempt = BootAttempt(
        attempt=1,
        resolved_target_profile=TargetProfile(name="t", architecture="x86_64"),
        resolved_rootfs_profile=RootfsProfile(name="r", source="/img.qcow2"),
        status=StepStatus.SUCCEEDED,
    )
    boot_result = StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="booted")
    store.record_boot_attempt(manifest.run_id, attempt=attempt, boot_result=boot_result)

    reloaded = store.load_manifest(manifest.run_id)
    assert [a.attempt for a in reloaded.boot_attempts] == [1]
    assert reloaded.step_results["boot"].status == StepStatus.SUCCEEDED


def test_record_boot_attempt_replaces_succeeded_boot(tmp_path):
    store = _store(tmp_path)
    manifest = store.create_run(_request())
    first = StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="boot-1")
    store.record_step_result(manifest.run_id, first)
    attempt2 = BootAttempt(
        attempt=2,
        resolved_target_profile=TargetProfile(name="t", architecture="x86_64"),
        resolved_rootfs_profile=RootfsProfile(name="r", source="/img.qcow2"),
        status=StepStatus.SUCCEEDED,
    )
    second = StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="boot-2")
    store.record_boot_attempt(manifest.run_id, attempt=attempt2, boot_result=second)
    reloaded = store.load_manifest(manifest.run_id)
    assert reloaded.step_results["boot"].summary == "boot-2"
    assert [a.attempt for a in reloaded.boot_attempts] == [2]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_store.py -q`
Expected: FAIL — `create_run()` got an unexpected keyword `resolved_build_profile`.

- [ ] **Step 3: Thread resolved profiles through `create_run` and add `record_boot_attempt`**

In `src/linux_debug_mcp/artifacts/store.py`, update the import (line 15) to include `BootAttempt`:

```python
from linux_debug_mcp.artifacts.manifest import BootAttempt, RunManifest
```

Replace `create_run` (lines 51-74) signature and the `RunManifest.create` call:

```python
    def create_run(
        self,
        request: RunRequest,
        *,
        resolved_build_profile: object | None = None,
        boot_attempts: list[BootAttempt] | None = None,
    ) -> RunManifest:
        run_id = self._validate_run_id(request.run_id or self._generate_run_id())
        run_dir = self._run_dir(run_id)
        if run_dir.exists():
            raise ManifestStateError(f"run already exists: {run_id}", ErrorCategory.CONFIGURATION_ERROR)

        created_run_dir = False
        try:
            run_dir.mkdir(parents=False)
            created_run_dir = True
            for subdir in self.SUBDIRS:
                (run_dir / subdir).mkdir()

            manifest = RunManifest.create(
                run_id=run_id,
                request=request.model_copy(update={"run_id": run_id}),
                resolved_build_profile=resolved_build_profile,
                boot_attempts=boot_attempts,
            )
            self._write_manifest(run_dir, manifest)
        except FileExistsError as exc:
            if created_run_dir:
                shutil.rmtree(run_dir, ignore_errors=True)
            raise ManifestStateError(f"run already exists: {run_id}", ErrorCategory.CONFIGURATION_ERROR) from exc
        except OSError as exc:
            if created_run_dir:
                shutil.rmtree(run_dir, ignore_errors=True)
            raise ManifestStateError(f"failed to create run {run_id}: {exc}") from exc
        return manifest
```

> Note: `resolved_build_profile: object | None` keeps `store.py` from importing `BuildProfile` directly; the value is passed straight through to `RunManifest.create`, which is typed for `BuildProfile`.

Add `record_boot_attempt` after `record_step_result` (after line 92):

```python
    def record_boot_attempt(
        self,
        run_id: str,
        *,
        attempt: BootAttempt,
        boot_result: StepResult,
    ) -> RunManifest:
        run_id = self._validate_run_id(run_id)
        run_dir = self._run_dir(run_id)
        with self._manifest_lock(run_dir):
            manifest = self.load_manifest(run_id)
            updated = manifest.with_boot_attempt(attempt)
            updated = updated.with_step_result(boot_result, replace_succeeded=True)
            self._write_manifest(run_dir, updated)
            return updated
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_store.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Run existing store-dependent tests for regressions**

Run: `uv run python -m pytest tests/test_server.py -q`
Expected: PASS (existing `create_run` callers pass no new kwargs, so behavior is unchanged).

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/artifacts/store.py tests/test_store.py
git commit -m "feat: add record_boot_attempt and resolved-profile freezing to ArtifactStore"
```

---

## Task 6: Resolve, merge, validate, and freeze at `create_run` (`server.py`)

**Files:**
- Modify: `src/linux_debug_mcp/server.py` — `create_run_handler` (lines 372-416)
- Test: `tests/test_server.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_server.py` (reuse existing fixtures/helpers in that file for a valid `source_path`; the snippet below uses `monkeypatch` to bypass `validate_source_path`):

```python
from linux_debug_mcp import server
from linux_debug_mcp.config import BootOverrides, BuildOverrides
from linux_debug_mcp.domain import StepStatus


def test_create_run_freezes_merged_profiles(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "validate_source_path", lambda p: p)
    response = server.create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path="/fake/src",
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        build_overrides=BuildOverrides(make_variables={"CC": "clang"}),
        boot_overrides=BootOverrides(kernel_args=["dhash_entries=1"]),
    )
    assert response.ok
    run_id = response.run_id
    store = server.ArtifactStore(tmp_path / "runs", create_root=False)
    manifest = store.load_manifest(run_id)
    assert manifest.resolved_build_profile.make_variables == {"CC": "clang"}
    assert manifest.boot_attempts == []  # attempt 1 not yet booted
    assert manifest.request.boot_overrides.kernel_args == ["dhash_entries=1"]


def test_create_run_rejects_unknown_base_profile(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "validate_source_path", lambda p: p)
    response = server.create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path="/fake/src",
        build_profile="does-not-exist",
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )
    assert not response.ok
    assert response.error.category.value == "configuration_error"
    # fail-fast: no run directory/manifest created on a bad base profile
    assert list((tmp_path / "runs").glob("*/manifest.json")) == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_server.py -q -k create_run_freezes`
Expected: FAIL — `create_run_handler` has no `build_overrides`/`boot_overrides` params.

- [ ] **Step 3: Implement the resolution/merge/freeze in `create_run_handler`**

In `src/linux_debug_mcp/server.py`, add imports near the existing `config` imports:

```python
from linux_debug_mcp.config import BootOverrides, BuildOverrides, merge_kernel_args
from linux_debug_mcp.safety.paths import validate_rootfs_source
```

Add a private resolution helper above `create_run_handler` (before line 372):

```python
def _resolve_initial_profiles(
    *,
    source_path: Path,
    sensitive_paths: list[Path],
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    build_overrides: BuildOverrides | None,
    boot_overrides: BootOverrides | None,
) -> tuple[BuildProfile, TargetProfile, RootfsProfile]:
    base_build = DEFAULT_BUILD_PROFILES[build_profile]
    base_target = DEFAULT_TARGET_PROFILES[target_profile]
    base_rootfs = DEFAULT_ROOTFS_PROFILES[rootfs_profile]

    resolved_build = base_build
    if build_overrides is not None and build_overrides.make_variables:
        resolved_build = base_build.model_copy(
            update={"make_variables": {**base_build.make_variables, **build_overrides.make_variables}}
        )

    resolved_target = base_target
    resolved_rootfs = base_rootfs
    if boot_overrides is not None:
        if boot_overrides.kernel_args:
            resolved_target = base_target.model_copy(
                update={"kernel_args": merge_kernel_args(base_target.kernel_args, boot_overrides.kernel_args)}
            )
        if boot_overrides.rootfs_source is not None:
            validated = validate_rootfs_source(
                Path(boot_overrides.rootfs_source),
                source_paths=[source_path],
                sensitive_paths=sensitive_paths,
            )
            resolved_rootfs = base_rootfs.model_copy(update={"source": str(validated)})
    return resolved_build, resolved_target, resolved_rootfs
```

Replace `create_run_handler` (lines 372-416) with:

```python
def create_run_handler(
    *,
    artifact_root: Path,
    source_path: str,
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    run_id: str | None = None,
    debug_profile: str | None = None,
    test_suite: str | None = None,
    build_overrides: BuildOverrides | None = None,
    boot_overrides: BootOverrides | None = None,
) -> ToolResponse:
    try:
        resolved_source_path = validate_source_path(Path(source_path))
    except PathSafetyError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
            details={"source_path": source_path},
        )
    for name, mapping in (
        (build_profile, DEFAULT_BUILD_PROFILES),
        (target_profile, DEFAULT_TARGET_PROFILES),
        (rootfs_profile, DEFAULT_ROOTFS_PROFILES),
    ):
        if name not in mapping:
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                message=f"unknown profile: {name}",
            )
    try:
        resolved_build, _resolved_target, _resolved_rootfs = _resolve_initial_profiles(
            source_path=resolved_source_path,
            sensitive_paths=[],
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            build_overrides=build_overrides,
            boot_overrides=boot_overrides,
        )
    except (PathSafetyError, ValueError) as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
        )
    request = RunRequest(
        source_path=str(resolved_source_path),
        build_profile=build_profile,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        debug_profile=debug_profile,
        test_suite=test_suite,
        run_id=run_id,
        build_overrides=build_overrides,
        boot_overrides=boot_overrides,
    )
    try:
        store = ArtifactStore(artifact_root, source_paths=[resolved_source_path])
        manifest = store.create_run(request, resolved_build_profile=resolved_build)
    except ManifestStateError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=str(exc),
            details={"artifact_root": str(artifact_root)},
        )
    manifest_path = artifact_root.expanduser().resolve() / manifest.run_id / "manifest.json"
    return ToolResponse.success(
        summary=f"created run {manifest.run_id}",
        run_id=manifest.run_id,
        data={"manifest": manifest.model_dump(mode="json"), "manifest_path": str(manifest_path)},
        artifacts=[ArtifactRef(path=str(manifest_path), kind="manifest")],
        suggested_next_actions=["kernel.build"],
    )
```

> The resolved target/rootfs are computed here to validate `rootfs_source` early (fail-fast), but the **frozen** target/rootfs land in `boot_attempts` at boot time (Task 9), not at create_run. Only `resolved_build_profile` is frozen now, because the build step consumes it next.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_server.py -q -k create_run`
Expected: PASS.

- [ ] **Step 5: Run the full server test module for regressions**

Run: `uv run python -m pytest tests/test_server.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server.py
git commit -m "feat: resolve, validate, and freeze profile overrides at create_run"
```

---

## Task 7: Build reads the resolved profile from the manifest (`server.py`)

**Files:**
- Modify: `src/linux_debug_mcp/server.py` — `_build_profile_from_manifest` (147-151), `kernel_build_handler` (621-676)
- Test: `tests/test_server.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_server.py`:

```python
def test_build_reads_resolved_profile_not_global(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "validate_source_path", lambda p: p)
    created = server.create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path="/fake/src",
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        build_overrides=server_build_overrides_clang(),
    )
    run_id = created.run_id
    store = server.ArtifactStore(tmp_path / "runs", create_root=False)
    manifest = store.load_manifest(run_id)
    resolved = server._build_profile_from_manifest(manifest)
    assert resolved.make_variables == {"CC": "clang"}


def server_build_overrides_clang():
    from linux_debug_mcp.config import BuildOverrides

    return BuildOverrides(make_variables={"CC": "clang"})


def test_build_profile_from_manifest_v1_fallback():
    from linux_debug_mcp.artifacts.manifest import RunManifest
    from linux_debug_mcp.domain import RunRequest

    manifest = RunManifest.create(
        run_id="r",
        request=RunRequest(
            source_path="/s", build_profile="x86_64-default", target_profile="local-qemu", rootfs_profile="minimal"
        ),
    )  # resolved_build_profile is None
    resolved = server._build_profile_from_manifest(manifest)
    assert resolved.name == "x86_64-default"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run python -m pytest tests/test_server.py -q -k "resolved_profile or v1_fallback"`
Expected: FAIL — `_build_profile_from_manifest` currently takes a `profile_name: str`, not a manifest.

- [ ] **Step 3: Change `_build_profile_from_manifest` to read the manifest**

Replace `_build_profile_from_manifest` (lines 147-151):

```python
def _build_profile_from_manifest(manifest: RunManifest) -> BuildProfile:
    if manifest.resolved_build_profile is not None:
        return manifest.resolved_build_profile
    profile_name = manifest.request.build_profile
    try:
        return DEFAULT_BUILD_PROFILES[profile_name]
    except KeyError as exc:
        raise ValueError(f"unknown build profile: {profile_name}") from exc
```

In `kernel_build_handler`, change the call site (line 667) from:

```python
        profile = _build_profile_from_manifest(requested_profile)
```

to:

```python
        profile = _build_profile_from_manifest(manifest)
```

> `requested_profile` (line 647) and the drift-check against `manifest.request.build_profile` (lines 648-654) stay unchanged — they still compare names. Only the profile *body* now comes from the manifest.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_server.py -q -k "resolved_profile or v1_fallback"`
Expected: PASS.

- [ ] **Step 5: Verify the global-mutation isolation**

Run: `uv run python -m pytest tests/test_server.py tests/test_workflow_build_boot_test_handler.py -q`
Expected: PASS (build path still works end-to-end with fakes).

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server.py
git commit -m "feat: build handler reads resolved profile from manifest with v1 fallback"
```

---

## Task 8: `plan_boot` per-attempt artifact directories (`libvirt_qemu.py`)

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py` — `plan_boot` (311-385)
- Test: `tests/test_libvirt_qemu_provider.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_libvirt_qemu_provider.py` (follow the file's existing fixture style for a `LibvirtQemuProvider` with a fake runner; the assertion below only inspects the returned `BootPlan` paths):

```python
def test_plan_boot_places_artifacts_under_attempt_dir(tmp_path, libvirt_provider_with_fake_runner):
    provider, target_profile, rootfs_profile, kernel_image = libvirt_provider_with_fake_runner
    run_dir = tmp_path / "run"
    for sub in ("target", "logs", "summaries", "boot"):
        (run_dir / sub).mkdir(parents=True)
    plan = provider.plan_boot(
        run_id="run-1",
        run_dir=run_dir,
        kernel_image_path=kernel_image,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        attempt=2,
    )
    assert plan.domain_xml_path == run_dir / "boot" / "attempt-2" / "domain.xml"
    assert plan.console_log_path == run_dir / "boot" / "attempt-2" / "console.log"
    assert plan.boot_log_path == run_dir / "boot" / "attempt-2" / "boot.log"
    assert plan.boot_plan_path == run_dir / "boot" / "attempt-2" / "boot-plan.json"
    assert plan.boot_summary_path == run_dir / "boot" / "attempt-2" / "boot-summary.json"
```

> If the existing test file has no reusable fixture, define `libvirt_provider_with_fake_runner` in the test mirroring the construction already used by other tests in that file (a `LibvirtQemuProvider(runner=<fake>)`, a `TargetProfile`, a `RootfsProfile` whose `source` is an existing file under `tmp_path`, and an existing kernel-image file). Reuse the patterns already present rather than inventing new fakes.

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -q -k attempt_dir`
Expected: FAIL — `plan_boot()` has no `attempt` parameter.

- [ ] **Step 3: Add the `attempt` parameter and relocate the paths**

In `src/linux_debug_mcp/providers/libvirt_qemu.py`, change the `plan_boot` signature (lines 311-319) to add `attempt`:

```python
    def plan_boot(
        self,
        *,
        run_id: str,
        run_dir: Path,
        kernel_image_path: Path,
        target_profile: TargetProfile,
        rootfs_profile: RootfsProfile,
        attempt: int = 1,
    ) -> BootPlan:
```

Replace the five fixed path constructions (lines 344-348):

```python
        attempt_dir = resolved_run_dir / "boot" / f"attempt-{attempt}"
        domain_xml_path = attempt_dir / "domain.xml"
        console_log_path = attempt_dir / "console.log"
        boot_log_path = attempt_dir / "boot.log"
        boot_plan_path = attempt_dir / "boot-plan.json"
        boot_summary_path = attempt_dir / "boot-summary.json"
```

> `_ensure_artifact_dirs` (line 639) already does `path.parent.mkdir(parents=True, exist_ok=True)` for each of these five paths, so it creates `boot/attempt-N/` automatically — no change needed there. `_artifact_refs` reads the same plan paths, so it follows the relocation with no change.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -q -k attempt_dir`
Expected: PASS.

- [ ] **Step 5: Run the provider test module for regressions**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -q`
Expected: PASS — existing callers omit `attempt`, defaulting to `1` → `boot/attempt-1/`. Existing tests that asserted the old fixed paths (`target/domain.xml`, `logs/console.log`, …) must be updated to the `boot/attempt-1/` locations; update those assertions as part of this step.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/providers/libvirt_qemu.py tests/test_libvirt_qemu_provider.py
git commit -m "feat: plan_boot writes artifacts under boot/attempt-N"
```

---

## Task 9: Boot handler — resolve from manifest, open new attempts, redact all returns (`server.py`)

**Files:**
- Modify: `src/linux_debug_mcp/server.py` — `target_boot_handler` (748-982), `_recorded_boot_success_response` (174-181)
- Test: `tests/test_target_boot_handler.py`

This is the largest task. It has four sub-changes: (a) resolve target/rootfs from the latest boot attempt (or merge new boot overrides into a new attempt), (b) widen the SUCCEEDED guard with an `opening_new_attempt` flag, (c) persist via `record_boot_attempt`, (d) route every return through `Redactor`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_target_boot_handler.py` (reuse the file's existing fake boot provider + a run created with a succeeded build; follow existing helpers in that module):

```python
def test_second_boot_with_new_kernel_args_opens_attempt_2(boot_ready_run, fake_boot_provider):
    store, run_id = boot_ready_run  # a run with a SUCCEEDED build + SUCCEEDED boot attempt 1
    from linux_debug_mcp.config import BootOverrides

    response = server.target_boot_handler(
        artifact_root=store.artifact_root,
        run_id=run_id,
        provider=fake_boot_provider,
        boot_overrides=BootOverrides(kernel_args=["dhash_entries=1"]),
    )
    assert response.ok
    manifest = store.load_manifest(run_id)
    assert [a.attempt for a in manifest.boot_attempts] == [1, 2]
    assert "dhash_entries=1" in manifest.boot_attempts[-1].resolved_target_profile.kernel_args


def test_boot_success_response_is_redacted(boot_ready_build, fake_boot_provider_echoing_secret):
    # fake provider returns details containing "token=supersecret"
    store, run_id = boot_ready_build
    response = server.target_boot_handler(
        artifact_root=store.artifact_root,
        run_id=run_id,
        provider=fake_boot_provider_echoing_secret,
    )
    assert "supersecret" not in str(response.data)
```

> These tests depend on fixtures that build a run with a succeeded build (and, for the first test, a succeeded boot attempt 1). Construct them with the existing fakes used elsewhere in `tests/test_target_boot_handler.py` / `tests/test_workflow_build_boot_test_handler.py`. The `fake_boot_provider_echoing_secret` is a fake whose `execute_boot` returns a `BootExecutionResult` with `details={"kernel_args": ["x=token=supersecret"]}` (a `token=`-shaped substring the `Redactor` matches).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_target_boot_handler.py -q -k "attempt_2 or redacted"`
Expected: FAIL — `target_boot_handler` has no `boot_overrides` param; responses are unredacted.

- [ ] **Step 3a: Add `boot_overrides` param and attempt resolution**

In `target_boot_handler` (line 748), add the parameter:

```python
    boot_overrides: BootOverrides | None = None,
```

Each boot attempt's resolved profiles are **`base profile + that boot's overrides`** (spec §4). The effective overrides for this boot are the boot-call `boot_overrides` if given, else — only when no attempt has run yet (the first boot) — the create_run intent `manifest.request.boot_overrides`. This is what carries the create_run `dhash_entries=1` into the first boot; without it that value would be silently dropped.

The name-based lookup at lines 790-801 already populated `resolved_target_profile`/`resolved_rootfs_profile` from `DEFAULT_*` (and applied `default_libvirt_uri`). Insert the override-layering block **after** the `target_ref` check (after line 803) and **before** the build-success check (line 805):

```python
    effective_boot_overrides = boot_overrides
    if effective_boot_overrides is None and not manifest.boot_attempts:
        effective_boot_overrides = manifest.request.boot_overrides
    if effective_boot_overrides is not None:
        try:
            if effective_boot_overrides.kernel_args:
                resolved_target_profile = resolved_target_profile.model_copy(
                    update={
                        "kernel_args": merge_kernel_args(
                            resolved_target_profile.kernel_args, effective_boot_overrides.kernel_args
                        )
                    }
                )
            if effective_boot_overrides.rootfs_source is not None:
                validated = validate_rootfs_source(
                    Path(effective_boot_overrides.rootfs_source),
                    source_paths=[Path(manifest.request.source_path)],
                    sensitive_paths=[],
                )
                resolved_rootfs_profile = resolved_rootfs_profile.model_copy(update={"source": str(validated)})
        except (PathSafetyError, ValueError) as exc:
            return _configuration_failure(run_id=run_id, message=str(exc))
```

Then, just before line 822 (`existing = manifest.step_results.get("boot")`), compute the new-attempt trigger and number. `has_new_boot_overrides` is true only for an **explicit boot-call** override (a re-boot), so it widens the SUCCEEDED guard; the first-boot application of `request.boot_overrides` does not (there is no succeeded boot to guard yet):

```python
    has_new_boot_overrides = boot_overrides is not None and (
        bool(boot_overrides.kernel_args) or boot_overrides.rootfs_source is not None
    )
    next_attempt = len(manifest.boot_attempts) + 1
```

- [ ] **Step 3b: Widen the SUCCEEDED guards**

Change the two early-return guards (lines 823 and 925) from `... and not force_reboot:` to also bypass when opening a new attempt:

Line 823:
```python
    if existing and existing.status == StepStatus.SUCCEEDED and not force_reboot and not has_new_boot_overrides:
        return _recorded_boot_success_response(run_id=run_id, result=existing)
```

Line 925 (inside the lock):
```python
            if (
                locked_existing
                and locked_existing.status == StepStatus.SUCCEEDED
                and not force_reboot
                and not has_new_boot_overrides
            ):
                return _recorded_boot_success_response(run_id=run_id, result=locked_existing)
```

Also set `replace_succeeded` true when opening a new attempt — change line 928:
```python
            replace_succeeded = bool(
                locked_existing and locked_existing.status == StepStatus.SUCCEEDED
            ) or has_new_boot_overrides
```

- [ ] **Step 3c: Thread `attempt` into `plan_boot` and record the attempt**

Pass `attempt=next_attempt` to the `plan_boot` call (line 941-947):

```python
                    plan = provider.plan_boot(
                        run_id=run_id,
                        run_dir=store.run_dir(run_id),
                        kernel_image_path=Path(kernel_image.path),
                        target_profile=resolved_target_profile,
                        rootfs_profile=resolved_rootfs_profile,
                        attempt=next_attempt,
                    )
```

In `execute_boot`, after the terminal result is built and before recording (replace lines 902-903), record via `record_boot_attempt` so the attempt and `step_results["boot"]` move together:

```python
        attempt_record = BootAttempt(
            attempt=next_attempt,
            resolved_target_profile=resolved_target_profile,
            resolved_rootfs_profile=resolved_rootfs_profile,
            status=execution.status,
        )
        store.record_boot_attempt(run_id, attempt=attempt_record, boot_result=terminal)
```

> Add `from linux_debug_mcp.artifacts.manifest import BootAttempt` to the server imports. The earlier `store.record_step_result(run_id, terminal, ...)` line at 903 is replaced by this block. The RUNNING and FAILED `record_step_result` calls (lines 850, 865, 887, 956) stay — only the terminal success/failure recording becomes `record_boot_attempt`. For the FAILED terminal at the bottom of `execute_boot`, also append an attempt (status FAILED) so a failed boot is still recorded as an attempt: wrap the terminal recording to call `record_boot_attempt` for both SUCCEEDED and FAILED terminal statuses (it always replaces and appends).

- [ ] **Step 3d: Redact every boot return point**

Add a redaction helper near the other boot response helpers (after line 181):

```python
def _redacted_boot_data(data: dict[str, Any]) -> dict[str, Any]:
    return Redactor().redact_value(data)
```

Apply `_redacted_boot_data(...)` to the `data=`/`details=` argument of every `ToolResponse.success`/`ToolResponse.failure` in `target_boot_handler` and to `_recorded_boot_success_response`. Specifically:
- `_recorded_boot_success_response` (174-181): wrap `data=result.details` → `data=_redacted_boot_data(result.details)`.
- fresh success (905-911): `data=_redacted_boot_data(terminal.details)`.
- failure returns (866-872, 888-895, 912-919, 957-964): `details=_redacted_boot_data(<details>)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_target_boot_handler.py -q -k "attempt_2 or redacted"`
Expected: PASS.

- [ ] **Step 5: Run the full boot + workflow test modules for regressions**

Run: `uv run python -m pytest tests/test_target_boot_handler.py tests/test_workflow_build_boot_test_handler.py tests/test_workflow_build_boot_debug_handler.py -q`
Expected: PASS. Existing tests that asserted boot artifact paths or the first-boot success now see `boot/attempt-1/` paths and a populated `boot_attempts` list — update those assertions where needed.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_target_boot_handler.py
git commit -m "feat: boot handler opens recorded attempts for new boot overrides and redacts responses"
```

---

## Task 10: `run_tests` binds to the boot attempt (`server.py`)

**Files:**
- Modify: `src/linux_debug_mcp/server.py` — `target_run_tests_handler` (985-1036)
- Test: `tests/test_target_run_tests_handler.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_target_run_tests_handler.py` (reuse existing fakes; build a run whose latest boot attempt swapped `rootfs_source`):

```python
def test_run_tests_uses_latest_boot_attempt_rootfs(tests_ready_run_with_attempt, capture_test_provider):
    store, run_id, swapped_source = tests_ready_run_with_attempt
    response = server.target_run_tests_handler(
        artifact_root=store.artifact_root,
        run_id=run_id,
        provider=capture_test_provider,
    )
    assert response.ok
    # capture_test_provider records the rootfs_profile it was planned with
    assert capture_test_provider.planned_rootfs.source == swapped_source
```

> `tests_ready_run_with_attempt` builds a manifest with a SUCCEEDED build, a SUCCEEDED boot whose `boot_attempts[-1].resolved_rootfs_profile.source` is an alternate image path, and `step_results["boot"]` SUCCEEDED. `capture_test_provider` is a fake whose `plan_tests` stores the `rootfs_profile` argument on `self.planned_rootfs`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run python -m pytest tests/test_target_run_tests_handler.py -q -k latest_boot_attempt`
Expected: FAIL — handler resolves rootfs from `DEFAULT_ROOTFS_PROFILES`, ignoring the attempt's swapped source.

- [ ] **Step 3: Resolve rootfs from the latest boot attempt**

In `target_run_tests_handler`, replace the rootfs resolution block (lines 1024-1032) with a preference for the latest boot attempt's frozen rootfs profile, falling back to the name-based lookup:

```python
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    test_suites = test_suites if test_suites is not None else DEFAULT_TEST_SUITES
    if manifest.boot_attempts:
        resolved_rootfs_profile = manifest.boot_attempts[-1].resolved_rootfs_profile
    else:
        try:
            resolved_rootfs_profile = rootfs_profiles[manifest.request.rootfs_profile]
        except KeyError:
            return _configuration_failure(
                run_id=run_id,
                message=f"unknown rootfs profile: {manifest.request.rootfs_profile}",
            )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run python -m pytest tests/test_target_run_tests_handler.py -q -k latest_boot_attempt`
Expected: PASS.

- [ ] **Step 5: Run the run_tests module for regressions**

Run: `uv run python -m pytest tests/test_target_run_tests_handler.py -q`
Expected: PASS — runs without boot attempts (legacy) still fall back to the name lookup.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_target_run_tests_handler.py
git commit -m "feat: run_tests binds to the latest boot attempt's rootfs profile"
```

---

## Task 11: Tool surface — expose overrides on `kernel.create_run` and `target.boot` (`server.py`)

**Files:**
- Modify: `src/linux_debug_mcp/server.py` — `create_app` tool wrappers (`kernel.create_run` 2228-2248; `target.boot`)
- Test: `tests/test_server.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_server.py`:

```python
def test_create_app_create_run_accepts_override_args(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "validate_source_path", lambda p: p)
    app = server.create_app()
    tool = app._tool_manager.get_tool("kernel.create_run")  # FastMCP tool registry
    result = tool.fn(
        source_path="/fake/src",
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        artifact_root=str(tmp_path / "runs"),
        kernel_args=["dhash_entries=1"],
        make_variables={"CC": "clang"},
    )
    assert result["ok"] is True
```

> If `app._tool_manager.get_tool(...)` differs in this FastMCP version, call the underlying handler directly instead: assert that `create_run_handler` accepts the same kwargs the wrapper forwards. The behavioral guarantee is that the tool wrapper builds `BootOverrides`/`BuildOverrides` from the flat args and forwards them.

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run python -m pytest tests/test_server.py -q -k override_args`
Expected: FAIL — the tool wrapper has no `kernel_args`/`make_variables` parameters.

- [ ] **Step 3: Extend the tool wrappers**

In `create_app`, replace the `kernel.create_run` wrapper (lines 2228-2248) to accept flat override args and build the override models:

```python
    @app.tool(name="kernel.create_run")
    def kernel_create_run(
        source_path: str,
        build_profile: str,
        target_profile: str,
        rootfs_profile: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        run_id: str | None = None,
        debug_profile: str | None = None,
        test_suite: str | None = None,
        kernel_args: list[str] | None = None,
        rootfs_source: str | None = None,
        make_variables: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        build_overrides = (
            BuildOverrides(make_variables=make_variables) if make_variables else None
        )
        boot_overrides = (
            BootOverrides(kernel_args=kernel_args or [], rootfs_source=rootfs_source)
            if (kernel_args or rootfs_source)
            else None
        )
        return create_run_handler(
            artifact_root=Path(artifact_root),
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            debug_profile=debug_profile,
            test_suite=test_suite,
            build_overrides=build_overrides,
            boot_overrides=boot_overrides,
        ).model_dump(mode="json")
```

Find the `target.boot` tool wrapper in `create_app` and add `kernel_args: list[str] | None = None` and `rootfs_source: str | None = None`, building a `BootOverrides` the same way and forwarding it as `boot_overrides=` to `target_boot_handler`.

> Construction-time validation: if an agent passes an unsafe `kernel_args` token, `BootOverrides(...)` raises `ValueError` inside the wrapper. Wrap the override construction in a `try/except ValueError` that returns `ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, message=str(exc)).model_dump(mode="json")` so a bad value is a clean configuration error, not an unhandled exception.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run python -m pytest tests/test_server.py -q -k override_args`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server.py
git commit -m "feat: expose override args on kernel.create_run and target.boot tools"
```

---

## Task 12: Full-flow integration test + final verification

**Files:**
- Test: `tests/test_workflow_build_boot_test_handler.py` (add an override-flow case)

- [ ] **Step 1: Write the integration test**

Add a test that drives `create_run → build → boot → run_tests` with fake providers, passing `kernel_args=["dhash_entries=1"]` and a swapped `rootfs_source`, asserting: the build uses the resolved profile; boot attempt 1 carries the merged `kernel_args`; a second boot with `kernel_args=["dhash_entries=2"]` produces `boot_attempts == [1, 2]` and reuses the build artifact (build step not re-run); `run_tests` binds to attempt 2's rootfs. Mirror the existing fake-provider wiring in that file.

```python
def test_override_flow_end_to_end(tmp_path, monkeypatch, fake_build_provider, fake_boot_provider, fake_test_provider):
    monkeypatch.setattr(server, "validate_source_path", lambda p: p)
    # ... create_run with overrides, build, boot, assert boot_attempts[1].kernel_args,
    #     second boot with new args -> boot_attempts == [1, 2], run_tests binds attempt 2.
    # Use the same fake providers and run-construction helpers already present in this module.
```

> Fill the body using the module's existing fakes — do not introduce real subprocess/libvirt calls. The assertions are the behavioral contract above.

- [ ] **Step 2: Run the integration test**

Run: `uv run python -m pytest tests/test_workflow_build_boot_test_handler.py -q -k override_flow`
Expected: PASS.

- [ ] **Step 3: Run the full suite**

Run: `uv run python -m pytest -q`
Expected: PASS (all previously-passing tests plus the new ones; 2 live-integration tests remain SKIPPED).

- [ ] **Step 4: Lint + format**

Run: `just lint`
Expected: clean (ruff `E,F,I,UP,B,SIM`, line length 120). Fix any findings.

- [ ] **Step 5: Confirm Phase-2 boundary is intact**

Run: `uv run python -m pytest -q -k config_fragment` and grep:
```bash
rg -n "config fragments are not supported" src/linux_debug_mcp/providers/local_kernel_build.py
```
Expected: the Phase-2 rejection guard at `local_kernel_build.py:88` is **still present** (Phase 1 does not touch `config_lines`).

- [ ] **Step 6: Commit**

```bash
git add tests/test_workflow_build_boot_test_handler.py
git commit -m "test: end-to-end override flow with boot-time iteration"
```

---

## Phase 1 Done — Review Checklist

Before declaring Phase 1 complete:

- [ ] `uv run python -m pytest -q` — green (2 expected skips).
- [ ] `just lint` — clean.
- [ ] Overrides flow create_run → manifest → build/boot/run_tests without reading module globals (the global-mutation isolation test passes).
- [ ] A second boot with new `kernel_args` appends `boot_attempts[2]`, reuses the build, re-points `step_results["boot"]`, and `run_tests` binds to it.
- [ ] Every boot handler return routes through `Redactor`.
- [ ] `config_lines` / `merge_config.sh` are untouched (Phase 2 boundary intact).
- [ ] Pause for review (per the execution request).
