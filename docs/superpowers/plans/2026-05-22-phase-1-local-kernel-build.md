# Phase 1 Local Kernel Build Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `kernel.build` for local x86_64 Linux kernel checkouts with per-run `O=` output, durable logs, build summaries, manifest step results, and idempotent repeat behavior.

**Architecture:** Keep the MCP handler thin: it validates the run, resolves the build profile, handles idempotency and locking, then delegates command planning and execution to a concrete local build provider. The provider works only with argv lists, copies a developer-prepared `.config` into the per-run build directory when needed, records logs and summaries, and reports structured success or failure data back to the handler. Existing manifest, artifact store, redaction, path safety, and response-envelope patterns remain the public contract.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, standard-library pathlib/json/subprocess/shutil/os/datetime, existing MCP SDK wrapper in `server.py`.

---

## File Structure

Create these files:

- `src/linux_debug_mcp/providers/local_kernel_build.py`: local build profile resolution, validation helpers, command planning, config seeding, dependency checks, subprocess execution, artifact detection, summary writing, and provider capability construction.
- `tests/test_local_kernel_build.py`: provider-level tests using fake tool lookup and fake subprocess execution; no real Linux build.
- `tests/test_kernel_build_handler.py`: direct `kernel_build_handler` tests for validation order, idempotency, profile mismatch, force rebuild rejection, manifest updates, and concurrency lock behavior.

Modify these files:

- `src/linux_debug_mcp/config.py`: extend `BuildProfile` with Phase 1 fields and validation for targets, jobs, provider name, make variables, and effective required tools.
- `src/linux_debug_mcp/domain.py`: add any small structured models needed by the provider, only if a dict would obscure test assertions; keep `ToolResponse` unchanged.
- `src/linux_debug_mcp/artifacts/store.py`: expose safe run paths and add a per-run build lock context manager beside the existing manifest lock.
- `src/linux_debug_mcp/artifacts/manifest.py`: preserve the Phase 0 succeeded-step idempotency rule while allowing a `running` build result to be recorded before execution.
- `src/linux_debug_mcp/providers/registry.py`: register the local kernel build provider and remove `kernel.build` from the stub-only provider.
- `src/linux_debug_mcp/server.py`: add `kernel_build_handler`, wire the MCP `kernel.build` tool to it, and leave later-phase tools stubbed.
- `tests/test_config.py`: add BuildProfile validation tests for Phase 1 fields.
- `tests/test_artifacts.py`: add build lock and running-result manifest tests.
- `tests/test_providers.py`: update default provider assertions for the local build provider.
- `tests/test_server.py`: keep Phase 0 handler tests intact and move build-specific tests into `tests/test_kernel_build_handler.py`.
- `README.md`: document Phase 1 local build behavior, developer-owned config, output layout, and remaining boot/debug limitations.

---

### Task 1: Build Profile Contract

**Files:**
- Modify: `src/linux_debug_mcp/config.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Add failing BuildProfile validation tests**

Append to `tests/test_config.py`:

```python
def test_build_profile_defaults_for_local_kernel_build() -> None:
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")

    assert profile.provider_name == "local-kernel-build"
    assert profile.output_policy == "per_run"
    assert profile.targets == ["bzImage"]
    assert profile.command_timeout_seconds == 3600
    assert profile.required_tools == []
    assert profile.effective_required_tools() == ["make"]
    assert profile.jobs is None
    assert profile.make_variables == {}
    assert profile.config_fragments == []


def test_build_profile_effective_required_tools_includes_make_once() -> None:
    profile = BuildProfile(
        name="clang",
        architecture="x86_64",
        required_tools=["clang", "make", "llvm-ar"],
    )

    assert profile.effective_required_tools() == ["make", "clang", "llvm-ar"]


@pytest.mark.parametrize("key", ["O", "ARCH", "KBUILD_OUTPUT", "bad-key", "1BAD", "CC PATH"])
def test_build_profile_rejects_reserved_or_invalid_make_variable_names(key: str) -> None:
    with pytest.raises(ValidationError):
        BuildProfile(name="bad", architecture="x86_64", make_variables={key: "1"})


@pytest.mark.parametrize("value", ["bad\0value", "bad\nvalue", "bad\tvalue"])
def test_build_profile_rejects_control_characters_in_make_variable_values(value: str) -> None:
    with pytest.raises(ValidationError):
        BuildProfile(name="bad", architecture="x86_64", make_variables={"LLVM": value})


def test_build_profile_rejects_invalid_jobs() -> None:
    with pytest.raises(ValidationError):
        BuildProfile(name="bad", architecture="x86_64", jobs=0)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
uv run python -m pytest tests/test_config.py -v
```

Expected: FAIL because `provider_name`, `targets`, `jobs`, `make_variables`, and `effective_required_tools` do not exist yet.

- [ ] **Step 3: Extend BuildProfile**

Replace the existing `BuildProfile` in `src/linux_debug_mcp/config.py` with:

```python
class BuildProfile(ConfigModel):
    name: str
    architecture: str
    provider_name: str = "local-kernel-build"
    output_policy: Literal["per_run", "shared"] = "per_run"
    targets: list[str] = Field(default_factory=lambda: ["bzImage"], min_length=1)
    command_timeout_seconds: int = Field(default=3600, ge=1)
    required_tools: list[str] = Field(default_factory=list)
    jobs: int | None = Field(default=None, ge=1)
    make_variables: dict[str, str] = Field(default_factory=dict)
    config_fragments: list[Path] = Field(default_factory=list)

    def effective_required_tools(self) -> list[str]:
        tools = ["make"]
        for tool in self.required_tools:
            if tool not in tools:
                tools.append(tool)
        return tools

    @field_validator("make_variables")
    @classmethod
    def validate_make_variables(cls, value: dict[str, str]) -> dict[str, str]:
        reserved = {"O", "ARCH", "KBUILD_OUTPUT"}
        name_pattern = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
        for key, item in value.items():
            if key in reserved:
                raise ValueError(f"make variable {key} is provider-owned")
            if not name_pattern.match(key):
                raise ValueError(f"make variable {key} is not a simple make variable name")
            if any(ord(char) < 32 for char in item):
                raise ValueError(f"make variable {key} contains a control character")
        return value
```

Add `import re` near the top of `src/linux_debug_mcp/config.py`.

- [ ] **Step 4: Run the config tests**

Run:

```bash
uv run python -m pytest tests/test_config.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/config.py tests/test_config.py
git commit -m "feat: extend build profile for local kernel builds"
```

---

### Task 2: Artifact Store Build Lock And Running Results

**Files:**
- Modify: `src/linux_debug_mcp/artifacts/store.py`
- Modify: `src/linux_debug_mcp/artifacts/manifest.py`
- Modify: `tests/test_artifacts.py`

- [ ] **Step 1: Add failing artifact store tests**

Append to `tests/test_artifacts.py`:

```python
def test_run_dir_returns_validated_run_path(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    assert store.run_dir("run-abc123") == tmp_path / "runs" / "run-abc123"


def test_build_lock_excludes_concurrent_builds(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    with store.build_lock("run-abc123"):
        with pytest.raises(ManifestStateError, match="build is locked"):
            with store.build_lock("run-abc123"):
                pass


def test_running_build_result_can_be_replaced_by_success(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    store.record_step_result(
        "run-abc123",
        StepResult(step_name="build", status=StepStatus.RUNNING, summary="build running"),
    )
    manifest = store.record_step_result(
        "run-abc123",
        StepResult(step_name="build", status=StepStatus.SUCCEEDED, summary="build succeeded"),
    )

    assert manifest.step_results["build"].summary == "build succeeded"
    assert manifest.step_results["build"].status == StepStatus.SUCCEEDED
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
uv run python -m pytest tests/test_artifacts.py -v
```

Expected: FAIL because `run_dir` and `build_lock` do not exist.

- [ ] **Step 3: Add public run path and build lock helpers**

In `src/linux_debug_mcp/artifacts/store.py`, add:

```python
    def run_dir(self, run_id: str) -> Path:
        return self._run_dir(run_id)

    @contextmanager
    def build_lock(self, run_id: str) -> Iterator[None]:
        run_dir = self._run_dir(run_id)
        lock_path = run_dir / ".build.lock"
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise ManifestStateError("build is locked", ErrorCategory.INFRASTRUCTURE_FAILURE) from exc
        except OSError as exc:
            raise ManifestStateError(f"failed to lock build: {exc}") from exc
        try:
            os.write(fd, str(os.getpid()).encode("ascii"))
            yield
        finally:
            os.close(fd)
            with suppress(FileNotFoundError):
                lock_path.unlink()
```

Keep `_manifest_lock` unchanged.

- [ ] **Step 4: Confirm running results are replaceable**

Inspect `src/linux_debug_mcp/artifacts/manifest.py`. The existing `with_step_result` rule only preserves already-succeeded results, so no code change should be required for replacing `running` with `succeeded`. If the test from Step 1 fails, update `with_step_result` only enough to preserve succeeded results and allow all other statuses to be replaced.

- [ ] **Step 5: Run artifact tests**

Run:

```bash
uv run python -m pytest tests/test_artifacts.py -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/artifacts/store.py src/linux_debug_mcp/artifacts/manifest.py tests/test_artifacts.py
git commit -m "feat: add per-run build locking"
```

---

### Task 3: Local Build Provider Planning

**Files:**
- Create: `src/linux_debug_mcp/providers/local_kernel_build.py`
- Create: `tests/test_local_kernel_build.py`

- [ ] **Step 1: Add failing command planning tests**

Create `tests/test_local_kernel_build.py`:

```python
from pathlib import Path

import pytest

from linux_debug_mcp.config import BuildProfile
from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.providers.local_kernel_build import LocalKernelBuildProvider


def test_plan_build_uses_per_run_output_and_argv_entries(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="x86_64-default", architecture="x86_64", jobs=8)

    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    assert plan.argv == ["make", "-C", str(source), f"O={output}", "ARCH=x86_64", "-j8", "bzImage"]
    assert plan.source_path == source
    assert plan.output_path == output
    assert plan.architecture == "x86_64"
    assert plan.targets == ["bzImage"]
    assert plan.timeout_seconds == 3600


def test_plan_build_appends_make_variables_after_provider_owned_args(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(
        name="clang",
        architecture="x86_64",
        targets=["bzImage", "modules"],
        make_variables={"LLVM": "1", "CC": "clang"},
    )

    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    assert plan.argv == [
        "make",
        "-C",
        str(source),
        f"O={output}",
        "ARCH=x86_64",
        "LLVM=1",
        "CC=clang",
        "bzImage",
        "modules",
    ]


def test_plan_build_rejects_unsupported_architecture(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="arm", architecture="arm64")

    with pytest.raises(ValueError, match="unsupported architecture"):
        provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)


def test_plan_build_rejects_unsupported_profile_policy(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="shared", architecture="x86_64", output_policy="shared")

    with pytest.raises(ValueError, match="unsupported output policy"):
        provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)


def test_plan_build_rejects_wrong_provider_name(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="remote", architecture="x86_64", provider_name="remote-kernel-build")

    with pytest.raises(ValueError, match="unsupported build provider"):
        provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)


def test_plan_build_rejects_config_fragments_until_supported(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(
        name="fragments",
        architecture="x86_64",
        config_fragments=[tmp_path / "debug.fragment"],
    )

    with pytest.raises(ValueError, match="config fragments are not supported"):
        provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)
```

- [ ] **Step 2: Run the provider planning tests to verify they fail**

Run:

```bash
uv run python -m pytest tests/test_local_kernel_build.py -v
```

Expected: FAIL because `local_kernel_build.py` does not exist.

- [ ] **Step 3: Add planning models and provider skeleton**

Create `src/linux_debug_mcp/providers/local_kernel_build.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from linux_debug_mcp.config import BuildProfile


@dataclass(frozen=True)
class BuildPlan:
    argv: list[str]
    source_path: Path
    output_path: Path
    architecture: str
    targets: list[str]
    profile_name: str
    timeout_seconds: int
    required_tools: list[str]


class LocalKernelBuildProvider:
    name = "local-kernel-build"
    supported_architectures = ["x86_64"]

    def plan_build(self, *, source_path: Path, output_path: Path, profile: BuildProfile) -> BuildPlan:
        if profile.provider_name != self.name:
            raise ValueError(f"unsupported build provider: {profile.provider_name}")
        if profile.architecture not in self.supported_architectures:
            raise ValueError(f"unsupported architecture: {profile.architecture}")
        if profile.output_policy != "per_run":
            raise ValueError(f"unsupported output policy: {profile.output_policy}")
        if profile.config_fragments:
            raise ValueError("config fragments are not supported by the local Phase 1 provider")
        argv = ["make", "-C", str(source_path), f"O={output_path}", "ARCH=x86_64"]
        if profile.jobs is not None:
            argv.append(f"-j{profile.jobs}")
        argv.extend(f"{key}={value}" for key, value in profile.make_variables.items())
        argv.extend(profile.targets)
        return BuildPlan(
            argv=argv,
            source_path=source_path,
            output_path=output_path,
            architecture=profile.architecture,
            targets=list(profile.targets),
            profile_name=profile.name,
            timeout_seconds=profile.command_timeout_seconds,
            required_tools=profile.effective_required_tools(),
        )
```

- [ ] **Step 4: Run provider planning tests**

Run:

```bash
uv run python -m pytest tests/test_local_kernel_build.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/local_kernel_build.py tests/test_local_kernel_build.py
git commit -m "feat: plan local kernel build commands"
```

---

### Task 4: Local Provider Config, Dependencies, Execution, And Summaries

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_kernel_build.py`
- Modify: `tests/test_local_kernel_build.py`

- [ ] **Step 1: Add fake runner and config/artifact tests**

Append to `tests/test_local_kernel_build.py`:

```python
class FakeRunner:
    def __init__(self, *, tools: dict[str, str] | None = None, returncode: int = 0, output: str = "") -> None:
        self.tools = {"make": "/usr/bin/make"} if tools is None else tools
        self.returncode = returncode
        self.output = output
        self.commands: list[list[str]] = []

    def which(self, command: str) -> str | None:
        return self.tools.get(command)

    def run(self, argv: list[str], *, timeout: int, log_path: Path) -> int:
        self.commands.append(argv)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(self.output, encoding="utf-8")
        return self.returncode


def test_prepare_config_seeds_source_config_when_output_config_missing(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")

    provider = LocalKernelBuildProvider()
    config_path = provider.prepare_config(source_path=source, output_path=output)

    assert config_path == output / ".config"
    assert config_path.read_text(encoding="utf-8") == "CONFIG_TEST=y\n"


def test_prepare_config_uses_existing_output_config_without_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)
    (source / ".config").write_text("CONFIG_SOURCE=y\n", encoding="utf-8")
    (output / ".config").write_text("CONFIG_OUTPUT=y\n", encoding="utf-8")

    provider = LocalKernelBuildProvider()
    config_path = provider.prepare_config(source_path=source, output_path=output)

    assert config_path.read_text(encoding="utf-8") == "CONFIG_OUTPUT=y\n"


def test_prepare_config_fails_without_developer_config(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)

    provider = LocalKernelBuildProvider()

    with pytest.raises(ValueError, match="missing developer-prepared .config"):
        provider.prepare_config(source_path=source, output_path=output)


def test_execute_success_records_artifacts_and_summary(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    logs = tmp_path / "runs" / "run-1" / "logs"
    summaries = tmp_path / "runs" / "run-1" / "summaries"
    source.mkdir()
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    (output / "arch" / "x86" / "boot").mkdir(parents=True)
    (output / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    (output / "vmlinux").write_text("symbols", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=FakeRunner(output="ok\n"))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(plan=plan, log_path=logs / "build.log", summary_path=summaries / "build-summary.json")

    assert result.status == "succeeded"
    assert {artifact.kind for artifact in result.artifacts} == {
        "build-log",
        "kernel-config",
        "kernel-image",
        "vmlinux",
        "build-summary",
    }
    assert (summaries / "build-summary.json").exists()


def test_execute_missing_required_tool_returns_missing_dependency(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider(runner=FakeRunner(tools={}))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64", required_tools=[])
    plan = provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)

    result = provider.execute_build(plan=plan, log_path=tmp_path / "build.log", summary_path=tmp_path / "summary.json")

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.MISSING_DEPENDENCY


def test_execute_checks_profile_required_tools(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider(runner=FakeRunner(tools={"make": "/usr/bin/make"}))
    profile = BuildProfile(name="clang", architecture="x86_64", required_tools=["clang"])
    plan = provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)

    result = provider.execute_build(plan=plan, log_path=tmp_path / "build.log", summary_path=tmp_path / "summary.json")

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.MISSING_DEPENDENCY
    assert result.details["missing_tools"] == ["clang"]


def test_execute_nonzero_make_returns_build_failure_with_redacted_tail(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "build"
    source.mkdir()
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=FakeRunner(returncode=2, output="token=secret\nfailed\n"))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(plan=plan, log_path=tmp_path / "build.log", summary_path=tmp_path / "summary.json")

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.BUILD_FAILURE
    assert "token=[REDACTED]" in result.diagnostic
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
uv run python -m pytest tests/test_local_kernel_build.py -v
```

Expected: FAIL because execution helpers do not exist.

- [ ] **Step 3: Implement runner protocol and provider result**

In `src/linux_debug_mcp/providers/local_kernel_build.py`, add imports:

```python
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, StepStatus
from linux_debug_mcp.safety.redaction import Redactor
```

Add:

```python
class BuildRunner(Protocol):
    def which(self, command: str) -> str | None:
        raise NotImplementedError

    def run(self, argv: list[str], *, timeout: int, log_path: Path) -> int:
        raise NotImplementedError


class SubprocessBuildRunner:
    def which(self, command: str) -> str | None:
        return shutil.which(command)

    def run(self, argv: list[str], *, timeout: int, log_path: Path) -> int:
        with log_path.open("w", encoding="utf-8") as log_file:
            completed = subprocess.run(
                argv,
                check=False,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
        return completed.returncode


@dataclass(frozen=True)
class BuildExecutionResult:
    status: StepStatus
    summary: str
    artifacts: list[ArtifactRef] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)
    error_category: ErrorCategory | None = None
    diagnostic: str | None = None
```

Update `LocalKernelBuildProvider.__init__`:

```python
    def __init__(self, *, runner: BuildRunner | None = None, redactor: Redactor | None = None) -> None:
        self.runner = runner or SubprocessBuildRunner()
        self.redactor = redactor or Redactor()
```

- [ ] **Step 4: Implement config preparation**

Add to `LocalKernelBuildProvider`:

```python
    def prepare_config(self, *, source_path: Path, output_path: Path) -> Path:
        output_path.mkdir(parents=True, exist_ok=True)
        output_config = output_path / ".config"
        if output_config.exists():
            return output_config
        source_config = source_path / ".config"
        if not source_config.exists():
            raise ValueError("missing developer-prepared .config")
        shutil.copy2(source_config, output_config)
        return output_config
```

- [ ] **Step 5: Implement execution and artifact detection**

Add provider methods:

```python
    def execute_build(self, *, plan: BuildPlan, log_path: Path, summary_path: Path) -> BuildExecutionResult:
        started_at = datetime.now(UTC)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        missing_tools = [tool for tool in plan.required_tools if self.runner.which(tool) is None]
        if missing_tools:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary="missing required build tools",
                error_category=ErrorCategory.MISSING_DEPENDENCY,
                details={"missing_tools": missing_tools, "argv": plan.argv},
            )
        try:
            self.prepare_config(source_path=plan.source_path, output_path=plan.output_path)
            exit_status = self.runner.run(plan.argv, timeout=plan.timeout_seconds, log_path=log_path)
        except ValueError as exc:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary=str(exc),
                error_category=ErrorCategory.CONFIGURATION_ERROR,
                details={"argv": plan.argv},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary=f"build infrastructure failure: {exc}",
                error_category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                details={"argv": plan.argv},
                diagnostic=self._log_tail(log_path),
            )
        ended_at = datetime.now(UTC)
        details = {
            "argv": plan.argv,
            "source_path": str(plan.source_path),
            "output_path": str(plan.output_path),
            "architecture": plan.architecture,
            "targets": plan.targets,
            "profile": plan.profile_name,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "timeout_seconds": plan.timeout_seconds,
            "exit_status": exit_status,
            "elapsed_seconds": (ended_at - started_at).total_seconds(),
        }
        artifacts_before_summary = self._detect_artifacts(plan=plan, log_path=log_path, summary_path=summary_path)
        self._write_summary(summary_path=summary_path, details=details, artifacts=artifacts_before_summary)
        artifacts = self._detect_artifacts(plan=plan, log_path=log_path, summary_path=summary_path)
        if exit_status != 0:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary="kernel build failed",
                artifacts=[artifact for artifact in artifacts if artifact.kind in {"build-log", "build-summary"}],
                details=details,
                error_category=ErrorCategory.BUILD_FAILURE,
                diagnostic=self._log_tail(log_path),
            )
        required = {str(plan.output_path / ".config"), str(plan.output_path / "arch" / "x86" / "boot" / "bzImage")}
        present = {artifact.path for artifact in artifacts}
        missing = sorted(required - present)
        if missing:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary="kernel build did not produce required artifacts",
                artifacts=artifacts,
                details={**details, "missing_artifacts": missing},
                error_category=ErrorCategory.BUILD_FAILURE,
                diagnostic=self._log_tail(log_path),
            )
        return BuildExecutionResult(
            status=StepStatus.SUCCEEDED,
            summary="kernel build succeeded",
            artifacts=artifacts,
            details=details,
        )
```

Add helper methods:

```python
    def _detect_artifacts(self, *, plan: BuildPlan, log_path: Path, summary_path: Path) -> list[ArtifactRef]:
        candidates = [
            (log_path, "build-log"),
            (plan.output_path / ".config", "kernel-config"),
            (plan.output_path / "arch" / "x86" / "boot" / "bzImage", "kernel-image"),
            (plan.output_path / "vmlinux", "vmlinux"),
            (summary_path, "build-summary"),
        ]
        return [ArtifactRef(path=str(path), kind=kind) for path, kind in candidates if path.exists()]

    def _write_summary(self, *, summary_path: Path, details: dict[str, object], artifacts: list[ArtifactRef]) -> None:
        payload = {**details, "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts]}
        summary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _log_tail(self, log_path: Path, *, limit: int = 4000) -> str | None:
        if not log_path.exists():
            return None
        text = log_path.read_text(encoding="utf-8", errors="replace")
        return self.redactor.redact_text(text[-limit:])
```

- [ ] **Step 6: Run provider tests**

Run:

```bash
uv run python -m pytest tests/test_local_kernel_build.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/linux_debug_mcp/providers/local_kernel_build.py tests/test_local_kernel_build.py
git commit -m "feat: execute local kernel builds with fakeable runner"
```

---

### Task 5: Kernel Build Handler And MCP Tool

**Files:**
- Create: `tests/test_kernel_build_handler.py`
- Modify: `src/linux_debug_mcp/server.py`

- [ ] **Step 1: Add failing handler tests**

Create `tests/test_kernel_build_handler.py`:

```python
import threading
from pathlib import Path

from linux_debug_mcp.providers.local_kernel_build import LocalKernelBuildProvider
from linux_debug_mcp.server import create_run_handler, kernel_build_handler


class NoopRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}"

    def run(self, argv: list[str], *, timeout: int, log_path: Path) -> int:
        self.commands.append(argv)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("ok\n", encoding="utf-8")
        return 0


class BlockingRunner(NoopRunner):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()

    def run(self, argv: list[str], *, timeout: int, log_path: Path) -> int:
        self.commands.append(argv)
        self.started.set()
        self.release.wait(timeout=5)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("ok\n", encoding="utf-8")
        return 0


def make_source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    return source


def create_run(tmp_path: Path, *, build_profile: str = "x86_64-default") -> tuple[Path, Path]:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"
    create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile=build_profile,
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )
    return source, artifact_root


def test_kernel_build_rejects_force_rebuild_true(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", force_rebuild=True)

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "force_rebuild=true" in response.error.message


def test_kernel_build_rejects_profile_mismatch(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path, build_profile="x86_64-default")

    response = kernel_build_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        build_profile="clang",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_kernel_build_rejects_missing_manifest_profile(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path, build_profile="unknown-profile")

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "unknown build profile" in response.error.message


def test_kernel_build_fails_without_developer_config(tmp_path: Path) -> None:
    source, artifact_root = create_run(tmp_path)
    (source / ".config").unlink()

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_kernel_build_repeat_success_returns_recorded_result(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    build_dir = artifact_root / "run-abc123" / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    runner = NoopRunner()
    provider = LocalKernelBuildProvider(runner=runner)

    first = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)
    second = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)

    assert first.ok is True
    assert second.ok is True
    assert second.summary == first.summary
    assert second.data["output_path"] == first.data["output_path"]
    assert len(runner.commands) == 1


def test_kernel_build_existing_running_state_fails_without_rerun(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    from linux_debug_mcp.artifacts.store import ArtifactStore
    from linux_debug_mcp.domain import StepResult, StepStatus

    runner = NoopRunner()
    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(
        "run-abc123",
        StepResult(step_name="build", status=StepStatus.RUNNING, summary="kernel build running"),
    )

    response = kernel_build_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=LocalKernelBuildProvider(runner=runner),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert "previous build is still recorded as running" in response.error.message
    assert runner.commands == []


def test_kernel_build_concurrent_calls_only_start_one_subprocess(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    build_dir = artifact_root / "run-abc123" / "build"
    (build_dir / "arch" / "x86" / "boot").mkdir(parents=True)
    (build_dir / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    runner = BlockingRunner()
    provider = LocalKernelBuildProvider(runner=runner)
    responses = []

    first = threading.Thread(
        target=lambda: responses.append(
            kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)
        )
    )
    first.start()
    assert runner.started.wait(timeout=5)

    second = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123", provider=provider)
    runner.release.set()
    first.join(timeout=5)

    assert not first.is_alive()
    assert len(runner.commands) == 1
    assert {response.ok for response in [*responses, second]} == {True, False}
    assert second.ok is False
    assert second.error is not None
    assert second.error.category == "infrastructure_failure"
    assert "build is locked" in second.error.message
```

- [ ] **Step 2: Run handler tests to verify they fail**

Run:

```bash
uv run python -m pytest tests/test_kernel_build_handler.py -v
```

Expected: FAIL because `kernel_build_handler` does not exist.

- [ ] **Step 3: Implement profile resolution in server.py**

In `src/linux_debug_mcp/server.py`, import:

```python
from linux_debug_mcp.config import BuildProfile
from linux_debug_mcp.domain import StepResult, StepStatus
from linux_debug_mcp.providers.local_kernel_build import LocalKernelBuildProvider
```

Add:

```python
DEFAULT_BUILD_PROFILES = {
    "x86_64-default": BuildProfile(name="x86_64-default", architecture="x86_64"),
}


def _build_profile_from_manifest(profile_name: str) -> BuildProfile:
    try:
        return DEFAULT_BUILD_PROFILES[profile_name]
    except KeyError as exc:
        raise ValueError(f"unknown build profile: {profile_name}") from exc
```

- [ ] **Step 4: Implement kernel_build_handler**

Add to `src/linux_debug_mcp/server.py`:

```python
def kernel_build_handler(
    *,
    artifact_root: Path,
    run_id: str,
    build_profile: str | None = None,
    force_rebuild: bool = False,
    provider: LocalKernelBuildProvider | None = None,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    if force_rebuild:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="force_rebuild=true is not supported until rebuild cleanup policy is implemented",
            run_id=run_id,
        )
    requested_profile = build_profile or manifest.request.build_profile
    if requested_profile != manifest.request.build_profile:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="build_profile must match the immutable run manifest request",
            run_id=run_id,
            details={"requested_profile": requested_profile, "manifest_profile": manifest.request.build_profile},
        )
    existing = manifest.step_results.get("build")
    if existing and existing.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=existing.summary,
            run_id=run_id,
            data=existing.details,
            artifacts=existing.artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    if existing and existing.status == StepStatus.RUNNING:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message="previous build is still recorded as running; inspect logs and create a new run or manually clean stale build state",
            run_id=run_id,
            details=existing.details,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    try:
        source_path = validate_source_path(Path(manifest.request.source_path))
        store = ArtifactStore(artifact_root, source_paths=[source_path], create_root=False)
        profile = _build_profile_from_manifest(requested_profile)
        provider = provider or LocalKernelBuildProvider()
        run_dir = store.run_dir(run_id)
        plan = provider.plan_build(source_path=source_path, output_path=run_dir / "build", profile=profile)
    except (PathSafetyError, ValueError, ManifestStateError) as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
            run_id=run_id,
        )
    log_path = store.run_dir(run_id) / "logs" / "build.log"
    summary_path = store.run_dir(run_id) / "summaries" / "build-summary.json"
    try:
        with store.build_lock(run_id):
            running = StepResult(
                step_name="build",
                status=StepStatus.RUNNING,
                summary="kernel build running",
                details={"argv": plan.argv, "log_path": str(log_path), "provider": provider.name},
                artifacts=[ArtifactRef(path=str(log_path), kind="build-log")],
            )
            store.record_step_result(run_id, running)
            execution = provider.execute_build(plan=plan, log_path=log_path, summary_path=summary_path)
            result = StepResult(
                step_name="build",
                status=execution.status,
                summary=execution.summary,
                artifacts=execution.artifacts,
                details=execution.details,
            )
            store.record_step_result(run_id, result)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    if execution.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=execution.summary,
            run_id=run_id,
            data=execution.details,
            artifacts=execution.artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    return ToolResponse.failure(
        category=execution.error_category or ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=execution.summary,
        run_id=run_id,
        details={**execution.details, "diagnostic": execution.diagnostic},
        suggested_next_actions=["artifacts.get_manifest"],
    )
```

- [ ] **Step 5: Wire the MCP tool**

In `create_app`, add a real `kernel.build` tool before the stub loop:

```python
    @app.tool(name="kernel.build")
    def kernel_build(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        build_profile: str | None = None,
        force_rebuild: bool = False,
    ) -> dict[str, Any]:
        return kernel_build_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            build_profile=build_profile,
            force_rebuild=force_rebuild,
        ).model_dump(mode="json")
```

Remove `"kernel.build"` from the later stub tool list.

- [ ] **Step 6: Run handler tests**

Run:

```bash
uv run python -m pytest tests/test_kernel_build_handler.py tests/test_server.py -v
```

Expected: PASS after updating the old `not_implemented_handler("kernel.build")` test in `tests/test_server.py` to use a later-phase tool such as `target.boot`.

- [ ] **Step 7: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_kernel_build_handler.py tests/test_server.py
git commit -m "feat: add kernel build handler"
```

---

### Task 6: Provenance, Required Tools, And Provider Capabilities

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_kernel_build.py`
- Modify: `src/linux_debug_mcp/providers/registry.py`
- Modify: `tests/test_local_kernel_build.py`
- Modify: `tests/test_providers.py`
- Modify: `tests/test_server.py`

- [ ] **Step 1: Add failing provenance and registry tests**

Add these imports near the top of `tests/test_local_kernel_build.py`:

```python
import json
import shutil
import subprocess
```

Append to `tests/test_local_kernel_build.py`:

```python
def test_source_revision_for_non_git_tree_records_unknown_reason(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    provider = LocalKernelBuildProvider()

    revision = provider.detect_source_revision(source)

    assert revision["commit"] is None
    assert revision["dirty"] is None
    assert revision["reason"]


def test_source_revision_for_git_tree_records_commit_and_dirty_state(tmp_path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    source = tmp_path / "linux"
    source.mkdir()
    subprocess.run(["git", "init"], cwd=source, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=source, check=True)
    (source / "README").write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "add", "README"], cwd=source, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=source, check=True, capture_output=True, text=True)
    expected_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    (source / "dirty").write_text("untracked\n", encoding="utf-8")
    provider = LocalKernelBuildProvider()

    revision = provider.detect_source_revision(source)

    assert revision == {"commit": expected_commit, "dirty": True, "reason": None}


def test_execute_summary_records_source_revision(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    summaries = tmp_path / "runs" / "run-1" / "summaries"
    source.mkdir()
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    (output / "arch" / "x86" / "boot").mkdir(parents=True)
    (output / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=FakeRunner(output="ok\n"))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    provider.execute_build(
        plan=plan,
        log_path=tmp_path / "runs" / "run-1" / "logs" / "build.log",
        summary_path=summaries / "build-summary.json",
    )

    summary = json.loads((summaries / "build-summary.json").read_text(encoding="utf-8"))
    assert summary["source_revision"]["commit"] is None
    assert summary["source_revision"]["dirty"] is None
    assert summary["source_revision"]["reason"]
```

Update `tests/test_providers.py` default registry test:

```python
def test_default_registry_exposes_phase_1_providers() -> None:
    registry = ProviderRegistry.with_defaults()

    providers = {provider.provider_name: provider for provider in registry.list_capabilities()}

    assert set(providers) == {"local-artifacts", "local-prereqs", "local-kernel-build", "stub-workflows"}
    assert "kernel.build" in providers["local-kernel-build"].operations
    assert "kernel.build" not in providers["stub-workflows"].operations
    assert "make" in providers["local-kernel-build"].required_host_tools
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
uv run python -m pytest tests/test_local_kernel_build.py tests/test_providers.py tests/test_server.py -v
```

Expected: FAIL because revision detection and local provider capability are not implemented.

- [ ] **Step 3: Implement source revision detection**

In `src/linux_debug_mcp/providers/local_kernel_build.py`, add:

```python
    def detect_source_revision(self, source_path: Path) -> dict[str, object]:
        try:
            commit = subprocess.check_output(
                ["git", "-C", str(source_path), "rev-parse", "HEAD"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            ).strip()
            dirty_status = subprocess.check_output(
                ["git", "-C", str(source_path), "status", "--porcelain"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"commit": None, "dirty": None, "reason": str(exc)}
        return {"commit": commit, "dirty": bool(dirty_status.strip()), "reason": None}
```

Call `detect_source_revision(plan.source_path)` before running `make` and include it in execution details and missing-tool details as `source_revision`:

```python
        source_revision = self.detect_source_revision(plan.source_path)
        missing_tools = [tool for tool in plan.required_tools if self.runner.which(tool) is None]
        if missing_tools:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary="missing required build tools",
                error_category=ErrorCategory.MISSING_DEPENDENCY,
                details={"missing_tools": missing_tools, "argv": plan.argv, "source_revision": source_revision},
            )
```

Then add `"source_revision": source_revision` to the later successful/subprocess-failure `details` dictionary.

- [ ] **Step 4: Add capability constructor**

In `src/linux_debug_mcp/providers/local_kernel_build.py`, add:

```python
from linux_debug_mcp.domain import OperationSemantics, ProviderCapability, TargetKind


def local_kernel_build_capability() -> ProviderCapability:
    return ProviderCapability(
        provider_name="local-kernel-build",
        provider_version="0.1.0",
        architectures=["x86_64"],
        target_kinds=[TargetKind.LOCAL],
        operations=["kernel.build"],
        required_host_tools=["make"],
        destructive_permissions=[],
        access_methods=["filesystem", "subprocess"],
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=False,
            cancelable=False,
            concurrent_safe=False,
        ),
    )
```

- [ ] **Step 5: Register the provider**

In `src/linux_debug_mcp/providers/registry.py`, import `local_kernel_build_capability`, register it in `with_defaults`, and remove `"kernel.build"` from the `stub-workflows` operations list.

- [ ] **Step 6: Run registry and provider tests**

Run:

```bash
uv run python -m pytest tests/test_local_kernel_build.py tests/test_providers.py tests/test_server.py -v
```

Expected: PASS after updating `test_list_providers_handler_returns_default_capabilities` in `tests/test_server.py` to include `"local-kernel-build"`.

- [ ] **Step 7: Commit**

```bash
git add src/linux_debug_mcp/providers/local_kernel_build.py src/linux_debug_mcp/providers/registry.py tests/test_local_kernel_build.py tests/test_providers.py tests/test_server.py
git commit -m "feat: expose local kernel build provider capability"
```

---

### Task 7: Idempotency, Concurrency, And Error Response Coverage

**Files:**
- Modify: `tests/test_kernel_build_handler.py`
- Modify: `src/linux_debug_mcp/server.py`
- Modify: `src/linux_debug_mcp/providers/local_kernel_build.py`

- [ ] **Step 1: Add focused handler coverage**

Append to `tests/test_kernel_build_handler.py`:

```python
def test_kernel_build_existing_build_lock_returns_failure(tmp_path: Path) -> None:
    _, artifact_root = create_run(tmp_path)
    from linux_debug_mcp.artifacts.store import ArtifactStore

    store = ArtifactStore(artifact_root, create_root=False)
    with store.build_lock("run-abc123"):
        response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert "build is locked" in response.error.message


def test_kernel_build_records_failed_step_result(tmp_path: Path) -> None:
    source, artifact_root = create_run(tmp_path)
    (source / ".config").unlink()

    response = kernel_build_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    manifest = kernel_build_handler.__globals__["ArtifactStore"](artifact_root, create_root=False).load_manifest("run-abc123")
    assert manifest.step_results["build"].status == "failed"
```

- [ ] **Step 2: Run handler tests to verify failures or gaps**

Run:

```bash
uv run python -m pytest tests/test_kernel_build_handler.py -v
```

Expected: FAIL if configuration errors before subprocess execution are not recorded as terminal build step results.

- [ ] **Step 3: Record terminal failures after running state**

In `kernel_build_handler`, ensure any provider execution result, including `CONFIGURATION_ERROR` from missing `.config`, is converted to a terminal `StepResult` and written through `store.record_step_result`.

Do not record a build step result for validation failures that occur before build lock acquisition, such as missing run, unsupported `force_rebuild`, profile mismatch, invalid source path, or unsupported architecture.

- [ ] **Step 4: Run handler tests**

Run:

```bash
uv run python -m pytest tests/test_kernel_build_handler.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py src/linux_debug_mcp/providers/local_kernel_build.py tests/test_kernel_build_handler.py
git commit -m "test: cover kernel build idempotency and lock failures"
```

---

### Task 8: README And Full Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README for Phase 1**

Replace the Phase 0 scope section with a current scope section:

```markdown
## Current Scope

Phase 1 provides:

- host prerequisite checks
- durable run workspace creation
- local x86_64 `kernel.build` for prepared Linux source checkouts
- per-run build output under `<artifact-root>/<run-id>/build`
- build log capture at `<artifact-root>/<run-id>/logs/build.log`
- build summary capture at `<artifact-root>/<run-id>/summaries/build-summary.json`
- manifest readback
- provider capability listing
- structured `not_implemented` responses for boot, test, artifact collection, workflow, and debug tools

Phase 1 does not boot kernels, create root filesystems, run SSH or serial commands, attach gdb, use remote builders, generate kernel configs, or apply config fragments automatically.
```

Add a `Local Kernel Builds` section:

````markdown
## Local Kernel Builds

`kernel.build` builds a developer-prepared local Linux checkout. The source tree
must contain `Kconfig` and `Makefile`, and the developer must provide a kernel
configuration either at `<source>/.config` or by pre-populating
`<artifact-root>/<run-id>/build/.config`.

The default Phase 1 command shape is:

```bash
make -C <source> O=<artifact-root>/<run-id>/build ARCH=x86_64 bzImage
```

The provider does not run `defconfig`, `olddefconfig`, `menuconfig`,
`localmodconfig`, or config fragment application. If the per-run build config is
missing and `<source>/.config` exists, the source config is copied into the
per-run build directory before `make` starts.

On success, artifacts include the build log, `.config`, `arch/x86/boot/bzImage`,
optional `vmlinux`, and `summaries/build-summary.json`.
````

- [ ] **Step 2: Run focused test suites**

Run:

```bash
uv run python -m pytest tests/test_config.py tests/test_artifacts.py tests/test_local_kernel_build.py tests/test_kernel_build_handler.py tests/test_providers.py tests/test_server.py -v
```

Expected: PASS.

- [ ] **Step 3: Run full test suite**

Run:

```bash
uv run python -m pytest
```

Expected: PASS.

- [ ] **Step 4: Run lint and format checks**

Run:

```bash
uv run ruff check .
uv run ruff format --check .
```

Expected: both commands exit 0.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: document phase 1 local kernel builds"
```

---

## Self-Review Checklist

- [ ] Spec coverage: local x86_64 build provider, `kernel.build` handler, per-run `O=`, config seeding, command planning, logs, artifacts, manifest result, idempotency, provider capability, tests, and README are each covered by a task.
- [ ] Explicit non-goals: no boot, rootfs, SSH, serial, gdb, remote build, ppc64le, auto config generation, or config fragments are introduced.
- [ ] Validation order: handler task validates run, rejects `force_rebuild=true`, checks profile mismatch, returns existing success, then plans and executes.
- [ ] Safety: `make_variables` validation prevents overriding `O`, `ARCH`, or `KBUILD_OUTPUT`; provider uses argv lists only.
- [ ] Test safety: default tests use fake runners and prepared temporary trees; no real kernel build is required.
- [ ] Completion: after Task 8, run `git status --short` and confirm only intentional files are changed or committed.
