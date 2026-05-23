# Sprint 3 Smoke Tests Artifacts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement SSH-first smoke-test execution, artifact bundle indexing, and the `workflow.build_boot_test` orchestration tool.

**Architecture:** Keep handlers responsible for run validation, immutable request checks, idempotency, locking, and MCP response shaping. Put SSH argv planning, option validation, bounded command execution, per-command artifact writing, dmesg capture, and `test-summary.json` generation behind a fakeable `LocalSshTestProvider`; implement artifact collection as a manifest/filesystem index rather than a copier.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, stdlib `subprocess`, `shlex.quote`, existing `ArtifactStore`, `RunManifest`, `ToolResponse`, provider registry, and response redaction helpers.

---

## Current-Code Constraints To Resolve First

- `RootfsProfile` has no SSH reachability fields beyond `access_method` and credential references; Sprint 3 needs explicit host, port, user, key reference, and validated SSH options.
- There is no `TestCommand` or `TestSuiteProfile` model, and `ServerConfig` has no `test_suites` map.
- `ArtifactStore` exposes build, boot, and target locks only. Sprint 3 needs `tests_lock(run_id)` and `collect_lock(run_id)`.
- `server.py` still registers `target.run_tests`, `artifacts.collect`, and `workflow.build_boot_test` as stubs.
- The default provider registry still groups Sprint 3 operations under `stub-workflows`; registering `local-ssh-tests` and narrowing the stub operation list must happen with the tool wiring.
- `Redactor` handles common key-value secrets, but snippets also need explicit redaction of configured SSH key references and output examples such as fake token strings.
- Existing tests rely on default `minimal` rootfs profile. After adding SSH fields, defaults must remain valid for boot tests while becoming suitable for smoke tests.

## Files

- Modify: `src/linux_debug_mcp/config.py` for `TestCommand`, `TestSuiteProfile`, rootfs SSH fields, validators, and `ServerConfig.test_suites`.
- Modify: `src/linux_debug_mcp/artifacts/store.py` for `tests_lock()` and `collect_lock()`.
- Create: `src/linux_debug_mcp/providers/local_ssh_tests.py` for SSH test planning, runner protocol, subprocess runner, command execution, artifact writing, dmesg capture, summaries, and provider capability.
- Modify: `src/linux_debug_mcp/providers/registry.py` to register `local-ssh-tests` and remove implemented Sprint 3 operations from stubs.
- Modify: `src/linux_debug_mcp/server.py` for default smoke suite/profile data, `target_run_tests_handler()`, `artifacts_collect_handler()`, `workflow_build_boot_test_handler()`, and MCP tool wiring.
- Modify: `src/linux_debug_mcp/safety/redaction.py` only if provider-level configured secret redaction needs a reusable helper.
- Create: `tests/test_local_ssh_tests_provider.py` for provider validation, argv planning, fake runner execution, timeouts, dmesg, layout, and redaction.
- Create: `tests/test_target_run_tests_handler.py` for handler validation, idempotency, locking, default suite, ad hoc commands, and failure mapping.
- Create: `tests/test_artifacts_collect_handler.py` for bundle contents, missing reference rules, idempotency, and locking.
- Create: `tests/test_workflow_build_boot_test_handler.py` for workflow success and build, boot, test, and collect failure boundaries.
- Modify: `tests/test_config.py`, `tests/test_artifacts.py`, `tests/test_providers.py`, `tests/test_server.py`, and `tests/test_redaction.py` for new profile fields, locks, providers, tool registration, and snippet redaction.
- Modify: `README.md` and `docs/fedora-libvirt-user-guide.md` for the Sprint 3 pilot flow and SSH expectations.

## Task 1: Add Smoke Test Profile Models

**Files:**
- Modify: `src/linux_debug_mcp/config.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Write failing config tests**

Add these tests to `tests/test_config.py`:

```python
from linux_debug_mcp.config import TestCommand, TestSuiteProfile


def test_sprint_3_rootfs_profile_accepts_ssh_access_fields() -> None:
    profile = RootfsProfile(
        name="minimal",
        source="/var/lib/linux-debug/rootfs.qcow2",
        access_method="ssh_and_serial",
        ssh_host="127.0.0.1",
        ssh_port=2222,
        ssh_user="root",
        ssh_key_ref="/tmp/id_ed25519",
        ssh_options={
            "ConnectTimeout": "5",
            "IdentitiesOnly": "yes",
            "LogLevel": "ERROR",
            "StrictHostKeyChecking": "accept-new",
        },
    )

    assert profile.ssh_host == "127.0.0.1"
    assert profile.ssh_port == 2222
    assert profile.ssh_user == "root"
    assert profile.ssh_options["ConnectTimeout"] == "5"


def test_test_suite_profile_accepts_ordered_commands() -> None:
    suite = TestSuiteProfile(
        name="smoke-basic",
        timeout_seconds=30,
        stop_on_failure=True,
        collect_dmesg=True,
        commands=[
            TestCommand(name="uname", argv=["uname", "-a"]),
            TestCommand(name="proc-version", argv=["test", "-r", "/proc/version"]),
        ],
    )

    assert [command.name for command in suite.commands] == ["uname", "proc-version"]
    assert suite.commands[0].required is True


@pytest.mark.parametrize("name", ["", "../bad", "bad/name", "bad name", "bad\nname"])
def test_test_command_rejects_non_filesystem_safe_names(name: str) -> None:
    with pytest.raises(ValidationError):
        TestCommand(name=name, argv=["uname"])


@pytest.mark.parametrize("argv", [[], [""], ["bad\narg"], ["bad\0arg"]])
def test_test_command_rejects_empty_or_control_character_argv(argv: list[str]) -> None:
    with pytest.raises(ValidationError):
        TestCommand(name="bad", argv=argv)


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("ProxyCommand", "nc bad 22"),
        ("ConnectTimeout", "0"),
        ("ConnectTimeout", "999999"),
        ("IdentitiesOnly", "maybe"),
        ("LogLevel", "DEBUG"),
        ("StrictHostKeyChecking", "no"),
        ("Bad Option", "yes"),
        ("Bad\nOption", "yes"),
    ],
)
def test_rootfs_profile_rejects_invalid_ssh_options(option: str, value: str) -> None:
    with pytest.raises(ValidationError):
        RootfsProfile(
            name="minimal",
            source="/var/lib/linux-debug/rootfs.qcow2",
            ssh_host="127.0.0.1",
            ssh_user="root",
            ssh_options={option: value},
        )
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
pytest tests/test_config.py -q
```

Expected: FAIL because `TestCommand`, `TestSuiteProfile`, and the rootfs SSH fields do not exist.

- [ ] **Step 3: Implement profile models and validators**

In `src/linux_debug_mcp/config.py`, keep the existing validator import shape:

```python
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator
```

Add helpers near the top of the file:

```python
_SAFE_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_ALLOWED_SSH_OPTIONS = {
    "ConnectTimeout": {"validator": "timeout"},
    "IdentitiesOnly": {"values": {"yes", "no"}},
    "LogLevel": {"values": {"ERROR", "QUIET", "VERBOSE"}},
    "StrictHostKeyChecking": {"values": {"accept-new", "yes"}},
}


def _has_control_character(value: str) -> bool:
    return any(unicodedata.category(char) == "Cc" for char in value)
```

Add the models before `RootfsProfile`:

```python
class TestCommand(ConfigModel):
    name: str
    argv: list[str] = Field(min_length=1)
    timeout_seconds: int | None = Field(default=None, ge=1)
    required: bool = True

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _SAFE_LABEL_PATTERN.match(value):
            raise ValueError("test command name must be filesystem safe")
        return value

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item:
                raise ValueError("test command argv entries must be non-empty")
            if _has_control_character(item):
                raise ValueError("test command argv entries must not contain control characters")
        return value


class TestSuiteProfile(ConfigModel):
    name: str
    commands: list[TestCommand] = Field(min_length=1)
    timeout_seconds: int = Field(default=30, ge=1)
    stop_on_failure: bool = True
    collect_dmesg: bool = True

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _SAFE_LABEL_PATTERN.match(value):
            raise ValueError("test suite name must be filesystem safe")
        return value
```

Extend `RootfsProfile`:

```python
class RootfsProfile(ConfigModel):
    name: str
    source: str
    source_type: Literal["disk_image", "directory"] = "disk_image"
    mutability: Literal["read_only", "copy_on_write", "mutable"] = "copy_on_write"
    access_method: Literal["ssh", "serial", "ssh_and_serial", "none"] = "ssh"
    credential_refs: list[SecretReference] = Field(default_factory=list)
    readiness_marker: str | None = None
    guest_writable_paths: list[str] = Field(default_factory=list)
    ssh_host: str | None = None
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str | None = None
    ssh_key_ref: str | None = None
    ssh_options: dict[str, str] = Field(default_factory=dict)

    @field_validator("ssh_host", "ssh_user", "ssh_key_ref")
    @classmethod
    def validate_optional_ssh_text(cls, value: str | None) -> str | None:
        if value is not None and (not value or _has_control_character(value)):
            raise ValueError("SSH profile fields must be non-empty and must not contain control characters")
        return value

    @field_validator("ssh_options")
    @classmethod
    def validate_ssh_options(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            if key not in _ALLOWED_SSH_OPTIONS:
                raise ValueError(f"unsupported SSH option: {key}")
            if not key or any(char.isspace() or unicodedata.category(char) == "Cc" for char in key):
                raise ValueError("SSH option names must be simple names")
            if not item or _has_control_character(item):
                raise ValueError(f"invalid SSH option value for {key}")
            rule = _ALLOWED_SSH_OPTIONS[key]
            if rule.get("validator") == "timeout":
                try:
                    parsed = int(item)
                except ValueError as exc:
                    raise ValueError("ConnectTimeout must be an integer") from exc
                if parsed < 1 or parsed > 3600:
                    raise ValueError("ConnectTimeout must be between 1 and 3600 seconds")
            elif item not in rule["values"]:
                raise ValueError(f"invalid SSH option value for {key}")
        return value
```

Extend `ServerConfig`:

```python
class ServerConfig(ConfigModel):
    artifact_root: Path
    build_profiles: dict[str, BuildProfile] = Field(default_factory=dict)
    rootfs_profiles: dict[str, RootfsProfile] = Field(default_factory=dict)
    target_profiles: dict[str, TargetProfile] = Field(default_factory=dict)
    debug_profiles: dict[str, DebugProfile] = Field(default_factory=dict)
    test_suites: dict[str, TestSuiteProfile] = Field(default_factory=dict)
    artifact_policy: ArtifactPolicy = Field(default_factory=ArtifactPolicy)
    logging_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    sensitive_paths: list[Path] = Field(default_factory=list)

    @field_validator("build_profiles", "rootfs_profiles", "target_profiles", "debug_profiles", "test_suites")
    @classmethod
    def profile_keys_match_names(cls, value: dict[str, ConfigModel], info: ValidationInfo) -> dict[str, ConfigModel]:
        for key, profile in value.items():
            if key != profile.name:
                raise ValueError(f"{info.field_name} profile key must match profile name")
        return value
```

- [ ] **Step 4: Run config tests**

Run:

```bash
pytest tests/test_config.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/config.py tests/test_config.py
git commit -m "feat: add smoke test profile models"
```

## Task 2: Add Test And Collection Locks

**Files:**
- Modify: `src/linux_debug_mcp/artifacts/store.py`
- Modify: `tests/test_artifacts.py`

- [ ] **Step 1: Write failing lock tests**

Add these tests to `tests/test_artifacts.py`:

```python
def test_tests_lock_excludes_concurrent_test_runs(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    with (
        store.tests_lock("run-abc123"),
        pytest.raises(ManifestStateError, match="tests are locked"),
        store.tests_lock("run-abc123"),
    ):
        pass


def test_collect_lock_excludes_concurrent_collection(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    with (
        store.collect_lock("run-abc123"),
        pytest.raises(ManifestStateError, match="artifact collection is locked"),
        store.collect_lock("run-abc123"),
    ):
        pass
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
pytest tests/test_artifacts.py::test_tests_lock_excludes_concurrent_test_runs tests/test_artifacts.py::test_collect_lock_excludes_concurrent_collection -q
```

Expected: FAIL because `tests_lock()` and `collect_lock()` do not exist.

- [ ] **Step 3: Implement locks**

Add these methods to `ArtifactStore` after `boot_lock()`:

```python
@contextmanager
def tests_lock(self, run_id: str) -> Iterator[None]:
    run_dir = self._run_dir(run_id)
    with self._file_lock(
        run_dir / ".tests.lock",
        locked_message="tests are locked",
        failure_prefix="failed to lock tests",
    ):
        yield


@contextmanager
def collect_lock(self, run_id: str) -> Iterator[None]:
    run_dir = self._run_dir(run_id)
    with self._file_lock(
        run_dir / ".collect.lock",
        locked_message="artifact collection is locked",
        failure_prefix="failed to lock artifact collection",
    ):
        yield
```

- [ ] **Step 4: Run artifact tests**

Run:

```bash
pytest tests/test_artifacts.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/artifacts/store.py tests/test_artifacts.py
git commit -m "feat: add test and collection locks"
```

## Task 3: Implement Local SSH Test Provider

**Files:**
- Create: `src/linux_debug_mcp/providers/local_ssh_tests.py`
- Create: `tests/test_local_ssh_tests_provider.py`

- [ ] **Step 1: Write fake-runner provider tests**

Create `tests/test_local_ssh_tests_provider.py` with these fixtures and representative tests:

```python
from dataclasses import dataclass
from pathlib import Path

import pytest

from linux_debug_mcp.config import RootfsProfile, TestCommand, TestSuiteProfile
from linux_debug_mcp.domain import ErrorCategory, StepStatus
from linux_debug_mcp.providers.local_ssh_tests import LocalSshTestProvider, SshCommandResult


@dataclass
class FakeSshRunner:
    available: bool = True
    results: list[SshCommandResult] | None = None
    calls: list[dict[str, object]] | None = None

    def __post_init__(self) -> None:
        self.results = self.results or []
        self.calls = []

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}" if self.available else None

    def run(self, argv: list[str], *, timeout: int, stdout_path: Path, stderr_path: Path) -> SshCommandResult:
        self.calls.append({"argv": argv, "timeout": timeout, "stdout_path": stdout_path, "stderr_path": stderr_path})
        result = self.results.pop(0) if self.results else SshCommandResult(exit_status=0, stdout="ok\n", stderr="")
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        return result


def rootfs(**kwargs: object) -> RootfsProfile:
    return RootfsProfile(
        name="minimal",
        source="/tmp/rootfs.qcow2",
        access_method="ssh_and_serial",
        ssh_host="127.0.0.1",
        ssh_port=2222,
        ssh_user="root",
        **kwargs,
    )


def suite(**kwargs: object) -> TestSuiteProfile:
    return TestSuiteProfile(
        name="smoke-basic",
        commands=[TestCommand(name="uname", argv=["uname", "-a"])],
        **kwargs,
    )


def test_plan_rejects_rootfs_without_ssh_access(tmp_path: Path) -> None:
    provider = LocalSshTestProvider(runner=FakeSshRunner())

    with pytest.raises(ValueError, match="SSH access"):
        provider.plan_tests(
            run_id="run-abc123",
            run_dir=tmp_path,
            rootfs_profile=rootfs(access_method="serial"),
            suite=suite(),
            adhoc_commands=[],
            attempt=1,
        )


def test_plan_builds_ssh_argv_with_quoted_remote_command_and_provider_defaults(tmp_path: Path) -> None:
    provider = LocalSshTestProvider(runner=FakeSshRunner())
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(ssh_key_ref="/tmp/id_ed25519"),
        suite=suite(),
        adhoc_commands=[],
        attempt=1,
    )

    command = plan.commands[0]
    assert command.ssh_argv[:2] == ["ssh", "-o"]
    assert "BatchMode=yes" in command.ssh_argv
    assert "UserKnownHostsFile=" + str(tmp_path / "target" / "known_hosts") in command.ssh_argv
    assert "-i" in command.ssh_argv
    assert command.ssh_argv[-3:] == ["root@127.0.0.1", "--", "uname -a"]


def test_plan_allows_adhoc_only_without_default_suite_commands(tmp_path: Path) -> None:
    provider = LocalSshTestProvider(runner=FakeSshRunner())
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(),
        suite=None,
        adhoc_commands=[TestCommand(name="adhoc-001", argv=["id"], required=True)],
        attempt=1,
    )

    assert plan.suite_name == "adhoc"
    assert [command.label for command in plan.commands] == ["adhoc-001"]
    assert plan.commands[0].argv == ["id"]


def test_execute_success_writes_per_command_artifacts_and_summary(tmp_path: Path) -> None:
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout="Linux test\n", stderr="")])
    provider = LocalSshTestProvider(runner=runner)
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(),
        suite=suite(collect_dmesg=False),
        adhoc_commands=[],
        attempt=1,
    )

    result = provider.execute_tests(plan)

    assert result.status == StepStatus.SUCCEEDED
    assert (tmp_path / "tests" / "attempt-001" / "001-uname" / "stdout.txt").read_text() == "Linux test\n"
    assert (tmp_path / "tests" / "attempt-001" / "001-uname" / "command.json").is_file()
    assert (tmp_path / "summaries" / "test-summary.json").is_file()
    assert any(artifact.kind == "test-summary" for artifact in result.artifacts)


def test_execute_missing_ssh_writes_failed_summary(tmp_path: Path) -> None:
    runner = FakeSshRunner(available=False)
    provider = LocalSshTestProvider(runner=runner)
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(),
        suite=suite(collect_dmesg=False),
        adhoc_commands=[],
        attempt=1,
    )

    result = provider.execute_tests(plan)

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.MISSING_DEPENDENCY
    assert (tmp_path / "summaries" / "test-summary.json").is_file()
    assert any(artifact.kind == "test-summary" for artifact in result.artifacts)


def test_execute_required_failure_stops_when_stop_on_failure_is_true(tmp_path: Path) -> None:
    runner = FakeSshRunner(
        results=[
            SshCommandResult(exit_status=1, stdout="", stderr="failed\n"),
            SshCommandResult(exit_status=0, stdout="should not run\n", stderr=""),
        ]
    )
    provider = LocalSshTestProvider(runner=runner)
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(),
        suite=TestSuiteProfile(
            name="smoke-basic",
            commands=[
                TestCommand(name="first", argv=["false"]),
                TestCommand(name="second", argv=["true"]),
            ],
            stop_on_failure=True,
            collect_dmesg=False,
        ),
        adhoc_commands=[],
        attempt=1,
    )

    result = provider.execute_tests(plan)

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.TEST_FAILURE
    assert len(runner.calls) == 1


def test_execute_collects_dmesg_without_failing_smoke_result(tmp_path: Path) -> None:
    runner = FakeSshRunner(
        results=[
            SshCommandResult(exit_status=0, stdout="ok\n", stderr=""),
            SshCommandResult(exit_status=1, stdout="", stderr="permission denied\n"),
        ]
    )
    provider = LocalSshTestProvider(runner=runner)
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(),
        suite=suite(collect_dmesg=True),
        adhoc_commands=[],
        attempt=1,
    )

    result = provider.execute_tests(plan)

    assert result.status == StepStatus.SUCCEEDED
    assert (tmp_path / "tests" / "attempt-001" / "dmesg.txt").is_file()
    assert result.details["dmesg"]["exit_status"] == 1


def test_summary_redacts_key_path_and_secret_like_output(tmp_path: Path) -> None:
    runner = FakeSshRunner(
        results=[
            SshCommandResult(exit_status=0, stdout="API_TOKEN=abc123 password=hunter2\n", stderr=""),
        ]
    )
    provider = LocalSshTestProvider(runner=runner)
    key_path = "/tmp/id_ed25519"
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(ssh_key_ref=key_path),
        suite=suite(collect_dmesg=False),
        adhoc_commands=[],
        attempt=1,
    )

    provider.execute_tests(plan)

    command_metadata = (tmp_path / "tests" / "attempt-001" / "001-uname" / "command.json").read_text(
        encoding="utf-8"
    )
    summary = (tmp_path / "summaries" / "test-summary.json").read_text(encoding="utf-8")
    combined = command_metadata + summary
    assert key_path not in combined
    assert "abc123" not in combined
    assert "hunter2" not in combined
    assert "[REDACTED]" in combined
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
pytest tests/test_local_ssh_tests_provider.py -q
```

Expected: FAIL because the provider module does not exist.

- [ ] **Step 3: Implement provider data types and planning**

Create `src/linux_debug_mcp/providers/local_ssh_tests.py` with these public data types:

```python
from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from linux_debug_mcp.config import RootfsProfile, TestCommand, TestSuiteProfile
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, OperationSemantics, ProviderCapability, StepStatus, TargetKind
from linux_debug_mcp.safety.redaction import Redactor


@dataclass(frozen=True)
class PlannedTestCommand:
    label: str
    argv: list[str]
    ssh_argv: list[str]
    timeout_seconds: int
    required: bool
    stdout_path: Path
    stderr_path: Path
    metadata_path: Path


@dataclass(frozen=True)
class TestPlan:
    run_id: str
    provider_name: str
    suite_name: str
    attempt: int
    attempt_dir: Path
    known_hosts_path: Path
    summary_path: Path
    commands: list[PlannedTestCommand]
    dmesg_command: PlannedTestCommand | None
    stop_on_failure: bool
    redactor: Redactor


@dataclass(frozen=True)
class SshCommandResult:
    exit_status: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


@dataclass(frozen=True)
class TestExecutionResult:
    status: StepStatus
    summary: str
    artifacts: list[ArtifactRef] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)
    error_category: ErrorCategory | None = None
    diagnostic: str | None = None


class SshRunner(Protocol):
    def which(self, command: str) -> str | None:
        raise NotImplementedError

    def run(self, argv: list[str], *, timeout: int, stdout_path: Path, stderr_path: Path) -> SshCommandResult:
        raise NotImplementedError
```

Implement `SubprocessSshRunner`:

```python
class SubprocessSshRunner:
    def which(self, command: str) -> str | None:
        return shutil.which(command)

    def run(self, argv: list[str], *, timeout: int, stdout_path: Path, stderr_path: Path) -> SshCommandResult:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with stdout_path.open("w", encoding="utf-8") as stdout_file, stderr_path.open("w", encoding="utf-8") as stderr_file:
                completed = subprocess.run(
                    argv,
                    check=False,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    text=True,
                    timeout=timeout,
                    shell=False,
                )
            return SshCommandResult(
                exit_status=completed.returncode,
                stdout=stdout_path.read_text(encoding="utf-8", errors="replace"),
                stderr=stderr_path.read_text(encoding="utf-8", errors="replace"),
            )
        except subprocess.TimeoutExpired as exc:
            stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""
            stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
            return SshCommandResult(exit_status=-1, stdout=stdout_text, stderr=stderr_text, timed_out=True)
```

Implement `LocalSshTestProvider.plan_tests()` with `suite: TestSuiteProfile | None` using:

```python
remote_command = " ".join(shlex.quote(item) for item in command.argv)
connect_timeout = rootfs_profile.ssh_options.get("ConnectTimeout", str(min(command_timeout, 10)))
strict_host_key_checking = rootfs_profile.ssh_options.get("StrictHostKeyChecking", "accept-new")
ssh_argv = [
    "ssh",
    "-o",
    "BatchMode=yes",
    "-o",
    f"UserKnownHostsFile={known_hosts_path}",
    "-o",
    f"ConnectTimeout={connect_timeout}",
    "-o",
    f"StrictHostKeyChecking={strict_host_key_checking}",
]
```

Rules:
- Reject `rootfs_profile.access_method` unless it is `ssh` or `ssh_and_serial`.
- Reject missing `ssh_host` or `ssh_user` with `ValueError("rootfs profile requires ssh_host and ssh_user for SSH test execution")`.
- Merge provider-owned defaults with profile-owned options; provider-owned `BatchMode` and `UserKnownHostsFile` must not be profile-overridable.
- Use `ConnectTimeout=min(command_timeout, 10)` unless the profile specifies a smaller valid value; if a profile `ConnectTimeout` is greater than a command timeout, raise `ValueError("ConnectTimeout cannot exceed command timeout")`.
- Add `-p <port>`, optional `-i <ssh_key_ref>`, profile `-o key=value` options, destination `<user>@<host>`, `--`, and the quoted remote command.
- If `suite is None`, do not add default suite commands in the provider; set `suite_name="adhoc"` and plan only the supplied ad hoc commands.
- If `suite is not None`, plan suite commands first with numbered labels such as `001-uname`; append ad hoc commands as `adhoc-001`, `adhoc-002`, and mark them required.
- Put command files under `<run>/tests/attempt-NNN/<label>/stdout.txt`, `stderr.txt`, and `command.json`.
- Put dmesg at `<run>/tests/attempt-NNN/dmesg.txt` and `<run>/tests/attempt-NNN/dmesg.stderr.txt` when the named suite has `collect_dmesg=True`; for ad hoc-only execution, set `collect_dmesg=True` so failed ad hoc smoke runs still preserve guest kernel diagnostics.
- Build `TestPlan.redactor = Redactor(secret_values=[rootfs_profile.ssh_key_ref] if rootfs_profile.ssh_key_ref else [])` during planning. Do not wait for a later redaction task; command metadata and summaries written by this provider must be redacted from the first provider implementation.

- [ ] **Step 4: Implement execution and summary writing**

Implement `LocalSshTestProvider.execute_tests(plan)`:

```python
def execute_tests(self, plan: TestPlan) -> TestExecutionResult:
    started_at = datetime.now(UTC)
    plan.attempt_dir.mkdir(parents=True, exist_ok=True)
    plan.summary_path.parent.mkdir(parents=True, exist_ok=True)
    if self.runner.which("ssh") is None:
        artifacts = [ArtifactRef(path=str(plan.summary_path), kind="test-summary")]
        payload = {
            "run_id": plan.run_id,
            "provider": plan.provider_name,
            "suite": plan.suite_name,
            "attempt": plan.attempt,
            "started_at": started_at.isoformat(),
            "ended_at": datetime.now(UTC).isoformat(),
            "status": StepStatus.FAILED,
            "error_category": ErrorCategory.MISSING_DEPENDENCY,
            "missing_tools": ["ssh"],
            "commands": [],
            "dmesg": None,
            "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
        }
        plan.summary_path.write_text(json.dumps(plan.redactor.redact_value(payload), indent=2, default=str), encoding="utf-8")
        return TestExecutionResult(
            status=StepStatus.FAILED,
            summary="missing required SSH tools",
            error_category=ErrorCategory.MISSING_DEPENDENCY,
            details={"missing_tools": ["ssh"]},
            artifacts=artifacts,
        )
    command_results = []
    required_failed = False
    for command in plan.commands:
        started = datetime.now(UTC)
        result = self.runner.run(
            command.ssh_argv,
            timeout=command.timeout_seconds,
            stdout_path=command.stdout_path,
            stderr_path=command.stderr_path,
        )
        ended = datetime.now(UTC)
        metadata = self._command_metadata(command=command, result=result, started_at=started, ended_at=ended)
        command.metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        command_results.append(metadata)
        if command.required and (result.exit_status != 0 or result.timed_out):
            required_failed = True
            if plan.stop_on_failure:
                break
    dmesg_result = self._run_dmesg(plan) if plan.dmesg_command is not None else None
    artifacts = self._existing_artifacts(plan)
    ended_at = datetime.now(UTC)
    status = StepStatus.FAILED if required_failed else StepStatus.SUCCEEDED
    payload = {
        "run_id": plan.run_id,
        "provider": plan.provider_name,
        "suite": plan.suite_name,
        "attempt": plan.attempt,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "status": status,
        "commands": command_results,
        "dmesg": dmesg_result,
        "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
    }
    plan.summary_path.write_text(json.dumps(plan.redactor.redact_value(payload), indent=2, default=str), encoding="utf-8")
    passed = sum(1 for item in command_results if item["exit_status"] == 0 and not item["timed_out"])
    failed = len(command_results) - passed
    return TestExecutionResult(
        status=status,
        summary=f"test suite {plan.suite_name} {'passed' if status == StepStatus.SUCCEEDED else 'failed'}: {passed} passed, {failed} failed",
        artifacts=artifacts,
        details={"suite": plan.suite_name, "attempt": plan.attempt, "counts": {"passed": passed, "failed": failed}, "commands": command_results, "dmesg": dmesg_result},
        error_category=ErrorCategory.TEST_FAILURE if status == StepStatus.FAILED else None,
        diagnostic=self._first_failure_snippet(command_results),
    )
```

Make `_command_metadata()` include `label`, redacted `argv`, redacted `ssh_argv`, `exit_status`, `timed_out`, `elapsed_seconds`, `stdout_path`, `stderr_path`, redacted bounded `stdout_snippet`, and redacted bounded `stderr_snippet`. Write `command.json` from already-redacted metadata by calling `plan.redactor.redact_value()` before serialization.

- [ ] **Step 5: Add provider capability**

Add:

```python
def local_ssh_tests_capability() -> ProviderCapability:
    return ProviderCapability(
        provider_name="local-ssh-tests",
        provider_version="0.1.0",
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        operations=["target.run_tests"],
        required_host_tools=["ssh"],
        destructive_permissions=[],
        access_methods=["ssh", "filesystem"],
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=False,
            cancelable=False,
            concurrent_safe=False,
        ),
    )
```

- [ ] **Step 6: Run provider tests**

Run:

```bash
pytest tests/test_local_ssh_tests_provider.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/linux_debug_mcp/providers/local_ssh_tests.py tests/test_local_ssh_tests_provider.py
git commit -m "feat: add local SSH smoke test provider"
```

## Task 4: Register Provider And Default Smoke Suite

**Files:**
- Modify: `src/linux_debug_mcp/providers/registry.py`
- Modify: `src/linux_debug_mcp/server.py`
- Modify: `tests/test_providers.py`
- Modify: `tests/test_server.py`

- [ ] **Step 1: Write failing provider and default tests**

Update `tests/test_server.py::test_list_providers_handler_returns_default_capabilities` to expect `local-ssh-tests` and remove `target.run_tests` from the stub operation assertion if one exists:

```python
assert {provider["provider_name"] for provider in response.data["providers"]} == {
    "local-artifacts",
    "local-kernel-build",
    "local-libvirt-qemu",
    "local-prereqs",
    "local-ssh-tests",
    "stub-workflows",
}
```

Add:

```python
from linux_debug_mcp.server import DEFAULT_TEST_SUITES


def test_default_smoke_basic_suite_matches_sprint_3_contract() -> None:
    suite = DEFAULT_TEST_SUITES["smoke-basic"]

    assert [command.argv for command in suite.commands] == [
        ["uname", "-a"],
        ["test", "-r", "/proc/version"],
        ["cat", "/proc/cmdline"],
    ]
    assert suite.timeout_seconds == 30
    assert suite.stop_on_failure is True
    assert suite.collect_dmesg is True
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
pytest tests/test_server.py tests/test_providers.py -q
```

Expected: FAIL because `local-ssh-tests` and `DEFAULT_TEST_SUITES` are not wired.

- [ ] **Step 3: Register provider and defaults**

In `src/linux_debug_mcp/providers/registry.py`:

```python
from linux_debug_mcp.providers.local_ssh_tests import local_ssh_tests_capability
```

Register `local_ssh_tests_capability()` before `stub-workflows`, and remove `target.run_tests` from the stub operations list.

In `src/linux_debug_mcp/server.py`, import `TestCommand` and `TestSuiteProfile` and add:

```python
DEFAULT_TEST_SUITES = {
    "smoke-basic": TestSuiteProfile(
        name="smoke-basic",
        timeout_seconds=30,
        stop_on_failure=True,
        collect_dmesg=True,
        commands=[
            TestCommand(name="uname", argv=["uname", "-a"]),
            TestCommand(name="proc-version", argv=["test", "-r", "/proc/version"]),
            TestCommand(name="proc-cmdline", argv=["cat", "/proc/cmdline"]),
        ],
    )
}
```

Extend `DEFAULT_ROOTFS_PROFILES["minimal"]` so Sprint 3 smoke tests have explicit SSH fields:

```python
ssh_host="127.0.0.1",
ssh_port=22,
ssh_user="root",
```

- [ ] **Step 4: Run tests**

Run:

```bash
pytest tests/test_server.py tests/test_providers.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/registry.py src/linux_debug_mcp/server.py tests/test_providers.py tests/test_server.py
git commit -m "feat: register SSH smoke test provider"
```

## Task 5: Implement target.run_tests Handler

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Create: `tests/test_target_run_tests_handler.py`

- [ ] **Step 1: Write failing handler tests**

Create `tests/test_target_run_tests_handler.py` with fake provider, run setup, and tests:

```python
from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import RootfsProfile, TestCommand, TestSuiteProfile
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus
from linux_debug_mcp.providers.local_ssh_tests import TestExecutionResult
from linux_debug_mcp.server import create_run_handler, target_run_tests_handler


class FakeTestProvider:
    name = "local-ssh-tests"

    def __init__(self, *, result: TestExecutionResult | None = None) -> None:
        self.result = result or TestExecutionResult(
            status=StepStatus.SUCCEEDED,
            summary="test suite smoke-basic passed: 1 passed, 0 failed",
            artifacts=[],
            details={"counts": {"passed": 1, "failed": 0}, "commands": []},
        )
        self.plans: list[dict[str, object]] = []
        self.executions = 0

    def plan_tests(self, **kwargs: object) -> object:
        self.plans.append(kwargs)
        return {"plan": kwargs}

    def execute_tests(self, plan: object) -> TestExecutionResult:
        self.executions += 1
        return self.result


def make_source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "linux"
    source.mkdir(parents=True)
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    return source


def create_booted_run(tmp_path: Path, *, run_id: str = "run-abc123", test_suite: str | None = None) -> Path:
    source = make_source_tree(tmp_path / run_id)
    artifact_root = tmp_path / "runs"
    response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id=run_id,
        test_suite=test_suite,
    )
    assert response.ok is True
    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(run_id, StepResult(step_name="build", status=StepStatus.SUCCEEDED, summary="build ok"))
    store.record_step_result(run_id, StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="boot ok"))
    return artifact_root


def rootfs(tmp_path: Path) -> RootfsProfile:
    return RootfsProfile(
        name="minimal",
        source=str(tmp_path / "rootfs.qcow2"),
        access_method="ssh_and_serial",
        ssh_host="127.0.0.1",
        ssh_user="root",
    )


def suites() -> dict[str, TestSuiteProfile]:
    return {
        "smoke-basic": TestSuiteProfile(
            name="smoke-basic",
            commands=[TestCommand(name="uname", argv=["uname", "-a"])],
        )
    }


def test_run_tests_requires_existing_run(tmp_path: Path) -> None:
    response = target_run_tests_handler(artifact_root=tmp_path / "runs", run_id="run-missing")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_run_tests_requires_succeeded_boot(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"
    create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )

    response = target_run_tests_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert "succeeded boot" in response.error.message


def test_run_tests_executes_default_suite_after_boot(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider()

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is True
    assert response.suggested_next_actions == ["artifacts.collect"]
    assert provider.plans[0]["suite"].name == "smoke-basic"
    assert provider.executions == 1


def test_run_tests_adhoc_only_does_not_add_default_suite(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider()

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        commands=[["id"]],
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is True
    assert provider.plans[0]["suite"] is None
    assert [command.argv for command in provider.plans[0]["adhoc_commands"]] == [["id"]]


def test_run_tests_rejects_manifest_test_suite_mismatch(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path, test_suite="smoke-basic")

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        test_suite="other-suite",
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
        provider=FakeTestProvider(),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "test_suite must match" in response.error.message


def test_run_tests_returns_recorded_success_without_force_rerun(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider()
    first = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )
    second = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert first.ok is True
    assert second.ok is True
    assert provider.executions == 1


def test_run_tests_force_rerun_replaces_success(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider()

    target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )
    target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        force_rerun=True,
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert provider.executions == 2


def test_run_tests_maps_provider_failure_to_test_failure(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider(
        result=TestExecutionResult(
            status=StepStatus.FAILED,
            summary="test suite smoke-basic failed: 0 passed, 1 failed",
            artifacts=[ArtifactRef(path=str(artifact_root / "run-abc123" / "tests" / "attempt-001" / "001-uname" / "stderr.txt"), kind="test-stderr")],
            details={"counts": {"passed": 0, "failed": 1}, "commands": [{"label": "001-uname"}]},
            error_category=ErrorCategory.TEST_FAILURE,
            diagnostic="failed",
        )
    )

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "test_failure"
    assert response.suggested_next_actions == ["artifacts.collect"]
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
pytest tests/test_target_run_tests_handler.py -q
```

Expected: FAIL because `target_run_tests_handler()` does not exist.

- [ ] **Step 3: Implement handler helpers**

In `server.py`, import `LocalSshTestProvider`, `TestExecutionResult`, and config models. Add helpers:

```python
def _recorded_test_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.success(
        summary=result.summary,
        run_id=run_id,
        data=result.details,
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.collect"],
    )


def _next_test_attempt(run_dir: Path) -> int:
    attempts = []
    tests_dir = run_dir / "tests"
    if tests_dir.exists():
        for path in tests_dir.glob("attempt-*"):
            try:
                attempts.append(int(path.name.removeprefix("attempt-")))
            except ValueError:
                continue
    return max(attempts, default=0) + 1
```

Add `_validate_adhoc_commands(commands: list[list[str]] | None) -> list[TestCommand]` that rejects empty argv, empty items, and control characters, then returns `TestCommand(name=f"adhoc-{index:03d}", argv=argv, required=True)` objects.

- [ ] **Step 4: Implement `target_run_tests_handler()`**

Add a handler with this signature:

```python
def target_run_tests_handler(
    *,
    artifact_root: Path,
    run_id: str,
    test_suite: str | None = None,
    commands: list[list[str]] | None = None,
    force_rerun: bool = False,
    provider: LocalSshTestProvider | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    test_suites: dict[str, TestSuiteProfile] | None = None,
) -> ToolResponse:
```

Behavior:
- Load `ArtifactStore(artifact_root, create_root=False)` and return `configuration_error` if `manifest.json` is absent.
- Require `manifest.step_results["boot"].status == StepStatus.SUCCEEDED`.
- Resolve ad hoc commands through `_validate_adhoc_commands` before selecting a suite.
- Resolve requested suite as `test_suite or manifest.request.test_suite`; if that value is still `None` and there are no ad hoc commands, use `"smoke-basic"`.
- If `manifest.request.test_suite` is set and requested suite differs, return `configuration_error`.
- Resolve rootfs profile and reject access method not in `{"ssh", "ssh_and_serial"}`.
- Resolve `suite_profile = test_suites[requested_suite]` when a requested suite exists; otherwise pass `suite=None` to the provider.
- If a succeeded `run_tests` result exists and `force_rerun` is false, return the recorded response.
- If an existing `RUNNING` result is found and `tests_lock()` cannot be acquired, return `infrastructure_failure` with the running result details.
- While holding `tests_lock()`, convert stale `RUNNING` to failed only after the lock is acquired.
- Record a running `StepResult` before provider execution.
- Call:

```python
plan = provider.plan_tests(
    run_id=run_id,
    run_dir=store.run_dir(run_id),
    rootfs_profile=resolved_rootfs_profile,
    suite=suite_profile,
    adhoc_commands=adhoc_commands,
    attempt=_next_test_attempt(store.run_dir(run_id)),
)
execution = provider.execute_tests(plan)
```

- Record terminal results with:

```python
terminal = StepResult(
    step_name="run_tests",
    status=execution.status,
    summary=execution.summary,
    artifacts=execution.artifacts,
    details=execution.details,
)
store.record_step_result(run_id, terminal, replace_succeeded=force_rerun)
```
- Return success if provider status succeeded; otherwise return failure with `execution.error_category or ErrorCategory.TEST_FAILURE`.

- [ ] **Step 5: Run handler tests**

Run:

```bash
pytest tests/test_target_run_tests_handler.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_target_run_tests_handler.py
git commit -m "feat: add target run tests handler"
```

## Task 6: Wire target.run_tests MCP Tool

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Modify: `tests/test_server.py`

- [ ] **Step 1: Write failing tool registration test**

In `tests/test_server.py`, add a helper that inspects FastMCP's local tool registry:

```python
def tool_names() -> set[str]:
    return set(create_app()._tool_manager._tools)
```

Then replace the current stub assertion for `target.run_tests` with:

```python
def test_target_run_tests_tool_is_registered_with_full_arguments() -> None:
    app = create_app()
    tool = app._tool_manager._tools["target.run_tests"]

    assert "target.run_tests" in tool_names()
    assert "force_rerun" in tool.parameters["properties"]
    assert "commands" in tool.parameters["properties"]
    assert tool.fn.__name__ == "target_run_tests"
```

Keep one focused serialization guard for handler responses:

```python
def test_target_run_tests_handler_response_serializes(tmp_path: Path) -> None:
    source, artifact_root = create_test_run(tmp_path)
    store = ArtifactStore(artifact_root, source_paths=[source])
    store.record_step_result("run-abc123", StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="boot ok"))

    response = get_manifest_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.model_dump(mode="json")["run_id"] == "run-abc123"
```

- [ ] **Step 2: Run tests and confirm current stubs**

Run:

```bash
pytest tests/test_server.py -q
```

Expected: FAIL until `target.run_tests` is removed from the stub loop and registered as a real tool.

- [ ] **Step 3: Wire MCP tool**

In `create_app()`, add before `make_stub()`:

```python
@app.tool(name="target.run_tests")
def target_run_tests(
    run_id: str,
    artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
    test_suite: str | None = None,
    commands: list[list[str]] | None = None,
    force_rerun: bool = False,
) -> dict[str, Any]:
    return target_run_tests_handler(
        artifact_root=Path(artifact_root),
        run_id=run_id,
        test_suite=test_suite,
        commands=commands,
        force_rerun=force_rerun,
    ).model_dump(mode="json")
```

Remove `"target.run_tests"` from the stub loop.

- [ ] **Step 4: Run server tests**

Run:

```bash
pytest tests/test_server.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server.py
git commit -m "feat: expose target run tests tool"
```

## Task 7: Implement Artifact Collection Handler

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Create: `tests/test_artifacts_collect_handler.py`

- [ ] **Step 1: Write failing collection tests**

Create `tests/test_artifacts_collect_handler.py`:

```python
from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import ArtifactRef, StepResult, StepStatus
from linux_debug_mcp.server import artifacts_collect_handler, create_run_handler


def make_source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "linux"
    source.mkdir(parents=True)
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    return source


def create_run(tmp_path: Path) -> Path:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"
    response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )
    assert response.ok is True
    return artifact_root


def test_collect_artifacts_writes_bundle_for_existing_manifest_refs(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    build_log = artifact_root / "run-abc123" / "logs" / "build.log"
    kernel_config = artifact_root / "run-abc123" / "build" / ".config"
    kernel_image = artifact_root / "run-abc123" / "build" / "arch" / "x86" / "boot" / "bzImage"
    build_log.write_text("build\n", encoding="utf-8")
    kernel_config.parent.mkdir(parents=True, exist_ok=True)
    kernel_config.write_text("CONFIG_TEST=y\n", encoding="utf-8")
    kernel_image.parent.mkdir(parents=True, exist_ok=True)
    kernel_image.write_text("kernel\n", encoding="utf-8")
    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(
        "run-abc123",
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="build ok",
            artifacts=[
                ArtifactRef(path=str(build_log), kind="build-log"),
                ArtifactRef(path=str(kernel_config), kind="kernel-config"),
                ArtifactRef(path=str(kernel_image), kind="kernel-image"),
            ],
        ),
    )

    response = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is True
    bundle_path = artifact_root / "run-abc123" / "summaries" / "artifact-bundle.json"
    assert bundle_path.is_file()
    assert any(artifact.kind == "artifact-bundle" for artifact in response.artifacts)
    assert response.data["rollup"]["missing_required"] == 0


def test_collect_artifacts_fails_when_succeeded_step_reference_is_missing(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    missing = artifact_root / "run-abc123" / "logs" / "missing-build.log"
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        "run-abc123",
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="build ok",
            artifacts=[ArtifactRef(path=str(missing), kind="build-log")],
        ),
    )

    response = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert any(artifact.kind == "artifact-bundle" for artifact in response.artifacts)
    assert response.error.details["rollup"]["missing_required"] >= 1


def test_collect_artifacts_fails_when_succeeded_build_omits_required_artifact_kind(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    build_log = artifact_root / "run-abc123" / "logs" / "build.log"
    build_log.write_text("build\n", encoding="utf-8")
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        "run-abc123",
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="build ok",
            artifacts=[ArtifactRef(path=str(build_log), kind="build-log")],
        ),
    )

    response = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"
    assert "kernel-config" in str(response.error.details)
    assert "kernel-image" in str(response.error.details)


def test_collect_artifacts_returns_recorded_success_without_force_recollect(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    first = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")
    second = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert first.ok is True
    assert second.ok is True
    assert second.summary == first.summary


def test_collect_artifacts_force_recollect_rewrites_bundle(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    first = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123")
    bundle_path = artifact_root / "run-abc123" / "summaries" / "artifact-bundle.json"
    old_text = bundle_path.read_text(encoding="utf-8")
    bundle_path.write_text('{"stale": true}', encoding="utf-8")

    second = artifacts_collect_handler(artifact_root=artifact_root, run_id="run-abc123", force_recollect=True)

    assert first.ok is True
    assert second.ok is True
    assert bundle_path.read_text(encoding="utf-8") != '{"stale": true}'
    assert bundle_path.read_text(encoding="utf-8") == old_text or "collected_at" in bundle_path.read_text(encoding="utf-8")
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
pytest tests/test_artifacts_collect_handler.py -q
```

Expected: FAIL because `artifacts_collect_handler()` does not exist.

- [ ] **Step 3: Implement bundle construction**

In `server.py`, add:

```python
def _bundle_for_manifest(*, manifest: RunManifest, run_dir: Path, bundle_path: Path) -> tuple[dict[str, Any], list[ArtifactRef], list[dict[str, Any]], list[dict[str, Any]]]:
    required_kinds_by_step = {
        "build": {"build-log", "kernel-config", "kernel-image"},
        "boot": {"domain-xml", "boot-plan", "console-log", "boot-log"},
        "run_tests": {"test-summary"},
    }
    optional_kinds_by_step = {"build": {"vmlinux"}}
    grouped: dict[str, list[dict[str, Any]]] = {}
    missing_required: list[dict[str, Any]] = []
    missing_optional: list[dict[str, Any]] = []
    collected_refs: list[ArtifactRef] = []
    for step in manifest.steps:
        result = manifest.step_results.get(step.name)
        grouped[step.name] = []
        if result is None:
            continue
        present_kinds = {artifact.kind for artifact in result.artifacts}
        if result.status == StepStatus.SUCCEEDED:
            for kind in sorted(required_kinds_by_step.get(step.name, set()) - present_kinds):
                missing_required.append({"step": step.name, "kind": kind, "reason": "required artifact kind was not recorded"})
            for kind in sorted(optional_kinds_by_step.get(step.name, set()) - present_kinds):
                missing_optional.append({"step": step.name, "kind": kind, "reason": "optional artifact kind was not recorded"})
        for artifact in result.artifacts:
            exists = Path(artifact.path).is_file()
            item = {**artifact.model_dump(mode="json"), "exists": exists}
            grouped[step.name].append(item)
            if exists:
                collected_refs.append(artifact)
            elif result.status == StepStatus.SUCCEEDED and artifact.kind not in optional_kinds_by_step.get(step.name, set()):
                missing_required.append({"step": step.name, "artifact": artifact.model_dump(mode="json")})
            else:
                missing_optional.append({"step": step.name, "artifact": artifact.model_dump(mode="json")})
    bundle_ref = ArtifactRef(path=str(bundle_path), kind="artifact-bundle")
    bundle = {
        "run_id": manifest.run_id,
        "collected_at": datetime.now(UTC).isoformat(),
        "selected_profiles": manifest.request.model_dump(mode="json"),
        "steps": {step.name: step.status for step in manifest.steps},
        "summaries": {
            name: {"status": result.status, "summary": result.summary}
            for name, result in manifest.step_results.items()
        },
        "artifacts_by_step": grouped,
        "missing_expected_artifacts": missing_required,
        "missing_optional_artifacts": missing_optional,
        "cleanup_state": manifest.cleanup_state,
        "rollup": {
            "ok": not missing_required,
            "missing_required": len(missing_required),
            "missing_optional": len(missing_optional),
        },
    }
    return bundle, [*collected_refs, bundle_ref], missing_required, missing_optional
```

Import `datetime`, `UTC`, and `RunManifest`. This required-kind check is intentionally step-aware: only succeeded steps enforce the required kind sets, failed steps index whatever evidence exists, and absent/pending/skipped steps do not create requirements.

- [ ] **Step 4: Implement `artifacts_collect_handler()`**

Add:

```python
def artifacts_collect_handler(
    *,
    artifact_root: Path,
    run_id: str,
    force_recollect: bool = False,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    existing = manifest.step_results.get("collect_artifacts")
    if existing and existing.status == StepStatus.SUCCEEDED and not force_recollect:
        return ToolResponse.success(
            summary=existing.summary,
            run_id=run_id,
            data=existing.details,
            artifacts=existing.artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    try:
        with store.collect_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("collect_artifacts")
            if existing and existing.status == StepStatus.SUCCEEDED and not force_recollect:
                return ToolResponse.success(summary=existing.summary, run_id=run_id, data=existing.details, artifacts=existing.artifacts)
            bundle_path = store.run_dir(run_id) / "summaries" / "artifact-bundle.json"
            bundle, artifacts, missing_required, missing_optional = _bundle_for_manifest(
                manifest=locked_manifest,
                run_dir=store.run_dir(run_id),
                bundle_path=bundle_path,
            )
            bundle_path.parent.mkdir(parents=True, exist_ok=True)
            bundle_path.write_text(json.dumps(Redactor().redact_value(bundle), indent=2, default=str), encoding="utf-8")
            status = StepStatus.FAILED if missing_required else StepStatus.SUCCEEDED
            result = StepResult(
                step_name="collect_artifacts",
                status=status,
                summary="artifact collection succeeded" if status == StepStatus.SUCCEEDED else "artifact collection found missing required artifacts",
                artifacts=artifacts,
                details={"bundle": bundle, "rollup": bundle["rollup"]},
            )
            store.record_step_result(run_id, result, replace_succeeded=force_recollect)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    if missing_required:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=result.summary,
            run_id=run_id,
            details={
                "bundle": bundle,
                "rollup": bundle["rollup"],
                "missing_required": missing_required,
                "missing_optional": missing_optional,
            },
            artifacts=artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    return ToolResponse.success(
        summary=result.summary,
        run_id=run_id,
        data=result.details,
        artifacts=artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )
```

- [ ] **Step 5: Run collection tests**

Run:

```bash
pytest tests/test_artifacts_collect_handler.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_artifacts_collect_handler.py
git commit -m "feat: add artifact collection handler"
```

## Task 8: Wire artifacts.collect MCP Tool And Provider Registry

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Modify: `src/linux_debug_mcp/providers/registry.py`
- Modify: `tests/test_server.py`
- Modify: `tests/test_providers.py`

- [ ] **Step 1: Write failing tool registration expectations**

Update provider tests so `stub-workflows` no longer lists `artifacts.collect`, and add this server test:

```python
def test_artifacts_collect_tool_is_registered_with_force_recollect() -> None:
    app = create_app()
    tool = app._tool_manager._tools["artifacts.collect"]

    assert "artifacts.collect" in tool_names()
    assert "force_recollect" in tool.parameters["properties"]
    assert tool.fn.__name__ == "artifacts_collect"
```

- [ ] **Step 2: Wire MCP tool**

Add before `make_stub()`:

```python
@app.tool(name="artifacts.collect")
def artifacts_collect(
    run_id: str,
    artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
    force_recollect: bool = False,
) -> dict[str, Any]:
    return artifacts_collect_handler(
        artifact_root=Path(artifact_root),
        run_id=run_id,
        force_recollect=force_recollect,
    ).model_dump(mode="json")
```

Remove `"artifacts.collect"` from the stub loop.

- [ ] **Step 3: Run tests**

Run:

```bash
pytest tests/test_server.py tests/test_providers.py -q
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/linux_debug_mcp/server.py src/linux_debug_mcp/providers/registry.py tests/test_server.py tests/test_providers.py
git commit -m "feat: expose artifact collection tool"
```

## Task 9: Implement workflow.build_boot_test Handler

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Create: `tests/test_workflow_build_boot_test_handler.py`

- [ ] **Step 1: Write failing workflow tests**

Create `tests/test_workflow_build_boot_test_handler.py` with monkeypatched handler fakes:

```python
from pathlib import Path

from linux_debug_mcp.domain import ErrorCategory, StepStatus, ToolResponse
from linux_debug_mcp.server import create_run_handler, workflow_build_boot_test_handler


def success(summary: str, *, run_id: str = "run-abc123") -> ToolResponse:
    return ToolResponse.success(summary=summary, run_id=run_id, data={"summary": summary})


def failure(category: ErrorCategory, message: str, *, run_id: str = "run-abc123") -> ToolResponse:
    return ToolResponse.failure(category=category, message=message, run_id=run_id)


def test_workflow_runs_build_boot_tests_and_collects(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr("linux_debug_mcp.server.create_run_handler", lambda **kwargs: success("created"))
    monkeypatch.setattr("linux_debug_mcp.server.kernel_build_handler", lambda **kwargs: calls.append("build") or success("built"))
    monkeypatch.setattr("linux_debug_mcp.server.target_boot_handler", lambda **kwargs: calls.append("boot") or success("booted"))
    monkeypatch.setattr("linux_debug_mcp.server.target_run_tests_handler", lambda **kwargs: calls.append("tests") or success("tested"))
    monkeypatch.setattr("linux_debug_mcp.server.artifacts_collect_handler", lambda **kwargs: calls.append("collect") or success("collected"))

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )

    assert response.ok is True
    assert calls == ["build", "boot", "tests", "collect"]
    assert response.data["latest_successful_step"] == "collect_artifacts"


def test_workflow_collects_and_returns_build_failure(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr("linux_debug_mcp.server.create_run_handler", lambda **kwargs: success("created"))
    monkeypatch.setattr("linux_debug_mcp.server.kernel_build_handler", lambda **kwargs: calls.append("build") or failure(ErrorCategory.BUILD_FAILURE, "build failed"))
    monkeypatch.setattr("linux_debug_mcp.server.artifacts_collect_handler", lambda **kwargs: calls.append("collect") or success("collected"))

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "build_failure"
    assert response.error.details["failing_step"] == "build"
    assert calls == ["build", "collect"]


def test_workflow_collects_after_test_failure(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr("linux_debug_mcp.server.create_run_handler", lambda **kwargs: success("created"))
    monkeypatch.setattr("linux_debug_mcp.server.kernel_build_handler", lambda **kwargs: calls.append("build") or success("built"))
    monkeypatch.setattr("linux_debug_mcp.server.target_boot_handler", lambda **kwargs: calls.append("boot") or success("booted"))
    monkeypatch.setattr("linux_debug_mcp.server.target_run_tests_handler", lambda **kwargs: calls.append("tests") or failure(ErrorCategory.TEST_FAILURE, "tests failed"))
    monkeypatch.setattr("linux_debug_mcp.server.artifacts_collect_handler", lambda **kwargs: calls.append("collect") or success("collected"))

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.details["failing_step"] == "run_tests"
    assert calls == ["build", "boot", "tests", "collect"]


def test_workflow_rejects_existing_run_request_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    artifact_root = tmp_path / "runs"
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        test_suite="smoke-basic",
    )
    assert created.ok is True

    response = workflow_build_boot_test_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="other-build-profile",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        test_suite="smoke-basic",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "immutable run manifest request" in response.error.message


def test_workflow_creates_missing_supplied_run_id_exactly(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}
    calls: list[str] = []

    def fake_create_run(**kwargs: object) -> ToolResponse:
        captured.update(kwargs)
        return success("created", run_id=str(kwargs["run_id"]))

    monkeypatch.setattr("linux_debug_mcp.server.create_run_handler", fake_create_run)
    monkeypatch.setattr("linux_debug_mcp.server.kernel_build_handler", lambda **kwargs: calls.append("build") or success("built", run_id="run-explicit"))
    monkeypatch.setattr("linux_debug_mcp.server.target_boot_handler", lambda **kwargs: calls.append("boot") or success("booted", run_id="run-explicit"))
    monkeypatch.setattr("linux_debug_mcp.server.target_run_tests_handler", lambda **kwargs: calls.append("tests") or success("tested", run_id="run-explicit"))
    monkeypatch.setattr("linux_debug_mcp.server.artifacts_collect_handler", lambda **kwargs: calls.append("collect") or success("collected", run_id="run-explicit"))

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-explicit",
    )

    assert response.ok is True
    assert captured["run_id"] == "run-explicit"
    assert calls == ["build", "boot", "tests", "collect"]
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
pytest tests/test_workflow_build_boot_test_handler.py -q
```

Expected: FAIL because `workflow_build_boot_test_handler()` does not exist.

- [ ] **Step 3: Implement workflow helper functions**

In `server.py`, add:

```python
def _workflow_failure_response(*, run_id: str | None, failing_step: str, latest_successful_step: str | None, response: ToolResponse, collect_response: ToolResponse | None) -> ToolResponse:
    details = {
        "failing_step": failing_step,
        "latest_successful_step": latest_successful_step,
        "failed_response": response.model_dump(mode="json"),
        "collect_response": collect_response.model_dump(mode="json") if collect_response else None,
    }
    category = response.error.category if response.error else ErrorCategory.INFRASTRUCTURE_FAILURE
    message = response.error.message if response.error else response.summary or f"{failing_step} failed"
    return ToolResponse.failure(
        category=category,
        message=message,
        run_id=run_id,
        details=details,
        artifacts=[*(response.artifacts or []), *((collect_response.artifacts if collect_response else []) or [])],
        suggested_next_actions=["artifacts.get_manifest", "Inspect artifact bundle"],
    )
```

- [ ] **Step 4: Implement `workflow_build_boot_test_handler()`**

Add:

```python
def workflow_build_boot_test_handler(
    *,
    artifact_root: Path,
    source_path: str,
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    run_id: str | None = None,
    test_suite: str | None = None,
    commands: list[list[str]] | None = None,
    force_rebuild: bool = False,
    force_reboot: bool = False,
    force_rerun_tests: bool = False,
    force_recollect: bool = False,
) -> ToolResponse:
```

Behavior:
- If `run_id` exists, load the manifest and compare source path, build profile, target profile, rootfs profile, and test suite; mismatch returns `configuration_error`.
- If `run_id` is absent or missing, call `create_run_handler()` with the supplied request and exact `run_id` if provided.
- Call `kernel_build_handler()`. If it fails, call `artifacts_collect_handler()` and return workflow failure for `build`.
- Call `target_boot_handler()`. If it fails, collect and return workflow failure for `boot`.
- Call `target_run_tests_handler()`. Always call collect afterward. If tests fail, return workflow failure for `run_tests`.
- On success, return:

```python
ToolResponse.success(
    summary="build, boot, test workflow succeeded",
    run_id=run_id,
    data={
        "steps": {
            "build": build_response.model_dump(mode="json"),
            "boot": boot_response.model_dump(mode="json"),
            "run_tests": test_response.model_dump(mode="json"),
            "collect_artifacts": collect_response.model_dump(mode="json"),
        },
        "latest_successful_step": "collect_artifacts",
        "artifact_bundle": next(
            (artifact.model_dump(mode="json") for artifact in collect_response.artifacts if artifact.kind == "artifact-bundle"),
            None,
        ),
    },
    artifacts=collect_response.artifacts,
    suggested_next_actions=["artifacts.get_manifest"],
)
```

- [ ] **Step 5: Run workflow tests**

Run:

```bash
pytest tests/test_workflow_build_boot_test_handler.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_workflow_build_boot_test_handler.py
git commit -m "feat: add build boot test workflow handler"
```

## Task 10: Wire workflow.build_boot_test MCP Tool

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Modify: `src/linux_debug_mcp/providers/registry.py`
- Modify: `tests/test_server.py`
- Modify: `tests/test_providers.py`

- [ ] **Step 1: Write failing workflow tool registration test**

Add to `tests/test_server.py`:

```python
def test_workflow_build_boot_test_tool_is_registered_with_force_flags() -> None:
    app = create_app()
    tool = app._tool_manager._tools["workflow.build_boot_test"]

    assert "workflow.build_boot_test" in tool_names()
    assert "force_rerun_tests" in tool.parameters["properties"]
    assert "force_recollect" in tool.parameters["properties"]
    assert tool.fn.__name__ == "workflow_build_boot_test"
```

- [ ] **Step 2: Wire MCP tool**

Add before `make_stub()`:

```python
@app.tool(name="workflow.build_boot_test")
def workflow_build_boot_test(
    source_path: str,
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
    run_id: str | None = None,
    test_suite: str | None = None,
    commands: list[list[str]] | None = None,
    force_rebuild: bool = False,
    force_reboot: bool = False,
    force_rerun_tests: bool = False,
    force_recollect: bool = False,
) -> dict[str, Any]:
    return workflow_build_boot_test_handler(
        artifact_root=Path(artifact_root),
        source_path=source_path,
        build_profile=build_profile,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        run_id=run_id,
        test_suite=test_suite,
        commands=commands,
        force_rebuild=force_rebuild,
        force_reboot=force_reboot,
        force_rerun_tests=force_rerun_tests,
        force_recollect=force_recollect,
    ).model_dump(mode="json")
```

Remove `"workflow.build_boot_test"` from the stub loop and from `stub-workflows` operations.

- [ ] **Step 3: Run server and provider tests**

Run:

```bash
pytest tests/test_server.py tests/test_providers.py -q
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/linux_debug_mcp/server.py src/linux_debug_mcp/providers/registry.py tests/test_server.py tests/test_providers.py
git commit -m "feat: expose build boot test workflow"
```

## Task 11: Add Response Redaction Regression Coverage

**Files:**
- Modify: `tests/test_redaction.py`
- Modify: `tests/test_target_run_tests_handler.py`
- Modify: `src/linux_debug_mcp/server.py`

- [ ] **Step 1: Write failing MCP response redaction test**

Add to `tests/test_target_run_tests_handler.py`:

```python
def test_run_tests_response_redacts_secret_like_snippets(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider(
        result=TestExecutionResult(
            status=StepStatus.FAILED,
            summary="test failed token=abc123",
            details={
                "counts": {"passed": 0, "failed": 1},
                "commands": [
                    {
                        "label": "001-uname",
                        "stdout_snippet": "API_TOKEN=abc123",
                        "stderr_snippet": "password=hunter2",
                    }
                ],
            },
            error_category=ErrorCategory.TEST_FAILURE,
            diagnostic="password=hunter2",
        )
    )

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    payload = response.model_dump(mode="json")
    assert "abc123" not in str(payload)
    assert "hunter2" not in str(payload)
    assert "[REDACTED]" in str(payload)


def test_run_tests_success_response_redacts_secret_like_snippets(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider(
        result=TestExecutionResult(
            status=StepStatus.SUCCEEDED,
            summary="test passed token=abc123",
            details={
                "counts": {"passed": 1, "failed": 0},
                "commands": [
                    {
                        "label": "001-uname",
                        "stdout_snippet": "API_TOKEN=abc123",
                        "stderr_snippet": "password=hunter2",
                    }
                ],
            },
        )
    )

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    payload = response.model_dump(mode="json")
    assert response.ok is True
    assert "abc123" not in str(payload)
    assert "hunter2" not in str(payload)
    assert "[REDACTED]" in str(payload)
```

- [ ] **Step 2: Run tests and confirm failure if response redaction is incomplete**

Run:

```bash
pytest tests/test_redaction.py tests/test_target_run_tests_handler.py -q
```

Expected: FAIL if `target_run_tests_handler()` returns provider details or diagnostics without applying `Redactor().redact_value()`.

- [ ] **Step 3: Implement handler response redaction**

Before returning `target.run_tests` success or failure responses, redact `execution.details`, `execution.diagnostic`, `execution.summary`, and artifact metadata:

```python
redactor = Redactor()
safe_details = redactor.redact_value(execution.details)
safe_summary = redactor.redact_text(execution.summary)
safe_diagnostic = redactor.redact_text(execution.diagnostic or "")
safe_artifacts = [ArtifactRef.model_validate(redactor.redact_value(artifact.model_dump(mode="json"))) for artifact in execution.artifacts]
```

Use the same redacted values in recorded `StepResult` details and MCP responses so `artifacts.get_manifest` cannot later re-expose unredacted snippets.

- [ ] **Step 4: Run response redaction tests**

Run:

```bash
pytest tests/test_redaction.py tests/test_target_run_tests_handler.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_target_run_tests_handler.py tests/test_redaction.py
git commit -m "test: cover run tests response redaction"
```

## Task 12: Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/fedora-libvirt-user-guide.md`

- [ ] **Step 1: Update README pilot flow**

Add a Sprint 3 section with these concrete examples:

```markdown
### Run SSH smoke tests

Sprint 3 expects the selected rootfs profile to already allow SSH login from the MCP server. The tool does not install packages, create users, copy SSH keys, discover guest addresses, or mutate the rootfs to enable login.

The default suite is `smoke-basic`:

- `uname -a`
- `test -r /proc/version`
- `cat /proc/cmdline`

After `kernel.build` and `target.boot` succeed:

```json
{
  "tool": "target.run_tests",
  "arguments": {
    "run_id": "run-abc123",
    "test_suite": "smoke-basic"
  }
}
```

Ad hoc commands are argv lists and run after the named suite:

```json
{
  "tool": "target.run_tests",
  "arguments": {
    "run_id": "run-abc123",
    "commands": [["sh", "-lc", "cat /proc/cmdline | tr ' ' '\\n'"]]
  }
}
```

Collect the artifact bundle:

```json
{
  "tool": "artifacts.collect",
  "arguments": {
    "run_id": "run-abc123"
  }
}
```

Run the full pilot workflow:

```json
{
  "tool": "workflow.build_boot_test",
  "arguments": {
    "source_path": "/home/dave/src/linux",
    "build_profile": "x86_64-default",
    "target_profile": "local-qemu",
    "rootfs_profile": "minimal",
    "test_suite": "smoke-basic"
  }
}
```

Smoke output is written under `.linux-debug-mcp/runs/<run-id>/tests/attempt-NNN/`, dmesg under the same attempt directory, serial console logs under `logs/`, and the bundle index at `summaries/artifact-bundle.json`.
```

- [ ] **Step 2: Update Fedora guide**

Add a section that states:

```markdown
## SSH Requirements For Smoke Tests

The Fedora rootfs must boot far enough for sshd to accept key-based or otherwise noninteractive login. The MCP server uses `ssh` with `BatchMode=yes`, a run-local `known_hosts` file, and bounded connection timeouts.

Sprint 3 does not install SSH keys, edit `sshd_config`, create host port forwards, parse DHCP leases, or discover guest IP addresses. Configure the `RootfsProfile` with `ssh_host`, `ssh_port`, `ssh_user`, optional `ssh_key_ref`, and the allowed SSH options before running `target.run_tests` or `workflow.build_boot_test`.
```

- [ ] **Step 3: Run documentation grep checks**

Run:

```bash
rg "workflow.build_boot_test|target.run_tests|artifacts.collect|ssh_host|smoke-basic" README.md docs/fedora-libvirt-user-guide.md
```

Expected: output contains both docs files and all listed terms.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/fedora-libvirt-user-guide.md
git commit -m "docs: document SSH smoke test pilot flow"
```

## Task 13: Final Integration Verification

**Files:**
- Source files should not change in this task unless verification exposes a defect.

- [ ] **Step 1: Run focused Sprint 3 tests**

Run:

```bash
pytest \
  tests/test_config.py \
  tests/test_artifacts.py \
  tests/test_local_ssh_tests_provider.py \
  tests/test_target_run_tests_handler.py \
  tests/test_artifacts_collect_handler.py \
  tests/test_workflow_build_boot_test_handler.py \
  tests/test_server.py \
  tests/test_providers.py \
  tests/test_redaction.py \
  -q
```

Expected: PASS.

- [ ] **Step 2: Run full test suite**

Run:

```bash
pytest -q
```

Expected: PASS with no tests requiring libvirt, QEMU, SSH connectivity, or a Linux guest unless explicitly gated by environment variables.

- [ ] **Step 3: Run lint/type checks available in repo tooling**

Run:

```bash
just --list
```

Then run the existing non-destructive quality commands listed by the justfile. If the justfile exposes `test`, `lint`, or `typecheck`, run:

```bash
just test
just lint
just typecheck
```

Expected: supported commands pass. If a command is absent, record that it was not available.

---

## Self-Review Checklist

- Spec coverage: Tasks cover `TestSuiteProfile`, SSH rootfs fields, `target.run_tests`, local SSH provider, stdout/stderr/status/timing/timeout capture, dmesg, redacted snippets, `artifacts.collect`, bundle summaries, `workflow.build_boot_test`, manifest updates, idempotency, locks, tests, and docs.
- Scope control: No task adds serial command execution, rootfs mutation, IP discovery, package/key installation, parallel tests, debug integration, or real guest requirements.
- Type consistency: `run_tests`, `collect_artifacts`, `TestCommand`, `TestSuiteProfile`, `LocalSshTestProvider`, and `TestExecutionResult` names are used consistently across provider, handlers, tests, and registry.
- Verification: The plan ends with focused Sprint 3 tests, full `pytest`, and available repo quality commands.
