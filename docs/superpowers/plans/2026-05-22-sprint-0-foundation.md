# Sprint 0 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Sprint 0 Python foundation for the Linux Debug MCP server: installable package, domain/config contracts, artifact manifests, safety/redaction, prerequisite checks, and runnable MCP tool stubs.

**Architecture:** Use a `src/` Python package with Pydantic v2 models as the stable contract across config, manifests, providers, and MCP responses. Keep behavior focused and unit-testable: no kernel builds, libvirt mutations, VM boots, SSH, serial, or gdb work in Sprint 0. Public MCP handlers call small service modules that validate paths, persist manifests atomically, redact sensitive values, and return one shared response envelope.

**Tech Stack:** Python 3.11+, setuptools `pyproject.toml`, Pydantic v2, Python MCP SDK imported as `mcp`, pytest, standard-library logging/pathlib/json/subprocess.

---

## File Structure

Create these files:

- `pyproject.toml`: package metadata, runtime dependencies, pytest config, console script.
- `src/linux_debug_mcp/__init__.py`: package version export.
- `src/linux_debug_mcp/domain.py`: enums and Pydantic domain/response models.
- `src/linux_debug_mcp/config.py`: profile and server config models.
- `src/linux_debug_mcp/safety/__init__.py`: safety package exports.
- `src/linux_debug_mcp/safety/secrets.py`: secret reference models.
- `src/linux_debug_mcp/safety/redaction.py`: redaction helper.
- `src/linux_debug_mcp/safety/paths.py`: host/guest path validation.
- `src/linux_debug_mcp/artifacts/__init__.py`: artifact package exports.
- `src/linux_debug_mcp/artifacts/manifest.py`: manifest model and step result helpers.
- `src/linux_debug_mcp/artifacts/store.py`: run workspace creation, locking, atomic manifest IO.
- `src/linux_debug_mcp/providers/__init__.py`: provider package exports.
- `src/linux_debug_mcp/providers/base.py`: provider capability aliases and constructors.
- `src/linux_debug_mcp/providers/registry.py`: static provider registry.
- `src/linux_debug_mcp/prereqs/__init__.py`: prereq package exports.
- `src/linux_debug_mcp/prereqs/checks.py`: non-destructive host prerequisite checks.
- `src/linux_debug_mcp/logging.py`: structured logging setup.
- `src/linux_debug_mcp/server.py`: MCP app factory, tool handlers, and console entrypoint.
- `tests/test_domain.py`: domain response and serialization tests.
- `tests/test_config.py`: config/profile validation tests.
- `tests/test_redaction.py`: redaction and secret reference tests.
- `tests/test_paths.py`: path validation tests.
- `tests/test_providers.py`: registry tests.
- `tests/test_artifacts.py`: artifact layout, manifest IO, idempotency tests.
- `tests/test_prereqs.py`: fake command runner prerequisite tests.
- `tests/test_server.py`: direct handler response-shape tests.
- `README.md`: update with install, test, server, run, manifest, and prereq guidance.

The initial package is intentionally small. Provider implementations for real build, boot, SSH, serial, and debug behavior are not created in Sprint 0.

---

### Task 1: Package Skeleton And Tooling

**Files:**
- Create: `pyproject.toml`
- Create: `src/linux_debug_mcp/__init__.py`
- Create: `tests/test_domain.py`

- [ ] **Step 1: Write the failing package/version test**

Create `tests/test_domain.py`:

```python
from linux_debug_mcp import __version__


def test_package_exports_version() -> None:
    assert __version__ == "0.1.0"
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
python -c "import linux_debug_mcp"
```

Expected: FAIL with `ModuleNotFoundError: No module named 'linux_debug_mcp'`.

- [ ] **Step 3: Add package metadata and version export**

Create `pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=69", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "linux-debug-mcp"
version = "0.1.0"
description = "MCP server foundation for Linux kernel build-boot-debug workflows"
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
  "mcp>=1.9,<2",
  "pydantic>=2.7,<3",
]

[project.optional-dependencies]
test = [
  "pytest>=8.2,<9",
]

[project.scripts]
linux-debug-mcp = "linux_debug_mcp.server:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
addopts = "-ra"
```

Create `src/linux_debug_mcp/__init__.py`:

```python
"""Linux Debug MCP server foundation."""

__version__ = "0.1.0"
```

- [ ] **Step 4: Install editable package with test dependencies**

Run:

```bash
python -m pip install -e '.[test]'
```

Expected: command exits 0 and installs `linux-debug-mcp`, `mcp`, `pydantic`, and `pytest` into the active environment.

- [ ] **Step 5: Run the package/version test to verify it passes**

Run:

```bash
python -m pytest tests/test_domain.py::test_package_exports_version -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/linux_debug_mcp/__init__.py tests/test_domain.py
git commit -m "feat: scaffold sprint 0 package"
```

---

### Task 2: Domain Models And Response Envelope

**Files:**
- Create: `src/linux_debug_mcp/domain.py`
- Modify: `tests/test_domain.py`

- [ ] **Step 1: Add failing domain and response tests**

Replace `tests/test_domain.py` with:

```python
from linux_debug_mcp import __version__
from linux_debug_mcp.domain import (
    ArtifactRef,
    ErrorCategory,
    ErrorInfo,
    OperationSemantics,
    PrerequisiteCheck,
    PrerequisiteStatus,
    ProviderCapability,
    StepStatus,
    TargetKind,
    ToolResponse,
)


def test_package_exports_version() -> None:
    assert __version__ == "0.1.0"


def test_success_response_serializes_with_shared_envelope() -> None:
    response = ToolResponse.success(
        summary="run created",
        run_id="run-123",
        data={"manifest_path": "/tmp/runs/run-123/manifest.json"},
        artifacts=[ArtifactRef(path="/tmp/runs/run-123/manifest.json", kind="manifest")],
        suggested_next_actions=["kernel.build"],
    )

    payload = response.model_dump(mode="json")

    assert payload["ok"] is True
    assert payload["status"] == "succeeded"
    assert payload["run_id"] == "run-123"
    assert payload["data"]["manifest_path"].endswith("manifest.json")
    assert payload["artifacts"][0]["kind"] == "manifest"
    assert payload["suggested_next_actions"] == ["kernel.build"]


def test_error_response_uses_nested_error_contract() -> None:
    response = ToolResponse.failure(
        category=ErrorCategory.NOT_IMPLEMENTED,
        message="kernel.build is implemented in Sprint 1",
        run_id="run-123",
        details={"tool": "kernel.build"},
        suggested_next_actions=["workflow.build_boot_test after Sprint 3"],
    )

    payload = response.model_dump(mode="json")

    assert payload["ok"] is False
    assert payload["status"] == "failed"
    assert payload["error"] == {
        "category": "not_implemented",
        "message": "kernel.build is implemented in Sprint 1",
        "details": {"tool": "kernel.build"},
    }


def test_provider_capability_records_semantics() -> None:
    capability = ProviderCapability(
        provider_name="local-artifacts",
        provider_version="0.1.0",
        architectures=["x86_64"],
        target_kinds=[TargetKind.LOCAL],
        operations=["artifacts.create_run"],
        required_host_tools=[],
        destructive_permissions=[],
        access_methods=["filesystem"],
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=False,
            cancelable=False,
            concurrent_safe=False,
        ),
    )

    assert capability.semantics.idempotent is True
    assert capability.target_kinds == [TargetKind.LOCAL]


def test_prerequisite_check_serializes_status_and_fix() -> None:
    check = PrerequisiteCheck(
        check_id="tool.gdb",
        status=PrerequisiteStatus.FAILED,
        message="gdb was not found",
        suggested_fix="Install gdb with your distro package manager.",
    )

    assert check.model_dump(mode="json") == {
        "check_id": "tool.gdb",
        "status": "failed",
        "message": "gdb was not found",
        "details": {},
        "suggested_fix": "Install gdb with your distro package manager.",
    }
```

- [ ] **Step 2: Run the domain tests to verify they fail**

Run:

```bash
python -m pytest tests/test_domain.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'linux_debug_mcp.domain'`.

- [ ] **Step 3: Implement domain models**

Create `src/linux_debug_mcp/domain.py`:

```python
from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELED = "canceled"


class ErrorCategory(StrEnum):
    CONFIGURATION_ERROR = "configuration_error"
    MISSING_DEPENDENCY = "missing_dependency"
    BUILD_FAILURE = "build_failure"
    BOOT_TIMEOUT = "boot_timeout"
    READINESS_FAILURE = "readiness_failure"
    TEST_FAILURE = "test_failure"
    DEBUG_ATTACH_FAILURE = "debug_attach_failure"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    NOT_IMPLEMENTED = "not_implemented"


class TargetKind(StrEnum):
    LOCAL = "local"
    REMOTE = "remote"
    VIRTUAL = "virtual"
    PHYSICAL = "physical"


class PrerequisiteStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class KernelSource(Model):
    path: str
    git_revision: str | None = None


class BuildArtifact(Model):
    architecture: str
    kernel_image: str | None = None
    vmlinux: str | None = None
    config: str | None = None


class ArtifactRef(Model):
    path: str
    kind: str
    sensitive: bool = False
    description: str | None = None


class ArtifactBundle(Model):
    run_id: str
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    summary_path: str | None = None


class RunRequest(Model):
    source_path: str
    build_profile: str
    target_profile: str
    rootfs_profile: str
    debug_profile: str | None = None
    test_suite: str | None = None
    run_id: str | None = None


class RunStep(Model):
    name: str
    status: StepStatus = StepStatus.PENDING
    provider: str | None = None


class StepResult(Model):
    step_name: str
    status: StepStatus
    summary: str
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class RunRecord(Model):
    run_id: str
    request: RunRequest
    steps: list[RunStep] = Field(default_factory=list)


class OperationSemantics(Model):
    idempotent: bool
    retryable: bool
    destructive: bool
    cancelable: bool
    concurrent_safe: bool


class ProviderDependency(Model):
    name: str
    kind: str = "host_tool"
    required: bool = True


class ProviderCapability(Model):
    provider_name: str
    provider_version: str
    architectures: list[str]
    target_kinds: list[TargetKind]
    operations: list[str]
    required_host_tools: list[str]
    destructive_permissions: list[str]
    access_methods: list[str]
    semantics: OperationSemantics


class PrerequisiteCheck(Model):
    check_id: str
    status: PrerequisiteStatus
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    suggested_fix: str | None = None


class ErrorInfo(Model):
    category: ErrorCategory
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ToolResponse(Model):
    ok: bool
    status: StepStatus
    summary: str | None = None
    run_id: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    error: ErrorInfo | None = None
    suggested_next_actions: list[str] = Field(default_factory=list)

    @classmethod
    def success(
        cls,
        *,
        summary: str,
        run_id: str | None = None,
        status: StepStatus = StepStatus.SUCCEEDED,
        data: dict[str, Any] | None = None,
        artifacts: list[ArtifactRef] | None = None,
        suggested_next_actions: list[str] | None = None,
    ) -> "ToolResponse":
        return cls(
            ok=True,
            status=status,
            summary=summary,
            run_id=run_id,
            data=data or {},
            artifacts=artifacts or [],
            suggested_next_actions=suggested_next_actions or [],
        )

    @classmethod
    def failure(
        cls,
        *,
        category: ErrorCategory,
        message: str,
        run_id: str | None = None,
        details: dict[str, Any] | None = None,
        suggested_next_actions: list[str] | None = None,
    ) -> "ToolResponse":
        return cls(
            ok=False,
            status=StepStatus.FAILED,
            run_id=run_id,
            error=ErrorInfo(category=category, message=message, details=details or {}),
            suggested_next_actions=suggested_next_actions or [],
        )
```

- [ ] **Step 4: Run the domain tests to verify they pass**

Run:

```bash
python -m pytest tests/test_domain.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/domain.py tests/test_domain.py
git commit -m "feat: define domain response models"
```

---

### Task 3: Configuration And Secret Reference Models

**Files:**
- Create: `src/linux_debug_mcp/config.py`
- Create: `src/linux_debug_mcp/safety/__init__.py`
- Create: `src/linux_debug_mcp/safety/secrets.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write failing config and secret reference tests**

Create `tests/test_config.py`:

```python
from pathlib import Path

import pytest
from pydantic import ValidationError

from linux_debug_mcp.config import (
    ArtifactPolicy,
    BuildProfile,
    DebugProfile,
    RootfsProfile,
    ServerConfig,
    TargetProfile,
)
from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind


def test_server_config_accepts_valid_pilot_profiles(tmp_path: Path) -> None:
    config = ServerConfig(
        artifact_root=tmp_path / "runs",
        build_profiles={
            "x86_64-default": BuildProfile(
                name="x86_64-default",
                architecture="x86_64",
                output_policy="per_run",
                command_timeout_seconds=3600,
                required_tools=["make", "gcc"],
            )
        },
        rootfs_profiles={
            "minimal": RootfsProfile(
                name="minimal",
                source="file:///var/lib/linux-debug/rootfs.qcow2",
                mutability="copy_on_write",
                access_method="ssh",
                credential_refs=[
                    SecretReference(kind=SecretReferenceKind.FILE, label="ssh-key", reference="/tmp/id_ed25519")
                ],
                readiness_marker="login:",
                guest_writable_paths=["/tmp"],
            )
        },
        target_profiles={
            "local-qemu": TargetProfile(
                name="local-qemu",
                architecture="x86_64",
                provider_name="libvirt-qemu",
                target_ref="linux-debug-dev",
                kernel_args=["console=ttyS0", "nokaslr"],
                timeout_seconds=300,
                cleanup_policy="preserve_failed",
                debug_gdbstub=True,
            )
        },
        debug_profiles={
            "gdbstub": DebugProfile(
                name="gdbstub",
                enabled_operations=["interrupt", "continue", "read_registers"],
                gdbstub_endpoint="localhost:1234",
                kaslr_policy="disabled",
                symbol_identity_required=True,
                evaluation_mode="predefined_inspectors",
            )
        },
        artifact_policy=ArtifactPolicy(
            retention_days=14,
            raw_logs_enabled=False,
            redact_responses=True,
            preserve_failed_runs=True,
        ),
    )

    assert config.artifact_root == tmp_path / "runs"
    assert config.build_profiles["x86_64-default"].architecture == "x86_64"
    assert config.rootfs_profiles["minimal"].credential_refs[0].label == "ssh-key"


def test_profile_names_must_match_dictionary_keys(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="profile key must match profile name"):
        ServerConfig(
            artifact_root=tmp_path,
            build_profiles={"wrong": BuildProfile(name="actual", architecture="x86_64")},
        )


def test_secret_reference_serializes_without_secret_value() -> None:
    ref = SecretReference(kind=SecretReferenceKind.ENV, label="token", reference="LINUX_DEBUG_TOKEN")

    assert ref.model_dump(mode="json") == {
        "kind": "env",
        "label": "token",
        "reference": "LINUX_DEBUG_TOKEN",
        "required": True,
    }
    assert "secret" not in ref.model_dump(mode="json")
```

- [ ] **Step 2: Run the config tests to verify they fail**

Run:

```bash
python -m pytest tests/test_config.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'linux_debug_mcp.config'`.

- [ ] **Step 3: Implement secret references**

Create `src/linux_debug_mcp/safety/__init__.py`:

```python
"""Safety helpers for paths, secrets, and redaction."""
```

Create `src/linux_debug_mcp/safety/secrets.py`:

```python
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class SecretReferenceKind(StrEnum):
    FILE = "file"
    ENV = "env"
    EXTERNAL = "external"


class SecretReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: SecretReferenceKind
    label: str
    reference: str
    required: bool = True
```

- [ ] **Step 4: Implement configuration models**

Create `src/linux_debug_mcp/config.py`:

```python
from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from linux_debug_mcp.safety.secrets import SecretReference


class ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class BuildProfile(ConfigModel):
    name: str
    architecture: str
    output_policy: Literal["per_run", "shared"] = "per_run"
    config_fragments: list[Path] = Field(default_factory=list)
    command_timeout_seconds: int = Field(default=3600, ge=1)
    required_tools: list[str] = Field(default_factory=list)


class RootfsProfile(ConfigModel):
    name: str
    source: str
    mutability: Literal["read_only", "copy_on_write", "mutable"] = "copy_on_write"
    access_method: Literal["ssh", "serial", "ssh_and_serial", "none"] = "ssh"
    credential_refs: list[SecretReference] = Field(default_factory=list)
    readiness_marker: str | None = None
    guest_writable_paths: list[str] = Field(default_factory=list)


class TargetProfile(ConfigModel):
    name: str
    architecture: str
    provider_name: str
    target_ref: str | None = None
    kernel_args: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=300, ge=1)
    cleanup_policy: Literal["preserve_all", "preserve_failed", "stop_failed", "remove_temporary"] = (
        "preserve_failed"
    )
    debug_gdbstub: bool = False


class DebugProfile(ConfigModel):
    name: str
    enabled_operations: list[str] = Field(default_factory=list)
    gdbstub_endpoint: str | None = None
    kaslr_policy: Literal["disabled", "known", "unknown"] = "disabled"
    symbol_identity_required: bool = True
    evaluation_mode: Literal["disabled", "predefined_inspectors", "limited_expressions"] = (
        "predefined_inspectors"
    )


class ArtifactPolicy(ConfigModel):
    retention_days: int = Field(default=14, ge=1)
    raw_logs_enabled: bool = False
    redact_responses: bool = True
    preserve_failed_runs: bool = True


class ServerConfig(ConfigModel):
    artifact_root: Path
    build_profiles: dict[str, BuildProfile] = Field(default_factory=dict)
    rootfs_profiles: dict[str, RootfsProfile] = Field(default_factory=dict)
    target_profiles: dict[str, TargetProfile] = Field(default_factory=dict)
    debug_profiles: dict[str, DebugProfile] = Field(default_factory=dict)
    artifact_policy: ArtifactPolicy = Field(default_factory=ArtifactPolicy)
    logging_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    sensitive_paths: list[Path] = Field(default_factory=list)

    @field_validator("build_profiles", "rootfs_profiles", "target_profiles", "debug_profiles")
    @classmethod
    def profile_keys_match_names(cls, value: dict[str, ConfigModel], info: ValidationInfo) -> dict[str, ConfigModel]:
        for key, profile in value.items():
            if key != profile.name:
                raise ValueError(f"{info.field_name} profile key must match profile name")
        return value
```

- [ ] **Step 5: Run the config tests to verify they pass**

Run:

```bash
python -m pytest tests/test_config.py -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/config.py src/linux_debug_mcp/safety/__init__.py src/linux_debug_mcp/safety/secrets.py tests/test_config.py
git commit -m "feat: add config and secret models"
```

---

### Task 4: Redaction And Path Safety

**Files:**
- Create: `src/linux_debug_mcp/safety/redaction.py`
- Create: `src/linux_debug_mcp/safety/paths.py`
- Create: `tests/test_redaction.py`
- Create: `tests/test_paths.py`

- [ ] **Step 1: Write failing redaction tests**

Create `tests/test_redaction.py`:

```python
from linux_debug_mcp.safety.redaction import Redactor


def test_redacts_registered_secret_values_from_text() -> None:
    redactor = Redactor(secret_values=["abc123"])

    assert redactor.redact_text("token=abc123") == "token=[REDACTED]"


def test_redacts_common_key_value_secret_patterns() -> None:
    redactor = Redactor()

    assert redactor.redact_text("password=hunter2 token: abc123") == "password=[REDACTED] token: [REDACTED]"


def test_redacts_environment_mapping() -> None:
    redactor = Redactor(secret_values=["topsecret"])

    assert redactor.redact_mapping({"API_TOKEN": "topsecret", "PATH": "/usr/bin"}) == {
        "API_TOKEN": "[REDACTED]",
        "PATH": "/usr/bin",
    }
```

- [ ] **Step 2: Write failing path safety tests**

Create `tests/test_paths.py`:

```python
from pathlib import Path

import pytest

from linux_debug_mcp.safety.paths import (
    PathSafetyError,
    validate_artifact_root,
    validate_guest_path,
    validate_run_id,
    validate_secret_file_reference,
    validate_source_path,
)
from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind


def test_artifact_root_allows_creatable_child_of_existing_parent(tmp_path: Path) -> None:
    root = validate_artifact_root(tmp_path / "runs", source_paths=[], sensitive_paths=[])

    assert root == (tmp_path / "runs").resolve()


def test_artifact_root_rejects_filesystem_root() -> None:
    with pytest.raises(PathSafetyError, match="artifact root is too broad"):
        validate_artifact_root(Path("/"), source_paths=[], sensitive_paths=[])


def test_artifact_root_rejects_source_checkout(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()

    with pytest.raises(PathSafetyError, match="artifact root overlaps source path"):
        validate_artifact_root(source, source_paths=[source], sensitive_paths=[])


def test_run_id_rejects_path_traversal_and_leading_dot() -> None:
    for value in ["../x", ".hidden", "run/123", "run;rm"]:
        with pytest.raises(PathSafetyError):
            validate_run_id(value)


def test_run_id_accepts_simple_identifier() -> None:
    assert validate_run_id("run-20260522-abc123") == "run-20260522-abc123"


def test_source_path_must_look_like_linux_tree(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()

    with pytest.raises(PathSafetyError, match="missing Linux tree marker"):
        validate_source_path(source)

    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")

    assert validate_source_path(source) == source.resolve()


def test_guest_path_requires_absolute_safe_posix_path() -> None:
    assert validate_guest_path("/tmp/linux-debug") == "/tmp/linux-debug"

    for value in ["tmp", "/tmp/../etc", "/tmp//x", "/tmp/has;semi"]:
        with pytest.raises(PathSafetyError):
            validate_guest_path(value)


def test_secret_file_reference_validates_shape_and_optional_existence(tmp_path: Path) -> None:
    secret_file = tmp_path / "id_ed25519"
    secret_file.write_text("fake-key", encoding="utf-8")
    ref = SecretReference(kind=SecretReferenceKind.FILE, label="ssh-key", reference=str(secret_file))

    assert validate_secret_file_reference(ref, must_exist=True) == secret_file.resolve()

    unsafe = SecretReference(kind=SecretReferenceKind.FILE, label="ssh-key", reference="../id_ed25519")
    with pytest.raises(PathSafetyError, match="secret file reference must be absolute"):
        validate_secret_file_reference(unsafe)
```

- [ ] **Step 3: Run safety tests to verify they fail**

Run:

```bash
python -m pytest tests/test_redaction.py tests/test_paths.py -v
```

Expected: FAIL with missing `redaction` and `paths` modules.

- [ ] **Step 4: Implement redaction**

Create `src/linux_debug_mcp/safety/redaction.py`:

```python
from __future__ import annotations

import re
from collections.abc import Mapping


REDACTION = "[REDACTED]"


class Redactor:
    def __init__(self, secret_values: list[str] | None = None) -> None:
        self._secret_values = [value for value in secret_values or [] if value]
        self._key_value_pattern = re.compile(
            r"(?i)\b(password|passwd|token|api[_-]?key|secret)(\s*[=:]\s*)([^\s]+)"
        )

    def redact_text(self, text: str) -> str:
        redacted = text
        for value in self._secret_values:
            redacted = redacted.replace(value, REDACTION)
        return self._key_value_pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTION}", redacted)

    def redact_mapping(self, values: Mapping[str, object]) -> dict[str, object]:
        redacted: dict[str, object] = {}
        for key, value in values.items():
            if isinstance(value, str):
                redacted[key] = self.redact_text(value)
            else:
                redacted[key] = value
        return redacted
```

- [ ] **Step 5: Implement path safety**

Create `src/linux_debug_mcp/safety/paths.py`:

```python
from __future__ import annotations

import re
from pathlib import Path

from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind


class PathSafetyError(ValueError):
    pass


_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHELL_METACHARS = set(";|&`$<>\\")


def _resolve_existing_or_parent(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.exists():
        return expanded.resolve()
    parent = expanded.parent
    if not parent.exists():
        raise PathSafetyError(f"parent does not exist for path: {path}")
    return parent.resolve() / expanded.name


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def validate_artifact_root(
    artifact_root: Path,
    *,
    source_paths: list[Path],
    sensitive_paths: list[Path],
) -> Path:
    resolved = _resolve_existing_or_parent(artifact_root)
    home = Path.home().resolve()
    if resolved in {Path("/"), home}:
        raise PathSafetyError("artifact root is too broad")

    existing_parent = resolved if resolved.exists() else resolved.parent
    if not existing_parent.exists():
        raise PathSafetyError("artifact root parent does not exist")

    for source in source_paths:
        source_resolved = _resolve_existing_or_parent(source)
        if resolved == source_resolved or _is_relative_to(resolved, source_resolved):
            raise PathSafetyError("artifact root overlaps source path")

    for sensitive in sensitive_paths:
        sensitive_resolved = _resolve_existing_or_parent(sensitive)
        if resolved == sensitive_resolved or _is_relative_to(resolved, sensitive_resolved):
            raise PathSafetyError("artifact root overlaps sensitive path")

    return resolved


def validate_run_id(run_id: str) -> str:
    if not _RUN_ID_PATTERN.match(run_id):
        raise PathSafetyError("run ID contains unsafe characters")
    if run_id.startswith(".") or ".." in run_id or "/" in run_id:
        raise PathSafetyError("run ID contains unsafe path syntax")
    if any(char in _SHELL_METACHARS for char in run_id):
        raise PathSafetyError("run ID contains shell metacharacters")
    return run_id


def validate_source_path(source_path: Path) -> Path:
    resolved = source_path.expanduser().resolve()
    if not resolved.is_dir():
        raise PathSafetyError("source path is not a directory")
    if not (resolved / "Kconfig").exists() or not (resolved / "Makefile").exists():
        raise PathSafetyError("source path missing Linux tree marker")
    return resolved


def validate_guest_path(path: str) -> str:
    if not path.startswith("/"):
        raise PathSafetyError("guest path must be absolute")
    if "//" in path or "/../" in path or path.endswith("/.."):
        raise PathSafetyError("guest path contains unsafe path components")
    if any(char in _SHELL_METACHARS for char in path) or any(ord(char) < 32 for char in path):
        raise PathSafetyError("guest path contains unsafe characters")
    return path


def validate_secret_file_reference(ref: SecretReference, *, must_exist: bool = False) -> Path:
    if ref.kind != SecretReferenceKind.FILE:
        raise PathSafetyError("secret reference is not file-based")
    path = Path(ref.reference).expanduser()
    if not path.is_absolute():
        raise PathSafetyError("secret file reference must be absolute")
    resolved = path.resolve()
    if any(char in _SHELL_METACHARS for char in str(resolved)) or any(ord(char) < 32 for char in str(resolved)):
        raise PathSafetyError("secret file reference contains unsafe characters")
    if must_exist and not resolved.is_file():
        raise PathSafetyError("secret file reference does not exist")
    return resolved
```

- [ ] **Step 6: Run safety tests to verify they pass**

Run:

```bash
python -m pytest tests/test_redaction.py tests/test_paths.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/linux_debug_mcp/safety/redaction.py src/linux_debug_mcp/safety/paths.py tests/test_redaction.py tests/test_paths.py
git commit -m "feat: add redaction and path safety"
```

---

### Task 5: Provider Registry

**Files:**
- Create: `src/linux_debug_mcp/providers/__init__.py`
- Create: `src/linux_debug_mcp/providers/base.py`
- Create: `src/linux_debug_mcp/providers/registry.py`
- Create: `tests/test_providers.py`

- [ ] **Step 1: Write failing provider registry tests**

Create `tests/test_providers.py`:

```python
import pytest

from linux_debug_mcp.domain import OperationSemantics, ProviderCapability, TargetKind
from linux_debug_mcp.providers.registry import ProviderRegistry


def capability(name: str) -> ProviderCapability:
    return ProviderCapability(
        provider_name=name,
        provider_version="0.1.0",
        architectures=["x86_64"],
        target_kinds=[TargetKind.LOCAL],
        operations=["host.check_prerequisites"],
        required_host_tools=[],
        destructive_permissions=[],
        access_methods=["filesystem"],
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=False,
            cancelable=False,
            concurrent_safe=True,
        ),
    )


def test_registry_lists_registered_capabilities() -> None:
    registry = ProviderRegistry()
    registry.register(capability("local-artifacts"))

    assert registry.list_capabilities()[0].provider_name == "local-artifacts"
    assert registry.get("local-artifacts").operations == ["host.check_prerequisites"]


def test_registry_rejects_duplicate_names() -> None:
    registry = ProviderRegistry()
    registry.register(capability("local-artifacts"))

    with pytest.raises(ValueError, match="already registered"):
        registry.register(capability("local-artifacts"))


def test_default_registry_exposes_sprint_0_providers() -> None:
    registry = ProviderRegistry.with_defaults()

    names = {provider.provider_name for provider in registry.list_capabilities()}

    assert names == {"local-artifacts", "local-prereqs", "stub-workflows"}
```

- [ ] **Step 2: Run provider tests to verify they fail**

Run:

```bash
python -m pytest tests/test_providers.py -v
```

Expected: FAIL with missing `linux_debug_mcp.providers` modules.

- [ ] **Step 3: Implement provider package**

Create `src/linux_debug_mcp/providers/__init__.py`:

```python
"""Provider contracts and registry."""
```

Create `src/linux_debug_mcp/providers/base.py`:

```python
from __future__ import annotations

from linux_debug_mcp.domain import OperationSemantics, ProviderCapability, TargetKind


def sprint0_capability(
    *,
    name: str,
    operations: list[str],
    access_methods: list[str],
    concurrent_safe: bool,
) -> ProviderCapability:
    return ProviderCapability(
        provider_name=name,
        provider_version="0.1.0",
        architectures=["x86_64"],
        target_kinds=[TargetKind.LOCAL, TargetKind.VIRTUAL],
        operations=operations,
        required_host_tools=[],
        destructive_permissions=[],
        access_methods=access_methods,
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=False,
            cancelable=False,
            concurrent_safe=concurrent_safe,
        ),
    )
```

Create `src/linux_debug_mcp/providers/registry.py`:

```python
from __future__ import annotations

from linux_debug_mcp.domain import ProviderCapability
from linux_debug_mcp.providers.base import sprint0_capability


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, ProviderCapability] = {}

    def register(self, capability: ProviderCapability) -> None:
        if capability.provider_name in self._providers:
            raise ValueError(f"provider already registered: {capability.provider_name}")
        self._providers[capability.provider_name] = capability

    def get(self, name: str) -> ProviderCapability:
        return self._providers[name]

    def list_capabilities(self) -> list[ProviderCapability]:
        return list(self._providers.values())

    @classmethod
    def with_defaults(cls) -> "ProviderRegistry":
        registry = cls()
        registry.register(
            sprint0_capability(
                name="local-artifacts",
                operations=["kernel.create_run", "artifacts.get_manifest"],
                access_methods=["filesystem"],
                concurrent_safe=False,
            )
        )
        registry.register(
            sprint0_capability(
                name="local-prereqs",
                operations=["host.check_prerequisites"],
                access_methods=["subprocess", "filesystem"],
                concurrent_safe=True,
            )
        )
        registry.register(
            sprint0_capability(
                name="stub-workflows",
                operations=[
                    "kernel.build",
                    "target.boot",
                    "target.run_tests",
                    "artifacts.collect",
                    "workflow.build_boot_test",
                    "workflow.build_boot_debug",
                    "debug.start_session",
                    "debug.interrupt",
                    "debug.continue",
                    "debug.set_breakpoint",
                    "debug.clear_breakpoint",
                    "debug.list_breakpoints",
                    "debug.read_registers",
                    "debug.read_symbol",
                    "debug.read_memory",
                    "debug.evaluate",
                    "debug.end_session",
                ],
                access_methods=["none"],
                concurrent_safe=True,
            )
        )
        return registry
```

- [ ] **Step 4: Run provider tests to verify they pass**

Run:

```bash
python -m pytest tests/test_providers.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers tests/test_providers.py
git commit -m "feat: add static provider registry"
```

---

### Task 6: Artifact Store And Manifest Persistence

**Files:**
- Create: `src/linux_debug_mcp/artifacts/__init__.py`
- Create: `src/linux_debug_mcp/artifacts/manifest.py`
- Create: `src/linux_debug_mcp/artifacts/store.py`
- Create: `tests/test_artifacts.py`

- [ ] **Step 1: Write failing artifact store tests**

Create `tests/test_artifacts.py`:

```python
from pathlib import Path

import pytest

from linux_debug_mcp.artifacts.manifest import RunManifest
from linux_debug_mcp.artifacts.store import ArtifactStore, ManifestStateError
from linux_debug_mcp.domain import RunRequest, StepResult, StepStatus


def request(run_id: str | None = None) -> RunRequest:
    return RunRequest(
        source_path="/src/linux",
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id=run_id,
    )


def make_source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    return source


def test_create_run_workspace_and_manifest(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])

    manifest = store.create_run(request(run_id="run-abc123"))

    run_dir = tmp_path / "runs" / "run-abc123"
    assert manifest.run_id == "run-abc123"
    assert (run_dir / "manifest.json").exists()
    for name in ["inputs", "logs", "build", "target", "tests", "debug", "summaries", "sensitive"]:
        assert (run_dir / name).is_dir()


def test_create_run_refuses_duplicate_run_id(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    with pytest.raises(ManifestStateError, match="already exists"):
        store.create_run(request(run_id="run-abc123"))


def test_artifact_store_rejects_source_checkout_as_root(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)

    with pytest.raises(ManifestStateError, match="artifact root overlaps source path"):
        ArtifactStore(source, source_paths=[source])


def test_manifest_round_trips_and_records_schema_version(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    created = store.create_run(request(run_id="run-abc123"))

    loaded = store.load_manifest("run-abc123")

    assert loaded == created
    assert loaded.schema_version == 1
    assert loaded.writer_version == "0.1.0"


def test_completed_step_result_is_not_overwritten(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))
    result = StepResult(step_name="create_run", status=StepStatus.SUCCEEDED, summary="created")

    updated = store.record_step_result("run-abc123", result)
    repeated = store.record_step_result(
        "run-abc123",
        StepResult(step_name="create_run", status=StepStatus.SUCCEEDED, summary="changed"),
    )

    assert updated.step_results["create_run"].summary == "created"
    assert repeated.step_results["create_run"].summary == "created"


def test_existing_manifest_lock_returns_structured_state_error(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))
    lock_path = tmp_path / "runs" / "run-abc123" / ".manifest.lock"
    lock_path.write_text("12345", encoding="utf-8")

    with pytest.raises(ManifestStateError, match="manifest is locked"):
        store.record_step_result(
            "run-abc123",
            StepResult(step_name="create_run", status=StepStatus.SUCCEEDED, summary="created"),
        )
```

- [ ] **Step 2: Run artifact tests to verify they fail**

Run:

```bash
python -m pytest tests/test_artifacts.py -v
```

Expected: FAIL with missing `linux_debug_mcp.artifacts` modules.

- [ ] **Step 3: Implement manifest model**

Create `src/linux_debug_mcp/artifacts/__init__.py`:

```python
"""Run artifact storage and manifests."""
```

Create `src/linux_debug_mcp/artifacts/manifest.py`:

```python
from __future__ import annotations

from datetime import UTC, datetime

from pydantic import Field

from linux_debug_mcp import __version__
from linux_debug_mcp.domain import Model, RunRequest, RunStep, StepResult, StepStatus


class RunManifest(Model):
    schema_version: int = 1
    writer_version: str = __version__
    run_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    request: RunRequest
    steps: list[RunStep] = Field(default_factory=list)
    step_results: dict[str, StepResult] = Field(default_factory=dict)
    cleanup_state: str = "not_started"

    @classmethod
    def create(cls, *, run_id: str, request: RunRequest) -> "RunManifest":
        return cls(
            run_id=run_id,
            request=request,
            steps=[
                RunStep(name="create_run", status=StepStatus.SUCCEEDED, provider="local-artifacts"),
                RunStep(name="build", status=StepStatus.PENDING),
                RunStep(name="boot", status=StepStatus.PENDING),
                RunStep(name="run_tests", status=StepStatus.PENDING),
                RunStep(name="collect_artifacts", status=StepStatus.PENDING),
                RunStep(name="debug", status=StepStatus.PENDING),
            ],
        )

    def with_step_result(self, result: StepResult) -> "RunManifest":
        if result.step_name in self.step_results:
            existing = self.step_results[result.step_name]
            if existing.status == StepStatus.SUCCEEDED:
                return self
        clone = self.model_copy(deep=True)
        clone.step_results[result.step_name] = result
        for step in clone.steps:
            if step.name == result.step_name:
                step.status = result.status
        return clone
```

- [ ] **Step 4: Implement artifact store**

Create `src/linux_debug_mcp/artifacts/store.py`:

```python
from __future__ import annotations

import json
import os
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from pydantic import ValidationError

from linux_debug_mcp.artifacts.manifest import RunManifest
from linux_debug_mcp.domain import ErrorCategory, RunRequest, StepResult
from linux_debug_mcp.safety.paths import PathSafetyError, validate_artifact_root, validate_run_id


class ManifestStateError(RuntimeError):
    def __init__(self, message: str, category: ErrorCategory = ErrorCategory.INFRASTRUCTURE_FAILURE) -> None:
        super().__init__(message)
        self.category = category


class ArtifactStore:
    SUBDIRS = ("inputs", "logs", "build", "target", "tests", "debug", "summaries", "sensitive")

    def __init__(
        self,
        artifact_root: Path,
        *,
        source_paths: list[Path] | None = None,
        sensitive_paths: list[Path] | None = None,
    ) -> None:
        try:
            self.artifact_root = validate_artifact_root(
                artifact_root,
                source_paths=source_paths or [],
                sensitive_paths=sensitive_paths or [],
            )
        except PathSafetyError as exc:
            raise ManifestStateError(str(exc), ErrorCategory.CONFIGURATION_ERROR) from exc
        self.artifact_root.mkdir(parents=True, exist_ok=True)

    def create_run(self, request: RunRequest) -> RunManifest:
        run_id = validate_run_id(request.run_id or self._generate_run_id())
        run_dir = self._run_dir(run_id)
        if run_dir.exists():
            raise ManifestStateError(f"run already exists: {run_id}", ErrorCategory.CONFIGURATION_ERROR)

        run_dir.mkdir(parents=False)
        for subdir in self.SUBDIRS:
            (run_dir / subdir).mkdir()

        manifest = RunManifest.create(run_id=run_id, request=request.model_copy(update={"run_id": run_id}))
        self._write_manifest(run_dir, manifest)
        return manifest

    def load_manifest(self, run_id: str) -> RunManifest:
        run_dir = self._run_dir(validate_run_id(run_id))
        manifest_path = run_dir / "manifest.json"
        try:
            return RunManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, json.JSONDecodeError) as exc:
            raise ManifestStateError(f"failed to read manifest for {run_id}: {exc}") from exc

    def record_step_result(self, run_id: str, result: StepResult) -> RunManifest:
        run_id = validate_run_id(run_id)
        run_dir = self._run_dir(run_id)
        with self._manifest_lock(run_dir):
            manifest = self.load_manifest(run_id)
            updated = manifest.with_step_result(result)
            if updated != manifest:
                self._write_manifest(run_dir, updated)
            return updated

    def _run_dir(self, run_id: str) -> Path:
        try:
            safe_run_id = validate_run_id(run_id)
        except PathSafetyError as exc:
            raise ManifestStateError(str(exc), ErrorCategory.CONFIGURATION_ERROR) from exc
        return self.artifact_root / safe_run_id

    def _write_manifest(self, run_dir: Path, manifest: RunManifest) -> None:
        manifest_path = run_dir / "manifest.json"
        temp_path = run_dir / ".manifest.json.tmp"
        temp_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
        os.replace(temp_path, manifest_path)

    def _generate_run_id(self) -> str:
        return f"run-{uuid.uuid4().hex[:16]}"

    @contextmanager
    def _manifest_lock(self, run_dir: Path) -> Iterator[None]:
        lock_path = run_dir / ".manifest.lock"
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise ManifestStateError("manifest is locked", ErrorCategory.INFRASTRUCTURE_FAILURE) from exc
        try:
            os.write(fd, str(os.getpid()).encode("ascii"))
            yield
        finally:
            os.close(fd)
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass
```

- [ ] **Step 5: Run artifact tests to verify they pass**

Run:

```bash
python -m pytest tests/test_artifacts.py -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/artifacts tests/test_artifacts.py
git commit -m "feat: add artifact store and manifests"
```

---

### Task 7: Prerequisite Checks

**Files:**
- Create: `src/linux_debug_mcp/prereqs/__init__.py`
- Create: `src/linux_debug_mcp/prereqs/checks.py`
- Create: `tests/test_prereqs.py`

- [ ] **Step 1: Write failing prerequisite tests**

Create `tests/test_prereqs.py`:

```python
from pathlib import Path

from linux_debug_mcp.prereqs.checks import PrerequisiteRunner, check_prerequisites


class FakeRunner:
    def __init__(self, available: set[str]) -> None:
        self.available = available

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}" if command in self.available else None

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        if command == ["virsh", "uri"]:
            return (0, "qemu:///system\n", "")
        return (1, "", "unsupported")


def test_prereq_checks_report_missing_tools(tmp_path: Path) -> None:
    checks = check_prerequisites(
        artifact_root=tmp_path,
        source_path=None,
        enable_libvirt_check=False,
        runner=FakeRunner({"make", "bash", "git"}),
    )

    by_id = {check.check_id: check for check in checks}

    assert by_id["python.version"].status == "passed"
    assert by_id["python.package.mcp"].status in {"passed", "failed"}
    assert by_id["tool.make"].status == "passed"
    assert by_id["tool.gdb"].status == "failed"
    assert by_id["compiler.c"].status == "failed"
    assert by_id["libvirt.uri"].status == "skipped"


def test_prereq_checks_accept_clang_when_gcc_is_missing(tmp_path: Path) -> None:
    checks = check_prerequisites(
        artifact_root=tmp_path,
        source_path=None,
        enable_libvirt_check=False,
        runner=FakeRunner({"make", "clang", "bash", "git", "qemu-system-x86_64", "virsh", "gdb"}),
    )

    by_id = {check.check_id: check for check in checks}

    assert by_id["compiler.c"].status == "passed"
    assert by_id["compiler.c"].details["command"] == "clang"


def test_prereq_checks_validate_source_tree(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")

    checks = check_prerequisites(
        artifact_root=tmp_path / "runs",
        source_path=source,
        enable_libvirt_check=True,
        runner=FakeRunner({"make", "gcc", "bash", "git", "qemu-system-x86_64", "virsh", "gdb"}),
    )

    by_id = {check.check_id: check for check in checks}

    assert by_id["artifact_root.writable"].status == "passed"
    assert by_id["source.linux_tree"].status == "passed"
    assert by_id["libvirt.uri"].status == "passed"
```

- [ ] **Step 2: Run prerequisite tests to verify they fail**

Run:

```bash
python -m pytest tests/test_prereqs.py -v
```

Expected: FAIL with missing `linux_debug_mcp.prereqs` modules.

- [ ] **Step 3: Implement prerequisite checks**

Create `src/linux_debug_mcp/prereqs/__init__.py`:

```python
"""Host prerequisite checks."""
```

Create `src/linux_debug_mcp/prereqs/checks.py`:

```python
from __future__ import annotations

import shutil
import subprocess
import sys
from importlib import util as importlib_util
from pathlib import Path
from typing import Protocol

from linux_debug_mcp.domain import PrerequisiteCheck, PrerequisiteStatus
from linux_debug_mcp.safety.paths import PathSafetyError, validate_artifact_root, validate_source_path


class PrerequisiteRunner(Protocol):
    def which(self, command: str) -> str | None:
        raise NotImplementedError

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        raise NotImplementedError


class SubprocessPrerequisiteRunner:
    def which(self, command: str) -> str | None:
        return shutil.which(command)

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return completed.returncode, completed.stdout, completed.stderr


def check_prerequisites(
    *,
    artifact_root: Path,
    source_path: Path | None,
    enable_libvirt_check: bool,
    runner: PrerequisiteRunner | None = None,
) -> list[PrerequisiteCheck]:
    runner = runner or SubprocessPrerequisiteRunner()
    checks: list[PrerequisiteCheck] = []
    checks.append(_python_version_check())
    checks.extend(_python_package_checks())
    for tool in ["make", "bash", "git", "qemu-system-x86_64", "virsh", "gdb"]:
        checks.append(_tool_check(tool, runner))
    checks.append(_compiler_check(runner))
    checks.append(_artifact_root_check(artifact_root, source_path))
    checks.append(_source_tree_check(source_path))
    checks.append(_libvirt_check(enable_libvirt_check, runner))
    return checks


def _python_version_check() -> PrerequisiteCheck:
    status = PrerequisiteStatus.PASSED if sys.version_info >= (3, 11) else PrerequisiteStatus.FAILED
    return PrerequisiteCheck(
        check_id="python.version",
        status=status,
        message=f"Python {sys.version_info.major}.{sys.version_info.minor}",
        suggested_fix=None if status == PrerequisiteStatus.PASSED else "Use Python 3.11 or newer.",
    )


def _tool_check(tool: str, runner: PrerequisiteRunner) -> PrerequisiteCheck:
    path = runner.which(tool)
    if path:
        return PrerequisiteCheck(
            check_id=f"tool.{tool}",
            status=PrerequisiteStatus.PASSED,
            message=f"{tool} found",
            details={"path": path},
        )
    return PrerequisiteCheck(
        check_id=f"tool.{tool}",
        status=PrerequisiteStatus.FAILED,
        message=f"{tool} was not found",
        suggested_fix=f"Install {tool} with your distribution package manager.",
    )


def _python_package_checks() -> list[PrerequisiteCheck]:
    checks: list[PrerequisiteCheck] = []
    for package in ["mcp", "pydantic"]:
        found = importlib_util.find_spec(package) is not None
        checks.append(
            PrerequisiteCheck(
                check_id=f"python.package.{package}",
                status=PrerequisiteStatus.PASSED if found else PrerequisiteStatus.FAILED,
                message=f"Python package {package} {'is installed' if found else 'is not installed'}",
                suggested_fix=None if found else "Run: python -m pip install -e '.[test]'",
            )
        )
    return checks


def _compiler_check(runner: PrerequisiteRunner) -> PrerequisiteCheck:
    for command in ["gcc", "clang"]:
        path = runner.which(command)
        if path:
            return PrerequisiteCheck(
                check_id="compiler.c",
                status=PrerequisiteStatus.PASSED,
                message=f"{command} found",
                details={"command": command, "path": path},
            )
    return PrerequisiteCheck(
        check_id="compiler.c",
        status=PrerequisiteStatus.FAILED,
        message="neither gcc nor clang was found",
        suggested_fix="Install gcc or clang with your distribution package manager.",
    )


def _artifact_root_check(artifact_root: Path, source_path: Path | None) -> PrerequisiteCheck:
    try:
        validate_artifact_root(
            artifact_root,
            source_paths=[source_path] if source_path else [],
            sensitive_paths=[],
        )
    except PathSafetyError as exc:
        return PrerequisiteCheck(
            check_id="artifact_root.writable",
            status=PrerequisiteStatus.FAILED,
            message=str(exc),
            suggested_fix="Choose a dedicated writable artifact directory outside the source checkout.",
        )
    return PrerequisiteCheck(
        check_id="artifact_root.writable",
        status=PrerequisiteStatus.PASSED,
        message="artifact root is usable",
    )


def _source_tree_check(source_path: Path | None) -> PrerequisiteCheck:
    if source_path is None:
        return PrerequisiteCheck(
            check_id="source.linux_tree",
            status=PrerequisiteStatus.SKIPPED,
            message="no source path supplied",
        )
    try:
        validate_source_path(source_path)
    except PathSafetyError as exc:
        return PrerequisiteCheck(
            check_id="source.linux_tree",
            status=PrerequisiteStatus.FAILED,
            message=str(exc),
            suggested_fix="Pass a local Linux source checkout containing Kconfig and Makefile.",
        )
    return PrerequisiteCheck(
        check_id="source.linux_tree",
        status=PrerequisiteStatus.PASSED,
        message="source path looks like a Linux tree",
    )


def _libvirt_check(enable_libvirt_check: bool, runner: PrerequisiteRunner) -> PrerequisiteCheck:
    if not enable_libvirt_check:
        return PrerequisiteCheck(
            check_id="libvirt.uri",
            status=PrerequisiteStatus.SKIPPED,
            message="libvirt check disabled",
        )
    if runner.which("virsh") is None:
        return PrerequisiteCheck(
            check_id="libvirt.uri",
            status=PrerequisiteStatus.FAILED,
            message="virsh was not found",
            suggested_fix="Install libvirt client tools before enabling the libvirt URI check.",
        )
    code, stdout, stderr = runner.run(["virsh", "uri"], timeout=10)
    if code == 0:
        return PrerequisiteCheck(
            check_id="libvirt.uri",
            status=PrerequisiteStatus.PASSED,
            message="libvirt client is visible",
            details={"uri": stdout.strip()},
        )
    return PrerequisiteCheck(
        check_id="libvirt.uri",
        status=PrerequisiteStatus.FAILED,
        message="virsh uri failed",
        details={"stderr": stderr.strip()},
        suggested_fix="Confirm libvirt is installed and your user can access the development connection.",
    )
```

- [ ] **Step 4: Run prerequisite tests to verify they pass**

Run:

```bash
python -m pytest tests/test_prereqs.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/prereqs tests/test_prereqs.py
git commit -m "feat: add host prerequisite checks"
```

---

### Task 8: MCP Server Handlers And Stubs

**Files:**
- Create: `src/linux_debug_mcp/logging.py`
- Create: `src/linux_debug_mcp/server.py`
- Create: `tests/test_server.py`

- [ ] **Step 1: Write failing direct handler tests**

Create `tests/test_server.py`:

```python
from pathlib import Path

from linux_debug_mcp.server import (
    create_run_handler,
    get_manifest_handler,
    list_providers_handler,
    not_implemented_handler,
    prerequisites_handler,
)


def test_create_run_handler_creates_manifest(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")

    response = create_run_handler(
        artifact_root=tmp_path,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )

    assert response.ok is True
    assert response.run_id == "run-abc123"
    assert (tmp_path / "run-abc123" / "manifest.json").exists()
    assert response.suggested_next_actions == ["kernel.build"]


def test_create_run_handler_rejects_source_checkout_as_artifact_root(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")

    response = create_run_handler(
        artifact_root=source,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_get_manifest_handler_returns_redacted_manifest(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")

    create_run_handler(
        artifact_root=tmp_path,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )

    response = get_manifest_handler(artifact_root=tmp_path, run_id="run-abc123")

    assert response.ok is True
    assert response.data["manifest"]["run_id"] == "run-abc123"


def test_prerequisites_handler_returns_checks(tmp_path: Path) -> None:
    response = prerequisites_handler(
        artifact_root=tmp_path,
        source_path=None,
        enable_libvirt_check=False,
    )

    assert response.ok is True
    assert "checks" in response.data
    assert any(check["check_id"] == "python.version" for check in response.data["checks"])


def test_list_providers_handler_returns_default_capabilities() -> None:
    response = list_providers_handler()

    assert response.ok is True
    assert {provider["provider_name"] for provider in response.data["providers"]} == {
        "local-artifacts",
        "local-prereqs",
        "stub-workflows",
    }


def test_not_implemented_handler_returns_structured_error() -> None:
    response = not_implemented_handler("kernel.build")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "not_implemented"
    assert response.error.details["tool"] == "kernel.build"
```

- [ ] **Step 2: Run server tests to verify they fail**

Run:

```bash
python -m pytest tests/test_server.py -v
```

Expected: FAIL with missing `linux_debug_mcp.server`.

- [ ] **Step 3: Implement structured logging helper**

Create `src/linux_debug_mcp/logging.py`:

```python
from __future__ import annotations

import logging


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
```

- [ ] **Step 4: Implement server handlers and MCP registration**

Create `src/linux_debug_mcp/server.py`:

```python
from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from linux_debug_mcp.artifacts.store import ArtifactStore, ManifestStateError
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, ToolResponse
from linux_debug_mcp.logging import configure_logging
from linux_debug_mcp.prereqs.checks import check_prerequisites
from linux_debug_mcp.providers.registry import ProviderRegistry
from linux_debug_mcp.safety.paths import PathSafetyError, validate_source_path


DEFAULT_ARTIFACT_ROOT = Path(".linux-debug-mcp/runs")


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
) -> ToolResponse:
    try:
        resolved_source_path = validate_source_path(Path(source_path))
    except PathSafetyError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
            details={"source_path": source_path},
        )
    request = RunRequest(
        source_path=str(resolved_source_path),
        build_profile=build_profile,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        debug_profile=debug_profile,
        test_suite=test_suite,
        run_id=run_id,
    )
    try:
        store = ArtifactStore(artifact_root, source_paths=[resolved_source_path])
        manifest = store.create_run(request)
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


def get_manifest_handler(*, artifact_root: Path, run_id: str) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root)
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    return ToolResponse.success(
        summary=f"loaded manifest for {run_id}",
        run_id=run_id,
        data={"manifest": manifest.model_dump(mode="json")},
        artifacts=[ArtifactRef(path=str(artifact_root.expanduser().resolve() / run_id / "manifest.json"), kind="manifest")],
    )


def prerequisites_handler(
    *,
    artifact_root: Path,
    source_path: str | None,
    enable_libvirt_check: bool = False,
) -> ToolResponse:
    checks = check_prerequisites(
        artifact_root=artifact_root,
        source_path=Path(source_path) if source_path else None,
        enable_libvirt_check=enable_libvirt_check,
    )
    failed = [check for check in checks if check.status == "failed"]
    return ToolResponse.success(
        summary=f"{len(failed)} prerequisite checks failed",
        data={"checks": [check.model_dump(mode="json") for check in checks]},
        suggested_next_actions=["Fix failed checks", "kernel.create_run"],
    )


def list_providers_handler() -> ToolResponse:
    registry = ProviderRegistry.with_defaults()
    return ToolResponse.success(
        summary="listed provider capabilities",
        data={"providers": [provider.model_dump(mode="json") for provider in registry.list_capabilities()]},
    )


def not_implemented_handler(tool_name: str, *, run_id: str | None = None) -> ToolResponse:
    sprint_by_prefix = {
        "kernel.build": "Sprint 1",
        "target.boot": "Sprint 2",
        "target.run_tests": "Sprint 3",
        "artifacts.collect": "Sprint 3",
        "workflow.build_boot_test": "Sprint 3",
        "workflow.build_boot_debug": "Sprint 4",
        "debug.": "Sprint 4",
    }
    sprint = "a later sprint"
    for prefix, value in sprint_by_prefix.items():
        if tool_name.startswith(prefix):
            sprint = value
            break
    return ToolResponse.failure(
        category=ErrorCategory.NOT_IMPLEMENTED,
        message=f"{tool_name} is implemented in {sprint}",
        run_id=run_id,
        details={"tool": tool_name, "sprint": sprint},
        suggested_next_actions=["Use host.check_prerequisites", "Use kernel.create_run"],
    )


def create_app() -> FastMCP:
    app = FastMCP("linux-debug-mcp")

    @app.tool(name="host.check_prerequisites")
    def host_check_prerequisites(
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        source_path: str | None = None,
        enable_libvirt_check: bool = False,
    ) -> dict[str, Any]:
        return prerequisites_handler(
            artifact_root=Path(artifact_root),
            source_path=source_path,
            enable_libvirt_check=enable_libvirt_check,
        ).model_dump(mode="json")

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
    ) -> dict[str, Any]:
        return create_run_handler(
            artifact_root=Path(artifact_root),
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            debug_profile=debug_profile,
            test_suite=test_suite,
        ).model_dump(mode="json")

    @app.tool(name="providers.list")
    def providers_list() -> dict[str, Any]:
        return list_providers_handler().model_dump(mode="json")

    @app.tool(name="artifacts.get_manifest")
    def artifacts_get_manifest(run_id: str, artifact_root: str = str(DEFAULT_ARTIFACT_ROOT)) -> dict[str, Any]:
        return get_manifest_handler(artifact_root=Path(artifact_root), run_id=run_id).model_dump(mode="json")

    for tool_name in [
        "kernel.build",
        "target.boot",
        "target.run_tests",
        "artifacts.collect",
        "workflow.build_boot_test",
        "workflow.build_boot_debug",
        "debug.start_session",
        "debug.interrupt",
        "debug.continue",
        "debug.set_breakpoint",
        "debug.clear_breakpoint",
        "debug.list_breakpoints",
        "debug.read_registers",
        "debug.read_symbol",
        "debug.read_memory",
        "debug.evaluate",
        "debug.end_session",
    ]:

        def stub(run_id: str | None = None, _tool_name: str = tool_name) -> dict[str, Any]:
            return not_implemented_handler(_tool_name, run_id=run_id).model_dump(mode="json")

        app.tool(name=tool_name)(stub)

    return app


def main() -> None:
    configure_logging()
    create_app().run()
```

- [ ] **Step 5: Run server tests to verify they pass**

Run:

```bash
python -m pytest tests/test_server.py -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/logging.py src/linux_debug_mcp/server.py tests/test_server.py
git commit -m "feat: add sprint 0 mcp handlers"
```

---

### Task 9: Documentation And Full Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README with Sprint 0 usage**

Replace `README.md` with:

```markdown
# Linux Development MCP Server

An MCP server foundation for Linux kernel development workflows in agentic
development environments.

## Sprint 0 Scope

Sprint 0 provides a runnable Python MCP skeleton and local foundation services:

- host prerequisite checks
- durable run workspace creation
- manifest readback
- provider capability listing
- structured `not_implemented` responses for later build, boot, test, artifact,
  workflow, and debug tools

Sprint 0 does not build kernels, modify libvirt domains, boot guests, run SSH or
serial commands, attach gdb, or collect real VM artifacts.

## Install

```bash
python -m pip install -e '.[test]'
```

## Test

```bash
python -m pytest
```

The unit tests do not require libvirt, QEMU, a Linux checkout, or gdb.

## Start The Server

```bash
linux-debug-mcp
```

The console script starts the MCP server using the Python MCP SDK.

## Foundational Tools

`host.check_prerequisites` checks local Python, host tools, artifact root
writability, optional Linux source tree markers, and optional non-destructive
libvirt visibility.

`kernel.create_run` creates a run directory under the artifact root and writes a
durable `manifest.json`.

`artifacts.get_manifest` returns a redacted manifest view.

`providers.list` returns Sprint 0 provider capability declarations.

Later-sprint tools return structured `not_implemented` responses.

## Artifact Layout

Each run is stored under:

```text
<artifact-root>/<run-id>/
  manifest.json
  inputs/
  logs/
  build/
  target/
  tests/
  debug/
  summaries/
  sensitive/
```

The manifest records schema version, writer version, immutable run inputs,
planned steps, step results, and cleanup state.

## Interpreting Prerequisite Failures

Each prerequisite result includes a stable `check_id`, status, message, optional
details, and suggested fix. Sprint 0 never installs packages or modifies the
host; apply fixes manually and rerun `host.check_prerequisites`.
```

- [ ] **Step 2: Run the full unit test suite**

Run:

```bash
python -m pytest
```

Expected: PASS for all tests.

- [ ] **Step 3: Verify editable install metadata and app construction**

Run:

```bash
python -m pip install -e '.[test]'
python -c "import linux_debug_mcp; print(linux_debug_mcp.__version__)"
python -c "from linux_debug_mcp.server import create_app; print(type(create_app()).__name__)"
```

Expected:

```text
0.1.0
FastMCP
```

The `pip install` command should exit 0. The second command prints `0.1.0`. The third command prints `FastMCP`.

- [ ] **Step 4: Verify the console entrypoint starts**

Run:

```bash
timeout 2 linux-debug-mcp || test $? -eq 124
```

Expected: command exits 0. Exit 124 from `timeout` is accepted because it means the MCP server stayed running until the bounded smoke check stopped it; any immediate import, packaging, or startup failure makes the command exit nonzero.

- [ ] **Step 5: Run diff hygiene check**

Run:

```bash
git diff --check
```

Expected: no output and exit 0.

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "docs: document sprint 0 foundation"
```

---

## Self-Review Checklist

Before marking implementation complete, verify each Sprint 0 requirement:

- [ ] Python package installs in editable mode with `python -m pip install -e '.[test]'`.
- [ ] Unit tests pass with `python -m pytest` and do not require libvirt, QEMU, a Linux checkout, or gdb.
- [ ] `create_app()` constructs the MCP server.
- [ ] `timeout 2 linux-debug-mcp || test $? -eq 124` proves the console entrypoint starts without an immediate crash.
- [ ] `host.check_prerequisites` handler returns structured checks and does not modify the host.
- [ ] `kernel.create_run` handler creates the run directory and `manifest.json`.
- [ ] `artifacts.get_manifest` returns a manifest through the shared response envelope.
- [ ] `providers.list` returns the static Sprint 0 capabilities.
- [ ] Stubbed later-sprint tools return `not_implemented`.
- [ ] README documents install, tests, server startup, run creation, manifest inspection, and prerequisite failures.
- [ ] `git diff --check` exits 0.
