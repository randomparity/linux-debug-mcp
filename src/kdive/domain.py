from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import Field

from kdive.config import BootOverrides, BuildOverrides
from kdive.model import Model


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
    STALE_HANDLE = "stale_handle"
    TRANSPORT_CONFLICT = "transport_conflict"


class PrerequisiteStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"


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
    build_overrides: BuildOverrides | None = None
    boot_overrides: BootOverrides | None = None


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
    ) -> ToolResponse:
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
        status: StepStatus = StepStatus.FAILED,
        details: dict[str, Any] | None = None,
        artifacts: list[ArtifactRef] | None = None,
        suggested_next_actions: list[str] | None = None,
    ) -> ToolResponse:
        return cls(
            ok=False,
            status=status,
            run_id=run_id,
            artifacts=artifacts or [],
            error=ErrorInfo(category=category, message=message, details=details or {}),
            suggested_next_actions=suggested_next_actions or [],
        )
