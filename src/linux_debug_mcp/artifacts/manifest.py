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
    ) -> RunManifest:
        return cls(
            run_id=run_id,
            request=request,
            resolved_build_profile=resolved_build_profile,
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
