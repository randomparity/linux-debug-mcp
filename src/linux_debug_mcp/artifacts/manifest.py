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
    def create(cls, *, run_id: str, request: RunRequest) -> RunManifest:
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

    def with_step_result(self, result: StepResult) -> RunManifest:
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
