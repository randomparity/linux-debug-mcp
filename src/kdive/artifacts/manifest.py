from __future__ import annotations

from datetime import UTC, datetime

from pydantic import Field

from kdive import __version__
from kdive.config import BuildProfile, RootfsProfile, TargetProfile
from kdive.domain import Model, RunRequest, RunStep, StepResult, StepStatus


class BootAttempt(Model):
    attempt: int
    resolved_target_profile: TargetProfile
    resolved_rootfs_profile: RootfsProfile
    status: StepStatus
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RunManifest(Model):
    schema_version: int = 3
    writer_version: str = __version__
    run_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    request: RunRequest
    steps: list[RunStep] = Field(default_factory=list)
    step_results: dict[str, StepResult] = Field(default_factory=dict)
    cleanup_state: str = "not_started"
    resolved_build_profile: BuildProfile | None = None
    resolved_target_profile: TargetProfile | None = None
    resolved_rootfs_profile: RootfsProfile | None = None
    boot_attempts: list[BootAttempt] = Field(default_factory=list)

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        request: RunRequest,
        resolved_build_profile: BuildProfile | None = None,
        resolved_target_profile: TargetProfile | None = None,
        resolved_rootfs_profile: RootfsProfile | None = None,
    ) -> RunManifest:
        return cls(
            run_id=run_id,
            request=request,
            resolved_build_profile=resolved_build_profile,
            resolved_target_profile=resolved_target_profile,
            resolved_rootfs_profile=resolved_rootfs_profile,
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

    def append_step_result(self, result: StepResult) -> RunManifest:
        """Append a new step result. Unlike ``with_step_result``, this never
        replaces an existing entry and never short-circuits — duplicate
        ``step_name`` raises. Spec §5.2 step 13 uses this for
        ``introspect:<call_id>`` records, where every call is a fresh entry
        and collisions are an internal bug (UUIDv4).

        ``self.steps`` is intentionally untouched. ``steps`` is the fixed
        *planned* list of six well-known workflow steps (create_run, build,
        boot, run_tests, collect_artifacts, debug). Introspect calls are
        dynamic — they grow ``step_results`` under ``introspect:<call_id>``
        keys but stay out of ``steps``.
        """
        if result.step_name in self.step_results:
            raise ValueError(f"step name already recorded: {result.step_name}")
        clone = self.model_copy(deep=True)
        clone.step_results[result.step_name] = result
        return clone

    def with_boot_attempt(self, attempt: BootAttempt) -> RunManifest:
        clone = self.model_copy(deep=True)
        clone.boot_attempts.append(attempt)
        return clone
