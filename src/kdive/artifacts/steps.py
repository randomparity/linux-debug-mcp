from __future__ import annotations

from kdive.artifacts.store import ArtifactStore, record_step_with_retry
from kdive.domain import StepResult


def record_append_only_terminal_step(store: ArtifactStore, run_id: str, result: StepResult) -> None:
    record_step_with_retry(store, run_id, result, append=True)
