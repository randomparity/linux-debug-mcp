from __future__ import annotations

from typing import cast

import pytest

from kdive.artifacts import store as artifact_store
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.domain import StepResult, StepStatus
from kdive.postmortem import handlers as postmortem_handlers


class _FlakyManifestStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, StepResult, bool, bool]] = []

    def record_step_result(
        self,
        run_id: str,
        result: StepResult,
        *,
        append: bool = False,
        replace_succeeded: bool = False,
    ) -> None:
        self.calls.append((run_id, result, append, replace_succeeded))
        if len(self.calls) == 1:
            raise ManifestStateError("manifest is locked")


def test_manifest_step_retry_retries_transient_manifest_lock() -> None:
    store = _FlakyManifestStore()
    result = StepResult(step_name="debug", status=StepStatus.SUCCEEDED, summary="debug completed")

    artifact_store.record_step_with_retry(
        cast(ArtifactStore, store),
        "run-1",
        result,
        append=True,
        replace_succeeded=False,
        initial_delay_seconds=0,
    )

    assert store.calls == [
        ("run-1", result, True, False),
        ("run-1", result, True, False),
    ]


def test_manifest_step_retry_surfaces_non_lock_manifest_errors() -> None:
    class _BrokenManifestStore:
        def record_step_result(
            self,
            run_id: str,
            result: StepResult,
            *,
            append: bool = False,
            replace_succeeded: bool = False,
        ) -> None:
            raise ManifestStateError("manifest is corrupt")

    with pytest.raises(ManifestStateError, match="manifest is corrupt"):
        artifact_store.record_step_with_retry(
            cast(ArtifactStore, _BrokenManifestStore()),
            "run-1",
            StepResult(step_name="debug", status=StepStatus.FAILED, summary="debug failed"),
            initial_delay_seconds=0,
        )


def test_postmortem_dump_handlers_are_owned_by_postmortem_module() -> None:
    from kdive import server

    assert postmortem_handlers.debug_postmortem_check_prereqs_handler.__module__ == "kdive.postmortem.handlers"
    assert postmortem_handlers.debug_postmortem_list_dumps_handler.__module__ == "kdive.postmortem.handlers"
    assert postmortem_handlers.debug_postmortem_fetch_handler.__module__ == "kdive.postmortem.handlers"
    app = server.create_app()
    assert app._tool_manager._tools["debug.postmortem.check_prereqs"].fn.__module__ == "kdive.postmortem.tools"
    assert app._tool_manager._tools["debug.postmortem.list_dumps"].fn.__module__ == "kdive.postmortem.tools"
    assert app._tool_manager._tools["debug.postmortem.fetch"].fn.__module__ == "kdive.postmortem.tools"


def test_debug_start_session_handler_is_owned_by_debug_module() -> None:
    from kdive import server
    from kdive.debug import session_handlers

    assert session_handlers.debug_start_session_handler.__module__ == "kdive.debug.session_handlers"
    assert not hasattr(server, "debug_start_session_handler")
