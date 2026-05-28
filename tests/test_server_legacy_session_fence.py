"""Task B7: version-skew fence for legacy (pre-Layer-4) DebugSessions.

A DebugSession persisted before the transport-ownership model existed carries a raw
`gdbstub_endpoint` but NO durable SessionRegistry ownership record. After the Layer-4 upgrade such
a session must NOT be silently resumed: when a stateful debug.* op loads it on a WIRED server
(session_registry/admission injected) and finds no ownership record for the target, the handler
refuses with DEBUG_ATTACH_FAILURE / `legacy_session_no_ownership` AND converts the target to a
`recovery_required` tombstone (durable + admission cache, the dual-write) so target.run_tests stays
gated and the legacy session can't bypass the durable model.

The fence is ADDITIVE: a legacy caller that passes neither dep (the existing debug-handler tests)
gets the unchanged path with no fence.
"""

from __future__ import annotations

from pathlib import Path

from conftest import (
    LEGACY_FENCE_KEY as KEY,
)
from conftest import (
    LEGACY_FENCE_RUN_ID as RUN_ID,
)
from conftest import (
    legacy_fence_build_transaction as _build_transaction,
)
from conftest import (
    legacy_fence_make_registry as _make_registry,
)
from conftest import (
    legacy_fence_profiles as _profiles,
)
from conftest import (
    rootfs,
)
from conftest import (
    seed_legacy_debug_session as _seed_legacy_debug_session,
)

from linux_debug_mcp.config import RootfsProfile
from linux_debug_mcp.domain import ErrorCategory, StepStatus
from linux_debug_mcp.providers.qemu_gdbstub import DebugProviderResult
from linux_debug_mcp.server import debug_continue_handler, debug_end_session_handler


class _ExplodingProvider:
    """The fence must short-circuit BEFORE the provider runs. If a debug op reaches this provider it
    means the legacy session was silently resumed — exactly what B7 forbids."""

    name = "local-qemu-gdbstub"

    def continue_execution(self, **kwargs):  # noqa: ANN003
        raise AssertionError("provider invoked: a legacy session was silently resumed, not fenced")


def test_legacy_session_without_ownership_record_is_refused(tmp_path: Path) -> None:
    artifact_root = _seed_legacy_debug_session(tmp_path)
    registry = _make_registry(tmp_path)
    _txn, admission = _build_transaction(registry=registry)
    # No ownership record was written for KEY — this is the legacy / version-skew shape.
    assert registry.read_record(KEY) is None

    response = debug_continue_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=_ExplodingProvider(),
        debug_profiles=_profiles(),
        admission=admission,
        session_registry=registry,
    )

    assert response.ok is False
    assert response.error.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert response.error.details["code"] == "legacy_session_no_ownership"


def test_legacy_session_converted_to_tombstone_when_not_executing(tmp_path: Path) -> None:
    artifact_root = _seed_legacy_debug_session(tmp_path)
    registry = _make_registry(tmp_path)
    _txn, admission = _build_transaction(registry=registry)

    response = debug_continue_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=_ExplodingProvider(),
        debug_profiles=_profiles(),
        admission=admission,
        session_registry=registry,
    )

    assert response.ok is False
    # The refusal dual-wrote a recovery_required tombstone: durable record + admission cache.
    tombstone = registry.read_tombstone(KEY)
    assert tombstone is not None
    assert tombstone.target_key == KEY
    # admission's write-through cache was marked too: an ordinary run-tests admit is now gated.
    assert admission._recovery_required.get(KEY) == tombstone.generation

    # End-to-end: target.run_tests is now blind-fenced (recovery_required), not silently runnable.
    from conftest import FakeTestProvider

    from linux_debug_mcp.server import target_run_tests_handler

    rootfs_profile: RootfsProfile = rootfs(tmp_path)
    tests = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs_profile},
        admission=admission,
        session_registry=registry,
    )
    assert tests.ok is False


def test_legacy_fence_inert_without_injected_deps(tmp_path: Path) -> None:
    """ADDITIVE gate: a legacy caller that passes no session_registry/admission gets the unchanged
    path — the fence never fires, and the op reaches the provider (proving no fence ran)."""
    artifact_root = _seed_legacy_debug_session(tmp_path)

    class _CountingProvider:
        name = "local-qemu-gdbstub"

        def __init__(self) -> None:
            self.calls = 0

        def continue_execution(self, **kwargs):  # noqa: ANN003
            self.calls += 1
            return DebugProviderResult(
                status=StepStatus.SUCCEEDED,
                summary="continued",
                session=kwargs["session"],
                details={"debug_session_id": kwargs["session"].session_id},
            )

    provider = _CountingProvider()
    response = debug_continue_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=provider,
        debug_profiles=_profiles(),
    )

    assert response.ok is True
    assert provider.calls == 1


class _DetachingEndSessionProvider:
    """End_session detach: returns the session with execution_state=ended, mirroring a successful
    gdb detach. The fence MUST allow the detach to run (force-end) but tombstone the target after."""

    name = "local-qemu-gdbstub"

    def __init__(self) -> None:
        self.calls = 0

    def end_session(self, **kwargs):  # noqa: ANN003
        self.calls += 1
        session = kwargs["session"].model_copy(
            update={"current_execution_state": "ended", "ended_at": "2026-05-27T00:01:00+00:00"}
        )
        return DebugProviderResult(
            status=StepStatus.SUCCEEDED,
            summary="debug session ended",
            session=session,
            details={"debug_session_id": session.session_id, "current_execution_state": "ended"},
        )


def test_legacy_session_end_session_writes_tombstone_after_detach(tmp_path: Path) -> None:
    """B7 review: end_session must NOT be silently allowed on a legacy session — force-end runs (gdb
    detach is the operation), but the target gets a recovery_required tombstone afterwards so
    target.run_tests stays gated and is not blind to the unmanaged stop that just got detached."""
    artifact_root = _seed_legacy_debug_session(tmp_path)
    registry = _make_registry(tmp_path)
    _txn, admission = _build_transaction(registry=registry)
    # No ownership record — legacy shape — so the pre-detach fence would otherwise refuse;
    # end_session bypasses it to permit force-end, then tombstones post-detach.
    assert registry.read_record(KEY) is None
    provider = _DetachingEndSessionProvider()

    end = debug_end_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=provider,
        debug_profiles=_profiles(),
        admission=admission,
        session_registry=registry,
    )

    # (a) the gdb detach succeeded (force-end ran).
    assert end.ok is True
    assert provider.calls == 1
    # (b) a recovery_required tombstone now exists for the target (dual-write).
    tombstone = registry.read_tombstone(KEY)
    assert tombstone is not None
    assert tombstone.target_key == KEY
    assert admission._recovery_required.get(KEY) == tombstone.generation

    # (c) target.run_tests is now gated, not blind to the just-detached unmanaged stop.
    from conftest import FakeTestProvider

    from linux_debug_mcp.server import target_run_tests_handler

    rootfs_profile: RootfsProfile = rootfs(tmp_path)
    tests = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs_profile},
        admission=admission,
        session_registry=registry,
    )
    assert tests.ok is False
    assert tests.error.category == ErrorCategory.READINESS_FAILURE
