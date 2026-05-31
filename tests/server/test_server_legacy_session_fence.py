"""Task B7: version-skew fence for legacy (pre-Layer-4) DebugSessions.

A DebugSession persisted before the transport-ownership model existed carries a raw
`gdbstub_endpoint` but NO durable SessionRegistry ownership record. After the Layer-4 upgrade such
a session must NOT be silently resumed: when a stateful debug.* op loads it on a WIRED server
(session_registry/admission injected) and finds no ownership record for the target, the handler
refuses with DEBUG_ATTACH_FAILURE / `legacy_session_no_ownership` AND converts the target to a
`recovery_required` tombstone (durable + admission cache, the dual-write) so target.run_tests stays
gated and the legacy session can't bypass the durable model.

The fence runs BEFORE the live-attachment lookup (ADR 0021 fence-then-lookup): a legacy session
never reaches the gdb/MI engine. Without the fence deps (no admission/registry) the fence is inert
and the op instead fails `no_live_session` (the engine holds no live attachment for it).
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
    FakeMiEngine,
    rootfs,
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
    seed_legacy_debug_session as _seed_legacy_debug_session,
)

from kdive.config import RootfsProfile
from kdive.domain import ErrorCategory
from kdive.providers.local.gdb_mi import GdbMiSessionRegistry
from kdive.server import debug_continue_handler, debug_end_session_handler


def test_legacy_session_without_ownership_record_is_refused(tmp_path: Path) -> None:
    artifact_root = _seed_legacy_debug_session(tmp_path)
    registry = _make_registry(tmp_path)
    _txn, admission = _build_transaction(registry=registry)
    # No ownership record was written for KEY — this is the legacy / version-skew shape.
    assert registry.read_record(KEY) is None

    response = debug_continue_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        debug_profiles=_profiles(),
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
    )

    assert response.ok is False
    # The fence fires before the live-attachment lookup, so the engine is never reached.
    assert response.error.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert response.error.details["code"] == "legacy_session_no_ownership"


def test_legacy_session_converted_to_tombstone_when_not_executing(tmp_path: Path) -> None:
    artifact_root = _seed_legacy_debug_session(tmp_path)
    registry = _make_registry(tmp_path)
    _txn, admission = _build_transaction(registry=registry)

    response = debug_continue_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        debug_profiles=_profiles(),
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
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

    from kdive.server import target_run_tests_handler

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
    """The fence is inert when no session_registry/admission is injected — it never fires. With the
    engine wired but no live attachment for this legacy session, the op then fails `no_live_session`
    (CONFIGURATION_ERROR), NOT `legacy_session_no_ownership` — proving the fence did not run."""
    artifact_root = _seed_legacy_debug_session(tmp_path)
    response = debug_continue_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        debug_profiles=_profiles(),
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
    )

    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "no_live_session"


def test_legacy_session_end_session_writes_tombstone_after_detach(tmp_path: Path) -> None:
    """B7 review: end_session must NOT be silently allowed on a legacy session — force-end runs (the
    live attachment, if any, is reaped), but the target gets a recovery_required tombstone afterwards
    so target.run_tests stays gated and is not blind to the unmanaged stop that just got detached."""
    artifact_root = _seed_legacy_debug_session(tmp_path)
    registry = _make_registry(tmp_path)
    _txn, admission = _build_transaction(registry=registry)
    # No ownership record — legacy shape — so the pre-detach fence would otherwise refuse;
    # end_session bypasses it to permit force-end, then tombstones post-detach.
    assert registry.read_record(KEY) is None

    end = debug_end_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        debug_profiles=_profiles(),
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
    )

    # (a) the force-end succeeded (end_session records the session ENDED).
    assert end.ok is True
    # (b) a recovery_required tombstone now exists for the target (dual-write).
    tombstone = registry.read_tombstone(KEY)
    assert tombstone is not None
    assert tombstone.target_key == KEY
    assert admission._recovery_required.get(KEY) == tombstone.generation

    # (c) target.run_tests is now gated, not blind to the just-detached unmanaged stop.
    from conftest import FakeTestProvider

    from kdive.server import target_run_tests_handler

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


# ---------------------------------------------------------------------------
# Finding F8 — debug.read_* must run the ownership assertion (no tombstone — reads are
# non-destructive), so a legacy DebugSession can't halt the kernel via `target remote` against
# a run the durable model has no record for.
# ---------------------------------------------------------------------------


def test_legacy_session_refused_in_debug_read_when_session_registry_wired(tmp_path: Path) -> None:
    """F8: when `session_registry` is threaded into a `debug.read_*` handler and no durable
    record exists for the run, the handler refuses with `legacy_session_no_ownership` BEFORE the
    live-attachment lookup."""
    from kdive.server import debug_read_registers_handler

    artifact_root = _seed_legacy_debug_session(tmp_path)
    registry = _make_registry(tmp_path)
    # legacy shape: no ownership record for KEY.
    assert registry.read_record(KEY) is None

    response = debug_read_registers_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        registers=["pc"],
        debug_profiles=_profiles(),
        session_registry=registry,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert response.error.details["code"] == "legacy_session_no_ownership"
    # F8 is read-non-destructive: no tombstone is written on the read path (the mutating-op
    # `_fence_legacy_debug_session` is the one that tombstones — `_assert_layer4_ownership` does not).
    assert registry.read_tombstone(KEY) is None
