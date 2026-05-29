"""Handler-level wiring + conformance tests for SessionGuard (issue #66).

The run/manifest/transaction setup helpers (`_create_debug_ready_run`, `_build_debug_transaction`,
`_make_test_registry`) and the fake providers are adapted from `tests/test_phase_b_integration_gaps.py`,
which already drives `debug_start_session_handler` through a wired Layer-4 transaction. The
`test_debug_start_session_closes_transport_on_failed_attach` test there is the resume-on-error
regression anchor this SessionGuard routing must keep green.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from _layer4_fakes import KEY, PLATFORM, FakeQemuTransport, build_txn

from linux_debug_mcp.config import DebugProfile
from linux_debug_mcp.coordination.admission import AdmissionError, AdmissionService
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.coordination.transaction import TransportTransaction
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.providers.qemu_gdbstub import DebugProviderResult, DebugSession, ProviderDebugError
from linux_debug_mcp.seams.guard import SessionGuard, SessionGuardContext
from linux_debug_mcp.seams.lifecycle import InProcessLifecycleDispatcher, LifecycleEvent, LifecycleKind
from linux_debug_mcp.seams.target import publish_ready_snapshot
from linux_debug_mcp.server import (
    _admit_run_tests_ssh_tier,
    debug_end_session_handler,
    debug_start_session_handler,
)
from linux_debug_mcp.transport.base import LineRole, TransportRef

from linux_debug_mcp.artifacts.store import ArtifactStore  # isort: skip

RUN_ID = "run-1"
GDBSTUB_ENDPOINT = {"host": "127.0.0.1", "port": 1234}
RSP_CHANNEL = TransportRef(
    provider="qemu-gdbstub",
    channel_id="rsp0",
    line_role=LineRole.RSP,
    caps=("rsp",),
    target_ref=GDBSTUB_ENDPOINT,
)


def _make_test_registry(tmp_path: Path) -> SessionRegistry:
    directory = tmp_path / "reg"
    directory.mkdir(parents=True, exist_ok=True)
    return SessionRegistry(directory=directory)


def _build_debug_transaction(
    registry: SessionRegistry, *, generation: int = 1
) -> tuple[TransportTransaction, AdmissionService]:
    txn, admission = build_txn(FakeQemuTransport(), registry=registry, generation=generation)
    publish_ready_snapshot(
        admission, target_key=KEY, generation=generation, transports=[RSP_CHANNEL], platform=PLATFORM
    )
    return txn, admission


def _create_debug_ready_run(tmp_path: Path) -> Path:
    artifact_root = tmp_path / "runs"
    source = tmp_path / "source"
    source.mkdir()
    store = ArtifactStore(artifact_root, source_paths=[source])
    manifest = store.create_run(
        RunRequest(
            source_path=str(source),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
            debug_profile="qemu-gdbstub-default",
            run_id=RUN_ID,
        )
    )
    vmlinux = artifact_root / manifest.run_id / "build" / "vmlinux"
    kernel = artifact_root / manifest.run_id / "build" / "bzImage"
    vmlinux.write_text("vmlinux", encoding="utf-8")
    kernel.write_text("kernel", encoding="utf-8")
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="built",
            artifacts=[
                ArtifactRef(path=str(kernel), kind="kernel-image"),
                ArtifactRef(path=str(vmlinux), kind="vmlinux"),
            ],
            details={"kernel_release": "6.9.0-test"},
        ),
    )
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary="booted",
            details={"debug_boot": True, "gdbstub_endpoint": GDBSTUB_ENDPOINT},
        ),
    )
    return artifact_root


def _profiles() -> dict[str, DebugProfile]:
    return {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")}


class _FakeDebugProviderOk:
    """Start + end capable fake gdbstub provider; start parks the session HALTED (stopped)."""

    name = "local-qemu-gdbstub"

    def start_session(self, **kwargs: Any) -> DebugProviderResult:
        run_dir = kwargs["run_dir"]
        session_path = run_dir / "debug" / "sessions" / "debug-1.json"
        transcript_path = run_dir / "debug" / "attempt-001" / "transcript.txt"
        commands_path = run_dir / "debug" / "attempt-001" / "commands.jsonl"
        summary_path = run_dir / "debug" / "attempt-001" / "debug-summary.json"
        for path in [session_path, transcript_path, commands_path, summary_path]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}", encoding="utf-8")
        session = DebugSession(
            session_id="debug-1",
            run_id=kwargs["run_id"],
            provider_name=self.name,
            gdbstub_endpoint=kwargs["gdbstub_endpoint"],
            vmlinux_path=str(kwargs["vmlinux_path"]),
            selected_debug_profile=kwargs["debug_profile"].name,
            attach_status="attached",
            started_at="2026-05-29T00:00:00+00:00",
            current_execution_state="stopped",
            transcript_path=str(transcript_path),
            command_metadata_path=str(commands_path),
            latest_summary_path=str(summary_path),
            symbol_identity_validation={"same_run_artifact_linkage": True, "live_banner_match": True},
        )
        session_path.write_text(session.model_dump_json(indent=2), encoding="utf-8")
        return DebugProviderResult(
            status=StepStatus.SUCCEEDED,
            summary="debug session started",
            session=session,
            artifacts=[
                ArtifactRef(path=str(session_path), kind="debug-session"),
                ArtifactRef(path=str(transcript_path), kind="debug-transcript", sensitive=True),
                ArtifactRef(path=str(commands_path), kind="debug-command-metadata"),
                ArtifactRef(path=str(summary_path), kind="debug-summary"),
            ],
            details={"debug_session_id": "debug-1"},
        )

    def end_session(self, **kwargs: Any) -> DebugProviderResult:
        session = kwargs["session"].model_copy(
            update={"current_execution_state": "ended", "ended_at": "2026-05-29T00:01:00+00:00"}
        )
        return DebugProviderResult(
            status=StepStatus.SUCCEEDED,
            summary="debug session ended",
            session=session,
            artifacts=[
                ArtifactRef(
                    path=str(kwargs["run_dir"] / "debug" / "sessions" / f"{session.session_id}.json"),
                    kind="debug-session",
                ),
            ],
            details={"debug_session_id": session.session_id, "current_execution_state": "ended"},
        )


class _FakeDebugProviderFailingAttach:
    name = "local-qemu-gdbstub"

    def start_session(self, **kwargs: Any) -> DebugProviderResult:
        raise ProviderDebugError(
            "gdb attach exploded",
            category=ErrorCategory.DEBUG_ATTACH_FAILURE,
            details={"code": "attach_failed"},
        )


# --------------------------------------------------------------------------- Task 5: wiring


def test_start_session_runs_enter_before_open(tmp_path):
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)
    calls: list[str] = []

    class _Pre:
        name = "pre"

        def check(self, ctx: SessionGuardContext) -> None:
            calls.append("pre")

    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=_FakeDebugProviderOk(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=SessionGuard(pre_attach=[_Pre()]),
    )
    assert resp.ok is True
    assert calls == ["pre"]


def test_start_session_open_failure_does_not_call_guard_teardown(tmp_path):
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)
    txn._guard.acquire(KEY)  # pre-hold the stop-capable guard so open() raises GuardConflict
    teardown_reasons: list[str] = []

    class _Guard(SessionGuard):
        def teardown(self, ctx, **kw):  # type: ignore[override]
            teardown_reasons.append(ctx.reason)
            return super().teardown(ctx, **kw)

    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=_FakeDebugProviderOk(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=_Guard(),
    )
    assert resp.ok is False  # the existing early TRANSPORT_CONFLICT return
    assert teardown_reasons == []  # open() failure is NOT a guard teardown path


def test_end_session_routes_through_guard_teardown(tmp_path):
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)
    provider = _FakeDebugProviderOk()
    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=provider,
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=SessionGuard(),
    )
    assert start.ok is True
    seen: list[str] = []

    class _Guard(SessionGuard):
        def teardown(self, ctx, **kw):  # type: ignore[override]
            seen.append(ctx.reason)
            return super().teardown(ctx, **kw)

    resp = debug_end_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=provider,
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=_Guard(),
    )
    assert resp.ok is True
    assert seen == ["ended"]


# --------------------------------------------------------------------------- Task 6: conformance


def test_resume_on_error_reaps_and_tombstones(tmp_path):
    # provider.start_session raises after _halt parked HALTED -> guard.teardown(reason="attach_error")
    # -> transaction.close(force=False): record deleted, closed_while_halted tombstone gates future
    # ssh-tier admit, guard freed. Mirrors test_phase_b_integration_gaps.py's resume-on-error anchor.
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=_FakeDebugProviderFailingAttach(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=SessionGuard(),
    )
    assert resp.ok is False
    assert registry.read_record(KEY) is None  # record deleted (not left HALTED)
    tombstone = registry.read_tombstone(KEY)
    assert tombstone is not None and tombstone.reason == "closed_while_halted"
    assert admission._bindings.get(KEY, []) == []  # promoted binding deregistered
    txn._guard.acquire(KEY)  # guard is free (no GuardConflict)


def test_ssh_tier_rejected_while_halted_then_admitted_after_end(tmp_path):
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)
    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=_FakeDebugProviderOk(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=SessionGuard(),
    )
    assert start.ok is True  # session parked HALTED
    with pytest.raises(AdmissionError) as exc:
        _admit_run_tests_ssh_tier(run_id=RUN_ID, admission=admission, session_registry=registry)
    assert exc.value.code == "target_halted"  # AC2: fast-rejected, not hung
    end = debug_end_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=_FakeDebugProviderOk(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=SessionGuard(),
    )
    assert end.ok is True
    handle = _admit_run_tests_ssh_tier(run_id=RUN_ID, admission=admission, session_registry=registry)
    assert handle is not None  # resumed -> ssh-tier admits again


def test_timeout_path_leaves_no_orphan_or_halted_record(tmp_path):
    # The dispatcher invalidation path is NOT routed through SessionGuard; the existing
    # _SessionSubscriber reap satisfies AC1's "times out" clause (no orphan, no live HALTED record).
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)
    # Bind a dispatcher so the opened session subscribes (production binds one in create_app;
    # build_txn does not). The bound _SessionSubscriber is what reaps on invalidation.
    dispatcher = InProcessLifecycleDispatcher()
    txn.bind_lifecycle(dispatcher)
    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=_FakeDebugProviderOk(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=SessionGuard(),
    )
    assert start.ok is True
    admission.invalidate_lifecycle(
        LifecycleEvent(target_key=KEY, kind=LifecycleKind.RESETTING), dispatcher, generation=1
    )
    assert registry.read_record(KEY) is None  # reaped by _SessionSubscriber
