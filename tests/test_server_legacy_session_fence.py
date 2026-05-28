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

from _layer4_fakes import FakeQemuTransport, build_txn
from conftest import rootfs

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile, RootfsProfile
from linux_debug_mcp.coordination.admission import AdmissionService
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.coordination.transaction import TransportTransaction
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.providers.qemu_gdbstub import DebugSession
from linux_debug_mcp.seams.target import (
    BreakHint,
    ConsoleKind,
    PlatformMetadata,
    TargetKey,
    publish_ready_snapshot,
)
from linux_debug_mcp.server import debug_continue_handler
from linux_debug_mcp.transport.base import LineRole, TransportRef

RUN_ID = "run-1"
KEY = TargetKey(provisioner="local-qemu", target_id=RUN_ID)
GDBSTUB_ENDPOINT = {"host": "127.0.0.1", "port": 1234}
RSP_CHANNEL = TransportRef(
    provider="qemu-gdbstub",
    channel_id="rsp0",
    line_role=LineRole.RSP,
    caps=("rsp",),
    target_ref=GDBSTUB_ENDPOINT,
)
PLATFORM_WITH_SSH = PlatformMetadata(
    console_kind=ConsoleKind.UART,
    console_count=1,
    dedicated_debug_line=False,
    ssh_reachable=True,
    break_hints=[BreakHint.GDBSTUB_NATIVE],
)


def _profiles() -> dict[str, DebugProfile]:
    return {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")}


def _build_transaction(
    *,
    registry: SessionRegistry,
    generation: int = 1,
) -> tuple[TransportTransaction, AdmissionService]:
    txn, admission = build_txn(FakeQemuTransport(), registry=registry, generation=generation)
    publish_ready_snapshot(
        admission,
        target_key=KEY,
        generation=generation,
        transports=[RSP_CHANNEL],
        platform=PLATFORM_WITH_SSH,
    )
    return txn, admission


def _make_registry(tmp_path: Path) -> SessionRegistry:
    directory = tmp_path / "reg"
    directory.mkdir(parents=True, exist_ok=True)
    return SessionRegistry(directory=directory)


def _seed_legacy_debug_session(tmp_path: Path) -> Path:
    """Create a run whose manifest records an ATTACHED, HALTED ('stopped') DebugSession with a raw
    gdbstub_endpoint and NO matching SessionRegistry ownership record — the pre-Layer-4 shape."""
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
    run_dir = store.run_dir(manifest.run_id)
    vmlinux = run_dir / "build" / "vmlinux"
    kernel = run_dir / "build" / "bzImage"
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

    session_path = run_dir / "debug" / "sessions" / "debug-1.json"
    transcript_path = run_dir / "debug" / "attempt-001" / "transcript.txt"
    commands_path = run_dir / "debug" / "attempt-001" / "commands.jsonl"
    summary_path = run_dir / "debug" / "attempt-001" / "debug-summary.json"
    for path in [session_path, transcript_path, commands_path, summary_path]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    session = DebugSession(
        session_id="debug-1",
        run_id=manifest.run_id,
        provider_name="local-qemu-gdbstub",
        gdbstub_endpoint=GDBSTUB_ENDPOINT,
        vmlinux_path=str(vmlinux),
        selected_debug_profile="qemu-gdbstub-default",
        attach_status="attached",
        started_at="2026-05-20T00:00:00+00:00",
        current_execution_state="stopped",
        transcript_path=str(transcript_path),
        command_metadata_path=str(commands_path),
        latest_summary_path=str(summary_path),
        symbol_identity_validation={"same_run_artifact_linkage": True, "live_banner_match": True},
    )
    session_path.write_text(session.model_dump_json(indent=2), encoding="utf-8")
    # Record the debug step pointing at the legacy session file — NO transport_session_id, the
    # hallmark of a pre-Layer-4 session (no ownership binding).
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="debug",
            status=StepStatus.SUCCEEDED,
            summary="debug session started",
            artifacts=[ArtifactRef(path=str(session_path), kind="debug-session")],
            details={"debug_session_id": "debug-1", "session_path": str(session_path)},
        ),
    )
    return artifact_root


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
            from linux_debug_mcp.providers.qemu_gdbstub import DebugProviderResult

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
