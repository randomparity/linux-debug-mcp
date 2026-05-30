"""Handler-level tests for debug.start_session / debug.read_memory / debug.end_session on the live
gdb/MI engine (#81). The session-of-record is the live attachment held by the registry; there is no
batch provider behind it."""

from pathlib import Path

from conftest import FakeMiEngine, build_debug_transport, kernel_provenance_details, write_vmlinux_with_build_id

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.providers.gdb_mi import GdbMiError, GdbMiSessionRegistry
from linux_debug_mcp.providers.qemu_gdbstub import DebugSession
from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.server import debug_end_session_handler, debug_read_memory_handler, debug_start_session_handler

RUN_ID = "run-debug"


def create_debug_ready_run(tmp_path: Path) -> tuple[Path, str]:
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
    write_vmlinux_with_build_id(vmlinux)
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
            details={
                "debug_boot": True,
                "gdbstub_endpoint": {"host": "127.0.0.1", "port": 1234},
                "kernel_provenance": kernel_provenance_details(),
            },
        ),
    )
    return artifact_root, manifest.run_id


def _profiles(**overrides) -> dict[str, DebugProfile]:
    return {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default", **overrides)}


class _Fixture:
    """A wired run: transport machinery + a shared engine and live-session registry, so a started
    session stays reachable by the per-op handlers."""

    def __init__(self, tmp_path: Path, *, engine: FakeMiEngine | None = None) -> None:
        self.artifact_root, self.run_id = create_debug_ready_run(tmp_path)
        self.registry, self.txn, self.admission = build_debug_transport(tmp_path, self.run_id)
        self.engine = engine or FakeMiEngine()
        self.sessions = GdbMiSessionRegistry()

    def start(self, *, profiles=None, **overrides):
        return debug_start_session_handler(
            artifact_root=self.artifact_root,
            run_id=self.run_id,
            debug_profiles=profiles or _profiles(),
            transaction=self.txn,
            admission=self.admission,
            session_registry=self.registry,
            gdb_mi_engine=self.engine,
            gdb_mi_sessions=self.sessions,
            **overrides,
        )

    def read_memory(self, *, profiles=None, **overrides):
        return debug_read_memory_handler(
            artifact_root=self.artifact_root,
            run_id=self.run_id,
            debug_profiles=profiles or _profiles(),
            session_registry=self.registry,
            gdb_mi_engine=self.engine,
            gdb_mi_sessions=self.sessions,
            **overrides,
        )

    def end(self, **overrides):
        return debug_end_session_handler(
            artifact_root=self.artifact_root,
            run_id=self.run_id,
            debug_profiles=_profiles(),
            transaction=self.txn,
            admission=self.admission,
            session_registry=self.registry,
            gdb_mi_engine=self.engine,
            gdb_mi_sessions=self.sessions,
            **overrides,
        )


def test_debug_start_session_records_manifest_debug_step(tmp_path: Path) -> None:
    fx = _Fixture(tmp_path)
    response = fx.start()

    assert response.ok is True
    session_id = response.data["debug_session_id"]
    assert session_id.startswith("debug-")
    assert response.data["current_execution_state"] == "stopped"
    assert response.data["gdbstub_endpoint"] == {"host": "127.0.0.1", "port": 1234}
    # The session-of-record transcript is the live engine's MI log (ADR 0021), not a batch attempt dir.
    assert response.data["transcript_path"].endswith("/debug/mi-probe.log")
    # build-id version-lock is authoritative; no live-banner symbol scrape remains.
    assert response.data["symbol_identity_validation"] == {}
    assert response.data["mi_probe"]["record"]["message"] == "connected"
    assert fx.sessions.get(session_id) is not None  # held live across calls
    manifest = ArtifactStore(fx.artifact_root, create_root=False).load_manifest(fx.run_id)
    assert manifest.step_results["debug"].status == StepStatus.SUCCEEDED
    assert manifest.step_results["debug"].details["debug_session_id"] == session_id


def test_debug_start_session_rejects_profile_without_start_operation(tmp_path: Path) -> None:
    fx = _Fixture(tmp_path)
    response = fx.start(profiles=_profiles(enabled_operations=["debug.read_registers"]))

    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert fx.engine.attached is False


def test_debug_start_session_is_idempotent_for_active_session(tmp_path: Path) -> None:
    fx = _Fixture(tmp_path)
    first = fx.start()
    second = fx.start()

    assert first.ok is True
    assert second.ok is True
    # The idempotent return surfaces the same active session without a second attach.
    assert first.data["debug_session_id"] == second.data["debug_session_id"]


def test_debug_start_session_redacts_engine_fault_details(tmp_path: Path) -> None:
    class _SecretFault(FakeMiEngine):
        def probe_read(self, attachment):
            raise GdbMiError(
                "token=secret leaked",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"diagnostic": "token=secret"},
            )

    fx = _Fixture(tmp_path, engine=_SecretFault())
    response = fx.start()

    assert response.ok is False
    assert response.error.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    # The fault message and details are redacted before they reach the caller.
    assert "secret" not in response.error.message
    assert response.error.details.get("diagnostic", "") in ("token=[REDACTED]", "[REDACTED]")
    # A faulted attach records no SUCCEEDED debug step.
    manifest = ArtifactStore(fx.artifact_root, create_root=False).load_manifest(fx.run_id)
    assert "debug" not in manifest.step_results


def test_debug_start_session_replaces_ended_session(tmp_path: Path) -> None:
    fx = _Fixture(tmp_path)
    first = fx.start()
    assert first.ok is True
    # end_session frees the transport guard and records the session ENDED.
    ended = fx.end(debug_session_id=first.data["debug_session_id"])
    assert ended.ok is True

    second = fx.start(new_session=True)
    assert second.ok is True
    manifest = ArtifactStore(fx.artifact_root, create_root=False).load_manifest(fx.run_id)
    assert manifest.step_results["debug"].details["current_execution_state"] == "stopped"


def test_debug_read_memory_requires_active_session(tmp_path: Path) -> None:
    fx = _Fixture(tmp_path)
    response = fx.read_memory(address=0x1000, byte_count=16)

    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_debug_read_memory_loads_active_session_and_invokes_engine(tmp_path: Path) -> None:
    fx = _Fixture(tmp_path)
    assert fx.start().ok is True

    response = fx.read_memory(address=0x1000, byte_count=2)

    assert response.ok is True
    assert response.data["memory"] == [{"contents": "deadbeef"}]
    assert ("read_memory", (0x1000, 2)) in fx.engine.calls


def test_debug_read_memory_rejects_profile_without_read_memory_operation(tmp_path: Path) -> None:
    fx = _Fixture(tmp_path)
    assert fx.start().ok is True

    response = fx.read_memory(
        address=0x1000,
        byte_count=2,
        profiles=_profiles(enabled_operations=["debug.start_session"]),
    )

    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_debug_read_memory_rejects_session_paths_outside_run_debug_dir(tmp_path: Path) -> None:
    fx = _Fixture(tmp_path)
    start = fx.start()
    assert start.ok is True
    store = ArtifactStore(fx.artifact_root, create_root=False)
    debug_result = store.load_manifest(fx.run_id).step_results["debug"]
    session_path = Path(debug_result.details["session_path"])
    session = DebugSession.model_validate_json(session_path.read_text(encoding="utf-8"))
    outside_path = tmp_path / "outside-transcript.txt"
    session_path.write_text(
        session.model_copy(update={"transcript_path": str(outside_path)}).model_dump_json(indent=2),
        encoding="utf-8",
    )

    response = fx.read_memory(address=0x1000, byte_count=2)

    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_start_session_persist_failure_reaps_and_resumes(tmp_path: Path, monkeypatch) -> None:
    """Guaranteed-resume invariant on the persistence partial-failure path: if writing the session
    file (or recording the manifest step) raises AFTER the live attachment is registered and the
    kernel is HALTED, the handler must reap the attachment, un-halt, and tear the transport down —
    never strand the kernel HALTED with the guard held."""
    import linux_debug_mcp.server as server

    fx = _Fixture(tmp_path)

    def _boom(**_kwargs):
        raise OSError("disk full while persisting the debug session")

    monkeypatch.setattr(server, "_persist_mi_debug_session", _boom)
    response = fx.start()

    assert response.ok is False
    assert response.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details["code"] == "debug_session_persist_failed"
    # The live attachment was reaped (force_resume un-halted the kernel) ...
    assert fx.engine.forced is True
    assert not fx.sessions._sessions  # the live-session registry was emptied
    # ... and the transport was torn down: the durable record is gone and the guard is free.
    assert fx.registry.read_record(TargetKey(provisioner="local-qemu", target_id=RUN_ID)) is None
    # no SUCCEEDED debug step was recorded.
    manifest = ArtifactStore(fx.artifact_root, create_root=False).load_manifest(RUN_ID)
    assert "debug" not in manifest.step_results


def test_read_memory_over_cap_rejected_through_handler(tmp_path: Path) -> None:
    """The 4096-byte cap is enforced at the handler boundary: the engine raises CONFIGURATION_ERROR
    and _debug_operation_response surfaces it (FakeMiEngine is permissive, so use a strict engine)."""

    class _CapEngine(FakeMiEngine):
        def read_memory(self, attachment, *, address: int, byte_count: int) -> dict[str, object]:
            if byte_count > 4096:
                raise GdbMiError("byte_count over cap", category=ErrorCategory.CONFIGURATION_ERROR)
            return super().read_memory(attachment, address=address, byte_count=byte_count)

    fx = _Fixture(tmp_path, engine=_CapEngine())
    assert fx.start().ok is True
    response = fx.read_memory(address=0x1000, byte_count=4097)
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_evaluate_unknown_inspector_rejected_through_handler(tmp_path: Path) -> None:
    """debug.evaluate rejects arbitrary expressions with CONFIGURATION_ERROR at the handler boundary."""
    from linux_debug_mcp.server import debug_evaluate_handler

    class _StrictEvalEngine(FakeMiEngine):
        def evaluate_inspector(self, attachment, *, inspector: str, arguments: dict[str, object]):
            if inspector not in ("kernel_version", "symbol_address"):
                raise GdbMiError("unknown inspector", category=ErrorCategory.CONFIGURATION_ERROR)
            return {"inspector": inspector}

    fx = _Fixture(tmp_path, engine=_StrictEvalEngine())
    assert fx.start().ok is True
    response = debug_evaluate_handler(
        artifact_root=fx.artifact_root,
        run_id=fx.run_id,
        inspector="$(rm -rf /)",
        debug_profiles=_profiles(),
        session_registry=fx.registry,
        gdb_mi_engine=fx.engine,
        gdb_mi_sessions=fx.sessions,
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_debug_end_session_finalizes_manifest_state(tmp_path: Path) -> None:
    fx = _Fixture(tmp_path)
    start = fx.start()
    assert start.ok is True

    response = fx.end(debug_session_id=start.data["debug_session_id"])

    assert response.ok is True
    assert response.data["current_execution_state"] == "ended"
    manifest = ArtifactStore(fx.artifact_root, create_root=False).load_manifest(fx.run_id)
    assert manifest.step_results["debug"].details["current_execution_state"] == "ended"
    # The live attachment was reaped on end.
    assert fx.sessions.get(start.data["debug_session_id"]) is None
