from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.providers.qemu_gdbstub import DebugProviderResult, DebugSession, ProviderDebugError
from linux_debug_mcp.server import debug_end_session_handler, debug_read_memory_handler, debug_start_session_handler


class FakeDebugProvider:
    name = "local-qemu-gdbstub"

    def __init__(self) -> None:
        self.calls = 0
        self.call_kwargs: list[dict[str, object]] = []

    def start_session(self, **kwargs):
        self.calls += 1
        self.call_kwargs.append(kwargs)
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
            started_at="2026-05-23T00:00:00+00:00",
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

    def read_memory(self, **kwargs):
        self.calls += 1
        self.call_kwargs.append(kwargs)
        return DebugProviderResult(
            status=StepStatus.SUCCEEDED,
            summary="memory read succeeded",
            session=kwargs["session"],
            details={
                "address": "0x1000",
                "byte_count": 2,
                "bytes": ["0x12", "0x34"],
                "stdout_snippet": "0x1000:\t0x12\t0x34\n",
            },
        )

    def end_session(self, **kwargs):
        self.calls += 1
        self.call_kwargs.append(kwargs)
        session = kwargs["session"].model_copy(
            update={
                "current_execution_state": "ended",
                "ended_at": "2026-05-23T00:01:00+00:00",
            }
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


class FailingDebugProvider:
    name = "local-qemu-gdbstub"

    def start_session(self, **kwargs):
        raise ProviderDebugError(
            "strict symbol identity live target check failed",
            category=ErrorCategory.DEBUG_ATTACH_FAILURE,
            details={"diagnostic": "token=secret", "symbol_identity_validation": {"live_banner_match": False}},
        )


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
            run_id="run-debug",
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
            details={
                "debug_boot": True,
                "gdbstub_endpoint": {"host": "127.0.0.1", "port": 1234},
            },
        ),
    )
    return artifact_root, manifest.run_id


def test_debug_start_session_records_manifest_debug_step(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)
    provider = FakeDebugProvider()

    response = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )

    assert response.ok is True
    assert response.data["debug_session_id"] == "debug-1"
    assert response.data["current_execution_state"] == "stopped"
    assert response.data["gdbstub_endpoint"] == {"host": "127.0.0.1", "port": 1234}
    assert response.data["transcript_path"].endswith("/debug/attempt-001/transcript.txt")
    assert response.data["command_metadata_path"].endswith("/debug/attempt-001/commands.jsonl")
    assert response.data["latest_summary_path"].endswith("/debug/attempt-001/debug-summary.json")
    assert response.data["symbol_identity_validation"] == {
        "same_run_artifact_linkage": True,
        "live_banner_match": True,
    }
    assert provider.call_kwargs[0]["build_metadata"] == {
        "kernel_release": "6.9.0-test",
        "kernel_image_path": str(artifact_root / run_id / "build" / "bzImage"),
        "vmlinux_path": str(artifact_root / run_id / "build" / "vmlinux"),
    }
    assert provider.call_kwargs[0]["boot_metadata"] == {
        "debug_boot": True,
        "gdbstub_endpoint": {"host": "127.0.0.1", "port": 1234},
        "kernel_image_path": str(artifact_root / run_id / "build" / "bzImage"),
    }
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest(run_id)
    assert manifest.step_results["debug"].status == StepStatus.SUCCEEDED
    assert manifest.step_results["debug"].details["debug_session_id"] == "debug-1"


def test_debug_start_session_rejects_profile_without_start_operation(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)
    provider = FakeDebugProvider()

    response = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={
            "qemu-gdbstub-default": DebugProfile(
                name="qemu-gdbstub-default",
                enabled_operations=["debug.read_registers"],
            )
        },
    )

    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert provider.calls == 0


def test_debug_start_session_is_idempotent_for_active_session(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)
    provider = FakeDebugProvider()

    first = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )
    second = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )

    assert first.ok is True
    assert second.ok is True
    assert provider.calls == 1


def test_debug_start_session_redacts_provider_error_details_before_recording(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)

    response = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=FailingDebugProvider(),
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.details["diagnostic"] == "token=[REDACTED]"
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest(run_id)
    assert manifest.step_results["debug"].details["diagnostic"] == "token=[REDACTED]"


def test_debug_start_session_replaces_ended_session_without_new_session_flag(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)
    provider = FakeDebugProvider()

    first = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )
    assert first.ok is True
    store = ArtifactStore(artifact_root, create_root=False)
    ended = StepResult(
        step_name="debug",
        status=StepStatus.SUCCEEDED,
        summary="debug session ended",
        artifacts=store.load_manifest(run_id).step_results["debug"].artifacts,
        details={**first.data, "current_execution_state": "ended"},
    )
    store.record_step_result(run_id, ended, replace_succeeded=True)

    second = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )

    assert second.ok is True
    assert provider.calls == 2
    manifest = store.load_manifest(run_id)
    assert manifest.step_results["debug"].details["current_execution_state"] == "stopped"


def test_debug_read_memory_requires_active_session(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)

    response = debug_read_memory_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        address=0x1000,
        byte_count=16,
        provider=FakeDebugProvider(),
    )

    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR


def test_debug_read_memory_loads_active_session_and_invokes_provider(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)
    provider = FakeDebugProvider()
    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )
    assert start.ok is True

    response = debug_read_memory_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        address=0x1000,
        byte_count=2,
        provider=provider,
    )

    assert response.ok is True
    assert response.data["bytes"] == ["0x12", "0x34"]
    assert provider.call_kwargs[-1]["run_dir"] == artifact_root / run_id
    assert provider.call_kwargs[-1]["address"] == 0x1000
    assert provider.call_kwargs[-1]["byte_count"] == 2
    assert provider.call_kwargs[-1]["session"].session_id == "debug-1"


def test_debug_read_memory_rejects_profile_without_read_memory_operation(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)
    provider = FakeDebugProvider()
    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )
    assert start.ok is True

    response = debug_read_memory_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        address=0x1000,
        byte_count=2,
        provider=provider,
        debug_profiles={
            "qemu-gdbstub-default": DebugProfile(
                name="qemu-gdbstub-default",
                enabled_operations=["debug.start_session"],
            )
        },
    )

    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert provider.calls == 1


def test_debug_read_memory_rejects_session_paths_outside_run_debug_dir(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)
    provider = FakeDebugProvider()
    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )
    assert start.ok is True
    store = ArtifactStore(artifact_root, create_root=False)
    manifest = store.load_manifest(run_id)
    debug_result = manifest.step_results["debug"]
    session_path = Path(debug_result.details["session_path"])
    session = DebugSession.model_validate_json(session_path.read_text(encoding="utf-8"))
    outside_path = tmp_path / "outside-transcript.txt"
    session_path.write_text(
        session.model_copy(update={"transcript_path": str(outside_path)}).model_dump_json(indent=2),
        encoding="utf-8",
    )

    response = debug_read_memory_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        address=0x1000,
        byte_count=2,
        provider=provider,
    )

    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert provider.calls == 1


def test_debug_end_session_finalizes_manifest_state(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)
    provider = FakeDebugProvider()
    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )
    assert start.ok is True

    response = debug_end_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=start.data["debug_session_id"],
        provider=provider,
    )

    assert response.ok is True
    assert response.data["current_execution_state"] == "ended"
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest(run_id)
    assert manifest.step_results["debug"].details["current_execution_state"] == "ended"
