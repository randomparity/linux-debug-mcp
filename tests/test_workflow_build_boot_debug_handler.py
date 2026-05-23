from pathlib import Path

from linux_debug_mcp.domain import ErrorCategory, ToolResponse
from linux_debug_mcp.server import create_run_handler, workflow_build_boot_debug_handler


def success(summary: str, *, run_id: str = "run-abc123") -> ToolResponse:
    return ToolResponse.success(summary=summary, run_id=run_id, data={"summary": summary})


def failure(category: ErrorCategory, message: str, *, run_id: str = "run-abc123") -> ToolResponse:
    return ToolResponse.failure(category=category, message=message, run_id=run_id)


def test_workflow_build_boot_debug_success(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []
    captured: dict[str, dict[str, object]] = {}

    monkeypatch.setattr(
        "linux_debug_mcp.server.create_run_handler",
        lambda **kwargs: captured.setdefault("create", kwargs) and calls.append("create") or success("created"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.kernel_build_handler",
        lambda **kwargs: captured.setdefault("build", kwargs) and calls.append("build") or success("built"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.target_boot_handler",
        lambda **kwargs: captured.setdefault("boot", kwargs) and calls.append("boot") or success("booted"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.debug_start_session_handler",
        lambda **kwargs: (
            captured.setdefault("debug", kwargs) and calls.append("debug") or success("debug session started")
        ),
    )

    response = workflow_build_boot_debug_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu-debug",
        rootfs_profile="minimal",
        run_id="run-explicit",
        debug_profile="qemu-gdbstub-default",
        force_rebuild=True,
        force_reboot=True,
        new_session=True,
    )

    assert calls == ["create", "build", "boot", "debug"]
    assert response.ok is True
    assert response.data["latest_successful_step"] == "debug"
    assert captured["create"]["run_id"] == "run-explicit"
    assert captured["create"]["debug_profile"] == "qemu-gdbstub-default"
    assert captured["build"]["force_rebuild"] is True
    assert captured["boot"]["force_reboot"] is True
    assert captured["debug"]["debug_profile"] == "qemu-gdbstub-default"
    assert captured["debug"]["new_session"] is True


def test_workflow_build_boot_debug_stops_before_debug_when_boot_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[str] = []

    monkeypatch.setattr(
        "linux_debug_mcp.server.create_run_handler",
        lambda **kwargs: calls.append("create") or success("created"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.kernel_build_handler",
        lambda **kwargs: calls.append("build") or success("built"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.target_boot_handler",
        lambda **kwargs: calls.append("boot") or failure(ErrorCategory.BOOT_TIMEOUT, "boot timed out"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.debug_start_session_handler",
        lambda **kwargs: calls.append("debug") or success("debug session started"),
    )

    response = workflow_build_boot_debug_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu-debug",
        rootfs_profile="minimal",
        debug_profile="qemu-gdbstub-default",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == ErrorCategory.BOOT_TIMEOUT
    assert response.data["failing_step"] == "boot"
    assert calls == ["create", "build", "boot"]


def test_workflow_build_boot_debug_stops_when_debug_start_fails(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr(
        "linux_debug_mcp.server.create_run_handler",
        lambda **kwargs: calls.append("create") or success("created"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.kernel_build_handler",
        lambda **kwargs: calls.append("build") or success("built"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.target_boot_handler",
        lambda **kwargs: calls.append("boot") or success("booted"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.debug_start_session_handler",
        lambda **kwargs: calls.append("debug") or failure(ErrorCategory.DEBUG_ATTACH_FAILURE, "debug attach failed"),
    )

    response = workflow_build_boot_debug_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu-debug",
        rootfs_profile="minimal",
        debug_profile="qemu-gdbstub-default",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert response.data["failing_step"] == "debug"
    assert calls == ["create", "build", "boot", "debug"]


def test_workflow_build_boot_debug_allows_explicit_profile_when_manifest_did_not_pin_one(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    artifact_root = tmp_path / "runs"
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu-debug",
        rootfs_profile="minimal",
        run_id="run-debug",
    )
    assert created.ok is True
    captured_debug: dict[str, object] = {}
    monkeypatch.setattr(
        "linux_debug_mcp.server.kernel_build_handler", lambda **kwargs: success("built", run_id="run-debug")
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.target_boot_handler", lambda **kwargs: success("booted", run_id="run-debug")
    )

    def fake_debug(**kwargs: object) -> ToolResponse:
        captured_debug.update(kwargs)
        return success("debug session started", run_id="run-debug")

    monkeypatch.setattr("linux_debug_mcp.server.debug_start_session_handler", fake_debug)

    response = workflow_build_boot_debug_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu-debug",
        rootfs_profile="minimal",
        run_id="run-debug",
        debug_profile="qemu-gdbstub-default",
    )

    assert response.ok is True
    assert captured_debug["debug_profile"] == "qemu-gdbstub-default"
