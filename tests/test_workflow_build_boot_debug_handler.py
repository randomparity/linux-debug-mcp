from pathlib import Path

from linux_debug_mcp.domain import ErrorCategory, ToolResponse
from linux_debug_mcp.server import workflow_build_boot_debug_handler


def success(summary: str, *, run_id: str = "run-abc123") -> ToolResponse:
    return ToolResponse.success(summary=summary, run_id=run_id, data={"summary": summary})


def failure(category: ErrorCategory, message: str, *, run_id: str = "run-abc123") -> ToolResponse:
    return ToolResponse.failure(category=category, message=message, run_id=run_id)


def test_workflow_build_boot_debug_success(tmp_path: Path, monkeypatch) -> None:
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

    assert calls == ["create", "build", "boot", "debug"]
    assert response.ok is True
    assert response.data["latest_successful_step"] == "debug"


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
