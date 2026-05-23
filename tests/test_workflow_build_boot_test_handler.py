from pathlib import Path

from linux_debug_mcp.domain import ErrorCategory, ToolResponse
from linux_debug_mcp.server import create_run_handler, workflow_build_boot_test_handler


def success(summary: str, *, run_id: str = "run-abc123") -> ToolResponse:
    return ToolResponse.success(summary=summary, run_id=run_id, data={"summary": summary})


def failure(category: ErrorCategory, message: str, *, run_id: str = "run-abc123") -> ToolResponse:
    return ToolResponse.failure(category=category, message=message, run_id=run_id)


def test_workflow_runs_build_boot_tests_and_collects(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr("linux_debug_mcp.server.create_run_handler", lambda **kwargs: success("created"))
    monkeypatch.setattr(
        "linux_debug_mcp.server.kernel_build_handler",
        lambda **kwargs: calls.append("build") or success("built"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.target_boot_handler",
        lambda **kwargs: calls.append("boot") or success("booted"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.target_run_tests_handler",
        lambda **kwargs: calls.append("tests") or success("tested"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.artifacts_collect_handler",
        lambda **kwargs: calls.append("collect") or success("collected"),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )

    assert response.ok is True
    assert calls == ["build", "boot", "tests", "collect"]
    assert response.data["latest_successful_step"] == "collect_artifacts"


def test_workflow_collects_and_returns_build_failure(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr("linux_debug_mcp.server.create_run_handler", lambda **kwargs: success("created"))
    monkeypatch.setattr(
        "linux_debug_mcp.server.kernel_build_handler",
        lambda **kwargs: calls.append("build") or failure(ErrorCategory.BUILD_FAILURE, "build failed"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.artifacts_collect_handler",
        lambda **kwargs: calls.append("collect") or success("collected"),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "build_failure"
    assert response.error.details["failing_step"] == "build"
    assert calls == ["build", "collect"]


def test_workflow_collects_after_test_failure(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr("linux_debug_mcp.server.create_run_handler", lambda **kwargs: success("created"))
    monkeypatch.setattr(
        "linux_debug_mcp.server.kernel_build_handler",
        lambda **kwargs: calls.append("build") or success("built"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.target_boot_handler",
        lambda **kwargs: calls.append("boot") or success("booted"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.target_run_tests_handler",
        lambda **kwargs: calls.append("tests") or failure(ErrorCategory.TEST_FAILURE, "tests failed"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.artifacts_collect_handler",
        lambda **kwargs: calls.append("collect") or success("collected"),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.details["failing_step"] == "run_tests"
    assert calls == ["build", "boot", "tests", "collect"]


def test_workflow_rejects_existing_run_request_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    artifact_root = tmp_path / "runs"
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        test_suite="smoke-basic",
    )
    assert created.ok is True

    response = workflow_build_boot_test_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="other-build-profile",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        test_suite="smoke-basic",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "immutable run manifest request" in response.error.message


def test_workflow_existing_run_uses_manifest_test_suite_when_omitted(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    artifact_root = tmp_path / "runs"
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
        test_suite="smoke-basic",
    )
    assert created.ok is True

    captured_tests: dict[str, object] = {}
    monkeypatch.setattr("linux_debug_mcp.server.kernel_build_handler", lambda **kwargs: success("built"))
    monkeypatch.setattr("linux_debug_mcp.server.target_boot_handler", lambda **kwargs: success("booted"))

    def fake_run_tests(**kwargs: object) -> ToolResponse:
        captured_tests.update(kwargs)
        return success("tested")

    monkeypatch.setattr("linux_debug_mcp.server.target_run_tests_handler", fake_run_tests)
    monkeypatch.setattr("linux_debug_mcp.server.artifacts_collect_handler", lambda **kwargs: success("collected"))

    response = workflow_build_boot_test_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )

    assert response.ok is True
    assert captured_tests["test_suite"] == "smoke-basic"


def test_workflow_creates_missing_supplied_run_id_exactly(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}
    calls: list[str] = []

    def fake_create_run(**kwargs: object) -> ToolResponse:
        captured.update(kwargs)
        return success("created", run_id=str(kwargs["run_id"]))

    monkeypatch.setattr("linux_debug_mcp.server.create_run_handler", fake_create_run)
    monkeypatch.setattr(
        "linux_debug_mcp.server.kernel_build_handler",
        lambda **kwargs: calls.append("build") or success("built", run_id="run-explicit"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.target_boot_handler",
        lambda **kwargs: calls.append("boot") or success("booted", run_id="run-explicit"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.target_run_tests_handler",
        lambda **kwargs: calls.append("tests") or success("tested", run_id="run-explicit"),
    )
    monkeypatch.setattr(
        "linux_debug_mcp.server.artifacts_collect_handler",
        lambda **kwargs: calls.append("collect") or success("collected", run_id="run-explicit"),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-explicit",
    )

    assert response.ok is True
    assert captured["run_id"] == "run-explicit"
    assert calls == ["build", "boot", "tests", "collect"]
