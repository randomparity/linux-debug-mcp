from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import ArtifactRef, StepResult, StepStatus
from linux_debug_mcp.server import (
    DEFAULT_TEST_SUITES,
    create_app,
    create_run_handler,
    get_manifest_handler,
    list_providers_handler,
    not_implemented_handler,
    prerequisites_handler,
)


def make_source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    return source


def create_test_run(tmp_path: Path, run_id: str = "run-abc123") -> tuple[Path, Path]:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"

    create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id=run_id,
    )
    return source, artifact_root


def tool_names() -> set[str]:
    return set(create_app()._tool_manager._tools)


def test_create_run_handler_creates_manifest(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"

    response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )

    assert response.ok is True
    assert response.run_id == "run-abc123"
    assert (artifact_root / "run-abc123" / "manifest.json").exists()
    assert response.suggested_next_actions == ["kernel.build"]


def test_create_run_handler_rejects_source_checkout_as_artifact_root(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)

    response = create_run_handler(
        artifact_root=source,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_create_run_handler_returns_failure_when_artifact_root_cannot_be_created(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"
    original_mkdir = Path.mkdir

    def fail_for_artifact_root(self: Path, *args: object, **kwargs: object) -> None:
        if self == artifact_root:
            raise PermissionError("permission denied")
        original_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_for_artifact_root)

    response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "infrastructure_failure"


def test_create_run_handler_rejects_unsafe_run_id(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"

    response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="../run-abc123",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_get_manifest_handler_returns_redacted_manifest(tmp_path: Path) -> None:
    _, artifact_root = create_test_run(tmp_path)

    response = get_manifest_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is True
    assert response.data["manifest"]["run_id"] == "run-abc123"


def test_get_manifest_handler_redacts_sensitive_manifest_fields(tmp_path: Path) -> None:
    source, artifact_root = create_test_run(tmp_path)
    store = ArtifactStore(artifact_root, source_paths=[source])
    store.record_step_result(
        "run-abc123",
        StepResult(
            step_name="collect_artifacts",
            status=StepStatus.SUCCEEDED,
            summary="collected token=topsecret",
            details={"password": "hunter2"},
            artifacts=[
                ArtifactRef(
                    path=str(artifact_root / "run-abc123" / "sensitive" / "serial.log"),
                    kind="serial-log",
                    sensitive=True,
                )
            ],
        ),
    )

    response = get_manifest_handler(artifact_root=artifact_root, run_id="run-abc123")

    manifest = response.data["manifest"]
    result = manifest["step_results"]["collect_artifacts"]
    assert result["summary"] == "collected token=[REDACTED]"
    assert result["details"]["password"] == "[REDACTED]"
    assert result["artifacts"][0]["path"] == "[REDACTED]"


def test_get_manifest_handler_rejects_unsafe_run_id(tmp_path: Path) -> None:
    response = get_manifest_handler(artifact_root=tmp_path / "runs", run_id="../run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_get_manifest_handler_does_not_create_missing_artifact_root(tmp_path: Path) -> None:
    artifact_root = tmp_path / "missing-runs"

    response = get_manifest_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert not artifact_root.exists()


def test_prerequisites_handler_returns_checks(tmp_path: Path) -> None:
    response = prerequisites_handler(
        artifact_root=tmp_path / "runs",
        source_path=None,
        enable_libvirt_check=False,
    )

    assert response.ok is True
    assert "checks" in response.data
    assert any(check["check_id"] == "python.version" for check in response.data["checks"])


def test_list_providers_handler_returns_default_capabilities() -> None:
    response = list_providers_handler()

    assert response.ok is True
    assert {provider["provider_name"] for provider in response.data["providers"]} == {
        "local-artifacts",
        "local-kernel-build",
        "local-libvirt-qemu",
        "local-qemu-gdbstub",
        "local-prereqs",
        "local-ssh-tests",
    }


def test_default_smoke_basic_suite_matches_sprint_3_contract() -> None:
    suite = DEFAULT_TEST_SUITES["smoke-basic"]

    assert [command.argv for command in suite.commands] == [
        ["uname", "-a"],
        ["test", "-r", "/proc/version"],
        ["cat", "/proc/cmdline"],
    ]
    assert suite.timeout_seconds == 30
    assert suite.stop_on_failure is True
    assert suite.collect_dmesg is True


def test_not_implemented_handler_returns_structured_error() -> None:
    response = not_implemented_handler("target.run_tests")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "not_implemented"
    assert response.error.details["tool"] == "target.run_tests"


def test_create_app_constructs_fastmcp_server() -> None:
    assert type(create_app()).__name__ == "FastMCP"


def test_create_app_registers_sprint_4_tools_as_real_handlers() -> None:
    app = create_app()
    tool_names = set(app._tool_manager._tools)

    assert "workflow.build_boot_debug" in tool_names
    assert "debug.start_session" in tool_names
    assert "debug.read_memory" in tool_names
    assert "debug.end_session" in tool_names


def test_target_run_tests_tool_is_registered_with_full_arguments() -> None:
    app = create_app()
    tool = app._tool_manager._tools["target.run_tests"]

    assert "target.run_tests" in tool_names()
    assert "force_rerun" in tool.parameters["properties"]
    assert "commands" in tool.parameters["properties"]
    assert tool.fn.__name__ == "target_run_tests"


def test_target_run_tests_handler_response_serializes(tmp_path: Path) -> None:
    source, artifact_root = create_test_run(tmp_path)
    store = ArtifactStore(artifact_root, source_paths=[source])
    store.record_step_result(
        "run-abc123",
        StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="boot ok"),
    )

    response = get_manifest_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.model_dump(mode="json")["run_id"] == "run-abc123"


def test_artifacts_collect_tool_is_registered_with_force_recollect() -> None:
    app = create_app()
    tool = app._tool_manager._tools["artifacts.collect"]

    assert "artifacts.collect" in tool_names()
    assert "force_recollect" in tool.parameters["properties"]
    assert tool.fn.__name__ == "artifacts_collect"


def test_workflow_build_boot_test_tool_is_registered_with_force_flags() -> None:
    app = create_app()
    tool = app._tool_manager._tools["workflow.build_boot_test"]

    assert "workflow.build_boot_test" in tool_names()
    assert "force_rerun_tests" in tool.parameters["properties"]
    assert "force_recollect" in tool.parameters["properties"]
    assert tool.fn.__name__ == "workflow_build_boot_test"
