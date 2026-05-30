from pathlib import Path

from conftest import make_source_tree

from linux_debug_mcp import server
from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import BootOverrides, BuildOverrides
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


def _get_tool_fn(app, name):
    return app._tool_manager._tools[name].fn


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
    providers = {provider["provider_name"]: provider for provider in response.data["providers"]}
    assert {
        "local-artifacts",
        "local-kernel-build",
        "local-libvirt-qemu",
        "local-qemu-gdbstub",
        "local-prereqs",
        "local-ssh-tests",
    }.issubset(providers)
    assert {
        "remote-build-stub",
        "remote-artifact-sync-stub",
        "reservation-stub",
        "provisioning-stub",
        "hardware-control-stub",
        "console-access-stub",
        "real-boot-stub",
    }.issubset(providers)
    assert providers["local-kernel-build"]["implementation_state"] == "implemented"
    assert providers["remote-build-stub"]["implementation_state"] == "stub"
    assert providers["remote-build-stub"]["documentation_paths"] == ["docs/ppc64le-provider-spike.md"]
    assert "operation_capabilities" in providers["remote-build-stub"]


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
    tools = app._tool_manager._tools
    tool_names = set(tools)

    assert "workflow.build_boot_debug" in tool_names
    assert "debug.start_session" in tool_names
    assert "debug.read_memory" in tool_names
    assert "debug.end_session" in tool_names
    assert tools["workflow.build_boot_debug"].fn.__name__ == "workflow_build_boot_debug"
    assert "debug_profile" in tools["workflow.build_boot_debug"].parameters["properties"]
    assert "new_session" in tools["workflow.build_boot_debug"].parameters["properties"]
    assert tools["debug.start_session"].fn.__name__ == "debug_start_session"
    assert "debug_profile" in tools["debug.start_session"].parameters["properties"]
    assert "new_session" in tools["debug.start_session"].parameters["properties"]
    assert tools["debug.read_memory"].fn.__name__ == "debug_read_memory"
    assert "address" in tools["debug.read_memory"].parameters["properties"]
    assert "byte_count" in tools["debug.read_memory"].parameters["properties"]
    assert tools["debug.end_session"].fn.__name__ == "debug_end_session"
    assert "debug_session_id" in tools["debug.end_session"].parameters["properties"]


def test_create_app_registers_future_provider_tools() -> None:
    app = create_app()
    tools = app._tool_manager._tools
    expected_fields = {
        "remote.build_kernel": {"architecture", "source_ref", "build_profile"},
        "remote.sync_artifacts": {"architecture", "external_artifact_ref"},
        "reservation.request_host": {"architecture", "reservation_pool"},
        "reservation.release_host": {"architecture", "reservation_id"},
        "provision.prepare_target": {"architecture", "target_name", "provisioning_profile"},
        "hardware.power_control": {"architecture", "target_name", "action"},
        "hardware.boot_kernel": {"architecture", "target_name", "kernel_artifact_ref"},
        "console.open_session": {"architecture", "target_name", "access_method"},
        "console.read": {"architecture", "console_session_id", "max_bytes"},
        "console.write": {"architecture", "console_session_id", "data"},
        "workflow.reserve_provision_boot": {
            "architecture",
            "reservation_pool",
            "target_name",
            "provisioning_profile",
            "kernel_artifact_ref",
        },
    }

    assert set(expected_fields).issubset(tools)
    for tool_name, fields in expected_fields.items():
        properties = tools[tool_name].parameters["properties"]
        assert fields.issubset(properties)
        assert {"provider_name", "timeout_seconds", "operation_label"}.issubset(properties)


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


def test_create_run_freezes_merged_profiles(tmp_path):
    source = make_source_tree(tmp_path)
    response = server.create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        build_overrides=BuildOverrides(make_variables={"CC": "clang"}),
        boot_overrides=BootOverrides(kernel_args=["dhash_entries=1"]),
    )
    assert response.ok
    run_id = response.run_id
    store = server.ArtifactStore(tmp_path / "runs", create_root=False)
    manifest = store.load_manifest(run_id)
    assert manifest.resolved_build_profile.make_variables == {"CC": "clang"}
    assert manifest.boot_attempts == []  # attempt 1 not yet booted
    assert manifest.request.boot_overrides.kernel_args == ["dhash_entries=1"]


def test_create_run_response_redacts_secret_make_variable(tmp_path):
    source = make_source_tree(tmp_path)
    response = server.create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        build_overrides=BuildOverrides(make_variables={"API_TOKEN": "supersecret"}),
    )
    assert response.ok
    # the create_run response embeds the manifest dump (which carries make_variables);
    # it must be redacted like the get_manifest view, not echoed verbatim.
    assert "supersecret" not in str(response.data)


def test_create_run_response_redacts_secret_shaped_config_line(tmp_path):
    source = make_source_tree(tmp_path)
    response = server.create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        build_overrides=BuildOverrides(config_lines=['CONFIG_CMDLINE="token=supersecret"']),
    )
    assert response.ok
    assert "supersecret" not in str(response.data)
    assert "[REDACTED]" in str(response.data)


def test_create_run_rejects_unknown_base_profile(tmp_path):
    source = make_source_tree(tmp_path)
    response = server.create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="does-not-exist",
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )
    assert not response.ok
    assert response.error.category.value == "configuration_error"
    # fail-fast: no run directory/manifest created on a bad base profile
    assert list((tmp_path / "runs").glob("*/manifest.json")) == []


def test_create_run_freezes_merged_config_lines(tmp_path):
    source = make_source_tree(tmp_path)
    response = server.create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        build_overrides=BuildOverrides(config_lines=["CONFIG_DEBUG_INFO=y"]),
    )
    assert response.ok
    run_id = response.run_id
    store = server.ArtifactStore(tmp_path / "runs", create_root=False)
    manifest = store.load_manifest(run_id)
    assert manifest.resolved_build_profile is not None
    assert manifest.resolved_build_profile.config_lines == ["CONFIG_DEBUG_INFO=y"]


def test_build_reads_resolved_profile_not_global(tmp_path):
    src = make_source_tree(tmp_path)
    created = server.create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(src),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        build_overrides=BuildOverrides(make_variables={"CC": "clang"}),
    )
    assert created.ok
    run_id = created.run_id
    store = server.ArtifactStore(tmp_path / "runs", create_root=False)
    manifest = store.load_manifest(run_id)
    resolved = server._build_profile_from_manifest(manifest)
    assert resolved.make_variables == {"CC": "clang"}


def test_build_profile_from_manifest_v1_fallback():
    from linux_debug_mcp.artifacts.manifest import RunManifest
    from linux_debug_mcp.domain import RunRequest

    manifest = RunManifest.create(
        run_id="r",
        request=RunRequest(
            source_path="/s",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        ),
    )  # resolved_build_profile is None
    resolved = server._build_profile_from_manifest(manifest)
    assert resolved.name == "x86_64-default"


def test_overrides_from_tool_args_builds_models():
    from linux_debug_mcp.config import BootOverrides, BuildOverrides

    build, boot = server._overrides_from_tool_args(
        kernel_args=["dhash_entries=1"], rootfs_source=None, make_variables={"CC": "clang"}, config_lines=None
    )
    assert isinstance(build, BuildOverrides) and build.make_variables == {"CC": "clang"}
    assert build.config_lines == []
    assert isinstance(boot, BootOverrides) and boot.kernel_args == ["dhash_entries=1"]

    none_build, none_boot = server._overrides_from_tool_args(
        kernel_args=None, rootfs_source=None, make_variables=None, config_lines=None
    )
    assert none_build is None and none_boot is None


def test_overrides_from_tool_args_builds_config_lines():
    build_overrides, boot_overrides = server._overrides_from_tool_args(
        kernel_args=None,
        rootfs_source=None,
        make_variables=None,
        config_lines=["CONFIG_DEBUG_INFO=y"],
    )
    assert build_overrides is not None
    assert build_overrides.config_lines == ["CONFIG_DEBUG_INFO=y"]
    assert boot_overrides is None


def test_overrides_from_tool_args_none_when_no_build_overrides():
    build_overrides, _ = server._overrides_from_tool_args(
        kernel_args=["nokaslr"], rootfs_source=None, make_variables=None, config_lines=None
    )
    assert build_overrides is None


def test_create_run_tool_accepts_overrides_and_rejects_bad_args(tmp_path: Path):
    src = make_source_tree(tmp_path)
    app = server.create_app()
    tool_fn = _get_tool_fn(app, "kernel.create_run")

    ok = tool_fn(
        source_path=str(src),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        artifact_root=str(tmp_path / "runs"),
        kernel_args=["dhash_entries=1"],
        make_variables={"CC": "clang"},
        config_lines=["CONFIG_DEBUG_INFO=y"],
    )
    assert ok["ok"] is True
    run_id = ok["run_id"]
    manifest = server.ArtifactStore(tmp_path / "runs", create_root=False).load_manifest(run_id)
    assert manifest.resolved_build_profile.config_lines == ["CONFIG_DEBUG_INFO=y"]

    bad = tool_fn(
        source_path=str(src),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        artifact_root=str(tmp_path / "runs2"),
        kernel_args=["bad;arg"],
    )
    assert bad["ok"] is False
    assert bad["error"]["category"] == "configuration_error"


def test_introspect_tool_is_registered() -> None:
    assert "debug.introspect.run" in tool_names()
    tool = create_app()._tool_manager._tools["debug.introspect.run"]
    assert tool.fn.__name__ == "debug_introspect_run"
    assert "script" in tool.parameters["properties"]
    assert "timeout_seconds" in tool.parameters["properties"]


def test_default_minimal_rootfs_is_builder_copy_on_write() -> None:
    from linux_debug_mcp.server import DEFAULT_ROOTFS_PROFILES

    minimal = DEFAULT_ROOTFS_PROFILES["minimal"]
    assert minimal.source_kind == "builder"
    assert minimal.mutability == "copy_on_write"
