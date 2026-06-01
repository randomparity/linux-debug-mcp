import inspect
from pathlib import Path

from conftest import make_source_tree
from mcp.server.fastmcp import FastMCP

from kdive import server
from kdive.artifacts.store import ArtifactStore
from kdive.config import TARGET_DESTRUCTIVE_PERMISSIONS, BootOverrides, BuildOverrides, RootfsProfile, TargetProfile
from kdive.coordination.admission import AdmissionService, SnapshotStore
from kdive.coordination.registry import SessionRegistry
from kdive.debug import bound_handlers as debug_bound_handlers
from kdive.domain import ArtifactRef, StepResult, StepStatus, ToolResponse
from kdive.kernel import handlers as kernel_handlers
from kdive.kernel import tools as kernel_tools
from kdive.prereqs.checks import PortProbeResult
from kdive.providers.handlers import list_providers_handler
from kdive.server import (
    DEFAULT_TEST_SUITES,
    create_app,
    create_run_handler,
    get_manifest_handler,
    not_implemented_handler,
    prerequisites_handler,
)
from kdive.target.tools import register_target_tools


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


def test_transport_halt_helper_is_not_reexported_by_server() -> None:
    from kdive.transport import handlers as transport_handlers

    assert hasattr(transport_handlers, "_halt_debug_transport")
    assert not hasattr(server, "_halt_debug_transport")


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


def test_prerequisites_handler_lives_outside_server_catch_all() -> None:
    assert prerequisites_handler.__module__ == "kdive.prereqs.handlers"


def test_debug_operation_handlers_live_outside_server_catch_all() -> None:
    for handler in (
        debug_bound_handlers.debug_read_registers_handler,
        debug_bound_handlers.debug_set_breakpoint_handler,
        debug_bound_handlers.debug_continue_handler,
    ):
        assert handler.__module__ == "kdive.debug.bound_handlers"
        assert "_debug_operation_response" in inspect.getsource(handler)
        assert "operation_core" in inspect.getsource(handler)
    assert not hasattr(server, "debug_read_registers_handler")


def test_live_introspect_handlers_live_outside_server_catch_all() -> None:
    from kdive.introspect import handlers as introspect_handlers

    app = create_app()

    assert introspect_handlers.debug_introspect_run_handler.__module__ == "kdive.introspect.handlers"
    assert introspect_handlers.debug_introspect_helper_handler.__module__ == "kdive.introspect.handlers"
    assert introspect_handlers.debug_introspect_check_prerequisites_handler.__module__ == "kdive.introspect.handlers"
    assert app._tool_manager._tools["debug.introspect.run"].fn.__module__ == "kdive.introspect.tools"
    assert app._tool_manager._tools["debug.introspect.helper"].fn.__module__ == "kdive.introspect.tools"
    assert app._tool_manager._tools["debug.introspect.check_prerequisites"].fn.__module__ == "kdive.introspect.tools"


def test_prerequisites_handler_readiness_skipped_without_profiles(tmp_path: Path) -> None:
    response = prerequisites_handler(artifact_root=tmp_path / "runs", source_path=None)
    by_id = {c["check_id"]: c for c in response.data["checks"]}
    assert by_id["kernel.config"]["status"] == "skipped"
    assert by_id["rootfs.image"]["status"] == "skipped"
    assert by_id["gdbstub.port"]["status"] == "skipped"


def test_prerequisites_handler_names_missing_rootfs_and_passes_config(tmp_path: Path) -> None:
    # Inject a builder rootfs profile pointing at an absent path so the check is deterministic
    # regardless of whether a real image exists at the default host location.
    missing_image = tmp_path / "rootfs" / "minimal.qcow2"
    response = prerequisites_handler(
        artifact_root=tmp_path / "runs",
        source_path=None,
        build_profile="x86_64-debug",
        target_profile="local-qemu-debug",
        rootfs_profile="minimal",
        rootfs_profiles={"minimal": RootfsProfile(name="minimal", source=str(missing_image), source_kind="builder")},
        port_probe=lambda h, p: PortProbeResult("free"),
    )
    by_id = {c["check_id"]: c for c in response.data["checks"]}
    assert by_id["kernel.config"]["status"] == "passed"
    assert by_id["rootfs.image"]["status"] == "failed"
    assert "just rootfs" in by_id["rootfs.image"]["suggested_fix"]
    assert by_id["gdbstub.port"]["status"] == "passed"


def test_prerequisites_handler_unknown_profile_is_failed_check(tmp_path: Path) -> None:
    response = prerequisites_handler(artifact_root=tmp_path / "runs", source_path=None, build_profile="does-not-exist")
    by_id = {c["check_id"]: c for c in response.data["checks"]}
    assert by_id["kernel.config"]["status"] == "failed"
    assert "unknown build profile" in by_id["kernel.config"]["message"]
    assert by_id["rootfs.image"]["status"] == "skipped"


def test_prerequisites_handler_port_check_uses_injected_target_registry(tmp_path: Path) -> None:
    response = prerequisites_handler(
        artifact_root=tmp_path / "runs",
        source_path=None,
        target_profile="custom",
        target_profiles={"custom": TargetProfile(name="custom", architecture="x86_64", debug_gdbstub=True)},
        port_probe=lambda h, p: PortProbeResult("in_use"),
    )
    by_id = {c["check_id"]: c for c in response.data["checks"]}
    assert by_id["gdbstub.port"]["status"] == "failed"
    assert "in use" in by_id["gdbstub.port"]["message"]


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


def test_default_smoke_basic_suite_matches_target_test_contract() -> None:
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
    assert "implementation_phase" in response.error.details
    assert "sprint" not in response.error.details


def test_create_app_constructs_fastmcp_server() -> None:
    assert type(create_app()).__name__ == "FastMCP"


def test_create_app_registers_debug_tools_as_real_handlers() -> None:
    app = create_app()
    tools = app._tool_manager._tools
    tool_names = set(tools)

    assert "workflow.build_boot_debug" in tool_names
    assert "debug.start_session" in tool_names
    assert "debug.read_memory" in tool_names
    assert "debug.end_session" in tool_names
    assert tools["workflow.build_boot_debug"].fn.__name__ == "workflow_build_boot_debug"
    assert tools["workflow.build_boot_debug"].fn.__module__ == "kdive.workflow.tools"
    workflow_debug_properties = tools["workflow.build_boot_debug"].parameters["properties"]
    assert {"profiles", "context", "options"}.issubset(workflow_debug_properties)
    assert {"debug_profile", "new_session", "force_rebuild", "force_reboot"}.isdisjoint(workflow_debug_properties)
    assert tools["debug.start_session"].fn.__name__ == "debug_start_session"
    start_properties = tools["debug.start_session"].parameters["properties"]
    assert {"context", "options"}.issubset(start_properties)
    assert {"artifact_root", "debug_profile", "new_session", "run_id"}.isdisjoint(start_properties)
    assert tools["debug.read_memory"].fn.__name__ == "debug_read_memory"
    read_memory_properties = tools["debug.read_memory"].parameters["properties"]
    assert {"address", "byte_count", "context"}.issubset(read_memory_properties)
    assert {"artifact_root", "debug_session_id", "run_id"}.isdisjoint(read_memory_properties)
    assert tools["debug.end_session"].fn.__name__ == "debug_end_session"
    assert "context" in tools["debug.end_session"].parameters["properties"]


def test_debug_tool_malformed_grouped_input_returns_configuration_error() -> None:
    response = _get_tool_fn(create_app(), "debug.start_session")(
        context={"unexpected": "field"},
    )

    assert response["ok"] is False
    assert response["error"]["category"] == "configuration_error"


def test_run_scoped_mcp_tool_families_keep_run_id_in_context() -> None:
    app = create_app()

    for tool_name in (
        "debug.start_session",
        "debug.read_memory",
        "debug.end_session",
        "debug.introspect.run",
        "debug.introspect.helper",
        "debug.introspect.check_prerequisites",
        "debug.introspect.from_vmcore",
        "debug.introspect.from_vmcore_helper",
        "debug.postmortem.crash",
        "debug.postmortem.triage",
        "debug.postmortem.check_prereqs",
        "debug.postmortem.list_dumps",
        "debug.postmortem.fetch",
    ):
        assert "run_id" not in app._tool_manager._tools[tool_name].parameters["properties"]


def test_workflow_tool_malformed_grouped_input_returns_configuration_error() -> None:
    response = _get_tool_fn(create_app(), "workflow.build_boot_test")(
        profiles={"unexpected": "field"},
    )

    assert response["ok"] is False
    assert response["error"]["category"] == "configuration_error"


def test_create_app_registers_stub_provider_tools() -> None:
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
        assert {"provider_context", "execution_options"}.issubset(properties)
        assert {"provider_name", "timeout_seconds", "operation_label"}.isdisjoint(properties)


def test_target_run_tests_tool_uses_grouped_context_and_options() -> None:
    app = create_app()
    tool = app._tool_manager._tools["target.run_tests"]

    assert "target.run_tests" in tool_names()
    properties = tool.parameters["properties"]
    assert {"context", "options"}.issubset(properties)
    assert {"force_rerun", "commands", "run_id", "artifact_root"}.isdisjoint(properties)
    assert tool.fn.__name__ == "target_run_tests"


def test_target_run_tests_tool_options_forward_acknowledged_permissions(tmp_path: Path) -> None:
    captured: dict[str, object] = {}
    app = FastMCP("test")
    register_target_tools(
        app,
        default_artifact_root=tmp_path / "default-runs",
        sensitive_paths=[],
        admission=AdmissionService(SnapshotStore()),
        session_registry=SessionRegistry(directory=tmp_path / "sessions"),
        target_boot_handler=lambda **kwargs: ToolResponse.success(summary="booted"),
        target_run_tests_handler=lambda **kwargs: (
            captured.update(kwargs) or ToolResponse.success(summary="tested", run_id="run-abc123")
        ),
    )
    tool = app._tool_manager._tools["target.run_tests"]

    response = tool.fn(
        context={"run_id": "run-abc123", "artifact_root": str(tmp_path / "runs")},
        options={
            "commands": [["uname", "-a"]],
            "acknowledged_permissions": TARGET_DESTRUCTIVE_PERMISSIONS["target.run_tests"],
        },
    )

    assert response["status"] == "succeeded"
    request = captured["request"]
    assert request.commands == [["uname", "-a"]]
    assert request.acknowledged_permissions == TARGET_DESTRUCTIVE_PERMISSIONS["target.run_tests"]


def test_target_run_tests_tool_and_handler_are_target_owned() -> None:
    from kdive.target import handlers as target_handlers

    tool = create_app()._tool_manager._tools["target.run_tests"]

    assert tool.fn.__module__ == "kdive.target.tools"
    assert target_handlers.target_run_tests_handler.__module__ == "kdive.target.handlers"


def test_target_boot_handler_is_target_owned() -> None:
    from kdive.target import handlers as target_handlers

    tool = create_app()._tool_manager._tools["target.boot"]

    assert tool.fn.__module__ == "kdive.target.tools"
    assert target_handlers.target_boot_handler.__module__ == "kdive.target.handlers"


def test_target_run_tests_handler_response_serializes(tmp_path: Path) -> None:
    source, artifact_root = create_test_run(tmp_path)
    store = ArtifactStore(artifact_root, source_paths=[source])
    store.record_step_result(
        "run-abc123",
        StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="boot ok"),
    )

    response = get_manifest_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.model_dump(mode="json")["run_id"] == "run-abc123"


def test_artifacts_collect_tool_uses_grouped_context_and_options() -> None:
    app = create_app()
    tool = app._tool_manager._tools["artifacts.collect"]

    assert "artifacts.collect" in tool_names()
    properties = tool.parameters["properties"]
    assert {"context", "options"}.issubset(properties)
    assert {"run_id", "artifact_root", "force_recollect"}.isdisjoint(properties)
    assert tool.fn.__name__ == "artifacts_collect"


def test_transport_tools_use_grouped_context_and_options() -> None:
    app = create_app()

    open_properties = app._tool_manager._tools["transport.open"].parameters["properties"]
    close_properties = app._tool_manager._tools["transport.close"].parameters["properties"]
    inject_properties = app._tool_manager._tools["transport.inject_break"].parameters["properties"]

    assert {"context", "options"}.issubset(open_properties)
    assert {"run_id", "recovery"}.isdisjoint(open_properties)
    assert {"context", "session_id"}.issubset(close_properties)
    assert {"run_id"}.isdisjoint(close_properties)
    assert {"context", "session_id", "options"}.issubset(inject_properties)
    assert {"run_id", "artifact_root", "acknowledged_permissions"}.isdisjoint(inject_properties)


def test_artifact_tools_use_grouped_context_and_package_module() -> None:
    app = create_app()
    collect_tool = app._tool_manager._tools["artifacts.collect"]
    manifest_tool = app._tool_manager._tools["artifacts.get_manifest"]

    manifest_properties = manifest_tool.parameters["properties"]
    assert {"context"}.issubset(manifest_properties)
    assert {"run_id", "artifact_root"}.isdisjoint(manifest_properties)

    assert collect_tool.fn.__module__ == "kdive.artifacts.tools"
    assert manifest_tool.fn.__module__ == "kdive.artifacts.tools"


def test_workflow_build_boot_test_tool_uses_grouped_options() -> None:
    app = create_app()
    tool = app._tool_manager._tools["workflow.build_boot_test"]

    assert "workflow.build_boot_test" in tool_names()
    properties = tool.parameters["properties"]
    assert {"profiles", "context", "options"}.issubset(properties)
    assert {"force_rerun_tests", "force_recollect", "force_rebuild", "force_reboot"}.isdisjoint(properties)
    assert tool.fn.__name__ == "workflow_build_boot_test"
    assert tool.fn.__module__ == "kdive.workflow.tools"


def test_root_kernel_and_host_tools_use_grouped_inputs() -> None:
    app = create_app()

    expected_properties = {
        "artifacts.get_manifest": {"context"},
        "host.check_prerequisites": {"context", "profiles", "options"},
        "kernel.create_run": {"profiles", "context", "options"},
        "kernel.build": {"context", "options"},
        "target.boot": {"context", "profiles", "options"},
        "target.run_tests": {"context", "options"},
    }
    flat_properties = {
        "artifact_root",
        "source_path",
        "run_id",
        "build_profile",
        "target_profile",
        "rootfs_profile",
        "force_rebuild",
        "force_reboot",
        "force_rerun",
        "boot_overrides",
        "build_overrides",
        "profile_specs",
        "commands",
    }

    for tool_name, expected in expected_properties.items():
        properties = app._tool_manager._tools[tool_name].parameters["properties"]
        assert expected.issubset(properties), tool_name
        assert flat_properties.isdisjoint(properties), tool_name


def test_mcp_tool_signatures_use_context_operand_options_order() -> None:
    app = create_app()

    expected_order = {
        "host.check_prerequisites": ["context", "profiles", "options"],
        "kernel.create_run": ["context", "profiles", "options"],
        "kernel.build": ["context", "options"],
        "target.boot": ["context", "profiles", "options"],
        "target.run_tests": ["context", "options"],
        "workflow.build_boot_test": ["context", "profiles", "options"],
        "workflow.build_boot_debug": ["context", "profiles", "options"],
        "debug.read_registers": ["context", "registers"],
        "debug.read_symbol": ["context", "symbol"],
        "debug.read_memory": ["context", "address", "byte_count"],
        "debug.evaluate": ["context", "inspector", "options"],
        "debug.load_module_symbols": ["context", "module", "options"],
        "debug.introspect.run": ["target", "script", "options"],
    }

    for tool_name, expected in expected_order.items():
        assert list(inspect.signature(app._tool_manager._tools[tool_name].fn).parameters) == expected, tool_name


def test_kernel_build_tool_and_handler_are_kernel_owned() -> None:
    from kdive.kernel import handlers as kernel_handlers

    tool = create_app()._tool_manager._tools["kernel.build"]

    assert tool.fn.__module__ == "kdive.kernel.tools"
    assert kernel_handlers.kernel_build_handler.__module__ == "kdive.kernel.handlers"


def test_core_tool_adapter_shapes_are_not_server_reexports() -> None:
    for name in ("KernelBuildContext", "KernelBuildOptions", "TargetRunContext", "TargetRunOptions"):
        assert not hasattr(server, name)


def test_host_prerequisites_tool_is_prereqs_owned() -> None:
    tool = create_app()._tool_manager._tools["host.check_prerequisites"]

    assert tool.fn.__module__ == "kdive.prereqs.tools"


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
    resolved = kernel_handlers._build_profile_from_manifest(manifest)
    assert resolved.make_variables == {"CC": "clang"}


def test_build_profile_from_manifest_v1_fallback():
    from kdive.artifacts.manifest import RunManifest
    from kdive.domain import RunRequest

    manifest = RunManifest.create(
        run_id="r",
        request=RunRequest(
            source_path="/s",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        ),
    )  # resolved_build_profile is None
    resolved = kernel_handlers._build_profile_from_manifest(manifest)
    assert resolved.name == "x86_64-default"


def test_create_run_shapes_from_tool_args_builds_models():
    from kdive.config import BootOverrides, BuildOverrides

    build, boot, build_spec, target_spec, rootfs_spec = kernel_tools.create_run_shapes_from_tool_args(
        build_overrides={"make_variables": {"CC": "clang"}},
        boot_overrides={"kernel_args": ["dhash_entries=1"]},
        profile_specs=None,
    )
    assert isinstance(build, BuildOverrides) and build.make_variables == {"CC": "clang"}
    assert isinstance(boot, BootOverrides) and boot.kernel_args == ["dhash_entries=1"]
    assert (build_spec, target_spec, rootfs_spec) == (None, None, None)

    none_build, none_boot, *_ = kernel_tools.create_run_shapes_from_tool_args(
        build_overrides=None,
        boot_overrides=None,
        profile_specs=None,
    )
    assert none_build is None and none_boot is None


def test_create_run_shapes_from_tool_args_builds_config_lines():
    build_overrides, boot_overrides, *_ = kernel_tools.create_run_shapes_from_tool_args(
        build_overrides={"config_lines": ["CONFIG_DEBUG_INFO=y"]},
        boot_overrides=None,
        profile_specs=None,
    )
    assert build_overrides is not None
    assert build_overrides.config_lines == ["CONFIG_DEBUG_INFO=y"]
    assert boot_overrides is None


def test_create_run_shapes_from_tool_args_none_when_no_build_overrides():
    build_overrides, boot_overrides, *_ = kernel_tools.create_run_shapes_from_tool_args(
        build_overrides=None,
        boot_overrides={"kernel_args": ["nokaslr"]},
        profile_specs=None,
    )
    assert build_overrides is None
    assert boot_overrides is not None


def test_create_run_tool_accepts_overrides_and_rejects_bad_args(tmp_path: Path):
    import inspect

    src = make_source_tree(tmp_path)
    app = server.create_app()
    tool_fn = _get_tool_fn(app, "kernel.create_run")
    params = inspect.signature(tool_fn).parameters

    assert set(params) == {"profiles", "context", "options"}

    ok = tool_fn(
        profiles=kernel_tools.CreateRunProfiles(
            source_path=str(src),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        ),
        context=kernel_tools.CreateRunContext(artifact_root=str(tmp_path / "runs")),
        options=kernel_tools.CreateRunOptions(
            boot_overrides={"kernel_args": ["dhash_entries=1"]},
            build_overrides={"make_variables": {"CC": "clang"}, "config_lines": ["CONFIG_DEBUG_INFO=y"]},
        ),
    )
    assert ok["ok"] is True
    run_id = ok["run_id"]
    manifest = ArtifactStore(tmp_path / "runs", create_root=False).load_manifest(run_id)
    assert manifest.resolved_build_profile.config_lines == ["CONFIG_DEBUG_INFO=y"]

    bad = tool_fn(
        profiles=kernel_tools.CreateRunProfiles(
            source_path=str(src),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        ),
        context=kernel_tools.CreateRunContext(artifact_root=str(tmp_path / "runs2")),
        options=kernel_tools.CreateRunOptions(boot_overrides={"kernel_args": ["bad;arg"]}),
    )
    assert bad["ok"] is False
    assert bad["error"]["category"] == "configuration_error"


def test_target_boot_tool_accepts_grouped_boot_overrides() -> None:
    import inspect

    tool_fn = _get_tool_fn(server.create_app(), "target.boot")
    params = inspect.signature(tool_fn).parameters

    assert set(params) == {"context", "profiles", "options"}


def test_core_tools_register_through_dedicated_adapter_modules() -> None:
    app = create_app()

    assert app._tool_manager._tools["kernel.create_run"].fn.__module__ == "kdive.kernel.tools"
    assert app._tool_manager._tools["target.boot"].fn.__module__ == "kdive.target.tools"


def test_introspect_tool_is_registered() -> None:
    assert "debug.introspect.run" in tool_names()
    tool = create_app()._tool_manager._tools["debug.introspect.run"]
    assert tool.fn.__name__ == "debug_introspect_run"
    assert tool.fn.__module__ == "kdive.introspect.tools"
    assert "script" in tool.parameters["properties"]
    assert "options" in tool.parameters["properties"]
    assert "run_id" not in tool.parameters["properties"]
    assert "timeout_seconds" not in tool.parameters["properties"]

    app = create_app()
    for tool_name in (
        "debug.introspect.run",
        "debug.introspect.helper",
        "debug.introspect.check_prerequisites",
        "debug.introspect.from_vmcore",
        "debug.introspect.from_vmcore_helper",
    ):
        assert app._tool_manager._tools[tool_name].fn.__module__ == "kdive.introspect.tools"


def test_default_minimal_rootfs_is_builder_copy_on_write() -> None:
    from kdive.server import DEFAULT_ROOTFS_PROFILES

    minimal = DEFAULT_ROOTFS_PROFILES["minimal"]
    assert minimal.source_kind == "builder"
    assert minimal.mutability == "copy_on_write"
