import pytest

from kdive.config import TARGET_DESTRUCTIVE_PERMISSIONS
from kdive.domain import (
    ImplementationState,
    OperationSemantics,
    ProviderCapability,
    ProviderOperationCapability,
    TargetKind,
)
from kdive.model import Model
from kdive.providers.local.qemu_gdbstub import DebugSession, DebugSessionState
from kdive.providers.plugins import ProviderPluginSpec, local_provider_plugin_specs
from kdive.providers.registry import ProviderRegistry


def capability(name: str) -> ProviderCapability:
    return ProviderCapability(
        provider_name=name,
        provider_version="0.1.0",
        architectures=["x86_64"],
        target_kinds=[TargetKind.LOCAL],
        operations=["host.check_prerequisites"],
        required_host_tools=[],
        destructive_permissions=[],
        access_methods=["filesystem"],
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=False,
            cancelable=False,
            concurrent_safe=True,
        ),
    )


def test_registry_lists_registered_capabilities() -> None:
    registry = ProviderRegistry()
    registry.register(capability("local-artifacts"))

    assert registry.list_capabilities()[0].provider_name == "local-artifacts"
    assert registry.get("local-artifacts").operations == ["host.check_prerequisites"]


def test_registry_rejects_duplicate_names() -> None:
    registry = ProviderRegistry()
    registry.register(capability("local-artifacts"))

    with pytest.raises(ValueError, match="already registered"):
        registry.register(capability("local-artifacts"))


def test_debug_session_uses_shared_model_base() -> None:
    assert issubclass(DebugSession, Model)
    assert DebugSession.__bases__ == (Model,)


def test_debug_session_state_is_typed_and_serializes_as_string() -> None:
    session = DebugSession(
        session_id="debug-1",
        run_id="run-1",
        provider_name="local-qemu-gdbstub",
        gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
        vmlinux_path="/tmp/vmlinux",
        selected_debug_profile="qemu-gdbstub-default",
        attach_status="attached",
        started_at="2026-01-01T00:00:00+00:00",
        current_execution_state="stopped",
        transcript_path="/tmp/transcript.log",
        command_metadata_path="/tmp/commands.jsonl",
        latest_summary_path="/tmp/debug-summary.json",
    )

    assert session.current_execution_state is DebugSessionState.STOPPED
    reloaded = DebugSession.model_validate_json(session.model_dump_json())
    assert reloaded.current_execution_state is DebugSessionState.STOPPED
    dumped = session.model_dump(mode="json")
    assert dumped["current_execution_state"] == "stopped"
    assert {
        "controller_mode",
        "active_controller_pid",
        "controller_last_observed_state",
        "active_controller_identity",
    }.isdisjoint(dumped)

    legacy = DebugSession.model_validate(
        {
            **dumped,
            "controller_mode": "attached",
            "active_controller_pid": 1234,
            "controller_last_observed_state": "running",
            "active_controller_identity": {"pid": 1234},
        }
    )
    assert legacy.controller_mode == "attached"
    assert legacy.active_controller_pid == 1234


def test_registry_get_unknown_provider_has_contextual_error() -> None:
    registry = ProviderRegistry()

    with pytest.raises(KeyError, match="unknown provider: missing-provider") as exc_info:
        registry.get("missing-provider")

    assert isinstance(exc_info.value.__cause__, KeyError)


def test_default_registry_exposes_sprint_1_providers() -> None:
    registry = ProviderRegistry.with_defaults()

    providers = {provider.provider_name: provider for provider in registry.list_capabilities()}

    assert {
        "local-artifacts",
        "local-prereqs",
        "local-kernel-build",
        "local-libvirt-qemu",
        "local-ssh-tests",
        "local-qemu-gdbstub",
    }.issubset(providers)
    assert "kernel.build" in providers["local-kernel-build"].operations
    assert "make" in providers["local-kernel-build"].required_host_tools

    libvirt_qemu = providers["local-libvirt-qemu"]
    assert libvirt_qemu.operations == ["target.boot"]
    assert libvirt_qemu.required_host_tools == ["virsh", "qemu-img"]
    assert libvirt_qemu.target_kinds == [TargetKind.VIRTUAL]
    assert libvirt_qemu.access_methods == ["libvirt", "serial-console", "filesystem"]
    assert libvirt_qemu.destructive_permissions == TARGET_DESTRUCTIVE_PERMISSIONS["target.boot"]
    assert libvirt_qemu.semantics.idempotent is True
    assert libvirt_qemu.semantics.retryable is True
    assert libvirt_qemu.semantics.destructive is True
    assert libvirt_qemu.semantics.cancelable is False
    assert libvirt_qemu.semantics.concurrent_safe is False

    ssh_tests = providers["local-ssh-tests"]
    assert ssh_tests.operations == ["target.run_tests"]
    assert ssh_tests.required_host_tools == ["ssh"]
    assert ssh_tests.target_kinds == [TargetKind.VIRTUAL]

    qemu_gdbstub = providers["local-qemu-gdbstub"]
    assert qemu_gdbstub.destructive_permissions == []
    assert all(capability.destructive_permissions == [] for capability in qemu_gdbstub.operation_capabilities)


def test_default_providers_expose_richer_metadata() -> None:
    registry = ProviderRegistry.with_defaults()

    for provider in registry.list_capabilities():
        assert provider.provider_family
        assert provider.implementation_state in {
            ImplementationState.IMPLEMENTED,
            ImplementationState.STUB,
        }
        assert provider.transports
        assert isinstance(provider.limitations, list)
        assert provider.semantics is not None
        assert provider.operations == [capability.operation for capability in provider.operation_capabilities]
        for operation_capability in provider.operation_capabilities:
            assert operation_capability.semantics is not None
            assert operation_capability.implementation_state == provider.implementation_state
            assert isinstance(operation_capability.required_host_tools, list)
            assert isinstance(operation_capability.destructive_permissions, list)
            assert isinstance(operation_capability.limitations, list)


def test_local_provider_families_and_transports_are_specific() -> None:
    providers = {provider.provider_name: provider for provider in ProviderRegistry.with_defaults().list_capabilities()}

    assert providers["local-artifacts"].provider_family == "artifacts"
    assert providers["local-artifacts"].transports == ["filesystem"]
    assert providers["local-prereqs"].provider_family == "host"
    assert providers["local-prereqs"].transports == ["subprocess", "filesystem"]
    assert providers["local-kernel-build"].provider_family == "build"
    assert providers["local-kernel-build"].transports == ["subprocess", "filesystem"]
    assert providers["local-libvirt-qemu"].provider_family == "boot"
    assert providers["local-libvirt-qemu"].transports == ["libvirt", "serial-console", "filesystem"]
    assert providers["local-ssh-tests"].provider_family == "test"
    assert providers["local-ssh-tests"].transports == ["ssh", "filesystem"]
    assert providers["local-qemu-gdbstub"].provider_family == "debug"
    assert providers["local-qemu-gdbstub"].transports == ["tcp", "gdb-remote", "filesystem"]


def test_provider_capability_rejects_operation_capability_mismatch() -> None:
    semantics = OperationSemantics(
        idempotent=True,
        retryable=True,
        destructive=False,
        cancelable=False,
        concurrent_safe=True,
    )
    with pytest.raises(ValueError, match="operations must match"):
        ProviderCapability(
            provider_name="bad-provider",
            provider_version="0.1.0",
            architectures=["x86_64"],
            target_kinds=[TargetKind.LOCAL],
            operations=["host.check_prerequisites"],
            operation_capabilities=[
                ProviderOperationCapability(operation="kernel.build", semantics=semantics),
            ],
            required_host_tools=[],
            destructive_permissions=[],
            access_methods=["filesystem"],
            semantics=semantics,
        )


def test_provider_plugin_spec_rejects_empty_labels() -> None:
    with pytest.raises(ValueError, match="plugin labels"):
        ProviderPluginSpec(
            plugin_name=" ",
            plugin_version="0.1.0",
            implementation_state=ImplementationState.IMPLEMENTED,
            provider_capability_factories=[lambda: capability("local-artifacts")],
        )
    with pytest.raises(ValueError, match="plugin labels"):
        ProviderPluginSpec(
            plugin_name="plugin",
            plugin_version=" ",
            implementation_state=ImplementationState.IMPLEMENTED,
            provider_capability_factories=[lambda: capability("local-artifacts")],
        )


def test_default_registry_loads_from_static_local_plugin_specs() -> None:
    specs = local_provider_plugin_specs()
    registry = ProviderRegistry.with_defaults()
    provider_names = {provider.provider_name for provider in registry.list_capabilities()}

    assert specs[0].provider_capability_factories
    assert "local-kernel-build" in provider_names
    metadata = registry.provider_plugin_metadata("local-kernel-build")
    assert metadata is not None
    assert metadata.plugin_name == "builtins.local"
    assert metadata.plugin_version == "0.1.0"
    assert metadata.documentation_paths == ["README.md"]


def test_registry_rejects_plugin_capability_state_mismatch() -> None:
    registry = ProviderRegistry()
    plugin_spec = ProviderPluginSpec(
        plugin_name="builtins.future-stubs",
        plugin_version="0.1.0",
        implementation_state=ImplementationState.STUB,
        provider_capability_factories=[lambda: capability("bad-stub")],
    )

    with pytest.raises(ValueError, match="implementation_state must match"):
        registry.register(capability("bad-stub"), plugin_spec=plugin_spec)


def test_default_registry_includes_future_stub_providers() -> None:
    registry = ProviderRegistry.with_defaults()
    providers = {provider.provider_name: provider for provider in registry.list_capabilities()}
    expected_stubs = {
        "remote-build-stub",
        "remote-artifact-sync-stub",
        "reservation-stub",
        "provisioning-stub",
        "hardware-control-stub",
        "console-access-stub",
        "real-boot-stub",
    }

    assert expected_stubs.issubset(providers)
    for provider_name in expected_stubs:
        provider = providers[provider_name]
        assert provider.implementation_state == ImplementationState.STUB
        assert provider.architectures == ["x86_64", "ppc64le"]
        assert provider.transports
        assert provider.limitations
        assert provider.operations == [capability.operation for capability in provider.operation_capabilities]
        assert provider.required_host_tools
        metadata = registry.provider_plugin_metadata(provider_name)
        assert metadata is not None
        assert metadata.documentation_paths == ["docs/ppc64le-provider-spike.md"]

    destructive_operations = {
        "reservation.request_host",
        "reservation.release_host",
        "provision.prepare_target",
        "hardware.power_control",
        "hardware.boot_kernel",
        "workflow.reserve_provision_boot",
    }
    operation_capabilities = [
        capability
        for provider in providers.values()
        for capability in provider.operation_capabilities
        if capability.operation in destructive_operations
    ]
    assert {capability.operation for capability in operation_capabilities} == destructive_operations
    assert all(capability.destructive_permissions for capability in operation_capabilities)


def test_registry_finds_providers_by_operation_and_architecture_deterministically() -> None:
    registry = ProviderRegistry.with_defaults()

    providers = registry.find_by_operation_and_architecture(
        operation="remote.build_kernel",
        architecture="ppc64le",
    )

    assert [provider.provider_name for provider in providers] == ["remote-build-stub"]


def test_registry_advertises_local_qemu_gdbstub_and_removes_sprint_4_stubs() -> None:
    registry = ProviderRegistry.with_defaults()
    providers = {provider.provider_name: provider for provider in registry.list_capabilities()}

    debug_provider = providers["local-qemu-gdbstub"]
    assert "debug.start_session" in debug_provider.operations
    assert "workflow.build_boot_debug" in debug_provider.operations
    # Phase D (#82): the runtime module-symbol op is advertised so providers.list surfaces it;
    # the drgn-only introspect op stays excluded (it is served by local-drgn-introspect).
    assert "debug.load_module_symbols" in debug_provider.operations
    assert "debug.introspect.run" not in debug_provider.operations
    assert debug_provider.semantics.destructive is True
    assert debug_provider.semantics.cancelable is True
    assert debug_provider.semantics.concurrent_safe is False
    assert "stub-workflows" not in providers or "debug.start_session" not in providers["stub-workflows"].operations
