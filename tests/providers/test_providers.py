from pathlib import Path
from typing import Any, get_args, get_type_hints

import pytest

from kdive.config import (
    PROVIDER_DESTRUCTIVE_PERMISSIONS,
    TARGET_DESTRUCTIVE_PERMISSIONS,
    TRANSPORT_DESTRUCTIVE_PERMISSIONS,
)
from kdive.model import Model
from kdive.providers import debug as debug_contracts
from kdive.providers.base import local_provider_capability
from kdive.providers.local.introspect import local_drgn_introspect
from kdive.providers.models import (
    ImplementationState,
    OperationSemantics,
    ProviderCapability,
    ProviderOperationCapability,
    TargetKind,
)
from kdive.providers.plugins import ProviderPluginSpec, local_provider_plugin_specs
from kdive.providers.registry import ProviderRegistry

DebugSession = debug_contracts.DebugSession
DebugSessionState = debug_contracts.DebugSessionState


def test_local_provider_modules_are_grouped_by_capability_family() -> None:
    local_root = Path(__file__).parents[2] / "src" / "kdive" / "providers" / "local"
    flat_modules = {path.name for path in local_root.glob("*.py")}

    assert flat_modules == {"__init__.py"}
    for family in ("build", "debug", "introspect", "postmortem", "target", "test"):
        assert (local_root / family / "__init__.py").is_file()


def test_provider_package_has_no_local_introspect_facade() -> None:
    provider_root = Path(__file__).parents[2] / "src" / "kdive" / "providers"

    assert not (provider_root / "introspect.py").exists()


def test_local_drgn_provider_does_not_reexport_wrapper_internals() -> None:
    wrapper_surface = {
        "SCRIPT_BYTE_CAP",
        "TARGET_PYTHON_ARGV",
        "WrapperRenderError",
        "render_vmcore_wrapper",
        "render_vmcore_wrapper_skeleton",
        "render_wrapper",
        "render_wrapper_skeleton",
        "user_script_sha256",
        "WRAPPER_TEMPLATE",
        "VMCORE_WRAPPER_TEMPLATE",
        "_WRAPPER_BODY",
        "RUNNER_DEFAULT_CAPS",
    }

    assert not (wrapper_surface & set(vars(local_drgn_introspect)))


def test_local_drgn_provider_exports_capability_factory_only() -> None:
    assert not hasattr(local_drgn_introspect, "LocalDrgnIntrospectProvider")
    assert callable(local_drgn_introspect.local_drgn_introspect_capability)


def _annotation_contains_any(annotation: object) -> bool:
    return annotation is Any or any(_annotation_contains_any(arg) for arg in get_args(annotation))


def test_gdb_mi_provider_contract_preserves_result_model_types() -> None:
    engine_result_methods = (
        "attach",
        "probe_read",
        "resolve_symbol",
        "load_module_symbols",
        "set_breakpoint",
        "set_watchpoint",
        "list_breakpoints",
        "backtrace",
        "list_variables",
        "continue_",
        "step",
        "next",
        "finish",
        "interrupt",
        "wait_for_stop",
    )
    registry_result_methods = ("get", "require", "reap")

    for name in engine_result_methods:
        hints = get_type_hints(getattr(debug_contracts.GdbMiEngine, name))
        assert not _annotation_contains_any(hints["return"]), name
    for name in registry_result_methods:
        hints = get_type_hints(getattr(debug_contracts.GdbMiSessionRegistry, name))
        assert not _annotation_contains_any(hints["return"]), name


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
    assert registry.get("local-artifacts") == capability("local-artifacts")
    assert registry.require("local-artifacts").operations == ["host.check_prerequisites"]


def test_registry_rejects_duplicate_names() -> None:
    registry = ProviderRegistry()
    registry.register(capability("local-artifacts"))

    with pytest.raises(ValueError, match="already registered"):
        registry.register(capability("local-artifacts"))


def test_debug_session_uses_shared_model_base() -> None:
    from kdive.providers.local.debug import qemu_gdbstub

    assert not hasattr(qemu_gdbstub, "DebugSession")
    assert not hasattr(qemu_gdbstub, "DebugSessionState")
    assert not hasattr(qemu_gdbstub, "ProviderDebugError")

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

    with pytest.raises(ValueError, match="controller_mode"):
        DebugSession.model_validate(
            {
                **dumped,
                "controller_mode": "attached",
                "active_controller_pid": 1234,
                "controller_last_observed_state": "running",
                "active_controller_identity": {"pid": 1234},
            }
        )


def test_debug_attach_status_is_typed_and_rejects_unknown_values() -> None:
    DebugAttachStatus = debug_contracts.DebugAttachStatus
    hints = get_type_hints(DebugSession)

    session = DebugSession(
        session_id="debug-1",
        run_id="run-1",
        provider_name="local-qemu-gdbstub",
        gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
        vmlinux_path="/tmp/vmlinux",
        selected_debug_profile="qemu-gdbstub-default",
        attach_status="attached",
        started_at="2026-01-01T00:00:00+00:00",
        transcript_path="/tmp/transcript.log",
        command_metadata_path="/tmp/commands.jsonl",
        latest_summary_path="/tmp/debug-summary.json",
    )

    assert hints["attach_status"] is DebugAttachStatus
    assert session.attach_status is DebugAttachStatus.ATTACHED
    assert session.model_dump(mode="json")["attach_status"] == "attached"
    with pytest.raises(ValueError, match="attach_status"):
        DebugSession.model_validate(
            {
                **session.model_dump(mode="json"),
                "attach_status": "detached",
            }
        )


def test_registry_get_unknown_provider_returns_none() -> None:
    registry = ProviderRegistry()

    assert registry.get("missing-provider") is None


def test_registry_require_unknown_provider_has_contextual_error() -> None:
    registry = ProviderRegistry()

    with pytest.raises(KeyError, match="unknown provider: missing-provider") as exc_info:
        registry.require("missing-provider")

    assert isinstance(exc_info.value.__cause__, KeyError)


def test_default_registry_exposes_local_provider_capabilities() -> None:
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
    assert libvirt_qemu.destructive_permissions == list(TARGET_DESTRUCTIVE_PERMISSIONS["target.boot"])
    assert libvirt_qemu.semantics.idempotent is True
    assert libvirt_qemu.semantics.retryable is True
    assert libvirt_qemu.semantics.destructive is True
    assert libvirt_qemu.semantics.cancelable is False
    assert libvirt_qemu.semantics.concurrent_safe is False

    ssh_tests = providers["local-ssh-tests"]
    assert ssh_tests.operations == ["target.run_tests"]
    assert ssh_tests.required_host_tools == ["ssh"]
    assert ssh_tests.target_kinds == [TargetKind.VIRTUAL]
    assert ssh_tests.destructive_permissions == list(TARGET_DESTRUCTIVE_PERMISSIONS["target.run_tests"])
    assert ssh_tests.semantics.destructive is True

    qemu_gdbstub = providers["local-qemu-gdbstub"]
    assert qemu_gdbstub.destructive_permissions == []
    operation_permissions = {
        capability.operation: capability.destructive_permissions for capability in qemu_gdbstub.operation_capabilities
    }
    assert operation_permissions["transport.inject_break"] == list(
        TRANSPORT_DESTRUCTIVE_PERMISSIONS["transport.inject_break"]
    )
    assert operation_permissions["workflow.build_boot_debug"] == list(TARGET_DESTRUCTIVE_PERMISSIONS["target.boot"])


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


def test_local_provider_capability_defaults_to_access_methods_transports_copy() -> None:
    access_methods = ["filesystem"]

    provider = local_provider_capability(
        name="local-example",
        operations=["host.check_prerequisites"],
        access_methods=access_methods,
        concurrent_safe=True,
    )
    access_methods.append("subprocess")

    assert provider.provider_name == "local-example"
    assert provider.provider_version == "0.1.0"
    assert provider.provider_family == "local"
    assert provider.architectures == ["x86_64"]
    assert provider.target_kinds == [TargetKind.LOCAL, TargetKind.VIRTUAL]
    assert provider.operations == ["host.check_prerequisites"]
    assert provider.required_host_tools == []
    assert provider.destructive_permissions == []
    assert provider.access_methods == ["filesystem"]
    assert provider.transports == ["filesystem"]
    assert provider.semantics == OperationSemantics(
        idempotent=True,
        retryable=True,
        destructive=False,
        cancelable=False,
        concurrent_safe=True,
    )


def test_local_provider_capability_preserves_explicit_transports_and_overrides() -> None:
    provider = local_provider_capability(
        name="remote-example",
        provider_family="debug",
        operations=["debug.start_session", "debug.end_session"],
        access_methods=["filesystem"],
        transports=[],
        concurrent_safe=False,
    )

    assert provider.provider_family == "debug"
    assert provider.operations == ["debug.start_session", "debug.end_session"]
    assert provider.transports == []
    assert provider.semantics.concurrent_safe is False


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
        plugin_name="builtins.stub-providers",
        plugin_version="0.1.0",
        implementation_state=ImplementationState.STUB,
        provider_capability_factories=[lambda: capability("bad-stub")],
    )

    with pytest.raises(ValueError, match="implementation_state must match"):
        registry.register(capability("bad-stub"), plugin_spec=plugin_spec)


def test_default_registry_includes_stub_providers() -> None:
    registry = ProviderRegistry.with_defaults()
    providers = {provider.provider_name: provider for provider in registry.list_capabilities()}
    expected_stubs = {
        "remote-build-stub",
        "remote-artifact-sync-stub",
        "reservation-stub",
        "provisioning-stub",
        "hardware-control-stub",
        "console-access-stub",
        "boot-orchestration-stub",
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
    assert {capability.operation: capability.destructive_permissions for capability in operation_capabilities} == {
        operation: list(permissions) for operation, permissions in PROVIDER_DESTRUCTIVE_PERMISSIONS.items()
    }


def test_registry_finds_providers_by_operation_and_architecture_deterministically() -> None:
    registry = ProviderRegistry.with_defaults()

    providers = registry.find_by_operation_and_architecture(
        operation="remote.build_kernel",
        architecture="ppc64le",
    )

    assert [provider.provider_name for provider in providers] == ["remote-build-stub"]


def test_registry_advertises_local_qemu_gdbstub_without_debug_stubs() -> None:
    registry = ProviderRegistry.with_defaults()
    providers = {provider.provider_name: provider for provider in registry.list_capabilities()}

    debug_provider = providers["local-qemu-gdbstub"]
    assert "debug.start_session" in debug_provider.operations
    assert "workflow.build_boot_debug" in debug_provider.operations
    # Phase D (#82): the runtime module-symbol op is advertised so providers.list surfaces it;
    # the drgn-only introspect op stays excluded (it is served by local-drgn-introspect).
    assert "debug.load_module_symbols" in debug_provider.operations
    assert "debug.introspect.run" not in debug_provider.operations
    assert "debug.introspect.write" not in debug_provider.operations
    assert debug_provider.semantics.destructive is True
    assert debug_provider.semantics.cancelable is True
    assert debug_provider.semantics.concurrent_safe is False
    operation_capabilities = {
        operation_capability.operation: operation_capability
        for operation_capability in debug_provider.operation_capabilities
    }
    assert operation_capabilities["transport.inject_break"].destructive_permissions == list(
        TRANSPORT_DESTRUCTIVE_PERMISSIONS["transport.inject_break"]
    )
    assert operation_capabilities["workflow.build_boot_debug"].destructive_permissions == list(
        TARGET_DESTRUCTIVE_PERMISSIONS["target.boot"]
    )
    assert all(
        operation_capabilities[operation].destructive_permissions == []
        for operation in debug_provider.operations
        if operation not in {"transport.inject_break", "workflow.build_boot_debug"}
    )
    assert "stub-workflows" not in providers or "debug.start_session" not in providers["stub-workflows"].operations
