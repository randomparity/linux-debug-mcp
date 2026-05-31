from __future__ import annotations

from collections.abc import Callable

from pydantic import Field, field_validator

from kdive.domain import ImplementationState, Model, ProviderCapability
from kdive.providers.base import sprint0_capability
from kdive.providers.local.build.local_kernel_build import local_kernel_build_capability
from kdive.providers.local.debug.qemu_gdbstub import local_qemu_gdbstub_capability
from kdive.providers.local.introspect.local_drgn_introspect import local_drgn_introspect_capability
from kdive.providers.local.local_ssh_tests import local_ssh_tests_capability
from kdive.providers.local.postmortem.local_crash_postmortem import local_crash_postmortem_capability
from kdive.providers.local.postmortem.local_vmcore_retrieval import local_vmcore_retrieval_capability
from kdive.providers.local.target.libvirt_qemu import local_libvirt_qemu_capability
from kdive.providers.stubs import stub_provider_capability_factories


class ProviderPluginSpec(Model):
    plugin_name: str
    plugin_version: str
    implementation_state: ImplementationState
    provider_capability_factories: list[Callable[[], ProviderCapability]]
    documentation_paths: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @field_validator("plugin_name", "plugin_version")
    @classmethod
    def reject_empty_label(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("plugin labels must not be empty")
        return value


def local_provider_plugin_specs() -> list[ProviderPluginSpec]:
    return [
        ProviderPluginSpec(
            plugin_name="builtins.local",
            plugin_version="0.1.0",
            implementation_state=ImplementationState.IMPLEMENTED,
            provider_capability_factories=[
                lambda: sprint0_capability(
                    name="local-artifacts",
                    operations=["kernel.create_run", "artifacts.get_manifest"],
                    access_methods=["filesystem"],
                    concurrent_safe=False,
                    provider_family="artifacts",
                    transports=["filesystem"],
                ),
                lambda: sprint0_capability(
                    name="local-prereqs",
                    operations=["host.check_prerequisites"],
                    access_methods=["subprocess", "filesystem"],
                    concurrent_safe=True,
                    provider_family="host",
                    transports=["subprocess", "filesystem"],
                ),
                local_kernel_build_capability,
                local_libvirt_qemu_capability,
                local_ssh_tests_capability,
                local_qemu_gdbstub_capability,
                local_drgn_introspect_capability,
                local_crash_postmortem_capability,
                local_vmcore_retrieval_capability,
            ],
            documentation_paths=["README.md"],
        )
    ]


def stub_provider_plugin_specs() -> list[ProviderPluginSpec]:
    return [
        ProviderPluginSpec(
            plugin_name="builtins.stub-providers",
            plugin_version="0.1.0",
            implementation_state=ImplementationState.STUB,
            provider_capability_factories=stub_provider_capability_factories(),
            documentation_paths=["docs/ppc64le-provider-spike.md"],
            limitations=[
                "Stub providers are discoverability-only and do not open network, serial, or power-control resources."
            ],
        )
    ]


def built_in_provider_plugin_specs() -> list[ProviderPluginSpec]:
    return [*local_provider_plugin_specs(), *stub_provider_plugin_specs()]


def builtin_provider_plugin_specs() -> list[ProviderPluginSpec]:
    return built_in_provider_plugin_specs()
