from __future__ import annotations

from pydantic import Field

from linux_debug_mcp.domain import Model, ProviderCapability
from linux_debug_mcp.providers.plugins import ProviderPluginSpec, built_in_provider_plugin_specs


class ProviderPluginMetadata(Model):
    plugin_name: str
    plugin_version: str
    documentation_paths: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, ProviderCapability] = {}
        self._plugin_metadata: dict[str, ProviderPluginMetadata] = {}

    def register(self, capability: ProviderCapability, *, plugin_spec: ProviderPluginSpec | None = None) -> None:
        if capability.provider_name in self._providers:
            raise ValueError(f"provider already registered: {capability.provider_name}")
        if plugin_spec is not None:
            if capability.implementation_state != plugin_spec.implementation_state:
                raise ValueError(
                    "provider implementation_state must match plugin implementation_state: "
                    f"{capability.provider_name}"
                )
            capability = capability.model_copy(update={"documentation_paths": list(plugin_spec.documentation_paths)})
        self._providers[capability.provider_name] = capability
        if plugin_spec is not None:
            self._plugin_metadata[capability.provider_name] = ProviderPluginMetadata(
                plugin_name=plugin_spec.plugin_name,
                plugin_version=plugin_spec.plugin_version,
                documentation_paths=list(plugin_spec.documentation_paths),
                limitations=list(plugin_spec.limitations),
            )

    def get(self, name: str) -> ProviderCapability:
        return self._providers[name]

    def list_capabilities(self) -> list[ProviderCapability]:
        return list(self._providers.values())

    def provider_plugin_metadata(self, provider_name: str) -> ProviderPluginMetadata | None:
        return self._plugin_metadata.get(provider_name)

    def find_by_operation_and_architecture(self, *, operation: str, architecture: str) -> list[ProviderCapability]:
        return sorted(
            (
                provider
                for provider in self._providers.values()
                if operation in provider.operations and architecture in provider.architectures
            ),
            key=lambda provider: provider.provider_name,
        )

    @classmethod
    def with_defaults(cls) -> ProviderRegistry:
        registry = cls()
        for plugin_spec in built_in_provider_plugin_specs():
            for factory in plugin_spec.provider_capability_factories:
                registry.register(factory(), plugin_spec=plugin_spec)
        return registry
