from __future__ import annotations

from linux_debug_mcp.domain import ProviderCapability
from linux_debug_mcp.providers.base import sprint0_capability


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, ProviderCapability] = {}

    def register(self, capability: ProviderCapability) -> None:
        if capability.provider_name in self._providers:
            raise ValueError(f"provider already registered: {capability.provider_name}")
        self._providers[capability.provider_name] = capability

    def get(self, name: str) -> ProviderCapability:
        return self._providers[name]

    def list_capabilities(self) -> list[ProviderCapability]:
        return list(self._providers.values())

    @classmethod
    def with_defaults(cls) -> ProviderRegistry:
        registry = cls()
        registry.register(
            sprint0_capability(
                name="local-artifacts",
                operations=["kernel.create_run", "artifacts.get_manifest"],
                access_methods=["filesystem"],
                concurrent_safe=False,
            )
        )
        registry.register(
            sprint0_capability(
                name="local-prereqs",
                operations=["host.check_prerequisites"],
                access_methods=["subprocess", "filesystem"],
                concurrent_safe=True,
            )
        )
        registry.register(
            sprint0_capability(
                name="stub-workflows",
                operations=[
                    "kernel.build",
                    "target.boot",
                    "target.run_tests",
                    "artifacts.collect",
                    "workflow.build_boot_test",
                    "workflow.build_boot_debug",
                    "debug.start_session",
                    "debug.interrupt",
                    "debug.continue",
                    "debug.set_breakpoint",
                    "debug.clear_breakpoint",
                    "debug.list_breakpoints",
                    "debug.read_registers",
                    "debug.read_symbol",
                    "debug.read_memory",
                    "debug.evaluate",
                    "debug.end_session",
                ],
                access_methods=["none"],
                concurrent_safe=True,
            )
        )
        return registry
