from __future__ import annotations

from linux_debug_mcp.domain import OperationSemantics, ProviderCapability, TargetKind


def sprint0_capability(
    *,
    name: str,
    operations: list[str],
    access_methods: list[str],
    concurrent_safe: bool,
) -> ProviderCapability:
    return ProviderCapability(
        provider_name=name,
        provider_version="0.1.0",
        architectures=["x86_64"],
        target_kinds=[TargetKind.LOCAL, TargetKind.VIRTUAL],
        operations=operations,
        required_host_tools=[],
        destructive_permissions=[],
        access_methods=access_methods,
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=False,
            cancelable=False,
            concurrent_safe=concurrent_safe,
        ),
    )
