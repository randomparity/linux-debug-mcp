from __future__ import annotations

from kdive.domain import OperationSemantics, ProviderCapability, TargetKind


def sprint0_capability(
    *,
    name: str,
    operations: list[str],
    access_methods: list[str],
    concurrent_safe: bool,
    provider_family: str = "local",
    transports: list[str] | None = None,
) -> ProviderCapability:
    return ProviderCapability(
        provider_name=name,
        provider_version="0.1.0",
        provider_family=provider_family,
        architectures=["x86_64"],
        target_kinds=[TargetKind.LOCAL, TargetKind.VIRTUAL],
        transports=transports or list(access_methods),
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
