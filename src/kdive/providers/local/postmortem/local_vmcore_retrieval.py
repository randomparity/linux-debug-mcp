"""local-vmcore-retrieval capability. #95 / ADR 0029 decision 10.

ssh-tier vmcore retrieval (list_dumps + fetch). fetch needs scp in addition to ssh,
so this is a dedicated capability rather than riding local-drgn-introspect (which
would over-declare scp for the pure introspect ops).
"""

from __future__ import annotations

from kdive.domain import (
    ImplementationState,
    OperationSemantics,
    ProviderCapability,
    TargetKind,
)


def local_vmcore_retrieval_capability() -> ProviderCapability:
    semantics = OperationSemantics(
        idempotent=False,
        retryable=True,
        destructive=False,
        cancelable=True,
        concurrent_safe=False,
    )
    return ProviderCapability(
        provider_name="local-vmcore-retrieval",
        provider_version="0.1.0",
        provider_family="debug",
        implementation_state=ImplementationState.IMPLEMENTED,
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["ssh"],
        operations=["debug.postmortem.list_dumps", "debug.postmortem.fetch"],
        required_host_tools=["ssh", "scp"],
        destructive_permissions=[],
        access_methods=["ssh", "filesystem"],
        semantics=semantics,
    )
