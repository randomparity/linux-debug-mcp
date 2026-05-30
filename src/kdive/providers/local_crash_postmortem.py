"""local-crash-postmortem capability. Spec §10 / ADR 0026.

Offline, concurrent-safe crash-utility postmortem; needs neither ssh nor drgn,
so it is a separate capability from local-drgn-introspect (which requires ssh).
"""

from __future__ import annotations

from kdive.domain import (
    ImplementationState,
    OperationSemantics,
    ProviderCapability,
    TargetKind,
)


def local_crash_postmortem_capability() -> ProviderCapability:
    semantics = OperationSemantics(
        idempotent=False,
        retryable=True,
        destructive=False,
        cancelable=True,
        concurrent_safe=True,
    )
    return ProviderCapability(
        provider_name="local-crash-postmortem",
        provider_version="0.1.0",
        provider_family="debug",
        implementation_state=ImplementationState.IMPLEMENTED,
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["filesystem"],
        operations=["debug.postmortem.crash", "debug.postmortem.triage"],
        required_host_tools=["crash", "timeout", "prlimit"],
        destructive_permissions=[],
        access_methods=["subprocess", "filesystem"],
        semantics=semantics,
    )
