"""local-drgn-introspect: live drgn-over-SSH introspection provider.

Spec: docs/superpowers/specs/2026-05-28-debug-introspect-run-design.md
"""

from __future__ import annotations

from kdive.providers.models import (
    ImplementationState,
    OperationSemantics,
    ProviderCapability,
    ProviderOperationCapability,
    TargetKind,
)


def local_drgn_introspect_capability() -> ProviderCapability:
    """Factory used by ``providers/plugins.py``. Spec §3.4 / §2 / ADR 0010.

    The live ssh-tier ops are ``concurrent_safe=False`` (admission-gated); the
    offline vmcore ops are ``concurrent_safe=True`` (interface-contracts §5.6
    rule 3 — never gated), advertised via per-operation overrides.
    """
    live_semantics = OperationSemantics(
        idempotent=False,
        retryable=True,
        destructive=False,
        cancelable=True,
        concurrent_safe=False,
    )
    vmcore_semantics = OperationSemantics(
        idempotent=False,
        retryable=True,
        destructive=False,
        cancelable=True,
        concurrent_safe=True,
    )
    vmcore_ops = {"debug.introspect.from_vmcore", "debug.introspect.from_vmcore_helper"}
    operations = [
        "debug.introspect.run",
        "debug.introspect.check_prerequisites",
        "debug.postmortem.check_prereqs",
        "debug.introspect.helper",
        "debug.introspect.from_vmcore",
        "debug.introspect.from_vmcore_helper",
    ]
    return ProviderCapability(
        provider_name="local-drgn-introspect",
        provider_version="0.2.0",
        provider_family="debug",
        implementation_state=ImplementationState.IMPLEMENTED,
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["ssh"],
        operations=operations,
        required_host_tools=["ssh"],
        destructive_permissions=[],
        access_methods=["ssh"],
        semantics=live_semantics,
        operation_capabilities=[
            ProviderOperationCapability(
                operation=op,
                semantics=(vmcore_semantics if op in vmcore_ops else live_semantics),
            )
            for op in operations
        ],
    )
