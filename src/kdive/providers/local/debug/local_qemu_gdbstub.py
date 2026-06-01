from __future__ import annotations

from types import MappingProxyType

from kdive.config import (
    ALLOWED_DEBUG_OPERATIONS,
    TARGET_DESTRUCTIVE_PERMISSIONS,
    TRANSPORT_DESTRUCTIVE_PERMISSIONS,
)
from kdive.providers.models import (
    OperationSemantics,
    ProviderCapability,
    ProviderOperationCapability,
    TargetKind,
)

# debug.introspect.run is implemented by local-drgn-introspect, not this provider.
# ALLOWED_DEBUG_OPERATIONS is the per-DebugProfile gate; the per-provider operations
# list must reflect what this provider actually serves.
QEMU_GDBSTUB_EXCLUDED_OPS = {"debug.introspect.run", "debug.introspect.write"}
QEMU_GDBSTUB_OPERATIONS = (
    "workflow.build_boot_debug",
    *[op for op in ALLOWED_DEBUG_OPERATIONS if op not in QEMU_GDBSTUB_EXCLUDED_OPS],
)
QEMU_GDBSTUB_DESTRUCTIVE_PERMISSIONS = MappingProxyType(
    {
        **TRANSPORT_DESTRUCTIVE_PERMISSIONS,
        "workflow.build_boot_debug": TARGET_DESTRUCTIVE_PERMISSIONS["target.boot"],
    }
)


def _operation_destructive_permissions(operation: str) -> list[str]:
    return list(QEMU_GDBSTUB_DESTRUCTIVE_PERMISSIONS.get(operation, []))


def local_qemu_gdbstub_capability() -> ProviderCapability:
    semantics = OperationSemantics(
        idempotent=False,
        retryable=True,
        destructive=True,
        cancelable=True,
        concurrent_safe=False,
    )
    return ProviderCapability(
        provider_name="local-qemu-gdbstub",
        provider_version="0.1.0",
        provider_family="debug",
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["tcp", "gdb-remote", "filesystem"],
        operations=list(QEMU_GDBSTUB_OPERATIONS),
        required_host_tools=["gdb"],
        destructive_permissions=[],
        access_methods=["gdbstub", "filesystem", "subprocess"],
        semantics=semantics,
        operation_capabilities=[
            ProviderOperationCapability(
                operation=operation,
                semantics=semantics,
                required_host_tools=["gdb"],
                destructive_permissions=_operation_destructive_permissions(operation),
            )
            for operation in QEMU_GDBSTUB_OPERATIONS
        ],
    )
