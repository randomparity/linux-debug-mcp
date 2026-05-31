from __future__ import annotations

from kdive.config import ALLOWED_DEBUG_OPERATIONS
from kdive.domain import (
    OperationSemantics,
    ProviderCapability,
    TargetKind,
)
from kdive.providers.debug import (
    DebugSession as DebugSession,
)
from kdive.providers.debug import (
    DebugSessionState as DebugSessionState,
)
from kdive.providers.debug import (
    ProviderDebugError as ProviderDebugError,
)

# debug.introspect.run is implemented by local-drgn-introspect, not this provider.
# ALLOWED_DEBUG_OPERATIONS is the per-DebugProfile gate; the per-provider operations
# list must reflect what this provider actually serves.
QEMU_GDBSTUB_OPERATIONS = [
    "workflow.build_boot_debug",
    *[op for op in ALLOWED_DEBUG_OPERATIONS if op != "debug.introspect.run"],
]


def local_qemu_gdbstub_capability() -> ProviderCapability:
    return ProviderCapability(
        provider_name="local-qemu-gdbstub",
        provider_version="0.1.0",
        provider_family="debug",
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["tcp", "gdb-remote", "filesystem"],
        operations=QEMU_GDBSTUB_OPERATIONS,
        required_host_tools=["gdb"],
        destructive_permissions=[],
        access_methods=["gdbstub", "filesystem", "subprocess"],
        semantics=OperationSemantics(
            idempotent=False,
            retryable=True,
            destructive=True,
            cancelable=True,
            concurrent_safe=False,
        ),
    )
