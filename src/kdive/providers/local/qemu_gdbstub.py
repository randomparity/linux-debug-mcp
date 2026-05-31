from __future__ import annotations

from typing import Literal

from pydantic import Field

from kdive.config import ALLOWED_DEBUG_OPERATIONS
from kdive.domain import (
    ArtifactRef,
    ErrorCategory,
    OperationSemantics,
    ProviderCapability,
    TargetKind,
)
from kdive.model import Model

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


class DebugSession(Model):
    """The persisted record of a debug session. With the gdb/MI engine (#81) the live attachment is
    held in-process by the GdbMiSessionRegistry; this durable record is the manifest-facing shape
    the per-op handlers reload. ``controller_mode``/``active_controller_*`` are inert legacy fields
    retained for back-compat — the in-process registry is the liveness source, not a pid."""

    session_id: str
    run_id: str
    provider_name: str
    gdbstub_endpoint: dict[str, object]
    vmlinux_path: str
    selected_debug_profile: str
    attach_status: str
    started_at: str
    ended_at: str | None = None
    current_execution_state: Literal["unknown", "running", "stopped", "ended"] = "unknown"
    breakpoints: dict[str, dict[str, object]] = Field(default_factory=dict)
    # Phase D (#82): module name -> {".text": "0x...", ...} loaded at runtime addresses via
    # add-symbol-file. Keyed by module name; the .text address is the idempotency key.
    loaded_modules: dict[str, dict[str, str]] = Field(default_factory=dict)
    controller_mode: Literal["batch", "attached"] = "batch"
    active_controller_pid: int | None = None
    controller_last_observed_state: str = "not_started"
    active_controller_identity: dict[str, object] = Field(default_factory=dict)
    transcript_path: str
    command_metadata_path: str
    latest_summary_path: str
    symbol_identity_validation: dict[str, object] = Field(default_factory=dict)


class ProviderDebugError(Exception):
    def __init__(
        self,
        message: str,
        *,
        category: ErrorCategory,
        details: dict[str, object] | None = None,
        artifacts: list[ArtifactRef] | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.details = details or {}
        self.artifacts = artifacts or []
