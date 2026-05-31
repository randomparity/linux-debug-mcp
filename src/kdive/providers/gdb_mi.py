"""Deprecated compatibility facade for ``kdive.providers.local.gdb_mi``.

New code should import from ``kdive.providers.local.gdb_mi`` directly.
This facade is kept only for existing external imports and should be removed
before the 0.2.0 release.
"""

from kdive.providers.local.gdb_mi import (
    CANONICAL_PROBE_SYMBOL,
    MAX_INTERACTIVE_WAIT_SEC,
    MAX_MEMORY_READ_BYTES,
    MAX_RESPONSE_SNIPPET,
    MIN_GDB_VERSION,
    RSP_REMOTE_TIMEOUT_SEC,
    BreakpointRef,
    Frame,
    GdbMiAttachment,
    GdbMiEngine,
    GdbMiError,
    GdbMiSessionRegistry,
    LoadedModule,
    MiController,
    MiRecord,
    PygdbmiController,
    ResolvedSymbol,
    StopRecord,
    Variable,
    parse_mi_records,
)

__all__ = [
    "CANONICAL_PROBE_SYMBOL",
    "MAX_INTERACTIVE_WAIT_SEC",
    "MAX_MEMORY_READ_BYTES",
    "MAX_RESPONSE_SNIPPET",
    "MIN_GDB_VERSION",
    "RSP_REMOTE_TIMEOUT_SEC",
    "BreakpointRef",
    "Frame",
    "GdbMiAttachment",
    "GdbMiEngine",
    "GdbMiError",
    "GdbMiSessionRegistry",
    "LoadedModule",
    "MiController",
    "MiRecord",
    "PygdbmiController",
    "ResolvedSymbol",
    "StopRecord",
    "Variable",
    "parse_mi_records",
]
