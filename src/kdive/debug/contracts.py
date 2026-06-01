from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Protocol

from kdive.config import DebugProfile
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ToolResponse
from kdive.providers.debug import GdbMiEngine, GdbMiSessionRegistry
from kdive.seams.guard import SessionGuard


class DebugOperationRequest(Protocol):
    profile_operation: str
    summary_name: str
    persist_manifest: bool
    requires_admission_fence: bool


class _DebugOperationMetadata:
    profile_operation: ClassVar[str]
    summary_name: ClassVar[str]
    persist_manifest: ClassVar[bool]
    requires_admission_fence: ClassVar[bool] = False


@dataclass(frozen=True)
class DebugReadRegistersRequest(_DebugOperationMetadata):
    registers: list[str]
    profile_operation: ClassVar[str] = "debug.read_registers"
    summary_name: ClassVar[str] = "read_registers"
    persist_manifest: ClassVar[bool] = False


@dataclass(frozen=True)
class DebugReadSymbolRequest(_DebugOperationMetadata):
    symbol: str
    profile_operation: ClassVar[str] = "debug.read_symbol"
    summary_name: ClassVar[str] = "read_symbol"
    persist_manifest: ClassVar[bool] = False


@dataclass(frozen=True)
class DebugReadMemoryRequest(_DebugOperationMetadata):
    address: int
    byte_count: int
    profile_operation: ClassVar[str] = "debug.read_memory"
    summary_name: ClassVar[str] = "read_memory"
    persist_manifest: ClassVar[bool] = False


@dataclass(frozen=True)
class DebugEvaluateRequest(_DebugOperationMetadata):
    inspector: str
    arguments: dict[str, object]
    profile_operation: ClassVar[str] = "debug.evaluate"
    summary_name: ClassVar[str] = "evaluate"
    persist_manifest: ClassVar[bool] = False


@dataclass(frozen=True)
class DebugSetBreakpointRequest(_DebugOperationMetadata):
    symbol: str
    profile_operation: ClassVar[str] = "debug.set_breakpoint"
    summary_name: ClassVar[str] = "set_breakpoint"
    persist_manifest: ClassVar[bool] = True
    requires_admission_fence: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugSetWatchpointRequest(_DebugOperationMetadata):
    symbol: str
    profile_operation: ClassVar[str] = "debug.set_watchpoint"
    summary_name: ClassVar[str] = "set_watchpoint"
    persist_manifest: ClassVar[bool] = True
    requires_admission_fence: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugClearBreakpointRequest(_DebugOperationMetadata):
    breakpoint_id: str
    profile_operation: ClassVar[str] = "debug.clear_breakpoint"
    summary_name: ClassVar[str] = "clear_breakpoint"
    persist_manifest: ClassVar[bool] = True
    requires_admission_fence: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugClearWatchpointRequest(_DebugOperationMetadata):
    breakpoint_id: str
    profile_operation: ClassVar[str] = "debug.clear_watchpoint"
    summary_name: ClassVar[str] = "clear_watchpoint"
    persist_manifest: ClassVar[bool] = True
    requires_admission_fence: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugListBreakpointsRequest(_DebugOperationMetadata):
    profile_operation: ClassVar[str] = "debug.list_breakpoints"
    summary_name: ClassVar[str] = "list_breakpoints"
    persist_manifest: ClassVar[bool] = False
    requires_admission_fence: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugBacktraceRequest(_DebugOperationMetadata):
    profile_operation: ClassVar[str] = "debug.backtrace"
    summary_name: ClassVar[str] = "backtrace"
    persist_manifest: ClassVar[bool] = False
    requires_admission_fence: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugListVariablesRequest(_DebugOperationMetadata):
    profile_operation: ClassVar[str] = "debug.list_variables"
    summary_name: ClassVar[str] = "list_variables"
    persist_manifest: ClassVar[bool] = False
    requires_admission_fence: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugContinueRequest(_DebugOperationMetadata):
    timeout_seconds: int | None
    profile_operation: ClassVar[str] = "debug.continue"
    summary_name: ClassVar[str] = "continue_execution"
    persist_manifest: ClassVar[bool] = True
    requires_admission_fence: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugStepRequest(_DebugOperationMetadata):
    timeout_seconds: int | None
    profile_operation: ClassVar[str] = "debug.step"
    summary_name: ClassVar[str] = "step"
    persist_manifest: ClassVar[bool] = True
    requires_admission_fence: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugNextRequest(_DebugOperationMetadata):
    timeout_seconds: int | None
    profile_operation: ClassVar[str] = "debug.next"
    summary_name: ClassVar[str] = "next"
    persist_manifest: ClassVar[bool] = True
    requires_admission_fence: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugFinishRequest(_DebugOperationMetadata):
    timeout_seconds: int | None
    profile_operation: ClassVar[str] = "debug.finish"
    summary_name: ClassVar[str] = "finish"
    persist_manifest: ClassVar[bool] = True
    requires_admission_fence: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugInterruptRequest(_DebugOperationMetadata):
    timeout_seconds: int | None
    profile_operation: ClassVar[str] = "debug.interrupt"
    summary_name: ClassVar[str] = "interrupt"
    persist_manifest: ClassVar[bool] = True
    requires_admission_fence: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugRuntime:
    debug_profiles: dict[str, DebugProfile] | None = None
    admission: AdmissionService | None = None
    transaction: TransportTransaction | None = None
    session_registry: SessionRegistry | None = None
    session_guard: SessionGuard | None = None
    gdb_mi_engine: GdbMiEngine | None = None
    gdb_mi_sessions: GdbMiSessionRegistry | None = None


class DebugOperationCore(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        debug_session_id: str | None,
        request: DebugOperationRequest,
        runtime: DebugRuntime,
    ) -> ToolResponse: ...
