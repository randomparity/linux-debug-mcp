from __future__ import annotations

from collections.abc import Callable, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol, TypeVar

from pydantic import Field
from pydantic.main import IncEx

from kdive.domain import ArtifactRef, ErrorCategory
from kdive.model import Model
from kdive.transport.core.base import Endpoint

MAX_INTERACTIVE_WAIT_SEC = 60
MAX_MEMORY_READ_BYTES = 4096


class DebugSessionState(StrEnum):
    UNKNOWN = "unknown"
    RUNNING = "running"
    STOPPED = "stopped"
    ENDED = "ended"


class DebugAttachStatus(StrEnum):
    ATTACHED = "attached"


class DebugSession(Model):
    """Persisted debug-session record shared by debug providers and feature handlers."""

    session_id: str
    run_id: str
    provider_name: str
    gdbstub_endpoint: dict[str, object]
    vmlinux_path: str
    selected_debug_profile: str
    attach_status: DebugAttachStatus
    started_at: str
    ended_at: str | None = None
    current_execution_state: DebugSessionState = DebugSessionState.UNKNOWN
    breakpoints: dict[str, dict[str, object]] = Field(default_factory=dict)
    loaded_modules: dict[str, dict[str, str]] = Field(default_factory=dict)
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


class GdbMiError(Exception):
    def __init__(
        self,
        message: str,
        *,
        category: ErrorCategory,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.details = details or {}


class GdbMiModelResult(Protocol):
    def model_dump(
        self,
        *,
        mode: Literal["json", "python"] | str = "python",
        include: IncEx | None = None,
        exclude: IncEx | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        exclude_unset: bool = False,
        exclude_defaults: bool = False,
        exclude_none: bool = False,
        exclude_computed_fields: bool = False,
        round_trip: bool = False,
        warnings: bool | Literal["none", "warn", "error"] = True,
        fallback: Callable[[Any], Any] | None = None,
        serialize_as_any: bool = False,
        polymorphic_serialization: bool | None = None,
    ) -> dict[str, Any]: ...


class GdbMiAttachment(Protocol):
    transcript_path: Path


GdbMiAttachmentT = TypeVar("GdbMiAttachmentT", bound=GdbMiAttachment)


class GdbMiRecord(GdbMiModelResult, Protocol): ...


class GdbMiResolvedSymbol(GdbMiModelResult, Protocol): ...


class GdbMiLoadedModule(GdbMiModelResult, Protocol):
    sections: dict[str, str]


class GdbMiBreakpointRef(GdbMiModelResult, Protocol):
    number: str


class GdbMiFrame(GdbMiModelResult, Protocol): ...


class GdbMiVariable(GdbMiModelResult, Protocol): ...


class GdbMiStopRecord(GdbMiModelResult, Protocol): ...


class GdbMiEngine(Protocol[GdbMiAttachmentT]):
    def attach(
        self, *, rsp_endpoint: Endpoint | None, vmlinux_path: Path, transcript_path: Path
    ) -> GdbMiAttachmentT: ...

    def probe_read(self, attachment: GdbMiAttachmentT) -> GdbMiRecord: ...

    def resolve_symbol(self, attachment: GdbMiAttachmentT, symbol_name: str) -> GdbMiResolvedSymbol: ...

    def load_module_symbols(
        self, attachment: GdbMiAttachmentT, *, name: str, ko_path: Path, sections: dict[str, str]
    ) -> GdbMiLoadedModule: ...

    def read_registers(self, attachment: GdbMiAttachmentT, register_names: list[str]) -> dict[str, object]: ...

    def read_symbol(self, attachment: GdbMiAttachmentT, symbol: str) -> dict[str, object]: ...

    def read_memory(self, attachment: GdbMiAttachmentT, *, address: int, byte_count: int) -> dict[str, object]: ...

    def evaluate_inspector(
        self, attachment: GdbMiAttachmentT, *, inspector: str, arguments: dict[str, object]
    ) -> dict[str, object]: ...

    def set_breakpoint(self, attachment: GdbMiAttachmentT, location: str) -> GdbMiBreakpointRef: ...

    def set_watchpoint(self, attachment: GdbMiAttachmentT, expression: str) -> GdbMiBreakpointRef: ...

    def clear_breakpoint(self, attachment: GdbMiAttachmentT, number: str) -> None: ...

    def clear_watchpoint(self, attachment: GdbMiAttachmentT, number: str) -> None: ...

    def list_breakpoints(self, attachment: GdbMiAttachmentT) -> Sequence[GdbMiBreakpointRef]: ...

    def backtrace(self, attachment: GdbMiAttachmentT) -> Sequence[GdbMiFrame]: ...

    def list_variables(self, attachment: GdbMiAttachmentT) -> Sequence[GdbMiVariable]: ...

    def continue_(self, attachment: GdbMiAttachmentT, *, timeout_sec: float) -> GdbMiStopRecord: ...

    def step(self, attachment: GdbMiAttachmentT, *, timeout_sec: float) -> GdbMiStopRecord: ...

    def next(self, attachment: GdbMiAttachmentT, *, timeout_sec: float) -> GdbMiStopRecord: ...

    def finish(self, attachment: GdbMiAttachmentT, *, timeout_sec: float) -> GdbMiStopRecord: ...

    def interrupt(self, attachment: GdbMiAttachmentT) -> GdbMiStopRecord | None: ...

    def wait_for_stop(self, attachment: GdbMiAttachmentT, *, timeout_sec: float) -> GdbMiStopRecord | None: ...

    def resume_and_detach(self, attachment: GdbMiAttachmentT) -> bool: ...

    def force_resume(self, attachment: GdbMiAttachmentT) -> bool: ...


class GdbMiSessionRegistry(Protocol[GdbMiAttachmentT]):
    def register(self, session_id: str, attachment: GdbMiAttachmentT) -> None: ...

    def get(self, session_id: str) -> GdbMiAttachmentT | None: ...

    def require(self, session_id: str) -> GdbMiAttachmentT: ...

    def reap(self, session_id: str) -> GdbMiAttachmentT | None: ...
