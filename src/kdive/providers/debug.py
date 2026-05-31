from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import Field

from kdive.domain import ArtifactRef, ErrorCategory
from kdive.model import Model
from kdive.transport.base import Endpoint

MAX_INTERACTIVE_WAIT_SEC = 60
MAX_MEMORY_READ_BYTES = 4096


class DebugSessionState(StrEnum):
    UNKNOWN = "unknown"
    RUNNING = "running"
    STOPPED = "stopped"
    ENDED = "ended"


class DebugSession(Model):
    """Persisted debug-session record shared by debug providers and feature handlers."""

    session_id: str
    run_id: str
    provider_name: str
    gdbstub_endpoint: dict[str, object]
    vmlinux_path: str
    selected_debug_profile: str
    attach_status: str
    started_at: str
    ended_at: str | None = None
    current_execution_state: DebugSessionState = DebugSessionState.UNKNOWN
    breakpoints: dict[str, dict[str, object]] = Field(default_factory=dict)
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


class GdbMiEngine(Protocol):
    def attach(self, *, rsp_endpoint: Endpoint | None, vmlinux_path: Path, transcript_path: Path) -> Any: ...

    def probe_read(self, attachment: Any) -> Any: ...

    def resolve_symbol(self, attachment: Any, symbol_name: str) -> Any: ...

    def load_module_symbols(self, attachment: Any, *, name: str, ko_path: Path, sections: dict[str, str]) -> Any: ...

    def read_registers(self, attachment: Any, register_names: list[str]) -> dict[str, object]: ...

    def read_symbol(self, attachment: Any, symbol: str) -> dict[str, object]: ...

    def read_memory(self, attachment: Any, *, address: int, byte_count: int) -> dict[str, object]: ...

    def evaluate_inspector(
        self, attachment: Any, *, inspector: str, arguments: dict[str, object]
    ) -> dict[str, object]: ...

    def set_breakpoint(self, attachment: Any, location: str) -> Any: ...

    def set_watchpoint(self, attachment: Any, expression: str) -> Any: ...

    def clear_breakpoint(self, attachment: Any, number: str) -> None: ...

    def clear_watchpoint(self, attachment: Any, number: str) -> None: ...

    def list_breakpoints(self, attachment: Any) -> list[Any]: ...

    def backtrace(self, attachment: Any) -> list[Any]: ...

    def list_variables(self, attachment: Any) -> list[Any]: ...

    def continue_(self, attachment: Any, *, timeout_sec: float) -> Any: ...

    def step(self, attachment: Any, *, timeout_sec: float) -> Any: ...

    def next(self, attachment: Any, *, timeout_sec: float) -> Any: ...

    def finish(self, attachment: Any, *, timeout_sec: float) -> Any: ...

    def interrupt(self, attachment: Any) -> Any: ...

    def wait_for_stop(self, attachment: Any, *, timeout_sec: float) -> Any: ...

    def resume_and_detach(self, attachment: Any) -> bool: ...

    def force_resume(self, attachment: Any) -> bool: ...


class GdbMiSessionRegistry(Protocol):
    def register(self, session_id: str, attachment: Any) -> None: ...

    def get(self, session_id: str) -> Any | None: ...

    def require(self, session_id: str) -> Any: ...

    def reap(self, session_id: str) -> Any | None: ...
