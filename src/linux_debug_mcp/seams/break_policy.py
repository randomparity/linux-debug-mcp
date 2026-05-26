from __future__ import annotations

from typing import Protocol, runtime_checkable

from linux_debug_mcp.seams.target import ConsoleKind, PlatformMetadata
from linux_debug_mcp.transport.base import BreakMethod, BreakPlan, LineRole, TransportRef

_SUPPORTS_UART_BREAK = "supports_uart_break"
_PROVIDES_RSP = "provides_rsp"

_RATIONALE = {
    BreakMethod.GDBSTUB_NATIVE: "rsp channel: gdb interrupts directly",
    BreakMethod.UART_BREAK: "dedicated debug line with UART break",
    BreakMethod.AGENT_PROXY_BREAK: "shared console with UART break via agent-proxy",
    BreakMethod.SYSRQ_G: "sysrq-g over ssh",
}


class BreakPlanError(ValueError):
    """Admission-time break-plan rejection. `code` is `no_break_plan` (no topology
    predicate holds) or `break_disproved` (every topology candidate positively
    disproved) — spec §4.8."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


@runtime_checkable
class BreakPolicy(Protocol):
    def plan(
        self,
        *,
        channel: TransportRef,
        platform: PlatformMetadata,
        disproved: set[BreakMethod] | None = None,
    ) -> BreakPlan: ...


class ReferenceBreakPolicy:
    """Encodes the contract §4.1 reference mappings as topology predicates against the
    *selected channel's* line_role + caps plus platform facts. Admission is
    topology-first (spec §4.8); disproof is disproof-only and injected by the caller."""

    def plan(
        self,
        *,
        channel: TransportRef,
        platform: PlatformMetadata,
        disproved: set[BreakMethod] | None = None,
    ) -> BreakPlan:
        disproved = disproved or set()
        candidates = self._candidates(channel, platform)
        if not candidates:
            raise BreakPlanError(
                "no break method's topology predicate holds for the selected channel",
                code="no_break_plan",
            )
        admissible = [method for method in candidates if method not in disproved]
        if not admissible:
            raise BreakPlanError(
                "every topology-admissible break method was positively disproved",
                code="break_disproved",
            )
        method = admissible[0]
        return BreakPlan(method=method, channel_id=channel.channel_id, rationale=_RATIONALE[method])

    def _candidates(self, channel: TransportRef, platform: PlatformMetadata) -> list[BreakMethod]:
        # Insertion order is preference order: line-native first, ssh fallback last.
        # `line_role` classifies the *selected* physical line; `console_kind` describes
        # the target's *primary* console. A dedicated_debug line is a separate reserved
        # UART, so its uart_break is per-channel and independent of console_kind. The
        # shared_console line *is* the primary console, so agent_proxy_break (a serial
        # BREAK on it) is only executable when that console is a UART — hvc/virtio have
        # different BREAK semantics (contract §4.1: console_kind=hvc → sysrq_g).
        candidates: list[BreakMethod] = []
        if channel.line_role is LineRole.RSP and _PROVIDES_RSP in channel.caps:
            candidates.append(BreakMethod.GDBSTUB_NATIVE)
        if channel.line_role is LineRole.DEDICATED_DEBUG and _SUPPORTS_UART_BREAK in channel.caps:
            candidates.append(BreakMethod.UART_BREAK)
        if (
            channel.line_role is LineRole.SHARED_CONSOLE
            and _SUPPORTS_UART_BREAK in channel.caps
            and platform.console_kind is ConsoleKind.UART
        ):
            candidates.append(BreakMethod.AGENT_PROXY_BREAK)
        if platform.ssh_reachable:
            candidates.append(BreakMethod.SYSRQ_G)
        return candidates
