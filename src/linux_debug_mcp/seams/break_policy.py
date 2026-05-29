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
    disproved) — spec §4.1."""

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
    topology-first (spec §4.1); disproof is disproof-only and injected by the caller."""

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
        # UART, so its uart_break is per-channel and independent of console_kind.
        #
        # agent_proxy_break's contract predicate (§4.1) is just shared_console +
        # supports_uart_break, and the no-ssh shared-console case is explicitly
        # admissible — so it is never excluded by console_kind. console_kind only sets
        # *preference*: a UART shared console prefers the line-native agent_proxy_break;
        # a non-UART (hvc/virtio) shared console prefers sysrq_g over ssh (hvterm BREAK
        # semantics differ from UART), keeping agent_proxy_break as a no-ssh fallback.
        shared_console_uart_break = (
            channel.line_role is LineRole.SHARED_CONSOLE and _SUPPORTS_UART_BREAK in channel.caps
        )
        prefer_agent_proxy = shared_console_uart_break and platform.console_kind is ConsoleKind.UART
        candidates: list[BreakMethod] = []
        if channel.line_role is LineRole.RSP and _PROVIDES_RSP in channel.caps:
            candidates.append(BreakMethod.GDBSTUB_NATIVE)
        if channel.line_role is LineRole.DEDICATED_DEBUG and _SUPPORTS_UART_BREAK in channel.caps:
            candidates.append(BreakMethod.UART_BREAK)
        if prefer_agent_proxy:
            candidates.append(BreakMethod.AGENT_PROXY_BREAK)
        if platform.ssh_reachable:
            candidates.append(BreakMethod.SYSRQ_G)
        if shared_console_uart_break and not prefer_agent_proxy:
            candidates.append(BreakMethod.AGENT_PROXY_BREAK)
        return candidates
