from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from linux_debug_mcp.seams.break_policy import BreakPlanError, BreakPolicy
from linux_debug_mcp.seams.target import PlatformMetadata, TargetKey
from linux_debug_mcp.transport.base import BreakMethod, BreakPlan, TransportRef


class SelectionError(RuntimeError):
    """No channel could be selected. `code` is `no_capable_channel` (no channel satisfies the
    required caps) or the break policy's `no_break_plan`/`break_disproved` (a capable channel
    exists but none has an executable break plan) — spec §4.1/§4.8."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


# §4.8: SYSRQ_G is issued over ssh and its preconditions (/proc/sys/kernel/sysrq,
# /proc/sysrq-trigger) are a property of the running KERNEL, not of any one console/RSP line — so
# a SYSRQ_G disproof is TARGET-WIDE and must prune the method on every channel of the target. The
# line-bound methods (gdbstub_native/uart_break/agent_proxy_break) are disproved per channel.
_TARGET_WIDE_BREAK_METHODS = frozenset({BreakMethod.SYSRQ_G})


@dataclass(frozen=True)
class BreakDisproof:
    """A §4.8 probe result proving a `BreakMethod` cannot execute. Its identity SCOPE is
    method-dependent: line-bound methods name a specific channel (`provider` + `channel_id`
    required); a TARGET-WIDE method (SYSRQ_G) carries no channel (both None) and applies to every
    channel of the target. Channel identity is keyed within a target (`channel_id` is unique only
    inside one target's `transports[]`, §3.2) and targets are isolated by `TargetKey`, so a
    line-bound disproof never poisons another target reusing the same provider/channel_id."""

    target_key: TargetKey
    method: BreakMethod
    provider: str | None = None
    channel_id: str | None = None

    def __post_init__(self) -> None:
        target_wide = self.method in _TARGET_WIDE_BREAK_METHODS
        if target_wide and (self.provider is not None or self.channel_id is not None):
            raise ValueError(f"{self.method} disproof is target-wide; it must not be scoped to a channel")
        if not target_wide and (self.provider is None or self.channel_id is None):
            raise ValueError(f"{self.method} disproof is line-bound; it must name a provider and channel_id")

    def applies_to(self, target_key: TargetKey, channel: TransportRef) -> bool:
        if self.target_key != target_key:
            return False
        if self.method in _TARGET_WIDE_BREAK_METHODS:
            return True  # target-wide: prunes the method on every channel of the target
        return self.provider == channel.provider and self.channel_id == channel.channel_id


@dataclass(frozen=True)
class Selection:
    channel: TransportRef
    break_plan: BreakPlan


def select_stop_capable_channel(
    *,
    target_key: TargetKey,
    transports: Sequence[TransportRef],
    required_caps: Iterable[str],
    platform: PlatformMetadata,
    break_policy: BreakPolicy,
    disproved: set[BreakDisproof] | None = None,
) -> Selection:
    """Pick the first `transports[]` channel for `target_key` (order is authoritative, contract
    §4.1) that satisfies `required_caps` AND has an executable break plan; a caps-sufficient but
    unbreakable channel is skipped, not selected. `disproved` is a set of `BreakDisproof` whose
    scope is method-aware (§4.8): a line-bound disproof prunes its method only on its own channel,
    while a target-wide disproof (SYSRQ_G) prunes that method on EVERY channel of the target — so
    an ssh-issued SysRq disproof recorded while evaluating one channel is not silently ignored for
    a sibling channel. Raises SelectionError(no_capable_channel) if no channel satisfies the caps;
    otherwise surfaces the aggregated no_break_plan/break_disproved code when capable channels
    exist but none is breakable."""
    required = set(required_caps)
    capable = [channel for channel in transports if required <= set(channel.caps)]
    if not capable:
        raise SelectionError("no channel satisfies the required caps", code="no_capable_channel")
    disproved = disproved or set()
    saw_disproved = False
    for channel in capable:
        channel_disproved = {d.method for d in disproved if d.applies_to(target_key, channel)}
        try:
            plan = break_policy.plan(channel=channel, platform=platform, disproved=channel_disproved)
        except BreakPlanError as exc:
            # Aggregate the contract's error taxonomy across ALL capable channels rather than
            # keeping only the last one: a positive disproof on any channel must not be
            # downgraded to no_break_plan by a later topology-less channel (§4.8).
            if exc.code == "break_disproved":
                saw_disproved = True
            continue
        return Selection(channel=channel, break_plan=plan)
    code = "break_disproved" if saw_disproved else "no_break_plan"
    raise SelectionError("no capable channel has an executable break plan", code=code)
