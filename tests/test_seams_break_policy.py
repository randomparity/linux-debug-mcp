import pytest

from linux_debug_mcp.seams.break_policy import BreakPlanError, ReferenceBreakPolicy
from linux_debug_mcp.seams.target import ConsoleKind, PlatformMetadata
from linux_debug_mcp.transport.base import BreakMethod, LineRole, TransportRef


def _platform(*, ssh: bool, console: ConsoleKind = ConsoleKind.UART) -> PlatformMetadata:
    return PlatformMetadata(
        console_kind=console,
        console_count=1,
        dedicated_debug_line=False,
        ssh_reachable=ssh,
    )


def _channel(role: LineRole, caps: list[str]) -> TransportRef:
    return TransportRef(provider="p", channel_id=f"{role}-0", line_role=role, caps=caps)


def test_rsp_channel_yields_gdbstub_native():
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.RSP, ["provides_rsp"]),
        platform=_platform(ssh=False),
    )
    assert plan.method is BreakMethod.GDBSTUB_NATIVE
    assert plan.channel_id == "rsp-0"


def test_dedicated_debug_uart_break():
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.DEDICATED_DEBUG, ["provides_console", "supports_uart_break"]),
        platform=_platform(ssh=False),
    )
    assert plan.method is BreakMethod.UART_BREAK


def test_shared_console_with_uart_break_and_no_ssh_admits_agent_proxy_break():
    # Contract §4.1 boundary case: this MUST be admitted via agent_proxy_break.
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.SHARED_CONSOLE, ["provides_console", "supports_uart_break"]),
        platform=_platform(ssh=False),
    )
    assert plan.method is BreakMethod.AGENT_PROXY_BREAK


def test_uart_shared_console_with_uart_break_and_ssh_prefers_agent_proxy_break():
    # ADR 0018 Decision 3: on a UART shared console that supports_uart_break, the
    # line-native agent_proxy_break is preferred over the ssh sysrq_g fallback even
    # when ssh IS reachable (candidate order [agent_proxy_break, sysrq_g]). The
    # existing shared-console agent_proxy_break test uses ssh=False, so the
    # line-native-beats-ssh ordering branch was previously uncovered.
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.SHARED_CONSOLE, ["provides_console", "supports_uart_break"]),
        platform=_platform(ssh=True),
    )
    assert plan.method is BreakMethod.AGENT_PROXY_BREAK


def test_uart_shared_console_agent_proxy_disproved_falls_back_to_sysrq_g():
    # Same UART shared console + ssh, but the preferred agent_proxy_break is
    # positively disproved: selection must fall back to the next candidate, sysrq_g,
    # rather than rejecting the channel.
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.SHARED_CONSOLE, ["provides_console", "supports_uart_break"]),
        platform=_platform(ssh=True),
        disproved={BreakMethod.AGENT_PROXY_BREAK},
    )
    assert plan.method is BreakMethod.SYSRQ_G


def test_shared_console_without_uart_break_and_no_ssh_has_no_plan():
    # Contract §4.1: no predicate holds -> no_break_plan (NOT break_disproved).
    policy = ReferenceBreakPolicy()
    with pytest.raises(BreakPlanError) as excinfo:
        policy.plan(
            channel=_channel(LineRole.SHARED_CONSOLE, ["provides_console"]),
            platform=_platform(ssh=False),
        )
    assert excinfo.value.code == "no_break_plan"


def test_line_native_preferred_over_ssh_fallback():
    # dedicated_debug + uart_break AND ssh_reachable -> uart_break wins over sysrq_g.
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.DEDICATED_DEBUG, ["provides_console", "supports_uart_break"]),
        platform=_platform(ssh=True),
    )
    assert plan.method is BreakMethod.UART_BREAK


def test_disproof_falls_back_to_next_candidate():
    # gdbstub_native disproved (RSP unreachable) but ssh present -> sysrq_g.
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.RSP, ["provides_rsp"]),
        platform=_platform(ssh=True),
        disproved={BreakMethod.GDBSTUB_NATIVE},
    )
    assert plan.method is BreakMethod.SYSRQ_G


def test_every_candidate_disproved_is_break_disproved():
    # Sole candidate sysrq_g, positively disproved -> break_disproved (NOT no_break_plan).
    policy = ReferenceBreakPolicy()
    with pytest.raises(BreakPlanError) as excinfo:
        policy.plan(
            channel=_channel(LineRole.SHARED_CONSOLE, ["provides_console"]),
            platform=_platform(ssh=True),
            disproved={BreakMethod.SYSRQ_G},
        )
    assert excinfo.value.code == "break_disproved"


def test_hvc_console_with_ssh_uses_sysrq_g():
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.SHARED_CONSOLE, ["provides_console"]),
        platform=_platform(ssh=True, console=ConsoleKind.HVC),
    )
    assert plan.method is BreakMethod.SYSRQ_G


def test_hvc_shared_console_with_uart_break_still_uses_sysrq_g():
    # Contract §4.1: console_kind=hvc → sysrq_g (hvterm BREAK semantics differ from
    # UART). A UART-style agent_proxy_break must not be planned on an HVC line even when
    # the channel advertises supports_uart_break.
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.SHARED_CONSOLE, ["provides_console", "supports_uart_break"]),
        platform=_platform(ssh=True, console=ConsoleKind.HVC),
    )
    assert plan.method is BreakMethod.SYSRQ_G


def test_hvc_shared_console_without_ssh_falls_back_to_agent_proxy_break():
    # Contract §4.1 boundary: shared_console + supports_uart_break + ssh_reachable=false
    # is admissible via agent_proxy_break. On a non-UART console sysrq_g is preferred but
    # needs ssh, so with no ssh the executable agent_proxy_break path must still be taken
    # rather than rejected as no_break_plan.
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.SHARED_CONSOLE, ["provides_console", "supports_uart_break"]),
        platform=_platform(ssh=False, console=ConsoleKind.HVC),
    )
    assert plan.method is BreakMethod.AGENT_PROXY_BREAK


def test_hvc_primary_console_still_allows_dedicated_uart_debug_line():
    # console_kind describes the *primary* console; a separate dedicated_debug UART line
    # can still break even when the primary console is HVC and ssh is unavailable. The
    # console_kind gate must not leak onto the per-channel dedicated-debug predicate.
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.DEDICATED_DEBUG, ["provides_console", "supports_uart_break"]),
        platform=_platform(ssh=False, console=ConsoleKind.HVC),
    )
    assert plan.method is BreakMethod.UART_BREAK
