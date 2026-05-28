import pytest

from linux_debug_mcp.coordination.selection import (
    BreakDisproof,
    Selection,
    SelectionError,
    select_stop_capable_channel,
)
from linux_debug_mcp.seams.break_policy import ReferenceBreakPolicy
from linux_debug_mcp.seams.target import ConsoleKind, PlatformMetadata, TargetKey
from linux_debug_mcp.transport.base import BreakMethod, LineRole, TransportRef

_TK = TargetKey(provisioner="local-qemu", target_id="run-1")


def _platform(*, ssh: bool, console: ConsoleKind = ConsoleKind.UART) -> PlatformMetadata:
    return PlatformMetadata(console_kind=console, console_count=1, dedicated_debug_line=False, ssh_reachable=ssh)


def _channel(channel_id: str, role: LineRole, caps: list[str]) -> TransportRef:
    return TransportRef(provider="p", channel_id=channel_id, line_role=role, caps=caps)


def test_picks_rsp_channel_with_gdbstub_native():
    policy = ReferenceBreakPolicy()
    selection = select_stop_capable_channel(
        target_key=_TK,
        transports=(_channel("rsp-0", LineRole.RSP, ["provides_rsp"]),),
        required_caps=["provides_rsp"],
        platform=_platform(ssh=False),
        break_policy=policy,
    )
    assert isinstance(selection, Selection)
    assert selection.channel.channel_id == "rsp-0"
    assert selection.break_plan.method is BreakMethod.GDBSTUB_NATIVE


def test_skips_caps_sufficient_but_unbreakable_channel():
    # First channel satisfies caps (provides_console) but is a shared console with no
    # uart_break and no ssh -> no_break_plan; selection must skip to the breakable one.
    policy = ReferenceBreakPolicy()
    unbreakable = _channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"])
    breakable = _channel("dbg-0", LineRole.DEDICATED_DEBUG, ["provides_console", "supports_uart_break"])
    selection = select_stop_capable_channel(
        target_key=_TK,
        transports=(unbreakable, breakable),
        required_caps=["provides_console"],
        platform=_platform(ssh=False),
        break_policy=policy,
    )
    assert selection.channel.channel_id == "dbg-0"
    assert selection.break_plan.method is BreakMethod.UART_BREAK


def test_transports_order_is_authoritative():
    # Two breakable channels; the first in transports[] order wins.
    policy = ReferenceBreakPolicy()
    first = _channel("dbg-0", LineRole.DEDICATED_DEBUG, ["provides_console", "supports_uart_break"])
    second = _channel("rsp-0", LineRole.RSP, ["provides_rsp"])
    selection = select_stop_capable_channel(
        target_key=_TK,
        transports=(first, second),
        required_caps=[],
        platform=_platform(ssh=False),
        break_policy=policy,
    )
    assert selection.channel.channel_id == "dbg-0"


def test_no_channel_satisfies_caps():
    policy = ReferenceBreakPolicy()
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(_channel("rsp-0", LineRole.RSP, ["provides_rsp"]),),
            required_caps=["provides_console"],
            platform=_platform(ssh=False),
            break_policy=policy,
        )
    assert excinfo.value.code == "no_capable_channel"


def test_capable_but_no_breakable_surfaces_break_policy_code():
    # Only channel satisfies caps but has no executable break (shared console, no uart, no ssh).
    policy = ReferenceBreakPolicy()
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(_channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"]),),
            required_caps=["provides_console"],
            platform=_platform(ssh=False),
            break_policy=policy,
        )
    assert excinfo.value.code == "no_break_plan"


def test_disproved_method_falls_through_to_break_disproved():
    # Sole candidate is sysrq_g (shared console, ssh) but it is positively disproved.
    policy = ReferenceBreakPolicy()
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(_channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"]),),
            required_caps=["provides_console"],
            platform=_platform(ssh=True),
            break_policy=policy,
            disproved={BreakDisproof(_TK, BreakMethod.SYSRQ_G)},  # target-wide, no channel scope
        )
    assert excinfo.value.code == "break_disproved"


def test_break_disproved_not_downgraded_by_a_later_topology_less_channel():
    # capable channel A's only candidate is positively disproved (break_disproved); capable
    # channel B has no topology candidate (no_break_plan). The aggregate must stay
    # break_disproved, not be downgraded to no_break_plan (contract §4.8 taxonomy).
    policy = ReferenceBreakPolicy()
    rsp = _channel("rsp-0", LineRole.RSP, ["provides_rsp"])
    console = _channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"])
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(rsp, console),
            required_caps=[],
            platform=_platform(ssh=False),
            break_policy=policy,
            disproved={BreakDisproof(_TK, BreakMethod.GDBSTUB_NATIVE, provider="p", channel_id="rsp-0")},
        )
    assert excinfo.value.code == "break_disproved"


def test_break_disproved_detected_regardless_of_channel_order():
    # Same two channels, opposite order: the disproof signal must survive even when the
    # topology-less channel is evaluated last.
    policy = ReferenceBreakPolicy()
    rsp = _channel("rsp-0", LineRole.RSP, ["provides_rsp"])
    console = _channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"])
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(console, rsp),
            required_caps=[],
            platform=_platform(ssh=False),
            break_policy=policy,
            disproved={BreakDisproof(_TK, BreakMethod.GDBSTUB_NATIVE, provider="p", channel_id="rsp-0")},
        )
    assert excinfo.value.code == "break_disproved"


def test_channel_scoped_disproof_does_not_poison_other_channels():
    # Two RSP channels both offer gdbstub_native; disproving it on rsp-0 (its endpoint
    # unreachable) must NOT disqualify rsp-1, which is selected instead (§4.8 channel-scoped).
    policy = ReferenceBreakPolicy()
    rsp0 = _channel("rsp-0", LineRole.RSP, ["provides_rsp"])
    rsp1 = _channel("rsp-1", LineRole.RSP, ["provides_rsp"])
    selection = select_stop_capable_channel(
        target_key=_TK,
        transports=(rsp0, rsp1),
        required_caps=["provides_rsp"],
        platform=_platform(ssh=False),
        break_policy=policy,
        disproved={BreakDisproof(_TK, BreakMethod.GDBSTUB_NATIVE, provider="p", channel_id="rsp-0")},
    )
    assert selection.channel.channel_id == "rsp-1"
    assert selection.break_plan.method is BreakMethod.GDBSTUB_NATIVE


def test_target_wide_sysrq_disproof_applies_to_every_channel():
    # §4.8: SYSRQ_G is issued over ssh and its preconditions are target-wide. Two shared consoles
    # both have only sysrq_g as their candidate (ssh present, no uart_break). A target-wide SysRq
    # disproof recorded while evaluating con-0 MUST also prune sysrq_g on con-1, so selection
    # returns break_disproved rather than "rescuing" the target via the sibling channel.
    policy = ReferenceBreakPolicy()
    con0 = _channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"])
    con1 = _channel("con-1", LineRole.SHARED_CONSOLE, ["provides_console"])
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(con0, con1),
            required_caps=["provides_console"],
            platform=_platform(ssh=True),
            break_policy=policy,
            disproved={BreakDisproof(_TK, BreakMethod.SYSRQ_G)},  # target-wide -> prunes both channels
        )
    assert excinfo.value.code == "break_disproved"


def test_target_wide_disproof_rejects_channel_scoping():
    # A SYSRQ_G disproof must not be constructed with a channel scope — its preconditions are
    # target-wide, so accidentally scoping it would silently let a sibling channel bypass it.
    with pytest.raises(ValueError):
        BreakDisproof(_TK, BreakMethod.SYSRQ_G, provider="p", channel_id="con-0")
    # and a line-bound method must name a channel
    with pytest.raises(ValueError):
        BreakDisproof(_TK, BreakMethod.GDBSTUB_NATIVE)


def test_disproof_is_isolated_per_full_channel_identity_across_providers():
    # Two transports share channel_id "rsp-0" under different providers; disproving provider A's
    # gdbstub_native must NOT poison provider B's identically-named channel (§3.2 identity is
    # (provider, channel_id)).
    policy = ReferenceBreakPolicy()
    chan_a = TransportRef(provider="provA", channel_id="rsp-0", line_role=LineRole.RSP, caps=["provides_rsp"])
    chan_b = TransportRef(provider="provB", channel_id="rsp-0", line_role=LineRole.RSP, caps=["provides_rsp"])
    selection = select_stop_capable_channel(
        target_key=_TK,
        transports=(chan_a, chan_b),
        required_caps=["provides_rsp"],
        platform=_platform(ssh=False),
        break_policy=policy,
        disproved={BreakDisproof(_TK, BreakMethod.GDBSTUB_NATIVE, provider="provA", channel_id="rsp-0")},
    )
    assert selection.channel.provider == "provB"
    assert selection.break_plan.method is BreakMethod.GDBSTUB_NATIVE


def test_disproof_for_one_targetkey_does_not_poison_another():
    # channel_id is unique only within a target; a disproof recorded against _TK must NOT apply
    # to a different TargetKey that happens to reuse the same provider/channel_id (§3.2).
    policy = ReferenceBreakPolicy()
    other = TargetKey(provisioner="local-qemu", target_id="other")
    selection = select_stop_capable_channel(
        target_key=other,
        transports=(_channel("rsp-0", LineRole.RSP, ["provides_rsp"]),),
        required_caps=["provides_rsp"],
        platform=_platform(ssh=False),
        break_policy=policy,
        disproved={
            BreakDisproof(_TK, BreakMethod.GDBSTUB_NATIVE, provider="p", channel_id="rsp-0")
        },  # keyed to _TK, not `other`
    )
    assert selection.break_plan.method is BreakMethod.GDBSTUB_NATIVE


def test_all_topology_less_channels_yield_no_break_plan():
    # No channel has any topology candidate -> no_break_plan (nothing was disproved).
    policy = ReferenceBreakPolicy()
    a = _channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"])
    b = _channel("con-1", LineRole.SHARED_CONSOLE, ["provides_console"])
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(a, b),
            required_caps=[],
            platform=_platform(ssh=False),
            break_policy=policy,
        )
    assert excinfo.value.code == "no_break_plan"
