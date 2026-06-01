from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from kdive.config import BootOverrides, DebugProfile, RootfsProfile, TargetProfile, TestSuiteProfile
from kdive.coordination.admission import AdmissionService, SnapshotStore
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.handlers import DebugRuntime
from kdive.debug.handlers import debug_backtrace_handler as _debug_backtrace_handler
from kdive.debug.handlers import debug_clear_breakpoint_handler as _debug_clear_breakpoint_handler
from kdive.debug.handlers import debug_clear_watchpoint_handler as _debug_clear_watchpoint_handler
from kdive.debug.handlers import debug_continue_handler as _debug_continue_handler
from kdive.debug.handlers import debug_evaluate_handler as _debug_evaluate_handler
from kdive.debug.handlers import debug_finish_handler as _debug_finish_handler
from kdive.debug.handlers import debug_interrupt_handler as _debug_interrupt_handler
from kdive.debug.handlers import debug_list_breakpoints_handler as _debug_list_breakpoints_handler
from kdive.debug.handlers import debug_list_variables_handler as _debug_list_variables_handler
from kdive.debug.handlers import debug_next_handler as _debug_next_handler
from kdive.debug.handlers import debug_read_memory_handler as _debug_read_memory_handler
from kdive.debug.handlers import debug_read_registers_handler as _debug_read_registers_handler
from kdive.debug.handlers import debug_read_symbol_handler as _debug_read_symbol_handler
from kdive.debug.handlers import debug_set_breakpoint_handler as _debug_set_breakpoint_handler
from kdive.debug.handlers import debug_set_watchpoint_handler as _debug_set_watchpoint_handler
from kdive.debug.handlers import debug_step_handler as _debug_step_handler
from kdive.debug.tools import (
    DebugBreakpointIdRequest,
    DebugEvaluateRequest,
    DebugExecutionRequest,
    DebugMemoryRequest,
    DebugRegistersRequest,
    DebugSessionRequest,
    DebugSymbolRequest,
)
from kdive.kernel.handlers import kernel_build_handler as _kernel_build_handler
from kdive.kernel.tools import KernelBuildHandlerRequest, KernelToolRuntime
from kdive.providers.local.build.local_kernel_build import LocalKernelBuildProvider
from kdive.providers.local.target.libvirt_qemu import LibvirtQemuProvider
from kdive.providers.local.test.local_ssh_tests import LocalSshTestProvider
from kdive.target.handlers import target_boot_handler as _target_boot_handler
from kdive.target.handlers import target_run_tests_handler as _target_run_tests_handler
from kdive.target.tools import TargetBootHandlerRequest, TargetRunTestsHandlerRequest, TargetToolRuntime
from kdive.transport.core.base import BreakPlan, TransportSession
from kdive.transport.core.break_inject import BreakRequestMethod
from kdive.transport.handlers import transport_close_handler as _transport_close_handler
from kdive.transport.handlers import transport_inject_break_handler as _transport_inject_break_handler
from kdive.transport.handlers import transport_open_handler as _transport_open_handler
from kdive.transport.tools import (
    TransportCloseHandlerRequest,
    TransportInjectBreakHandlerRequest,
    TransportOpenHandlerRequest,
    TransportToolContext,
)

BreakMechanism = Callable[[BreakRequestMethod, BreakPlan | None], None]
ProbeHalted = Callable[[TransportSession], bool]


def debug_read_registers_handler(
    *,
    artifact_root: Path,
    run_id: str,
    registers: list[str],
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
):
    return _debug_read_registers_handler(
        request=DebugRegistersRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
            registers=registers,
        ),
        runtime=runtime,
    )


def debug_read_symbol_handler(
    *,
    artifact_root: Path,
    run_id: str,
    symbol: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
):
    return _debug_read_symbol_handler(
        request=DebugSymbolRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
            symbol=symbol,
        ),
        runtime=runtime,
    )


def debug_read_memory_handler(
    *,
    artifact_root: Path,
    run_id: str,
    address: int,
    byte_count: int,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
):
    return _debug_read_memory_handler(
        request=DebugMemoryRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
            address=address,
            byte_count=byte_count,
        ),
        runtime=runtime,
    )


def debug_evaluate_handler(
    *,
    artifact_root: Path,
    run_id: str,
    inspector: str,
    runtime: DebugRuntime,
    arguments: dict[str, object] | None = None,
    debug_session_id: str | None = None,
):
    return _debug_evaluate_handler(
        request=DebugEvaluateRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
            inspector=inspector,
            arguments=arguments,
        ),
        runtime=runtime,
    )


def _debug_symbol_control_handler(handler, *, artifact_root, run_id, symbol, runtime, debug_session_id=None):
    return handler(
        request=DebugSymbolRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
            symbol=symbol,
        ),
        runtime=runtime,
    )


def debug_set_breakpoint_handler(
    *, artifact_root: Path, run_id: str, symbol: str, runtime: DebugRuntime, debug_session_id: str | None = None
):
    return _debug_symbol_control_handler(
        _debug_set_breakpoint_handler,
        artifact_root=artifact_root,
        run_id=run_id,
        symbol=symbol,
        runtime=runtime,
        debug_session_id=debug_session_id,
    )


def debug_set_watchpoint_handler(
    *, artifact_root: Path, run_id: str, symbol: str, runtime: DebugRuntime, debug_session_id: str | None = None
):
    return _debug_symbol_control_handler(
        _debug_set_watchpoint_handler,
        artifact_root=artifact_root,
        run_id=run_id,
        symbol=symbol,
        runtime=runtime,
        debug_session_id=debug_session_id,
    )


def _debug_breakpoint_id_handler(handler, *, artifact_root, run_id, breakpoint_id, runtime, debug_session_id=None):
    return handler(
        request=DebugBreakpointIdRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
            breakpoint_id=breakpoint_id,
        ),
        runtime=runtime,
    )


def debug_clear_breakpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    breakpoint_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
):
    return _debug_breakpoint_id_handler(
        _debug_clear_breakpoint_handler,
        artifact_root=artifact_root,
        run_id=run_id,
        breakpoint_id=breakpoint_id,
        runtime=runtime,
        debug_session_id=debug_session_id,
    )


def debug_clear_watchpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    breakpoint_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
):
    return _debug_breakpoint_id_handler(
        _debug_clear_watchpoint_handler,
        artifact_root=artifact_root,
        run_id=run_id,
        breakpoint_id=breakpoint_id,
        runtime=runtime,
        debug_session_id=debug_session_id,
    )


def _debug_session_query_handler(handler, *, artifact_root, run_id, runtime, debug_session_id=None):
    return handler(
        request=DebugSessionRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
        ),
        runtime=runtime,
    )


def debug_list_breakpoints_handler(
    *, artifact_root: Path, run_id: str, runtime: DebugRuntime, debug_session_id: str | None = None
):
    return _debug_session_query_handler(
        _debug_list_breakpoints_handler,
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        debug_session_id=debug_session_id,
    )


def debug_backtrace_handler(
    *, artifact_root: Path, run_id: str, runtime: DebugRuntime, debug_session_id: str | None = None
):
    return _debug_session_query_handler(
        _debug_backtrace_handler,
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        debug_session_id=debug_session_id,
    )


def debug_list_variables_handler(
    *, artifact_root: Path, run_id: str, runtime: DebugRuntime, debug_session_id: str | None = None
):
    return _debug_session_query_handler(
        _debug_list_variables_handler,
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        debug_session_id=debug_session_id,
    )


def _debug_execution_handler(
    handler,
    *,
    artifact_root,
    run_id,
    runtime,
    debug_session_id=None,
    timeout_seconds=None,
):
    return handler(
        request=DebugExecutionRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
            timeout_seconds=timeout_seconds,
        ),
        runtime=runtime,
    )


def debug_continue_handler(
    *,
    artifact_root: Path,
    run_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
    timeout_seconds: int | None = None,
):
    return _debug_execution_handler(
        _debug_continue_handler,
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        debug_session_id=debug_session_id,
        timeout_seconds=timeout_seconds,
    )


def debug_step_handler(
    *,
    artifact_root: Path,
    run_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
    timeout_seconds: int | None = None,
):
    return _debug_execution_handler(
        _debug_step_handler,
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        debug_session_id=debug_session_id,
        timeout_seconds=timeout_seconds,
    )


def debug_next_handler(
    *,
    artifact_root: Path,
    run_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
    timeout_seconds: int | None = None,
):
    return _debug_execution_handler(
        _debug_next_handler,
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        debug_session_id=debug_session_id,
        timeout_seconds=timeout_seconds,
    )


def debug_finish_handler(
    *,
    artifact_root: Path,
    run_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
    timeout_seconds: int | None = None,
):
    return _debug_execution_handler(
        _debug_finish_handler,
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        debug_session_id=debug_session_id,
        timeout_seconds=timeout_seconds,
    )


def debug_interrupt_handler(
    *,
    artifact_root: Path,
    run_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
    timeout_seconds: int | None = None,
):
    return _debug_execution_handler(
        _debug_interrupt_handler,
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        debug_session_id=debug_session_id,
        timeout_seconds=timeout_seconds,
    )


def kernel_build_handler(
    *,
    artifact_root: Path,
    run_id: str,
    build_profile: str | None = None,
    force_rebuild: bool = False,
    provider: LocalKernelBuildProvider | None = None,
):
    return _kernel_build_handler(
        request=KernelBuildHandlerRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            build_profile=build_profile,
            force_rebuild=force_rebuild,
        ),
        runtime=KernelToolRuntime(sensitive_paths=[], build_provider=provider),
    )


def target_boot_handler(
    *,
    artifact_root: Path,
    run_id: str,
    target_profile: str | None = None,
    rootfs_profile: str | None = None,
    force_reboot: bool = False,
    provider: LibvirtQemuProvider | None = None,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    default_libvirt_uri: str | None = None,
    boot_overrides: BootOverrides | None = None,
    acknowledged_permissions: list[str] | None = None,
    sensitive_paths: list[Path] | None = None,
    admission: AdmissionService | None = None,
):
    return _target_boot_handler(
        request=TargetBootHandlerRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            force_reboot=force_reboot,
            boot_overrides=boot_overrides,
            acknowledged_permissions=acknowledged_permissions,
        ),
        runtime=TargetToolRuntime(
            sensitive_paths=sensitive_paths or [],
            admission=admission,
            session_registry=None,
            boot_provider=provider,
            target_profiles=target_profiles,
            rootfs_profiles=rootfs_profiles,
            default_libvirt_uri=default_libvirt_uri,
        ),
    )


def target_run_tests_handler(
    *,
    artifact_root: Path,
    run_id: str,
    test_suite: str | None = None,
    commands: list[list[str]] | None = None,
    force_rerun: bool = False,
    attempt: int | None = None,
    acknowledged_permissions: list[str] | None = None,
    provider: LocalSshTestProvider | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    test_suites: dict[str, TestSuiteProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
):
    return _target_run_tests_handler(
        request=TargetRunTestsHandlerRequest(
            artifact_root=artifact_root,
            run_id=run_id,
            test_suite=test_suite,
            commands=commands,
            force_rerun=force_rerun,
            attempt=attempt,
            acknowledged_permissions=acknowledged_permissions,
        ),
        runtime=TargetToolRuntime(
            sensitive_paths=[],
            admission=admission,
            session_registry=session_registry,
            test_provider=provider,
            rootfs_profiles=rootfs_profiles,
            test_suites=test_suites,
        ),
    )


def _transport_runtime(
    *,
    default_artifact_root: Path,
    transaction: TransportTransaction,
    admission: AdmissionService,
    session_registry: SessionRegistry,
    debug_profiles: dict[str, DebugProfile] | None = None,
    break_mechanism: BreakMechanism | None = None,
    probe_halted: ProbeHalted | None = None,
) -> TransportToolContext:
    kwargs = {
        "default_artifact_root": default_artifact_root,
        "transaction": transaction,
        "admission": admission,
        "session_registry": session_registry,
        "debug_profiles": debug_profiles,
        "break_mechanism": break_mechanism,
    }
    if probe_halted is not None:
        kwargs["probe_halted"] = probe_halted
    return TransportToolContext(**kwargs)


def transport_open_handler(
    *,
    run_id: str,
    transaction: TransportTransaction,
    admission: AdmissionService,
    session_registry: SessionRegistry,
    recovery: bool = False,
):
    return _transport_open_handler(
        request=TransportOpenHandlerRequest(run_id=run_id, recovery=recovery),
        runtime=_transport_runtime(
            default_artifact_root=Path("."),
            transaction=transaction,
            admission=admission,
            session_registry=session_registry,
        ),
    )


def transport_close_handler(
    *,
    run_id: str,
    session_id: str,
    transaction: TransportTransaction,
    session_registry: SessionRegistry,
    admission: AdmissionService | None = None,
):
    return _transport_close_handler(
        request=TransportCloseHandlerRequest(run_id=run_id, session_id=session_id),
        runtime=_transport_runtime(
            default_artifact_root=Path("."),
            transaction=transaction,
            admission=admission or AdmissionService(SnapshotStore()),
            session_registry=session_registry,
        ),
    )


def transport_inject_break_handler(
    *,
    run_id: str,
    session_id: str,
    transaction: TransportTransaction,
    admission: AdmissionService,
    session_registry: SessionRegistry,
    acknowledged_permissions: list[str] | None = None,
    artifact_root: Path | None = None,
    break_mechanism: BreakMechanism | None = None,
    probe_halted: ProbeHalted | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
):
    return _transport_inject_break_handler(
        request=TransportInjectBreakHandlerRequest(
            run_id=run_id,
            session_id=session_id,
            acknowledged_permissions=acknowledged_permissions,
            artifact_root=artifact_root,
        ),
        runtime=_transport_runtime(
            default_artifact_root=artifact_root or Path("."),
            transaction=transaction,
            admission=admission,
            session_registry=session_registry,
            debug_profiles=debug_profiles,
            break_mechanism=break_mechanism,
            probe_halted=probe_halted,
        ),
    )
