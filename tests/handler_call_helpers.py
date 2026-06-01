from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from kdive.artifacts.contracts import CreateRunHandlerRequest, CreateRunRuntime
from kdive.artifacts.handlers import create_run_handler as _create_run_handler
from kdive.config import BootOverrides, BuildOverrides, DebugProfile, RootfsProfile, TargetProfile, TestSuiteProfile
from kdive.coordination.admission import AdmissionService, SnapshotStore
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.contracts import (
    DebugBacktraceRequest,
    DebugClearBreakpointRequest,
    DebugClearWatchpointRequest,
    DebugContinueRequest,
    DebugEvaluateRequest,
    DebugFinishRequest,
    DebugInterruptRequest,
    DebugListBreakpointsRequest,
    DebugListVariablesRequest,
    DebugNextRequest,
    DebugOperationRequest,
    DebugReadMemoryRequest,
    DebugReadRegistersRequest,
    DebugReadSymbolRequest,
    DebugRuntime,
    DebugSetBreakpointRequest,
    DebugSetWatchpointRequest,
    DebugStepRequest,
)
from kdive.debug.operations import debug_operation_response
from kdive.kernel.handlers import kernel_build_handler as _kernel_build_handler
from kdive.kernel.tools import KernelBuildHandlerRequest, KernelToolRuntime
from kdive.providers.local.build.local_kernel_build import LocalKernelBuildProvider
from kdive.providers.local.target.local_libvirt_qemu import LibvirtQemuProvider
from kdive.providers.local.test.local_ssh_tests import LocalSshTestProvider
from kdive.target.boot_handler import target_boot_handler as _target_boot_handler
from kdive.target.test_handler import target_run_tests_handler as _target_run_tests_handler
from kdive.target.tools import TargetBootHandlerRequest, TargetRunTestsHandlerRequest, TargetToolRuntime
from kdive.transport.core.base import TransportSession
from kdive.transport.handlers import transport_close_handler as _transport_close_handler
from kdive.transport.handlers import transport_inject_break_handler as _transport_inject_break_handler
from kdive.transport.handlers import transport_open_handler as _transport_open_handler
from kdive.transport.tools import (
    BreakMechanism,
    TransportCloseHandlerRequest,
    TransportInjectBreakHandlerRequest,
    TransportOpenHandlerRequest,
    TransportToolContext,
)

ProbeHalted = Callable[[TransportSession], bool]


def create_run_handler(
    *,
    artifact_root: Path,
    source_path: str,
    build_profile: str | None = None,
    target_profile: str | None = None,
    rootfs_profile: str | None = None,
    run_id: str | None = None,
    debug_profile: str | None = None,
    test_suite: str | None = None,
    build_overrides: BuildOverrides | None = None,
    boot_overrides: BootOverrides | None = None,
    sensitive_paths: list[Path] | None = None,
    build_profile_spec: dict[str, object] | None = None,
    target_profile_spec: dict[str, object] | None = None,
    rootfs_profile_spec: dict[str, object] | None = None,
):
    return _create_run_handler(
        request=CreateRunHandlerRequest(
            artifact_root=artifact_root,
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            debug_profile=debug_profile,
            test_suite=test_suite,
            build_overrides=build_overrides,
            boot_overrides=boot_overrides,
            build_profile_spec=build_profile_spec,
            target_profile_spec=target_profile_spec,
            rootfs_profile_spec=rootfs_profile_spec,
        ),
        runtime=CreateRunRuntime(sensitive_paths=sensitive_paths or []),
    )


def _debug_operation(
    *,
    artifact_root: Path,
    run_id: str,
    runtime: DebugRuntime,
    operation_request: DebugOperationRequest,
    debug_session_id: str | None = None,
):
    return debug_operation_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        request=operation_request,
        runtime=runtime,
    )


def debug_read_registers_handler(
    *,
    artifact_root: Path,
    run_id: str,
    registers: list[str],
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugReadRegistersRequest(registers=registers),
        debug_session_id=debug_session_id,
    )


def debug_read_symbol_handler(
    *,
    artifact_root: Path,
    run_id: str,
    symbol: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugReadSymbolRequest(symbol=symbol),
        debug_session_id=debug_session_id,
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
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugReadMemoryRequest(address=address, byte_count=byte_count),
        debug_session_id=debug_session_id,
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
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugEvaluateRequest(inspector=inspector, arguments=arguments or {}),
        debug_session_id=debug_session_id,
    )


def debug_set_breakpoint_handler(
    *, artifact_root: Path, run_id: str, symbol: str, runtime: DebugRuntime, debug_session_id: str | None = None
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugSetBreakpointRequest(symbol=symbol),
        debug_session_id=debug_session_id,
    )


def debug_set_watchpoint_handler(
    *, artifact_root: Path, run_id: str, symbol: str, runtime: DebugRuntime, debug_session_id: str | None = None
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugSetWatchpointRequest(symbol=symbol),
        debug_session_id=debug_session_id,
    )


def debug_clear_breakpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    breakpoint_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugClearBreakpointRequest(breakpoint_id=breakpoint_id),
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
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugClearWatchpointRequest(breakpoint_id=breakpoint_id),
        debug_session_id=debug_session_id,
    )


def debug_list_breakpoints_handler(
    *, artifact_root: Path, run_id: str, runtime: DebugRuntime, debug_session_id: str | None = None
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugListBreakpointsRequest(),
        debug_session_id=debug_session_id,
    )


def debug_backtrace_handler(
    *, artifact_root: Path, run_id: str, runtime: DebugRuntime, debug_session_id: str | None = None
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugBacktraceRequest(),
        debug_session_id=debug_session_id,
    )


def debug_list_variables_handler(
    *, artifact_root: Path, run_id: str, runtime: DebugRuntime, debug_session_id: str | None = None
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugListVariablesRequest(),
        debug_session_id=debug_session_id,
    )


def debug_continue_handler(
    *,
    artifact_root: Path,
    run_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
    timeout_seconds: int | None = None,
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugContinueRequest(timeout_seconds=timeout_seconds),
        debug_session_id=debug_session_id,
    )


def debug_step_handler(
    *,
    artifact_root: Path,
    run_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
    timeout_seconds: int | None = None,
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugStepRequest(timeout_seconds=timeout_seconds),
        debug_session_id=debug_session_id,
    )


def debug_next_handler(
    *,
    artifact_root: Path,
    run_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
    timeout_seconds: int | None = None,
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugNextRequest(timeout_seconds=timeout_seconds),
        debug_session_id=debug_session_id,
    )


def debug_finish_handler(
    *,
    artifact_root: Path,
    run_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
    timeout_seconds: int | None = None,
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugFinishRequest(timeout_seconds=timeout_seconds),
        debug_session_id=debug_session_id,
    )


def debug_interrupt_handler(
    *,
    artifact_root: Path,
    run_id: str,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
    timeout_seconds: int | None = None,
):
    return _debug_operation(
        artifact_root=artifact_root,
        run_id=run_id,
        runtime=runtime,
        operation_request=DebugInterruptRequest(timeout_seconds=timeout_seconds),
        debug_session_id=debug_session_id,
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
    if probe_halted is not None:
        return TransportToolContext(
            default_artifact_root=default_artifact_root,
            transaction=transaction,
            admission=admission,
            session_registry=session_registry,
            debug_profiles=debug_profiles,
            break_mechanism=break_mechanism,
            probe_halted=probe_halted,
        )
    return TransportToolContext(
        default_artifact_root=default_artifact_root,
        transaction=transaction,
        admission=admission,
        session_registry=session_registry,
        debug_profiles=debug_profiles,
        break_mechanism=break_mechanism,
    )


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
