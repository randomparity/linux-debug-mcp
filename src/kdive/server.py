from __future__ import annotations

import contextlib
import logging
import os
import re
import shlex
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from kdive.artifacts.handlers import (
    artifacts_collect_handler,
    create_run_handler,
    get_manifest_handler,
)
from kdive.artifacts.manifest import RunManifest
from kdive.artifacts.store import ArtifactStore, record_step_with_retry
from kdive.config import (
    BootOverrides,
    BuildOverrides,
    RootfsOverrides,
    ServerConfig,
)
from kdive.coordination.admission import (
    AdmissionService,
    SnapshotStore,
)
from kdive.coordination.lease import ConsoleLeaseManager
from kdive.coordination.registry import OrphanReap, SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.bound_handlers import (
    debug_backtrace_handler,
    debug_clear_breakpoint_handler,
    debug_clear_watchpoint_handler,
    debug_continue_handler,
    debug_evaluate_handler,
    debug_finish_handler,
    debug_interrupt_handler,
    debug_list_breakpoints_handler,
    debug_list_variables_handler,
    debug_next_handler,
    debug_read_memory_handler,
    debug_read_registers_handler,
    debug_read_symbol_handler,
    debug_set_breakpoint_handler,
    debug_set_watchpoint_handler,
    debug_step_handler,
)
from kdive.debug.module_symbols import debug_load_module_symbols_handler
from kdive.debug.session_end import debug_end_session_handler
from kdive.debug.session_handlers import debug_start_session_handler
from kdive.debug.tools import DebugToolContext, DebugToolHandlers, register_debug_tools
from kdive.default_profiles import DEFAULT_BUILD_PROFILES as _DEFAULT_BUILD_PROFILES
from kdive.default_profiles import DEFAULT_DEBUG_PROFILES as _DEFAULT_DEBUG_PROFILES
from kdive.default_profiles import DEFAULT_ROOTFS_PROFILES as _DEFAULT_ROOTFS_PROFILES
from kdive.default_profiles import (
    DEFAULT_TARGET_PROFILES as _DEFAULT_TARGET_PROFILES,
)
from kdive.domain import (
    ErrorCategory,
    StepResult,
    ToolResponse,
)
from kdive.introspect.handlers import (
    debug_introspect_check_prerequisites_handler,
    debug_introspect_from_vmcore_handler,
    debug_introspect_from_vmcore_helper_handler,
    debug_introspect_helper_handler,
    debug_introspect_run_handler,
)
from kdive.introspect.tools import register_introspect_tools
from kdive.kernel import tools as kernel_tools
from kdive.kernel.handlers import kernel_build_handler
from kdive.postmortem.crash_handler import (
    debug_postmortem_crash_handler,
)
from kdive.postmortem.handlers import (
    build_scp_argv as build_scp_argv,
)
from kdive.postmortem.handlers import (
    debug_postmortem_check_prereqs_handler,
    debug_postmortem_fetch_handler,
    debug_postmortem_list_dumps_handler,
    debug_postmortem_triage_handler,
)
from kdive.postmortem.tools import register_postmortem_tools
from kdive.prereqs.handlers import prerequisites_handler
from kdive.prereqs.tools import register_prereq_tools
from kdive.providers.local.debug.gdb_mi import (
    GdbMiEngine as LocalGdbMiEngine,
)
from kdive.providers.local.debug.gdb_mi import (
    GdbMiSessionRegistry as LocalGdbMiSessionRegistry,
)
from kdive.safety.logging import SECRET_REGISTRY, configure_logging
from kdive.safety.runtime_locks import private_runtime_registry_dir
from kdive.safety.secrets import SecretReferenceKind
from kdive.seams.break_policy import ReferenceBreakPolicy
from kdive.seams.guard import (
    InProcessStopCapableGuard,
    SessionGuard,
)
from kdive.seams.lifecycle import (
    InProcessLifecycleDispatcher,
    LifecycleDispatcher,
    LifecycleEvent,
    LifecycleKind,
)
from kdive.seams.secrets import (
    EnvSecretsBackend,
    ExternalSecretsBackend,
    KeyringSecretsBackend,
    SecretsBackend,
    SecretsResolutionError,
    SecretsStore,
)
from kdive.target import tools as target_tools
from kdive.target.handlers import DEFAULT_TEST_SUITES as _DEFAULT_TEST_SUITES
from kdive.target.handlers import target_boot_handler, target_run_tests_handler
from kdive.tools.artifacts import register_artifact_tools
from kdive.tools.providers import register_provider_tools
from kdive.transport.backends.proxy import AgentProxyBackend
from kdive.transport.backends.qemu_gdbstub import QemuGdbstubTransport
from kdive.transport.core.base import (
    EndpointExposure,
    Transport,
    TransportLocality,
    TransportRegistry,
)
from kdive.transport.handlers import (
    transport_close_handler,
    transport_inject_break_handler,
    transport_open_handler,
)
from kdive.transport.tools import TransportToolContext, TransportToolHandlers, register_transport_tools
from kdive.workflow.handlers import (
    WorkflowHandlerDependencies,
    workflow_build_boot_debug_handler,
    workflow_build_boot_test_handler,
)
from kdive.workflow.tools import register_workflow_tools

logger = logging.getLogger(__name__)
DEFAULT_BUILD_PROFILES = _DEFAULT_BUILD_PROFILES
DEFAULT_DEBUG_PROFILES = _DEFAULT_DEBUG_PROFILES
DEFAULT_ROOTFS_PROFILES = _DEFAULT_ROOTFS_PROFILES
DEFAULT_TARGET_PROFILES = _DEFAULT_TARGET_PROFILES
DEFAULT_TEST_SUITES = _DEFAULT_TEST_SUITES
CreateRunContext = kernel_tools.CreateRunContext
CreateRunOptions = kernel_tools.CreateRunOptions
CreateRunProfiles = kernel_tools.CreateRunProfiles

_RequiredT = TypeVar("_RequiredT")


def _require_value(value: _RequiredT | None, message: str) -> _RequiredT:
    if value is None:
        raise RuntimeError(message)
    return value


DEFAULT_ARTIFACT_ROOT = Path(".kdive/runs")


SERVER_CONFIG_ENV_VAR = "KDIVE_CONFIG"
RUNNING_BOOT_MESSAGE = "previous boot is still recorded as running"
RUNNING_TESTS_MESSAGE = "previous test run is still recorded as running"
# debug.introspect.run stdout cap. Sized above the wrapper's 1 MiB total_json
# payload (local_drgn_introspect.py) so a legitimate run is never killed, while
# still bounding a hostile target that ignores the wrapper.
RUN_STDOUT_CAP = 2 * 1024 * 1024

# Seconds added to a caller's command timeout when bounding the outer SSH transport. The remote
# command is killed at its own deadline; this grace lets the transport observe that exit and return
# a clean result before the SSH layer itself times out.
SSH_TIMEOUT_GRACE_SECONDS = 10

__all__ = (
    "DEFAULT_ARTIFACT_ROOT",
    "DEFAULT_BUILD_PROFILES",
    "DEFAULT_DEBUG_PROFILES",
    "DEFAULT_ROOTFS_PROFILES",
    "DEFAULT_TARGET_PROFILES",
    "DEFAULT_TEST_SUITES",
    "RUN_STDOUT_CAP",
    "SERVER_CONFIG_ENV_VAR",
    "SSH_TIMEOUT_GRACE_SECONDS",
    "create_app",
    "load_server_config",
    "main",
)


_INTROSPECT_STEP_NAME_RE = re.compile(r"^introspect:")
_POSTMORTEM_CRASH_STEP_RE = re.compile(r"^postmortem\.crash:[0-9a-f]{32}$")


def _count_introspect_calls(manifest: RunManifest) -> int:
    """Spec §5.2 step 4a / R3-F5. Named so tests can monkey-patch it."""
    return sum(1 for name in manifest.step_results if _INTROSPECT_STEP_NAME_RE.match(name))


def _head_tail(s: str, *, head: int, tail: int) -> str:
    """Spec §3.2: snippet helper — head N + middle marker + tail N."""
    if len(s) <= head + tail:
        return s
    return f"{s[:head]}\n…[truncated]…\n{s[-tail:]}"


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _chmod_best_effort(path: Path, mode: int) -> None:
    """chmod that tolerates concurrent deletion (TD-15). A path removed between its enumeration
    (e.g. a ``glob``) and this call raises FileNotFoundError — the expected benign race on the
    sensitive/ tree — which is suppressed; any other OSError still propagates. Centralizing the
    TOCTOU handling here keeps the several sensitive-file tightening sites from each re-deriving it."""
    with contextlib.suppress(FileNotFoundError):
        path.chmod(mode)


def _record_terminal_introspect_result(store: ArtifactStore, run_id: str, result: StepResult) -> None:
    # Spec §5.2 step 13: every introspect:<call_id> is a fresh entry (UUIDv4) — append, never replace.
    record_step_with_retry(store, run_id, result, append=True)


def _configuration_failure(*, run_id: str, message: str, details: dict[str, Any] | None = None) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
    )


# Live and vmcore introspection handlers live in kdive.introspect.handlers/execution.


# Postmortem triage composition lives in kdive.postmortem.handlers.


# Debug operation response and persistence live in kdive.debug.operations.


def _workflow_handler_dependencies() -> WorkflowHandlerDependencies:
    return WorkflowHandlerDependencies(
        create_run_handler=create_run_handler,
        kernel_build_handler=kernel_build_handler,
        target_boot_handler=target_boot_handler,
        target_run_tests_handler=target_run_tests_handler,
        debug_start_session_handler=debug_start_session_handler,
        artifacts_collect_handler=artifacts_collect_handler,
    )


def not_implemented_handler(tool_name: str, *, run_id: str | None = None) -> ToolResponse:
    sprint_by_prefix = {
        "kernel.build": "Sprint 1",
        "target.boot": "Sprint 2",
        "target.run_tests": "Sprint 3",
        "artifacts.collect": "Sprint 3",
        "workflow.build_boot_test": "Sprint 3",
        "workflow.build_boot_debug": "Sprint 4",
        "debug.": "Sprint 4",
    }
    sprint = "a later sprint"
    for prefix, value in sprint_by_prefix.items():
        if tool_name.startswith(prefix):
            sprint = value
            break
    return ToolResponse.failure(
        category=ErrorCategory.NOT_IMPLEMENTED,
        message=f"{tool_name} is implemented in {sprint}",
        run_id=run_id,
        details={"tool": tool_name, "sprint": sprint},
        suggested_next_actions=["Use host.check_prerequisites", "Use kernel.create_run"],
    )


def _overrides_from_tool_args(
    *,
    kernel_args: list[str] | None,
    rootfs_source: str | None,
    make_variables: dict[str, str] | None,
    config_lines: list[str] | None,
    rootfs_overrides: dict[str, Any] | None = None,
) -> tuple[BuildOverrides | None, BootOverrides | None]:
    build_overrides = (
        BuildOverrides(make_variables=make_variables or {}, config_lines=config_lines or [])
        if (make_variables or config_lines)
        else None
    )
    # RootfsOverrides validation raises pydantic ValidationError (a ValueError subclass), which
    # the tool wrappers surface as a configuration error.
    rootfs = RootfsOverrides(**rootfs_overrides) if rootfs_overrides else None
    boot_overrides = (
        BootOverrides(kernel_args=kernel_args or [], rootfs_source=rootfs_source, rootfs=rootfs)
        if (kernel_args or rootfs_source or rootfs)
        else None
    )
    return build_overrides, boot_overrides


def load_server_config() -> ServerConfig | None:
    """Load the operator ServerConfig from the path in ``KDIVE_CONFIG``, if set.

    Returns ``None`` when the env var is unset or empty: no operator config is loaded and the
    built-in path-safety guards still apply. Raises ``ValueError`` with actionable context when
    the path is set but cannot be read or does not parse as a valid ``ServerConfig``.
    """
    config_path_value = os.environ.get(SERVER_CONFIG_ENV_VAR)
    if not config_path_value:
        return None
    config_path = Path(config_path_value).expanduser()
    try:
        raw = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read server config at {config_path}: {exc}") from exc
    try:
        return ServerConfig.model_validate_json(raw)
    except ValidationError as exc:
        raise ValueError(f"invalid server config at {config_path}: {exc}") from exc


@dataclass
class _TransportMachinery:
    """The Layer-4 coordination collaborators create_app threads into the transport/debug/run_tests
    tool wrappers (ADR 0005). One AdmissionService over one SnapshotStore so the boot snapshot
    producer and the transport gates share authoritative facts; one durable SessionRegistry holding
    the host-global single-instance flock + ownership records. The `lifecycle_dispatcher` is the
    shared §4.5 dispatcher bound into the transaction at construction; an out-of-band event source
    drives `admission.invalidate_lifecycle(..., dispatcher, ...)` against this instance so the
    transaction's _SessionSubscriber.force_drop() path is reachable from production."""

    session_registry: SessionRegistry
    admission: AdmissionService
    transaction: TransportTransaction
    transport_registry: TransportRegistry
    lifecycle_dispatcher: LifecycleDispatcher
    session_guard: SessionGuard


def _default_local_transports() -> dict[str, Transport]:
    """The local-only x86_64 stop-capable transport map (CLAUDE.md: local QEMU gdbstub today). The
    qemu-gdbstub RSP passthrough is the one stop-capable provider the boot snapshot advertises; the
    serial-local/agent-proxy console transport is a gated C3 integration concern."""
    qemu = QemuGdbstubTransport()
    return {qemu.capability.provider_name: qemu}


def _build_transport_registry(transports: dict[str, Transport]) -> TransportRegistry:
    registry = TransportRegistry()
    for transport in transports.values():
        registry.register(transport.capability)
    return registry


def _validate_transport_registry(registry: TransportRegistry) -> None:
    """Startup capability belt (spec §8.4): re-check every registered transport so a misconfigured
    registry fails loud before serving. TransportCapability's model validator already rejects
    REMOTE+loopback_local at construction, but a forged/corrupt registry state could bypass it; this
    re-asserts the invariant on the live registry so trusted metadata can never authorize an off-host
    raw TCP endpoint."""
    for capability in registry.list_capabilities():
        if (
            capability.locality is TransportLocality.REMOTE
            and capability.endpoint_exposure is EndpointExposure.LOOPBACK_LOCAL
        ):
            raise ValueError(
                f"transport {capability.provider_name!r} is REMOTE but advertises loopback_local "
                "endpoint exposure; remote/out-of-band transports are structurally brokered_required "
                "(§3.2, §8.4) — refusing to serve a misconfigured transport registry"
            )


def _build_transport_machinery(
    *,
    session_registry: SessionRegistry | None,
    transport_registry: TransportRegistry | None,
) -> _TransportMachinery:
    """Construct the Layer-4 machinery, acquire the single-instance flock, and run crash
    reconciliation BEFORE returning — so no tool can admit before reconcile has reaped orphan
    backends and re-asserted recovery tombstones (ADR 0005, spec §10.2).

    A default (uninjected) `session_registry` is rooted at a fresh per-process temp dir, NOT the
    host-global `private_runtime_registry_dir()`: many tests construct create_app() repeatedly in one
    process, and the production single-instance flock is host-global, so production wires the real
    registry explicitly in main(); the default stays test-safe (no cross-test flock contention).
    """
    transports = _default_local_transports()
    transport_registry = transport_registry if transport_registry is not None else _build_transport_registry(transports)
    _validate_transport_registry(transport_registry)

    snapshot_store = SnapshotStore()
    admission = AdmissionService(snapshot_store)
    # Bind the §4.5 lifecycle dispatcher so each opened session subscribes its
    # _SessionSubscriber; the reap callback below routes `LifecycleEvent`s through it so the
    # transaction's force_drop teardown (FENCED guard/lease release + backend reap + record
    # delete + handle deregistration) is reachable from production.
    lifecycle_dispatcher = InProcessLifecycleDispatcher()

    # Production lifecycle-event source: `registry.reconcile()`'s orphan-backend reap is the one
    # production point at which "the backend died" is known. The closure drives
    # `admission.invalidate_lifecycle(target_key, CRASHED)`, which runs the §4.5 chain end-to-end
    # (close_admission → dispatcher.emit → _SessionSubscriber.force_drop → guard/lease release +
    # record delete + handle deregister). Registry imports stay free of admission/lifecycle — the
    # closure's body lives here, the registry just invokes it.
    #
    # Only close admission when we actually killed a live orphan backend
    # (`close_admission_required`). For the common cold-restart case where the durable record's
    # backend was already dead (or `backend_pid is None` — qemu-gdbstub), we emit the lifecycle event
    # for any subscriber but do NOT set `_closed_at` for the target. No production code path calls
    # `reopen()`, so a `_closed_at` write would permanently brick admission for the target until
    # process restart.
    def _on_orphan_reaped(reap: OrphanReap) -> None:
        admission.invalidate_lifecycle(
            LifecycleEvent(target_key=reap.target_key, kind=LifecycleKind.CRASHED),
            lifecycle_dispatcher,
            generation=reap.record.generation,
            close_admission=reap.close_admission_required,
        )

    if session_registry is None:
        session_registry = SessionRegistry(
            directory=Path(tempfile.mkdtemp(prefix="kdive-registry-")),
            on_orphan_reaped=_on_orphan_reaped,
        )
    else:
        # An injected registry (test wiring) may not have been constructed with the callback.
        # Bind explicitly before the instance lock/reconcile lifecycle starts.
        session_registry.bind_orphan_reap_callback(_on_orphan_reaped)

    secrets_backends: dict[SecretReferenceKind, SecretsBackend] = {SecretReferenceKind.ENV: EnvSecretsBackend()}
    # keyring extra not installed -> the kind stays unavailable until configured
    with contextlib.suppress(SecretsResolutionError):
        secrets_backends[SecretReferenceKind.KEYRING] = KeyringSecretsBackend()
    _external_cmd = os.environ.get("KDIVE_SECRETS_EXTERNAL_CMD")
    if _external_cmd:
        secrets_backends[SecretReferenceKind.EXTERNAL] = ExternalSecretsBackend(command=shlex.split(_external_cmd))

    transaction = TransportTransaction(
        admission=admission,
        registry=session_registry,
        guard=InProcessStopCapableGuard(),
        leases=ConsoleLeaseManager(),
        secrets=SecretsStore(definitions=[], backends=secrets_backends, registry=SECRET_REGISTRY),
        break_policy=ReferenceBreakPolicy(),
        transports=transports,
    )
    transaction.bind_lifecycle(lifecycle_dispatcher)

    # Single-instance flock + reconcile-before-serve: acquire the host-global lock, then reap orphan
    # backends / re-assert durable tombstones BEFORE any tool can admit. acquire_instance_lock()
    # raises InstanceLockError on a 2nd live instance; it propagates out of create_app unchanged so
    # the process fails loud rather than admitting alongside the first. The fenced reaper is the
    # ADR-0004 start-time probe (AgentProxyBackend.stop_by_identity): it signals a pid ONLY when the
    # live start-time fingerprint matches the durable record, so a reused pid is never killed. The
    # lock is held for the process lifetime — create_app has no teardown hook, so this is
    # acquire-on-construct, release-on-process-exit.
    session_registry.acquire_instance_lock()
    report = session_registry.reconcile(proxy=AgentProxyBackend(), admission=admission)
    # Surface every callback failure through the project logger. `reconcile()` still deletes reaped
    # records, but a callback failure can lose the lifecycle event for those targets. Visibility
    # lets operators triage; this is not fatal because reconcile-before-serve must always proceed.
    for record, exc in report.failures:
        logger.warning(
            "transport: reconcile lifecycle callback raised for session %s (target %s): %s",
            record.session_id,
            record.target_key,
            exc,
        )
    return _TransportMachinery(
        session_registry=session_registry,
        admission=admission,
        transaction=transaction,
        transport_registry=transport_registry,
        lifecycle_dispatcher=lifecycle_dispatcher,
        # One stateless SessionGuard for the debug start/end handlers. #66 ships empty slots;
        # #69 (watchdog) and #70 (symbol version-lock) add steps/preconditions here later.
        session_guard=SessionGuard(),
    )


def create_app(
    config: ServerConfig | None = None,
    *,
    session_registry: SessionRegistry | None = None,
    transport_registry: TransportRegistry | None = None,
) -> FastMCP:
    app = FastMCP("kdive")
    # Operator-configured sensitive paths are the only ServerConfig field consumed today; they
    # are threaded into the rootfs-source validation in kernel.create_run and target.boot.
    # Profiles remain code-defined (the DEFAULT_* registries) — wiring those is separate work.
    sensitive_paths = list(config.sensitive_paths) if config is not None else []

    # Construct the Layer-4 transport machinery, acquire the single-instance flock, validate the
    # capability registry, and reconcile crashes BEFORE registering (and therefore before serving)
    # any tool — so a transport/debug/run_tests op can never admit ahead of crash recovery.
    machinery = _build_transport_machinery(
        session_registry=session_registry,
        transport_registry=transport_registry,
    )
    transport_transaction = machinery.transaction
    admission_service = machinery.admission
    durable_registry = machinery.session_registry
    session_guard = machinery.session_guard
    # The persistent gdb/MI engine (#79) and the in-process live-session registry (#81, ADR 0021).
    # The engine spawns a fresh gdb -i=mi3 per attach; the registry holds each live attachment across
    # MCP tool calls keyed by DebugSession.session_id so the per-op handlers can issue MI verbs.
    gdb_mi_engine = LocalGdbMiEngine()
    gdb_mi_sessions = LocalGdbMiSessionRegistry()
    # Stash the assembled machinery on the FastMCP instance so test-injection and any future
    # in-process lifecycle event source can reach the SAME admission/transaction/dispatcher trio
    # the tool wrappers close over (rather than constructing a parallel set that would not share
    # state with the live wrappers). Private attribute by convention; not part of the wire surface.
    # FastMCP has no slot for this; setattr makes the dynamic stash explicit so static checkers
    # do not flag a missing attribute on a third-party class we cannot extend.
    setattr(app, "_transport_machinery", machinery)  # noqa: B010

    register_prereq_tools(
        app,
        default_artifact_root=DEFAULT_ARTIFACT_ROOT,
        prerequisites_handler=prerequisites_handler,
    )

    kernel_tools.register_kernel_tools(
        app,
        default_artifact_root=DEFAULT_ARTIFACT_ROOT,
        sensitive_paths=sensitive_paths,
        create_run_handler=create_run_handler,
        kernel_build_handler=kernel_build_handler,
    )

    register_provider_tools(app)

    @app.tool(name="artifacts.get_manifest")
    def artifacts_get_manifest(run_id: str, artifact_root: str = str(DEFAULT_ARTIFACT_ROOT)) -> dict[str, Any]:
        return get_manifest_handler(artifact_root=Path(artifact_root), run_id=run_id).model_dump(mode="json")

    target_tools.register_target_tools(
        app,
        default_artifact_root=DEFAULT_ARTIFACT_ROOT,
        sensitive_paths=sensitive_paths,
        admission=admission_service,
        session_registry=durable_registry,
        target_boot_handler=target_boot_handler,
        target_run_tests_handler=target_run_tests_handler,
    )

    register_introspect_tools(
        app,
        default_artifact_root=DEFAULT_ARTIFACT_ROOT,
        admission=admission_service,
        session_registry=durable_registry,
        run_handler=debug_introspect_run_handler,
        helper_handler=debug_introspect_helper_handler,
        check_prereqs_handler=debug_introspect_check_prerequisites_handler,
        from_vmcore_handler=debug_introspect_from_vmcore_handler,
        from_vmcore_helper_handler=debug_introspect_from_vmcore_helper_handler,
    )

    register_postmortem_tools(
        app,
        default_artifact_root=DEFAULT_ARTIFACT_ROOT,
        admission=admission_service,
        session_registry=durable_registry,
        crash_handler=debug_postmortem_crash_handler,
        triage_handler=debug_postmortem_triage_handler,
        check_prereqs_handler=debug_postmortem_check_prereqs_handler,
        list_dumps_handler=debug_postmortem_list_dumps_handler,
        fetch_handler=debug_postmortem_fetch_handler,
    )

    register_artifact_tools(
        app,
        default_artifact_root=DEFAULT_ARTIFACT_ROOT,
        collect_handler=artifacts_collect_handler,
    )

    register_debug_tools(
        app,
        context=DebugToolContext(
            default_artifact_root=DEFAULT_ARTIFACT_ROOT,
            transaction=transport_transaction,
            admission=admission_service,
            session_registry=durable_registry,
            session_guard=session_guard,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ),
        handlers=DebugToolHandlers(
            start_session=debug_start_session_handler,
            read_registers=debug_read_registers_handler,
            read_symbol=debug_read_symbol_handler,
            read_memory=debug_read_memory_handler,
            evaluate=debug_evaluate_handler,
            load_module_symbols=debug_load_module_symbols_handler,
            set_breakpoint=debug_set_breakpoint_handler,
            set_watchpoint=debug_set_watchpoint_handler,
            clear_breakpoint=debug_clear_breakpoint_handler,
            clear_watchpoint=debug_clear_watchpoint_handler,
            list_breakpoints=debug_list_breakpoints_handler,
            backtrace=debug_backtrace_handler,
            list_variables=debug_list_variables_handler,
            continue_execution=debug_continue_handler,
            step=debug_step_handler,
            next=debug_next_handler,
            finish=debug_finish_handler,
            interrupt=debug_interrupt_handler,
            end_session=debug_end_session_handler,
        ),
    )

    register_transport_tools(
        app,
        context=TransportToolContext(
            default_artifact_root=DEFAULT_ARTIFACT_ROOT,
            transaction=transport_transaction,
            admission=admission_service,
            session_registry=durable_registry,
        ),
        handlers=TransportToolHandlers(
            open=transport_open_handler,
            close=transport_close_handler,
            inject_break=transport_inject_break_handler,
        ),
    )

    register_workflow_tools(
        app,
        default_artifact_root=DEFAULT_ARTIFACT_ROOT,
        admission=admission_service,
        session_registry=durable_registry,
        transaction=transport_transaction,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
        dependencies=_workflow_handler_dependencies(),
        build_boot_test_handler=workflow_build_boot_test_handler,
        build_boot_debug_handler=workflow_build_boot_debug_handler,
    )

    return app


def main() -> None:
    configure_logging()
    # Production wires the host-global durable registry explicitly so the single-instance flock +
    # crash reconciliation are host-wide (ADR 0005): a second server process fails loud on the shared
    # instance.lock. The default create_app() registry is a per-process temp dir (test-safe), so this
    # injection is the one place the real host-global path is taken.
    registry = SessionRegistry(directory=private_runtime_registry_dir())
    create_app(load_server_config(), session_registry=registry).run()
