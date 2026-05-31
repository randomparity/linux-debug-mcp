from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import os
import re
import shlex
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any, Protocol, TypeVar, cast

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from kdive.artifacts.handlers import (
    _redacted_artifacts,
    artifacts_collect_handler,
    create_run_handler,
    get_manifest_handler,
)
from kdive.artifacts.manifest import BootAttempt, RunManifest
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import (
    TARGET_DESTRUCTIVE_PERMISSIONS,
    BootOverrides,
    BuildOverrides,
    BuildProfile,
    DebugProfile,
    RootfsOverrides,
    RootfsProfile,
    ServerConfig,
    TargetProfile,
    TestCommand,
    TestSuiteProfile,
    merge_kernel_args,
    missing_destructive_permissions,
)
from kdive.coordination.admission import (
    AdmissionError,
    AdmissionHandle,
    AdmissionService,
    SnapshotStore,
    publish_ready_snapshot,
)
from kdive.coordination.endpoint_safety import EndpointSafetyError
from kdive.coordination.exec_probe import probe_execution_state
from kdive.coordination.lease import ConsoleLeaseManager
from kdive.coordination.registry import OrphanReap, SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.handlers import (
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
from kdive.debug.operations import (
    _break_entry_method as _break_entry_method,
)
from kdive.debug.operations import (
    _debug_operation_response,
    _debug_session_details_from_result,
    _debug_session_manifest_details,
    _enforce_debug_ownership_fence,
    _is_legacy_debug_session,
    _load_active_debug_session,
    _mark_legacy_session_recovery_required,
    _mi_session_artifacts,
    _persist_mi_debug_session,
    _preserved_debug_step_details,
    _recorded_transport_session_id,
    _resume_debug_transport,
    _teardown_debug_transport,
    _teardown_stalled_debug_session,
)
from kdive.debug.operations import (
    _engine_op_data as _engine_op_data,
)
from kdive.debug.operations import (
    _interrupt_op_data as _interrupt_op_data,
)
from kdive.debug.session_handlers import debug_start_session_handler
from kdive.debug.tools import DebugToolContext, DebugToolHandlers, register_debug_tools
from kdive.default_profiles import (
    DEFAULT_BUILD_PROFILES,
    DEFAULT_ROOTFS_PROFILES,
    DEFAULT_TARGET_PROFILES,
)
from kdive.default_profiles import DEFAULT_DEBUG_PROFILES as _DEFAULT_DEBUG_PROFILES
from kdive.domain import (
    ArtifactRef,
    DebugIntrospectCheckPrerequisitesRequest,
    ErrorCategory,
    PrerequisiteCheck,
    PrerequisiteStatus,
    StepResult,
    StepStatus,
    ToolResponse,
)
from kdive.introspect.execution import (
    _record_introspect_failure as _record_introspect_failure,
)
from kdive.introspect.execution import (
    _redact_and_truncate,
    _target_python_remote_argv,
)
from kdive.introspect.execution import (
    _rollback_introspect_admission as _rollback_introspect_admission,
)
from kdive.introspect.handlers import (
    debug_introspect_from_vmcore_handler,
    debug_introspect_from_vmcore_helper_handler,
    debug_introspect_helper_handler,
    debug_introspect_run_handler,
)
from kdive.introspect.tools import register_introspect_tools
from kdive.kernel import tools as kernel_tools
from kdive.logging import SECRET_REGISTRY, configure_logging
from kdive.model import Model
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
from kdive.prereqs.drgn_probe import (
    PROBE_SCRIPT,
    UNKNOWN,
    USABLE,
    build_probe_checks,
    python_missing_checks,
)
from kdive.prereqs.handlers import prerequisites_handler
from kdive.prereqs.kdump_probe import build_kdump_checks
from kdive.providers.debug import (
    DebugSession,
    DebugSessionState,
    GdbMiEngine,
    GdbMiError,
    GdbMiSessionRegistry,
    ProviderDebugError,
)
from kdive.providers.local.gdb_mi import (
    CANONICAL_PROBE_SYMBOL,
)
from kdive.providers.local.gdb_mi import (
    GdbMiEngine as LocalGdbMiEngine,
)
from kdive.providers.local.gdb_mi import (
    GdbMiSessionRegistry as LocalGdbMiSessionRegistry,
)
from kdive.providers.local.libvirt_qemu import LibvirtQemuProvider, ProviderBootError
from kdive.providers.local.local_kernel_build import (
    BuildIdMissing,
    LocalKernelBuildProvider,
    ReadelfUnavailable,
)
from kdive.providers.local.local_ssh_tests import (
    LocalSshTestProvider,
    TestPlan,
)
from kdive.providers.ssh import SshCommandResult, SshRunner, SubprocessSshRunner, TestExecutionResult, build_ssh_argv
from kdive.rootfs.sources import RootfsSourceError, resolve_rootfs_source
from kdive.safety.paths import (
    PathSafetyError,
    validate_rootfs_source,
    validate_source_path,
)
from kdive.safety.redaction import Redactor
from kdive.safety.runtime_locks import private_runtime_registry_dir
from kdive.safety.secrets import SecretReferenceKind
from kdive.seams.break_policy import ReferenceBreakPolicy
from kdive.seams.guard import (
    GuardConflict,
    InProcessStopCapableGuard,
    PreconditionError,
    SessionGuard,
    SessionGuardContext,
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
from kdive.seams.target import (
    BreakHint,
    ConsoleKind,
    KernelProvenance,
    PlatformMetadata,
    TargetKey,
)
from kdive.symbols.build_id import BuildIdReadError, read_elf_build_id
from kdive.symbols.verify import (
    BUILD_ID_RE,
    ProvenanceMismatch,
    verify_vmlinux_provenance,
)
from kdive.target import tools as target_tools
from kdive.tools.artifacts import register_artifact_tools
from kdive.tools.providers import register_provider_tools
from kdive.transport.base import (
    EndpointExposure,
    ExecutionState,
    LineRole,
    OpenRequest,
    Transport,
    TransportLocality,
    TransportRef,
    TransportRegistry,
    TransportSession,
)
from kdive.transport.handlers import (
    _ensure_debug_operation_enabled,
    _halt_debug_transport,
    _require_snapshot,
    _resolve_debug_profile,
    transport_close_handler,
    transport_inject_break_handler,
    transport_open_handler,
)
from kdive.transport.proxy import AgentProxyBackend
from kdive.transport.qemu_gdbstub import QemuGdbstubTransport
from kdive.transport.tools import TransportToolContext, TransportToolHandlers, register_transport_tools
from kdive.workflow.handlers import (
    WorkflowHandlerDependencies,
    workflow_build_boot_debug_handler,
    workflow_build_boot_test_handler,
)
from kdive.workflow.tools import register_workflow_tools

logger = logging.getLogger(__name__)
DEFAULT_DEBUG_PROFILES = _DEFAULT_DEBUG_PROFILES
CreateRunContext = kernel_tools.CreateRunContext
CreateRunOptions = kernel_tools.CreateRunOptions
CreateRunProfiles = kernel_tools.CreateRunProfiles
TargetBootContext = target_tools.TargetBootContext
TargetBootOptions = target_tools.TargetBootOptions
TargetBootProfiles = target_tools.TargetBootProfiles

_RequiredT = TypeVar("_RequiredT")


def _require_value(value: _RequiredT | None, message: str) -> _RequiredT:
    if value is None:
        raise RuntimeError(message)
    return value


def _require_dict(value: object, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(message)
    return cast(dict[str, Any], value)


DEFAULT_ARTIFACT_ROOT = Path(".kdive/runs")


class HostPrerequisitesContext(Model):
    artifact_root: str | None = None


class HostPrerequisitesProfiles(Model):
    build_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class HostPrerequisitesOptions(Model):
    source_path: str | None = None
    enable_libvirt_check: bool = False


class KernelBuildContext(Model):
    run_id: str
    artifact_root: str | None = None


class KernelBuildOptions(Model):
    build_profile: str | None = None
    force_rebuild: bool = False


class TargetRunContext(Model):
    run_id: str
    artifact_root: str | None = None


class TargetRunOptions(Model):
    test_suite: str | None = None
    commands: list[list[str]] | None = None
    force_rerun: bool = False
    attempt: int | None = None


SERVER_CONFIG_ENV_VAR = "KDIVE_CONFIG"
DEFAULT_TEST_SUITES = {
    "smoke-basic": TestSuiteProfile(
        name="smoke-basic",
        timeout_seconds=30,
        stop_on_failure=True,
        collect_dmesg=True,
        commands=[
            TestCommand(name="uname", argv=["uname", "-a"]),
            TestCommand(name="proc-version", argv=["test", "-r", "/proc/version"]),
            TestCommand(name="proc-cmdline", argv=["cat", "/proc/cmdline"]),
        ],
    )
}
RUNNING_BUILD_MESSAGE = (
    "previous build is still recorded as running; inspect logs and create a new run or manually clean stale build state"
)
RUNNING_BOOT_MESSAGE = "previous boot is still recorded as running"
RUNNING_TESTS_MESSAGE = "previous test run is still recorded as running"
# Spec §6/§7: bound the probe's local footprint at three layers. The streaming
# cap passed to the SSH runner (max_stdout_bytes) kills the probe the moment its
# transcript on disk exceeds the cap, so a noisy/hostile target cannot fill local
# disk within the timeout window; `_read_capped` is the post-run backstop that
# guards json.loads memory (and covers direct-write test fakes that bypass the
# streaming path); wall-clock is bounded by the remote `timeout` prefix.
PROBE_STDOUT_CAP = 256 * 1024
# debug.introspect.run stdout cap. Sized above the wrapper's 1 MiB total_json
# payload (local_drgn_introspect.py) so a legitimate run is never killed, while
# still bounding a hostile target that ignores the wrapper.
RUN_STDOUT_CAP = 2 * 1024 * 1024

# Seconds added to a caller's command timeout when bounding the outer SSH transport. The remote
# command is killed at its own deadline; this grace lets the transport observe that exit and return
# a clean result before the SSH layer itself times out.
SSH_TIMEOUT_GRACE_SECONDS = 10


def _recorded_build_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.success(
        summary=result.summary,
        run_id=run_id,
        data=Redactor().redact_value(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _running_build_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=RUNNING_BUILD_MESSAGE,
        run_id=run_id,
        details=Redactor().redact_value(result.details),
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _build_profile_from_manifest(manifest: RunManifest) -> BuildProfile:
    if manifest.resolved_build_profile is not None:
        return manifest.resolved_build_profile
    profile_name = manifest.request.build_profile
    try:
        return DEFAULT_BUILD_PROFILES[profile_name]
    except KeyError as exc:
        raise ValueError(f"unknown build profile: {profile_name}") from exc


def _record_step_with_retry(
    store: ArtifactStore,
    run_id: str,
    result: StepResult,
    *,
    append: bool = False,
    replace_succeeded: bool = False,
    attempts: int = 5,
    initial_delay_seconds: float = 0.01,
) -> None:
    """Single manifest-lock retry-with-backoff for recording a terminal step (TD-99). The build,
    introspect (``append=True`` — every ``introspect:<call_id>`` is a fresh entry, never a replace),
    and fetch (``replace_succeeded`` — a ``force`` re-fetch overwrites the SUCCEEDED step) paths all
    funnel through this one loop instead of cloning it. Only a transient "manifest is locked"
    ManifestStateError is retried; any other error (or the final attempt) propagates."""
    delay_seconds = initial_delay_seconds
    for attempt in range(attempts):
        try:
            store.record_step_result(run_id, result, append=append, replace_succeeded=replace_succeeded)
            return
        except ManifestStateError as exc:
            if "manifest is locked" not in str(exc) or attempt == attempts - 1:
                raise
            time.sleep(delay_seconds)
            delay_seconds *= 2


def _record_terminal_build_result(store: ArtifactStore, run_id: str, result: StepResult) -> None:
    _record_step_with_retry(store, run_id, result)


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
    _record_step_with_retry(store, run_id, result, append=True)


def _redacted_boot_data(data: dict[str, Any]) -> dict[str, Any]:
    return Redactor().redact_value(data)


def _boot_success_next_actions(details: dict[str, Any]) -> list[str]:
    """A frozen boot steers the agent to attach; a normal boot to the manifest."""
    if details.get("console_status") == "frozen":
        return ["debug.start_session"]
    return ["artifacts.get_manifest"]


def _recorded_boot_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.success(
        summary=result.summary,
        run_id=run_id,
        data=_redacted_boot_data(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=_boot_success_next_actions(result.details),
    )


def _recorded_test_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    redactor = Redactor()
    return ToolResponse.success(
        summary=redactor.redact_text(result.summary),
        run_id=run_id,
        data=redactor.redact_value(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.collect"],
    )


def _admit_run_tests_ssh_tier(
    *,
    run_id: str,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
) -> AdmissionHandle | None:
    """The §5.6 ssh-tier execution-state gate for target.run_tests. Returns an AdmissionHandle when
    both `admission` and `session_registry` are supplied, else None — when either is absent the gate
    is inert and the caller runs ungated (every legacy caller passes neither). Reads `generation` and
    `platform` from the authoritative snapshot the boot step published (never re-derives them), takes
    a FRESH execution-state probe, and admits the ssh tier against it. A HALTED target makes
    admit_ssh_tier raise AdmissionError(READINESS_FAILURE/target_halted); the caller maps it to a
    failure response and never writes a RUNNING step."""
    if admission is None or session_registry is None:
        return None
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = _require_snapshot(admission, target_key)
    proof = probe_execution_state(
        registry=session_registry, admission=admission, target_key=target_key, generation=snapshot.generation
    )
    if proof.state is ExecutionState.HALTED:
        # Fail-closed before admission: a HALTED kernel cannot serve an ssh test run, and admit_ssh_tier
        # only inspects the proof for a DEBUGGING-state snapshot. The probe read the authoritative
        # execution_state the stop-capable controller persisted, so a HALTED probe rejects regardless
        # of the snapshot's coarse READY/DEBUGGING state (§5.6).
        raise AdmissionError(
            "target halted in debugger; resume or detach before running tests",
            category=ErrorCategory.READINESS_FAILURE,
            code="target_halted",
        )
    return admission.admit_ssh_tier(target_key, snapshot.generation, snapshot.platform, execution_proof=proof)


def _reject_if_target_halted(
    *,
    run_id: str,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
    action: str = "probing kdump prerequisites",
) -> ToolResponse | None:
    """§5.6 rule 2 proof-only fast-reject for the read-only kdump prereq probe.

    Returns a READINESS_FAILURE/target_halted response when the target is HALTED, else
    None (proceed). Inert when admission/registry are absent (handler-test and legacy
    callers run ungated). Unlike `_admit_run_tests_ssh_tier` it does NOT promote the
    ssh tier — a bounded single-shot read-only probe only needs the immediate
    rejection; the SSH command timeout bounds the residual TOCTOU window (ADR 0028
    decision 3). May raise AdmissionError(snapshot_missing); the caller maps it to its
    carried category/code.
    """
    if admission is None or session_registry is None:
        return None
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = _require_snapshot(admission, target_key)
    proof = probe_execution_state(
        registry=session_registry, admission=admission, target_key=target_key, generation=snapshot.generation
    )
    if proof.state is ExecutionState.HALTED:
        return ToolResponse.failure(
            category=ErrorCategory.READINESS_FAILURE,
            run_id=run_id,
            message=f"target halted in debugger; resume or detach before {action}",
            details={"code": "target_halted"},
            suggested_next_actions=["debug.continue", "debug.end_session"],
        )
    return None


def _execute_tests_under_gate(
    *,
    provider: LocalSshTestProvider,
    plan: TestPlan,
    admission: AdmissionService | None,
    handle: AdmissionHandle | None,
) -> TestExecutionResult:
    """Run the ssh-tier test execution under the admission handle's cancel fence (§5.6) and dispose
    the handle. When `handle` is None the gate is inert: run ungated, no cancel. Otherwise bridge the
    handle's private halt-cancel into the runner's own Event with a TEARDOWN-BOUNDED daemon watcher
    that POLLS `wait_cancelled` and is JOINED on every exit path — a fire-and-forget unbounded
    `wait_cancelled(None)` would leak the thread and pin the completed handle on a clean run, because
    complete()/_dispose_locked() never set `_cancel`. `admission.complete(handle)` raises
    AdmissionError(execution_state_changed) when the op spanned a halt; that propagates so the caller
    terminalizes the RUNNING step to FAILED instead of recording the (invalid) execution outcome."""
    if handle is None or admission is None:
        return provider.execute_tests(plan)

    runner_cancel = threading.Event()
    watch_done = threading.Event()

    def _watch() -> None:
        # bounded poll, NOT an unbounded park: complete()/_dispose_locked() never set the handle's
        # _cancel, so wait_cancelled(None) would block forever on a clean run and leak the thread +
        # the pinned completed handle + this closure.
        while not watch_done.is_set():
            if handle.wait_cancelled(0.1):
                runner_cancel.set()
                return

    watcher = threading.Thread(target=_watch, daemon=True)
    watcher.start()
    try:
        result = provider.execute_tests(plan, cancel=runner_cancel)
        admission.complete(handle)  # may raise AdmissionError(execution_state_changed)
        return result
    finally:
        watch_done.set()  # stop the poll loop on EVERY exit path
        watcher.join(timeout=2)  # …and reap it before returning — no parked thread


def _recorded_test_failure_response(*, run_id: str, result: StepResult) -> ToolResponse:
    redactor = Redactor()
    return ToolResponse.failure(
        category=ErrorCategory.TEST_FAILURE,
        message=redactor.redact_text(result.summary),
        run_id=run_id,
        details=redactor.redact_value(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.collect"],
    )


def _running_boot_response(*, run_id: str, result: StepResult, message: str = RUNNING_BOOT_MESSAGE) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=message,
        run_id=run_id,
        details=_redacted_boot_data(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _running_tests_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=RUNNING_TESTS_MESSAGE,
        run_id=run_id,
        details=Redactor().redact_value(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _configuration_failure(*, run_id: str, message: str, details: dict[str, Any] | None = None) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
    )


@dataclass(frozen=True)
class _HandlerFailure:
    category: ErrorCategory
    message: str
    run_id: str | None = None
    details: dict[str, Any] | None = None


def _configuration_handler_failure(
    *,
    run_id: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> _HandlerFailure:
    return _HandlerFailure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
    )


def _tool_response_from_handler_failure(failure: _HandlerFailure) -> ToolResponse:
    return ToolResponse.failure(
        category=failure.category,
        message=failure.message,
        run_id=failure.run_id,
        details=failure.details,
    )


def _find_kernel_image(build_result: StepResult) -> ArtifactRef | None:
    for artifact in build_result.artifacts:
        if artifact.kind == "kernel-image":
            return artifact
    return None


def _find_artifact(result: StepResult, kind: str) -> ArtifactRef | None:
    for artifact in result.artifacts:
        if artifact.kind == kind:
            return artifact
    return None


def _artifact_run_relative_ref(artifact: ArtifactRef | None, *, run_root: Path) -> tuple[str | None, str | None]:
    """Return (run-relative ref, error-code).

    error-code is set only when a present artifact's path is not under run_root.
    """
    if artifact is None:
        return None, None
    try:
        return str(Path(artifact.path).resolve().relative_to(run_root)), None
    except ValueError:
        return None, "artifact_path_unexpected"


def _capture_kernel_provenance(
    *,
    build_step: StepResult | None,
    boot_details: dict[str, Any],
    run_dir: Path,
) -> dict[str, Any]:
    """Synthesize a KernelProvenance from the build + boot records (design §3).

    Returns one of:
      - ``{"kernel_provenance": <model_dump>, ["kernel_provenance_capture_notes": [...]]}``
      - ``{"kernel_provenance_capture_error": {"code": ..., "message": ...}}``
    Never raises; a missing required field is a typed capture error so an
    otherwise-good boot still SUCCEEDS.
    """
    if build_step is None:
        return {
            "kernel_provenance_capture_error": {"code": "build_id_unavailable", "message": "no build step recorded"}
        }
    build_id = build_step.details.get("build_id")
    if not isinstance(build_id, str):
        return {
            "kernel_provenance_capture_error": {"code": "build_id_unavailable", "message": "build recorded no build_id"}
        }
    release = build_step.details.get("kernel_release")
    if not isinstance(release, str):
        return {
            "kernel_provenance_capture_error": {
                "code": "release_unavailable",
                "message": "build recorded no kernel_release",
            }
        }

    run_root = run_dir.resolve()
    notes: list[str] = []
    config_artifact = _find_artifact(build_step, "kernel-config")
    config_ref, config_err = _artifact_run_relative_ref(config_artifact, run_root=run_root)
    if config_err is not None:
        return {
            "kernel_provenance_capture_error": {
                "code": config_err,
                "message": "kernel-config artifact is outside the run directory",
            }
        }
    if config_artifact is None:
        notes.append("config_artifact_missing")

    vmlinux_artifact = _find_artifact(build_step, "vmlinux")
    if vmlinux_artifact is not None:
        vmlinux_ref, vmlinux_err = _artifact_run_relative_ref(vmlinux_artifact, run_root=run_root)
        if vmlinux_err is not None:
            return {
                "kernel_provenance_capture_error": {
                    "code": vmlinux_err,
                    "message": "vmlinux artifact is outside the run directory",
                }
            }
    else:
        vmlinux_ref = "build/vmlinux"
        notes.append("vmlinux_artifact_missing")

    kernel_args = boot_details.get("kernel_args")
    cmdline = " ".join(kernel_args) if isinstance(kernel_args, list) else ""

    provenance = KernelProvenance(
        build_id=build_id,
        release=release,
        vmlinux_ref=vmlinux_ref or "build/vmlinux",
        modules_ref=None,
        cmdline=cmdline,
        config_ref=config_ref,
    )
    result: dict[str, Any] = {"kernel_provenance": provenance.model_dump(mode="json")}
    if notes:
        result["kernel_provenance_capture_notes"] = notes
    return result


def _next_test_attempt(run_dir: Path) -> int:
    attempts = []
    tests_dir = run_dir / "tests"
    if tests_dir.exists():
        for path in tests_dir.glob("attempt-*"):
            try:
                attempts.append(int(path.name.removeprefix("attempt-")))
            except ValueError:
                continue
    return max(attempts, default=0) + 1


def _validate_adhoc_commands(commands: list[list[str]] | None) -> list[TestCommand]:
    validated: list[TestCommand] = []
    for index, argv in enumerate(commands or [], start=1):
        validated.append(TestCommand(name=f"adhoc-{index:03d}", argv=argv, required=True))
    return validated


def _select_boot_attempt(boot_attempts: list[BootAttempt], attempt: int | None) -> BootAttempt:
    """Return the boot attempt tests should bind to (default: the latest recorded attempt).

    Raises ValueError if an explicitly requested attempt does not exist or did not succeed.
    """
    if attempt is None:
        return boot_attempts[-1]
    selected = next((record for record in boot_attempts if record.attempt == attempt), None)
    if selected is None:
        available = sorted(record.attempt for record in boot_attempts)
        raise ValueError(f"boot attempt {attempt} not found; recorded attempts: {available}")
    if selected.status != StepStatus.SUCCEEDED:
        raise ValueError(f"boot attempt {attempt} did not succeed (status: {selected.status})")
    return selected


def kernel_build_handler(
    *,
    artifact_root: Path,
    run_id: str,
    build_profile: str | None = None,
    force_rebuild: bool = False,
    provider: LocalKernelBuildProvider | None = None,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                message=f"run not found: {run_id}",
                run_id=run_id,
            )
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    if force_rebuild:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="force_rebuild=true is not supported until rebuild cleanup policy is implemented",
            run_id=run_id,
        )
    requested_profile = build_profile or manifest.request.build_profile
    if requested_profile != manifest.request.build_profile:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="build_profile must match the immutable run manifest request",
            run_id=run_id,
            details={"requested_profile": requested_profile, "manifest_profile": manifest.request.build_profile},
        )
    existing = manifest.step_results.get("build")
    if existing and existing.status == StepStatus.SUCCEEDED:
        return _recorded_build_success_response(run_id=run_id, result=existing)
    if existing and existing.status == StepStatus.RUNNING:
        try:
            with store.build_lock(run_id):
                return _running_build_response(run_id=run_id, result=existing)
        except ManifestStateError as exc:
            return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    try:
        source_path = validate_source_path(Path(manifest.request.source_path))
        store = ArtifactStore(artifact_root, source_paths=[source_path], create_root=False)
        profile = _build_profile_from_manifest(manifest)
        provider = provider or LocalKernelBuildProvider()
        run_dir = store.run_dir(run_id)
        plan = provider.plan_build(source_path=source_path, output_path=run_dir / "build", profile=profile)
    except (PathSafetyError, ValueError, ManifestStateError) as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
            run_id=run_id,
        )
    log_path = store.run_dir(run_id) / "logs" / "build.log"
    summary_path = store.run_dir(run_id) / "summaries" / "build-summary.json"
    try:
        with store.build_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("build")
            if existing and existing.status == StepStatus.SUCCEEDED:
                return _recorded_build_success_response(run_id=run_id, result=existing)
            if existing and existing.status == StepStatus.RUNNING:
                return _running_build_response(run_id=run_id, result=existing)
            running = StepResult(
                step_name="build",
                status=StepStatus.RUNNING,
                summary="kernel build running",
                details={"argv": plan.argv, "log_path": str(log_path), "provider": provider.name},
                artifacts=[ArtifactRef(path=str(log_path), kind="build-log")],
            )
            store.record_step_result(run_id, running)
            try:
                execution = provider.execute_build(plan=plan, log_path=log_path, summary_path=summary_path)
            except ReadelfUnavailable as exc:
                # exc.artifacts carries the build artifacts the provider already produced
                # (vmlinux, .config, build-log). Persist them in the FAILED StepResult so
                # operators can inspect why readelf came up empty without re-running the build.
                failed = StepResult(
                    step_name="build",
                    status=StepStatus.FAILED,
                    summary="readelf unavailable while extracting build_id",
                    artifacts=exc.artifacts,
                    details={"code": "readelf_unavailable", "error": str(exc), "provider": provider.name},
                )
                _record_terminal_build_result(store, run_id, failed)
                return ToolResponse.failure(
                    category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                    message=(
                        "readelf unavailable while extracting build_id; "
                        "the recorded FAILED build step retains vmlinux and the build log "
                        "for forensic inspection"
                    ),
                    run_id=run_id,
                    details={"code": "readelf_unavailable"},
                    artifacts=exc.artifacts,
                    suggested_next_actions=["artifacts.get_manifest"],
                )
            except BuildIdMissing as exc:
                # Same artifact-preservation rationale as ReadelfUnavailable above.
                failed = StepResult(
                    step_name="build",
                    status=StepStatus.FAILED,
                    summary="vmlinux has no .note.gnu.build-id",
                    artifacts=exc.artifacts,
                    details={"code": "build_id_missing", "error": str(exc), "provider": provider.name},
                )
                _record_terminal_build_result(store, run_id, failed)
                return ToolResponse.failure(
                    category=ErrorCategory.BUILD_FAILURE,
                    message=(
                        "vmlinux has no .note.gnu.build-id; rebuild with LD_BUILD_ID=sha1 "
                        "or equivalent (spec §7). The FAILED build step retains vmlinux "
                        "and the build log so the failure can be diagnosed without "
                        "re-running the build."
                    ),
                    run_id=run_id,
                    details={"code": "build_id_missing"},
                    artifacts=exc.artifacts,
                    suggested_next_actions=["artifacts.get_manifest"],
                )
            except Exception as exc:
                result = StepResult(
                    step_name="build",
                    status=StepStatus.FAILED,
                    summary="unexpected build provider failure",
                    artifacts=[ArtifactRef(path=str(log_path), kind="build-log")],
                    details={
                        "argv": plan.argv,
                        "log_path": str(log_path),
                        "provider": provider.name,
                        "exception_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )
                _record_terminal_build_result(store, run_id, result)
                return ToolResponse.failure(
                    category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                    message=result.summary,
                    run_id=run_id,
                    details=Redactor().redact_value(result.details),
                    artifacts=result.artifacts,
                    suggested_next_actions=["artifacts.get_manifest"],
                )
            result = StepResult(
                step_name="build",
                status=execution.status,
                summary=execution.summary,
                artifacts=execution.artifacts,
                details=execution.details,
            )
            _record_terminal_build_result(store, run_id, result)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    if execution.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=execution.summary,
            run_id=run_id,
            data=Redactor().redact_value(execution.details),
            artifacts=execution.artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    return ToolResponse.failure(
        category=execution.error_category or ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=execution.summary,
        run_id=run_id,
        details=Redactor().redact_value({**execution.details, "diagnostic": execution.diagnostic}),
        artifacts=execution.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _short_circuit_boot_success(
    *,
    run_id: str,
    result: StepResult,
    admission: AdmissionService | None,
    manifest: RunManifest,
    rootfs_profile: RootfsProfile,
) -> ToolResponse:
    """Republish the boot READY snapshot before returning the recorded-SUCCEEDED short-circuit.

    A long-lived server boots a target, then restarts: `AdmissionService._store` is empty (the
    in-memory snapshot doesn't survive the process). Re-invoking `target.boot` short-circuits on
    the recorded SUCCEEDED step and returns immediately. Without this helper, the snapshot stays
    empty and the next `target.run_tests` / `debug.start_session` fails at `_require_snapshot`.

    Republishing the same `TargetSnapshot` to the same `TargetKey` is idempotent on
    `SnapshotStore` (`put()` enforces non-regression but accepts equal-generation writes), so two
    consecutive short-circuit calls in one process leave the store unchanged after the second.
    `admission is None` (defensive — matches the optional-deps style elsewhere) is a no-op.
    """
    if admission is not None:
        details = result.details if isinstance(result.details, dict) else {}
        gdbstub_endpoint = details.get("gdbstub_endpoint") if isinstance(details, dict) else None
        if gdbstub_endpoint is not None and not isinstance(gdbstub_endpoint, dict):
            gdbstub_endpoint = None  # malformed recorded value → publish without gdbstub
        # The generation passed to _publish_boot_ready_snapshot at first-boot time is the boot
        # `attempt` counter (see execute_boot). For a short-circuit, the SUCCEEDED step
        # corresponds to the last recorded boot_attempts entry — the same attempt number that
        # produced the recorded snapshot, so the republish carries an IDENTICAL generation.
        attempt = manifest.boot_attempts[-1].attempt if manifest.boot_attempts else 1
        _publish_boot_ready_snapshot(
            admission,
            run_id=run_id,
            generation=attempt,
            gdbstub_endpoint=gdbstub_endpoint,
            rootfs_profile=rootfs_profile,
        )
    return _recorded_boot_success_response(run_id=run_id, result=result)


def _publish_boot_ready_snapshot(
    admission: AdmissionService,
    *,
    run_id: str,
    generation: int,
    gdbstub_endpoint: dict[str, Any] | None,
    rootfs_profile: RootfsProfile,
) -> None:
    """Publish the authoritative READY TargetSnapshot for a local-qemu boot (ADR 0007).

    No provisioner exists on the local path, so the boot step is the snapshot producer: it mints
    the RSP TransportRef from the recorded gdbstub endpoint (so admission can re-bind transport.open
    requests) and the platform facts admission re-binds against. `generation` is the boot attempt
    number, so a reboot bumps it and invalidates handles minted against the prior incarnation.
    """
    transports: list[TransportRef] = []
    if gdbstub_endpoint is not None:
        transports.append(
            TransportRef(
                provider="qemu-gdbstub",
                channel_id="rsp0",
                line_role=LineRole.RSP,
                caps=("rsp",),
                target_ref=gdbstub_endpoint,
            )
        )
    platform = PlatformMetadata(
        console_kind=ConsoleKind.UART,
        console_count=1,
        dedicated_debug_line=False,
        ssh_reachable=rootfs_profile.ssh_host is not None,
        break_hints=[BreakHint.GDBSTUB_NATIVE],
    )
    publish_ready_snapshot(
        admission,
        target_key=TargetKey(provisioner="local-qemu", target_id=run_id),
        generation=generation,
        transports=transports,
        platform=platform,
    )


def _finalize_boot_execution(
    execution: Any,
    *,
    store: ArtifactStore,
    run_id: str,
    attempt: int,
    manifest: RunManifest,
    kernel_image: ArtifactRef,
    resolved_target_profile: TargetProfile,
    resolved_rootfs_profile: RootfsProfile,
    admission: AdmissionService | None,
    plan_gdbstub_endpoint: dict[str, Any] | None,
) -> ToolResponse:
    """Record the terminal boot step + BootAttempt, capture kernel provenance on success, publish
    the READY snapshot, and map the execution outcome to a ToolResponse (TD-102)."""
    terminal_details: dict[str, Any] = {**execution.details, "kernel_image_path": str(kernel_image.path)}
    if execution.status == StepStatus.SUCCEEDED:
        try:
            terminal_details.update(
                _capture_kernel_provenance(
                    build_step=manifest.step_results.get("build"),
                    boot_details=execution.details,
                    run_dir=store.run_dir(run_id),
                )
            )
        except Exception as capture_exc:  # provenance capture must never fail an otherwise-good boot
            # Broad catch is deliberate (a good boot must not be lost to a
            # capture defect) but must NOT be silent: log with traceback so a
            # masked programming bug is observable, then record a typed error.
            logger.warning("kernel provenance capture failed: %s", capture_exc, exc_info=True)
            terminal_details["kernel_provenance_capture_error"] = {
                "code": "capture_unexpected_error",
                "message": f"{type(capture_exc).__name__}: {capture_exc}",
            }
    terminal = StepResult(
        step_name="boot",
        status=execution.status,
        summary=execution.summary,
        artifacts=execution.artifacts,
        details=terminal_details,
    )
    attempt_record = BootAttempt(
        attempt=attempt,
        resolved_target_profile=resolved_target_profile,
        resolved_rootfs_profile=resolved_rootfs_profile,
        status=execution.status,
    )
    store.record_boot_attempt(run_id, attempt=attempt_record, boot_result=terminal)
    if execution.status == StepStatus.SUCCEEDED and admission is not None:
        _publish_boot_ready_snapshot(
            admission,
            run_id=run_id,
            generation=attempt,
            gdbstub_endpoint=plan_gdbstub_endpoint,
            rootfs_profile=resolved_rootfs_profile,
        )
    if execution.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=execution.summary,
            run_id=run_id,
            data=_redacted_boot_data(terminal.details),
            artifacts=execution.artifacts,
            suggested_next_actions=_boot_success_next_actions(terminal.details),
        )
    return ToolResponse.failure(
        category=execution.error_category or ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=execution.summary,
        run_id=run_id,
        details=_redacted_boot_data({**execution.details, "diagnostic": execution.diagnostic}),
        artifacts=execution.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _record_boot_attempt_failure(
    *,
    store: ArtifactStore,
    run_id: str,
    attempt_record: BootAttempt,
    failed: StepResult,
    category: ErrorCategory,
) -> ToolResponse:
    """Record a FAILED BootAttempt + terminal boot step and return the matching ToolResponse — the
    shared tail of _execute_boot_attempt's provider-error and unexpected-error arms (TD-102)."""
    store.record_boot_attempt(run_id, attempt=attempt_record, boot_result=failed)
    return ToolResponse.failure(
        category=category,
        message=failed.summary,
        run_id=run_id,
        details=_redacted_boot_data(failed.details),
        artifacts=failed.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _execute_boot_attempt(
    *,
    plan: Any,
    retrying_after_failure: bool,
    replace_succeeded: bool,
    attempt: int,
    manifest: RunManifest,
    provider: LibvirtQemuProvider,
    store: ArtifactStore,
    run_id: str,
    resolved_target_profile: TargetProfile,
    resolved_rootfs_profile: RootfsProfile,
    kernel_image: ArtifactRef,
    force_reboot: bool,
    admission: AdmissionService | None,
) -> ToolResponse:
    """Run one boot attempt: write the RUNNING step, execute the provider, capture provenance on
    success, record the BootAttempt + terminal step, publish the READY snapshot, and map the
    outcome to a ToolResponse. Extracted from target_boot_handler (TD-102)."""

    def _failed_attempt_record() -> BootAttempt:
        return BootAttempt(
            attempt=attempt,
            resolved_target_profile=resolved_target_profile,
            resolved_rootfs_profile=resolved_rootfs_profile,
            status=StepStatus.FAILED,
        )

    plan_gdbstub_endpoint = getattr(plan, "gdbstub_endpoint", None)
    if plan_gdbstub_endpoint is not None and hasattr(plan_gdbstub_endpoint, "as_dict"):
        plan_gdbstub_endpoint = plan_gdbstub_endpoint.as_dict()
    running = StepResult(
        step_name="boot",
        status=StepStatus.RUNNING,
        summary="target boot running",
        details={
            "provider": provider.name,
            "domain": plan.domain_name,
            "target_profile": resolved_target_profile.name,
            "rootfs_profile": resolved_rootfs_profile.name,
            "kernel_image_path": str(kernel_image.path),
            "boot_log_path": str(plan.boot_log_path),
            "boot_plan_path": str(plan.boot_plan_path),
            "debug_boot": getattr(plan, "debug_gdbstub", False),
            "gdbstub_endpoint": plan_gdbstub_endpoint,
            "nokaslr_source": getattr(plan, "nokaslr_source", "not_applicable"),
        },
        artifacts=[ArtifactRef(path=str(plan.boot_log_path), kind="boot-log")],
    )
    store.record_step_result(run_id, running, replace_succeeded=replace_succeeded)
    try:
        execution = provider.execute_boot(
            plan,
            force_reboot=force_reboot,
            retrying_after_failure=retrying_after_failure,
        )
    except ProviderBootError as exc:
        failed = StepResult(
            step_name="boot", status=StepStatus.FAILED, summary=str(exc), artifacts=exc.artifacts, details=exc.details
        )
        return _record_boot_attempt_failure(
            store=store, run_id=run_id, attempt_record=_failed_attempt_record(), failed=failed, category=exc.category
        )
    except Exception as exc:
        failed = StepResult(
            step_name="boot",
            status=StepStatus.FAILED,
            summary="unexpected boot provider failure",
            artifacts=[ArtifactRef(path=str(plan.boot_log_path), kind="boot-log")],
            details={
                "provider": provider.name,
                "domain": plan.domain_name,
                "exception_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        return _record_boot_attempt_failure(
            store=store,
            run_id=run_id,
            attempt_record=_failed_attempt_record(),
            failed=failed,
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        )
    return _finalize_boot_execution(
        execution,
        store=store,
        run_id=run_id,
        attempt=attempt,
        manifest=manifest,
        kernel_image=kernel_image,
        resolved_target_profile=resolved_target_profile,
        resolved_rootfs_profile=resolved_rootfs_profile,
        admission=admission,
        plan_gdbstub_endpoint=plan_gdbstub_endpoint,
    )


def _assert_profile_matches_manifest(
    *, kind: str, requested: str | None, manifest_value: str | None, run_id: str
) -> _HandlerFailure | None:
    """The {target,rootfs}_profile passed to a step must equal the immutable manifest request
    (manifest invariant / TD-102). Returns a CONFIGURATION_ERROR on mismatch, else None."""
    if requested == manifest_value:
        return None
    return _configuration_handler_failure(
        run_id=run_id,
        message=f"{kind}_profile must match the immutable run manifest request",
        details={"requested_profile": requested, "manifest_profile": manifest_value},
    )


def _apply_boot_overrides(
    *,
    resolved_target_profile: TargetProfile,
    resolved_rootfs_profile: RootfsProfile,
    overrides: BootOverrides,
    manifest: RunManifest,
    sensitive_paths: list[Path] | None,
    run_id: str,
) -> tuple[TargetProfile, RootfsProfile] | _HandlerFailure:
    """Merge a BootOverrides into the resolved target/rootfs profiles (TD-102): kernel_args are
    merged, wait_for_debugger is replaced, and the rootfs source/fields are validated and copied in.
    Returns the updated ``(target, rootfs)`` pair, or a CONFIGURATION_ERROR ToolResponse if a rootfs
    source fails path-safety validation."""
    try:
        if overrides.kernel_args:
            resolved_target_profile = resolved_target_profile.model_copy(
                update={"kernel_args": merge_kernel_args(resolved_target_profile.kernel_args, overrides.kernel_args)}
            )
        if overrides.wait_for_debugger is not None:
            resolved_target_profile = resolved_target_profile.model_copy(
                update={"wait_for_debugger": overrides.wait_for_debugger}
            )
        rootfs_update: dict[str, object] = {}
        if overrides.rootfs_source is not None:
            validated = validate_rootfs_source(
                Path(overrides.rootfs_source),
                source_paths=[Path(manifest.request.source_path)],
                # Operator-configured sensitive paths threaded in by create_app (empty when no
                # ServerConfig is loaded); the built-in guards always apply.
                sensitive_paths=sensitive_paths or [],
            )
            rootfs_update["source"] = str(validated)
        if overrides.rootfs is not None:
            # Each override field was validated at BootOverrides construction; RootfsProfile has no
            # cross-field validators, so model_copy yields a valid profile.
            rootfs_update.update(overrides.rootfs.as_profile_update())
        if rootfs_update:
            resolved_rootfs_profile = resolved_rootfs_profile.model_copy(update=rootfs_update)
    except (PathSafetyError, ValueError) as exc:
        return _configuration_handler_failure(run_id=run_id, message=str(exc))
    return resolved_target_profile, resolved_rootfs_profile


@dataclass(frozen=True)
class _ResolvedBootInputs:
    """The profile/kernel inputs target_boot_handler resolves before taking the boot locks."""

    resolved_target_profile: TargetProfile
    resolved_rootfs_profile: RootfsProfile
    target_ref: str
    kernel_image: ArtifactRef


def _resolve_boot_inputs(
    *,
    manifest: RunManifest,
    run_id: str,
    target_profile: str | None,
    rootfs_profile: str | None,
    target_profiles: dict[str, TargetProfile] | None,
    rootfs_profiles: dict[str, RootfsProfile] | None,
    default_libvirt_uri: str | None,
    boot_overrides: BootOverrides | None,
    sensitive_paths: list[Path] | None,
) -> _ResolvedBootInputs | _HandlerFailure:
    """Resolve and validate the boot inputs (TD-102): the requested profiles must match the
    immutable manifest request; named profiles resolve from the registry (inline ones come frozen
    off the manifest); boot_overrides are merged into the resolved profiles; and the build must
    have succeeded with a kernel-image artifact of the matching architecture. Returns the resolved
    inputs, or a CONFIGURATION_ERROR ToolResponse on the first failed check."""
    requested_target_profile = target_profile or manifest.request.target_profile
    requested_rootfs_profile = rootfs_profile or manifest.request.rootfs_profile
    for kind, requested, manifest_value in (
        ("target", requested_target_profile, manifest.request.target_profile),
        ("rootfs", requested_rootfs_profile, manifest.request.rootfs_profile),
    ):
        mismatch = _assert_profile_matches_manifest(
            kind=kind, requested=requested, manifest_value=manifest_value, run_id=run_id
        )
        if mismatch is not None:
            return mismatch

    target_profiles = target_profiles if target_profiles is not None else DEFAULT_TARGET_PROFILES
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    # Inline profiles (no named registry entry) were frozen into the manifest at create time;
    # prefer them. Named profiles are resolved by name from the registry as before.
    if manifest.resolved_target_profile is not None:
        resolved_target_profile = manifest.resolved_target_profile
    else:
        try:
            resolved_target_profile = target_profiles[requested_target_profile]
        except KeyError:
            return _configuration_handler_failure(
                run_id=run_id, message=f"unknown target profile: {requested_target_profile}"
            )
    if manifest.resolved_rootfs_profile is not None:
        resolved_rootfs_profile = manifest.resolved_rootfs_profile
    else:
        try:
            resolved_rootfs_profile = rootfs_profiles[requested_rootfs_profile]
        except KeyError:
            return _configuration_handler_failure(
                run_id=run_id, message=f"unknown rootfs profile: {requested_rootfs_profile}"
            )
    if resolved_target_profile.libvirt_uri is None and default_libvirt_uri is not None:
        resolved_target_profile = resolved_target_profile.model_copy(update={"libvirt_uri": default_libvirt_uri})
    if resolved_target_profile.target_ref is None:
        return _configuration_handler_failure(run_id=run_id, message="target profile target_ref is required")
    target_ref = resolved_target_profile.target_ref

    effective_boot_overrides = boot_overrides
    if effective_boot_overrides is None and not manifest.boot_attempts:
        effective_boot_overrides = manifest.request.boot_overrides
    if effective_boot_overrides is not None:
        merged = _apply_boot_overrides(
            resolved_target_profile=resolved_target_profile,
            resolved_rootfs_profile=resolved_rootfs_profile,
            overrides=effective_boot_overrides,
            manifest=manifest,
            sensitive_paths=sensitive_paths,
            run_id=run_id,
        )
        if isinstance(merged, _HandlerFailure):
            return merged
        resolved_target_profile, resolved_rootfs_profile = merged

    build_result = manifest.step_results.get("build")
    if build_result is None or build_result.status != StepStatus.SUCCEEDED:
        return _configuration_handler_failure(run_id=run_id, message="target boot requires a succeeded build")
    kernel_image = _find_kernel_image(build_result)
    if kernel_image is None:
        return _configuration_handler_failure(
            run_id=run_id, message="succeeded build did not record a kernel-image artifact"
        )
    build_architecture = build_result.details.get("architecture")
    if build_architecture is not None and build_architecture != resolved_target_profile.architecture:
        return _configuration_handler_failure(
            run_id=run_id,
            message="build architecture does not match target profile architecture",
            details={
                "build_architecture": build_architecture,
                "target_architecture": resolved_target_profile.architecture,
            },
        )

    return _ResolvedBootInputs(
        resolved_target_profile=resolved_target_profile,
        resolved_rootfs_profile=resolved_rootfs_profile,
        target_ref=target_ref,
        kernel_image=kernel_image,
    )


def _plan_boot_or_failure(
    *,
    provider: LibvirtQemuProvider,
    store: ArtifactStore,
    run_id: str,
    kernel_image: ArtifactRef,
    resolved_target_profile: TargetProfile,
    resolved_rootfs_profile: RootfsProfile,
    next_attempt: int,
    replace_succeeded: bool,
    force_reboot: bool,
) -> Any:
    """Resolve the rootfs source and plan the boot under the target lock (TD-102), recording a
    FAILED step + returning a ToolResponse on a rootfs/provider/manifest error. Returns the boot
    plan on success (the caller runs the attempt)."""
    try:
        resolve_rootfs_source(resolved_rootfs_profile)
        plan = provider.plan_boot(
            run_id=run_id,
            run_dir=store.run_dir(run_id),
            kernel_image_path=Path(kernel_image.path),
            target_profile=resolved_target_profile,
            rootfs_profile=resolved_rootfs_profile,
            attempt=next_attempt,
        )
    except RootfsSourceError as exc:
        fix_details = {"suggested_fix": exc.suggested_fix} if exc.suggested_fix else {}
        failed = StepResult(
            step_name="boot",
            status=StepStatus.FAILED,
            summary=str(exc),
            details=fix_details,
        )
        store.record_step_result(run_id, failed, replace_succeeded=replace_succeeded or force_reboot)
        return ToolResponse.failure(
            category=exc.category,
            message=str(exc),
            run_id=run_id,
            details=fix_details,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    except ProviderBootError as exc:
        failed = StepResult(
            step_name="boot",
            status=StepStatus.FAILED,
            summary=str(exc),
            artifacts=exc.artifacts,
            details=exc.details,
        )
        store.record_step_result(run_id, failed, replace_succeeded=replace_succeeded or force_reboot)
        return ToolResponse.failure(
            category=exc.category,
            message=str(exc),
            run_id=run_id,
            details=_redacted_boot_data(exc.details),
            artifacts=exc.artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    except (ManifestStateError, OSError, ValueError) as exc:
        return _configuration_failure(run_id=run_id, message=str(exc))
    return plan


def _boot_under_locks(
    *,
    store: ArtifactStore,
    run_id: str,
    target_ref: str,
    resolved_target_profile: TargetProfile,
    resolved_rootfs_profile: RootfsProfile,
    kernel_image: ArtifactRef,
    force_reboot: bool,
    has_new_boot_overrides: bool,
    existing: StepResult | None,
    provider: LibvirtQemuProvider,
    admission: AdmissionService | None,
) -> ToolResponse:
    """Take boot_lock then target_lock, re-check the SUCCEEDED short-circuit under the lock,
    recover a stale RUNNING step, plan the boot, and run the attempt (TD-102). A concurrent
    holder surfaces as a RUNNING response via the boot-locked ManifestStateError arm."""
    try:
        with store.boot_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            locked_existing = locked_manifest.step_results.get("boot")
            if (
                locked_existing
                and locked_existing.status == StepStatus.SUCCEEDED
                and not force_reboot
                and not has_new_boot_overrides
            ):
                return _short_circuit_boot_success(
                    run_id=run_id,
                    result=locked_existing,
                    admission=admission,
                    manifest=locked_manifest,
                    rootfs_profile=resolved_rootfs_profile,
                )
            next_attempt = len(locked_manifest.boot_attempts) + 1
            retrying_after_failure = bool(locked_existing and locked_existing.status == StepStatus.FAILED)
            replace_succeeded = (
                bool(locked_existing and locked_existing.status == StepStatus.SUCCEEDED) or has_new_boot_overrides
            )
            with store.target_lock(target_ref):
                if locked_existing and locked_existing.status == StepStatus.RUNNING:
                    stale_failed = StepResult(
                        step_name="boot",
                        status=StepStatus.FAILED,
                        summary=locked_existing.summary,
                        artifacts=locked_existing.artifacts,
                        details={**locked_existing.details, "stale_running_recovered": True},
                    )
                    store.record_step_result(run_id, stale_failed)
                    retrying_after_failure = True
                plan = _plan_boot_or_failure(
                    provider=provider,
                    store=store,
                    run_id=run_id,
                    kernel_image=kernel_image,
                    resolved_target_profile=resolved_target_profile,
                    resolved_rootfs_profile=resolved_rootfs_profile,
                    next_attempt=next_attempt,
                    replace_succeeded=replace_succeeded,
                    force_reboot=force_reboot,
                )
                if isinstance(plan, ToolResponse):
                    return plan
                return _execute_boot_attempt(
                    plan=plan,
                    retrying_after_failure=retrying_after_failure,
                    replace_succeeded=replace_succeeded or force_reboot,
                    attempt=next_attempt,
                    manifest=locked_manifest,
                    provider=provider,
                    store=store,
                    run_id=run_id,
                    resolved_target_profile=resolved_target_profile,
                    resolved_rootfs_profile=resolved_rootfs_profile,
                    kernel_image=kernel_image,
                    force_reboot=force_reboot,
                    admission=admission,
                )
    except ManifestStateError as exc:
        if "boot is locked" in str(exc):
            try:
                refreshed = store.load_manifest(run_id).step_results.get("boot")
            except ManifestStateError:
                refreshed = None
            if refreshed and refreshed.status == StepStatus.RUNNING:
                return _running_boot_response(run_id=run_id, result=refreshed)
            if existing and existing.status == StepStatus.RUNNING:
                return _running_boot_response(run_id=run_id, result=existing)
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)


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
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    resolved_inputs = _resolve_boot_inputs(
        manifest=manifest,
        run_id=run_id,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        target_profiles=target_profiles,
        rootfs_profiles=rootfs_profiles,
        default_libvirt_uri=default_libvirt_uri,
        boot_overrides=boot_overrides,
        sensitive_paths=sensitive_paths,
    )
    if isinstance(resolved_inputs, _HandlerFailure):
        return _tool_response_from_handler_failure(resolved_inputs)
    resolved_target_profile = resolved_inputs.resolved_target_profile
    resolved_rootfs_profile = resolved_inputs.resolved_rootfs_profile
    target_ref = resolved_inputs.target_ref
    kernel_image = resolved_inputs.kernel_image

    has_new_boot_overrides = boot_overrides is not None and (
        bool(boot_overrides.kernel_args)
        or boot_overrides.rootfs_source is not None
        or boot_overrides.has_rootfs_field_overrides()
        or boot_overrides.wait_for_debugger is not None
    )

    existing = manifest.step_results.get("boot")
    if existing and existing.status == StepStatus.SUCCEEDED and not force_reboot and not has_new_boot_overrides:
        return _short_circuit_boot_success(
            run_id=run_id,
            result=existing,
            admission=admission,
            manifest=manifest,
            rootfs_profile=resolved_rootfs_profile,
        )

    missing = missing_destructive_permissions(
        "target.boot",
        acknowledged_permissions or [],
        registry=TARGET_DESTRUCTIVE_PERMISSIONS,
    )
    if missing:
        return _configuration_failure(
            run_id=run_id,
            message="target.boot requires acknowledged destructive permissions before booting",
            details={"code": "permission_required", "required_permissions": missing},
        )

    provider = provider or LibvirtQemuProvider()

    return _boot_under_locks(
        store=store,
        run_id=run_id,
        target_ref=target_ref,
        resolved_target_profile=resolved_target_profile,
        resolved_rootfs_profile=resolved_rootfs_profile,
        kernel_image=kernel_image,
        force_reboot=force_reboot,
        has_new_boot_overrides=has_new_boot_overrides,
        existing=existing,
        provider=provider,
        admission=admission,
    )


def _ssh_host_is_unset_or_loopback(host: str | None) -> bool:
    """True when ``host`` is unset/empty, ``localhost``, or a loopback IP (ADR 0032 d6).

    Any other value — a routable IP or a non-IP DNS name — is a deliberate operator
    override and returns False so it is preserved.
    """
    if host is None or not host.strip():
        return True
    normalized = host.strip()
    if normalized.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _validated_guest_ip(value: object) -> str | None:
    """Return a routable IP string from an untrusted persisted ``guest_ip`` or None (ADR 0032 d7).

    Re-validates the on-disk value before it can reach an SSH argv: rejects non-strings,
    non-IP text, and loopback/link-local/unspecified addresses, keeping the SSH target
    injection-free even if the manifest was corrupted between boot and test.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified:
        return None
    return str(parsed)


@dataclass(frozen=True)
class _RunTestsInputs:
    provider: LocalSshTestProvider
    rootfs_profile: RootfsProfile
    suite_profile: TestSuiteProfile | None
    adhoc_commands: list[TestCommand]
    existing: StepResult | None


@dataclass(frozen=True)
class _CompletedRunTests:
    execution: TestExecutionResult
    summary: str
    details: dict[str, Any]
    diagnostic: str
    artifacts: list[ArtifactRef]


def _resolve_run_tests_inputs(
    *,
    run_id: str,
    manifest: RunManifest,
    boot_result: StepResult,
    test_suite: str | None,
    commands: list[list[str]] | None,
    force_rerun: bool,
    attempt: int | None,
    provider: LocalSshTestProvider | None,
    rootfs_profiles: dict[str, RootfsProfile] | None,
    test_suites: dict[str, TestSuiteProfile] | None,
) -> tuple[_RunTestsInputs | None, ToolResponse | None]:
    try:
        adhoc_commands = _validate_adhoc_commands(commands)
    except ValueError as exc:
        return None, _configuration_failure(run_id=run_id, message=str(exc))

    requested_suite = test_suite or manifest.request.test_suite
    if manifest.request.test_suite is not None and requested_suite != manifest.request.test_suite:
        return None, _configuration_failure(
            run_id=run_id,
            message="test_suite must match the immutable run manifest request",
            details={"requested_suite": requested_suite, "manifest_suite": manifest.request.test_suite},
        )
    if requested_suite is None and not adhoc_commands:
        requested_suite = "smoke-basic"

    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    test_suites = test_suites if test_suites is not None else DEFAULT_TEST_SUITES
    if manifest.boot_attempts:
        try:
            resolved_rootfs_profile = _select_boot_attempt(manifest.boot_attempts, attempt).resolved_rootfs_profile
        except ValueError as exc:
            return None, _configuration_failure(run_id=run_id, message=str(exc))
    elif attempt is not None:
        return None, _configuration_failure(
            run_id=run_id, message=f"boot attempt {attempt} not found: no boot attempts recorded for this run"
        )
    else:
        try:
            resolved_rootfs_profile = rootfs_profiles[manifest.request.rootfs_profile]
        except KeyError:
            return None, _configuration_failure(
                run_id=run_id,
                message=f"unknown rootfs profile: {manifest.request.rootfs_profile}",
            )

    boot_details = boot_result.details if isinstance(boot_result.details, dict) else {}
    guest_ip = _validated_guest_ip(boot_details.get("guest_ip"))
    if guest_ip is not None and _ssh_host_is_unset_or_loopback(resolved_rootfs_profile.ssh_host):
        resolved_rootfs_profile = resolved_rootfs_profile.model_copy(update={"ssh_host": guest_ip})
    elif boot_details.get("guest_ip") is not None and guest_ip is None:
        logger.warning(
            "run %s: discarding invalid persisted guest_ip %r; using configured ssh_host",
            run_id,
            boot_details.get("guest_ip"),
        )

    try:
        suite_profile = test_suites[requested_suite] if requested_suite is not None else None
    except KeyError:
        return None, _configuration_failure(run_id=run_id, message=f"unknown test suite: {requested_suite}")

    existing = manifest.step_results.get("run_tests")
    if existing and existing.status == StepStatus.SUCCEEDED and not force_rerun:
        return None, _recorded_test_success_response(run_id=run_id, result=existing)
    if existing and existing.status == StepStatus.FAILED and not force_rerun:
        return None, _recorded_test_failure_response(run_id=run_id, result=existing)

    return (
        _RunTestsInputs(
            provider=provider or LocalSshTestProvider(),
            rootfs_profile=resolved_rootfs_profile,
            suite_profile=suite_profile,
            adhoc_commands=adhoc_commands,
            existing=existing,
        ),
        None,
    )


def _record_run_tests_post_admission_failure(
    *,
    store: ArtifactStore,
    run_id: str,
    provider_name: str,
    force_rerun: bool,
    summary: str,
    details: dict[str, Any],
    category: ErrorCategory,
    message: str,
) -> ToolResponse:
    terminal = StepResult(
        step_name="run_tests",
        status=StepStatus.FAILED,
        summary=summary,
        details={"provider": provider_name, **details},
    )
    store.record_step_result(run_id, terminal, replace_succeeded=force_rerun)
    return ToolResponse.failure(
        category=category,
        message=message,
        run_id=run_id,
        details=Redactor().redact_value(terminal.details),
        suggested_next_actions=["artifacts.collect"],
    )


def _locked_run_tests_execution(
    *,
    store: ArtifactStore,
    run_id: str,
    inputs: _RunTestsInputs,
    force_rerun: bool,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
) -> _CompletedRunTests | ToolResponse:
    with store.tests_lock(run_id):
        locked_manifest = store.load_manifest(run_id)
        existing = locked_manifest.step_results.get("run_tests")
        if existing and existing.status == StepStatus.SUCCEEDED and not force_rerun:
            return _recorded_test_success_response(run_id=run_id, result=existing)
        if existing and existing.status == StepStatus.FAILED and not force_rerun:
            return _recorded_test_failure_response(run_id=run_id, result=existing)
        if existing and existing.status == StepStatus.RUNNING:
            stale_failed = StepResult(
                step_name="run_tests",
                status=StepStatus.FAILED,
                summary=existing.summary,
                artifacts=existing.artifacts,
                details={**existing.details, "stale_running_recovered": True},
            )
            store.record_step_result(run_id, stale_failed)

        attempt = _next_test_attempt(store.run_dir(run_id))
        try:
            plan = inputs.provider.plan_tests(
                run_id=run_id,
                run_dir=store.run_dir(run_id),
                rootfs_profile=inputs.rootfs_profile,
                suite=inputs.suite_profile,
                adhoc_commands=inputs.adhoc_commands,
                attempt=attempt,
            )
        except ValueError as exc:
            return _configuration_failure(run_id=run_id, message=str(exc))
        try:
            handle = _admit_run_tests_ssh_tier(run_id=run_id, admission=admission, session_registry=session_registry)
        except AdmissionError as exc:
            return ToolResponse.failure(
                category=exc.category,
                message=str(exc),
                run_id=run_id,
                details={"code": exc.code},
                suggested_next_actions=["artifacts.collect"],
            )
        running = StepResult(
            step_name="run_tests",
            status=StepStatus.RUNNING,
            summary="target tests running",
            details={
                "provider": inputs.provider.name,
                "suite": inputs.suite_profile.name if inputs.suite_profile is not None else "adhoc",
                "attempt": attempt,
            },
        )
        store.record_step_result(run_id, running, replace_succeeded=force_rerun)
        try:
            execution = _execute_tests_under_gate(
                provider=inputs.provider, plan=plan, admission=admission, handle=handle
            )
        except AdmissionError as exc:
            if handle is not None and admission is not None:
                with contextlib.suppress(Exception):
                    admission.rollback(handle)
            return _record_run_tests_post_admission_failure(
                store=store,
                run_id=run_id,
                provider_name=inputs.provider.name,
                force_rerun=force_rerun,
                summary="test run spanned an execution-state transition (target halted)",
                details={"code": exc.code, "error": str(exc)},
                category=exc.category,
                message=str(exc),
            )
        except Exception as exc:
            if handle is not None and admission is not None:
                with contextlib.suppress(Exception):
                    admission.rollback(handle)
            return _record_run_tests_post_admission_failure(
                store=store,
                run_id=run_id,
                provider_name=inputs.provider.name,
                force_rerun=force_rerun,
                summary="unexpected test provider failure",
                details={"exception_type": type(exc).__name__, "error": str(exc)},
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                message="unexpected test provider failure",
            )
        redactor = Redactor()
        safe_details = redactor.redact_value(execution.details)
        safe_summary = redactor.redact_text(execution.summary)
        safe_diagnostic = redactor.redact_text(execution.diagnostic or "")
        safe_artifacts = _redacted_artifacts(execution.artifacts, redactor)
        terminal = StepResult(
            step_name="run_tests",
            status=execution.status,
            summary=safe_summary,
            artifacts=safe_artifacts,
            details=safe_details,
        )
        store.record_step_result(run_id, terminal, replace_succeeded=force_rerun)
    return _CompletedRunTests(
        execution=execution,
        summary=safe_summary,
        details=safe_details,
        diagnostic=safe_diagnostic,
        artifacts=safe_artifacts,
    )


def target_run_tests_handler(
    *,
    artifact_root: Path,
    run_id: str,
    test_suite: str | None = None,
    commands: list[list[str]] | None = None,
    force_rerun: bool = False,
    attempt: int | None = None,
    provider: LocalSshTestProvider | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    test_suites: dict[str, TestSuiteProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    boot_result = manifest.step_results.get("boot")
    if boot_result is None or boot_result.status != StepStatus.SUCCEEDED:
        return _configuration_failure(run_id=run_id, message="target run tests requires a succeeded boot")

    inputs, input_failure = _resolve_run_tests_inputs(
        run_id=run_id,
        manifest=manifest,
        boot_result=boot_result,
        test_suite=test_suite,
        commands=commands,
        force_rerun=force_rerun,
        attempt=attempt,
        provider=provider,
        rootfs_profiles=rootfs_profiles,
        test_suites=test_suites,
    )
    if input_failure is not None:
        return input_failure
    inputs = _require_value(inputs, "run tests inputs missing after successful resolution")

    try:
        completed = _locked_run_tests_execution(
            store=store,
            run_id=run_id,
            inputs=inputs,
            force_rerun=force_rerun,
            admission=admission,
            session_registry=session_registry,
        )
        if isinstance(completed, ToolResponse):
            return completed
    except ManifestStateError as exc:
        if "tests are locked" in str(exc):
            try:
                refreshed = store.load_manifest(run_id).step_results.get("run_tests")
            except ManifestStateError:
                refreshed = None
            if refreshed and refreshed.status == StepStatus.RUNNING:
                return _running_tests_response(run_id=run_id, result=refreshed)
            if inputs.existing and inputs.existing.status == StepStatus.RUNNING:
                return _running_tests_response(run_id=run_id, result=inputs.existing)
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    if completed.execution.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=completed.summary,
            run_id=run_id,
            data=completed.details,
            artifacts=completed.artifacts,
            suggested_next_actions=["artifacts.collect"],
        )
    return ToolResponse.failure(
        category=completed.execution.error_category or ErrorCategory.TEST_FAILURE,
        message=completed.summary,
        run_id=run_id,
        details={
            **completed.details,
            "diagnostic": completed.diagnostic,
        },
        artifacts=completed.artifacts,
        suggested_next_actions=["artifacts.collect"],
    )


class _SupportsProbeRequest(Protocol):
    """Structural type for the run-scoped fields ``_resolve_probe_context`` reads.

    Lets ``DebugIntrospectCheckPrerequisitesRequest`` and
    ``DebugPostmortemCheckPrereqsRequest`` (field-identical, distinct tools) share the
    resolver without ``ty`` rejecting the second model (it does not duck-type Pydantic
    models by structure unless the parameter is a Protocol). See ADR 0028 decision 8.
    """

    run_id: str
    manifest_target_profile: str
    timeout_seconds: int
    debug_profile: str | None
    target_profile: str | None
    rootfs_profile: str | None


class _SupportsDumpRequest(Protocol):
    """Structural type for the ``dump_dir`` field both retrieval requests carry (#95)."""

    dump_dir: str | None


@dataclass(frozen=True)
class _ProbeContext:
    store: ArtifactStore
    run_id: str
    rootfs: RootfsProfile
    host_build_id: str | None
    redactor: Redactor


def _resolve_probe_context(
    request: _SupportsProbeRequest,
    *,
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile],
    timeout_band: tuple[int, int] = (5, 60),
) -> tuple[_ProbeContext | None, ToolResponse | None]:
    """Spec §6: all pre-SSH validation. Returns (context, None) on success or
    (None, failure-response) on any short-circuit."""
    run_id = request.run_id
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        if not (store.run_dir(run_id) / "manifest.json").is_file():
            return None, _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return None, ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    for field_name, requested, recorded in (
        ("target_profile", request.target_profile, manifest.request.target_profile),
        ("rootfs_profile", request.rootfs_profile, manifest.request.rootfs_profile),
        ("debug_profile", request.debug_profile, manifest.request.debug_profile),
    ):
        if requested is not None and recorded is not None and requested != recorded:
            return None, _configuration_failure(
                run_id=run_id,
                message=f"{field_name} must match the immutable run manifest request",
                details={
                    "requested_profile": requested,
                    "manifest_profile": recorded,
                    "code": "manifest_profile_mismatch",
                },
            )
    if request.manifest_target_profile != manifest.request.target_profile:
        return None, _configuration_failure(
            run_id=run_id,
            message="manifest_target_profile must match the immutable run manifest target_profile",
            details={
                "requested_target_profile": request.manifest_target_profile,
                "manifest_target_profile": manifest.request.target_profile,
                "code": "manifest_profile_mismatch",
            },
        )
    lo, hi = timeout_band
    if not (lo <= request.timeout_seconds <= hi):
        return None, _configuration_failure(
            run_id=run_id,
            message=f"timeout_seconds must be in [{lo}, {hi}]; got {request.timeout_seconds}",
            details={"code": "invalid_timeout"},
        )

    boot = manifest.step_results.get("boot")
    if boot is None or boot.status != StepStatus.SUCCEEDED:
        return None, ToolResponse.failure(
            category=ErrorCategory.READINESS_FAILURE,
            run_id=run_id,
            message="target has not booted; boot it before probing prerequisites",
            details={"code": "target_not_booted"},
            suggested_next_actions=["target.boot"],
        )

    rootfs_name = request.rootfs_profile or manifest.request.rootfs_profile
    try:
        rootfs = rootfs_profiles[rootfs_name]
    except KeyError:
        return None, _configuration_failure(run_id=run_id, message=f"unknown rootfs profile: {rootfs_name}")
    if rootfs.access_method not in {"ssh", "ssh_and_serial"}:
        return None, _configuration_failure(
            run_id=run_id,
            message=f"rootfs access_method must be ssh; got {rootfs.access_method}",
            details={"code": "unsupported_access_method"},
        )
    for field_name, value in (("ssh_host", rootfs.ssh_host), ("ssh_user", rootfs.ssh_user)):
        if not value:
            return None, _configuration_failure(
                run_id=run_id,
                message=f"rootfs profile is missing required SSH field: {field_name}",
                details={"code": "missing_ssh_field", "field": field_name},
            )

    build = manifest.step_results.get("build")
    host_build_id = build.details.get("build_id") if build is not None else None
    redactor = Redactor(secret_values=[rootfs.ssh_key_ref] if rootfs.ssh_key_ref else [])
    return (
        _ProbeContext(
            store=store,
            run_id=run_id,
            rootfs=rootfs,
            host_build_id=host_build_id,
            redactor=redactor,
        ),
        None,
    )


def debug_introspect_check_prerequisites_handler(
    request: DebugIntrospectCheckPrerequisitesRequest,
    *,
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
) -> ToolResponse:
    """Spec §3-§7: target-side drgn prerequisite probe."""
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    _ctx, failure = _resolve_probe_context(request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles)
    if failure is not None:
        return failure
    ctx = _require_value(_ctx, "probe context missing after successful resolution")
    run_id = ctx.run_id

    try:
        halted = _reject_if_target_halted(
            run_id=run_id,
            admission=admission,
            session_registry=session_registry,
            action="probing introspect prerequisites",
        )
    except AdmissionError as exc:
        return ToolResponse.failure(category=exc.category, run_id=run_id, message=str(exc), details={"code": exc.code})
    if halted is not None:
        return halted

    runner: SshRunner = ssh_runner or SubprocessSshRunner()
    probe_id = uuid.uuid4().hex
    agent_dir, sensitive_dir = _prepare_probe_dirs(ctx.store, run_id, probe_id)

    use_sudo = ctx.rootfs.ssh_user != "root"
    remote_argv = _target_python_remote_argv(timeout_seconds=request.timeout_seconds, use_sudo=use_sudo)
    try:
        ssh_argv = build_ssh_argv(
            rootfs_profile=ctx.rootfs,
            known_hosts_path=ctx.store.run_dir(run_id) / "sensitive" / "known_hosts",
            command=remote_argv,
            command_timeout=request.timeout_seconds + SSH_TIMEOUT_GRACE_SECONDS,
        )
    except ValueError as exc:
        return _configuration_failure(
            run_id=run_id,
            message=_redact_and_truncate(ctx.redactor, str(exc), cap=256),
            details={"code": "invalid_ssh_options"},
        )

    stdout_path = sensitive_dir / "stdout.raw"
    stderr_path = sensitive_dir / "stderr.raw"
    try:
        ssh_result = runner.run(
            ssh_argv,
            timeout=request.timeout_seconds + SSH_TIMEOUT_GRACE_SECONDS,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            stdin=PROBE_SCRIPT,
            max_stdout_bytes=PROBE_STDOUT_CAP,
        )
    except Exception as exc:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=_redact_and_truncate(ctx.redactor, f"ssh probe raised: {exc}", cap=256),
            details={"code": "ssh_failure"},
        )
    for _path in (stdout_path, stderr_path):
        _chmod_best_effort(_path, 0o600)

    return _assemble_probe_response(
        ctx,
        ssh_result=ssh_result,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        agent_dir=agent_dir,
        probe_id=probe_id,
    )


def _read_capped(path: Path, cap: int) -> str | None:
    """Read the file iff its byte size is within *cap*; None if oversized."""
    if not path.exists():
        return ""
    if path.stat().st_size > cap:
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def _prepare_probe_dirs(
    store: ArtifactStore,
    run_id: str,
    probe_id: str,
    *,
    category: tuple[str, ...] = ("debug", "checkprereq"),
) -> tuple[Path, Path]:
    """Create the agent-visible and sensitive probe directories with 0o700.

    ``category`` is the path under the run dir (and under ``sensitive/``) the probe
    writes to; defaults to the introspect ``debug/checkprereq`` layout. Postmortem
    passes ``("debug", "postmortem", "check_prereqs")``. Returns ``(agent_dir,
    sensitive_dir)``.
    """
    run_dir = store.run_dir(run_id)
    agent_dir = run_dir.joinpath(*category, probe_id)
    sensitive_dir = run_dir.joinpath("sensitive", *category, probe_id)
    agent_dir.mkdir(parents=True, mode=0o700)
    sensitive_dir.mkdir(parents=True, mode=0o700)
    sensitive_root = run_dir / "sensitive"
    current = sensitive_dir
    while current != sensitive_root and current != run_dir:
        _chmod_best_effort(current, 0o700)
        current = current.parent
    return agent_dir, sensitive_dir


def _no_json_response(
    ctx: _ProbeContext,
    *,
    ssh_result: SshCommandResult,
    agent_dir: Path,
    stdout_path: Path,
    stderr_path: Path,
    probe_id: str,
    parsed: Any,
) -> ToolResponse | None:
    """Handle the cases where the probe returned no parseable JSON dict.

    Returns the 127-success / 255-failure / non-dict-failure response, or
    ``None`` to fall through to the normal ``build_probe_checks`` path.
    """
    if isinstance(parsed, dict):
        return None
    run_id = ctx.run_id
    if ssh_result.exit_status == 127:
        checks, verdict = python_missing_checks()
        return _probe_success(
            ctx,
            agent_dir=agent_dir,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            probe_id=probe_id,
            checks=checks,
            verdict=verdict,
            parsed=None,
        )
    if ssh_result.exit_status == 255:
        snippet = _redact_and_truncate(ctx.redactor, ssh_result.stderr_snippet or "", cap=256)
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="probe ssh transport failed before the target ran",
            details={"code": "ssh_connect_failure", "stderr": snippet},
        )
    snippet = _redact_and_truncate(ctx.redactor, ssh_result.stderr_snippet or "", cap=256)
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        run_id=run_id,
        message=f"probe did not return parseable JSON (exit {ssh_result.exit_status})",
        details={"code": "probe_unparseable", "stderr": snippet},
    )


def _assemble_probe_response(
    ctx: _ProbeContext,
    *,
    ssh_result: SshCommandResult,
    stdout_path: Path,
    stderr_path: Path,
    agent_dir: Path,
    probe_id: str,
) -> ToolResponse:
    run_id = ctx.run_id
    if ssh_result.oversized_output:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=f"probe stdout exceeded {PROBE_STDOUT_CAP} bytes",
            details={"code": "oversized_output"},
        )
    raw_stdout = _read_capped(stdout_path, PROBE_STDOUT_CAP)
    if raw_stdout is None:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=f"probe stdout exceeded {PROBE_STDOUT_CAP} bytes",
            details={"code": "oversized_output"},
        )
    if ssh_result.cancelled or ssh_result.timed_out or ssh_result.stdin_failed:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="probe ssh round trip failed",
            details={"code": "ssh_failure"},
        )
    try:
        parsed = json.loads(raw_stdout) if raw_stdout else None
    except json.JSONDecodeError:
        parsed = None

    no_json = _no_json_response(
        ctx,
        ssh_result=ssh_result,
        agent_dir=agent_dir,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        probe_id=probe_id,
        parsed=parsed,
    )
    if no_json is not None:
        return no_json

    parsed = _require_dict(parsed, "probe stdout parser returned non-dict without failure")
    checks, verdict = build_probe_checks(parsed, host_build_id=ctx.host_build_id)
    return _probe_success(
        ctx,
        agent_dir=agent_dir,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        probe_id=probe_id,
        checks=checks,
        verdict=verdict,
        parsed=parsed,
    )


def _probe_success(
    ctx: _ProbeContext,
    *,
    agent_dir: Path,
    stdout_path: Path,
    stderr_path: Path,
    probe_id: str,
    checks: list[PrerequisiteCheck],
    verdict: str,
    parsed: dict[str, Any] | None,
) -> ToolResponse:
    artifacts = [
        ArtifactRef(path=str(stdout_path), kind="probe-stdout", sensitive=True),
        ArtifactRef(path=str(stderr_path), kind="probe-stderr", sensitive=True),
    ]
    if parsed is not None:
        report_path = agent_dir / "probe.json"
        report_path.write_text(json.dumps(ctx.redactor.redact_value(parsed)), encoding="utf-8")
        artifacts.append(ArtifactRef(path=str(report_path), kind="probe-report", sensitive=False))
    failed = sum(1 for c in checks if c.status == PrerequisiteStatus.FAILED)
    next_actions = ["debug.introspect.run"] if verdict in {USABLE, UNKNOWN} else ["host.check_prerequisites"]
    return ToolResponse.success(
        summary=f"introspect prerequisites: {verdict} ({failed} failed checks)",
        run_id=ctx.run_id,
        data={
            "introspect_usable": verdict,
            "probe_id": probe_id,
            "checks": ctx.redactor.redact_value([c.model_dump(mode="json") for c in checks]),
        },
        artifacts=artifacts,
        suggested_next_actions=next_actions,
    )


def _parse_probe_stdout(
    ctx: _ProbeContext,
    *,
    ssh_result: SshCommandResult,
    stdout_path: Path,
    noun: str,
    no_python_message: str,
) -> tuple[dict[str, Any] | None, ToolResponse | None]:
    """Shared SSH-probe stdout gate (TD-100): the oversized → cap → cancelled/timeout → exit-255 →
    exit-127 → unparseable-JSON ladder the kdump-readiness and dump-enumeration probes both ran
    byte-for-byte (modulo the ``noun`` in each message and the no-python text). Returns
    ``(parsed_object, None)`` when the target produced a JSON object, else ``(None, failure)``.

    (`_assemble_probe_response` deliberately does NOT use this: its introspect prereq check is
    advisory, so a no-JSON / no-python target gets a degraded report via ``_no_json_response``, not
    the hard INFRASTRUCTURE_FAILURE this gate returns.)"""
    run_id = ctx.run_id

    def fail(message: str, code: str, **extra: object) -> ToolResponse:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=message,
            details={"code": code, **extra},
        )

    oversized = f"{noun} stdout exceeded {PROBE_STDOUT_CAP} bytes"
    if ssh_result.oversized_output:
        return None, fail(oversized, "oversized_output")
    raw_stdout = _read_capped(stdout_path, PROBE_STDOUT_CAP)
    if raw_stdout is None:
        return None, fail(oversized, "oversized_output")
    if ssh_result.cancelled or ssh_result.timed_out or ssh_result.stdin_failed:
        return None, fail(f"{noun} ssh round trip failed", "ssh_failure")
    if ssh_result.exit_status == 255:
        snippet = _redact_and_truncate(ctx.redactor, ssh_result.stderr_snippet or "", cap=256)
        return None, fail(f"{noun} ssh transport failed before the target ran", "ssh_connect_failure", stderr=snippet)
    if ssh_result.exit_status == 127:
        return None, fail(no_python_message, "probe_no_python")
    try:
        parsed = json.loads(raw_stdout) if raw_stdout else None
    except json.JSONDecodeError:
        parsed = None
    if not isinstance(parsed, dict):
        snippet = _redact_and_truncate(ctx.redactor, ssh_result.stderr_snippet or "", cap=256)
        return None, fail(
            f"{noun} did not return parseable JSON (exit {ssh_result.exit_status})", "probe_unparseable", stderr=snippet
        )
    return parsed, None


def _assemble_kdump_response(
    ctx: _ProbeContext,
    *,
    ssh_result: SshCommandResult,
    stdout_path: Path,
    stderr_path: Path,
    agent_dir: Path,
    probe_id: str,
) -> ToolResponse:
    run_id = ctx.run_id
    parsed, failure = _parse_probe_stdout(
        ctx,
        ssh_result=ssh_result,
        stdout_path=stdout_path,
        noun="probe",
        no_python_message="python3 is not available on the target; cannot probe kdump readiness",
    )
    if failure is not None:
        return failure
    parsed = _require_value(parsed, "kdump probe parser returned no data without failure")

    checks, mechanism = build_kdump_checks(parsed)
    kdump_ready = not any(c.status == PrerequisiteStatus.FAILED for c in checks)
    report_path = agent_dir / "probe.json"
    report_path.write_text(json.dumps(ctx.redactor.redact_value(parsed)), encoding="utf-8")
    artifacts = [
        ArtifactRef(path=str(stdout_path), kind="probe-stdout", sensitive=True),
        ArtifactRef(path=str(stderr_path), kind="probe-stderr", sensitive=True),
        ArtifactRef(path=str(report_path), kind="probe-report", sensitive=False),
    ]
    failed = sum(1 for c in checks if c.status == PrerequisiteStatus.FAILED)
    return ToolResponse.success(
        summary=f"kdump prerequisites: {'ready' if kdump_ready else 'not ready'} ({mechanism}, {failed} failed)",
        run_id=run_id,
        data={
            "kdump_ready": kdump_ready,
            "mechanism": mechanism,
            "probe_id": probe_id,
            "checks": ctx.redactor.redact_value([c.model_dump(mode="json") for c in checks]),
        },
        artifacts=artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


# Live and vmcore introspection handlers live in kdive.introspect.handlers/execution.


# Postmortem triage composition lives in kdive.postmortem.handlers.


def _debug_open_request(*, run_id: str, gdbstub_endpoint: dict[str, Any], admission: AdmissionService) -> OpenRequest:
    """Build the §4.3 transport.open request for the recorded gdbstub endpoint, reading
    `generation`/`platform` from the authoritative snapshot the boot step published (never
    re-deriving them — ADR 0007). The RSP channel mirrors the boot snapshot producer."""
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = _require_snapshot(admission, target_key)
    return OpenRequest(
        target_key=target_key,
        generation=snapshot.generation,
        transport_ref=TransportRef(
            provider="qemu-gdbstub",
            channel_id="rsp0",
            line_role=LineRole.RSP,
            caps=("rsp",),
            target_ref=gdbstub_endpoint,
            # The qemu-gdbstub transport reads the RSP host/port from opts (transport.qemu_gdbstub),
            # so the endpoint must be in opts, not only target_ref, or attach raises KeyError: 'port'.
            opts=gdbstub_endpoint,
        ),
        required_caps=["rsp"],
        platform=snapshot.platform,
    )


def _mi_probe_transcript_path(run_dir: Path) -> Path:
    """The live gdb/MI session's transcript. ADR 0021: this is the session-of-record transcript the
    persisted DebugSession references (it is the same file the attach probe writes into)."""
    return run_dir / "debug" / "mi-probe.log"


def _run_mi_attach_probe(
    *,
    engine: GdbMiEngine,
    transport_session: TransportSession,
    vmlinux_path: Path,
    run_dir: Path,
    run_id: str,
    session_id: str,
    gdb_mi_sessions: GdbMiSessionRegistry,
    transaction: TransportTransaction,
    admission: AdmissionService,
    session_registry: SessionRegistry,
    session_guard: SessionGuard | None,
    redactor: Redactor,
) -> tuple[ToolResponse | None, dict[str, object]]:
    """Attach the persistent gdb/MI engine over the guard-protected TransportSession.rsp_endpoint,
    read one MI record as typed JSON, resolve the canonical probe symbol, and — on success — REGISTER
    the live attachment under ``session_id`` and leave it ATTACHED (ADR 0021 decision 1). Returns
    ``(None, {"mi_probe": ...})`` on success (the typed record is merged into the debug step details),
    or ``(failure_response, {})`` after a guaranteed-resume teardown that never leaves the kernel
    HALTED and reaps any partial registration. The live session is the sole session-of-record; there
    is no batch attach behind it."""
    transcript_path = _mi_probe_transcript_path(run_dir)
    attachment = None
    try:
        attachment = engine.attach(
            rsp_endpoint=transport_session.rsp_endpoint, vmlinux_path=vmlinux_path, transcript_path=transcript_path
        )
        record = engine.probe_read(attachment)
        symbol = engine.resolve_symbol(attachment, CANONICAL_PROBE_SYMBOL)
        # Keep the engine attached and hold the live attachment across MCP calls under the minted
        # session id (ADR 0021) — the per-op handlers look it up to issue MI verbs. NO detach here.
        gdb_mi_sessions.register(session_id, attachment)
        mi_probe: dict[str, object] = {
            "mi_probe": redactor.redact_value(
                {
                    "record": record.model_dump(mode="json"),
                    "symbol": symbol.model_dump(mode="json"),
                    "transcript_path": str(transcript_path),
                }
            )
        }
        return None, mi_probe
    except Exception as exc:  # noqa: BLE001 - the guaranteed-resume invariant is unconditional
        # The invariant is "the target is NEVER left HALTED on a tool error" (engine crash, RSP
        # timeout, AND a raised tool exception). So this catch is intentionally broad: a non-GdbMiError
        # (e.g. an unwrapped pygdbmi error) must still trigger resume + teardown, not escape and strand
        # the kernel HALTED with the guard held. KeyboardInterrupt/SystemExit (BaseException, not
        # Exception) still propagate. The error is re-reported as a failure response, never swallowed.
        category = exc.category if isinstance(exc, GdbMiError) else ErrorCategory.INFRASTRUCTURE_FAILURE
        base_details = exc.details if isinstance(exc, GdbMiError) else {}
        # If attach failed before connecting (bad endpoint / missing gdb / missing vmlinux), no RSP
        # connection was made, so the engine never halted the target -> treat resume as confirmed so
        # the durable record is un-halted and no recovery tombstone is left. Otherwise run the
        # guaranteed-resume (best-effort continue + disconnect + kill).
        resume_confirmed = engine.force_resume(attachment) if attachment is not None else True
        # Reap any registration (idempotent no-op when the fault preceded register()) so a failed
        # attach never leaves a dangling live attachment behind the freed durable record.
        gdb_mi_sessions.reap(session_id)
        if resume_confirmed:
            # Best-effort: the un-halt is a durable write that could raise (e.g. OSError on a full
            # disk). It MUST NOT be able to skip the teardown below, or the guaranteed-resume
            # invariant would be defeated (guard left held, kernel left HALTED). If the EXECUTING
            # write fails, teardown's close(force=False) then leaves a closed_while_halted recovery
            # tombstone -- the conservative fallback -- and still releases the guard.
            with contextlib.suppress(Exception):
                _resume_debug_transport(
                    session=transport_session, admission=admission, session_registry=session_registry
                )
        _teardown_debug_transport(
            transport_session=transport_session,
            transaction=transaction,
            session_registry=session_registry,
            session_guard=session_guard,
        )
        details = redactor.redact_value({**base_details, "transport_session_id": transport_session.session_id})
        failure = ToolResponse.failure(
            category=category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=details,
            suggested_next_actions=["host.check_prerequisites", "artifacts.get_manifest"],
        )
        return failure, {}


_LOSSY_OUT_OF_BAND_CONSOLES = frozenset({ConsoleKind.HVC, ConsoleKind.VIRTIO})
_TRANSPORT_QUALITY_WARNING = (
    "gdb/MI RSP is riding a lossy out-of-band console ({console_kind}); break-in and live"
    " transcripts may be dropped or corrupted. Prefer the in-guest/postmortem tiers for"
    " reliable inspection."
)
_LOSSY_TRANSPORT_NEXT_ACTIONS = ("debug.kdb", "debug.introspect.run")


def is_lossy_out_of_band(console_kind: ConsoleKind) -> bool:
    """True when the RSP travels over a console whose framing can silently drop or corrupt bytes
    (paravirtual HVC, virtio-console) rather than a dedicated UART line. ADR 0024 decision 2: the
    warning is keyed on console framing quality, never on the selected line's role."""
    return console_kind in _LOSSY_OUT_OF_BAND_CONSOLES


def _build_mi_debug_session(
    *,
    session_id: str,
    run_id: str,
    vmlinux_path: Path,
    gdbstub_endpoint: dict[str, object],
    profile_name: str,
    transcript_path: Path,
    started_at: str,
) -> DebugSession:
    """Build the persisted DebugSession for the live gdb/MI attach (ADR 0021). The id is minted once
    in the handler BEFORE the probe and threaded here, so the registry key and the persisted id are
    identical. Symbol-identity validation is empty: the #70 build-id version-lock gate ran before the
    attach and is authoritative (ADR 0021 decision 2b) — there is no live-banner scrape."""
    attempt_dir = transcript_path.parent
    return DebugSession(
        session_id=session_id,
        run_id=run_id,
        provider_name="local-qemu-gdbstub",
        gdbstub_endpoint=gdbstub_endpoint,
        vmlinux_path=str(vmlinux_path),
        selected_debug_profile=profile_name,
        attach_status="attached",
        started_at=started_at,
        ended_at=None,
        current_execution_state=DebugSessionState.STOPPED,
        breakpoints={},
        transcript_path=str(transcript_path),
        command_metadata_path=str(attempt_dir / "commands.jsonl"),
        latest_summary_path=str(attempt_dir / "debug-summary.json"),
        symbol_identity_validation={},
    )


def _verify_gdb_symbol_version_lock(
    *,
    boot_result: StepResult,
    vmlinux_path: Path,
    run_id: str,
    build_id_reader: Callable[[Path], str],
) -> ToolResponse | None:
    """#70 / ADR 0017: verify the on-disk vmlinux ELF build-id equals the
    boot-recorded §4.2 KernelProvenance.build_id. Returns a failure ToolResponse to
    abort the attach, or None to proceed. Unconditional (independent of
    symbol_identity_required) -- a detected mismatch is bogus symbols.

    *vmlinux_path* is the manifest-recorded build artifact (trusted: the artifact
    root is the trust boundary), read read-only for its ELF build-id note; the gdb
    provider performs the authoritative under-run-dir path confinement at attach.
    """
    provenance = boot_result.details.get("kernel_provenance")
    if not isinstance(provenance, dict):
        capture_error = boot_result.details.get("kernel_provenance_capture_error")
        details: dict[str, Any] = {"code": "provenance_missing"}
        if isinstance(capture_error, dict):
            message = f"boot did not record a KernelProvenance: {capture_error.get('message', 'capture failed')}"
            details["capture_error"] = capture_error.get("code")
        else:
            message = (
                "boot for this run did not record a KernelProvenance (it predates "
                "provenance capture). Re-run target.boot with force_reboot=true to capture it."
            )
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=message,
            details=details,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    expected_build_id = provenance.get("build_id")
    if not isinstance(expected_build_id, str) or not BUILD_ID_RE.match(expected_build_id):
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="recorded build_id is malformed",
            details={"code": "provenance_corrupt", "recorded": str(expected_build_id)},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    try:
        verify_vmlinux_provenance(
            expected_build_id=expected_build_id,
            vmlinux_path=vmlinux_path,
            build_id_reader=build_id_reader,
        )
    except BuildIdReadError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"could not read a GNU build-id from the vmlinux to verify symbols: {exc}",
            details={"code": "vmlinux_build_id_unreadable"},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    except ProvenanceMismatch as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(
                f"vmlinux build-id {exc.observed!r} does not match the booted kernel's recorded "
                f"build-id {exc.expected!r}; rebuild or re-boot so the booted kernel and the "
                "vmlinux on disk share a build-id"
            ),
            details={"code": "provenance_mismatch", "expected": exc.expected, "observed": exc.observed},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    return None


def _debug_start_session_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_profile: str | None = None,
    new_session: bool = False,
    debug_profiles: dict[str, DebugProfile] | None = None,
    transaction: TransportTransaction | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    recovery: bool = False,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    build_result = manifest.step_results.get("build")
    if build_result is None or build_result.status != StepStatus.SUCCEEDED:
        return _configuration_failure(run_id=run_id, message="debug start session requires a succeeded build")
    boot_result = manifest.step_results.get("boot")
    if boot_result is None or boot_result.status != StepStatus.SUCCEEDED:
        return _configuration_failure(run_id=run_id, message="debug start session requires a succeeded boot")
    if boot_result.details.get("debug_boot") is not True:
        return _configuration_failure(run_id=run_id, message="debug start session requires a debug boot")
    vmlinux = _find_artifact(build_result, "vmlinux")
    if vmlinux is None:
        return _configuration_failure(run_id=run_id, message="succeeded build did not record a vmlinux artifact")
    kernel_image = _find_artifact(build_result, "kernel-image")
    if kernel_image is None:
        return _configuration_failure(run_id=run_id, message="succeeded build did not record a kernel-image artifact")
    gdbstub_endpoint = boot_result.details.get("gdbstub_endpoint")
    if not isinstance(gdbstub_endpoint, dict):
        return _configuration_failure(run_id=run_id, message="succeeded debug boot did not record a gdbstub endpoint")

    requested_profile = debug_profile or manifest.request.debug_profile or "qemu-gdbstub-default"
    if (
        manifest.request.debug_profile is not None
        and debug_profile is not None
        and debug_profile != manifest.request.debug_profile
    ):
        return _configuration_failure(
            run_id=run_id,
            message="debug_profile must match the immutable run manifest request",
            details={"requested_profile": debug_profile, "manifest_profile": manifest.request.debug_profile},
        )
    try:
        resolved_debug_profile = _resolve_debug_profile(
            profile_name=requested_profile,
            debug_profiles=debug_profiles,
        )
        _ensure_debug_operation_enabled(resolved_debug_profile, "debug.start_session")
    except ProviderDebugError as exc:
        return _configuration_failure(run_id=run_id, message=str(exc), details=exc.details)

    redactor = Redactor()
    started_at = datetime.now(UTC).isoformat()
    try:
        with store.debug_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("debug")
            replace_existing_debug = new_session
            if existing and not new_session:
                active_session = _debug_session_details_from_result(existing)
                if active_session is not None:
                    return ToolResponse.success(
                        summary=redactor.redact_text(existing.summary),
                        run_id=run_id,
                        data=redactor.redact_value(active_session),
                        artifacts=_redacted_artifacts(existing.artifacts, redactor),
                        suggested_next_actions=["debug.interrupt", "debug.read_registers", "artifacts.get_manifest"],
                    )
                replace_existing_debug = existing.status == StepStatus.SUCCEEDED
            # #70 / ADR 0017: symbol version-lock BEFORE any acquisition or attach.
            # Runs on every fresh attach (incl. new_session / replace / recovery), after the
            # idempotent SUCCEEDED short-circuit above so re-reading a healthy session never
            # re-gates. A failure returns with nothing acquired and no debug step recorded.
            version_lock_failure = _verify_gdb_symbol_version_lock(
                boot_result=boot_result,
                vmlinux_path=Path(vmlinux.path),
                run_id=run_id,
                build_id_reader=build_id_reader,
            )
            if version_lock_failure is not None:
                return version_lock_failure
            # The live gdb/MI engine attach IS the session-of-record (ADR 0021): there is no batch
            # attach behind it, so the transport machinery AND the engine+registry are mandatory.
            if not (
                transaction is not None
                and admission is not None
                and session_registry is not None
                and gdb_mi_engine is not None
                and gdb_mi_sessions is not None
            ):
                return ToolResponse.failure(
                    category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                    message="debug.start_session requires the transport machinery and the gdb/MI engine",
                    run_id=run_id,
                    details={"code": "debug_engine_unavailable"},
                    suggested_next_actions=["artifacts.get_manifest"],
                )
            target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
            if session_guard is not None:
                # Pre-attach preconditions (#70 static checks) run BEFORE any acquisition; a
                # failure aborts with nothing acquired, so there is nothing to tear down.
                try:
                    session_guard.enter(
                        SessionGuardContext(target_key=target_key, generation=0, session_id=None, reason="attach_error")
                    )
                except PreconditionError as exc:
                    return ToolResponse.failure(
                        category=ErrorCategory.READINESS_FAILURE,
                        message=str(exc),
                        run_id=run_id,
                        details={"code": "precondition_failed", "precondition": exc.name},
                        suggested_next_actions=["artifacts.get_manifest"],
                    )
            try:
                request = _debug_open_request(run_id=run_id, gdbstub_endpoint=gdbstub_endpoint, admission=admission)
                transport_session = transaction.open(request, recovery=recovery)
            except (GuardConflict, EndpointSafetyError) as exc:
                # Guard and endpoint conflicts are transport-resource conflicts, not gdb attach
                # failures.
                return ToolResponse.failure(
                    category=ErrorCategory.TRANSPORT_CONFLICT,
                    message=str(exc),
                    run_id=run_id,
                    details={"code": getattr(exc, "code", "stop_capable_conflict")},
                    suggested_next_actions=["artifacts.get_manifest"],
                )
            except AdmissionError as exc:
                return ToolResponse.failure(
                    category=exc.category,
                    message=str(exc),
                    run_id=run_id,
                    details={"code": exc.code},
                    suggested_next_actions=["artifacts.get_manifest"],
                )
            # Persist HALTED + bump the execution epoch BEFORE the gdb attach halts the kernel, so
            # target.run_tests rejects with target_halted for the debugger's whole window.
            _halt_debug_transport(session=transport_session, admission=admission, session_registry=session_registry)
            # Mint the session id ONCE before the probe and thread it into BOTH the live registry
            # (register inside the probe) and the persisted DebugSession, so the registry key and the
            # persisted id are identical — the per-op lookup finds the right attachment.
            session_id = f"debug-{uuid.uuid4().hex}"
            probe_failure, mi_probe_details = _run_mi_attach_probe(
                engine=gdb_mi_engine,
                transport_session=transport_session,
                vmlinux_path=Path(vmlinux.path),
                run_dir=store.run_dir(run_id),
                run_id=run_id,
                session_id=session_id,
                gdb_mi_sessions=gdb_mi_sessions,
                transaction=transaction,
                admission=admission,
                session_registry=session_registry,
                session_guard=session_guard,
                redactor=redactor,
            )
            if probe_failure is not None:
                return probe_failure
            # The live attach succeeded and is registered + held HALTED. Build, persist, and record
            # the session-of-record from it (no batch attach). Everything below runs AFTER the live
            # attachment is registered and the kernel is HALTED, so a persistence/manifest fault here
            # MUST run the guaranteed-resume teardown (reap + un-halt + close) rather than escape and
            # strand the kernel HALTED with the guard held and the attachment leaked.
            try:
                session = _build_mi_debug_session(
                    session_id=session_id,
                    run_id=run_id,
                    vmlinux_path=Path(vmlinux.path),
                    gdbstub_endpoint=gdbstub_endpoint,
                    profile_name=resolved_debug_profile.name,
                    transcript_path=_mi_probe_transcript_path(store.run_dir(run_id)),
                    started_at=started_at,
                )
                session_path = _persist_mi_debug_session(store=store, run_id=run_id, session=session)
                artifacts = [
                    ArtifactRef(path=str(session_path), kind="debug-session"),
                    ArtifactRef(path=session.transcript_path, kind="debug-transcript", sensitive=True),
                ]
                details = _debug_session_manifest_details(store=store, run_id=run_id, session=session)
                details.update(mi_probe_details)
                details["transport_session_id"] = transport_session.session_id
                # Post-attach preconditions (#70 build-id-vs-running-kernel) run with the live session,
                # BEFORE the SUCCEEDED debug step is persisted: a rejection reaps the live attachment
                # (force_resume un-halts the kernel) and tears the transport down, so the manifest never
                # records a SUCCEEDED session that teardown just deleted.
                if session_guard is not None:
                    sid = transport_session.session_id
                    tkey = transport_session.target_key
                    post_ctx = SessionGuardContext(
                        target_key=tkey, generation=transport_session.generation, session_id=sid, reason="attach_error"
                    )
                    try:
                        session_guard.verify_attached(post_ctx, transport_session)
                    except PreconditionError as exc:
                        reaped = gdb_mi_sessions.reap(session_id)
                        if reaped is not None:
                            with contextlib.suppress(Exception):
                                gdb_mi_engine.force_resume(reaped)
                        session_guard.teardown(
                            post_ctx,
                            close=lambda: transaction.close(sid, force=False),
                            read_record=lambda: session_registry.read_record(tkey),
                            force_reap=lambda: transaction.force_release(sid),
                        )
                        return ToolResponse.failure(
                            category=ErrorCategory.READINESS_FAILURE,
                            message=str(exc),
                            run_id=run_id,
                            details={"code": "precondition_failed", "precondition": exc.name},
                            suggested_next_actions=["artifacts.get_manifest"],
                        )
                terminal = StepResult(
                    step_name="debug",
                    status=StepStatus.SUCCEEDED,
                    summary="gdb/MI debug session started",
                    artifacts=artifacts,
                    details=details,
                )
                store.record_step_result(run_id, terminal, replace_succeeded=replace_existing_debug)
            except Exception as exc:  # noqa: BLE001 - guaranteed-resume is unconditional after register
                # Persisting the session file or recording the manifest step failed (OSError on a full
                # disk, a ManifestStateError, ...). The live attachment is already registered and the
                # kernel HALTED, so reap + un-halt + tear the transport down before reporting, or the
                # target would be stranded HALTED with the guard held until process restart.
                reaped = gdb_mi_sessions.reap(session_id)
                if reaped is not None:
                    with contextlib.suppress(Exception):
                        gdb_mi_engine.force_resume(reaped)
                with contextlib.suppress(Exception):
                    _resume_debug_transport(
                        session=transport_session, admission=admission, session_registry=session_registry
                    )
                _teardown_debug_transport(
                    transport_session=transport_session,
                    transaction=transaction,
                    session_registry=session_registry,
                    session_guard=session_guard,
                )
                category = exc.category if isinstance(exc, ManifestStateError) else ErrorCategory.INFRASTRUCTURE_FAILURE
                return ToolResponse.failure(
                    category=category,
                    message=redactor.redact_text(str(exc)),
                    run_id=run_id,
                    details={"code": "debug_session_persist_failed"},
                    suggested_next_actions=["host.check_prerequisites", "artifacts.get_manifest"],
                )
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    next_actions = ["debug.interrupt", "debug.read_registers", "artifacts.get_manifest"]
    snapshot = admission.current_snapshot(target_key)
    if snapshot is not None and is_lossy_out_of_band(snapshot.platform.console_kind):
        # ADR 0024 decision 2: the RSP rides a console whose framing can silently drop bytes, so
        # break-in and live transcripts are unreliable. Surface the warning and steer the agent at
        # the in-guest/postmortem tiers, which do not depend on the lossy out-of-band path.
        details["transport_quality_warning"] = _TRANSPORT_QUALITY_WARNING.format(
            console_kind=snapshot.platform.console_kind.value
        )
        next_actions = [*_LOSSY_TRANSPORT_NEXT_ACTIONS, *next_actions]
    return ToolResponse.success(
        summary="gdb/MI debug session started",
        run_id=run_id,
        data=redactor.redact_value(details),
        artifacts=_redacted_artifacts(artifacts, redactor),
        suggested_next_actions=next_actions,
    )


# Debug operation response and persistence live in kdive.debug.operations.


# Phase D (#82): a loadable kernel module's name (sysfs normalizes the source name's hyphens to
# underscores under /sys/module/, so the agent-facing name is the underscore form).
_MODULE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# The sysfs section files the module-symbol load sources; .text is mandatory (add-symbol-file's
# positional address), the rest are best-effort -s arguments.
_MODULE_SECTION_FILES = (".text", ".data", ".rodata", ".bss")
# Emitted by the remote reader when /sys/module/<name>/sections is absent (module not loaded).
_NO_MODULE_SENTINEL = "__NO_MODULE__"


def _read_module_sections(
    *,
    ssh_runner: SshRunner,
    rootfs_profile: RootfsProfile,
    known_hosts_path: Path,
    module_name: str,
    work_dir: Path,
    timeout: int = 15,
) -> dict[str, str]:
    """Read a module's runtime section base addresses from guest sysfs over SSH (ADR 0022). Returns
    the section->address map (``.text`` guaranteed present). Raises ProviderDebugError with
    ``module_not_loaded`` when the module's sysfs directory is absent and ``section_addresses_unreadable``
    when ``.text`` cannot be read (e.g. a non-root SSH identity on a hardened guest). The module name
    is passed as a discrete ``$1`` argv token, never interpolated into the script."""
    work_dir.mkdir(parents=True, exist_ok=True)
    section_list = " ".join(_MODULE_SECTION_FILES)
    script = (
        'd="/sys/module/$1/sections"; '
        f'if [ ! -d "$d" ]; then echo "{_NO_MODULE_SENTINEL}"; exit 0; fi; '
        f"for s in {section_list}; do "
        'if [ -r "$d/$s" ]; then printf "%s %s\\n" "$s" "$(cat "$d/$s")"; fi; done'
    )
    remote = ["sh", "-c", script, "kdive-sections", module_name]
    argv = build_ssh_argv(
        rootfs_profile=rootfs_profile,
        known_hosts_path=known_hosts_path,
        command=remote,
        command_timeout=timeout + SSH_TIMEOUT_GRACE_SECONDS,
    )
    result = ssh_runner.run(
        argv,
        timeout=timeout + SSH_TIMEOUT_GRACE_SECONDS,
        stdout_path=work_dir / "module-sections.out",
        stderr_path=work_dir / "module-sections.err",
    )
    stdout = getattr(result, "stdout", "") or ""
    # A connection failure (timeout / non-zero exit with no output) means the guest has no usable SSH
    # path to self-discover the addresses: report ssh_unreachable so the agent passes an explicit map.
    if not stdout.strip() and (getattr(result, "timed_out", False) or getattr(result, "exit_status", 0) != 0):
        raise ProviderDebugError(
            f"could not reach the target over SSH to read module {module_name!r} section addresses",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"code": "ssh_unreachable", "module": module_name},
        )
    if _NO_MODULE_SENTINEL in stdout:
        raise ProviderDebugError(
            f"module {module_name!r} is not loaded on the target (no /sys/module/{module_name}/sections)",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"code": "module_not_loaded", "module": module_name},
        )
    sections: dict[str, str] = {}
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            sections[parts[0]] = parts[1]
    if ".text" not in sections:
        raise ProviderDebugError(
            f"could not read the .text section address for module {module_name!r}",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={
                "code": "section_addresses_unreadable",
                "module": module_name,
                "hint": "/sys/module/<name>/sections/* are root-readable; use a root-capable SSH identity",
            },
        )
    return sections


def _default_module_ko_finder(build_tree: Path, module_name: str) -> Path | None:
    """Find the module object under the recorded build tree, trying the underscore AND hyphen
    spellings (the on-disk object keeps the source name, sysfs reports the normalized name) and
    preferring the ``.ko.debug`` variant. The result is confined under the build tree by rglob."""
    spellings = [module_name, module_name.replace("_", "-"), module_name.replace("-", "_")]
    for suffix in (".ko.debug", ".ko"):
        for spelling in spellings:
            for found in sorted(build_tree.rglob(f"{spelling}{suffix}")):
                return found
    return None


def debug_load_module_symbols_handler(
    *,
    artifact_root: Path,
    run_id: str,
    module: str,
    sections: dict[str, str] | None = None,
    ko_path: str | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    module_ko_finder: Callable[[Path, str], Path | None] | None = None,
    transaction: TransportTransaction | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    """Load a loadable module's symbols at runtime addresses so a breakpoint in the module resolves
    (ADR 0022). Sources the per-module section bases from guest sysfs over the injectable SshRunner
    (or an explicit ``sections`` override), resolves the ``.ko`` under the build tree, runs the
    engine's ``add-symbol-file``, and records an idempotent ``loaded_modules`` ledger."""
    store = ArtifactStore(artifact_root, create_root=False)
    if not (store.run_dir(run_id) / "manifest.json").is_file():
        return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
    if gdb_mi_engine is None or gdb_mi_sessions is None:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message="the gdb/MI engine is not available on this server instance",
            run_id=run_id,
            details={"code": "debug_engine_unavailable"},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    redactor = Redactor()
    finder = module_ko_finder or _default_module_ko_finder
    loaded_payload: dict[str, object] = {}
    try:
        with store.debug_lock(run_id):
            session = _load_active_debug_session(store, run_id, debug_session_id)
            _enforce_debug_ownership_fence(run_id=run_id, admission=admission, session_registry=session_registry)
            profile = _resolve_debug_profile(profile_name=session.selected_debug_profile, debug_profiles=debug_profiles)
            _ensure_debug_operation_enabled(profile, "debug.load_module_symbols")
            if not _MODULE_NAME_RE.match(module):
                return _configuration_failure(
                    run_id=run_id,
                    message=f"module must be a bare module identifier, got {module!r}",
                    details={"code": "invalid_module_name", "module": module},
                )
            attachment = gdb_mi_sessions.require(session.session_id)
            resolved_sections = _resolve_module_sections(
                store=store,
                run_id=run_id,
                module=module,
                sections=sections,
                ssh_runner=ssh_runner,
                rootfs_profiles=rootfs_profiles,
            )
            existing = session.loaded_modules.get(module)
            if existing is not None:
                if existing.get(".text") == resolved_sections.get(".text"):
                    return ToolResponse.success(
                        summary=f"module {module} symbols already loaded",
                        run_id=run_id,
                        data={"loaded_module": {"name": module, "sections": existing}},
                        suggested_next_actions=["debug.set_breakpoint"],
                    )
                return _configuration_failure(
                    run_id=run_id,
                    message=f"module {module} .text address changed since it was loaded; re-attach (debug.end_session)",
                    details={"code": "module_address_changed", "module": module},
                )
            build_tree = store.run_dir(run_id) / "build"
            resolved_ko = _resolve_module_ko(build_tree=build_tree, module=module, ko_path=ko_path, finder=finder)
            if resolved_ko is None:
                return _configuration_failure(
                    run_id=run_id,
                    message=f"no module object (.ko/.ko.debug) found for {module} under the build tree",
                    details={
                        "code": "module_object_not_found",
                        "module": module,
                        "spellings_tried": [module, module.replace("_", "-"), module.replace("-", "_")],
                    },
                )
            try:
                loaded = gdb_mi_engine.load_module_symbols(
                    attachment, name=module, ko_path=resolved_ko, sections=resolved_sections
                )
            except GdbMiError as exc:
                if exc.details.get("code") == "transport_stall":
                    reaped = gdb_mi_sessions.reap(session.session_id)
                    if reaped is not None:
                        with contextlib.suppress(Exception):
                            gdb_mi_engine.force_resume(reaped)
                    _teardown_stalled_debug_session(
                        run_id=run_id,
                        admission=admission,
                        session_registry=session_registry,
                        transaction=transaction,
                        session_guard=session_guard,
                    )
                    return ToolResponse.failure(
                        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                        message=redactor.redact_text(str(exc)),
                        run_id=run_id,
                        details={"code": "transport_stall"},
                        suggested_next_actions=["debug.start_session", "debug.kdb", "debug.introspect.run"],
                    )
                raise
            except ProviderDebugError:
                raise
            except Exception as exc:
                reaped = gdb_mi_sessions.reap(session.session_id)
                if reaped is not None:
                    with contextlib.suppress(Exception):
                        gdb_mi_engine.force_resume(reaped)
                return ToolResponse.failure(
                    category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                    message=redactor.redact_text(f"the gdb/MI engine faulted during debug.load_module_symbols: {exc}"),
                    run_id=run_id,
                    details={"code": "debug_engine_faulted"},
                    suggested_next_actions=["debug.end_session", "artifacts.get_manifest"],
                )
            ledger = dict(session.loaded_modules)
            ledger[module] = dict(loaded.sections)
            updated_session = session.model_copy(update={"loaded_modules": ledger})
            loaded_payload = loaded.model_dump(mode="json")
            _persist_mi_debug_session(store=store, run_id=run_id, session=updated_session)
            details = {
                **_debug_session_manifest_details(store=store, run_id=run_id, session=updated_session),
                **_preserved_debug_step_details(store, run_id),
                "loaded_module": loaded_payload,
            }
            store.record_step_result(
                run_id,
                StepResult(
                    step_name="debug",
                    status=StepStatus.SUCCEEDED,
                    summary="debug.load_module_symbols succeeded",
                    artifacts=_mi_session_artifacts(store=store, run_id=run_id, session=updated_session),
                    details=details,
                ),
                replace_succeeded=True,
            )
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    except ProviderDebugError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value(exc.details),
            suggested_next_actions=["debug.start_session", "artifacts.get_manifest"],
        )
    except GdbMiError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value(exc.details),
            suggested_next_actions=["debug.start_session", "artifacts.get_manifest"],
        )
    except OSError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=redactor.redact_text(f"failed to record debug.load_module_symbols: {exc}"),
            run_id=run_id,
            details={"code": "debug_session_op_record_failed"},
            suggested_next_actions=["debug.end_session", "artifacts.get_manifest"],
        )
    return ToolResponse.success(
        summary=f"debug.load_module_symbols loaded {module}",
        run_id=run_id,
        data=redactor.redact_value({"loaded_module": loaded_payload}),
        suggested_next_actions=["debug.set_breakpoint"],
    )


def _resolve_module_sections(
    *,
    store: ArtifactStore,
    run_id: str,
    module: str,
    sections: dict[str, str] | None,
    ssh_runner: SshRunner | None,
    rootfs_profiles: dict[str, RootfsProfile] | None,
) -> dict[str, str]:
    """Resolve the module's section addresses: an explicit ``sections`` override (no SSH) or a read
    from guest sysfs over SSH. Mirrors the introspect handlers' ``runner = ssh_runner or
    SubprocessSshRunner()`` — the injected runner is for tests; an unreachable guest surfaces
    ``ssh_unreachable`` from the read result, not from a missing runner."""
    if sections is not None:
        return {str(name): str(address) for name, address in sections.items()}
    runner: SshRunner = ssh_runner or SubprocessSshRunner()
    manifest = store.load_manifest(run_id)
    profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    rootfs_name = manifest.request.rootfs_profile
    rootfs_profile = manifest.resolved_rootfs_profile or profiles.get(rootfs_name)
    if rootfs_profile is None:
        raise ProviderDebugError(
            f"unknown rootfs profile {rootfs_name!r} for module section discovery",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"code": "unknown_rootfs_profile", "rootfs_profile": rootfs_name},
        )
    return _read_module_sections(
        ssh_runner=runner,
        rootfs_profile=rootfs_profile,
        known_hosts_path=store.run_dir(run_id) / "sensitive" / "known_hosts",
        module_name=module,
        work_dir=store.run_dir(run_id) / "debug",
    )


def _resolve_module_ko(
    *, build_tree: Path, module: str, ko_path: str | None, finder: Callable[[Path, str], Path | None]
) -> Path | None:
    """Resolve the module object path, confined under the build tree. An explicit ``ko_path`` must
    resolve under the build tree (PathSafetyError → CONFIGURATION_ERROR); otherwise the finder
    searches it."""
    if ko_path is not None:
        resolved = Path(ko_path).expanduser().resolve()
        try:
            if not resolved.is_relative_to(build_tree.resolve()):
                raise PathSafetyError(f"module object path escapes the build tree: {ko_path}")
        except PathSafetyError as exc:
            raise ProviderDebugError(
                str(exc), category=ErrorCategory.CONFIGURATION_ERROR, details={"code": "module_object_unsafe_path"}
            ) from exc
        return resolved if resolved.is_file() else None
    return finder(build_tree, module)


def _end_mi_debug_session(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    debug_profiles: dict[str, DebugProfile] | None,
    gdb_mi_engine: GdbMiEngine | None,
    gdb_mi_sessions: GdbMiSessionRegistry | None,
) -> ToolResponse:
    """Reap the live gdb/MI attachment (force_resume un-halts the kernel) and record the session
    ENDED. ADR 0021: end_session does NOT issue an interactive verb — it tears the live session down.
    Idempotent: re-ending an already-ended session reaps nothing and re-records ENDED. The legacy
    pre-detach fence is intentionally bypassed (this is the one op that force-ends a legacy stop)."""
    store = ArtifactStore(artifact_root, create_root=False)
    if not (store.run_dir(run_id) / "manifest.json").is_file():
        return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
    redactor = Redactor()
    try:
        with store.debug_lock(run_id):
            session = _load_active_debug_session(store, run_id, debug_session_id, allow_ended=True)
            profile = _resolve_debug_profile(profile_name=session.selected_debug_profile, debug_profiles=debug_profiles)
            _ensure_debug_operation_enabled(profile, "debug.end_session")
            ended = session.model_copy(
                update={"current_execution_state": DebugSessionState.ENDED, "ended_at": datetime.now(UTC).isoformat()}
            )
            # Durably record ENDED BEFORE the irreversible reap+force_resume. A disk/manifest fault
            # here must leave the live attachment intact and the durable record legitimately HALTED
            # (re-runnable), never resumed-yet-owned — which would strand target.run_tests on a kernel
            # that is actually running free with no live session left to act on.
            _persist_mi_debug_session(store=store, run_id=run_id, session=ended)
            details = {
                **_debug_session_manifest_details(store=store, run_id=run_id, session=ended),
                **_preserved_debug_step_details(store, run_id),
            }
            terminal = StepResult(
                step_name="debug",
                status=StepStatus.SUCCEEDED,
                summary="debug.end_session succeeded",
                artifacts=_mi_session_artifacts(store=store, run_id=run_id, session=ended),
                details=details,
            )
            store.record_step_result(run_id, terminal, replace_succeeded=True)
            # Point of no return: un-halt the kernel only after the ENDED bookkeeping is durable.
            if gdb_mi_sessions is not None:
                reaped = gdb_mi_sessions.reap(session.session_id)
                if reaped is not None and gdb_mi_engine is not None:
                    with contextlib.suppress(Exception):
                        gdb_mi_engine.force_resume(reaped)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    except OSError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=redactor.redact_text(f"failed to record debug.end_session: {exc}"),
            run_id=run_id,
            details={"code": "debug_session_end_record_failed"},
            suggested_next_actions=["debug.end_session", "artifacts.get_manifest"],
        )
    except ProviderDebugError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value(exc.details),
            suggested_next_actions=["debug.start_session", "artifacts.get_manifest"],
        )
    return ToolResponse.success(
        summary="debug.end_session succeeded",
        run_id=run_id,
        data=redactor.redact_value(details),
        artifacts=_redacted_artifacts(_mi_session_artifacts(store=store, run_id=run_id, session=ended), redactor),
        suggested_next_actions=["artifacts.get_manifest"],
    )


def debug_end_session_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    transaction: TransportTransaction | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    # Capture the transport binding BEFORE the reap rewrites the debug step (end_session records
    # `current_execution_state="ended"`).
    transport_session_id = (
        _recorded_transport_session_id(artifact_root=artifact_root, run_id=run_id) if transaction is not None else None
    )
    # end_session is the one stateful operation that may detach an unmanaged session. Detect it before
    # detach because the detach rewrites the manifest's debug step; managed sessions keep both a
    # durable ownership record and a transport_session_id, so transaction.close() governs them.
    is_legacy_session = _is_legacy_debug_session(
        admission=admission,
        session_registry=session_registry,
        transport_session_id=transport_session_id,
        run_id=run_id,
    )
    response = _end_mi_debug_session(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )
    # Clean detach only: close the transaction (release guard/lease, delete the durable record,
    # deregister the AdmissionHandle) AFTER the provider detach succeeded. A failed end leaves the
    # session owned so a retry/recovery can act on it. No transport binding ⇒ nothing to close.
    # force=True: a clean end_session resumed the kernel (the durable record was parked HALTED at
    # attach), so the target needs no recovery gating — skip the close-while-halted tombstone that
    # would otherwise leave the next attach `recovery_required`.
    if response.ok and transaction is not None and transport_session_id is not None:
        if session_guard is not None and session_registry is not None:
            tkey = TargetKey(provisioner="local-qemu", target_id=run_id)
            # Carry the real incarnation generation (not a 0 placeholder) so a #69/#70 teardown step
            # keyed on it fences correctly; fall back to 0 only if the record is already gone.
            ended_record = session_registry.read_record(tkey)
            ended_generation = ended_record.generation if ended_record is not None else 0
            session_guard.teardown(
                SessionGuardContext(
                    target_key=tkey,
                    generation=ended_generation,
                    session_id=transport_session_id,
                    reason="ended",
                ),
                close=lambda: transaction.close(transport_session_id, force=True),
                read_record=lambda: session_registry.read_record(tkey),
                force_reap=lambda: transaction.force_release(transport_session_id),
            )
        else:
            transaction.close(transport_session_id, force=True)
    # An unmanaged session bypasses the pre-detach fence only for this force-end operation. After a
    # successful detach, keep SSH/test work gated until a recovery transport open or reset clears the
    # recovery-required tombstone.
    if response.ok and is_legacy_session:
        admission = _require_value(admission, "admission service missing for legacy session recovery marker")
        session_registry = _require_value(
            session_registry, "session registry missing for legacy session recovery marker"
        )
        _mark_legacy_session_recovery_required(run_id=run_id, admission=admission, session_registry=session_registry)
    return response


def _workflow_handler_dependencies() -> WorkflowHandlerDependencies:
    return WorkflowHandlerDependencies(
        create_run_handler=create_run_handler,
        kernel_build_handler=kernel_build_handler,
        target_boot_handler=target_boot_handler,
        target_run_tests_handler=target_run_tests_handler,
        debug_start_session_handler=debug_start_session_handler,
        artifacts_collect_handler=artifacts_collect_handler,
    )


debug_read_registers_handler = partial(debug_read_registers_handler, operation_core=_debug_operation_response)
debug_read_symbol_handler = partial(debug_read_symbol_handler, operation_core=_debug_operation_response)
debug_read_memory_handler = partial(debug_read_memory_handler, operation_core=_debug_operation_response)
debug_evaluate_handler = partial(debug_evaluate_handler, operation_core=_debug_operation_response)
debug_set_breakpoint_handler = partial(debug_set_breakpoint_handler, operation_core=_debug_operation_response)
debug_set_watchpoint_handler = partial(debug_set_watchpoint_handler, operation_core=_debug_operation_response)
debug_clear_breakpoint_handler = partial(debug_clear_breakpoint_handler, operation_core=_debug_operation_response)
debug_clear_watchpoint_handler = partial(debug_clear_watchpoint_handler, operation_core=_debug_operation_response)
debug_list_breakpoints_handler = partial(debug_list_breakpoints_handler, operation_core=_debug_operation_response)
debug_backtrace_handler = partial(debug_backtrace_handler, operation_core=_debug_operation_response)
debug_list_variables_handler = partial(debug_list_variables_handler, operation_core=_debug_operation_response)
debug_continue_handler = partial(debug_continue_handler, operation_core=_debug_operation_response)
debug_step_handler = partial(debug_step_handler, operation_core=_debug_operation_response)
debug_next_handler = partial(debug_next_handler, operation_core=_debug_operation_response)
debug_finish_handler = partial(debug_finish_handler, operation_core=_debug_operation_response)
debug_interrupt_handler = partial(debug_interrupt_handler, operation_core=_debug_operation_response)


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

    @app.tool(name="host.check_prerequisites")
    def host_check_prerequisites(
        context: HostPrerequisitesContext | None = None,
        profiles: HostPrerequisitesProfiles | None = None,
        options: HostPrerequisitesOptions | None = None,
    ) -> dict[str, Any]:
        context = context or HostPrerequisitesContext()
        profiles = profiles or HostPrerequisitesProfiles()
        options = options or HostPrerequisitesOptions()
        return prerequisites_handler(
            artifact_root=Path(context.artifact_root or str(DEFAULT_ARTIFACT_ROOT)),
            source_path=options.source_path,
            enable_libvirt_check=options.enable_libvirt_check,
            build_profile=profiles.build_profile,
            target_profile=profiles.target_profile,
            rootfs_profile=profiles.rootfs_profile,
        ).model_dump(mode="json")

    kernel_tools.register_kernel_tools(
        app,
        default_artifact_root=DEFAULT_ARTIFACT_ROOT,
        sensitive_paths=sensitive_paths,
        create_run_handler=create_run_handler,
    )

    register_provider_tools(app)

    @app.tool(name="artifacts.get_manifest")
    def artifacts_get_manifest(run_id: str, artifact_root: str = str(DEFAULT_ARTIFACT_ROOT)) -> dict[str, Any]:
        return get_manifest_handler(artifact_root=Path(artifact_root), run_id=run_id).model_dump(mode="json")

    @app.tool(name="kernel.build")
    def kernel_build(
        context: KernelBuildContext,
        options: KernelBuildOptions | None = None,
    ) -> dict[str, Any]:
        options = options or KernelBuildOptions()
        return kernel_build_handler(
            artifact_root=Path(context.artifact_root or str(DEFAULT_ARTIFACT_ROOT)),
            run_id=context.run_id,
            build_profile=options.build_profile,
            force_rebuild=options.force_rebuild,
        ).model_dump(mode="json")

    target_tools.register_target_tools(
        app,
        default_artifact_root=DEFAULT_ARTIFACT_ROOT,
        sensitive_paths=sensitive_paths,
        admission=admission_service,
        target_boot_handler=target_boot_handler,
    )

    @app.tool(name="target.run_tests")
    def target_run_tests(
        context: TargetRunContext,
        options: TargetRunOptions | None = None,
    ) -> dict[str, Any]:
        options = options or TargetRunOptions()
        return target_run_tests_handler(
            artifact_root=Path(context.artifact_root or str(DEFAULT_ARTIFACT_ROOT)),
            run_id=context.run_id,
            test_suite=options.test_suite,
            commands=options.commands,
            force_rerun=options.force_rerun,
            attempt=options.attempt,
            admission=admission_service,
            session_registry=durable_registry,
        ).model_dump(mode="json")

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
