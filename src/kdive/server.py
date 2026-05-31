from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shlex
import tempfile
import time
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
from kdive.artifacts.manifest import RunManifest
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import (
    BootOverrides,
    BuildOverrides,
    DebugProfile,
    RootfsOverrides,
    RootfsProfile,
    ServerConfig,
)
from kdive.coordination.admission import (
    AdmissionService,
    SnapshotStore,
)
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
from kdive.default_profiles import DEFAULT_BUILD_PROFILES as _DEFAULT_BUILD_PROFILES
from kdive.default_profiles import DEFAULT_DEBUG_PROFILES as _DEFAULT_DEBUG_PROFILES
from kdive.default_profiles import (
    DEFAULT_ROOTFS_PROFILES,
)
from kdive.default_profiles import (
    DEFAULT_TARGET_PROFILES as _DEFAULT_TARGET_PROFILES,
)
from kdive.domain import (
    ArtifactRef,
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
)
from kdive.introspect.execution import (
    _rollback_introspect_admission as _rollback_introspect_admission,
)
from kdive.introspect.execution import _target_python_remote_argv as _INTROSPECT_TARGET_PYTHON_REMOTE_ARGV
from kdive.introspect.handlers import (
    debug_introspect_check_prerequisites_handler,
    debug_introspect_from_vmcore_handler,
    debug_introspect_from_vmcore_helper_handler,
    debug_introspect_helper_handler,
    debug_introspect_run_handler,
)
from kdive.introspect.tools import register_introspect_tools
from kdive.kernel import tools as kernel_tools
from kdive.kernel.handlers import _build_profile_from_manifest as _build_profile_from_manifest
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
from kdive.prereqs.drgn_probe import (
    UNKNOWN,
    USABLE,
    build_probe_checks,
    python_missing_checks,
)
from kdive.prereqs.handlers import prerequisites_handler
from kdive.prereqs.kdump_probe import build_kdump_checks
from kdive.prereqs.tools import register_prereq_tools
from kdive.providers.debug import (
    DebugSession,
    DebugSessionState,
    GdbMiEngine,
    GdbMiError,
    GdbMiSessionRegistry,
    ProviderDebugError,
)
from kdive.providers.local.debug.gdb_mi import (
    CANONICAL_PROBE_SYMBOL,
)
from kdive.providers.local.debug.gdb_mi import (
    GdbMiEngine as LocalGdbMiEngine,
)
from kdive.providers.local.debug.gdb_mi import (
    GdbMiSessionRegistry as LocalGdbMiSessionRegistry,
)
from kdive.providers.ssh import SshCommandResult, SshRunner, SubprocessSshRunner, build_ssh_argv
from kdive.safety.logging import SECRET_REGISTRY, configure_logging
from kdive.safety.paths import (
    PathSafetyError,
)
from kdive.safety.redaction import Redactor
from kdive.safety.runtime_locks import private_runtime_registry_dir
from kdive.safety.secrets import SecretReferenceKind
from kdive.seams.break_policy import ReferenceBreakPolicy
from kdive.seams.guard import (
    InProcessStopCapableGuard,
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
    ConsoleKind,
    TargetKey,
)
from kdive.symbols.build_id import BuildIdReadError
from kdive.symbols.verify import (
    BUILD_ID_RE,
    ProvenanceMismatch,
    verify_vmlinux_provenance,
)
from kdive.target import tools as target_tools
from kdive.target.handlers import DEFAULT_TEST_SUITES as _DEFAULT_TEST_SUITES
from kdive.target.handlers import _admit_run_tests_ssh_tier as _admit_run_tests_ssh_tier
from kdive.target.handlers import _artifact_run_relative_ref as _artifact_run_relative_ref
from kdive.target.handlers import _boot_under_locks as _boot_under_locks
from kdive.target.handlers import _capture_kernel_provenance as _capture_kernel_provenance
from kdive.target.handlers import _find_artifact as _find_artifact
from kdive.target.handlers import _find_kernel_image as _find_kernel_image
from kdive.target.handlers import _publish_boot_ready_snapshot as _publish_boot_ready_snapshot
from kdive.target.handlers import _resolve_boot_inputs as _resolve_boot_inputs
from kdive.target.handlers import _ssh_host_is_unset_or_loopback as _ssh_host_is_unset_or_loopback
from kdive.target.handlers import _validated_guest_ip as _validated_guest_ip
from kdive.target.handlers import target_boot_handler, target_run_tests_handler
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
    _require_snapshot,
    _resolve_debug_profile,
    transport_close_handler,
    transport_inject_break_handler,
    transport_open_handler,
)
from kdive.transport.handlers import (
    _halt_debug_transport as _halt_debug_transport,
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
DEFAULT_BUILD_PROFILES = _DEFAULT_BUILD_PROFILES
DEFAULT_DEBUG_PROFILES = _DEFAULT_DEBUG_PROFILES
DEFAULT_TARGET_PROFILES = _DEFAULT_TARGET_PROFILES
DEFAULT_TEST_SUITES = _DEFAULT_TEST_SUITES
_target_python_remote_argv = _INTROSPECT_TARGET_PYTHON_REMOTE_ARGV
CreateRunContext = kernel_tools.CreateRunContext
CreateRunOptions = kernel_tools.CreateRunOptions
CreateRunProfiles = kernel_tools.CreateRunProfiles

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


SERVER_CONFIG_ENV_VAR = "KDIVE_CONFIG"
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


def _configuration_failure(*, run_id: str, message: str, details: dict[str, Any] | None = None) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
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
