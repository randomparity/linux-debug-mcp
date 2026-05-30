from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shlex
import shutil
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from linux_debug_mcp.artifacts.manifest import BootAttempt, RunManifest
from linux_debug_mcp.artifacts.store import ArtifactStore, ManifestStateError
from linux_debug_mcp.config import (
    ALLOWED_DEBUG_OPERATIONS,
    INTROSPECT_DESTRUCTIVE_PERMISSIONS,
    MAX_INTROSPECT_CALLS_PER_RUN,
    PRELUDE_WARNING_FRACTION_PCT,
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
    merge_config_lines,
    merge_kernel_args,
    missing_destructive_permissions,
)
from linux_debug_mcp.coordination.admission import (
    AdmissionError,
    AdmissionHandle,
    AdmissionService,
    SnapshotStore,
    TargetSnapshot,
)
from linux_debug_mcp.coordination.endpoint_safety import EndpointSafetyError
from linux_debug_mcp.coordination.exec_probe import probe_execution_state, probe_rsp_halted
from linux_debug_mcp.coordination.lease import ConsoleLeaseManager
from linux_debug_mcp.coordination.registry import OrphanReap, RecoveryTombstone, SessionRegistry
from linux_debug_mcp.coordination.transaction import TransportTransaction
from linux_debug_mcp.domain import (
    ArtifactRef,
    DebugIntrospectCheckPrerequisitesRequest,
    DebugIntrospectFromVmcoreHelperRequest,
    DebugIntrospectFromVmcoreRequest,
    DebugIntrospectHelperRequest,
    DebugIntrospectRunRequest,
    ErrorCategory,
    PrerequisiteCheck,
    PrerequisiteStatus,
    RunRequest,
    StepResult,
    StepStatus,
    ToolResponse,
)
from linux_debug_mcp.introspect_helpers import HELPER_REGISTRY, HelperSpec
from linux_debug_mcp.logging import SECRET_REGISTRY, configure_logging
from linux_debug_mcp.prereqs.checks import check_prerequisites
from linux_debug_mcp.prereqs.drgn_probe import (
    PROBE_SCRIPT,
    UNKNOWN,
    USABLE,
    build_probe_checks,
    python_missing_checks,
)
from linux_debug_mcp.providers.contracts import (
    ConsoleReadRequest,
    ConsoleSessionRequest,
    ConsoleWriteRequest,
    HardwareControlRequest,
    ProviderRequest,
    ProvisioningRequest,
    RealBootRequest,
    RemoteArtifactSyncRequest,
    RemoteBuildRequest,
    ReservationReleaseRequest,
    ReservationRequest,
    ReserveProvisionBootRequest,
)
from linux_debug_mcp.providers.gdb_mi import (
    CANONICAL_PROBE_SYMBOL,
    GdbMiAttachment,
    GdbMiEngine,
    GdbMiError,
    GdbMiSessionRegistry,
)
from linux_debug_mcp.providers.libvirt_qemu import LibvirtQemuProvider, ProviderBootError
from linux_debug_mcp.providers.local_drgn_introspect import (
    SCRIPT_BYTE_CAP,
    TARGET_PYTHON_ARGV,
    WrapperRenderError,
    render_vmcore_wrapper,
    render_vmcore_wrapper_skeleton,
    render_wrapper,
    render_wrapper_skeleton,
    user_script_sha256,
)
from linux_debug_mcp.providers.local_kernel_build import (
    BuildIdMissing,
    LocalKernelBuildProvider,
    ReadelfUnavailable,
)
from linux_debug_mcp.providers.local_ssh_tests import (
    LocalSshTestProvider,
    SshCommandResult,
    SshRunner,
    SubprocessSshRunner,
    TestExecutionResult,
    TestPlan,
    build_ssh_argv,
)
from linux_debug_mcp.providers.qemu_gdbstub import (
    DebugSession,
    ProviderDebugError,
)
from linux_debug_mcp.providers.registry import ProviderRegistry
from linux_debug_mcp.providers.stubs import (
    future_not_implemented_response,
    select_future_provider,
)
from linux_debug_mcp.safety.paths import (
    PathSafetyError,
    confine_run_relative,
    validate_rootfs_source,
    validate_source_path,
)
from linux_debug_mcp.safety.redaction import Redactor
from linux_debug_mcp.safety.runtime_locks import private_runtime_registry_dir
from linux_debug_mcp.safety.secrets import SecretReferenceKind
from linux_debug_mcp.seams.break_policy import ReferenceBreakPolicy
from linux_debug_mcp.seams.guard import (
    GuardConflict,
    InProcessStopCapableGuard,
    PreconditionError,
    SessionGuard,
    SessionGuardContext,
)
from linux_debug_mcp.seams.lifecycle import (
    InProcessLifecycleDispatcher,
    LifecycleDispatcher,
    LifecycleEvent,
    LifecycleKind,
)
from linux_debug_mcp.seams.secrets import (
    EnvSecretsBackend,
    ExternalSecretsBackend,
    KeyringSecretsBackend,
    SecretsBackend,
    SecretsResolutionError,
    SecretsStore,
)
from linux_debug_mcp.seams.target import (
    BreakHint,
    ConsoleKind,
    KernelProvenance,
    PlatformMetadata,
    TargetKey,
    publish_ready_snapshot,
)
from linux_debug_mcp.symbols.build_id import BuildIdReadError, read_elf_build_id
from linux_debug_mcp.symbols.resolve import SymbolResolutionError, resolve_symbols
from linux_debug_mcp.symbols.verify import (
    BUILD_ID_RE,
    ProvenanceMismatch,
    verify_build_id,
    verify_vmlinux_provenance,
)
from linux_debug_mcp.transport.base import (
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
from linux_debug_mcp.transport.break_inject import InjectBreakError, inject_break
from linux_debug_mcp.transport.proxy import AgentProxyBackend
from linux_debug_mcp.transport.qemu_gdbstub import QemuGdbstubTransport

logger = logging.getLogger(__name__)

DEFAULT_ARTIFACT_ROOT = Path(".linux-debug-mcp/runs")
SERVER_CONFIG_ENV_VAR = "LINUX_DEBUG_MCP_CONFIG"
DEFAULT_BUILD_PROFILES = {
    "x86_64-default": BuildProfile(name="x86_64-default", architecture="x86_64"),
}
DEFAULT_TARGET_PROFILES = {
    "local-qemu": TargetProfile(
        name="local-qemu",
        architecture="x86_64",
        target_ref="mcp-linux-debug-dev",
        managed_domain=True,
        managed_domain_prefix="mcp-linux-debug-",
        libvirt_uri="qemu:///system",
    ),
    "local-qemu-debug": TargetProfile(
        name="local-qemu-debug",
        architecture="x86_64",
        target_ref="mcp-linux-debug-dev-debug",
        managed_domain=True,
        managed_domain_prefix="mcp-linux-debug-",
        libvirt_uri="qemu:///system",
        debug_gdbstub=True,
        gdbstub_endpoint="127.0.0.1:1234",
    ),
}
DEFAULT_ROOTFS_PROFILES = {
    "minimal": RootfsProfile(
        name="minimal",
        source="/var/lib/linux-debug-mcp/rootfs/minimal.qcow2",
        mutability="read_only",
        readiness_marker="linux-debug-mcp-ready",
        ssh_host="127.0.0.1",
        ssh_port=22,
        ssh_user="root",
    ),
}
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
DEFAULT_DEBUG_PROFILES = {
    "qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default"),
}
DEBUG_METHOD_OPERATIONS = {
    "read_registers": "debug.read_registers",
    "read_symbol": "debug.read_symbol",
    "read_memory": "debug.read_memory",
    "evaluate": "debug.evaluate",
    "set_breakpoint": "debug.set_breakpoint",
    "set_watchpoint": "debug.set_watchpoint",
    "clear_breakpoint": "debug.clear_breakpoint",
    "clear_watchpoint": "debug.clear_watchpoint",
    "list_breakpoints": "debug.list_breakpoints",
    "backtrace": "debug.backtrace",
    "list_variables": "debug.list_variables",
    "continue_execution": "debug.continue",
    "step": "debug.step",
    "next": "debug.next",
    "finish": "debug.finish",
    "interrupt": "debug.interrupt",
    "end_session": "debug.end_session",
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


def _target_python_remote_argv(*, timeout_seconds: int, use_sudo: bool) -> list[str]:
    """Build the remote argv shared by the probe and the introspect runner.

    Spec §4 shared-interpreter invariant: both ``debug.introspect.run`` and
    ``debug.introspect.check_prerequisites`` must run the interpreter through a
    byte-identical SSH + interpreter invocation, *including* the privilege
    prefix. A non-root SSH login runs the interpreter under ``sudo`` in both
    paths so the probe checks drgn/debuginfo at the same privilege level the
    runner will use.
    """
    argv = ["timeout", "--kill-after=2s", f"{timeout_seconds}s"]
    if use_sudo:
        argv.append("sudo")
    argv.extend(TARGET_PYTHON_ARGV)
    return argv


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


def _record_terminal_build_result(
    store: ArtifactStore,
    run_id: str,
    result: StepResult,
    *,
    attempts: int = 5,
    initial_delay_seconds: float = 0.01,
) -> None:
    delay_seconds = initial_delay_seconds
    for attempt in range(attempts):
        try:
            store.record_step_result(run_id, result)
            return
        except ManifestStateError as exc:
            if "manifest is locked" not in str(exc) or attempt == attempts - 1:
                raise
            time.sleep(delay_seconds)
            delay_seconds *= 2


_INTROSPECT_STEP_NAME_RE = re.compile(r"^introspect:")


def _count_introspect_calls(manifest: RunManifest) -> int:
    """Spec §5.2 step 4a / R3-F5. Named so tests can monkey-patch it."""
    return sum(1 for name in manifest.step_results if _INTROSPECT_STEP_NAME_RE.match(name))


def _redact_and_truncate(redactor: Redactor, text: str, cap: int = 256) -> str:
    """Spec §5.2 step 5, step 9, §6.3 — redact BEFORE truncate (R2-F3).

    The order matters: ``Redactor.redact_text`` does literal substring
    replacement against ``secret_values``, so truncating first could split
    an ``ssh_key_ref`` mid-secret and leave an unmatched prefix in the
    diagnostic.
    """
    redacted = redactor.redact_text(text)
    return redacted[:cap]


def _head_tail(s: str, *, head: int, tail: int) -> str:
    """Spec §3.2: snippet helper — head N + middle marker + tail N."""
    if len(s) <= head + tail:
        return s
    return f"{s[:head]}\n…[truncated]…\n{s[-tail:]}"


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _record_terminal_introspect_result(
    store: ArtifactStore,
    run_id: str,
    result: StepResult,
    *,
    attempts: int = 5,
    initial_delay_seconds: float = 0.01,
) -> None:
    """Clone of ``_record_terminal_build_result`` that appends rather than
    replaces. Spec §5.2 step 13: every ``introspect:<call_id>`` is a fresh
    entry — collisions are an internal bug (UUIDv4).
    """
    delay_seconds = initial_delay_seconds
    for attempt in range(attempts):
        try:
            store.record_step_result(run_id, result, append=True)
            return
        except ManifestStateError as exc:
            if "manifest is locked" not in str(exc) or attempt == attempts - 1:
                raise
            time.sleep(delay_seconds)
            delay_seconds *= 2


def _record_introspect_failure(
    *,
    store: ArtifactStore,
    run_id: str,
    call_id: str,
    category: ErrorCategory,
    code: str,
    message: str,
    agent_dir: Path,
    sensitive_dir: Path,
    redactor: Redactor,
    raw_stderr: str,
    ssh_exit: int,
    request_timeout_seconds: int,
    duration_ms: int,
    ssh_user: str | None,
    outcome_status_for_forensics: str | None,
    include_stdout_json: bool = False,
    redacted_payload: dict[str, Any] | None = None,
    allow_write: bool = False,
    acknowledged_permissions: list[str] | None = None,
) -> ToolResponse:
    """Persist artifacts, record the FAILED step, return ``ToolResponse.failure``.

    ``request_timeout_seconds`` is the caller's *budget* (spec §6.2);
    ``duration_ms`` is the measured wall-clock duration. Keeping success and
    failure record shapes symmetric lets forensic tooling treat the two
    paths uniformly. ``ssh_user`` is required (no "unknown" placeholder).

    Note (R6-F3): the ``WrapperRenderError`` path in Step 9.5 does NOT call
    this helper — the render failure happens before SSH runs, so there is
    no stderr/stdout text to redact. That path writes the FAILED
    ``StepResult`` directly.
    """
    (agent_dir / "stderr.log").write_text(redactor.redact_text(raw_stderr), encoding="utf-8")
    if include_stdout_json and redacted_payload is not None:
        (agent_dir / "stdout.json").write_text(json.dumps(redacted_payload), encoding="utf-8")
    artifacts: list[ArtifactRef] = [
        ArtifactRef(path=str(agent_dir / "request.json"), kind="application/json"),
        ArtifactRef(path=str(agent_dir / "wrapper.skeleton.py"), kind="text/x-python"),
        ArtifactRef(path=str(sensitive_dir / "wrapper.py"), kind="text/x-python", sensitive=True),
        ArtifactRef(path=str(agent_dir / "stderr.log"), kind="text/plain"),
    ]
    if include_stdout_json:
        artifacts.append(ArtifactRef(path=str(agent_dir / "stdout.json"), kind="application/json"))
    # Iter-2 finding 2: SSH now writes raw stdout/stderr straight to
    # sensitive/, so register both for forensics on every failure path
    # (subject to existence — admit-time / preflight failures skip SSH).
    for raw_name in ("stdout.raw", "stderr.raw"):
        raw_path = sensitive_dir / raw_name
        if raw_path.exists():
            artifacts.append(
                ArtifactRef(
                    path=str(raw_path),
                    kind="application/octet-stream",
                    sensitive=True,
                )
            )
    details: dict[str, Any] = {
        "call_id": call_id,
        "timeout_seconds": request_timeout_seconds,
        "duration_ms": duration_ms,
        "wrapper_exit_code": ssh_exit,
        "outcome_status": outcome_status_for_forensics,
        "code": code,
    }
    # ssh_user is None on the vmcore path (no SSH user); omit the key rather
    # than recording a misleading `ssh_user: null` on a non-SSH step.
    if ssh_user is not None:
        details["ssh_user"] = ssh_user
    # ADR 0011 / #56 audit: record allow_write on every live call so failed/blocked
    # write-mode calls remain visible in the manifest; record the satisfied required
    # permissions only when write mode was used.
    details["allow_write"] = allow_write
    if allow_write:
        details["acknowledged_permissions"] = list(acknowledged_permissions or [])
    step = StepResult(
        step_name=f"introspect:{call_id}",
        status=StepStatus.FAILED,
        summary=message,
        artifacts=artifacts,
        details=details,
    )
    _record_terminal_introspect_result(store, run_id, step)
    public = [a for a in artifacts if not a.sensitive]
    return ToolResponse.failure(
        category=category,
        run_id=run_id,
        message=message,
        details={"code": code, "call_id": call_id, "outcome_status": outcome_status_for_forensics},
        artifacts=public,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _redacted_boot_data(data: dict[str, Any]) -> dict[str, Any]:
    return Redactor().redact_value(data)


def _recorded_boot_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.success(
        summary=result.summary,
        run_id=run_id,
        data=_redacted_boot_data(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
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


def _redacted_artifacts(artifacts: list[ArtifactRef], redactor: Redactor | None = None) -> list[ArtifactRef]:
    redactor = redactor or Redactor()
    return [
        ArtifactRef.model_validate(redactor.redact_value(artifact.model_dump(mode="json"))) for artifact in artifacts
    ]


def _recorded_collect_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    redactor = Redactor()
    return ToolResponse.success(
        summary=redactor.redact_text(result.summary),
        run_id=run_id,
        data=redactor.redact_value(result.details),
        artifacts=_redacted_artifacts(result.artifacts, redactor),
        suggested_next_actions=["artifacts.get_manifest"],
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


def _debug_session_details_from_result(result: StepResult, *, allow_ended: bool = False) -> dict[str, Any] | None:
    if result.status != StepStatus.SUCCEEDED:
        return None
    if not allow_ended and result.details.get("current_execution_state") == "ended":
        return None
    return result.details


def _debug_session_manifest_details(*, store: ArtifactStore, run_id: str, session: DebugSession) -> dict[str, Any]:
    details: dict[str, Any] = {
        "debug_session_id": session.session_id,
        "session_path": str(store.run_dir(run_id) / "debug" / "sessions" / f"{session.session_id}.json"),
        "current_execution_state": session.current_execution_state,
        "gdbstub_endpoint": session.gdbstub_endpoint,
        "transcript_path": session.transcript_path,
        "command_metadata_path": session.command_metadata_path,
        "latest_summary_path": session.latest_summary_path,
        "symbol_identity_validation": session.symbol_identity_validation,
        "breakpoints": session.breakpoints,
        "controller_mode": session.controller_mode,
        "active_controller_pid": session.active_controller_pid,
        "controller_last_observed_state": session.controller_last_observed_state,
    }
    if session.ended_at is not None:
        details["ended_at"] = session.ended_at
    return details


def _ensure_debug_operation_enabled(profile: DebugProfile, operation: str) -> None:
    if operation not in set(ALLOWED_DEBUG_OPERATIONS):
        raise ProviderDebugError(
            "unsupported debug operation",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"operation": operation},
        )
    if operation not in profile.enabled_operations:
        raise ProviderDebugError(
            "debug operation is disabled by selected profile",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"debug_profile": profile.name, "operation": operation},
        )


def _resolve_debug_profile(
    *,
    profile_name: str,
    debug_profiles: dict[str, DebugProfile] | None,
) -> DebugProfile:
    profiles = debug_profiles if debug_profiles is not None else DEFAULT_DEBUG_PROFILES
    try:
        return profiles[profile_name]
    except KeyError as exc:
        raise ProviderDebugError(
            "unknown debug profile",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"debug_profile": profile_name},
        ) from exc


def _require_run_debug_path(path: Path, *, run_dir: Path, description: str) -> Path:
    try:
        resolved = path.expanduser().resolve()
        debug_dir = (run_dir / "debug").expanduser().resolve()
    except OSError as exc:
        raise ProviderDebugError(
            f"{description} is invalid",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"path": str(path), "error": str(exc)},
        ) from exc
    if not resolved.is_relative_to(debug_dir):
        raise ProviderDebugError(
            f"{description} must be inside the run debug directory",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"path": str(path), "debug_dir": str(debug_dir)},
        )
    return resolved


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


@dataclass(frozen=True)
class _ResolvedProfiles:
    build: BuildProfile
    target: TargetProfile
    rootfs: RootfsProfile


_ProfileT = TypeVar("_ProfileT", BuildProfile, TargetProfile, RootfsProfile)


def _resolve_base_profile(
    kind: str,
    *,
    name: str | None,
    spec: dict[str, Any] | None,
    registry: dict[str, _ProfileT],
    model: type[_ProfileT],
) -> _ProfileT:
    """Resolve a base profile from exactly one of a named registry entry or an inline spec."""
    if name is not None and spec is not None:
        raise ValueError(f"provide either {kind}_profile or {kind}_profile_spec, not both")
    if name is None and spec is None:
        raise ValueError(f"{kind}_profile or {kind}_profile_spec is required")
    if spec is not None:
        try:
            return model.model_validate(spec)
        except ValidationError as exc:
            raise ValueError(f"invalid {kind}_profile_spec: {exc.error_count()} validation error(s)") from exc
    if name not in registry:
        raise ValueError(f"unknown profile: {name}")
    return registry[name]


def _resolve_initial_profiles(
    *,
    source_path: Path,
    sensitive_paths: list[Path],
    build_profile: str | None,
    build_profile_spec: dict[str, Any] | None,
    target_profile: str | None,
    target_profile_spec: dict[str, Any] | None,
    rootfs_profile: str | None,
    rootfs_profile_spec: dict[str, Any] | None,
    build_overrides: BuildOverrides | None,
    boot_overrides: BootOverrides | None,
) -> _ResolvedProfiles:
    base_build = _resolve_base_profile(
        "build", name=build_profile, spec=build_profile_spec, registry=DEFAULT_BUILD_PROFILES, model=BuildProfile
    )
    base_target = _resolve_base_profile(
        "target", name=target_profile, spec=target_profile_spec, registry=DEFAULT_TARGET_PROFILES, model=TargetProfile
    )
    base_rootfs = _resolve_base_profile(
        "rootfs", name=rootfs_profile, spec=rootfs_profile_spec, registry=DEFAULT_ROOTFS_PROFILES, model=RootfsProfile
    )

    # model_copy(update=...) skips field validators, which is safe here: both base and
    # override values were validated at construction (BuildProfile/BootOverrides), and the
    # merges only union dicts, de-dup kernel-arg tokens by key, or merge config_lines by
    # symbol (last wins) over already-validated values, so the result stays valid.
    resolved_build = base_build
    if build_overrides is not None:
        build_update: dict[str, object] = {}
        if build_overrides.make_variables:
            build_update["make_variables"] = {**base_build.make_variables, **build_overrides.make_variables}
        if build_overrides.config_lines:
            build_update["config_lines"] = merge_config_lines(base_build.config_lines, build_overrides.config_lines)
        if build_update:
            resolved_build = base_build.model_copy(update=build_update)

    # An inline rootfs spec carries an agent-controlled `source`. Subject it to the same
    # path-safety guards as a rootfs_source override (sensitive paths, source-tree overlap,
    # shell/control chars, /, $HOME, must-be-a-file) so inline profiles cannot bypass them, and
    # freeze the resolved (symlink-canonical) path that was validated.
    if rootfs_profile_spec is not None:
        validated_source = validate_rootfs_source(
            Path(base_rootfs.source),
            source_paths=[source_path],
            sensitive_paths=sensitive_paths,
        )
        base_rootfs = base_rootfs.model_copy(update={"source": str(validated_source)})

    # Fail-fast on a bad rootfs override at run creation; the resolved rootfs is re-derived at boot.
    if boot_overrides is not None and boot_overrides.rootfs_source is not None:
        validate_rootfs_source(
            Path(boot_overrides.rootfs_source),
            source_paths=[source_path],
            sensitive_paths=sensitive_paths,
        )
    return _ResolvedProfiles(build=resolved_build, target=base_target, rootfs=base_rootfs)


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
    build_profile_spec: dict[str, Any] | None = None,
    target_profile_spec: dict[str, Any] | None = None,
    rootfs_profile_spec: dict[str, Any] | None = None,
) -> ToolResponse:
    try:
        resolved_source_path = validate_source_path(Path(source_path))
    except PathSafetyError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
            details={"source_path": source_path},
        )
    try:
        resolved = _resolve_initial_profiles(
            source_path=Path(resolved_source_path),
            # Operator-configured sensitive paths (from a loaded ServerConfig, threaded in by
            # create_app) are enforced here alongside the built-in validate_rootfs_source guards
            # (reject /, $HOME, non-file, source-tree overlap, shell/control chars,
            # symlink-resolved). When no config is loaded this is empty and only the built-ins apply.
            sensitive_paths=sensitive_paths or [],
            build_profile=build_profile,
            build_profile_spec=build_profile_spec,
            target_profile=target_profile,
            target_profile_spec=target_profile_spec,
            rootfs_profile=rootfs_profile,
            rootfs_profile_spec=rootfs_profile_spec,
            build_overrides=build_overrides,
            boot_overrides=boot_overrides,
        )
    except (PathSafetyError, ValueError) as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message=str(exc),
        )
    request = RunRequest(
        source_path=str(resolved_source_path),
        build_profile=resolved.build.name,
        target_profile=resolved.target.name,
        rootfs_profile=resolved.rootfs.name,
        debug_profile=debug_profile,
        test_suite=test_suite,
        run_id=run_id,
        build_overrides=build_overrides,
        boot_overrides=boot_overrides,
    )
    try:
        store = ArtifactStore(artifact_root, source_paths=[resolved_source_path])
        # The build profile is always frozen (named base + overrides). Target/rootfs are frozen
        # only when supplied inline, since named profiles are re-resolved by name at boot.
        manifest = store.create_run(
            request,
            resolved_build_profile=resolved.build,
            resolved_target_profile=resolved.target if target_profile_spec is not None else None,
            resolved_rootfs_profile=resolved.rootfs if rootfs_profile_spec is not None else None,
        )
    except ManifestStateError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=str(exc),
            details={"artifact_root": str(artifact_root)},
        )
    manifest_path = artifact_root.expanduser().resolve() / manifest.run_id / "manifest.json"
    return ToolResponse.success(
        summary=f"created run {manifest.run_id}",
        run_id=manifest.run_id,
        data={
            "manifest": Redactor().redact_value(manifest.model_dump(mode="json")),
            "manifest_path": str(manifest_path),
        },
        artifacts=[ArtifactRef(path=str(manifest_path), kind="manifest")],
        suggested_next_actions=["kernel.build"],
    )


def get_manifest_handler(*, artifact_root: Path, run_id: str) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    return ToolResponse.success(
        summary=f"loaded manifest for {run_id}",
        run_id=run_id,
        data={"manifest": Redactor().redact_value(manifest.model_dump(mode="json"))},
        artifacts=[
            ArtifactRef(path=str(artifact_root.expanduser().resolve() / run_id / "manifest.json"), kind="manifest")
        ],
    )


def prerequisites_handler(
    *,
    artifact_root: Path,
    source_path: str | None,
    enable_libvirt_check: bool = False,
) -> ToolResponse:
    checks = check_prerequisites(
        artifact_root=artifact_root,
        source_path=Path(source_path) if source_path else None,
        enable_libvirt_check=enable_libvirt_check,
    )
    failed = [check for check in checks if check.status == "failed"]
    return ToolResponse.success(
        summary=f"{len(failed)} prerequisite checks failed",
        data={"checks": [check.model_dump(mode="json") for check in checks]},
        suggested_next_actions=["Fix failed checks", "kernel.create_run"],
    )


def list_providers_handler() -> ToolResponse:
    registry = ProviderRegistry.with_defaults()
    providers = []
    for provider in registry.list_capabilities():
        provider_payload = provider.model_dump(mode="json")
        plugin_metadata = registry.provider_plugin_metadata(provider.provider_name)
        if plugin_metadata is not None:
            provider_payload["plugin"] = plugin_metadata.model_dump(mode="json")
            provider_payload["documentation_paths"] = list(plugin_metadata.documentation_paths)
        providers.append(provider_payload)
    return ToolResponse.success(
        summary="listed provider capabilities",
        data={"providers": providers},
    )


def _validation_error_details(exc: ValidationError) -> dict[str, Any]:
    return {
        "validation_errors": [
            {
                "field": ".".join(str(part) for part in error.get("loc", ())),
                "type": error.get("type", "validation_error"),
            }
            for error in exc.errors(include_input=False)
        ]
    }


def _future_stub_handler(
    *,
    contract: type[ProviderRequest],
    operation: str,
    payload: dict[str, Any],
    registry: ProviderRegistry | None = None,
) -> ToolResponse:
    redactor = Redactor()
    try:
        request = contract(**payload)
    except ValidationError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="future provider request failed validation",
            details=redactor.redact_value(_validation_error_details(exc)),
            suggested_next_actions=["providers.list"],
        )

    registry = registry or ProviderRegistry.with_defaults()
    provider = select_future_provider(
        registry,
        operation=operation,
        architecture=request.architecture,
        provider_name=request.provider_name,
    )
    if isinstance(provider, ToolResponse):
        return provider

    plugin_metadata = registry.provider_plugin_metadata(provider.provider_name)
    documentation_paths = (
        list(plugin_metadata.documentation_paths) if plugin_metadata is not None else list(provider.documentation_paths)
    )
    return future_not_implemented_response(
        provider=provider,
        operation=operation,
        architecture=request.architecture,
        documentation_paths=documentation_paths,
    )


def remote_build_kernel_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=RemoteBuildRequest,
        operation="remote.build_kernel",
        payload=kwargs,
        registry=registry,
    )


def remote_sync_artifacts_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=RemoteArtifactSyncRequest,
        operation="remote.sync_artifacts",
        payload=kwargs,
        registry=registry,
    )


def reservation_request_host_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ReservationRequest,
        operation="reservation.request_host",
        payload=kwargs,
        registry=registry,
    )


def reservation_release_host_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ReservationReleaseRequest,
        operation="reservation.release_host",
        payload=kwargs,
        registry=registry,
    )


def provision_prepare_target_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ProvisioningRequest,
        operation="provision.prepare_target",
        payload=kwargs,
        registry=registry,
    )


def hardware_power_control_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=HardwareControlRequest,
        operation="hardware.power_control",
        payload=kwargs,
        registry=registry,
    )


def hardware_boot_kernel_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=RealBootRequest,
        operation="hardware.boot_kernel",
        payload=kwargs,
        registry=registry,
    )


def console_open_session_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ConsoleSessionRequest,
        operation="console.open_session",
        payload=kwargs,
        registry=registry,
    )


def console_read_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ConsoleReadRequest,
        operation="console.read",
        payload=kwargs,
        registry=registry,
    )


def console_write_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ConsoleWriteRequest,
        operation="console.write",
        payload=kwargs,
        registry=registry,
    )


def workflow_reserve_provision_boot_handler(*, registry: ProviderRegistry | None = None, **kwargs: Any) -> ToolResponse:
    return _future_stub_handler(
        contract=ReserveProvisionBootRequest,
        operation="workflow.reserve_provision_boot",
        payload=kwargs,
        registry=registry,
    )


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
                # Plan review finding 6 / spec §7 R2-F6: exc.artifacts carries the
                # build artifacts the provider already produced (vmlinux, .config,
                # build-log). Persist them in the FAILED StepResult so operators can
                # inspect why readelf came up empty without re-running the build.
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
                # Plan review finding 6 / spec §7 R2-F6: same artifact-preservation
                # rationale as ReadelfUnavailable above.
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

    requested_target_profile = target_profile or manifest.request.target_profile
    requested_rootfs_profile = rootfs_profile or manifest.request.rootfs_profile
    if requested_target_profile != manifest.request.target_profile:
        return _configuration_failure(
            run_id=run_id,
            message="target_profile must match the immutable run manifest request",
            details={
                "requested_profile": requested_target_profile,
                "manifest_profile": manifest.request.target_profile,
            },
        )
    if requested_rootfs_profile != manifest.request.rootfs_profile:
        return _configuration_failure(
            run_id=run_id,
            message="rootfs_profile must match the immutable run manifest request",
            details={
                "requested_profile": requested_rootfs_profile,
                "manifest_profile": manifest.request.rootfs_profile,
            },
        )

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
            return _configuration_failure(run_id=run_id, message=f"unknown target profile: {requested_target_profile}")
    if manifest.resolved_rootfs_profile is not None:
        resolved_rootfs_profile = manifest.resolved_rootfs_profile
    else:
        try:
            resolved_rootfs_profile = rootfs_profiles[requested_rootfs_profile]
        except KeyError:
            return _configuration_failure(run_id=run_id, message=f"unknown rootfs profile: {requested_rootfs_profile}")
    if resolved_target_profile.libvirt_uri is None and default_libvirt_uri is not None:
        resolved_target_profile = resolved_target_profile.model_copy(update={"libvirt_uri": default_libvirt_uri})
    if resolved_target_profile.target_ref is None:
        return _configuration_failure(run_id=run_id, message="target profile target_ref is required")
    target_ref = resolved_target_profile.target_ref

    effective_boot_overrides = boot_overrides
    if effective_boot_overrides is None and not manifest.boot_attempts:
        effective_boot_overrides = manifest.request.boot_overrides
    if effective_boot_overrides is not None:
        try:
            if effective_boot_overrides.kernel_args:
                resolved_target_profile = resolved_target_profile.model_copy(
                    update={
                        "kernel_args": merge_kernel_args(
                            resolved_target_profile.kernel_args, effective_boot_overrides.kernel_args
                        )
                    }
                )
            rootfs_update: dict[str, object] = {}
            if effective_boot_overrides.rootfs_source is not None:
                validated = validate_rootfs_source(
                    Path(effective_boot_overrides.rootfs_source),
                    source_paths=[Path(manifest.request.source_path)],
                    # Operator-configured sensitive paths threaded in by create_app (empty when
                    # no ServerConfig is loaded); the built-in guards always apply.
                    sensitive_paths=sensitive_paths or [],
                )
                rootfs_update["source"] = str(validated)
            if effective_boot_overrides.rootfs is not None:
                # Each override field was validated at BootOverrides construction; RootfsProfile
                # has no cross-field validators, so model_copy yields a valid profile.
                rootfs_update.update(effective_boot_overrides.rootfs.as_profile_update())
            if rootfs_update:
                resolved_rootfs_profile = resolved_rootfs_profile.model_copy(update=rootfs_update)
        except (PathSafetyError, ValueError) as exc:
            return _configuration_failure(run_id=run_id, message=str(exc))

    build_result = manifest.step_results.get("build")
    if build_result is None or build_result.status != StepStatus.SUCCEEDED:
        return _configuration_failure(run_id=run_id, message="target boot requires a succeeded build")
    kernel_image = _find_kernel_image(build_result)
    if kernel_image is None:
        return _configuration_failure(run_id=run_id, message="succeeded build did not record a kernel-image artifact")
    build_architecture = build_result.details.get("architecture")
    if build_architecture is not None and build_architecture != resolved_target_profile.architecture:
        return _configuration_failure(
            run_id=run_id,
            message="build architecture does not match target profile architecture",
            details={
                "build_architecture": build_architecture,
                "target_architecture": resolved_target_profile.architecture,
            },
        )

    has_new_boot_overrides = boot_overrides is not None and (
        bool(boot_overrides.kernel_args)
        or boot_overrides.rootfs_source is not None
        or boot_overrides.has_rootfs_field_overrides()
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

    provider = provider or LibvirtQemuProvider()

    def execute_boot(
        *, plan: Any, retrying_after_failure: bool, replace_succeeded: bool, attempt: int, manifest: RunManifest
    ) -> ToolResponse:
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
                step_name="boot",
                status=StepStatus.FAILED,
                summary=str(exc),
                artifacts=exc.artifacts,
                details=exc.details,
            )
            store.record_boot_attempt(run_id, attempt=_failed_attempt_record(), boot_result=failed)
            return ToolResponse.failure(
                category=exc.category,
                message=str(exc),
                run_id=run_id,
                details=_redacted_boot_data(exc.details),
                artifacts=exc.artifacts,
                suggested_next_actions=["artifacts.get_manifest"],
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
            store.record_boot_attempt(run_id, attempt=_failed_attempt_record(), boot_result=failed)
            return ToolResponse.failure(
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                message=failed.summary,
                run_id=run_id,
                details=_redacted_boot_data(failed.details),
                artifacts=failed.artifacts,
                suggested_next_actions=["artifacts.get_manifest"],
            )
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
                suggested_next_actions=["artifacts.get_manifest"],
            )
        return ToolResponse.failure(
            category=execution.error_category or ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=execution.summary,
            run_id=run_id,
            details=_redacted_boot_data({**execution.details, "diagnostic": execution.diagnostic}),
            artifacts=execution.artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )

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
                try:
                    plan = provider.plan_boot(
                        run_id=run_id,
                        run_dir=store.run_dir(run_id),
                        kernel_image_path=Path(kernel_image.path),
                        target_profile=resolved_target_profile,
                        rootfs_profile=resolved_rootfs_profile,
                        attempt=next_attempt,
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
                return execute_boot(
                    plan=plan,
                    retrying_after_failure=retrying_after_failure,
                    replace_succeeded=replace_succeeded or force_reboot,
                    attempt=next_attempt,
                    manifest=locked_manifest,
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

    try:
        adhoc_commands = _validate_adhoc_commands(commands)
    except ValueError as exc:
        return _configuration_failure(run_id=run_id, message=str(exc))

    requested_suite = test_suite or manifest.request.test_suite
    if manifest.request.test_suite is not None and requested_suite != manifest.request.test_suite:
        return _configuration_failure(
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
            return _configuration_failure(run_id=run_id, message=str(exc))
    elif attempt is not None:
        return _configuration_failure(
            run_id=run_id, message=f"boot attempt {attempt} not found: no boot attempts recorded for this run"
        )
    else:
        try:
            resolved_rootfs_profile = rootfs_profiles[manifest.request.rootfs_profile]
        except KeyError:
            return _configuration_failure(
                run_id=run_id,
                message=f"unknown rootfs profile: {manifest.request.rootfs_profile}",
            )
    try:
        suite_profile = test_suites[requested_suite] if requested_suite is not None else None
    except KeyError:
        return _configuration_failure(run_id=run_id, message=f"unknown test suite: {requested_suite}")

    existing = manifest.step_results.get("run_tests")
    if existing and existing.status == StepStatus.SUCCEEDED and not force_rerun:
        return _recorded_test_success_response(run_id=run_id, result=existing)
    if existing and existing.status == StepStatus.FAILED and not force_rerun:
        return _recorded_test_failure_response(run_id=run_id, result=existing)

    provider = provider or LocalSshTestProvider()
    try:
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
                plan = provider.plan_tests(
                    run_id=run_id,
                    run_dir=store.run_dir(run_id),
                    rootfs_profile=resolved_rootfs_profile,
                    suite=suite_profile,
                    adhoc_commands=adhoc_commands,
                    attempt=attempt,
                )
            except ValueError as exc:
                return _configuration_failure(run_id=run_id, message=str(exc))
            try:
                handle = _admit_run_tests_ssh_tier(
                    run_id=run_id, admission=admission, session_registry=session_registry
                )
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
                    "provider": provider.name,
                    "suite": suite_profile.name if suite_profile is not None else "adhoc",
                    "attempt": attempt,
                },
            )
            store.record_step_result(run_id, running, replace_succeeded=force_rerun)
            try:
                execution = _execute_tests_under_gate(provider=provider, plan=plan, admission=admission, handle=handle)
            except AdmissionError as exc:
                # The op spanned a halt (cancel_ssh_tier set the fence). The PROMOTED ssh-tier
                # handle is cancelled but undisposed; without rollback it lingers in
                # admission._bindings and would block reopen()/admit (`bindings_outstanding`). The
                # target is NOT torn down by cancel_ssh_tier (admission stays open, §5.6), so the
                # standard rollback path applies (no confirm_reaped gate). Guarded so a disposal
                # hiccup never masks the original AdmissionError.
                if handle is not None and admission is not None:
                    with contextlib.suppress(Exception):
                        admission.rollback(handle)
                terminal = StepResult(
                    step_name="run_tests",
                    status=StepStatus.FAILED,
                    summary="test run spanned an execution-state transition (target halted)",
                    details={"provider": provider.name, "code": exc.code, "error": str(exc)},
                )
                store.record_step_result(run_id, terminal, replace_succeeded=force_rerun)
                return ToolResponse.failure(
                    category=exc.category,
                    message=str(exc),
                    run_id=run_id,
                    details={"code": exc.code},
                    suggested_next_actions=["artifacts.collect"],
                )
            except Exception as exc:
                # The provider blew up after admit but before complete(). Symmetric to the halt path
                # above: the PROMOTED handle is undisposed and would linger; rollback deregisters it
                # cleanly. Guarded so the cleanup never masks the original exception detail.
                if handle is not None and admission is not None:
                    with contextlib.suppress(Exception):
                        admission.rollback(handle)
                terminal = StepResult(
                    step_name="run_tests",
                    status=StepStatus.FAILED,
                    summary="unexpected test provider failure",
                    details={"provider": provider.name, "exception_type": type(exc).__name__, "error": str(exc)},
                )
                store.record_step_result(run_id, terminal, replace_succeeded=force_rerun)
                return ToolResponse.failure(
                    category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                    message=terminal.summary,
                    run_id=run_id,
                    details=Redactor().redact_value(terminal.details),
                    suggested_next_actions=["artifacts.collect"],
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
    except ManifestStateError as exc:
        if "tests are locked" in str(exc):
            try:
                refreshed = store.load_manifest(run_id).step_results.get("run_tests")
            except ManifestStateError:
                refreshed = None
            if refreshed and refreshed.status == StepStatus.RUNNING:
                return _running_tests_response(run_id=run_id, result=refreshed)
            if existing and existing.status == StepStatus.RUNNING:
                return _running_tests_response(run_id=run_id, result=existing)
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    if execution.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=safe_summary,
            run_id=run_id,
            data=safe_details,
            artifacts=safe_artifacts,
            suggested_next_actions=["artifacts.collect"],
        )
    return ToolResponse.failure(
        category=execution.error_category or ErrorCategory.TEST_FAILURE,
        message=safe_summary,
        run_id=run_id,
        details={
            **safe_details,
            "diagnostic": safe_diagnostic,
        },
        artifacts=safe_artifacts,
        suggested_next_actions=["artifacts.collect"],
    )


@dataclass(frozen=True)
class _ProbeContext:
    store: ArtifactStore
    run_id: str
    rootfs: RootfsProfile
    host_build_id: str | None
    redactor: Redactor


def _resolve_probe_context(
    request: DebugIntrospectCheckPrerequisitesRequest,
    *,
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile],
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
    if request.target_ref != manifest.request.target_profile:
        return None, _configuration_failure(
            run_id=run_id,
            message="target_ref must match the immutable run manifest target_profile",
            details={
                "requested_target_ref": request.target_ref,
                "manifest_target_profile": manifest.request.target_profile,
                "code": "manifest_profile_mismatch",
            },
        )
    if not (5 <= request.timeout_seconds <= 60):
        return None, _configuration_failure(
            run_id=run_id,
            message=f"timeout_seconds must be in [5, 60]; got {request.timeout_seconds}",
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
) -> ToolResponse:
    """Spec §3-§7: target-side drgn prerequisite probe."""
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    _ctx, failure = _resolve_probe_context(request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles)
    if failure is not None:
        return failure
    assert _ctx is not None
    ctx = _ctx
    run_id = ctx.run_id

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
            command_timeout=request.timeout_seconds + 10,
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
            timeout=request.timeout_seconds + 10,
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
        with contextlib.suppress(FileNotFoundError):
            _path.chmod(0o600)

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


def _prepare_probe_dirs(store: ArtifactStore, run_id: str, probe_id: str) -> tuple[Path, Path]:
    """Create the agent-visible and sensitive probe directories with 0o700.

    Returns ``(agent_dir, sensitive_dir)``.
    """
    agent_dir = store.run_dir(run_id) / "debug" / "checkprereq" / probe_id
    sensitive_dir = store.run_dir(run_id) / "sensitive" / "debug" / "checkprereq" / probe_id
    agent_dir.mkdir(parents=True, mode=0o700)
    sensitive_dir.mkdir(parents=True, mode=0o700)
    for _dir in (sensitive_dir, sensitive_dir.parent, sensitive_dir.parent.parent):
        with contextlib.suppress(FileNotFoundError):
            _dir.chmod(0o700)
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

    assert isinstance(parsed, dict)
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


IntrospectPostValidator = Callable[[dict[str, Any]], "PostValidatorVerdict | None"]


@dataclass
class PostValidatorVerdict:
    """Lets a caller turn a wrapper-`ok` payload into a typed failure while
    keeping the manifest record and the response in agreement.
    """

    ok: bool
    failure_code: str | None = None
    failure_message: str | None = None
    failure_category: ErrorCategory | None = None
    extra_step_details: dict[str, Any] = field(default_factory=dict)
    extra_response_data: dict[str, Any] = field(default_factory=dict)


def _introspect_args_json(request: DebugIntrospectRunRequest) -> str:
    """JSON-encode the request's args for the wrapper.

    Both DebugIntrospectRunRequest and the helper path carry an `args` field; the
    `debug.introspect.run` MCP tool wrapper simply doesn't expose it to callers (so it stays {}).
    """
    return json.dumps(request.args or {})


def _execute_introspect_call(
    request: DebugIntrospectRunRequest,
    *,
    artifact_root: Path,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    clock: Callable[[], datetime] | None = None,
    operation_name: str = "debug.introspect.run",
    caps: dict[str, int] | None = None,
    post_validator: IntrospectPostValidator | None = None,
) -> ToolResponse:
    """Shared core for `debug.introspect.run` (§5.2) and `debug.introspect.helper`
    (§6). Execute a user-supplied drgn Python script over SSH against a live
    target VM and return structured JSON.
    """
    run_id = request.run_id
    now = clock or _utcnow

    # Spec §5.2 step 1: resolve profiles + load manifest.
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    target_profiles = target_profiles if target_profiles is not None else DEFAULT_TARGET_PROFILES
    debug_profiles = debug_profiles if debug_profiles is not None else DEFAULT_DEBUG_PROFILES

    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    # Iter-1 finding 1: every later step must honour the manifest-immutability
    # invariant for profile fields. Mirrors `target_boot_handler` (server.py
    # ~1373) and `debug_start_session_handler` (~2572). The introspect handler
    # previously resolved whatever the caller passed, silently substituting a
    # different rootfs/debug profile than the run booted with.
    if request.target_profile is not None and request.target_profile != manifest.request.target_profile:
        return _configuration_failure(
            run_id=run_id,
            message="target_profile must match the immutable run manifest request",
            details={
                "requested_profile": request.target_profile,
                "manifest_profile": manifest.request.target_profile,
                "code": "manifest_profile_mismatch",
            },
        )
    if request.rootfs_profile is not None and request.rootfs_profile != manifest.request.rootfs_profile:
        return _configuration_failure(
            run_id=run_id,
            message="rootfs_profile must match the immutable run manifest request",
            details={
                "requested_profile": request.rootfs_profile,
                "manifest_profile": manifest.request.rootfs_profile,
                "code": "manifest_profile_mismatch",
            },
        )
    if (
        manifest.request.debug_profile is not None
        and request.debug_profile is not None
        and request.debug_profile != manifest.request.debug_profile
    ):
        return _configuration_failure(
            run_id=run_id,
            message="debug_profile must match the immutable run manifest request",
            details={
                "requested_profile": request.debug_profile,
                "manifest_profile": manifest.request.debug_profile,
                "code": "manifest_profile_mismatch",
            },
        )
    # Iter-1 finding 3: spec §3.1 / line 84 describes `target_ref` as the
    # "target profile name", so a divergent value names a different target
    # than the run booted with. The handler previously read this field and
    # discarded it, allowing agents to pass arbitrary values.
    if request.target_ref != manifest.request.target_profile:
        return _configuration_failure(
            run_id=run_id,
            message="target_ref must match the immutable run manifest target_profile",
            details={
                "requested_target_ref": request.target_ref,
                "manifest_target_profile": manifest.request.target_profile,
                "code": "manifest_profile_mismatch",
            },
        )

    rootfs_name = request.rootfs_profile or manifest.request.rootfs_profile
    try:
        resolved_rootfs = rootfs_profiles[rootfs_name]
    except KeyError:
        return _configuration_failure(run_id=run_id, message=f"unknown rootfs profile: {rootfs_name}")

    debug_name = request.debug_profile or manifest.request.debug_profile or "qemu-gdbstub-default"
    try:
        resolved_debug = _resolve_debug_profile(profile_name=debug_name, debug_profiles=debug_profiles)
    except ProviderDebugError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id, details=exc.details)

    redactor = Redactor(secret_values=[resolved_rootfs.ssh_key_ref] if resolved_rootfs.ssh_key_ref else [])

    # Spec §5.2 step 2: operation gating.
    try:
        _ensure_debug_operation_enabled(resolved_debug, operation_name)
    except ProviderDebugError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=str(exc),
            run_id=run_id,
            details={**exc.details, "code": "operation_disabled"},
        )

    # Spec §5.2 step 3 / ADR 0011: write-mode policy gate (live path only). The
    # security boundary is host-side and runs before any SSH/admission work: a
    # write requires BOTH the DebugProfile write capability AND a per-call ack.
    if request.allow_write:
        try:
            _ensure_debug_operation_enabled(resolved_debug, "debug.introspect.write")
        except ProviderDebugError as exc:
            return ToolResponse.failure(
                category=exc.category,
                message=str(exc),
                run_id=run_id,
                details={**exc.details, "code": "operation_disabled"},
            )
        missing = missing_destructive_permissions(
            operation_name,
            request.acknowledged_permissions,
            registry=INTROSPECT_DESTRUCTIVE_PERMISSIONS,
        )
        if missing:
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                run_id=run_id,
                message=(
                    "debug.introspect.run write mode is destructive; acknowledge its required permissions to proceed"
                ),
                details={"code": "permission_required", "required_permissions": missing},
            )
    # The satisfied required permissions for audit/recording (the gate guarantees all
    # required perms are acknowledged when allow_write is set; empty otherwise).
    write_mode_permissions = (
        list(INTROSPECT_DESTRUCTIVE_PERMISSIONS.get(operation_name, [])) if request.allow_write else []
    )
    if not (5 <= request.timeout_seconds <= 300):
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"timeout_seconds must be in [5, 300]; got {request.timeout_seconds}",
            details={"code": "invalid_timeout"},
        )
    script_bytes = request.script.encode("utf-8")
    if not script_bytes:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message="script must not be empty",
            details={"code": "invalid_script"},
        )
    if len(script_bytes) > SCRIPT_BYTE_CAP:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"script exceeds {SCRIPT_BYTE_CAP} bytes",
            details={"code": "invalid_script"},
        )

    # Design §4: build_id flows from the boot-recorded KernelProvenance, the
    # authoritative §4.2 record — not the build step.
    boot_step = manifest.step_results.get("boot")
    provenance = boot_step.details.get("kernel_provenance") if boot_step is not None else None
    if not isinstance(provenance, dict):
        capture_error = boot_step.details.get("kernel_provenance_capture_error") if boot_step is not None else None
        if isinstance(capture_error, dict):
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                run_id=run_id,
                message=(f"boot did not record a KernelProvenance: {capture_error.get('message', 'capture failed')}"),
                details={
                    "code": "provenance_missing",
                    "capture_error": capture_error.get("code"),
                },
            )
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(
                "boot for this run did not record a KernelProvenance (it predates "
                "provenance capture). Re-run target.boot with force_reboot=true; a "
                "plain re-run short-circuits the recorded SUCCEEDED boot and will "
                "not re-capture provenance."
            ),
            details={"code": "provenance_missing"},
        )
    build_id = provenance.get("build_id")
    if not isinstance(build_id, str) or not BUILD_ID_RE.match(build_id):
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="recorded build_id is malformed",
            details={"code": "provenance_corrupt", "recorded": str(build_id)},
        )

    # Spec §5.2 step 4a: manifest call budget.
    if _count_introspect_calls(manifest) >= MAX_INTROSPECT_CALLS_PER_RUN:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(
                f"introspect call budget exhausted (>= {MAX_INTROSPECT_CALLS_PER_RUN}); "
                "start a new run via kernel.create_run"
            ),
            details={"code": "manifest_call_budget_exhausted"},
        )

    # Spec §5.2 step 4b: sensitive/ parent-mode preflight (R4-F1).
    sensitive_dir = store.run_dir(run_id) / "sensitive"
    try:
        mode = sensitive_dir.stat().st_mode & 0o777
    except FileNotFoundError:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(f"{sensitive_dir} is missing; re-run kernel.create_run to recreate the run layout."),
            details={"code": "sensitive_dir_missing"},
        )
    if mode & 0o077:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(
                f"{sensitive_dir} mode is {oct(mode)}; expected 0o700. "
                "Re-run kernel.create_run, or chmod 0700 the directory."
            ),
            details={"code": "sensitive_dir_too_permissive", "actual_mode": oct(mode)},
        )

    runner: SshRunner = ssh_runner or SubprocessSshRunner()
    # Iter-1 finding 6: sudo as root is documented as a no-op in spec §3.2,
    # so for root logins the preflight has nothing to assert and the real
    # invocation should not prepend `sudo` either. The previous code skipped
    # the preflight but still invoked `sudo python3 -`, producing a confusing
    # in-SSH failure when sudo was missing on a root-login target.
    use_sudo = resolved_rootfs.ssh_user != "root"

    # Spec §5.2 step 5: sudo preflight (only when sudo is needed).
    if use_sudo:
        try:
            sudo_argv = build_ssh_argv(
                rootfs_profile=resolved_rootfs,
                known_hosts_path=store.run_dir(run_id) / "sensitive" / "known_hosts",
                command=["sudo", "-n", "true"],
                command_timeout=5,
            )
        except ValueError as exc:
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                run_id=run_id,
                message=_redact_and_truncate(redactor, str(exc), cap=256),
                details={"code": "invalid_ssh_options"},
            )
        preflight_stdout = store.run_dir(run_id) / "logs" / "sudo_preflight.stdout"
        preflight_stderr = store.run_dir(run_id) / "logs" / "sudo_preflight.stderr"
        preflight_stdout.parent.mkdir(parents=True, exist_ok=True)
        # Route preflight output under sensitive/ so guest stderr (which may
        # carry secrets) does not land on disk in agent-visible logs/.
        sensitive_preflight_stderr = store.run_dir(run_id) / "sensitive" / "sudo_preflight.stderr"
        try:
            sudo_result = runner.run(
                sudo_argv,
                timeout=5,
                stdout_path=preflight_stdout,
                stderr_path=sensitive_preflight_stderr,
            )
        except Exception as exc:
            return ToolResponse.failure(
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                run_id=run_id,
                message=_redact_and_truncate(redactor, f"sudo preflight raised: {exc}", cap=256),
                details={"code": "ssh_failure"},
            )
        # Persist a redacted copy in the agent-visible location so forensic
        # tooling sees a stable artifact path even when the raw file is sealed
        # under sensitive/.
        if sensitive_preflight_stderr.exists():
            with contextlib.suppress(FileNotFoundError):
                sensitive_preflight_stderr.chmod(0o600)
            raw_preflight_stderr = sensitive_preflight_stderr.read_text(encoding="utf-8", errors="replace")
            preflight_stderr.write_text(redactor.redact_text(raw_preflight_stderr), encoding="utf-8")
        if sudo_result.exit_status != 0:
            stderr_for_message = sudo_result.stderr or sudo_result.stderr_snippet or ""
            message = _redact_and_truncate(redactor, stderr_for_message, cap=256)
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                run_id=run_id,
                message=f"sudo -n true failed: {message}",
                details={"code": "sudo_requires_password"},
            )

    # Spec §5.2 step 6: admission gate.
    if admission is None or session_registry is None:
        return ToolResponse.failure(
            category=ErrorCategory.READINESS_FAILURE,
            run_id=run_id,
            message="admission service unavailable",
            details={"code": "admission_service_unavailable"},
        )
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = admission.current_snapshot(target_key)
    if snapshot is None:
        # Iter-1 finding 7: align with `_require_snapshot` and the rest of
        # the debug.* handlers — "no snapshot exists" is `snapshot_missing`,
        # not `target_not_ready`.
        return ToolResponse.failure(
            category=ErrorCategory.READINESS_FAILURE,
            run_id=run_id,
            message="no authoritative snapshot for target; boot must publish a READY snapshot first",
            details={"code": "snapshot_missing"},
        )
    proof = probe_execution_state(
        registry=session_registry,
        admission=admission,
        target_key=target_key,
        generation=snapshot.generation,
    )
    try:
        handle = admission.admit_ssh_tier(
            target_key,
            snapshot.generation,
            snapshot.platform,
            lease=snapshot.lease,
            execution_proof=proof,
        )
    except AdmissionError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=str(exc),
            run_id=run_id,
            details={"code": exc.code},
            suggested_next_actions=["artifacts.collect"],
        )

    # R6-F3: Step 9.4 admitted us — Steps 9.5–9.10 must always complete
    # (Step 9.6 happy path) or roll back (this envelope) the admission
    # handle. Mirrors target_run_tests_handler:1588-1620.
    admission_disposed = False
    try:
        call_id = uuid.uuid4().hex
        agent_dir = store.run_dir(run_id) / "debug" / "introspect" / call_id
        sensitive_call_dir = store.run_dir(run_id) / "sensitive" / "debug" / "introspect" / call_id
        agent_dir.mkdir(parents=True, mode=0o700)
        sensitive_call_dir.mkdir(parents=True, mode=0o700)
        # Defensive chmod — intermediate dirs may have inherited umask.
        sensitive_call_dir.chmod(0o700)
        sensitive_call_dir.parent.chmod(0o700)
        sensitive_call_dir.parent.parent.chmod(0o700)

        # ADR 0011 / #56: one audit line per executed write-mode call, emitted as
        # soon as the call_id is minted so it fires exactly once for every call
        # that also gets a manifest step (independent of the later runner outcome).
        if request.allow_write:
            logger.warning(
                "audit: %s write-mode invocation run_id=%s call_id=%s permissions=%s",
                operation_name,
                run_id,
                call_id,
                write_mode_permissions,
            )

        args_json = _introspect_args_json(request)
        try:
            wrapper = render_wrapper(
                user_script=request.script,
                expected_build_id=build_id,
                call_id=call_id,
                args_json=args_json,
                caps=caps,
                allow_write=request.allow_write,
            )
            skeleton = render_wrapper_skeleton(
                expected_build_id=build_id,
                call_id=call_id,
                user_script_sha256_hex=user_script_sha256(request.script),
                args_json=args_json,
                caps=caps,
            )
        except WrapperRenderError as exc:
            # R6-F3: render failure before SSH ran. Release the admission
            # handle, clean up the orphan directories, and write a forensic
            # FAILED StepResult directly (no SSH means no stderr/stdout to
            # redact via _record_introspect_failure).
            try:
                admission.rollback(handle)
            except Exception:
                # Iter-2 finding 3: surface rollback failures rather than
                # swallowing them; the operator needs to know if the
                # admission state for this target_key is now corrupt.
                logger.exception("admission rollback failed for introspect call_id=%s run_id=%s", call_id, run_id)
            shutil.rmtree(agent_dir, ignore_errors=True)
            shutil.rmtree(sensitive_call_dir, ignore_errors=True)
            failed = StepResult(
                step_name=f"introspect:{call_id}",
                status=StepStatus.FAILED,
                summary=f"wrapper render error: {exc}",
                artifacts=[],
                details={
                    "call_id": call_id,
                    "code": "wrapper_render_error",
                    "ssh_user": resolved_rootfs.ssh_user,
                    "outcome_status": None,
                    "timeout_seconds": request.timeout_seconds,
                    "duration_ms": 0,
                    "wrapper_exit_code": None,
                    "allow_write": request.allow_write,
                },
            )
            _record_terminal_introspect_result(store, run_id, failed)
            return ToolResponse.failure(
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                run_id=run_id,
                message=f"wrapper render error: {exc}",
                details={"code": "wrapper_render_error", "call_id": call_id},
                suggested_next_actions=["artifacts.get_manifest"],
            )

        # Create wrapper.py with mode=0o600 atomically — write_text + chmod
        # leaves a window where the file is umask-default readable.
        wrapper_path = sensitive_call_dir / "wrapper.py"
        wrapper_fd = os.open(wrapper_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(wrapper_fd, "w", encoding="utf-8") as wrapper_handle:
                wrapper_handle.write(wrapper)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                wrapper_path.unlink()
            raise
        (agent_dir / "wrapper.skeleton.py").write_text(skeleton, encoding="utf-8")

        # Iter-1 finding 5: the agent-visible request.json must NOT carry the
        # plaintext script — the wrapper.py copy in sensitive/ is the only
        # protected source. Replace `script` with the same `sha256:` pointer
        # used in wrapper.skeleton.py so the two agent-visible artifacts
        # carry consistent sensitivity treatment.
        request_dump = request.model_dump(mode="json")
        request_dump["script"] = f"sha256:{user_script_sha256(request.script)}"
        redacted_request = redactor.redact_value(request_dump)
        (agent_dir / "request.json").write_text(json.dumps(redacted_request), encoding="utf-8")

        # Spec §5.2 steps 9–10: SSH invocation + cancellation watcher.
        user_timeout = request.timeout_seconds
        # Iter-1 finding 6: ssh_user=root means sudo is a no-op (spec §3.2);
        # invoking it anyway risks a confusing in-SSH failure when sudo is
        # missing on a root-login target.
        remote_argv = _target_python_remote_argv(timeout_seconds=user_timeout, use_sudo=use_sudo)
        try:
            ssh_argv = build_ssh_argv(
                rootfs_profile=resolved_rootfs,
                known_hosts_path=store.run_dir(run_id) / "sensitive" / "known_hosts",
                command=remote_argv,
                command_timeout=user_timeout + 10,
            )
        except ValueError as exc:
            # build_ssh_argv raises when RootfsProfile.ssh_options['ConnectTimeout']
            # exceeds the command timeout — surface as CONFIGURATION_ERROR rather
            # than letting it fall into the outer broad-except.
            try:
                admission.rollback(handle)
            except Exception:
                logger.exception("admission rollback failed for introspect call_id=%s run_id=%s", call_id, run_id)
            admission_disposed = True
            shutil.rmtree(agent_dir, ignore_errors=True)
            shutil.rmtree(sensitive_call_dir, ignore_errors=True)
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                run_id=run_id,
                message=_redact_and_truncate(redactor, str(exc), cap=256),
                details={"code": "invalid_ssh_options", "call_id": call_id},
                suggested_next_actions=["artifacts.collect"],
            )
        # Iter-2 finding 2: SSH output may contain unredacted user-script
        # stdout, drgn output, and stderr — write straight to <sensitive>/
        # so the dir-mode 0700 + file-mode 0600 protection is uniform across
        # success and failure paths and no `.tmp` file is ever left in the
        # agent-visible directory.
        stdout_path = sensitive_call_dir / "stdout.raw"
        stderr_path = sensitive_call_dir / "stderr.raw"

        cancel_event = threading.Event()
        stop_watcher = threading.Event()

        def _watcher() -> None:
            while not stop_watcher.is_set():
                if handle.wait_cancelled(0.1):
                    cancel_event.set()
                    return

        thread = threading.Thread(target=_watcher, daemon=True)
        thread.start()
        started_at = now()
        # Monotonic clock for duration_ms — wall-clock subtraction goes negative
        # under NTP slew or leap-second smear and misfires PRELUDE_WARNING.
        started_monotonic = time.monotonic()
        try:
            ssh_result = runner.run(
                ssh_argv,
                timeout=user_timeout + 10,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                cancel=cancel_event,
                stdin=wrapper,
                max_stdout_bytes=RUN_STDOUT_CAP,
            )
        finally:
            stop_watcher.set()
            thread.join()

        # Iter-2 finding 2: defense-in-depth — tighten file mode on the
        # SSH-output files that the runner created with umask-default perms.
        # The dir mode (0o700 on sensitive_call_dir) already blocks other
        # local users; the explicit 0o600 chmod makes that explicit and
        # survives any future relocation.
        # Iter-3 finding 2: skip the exists() probe — `chmod` itself raises
        # FileNotFoundError for a missing path, and a concurrent delete
        # between exists() and chmod() would turn a benign race into a
        # handler crash that drops the call's manifest record.
        for _raw_path in (stdout_path, stderr_path):
            with contextlib.suppress(FileNotFoundError):
                _raw_path.chmod(0o600)

        # admission_disposed flips True as soon as either complete() succeeds
        # or rollback() runs — the outer `except` then skips a redundant
        # rollback that would log a spurious handle_already_disposed.
        try:
            admission.complete(handle)
            admission_disposed = True
        except AdmissionError as exc:
            # Iter-1 finding 2: previously this path returned without
            # rolling back the handle (leaking it in admission._bindings)
            # and without recording any StepResult — leaving SSH's on-disk
            # artifacts orphaned with no manifest trace. Roll back the
            # admission binding and append a FAILED introspect:<call_id>
            # record so the manifest reflects the on-disk state.
            try:
                admission.rollback(handle)
            except Exception:
                # Iter-2 finding 3: silent suppression hides real
                # admission-state corruption from operators. Log the
                # exception with enough context to find the offending call.
                logger.exception("admission rollback failed for introspect call_id=%s run_id=%s", call_id, run_id)
            admission_disposed = True
            raw_stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
            duration_ms = int((time.monotonic() - started_monotonic) * 1000)
            return _record_introspect_failure(
                store=store,
                run_id=run_id,
                call_id=call_id,
                category=exc.category,
                code=exc.code,
                message=redactor.redact_text(str(exc)),
                agent_dir=agent_dir,
                sensitive_dir=sensitive_call_dir,
                redactor=redactor,
                raw_stderr=raw_stderr,
                ssh_exit=ssh_result.exit_status,
                request_timeout_seconds=request.timeout_seconds,
                duration_ms=duration_ms,
                ssh_user=resolved_rootfs.ssh_user,
                outcome_status_for_forensics=None,
                allow_write=request.allow_write,
                acknowledged_permissions=write_mode_permissions,
            )

        # Spec §5.2 step 11+: shared post-runner finalization (live + vmcore).
        finished_at = now()
        duration_ms = int((time.monotonic() - started_monotonic) * 1000)
        return _finalize_introspect_call(
            store=store,
            run_id=run_id,
            call_id=call_id,
            ssh_result=ssh_result,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            agent_dir=agent_dir,
            sensitive_call_dir=sensitive_call_dir,
            redactor=redactor,
            expected_build_id=build_id,
            request_timeout_seconds=request.timeout_seconds,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            operation_name=operation_name,
            drgn_open_message="drgn could not attach to the live target",
            exec_principal=resolved_rootfs.ssh_user,
            post_validator=post_validator,
            allow_write=request.allow_write,
            acknowledged_permissions=write_mode_permissions,
        )

    except Exception:
        # R6-F3: any unhandled exception between admit (step 6) and the
        # happy-path admission.complete() must release the admission handle
        # or it lingers in admission._bindings and blocks subsequent admit()
        # calls. Re-raise so the standard error path produces the response.
        # Skip rollback if the handle is already disposed — calling rollback
        # twice raises handle_already_disposed and pollutes logs on every
        # post-complete() failure (e.g. the manifest record path).
        if not admission_disposed:
            try:
                admission.rollback(handle)
            except Exception:
                # Iter-2 finding 3: don't let a secondary rollback failure
                # disappear silently — the primary exception is re-raised below,
                # but the operator still needs admission-state diagnostics.
                logger.exception("admission rollback failed while unwinding introspect handler for run_id=%s", run_id)
        raise


def _finalize_introspect_call(
    *,
    store: ArtifactStore,
    run_id: str,
    call_id: str,
    ssh_result: SshCommandResult,
    stdout_path: Path,
    stderr_path: Path,
    agent_dir: Path,
    sensitive_call_dir: Path,
    redactor: Redactor,
    expected_build_id: str,
    request_timeout_seconds: int,
    started_at: datetime,
    finished_at: datetime,
    duration_ms: int,
    operation_name: str,
    drgn_open_message: str,
    exec_principal: str | None,
    post_validator: IntrospectPostValidator | None,
    allow_write: bool = False,
    acknowledged_permissions: list[str] | None = None,
) -> ToolResponse:
    """Shared post-runner stage for both the live (`_execute_introspect_call`)
    and offline (`_execute_vmcore_introspect_call`) paths (spec §7 / ADR 0010).

    Everything from the runner-result triage through outcome discrimination,
    host-side `verify_build_id`, redaction, the `introspect:<call_id>` manifest
    step, and the success/post-validator response is identical between the two
    paths; only `expected_build_id`, `exec_principal` (None for vmcore — no SSH
    user), `operation_name`, `drgn_open_message`, and `post_validator` differ.
    """
    # Spec §5.2 step 11: exit-code + JSON parsing.
    raw_stdout = _read_capped(stdout_path, RUN_STDOUT_CAP)
    raw_stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""

    parsed: dict[str, Any] | None
    try:
        parsed = json.loads(raw_stdout) if raw_stdout else None
    except json.JSONDecodeError:
        parsed = None

    ssh_exit = ssh_result.exit_status

    def _fail(
        *,
        category: ErrorCategory,
        code: str,
        message: str,
        outcome_status_for_forensics: str | None,
        include_stdout_json: bool = False,
        redacted_payload: dict[str, Any] | None = None,
    ) -> ToolResponse:
        return _record_introspect_failure(
            store=store,
            run_id=run_id,
            call_id=call_id,
            category=category,
            code=code,
            message=message,
            agent_dir=agent_dir,
            sensitive_dir=sensitive_call_dir,
            redactor=redactor,
            raw_stderr=raw_stderr,
            ssh_exit=ssh_exit,
            request_timeout_seconds=request_timeout_seconds,
            duration_ms=duration_ms,
            ssh_user=exec_principal,
            outcome_status_for_forensics=outcome_status_for_forensics,
            include_stdout_json=include_stdout_json,
            redacted_payload=redacted_payload,
            allow_write=allow_write,
            acknowledged_permissions=acknowledged_permissions,
        )

    if ssh_result.oversized_output or raw_stdout is None:
        return _fail(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="oversized_output",
            message=f"introspect stdout exceeded {RUN_STDOUT_CAP} bytes",
            outcome_status_for_forensics=None,
        )

    if ssh_result.cancelled:
        return _fail(
            category=ErrorCategory.READINESS_FAILURE,
            code="introspect_cancelled",
            message="introspect call cancelled by admission fence",
            outcome_status_for_forensics=None,
        )

    if ssh_result.stdin_failed:
        # Wrapper payload was truncated mid-write (BrokenPipe / OSError). The
        # interpreter saw an incomplete script — any exit code or stdout it
        # produced is meaningless. Classify as transport failure.
        return _fail(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="ssh_stdin_failure",
            message="wrapper payload was not fully written to the runner stdin",
            outcome_status_for_forensics=None,
        )

    if ssh_result.timed_out:
        return _fail(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="ssh_timeout",
            message="runner round trip exceeded host-side timeout margin",
            outcome_status_for_forensics=None,
        )

    if ssh_exit == 124 and parsed is None:
        return _fail(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="introspect_timeout",
            message="timeout(1) fired",
            outcome_status_for_forensics=None,
        )

    if parsed is None:
        # Stdout was non-empty but not JSON; raw bytes are already under
        # sensitive/stdout.raw with a tightened mode.
        return _fail(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="wrapper_crash",
            message=f"wrapper exited {ssh_exit} without a parseable JSON document",
            outcome_status_for_forensics=None,
        )

    # JSON parsed. Discriminate on outcome.status per §4.3.
    redacted_payload = redactor.redact_value(parsed)
    outcome_obj = redacted_payload.get("outcome") if isinstance(redacted_payload, dict) else None
    outcome_status = outcome_obj.get("status") if isinstance(outcome_obj, dict) else None
    rp = redacted_payload if isinstance(redacted_payload, dict) else None

    if outcome_status == "drgn_open_failure":
        return _fail(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="drgn_open_failure",
            message=drgn_open_message,
            outcome_status_for_forensics=outcome_status,
            include_stdout_json=True,
            redacted_payload=rp,
        )
    if outcome_status == "drgn_version_skew":
        return _fail(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="drgn_version_skew",
            message="drgn lacks main_module().build_id (version skew)",
            outcome_status_for_forensics=outcome_status,
            include_stdout_json=True,
            redacted_payload=rp,
        )
    if outcome_status == "provenance_unverifiable":
        return _fail(
            category=ErrorCategory.CONFIGURATION_ERROR,
            code="provenance_unverifiable",
            message="vmcore carries no embedded build-id; provenance cannot be verified",
            outcome_status_for_forensics=outcome_status,
            include_stdout_json=True,
            redacted_payload=rp,
        )
    if outcome_status == "provenance_mismatch":
        return _fail(
            category=ErrorCategory.CONFIGURATION_ERROR,
            code="provenance_mismatch",
            message="kernel build_id does not match the expected build_id",
            outcome_status_for_forensics=outcome_status,
            include_stdout_json=True,
            redacted_payload=rp,
        )
    if outcome_status == "script_compile_error":
        return _fail(
            category=ErrorCategory.CONFIGURATION_ERROR,
            code="script_compile_error",
            message="user script failed to compile",
            outcome_status_for_forensics=outcome_status,
            include_stdout_json=True,
            redacted_payload=rp,
        )
    if outcome_status == "write_mode_disabled":
        # ADR 0011 / #56: the wrapper guard refused a drgn write under allow_write=false.
        # Must be an explicit branch — an unmatched outcome status falls through to the
        # success path below (`status="ok"`), which would report a blocked write as success.
        return _fail(
            category=ErrorCategory.CONFIGURATION_ERROR,
            code="write_mode_disabled",
            message="script attempted a drgn write API but allow_write is false",
            outcome_status_for_forensics=outcome_status,
            include_stdout_json=True,
            redacted_payload=rp,
        )
    if outcome_status == "wrapper_internal_error":
        # R4-F3: forensic-only on disk; agent-facing collapses to wrapper_crash.
        return _fail(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="wrapper_crash",
            message="wrapper exited 6 with a minimal-recovery JSON document",
            outcome_status_for_forensics="wrapper_internal_error",
            include_stdout_json=True,
            redacted_payload=rp,
        )

    # Design §4: host-authoritative provenance verify. The wrapper already
    # self-aborted on mismatch (handled above); reaching here on an "ok" outcome
    # with a disagreeing or absent id is a wrapper fault — fail loud, never skip.
    # Verify the RAW parsed id, never the redacted payload.
    observed_build_id = parsed.get("build_id") if isinstance(parsed, dict) else None
    if not isinstance(observed_build_id, str):
        return _fail(
            category=ErrorCategory.CONFIGURATION_ERROR,
            code="provenance_mismatch",
            message="wrapper reported success without a build_id; cannot confirm provenance",
            outcome_status_for_forensics="provenance_inconsistent",
            include_stdout_json=True,
            redacted_payload=rp,
        )
    try:
        verify_build_id(expected=expected_build_id, observed=observed_build_id)
    except ProvenanceMismatch:
        return _fail(
            category=ErrorCategory.CONFIGURATION_ERROR,
            code="provenance_mismatch",
            message="host build_id verify disagrees with the wrapper-reported id",
            outcome_status_for_forensics="provenance_inconsistent",
            include_stdout_json=True,
            redacted_payload=rp,
        )

    # Spec §5.2 step 12: redaction post-processing for the happy path.
    (agent_dir / "stdout.json").write_text(json.dumps(redacted_payload), encoding="utf-8")
    (agent_dir / "stderr.log").write_text(redactor.redact_text(raw_stderr), encoding="utf-8")

    emits = redacted_payload.get("emits", []) if isinstance(redacted_payload, dict) else []
    user_stdout = redacted_payload.get("user_stdout", "") if isinstance(redacted_payload, dict) else ""
    truncated = redacted_payload.get("truncated", {}) if isinstance(redacted_payload, dict) else {}
    prelude_ms = redacted_payload.get("prelude_ms", 0) if isinstance(redacted_payload, dict) else 0
    warnings = redacted_payload.get("warnings", []) if isinstance(redacted_payload, dict) else []

    diagnostic: str | None = None
    if prelude_ms * 100 >= PRELUDE_WARNING_FRACTION_PCT * request_timeout_seconds * 1000:
        diagnostic = (
            f"prelude ({prelude_ms} ms) consumed >= "
            f"{PRELUDE_WARNING_FRACTION_PCT}% of timeout_seconds "
            f"({request_timeout_seconds} s); consider raising timeout_seconds."
        )

    # Spec §4.3: only these keys are part of the response outcome contract for
    # status=error. Allowlist (not spread) so a hostile wrapper cannot inject keys.
    _SCRIPT_ERROR_OUTCOME_KEYS = ("error_type", "error_message", "traceback")
    status = "script_error" if outcome_status == "error" else "ok"
    if status == "script_error" and isinstance(outcome_obj, dict):
        outcome_for_response: dict[str, Any] = {"status": "error"}
        for _k in _SCRIPT_ERROR_OUTCOME_KEYS:
            if _k in outcome_obj:
                outcome_for_response[_k] = outcome_obj[_k]
    else:
        outcome_for_response = {"status": "ok"}

    user_stdout_snippet = _head_tail(user_stdout, head=2048, tail=2048)
    drgn_stderr_snippet = _head_tail(redactor.redact_text(raw_stderr), head=2048, tail=2048)

    # Spec §5.2 step 13: manifest record under the lock.
    artifacts: list[ArtifactRef] = [
        ArtifactRef(path=str(agent_dir / "request.json"), kind="application/json"),
        ArtifactRef(path=str(agent_dir / "wrapper.skeleton.py"), kind="text/x-python"),
        ArtifactRef(
            path=str(sensitive_call_dir / "wrapper.py"),
            kind="text/x-python",
            sensitive=True,
        ),
        ArtifactRef(path=str(agent_dir / "stdout.json"), kind="application/json"),
        ArtifactRef(path=str(agent_dir / "stderr.log"), kind="text/plain"),
    ]
    for raw_name in ("stdout.raw", "stderr.raw"):
        raw_path = sensitive_call_dir / raw_name
        if raw_path.exists():
            artifacts.append(
                ArtifactRef(
                    path=str(raw_path),
                    kind="application/octet-stream",
                    sensitive=True,
                )
            )

    verdict = post_validator(redacted_payload) if post_validator is not None else None
    step_status = StepStatus.SUCCEEDED
    step_failure_code = None
    if verdict is not None and not verdict.ok:
        step_status = StepStatus.FAILED
        step_failure_code = verdict.failure_code

    step_details: dict[str, Any] = {
        "call_id": call_id,
        "build_id": redacted_payload.get("build_id") if isinstance(redacted_payload, dict) else None,
        "timeout_seconds": request_timeout_seconds,
        "wrapper_exit_code": ssh_result.exit_status,
        "duration_ms": duration_ms,
        "prelude_ms": prelude_ms,
        "truncated": truncated,
        "outcome_status": outcome_status,
    }
    # exec_principal is None on the vmcore path (no SSH user); omit the key
    # rather than recording a misleading `ssh_user: null` on a non-SSH step.
    if exec_principal is not None:
        step_details["ssh_user"] = exec_principal
    # ADR 0011 / #56 audit: allow_write on every live call; satisfied required
    # permissions only when write mode was used.
    step_details["allow_write"] = allow_write
    if allow_write:
        step_details["acknowledged_permissions"] = list(acknowledged_permissions or [])
    if verdict is not None:
        step_details.update(verdict.extra_step_details)
    if step_status is StepStatus.FAILED:
        step_details["code"] = step_failure_code

    summary = (
        f"introspect call {call_id[:8]} ok"
        if step_status is StepStatus.SUCCEEDED
        else f"introspect call {call_id[:8]} failed: {step_failure_code}"
    )
    step = StepResult(
        step_name=f"introspect:{call_id}",
        status=step_status,
        summary=summary,
        artifacts=artifacts,
        details=step_details,
    )
    _record_terminal_introspect_result(store, run_id, step)

    public_artifacts = [a for a in artifacts if not a.sensitive]

    if verdict is not None and not verdict.ok:
        return ToolResponse.failure(
            category=verdict.failure_category or ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=verdict.failure_message or "post-validator rejected the introspect result",
            details={"code": verdict.failure_code, "call_id": call_id},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    if verdict is not None and verdict.ok:
        return ToolResponse.success(
            summary=f"introspect call {call_id[:8]} ok",
            run_id=run_id,
            status=StepStatus.SUCCEEDED,
            artifacts=public_artifacts,
            suggested_next_actions=["artifacts.get_manifest", operation_name],
            data={
                **verdict.extra_response_data,
                "call_id": call_id,
                "truncated": truncated,
                "prelude_ms": prelude_ms,
            },
        )
    response_data: dict[str, Any] = {
        "call_id": call_id,
        "status": status,
        "outcome": outcome_for_response,
        "emits": emits,
        "user_stdout_snippet": user_stdout_snippet,
        "drgn_stderr_snippet": drgn_stderr_snippet,
        "build_id": redacted_payload.get("build_id") if isinstance(redacted_payload, dict) else None,
        "truncated": truncated,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_ms": duration_ms,
        "prelude_ms": prelude_ms,
        "artifacts": [a.model_dump(mode="json") for a in public_artifacts],
        "diagnostic": diagnostic,
    }
    # The live wrapper never emits warnings (vmcore-only field); include the key
    # only when present so the live `debug.introspect.run` response is unchanged.
    if warnings:
        response_data["warnings"] = warnings
    return ToolResponse.success(
        summary=f"introspect call {call_id[:8]} ok",
        run_id=run_id,
        status=StepStatus.SUCCEEDED,
        artifacts=public_artifacts,
        suggested_next_actions=["artifacts.get_manifest", operation_name],
        data=response_data,
    )


def debug_introspect_run_handler(
    request: DebugIntrospectRunRequest,
    *,
    artifact_root: Path,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    """Thin wrapper over the shared core. `run` opts into no cap override and no post-validator."""
    return _execute_introspect_call(
        request,
        artifact_root=artifact_root,
        target_profiles=target_profiles,
        rootfs_profiles=rootfs_profiles,
        debug_profiles=debug_profiles,
        ssh_runner=ssh_runner,
        admission=admission,
        session_registry=session_registry,
        clock=clock,
        operation_name="debug.introspect.run",
        caps=None,
        post_validator=None,
    )


HELPER_CAP_PROFILE: dict[str, int] = {
    "per_emit_bytes": 4 * 1024 * 1024,
    "emits": 4,
    "total_json": 8 * 1024 * 1024,
}


def _make_helper_post_validator(spec: HelperSpec) -> IntrospectPostValidator:
    """Spec §3.3/§6: validate the single redacted emit into the helper's
    output_model; keep the manifest step status in agreement with the response.
    """

    def _validate(redacted_payload: dict[str, Any]) -> PostValidatorVerdict:
        details_stub: dict[str, Any] = {"helper": spec.name, "version": spec.version}
        # A drgn script that RAISED is a script error, NOT schema drift —
        # surface helper_script_error with the redacted traceback so the
        # primary diagnostic is in the response, not buried on disk.
        outcome = redacted_payload.get("outcome") if isinstance(redacted_payload, dict) else None
        outcome_status = outcome.get("status") if isinstance(outcome, dict) else None
        if outcome_status == "error":
            etype = outcome.get("error_type") if isinstance(outcome, dict) else None
            emsg = outcome.get("error_message") if isinstance(outcome, dict) else None
            return PostValidatorVerdict(
                ok=False,
                failure_code="helper_script_error",
                failure_message=_redact_and_truncate(Redactor(), f"{etype}: {emsg}", cap=512),
                failure_category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                extra_step_details={**details_stub, "error_type": etype},
            )
        emits = redacted_payload.get("emits") if isinstance(redacted_payload, dict) else None
        if not isinstance(emits, list) or len(emits) != 1:
            return PostValidatorVerdict(
                ok=False,
                failure_code="helper_schema_drift",
                failure_message=(f"expected exactly one emit, got {0 if not isinstance(emits, list) else len(emits)}"),
                failure_category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                extra_step_details={**details_stub},
            )
        try:
            model = spec.output_model.model_validate(emits[0])
        except ValidationError as exc:
            return PostValidatorVerdict(
                ok=False,
                failure_code="helper_schema_drift",
                failure_message=_redact_and_truncate(Redactor(), str(exc), cap=512),
                failure_category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                extra_step_details={**details_stub},
            )
        return PostValidatorVerdict(
            ok=True,
            extra_step_details={**details_stub},
            extra_response_data={
                "helper": spec.name,
                "version": spec.version,
                "result": model.model_dump(mode="json"),
            },
        )

    return _validate


def debug_introspect_helper_handler(
    request: DebugIntrospectHelperRequest,
    *,
    artifact_root: Path,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    """Spec §6. Resolve a curated helper, validate its args, and run its drgn
    script through the shared core under the raised helper cap profile.
    """
    spec = HELPER_REGISTRY.get(request.name)
    if spec is None:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=request.run_id,
            message=f"unknown helper {request.name!r}; valid: {sorted(HELPER_REGISTRY)}",
            details={"code": "unknown_helper", "valid": sorted(HELPER_REGISTRY)},
            suggested_next_actions=["debug.introspect.helper"],
        )
    try:
        validated_args = spec.args_model.model_validate(request.args)
    except ValidationError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=request.run_id,
            message=_redact_and_truncate(Redactor(), str(exc), cap=512),
            details={"code": "helper_args_invalid"},
            suggested_next_actions=["debug.introspect.helper"],
        )
    run_request = DebugIntrospectRunRequest(
        run_id=request.run_id,
        target_ref=request.target_ref,
        script=spec.script,
        timeout_seconds=request.timeout_seconds,
        allow_write=False,
        debug_profile=request.debug_profile,
        target_profile=request.target_profile,
        rootfs_profile=request.rootfs_profile,
        args=validated_args.model_dump(mode="json"),
    )
    return _execute_introspect_call(
        run_request,
        artifact_root=artifact_root,
        target_profiles=target_profiles,
        rootfs_profiles=rootfs_profiles,
        debug_profiles=debug_profiles,
        ssh_runner=ssh_runner,
        admission=admission,
        session_registry=session_registry,
        clock=clock,
        operation_name="debug.introspect.helper",
        caps=HELPER_CAP_PROFILE,
        post_validator=_make_helper_post_validator(spec),
    )


def _execute_vmcore_introspect_call(
    request: DebugIntrospectFromVmcoreRequest,
    *,
    artifact_root: Path,
    runner: SshRunner | None = None,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
    clock: Callable[[], datetime] | None = None,
    operation_name: str = "debug.introspect.from_vmcore",
    caps: dict[str, int] | None = None,
    post_validator: IntrospectPostValidator | None = None,
) -> ToolResponse:
    """Offline vmcore drgn introspection (spec §6 / ADR 0010).

    Runs the user/helper drgn script against a captured vmcore on the agent
    host via a local ``python3`` subprocess. No admission gate, no SSH, no sudo
    — vmcore analysis is always concurrent-safe (interface-contracts §5.6 rule
    3). The build_id fail-loud compares the vmcore's embedded id against the
    host-parsed id of the supplied vmlinux.
    """
    run_id = request.run_id
    now = clock or _utcnow

    try:
        store = ArtifactStore(artifact_root, create_root=False)
        if not (store.run_dir(run_id) / "manifest.json").is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    # Spec §6 step 2 / ADR 0011: a vmcore is an immutable core-dump file and the
    # offline path carries no DebugProfile to gate against, so write mode does not
    # apply here (it would be a phantom feature) — reject it with an accurate reason.
    if request.allow_write:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message="write mode is not applicable to offline vmcore analysis; the core file is immutable",
            details={"code": "write_mode_not_applicable"},
        )
    if not (5 <= request.timeout_seconds <= 300):
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"timeout_seconds must be in [5, 300]; got {request.timeout_seconds}",
            details={"code": "invalid_timeout"},
        )
    script_bytes = request.script.encode("utf-8")
    if not script_bytes or len(script_bytes) > SCRIPT_BYTE_CAP:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message="script must be non-empty and <= the script byte cap",
            details={"code": "invalid_script"},
        )

    # Spec §6 step 3: shared introspect call budget.
    if _count_introspect_calls(manifest) >= MAX_INTROSPECT_CALLS_PER_RUN:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(
                f"introspect call budget exhausted (>= {MAX_INTROSPECT_CALLS_PER_RUN}); "
                "start a new run via kernel.create_run"
            ),
            details={"code": "manifest_call_budget_exhausted"},
        )

    # Spec §6 step 4: sensitive/ parent-mode preflight.
    run_dir = store.run_dir(run_id)
    sensitive_dir = run_dir / "sensitive"
    try:
        mode = sensitive_dir.stat().st_mode & 0o777
    except FileNotFoundError:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"{sensitive_dir} is missing; re-run kernel.create_run to recreate the run layout.",
            details={"code": "sensitive_dir_missing"},
        )
    if mode & 0o077:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(f"{sensitive_dir} mode is {oct(mode)}; expected 0o700. Re-run kernel.create_run."),
            details={"code": "sensitive_dir_too_permissive", "actual_mode": oct(mode)},
        )

    # Spec §6 step 5: resolve symbols (confine vmlinux/modules to run_dir) and
    # confine the vmcore ref. Build a KernelProvenance shell purely to reuse the
    # #53 resolver; build_id="" is unused by resolve_symbols.
    redactor = Redactor(secret_values=[])
    provenance_shell = KernelProvenance(
        build_id="",
        release="",
        vmlinux_ref=request.vmlinux_ref,
        modules_ref=request.modules_ref,
        cmdline="",
        config_ref=None,
    )
    try:
        resolved = resolve_symbols(provenance_shell, run_dir=run_dir)
    except SymbolResolutionError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=str(exc),
            details={"code": "symbol_resolution_failed", "resolver_code": exc.code},
        )
    try:
        vmcore_path = confine_run_relative(request.vmcore_ref, run_dir=run_dir)
    except PathSafetyError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=str(exc),
            details={"code": "vmcore_not_found"},
        )
    if not vmcore_path.is_file():
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"vmcore not found at {request.vmcore_ref!r}",
            details={"code": "vmcore_not_found"},
        )

    # Spec §6 step 6: host-authoritative expected build_id from the vmlinux ELF.
    try:
        expected_build_id = build_id_reader(resolved.vmlinux_path)
    except BuildIdReadError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"could not read a GNU build-id from the supplied vmlinux: {exc}",
            details={"code": "vmlinux_build_id_unreadable"},
        )
    if not BUILD_ID_RE.match(expected_build_id):
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message="vmlinux build_id is malformed",
            details={"code": "vmlinux_build_id_unreadable", "recorded": expected_build_id},
        )

    # Spec §6 step 7: mint call_id, lay out dirs, render + persist the wrapper.
    call_id = uuid.uuid4().hex
    agent_dir = run_dir / "debug" / "introspect" / call_id
    sensitive_call_dir = run_dir / "sensitive" / "debug" / "introspect" / call_id
    agent_dir.mkdir(parents=True, mode=0o700)
    sensitive_call_dir.mkdir(parents=True, mode=0o700)
    sensitive_call_dir.chmod(0o700)
    sensitive_call_dir.parent.chmod(0o700)
    sensitive_call_dir.parent.parent.chmod(0o700)

    args_json = json.dumps(request.args or {})
    modules_arg = str(resolved.modules_path) if resolved.modules_path is not None else None
    try:
        wrapper = render_vmcore_wrapper(
            user_script=request.script,
            expected_build_id=expected_build_id,
            call_id=call_id,
            vmcore_path=str(vmcore_path),
            vmlinux_path=str(resolved.vmlinux_path),
            modules_path=modules_arg,
            args_json=args_json,
            caps=caps,
        )
        skeleton = render_vmcore_wrapper_skeleton(
            expected_build_id=expected_build_id,
            call_id=call_id,
            user_script_sha256_hex=user_script_sha256(request.script),
            vmcore_path=str(vmcore_path),
            vmlinux_path=str(resolved.vmlinux_path),
            modules_path=modules_arg,
            args_json=args_json,
            caps=caps,
        )
    except WrapperRenderError as exc:
        shutil.rmtree(agent_dir, ignore_errors=True)
        shutil.rmtree(sensitive_call_dir, ignore_errors=True)
        failed = StepResult(
            step_name=f"introspect:{call_id}",
            status=StepStatus.FAILED,
            summary=f"wrapper render error: {exc}",
            artifacts=[],
            details={
                "call_id": call_id,
                "code": "wrapper_render_error",
                "outcome_status": None,
                "timeout_seconds": request.timeout_seconds,
                "duration_ms": 0,
                "wrapper_exit_code": None,
            },
        )
        _record_terminal_introspect_result(store, run_id, failed)
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=f"wrapper render error: {exc}",
            details={"code": "wrapper_render_error", "call_id": call_id},
            suggested_next_actions=["artifacts.get_manifest"],
        )

    wrapper_path = sensitive_call_dir / "wrapper.py"
    wrapper_fd = os.open(wrapper_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(wrapper_fd, "w", encoding="utf-8") as wrapper_handle:
            wrapper_handle.write(wrapper)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            wrapper_path.unlink()
        raise
    (agent_dir / "wrapper.skeleton.py").write_text(skeleton, encoding="utf-8")

    request_dump = request.model_dump(mode="json")
    request_dump["script"] = f"sha256:{user_script_sha256(request.script)}"
    (agent_dir / "request.json").write_text(json.dumps(redactor.redact_value(request_dump)), encoding="utf-8")

    # Spec §6 step 8: local drgn subprocess (no SSH, no sudo, no admission).
    stdout_path = sensitive_call_dir / "stdout.raw"
    stderr_path = sensitive_call_dir / "stderr.raw"
    active_runner: SshRunner = runner or SubprocessSshRunner()
    argv = ["timeout", "--kill-after=2s", f"{request.timeout_seconds}s", "python3", "-"]
    started_at = now()
    started_monotonic = time.monotonic()
    ssh_result = active_runner.run(
        argv,
        timeout=request.timeout_seconds + 10,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        cancel=threading.Event(),
        stdin=wrapper,
        max_stdout_bytes=RUN_STDOUT_CAP,
    )
    for raw_path in (stdout_path, stderr_path):
        with contextlib.suppress(FileNotFoundError):
            raw_path.chmod(0o600)

    finished_at = now()
    duration_ms = int((time.monotonic() - started_monotonic) * 1000)
    return _finalize_introspect_call(
        store=store,
        run_id=run_id,
        call_id=call_id,
        ssh_result=ssh_result,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        agent_dir=agent_dir,
        sensitive_call_dir=sensitive_call_dir,
        redactor=redactor,
        expected_build_id=expected_build_id,
        request_timeout_seconds=request.timeout_seconds,
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
        operation_name=operation_name,
        drgn_open_message="drgn could not open the vmcore",
        exec_principal=None,
        post_validator=post_validator,
    )


def debug_introspect_from_vmcore_handler(
    request: DebugIntrospectFromVmcoreRequest,
    *,
    artifact_root: Path,
    runner: SshRunner | None = None,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    """Spec §6 / ADR 0010. Offline vmcore drgn introspection; no admission gate."""
    return _execute_vmcore_introspect_call(
        request,
        artifact_root=artifact_root,
        runner=runner,
        build_id_reader=build_id_reader,
        clock=clock,
        operation_name="debug.introspect.from_vmcore",
        caps=None,
        post_validator=None,
    )


def debug_introspect_from_vmcore_helper_handler(
    request: DebugIntrospectFromVmcoreHelperRequest,
    *,
    artifact_root: Path,
    runner: SshRunner | None = None,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    """Spec §3.1. Run a curated HELPER_REGISTRY helper against a vmcore, reusing
    the live helper's post-validator and cap profile unchanged.
    """
    spec = HELPER_REGISTRY.get(request.name)
    if spec is None:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=request.run_id,
            message=f"unknown helper {request.name!r}; valid: {sorted(HELPER_REGISTRY)}",
            details={"code": "unknown_helper", "valid": sorted(HELPER_REGISTRY)},
            suggested_next_actions=["debug.introspect.from_vmcore_helper"],
        )
    try:
        validated_args = spec.args_model.model_validate(request.args)
    except ValidationError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=request.run_id,
            message=_redact_and_truncate(Redactor(), str(exc), cap=512),
            details={"code": "helper_args_invalid"},
            suggested_next_actions=["debug.introspect.from_vmcore_helper"],
        )
    run_request = DebugIntrospectFromVmcoreRequest(
        run_id=request.run_id,
        vmcore_ref=request.vmcore_ref,
        vmlinux_ref=request.vmlinux_ref,
        modules_ref=request.modules_ref,
        script=spec.script,
        timeout_seconds=request.timeout_seconds,
        allow_write=False,
        args=validated_args.model_dump(mode="json"),
    )
    return _execute_vmcore_introspect_call(
        run_request,
        artifact_root=artifact_root,
        runner=runner,
        build_id_reader=build_id_reader,
        clock=clock,
        operation_name="debug.introspect.from_vmcore_helper",
        caps=HELPER_CAP_PROFILE,
        post_validator=_make_helper_post_validator(spec),
    )


def _require_snapshot(admission: AdmissionService, target_key: TargetKey) -> TargetSnapshot:
    """Read the authoritative snapshot for a target, raising `snapshot_missing` when boot has
    not published one yet. `stale_handle` means a caller's handle/request is bound to a
    now-superseded incarnation; "no snapshot exists at all" is a distinct precondition failure,
    so it carries its own code. Single source of the `current_snapshot(...) → raise if None`
    check shared by every snapshot-reading path (transport.open request builders + inject_break)."""
    snapshot = admission.current_snapshot(target_key)
    if snapshot is None:
        raise AdmissionError(
            "no authoritative snapshot for target; boot must publish a READY snapshot first",
            category=ErrorCategory.READINESS_FAILURE,
            code="snapshot_missing",
        )
    return snapshot


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
        ),
        required_caps=["rsp"],
        platform=snapshot.platform,
    )


def _halt_debug_transport(
    *,
    session: TransportSession,
    admission: AdmissionService,
    session_registry: SessionRegistry,
) -> None:
    """Persist the EXECUTING→HALTED transition BEFORE the gdb attach runs (the attach halts the
    kernel). The durable HALTED record is what the run-tests probe reads, and
    note_execution_transition bumps the execution epoch so a pre-halt EXECUTING ssh proof can never
    be replayed across the halt. The ordering (durable write, then note) makes target.run_tests
    reject with `target_halted` for the whole window the debugger owns the kernel.

    Spec §4.6 / ADR-0006 async-halt cancellation: after recording the transition, immediately
    cancel the fence on every in-flight ssh-tier binding admitted at-or-before this halt's epoch.
    Without this call the run-tests watcher would poll until the SSH provider's per-command
    timeout (default 30s); with it, an admitted run_tests racing the halt observes the cancel
    fence and rolls back in <5s. The two calls are not atomic — a fresh `admit_ssh_tier` admitted
    between them carries the post-bump epoch (so its stamped proof at the old epoch is already
    stale and rejected) and is correctly left untouched here."""
    session_registry.write_record(session.model_copy(update={"execution_state": ExecutionState.HALTED}))
    halt_epoch = admission.note_execution_transition(session.target_key, session.generation)
    admission.cancel_ssh_tier(session.target_key, session.generation, halt_epoch=halt_epoch)


def _resume_debug_transport(
    *,
    session: TransportSession,
    admission: AdmissionService,
    session_registry: SessionRegistry,
) -> None:
    """Inverse of `_halt_debug_transport` for the guaranteed-resume path: once the MI engine confirms
    the kernel is EXECUTING again (best-effort continue + RSP disconnect), persist HALTED->EXECUTING
    and bump the execution epoch so a fresh ssh-tier proof at the new epoch is accepted. Writing the
    durable record EXECUTING also makes a subsequent transaction.close() leave NO closed_while_halted
    recovery tombstone, so a fresh ssh-tier operation succeeds with the target back in EXECUTING
    (interface-contracts §5.6)."""
    session_registry.write_record(session.model_copy(update={"execution_state": ExecutionState.EXECUTING}))
    admission.note_execution_transition(session.target_key, session.generation)


def _teardown_debug_transport(
    *,
    transport_session: TransportSession,
    transaction: TransportTransaction,
    session_registry: SessionRegistry | None,
    session_guard: SessionGuard | None,
) -> None:
    """Tear down an open transport session after a failed attach: SessionGuard-supervised close when
    the guard is wired, else a guarded transaction.close(force=False). Shared by the legacy batch
    attach-failure path and the Phase-A MI probe-failure path."""
    sid = transport_session.session_id
    tkey = transport_session.target_key
    if session_guard is not None and session_registry is not None:
        session_guard.teardown(
            SessionGuardContext(
                target_key=tkey, generation=transport_session.generation, session_id=sid, reason="attach_error"
            ),
            close=lambda: transaction.close(sid, force=False),
            read_record=lambda: session_registry.read_record(tkey),
            force_reap=lambda: transaction.force_release(sid),
        )
    else:
        with contextlib.suppress(Exception):
            transaction.close(sid, force=False)


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
    attach and is authoritative (ADR 0021 decision 2b) — there is no live-banner scrape. The legacy
    ``controller_*`` fields are inert: the in-process registry is the liveness source, not a pid."""
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
        current_execution_state="stopped",
        breakpoints={},
        controller_mode="attached",
        active_controller_pid=None,
        controller_last_observed_state="attached",
        active_controller_identity={},
        transcript_path=str(transcript_path),
        command_metadata_path=str(attempt_dir / "commands.jsonl"),
        latest_summary_path=str(attempt_dir / "debug-summary.json"),
        symbol_identity_validation={},
    )


def _persist_mi_debug_session(*, store: ArtifactStore, run_id: str, session: DebugSession) -> Path:
    """Write the DebugSession JSON to ``<run>/debug/sessions/<session_id>.json`` (the path
    ``_debug_session_manifest_details`` records and ``_load_active_debug_session`` reads back) and
    ensure its transcript/metadata directory exists. Returns the session-file path."""
    session_path = store.run_dir(run_id) / "debug" / "sessions" / f"{session.session_id}.json"
    session_path.parent.mkdir(parents=True, exist_ok=True)
    Path(session.transcript_path).parent.mkdir(parents=True, exist_ok=True)
    session_path.write_text(session.model_dump_json(indent=2), encoding="utf-8")
    return session_path


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


def debug_start_session_handler(
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
                # Finding F13: these are transport-resource conflicts (guard already held, or endpoint
                # exposure refusal), not gdb attach failures.
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
            # the session-of-record from it (no batch attach).
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
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    return ToolResponse.success(
        summary="gdb/MI debug session started",
        run_id=run_id,
        data=redactor.redact_value(details),
        artifacts=_redacted_artifacts(artifacts, redactor),
        suggested_next_actions=["debug.interrupt", "debug.read_registers", "artifacts.get_manifest"],
    )


def _load_active_debug_session(
    store: ArtifactStore,
    run_id: str,
    debug_session_id: str | None = None,
    *,
    allow_ended: bool = False,
) -> DebugSession:
    manifest = store.load_manifest(run_id)
    debug_result = manifest.step_results.get("debug")
    if debug_result is None:
        raise ProviderDebugError(
            "active debug session required",
            category=ErrorCategory.CONFIGURATION_ERROR,
        )
    active_details = _debug_session_details_from_result(debug_result, allow_ended=allow_ended)
    if active_details is None:
        raise ProviderDebugError(
            "active debug session required",
            category=ErrorCategory.CONFIGURATION_ERROR,
        )
    active_session_id = active_details.get("debug_session_id")
    if debug_session_id is not None and active_session_id != debug_session_id:
        raise ProviderDebugError(
            "requested debug session is not active",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"requested_debug_session_id": debug_session_id, "active_debug_session_id": active_session_id},
        )
    session_path_value = active_details.get("session_path")
    if type(session_path_value) is not str:
        raise ProviderDebugError(
            "active debug session did not record a session path",
            category=ErrorCategory.CONFIGURATION_ERROR,
        )
    run_dir = store.run_dir(run_id)
    session_path = _require_run_debug_path(Path(session_path_value), run_dir=run_dir, description="session path")
    try:
        session = DebugSession.model_validate_json(session_path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise ProviderDebugError(
            "failed to load active debug session",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"session_path": str(session_path), "error": str(exc)},
        ) from exc
    if session.run_id != run_id or session.provider_name != "local-qemu-gdbstub":
        raise ProviderDebugError(
            "active debug session file does not match run",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={
                "session_path": str(session_path),
                "session_run_id": session.run_id,
                "provider_name": session.provider_name,
            },
        )
    for description, path_value in [
        ("transcript path", session.transcript_path),
        ("command metadata path", session.command_metadata_path),
        ("summary path", session.latest_summary_path),
    ]:
        _require_run_debug_path(Path(path_value), run_dir=run_dir, description=description)
    if session.session_id != active_session_id:
        raise ProviderDebugError(
            "active debug session file does not match manifest",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"session_path": str(session_path), "session_id": session.session_id},
        )
    if (not allow_ended and session.current_execution_state == "ended") or session.attach_status != "attached":
        raise ProviderDebugError(
            "active debug session required",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"debug_session_id": session.session_id},
        )
    return session


def _mark_legacy_session_recovery_required(
    *, run_id: str, admission: AdmissionService, session_registry: SessionRegistry
) -> None:
    """Dual-write the `legacy_session_no_ownership` tombstone for a legacy DebugSession's target
    (Finding #5): durable `write_tombstone` + admission cache `mark_recovery_required`, never one
    alone. Generation is the authoritative snapshot's when one exists, else 0 (fail-closed at bare
    startup — admission's gate treats a tombstone-not-strictly-older-than-the-snapshot as live)."""
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = admission.current_snapshot(target_key)
    generation = snapshot.generation if snapshot is not None else 0
    session_registry.write_tombstone(
        RecoveryTombstone(target_key=target_key, generation=generation, reason="legacy_session_no_ownership")
    )
    admission.mark_recovery_required(target_key, generation)


def _assert_layer4_ownership(
    *,
    run_id: str,
    session_registry: SessionRegistry | None,
) -> None:
    """Pure ownership check (Finding F8). When `session_registry` is wired, raise
    `legacy_session_no_ownership` if no `TargetKey("local-qemu", run_id)` durable record exists.
    Does NOT tombstone — that side-effect belongs to `_fence_legacy_debug_session`, which the
    stateful mutating debug.* path uses; pure-read paths just need the assertion so they cannot
    silently halt the kernel as a side-effect of `target remote` against a legacy session.

    Inert (None) when no `session_registry` is supplied — every legacy caller passes none, so the
    read paths stay unchanged on a non-wired server."""
    if session_registry is None:
        return
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    if session_registry.read_record(target_key) is not None:
        return  # Layer-4-owned session; the durable record governs it.
    raise ProviderDebugError(
        "legacy debug session predates the transport-ownership model and has no durable record; "
        "it cannot be silently resumed.",
        category=ErrorCategory.DEBUG_ATTACH_FAILURE,
        details={"code": "legacy_session_no_ownership", "debug_session_id": None},
    )


def _fence_legacy_debug_session(
    *,
    run_id: str,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
) -> None:
    """Version-skew fence (§4.7/B7). A DebugSession persisted before the transport-ownership model
    carries a raw gdbstub_endpoint but NO durable SessionRegistry record. On a WIRED server a
    stateful mutating debug.* op must NOT silently resume it — that would bypass the durable model
    and leave target.run_tests blind to a kernel a stale session already halted. Stateful mutating
    debug.* ops take BOTH `admission` and `session_registry`; the read path takes
    `session_registry` only (Finding F8) and runs the lighter `_assert_layer4_ownership` instead.

    Additive: inert unless BOTH `admission` and `session_registry` are injected (every legacy caller
    passes neither). When wired:
    - A record EXISTS for TargetKey("local-qemu", run_id) ⇒ Layer-4-owned ⇒ proceed.
    - NO record ⇒ legacy: dual-write a recovery_required tombstone and REFUSE with
      DEBUG_ATTACH_FAILURE / `legacy_session_no_ownership`.

    A probe-permits-force-end branch is intentionally NOT implemented in #10: the probe reads the
    same SessionRegistry record this fence already confirmed absent, so it can only return UNKNOWN.
    An out-of-band EXECUTING source could permit force-ending a legacy session in a future layer —
    but #10 always refuses + tombstones. (`debug.end_session` is the one operation that must still
    detach a legacy session; it bypasses this fence and writes the tombstone post-detach instead.)"""
    if admission is None or session_registry is None:
        return
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    if session_registry.read_record(target_key) is not None:
        return  # Layer-4-owned session; the durable record governs it.
    _mark_legacy_session_recovery_required(run_id=run_id, admission=admission, session_registry=session_registry)
    raise ProviderDebugError(
        "legacy debug session predates the transport-ownership model and has no durable record; "
        "it cannot be silently resumed. The target is now recovery_required.",
        category=ErrorCategory.DEBUG_ATTACH_FAILURE,
        details={"code": "legacy_session_no_ownership", "debug_session_id": None},
    )


# Stateful debug.* ops whose effect changes the persisted breakpoint ledger; after each, the ledger
# is rebuilt from gdb's authoritative -break-list so the manifest matches the engine.
_BREAKPOINT_MUTATORS = frozenset({"set_breakpoint", "set_watchpoint", "clear_breakpoint", "clear_watchpoint"})
# Interactive resume verbs (continue/step/next/finish): engine method + how the timeout maps.
_EXEC_VERBS = {
    "continue_execution": lambda engine, att, timeout: engine.continue_(att, timeout_sec=timeout),
    "step": lambda engine, att, timeout: engine.step(att, timeout_sec=timeout),
    "next": lambda engine, att, timeout: engine.next(att, timeout_sec=timeout),
    "finish": lambda engine, att, timeout: engine.finish(att, timeout_sec=timeout),
}


def _engine_op_data(
    *, engine: GdbMiEngine, attachment: GdbMiAttachment, method_name: str, kwargs: dict[str, object]
) -> dict[str, object]:
    """Dispatch one debug.* operation onto the live gdb/MI attachment and return its typed JSON as a
    dict (the engine has already redacted every value). ``end_session`` is NOT routed here — it has a
    dedicated reap path. An unknown method is a CONFIGURATION_ERROR (defence in depth; the handler
    layer already gated the op name)."""
    if method_name == "read_registers":
        registers = kwargs["registers"]
        names = [str(name) for name in registers] if isinstance(registers, list) else []
        return engine.read_registers(attachment, names)
    if method_name == "read_symbol":
        return engine.read_symbol(attachment, str(kwargs["symbol"]))
    if method_name == "read_memory":
        address = kwargs["address"]
        byte_count = kwargs["byte_count"]
        if not isinstance(address, int) or not isinstance(byte_count, int):
            raise GdbMiError("address and byte_count must be integers", category=ErrorCategory.CONFIGURATION_ERROR)
        return engine.read_memory(attachment, address=address, byte_count=byte_count)
    if method_name == "evaluate":
        arguments = kwargs.get("arguments")
        evaluate_args: dict[str, object] = (
            {str(key): value for key, value in arguments.items()} if isinstance(arguments, dict) else {}
        )
        return engine.evaluate_inspector(attachment, inspector=str(kwargs["inspector"]), arguments=evaluate_args)
    if method_name == "set_breakpoint":
        return {"breakpoint": engine.set_breakpoint(attachment, str(kwargs["symbol"])).model_dump(mode="json")}
    if method_name == "set_watchpoint":
        return {"breakpoint": engine.set_watchpoint(attachment, str(kwargs["symbol"])).model_dump(mode="json")}
    if method_name == "clear_breakpoint":
        engine.clear_breakpoint(attachment, str(kwargs["breakpoint_id"]))
        return {}
    if method_name == "clear_watchpoint":
        engine.clear_watchpoint(attachment, str(kwargs["breakpoint_id"]))
        return {}
    if method_name == "list_breakpoints":
        return {"breakpoints": [ref.model_dump(mode="json") for ref in engine.list_breakpoints(attachment)]}
    if method_name == "backtrace":
        return {"frames": [frame.model_dump(mode="json") for frame in engine.backtrace(attachment)]}
    if method_name == "list_variables":
        return {"variables": [var.model_dump(mode="json") for var in engine.list_variables(attachment)]}
    if method_name == "interrupt":
        stop = engine.interrupt(attachment)
        stop_payload = stop.model_dump(mode="json") if stop is not None else None
        return {"stop": stop_payload, "current_execution_state": "stopped"}
    if method_name in _EXEC_VERBS:
        timeout = kwargs.get("timeout_seconds")
        stop = _EXEC_VERBS[method_name](engine, attachment, timeout)
        return {"stop": stop.model_dump(mode="json"), "current_execution_state": "stopped"}
    raise GdbMiError(
        "unsupported debug operation", category=ErrorCategory.CONFIGURATION_ERROR, details={"operation": method_name}
    )


def _mi_session_artifacts(*, store: ArtifactStore, run_id: str, session: DebugSession) -> list[ArtifactRef]:
    """The debug step's artifacts for the live session: the session JSON and its transcript. Rebuilt
    on each persisted op so a stateful re-record keeps the same artifact set start_session minted."""
    session_path = store.run_dir(run_id) / "debug" / "sessions" / f"{session.session_id}.json"
    return [
        ArtifactRef(path=str(session_path), kind="debug-session"),
        ArtifactRef(path=session.transcript_path, kind="debug-transcript", sensitive=True),
    ]


def _preserved_debug_step_details(store: ArtifactStore, run_id: str) -> dict[str, object]:
    """The start_session bindings a stateful re-record must carry forward (else a later end_session
    could not close the transport, and the MI probe record would be lost): transport_session_id and
    the typed mi_probe block."""
    try:
        existing = store.load_manifest(run_id).step_results.get("debug")
    except ManifestStateError:
        return {}
    if existing is None:
        return {}
    return {key: existing.details[key] for key in ("transport_session_id", "mi_probe") if key in existing.details}


def _debug_operation_response(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    method_name: str,
    kwargs: dict[str, object],
    persist_manifest: bool,
    allow_ended: bool = False,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    if gdb_mi_engine is None or gdb_mi_sessions is None:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message="the gdb/MI engine is not available on this server instance",
            run_id=run_id,
            details={"code": "debug_engine_unavailable"},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    redactor = Redactor()
    try:
        with store.debug_lock(run_id):
            session = _load_active_debug_session(store, run_id, debug_session_id, allow_ended=allow_ended)
            # Mutating-op fence (tombstones the legacy session) when BOTH admission + registry are
            # wired; pure-read assertion (no tombstone — reads are non-destructive) when only the
            # registry is wired. Finding F8: every debug.* path that connects gdb gets at least the
            # ownership assertion, so a legacy session can never silently halt the kernel as a side
            # effect of `target remote` against a run target.run_tests is unaware of. This runs BEFORE
            # the live-attachment lookup (ADR 0021 fence-then-lookup).
            if admission is not None:
                _fence_legacy_debug_session(run_id=run_id, admission=admission, session_registry=session_registry)
            else:
                _assert_layer4_ownership(run_id=run_id, session_registry=session_registry)
            profile = _resolve_debug_profile(
                profile_name=session.selected_debug_profile,
                debug_profiles=debug_profiles,
            )
            _ensure_debug_operation_enabled(profile, DEBUG_METHOD_OPERATIONS[method_name])
            attachment = gdb_mi_sessions.require(session.session_id)
            data = _engine_op_data(engine=gdb_mi_engine, attachment=attachment, method_name=method_name, kwargs=kwargs)
            updated_session = session
            if method_name in _BREAKPOINT_MUTATORS:
                ledger = {ref.number: ref.model_dump(mode="json") for ref in gdb_mi_engine.list_breakpoints(attachment)}
                updated_session = session.model_copy(update={"breakpoints": ledger})
            if persist_manifest:
                _persist_mi_debug_session(store=store, run_id=run_id, session=updated_session)
                details = {
                    **_debug_session_manifest_details(store=store, run_id=run_id, session=updated_session),
                    **_preserved_debug_step_details(store, run_id),
                    **data,
                }
                terminal = StepResult(
                    step_name="debug",
                    status=StepStatus.SUCCEEDED,
                    summary=f"debug.{method_name} succeeded",
                    artifacts=_mi_session_artifacts(store=store, run_id=run_id, session=updated_session),
                    details=details,
                )
                store.record_step_result(run_id, terminal, replace_succeeded=True)
            else:
                details = data
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    except ProviderDebugError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value(exc.details),
            artifacts=_redacted_artifacts(exc.artifacts, redactor),
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

    op_artifacts = _mi_session_artifacts(store=store, run_id=run_id, session=updated_session)
    return ToolResponse.success(
        summary=f"debug.{method_name} succeeded",
        run_id=run_id,
        data=redactor.redact_value(details),
        artifacts=_redacted_artifacts(op_artifacts, redactor),
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _debug_read_response(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    method_name: str,
    kwargs: dict[str, object],
    debug_profiles: dict[str, DebugProfile] | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    """Pure-read debug.* path. Takes `session_registry` (Finding F8) but NOT `admission`: reads
    do not register an ssh-tier admission, so the structural read/ssh-tier separation is
    preserved (the `test_debug_read_not_ssh_gated` invariant still holds). The registry presence
    drives the lighter `_assert_layer4_ownership` check, which closes the legacy-fence bypass
    where a `debug.read_*` call would silently halt the kernel via `target remote` against a run
    target.run_tests had no durable record for."""
    return _debug_operation_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name=method_name,
        kwargs=kwargs,
        persist_manifest=False,
        debug_profiles=debug_profiles,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_read_registers_handler(
    *,
    artifact_root: Path,
    run_id: str,
    registers: list[str],
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_read_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="read_registers",
        kwargs={"registers": registers},
        debug_profiles=debug_profiles,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_read_symbol_handler(
    *,
    artifact_root: Path,
    run_id: str,
    symbol: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_read_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="read_symbol",
        kwargs={"symbol": symbol},
        debug_profiles=debug_profiles,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_read_memory_handler(
    *,
    artifact_root: Path,
    run_id: str,
    address: int,
    byte_count: int,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_read_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="read_memory",
        kwargs={"address": address, "byte_count": byte_count},
        debug_profiles=debug_profiles,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_evaluate_handler(
    *,
    artifact_root: Path,
    run_id: str,
    inspector: str,
    arguments: dict[str, object] | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_read_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="evaluate",
        kwargs={"inspector": inspector, "arguments": arguments or {}},
        debug_profiles=debug_profiles,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def _debug_stateful_response(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    method_name: str,
    kwargs: dict[str, object],
    allow_ended: bool = False,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_operation_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name=method_name,
        kwargs=kwargs,
        persist_manifest=True,
        allow_ended=allow_ended,
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_set_breakpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    symbol: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="set_breakpoint",
        kwargs={"symbol": symbol},
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_set_watchpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    symbol: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="set_watchpoint",
        kwargs={"symbol": symbol},
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_clear_breakpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    breakpoint_id: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="clear_breakpoint",
        kwargs={"breakpoint_id": breakpoint_id},
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_clear_watchpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    breakpoint_id: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="clear_watchpoint",
        kwargs={"breakpoint_id": breakpoint_id},
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_list_breakpoints_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="list_breakpoints",
        kwargs={},
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_backtrace_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="backtrace",
        kwargs={},
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_list_variables_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="list_variables",
        kwargs={},
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_continue_handler(
    *,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="continue_execution",
        kwargs={"timeout_seconds": timeout_seconds},
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_step_handler(
    *,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="step",
        kwargs={"timeout_seconds": timeout_seconds},
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_next_handler(
    *,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="next",
        kwargs={"timeout_seconds": timeout_seconds},
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_finish_handler(
    *,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="finish",
        kwargs={"timeout_seconds": timeout_seconds},
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_interrupt_handler(
    *,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_stateful_response(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name="interrupt",
        kwargs={"timeout_seconds": timeout_seconds},
        debug_profiles=debug_profiles,
        admission=admission,
        session_registry=session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def _recorded_transport_session_id(*, artifact_root: Path, run_id: str) -> str | None:
    """Read the transport-ownership binding `debug.start_session` persisted into the debug step
    details (set only on the transaction-backed path). None when the run/manifest/step is absent or
    no transport session was bound — the legacy ungated path records nothing, so close() is skipped."""
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        if not (store.run_dir(run_id) / "manifest.json").is_file():
            return None
        debug_result = store.load_manifest(run_id).step_results.get("debug")
    except ManifestStateError:
        return None
    if debug_result is None:
        return None
    transport_session_id = debug_result.details.get("transport_session_id")
    return transport_session_id if isinstance(transport_session_id, str) else None


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
            if gdb_mi_sessions is not None:
                reaped = gdb_mi_sessions.reap(session.session_id)
                if reaped is not None and gdb_mi_engine is not None:
                    with contextlib.suppress(Exception):
                        gdb_mi_engine.force_resume(reaped)
            ended = session.model_copy(
                update={"current_execution_state": "ended", "ended_at": datetime.now(UTC).isoformat()}
            )
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
    # B7 review: end_session is the one stateful op that must still detach a LEGACY session (force-end
    # is the operation here), so the pre-detach fence is bypassed. A legacy session is one whose target
    # has no SessionRegistry ownership record; detect it BEFORE the detach so the post-detach tombstone
    # path below runs even though end_session rewrites the manifest's debug step. A Layer-4-owned
    # session has a record AND a `transport_session_id` — the transaction.close() branch governs it.
    is_legacy_session = (
        admission is not None
        and session_registry is not None
        and transport_session_id is None
        and session_registry.read_record(TargetKey(provisioner="local-qemu", target_id=run_id)) is None
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
    # B7 review (#10): a LEGACY session bypassed the pre-detach fence so end_session could force-end
    # the unmanaged stop, but target.run_tests would otherwise stay BLIND to that detach — exactly the
    # failure mode B7 fences against. Dual-write a recovery_required tombstone AFTER the successful
    # detach so run_tests stays gated until a `transport.open(recovery=True)` (or reset) clears it.
    if response.ok and is_legacy_session:
        assert admission is not None and session_registry is not None  # narrowed by is_legacy_session
        _mark_legacy_session_recovery_required(run_id=run_id, admission=admission, session_registry=session_registry)
    return response


def _transport_disabled_failure(*, run_id: str) -> ToolResponse:
    """The Layer-4 coordination collaborators (transaction/admission/registry) are not wired.
    create_app wiring is B6; until then a transport tool fails closed rather than acting."""
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message="transport coordination is not available on this server instance",
        run_id=run_id,
        details={"code": "transport_unavailable"},
    )


def _transport_open_request(*, run_id: str, admission: AdmissionService) -> OpenRequest:
    """Build the §4.3 transport.open request from the authoritative snapshot the boot step
    published: it reads `generation`/`platform` and the RSP channel straight from the snapshot
    (never re-derived — ADR 0007), so admission re-binds the request against its own facts and a
    snapshot naming an unregistered provider flows through to the transaction's lookup (mapped to
    CONFIGURATION_ERROR by the handler), not silently rewritten to qemu-gdbstub."""
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = _require_snapshot(admission, target_key)
    rsp_channel = next((ref for ref in snapshot.transports if ref.line_role is LineRole.RSP), None)
    if rsp_channel is None:
        raise AdmissionError(
            "authoritative snapshot exposes no RSP channel for a stop-capable open",
            category=ErrorCategory.READINESS_FAILURE,
            code="no_rsp_channel",
        )
    return OpenRequest(
        target_key=target_key,
        generation=snapshot.generation,
        transport_ref=rsp_channel,
        required_caps=["rsp"],
        platform=snapshot.platform,
    )


def transport_open_handler(
    *,
    run_id: str,
    recovery: bool = False,
    transaction: TransportTransaction | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
) -> ToolResponse:
    """transport.open: open a stop-capable transport session against the run's READY target,
    returning the session id and the bound loopback RSP endpoint. `recovery=True` admits through
    the recovery gate (clearing the recovery tombstone on commit) — the one path permitted while a
    target is recovery_required."""
    if transaction is None or admission is None or session_registry is None:
        return _transport_disabled_failure(run_id=run_id)
    # Finding F15: every failure path that surfaces `str(exc)` to the agent runs the text through
    # `Redactor` so an `OSError`/`EndpointSafetyError` message containing a secret-looking
    # endpoint path or generation number cannot leak. Details dicts pass through `redact_value`
    # for the same reason. Matches the pattern at `_debug_operation_response`.
    redactor = Redactor()
    try:
        request = _transport_open_request(run_id=run_id, admission=admission)
        session = transaction.open(request, recovery=recovery)
    except KeyError:
        # carried review note #1: a request naming a provider absent from the transaction's
        # transports map raises a bare KeyError; surface it as CONFIGURATION_ERROR, not a crash.
        return _configuration_failure(
            run_id=run_id,
            message=redactor.redact_text(f"no transport provider registered for {request.transport_ref.provider!r}"),
            details=redactor.redact_value({"code": "unknown_transport_provider"}),
        )
    except (GuardConflict, EndpointSafetyError) as exc:
        # Finding F13: see transport.open's mirror branch — guard/endpoint conflicts route
        # through TRANSPORT_CONFLICT, not the gdb-attach-specific DEBUG_ATTACH_FAILURE.
        return ToolResponse.failure(
            category=ErrorCategory.TRANSPORT_CONFLICT,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value({"code": getattr(exc, "code", "stop_capable_conflict")}),
            suggested_next_actions=["providers.list"],
        )
    except AdmissionError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value({"code": exc.code}),
            suggested_next_actions=["providers.list"],
        )
    return ToolResponse.success(
        summary=f"transport session {session.session_id} open",
        run_id=run_id,
        data={
            "session_id": session.session_id,
            "provider": session.provider,
            "channel_id": session.channel_id,
            "generation": session.generation,
            "rsp_endpoint": session.rsp_endpoint.model_dump(mode="json") if session.rsp_endpoint else None,
            "console_endpoint": session.console_endpoint.model_dump(mode="json") if session.console_endpoint else None,
        },
        suggested_next_actions=["debug.start_session"],
    )


def _resolve_session_for_run(
    *,
    session_registry: SessionRegistry,
    session_id: str,
    run_id: str,
) -> TransportSession | None:
    """Look up a TransportSession by session_id and verify it belongs to `run_id` (Finding F7).
    Returns the record on a match. Returns None if no record exists (caller decides whether that
    is a no-op success — `transport.close` — or a `unknown_session` failure — `inject_break`).
    Raises a `_SessionRunMismatch` (a stub `ValueError`) when the session exists but belongs to
    a different run; the caller surfaces this as a `session_run_mismatch` configuration_error so
    a caller cannot halt/close some OTHER run's kernel by passing its session_id under run_id=X."""
    record = next((r for r in session_registry.list_records() if r.session_id == session_id), None)
    if record is None:
        return None
    target_key = record.target_key
    if target_key.provisioner != "local-qemu" or target_key.target_id != run_id:
        raise _SessionRunMismatch(
            f"session {session_id!r} belongs to target {target_key.provisioner}/{target_key.target_id}, "
            f"not run {run_id!r}"
        )
    return record


class _SessionRunMismatch(ValueError):
    """Signal that a caller asked to operate on `session_id` under a `run_id` that does not own
    it — see `_resolve_session_for_run` (Finding F7)."""


def transport_close_handler(
    *,
    run_id: str,
    session_id: str,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
) -> ToolResponse:
    """transport.close: tear down an open transport session — close the backend, release the
    guard/lease, deregister the admission binding, and delete the durable record. An unknown
    session id is a no-op success (the record is already gone) but the response is marked
    `data["already_closed"] = True` so the caller can distinguish "I closed a live session" from
    "the session was already gone" (e.g. reaped out-of-band by reconcile() / lifecycle force_drop).
    A session that exists but belongs to a different run is refused as `session_run_mismatch`
    (Finding F7) — never close another run's session."""
    if transaction is None or session_registry is None:
        return _transport_disabled_failure(run_id=run_id)
    try:
        record = _resolve_session_for_run(session_registry=session_registry, session_id=session_id, run_id=run_id)
    except _SessionRunMismatch as exc:
        return _configuration_failure(
            run_id=run_id,
            message=str(exc),
            details={"code": "session_run_mismatch"},
        )
    if record is None:
        # The record was reaped out-of-band (reconcile() on restart, or a CRASHED/RESETTING
        # lifecycle event drove force_drop) before this close arrived. transaction.close would
        # no-op anyway; surface the distinction explicitly so callers can tell.
        return ToolResponse.success(
            summary=f"transport session {session_id} already closed",
            run_id=run_id,
            data={"session_id": session_id, "already_closed": True},
            suggested_next_actions=["transport.open"],
        )
    transaction.close(session_id)
    return ToolResponse.success(
        summary=f"transport session {session_id} closed",
        run_id=run_id,
        data={"session_id": session_id, "already_closed": False},
        suggested_next_actions=["transport.open"],
    )


def transport_inject_break_handler(
    *,
    run_id: str,
    session_id: str,
    acknowledged_permissions: list[str] | None = None,
    artifact_root: Path | None = None,
    transaction: TransportTransaction | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    break_mechanism: Callable[..., None] = inject_break,
    probe_halted: Callable[[TransportSession], bool] = probe_rsp_halted,
) -> ToolResponse:
    """transport.inject_break: drop the target kernel into the debugger over an open session.

    This is DESTRUCTIVE — it is refused unless the caller acknowledges every permission in
    `TRANSPORT_DESTRUCTIVE_PERMISSIONS["transport.inject_break"]`. The durable record is written
    `execution_state=HALTED` BEFORE the break mechanism runs (so a death during the break can never
    strand the record as EXECUTING and let an ssh-tier op admit against a halted kernel), and the
    execution epoch is bumped to invalidate any pre-halt EXECUTING proof. If the break is
    unconfirmable — the mechanism raises a known `InjectBreakError` OR any other exception (an
    OSError, or the B6 real-mechanism missing-kwargs trap) — the record is written `UNKNOWN`,
    NEVER left EXECUTING and never stranded at the optimistic HALTED.

    Finding #4 / ADR 0006: after the mechanism returns successfully, the handler RE-PROBES the
    execution state. The mechanism's return value alone is not authoritative — a silent-no-op
    wiring or a misconfigured `break_plan` can return success while the kernel keeps running. If
    the probe observes anything other than HALTED (including a probe exception / timeout), the
    handler dual-writes UNKNOWN to the durable record and returns
    DEBUG_ATTACH_FAILURE/break_unconfirmed — preserving the existing fail-closed posture.
    """
    if transaction is None or admission is None or session_registry is None:
        return _transport_disabled_failure(run_id=run_id)
    missing = missing_destructive_permissions("transport.inject_break", acknowledged_permissions or [])
    if missing:
        return _configuration_failure(
            run_id=run_id,
            message="transport.inject_break is destructive; acknowledge its required permissions to proceed",
            details={"code": "permission_required", "required_permissions": missing},
        )
    # Finding F14: inject_break is destructive — gate it by `DebugProfile.enabled_operations` like
    # every other halting debug.* op. Resolve the run's debug profile from its manifest when
    # `artifact_root` is supplied (production wiring), otherwise fall through to the default
    # profile name (test handlers that exercise the post-permission path don't load a manifest).
    requested_profile = "qemu-gdbstub-default"
    if artifact_root is not None:
        try:
            store = ArtifactStore(artifact_root, create_root=False)
            requested_profile = store.load_manifest(run_id).request.debug_profile or "qemu-gdbstub-default"
        except (ManifestStateError, FileNotFoundError, OSError):
            # No manifest for this run (or unreadable) — fall back to the default profile name;
            # _resolve_debug_profile will fail closed if the name is unknown in the registry.
            pass
    try:
        resolved_profile = _resolve_debug_profile(profile_name=requested_profile, debug_profiles=debug_profiles)
        _ensure_debug_operation_enabled(resolved_profile, "transport.inject_break")
    except ProviderDebugError as exc:
        return _configuration_failure(run_id=run_id, message=str(exc), details=exc.details)
    try:
        record = _resolve_session_for_run(
            session_registry=session_registry,
            session_id=session_id,
            run_id=run_id,
        )
    except _SessionRunMismatch as exc:
        # Finding F7: never halt some OTHER run's kernel because a caller passed a foreign
        # session_id under run_id=X. Refuse before _halt_debug_transport writes HALTED.
        return _configuration_failure(
            run_id=run_id,
            message=str(exc),
            details={"code": "session_run_mismatch"},
        )
    if record is None:
        return _configuration_failure(
            run_id=run_id,
            message=f"no open transport session for break injection: {session_id}",
            details={"code": "unknown_session"},
        )
    # Persist HALTED + bump the execution epoch BEFORE the break runs (the ordering target.run_tests
    # depends on to reject `target_halted` for the whole window the debugger owns the kernel). Reuse
    # the one helper that defines the durable-write-then-note ordering.
    _halt_debug_transport(session=record, admission=admission, session_registry=session_registry)
    # Finding F15: redact every exception message / details dict before surfacing them to the
    # agent. An InjectBreakError.details (or an OSError str) can carry endpoint paths, generation
    # numbers, or attached secrets; matches the redaction pattern at `_debug_operation_response`.
    redactor = Redactor()
    try:
        break_mechanism(method="auto", break_plan=record.break_plan)
    except InjectBreakError as exc:
        # A KNOWN break failure: record UNKNOWN (never the stale optimistic HALTED) and surface the
        # mechanism's own ErrorCategory so admission fails closed until a fresh probe runs.
        session_registry.write_record(record.model_copy(update={"execution_state": ExecutionState.UNKNOWN}))
        exc_details = dict(getattr(exc, "details", {}) or {})
        details = redactor.redact_value(
            {
                **exc_details,
                "code": "break_unconfirmed",
                "execution_state": ExecutionState.UNKNOWN.value,
            }
        )
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=details,
            suggested_next_actions=["providers.list"],
        )
    except Exception as exc:
        # ANY other mechanism failure (OSError, a missing-kwargs TypeError from a real wiring bug)
        # MUST hold the same invariant: an unconfirmable break can never leave EXECUTING or a stale
        # HALTED, so fail closed to UNKNOWN rather than crash after the durable HALTED write.
        session_registry.write_record(record.model_copy(update={"execution_state": ExecutionState.UNKNOWN}))
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=redactor.redact_text(f"break mechanism failed unexpectedly: {exc}"),
            run_id=run_id,
            details=redactor.redact_value(
                {"code": "break_unconfirmed", "execution_state": ExecutionState.UNKNOWN.value}
            ),
            suggested_next_actions=["providers.list"],
        )
    # Post-probe (Finding F2/F4): perform a REAL bounded RSP `?` exchange against the session's
    # rsp_endpoint to confirm the kernel actually halted. Reading the cached `execution_state`
    # flag back (the prior implementation) was circular — `_halt_debug_transport` above writes
    # HALTED to that same field, so a kernel that silently kept running would still report HALTED
    # and `break_unconfirmed` was unreachable on the success path (ADR 0001's rejected design).
    # A probe exception or any non-stop-reply observation is fail-closed to UNKNOWN — matching
    # the existing exception-branch posture and the §5.6 "no optimistic admit" rule.
    try:
        halted_observed = probe_halted(record)
    except Exception:  # noqa: BLE001 — probe failure ⇒ unknown, fail closed
        halted_observed = False
    if not halted_observed:
        session_registry.write_record(record.model_copy(update={"execution_state": ExecutionState.UNKNOWN}))
        return ToolResponse.failure(
            category=ErrorCategory.DEBUG_ATTACH_FAILURE,
            message="inject_break: post-probe did not confirm HALTED",
            run_id=run_id,
            details={
                "code": "break_unconfirmed",
                "execution_state": ExecutionState.UNKNOWN.value,
                "probe_observed": ExecutionState.UNKNOWN.value,
            },
            suggested_next_actions=["providers.list"],
        )
    return ToolResponse.success(
        summary=f"break injected on transport session {session_id}; target halted",
        run_id=run_id,
        data={"session_id": session_id, "execution_state": ExecutionState.HALTED.value},
        suggested_next_actions=["debug.start_session"],
    )


def _bundle_for_manifest(
    *,
    manifest: RunManifest,
    run_dir: Path,
    bundle_path: Path,
) -> tuple[dict[str, Any], list[ArtifactRef], list[dict[str, Any]], list[dict[str, Any]]]:
    required_kinds_by_step = {
        "build": {"build-log", "kernel-config", "kernel-image"},
        "boot": {"domain-xml", "boot-plan", "console-log", "boot-log"},
        "debug": {"debug-command-metadata", "debug-session", "debug-summary", "debug-transcript"},
        "run_tests": {"test-summary"},
    }
    optional_kinds_by_step = {"build": {"vmlinux"}}
    grouped: dict[str, list[dict[str, Any]]] = {}
    missing_required: list[dict[str, Any]] = []
    missing_optional: list[dict[str, Any]] = []
    collected_refs: list[ArtifactRef] = []
    for step in manifest.steps:
        result = manifest.step_results.get(step.name)
        grouped[step.name] = []
        if result is None:
            continue
        present_kinds = {artifact.kind for artifact in result.artifacts}
        if result.status == StepStatus.SUCCEEDED:
            for kind in sorted(required_kinds_by_step.get(step.name, set()) - present_kinds):
                missing_required.append(
                    {"step": step.name, "kind": kind, "reason": "required artifact kind was not recorded"}
                )
            for kind in sorted(optional_kinds_by_step.get(step.name, set()) - present_kinds):
                missing_optional.append(
                    {"step": step.name, "kind": kind, "reason": "optional artifact kind was not recorded"}
                )
        for artifact in result.artifacts:
            exists = Path(artifact.path).is_file()
            item = {**artifact.model_dump(mode="json"), "exists": exists}
            grouped[step.name].append(item)
            if exists:
                collected_refs.append(artifact)
            elif result.status == StepStatus.SUCCEEDED and artifact.kind not in optional_kinds_by_step.get(
                step.name, set()
            ):
                missing_required.append({"step": step.name, "artifact": artifact.model_dump(mode="json")})
            else:
                missing_optional.append({"step": step.name, "artifact": artifact.model_dump(mode="json")})

    # Iter-2 finding 1: dynamic step results (e.g., introspect:<call_id>)
    # are not in the fixed `manifest.steps` list but DO exist in
    # `manifest.step_results`. Without this pass, every introspect artifact
    # is silently dropped from the bundle, _collection_covers_manifest
    # returns False on every subsequent call (forcing a re-bundle that
    # still misses the same artifacts), and forensic exports lose every
    # introspect call. Group them under their actual step_results key so
    # the bundle's "artifacts_by_step" shape stays self-describing.
    fixed_step_names = {step.name for step in manifest.steps}
    for step_name, result in manifest.step_results.items():
        if step_name in fixed_step_names:
            continue
        grouped[step_name] = []
        for artifact in result.artifacts:
            exists = Path(artifact.path).is_file()
            item = {**artifact.model_dump(mode="json"), "exists": exists}
            grouped[step_name].append(item)
            if exists:
                collected_refs.append(artifact)
            elif result.status == StepStatus.SUCCEEDED:
                missing_required.append({"step": step_name, "artifact": artifact.model_dump(mode="json")})
            else:
                missing_optional.append({"step": step_name, "artifact": artifact.model_dump(mode="json")})
    bundle_ref = ArtifactRef(path=str(bundle_path), kind="artifact-bundle")
    bundle = {
        "run_id": manifest.run_id,
        "run_dir": str(run_dir),
        "collected_at": datetime.now(UTC).isoformat(),
        "selected_profiles": manifest.request.model_dump(mode="json"),
        "steps": {step.name: step.status for step in manifest.steps},
        "summaries": {
            name: {"status": result.status, "summary": result.summary} for name, result in manifest.step_results.items()
        },
        "artifacts_by_step": grouped,
        "missing_expected_artifacts": missing_required,
        "missing_optional_artifacts": missing_optional,
        "cleanup_state": manifest.cleanup_state,
        "rollup": {
            "ok": not missing_required,
            "missing_required": len(missing_required),
            "missing_optional": len(missing_optional),
        },
    }
    return bundle, [*collected_refs, bundle_ref], missing_required, missing_optional


def _collection_covers_manifest(*, manifest: RunManifest, collect_result: StepResult) -> bool:
    collected = {
        (artifact.path, artifact.kind) for artifact in collect_result.artifacts if artifact.kind != "artifact-bundle"
    }
    current = {
        (artifact.path, artifact.kind)
        for step_name, result in manifest.step_results.items()
        if step_name != "collect_artifacts"
        for artifact in result.artifacts
    }
    return current.issubset(collected)


def artifacts_collect_handler(
    *,
    artifact_root: Path,
    run_id: str,
    force_recollect: bool = False,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    existing = manifest.step_results.get("collect_artifacts")
    if (
        existing
        and existing.status == StepStatus.SUCCEEDED
        and not force_recollect
        and _collection_covers_manifest(manifest=manifest, collect_result=existing)
    ):
        return _recorded_collect_success_response(run_id=run_id, result=existing)
    try:
        with store.collect_lock(run_id):
            locked_manifest = store.load_manifest(run_id)
            existing = locked_manifest.step_results.get("collect_artifacts")
            replace_succeeded = force_recollect or bool(existing and existing.status == StepStatus.SUCCEEDED)
            if (
                existing
                and existing.status == StepStatus.SUCCEEDED
                and not force_recollect
                and _collection_covers_manifest(manifest=locked_manifest, collect_result=existing)
            ):
                return _recorded_collect_success_response(run_id=run_id, result=existing)
            bundle_path = store.run_dir(run_id) / "summaries" / "artifact-bundle.json"
            bundle, artifacts, missing_required, missing_optional = _bundle_for_manifest(
                manifest=locked_manifest,
                run_dir=store.run_dir(run_id),
                bundle_path=bundle_path,
            )
            bundle_path.parent.mkdir(parents=True, exist_ok=True)
            bundle_path.write_text(
                json.dumps(Redactor().redact_value(bundle), indent=2, default=str),
                encoding="utf-8",
            )
            status = StepStatus.FAILED if missing_required else StepStatus.SUCCEEDED
            result = StepResult(
                step_name="collect_artifacts",
                status=status,
                summary=(
                    "artifact collection succeeded"
                    if status == StepStatus.SUCCEEDED
                    else "artifact collection found missing required artifacts"
                ),
                artifacts=artifacts,
                details={"bundle": bundle, "rollup": bundle["rollup"]},
            )
            store.record_step_result(run_id, result, replace_succeeded=replace_succeeded)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    redactor = Redactor()
    safe_bundle = redactor.redact_value(bundle)
    safe_artifacts = _redacted_artifacts(artifacts, redactor)
    if missing_required:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=redactor.redact_text(result.summary),
            run_id=run_id,
            details={
                "bundle": safe_bundle,
                "rollup": safe_bundle["rollup"],
                "missing_required": redactor.redact_value(missing_required),
                "missing_optional": redactor.redact_value(missing_optional),
            },
            artifacts=safe_artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    return ToolResponse.success(
        summary=redactor.redact_text(result.summary),
        run_id=run_id,
        data={"bundle": safe_bundle, "rollup": safe_bundle["rollup"]},
        artifacts=safe_artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _workflow_failure_response(
    *,
    run_id: str | None,
    failing_step: str,
    latest_successful_step: str | None,
    response: ToolResponse,
    collect_response: ToolResponse | None,
) -> ToolResponse:
    details = {
        "failing_step": failing_step,
        "latest_successful_step": latest_successful_step,
        "failed_response": response.model_dump(mode="json"),
        "collect_response": collect_response.model_dump(mode="json") if collect_response else None,
    }
    category = response.error.category if response.error else ErrorCategory.INFRASTRUCTURE_FAILURE
    message = response.error.message if response.error else response.summary or f"{failing_step} failed"
    failure_response = ToolResponse.failure(
        category=category,
        message=message,
        run_id=run_id,
        details=details,
        artifacts=[*(response.artifacts or []), *((collect_response.artifacts if collect_response else []) or [])],
        suggested_next_actions=["artifacts.get_manifest", "Inspect artifact bundle"],
    )
    failure_response.data = details
    return failure_response


def workflow_build_boot_test_handler(
    *,
    artifact_root: Path,
    source_path: str,
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    run_id: str | None = None,
    test_suite: str | None = None,
    commands: list[list[str]] | None = None,
    force_rebuild: bool = False,
    force_reboot: bool = False,
    force_rerun_tests: bool = False,
    force_recollect: bool = False,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
) -> ToolResponse:
    if run_id is not None:
        try:
            store = ArtifactStore(artifact_root, create_root=False)
            manifest_path = store.run_dir(run_id) / "manifest.json"
            if manifest_path.is_file():
                manifest = store.load_manifest(run_id)
                resolved_test_suite = test_suite if test_suite is not None else manifest.request.test_suite
                try:
                    resolved_source_path = str(validate_source_path(Path(source_path)))
                except PathSafetyError as exc:
                    return ToolResponse.failure(
                        category=ErrorCategory.CONFIGURATION_ERROR,
                        message=str(exc),
                        run_id=run_id,
                        details={"source_path": source_path},
                    )
                expected = {
                    "source_path": resolved_source_path,
                    "build_profile": build_profile,
                    "target_profile": target_profile,
                    "rootfs_profile": rootfs_profile,
                    "test_suite": resolved_test_suite,
                }
                actual = {
                    "source_path": manifest.request.source_path,
                    "build_profile": manifest.request.build_profile,
                    "target_profile": manifest.request.target_profile,
                    "rootfs_profile": manifest.request.rootfs_profile,
                    "test_suite": manifest.request.test_suite,
                }
                mismatches = {
                    key: {"requested": expected[key], "manifest": actual[key]}
                    for key in expected
                    if expected[key] != actual[key]
                }
                if mismatches:
                    return ToolResponse.failure(
                        category=ErrorCategory.CONFIGURATION_ERROR,
                        message="immutable run manifest request mismatch",
                        run_id=run_id,
                        details={"mismatches": mismatches},
                    )
                test_suite = resolved_test_suite
        except ManifestStateError as exc:
            return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    if run_id is None or not (artifact_root / run_id / "manifest.json").is_file():
        create_response = create_run_handler(
            artifact_root=artifact_root,
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            test_suite=test_suite,
        )
        if not create_response.ok:
            return create_response
        run_id = create_response.run_id
    if run_id is None:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="workflow.build_boot_test could not establish a run_id",
        )

    build_response = kernel_build_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        build_profile=build_profile,
        force_rebuild=force_rebuild,
    )
    if not build_response.ok:
        collect_response = artifacts_collect_handler(
            artifact_root=artifact_root,
            run_id=run_id,
            force_recollect=force_recollect,
        )
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="build",
            latest_successful_step=None,
            response=build_response,
            collect_response=collect_response,
        )

    boot_response = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        force_reboot=force_reboot,
        admission=admission,
    )
    if not boot_response.ok:
        collect_response = artifacts_collect_handler(
            artifact_root=artifact_root,
            run_id=run_id,
            force_recollect=force_recollect,
        )
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="boot",
            latest_successful_step="build",
            response=boot_response,
            collect_response=collect_response,
        )

    test_response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        test_suite=test_suite,
        commands=commands,
        force_rerun=force_rerun_tests,
        admission=admission,
        session_registry=session_registry,
    )
    collect_response = artifacts_collect_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        force_recollect=force_recollect,
    )
    if not test_response.ok:
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="run_tests",
            latest_successful_step="boot",
            response=test_response,
            collect_response=collect_response,
        )
    if not collect_response.ok:
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="collect_artifacts",
            latest_successful_step="run_tests",
            response=collect_response,
            collect_response=collect_response,
        )
    return ToolResponse.success(
        summary="build, boot, test workflow succeeded",
        run_id=run_id,
        data={
            "steps": {
                "build": build_response.model_dump(mode="json"),
                "boot": boot_response.model_dump(mode="json"),
                "run_tests": test_response.model_dump(mode="json"),
                "collect_artifacts": collect_response.model_dump(mode="json"),
            },
            "latest_successful_step": "collect_artifacts",
            "artifact_bundle": next(
                (
                    artifact.model_dump(mode="json")
                    for artifact in collect_response.artifacts
                    if artifact.kind == "artifact-bundle"
                ),
                None,
            ),
        },
        artifacts=collect_response.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def workflow_build_boot_debug_handler(
    *,
    artifact_root: Path,
    source_path: str,
    build_profile: str,
    target_profile: str,
    rootfs_profile: str,
    run_id: str | None = None,
    debug_profile: str | None = None,
    force_rebuild: bool = False,
    force_reboot: bool = False,
    new_session: bool = False,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    transaction: TransportTransaction | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    if run_id is not None:
        try:
            store = ArtifactStore(artifact_root, create_root=False)
            manifest_path = store.run_dir(run_id) / "manifest.json"
            if manifest_path.is_file():
                manifest = store.load_manifest(run_id)
                resolved_debug_profile = debug_profile if debug_profile is not None else manifest.request.debug_profile
                try:
                    resolved_source_path = str(validate_source_path(Path(source_path)))
                except PathSafetyError as exc:
                    return ToolResponse.failure(
                        category=ErrorCategory.CONFIGURATION_ERROR,
                        message=str(exc),
                        run_id=run_id,
                        details={"source_path": source_path},
                    )
                expected = {
                    "source_path": resolved_source_path,
                    "build_profile": build_profile,
                    "target_profile": target_profile,
                    "rootfs_profile": rootfs_profile,
                    **({"debug_profile": resolved_debug_profile} if manifest.request.debug_profile is not None else {}),
                }
                actual = {
                    "source_path": manifest.request.source_path,
                    "build_profile": manifest.request.build_profile,
                    "target_profile": manifest.request.target_profile,
                    "rootfs_profile": manifest.request.rootfs_profile,
                    **(
                        {"debug_profile": manifest.request.debug_profile}
                        if manifest.request.debug_profile is not None
                        else {}
                    ),
                }
                mismatches = {
                    key: {"requested": expected[key], "manifest": actual[key]}
                    for key in expected
                    if expected[key] != actual[key]
                }
                if mismatches:
                    return ToolResponse.failure(
                        category=ErrorCategory.CONFIGURATION_ERROR,
                        message="immutable run manifest request mismatch",
                        run_id=run_id,
                        details={"mismatches": mismatches},
                    )
                if manifest.request.debug_profile is not None or debug_profile is None:
                    debug_profile = resolved_debug_profile
        except ManifestStateError as exc:
            return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    if run_id is None or not (artifact_root / run_id / "manifest.json").is_file():
        create_response = create_run_handler(
            artifact_root=artifact_root,
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            debug_profile=debug_profile,
        )
        if not create_response.ok:
            return create_response
        run_id = create_response.run_id
    if run_id is None:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            message="workflow.build_boot_debug could not establish a run_id",
        )

    build_response = kernel_build_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        build_profile=build_profile,
        force_rebuild=force_rebuild,
    )
    if not build_response.ok:
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="build",
            latest_successful_step=None,
            response=build_response,
            collect_response=None,
        )

    boot_response = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
        force_reboot=force_reboot,
        admission=admission,
    )
    if not boot_response.ok:
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="boot",
            latest_successful_step="build",
            response=boot_response,
            collect_response=None,
        )

    debug_response = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profile=debug_profile,
        new_session=new_session,
        transaction=transaction,
        admission=admission,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )
    if not debug_response.ok:
        return _workflow_failure_response(
            run_id=run_id,
            failing_step="debug",
            latest_successful_step="boot",
            response=debug_response,
            collect_response=None,
        )

    return ToolResponse.success(
        summary="build, boot, debug workflow succeeded",
        run_id=run_id,
        data={
            "steps": {
                "build": build_response.model_dump(mode="json"),
                "boot": boot_response.model_dump(mode="json"),
                "debug": debug_response.model_dump(mode="json"),
            },
            "latest_successful_step": "debug",
        },
        artifacts=debug_response.artifacts,
        suggested_next_actions=["debug.read_registers", "debug.evaluate", "debug.end_session"],
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
    """Load the operator ServerConfig from the path in ``LINUX_DEBUG_MCP_CONFIG``, if set.

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

    # Production lifecycle-event source (Finding #3 / ADR 0006): `registry.reconcile()`'s
    # orphan-backend reap is the one production point at which "the backend died" is known in
    # #10. The closure drives `admission.invalidate_lifecycle(target_key, CRASHED)`, which runs
    # the §4.5 chain end-to-end (close_admission → dispatcher.emit → _SessionSubscriber.force_drop
    # → guard/lease release + record delete + handle deregister). Registry imports stay free of
    # admission/lifecycle — the closure's body lives here, the registry just invokes it.
    #
    # Finding F1: only close admission when we actually killed a live orphan backend
    # (`close_admission_required`). For the common cold-restart case where the durable record's
    # backend was already dead (or `backend_pid is None` — qemu-gdbstub), we emit the lifecycle
    # event for any subscriber but do NOT set `_closed_at` for the target. No production code
    # path calls `reopen()`, so a `_closed_at` write would permanently brick admission for the
    # target until process restart.
    def _on_orphan_reaped(reap: OrphanReap) -> None:
        admission.invalidate_lifecycle(
            LifecycleEvent(target_key=reap.target_key, kind=LifecycleKind.CRASHED),
            lifecycle_dispatcher,
            generation=reap.record.generation,
            close_admission=reap.close_admission_required,
        )

    if session_registry is None:
        session_registry = SessionRegistry(
            directory=Path(tempfile.mkdtemp(prefix="linux-debug-mcp-registry-")),
            on_orphan_reaped=_on_orphan_reaped,
        )
    else:
        # An injected registry (test wiring) may not have been constructed with the callback.
        # The callback hook is a private attribute; setting it here lets test fixtures share the
        # production behavior without forcing every test that builds a SessionRegistry by hand
        # to know about the §4.5 reap-source contract.
        session_registry._on_orphan_reaped = _on_orphan_reaped

    secrets_backends: dict[SecretReferenceKind, SecretsBackend] = {SecretReferenceKind.ENV: EnvSecretsBackend()}
    # keyring extra not installed -> the kind stays unavailable until configured
    with contextlib.suppress(SecretsResolutionError):
        secrets_backends[SecretReferenceKind.KEYRING] = KeyringSecretsBackend()
    _external_cmd = os.environ.get("LDM_SECRETS_EXTERNAL_CMD")
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
    # Finding F9: surface every callback failure through the project logger. `reconcile()` no
    # longer silently swallows them; reaped records were still deleted, but the lifecycle event
    # for those targets may have been lost. Visibility lets operators triage; this is not fatal
    # because reconcile-before-serve must always proceed (a wedge here would deny service).
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
    app = FastMCP("linux-debug-mcp")
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
    gdb_mi_engine = GdbMiEngine()
    gdb_mi_sessions = GdbMiSessionRegistry()
    # Stash the assembled machinery on the FastMCP instance so test-injection and any future
    # in-process lifecycle event source can reach the SAME admission/transaction/dispatcher trio
    # the tool wrappers close over (rather than constructing a parallel set that would not share
    # state with the live wrappers). Private attribute by convention; not part of the wire surface.
    # FastMCP has no slot for this; setattr makes the dynamic stash explicit so static checkers
    # do not flag a missing attribute on a third-party class we cannot extend.
    setattr(app, "_transport_machinery", machinery)  # noqa: B010

    @app.tool(name="host.check_prerequisites")
    def host_check_prerequisites(
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        source_path: str | None = None,
        enable_libvirt_check: bool = False,
    ) -> dict[str, Any]:
        return prerequisites_handler(
            artifact_root=Path(artifact_root),
            source_path=source_path,
            enable_libvirt_check=enable_libvirt_check,
        ).model_dump(mode="json")

    @app.tool(name="kernel.create_run")
    def kernel_create_run(
        source_path: str,
        build_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        run_id: str | None = None,
        debug_profile: str | None = None,
        test_suite: str | None = None,
        kernel_args: list[str] | None = None,
        rootfs_source: str | None = None,
        make_variables: dict[str, str] | None = None,
        config_lines: list[str] | None = None,
        rootfs_overrides: dict[str, Any] | None = None,
        build_profile_spec: dict[str, Any] | None = None,
        target_profile_spec: dict[str, Any] | None = None,
        rootfs_profile_spec: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            build_overrides, boot_overrides = _overrides_from_tool_args(
                kernel_args=kernel_args,
                rootfs_source=rootfs_source,
                make_variables=make_variables,
                config_lines=config_lines,
                rootfs_overrides=rootfs_overrides,
            )
        except ValueError as exc:
            return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, message=str(exc)).model_dump(
                mode="json"
            )
        return create_run_handler(
            artifact_root=Path(artifact_root),
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            debug_profile=debug_profile,
            test_suite=test_suite,
            build_overrides=build_overrides,
            boot_overrides=boot_overrides,
            sensitive_paths=sensitive_paths,
            build_profile_spec=build_profile_spec,
            target_profile_spec=target_profile_spec,
            rootfs_profile_spec=rootfs_profile_spec,
        ).model_dump(mode="json")

    @app.tool(name="providers.list")
    def providers_list() -> dict[str, Any]:
        return list_providers_handler().model_dump(mode="json")

    @app.tool(name="remote.build_kernel")
    def remote_build_kernel(
        architecture: str,
        source_ref: str,
        build_profile: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        output_artifact_ref: str | None = None,
    ) -> dict[str, Any]:
        return remote_build_kernel_handler(
            architecture=architecture,
            source_ref=source_ref,
            build_profile=build_profile,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            output_artifact_ref=output_artifact_ref,
        ).model_dump(mode="json")

    @app.tool(name="remote.sync_artifacts")
    def remote_sync_artifacts(
        architecture: str,
        external_artifact_ref: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        destination_artifact_ref: str | None = None,
    ) -> dict[str, Any]:
        return remote_sync_artifacts_handler(
            architecture=architecture,
            external_artifact_ref=external_artifact_ref,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            destination_artifact_ref=destination_artifact_ref,
        ).model_dump(mode="json")

    @app.tool(name="reservation.request_host")
    def reservation_request_host(
        architecture: str,
        reservation_pool: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        reservation_token_ref: str | None = None,
    ) -> dict[str, Any]:
        return reservation_request_host_handler(
            architecture=architecture,
            reservation_pool=reservation_pool,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            reservation_token_ref=reservation_token_ref,
        ).model_dump(mode="json")

    @app.tool(name="reservation.release_host")
    def reservation_release_host(
        architecture: str,
        reservation_id: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        return reservation_release_host_handler(
            architecture=architecture,
            reservation_id=reservation_id,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
        ).model_dump(mode="json")

    @app.tool(name="provision.prepare_target")
    def provision_prepare_target(
        architecture: str,
        target_name: str,
        provisioning_profile: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        reservation_id: str | None = None,
        credential_ref: str | None = None,
    ) -> dict[str, Any]:
        return provision_prepare_target_handler(
            architecture=architecture,
            target_name=target_name,
            provisioning_profile=provisioning_profile,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            reservation_id=reservation_id,
            credential_ref=credential_ref,
        ).model_dump(mode="json")

    @app.tool(name="hardware.power_control")
    def hardware_power_control(
        architecture: str,
        target_name: str,
        action: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        bmc_credential_ref: str | None = None,
    ) -> dict[str, Any]:
        return hardware_power_control_handler(
            architecture=architecture,
            target_name=target_name,
            action=action,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            bmc_credential_ref=bmc_credential_ref,
        ).model_dump(mode="json")

    @app.tool(name="hardware.boot_kernel")
    def hardware_boot_kernel(
        architecture: str,
        target_name: str,
        kernel_artifact_ref: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        boot_profile: str | None = None,
        reservation_id: str | None = None,
    ) -> dict[str, Any]:
        return hardware_boot_kernel_handler(
            architecture=architecture,
            target_name=target_name,
            kernel_artifact_ref=kernel_artifact_ref,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            boot_profile=boot_profile,
            reservation_id=reservation_id,
        ).model_dump(mode="json")

    @app.tool(name="console.open_session")
    def console_open_session(
        architecture: str,
        target_name: str,
        access_method: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        credential_ref: str | None = None,
    ) -> dict[str, Any]:
        return console_open_session_handler(
            architecture=architecture,
            target_name=target_name,
            access_method=access_method,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            credential_ref=credential_ref,
        ).model_dump(mode="json")

    @app.tool(name="console.read")
    def console_read(
        architecture: str,
        console_session_id: str,
        max_bytes: int = 4096,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        return console_read_handler(
            architecture=architecture,
            console_session_id=console_session_id,
            max_bytes=max_bytes,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
        ).model_dump(mode="json")

    @app.tool(name="console.write")
    def console_write(
        architecture: str,
        console_session_id: str,
        data: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        return console_write_handler(
            architecture=architecture,
            console_session_id=console_session_id,
            data=data,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
        ).model_dump(mode="json")

    @app.tool(name="workflow.reserve_provision_boot")
    def workflow_reserve_provision_boot(
        architecture: str,
        reservation_pool: str,
        target_name: str,
        provisioning_profile: str,
        kernel_artifact_ref: str,
        provider_name: str | None = None,
        timeout_seconds: int = 300,
        operation_label: str | None = None,
        run_id: str | None = None,
        reservation_token_ref: str | None = None,
        credential_ref: str | None = None,
        bmc_credential_ref: str | None = None,
    ) -> dict[str, Any]:
        return workflow_reserve_provision_boot_handler(
            architecture=architecture,
            reservation_pool=reservation_pool,
            target_name=target_name,
            provisioning_profile=provisioning_profile,
            kernel_artifact_ref=kernel_artifact_ref,
            provider_name=provider_name,
            timeout_seconds=timeout_seconds,
            operation_label=operation_label,
            run_id=run_id,
            reservation_token_ref=reservation_token_ref,
            credential_ref=credential_ref,
            bmc_credential_ref=bmc_credential_ref,
        ).model_dump(mode="json")

    @app.tool(name="artifacts.get_manifest")
    def artifacts_get_manifest(run_id: str, artifact_root: str = str(DEFAULT_ARTIFACT_ROOT)) -> dict[str, Any]:
        return get_manifest_handler(artifact_root=Path(artifact_root), run_id=run_id).model_dump(mode="json")

    @app.tool(name="kernel.build")
    def kernel_build(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        build_profile: str | None = None,
        force_rebuild: bool = False,
    ) -> dict[str, Any]:
        return kernel_build_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            build_profile=build_profile,
            force_rebuild=force_rebuild,
        ).model_dump(mode="json")

    @app.tool(name="target.boot")
    def target_boot(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
        force_reboot: bool = False,
        kernel_args: list[str] | None = None,
        rootfs_source: str | None = None,
        rootfs_overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            _build_overrides, boot_overrides = _overrides_from_tool_args(
                kernel_args=kernel_args,
                rootfs_source=rootfs_source,
                make_variables=None,
                config_lines=None,
                rootfs_overrides=rootfs_overrides,
            )
        except ValueError as exc:
            return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, message=str(exc)).model_dump(
                mode="json"
            )
        return target_boot_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            force_reboot=force_reboot,
            boot_overrides=boot_overrides,
            sensitive_paths=sensitive_paths,
            admission=admission_service,
        ).model_dump(mode="json")

    @app.tool(name="target.run_tests")
    def target_run_tests(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        test_suite: str | None = None,
        commands: list[list[str]] | None = None,
        force_rerun: bool = False,
        attempt: int | None = None,
    ) -> dict[str, Any]:
        return target_run_tests_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            test_suite=test_suite,
            commands=commands,
            force_rerun=force_rerun,
            attempt=attempt,
            admission=admission_service,
            session_registry=durable_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.run")
    def debug_introspect_run(
        run_id: str,
        target_ref: str,
        script: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        timeout_seconds: int = 30,
        allow_write: bool = False,
        acknowledged_permissions: list[str] | None = None,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugIntrospectRunRequest(
            run_id=run_id,
            target_ref=target_ref,
            script=script,
            timeout_seconds=timeout_seconds,
            allow_write=allow_write,
            acknowledged_permissions=acknowledged_permissions or [],
            debug_profile=debug_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
        )
        return debug_introspect_run_handler(
            request,
            artifact_root=Path(artifact_root),
            admission=admission_service,
            session_registry=durable_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.helper")
    def debug_introspect_helper(
        run_id: str,
        target_ref: str,
        name: str,
        args: dict[str, Any] | None = None,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        timeout_seconds: int = 30,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugIntrospectHelperRequest(
            run_id=run_id,
            target_ref=target_ref,
            name=name,
            args=args or {},
            timeout_seconds=timeout_seconds,
            debug_profile=debug_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
        )
        return debug_introspect_helper_handler(
            request,
            artifact_root=Path(artifact_root),
            admission=admission_service,
            session_registry=durable_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.check_prerequisites")
    def debug_introspect_check_prerequisites(
        run_id: str,
        target_ref: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        timeout_seconds: int = 20,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugIntrospectCheckPrerequisitesRequest(
            run_id=run_id,
            target_ref=target_ref,
            timeout_seconds=timeout_seconds,
            debug_profile=debug_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
        )
        return debug_introspect_check_prerequisites_handler(
            request,
            artifact_root=Path(artifact_root),
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.from_vmcore")
    def debug_introspect_from_vmcore(
        run_id: str,
        vmcore_ref: str,
        vmlinux_ref: str,
        script: str,
        modules_ref: str | None = None,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        timeout_seconds: int = 30,
        allow_write: bool = False,
        args: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        request = DebugIntrospectFromVmcoreRequest(
            run_id=run_id,
            vmcore_ref=vmcore_ref,
            vmlinux_ref=vmlinux_ref,
            script=script,
            modules_ref=modules_ref,
            timeout_seconds=timeout_seconds,
            allow_write=allow_write,
            args=args or {},
        )
        return debug_introspect_from_vmcore_handler(
            request,
            artifact_root=Path(artifact_root),
        ).model_dump(mode="json")

    @app.tool(name="debug.introspect.from_vmcore_helper")
    def debug_introspect_from_vmcore_helper(
        run_id: str,
        vmcore_ref: str,
        vmlinux_ref: str,
        name: str,
        modules_ref: str | None = None,
        args: dict[str, Any] | None = None,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        timeout_seconds: int = 30,
    ) -> dict[str, Any]:
        request = DebugIntrospectFromVmcoreHelperRequest(
            run_id=run_id,
            vmcore_ref=vmcore_ref,
            vmlinux_ref=vmlinux_ref,
            name=name,
            modules_ref=modules_ref,
            args=args or {},
            timeout_seconds=timeout_seconds,
        )
        return debug_introspect_from_vmcore_helper_handler(
            request,
            artifact_root=Path(artifact_root),
        ).model_dump(mode="json")

    @app.tool(name="artifacts.collect")
    def artifacts_collect(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        force_recollect: bool = False,
    ) -> dict[str, Any]:
        return artifacts_collect_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            force_recollect=force_recollect,
        ).model_dump(mode="json")

    @app.tool(name="debug.start_session")
    def debug_start_session(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_profile: str | None = None,
        new_session: bool = False,
    ) -> dict[str, Any]:
        return debug_start_session_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_profile=debug_profile,
            new_session=new_session,
            transaction=transport_transaction,
            admission=admission_service,
            session_registry=durable_registry,
            session_guard=session_guard,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.read_registers")
    def debug_read_registers(
        run_id: str,
        registers: list[str],
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_read_registers_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            registers=registers,
            debug_session_id=debug_session_id,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.read_symbol")
    def debug_read_symbol(
        run_id: str,
        symbol: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_read_symbol_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            symbol=symbol,
            debug_session_id=debug_session_id,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.read_memory")
    def debug_read_memory(
        run_id: str,
        address: int,
        byte_count: int,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_read_memory_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            address=address,
            byte_count=byte_count,
            debug_session_id=debug_session_id,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.evaluate")
    def debug_evaluate(
        run_id: str,
        inspector: str,
        arguments: dict[str, object] | None = None,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_evaluate_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            inspector=inspector,
            arguments=arguments,
            debug_session_id=debug_session_id,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.set_breakpoint")
    def debug_set_breakpoint(
        run_id: str,
        symbol: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_set_breakpoint_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            symbol=symbol,
            debug_session_id=debug_session_id,
            admission=admission_service,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.set_watchpoint")
    def debug_set_watchpoint(
        run_id: str,
        symbol: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_set_watchpoint_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            symbol=symbol,
            debug_session_id=debug_session_id,
            admission=admission_service,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.clear_breakpoint")
    def debug_clear_breakpoint(
        run_id: str,
        breakpoint_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_clear_breakpoint_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            breakpoint_id=breakpoint_id,
            debug_session_id=debug_session_id,
            admission=admission_service,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.clear_watchpoint")
    def debug_clear_watchpoint(
        run_id: str,
        breakpoint_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_clear_watchpoint_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            breakpoint_id=breakpoint_id,
            debug_session_id=debug_session_id,
            admission=admission_service,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.list_breakpoints")
    def debug_list_breakpoints(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_list_breakpoints_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
            admission=admission_service,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.backtrace")
    def debug_backtrace(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_backtrace_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
            admission=admission_service,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.list_variables")
    def debug_list_variables(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_list_variables_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
            admission=admission_service,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.continue")
    def debug_continue(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return debug_continue_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
            timeout_seconds=timeout_seconds,
            admission=admission_service,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.step")
    def debug_step(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return debug_step_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
            timeout_seconds=timeout_seconds,
            admission=admission_service,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.next")
    def debug_next(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return debug_next_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
            timeout_seconds=timeout_seconds,
            admission=admission_service,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.finish")
    def debug_finish(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return debug_finish_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
            timeout_seconds=timeout_seconds,
            admission=admission_service,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.interrupt")
    def debug_interrupt(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return debug_interrupt_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
            timeout_seconds=timeout_seconds,
            admission=admission_service,
            session_registry=durable_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="debug.end_session")
    def debug_end_session(
        run_id: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return debug_end_session_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            debug_session_id=debug_session_id,
            transaction=transport_transaction,
            admission=admission_service,
            session_registry=durable_registry,
            session_guard=session_guard,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    @app.tool(name="transport.open")
    def transport_open(run_id: str, recovery: bool = False) -> dict[str, Any]:
        return transport_open_handler(
            run_id=run_id,
            recovery=recovery,
            transaction=transport_transaction,
            admission=admission_service,
            session_registry=durable_registry,
        ).model_dump(mode="json")

    @app.tool(name="transport.close")
    def transport_close(run_id: str, session_id: str) -> dict[str, Any]:
        return transport_close_handler(
            run_id=run_id,
            session_id=session_id,
            transaction=transport_transaction,
            session_registry=durable_registry,
        ).model_dump(mode="json")

    @app.tool(name="transport.inject_break")
    def transport_inject_break(
        run_id: str,
        session_id: str,
        acknowledged_permissions: list[str] | None = None,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
    ) -> dict[str, Any]:
        # The real break_mechanism args (proxy/proxy_handle/ssh_runner/ssh_argv_prefix) belong to the
        # gated agent-proxy/PTY harness (a C3 integration concern); the only local-qemu break is
        # gdbstub-native, which needs no injection. So the wrapper keeps the default mechanism: B5's
        # handler fails closed to UNKNOWN+failure on any mechanism error, so a missing-harness call is
        # safe. Full break wiring is deferred to C3.
        return transport_inject_break_handler(
            run_id=run_id,
            session_id=session_id,
            acknowledged_permissions=acknowledged_permissions,
            artifact_root=Path(artifact_root),
            transaction=transport_transaction,
            admission=admission_service,
            session_registry=durable_registry,
        ).model_dump(mode="json")

    @app.tool(name="workflow.build_boot_test")
    def workflow_build_boot_test(
        source_path: str,
        build_profile: str,
        target_profile: str,
        rootfs_profile: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        run_id: str | None = None,
        test_suite: str | None = None,
        commands: list[list[str]] | None = None,
        force_rebuild: bool = False,
        force_reboot: bool = False,
        force_rerun_tests: bool = False,
        force_recollect: bool = False,
    ) -> dict[str, Any]:
        return workflow_build_boot_test_handler(
            artifact_root=Path(artifact_root),
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            test_suite=test_suite,
            commands=commands,
            force_rebuild=force_rebuild,
            force_reboot=force_reboot,
            force_rerun_tests=force_rerun_tests,
            force_recollect=force_recollect,
            admission=admission_service,
            session_registry=durable_registry,
        ).model_dump(mode="json")

    @app.tool(name="workflow.build_boot_debug")
    def workflow_build_boot_debug(
        source_path: str,
        build_profile: str,
        target_profile: str,
        rootfs_profile: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        run_id: str | None = None,
        debug_profile: str | None = None,
        force_rebuild: bool = False,
        force_reboot: bool = False,
        new_session: bool = False,
    ) -> dict[str, Any]:
        return workflow_build_boot_debug_handler(
            artifact_root=Path(artifact_root),
            source_path=source_path,
            build_profile=build_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
            run_id=run_id,
            debug_profile=debug_profile,
            force_rebuild=force_rebuild,
            force_reboot=force_reboot,
            new_session=new_session,
            admission=admission_service,
            session_registry=durable_registry,
            transaction=transport_transaction,
            session_guard=session_guard,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ).model_dump(mode="json")

    return app


def main() -> None:
    configure_logging()
    # Production wires the host-global durable registry explicitly so the single-instance flock +
    # crash reconciliation are host-wide (ADR 0005): a second server process fails loud on the shared
    # instance.lock. The default create_app() registry is a per-process temp dir (test-safe), so this
    # injection is the one place the real host-global path is taken.
    registry = SessionRegistry(directory=private_runtime_registry_dir())
    create_app(load_server_config(), session_registry=registry).run()
