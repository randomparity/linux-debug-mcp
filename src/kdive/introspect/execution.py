from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from kdive.artifacts.manifest import RunManifest
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import (
    INTROSPECT_DESTRUCTIVE_PERMISSIONS,
    MAX_INTROSPECT_CALLS_PER_RUN,
    PRELUDE_WARNING_FRACTION_PCT,
    DebugProfile,
    RootfsProfile,
    TargetProfile,
    missing_destructive_permissions,
)
from kdive.coordination.admission import AdmissionError, AdmissionHandle, AdmissionService, TargetSnapshot
from kdive.coordination.exec_probe import probe_execution_state
from kdive.coordination.registry import SessionRegistry
from kdive.default_profiles import DEFAULT_DEBUG_PROFILES, DEFAULT_ROOTFS_PROFILES, DEFAULT_TARGET_PROFILES
from kdive.domain import ArtifactRef, DebugIntrospectRunRequest, ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.introspect_helpers import HelperSpec
from kdive.providers.local.local_drgn_introspect import (
    SCRIPT_BYTE_CAP,
    TARGET_PYTHON_ARGV,
    WrapperRenderError,
    render_wrapper,
    render_wrapper_skeleton,
    user_script_sha256,
)
from kdive.providers.local.local_ssh_tests import SshCommandResult, SshRunner, SubprocessSshRunner, build_ssh_argv
from kdive.providers.local.qemu_gdbstub import ProviderDebugError
from kdive.safety.redaction import Redactor
from kdive.seams.target import TargetKey
from kdive.symbols.verify import BUILD_ID_RE, ProvenanceMismatch, verify_build_id
from kdive.transport.handlers import _ensure_debug_operation_enabled, _resolve_debug_profile

logger = logging.getLogger(__name__)

RUN_STDOUT_CAP = 2 * 1024 * 1024
SSH_TIMEOUT_GRACE_SECONDS = 10


def _require_value(value: Any | None, message: str) -> Any:
    if value is None:
        raise RuntimeError(message)
    return value


def _target_python_remote_argv(*, timeout_seconds: int, use_sudo: bool) -> list[str]:
    argv = ["timeout", "--kill-after=2s", f"{timeout_seconds}s"]
    if use_sudo:
        argv.append("sudo")
    argv.extend(TARGET_PYTHON_ARGV)
    return argv


def _record_step_with_retry(store: ArtifactStore, run_id: str, result: StepResult, *, append: bool = False) -> None:
    delay_seconds = 0.01
    for attempt in range(5):
        try:
            store.record_step_result(run_id, result, append=append)
            return
        except ManifestStateError as exc:
            if "manifest is locked" not in str(exc) or attempt == 4:
                raise
            time.sleep(delay_seconds)
            delay_seconds *= 2


_INTROSPECT_STEP_NAME_RE = re.compile(r"^introspect:")
_POSTMORTEM_CRASH_STEP_RE = re.compile(r"^postmortem\.crash:[0-9a-f]{32}$")


def _count_introspect_calls(manifest: RunManifest) -> int:
    """Spec §5.2 step 4a / R3-F5. Named so tests can monkey-patch it."""
    return sum(1 for name in manifest.step_results if _INTROSPECT_STEP_NAME_RE.match(name))


def _rollback_introspect_admission(
    admission: AdmissionService, handle: AdmissionHandle, *, call_id: str, run_id: str
) -> None:
    """Roll back a promoted admission handle on an introspect-call failure, logging (never
    swallowing) a rollback failure — a corrupt admission state for this target_key must be visible
    to the operator."""
    try:
        admission.rollback(handle)
    except Exception:  # noqa: BLE001 - surface, don't swallow: operator must see admission corruption
        logger.exception("admission rollback failed for introspect call_id=%s run_id=%s", call_id, run_id)


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
    # Raw SSH stdout/stderr live under sensitive/; register existing files for
    # forensics on every failure path. Admit-time and preflight failures skip SSH.
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


def _configuration_failure(*, run_id: str, message: str, details: dict[str, Any] | None = None) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
    )


def _read_capped(path: Path, cap: int) -> str | None:
    """Read the file iff its byte size is within *cap*; None if oversized."""
    if not path.exists():
        return ""
    if path.stat().st_size > cap:
        return None
    return path.read_text(encoding="utf-8", errors="replace")


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


@dataclass(frozen=True)
class _IntrospectSshRun:
    result: SshCommandResult
    started_at: datetime
    started_monotonic: float


@dataclass(frozen=True)
class _IntrospectCallWorkspace:
    call_id: str
    agent_dir: Path
    sensitive_call_dir: Path
    wrapper: str
    stdout_path: Path
    stderr_path: Path


@dataclass(frozen=True)
class _IntrospectAdmission:
    target_key: TargetKey
    snapshot: TargetSnapshot
    proof: Any
    handle: AdmissionHandle


def _prepare_introspect_call_workspace(
    *,
    store: ArtifactStore,
    run_id: str,
    request: DebugIntrospectRunRequest,
    build_id: str,
    caps: dict[str, int] | None,
    operation_name: str,
    resolved_rootfs: RootfsProfile,
    redactor: Redactor,
    write_mode_permissions: list[str],
    admission: AdmissionService,
    handle: AdmissionHandle,
) -> tuple[_IntrospectCallWorkspace | None, ToolResponse | None]:
    call_id = uuid.uuid4().hex
    agent_dir = store.run_dir(run_id) / "debug" / "introspect" / call_id
    sensitive_call_dir = store.run_dir(run_id) / "sensitive" / "debug" / "introspect" / call_id
    agent_dir.mkdir(parents=True, mode=0o700)
    sensitive_call_dir.mkdir(parents=True, mode=0o700)
    # Defensive chmod — intermediate dirs may have inherited umask.
    sensitive_call_dir.chmod(0o700)
    sensitive_call_dir.parent.chmod(0o700)
    sensitive_call_dir.parent.parent.chmod(0o700)

    # Emit one audit line per write-mode call after call_id is minted, so
    # audit and manifest records share the same stable call identity.
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
        # R6-F3: render failure before SSH ran. Release the admission handle,
        # clean up the orphan directories, and write a forensic FAILED
        # StepResult directly (no SSH means no stderr/stdout to redact via
        # _record_introspect_failure).
        _rollback_introspect_admission(admission, handle, call_id=call_id, run_id=run_id)
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
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=f"wrapper render error: {exc}",
            details={"code": "wrapper_render_error", "call_id": call_id},
            suggested_next_actions=["artifacts.get_manifest"],
        )

    # Create wrapper.py with mode=0o600 atomically — write_text + chmod leaves
    # a window where the file is umask-default readable.
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

    # Agent-visible request.json must not carry the plaintext script; the
    # protected wrapper.py in sensitive/ is the only source copy.
    request_dump = request.model_dump(mode="json")
    request_dump["script"] = f"sha256:{user_script_sha256(request.script)}"
    redacted_request = redactor.redact_value(request_dump)
    (agent_dir / "request.json").write_text(json.dumps(redacted_request), encoding="utf-8")

    return (
        _IntrospectCallWorkspace(
            call_id=call_id,
            agent_dir=agent_dir,
            sensitive_call_dir=sensitive_call_dir,
            wrapper=wrapper,
            stdout_path=sensitive_call_dir / "stdout.raw",
            stderr_path=sensitive_call_dir / "stderr.raw",
        ),
        None,
    )


def _run_introspect_ssh_with_cancellation(
    *,
    runner: SshRunner,
    ssh_argv: list[str],
    handle: AdmissionHandle,
    timeout_seconds: int,
    stdout_path: Path,
    stderr_path: Path,
    wrapper: str,
    now: Callable[[], datetime],
) -> _IntrospectSshRun:
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
    started_monotonic = time.monotonic()
    try:
        ssh_result = runner.run(
            ssh_argv,
            timeout=timeout_seconds + SSH_TIMEOUT_GRACE_SECONDS,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            cancel=cancel_event,
            stdin=wrapper,
            max_stdout_bytes=RUN_STDOUT_CAP,
        )
    finally:
        stop_watcher.set()
        thread.join()
    return _IntrospectSshRun(result=ssh_result, started_at=started_at, started_monotonic=started_monotonic)


def _run_introspect_sudo_preflight(
    *,
    runner: SshRunner,
    store: ArtifactStore,
    run_id: str,
    resolved_rootfs: RootfsProfile,
    redactor: Redactor,
) -> ToolResponse | None:
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
    # Route preflight output under sensitive/ so guest stderr (which may carry secrets) does not land
    # on disk in agent-visible logs/.
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
    # Persist a redacted copy in the agent-visible location so forensic tooling sees a stable
    # artifact path even when the raw file is sealed under sensitive/.
    if sensitive_preflight_stderr.exists():
        _chmod_best_effort(sensitive_preflight_stderr, 0o600)
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
    return None


def _admit_introspect_call(
    *,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
    run_id: str,
) -> tuple[_IntrospectAdmission | None, ToolResponse | None]:
    if admission is None or session_registry is None:
        return None, ToolResponse.failure(
            category=ErrorCategory.READINESS_FAILURE,
            run_id=run_id,
            message="admission service unavailable",
            details={"code": "admission_service_unavailable"},
        )
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = admission.current_snapshot(target_key)
    if snapshot is None:
        # No authoritative snapshot means boot has not published a READY target state for this run yet.
        return None, ToolResponse.failure(
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
        return None, ToolResponse.failure(
            category=exc.category,
            message=str(exc),
            run_id=run_id,
            details={"code": exc.code},
            suggested_next_actions=["artifacts.collect"],
        )
    return _IntrospectAdmission(target_key=target_key, snapshot=snapshot, proof=proof, handle=handle), None


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

    # Every later step must honour the run manifest's immutable profile fields,
    # so live introspection cannot silently target a different rootfs/debug setup.
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
    # The request's manifest target profile must name the same target profile
    # recorded when the run was created.
    if request.manifest_target_profile != manifest.request.target_profile:
        return _configuration_failure(
            run_id=run_id,
            message="manifest_target_profile must match the immutable run manifest target_profile",
            details={
                "requested_target_profile": request.manifest_target_profile,
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

    # ssh_key_ref (the SSH identity-file path) is the only secret-bearing value in this handler's
    # scope: the sudo preflight below runs `sudo -n true` (non-interactive — sudo never prompts for
    # or echoes a password; NOPASSWD per ADR 0037), and RootfsProfile.credential_refs is not resolved
    # by any code path, so no other user secret can reach the preflight stderr this redactor masks
    # (TD-16). Broaden this seed if credential_refs is ever wired into the SSH connection.
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
    # sudo as root is a no-op: root logins skip both the preflight and the
    # runtime `sudo python3 -` prefix.
    use_sudo = resolved_rootfs.ssh_user != "root"

    # Spec §5.2 step 5: sudo preflight (only when sudo is needed).
    if use_sudo:
        preflight_failure = _run_introspect_sudo_preflight(
            runner=runner,
            store=store,
            run_id=run_id,
            resolved_rootfs=resolved_rootfs,
            redactor=redactor,
        )
        if preflight_failure is not None:
            return preflight_failure

    # Spec §5.2 step 6: admission gate.
    introspect_admission, admission_failure = _admit_introspect_call(
        admission=admission,
        session_registry=session_registry,
        run_id=run_id,
    )
    if admission_failure is not None:
        return admission_failure
    admission = _require_value(admission, "admission service missing after successful admission")
    introspect_admission = _require_value(introspect_admission, "admission handle missing after successful admission")
    handle = introspect_admission.handle

    # R6-F3: Step 9.4 admitted us — Steps 9.5–9.10 must always complete
    # (Step 9.6 happy path) or roll back (this envelope) the admission
    # handle. Mirrors target_run_tests_handler:1588-1620.
    admission_disposed = False
    try:
        workspace, workspace_failure = _prepare_introspect_call_workspace(
            store=store,
            run_id=run_id,
            request=request,
            build_id=build_id,
            caps=caps,
            operation_name=operation_name,
            resolved_rootfs=resolved_rootfs,
            redactor=redactor,
            write_mode_permissions=write_mode_permissions,
            admission=admission,
            handle=handle,
        )
        if workspace_failure is not None:
            admission_disposed = True
            return workspace_failure
        workspace = _require_value(workspace, "introspection workspace missing after successful preparation")
        call_id = workspace.call_id
        agent_dir = workspace.agent_dir
        sensitive_call_dir = workspace.sensitive_call_dir
        wrapper = workspace.wrapper
        stdout_path = workspace.stdout_path
        stderr_path = workspace.stderr_path

        # Spec §5.2 steps 9–10: SSH invocation + cancellation watcher.
        user_timeout = request.timeout_seconds
        # ssh_user=root keeps the remote argv free of sudo for the same reason
        # the preflight is skipped above.
        remote_argv = _target_python_remote_argv(timeout_seconds=user_timeout, use_sudo=use_sudo)
        try:
            ssh_argv = build_ssh_argv(
                rootfs_profile=resolved_rootfs,
                known_hosts_path=store.run_dir(run_id) / "sensitive" / "known_hosts",
                command=remote_argv,
                command_timeout=user_timeout + SSH_TIMEOUT_GRACE_SECONDS,
            )
        except ValueError as exc:
            # build_ssh_argv raises when RootfsProfile.ssh_options['ConnectTimeout']
            # exceeds the command timeout — surface as CONFIGURATION_ERROR rather
            # than letting it fall into the outer broad-except.
            _rollback_introspect_admission(admission, handle, call_id=call_id, run_id=run_id)
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
        ssh_run = _run_introspect_ssh_with_cancellation(
            runner=runner,
            ssh_argv=ssh_argv,
            handle=handle,
            timeout_seconds=user_timeout,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            wrapper=wrapper,
            now=now,
        )
        ssh_result = ssh_run.result

        # Tighten raw SSH-output file modes. `chmod` is attempted directly so a
        # missing file remains a best-effort no-op instead of a check/use race.
        for _raw_path in (stdout_path, stderr_path):
            _chmod_best_effort(_raw_path, 0o600)

        # admission_disposed flips True as soon as either complete() succeeds
        # or rollback() runs — the outer `except` then skips a redundant
        # rollback that would log a spurious handle_already_disposed.
        try:
            admission.complete(handle)
            admission_disposed = True
        except AdmissionError as exc:
            # A completion failure still owns SSH artifacts on disk; roll back
            # the admission binding and append a FAILED introspect:<call_id>
            # record so the manifest reflects that state.
            _rollback_introspect_admission(admission, handle, call_id=call_id, run_id=run_id)
            admission_disposed = True
            raw_stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
            duration_ms = int((time.monotonic() - ssh_run.started_monotonic) * 1000)
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
        duration_ms = int((time.monotonic() - ssh_run.started_monotonic) * 1000)
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
            started_at=ssh_run.started_at,
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
                # The primary exception is re-raised below, but a rollback
                # failure still needs admission-state diagnostics.
                logger.exception("admission rollback failed while unwinding introspect handler for run_id=%s", run_id)
        raise


def _persist_introspect_success_artifacts(
    *,
    agent_dir: Path,
    sensitive_call_dir: Path,
    redacted_payload: Any,
    raw_stderr: str,
    redactor: Redactor,
) -> list[ArtifactRef]:
    (agent_dir / "stdout.json").write_text(json.dumps(redacted_payload), encoding="utf-8")
    (agent_dir / "stderr.log").write_text(redactor.redact_text(raw_stderr), encoding="utf-8")

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
    return artifacts


def _build_introspect_success_response(
    *,
    call_id: str,
    redacted_payload: Any,
    outcome_status: Any,
    raw_stderr: str,
    redactor: Redactor,
    request_timeout_seconds: int,
    started_at: datetime,
    finished_at: datetime,
    duration_ms: int,
    public_artifacts: list[ArtifactRef],
) -> dict[str, Any]:
    payload = redacted_payload if isinstance(redacted_payload, dict) else {}
    outcome_obj = payload.get("outcome")
    emits = payload.get("emits", [])
    user_stdout = payload.get("user_stdout", "")
    truncated = payload.get("truncated", {})
    prelude_ms = payload.get("prelude_ms", 0)
    warnings = payload.get("warnings", [])

    diagnostic: str | None = None
    if prelude_ms * 100 >= PRELUDE_WARNING_FRACTION_PCT * request_timeout_seconds * 1000:
        diagnostic = (
            f"prelude ({prelude_ms} ms) consumed >= "
            f"{PRELUDE_WARNING_FRACTION_PCT}% of timeout_seconds "
            f"({request_timeout_seconds} s); consider raising timeout_seconds."
        )

    # Spec §4.3: only these keys are part of the response outcome contract for status=error.
    _SCRIPT_ERROR_OUTCOME_KEYS = ("error_type", "error_message", "traceback")
    status = "script_error" if outcome_status == "error" else "ok"
    if status == "script_error" and isinstance(outcome_obj, dict):
        outcome_for_response: dict[str, Any] = {"status": "error"}
        for key in _SCRIPT_ERROR_OUTCOME_KEYS:
            if key in outcome_obj:
                outcome_for_response[key] = outcome_obj[key]
    else:
        outcome_for_response = {"status": "ok"}

    response_data: dict[str, Any] = {
        "call_id": call_id,
        "status": status,
        "outcome": outcome_for_response,
        "emits": emits,
        "user_stdout_snippet": _head_tail(user_stdout, head=2048, tail=2048),
        "drgn_stderr_snippet": _head_tail(redactor.redact_text(raw_stderr), head=2048, tail=2048),
        "build_id": payload.get("build_id"),
        "truncated": truncated,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_ms": duration_ms,
        "prelude_ms": prelude_ms,
        "artifacts": [artifact.model_dump(mode="json") for artifact in public_artifacts],
        "diagnostic": diagnostic,
    }
    # The live wrapper never emits warnings (vmcore-only field); include the key only when present
    # so the live `debug.introspect.run` response is unchanged.
    if warnings:
        response_data["warnings"] = warnings
    return response_data


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

    artifacts = _persist_introspect_success_artifacts(
        agent_dir=agent_dir,
        sensitive_call_dir=sensitive_call_dir,
        redacted_payload=redacted_payload,
        raw_stderr=raw_stderr,
        redactor=redactor,
    )
    public_artifacts = [artifact for artifact in artifacts if not artifact.sensitive]
    success_response = _build_introspect_success_response(
        call_id=call_id,
        redacted_payload=redacted_payload,
        outcome_status=outcome_status,
        raw_stderr=raw_stderr,
        redactor=redactor,
        request_timeout_seconds=request_timeout_seconds,
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
        public_artifacts=public_artifacts,
    )
    truncated = success_response["truncated"]
    prelude_ms = success_response["prelude_ms"]

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
    return ToolResponse.success(
        summary=f"introspect call {call_id[:8]} ok",
        run_id=run_id,
        status=StepStatus.SUCCEEDED,
        artifacts=public_artifacts,
        suggested_next_actions=["artifacts.get_manifest", operation_name],
        data=success_response,
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
