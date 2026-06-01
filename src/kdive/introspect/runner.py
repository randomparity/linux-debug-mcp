from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from kdive.artifacts.store import ArtifactStore
from kdive.config import RootfsProfile
from kdive.coordination.admission import AdmissionError, AdmissionHandle, AdmissionService, TargetSnapshot
from kdive.coordination.exec_probe import probe_execution_state
from kdive.coordination.registry import SessionRegistry
from kdive.domain import ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.introspect.context import _LiveIntrospectPreAdmissionContext, _require_value
from kdive.introspect.models import DebugIntrospectRunRequest
from kdive.introspect.result import (
    RUN_STDOUT_CAP,
    IntrospectFinalizationContext,
    IntrospectPostValidator,
    _chmod_best_effort,
    _finalize_introspect_call,
    _IntrospectFinalizedRun,
    _record_introspect_failure,
    _record_terminal_introspect_result,
    _redact_and_truncate,
)
from kdive.introspect.wrappers import (
    TARGET_PYTHON_ARGV,
    WrapperRenderError,
    render_wrapper,
    render_wrapper_skeleton,
    user_script_sha256,
)
from kdive.providers.ssh import SSH_TIMEOUT_GRACE_SECONDS, SshCommandResult, SshRunner, build_ssh_argv
from kdive.safety.redaction import Redactor
from kdive.seams.probes import probe_runner_exception_failure
from kdive.seams.target import TargetKey

logger = logging.getLogger(__name__)


def _target_python_remote_argv(*, timeout_seconds: int, use_sudo: bool) -> list[str]:
    argv = ["timeout", "--kill-after=2s", f"{timeout_seconds}s"]
    if use_sudo:
        argv.append("sudo")
    argv.extend(TARGET_PYTHON_ARGV)
    return argv


def _rollback_introspect_admission(
    admission: AdmissionService, handle: AdmissionHandle, *, call_id: str, run_id: str
) -> None:
    try:
        admission.rollback(handle)
    except Exception:
        logger.exception("admission rollback failed for introspect call_id=%s run_id=%s", call_id, run_id)


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


def _introspect_render_failure(
    *,
    store: ArtifactStore,
    run_id: str,
    call_id: str,
    agent_dir: Path,
    sensitive_call_dir: Path,
    request: DebugIntrospectRunRequest,
    resolved_rootfs: RootfsProfile,
    admission: AdmissionService,
    handle: AdmissionHandle,
    exc: WrapperRenderError,
) -> ToolResponse:
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
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        run_id=run_id,
        message=f"wrapper render error: {exc}",
        details={"code": "wrapper_render_error", "call_id": call_id},
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _persist_introspect_workspace_files(
    *,
    agent_dir: Path,
    sensitive_call_dir: Path,
    request: DebugIntrospectRunRequest,
    wrapper: str,
    skeleton: str,
    redactor: Redactor,
) -> None:
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
    redacted_request = redactor.redact_value(request_dump)
    (agent_dir / "request.json").write_text(json.dumps(redacted_request), encoding="utf-8")


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
        return (
            None,
            _introspect_render_failure(
                store=store,
                run_id=run_id,
                call_id=call_id,
                agent_dir=agent_dir,
                sensitive_call_dir=sensitive_call_dir,
                request=request,
                resolved_rootfs=resolved_rootfs,
                admission=admission,
                handle=handle,
                exc=exc,
            ),
        )

    # Create wrapper.py with mode=0o600 atomically — write_text + chmod leaves
    # a window where the file is umask-default readable.
    # Agent-visible request.json must not carry the plaintext script; the
    # protected wrapper.py in sensitive/ is the only source copy.
    _persist_introspect_workspace_files(
        agent_dir=agent_dir,
        sensitive_call_dir=sensitive_call_dir,
        request=request,
        wrapper=wrapper,
        skeleton=skeleton,
        redactor=redactor,
    )

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
        return probe_runner_exception_failure(
            run_id=run_id,
            redactor=redactor,
            exc=exc,
            operation="sudo preflight",
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


def _run_live_wrapper(
    *,
    runner: SshRunner,
    store: ArtifactStore,
    request: DebugIntrospectRunRequest,
    resolved_rootfs: RootfsProfile,
    workspace: _IntrospectCallWorkspace,
    admission: AdmissionService,
    handle: AdmissionHandle,
    redactor: Redactor,
    use_sudo: bool,
    write_mode_permissions: list[str],
    now: Callable[[], datetime],
) -> tuple[_IntrospectSshRun | None, ToolResponse | None, bool]:
    call_id = workspace.call_id
    agent_dir = workspace.agent_dir
    sensitive_call_dir = workspace.sensitive_call_dir
    user_timeout = request.timeout_seconds
    remote_argv = _target_python_remote_argv(timeout_seconds=user_timeout, use_sudo=use_sudo)
    try:
        ssh_argv = build_ssh_argv(
            rootfs_profile=resolved_rootfs,
            known_hosts_path=store.run_dir(request.run_id) / "sensitive" / "known_hosts",
            command=remote_argv,
            command_timeout=user_timeout + SSH_TIMEOUT_GRACE_SECONDS,
        )
    except ValueError as exc:
        _rollback_introspect_admission(admission, handle, call_id=call_id, run_id=request.run_id)
        shutil.rmtree(agent_dir, ignore_errors=True)
        shutil.rmtree(sensitive_call_dir, ignore_errors=True)
        return (
            None,
            ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                run_id=request.run_id,
                message=_redact_and_truncate(redactor, str(exc), cap=256),
                details={"code": "invalid_ssh_options", "call_id": call_id},
                suggested_next_actions=["artifacts.collect"],
            ),
            True,
        )
    ssh_started_monotonic = time.monotonic()
    try:
        ssh_run = _run_introspect_ssh_with_cancellation(
            runner=runner,
            ssh_argv=ssh_argv,
            handle=handle,
            timeout_seconds=user_timeout,
            stdout_path=workspace.stdout_path,
            stderr_path=workspace.stderr_path,
            wrapper=workspace.wrapper,
            now=now,
        )
    except Exception as exc:
        _rollback_introspect_admission(admission, handle, call_id=call_id, run_id=request.run_id)
        raw_stderr = (
            workspace.stderr_path.read_text(encoding="utf-8", errors="replace")
            if workspace.stderr_path.exists()
            else ""
        )
        code = "ssh_failure" if isinstance(exc, OSError) else "introspect_runner_failure"
        return (
            None,
            _record_introspect_failure(
                store=store,
                run_id=request.run_id,
                call_id=call_id,
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                code=code,
                message=redactor.redact_text(f"live introspect runner failed: {exc}"),
                agent_dir=agent_dir,
                sensitive_dir=sensitive_call_dir,
                redactor=redactor,
                raw_stderr=raw_stderr,
                ssh_exit=-1,
                request_timeout_seconds=request.timeout_seconds,
                duration_ms=int((time.monotonic() - ssh_started_monotonic) * 1000),
                ssh_user=resolved_rootfs.ssh_user,
                outcome_status_for_forensics=None,
                allow_write=request.allow_write,
                acknowledged_permissions=write_mode_permissions,
            ),
            True,
        )
    ssh_result = ssh_run.result
    for raw_path in (workspace.stdout_path, workspace.stderr_path):
        _chmod_best_effort(raw_path, 0o600)
    try:
        admission.complete(handle)
    except AdmissionError as exc:
        _rollback_introspect_admission(admission, handle, call_id=call_id, run_id=request.run_id)
        raw_stderr = (
            workspace.stderr_path.read_text(encoding="utf-8", errors="replace")
            if workspace.stderr_path.exists()
            else ""
        )
        duration_ms = int((time.monotonic() - ssh_run.started_monotonic) * 1000)
        return (
            None,
            _record_introspect_failure(
                store=store,
                run_id=request.run_id,
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
            ),
            True,
        )
    return ssh_run, None, True


def _execute_admitted_introspect_ssh(
    *,
    request: DebugIntrospectRunRequest,
    pre_admission: _LiveIntrospectPreAdmissionContext,
    runner: SshRunner,
    admission: AdmissionService,
    introspect_admission: _IntrospectAdmission,
    now: Callable[[], datetime],
    operation_name: str,
    caps: dict[str, int] | None,
    post_validator: IntrospectPostValidator | None,
) -> ToolResponse:
    store = pre_admission.store
    resolved_rootfs = pre_admission.resolved_rootfs
    redactor = pre_admission.redactor
    build_id = pre_admission.build_id
    write_mode_permissions = pre_admission.write_mode_permissions
    use_sudo = pre_admission.use_sudo
    run_id = request.run_id
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

        ssh_run, runner_failure, admission_disposed = _run_live_wrapper(
            runner=runner,
            store=store,
            request=request,
            resolved_rootfs=resolved_rootfs,
            workspace=workspace,
            admission=admission,
            handle=handle,
            redactor=redactor,
            use_sudo=use_sudo,
            write_mode_permissions=write_mode_permissions,
            now=now,
        )
        if runner_failure is not None:
            return runner_failure
        ssh_run = _require_value(ssh_run, "SSH run missing after successful live wrapper execution")

        # Spec §5.2 step 11+: shared post-runner finalization (live + vmcore).
        finished_at = now()
        duration_ms = int((time.monotonic() - ssh_run.started_monotonic) * 1000)
        return _finalize_introspect_call(
            IntrospectFinalizationContext(
                store=store,
                run_id=run_id,
                workspace=workspace,
                run=_IntrospectFinalizedRun(
                    ssh_result=ssh_run.result,
                    started_at=ssh_run.started_at,
                    finished_at=finished_at,
                    duration_ms=duration_ms,
                ),
                redactor=redactor,
                expected_build_id=build_id,
                request_timeout_seconds=request.timeout_seconds,
                operation_name=operation_name,
                drgn_open_message="drgn could not attach to the live target",
                exec_principal=resolved_rootfs.ssh_user,
                post_validator=post_validator,
                allow_write=request.allow_write,
                acknowledged_permissions=write_mode_permissions,
            )
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
