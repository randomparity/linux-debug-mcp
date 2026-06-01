from __future__ import annotations

import contextlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from kdive.artifacts.steps import record_append_only_terminal_step as _record_terminal_introspect_result
from kdive.artifacts.store import ArtifactStore
from kdive.config import PRELUDE_WARNING_FRACTION_PCT
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.introspect.helpers import HelperSpec
from kdive.providers.ssh import SshCommandResult
from kdive.safety.redaction import Redactor
from kdive.symbols.verify import ProvenanceMismatch, verify_build_id

RUN_STDOUT_CAP = 2 * 1024 * 1024


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


def _chmod_best_effort(path: Path, mode: int) -> None:
    """chmod that tolerates concurrent deletion (TD-15). A path removed between its enumeration
    (e.g. a ``glob``) and this call raises FileNotFoundError — the expected benign race on the
    sensitive/ tree — which is suppressed; any other OSError still propagates. Centralizing the
    TOCTOU handling here keeps the several sensitive-file tightening sites from each re-deriving it."""
    with contextlib.suppress(FileNotFoundError):
        path.chmod(mode)


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
    """Lets a caller turn a wrapper-ok payload into a typed failure while
    keeping the manifest record and the response in agreement.
    """

    ok: bool
    failure_code: str | None = None
    failure_message: str | None = None
    failure_category: ErrorCategory | None = None
    extra_step_details: dict[str, Any] = field(default_factory=dict)
    extra_response_data: dict[str, Any] = field(default_factory=dict)


class IntrospectFinalizationWorkspace(Protocol):
    call_id: str
    agent_dir: Path
    sensitive_call_dir: Path
    stdout_path: Path
    stderr_path: Path


class IntrospectFinalizationRun(Protocol):
    ssh_result: SshCommandResult
    started_at: datetime
    finished_at: datetime
    duration_ms: int


@dataclass(frozen=True)
class _IntrospectFinalizedRun:
    ssh_result: SshCommandResult
    started_at: datetime
    finished_at: datetime
    duration_ms: int


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


def _introspect_runner_failure_tuple(
    *,
    raw_stdout: str,
    raw_stderr: str,
    ssh_exit: int,
    fail: Callable[..., ToolResponse],
    category: ErrorCategory,
    code: str,
    message: str,
) -> tuple[str, str, dict[str, Any], int, ToolResponse]:
    return (
        raw_stdout,
        raw_stderr,
        {},
        ssh_exit,
        fail(
            category=category,
            code=code,
            message=message,
            raw_stderr=raw_stderr,
            ssh_exit=ssh_exit,
            outcome_status_for_forensics=None,
        ),
    )


def _triage_introspect_runner_output(
    *,
    ssh_result: SshCommandResult,
    stdout_path: Path,
    stderr_path: Path,
    fail: Callable[..., ToolResponse],
) -> tuple[str, str, dict[str, Any], int, ToolResponse | None]:
    # Spec §5.2 step 11: exit-code + JSON parsing.
    raw_stdout = _read_capped(stdout_path, RUN_STDOUT_CAP)
    raw_stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""

    parsed: dict[str, Any] | None
    try:
        parsed = json.loads(raw_stdout) if raw_stdout else None
    except json.JSONDecodeError:
        parsed = None

    ssh_exit = ssh_result.exit_status

    if ssh_result.oversized_output or raw_stdout is None:
        return _introspect_runner_failure_tuple(
            raw_stdout="",
            raw_stderr=raw_stderr,
            ssh_exit=ssh_exit,
            fail=fail,
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="oversized_output",
            message=f"introspect stdout exceeded {RUN_STDOUT_CAP} bytes",
        )

    if ssh_result.cancelled:
        return _introspect_runner_failure_tuple(
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            ssh_exit=ssh_exit,
            fail=fail,
            category=ErrorCategory.READINESS_FAILURE,
            code="introspect_cancelled",
            message="introspect call cancelled by admission fence",
        )

    if ssh_result.stdin_failed:
        # Wrapper payload was truncated mid-write (BrokenPipe / OSError). The
        # interpreter saw an incomplete script — any exit code or stdout it
        # produced is meaningless. Classify as transport failure.
        return _introspect_runner_failure_tuple(
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            ssh_exit=ssh_exit,
            fail=fail,
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="ssh_stdin_failure",
            message="wrapper payload was not fully written to the runner stdin",
        )

    if ssh_result.timed_out:
        return _introspect_runner_failure_tuple(
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            ssh_exit=ssh_exit,
            fail=fail,
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="ssh_timeout",
            message="runner round trip exceeded host-side timeout margin",
        )

    if ssh_exit == 124 and parsed is None:
        return _introspect_runner_failure_tuple(
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            ssh_exit=ssh_exit,
            fail=fail,
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="introspect_timeout",
            message="timeout(1) fired",
        )

    if parsed is None:
        # Stdout was non-empty but not JSON; raw bytes are already under
        # sensitive/stdout.raw with a tightened mode.
        return _introspect_runner_failure_tuple(
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            ssh_exit=ssh_exit,
            fail=fail,
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            code="wrapper_crash",
            message=f"wrapper exited {ssh_exit} without a parseable JSON document",
        )

    return raw_stdout, raw_stderr, parsed, ssh_exit, None


def _introspect_wrapper_failure_by_status(
    drgn_open_message: str,
) -> dict[str, tuple[ErrorCategory, str, str, str]]:
    return {
        "drgn_open_failure": (
            ErrorCategory.INFRASTRUCTURE_FAILURE,
            "drgn_open_failure",
            drgn_open_message,
            "drgn_open_failure",
        ),
        "drgn_version_skew": (
            ErrorCategory.INFRASTRUCTURE_FAILURE,
            "drgn_version_skew",
            "drgn lacks main_module().build_id (version skew)",
            "drgn_version_skew",
        ),
        "provenance_unverifiable": (
            ErrorCategory.CONFIGURATION_ERROR,
            "provenance_unverifiable",
            "vmcore carries no embedded build-id; provenance cannot be verified",
            "provenance_unverifiable",
        ),
        "provenance_mismatch": (
            ErrorCategory.CONFIGURATION_ERROR,
            "provenance_mismatch",
            "kernel build_id does not match the expected build_id",
            "provenance_mismatch",
        ),
        "script_compile_error": (
            ErrorCategory.CONFIGURATION_ERROR,
            "script_compile_error",
            "user script failed to compile",
            "script_compile_error",
        ),
        # ADR 0011 / #56: the wrapper guard refused a drgn write under allow_write=false.
        # Must be mapped — an unmatched outcome status falls through to the success path below
        # (`status="ok"`), which would report a blocked write as success.
        "write_mode_disabled": (
            ErrorCategory.CONFIGURATION_ERROR,
            "write_mode_disabled",
            "script attempted a drgn write API but allow_write is false",
            "write_mode_disabled",
        ),
        # R4-F3: forensic-only on disk; agent-facing collapses to wrapper_crash.
        "wrapper_internal_error": (
            ErrorCategory.INFRASTRUCTURE_FAILURE,
            "wrapper_crash",
            "wrapper exited 6 with a minimal-recovery JSON document",
            "wrapper_internal_error",
        ),
    }


def _map_introspect_wrapper_failure(
    *,
    parsed: dict[str, Any],
    redacted_payload: Any,
    outcome_status: Any,
    expected_build_id: str,
    drgn_open_message: str,
    raw_stderr: str,
    ssh_exit: int,
    fail: Callable[..., ToolResponse],
) -> ToolResponse | None:
    rp = redacted_payload if isinstance(redacted_payload, dict) else None
    failure_spec = (
        _introspect_wrapper_failure_by_status(drgn_open_message).get(outcome_status)
        if isinstance(outcome_status, str)
        else None
    )
    if failure_spec is not None:
        category, code, message, forensic_status = failure_spec
        return fail(
            category=category,
            code=code,
            message=message,
            raw_stderr=raw_stderr,
            ssh_exit=ssh_exit,
            outcome_status_for_forensics=forensic_status,
            include_stdout_json=True,
            redacted_payload=rp,
        )

    # Design §4: host-authoritative provenance verify. The wrapper already
    # self-aborted on mismatch (handled above); reaching here on an "ok" outcome
    # with a disagreeing or absent id is a wrapper fault — fail loud, never skip.
    # Verify the RAW parsed id, never the redacted payload.
    observed_build_id = parsed.get("build_id")
    if not isinstance(observed_build_id, str):
        return fail(
            category=ErrorCategory.CONFIGURATION_ERROR,
            code="provenance_mismatch",
            message="wrapper reported success without a build_id; cannot confirm provenance",
            raw_stderr=raw_stderr,
            ssh_exit=ssh_exit,
            outcome_status_for_forensics="provenance_inconsistent",
            include_stdout_json=True,
            redacted_payload=rp,
        )
    try:
        verify_build_id(expected=expected_build_id, observed=observed_build_id)
    except ProvenanceMismatch:
        return fail(
            category=ErrorCategory.CONFIGURATION_ERROR,
            code="provenance_mismatch",
            message="host build_id verify disagrees with the wrapper-reported id",
            raw_stderr=raw_stderr,
            ssh_exit=ssh_exit,
            outcome_status_for_forensics="provenance_inconsistent",
            include_stdout_json=True,
            redacted_payload=rp,
        )
    return None


def _record_introspect_success(
    *,
    store: ArtifactStore,
    run_id: str,
    call_id: str,
    ssh_result: SshCommandResult,
    agent_dir: Path,
    sensitive_call_dir: Path,
    redacted_payload: Any,
    outcome_status: Any,
    raw_stderr: str,
    redactor: Redactor,
    request_timeout_seconds: int,
    started_at: datetime,
    finished_at: datetime,
    duration_ms: int,
    operation_name: str,
    exec_principal: str | None,
    post_validator: IntrospectPostValidator | None,
    allow_write: bool,
    acknowledged_permissions: list[str] | None,
) -> ToolResponse:
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


def _finalize_introspect_call(
    *,
    store: ArtifactStore,
    run_id: str,
    workspace: IntrospectFinalizationWorkspace,
    run: IntrospectFinalizationRun,
    redactor: Redactor,
    expected_build_id: str,
    request_timeout_seconds: int,
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

    def _fail(
        *,
        category: ErrorCategory,
        code: str,
        message: str,
        raw_stderr: str,
        ssh_exit: int,
        outcome_status_for_forensics: str | None,
        include_stdout_json: bool = False,
        redacted_payload: dict[str, Any] | None = None,
    ) -> ToolResponse:
        return _record_introspect_failure(
            store=store,
            run_id=run_id,
            call_id=workspace.call_id,
            category=category,
            code=code,
            message=message,
            agent_dir=workspace.agent_dir,
            sensitive_dir=workspace.sensitive_call_dir,
            redactor=redactor,
            raw_stderr=raw_stderr,
            ssh_exit=ssh_exit,
            request_timeout_seconds=request_timeout_seconds,
            duration_ms=run.duration_ms,
            ssh_user=exec_principal,
            outcome_status_for_forensics=outcome_status_for_forensics,
            include_stdout_json=include_stdout_json,
            redacted_payload=redacted_payload,
            allow_write=allow_write,
            acknowledged_permissions=acknowledged_permissions,
        )

    _, raw_stderr, parsed, ssh_exit, terminal = _triage_introspect_runner_output(
        ssh_result=run.ssh_result,
        stdout_path=workspace.stdout_path,
        stderr_path=workspace.stderr_path,
        fail=_fail,
    )
    if terminal is not None:
        return terminal

    # JSON parsed. Discriminate on outcome.status per §4.3.
    redacted_payload = redactor.redact_value(parsed)
    outcome_obj = redacted_payload.get("outcome") if isinstance(redacted_payload, dict) else None
    outcome_status = outcome_obj.get("status") if isinstance(outcome_obj, dict) else None

    terminal = _map_introspect_wrapper_failure(
        parsed=parsed,
        redacted_payload=redacted_payload,
        outcome_status=outcome_status,
        expected_build_id=expected_build_id,
        drgn_open_message=drgn_open_message,
        raw_stderr=raw_stderr,
        ssh_exit=ssh_exit,
        fail=_fail,
    )
    if terminal is not None:
        return terminal

    return _record_introspect_success(
        store=store,
        run_id=run_id,
        call_id=workspace.call_id,
        ssh_result=run.ssh_result,
        agent_dir=workspace.agent_dir,
        sensitive_call_dir=workspace.sensitive_call_dir,
        redacted_payload=redacted_payload,
        outcome_status=outcome_status,
        raw_stderr=raw_stderr,
        redactor=redactor,
        request_timeout_seconds=request_timeout_seconds,
        started_at=run.started_at,
        finished_at=run.finished_at,
        duration_ms=run.duration_ms,
        operation_name=operation_name,
        exec_principal=exec_principal,
        post_validator=post_validator,
        allow_write=allow_write,
        acknowledged_permissions=acknowledged_permissions,
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
