from __future__ import annotations

import contextlib
import json
import re
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import (
    CRASH_COMMAND_ALLOWLIST,
    CRASH_PER_CMD_CAP,
    CRASH_SCRIPT_BYTE_CAP,
    CRASH_STDOUT_CAP,
    MAX_CRASH_COMMANDS,
    MAX_POSTMORTEM_CRASH_CALLS_PER_RUN,
)
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.postmortem.crash_batch import build_command_script, collect_command_outputs
from kdive.postmortem.crash_commands import crash_command_rejection_reason, validate_modules_path
from kdive.postmortem.crash_parsers import parse_command
from kdive.postmortem.models import DebugPostmortemCrashRequest
from kdive.providers.ssh import SshCommandResult, SshRunner, SubprocessSshRunner
from kdive.safety.paths import PathSafetyError, confine_run_relative
from kdive.safety.redaction import Redactor
from kdive.seams.target import KernelProvenance
from kdive.symbols.build_id import BuildIdReadError, read_elf_build_id
from kdive.symbols.resolve import SymbolResolutionError, resolve_symbols
from kdive.symbols.verify import BUILD_ID_RE
from kdive.symbols.vmcore_build_id import (
    VmcoreBuildIdAbsent,
    VmcoreBuildIdError,
    VmcoreFormatUnsupported,
    read_vmcore_build_id,
)

SSH_TIMEOUT_GRACE_SECONDS = 10
_POSTMORTEM_CRASH_STEP_RE = re.compile(r"^postmortem\.crash:[0-9a-f]{32}$")


@dataclass(frozen=True)
class PostmortemVmcoreContext:
    store: ArtifactStore
    manifest: Any
    run_dir: Path
    vmcore_path: Path
    vmlinux_path: Path
    modules_path: str | None
    vmcore_build_id: str


def _require_postmortem_context(ctx: PostmortemVmcoreContext | None) -> PostmortemVmcoreContext:
    if ctx is None:
        raise RuntimeError("postmortem vmcore context missing after successful resolution")
    return ctx


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _chmod_best_effort(path: Path, mode: int) -> None:
    with contextlib.suppress(FileNotFoundError):
        path.chmod(mode)


def _record_postmortem_crash_step_with_retry(
    store: ArtifactStore,
    run_id: str,
    result: StepResult,
    *,
    append: bool = False,
    attempts: int = 5,
    initial_delay_seconds: float = 0.01,
) -> None:
    delay_seconds = initial_delay_seconds
    for attempt in range(attempts):
        try:
            store.record_step_result(run_id, result, append=append)
            return
        except ManifestStateError as exc:
            if "manifest is locked" not in str(exc) or attempt == attempts - 1:
                raise
            time.sleep(delay_seconds)
            delay_seconds *= 2


def _record_terminal_crash_result(store: ArtifactStore, run_id: str, result: StepResult) -> None:
    _record_postmortem_crash_step_with_retry(store, run_id, result, append=True)


def _crash_config_failure(run_id: str, code: str, message: str) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        run_id=run_id,
        message=message,
        details={"code": code},
        suggested_next_actions=["artifacts.get_manifest", "debug.postmortem.crash"],
    )


def _validate_crash_commands(run_id: str, commands: list[str]) -> ToolResponse | None:
    """Spec §3.4 / §6 step 2. Returns a failure response or None if all pass."""
    if not commands or len(commands) > MAX_CRASH_COMMANDS:
        return _crash_config_failure(run_id, "invalid_commands", f"commands must be 1..{MAX_CRASH_COMMANDS}")
    stripped = [c.strip() for c in commands]
    if len(set(stripped)) != len(stripped):
        return _crash_config_failure(run_id, "invalid_commands", "duplicate command")
    script_bytes = sum(len(c.encode("utf-8")) for c in stripped)
    if script_bytes > CRASH_SCRIPT_BYTE_CAP:
        return _crash_config_failure(run_id, "invalid_commands", "command script too large")
    for command in stripped:
        reason = crash_command_rejection_reason(command, CRASH_COMMAND_ALLOWLIST)
        if reason is not None:
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                run_id=run_id,
                message=f"command not permitted: {reason}",
                details={"code": "command_not_permitted", "command": command, "reason": reason},
                suggested_next_actions=["debug.postmortem.crash"],
            )
    return None


def _crash_build_id_fail_loud(
    run_id: str,
    vmcore_path: Path,
    vmlinux_path: Path,
    vmcore_reader: Callable[[Path], str],
    vmlinux_reader: Callable[[Path], str],
) -> tuple[str, ToolResponse | None]:
    """Spec §5. Returns (vmcore_build_id, None) on a verified match, else ("", failure)."""
    try:
        expected = vmlinux_reader(vmlinux_path)
    except BuildIdReadError as exc:
        return "", _crash_config_failure(run_id, "vmlinux_build_id_unreadable", f"vmlinux build-id unreadable: {exc}")
    if not BUILD_ID_RE.match(expected):
        return "", _crash_config_failure(run_id, "vmlinux_build_id_unreadable", "malformed vmlinux build-id")
    try:
        observed = vmcore_reader(vmcore_path)
    except VmcoreFormatUnsupported as exc:
        return "", _crash_config_failure(run_id, "vmcore_format_unsupported", str(exc))
    except VmcoreBuildIdAbsent as exc:
        return "", _crash_config_failure(run_id, "provenance_unverifiable", str(exc))
    except VmcoreBuildIdError as exc:
        return "", _crash_config_failure(run_id, "vmcore_build_id_unreadable", str(exc))
    if observed != expected:
        return "", _crash_config_failure(
            run_id, "provenance_mismatch", "vmcore build-id does not match the supplied vmlinux"
        )
    return observed, None


def resolve_postmortem_vmcore_context(
    request: Any,
    *,
    artifact_root: Path,
    vmcore_build_id_reader: Callable[[Path], str],
    vmlinux_build_id_reader: Callable[[Path], str],
) -> tuple[PostmortemVmcoreContext | None, ToolResponse | None]:
    run_id = request.run_id
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        if not (store.run_dir(run_id) / "manifest.json").is_file():
            return None, _crash_config_failure(run_id, "run_not_found", f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return None, ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    if not (5 <= request.timeout_seconds <= 300):
        return None, _crash_config_failure(
            run_id, "invalid_timeout", f"timeout_seconds must be in [5, 300]; got {request.timeout_seconds}"
        )

    run_dir = store.run_dir(run_id)
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
        return None, _crash_config_failure(run_id, "symbol_resolution_failed", str(exc))
    try:
        vmcore_path = confine_run_relative(request.vmcore_ref, run_dir=run_dir)
    except PathSafetyError as exc:
        return None, _crash_config_failure(run_id, "vmcore_not_found", str(exc))
    if not vmcore_path.is_file():
        return None, _crash_config_failure(run_id, "vmcore_not_found", f"vmcore not found at {request.vmcore_ref!r}")

    modules_path = str(resolved.modules_path) if resolved.modules_path is not None else None
    if modules_path is not None and not validate_modules_path(modules_path):
        return None, _crash_config_failure(run_id, "modules_path_unsafe", "resolved modules path has unsafe characters")

    vmcore_build_id, failure = _crash_build_id_fail_loud(
        run_id, vmcore_path, resolved.vmlinux_path, vmcore_build_id_reader, vmlinux_build_id_reader
    )
    if failure is not None:
        return None, failure

    return (
        PostmortemVmcoreContext(
            store=store,
            manifest=manifest,
            run_dir=run_dir,
            vmcore_path=vmcore_path,
            vmlinux_path=resolved.vmlinux_path,
            modules_path=modules_path,
            vmcore_build_id=vmcore_build_id,
        ),
        None,
    )


def debug_postmortem_crash_handler(
    request: DebugPostmortemCrashRequest,
    *,
    artifact_root: Path,
    runner: SshRunner | None = None,
    vmcore_build_id_reader: Callable[[Path], str] = read_vmcore_build_id,
    vmlinux_build_id_reader: Callable[[Path], str] = read_elf_build_id,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    """Spec §6 / ADR 0026. Host-side crash batch runner; no admission gate."""
    run_id = request.run_id
    now = clock or _utcnow
    ctx, failure = resolve_postmortem_vmcore_context(
        request,
        artifact_root=artifact_root,
        vmcore_build_id_reader=vmcore_build_id_reader,
        vmlinux_build_id_reader=vmlinux_build_id_reader,
    )
    if failure is not None:
        return failure
    ctx = _require_postmortem_context(ctx)
    bad_commands = _validate_crash_commands(run_id, request.commands)
    if bad_commands is not None:
        return bad_commands
    crash_steps = sum(1 for n in ctx.manifest.step_results if _POSTMORTEM_CRASH_STEP_RE.match(n))
    if crash_steps >= MAX_POSTMORTEM_CRASH_CALLS_PER_RUN:
        return _crash_config_failure(
            run_id, "manifest_call_budget_exhausted", "crash call budget exhausted; start a new run"
        )

    store = ctx.store
    run_dir = ctx.run_dir
    sensitive_dir = run_dir / "sensitive"
    try:
        mode = sensitive_dir.stat().st_mode & 0o777
    except FileNotFoundError:
        return _crash_config_failure(run_id, "sensitive_dir_missing", f"{sensitive_dir} is missing")
    if mode & 0o077:
        return _crash_config_failure(run_id, "sensitive_dir_too_permissive", f"{sensitive_dir} mode is {oct(mode)}")

    call_id = uuid.uuid4().hex
    agent_dir = run_dir / "debug" / "postmortem" / "crash" / call_id
    sensitive_call_dir = run_dir / "sensitive" / "debug" / "postmortem" / "crash" / call_id
    agent_dir.mkdir(parents=True, mode=0o700)
    sensitive_call_dir.mkdir(parents=True, mode=0o700)
    # mkdir(mode=) applies only to the leaf; tighten the intermediate sensitive
    # dirs to 0700 too so the raw output tree never relies solely on the
    # sensitive/ ancestor (mirrors _execute_vmcore_introspect_call).
    sensitive_call_dir.chmod(0o700)
    sensitive_call_dir.parent.chmod(0o700)
    sensitive_call_dir.parent.parent.chmod(0o700)

    stripped_commands = [c.strip() for c in request.commands]
    cmd_script = build_command_script(stripped_commands, sensitive_call_dir, ctx.modules_path)
    redactor = Redactor(secret_values=[])
    (agent_dir / "request.json").write_text(
        json.dumps(redactor.redact_value(request.model_dump(mode="json"))), encoding="utf-8"
    )

    stdout_path = sensitive_call_dir / "stdout.raw"
    stderr_path = sensitive_call_dir / "stderr.raw"
    active_runner: SshRunner = runner or SubprocessSshRunner()
    argv = [
        "prlimit",
        f"--fsize={CRASH_PER_CMD_CAP}",
        "timeout",
        "--kill-after=2s",
        f"{request.timeout_seconds}s",
        "crash",
        "-s",
        str(ctx.vmlinux_path),
        str(ctx.vmcore_path),
    ]
    started_at = now()
    started_monotonic = time.monotonic()
    try:
        ssh_result = active_runner.run(
            argv,
            timeout=request.timeout_seconds + SSH_TIMEOUT_GRACE_SECONDS,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            cancel=threading.Event(),
            stdin=cmd_script,
            max_stdout_bytes=CRASH_STDOUT_CAP,
        )
    except Exception as exc:  # noqa: BLE001 - offline boundary: return typed ToolResponse, do not leak raw exceptions
        duration_ms = int((time.monotonic() - started_monotonic) * 1000)
        artifacts = [ArtifactRef(path=str(agent_dir / "request.json"), kind="application/json")]
        failed = StepResult(
            step_name=f"postmortem.crash:{call_id}",
            status=StepStatus.FAILED,
            summary="postmortem crash failed before runner finalization",
            artifacts=artifacts,
            details={
                "call_id": call_id,
                "code": "postmortem_crash_failed",
                "exception_type": type(exc).__name__,
                "duration_ms": duration_ms,
            },
        )
        _record_terminal_crash_result(store, run_id, failed)
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="postmortem crash failed before runner finalization",
            details={"code": "postmortem_crash_failed", "call_id": call_id, "exception_type": type(exc).__name__},
            artifacts=artifacts,
            suggested_next_actions=["artifacts.get_manifest"],
        )
    # The per-command output files are written by the crash child at its own
    # umask (commonly 0644) and carry raw, unredacted guest memory; tighten them
    # (and stdout/stderr) to 0600 so they match the sensitive/ 0700 discipline.
    raw_files = [stdout_path, stderr_path, *sensitive_call_dir.glob("cmd-*.out")]
    mod_load_path = sensitive_call_dir / "mod-load.out"
    if mod_load_path.exists():
        raw_files.append(mod_load_path)
    for raw_path in raw_files:
        _chmod_best_effort(raw_path, 0o600)
    duration_ms = int((time.monotonic() - started_monotonic) * 1000)
    return _finalize_crash_call(
        store=store,
        run_id=run_id,
        call_id=call_id,
        ssh_result=ssh_result,
        sensitive_call_dir=sensitive_call_dir,
        agent_dir=agent_dir,
        redactor=redactor,
        commands=stripped_commands,
        modules_requested=ctx.modules_path is not None,
        vmcore_build_id=ctx.vmcore_build_id,
        started_at=started_at,
        finished_at=now(),
        duration_ms=duration_ms,
    )


def _finalize_crash_call(
    *,
    store: ArtifactStore,
    run_id: str,
    call_id: str,
    ssh_result: SshCommandResult,
    sensitive_call_dir: Path,
    agent_dir: Path,
    redactor: Redactor,
    commands: list[str],
    modules_requested: bool,
    vmcore_build_id: str,
    started_at: datetime,
    finished_at: datetime,
    duration_ms: int,
) -> ToolResponse:
    """Spec §4.1 / §6 step 9. Runner-terminal failures win over the file-count
    rule; a clean run with >=1 output file is a success with per-command markers."""
    step_name = f"postmortem.crash:{call_id}"

    def _infra_fail(code: str, message: str) -> ToolResponse:
        store_step = StepResult(
            step_name=step_name,
            status=StepStatus.FAILED,
            summary=message,
            artifacts=[],
            details={"call_id": call_id, "code": code, "duration_ms": duration_ms},
        )
        _record_terminal_crash_result(store, run_id, store_step)
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=message,
            details={"code": code, "call_id": call_id},
            suggested_next_actions=["artifacts.get_manifest"],
        )

    if ssh_result.oversized_output:
        return _infra_fail("oversized_output", "crash session stdout exceeded the cap")
    if ssh_result.cancelled:
        return _infra_fail("crash_cancelled", "crash call cancelled")
    if ssh_result.stdin_failed:
        return _infra_fail("crash_stdin_failure", "crash command script not fully written")
    if ssh_result.timed_out or ssh_result.exit_status == 124:
        return _infra_fail("crash_timeout", "crash run exceeded the timeout")

    segments, truncated = collect_command_outputs(
        sensitive_call_dir, commands, per_cmd_cap=CRASH_PER_CMD_CAP, total_cap=CRASH_STDOUT_CAP
    )
    if all(seg["capture"] == "not_captured" for seg in segments) and ssh_result.exit_status != 0:
        return _infra_fail("crash_open_failure", "crash produced no command output (could not open the pair)")

    results: dict[str, Any] = {}
    transcript_parts: list[str] = []
    for seg in segments:
        command = seg["command"]
        if seg["capture"] == "not_captured":
            results[command] = {"parsed": False, "reason": "not_captured", "raw": None}
            continue
        raw = redactor.redact_text(seg["raw"] or "")
        transcript_parts.append(f"$ {command}\n{raw}")
        if seg["capture"] == "output_truncated":
            results[command] = {"parsed": False, "reason": "output_truncated", "raw": raw}
            continue
        parsed = parse_command(command, raw)
        results[command] = redactor.redact_value(parsed)

    module_symbols = None
    if modules_requested:
        mod_file = sensitive_call_dir / "mod-load.out"
        mod_text = mod_file.read_text(encoding="utf-8", errors="replace") if mod_file.is_file() else ""
        status = "loaded" if mod_file.is_file() and "cannot" not in mod_text.lower() else "load_failed"
        module_symbols = {"requested": True, "status": status, "detail": redactor.redact_text(mod_text[:512])}

    transcript_path = agent_dir / "transcript.txt"
    parsed_path = agent_dir / "parsed.json"
    transcript_path.write_text(redactor.redact_text("\n\n".join(transcript_parts)), encoding="utf-8")
    parsed_path.write_text(json.dumps(results), encoding="utf-8")
    artifacts = [
        ArtifactRef(path=str(transcript_path.relative_to(store.run_dir(run_id))), kind="crash_transcript"),
        ArtifactRef(path=str(parsed_path.relative_to(store.run_dir(run_id))), kind="crash_parsed_json"),
    ]
    step = StepResult(
        step_name=step_name,
        status=StepStatus.SUCCEEDED,
        summary=f"crash batch: {len(commands)} command(s)",
        artifacts=artifacts,
        details={"call_id": call_id, "vmcore_build_id": vmcore_build_id, "duration_ms": duration_ms},
    )
    _record_terminal_crash_result(store, run_id, step)
    data: dict[str, Any] = {
        "call_id": call_id,
        "vmcore_build_id": vmcore_build_id,
        "results": results,
        "truncated": truncated,
        "crash_exit_code": ssh_result.exit_status,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_ms": duration_ms,
    }
    if module_symbols is not None:
        data["module_symbols"] = module_symbols
    return ToolResponse.success(
        summary=f"crash batch over {len(commands)} command(s)",
        run_id=run_id,
        data=data,
        artifacts=artifacts,
        suggested_next_actions=["artifacts.get_manifest", "debug.postmortem.crash"],
    )
