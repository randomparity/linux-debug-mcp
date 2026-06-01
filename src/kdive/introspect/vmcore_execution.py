from __future__ import annotations

import contextlib
import json
import os
import shutil
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from kdive.artifacts.manifest import RunManifest
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.handlers.shared import _require_value
from kdive.introspect.context import (
    MAX_INTROSPECT_CALLS_PER_RUN,
    _configuration_failure,
    _count_introspect_calls,
)
from kdive.introspect.models import DebugIntrospectFromVmcoreRequest
from kdive.introspect.result import (
    RUN_STDOUT_CAP,
    IntrospectFinalizationContext,
    IntrospectPostValidator,
    _chmod_best_effort,
    _finalize_introspect_call,
    _record_terminal_introspect_result,
)
from kdive.introspect.wrappers import (
    SCRIPT_BYTE_CAP,
    WrapperRenderError,
    render_vmcore_wrapper,
    render_vmcore_wrapper_skeleton,
    user_script_sha256,
)
from kdive.providers.ssh import (
    SSH_TIMEOUT_GRACE_SECONDS,
    CommandResult,
    CommandRunner,
    SubprocessCommandRunner,
)
from kdive.safety.paths import PathSafetyError, confine_run_relative
from kdive.safety.redaction import Redactor
from kdive.seams.target import KernelProvenance
from kdive.symbols.build_id import BuildIdReadError, read_elf_build_id
from kdive.symbols.resolve import SymbolResolutionError, resolve_symbols
from kdive.symbols.verify import BUILD_ID_RE


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class VmcoreIntrospectContext:
    store: ArtifactStore
    run_id: str
    run_dir: Path
    redactor: Redactor
    vmcore_path: Path
    vmlinux_path: Path
    modules_path: str | None
    expected_build_id: str


@dataclass(frozen=True)
class VmcoreIntrospectInputs:
    vmcore_path: Path
    vmlinux_path: Path
    modules_path: str | None
    expected_build_id: str


@dataclass(frozen=True)
class VmcoreIntrospectWorkspace:
    call_id: str
    agent_dir: Path
    sensitive_call_dir: Path
    wrapper: str
    stdout_path: Path
    stderr_path: Path


@dataclass(frozen=True)
class VmcoreIntrospectRun:
    command_result: CommandResult
    started_at: datetime
    finished_at: datetime
    duration_ms: int

    @property
    def ssh_result(self) -> CommandResult:
        return self.command_result


def _validate_vmcore_introspect_request(
    request: DebugIntrospectFromVmcoreRequest,
    *,
    store: ArtifactStore,
    manifest: RunManifest,
) -> ToolResponse | None:
    run_id = request.run_id
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

    sensitive_dir = store.run_dir(run_id) / "sensitive"
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
    return None


def _resolve_vmcore_introspect_inputs(
    request: DebugIntrospectFromVmcoreRequest,
    *,
    run_dir: Path,
    build_id_reader: Callable[[Path], str],
) -> tuple[VmcoreIntrospectInputs | None, ToolResponse | None]:
    run_id = request.run_id
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
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=str(exc),
            details={"code": "symbol_resolution_failed", "resolver_code": exc.code},
        )
    try:
        vmcore_path = confine_run_relative(request.vmcore_ref, run_dir=run_dir)
    except PathSafetyError as exc:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=str(exc),
            details={"code": "vmcore_not_found"},
        )
    if not vmcore_path.is_file():
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"vmcore not found at {request.vmcore_ref!r}",
            details={"code": "vmcore_not_found"},
        )

    try:
        expected_build_id = build_id_reader(resolved.vmlinux_path)
    except BuildIdReadError as exc:
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=f"could not read a GNU build-id from the supplied vmlinux: {exc}",
            details={"code": "vmlinux_build_id_unreadable"},
        )
    if not BUILD_ID_RE.match(expected_build_id):
        return None, ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message="vmlinux build_id is malformed",
            details={"code": "vmlinux_build_id_unreadable", "recorded": expected_build_id},
        )

    return (
        VmcoreIntrospectInputs(
            vmcore_path=vmcore_path,
            vmlinux_path=resolved.vmlinux_path,
            modules_path=str(resolved.modules_path) if resolved.modules_path is not None else None,
            expected_build_id=expected_build_id,
        ),
        None,
    )


def _resolve_vmcore_introspect_context(
    request: DebugIntrospectFromVmcoreRequest,
    *,
    artifact_root: Path,
    build_id_reader: Callable[[Path], str],
) -> tuple[VmcoreIntrospectContext | None, ToolResponse | None]:
    run_id = request.run_id
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        if not (store.run_dir(run_id) / "manifest.json").is_file():
            return None, _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return None, ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    validation_failure = _validate_vmcore_introspect_request(request, store=store, manifest=manifest)
    if validation_failure is not None:
        return None, validation_failure

    run_dir = store.run_dir(run_id)
    inputs, input_failure = _resolve_vmcore_introspect_inputs(request, run_dir=run_dir, build_id_reader=build_id_reader)
    if input_failure is not None:
        return None, input_failure
    inputs = _require_value(inputs, "vmcore introspect inputs missing after successful resolution")
    return (
        VmcoreIntrospectContext(
            store=store,
            run_id=run_id,
            run_dir=run_dir,
            redactor=Redactor(secret_values=[]),
            vmcore_path=inputs.vmcore_path,
            vmlinux_path=inputs.vmlinux_path,
            modules_path=inputs.modules_path,
            expected_build_id=inputs.expected_build_id,
        ),
        None,
    )


def _prepare_vmcore_introspect_workspace(
    ctx: VmcoreIntrospectContext,
    request: DebugIntrospectFromVmcoreRequest,
    *,
    caps: dict[str, int] | None,
) -> tuple[VmcoreIntrospectWorkspace | None, ToolResponse | None]:
    call_id = uuid.uuid4().hex
    agent_dir = ctx.run_dir / "debug" / "introspect" / call_id
    sensitive_call_dir = ctx.run_dir / "sensitive" / "debug" / "introspect" / call_id
    agent_dir.mkdir(parents=True, mode=0o700)
    sensitive_call_dir.mkdir(parents=True, mode=0o700)
    sensitive_call_dir.chmod(0o700)
    sensitive_call_dir.parent.chmod(0o700)
    sensitive_call_dir.parent.parent.chmod(0o700)

    args_json = json.dumps(request.args or {})
    try:
        wrapper = render_vmcore_wrapper(
            user_script=request.script,
            expected_build_id=ctx.expected_build_id,
            call_id=call_id,
            vmcore_path=str(ctx.vmcore_path),
            vmlinux_path=str(ctx.vmlinux_path),
            modules_path=ctx.modules_path,
            args_json=args_json,
            caps=caps,
        )
        skeleton = render_vmcore_wrapper_skeleton(
            expected_build_id=ctx.expected_build_id,
            call_id=call_id,
            user_script_sha256_hex=user_script_sha256(request.script),
            vmcore_path=str(ctx.vmcore_path),
            vmlinux_path=str(ctx.vmlinux_path),
            modules_path=ctx.modules_path,
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
        _record_terminal_introspect_result(ctx.store, ctx.run_id, failed)
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=ctx.run_id,
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
    (agent_dir / "request.json").write_text(json.dumps(ctx.redactor.redact_value(request_dump)), encoding="utf-8")

    return (
        VmcoreIntrospectWorkspace(
            call_id=call_id,
            agent_dir=agent_dir,
            sensitive_call_dir=sensitive_call_dir,
            wrapper=wrapper,
            stdout_path=sensitive_call_dir / "stdout.raw",
            stderr_path=sensitive_call_dir / "stderr.raw",
        ),
        None,
    )


def _run_vmcore_introspect_wrapper(
    ctx: VmcoreIntrospectContext,
    workspace: VmcoreIntrospectWorkspace,
    request: DebugIntrospectFromVmcoreRequest,
    *,
    runner: CommandRunner | None,
    clock: Callable[[], datetime],
) -> tuple[VmcoreIntrospectRun | None, ToolResponse | None]:
    active_process_runner: CommandRunner = runner or SubprocessCommandRunner()
    argv = ["timeout", "--kill-after=2s", f"{request.timeout_seconds}s", "python3", "-"]
    started_at = clock()
    started_monotonic = time.monotonic()
    try:
        command_result = active_process_runner.run(
            argv,
            timeout=request.timeout_seconds + SSH_TIMEOUT_GRACE_SECONDS,
            stdout_path=workspace.stdout_path,
            stderr_path=workspace.stderr_path,
            cancel=threading.Event(),
            stdin=workspace.wrapper,
            max_stdout_bytes=RUN_STDOUT_CAP,
        )
    except Exception as exc:  # noqa: BLE001 - offline boundary: return typed ToolResponse, do not leak raw exceptions
        duration_ms = int((time.monotonic() - started_monotonic) * 1000)
        artifacts = [
            ArtifactRef(path=str(workspace.agent_dir / "request.json"), kind="application/json"),
            ArtifactRef(path=str(workspace.agent_dir / "wrapper.skeleton.py"), kind="text/x-python"),
            ArtifactRef(path=str(workspace.sensitive_call_dir / "wrapper.py"), kind="text/x-python", sensitive=True),
        ]
        failed = StepResult(
            step_name=f"introspect:{workspace.call_id}",
            status=StepStatus.FAILED,
            summary="offline introspection failed before runner finalization",
            artifacts=artifacts,
            details={
                "call_id": workspace.call_id,
                "code": "offline_introspect_failed",
                "exception_type": type(exc).__name__,
                "duration_ms": duration_ms,
            },
        )
        _record_terminal_introspect_result(ctx.store, ctx.run_id, failed)
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=ctx.run_id,
            message="offline introspection failed before runner finalization",
            details={
                "code": "offline_introspect_failed",
                "call_id": workspace.call_id,
                "exception_type": type(exc).__name__,
            },
            artifacts=[artifact for artifact in artifacts if not artifact.sensitive],
            suggested_next_actions=["artifacts.get_manifest"],
        )
    for raw_path in (workspace.stdout_path, workspace.stderr_path):
        _chmod_best_effort(raw_path, 0o600)
    return (
        VmcoreIntrospectRun(
            command_result=command_result,
            started_at=started_at,
            finished_at=clock(),
            duration_ms=int((time.monotonic() - started_monotonic) * 1000),
        ),
        None,
    )


def _execute_vmcore_introspect_call(
    request: DebugIntrospectFromVmcoreRequest,
    *,
    artifact_root: Path,
    runner: CommandRunner | None = None,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
    clock: Callable[[], datetime] | None = None,
    operation_name: str = "debug.introspect.from_vmcore",
    caps: dict[str, int] | None = None,
    post_validator: IntrospectPostValidator | None = None,
) -> ToolResponse:
    """Offline vmcore drgn introspection (spec §6 / ADR 0010).

    Runs the user/helper drgn script against a captured vmcore on the agent host via a local
    ``python3`` subprocess. No admission gate, no SSH, no sudo; vmcore analysis is always
    concurrent-safe (interface-contracts §5.6 rule 3).
    """
    now = clock or _utcnow
    ctx, failure = _resolve_vmcore_introspect_context(
        request, artifact_root=artifact_root, build_id_reader=build_id_reader
    )
    if failure is not None:
        return failure
    if ctx is None:
        raise RuntimeError("vmcore introspect context missing after successful resolution")
    workspace, failure = _prepare_vmcore_introspect_workspace(ctx, request, caps=caps)
    if failure is not None:
        return failure
    if workspace is None:
        raise RuntimeError("vmcore introspect workspace missing after successful preparation")
    run, failure = _run_vmcore_introspect_wrapper(ctx, workspace, request, runner=runner, clock=now)
    if failure is not None:
        return failure
    if run is None:
        raise RuntimeError("vmcore introspect run missing after successful wrapper execution")
    return _finalize_introspect_call(
        IntrospectFinalizationContext(
            store=ctx.store,
            run_id=ctx.run_id,
            workspace=workspace,
            run=run,
            redactor=ctx.redactor,
            expected_build_id=ctx.expected_build_id,
            request_timeout_seconds=request.timeout_seconds,
            operation_name=operation_name,
            drgn_open_message="drgn could not open the vmcore",
            exec_principal=None,
            post_validator=post_validator,
        )
    )
