from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from kdive.config import RootfsProfile
from kdive.coordination.admission import AdmissionError, AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.default_profiles import DEFAULT_ROOTFS_PROFILES
from kdive.domain import ErrorCategory, ToolResponse
from kdive.handlers.shared import _require_value
from kdive.introspect.context import (
    LiveIntrospectRuntime,
    _configuration_failure,
)
from kdive.introspect.execution import _execute_introspect_call
from kdive.introspect.helpers import get_helper_registry
from kdive.introspect.models import (
    DebugIntrospectCheckPrerequisitesRequest,
    DebugIntrospectFromVmcoreHelperRequest,
    DebugIntrospectFromVmcoreRequest,
    DebugIntrospectHelperRequest,
    DebugIntrospectRunRequest,
)
from kdive.introspect.probes import assemble_introspect_probe_response
from kdive.introspect.result import (
    HELPER_CAP_PROFILE,
    _chmod_best_effort,
    _make_helper_post_validator,
    _redact_and_truncate,
)
from kdive.introspect.runner import _target_python_remote_argv
from kdive.introspect.vmcore_execution import (
    _execute_vmcore_introspect_call,
)
from kdive.prereqs.drgn_probe import PROBE_SCRIPT
from kdive.providers.ssh import (
    SSH_TIMEOUT_GRACE_SECONDS,
    CommandRunner,
    SshRunner,
    SubprocessSshRunner,
    build_ssh_argv,
)
from kdive.safety.redaction import Redactor
from kdive.seams.probes import (
    PROBE_STDOUT_CAP,
    prepare_probe_dirs,
    probe_runner_exception_failure,
    reject_if_target_halted,
    resolve_probe_context,
)
from kdive.symbols.build_id import read_elf_build_id


def debug_introspect_check_prerequisites_handler(
    request: DebugIntrospectCheckPrerequisitesRequest,
    *,
    artifact_root: Path,
    rootfs_profiles: Mapping[str, RootfsProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
) -> ToolResponse:
    """Target-side drgn prerequisite probe."""
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    _ctx, failure = resolve_probe_context(request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles)
    if failure is not None:
        return failure
    ctx = _require_value(_ctx, "probe context missing after successful resolution")
    run_id = ctx.run_id

    try:
        halted = reject_if_target_halted(
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
    agent_dir, sensitive_dir = prepare_probe_dirs(ctx.store, run_id, probe_id)

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
        return probe_runner_exception_failure(
            run_id=run_id,
            redactor=ctx.redactor,
            exc=exc,
            operation="ssh probe",
        )
    for _path in (stdout_path, stderr_path):
        _chmod_best_effort(_path, 0o600)

    return assemble_introspect_probe_response(
        ctx,
        ssh_result=ssh_result,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        agent_dir=agent_dir,
        probe_id=probe_id,
    )


def debug_introspect_run_handler(
    request: DebugIntrospectRunRequest,
    *,
    runtime: LiveIntrospectRuntime,
) -> ToolResponse:
    return _execute_introspect_call(
        request,
        runtime=runtime,
        operation_name="debug.introspect.run",
        caps=None,
        post_validator=None,
    )


def debug_introspect_helper_handler(
    request: DebugIntrospectHelperRequest,
    *,
    runtime: LiveIntrospectRuntime,
) -> ToolResponse:
    helper_registry = get_helper_registry()
    spec = helper_registry.get(request.name)
    if spec is None:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=request.run_id,
            message=f"unknown helper {request.name!r}; valid: {sorted(helper_registry)}",
            details={"code": "unknown_helper", "valid": sorted(helper_registry)},
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
        manifest_target_profile=request.manifest_target_profile,
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
        runtime=runtime,
        operation_name="debug.introspect.helper",
        caps=HELPER_CAP_PROFILE,
        post_validator=_make_helper_post_validator(spec),
    )


def debug_introspect_from_vmcore_handler(
    request: DebugIntrospectFromVmcoreRequest,
    *,
    artifact_root: Path,
    runner: CommandRunner | None = None,
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
    runner: CommandRunner | None = None,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    """Spec §3.1. Run a curated helper against a vmcore, reusing the live helper's post-validator
    and cap profile unchanged."""
    helper_registry = get_helper_registry()
    spec = helper_registry.get(request.name)
    if spec is None:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=request.run_id,
            message=f"unknown helper {request.name!r}; valid: {sorted(helper_registry)}",
            details={"code": "unknown_helper", "valid": sorted(helper_registry)},
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
