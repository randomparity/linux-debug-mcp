from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path

from pydantic import ValidationError

from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import (
    DEFAULT_FETCH_MAX_BYTES,
    FETCH_DISK_HEADROOM_BYTES,
    FETCH_TIMEOUT_BAND,
    RootfsProfile,
)
from kdive.coordination.admission import AdmissionError
from kdive.default_profiles import DEFAULT_ROOTFS_PROFILES
from kdive.domain import (
    ArtifactRef,
    ErrorCategory,
    StepResult,
    StepStatus,
    ToolResponse,
)
from kdive.handlers.shared import _require_value
from kdive.postmortem.dumps import (
    FetchSpec,
    derive_dump_id,
    is_within_dump_dir,
    parse_dump_listing,
    plan_fetch,
    render_dump_list_script,
)
from kdive.postmortem.models import (
    DebugPostmortemCheckPrereqsRequest,
    DebugPostmortemFetchRequest,
    DebugPostmortemListDumpsRequest,
    DumpEntry,
    FetchedFile,
)
from kdive.postmortem.probes import assemble_kdump_probe_response, validated_dump_dir
from kdive.postmortem.tools import PostmortemToolRuntime
from kdive.prereqs.kdump_probe import render_kdump_probe_script
from kdive.providers.ssh import (
    SSH_TIMEOUT_GRACE_SECONDS,
    SshCommandResult,
    SshRunner,
    SubprocessSshRunner,
    build_ssh_argv,
)
from kdive.target.probes import (
    PROBE_STDOUT_CAP,
    ProbeContext,
    chmod_best_effort,
    configuration_failure,
    parse_probe_stdout,
    prepare_probe_dirs,
    probe_runner_exception_failure,
    redact_and_truncate,
    reject_if_target_halted,
    resolve_probe_context,
    target_python_remote_argv,
)


def _atomic_write_text(path: Path, text: str) -> None:
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temp_fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(temp_fd, "w", encoding="utf-8") as temp_file:
            temp_file.write(text)
            temp_file.flush()
        os.replace(temp_path, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            temp_path.unlink()
        raise


def build_scp_argv(
    *,
    rootfs_profile: RootfsProfile,
    known_hosts_path: Path,
    remote_path: str,
    local_dest: Path,
    command_timeout: int,
) -> list[str]:
    import shlex

    configured_timeout = rootfs_profile.ssh_options.get("ConnectTimeout")
    if configured_timeout is not None and int(configured_timeout) > command_timeout:
        raise ValueError("ConnectTimeout cannot exceed command timeout")
    connect_timeout = configured_timeout or str(min(command_timeout, 10))
    strict = rootfs_profile.ssh_options.get("StrictHostKeyChecking", "accept-new")
    argv = [
        "scp",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts_path}",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-o",
        f"StrictHostKeyChecking={strict}",
    ]
    for key in sorted(rootfs_profile.ssh_options):
        if key in {"ConnectTimeout", "StrictHostKeyChecking"}:
            continue
        argv.extend(["-o", f"{key}={rootfs_profile.ssh_options[key]}"])
    argv.extend(["-P", str(rootfs_profile.ssh_port)])
    if rootfs_profile.ssh_key_ref:
        argv.extend(["-i", rootfs_profile.ssh_key_ref])
    source = f"{rootfs_profile.ssh_user}@{rootfs_profile.ssh_host}:{shlex.quote(remote_path)}"
    argv.extend([source, str(local_dest)])
    return argv


def _parse_enumeration_result(
    ctx: ProbeContext, *, ssh_result: SshCommandResult, stdout_path: Path
) -> tuple[dict[str, object] | None, ToolResponse | None]:
    return parse_probe_stdout(
        ctx,
        ssh_result=ssh_result,
        stdout_path=stdout_path,
        noun="enumeration",
        no_python_message="python3 is not available on the target; cannot enumerate dumps",
    )


def _run_dump_enumeration(
    ctx: ProbeContext,
    *,
    runner: SshRunner,
    dump_dir: str,
    timeout_seconds: int,
    category: tuple[str, ...],
) -> tuple[dict[str, object] | None, ToolResponse | None]:
    run_id = ctx.run_id
    probe_id = uuid.uuid4().hex
    agent_dir, sensitive_dir = prepare_probe_dirs(ctx.store, run_id, probe_id, category=category)
    use_sudo = ctx.rootfs.ssh_user != "root"
    remote_argv = target_python_remote_argv(timeout_seconds=timeout_seconds, use_sudo=use_sudo)
    script = render_dump_list_script(dump_dir=dump_dir)
    try:
        ssh_argv = build_ssh_argv(
            rootfs_profile=ctx.rootfs,
            known_hosts_path=ctx.store.run_dir(run_id) / "sensitive" / "known_hosts",
            command=remote_argv,
            command_timeout=timeout_seconds + SSH_TIMEOUT_GRACE_SECONDS,
        )
    except ValueError as exc:
        return None, configuration_failure(
            run_id=run_id,
            message=redact_and_truncate(ctx.redactor, str(exc), cap=256),
            details={"code": "invalid_ssh_options"},
        )
    stdout_path = sensitive_dir / "stdout.raw"
    stderr_path = sensitive_dir / "stderr.raw"
    try:
        ssh_result = runner.run(
            ssh_argv,
            timeout=timeout_seconds + SSH_TIMEOUT_GRACE_SECONDS,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            stdin=script,
            max_stdout_bytes=PROBE_STDOUT_CAP,
        )
    except Exception as exc:
        return None, probe_runner_exception_failure(
            run_id=run_id,
            redactor=ctx.redactor,
            exc=exc,
            operation="ssh probe",
        )
    for path in (stdout_path, stderr_path):
        chmod_best_effort(path, 0o600)
    parsed, failure = _parse_enumeration_result(ctx, ssh_result=ssh_result, stdout_path=stdout_path)
    if failure is not None:
        return None, failure
    parsed = _require_value(parsed, "dump enumeration parser returned no data without failure")
    _atomic_write_text(agent_dir / "probe.json", json.dumps(ctx.redactor.redact_value(parsed)))
    return parsed, None


_DUMP_LISTING_SHAPE_ERRORS = (KeyError, TypeError, ValueError, AttributeError, ValidationError)


def _parse_dump_listing_at_boundary(
    ctx: ProbeContext, parsed: dict[str, object]
) -> tuple[list[DumpEntry] | None, ToolResponse | None]:
    enumeration_errors = parsed.get("enumeration_errors") or []
    if enumeration_errors:
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=ctx.run_id,
            message="dump enumeration was incomplete on the target",
            details={
                "code": "dump_enumeration_incomplete",
                "enumeration_errors": ctx.redactor.redact_value(enumeration_errors),
            },
            suggested_next_actions=["debug.postmortem.check_prereqs"],
        )
    try:
        return parse_dump_listing(parsed), None
    except _DUMP_LISTING_SHAPE_ERRORS as exc:
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=ctx.run_id,
            message="dump enumeration returned malformed listing data",
            details={
                "code": "malformed_dump_listing",
                "reason": redact_and_truncate(ctx.redactor, str(exc), cap=256),
            },
        )


def _match_dump_at_boundary(
    ctx: ProbeContext, parsed: dict[str, object], dump_ref: str
) -> tuple[DumpEntry | None, ToolResponse | None]:
    entries, failure = _parse_dump_listing_at_boundary(ctx, parsed)
    if failure is not None:
        return None, failure
    entries = _require_value(entries, "dump listing parser returned no entries without failure")
    for entry in entries:
        if entry.path == dump_ref:
            return entry, None
    return None, None


def _core_name(entry: DumpEntry) -> str:
    for name in ("vmcore", "vmcore.flat", "vmcore-incomplete"):
        if name in entry.file_sizes:
            return name
    return "vmcore"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record_fetch_result(store: ArtifactStore, run_id: str, result: StepResult, *, replace_succeeded: bool) -> None:
    delay_seconds = 0.01
    for attempt in range(5):
        try:
            store.record_step_result(run_id, result, replace_succeeded=replace_succeeded)
            return
        except ManifestStateError as exc:
            if "manifest is locked" not in str(exc) or attempt == 4:
                raise
            time.sleep(delay_seconds)
            delay_seconds *= 2


def _stage_one_file(
    *,
    runner: SshRunner,
    ctx: ProbeContext,
    spec: FetchSpec,
    dest_dir: Path,
    sensitive_dir: Path,
    timeout_seconds: int,
) -> tuple[FetchedFile | None, ToolResponse | None]:
    run_id = ctx.run_id
    local_dest = dest_dir / spec.local_name
    try:
        scp_argv = build_scp_argv(
            rootfs_profile=ctx.rootfs,
            known_hosts_path=ctx.store.run_dir(run_id) / "sensitive" / "known_hosts",
            remote_path=spec.remote_path,
            local_dest=local_dest,
            command_timeout=timeout_seconds,
        )
    except ValueError as exc:
        return None, configuration_failure(
            run_id=run_id,
            message=redact_and_truncate(ctx.redactor, str(exc), cap=256),
            details={"code": "invalid_ssh_options"},
        )
    stdout_path = sensitive_dir / f"{spec.local_name}.scp.out"
    stderr_path = sensitive_dir / f"{spec.local_name}.scp.err"
    try:
        result = runner.run(
            scp_argv,
            timeout=timeout_seconds,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            max_stdout_bytes=None,
        )
    except Exception as exc:
        return None, probe_runner_exception_failure(
            run_id=run_id,
            redactor=ctx.redactor,
            exc=exc,
            operation="scp",
        )
    if result.exit_status != 0 or result.timed_out or result.cancelled:
        snippet = redact_and_truncate(ctx.redactor, result.stderr_snippet or "", cap=256)
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=f"scp of {spec.local_name} failed",
            details={"code": "incomplete_transfer", "stderr": snippet},
        )
    local_size = local_dest.stat().st_size if local_dest.is_file() else -1
    if local_size != spec.expected_size:
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=f"{spec.local_name} truncated: got {local_size} bytes, expected {spec.expected_size}",
            details={"code": "incomplete_transfer"},
        )
    ref = str(local_dest.relative_to(ctx.store.run_dir(run_id)))
    return FetchedFile(name=spec.local_name, ref=ref, sha256=_sha256_file(local_dest), size_bytes=local_size), None


def _fetch_success_response(run_id: str, details: dict[str, object], *, already_fetched: bool) -> ToolResponse:
    data = {**details, "already_fetched": already_fetched}
    return ToolResponse.success(
        summary=f"dump {details['dump_id']} staged ({details['total_bytes']} bytes)",
        run_id=run_id,
        data=data,
        suggested_next_actions=[
            "debug.postmortem.crash",
            "debug.postmortem.triage",
            "debug.introspect.from_vmcore",
        ],
    )


def debug_postmortem_check_prereqs_handler(
    request: DebugPostmortemCheckPrereqsRequest,
    *,
    runtime: PostmortemToolRuntime,
) -> ToolResponse:
    profiles = runtime.rootfs_profiles if runtime.rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    resolved_ctx, failure = resolve_probe_context(
        request,
        artifact_root=runtime.artifact_root,
        rootfs_profiles=profiles,
    )
    if failure is not None:
        return failure
    ctx = _require_value(resolved_ctx, "probe context missing after successful resolution")
    run_id = ctx.run_id

    try:
        halted = reject_if_target_halted(
            run_id=run_id,
            admission=runtime.admission,
            session_registry=runtime.session_registry,
        )
    except AdmissionError as exc:
        return ToolResponse.failure(category=exc.category, run_id=run_id, message=str(exc), details={"code": exc.code})
    if halted is not None:
        return halted

    runner: SshRunner = runtime.ssh_runner or SubprocessSshRunner()
    probe_id = uuid.uuid4().hex
    agent_dir, sensitive_dir = prepare_probe_dirs(
        ctx.store, run_id, probe_id, category=("debug", "postmortem", "check_prereqs")
    )

    use_sudo = ctx.rootfs.ssh_user != "root"
    remote_argv = target_python_remote_argv(timeout_seconds=request.timeout_seconds, use_sudo=use_sudo)
    script = render_kdump_probe_script(systemctl_timeout=max(2, request.timeout_seconds // 2))
    try:
        ssh_argv = build_ssh_argv(
            rootfs_profile=ctx.rootfs,
            known_hosts_path=ctx.store.run_dir(run_id) / "sensitive" / "known_hosts",
            command=remote_argv,
            command_timeout=request.timeout_seconds + SSH_TIMEOUT_GRACE_SECONDS,
        )
    except ValueError as exc:
        return configuration_failure(
            run_id=run_id,
            message=redact_and_truncate(ctx.redactor, str(exc), cap=256),
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
            stdin=script,
            max_stdout_bytes=PROBE_STDOUT_CAP,
        )
    except Exception as exc:
        return probe_runner_exception_failure(
            run_id=run_id,
            redactor=ctx.redactor,
            exc=exc,
            operation="ssh probe",
        )
    for path in (stdout_path, stderr_path):
        chmod_best_effort(path, 0o600)

    return assemble_kdump_probe_response(
        ctx,
        ssh_result=ssh_result,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        agent_dir=agent_dir,
        probe_id=probe_id,
    )


def _admit_fetch_entry(
    ctx: ProbeContext, *, runner: SshRunner, request: DebugPostmortemFetchRequest, dump_dir: str, dest_dir: Path
) -> tuple[DumpEntry | None, ToolResponse | None]:
    run_id = ctx.run_id
    parsed, failure = _run_dump_enumeration(
        ctx,
        runner=runner,
        dump_dir=dump_dir,
        timeout_seconds=min(request.timeout_seconds, 60),
        category=("debug", "postmortem", "fetch", "enumerate"),
    )
    if failure is not None:
        return None, failure
    parsed = _require_value(parsed, "dump enumeration returned no data without failure")
    entry, failure = _match_dump_at_boundary(ctx, parsed, request.dump_ref)
    if failure is not None:
        return None, failure
    if entry is None:
        return None, configuration_failure(
            run_id=run_id,
            message=f"dump_ref not found in current listing: {request.dump_ref!r}",
            details={"code": "dump_not_found"},
        )
    if not is_within_dump_dir(entry.path, dump_dir):
        return None, configuration_failure(
            run_id=run_id,
            message=f"dump path {entry.path!r} is outside the enumerated dump_dir {dump_dir!r}",
            details={"code": "dump_path_outside_dir"},
        )
    if _core_name(entry) == "vmcore.flat":
        return None, ToolResponse.failure(
            category=ErrorCategory.READINESS_FAILURE,
            run_id=run_id,
            message=(
                "dump is in makedumpfile flat format (vmcore.flat); rebuild it on the target with "
                "`makedumpfile -R` to a vmcore before fetching"
            ),
            details={"code": "dump_flat_format"},
            suggested_next_actions=["debug.postmortem.list_dumps"],
        )
    if entry.incomplete and not request.force:
        return None, ToolResponse.failure(
            category=ErrorCategory.READINESS_FAILURE,
            run_id=run_id,
            message="dump is in-progress (vmcore-incomplete); pass force to fetch the partial anyway",
            details={"code": "dump_incomplete"},
            suggested_next_actions=["debug.postmortem.list_dumps"],
        )
    total = sum(entry.file_sizes.values()) or entry.size_bytes
    ceiling = request.max_bytes if request.max_bytes is not None else DEFAULT_FETCH_MAX_BYTES
    if total > ceiling:
        return None, configuration_failure(
            run_id=run_id,
            message=f"dump total {total} bytes exceeds ceiling {ceiling}",
            details={"code": "dump_too_large"},
        )
    free = shutil.disk_usage(ctx.store.run_dir(run_id)).free
    if free < total + FETCH_DISK_HEADROOM_BYTES:
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=f"insufficient host disk: {free} free, need {total} + headroom",
            details={"code": "insufficient_disk"},
        )
    return entry, None


def _fetch_under_lock(
    ctx: ProbeContext,
    *,
    runner: SshRunner,
    request: DebugPostmortemFetchRequest,
    dump_dir: str,
    dump_id: str,
    dest_dir: Path,
) -> ToolResponse:
    run_id = ctx.run_id
    step_name = f"postmortem.fetch:{dump_id}"
    with ctx.store.postmortem_fetch_lock(run_id):
        manifest = ctx.store.load_manifest(run_id)
        prior = manifest.step_results.get(step_name)
        if prior is not None and prior.status == StepStatus.SUCCEEDED and not request.force:
            return _fetch_success_response(run_id, dict(prior.details), already_fetched=True)
        entry, failure = _admit_fetch_entry(ctx, runner=runner, request=request, dump_dir=dump_dir, dest_dir=dest_dir)
        if failure is not None:
            return failure
        entry = _require_value(entry, "fetch entry missing after admission")
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        dest_dir.mkdir(parents=True, mode=0o700)
        sensitive_dir = ctx.store.run_dir(run_id) / "sensitive" / "debug" / "postmortem" / "fetch" / dump_id
        sensitive_dir.mkdir(parents=True, exist_ok=True)
        sensitive_dir.chmod(0o700)
        fetched: list[FetchedFile] = []
        ref_map: dict[str, str | None] = {
            "vmcore_ref": None,
            "vmlinux_ref": None,
            "vmcoreinfo_ref": None,
            "vmcore_dmesg_ref": None,
            "modules_ref": None,
        }
        for spec in plan_fetch(entry, vmcore_name=_core_name(entry)):
            staged, failure = _stage_one_file(
                runner=runner,
                ctx=ctx,
                spec=spec,
                dest_dir=dest_dir,
                sensitive_dir=sensitive_dir,
                timeout_seconds=request.timeout_seconds,
            )
            if failure is not None:
                shutil.rmtree(dest_dir, ignore_errors=True)
                return failure
            staged = _require_value(staged, "fetch stage returned no file without failure")
            fetched.append(staged)
            ref_map[spec.ref_key] = staged.ref
        details: dict[str, object] = {
            "dump_id": dump_id,
            "total_bytes": sum(f.size_bytes for f in fetched),
            "files": ctx.redactor.redact_value([f.model_dump(mode="json") for f in fetched]),
            **ref_map,
        }
        _atomic_write_text(dest_dir / "fetch.json", json.dumps(details))
        step = StepResult(
            step_name=step_name,
            status=StepStatus.SUCCEEDED,
            summary=f"fetched dump {dump_id} ({len(fetched)} files)",
            artifacts=[ArtifactRef(path=str(dest_dir / "fetch.json"), kind="application/json")],
            details=details,
        )
        _record_fetch_result(ctx.store, run_id, step, replace_succeeded=request.force)
    return _fetch_success_response(run_id, details, already_fetched=False)


def debug_postmortem_list_dumps_handler(
    request: DebugPostmortemListDumpsRequest,
    *,
    runtime: PostmortemToolRuntime,
) -> ToolResponse:
    profiles = runtime.rootfs_profiles if runtime.rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    resolved_ctx, failure = resolve_probe_context(
        request,
        artifact_root=runtime.artifact_root,
        rootfs_profiles=profiles,
    )
    if failure is not None:
        return failure
    ctx = _require_value(resolved_ctx, "probe context missing after successful resolution")
    dump_dir, dd_failure = validated_dump_dir(request, ctx.run_id)
    if dd_failure is not None:
        return dd_failure
    dump_dir = _require_value(dump_dir, "dump directory missing after validation")
    try:
        halted = reject_if_target_halted(
            run_id=ctx.run_id,
            admission=runtime.admission,
            session_registry=runtime.session_registry,
            action="enumerating dumps",
        )
    except AdmissionError as exc:
        return ToolResponse.failure(
            category=exc.category, run_id=ctx.run_id, message=str(exc), details={"code": exc.code}
        )
    if halted is not None:
        return halted
    runner: SshRunner = runtime.ssh_runner or SubprocessSshRunner()
    parsed, failure = _run_dump_enumeration(
        ctx,
        runner=runner,
        dump_dir=dump_dir,
        timeout_seconds=request.timeout_seconds,
        category=("debug", "postmortem", "list_dumps"),
    )
    if failure is not None:
        return failure
    parsed = _require_value(parsed, "dump enumeration returned no data without failure")
    entries, failure = _parse_dump_listing_at_boundary(ctx, parsed)
    if failure is not None:
        return failure
    entries = _require_value(entries, "dump listing parser returned no entries without failure")
    return ToolResponse.success(
        summary=f"found {len(entries)} captured dump(s) under {dump_dir}",
        run_id=ctx.run_id,
        data={
            "dump_dir": dump_dir,
            "dumps": ctx.redactor.redact_value([e.model_dump(mode="json") for e in entries]),
        },
        suggested_next_actions=["debug.postmortem.fetch"],
    )


def debug_postmortem_fetch_handler(
    request: DebugPostmortemFetchRequest,
    *,
    runtime: PostmortemToolRuntime,
) -> ToolResponse:
    profiles = runtime.rootfs_profiles if runtime.rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    resolved_ctx, failure = resolve_probe_context(
        request, artifact_root=runtime.artifact_root, rootfs_profiles=profiles, timeout_band=FETCH_TIMEOUT_BAND
    )
    if failure is not None:
        return failure
    ctx = _require_value(resolved_ctx, "probe context missing after successful resolution")
    run_id = ctx.run_id
    dump_dir, dd_failure = validated_dump_dir(request, run_id)
    if dd_failure is not None:
        return dd_failure
    dump_dir = _require_value(dump_dir, "dump directory missing after validation")
    try:
        halted = reject_if_target_halted(
            run_id=run_id,
            admission=runtime.admission,
            session_registry=runtime.session_registry,
            action="fetching a dump",
        )
    except AdmissionError as exc:
        return ToolResponse.failure(category=exc.category, run_id=run_id, message=str(exc), details={"code": exc.code})
    if halted is not None:
        return halted
    runner: SshRunner = runtime.ssh_runner or SubprocessSshRunner()
    dump_id = derive_dump_id(request.dump_ref)
    dest_dir = ctx.store.run_dir(run_id) / "debug" / "postmortem" / "dumps" / dump_id
    return _fetch_under_lock(ctx, runner=runner, request=request, dump_dir=dump_dir, dump_id=dump_id, dest_dir=dest_dir)
