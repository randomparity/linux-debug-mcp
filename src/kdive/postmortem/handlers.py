from __future__ import annotations

import hashlib
import json
import shutil
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import (
    DEFAULT_FETCH_MAX_BYTES,
    FETCH_DISK_HEADROOM_BYTES,
    FETCH_TIMEOUT_BAND,
    TRIAGE_CRASH_COMMANDS,
    TRIAGE_DMESG_HELPER,
    TRIAGE_MODULES_HELPER,
    RootfsProfile,
)
from kdive.coordination.admission import AdmissionError
from kdive.default_profiles import DEFAULT_ROOTFS_PROFILES
from kdive.domain import (
    ArtifactRef,
    DebugIntrospectFromVmcoreHelperRequest,
    ErrorCategory,
    StepResult,
    StepStatus,
    ToolResponse,
)
from kdive.handlers.shared import _require_value
from kdive.introspect.execution import _record_terminal_introspect_result, _utcnow
from kdive.introspect.handlers import debug_introspect_from_vmcore_helper_handler
from kdive.postmortem.crash_handler import (
    debug_postmortem_crash_handler,
    resolve_postmortem_vmcore_context,
)
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
    DebugPostmortemCrashRequest,
    DebugPostmortemFetchRequest,
    DebugPostmortemListDumpsRequest,
    DebugPostmortemTriageReport,
    DebugPostmortemTriageRequest,
    DumpEntry,
    FetchedFile,
)
from kdive.postmortem.probes import assemble_kdump_probe_response, validated_dump_dir
from kdive.postmortem.triage import CrashOutcome, DrgnOutcome, any_section_ok, assemble_report
from kdive.prereqs.kdump_probe import render_kdump_probe_script
from kdive.providers.ssh import SshCommandResult, SshRunner, SubprocessSshRunner, build_ssh_argv
from kdive.safety.redaction import Redactor
from kdive.seams.probes import (
    PROBE_STDOUT_CAP,
    chmod_best_effort,
    configuration_failure,
    parse_probe_stdout,
    prepare_probe_dirs,
    redact_and_truncate,
    reject_if_target_halted,
    resolve_probe_context,
    target_python_remote_argv,
)
from kdive.symbols.build_id import read_elf_build_id
from kdive.symbols.vmcore_build_id import read_vmcore_build_id

SSH_TIMEOUT_GRACE_SECONDS = 10


@dataclass(frozen=True)
class _TriageSourceResponses:
    crash: ToolResponse
    dmesg: ToolResponse
    modules: ToolResponse


@dataclass(frozen=True)
class _TriageReportState:
    report: DebugPostmortemTriageReport
    sub_call_ids: dict[str, str | None]
    started_at: datetime
    finished_at: datetime
    duration_ms: int


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
    ctx: Any, *, ssh_result: SshCommandResult, stdout_path: Path
) -> tuple[dict[str, object] | None, ToolResponse | None]:
    return parse_probe_stdout(
        ctx,
        ssh_result=ssh_result,
        stdout_path=stdout_path,
        noun="enumeration",
        no_python_message="python3 is not available on the target; cannot enumerate dumps",
    )


def _run_dump_enumeration(
    ctx: Any,
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
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=redact_and_truncate(ctx.redactor, f"ssh probe raised: {exc}", cap=256),
            details={"code": "ssh_failure"},
        )
    for path in (stdout_path, stderr_path):
        chmod_best_effort(path, 0o600)
    parsed, failure = _parse_enumeration_result(ctx, ssh_result=ssh_result, stdout_path=stdout_path)
    if failure is not None:
        return None, failure
    parsed = _require_value(parsed, "dump enumeration parser returned no data without failure")
    (agent_dir / "probe.json").write_text(json.dumps(ctx.redactor.redact_value(parsed)), encoding="utf-8")
    return parsed, None


_DUMP_LISTING_SHAPE_ERRORS = (KeyError, TypeError, ValueError, AttributeError, ValidationError)


def _parse_dump_listing_at_boundary(
    ctx: Any, parsed: dict[str, object]
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
    ctx: Any, parsed: dict[str, object], dump_ref: str
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
    ctx: Any,
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
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=redact_and_truncate(ctx.redactor, f"scp raised: {exc}", cap=256),
            details={"code": "ssh_failure"},
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
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: Any | None = None,
    session_registry: Any | None = None,
) -> ToolResponse:
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    resolved_ctx, failure = resolve_probe_context(request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles)
    if failure is not None:
        return failure
    ctx = _require_value(resolved_ctx, "probe context missing after successful resolution")
    run_id = ctx.run_id

    try:
        halted = reject_if_target_halted(run_id=run_id, admission=admission, session_registry=session_registry)
    except AdmissionError as exc:
        return ToolResponse.failure(category=exc.category, run_id=run_id, message=str(exc), details={"code": exc.code})
    if halted is not None:
        return halted

    runner: SshRunner = ssh_runner or SubprocessSshRunner()
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
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message=redact_and_truncate(ctx.redactor, f"ssh probe raised: {exc}", cap=256),
            details={"code": "ssh_failure"},
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
    ctx: Any, *, runner: SshRunner, request: DebugPostmortemFetchRequest, dump_dir: str, dest_dir: Path
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
    ctx: Any,
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
        (dest_dir / "fetch.json").write_text(json.dumps(details), encoding="utf-8")
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
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: Any | None = None,
    session_registry: Any | None = None,
) -> ToolResponse:
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    resolved_ctx, failure = resolve_probe_context(request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles)
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
            admission=admission,
            session_registry=session_registry,
            action="enumerating dumps",
        )
    except AdmissionError as exc:
        return ToolResponse.failure(
            category=exc.category, run_id=ctx.run_id, message=str(exc), details={"code": exc.code}
        )
    if halted is not None:
        return halted
    runner: SshRunner = ssh_runner or SubprocessSshRunner()
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
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: Any | None = None,
    session_registry: Any | None = None,
) -> ToolResponse:
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    resolved_ctx, failure = resolve_probe_context(
        request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles, timeout_band=FETCH_TIMEOUT_BAND
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
            run_id=run_id, admission=admission, session_registry=session_registry, action="fetching a dump"
        )
    except AdmissionError as exc:
        return ToolResponse.failure(category=exc.category, run_id=run_id, message=str(exc), details={"code": exc.code})
    if halted is not None:
        return halted
    runner: SshRunner = ssh_runner or SubprocessSshRunner()
    dump_id = derive_dump_id(request.dump_ref)
    dest_dir = ctx.store.run_dir(run_id) / "debug" / "postmortem" / "dumps" / dump_id
    return _fetch_under_lock(ctx, runner=runner, request=request, dump_dir=dump_dir, dump_id=dump_id, dest_dir=dest_dir)


def _triage_subcall_id(resp: ToolResponse) -> str | None:
    """The sub-call's own call_id, on success (data) or failure (error.details)."""
    cid = resp.data.get("call_id") if resp.ok else (resp.error.details if resp.error else {}).get("call_id")
    return cid if isinstance(cid, str) else None


def _triage_reason(resp: ToolResponse) -> str:
    """A failed sub-call's stable error code, defensively (details may be empty)."""
    details = resp.error.details if resp.error else {}
    code = details.get("code")
    return code if isinstance(code, str) and code else "sub_call_failed"


def _triage_subcall_failure(*, run_id: str, code: str, exc: Exception) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        run_id=run_id,
        message="postmortem triage subcall failed before returning a tool response",
        details={"code": code, "exception_type": type(exc).__name__},
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _run_triage_sources(
    request: DebugPostmortemTriageRequest,
    *,
    artifact_root: Path,
    runner: SshRunner | None,
    vmcore_build_id_reader: Callable[[Path], str],
    vmlinux_build_id_reader: Callable[[Path], str],
    clock: Callable[[], datetime] | None,
    crash_handler: Callable[..., ToolResponse],
    drgn_helper_handler: Callable[..., ToolResponse],
) -> _TriageSourceResponses:
    run_id = request.run_id
    try:
        crash_resp = crash_handler(
            DebugPostmortemCrashRequest(
                run_id=run_id,
                vmcore_ref=request.vmcore_ref,
                vmlinux_ref=request.vmlinux_ref,
                modules_ref=request.modules_ref,
                commands=list(TRIAGE_CRASH_COMMANDS),
                timeout_seconds=request.timeout_seconds,
            ),
            artifact_root=artifact_root,
            runner=runner,
            vmcore_build_id_reader=vmcore_build_id_reader,
            vmlinux_build_id_reader=vmlinux_build_id_reader,
            clock=clock,
        )
    except Exception as exc:  # noqa: BLE001 - triage boundary normalizes subcall exceptions
        crash_resp = _triage_subcall_failure(run_id=run_id, code="postmortem_crash_failed", exc=exc)

    def drgn(name: str) -> ToolResponse:
        try:
            return drgn_helper_handler(
                DebugIntrospectFromVmcoreHelperRequest(
                    run_id=run_id,
                    vmcore_ref=request.vmcore_ref,
                    vmlinux_ref=request.vmlinux_ref,
                    modules_ref=None,
                    name=name,
                    timeout_seconds=request.timeout_seconds,
                ),
                artifact_root=artifact_root,
                runner=runner,
                build_id_reader=vmlinux_build_id_reader,
                clock=clock,
            )
        except Exception as exc:  # noqa: BLE001 - triage boundary normalizes subcall exceptions
            return _triage_subcall_failure(run_id=run_id, code="offline_introspect_failed", exc=exc)

    return _TriageSourceResponses(
        crash=crash_resp,
        dmesg=drgn(TRIAGE_DMESG_HELPER),
        modules=drgn(TRIAGE_MODULES_HELPER),
    )


def _build_triage_report_state(
    *,
    vmcore_build_id: str,
    sources: _TriageSourceResponses,
    started_at: datetime,
    finished_at: datetime,
    duration_ms: int,
) -> _TriageReportState:
    return _TriageReportState(
        report=assemble_report(
            vmcore_build_id=vmcore_build_id,
            crash=_triage_crash_outcome(sources.crash),
            dmesg=_triage_drgn_outcome(sources.dmesg),
            modules=_triage_drgn_outcome(sources.modules),
        ),
        sub_call_ids={
            "crash": _triage_subcall_id(sources.crash),
            "dmesg": _triage_subcall_id(sources.dmesg),
            "modules": _triage_subcall_id(sources.modules),
        },
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
    )


def _triage_crash_outcome(response: ToolResponse) -> CrashOutcome:
    return CrashOutcome(
        ok=response.ok,
        reason=None if response.ok else _triage_reason(response),
        results=response.data.get("results", {}) if response.ok else {},
    )


def _triage_drgn_outcome(response: ToolResponse) -> DrgnOutcome:
    return DrgnOutcome(
        ok=response.ok,
        reason=None if response.ok else _triage_reason(response),
        result=response.data.get("result", {}) if response.ok else {},
    )


def _record_failed_triage(
    *,
    store: ArtifactStore,
    run_id: str,
    state: _TriageReportState,
    redactor: Redactor,
) -> ToolResponse:
    section_reasons = {
        "panic_reason": state.report.panic_reason.reason,
        "faulting_task": state.report.faulting_task.reason,
        "backtrace": state.report.backtrace.reason,
        "recent_dmesg": state.report.recent_dmesg.reason,
        "modules": state.report.modules.reason,
    }
    details = redactor.redact_value(
        {
            "code": "triage_all_sources_failed",
            "sub_call_ids": state.sub_call_ids,
            "section_reasons": section_reasons,
        }
    )
    _record_terminal_introspect_result(
        store,
        run_id,
        StepResult(
            step_name=f"postmortem.triage:{uuid.uuid4().hex}",
            status=StepStatus.FAILED,
            summary="triage: all sources failed",
            artifacts=[],
            details={"code": "triage_all_sources_failed", "duration_ms": state.duration_ms},
        ),
    )
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        run_id=run_id,
        message="triage produced no usable section; both crash and drgn sources failed",
        details=details,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _persist_successful_triage_report(
    *,
    store: ArtifactStore,
    run_id: str,
    run_dir: Path,
    vmcore_build_id: str,
    state: _TriageReportState,
    redactor: Redactor,
) -> ToolResponse:
    call_id = uuid.uuid4().hex
    redacted_report = redactor.redact_value(state.report.model_dump(mode="json"))
    agent_dir = run_dir / "debug" / "postmortem" / "triage" / call_id
    agent_dir.mkdir(parents=True, mode=0o700)
    report_path = agent_dir / "report.json"
    report_path.write_text(json.dumps(redacted_report), encoding="utf-8")
    artifact = ArtifactRef(path=str(report_path.relative_to(run_dir)), kind="triage_report_json")
    partial = not all(
        section["status"] == "ok"
        for section in (
            redacted_report["panic_reason"],
            redacted_report["faulting_task"],
            redacted_report["backtrace"],
            redacted_report["recent_dmesg"],
            redacted_report["modules"],
        )
    )
    _record_terminal_introspect_result(
        store,
        run_id,
        StepResult(
            step_name=f"postmortem.triage:{call_id}",
            status=StepStatus.SUCCEEDED,
            summary=f"triage report (partial={partial})",
            artifacts=[artifact],
            details={
                "call_id": call_id,
                "vmcore_build_id": vmcore_build_id,
                "partial": partial,
                "duration_ms": state.duration_ms,
            },
        ),
    )
    return ToolResponse.success(
        summary=f"triage report (partial={partial})",
        run_id=run_id,
        data={
            "call_id": call_id,
            "report": redacted_report,
            "partial": partial,
            "vmcore_build_id": vmcore_build_id,
            "sub_call_ids": state.sub_call_ids,
            "started_at": state.started_at.isoformat(),
            "finished_at": state.finished_at.isoformat(),
            "duration_ms": state.duration_ms,
        },
        artifacts=[artifact],
        suggested_next_actions=[
            "debug.postmortem.crash",
            "debug.introspect.from_vmcore_helper",
            "artifacts.get_manifest",
        ],
    )


def debug_postmortem_triage_handler(
    request: DebugPostmortemTriageRequest,
    *,
    artifact_root: Path,
    runner: SshRunner | None = None,
    vmcore_build_id_reader: Callable[[Path], str] = read_vmcore_build_id,
    vmlinux_build_id_reader: Callable[[Path], str] = read_elf_build_id,
    clock: Callable[[], datetime] | None = None,
    crash_handler: Callable[..., ToolResponse] = debug_postmortem_crash_handler,
    drgn_helper_handler: Callable[..., ToolResponse] = debug_introspect_from_vmcore_helper_handler,
) -> ToolResponse:
    """Spec §4 / ADR 0027. Compose the crash + drgn offline tiers into one report; no admission gate."""
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
    if ctx is None:
        raise RuntimeError("postmortem vmcore context missing after successful resolution")
    store = ctx.store
    run_dir = ctx.run_dir
    vmcore_build_id = ctx.vmcore_build_id

    started_at = now()
    started_monotonic = time.monotonic()
    sources = _run_triage_sources(
        request,
        artifact_root=artifact_root,
        runner=runner,
        vmcore_build_id_reader=vmcore_build_id_reader,
        vmlinux_build_id_reader=vmlinux_build_id_reader,
        clock=clock,
        crash_handler=crash_handler,
        drgn_helper_handler=drgn_helper_handler,
    )
    duration_ms = int((time.monotonic() - started_monotonic) * 1000)
    state = _build_triage_report_state(
        vmcore_build_id=vmcore_build_id,
        sources=sources,
        started_at=started_at,
        finished_at=now(),
        duration_ms=duration_ms,
    )
    redactor = Redactor(secret_values=[])

    if not any_section_ok(state.report):
        return _record_failed_triage(store=store, run_id=run_id, state=state, redactor=redactor)

    return _persist_successful_triage_report(
        store=store,
        run_id=run_id,
        run_dir=run_dir,
        vmcore_build_id=vmcore_build_id,
        state=state,
        redactor=redactor,
    )
