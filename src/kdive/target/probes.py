from __future__ import annotations

import contextlib
import json
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import RootfsProfile
from kdive.coordination.admission import AdmissionService
from kdive.coordination.exec_probe import probe_execution_state
from kdive.coordination.registry import SessionRegistry
from kdive.domain import ArtifactRef, ErrorCategory, PrerequisiteCheck, PrerequisiteStatus, StepStatus, ToolResponse
from kdive.handlers.shared import _require_value
from kdive.postmortem.dumps import DEFAULT_DUMP_DIR
from kdive.prereqs.drgn_probe import UNKNOWN, USABLE, build_probe_checks, python_missing_checks
from kdive.prereqs.kdump_probe import build_kdump_checks
from kdive.providers.ssh import SshCommandResult
from kdive.safety.redaction import Redactor
from kdive.seams.target import TargetKey
from kdive.transport.base import ExecutionState
from kdive.transport.handlers import _require_snapshot

PROBE_STDOUT_CAP = 256 * 1024


def _configuration_failure(*, run_id: str, message: str, details: dict[str, Any] | None = None) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
    )


def _target_python_remote_argv(*, timeout_seconds: int, use_sudo: bool) -> list[str]:
    """Return the remote argv that runs a Python probe under bounded time."""
    command = [
        "timeout",
        "--kill-after=2s",
        f"{timeout_seconds}s",
        "python3",
        "-",
    ]
    if not use_sudo:
        return command
    quoted = " ".join(shlex.quote(part) for part in command)
    return ["sudo", "-n", "sh", "-c", quoted]


def _redact_and_truncate(redactor: Redactor, text: str, cap: int = 256) -> str:
    redacted = redactor.redact_text(text)
    return redacted[:cap] + ("..." if len(redacted) > cap else "")


def _chmod_best_effort(path: Path, mode: int) -> None:
    with contextlib.suppress(OSError):
        path.chmod(mode)


def _read_capped(path: Path, cap: int) -> str | None:
    """Read the file iff its byte size is within *cap*; None if oversized."""
    if not path.exists():
        return ""
    if path.stat().st_size > cap:
        return None
    return path.read_text(encoding="utf-8", errors="replace")


class _SupportsProbeRequest(Protocol):
    run_id: str
    manifest_target_profile: str
    timeout_seconds: int
    debug_profile: str | None
    target_profile: str | None
    rootfs_profile: str | None


class _SupportsDumpRequest(Protocol):
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
    """Shared run/rootfs validation for target-side prerequisite and dump probes."""
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
        _ProbeContext(store=store, run_id=run_id, rootfs=rootfs, host_build_id=host_build_id, redactor=redactor),
        None,
    )


def _reject_if_target_halted(
    *,
    run_id: str,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
    action: str = "probing kdump prerequisites",
) -> ToolResponse | None:
    """Proof-only fast-reject for read-only target probes."""
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


def _prepare_probe_dirs(
    store: ArtifactStore,
    run_id: str,
    probe_id: str,
    *,
    category: tuple[str, ...] = ("debug", "checkprereq"),
) -> tuple[Path, Path]:
    """Create the agent-visible and sensitive probe directories with 0o700."""
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


def _parse_probe_stdout(
    ctx: _ProbeContext,
    *,
    ssh_result: SshCommandResult,
    stdout_path: Path,
    noun: str,
    no_python_message: str,
) -> tuple[dict[str, Any] | None, ToolResponse | None]:
    """Shared SSH-probe stdout gate for kdump-readiness and dump-enumeration probes."""
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
    """Handle no-JSON cases for advisory drgn prerequisite probes."""
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

    parsed = _require_value(parsed if isinstance(parsed, dict) else None, "probe stdout parser returned non-dict")
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


def _validated_dump_dir(request: _SupportsDumpRequest, run_id: str) -> tuple[str | None, ToolResponse | None]:
    dump_dir = request.dump_dir or DEFAULT_DUMP_DIR
    if not dump_dir.startswith("/"):
        return None, _configuration_failure(
            run_id=run_id,
            message=f"dump_dir must be an absolute path; got {dump_dir!r}",
            details={"code": "invalid_dump_dir"},
        )
    return dump_dir, None
