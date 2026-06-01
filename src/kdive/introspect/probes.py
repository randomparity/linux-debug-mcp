from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kdive.domain import ArtifactRef, ErrorCategory, PrerequisiteCheck, PrerequisiteStatus, ToolResponse
from kdive.handlers.shared import _require_value
from kdive.prereqs.drgn_probe import UNKNOWN, USABLE, build_probe_checks, python_missing_checks
from kdive.providers.ssh import SshCommandResult
from kdive.seams.probes import PROBE_STDOUT_CAP, ProbeContext, read_capped, redact_and_truncate


def _no_json_response(
    ctx: ProbeContext,
    *,
    ssh_result: SshCommandResult,
    agent_dir: Path,
    stdout_path: Path,
    stderr_path: Path,
    probe_id: str,
    parsed: Any,
) -> ToolResponse | None:
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
        snippet = redact_and_truncate(ctx.redactor, ssh_result.stderr_snippet or "", cap=256)
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            run_id=run_id,
            message="probe ssh transport failed before the target ran",
            details={"code": "ssh_connect_failure", "stderr": snippet},
        )
    snippet = redact_and_truncate(ctx.redactor, ssh_result.stderr_snippet or "", cap=256)
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        run_id=run_id,
        message=f"probe did not return parseable JSON (exit {ssh_result.exit_status})",
        details={"code": "probe_unparseable", "stderr": snippet},
    )


def assemble_introspect_probe_response(
    ctx: ProbeContext,
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
    raw_stdout = read_capped(stdout_path, PROBE_STDOUT_CAP)
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
    ctx: ProbeContext,
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
