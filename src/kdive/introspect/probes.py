from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kdive.domain import ArtifactRef, PrerequisiteCheck, PrerequisiteStatus, ToolResponse
from kdive.handlers.shared import _require_value
from kdive.prereqs.drgn_probe import UNKNOWN, USABLE, build_probe_checks, python_missing_checks
from kdive.providers.ssh import SshCommandResult
from kdive.target.probes import ProbeContext, parse_probe_stdout


def _python_missing_probe_success(
    ctx: ProbeContext,
    *,
    agent_dir: Path,
    stdout_path: Path,
    stderr_path: Path,
    probe_id: str,
) -> ToolResponse:
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


def assemble_introspect_probe_response(
    ctx: ProbeContext,
    *,
    ssh_result: SshCommandResult,
    stdout_path: Path,
    stderr_path: Path,
    agent_dir: Path,
    probe_id: str,
) -> ToolResponse:
    parsed, failure = parse_probe_stdout(
        ctx,
        ssh_result=ssh_result,
        stdout_path=stdout_path,
        noun="probe",
        no_python_message="target python3 is not available",
    )
    if failure is not None:
        if failure.error is not None and failure.error.details.get("code") == "probe_no_python":
            return _python_missing_probe_success(
                ctx,
                agent_dir=agent_dir,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                probe_id=probe_id,
            )
        return failure

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
