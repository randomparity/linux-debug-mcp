from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from kdive.domain import ArtifactRef, PrerequisiteStatus, ToolResponse
from kdive.handlers.shared import _require_value
from kdive.postmortem.dumps import DEFAULT_DUMP_DIR
from kdive.prereqs.kdump_probe import build_kdump_checks
from kdive.providers.ssh import SshCommandResult
from kdive.target.probes import ProbeContext, configuration_failure, parse_probe_stdout


class _SupportsDumpRequest(Protocol):
    dump_dir: str | None


def assemble_kdump_probe_response(
    ctx: ProbeContext,
    *,
    ssh_result: SshCommandResult,
    stdout_path: Path,
    stderr_path: Path,
    agent_dir: Path,
    probe_id: str,
) -> ToolResponse:
    run_id = ctx.run_id
    parsed, failure = parse_probe_stdout(
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


def validated_dump_dir(request: _SupportsDumpRequest, run_id: str) -> tuple[str | None, ToolResponse | None]:
    dump_dir = request.dump_dir or DEFAULT_DUMP_DIR
    if not dump_dir.startswith("/"):
        return None, configuration_failure(
            run_id=run_id,
            message=f"dump_dir must be an absolute path; got {dump_dir!r}",
            details={"code": "invalid_dump_dir"},
        )
    return dump_dir, None
