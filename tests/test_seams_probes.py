from pathlib import Path

from kdive.artifacts.store import ArtifactStore
from kdive.config import RootfsProfile
from kdive.domain import ErrorCategory
from kdive.providers.ssh import SshCommandResult
from kdive.safety.redaction import Redactor
from kdive.seams.probes import ProbeContext, parse_probe_stdout


def _probe_context(tmp_path: Path) -> ProbeContext:
    rootfs = RootfsProfile(
        name="minimal",
        source="/img.qcow2",
        access_method="ssh",
        ssh_host="127.0.0.1",
        ssh_user="root",
        ssh_key_ref="secret-dir",
    )
    return ProbeContext(
        store=ArtifactStore(tmp_path),
        run_id="run-1",
        rootfs=rootfs,
        host_build_id=None,
        redactor=Redactor(secret_values=["secret-dir"]),
    )


def test_parse_probe_stdout_returns_failure_when_stdout_is_unreadable(tmp_path: Path) -> None:
    stdout_path = tmp_path / "secret-dir"
    stdout_path.mkdir()

    parsed, failure = parse_probe_stdout(
        _probe_context(tmp_path),
        ssh_result=SshCommandResult(exit_status=0),
        stdout_path=stdout_path,
        noun="probe",
        no_python_message="python3 missing",
    )

    assert parsed is None
    assert failure is not None
    assert failure.ok is False
    assert failure.error is not None
    assert failure.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert failure.error.details["code"] == "probe_stdout_unreadable"
    assert failure.error.details["exception_type"] == "IsADirectoryError"
    assert "[REDACTED]" in failure.error.details["exception_message"]
    assert "secret-dir" not in str(failure.model_dump(mode="json"))
