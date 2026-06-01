from kdive.domain import PrerequisiteStatus
from kdive.prereqs.checks import check_prerequisites


class _Runner:
    def __init__(self, present):
        self._present = present

    def which(self, command):
        if command == "agent-proxy" and self._present:
            return "/usr/local/bin/agent-proxy"
        return ("/bin/" + command) if self._present else None

    def run(self, command, timeout):
        return (0, "", "")


def _check(checks, check_id):
    return next(c for c in checks if c.check_id == check_id)


def test_agent_proxy_present_passes(tmp_path):
    checks = check_prerequisites(
        artifact_root=tmp_path, source_path=None, enable_libvirt_check=False, runner=_Runner(present=True)
    )
    assert _check(checks, "tool.agent-proxy").status is PrerequisiteStatus.PASSED


def test_agent_proxy_absent_warns_with_remediation(tmp_path):
    checks = check_prerequisites(
        artifact_root=tmp_path, source_path=None, enable_libvirt_check=False, runner=_Runner(present=False)
    )
    check = _check(checks, "tool.agent-proxy")
    assert check.status is PrerequisiteStatus.WARNING
    assert "agent-proxy" in (check.suggested_fix or "")
