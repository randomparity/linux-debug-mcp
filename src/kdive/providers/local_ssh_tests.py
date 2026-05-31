"""Deprecated compatibility facade for ``kdive.providers.local.local_ssh_tests``.

New code should import from ``kdive.providers.local.local_ssh_tests`` directly.
This facade is kept only for existing external imports and should be removed
before the 0.2.0 release.
"""

from kdive.providers.local.local_ssh_tests import (
    LocalSshTestProvider,
    PlannedTestCommand,
    SshCommandResult,
    SshRunner,
    SubprocessSshRunner,
    TestExecutionResult,
    TestPlan,
    build_ssh_argv,
    local_ssh_tests_capability,
)

__all__ = [
    "LocalSshTestProvider",
    "PlannedTestCommand",
    "SshCommandResult",
    "SshRunner",
    "SubprocessSshRunner",
    "TestExecutionResult",
    "TestPlan",
    "build_ssh_argv",
    "local_ssh_tests_capability",
]
