"""Tests for debug.introspect.check_prerequisites (spec §3-§9)."""

from pathlib import Path  # noqa: F401 — used by later tasks appended to this file

import pytest
from pydantic import ValidationError

from linux_debug_mcp.domain import DebugIntrospectCheckPrerequisitesRequest


def test_request_defaults_and_extra_forbidden() -> None:
    req = DebugIntrospectCheckPrerequisitesRequest(run_id="r1", target_ref="local-qemu")
    assert req.timeout_seconds == 20
    assert req.debug_profile is None
    with pytest.raises(ValidationError):
        DebugIntrospectCheckPrerequisitesRequest(run_id="r1", target_ref="t", bogus=1)
