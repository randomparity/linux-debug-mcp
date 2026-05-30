from __future__ import annotations

import pytest
from pydantic import ValidationError

from linux_debug_mcp.domain import DebugPostmortemCheckPrereqsRequest


def test_request_defaults_and_fields() -> None:
    req = DebugPostmortemCheckPrereqsRequest(run_id="r1", target_ref="x86_64-default")
    assert req.timeout_seconds == 20
    assert req.debug_profile is None


def test_request_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        DebugPostmortemCheckPrereqsRequest(run_id="r1", target_ref="x", bogus=1)
