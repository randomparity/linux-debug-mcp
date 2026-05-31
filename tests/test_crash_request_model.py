from __future__ import annotations

import pytest
from pydantic import ValidationError

from kdive.postmortem.models import DebugPostmortemCrashRequest


def test_request_defaults() -> None:
    r = DebugPostmortemCrashRequest(
        run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", commands=["bt"]
    )
    assert r.modules_ref is None
    assert r.timeout_seconds == 60


def test_request_forbids_extra() -> None:
    with pytest.raises(ValidationError):
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="c",
            vmlinux_ref="v",
            commands=["bt"],
            target_ref="nope",
        )
