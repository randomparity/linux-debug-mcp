from __future__ import annotations

from pathlib import Path

import pytest

from kdive.domain import ErrorCategory
from kdive.providers.gdb_mi import GdbMiAttachment, GdbMiError, GdbMiSessionRegistry


class _Ctrl:
    def __init__(self) -> None:
        self.exited = False

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]:
        return []

    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        return []

    def exit(self) -> None:
        self.exited = True


def _attachment(tmp_path: Path) -> GdbMiAttachment:
    return GdbMiAttachment(controller=_Ctrl(), rsp_host="127.0.0.1", rsp_port=1, transcript_path=tmp_path / "t.log")


def test_register_get_reap_roundtrip(tmp_path: Path) -> None:
    registry = GdbMiSessionRegistry()
    attachment = _attachment(tmp_path)
    registry.register("sid-1", attachment)
    assert registry.get("sid-1") is attachment
    assert registry.reap("sid-1") is attachment
    assert registry.get("sid-1") is None


def test_require_missing_raises_no_live_session(tmp_path: Path) -> None:
    registry = GdbMiSessionRegistry()
    with pytest.raises(GdbMiError) as exc:
        registry.require("absent")
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert exc.value.details.get("code") == "no_live_session"


def test_reap_absent_is_noop(tmp_path: Path) -> None:
    registry = GdbMiSessionRegistry()
    assert registry.reap("absent") is None
