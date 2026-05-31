from __future__ import annotations

from typing import TypeVar

_RequiredT = TypeVar("_RequiredT")


def _require_value(value: _RequiredT | None, message: str) -> _RequiredT:
    if value is None:
        raise RuntimeError(message)
    return value
