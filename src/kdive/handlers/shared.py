from __future__ import annotations

from typing import TypeVar

from kdive.domain import ErrorCategory, ToolResponse

_RequiredT = TypeVar("_RequiredT")


def _require_value(value: _RequiredT | None, message: str) -> _RequiredT:
    if value is None:
        raise RuntimeError(message)
    return value


def configuration_failure_response(
    *,
    run_id: str,
    message: str,
    details: dict[str, object] | None = None,
) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
    )
