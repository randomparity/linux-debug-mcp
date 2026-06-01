from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypeVar

from kdive.domain import ErrorCategory, ToolResponse
from kdive.handlers.shared import configuration_failure_response

_RequiredT = TypeVar("_RequiredT")

_configuration_failure = configuration_failure_response


@dataclass(frozen=True)
class _HandlerFailure:
    category: ErrorCategory
    message: str
    run_id: str | None = None
    details: dict[str, Any] | None = None


def _require_value(value: _RequiredT | None, message: str) -> _RequiredT:
    if value is None:
        raise RuntimeError(message)
    return value


def _configuration_handler_failure(
    *,
    run_id: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> _HandlerFailure:
    return _HandlerFailure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
    )


def _tool_response_from_handler_failure(failure: _HandlerFailure) -> ToolResponse:
    return ToolResponse.failure(
        category=failure.category,
        message=failure.message,
        run_id=failure.run_id,
        details=failure.details,
    )
