from __future__ import annotations

from typing import Any, TypeVar

from kdive.domain import ErrorCategory, ToolResponse
from kdive.model import Model

_ModelT = TypeVar("_ModelT", bound=Model)


def adapter_validation_failure(exc: Exception) -> dict[str, Any]:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=str(exc),
    ).model_dump(mode="json")


def model_arg(value: object, model_type: type[_ModelT]) -> _ModelT:
    if isinstance(value, model_type):
        return value
    return model_type.model_validate(value)


def optional_model_arg(value: object | None, model_type: type[_ModelT]) -> _ModelT:
    if value is None:
        return model_type()
    return model_arg(value, model_type)
