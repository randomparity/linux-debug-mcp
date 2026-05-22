from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTION = "[REDACTED]"


class Redactor:
    def __init__(self, secret_values: list[str] | None = None) -> None:
        self._secret_values = [value for value in secret_values or [] if value]
        self._key_value_pattern = re.compile(r"(?i)\b(password|passwd|token|api[_-]?key|secret)(\s*[=:]\s*)([^\s]+)")
        self._secret_key_pattern = re.compile(r"(?i)(password|passwd|token|api[_-]?key|secret)")

    def redact_text(self, text: str) -> str:
        redacted = text
        for value in self._secret_values:
            redacted = redacted.replace(value, REDACTION)
        return self._key_value_pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTION}", redacted)

    def redact_mapping(self, values: Mapping[str, object]) -> dict[str, object]:
        return self.redact_value(dict(values))

    def redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, Mapping):
            sensitive = value.get("sensitive") is True
            redacted: dict[str, Any] = {}
            for key, item in value.items():
                if sensitive and key == "path" or isinstance(item, str) and self._secret_key_pattern.search(str(key)):
                    redacted[key] = REDACTION
                else:
                    redacted[key] = self.redact_value(item)
            return redacted
        if isinstance(value, list):
            return [self.redact_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact_value(item) for item in value)
        return value
