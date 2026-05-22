from __future__ import annotations

import re
from collections.abc import Mapping


REDACTION = "[REDACTED]"


class Redactor:
    def __init__(self, secret_values: list[str] | None = None) -> None:
        self._secret_values = [value for value in secret_values or [] if value]
        self._key_value_pattern = re.compile(
            r"(?i)\b(password|passwd|token|api[_-]?key|secret)(\s*[=:]\s*)([^\s]+)"
        )

    def redact_text(self, text: str) -> str:
        redacted = text
        for value in self._secret_values:
            redacted = redacted.replace(value, REDACTION)
        return self._key_value_pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTION}", redacted)

    def redact_mapping(self, values: Mapping[str, object]) -> dict[str, object]:
        redacted: dict[str, object] = {}
        for key, value in values.items():
            if isinstance(value, str):
                redacted[key] = self.redact_text(value)
            else:
                redacted[key] = value
        return redacted
