from __future__ import annotations

import logging

from linux_debug_mcp.safety.redaction import SecretRedactionFilter
from linux_debug_mcp.safety.secret_registry import SecretRegistry

SECRET_REGISTRY = SecretRegistry()


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    attach_redaction_filter(logging.getLogger())


def attach_redaction_filter(logger: logging.Logger) -> None:
    """Attach the secret-redaction filter to every handler on ``logger``, idempotently."""
    for handler in logger.handlers:
        if not any(isinstance(existing, SecretRedactionFilter) for existing in handler.filters):
            handler.addFilter(SecretRedactionFilter(SECRET_REGISTRY))
