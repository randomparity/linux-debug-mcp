import io
import logging

from kdive.logging import SECRET_REGISTRY, attach_redaction_filter, configure_logging
from kdive.safety.redaction import REDACTION, SecretRedactionFilter


def test_configure_logging_attaches_filter_to_root_handlers():
    configure_logging("INFO")
    root = logging.getLogger()
    assert root.handlers, "configure_logging must install at least one handler"
    assert all(
        any(isinstance(existing, SecretRedactionFilter) for existing in handler.filters) for handler in root.handlers
    )


def test_attach_redaction_filter_redacts_on_a_controlled_handler():
    SECRET_REGISTRY.register("rootcred", scope="install-test")
    try:
        buffer = io.StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("install.controlled")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)
        attach_redaction_filter(logger)
        logger.info("value rootcred")
        out = buffer.getvalue()
        assert "rootcred" not in out
        assert REDACTION in out
    finally:
        SECRET_REGISTRY.release("install-test")
