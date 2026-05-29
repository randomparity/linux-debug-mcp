import logging

from linux_debug_mcp.safety.redaction import REDACTION, SecretRedactionFilter
from linux_debug_mcp.safety.secret_registry import SecretRegistry


def _buffer_logger(name: str, registry: SecretRegistry) -> tuple[logging.Logger, list[str]]:
    records: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(self.format(record))

    handler = _Capture()
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.addFilter(SecretRedactionFilter(registry))
    logger = logging.getLogger(name)
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    return logger, records


def test_registered_value_and_keyword_pair_are_redacted():
    reg = SecretRegistry()
    reg.register("hunter2", scope="s")
    logger, records = _buffer_logger("rf.t1", reg)
    logger.error("auth token=%s value hunter2 here", "abc123")
    assert "hunter2" not in records[0]
    assert "abc123" not in records[0]  # token= keyword pair masked
    assert REDACTION in records[0]


def test_non_propagating_child_logger_still_redacts():
    reg = SecretRegistry()
    reg.register("sekret", scope="s")
    logger, records = _buffer_logger("parent.child", reg)
    logger.error("leak sekret")
    assert "sekret" not in records[0]


def test_exception_traceback_is_redacted():
    reg = SecretRegistry()
    reg.register("tracecred", scope="s")
    logger, records = _buffer_logger("rf.t3", reg)
    try:
        raise RuntimeError("boom tracecred")
    except RuntimeError:
        logger.exception("failed")
    assert "tracecred" not in records[0]


def test_bad_format_string_does_not_break_logging():
    reg = SecretRegistry()
    logger, records = _buffer_logger("rf.t4", reg)
    logger.error("missing arg %s and %s", "only-one")  # would raise in getMessage()
    assert records  # a record was still emitted, no exception escaped


def test_non_string_msg_is_handled():
    reg = SecretRegistry()
    reg.register("objcred", scope="s")
    logger, records = _buffer_logger("rf.t5", reg)
    logger.error({"k": "objcred"})  # non-string msg
    assert "objcred" not in records[0]


def test_eviction_stops_value_masking():
    reg = SecretRegistry()
    reg.register("evictme", scope="s")
    logger, records = _buffer_logger("rf.t6", reg)
    reg.release("s")
    logger.error("plain evictme text")
    # value no longer force-masked once its scope released (no keyword pattern either)
    assert "evictme" in records[0]
