from linux_debug_mcp.safety.redaction import Redactor


def test_redacts_registered_secret_values_from_text() -> None:
    redactor = Redactor(secret_values=["abc123"])

    assert redactor.redact_text("token=abc123") == "token=[REDACTED]"


def test_redacts_common_key_value_secret_patterns() -> None:
    redactor = Redactor()

    assert redactor.redact_text("password=hunter2 token: abc123") == "password=[REDACTED] token: [REDACTED]"


def test_redacts_environment_mapping() -> None:
    redactor = Redactor(secret_values=["topsecret"])

    assert redactor.redact_mapping({"API_TOKEN": "topsecret", "PATH": "/usr/bin"}) == {
        "API_TOKEN": "[REDACTED]",
        "PATH": "/usr/bin",
    }
