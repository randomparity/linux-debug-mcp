from kdive.safety.redaction import REDACTION, Redactor


def test_redacts_registered_secret_values_from_text() -> None:
    redactor = Redactor(secret_values=["abc123"])

    assert redactor.redact_text("token=abc123") == "token=[REDACTED]"


def test_redacts_common_key_value_secret_patterns() -> None:
    redactor = Redactor()

    assert redactor.redact_text("password=hunter2 token: abc123") == "password=[REDACTED] token: [REDACTED]"


def test_redacts_prefixed_token_key_value_patterns() -> None:
    redactor = Redactor()

    assert redactor.redact_text("API_TOKEN=secret-token-value") == "API_TOKEN=[REDACTED]"


def test_redacts_environment_mapping() -> None:
    redactor = Redactor(secret_values=["topsecret"])

    assert redactor.redact_mapping({"API_TOKEN": "topsecret", "PATH": "/usr/bin"}) == {
        "API_TOKEN": "[REDACTED]",
        "PATH": "/usr/bin",
    }


def test_redacts_non_string_values_under_secret_named_keys() -> None:
    # TD-01: a secret-named key must be masked regardless of the value's type; an int,
    # list, or bool under "password"/"api_key"/"token" must not leak verbatim.
    redactor = Redactor()

    assert redactor.redact_value({"password": 12345, "api_key": ["a", "b"], "nested": {"token": True}}) == {
        "password": REDACTION,
        "api_key": REDACTION,
        "nested": {"token": REDACTION},
    }


def test_redacts_nested_values_and_sensitive_artifact_paths() -> None:
    redactor = Redactor(secret_values=["topsecret"])

    value = {
        "step_results": {
            "collect": {
                "details": {"token": "topsecret", "nested": ["password=hunter2"]},
                "artifacts": [
                    {
                        "kind": "log",
                        "path": "/tmp/runs/run-abc123/sensitive/serial.log",
                        "sensitive": True,
                    }
                ],
            }
        }
    }

    assert redactor.redact_value(value) == {
        "step_results": {
            "collect": {
                "details": {"token": "[REDACTED]", "nested": ["password=[REDACTED]"]},
                "artifacts": [
                    {
                        "kind": "log",
                        "path": "[REDACTED]",
                        "sensitive": True,
                    }
                ],
            }
        }
    }
