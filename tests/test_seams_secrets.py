import pytest

from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind
from linux_debug_mcp.seams.secrets import (
    EnvSecretsResolver,
    SecretsResolutionError,
    SecretsResolver,
)


class _FakeResolver:
    """A test fake proving the Protocol is consumable without #08's real backend."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def resolve(self, refs: list[str]) -> dict[str, str]:
        return {ref: self._values[ref] for ref in refs if ref in self._values}


def test_resolver_and_fake_satisfy_protocol():
    assert isinstance(EnvSecretsResolver([]), SecretsResolver)
    assert isinstance(_FakeResolver({}), SecretsResolver)


def test_resolves_env_reference(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "s3cr3t")
    ref = SecretReference(kind=SecretReferenceKind.ENV, label="tok", reference="MY_TOKEN")
    resolver = EnvSecretsResolver([ref])
    assert resolver.resolve(["MY_TOKEN"]) == {"MY_TOKEN": "s3cr3t"}


def test_unknown_reference_raises():
    resolver = EnvSecretsResolver([])
    with pytest.raises(SecretsResolutionError):
        resolver.resolve(["nope"])


def test_file_kind_is_deferred_to_08(tmp_path):
    # #10 creates no file credential source; file refs are owned by #08. The resolver
    # must NOT read the file — it raises before any IO.
    secret_file = tmp_path / "key"
    secret_file.write_text("TOP-SECRET-VALUE", encoding="utf-8")
    ref = SecretReference(kind=SecretReferenceKind.FILE, label="k", reference=str(secret_file))
    resolver = EnvSecretsResolver([ref])
    with pytest.raises(SecretsResolutionError) as excinfo:
        resolver.resolve([str(secret_file)])
    # Deferred, not read: the file's contents never appear in the error.
    assert "TOP-SECRET-VALUE" not in str(excinfo.value)
    assert "#08" in str(excinfo.value)


def test_external_kind_is_deferred_to_08():
    ref = SecretReference(kind=SecretReferenceKind.EXTERNAL, label="x", reference="vault://x")
    resolver = EnvSecretsResolver([ref])
    with pytest.raises(SecretsResolutionError) as excinfo:
        resolver.resolve(["vault://x"])
    assert "#08" in str(excinfo.value)


def test_missing_required_env_raises():
    ref = SecretReference(kind=SecretReferenceKind.ENV, label="tok", reference="ABSENT_VAR")
    resolver = EnvSecretsResolver([ref])
    with pytest.raises(SecretsResolutionError):
        resolver.resolve(["ABSENT_VAR"])


def test_duplicate_reference_required_then_optional_is_rejected():
    # A duplicate reference must not let an optional definition silently mask a required
    # one — that would turn a missing credential into an empty resolve() instead of error.
    refs = [
        SecretReference(kind=SecretReferenceKind.ENV, label="a", reference="DUP", required=True),
        SecretReference(kind=SecretReferenceKind.ENV, label="b", reference="DUP", required=False),
    ]
    with pytest.raises(SecretsResolutionError):
        EnvSecretsResolver(refs)


def test_duplicate_reference_cross_kind_is_rejected():
    # An env ref must not be able to mask a file/external ref carrying the same string.
    refs = [
        SecretReference(kind=SecretReferenceKind.FILE, label="f", reference="DUP"),
        SecretReference(kind=SecretReferenceKind.ENV, label="e", reference="DUP"),
    ]
    with pytest.raises(SecretsResolutionError):
        EnvSecretsResolver(refs)


def test_missing_optional_env_is_skipped(monkeypatch):
    monkeypatch.delenv("OPT_VAR", raising=False)
    ref = SecretReference(kind=SecretReferenceKind.ENV, label="opt", reference="OPT_VAR", required=False)
    resolver = EnvSecretsResolver([ref])
    assert resolver.resolve(["OPT_VAR"]) == {}


def test_inject_break_failure_response_redacts_secret_in_exception_message(tmp_path):
    """Finding F15: a mechanism that raises an `InjectBreakError` carrying a secret-looking
    value in its message OR its `details` dict must NOT leak the secret into the
    `ToolResponse.message`/`details` the agent sees. The handler runs both through `Redactor`,
    so a `token=xyzABC123` substring is replaced with `[REDACTED]`."""
    from _layer4_fakes import KEY, FakeQemuTransport, build_txn

    from linux_debug_mcp.config import TRANSPORT_DESTRUCTIVE_PERMISSIONS
    from linux_debug_mcp.coordination.registry import SessionRegistry
    from linux_debug_mcp.domain import ErrorCategory
    from linux_debug_mcp.safety.redaction import REDACTION
    from linux_debug_mcp.server import transport_inject_break_handler, transport_open_handler
    from linux_debug_mcp.transport.break_inject import InjectBreakError

    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    open_response = transport_open_handler(run_id="run-1", transaction=txn, admission=admission, session_registry=reg)
    session_id = open_response.data["session_id"]

    def leaky_break(**_kwargs):
        # The mechanism raises an InjectBreakError whose message and details both contain a
        # secret-like value the Redactor pattern catches (`token=...`, `password=...`, etc.).
        raise InjectBreakError(
            "break failed: token=xyzABC123 in proxy connection",
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            details={"password": "topsecretpass", "endpoint": "tcp://127.0.0.1:5551"},
        )

    result = transport_inject_break_handler(
        run_id="run-1",
        session_id=session_id,
        acknowledged_permissions=TRANSPORT_DESTRUCTIVE_PERMISSIONS["transport.inject_break"],
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=leaky_break,
    )

    assert result.ok is False
    # The raw secret value does not appear in the message; Redactor substituted [REDACTED].
    assert "xyzABC123" not in result.error.message
    assert REDACTION in result.error.message
    # The `password` key in details is masked by the secret-key pattern (the Redactor masks
    # values whose key matches password/token/secret/etc.).
    assert result.error.details.get("password") == REDACTION
    # The durable record was still rolled to UNKNOWN — secret-redaction does not alter the
    # fail-closed posture for unconfirmable breaks.
    assert reg.read_record(KEY).execution_state.value == "unknown"
