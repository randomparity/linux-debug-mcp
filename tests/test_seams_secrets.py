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


def test_missing_optional_env_is_skipped(monkeypatch):
    monkeypatch.delenv("OPT_VAR", raising=False)
    ref = SecretReference(kind=SecretReferenceKind.ENV, label="opt", reference="OPT_VAR", required=False)
    resolver = EnvSecretsResolver([ref])
    assert resolver.resolve(["OPT_VAR"]) == {}
