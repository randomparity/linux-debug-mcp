import subprocess
import sys

import pytest

from kdive.safety.secret_registry import SecretRegistry
from kdive.safety.secrets import SecretReference, SecretReferenceKind
from kdive.seams.secrets import (
    EnvSecretsBackend,
    ExternalSecretsBackend,
    KeyringSecretsBackend,
    SecretsBackend,
    SecretsResolutionError,
    SecretsResolver,
    SecretsStore,
)

# --- backends -------------------------------------------------------------------------


def test_env_backend_is_a_backend_and_reads_env(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "s3cr3t")  # pragma: allowlist secret
    backend = EnvSecretsBackend()
    assert isinstance(backend, SecretsBackend)
    assert backend.kind is SecretReferenceKind.ENV
    ref = SecretReference(kind=SecretReferenceKind.ENV, label="t", reference="MY_TOKEN")
    assert backend.get(ref) == "s3cr3t"


def test_env_backend_absent_is_none(monkeypatch):
    monkeypatch.delenv("ABSENT", raising=False)
    ref = SecretReference(kind=SecretReferenceKind.ENV, label="t", reference="ABSENT")
    assert EnvSecretsBackend().get(ref) is None


def test_keyring_backend_missing_lib_raises_secret_free(monkeypatch):
    monkeypatch.setitem(sys.modules, "keyring", None)  # force the lazy import to fail
    with pytest.raises(SecretsResolutionError) as exc:
        KeyringSecretsBackend()
    assert "keyring" in str(exc.value).lower()


def test_keyring_backend_reads_via_injected_getter():
    calls = {}

    def fake_get(service, username):
        calls["args"] = (service, username)
        return "kr-secret"

    backend = KeyringSecretsBackend(get_password=fake_get)
    ref = SecretReference(kind=SecretReferenceKind.KEYRING, label="bmc", reference="svc/user")
    assert backend.get(ref) == "kr-secret"
    assert calls["args"] == ("svc", "user")


def test_keyring_backend_rejects_malformed_reference():
    backend = KeyringSecretsBackend(get_password=lambda s, u: "x")
    ref = SecretReference(kind=SecretReferenceKind.KEYRING, label="bad", reference="no-slash")
    with pytest.raises(SecretsResolutionError):
        backend.get(ref)


def _external_ref(reference="kv/bmc"):
    return SecretReference(kind=SecretReferenceKind.EXTERNAL, label="bmc", reference=reference)


def test_external_reads_stdout_and_passes_reference_via_argv():
    seen = {}

    def fake_run(argv, timeout):
        seen["argv"] = argv
        seen["timeout"] = timeout
        return 0, "ext-secret\n", ""

    backend = ExternalSecretsBackend(command=["helper"], runner=fake_run, timeout=5.0)
    assert backend.get(_external_ref("kv/bmc")) == "ext-secret"
    assert seen["argv"] == ["helper", "kv/bmc"]
    assert seen["timeout"] == 5.0


def test_external_nonzero_exit_raises_without_output():
    def fake_run(argv, timeout):
        return 3, "should-not-leak", "stderr-should-not-leak"

    backend = ExternalSecretsBackend(command=["helper"], runner=fake_run)
    with pytest.raises(SecretsResolutionError) as exc:
        backend.get(_external_ref())
    assert "should-not-leak" not in str(exc.value)
    assert "stderr-should-not-leak" not in str(exc.value)


def test_external_timeout_raises():
    def fake_run(argv, timeout):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

    backend = ExternalSecretsBackend(command=["helper"], runner=fake_run, timeout=0.1)
    with pytest.raises(SecretsResolutionError):
        backend.get(_external_ref())


def test_external_empty_command_rejected():
    with pytest.raises(SecretsResolutionError):
        ExternalSecretsBackend(command=[])


# --- store ----------------------------------------------------------------------------


def _store(defs, *, registry=None, backends=None):
    return SecretsStore(
        definitions=defs,
        backends=backends or {SecretReferenceKind.ENV: EnvSecretsBackend()},
        registry=registry or SecretRegistry(),
    )


class _FakeResolver:
    """A test fake proving the Protocol is consumable without a real backend."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def resolve(self, refs: list[str], *, scope: object | None = None) -> dict[str, str]:
        return {ref: self._values[ref] for ref in refs if ref in self._values}


def test_store_and_fake_satisfy_protocol():
    assert isinstance(_store([]), SecretsResolver)
    assert isinstance(_FakeResolver({}), SecretsResolver)


def test_resolves_env_and_registers_value(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "s3cr3t")  # pragma: allowlist secret
    reg = SecretRegistry()
    store = _store(
        [SecretReference(kind=SecretReferenceKind.ENV, label="t", reference="MY_TOKEN")],
        registry=reg,
    )
    assert store.resolve(["MY_TOKEN"], scope="sess") == {"MY_TOKEN": "s3cr3t"}
    assert "s3cr3t" in reg.snapshot()
    reg.release("sess")
    assert "s3cr3t" not in reg.snapshot()


def test_unknown_reference_raises():
    with pytest.raises(SecretsResolutionError):
        _store([]).resolve(["nope"])


def test_kind_without_backend_raises():
    store = SecretsStore(
        definitions=[SecretReference(kind=SecretReferenceKind.KEYRING, label="k", reference="s/u")],
        backends={},
        registry=SecretRegistry(),
    )
    with pytest.raises(SecretsResolutionError) as exc:
        store.resolve(["s/u"])
    assert "not enabled" in str(exc.value)


def test_file_kind_is_rejected_without_reading(tmp_path):
    secret_file = tmp_path / "key"
    secret_file.write_text("TOP-SECRET-VALUE", encoding="utf-8")  # pragma: allowlist secret
    store = SecretsStore(
        definitions=[SecretReference(kind=SecretReferenceKind.FILE, label="f", reference=str(secret_file))],
        backends={SecretReferenceKind.ENV: EnvSecretsBackend()},
        registry=SecretRegistry(),
    )
    with pytest.raises(SecretsResolutionError) as exc:
        store.resolve([str(secret_file)])
    assert "TOP-SECRET-VALUE" not in str(exc.value)


def test_missing_required_raises(monkeypatch):
    monkeypatch.delenv("ABSENT_VAR", raising=False)
    store = _store([SecretReference(kind=SecretReferenceKind.ENV, label="t", reference="ABSENT_VAR")])
    with pytest.raises(SecretsResolutionError):
        store.resolve(["ABSENT_VAR"])


def test_empty_required_is_absent(monkeypatch):
    monkeypatch.setenv("EMPTY_VAR", "")
    store = _store([SecretReference(kind=SecretReferenceKind.ENV, label="t", reference="EMPTY_VAR")])
    with pytest.raises(SecretsResolutionError):
        store.resolve(["EMPTY_VAR"])


def test_missing_optional_is_skipped(monkeypatch):
    monkeypatch.delenv("OPT_VAR", raising=False)
    store = _store([SecretReference(kind=SecretReferenceKind.ENV, label="o", reference="OPT_VAR", required=False)])
    assert store.resolve(["OPT_VAR"]) == {}


def test_duplicate_definition_rejected_at_construction():
    with pytest.raises(SecretsResolutionError):
        _store(
            [
                SecretReference(kind=SecretReferenceKind.ENV, label="a", reference="DUP", required=True),
                SecretReference(kind=SecretReferenceKind.ENV, label="b", reference="DUP", required=False),
            ]
        )


def test_duplicate_definition_cross_kind_rejected():
    with pytest.raises(SecretsResolutionError):
        _store(
            [
                SecretReference(kind=SecretReferenceKind.FILE, label="f", reference="DUP"),
                SecretReference(kind=SecretReferenceKind.ENV, label="e", reference="DUP"),
            ]
        )
