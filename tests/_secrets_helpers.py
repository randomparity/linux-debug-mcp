"""Shared test helper: build an env-only `SecretsStore` standing in for the removed
`EnvSecretsResolver`. Tests alias `make_env_secrets` to the old name, so existing
construction call sites (`EnvSecretsResolver([...])`) keep working unchanged."""

from __future__ import annotations

from collections.abc import Iterable

from kdive.safety.secret_registry import SecretRegistry
from kdive.safety.secrets import SecretReference, SecretReferenceKind
from kdive.seams.secrets import EnvSecretsBackend, SecretsStore


def make_env_secrets(definitions: Iterable[SecretReference] = ()) -> SecretsStore:
    return SecretsStore(
        definitions=list(definitions),
        backends={SecretReferenceKind.ENV: EnvSecretsBackend()},
        registry=SecretRegistry(),
    )
