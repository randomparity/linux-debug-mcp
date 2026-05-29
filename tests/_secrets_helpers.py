"""Shared test helper: build an env-only `SecretsStore` standing in for the removed
`EnvSecretsResolver`. Tests alias `make_env_secrets` to the old name, so existing
construction call sites (`EnvSecretsResolver([...])`) keep working unchanged."""

from __future__ import annotations

from collections.abc import Iterable

from linux_debug_mcp.safety.secret_registry import SecretRegistry
from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind
from linux_debug_mcp.seams.secrets import EnvSecretsBackend, SecretsStore


def make_env_secrets(definitions: Iterable[SecretReference] = ()) -> SecretsStore:
    return SecretsStore(
        definitions=list(definitions),
        backends={SecretReferenceKind.ENV: EnvSecretsBackend()},
        registry=SecretRegistry(),
    )
