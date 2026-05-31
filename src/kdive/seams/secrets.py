from __future__ import annotations

import os
import subprocess
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Protocol, runtime_checkable

from kdive.safety.secret_registry import SecretRegistry
from kdive.safety.secrets import SecretReference, SecretReferenceKind


class SecretsResolutionError(ValueError):
    """Raised when a secret reference cannot be resolved. Messages MUST never contain
    a resolved secret value, a file's contents, or backend output (spec §3.4, §8)."""


@runtime_checkable
class SecretsResolver(Protocol):
    def resolve(self, refs: list[str], *, scope: object | None = None) -> dict[str, str]: ...


class SecretsBackend(ABC):
    """Per-source secret primitive (issue #65 `Secrets` ABC). A backend resolves one
    reference kind."""

    @property
    @abstractmethod
    def kind(self) -> SecretReferenceKind: ...

    @abstractmethod
    def get(self, reference: SecretReference) -> str | None:
        """Return the secret value, or None when the source has no value for this
        reference. Raise `SecretsResolutionError` only on a backend fault (keyring locked,
        helper command failed). Implementations MUST NOT include any secret value in an
        exception message or log line, and MUST NOT log child-process stdout/stderr."""


class EnvSecretsBackend(SecretsBackend):
    """Resolves environment-variable references. No new dependency."""

    @property
    def kind(self) -> SecretReferenceKind:
        return SecretReferenceKind.ENV

    def get(self, reference: SecretReference) -> str | None:
        return os.environ.get(reference.reference)


class KeyringSecretsBackend(SecretsBackend):
    """OS keyring backend. `keyring` is an optional extra imported lazily; tests inject
    `get_password` so they run without the library. `reference` is `service/username`
    (split on the first `/`); neither component's value is ever logged."""

    def __init__(self, *, get_password: Callable[[str, str], str | None] | None = None) -> None:
        if get_password is None:
            try:
                import keyring  # ty: ignore[unresolved-import]  # optional extra; ImportError becomes SecretsResolutionError
            except ImportError as exc:
                raise SecretsResolutionError(
                    "keyring backend requires the 'keyring' extra: install kdive[keyring]"
                ) from exc
            get_password = keyring.get_password
        self._get_password = get_password

    @property
    def kind(self) -> SecretReferenceKind:
        return SecretReferenceKind.KEYRING

    def get(self, reference: SecretReference) -> str | None:
        service, separator, username = reference.reference.partition("/")
        if not separator or not service or not username:
            raise SecretsResolutionError(f"keyring reference {reference.label!r} must be 'service/username'")
        try:
            return self._get_password(service, username)
        except Exception as exc:  # backend fault — never include the value
            raise SecretsResolutionError(f"keyring lookup failed for {reference.label!r}") from exc


class ExternalSecretsBackend(SecretsBackend):
    """Operator-configured resolver command. The (non-secret) reference is the final argv
    element; the secret is read from the child's stdout. stderr is used only to decide
    success and is never logged or surfaced. `runner` is an injectable seam returning
    `(returncode, stdout, stderr)` and may raise `subprocess.TimeoutExpired`."""

    def __init__(
        self,
        *,
        command: list[str],
        runner: Callable[[list[str], float], tuple[int, str, str]] | None = None,
        timeout: float = 10.0,
    ) -> None:
        if not command:
            raise SecretsResolutionError("external secrets command must be non-empty")
        self._command = list(command)
        self._timeout = timeout
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(argv: list[str], timeout: float) -> tuple[int, str, str]:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout, proc.stderr

    @property
    def kind(self) -> SecretReferenceKind:
        return SecretReferenceKind.EXTERNAL

    def get(self, reference: SecretReference) -> str | None:
        argv = [*self._command, reference.reference]
        try:
            returncode, stdout, _stderr = self._runner(argv, self._timeout)
        except subprocess.TimeoutExpired as exc:
            raise SecretsResolutionError(f"external secrets command timed out for {reference.label!r}") from exc
        if returncode != 0:
            raise SecretsResolutionError(
                f"external secrets command failed ({self._command[0]}) for {reference.label!r}"
            )
        return stdout.strip("\n") or None


class SecretsStore:
    """Implements `SecretsResolver` by dispatching each opaque ref to the backend named by
    its server-side `SecretReference`. The caller never selects a backend. Every resolved
    value is registered with the `SecretRegistry` under `scope` before it is returned."""

    def __init__(
        self,
        *,
        definitions: list[SecretReference],
        backends: dict[SecretReferenceKind, SecretsBackend],
        registry: SecretRegistry,
    ) -> None:
        by_reference: dict[str, SecretReference] = {}
        for definition in definitions:
            if definition.reference in by_reference:
                raise SecretsResolutionError(
                    f"duplicate secret reference: {definition.reference}; resolution would be "
                    "order-dependent (requiredness/kind could be silently overridden)"
                )
            by_reference[definition.reference] = definition
        self._by_reference = by_reference
        self._backends = dict(backends)
        self._registry = registry

    def resolve(self, refs: list[str], *, scope: object | None = None) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for ref in refs:
            definition = self._by_reference.get(ref)
            if definition is None:
                raise SecretsResolutionError(f"unknown secret reference: {ref}")
            if definition.kind is SecretReferenceKind.FILE:
                raise SecretsResolutionError(
                    f"file-backed secret {definition.label!r} is not supported "
                    "(repo files are forbidden); use env/keyring/external"
                )
            backend = self._backends.get(definition.kind)
            if backend is None:
                raise SecretsResolutionError(
                    f"{definition.kind} secret backend is not enabled for {definition.label!r}"
                )
            value = backend.get(definition)
            if not value:  # None or empty-string == absent
                if definition.required:
                    raise SecretsResolutionError(f"required secret not set: {definition.label!r}")
                continue
            self._registry.register(value, scope=scope)
            resolved[ref] = value
        return resolved
