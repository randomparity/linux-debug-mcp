from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind


class SecretsResolutionError(ValueError):
    """Raised when a secret reference cannot be resolved. Messages MUST never contain
    a resolved secret value (spec §3.4, §8)."""


@runtime_checkable
class SecretsResolver(Protocol):
    def resolve(self, refs: list[str]) -> dict[str, str]: ...


class EnvSecretsResolver:
    """Minimal #08 seam. Resolves **env** refs only. `file` and `external` refs are
    **deferred to the #08 secrets store** — this issue creates no credential source and
    reads no files (the ownership map puts secret resolution under #08; the #08 hardening
    rule is "sources are env / external store / OS keyring — never repo files"). The
    `SecretsResolver` Protocol lets #08 drop in the real keyring/external/file backend
    unchanged, with its own validation, audit, and leak tests. Resolved env values are
    never persisted to session JSON, the manifest, logs, or tool output — that is
    enforced by callers; this only produces them.

    This is a deliberate, flagged deviation from spec §3.4 (which lists "env + file" for
    the minimal resolver): #08 owns credential policy and forbids repo files, so #10
    ships env-only and defers the rest."""

    def __init__(self, references: list[SecretReference]) -> None:
        by_reference: dict[str, SecretReference] = {}
        for ref in references:
            if ref.reference in by_reference:
                raise SecretsResolutionError(
                    f"duplicate secret reference: {ref.reference}; resolution would be "
                    "order-dependent (requiredness/kind could be silently overridden)"
                )
            by_reference[ref.reference] = ref
        self._by_reference = by_reference

    def resolve(self, refs: list[str]) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for ref in refs:
            definition = self._by_reference.get(ref)
            if definition is None:
                raise SecretsResolutionError(f"unknown secret reference: {ref}")
            if definition.kind is not SecretReferenceKind.ENV:
                raise SecretsResolutionError(
                    f"{definition.kind} secret refs are deferred to the #08 secrets "
                    "store; the #10 minimal resolver resolves env only"
                )
            value = os.environ.get(definition.reference)
            if value is None:
                if definition.required:
                    raise SecretsResolutionError(f"required env secret not set: {definition.reference}")
                continue
            resolved[ref] = value
        return resolved
