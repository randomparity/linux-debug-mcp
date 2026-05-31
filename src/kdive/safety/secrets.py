from __future__ import annotations

from enum import StrEnum

from kdive.model import Model


class SecretReferenceKind(StrEnum):
    FILE = "file"
    ENV = "env"
    EXTERNAL = "external"
    KEYRING = "keyring"


class SecretReference(Model):
    kind: SecretReferenceKind
    label: str
    reference: str
    required: bool = True
