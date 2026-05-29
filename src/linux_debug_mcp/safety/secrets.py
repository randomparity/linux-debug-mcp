from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class SecretReferenceKind(StrEnum):
    FILE = "file"
    ENV = "env"
    EXTERNAL = "external"
    KEYRING = "keyring"


class SecretReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: SecretReferenceKind
    label: str
    reference: str
    required: bool = True
