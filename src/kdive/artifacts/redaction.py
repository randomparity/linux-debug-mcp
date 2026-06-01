from __future__ import annotations

from kdive.domain import ArtifactRef
from kdive.safety.redaction import Redactor


def redacted_artifacts(artifacts: list[ArtifactRef], redactor: Redactor | None = None) -> list[ArtifactRef]:
    redactor = redactor or Redactor()
    return [
        ArtifactRef.model_validate(redactor.redact_value(artifact.model_dump(mode="json"))) for artifact in artifacts
    ]
