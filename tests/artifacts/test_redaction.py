from kdive.artifacts.redaction import redacted_artifacts
from kdive.domain import ArtifactRef
from kdive.safety.redaction import Redactor


def test_redacted_artifacts_masks_sensitive_artifact_paths() -> None:
    artifact = ArtifactRef(path="/tmp/run/token-secret/serial.log", kind="serial-log", sensitive=True)

    redacted = redacted_artifacts([artifact], Redactor(secret_values=["token-secret"]))

    assert redacted == [ArtifactRef(path="[REDACTED]", kind="serial-log", sensitive=True)]
