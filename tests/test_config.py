from pathlib import Path

import pytest
from pydantic import ValidationError

from linux_debug_mcp.config import (
    ArtifactPolicy,
    BuildProfile,
    DebugProfile,
    RootfsProfile,
    ServerConfig,
    TargetProfile,
)
from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind


def test_server_config_accepts_valid_pilot_profiles(tmp_path: Path) -> None:
    config = ServerConfig(
        artifact_root=tmp_path / "runs",
        build_profiles={
            "x86_64-default": BuildProfile(
                name="x86_64-default",
                architecture="x86_64",
                output_policy="per_run",
                command_timeout_seconds=3600,
                required_tools=["make", "gcc"],
            )
        },
        rootfs_profiles={
            "minimal": RootfsProfile(
                name="minimal",
                source="file:///var/lib/linux-debug/rootfs.qcow2",
                mutability="copy_on_write",
                access_method="ssh",
                credential_refs=[
                    SecretReference(kind=SecretReferenceKind.FILE, label="ssh-key", reference="/tmp/id_ed25519")
                ],
                readiness_marker="login:",
                guest_writable_paths=["/tmp"],
            )
        },
        target_profiles={
            "local-qemu": TargetProfile(
                name="local-qemu",
                architecture="x86_64",
                provider_name="libvirt-qemu",
                target_ref="linux-debug-dev",
                kernel_args=["console=ttyS0", "nokaslr"],
                timeout_seconds=300,
                cleanup_policy="preserve_failed",
                debug_gdbstub=True,
            )
        },
        debug_profiles={
            "gdbstub": DebugProfile(
                name="gdbstub",
                enabled_operations=["interrupt", "continue", "read_registers"],
                gdbstub_endpoint="localhost:1234",
                kaslr_policy="disabled",
                symbol_identity_required=True,
                evaluation_mode="predefined_inspectors",
            )
        },
        artifact_policy=ArtifactPolicy(
            retention_days=14,
            raw_logs_enabled=False,
            redact_responses=True,
            preserve_failed_runs=True,
        ),
    )

    assert config.artifact_root == tmp_path / "runs"
    assert config.build_profiles["x86_64-default"].architecture == "x86_64"
    assert config.rootfs_profiles["minimal"].credential_refs[0].label == "ssh-key"


def test_profile_names_must_match_dictionary_keys(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="profile key must match profile name"):
        ServerConfig(
            artifact_root=tmp_path,
            build_profiles={"wrong": BuildProfile(name="actual", architecture="x86_64")},
        )


def test_secret_reference_serializes_without_secret_value() -> None:
    ref = SecretReference(kind=SecretReferenceKind.ENV, label="token", reference="LINUX_DEBUG_TOKEN")

    assert ref.model_dump(mode="json") == {
        "kind": "env",
        "label": "token",
        "reference": "LINUX_DEBUG_TOKEN",
        "required": True,
    }
    assert "secret" not in ref.model_dump(mode="json")
