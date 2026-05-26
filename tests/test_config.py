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
    TestCommand,
    TestSuiteProfile,
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
                provider_name="local-libvirt-qemu",
                target_ref="linux-debug-dev",
                kernel_args=["console=ttyS0", "nokaslr"],
                timeout_seconds=300,
                cleanup_policy="preserve_on_failure",
                debug_gdbstub=True,
                gdbstub_endpoint="localhost:1234",
            )
        },
        debug_profiles={
            "gdbstub": DebugProfile(
                name="gdbstub",
                enabled_operations=["debug.interrupt", "debug.continue", "debug.read_registers"],
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


def test_sprint_2_profiles_accept_libvirt_boot_fields(tmp_path: Path) -> None:
    rootfs = RootfsProfile(
        name="minimal",
        source=str(tmp_path / "rootfs.qcow2"),
        source_type="disk_image",
        mutability="read_only",
        access_method="serial",
        readiness_marker="linux-debug-ready",
    )
    target = TargetProfile(
        name="local-qemu",
        architecture="x86_64",
        provider_name="local-libvirt-qemu",
        target_ref="mcp-linux-debug-dev",
        kernel_args=["nokaslr"],
        timeout_seconds=120,
        cleanup_policy="preserve_on_failure",
        libvirt_uri="qemu:///system",
        managed_domain=True,
        managed_domain_prefix="mcp-",
    )

    assert rootfs.source_type == "disk_image"
    assert target.libvirt_uri == "qemu:///system"
    assert target.managed_domain is True


def test_target_profile_accepts_local_gdbstub_endpoint() -> None:
    profile = TargetProfile(
        name="local-qemu",
        architecture="x86_64",
        target_ref="mcp-linux-debug-dev",
        managed_domain=True,
        libvirt_uri="qemu:///system",
        debug_gdbstub=True,
        gdbstub_endpoint="127.0.0.1:1234",
    )

    assert profile.debug_gdbstub is True
    assert profile.gdbstub_endpoint == "127.0.0.1:1234"


def test_default_debug_profile_matches_sprint_4_policy() -> None:
    profile = DebugProfile(name="qemu-gdbstub-default")

    assert profile.kaslr_policy == "disabled"
    assert profile.symbol_identity_required is True
    assert profile.evaluation_mode == "predefined_inspectors"
    assert profile.enabled_operations == [
        "debug.start_session",
        "debug.interrupt",
        "debug.continue",
        "debug.set_breakpoint",
        "debug.clear_breakpoint",
        "debug.list_breakpoints",
        "debug.read_registers",
        "debug.read_symbol",
        "debug.read_memory",
        "debug.evaluate",
        "debug.end_session",
    ]


def test_debug_profile_rejects_unsupported_sprint_4_policy() -> None:
    with pytest.raises(ValidationError):
        DebugProfile(name="bad", kaslr_policy="known")

    with pytest.raises(ValidationError):
        DebugProfile(name="bad", evaluation_mode="limited_expressions")


def test_debug_profile_rejects_unknown_enabled_operation() -> None:
    with pytest.raises(ValidationError):
        DebugProfile(name="bad", enabled_operations=["debug.raw_gdb"])


def test_sprint_3_rootfs_profile_accepts_ssh_access_fields() -> None:
    profile = RootfsProfile(
        name="minimal",
        source="/var/lib/linux-debug/rootfs.qcow2",
        access_method="ssh_and_serial",
        ssh_host="127.0.0.1",
        ssh_port=2222,
        ssh_user="root",
        ssh_key_ref="/tmp/id_ed25519",
        ssh_options={
            "ConnectTimeout": "5",
            "IdentitiesOnly": "yes",
            "LogLevel": "ERROR",
            "StrictHostKeyChecking": "accept-new",
        },
    )

    assert profile.ssh_host == "127.0.0.1"
    assert profile.ssh_port == 2222
    assert profile.ssh_user == "root"
    assert profile.ssh_options["ConnectTimeout"] == "5"


def test_test_suite_profile_accepts_ordered_commands() -> None:
    suite = TestSuiteProfile(
        name="smoke-basic",
        timeout_seconds=30,
        stop_on_failure=True,
        collect_dmesg=True,
        commands=[
            TestCommand(name="uname", argv=["uname", "-a"]),
            TestCommand(name="proc-version", argv=["test", "-r", "/proc/version"]),
        ],
    )

    assert [command.name for command in suite.commands] == ["uname", "proc-version"]
    assert suite.commands[0].required is True


@pytest.mark.parametrize("name", ["", "../bad", "bad/name", "bad name", "bad\nname"])
def test_test_command_rejects_non_filesystem_safe_names(name: str) -> None:
    with pytest.raises(ValidationError):
        TestCommand(name=name, argv=["uname"])


@pytest.mark.parametrize("argv", [[], [""], ["bad\narg"], ["bad\0arg"]])
def test_test_command_rejects_empty_or_control_character_argv(argv: list[str]) -> None:
    with pytest.raises(ValidationError):
        TestCommand(name="bad", argv=argv)


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("ProxyCommand", "nc bad 22"),
        ("ConnectTimeout", "0"),
        ("ConnectTimeout", "999999"),
        ("IdentitiesOnly", "maybe"),
        ("LogLevel", "DEBUG"),
        ("StrictHostKeyChecking", "no"),
        ("Bad Option", "yes"),
        ("Bad\nOption", "yes"),
    ],
)
def test_rootfs_profile_rejects_invalid_ssh_options(option: str, value: str) -> None:
    with pytest.raises(ValidationError):
        RootfsProfile(
            name="minimal",
            source="/var/lib/linux-debug/rootfs.qcow2",
            ssh_host="127.0.0.1",
            ssh_user="root",
            ssh_options={option: value},
        )


@pytest.mark.parametrize("cleanup_policy", ["preserve_all", "preserve_failed", "stop_failed", "remove_temporary"])
def test_sprint_2_target_profile_rejects_old_cleanup_policy_values(cleanup_policy: str) -> None:
    with pytest.raises(ValidationError):
        TargetProfile(
            name="local-qemu",
            architecture="x86_64",
            provider_name="local-libvirt-qemu",
            cleanup_policy=cleanup_policy,
        )


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


def test_build_profile_defaults_for_local_kernel_build() -> None:
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")

    assert profile.provider_name == "local-kernel-build"
    assert profile.output_policy == "per_run"
    assert profile.targets == ["bzImage"]
    assert profile.command_timeout_seconds == 3600
    assert profile.required_tools == []
    assert profile.effective_required_tools() == ["make"]
    assert profile.jobs is None
    assert profile.make_variables == {}
    assert profile.config_lines == []


def test_build_profile_effective_required_tools_includes_make_once() -> None:
    profile = BuildProfile(
        name="clang",
        architecture="x86_64",
        required_tools=["clang", "make", "clang", "llvm-ar"],
    )

    assert profile.effective_required_tools() == ["make", "clang", "clang", "llvm-ar"]


@pytest.mark.parametrize("key", ["O", "ARCH", "KBUILD_OUTPUT", "bad-key", "1BAD", "CC PATH"])
def test_build_profile_rejects_reserved_or_invalid_make_variable_names(key: str) -> None:
    with pytest.raises(ValidationError):
        BuildProfile(name="bad", architecture="x86_64", make_variables={key: "1"})


@pytest.mark.parametrize("value", ["bad\0value", "bad\nvalue", "bad\tvalue", "bad\x7fvalue", "bad\x85value"])
def test_build_profile_rejects_control_characters_in_make_variable_values(value: str) -> None:
    with pytest.raises(ValidationError):
        BuildProfile(name="bad", architecture="x86_64", make_variables={"LLVM": value})


def test_build_profile_rejects_invalid_jobs() -> None:
    with pytest.raises(ValidationError):
        BuildProfile(name="bad", architecture="x86_64", jobs=0)


@pytest.mark.parametrize("target", ["", "O=/tmp/out", "ARCH=arm64", "--eval=$(shell id)", "-f", "bad target"])
def test_build_profile_rejects_targets_that_can_change_make_policy(target: str) -> None:
    with pytest.raises(ValidationError):
        BuildProfile(name="bad", architecture="x86_64", targets=[target])
