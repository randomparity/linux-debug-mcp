from pathlib import Path

import pytest
from pydantic import ValidationError

from linux_debug_mcp.config import (
    ALLOWED_DEBUG_OPERATIONS,
    INTROSPECT_DESTRUCTIVE_PERMISSIONS,
    MAX_INTROSPECT_CALLS_PER_RUN,
    PRELUDE_WARNING_FRACTION_PCT,
    ArtifactPolicy,
    BootOverrides,
    BuildOverrides,
    BuildProfile,
    DebugProfile,
    RootfsProfile,
    ServerConfig,
    TargetProfile,
    TestCommand,
    TestSuiteProfile,
    missing_destructive_permissions,
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
        "debug.step",
        "debug.next",
        "debug.finish",
        "debug.backtrace",
        "debug.list_variables",
        "debug.set_watchpoint",
        "debug.clear_watchpoint",
        "debug.read_registers",
        "debug.read_symbol",
        "debug.read_memory",
        "debug.evaluate",
        "debug.load_module_symbols",
        "debug.end_session",
        "transport.inject_break",
        "debug.introspect.run",
        "debug.introspect.helper",
        "debug.introspect.from_vmcore",
        "debug.introspect.from_vmcore_helper",
        "debug.postmortem.crash",
        "debug.postmortem.triage",
        "debug.postmortem.check_prereqs",
        "debug.postmortem.list_dumps",
        "debug.postmortem.fetch",
        "debug.introspect.write",
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


def test_build_profile_base_config_defaults_empty() -> None:
    assert BuildProfile(name="x86_64-default", architecture="x86_64").base_config == []


def test_build_profile_accepts_ordered_base_config_targets() -> None:
    profile = BuildProfile(name="debug", architecture="x86_64", base_config=["defconfig", "kvm_guest.config"])

    assert profile.base_config == ["defconfig", "kvm_guest.config"]


@pytest.mark.parametrize("target", ["", "O=/tmp/out", "--eval=$(shell id)", "-j8", "bad target", "; rm -rf"])
def test_build_profile_rejects_invalid_base_config_target(target: str) -> None:
    with pytest.raises(ValidationError):
        BuildProfile(name="bad", architecture="x86_64", base_config=[target])


def test_build_overrides_base_config_defaults_empty() -> None:
    assert BuildOverrides().base_config == []


def test_build_overrides_accepts_ordered_base_config_targets() -> None:
    assert BuildOverrides(base_config=["tinyconfig"]).base_config == ["tinyconfig"]


@pytest.mark.parametrize("target", ["", "-f", "bad target", "ARCH=arm64"])
def test_build_overrides_rejects_invalid_base_config_target(target: str) -> None:
    with pytest.raises(ValidationError):
        BuildOverrides(base_config=[target])


def test_allowed_debug_operations_includes_introspect_run() -> None:
    assert "debug.introspect.run" in ALLOWED_DEBUG_OPERATIONS


def test_allowed_debug_operations_includes_introspect_write() -> None:
    assert "debug.introspect.write" in ALLOWED_DEBUG_OPERATIONS


def test_introspect_destructive_permissions_has_run_entry() -> None:
    assert INTROSPECT_DESTRUCTIVE_PERMISSIONS["debug.introspect.run"] == [
        "mutate live kernel state via drgn write APIs"
    ]


def test_missing_destructive_permissions_introspect_registry() -> None:
    required = INTROSPECT_DESTRUCTIVE_PERMISSIONS["debug.introspect.run"]
    assert (
        missing_destructive_permissions("debug.introspect.run", [], registry=INTROSPECT_DESTRUCTIVE_PERMISSIONS)
        == required
    )
    assert (
        missing_destructive_permissions("debug.introspect.run", required, registry=INTROSPECT_DESTRUCTIVE_PERMISSIONS)
        == []
    )
    assert (
        missing_destructive_permissions(
            "debug.introspect.run", [*required, "extra"], registry=INTROSPECT_DESTRUCTIVE_PERMISSIONS
        )
        == []
    )


def test_missing_destructive_permissions_defaults_to_transport_registry() -> None:
    assert missing_destructive_permissions("transport.inject_break", []) == ["drop target kernel into the debugger"]


def test_max_introspect_calls_per_run_default() -> None:
    assert MAX_INTROSPECT_CALLS_PER_RUN == 1000


def test_prelude_warning_fraction_pct_default() -> None:
    assert PRELUDE_WARNING_FRACTION_PCT == 40


def test_new_phase_c_debug_operations_are_allowed() -> None:
    for op in [
        "debug.step",
        "debug.next",
        "debug.finish",
        "debug.backtrace",
        "debug.list_variables",
        "debug.set_watchpoint",
        "debug.clear_watchpoint",
    ]:
        assert op in ALLOWED_DEBUG_OPERATIONS


def test_default_debug_profile_enables_new_ops() -> None:
    profile = DebugProfile(name="x")
    assert "debug.step" in profile.enabled_operations
    assert "debug.set_watchpoint" in profile.enabled_operations


def test_rootfs_profile_source_kind_defaults_to_local_path() -> None:
    from linux_debug_mcp.config import RootfsProfile

    profile = RootfsProfile(name="minimal", source="/img.qcow2")
    assert profile.source_kind == "local_path"


def test_rootfs_profile_accepts_each_source_kind() -> None:
    from linux_debug_mcp.config import RootfsProfile

    for kind in ("local_path", "builder", "prebuilt", "url"):
        profile = RootfsProfile(name="m", source="/img.qcow2", source_kind=kind)
        assert profile.source_kind == kind


def test_rootfs_profile_rejects_unknown_source_kind() -> None:
    import pytest
    from pydantic import ValidationError

    from linux_debug_mcp.config import RootfsProfile

    with pytest.raises(ValidationError):
        RootfsProfile(name="m", source="/img.qcow2", source_kind="nfs")


def test_target_profile_wait_for_debugger_defaults_false() -> None:
    profile = TargetProfile(name="t", architecture="x86_64")
    assert profile.wait_for_debugger is False


def test_target_profile_wait_for_debugger_requires_debug_gdbstub() -> None:
    with pytest.raises(ValidationError, match="wait_for_debugger requires debug_gdbstub"):
        TargetProfile(name="t", architecture="x86_64", wait_for_debugger=True)


def test_target_profile_wait_for_debugger_accepts_with_gdbstub() -> None:
    profile = TargetProfile(name="t", architecture="x86_64", debug_gdbstub=True, wait_for_debugger=True)
    assert profile.wait_for_debugger is True


def test_boot_overrides_wait_for_debugger_is_tristate() -> None:
    assert BootOverrides().wait_for_debugger is None
    assert BootOverrides(wait_for_debugger=True).wait_for_debugger is True
    assert BootOverrides(wait_for_debugger=False).wait_for_debugger is False
