import pytest

from linux_debug_mcp.config import (
    BootOverrides,
    BuildOverrides,
    BuildProfile,
    RootfsOverrides,
    TargetProfile,
    merge_config_lines,
    merge_kernel_args,
    validate_config_line_tokens,
)
from linux_debug_mcp.safety.redaction import Redactor


def test_kernel_args_accepts_safe_tokens():
    overrides = BootOverrides(kernel_args=["dhash_entries=1", "nokaslr", "console=ttyS0,115200"])
    assert overrides.kernel_args == ["dhash_entries=1", "nokaslr", "console=ttyS0,115200"]


@pytest.mark.parametrize(
    "token",
    [
        "mem=512M",
        "foo=a+b",
        "bar=50%",
        "init=/sbin/init@2",
        'foo="bar baz"',
        'console="ttyS0,115200n8"',
        'cmd="a b c"',
        'empty=""',
    ],
)
def test_kernel_args_accepts_extended_and_quoted_tokens(token):
    overrides = BootOverrides(kernel_args=[token])
    assert overrides.kernel_args == [token]


@pytest.mark.parametrize(
    "token",
    [
        "foo; rm -rf /",
        "a b",
        "x=$(id)",
        "tab\tval",
        "pipe|x",
        "nokaslr\n",
        "console=ttyS0\r",
        # Quote-based injection attempts must stay rejected:
        'foo="bar" evil=1',  # content after the closing quote
        'foo="a"b"c"',  # multiple quote pairs
        'foo="bar',  # unbalanced quote
        'foo=bar"baz"',  # quote not introduced by ="
        'foo="bar\nbaz"',  # C0 control character inside quotes
        'foo="bar\x85baz"',  # C1 control character inside quotes
        'foo="café"',  # non-ASCII inside quotes
        '"foo bar"',  # whole-arg quote without a key
    ],
)
def test_kernel_args_rejects_unsafe_tokens(token):
    with pytest.raises(ValueError):
        BootOverrides(kernel_args=[token])


def test_kernel_args_rejects_duplicate_keys_in_same_list():
    with pytest.raises(ValueError, match="duplicate kernel argument key"):
        BootOverrides(kernel_args=["dhash_entries=1", "dhash_entries=2"])


def test_target_profile_kernel_args_validated():
    with pytest.raises(ValueError):
        TargetProfile(name="t", architecture="x86_64", kernel_args=["bad;arg"])


def test_build_overrides_make_variables_reuse_existing_rules():
    BuildOverrides(make_variables={"CC": "clang"})
    with pytest.raises(ValueError):
        BuildOverrides(make_variables={"O": "x"})  # reserved, provider-owned


def test_make_variable_name_rejects_trailing_newline():
    with pytest.raises(ValueError):
        BuildOverrides(make_variables={"CC\n": "clang"})


def test_merge_kernel_args_dedups_by_key():
    base = ["console=ttyS0", "nokaslr", "dhash_entries=2"]
    override = ["dhash_entries=1", "quiet"]
    assert merge_kernel_args(base, override) == ["console=ttyS0", "nokaslr", "dhash_entries=1", "quiet"]


def test_merge_kernel_args_dedups_bare_flag():
    assert merge_kernel_args(["nokaslr", "ro"], ["nokaslr"]) == ["ro", "nokaslr"]


def test_merge_kernel_args_dedups_quoted_value_by_key():
    base = ["console=ttyS0", "foo=old"]
    override = ['foo="new value"']
    assert merge_kernel_args(base, override) == ["console=ttyS0", 'foo="new value"']


def test_rootfs_overrides_accepts_supported_fields():
    overrides = RootfsOverrides(
        mutability="mutable",
        access_method="ssh_and_serial",
        readiness_marker="ready-marker",
        ssh_host="10.0.0.5",
        ssh_port=2222,
        ssh_user="debugger",
        ssh_key_ref="vault://key",
        ssh_options={"StrictHostKeyChecking": "yes"},
    )
    update = overrides.as_profile_update()
    assert update["mutability"] == "mutable"
    assert update["ssh_port"] == 2222
    assert update["ssh_options"] == {"StrictHostKeyChecking": "yes"}


def test_rootfs_overrides_as_update_excludes_unset_fields():
    overrides = RootfsOverrides(ssh_user="debugger")
    assert overrides.as_profile_update() == {"ssh_user": "debugger"}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ssh_port": 0},
        {"ssh_port": 70000},
        {"ssh_user": "bad\nuser"},
        {"ssh_user": ""},
        {"readiness_marker": "marker\nbad"},
        {"ssh_options": {"UnknownOption": "x"}},
        {"ssh_options": {"StrictHostKeyChecking": "maybe"}},
        {"ssh_options": {"ConnectTimeout": "0"}},
        {"mutability": "wibble"},
        {"access_method": "telepathy"},
        # source/name are not overridable here: source must go through the path-safety-guarded
        # rootfs_source, and extra="forbid" rejects unknown keys, so rootfs_overrides cannot
        # bypass the guard.
        {"source": "/etc/shadow"},
        {"name": "evil"},
    ],
)
def test_rootfs_overrides_rejects_invalid_fields(kwargs):
    with pytest.raises(ValueError):
        RootfsOverrides(**kwargs)


def test_boot_overrides_has_rootfs_field_overrides():
    assert BootOverrides().has_rootfs_field_overrides() is False
    assert BootOverrides(rootfs=RootfsOverrides()).has_rootfs_field_overrides() is False
    assert BootOverrides(rootfs=RootfsOverrides(ssh_user="x")).has_rootfs_field_overrides() is True


def test_rootfs_overrides_are_redacted_by_registered_secret():
    overrides = BootOverrides(rootfs=RootfsOverrides(ssh_user="topsecretuser"))
    redacted = Redactor(secret_values=["topsecretuser"]).redact_value(overrides.model_dump(mode="json"))
    assert "topsecretuser" not in str(redacted)
    assert "[REDACTED]" in str(redacted)


@pytest.mark.parametrize(
    "line",
    [
        "CONFIG_DEBUG_INFO=y",
        "CONFIG_FOO=m",
        "# CONFIG_BAR is not set",
        "CONFIG_NR_CPUS=8",
        "CONFIG_DELAY=-1",
        "CONFIG_BASE=0x1000",
        'CONFIG_CMDLINE="console=ttyS0 nokaslr"',
    ],
)
def test_validate_config_line_accepts_valid_grammar(line: str) -> None:
    assert validate_config_line_tokens([line]) == [line]


@pytest.mark.parametrize(
    "line",
    [
        "CONFIG_FOO",  # no value
        "CONFIG_FOO=maybe",  # not y/m/n/int/hex/string
        "CONFIG_foo=y",  # lowercase symbol
        "CONFIG_FOO=y; rm -rf /",  # shell injection
        "rm -rf /",  # not a config line
        "# CONFIG_FOO is unset",  # wrong "is not set" phrasing
        'CONFIG_X="bad\nnewline"',  # embedded newline
        'CONFIG_X="bad\rcarriage"',  # embedded carriage return
        "CONFIG_FOO=y\nCONFIG_BAR=y",  # multi-line single token
        "CONFIG_FOO=y\n",  # trailing newline (must not slip past the anchor)
    ],
)
def test_validate_config_line_rejects_invalid_grammar(line: str) -> None:
    with pytest.raises(ValueError, match="invalid kernel config line"):
        validate_config_line_tokens([line])


def test_validate_config_line_rejects_duplicate_symbol() -> None:
    with pytest.raises(ValueError, match="duplicate kernel config symbol"):
        validate_config_line_tokens(["CONFIG_A=y", "CONFIG_A=n"])


def test_validate_config_line_rejects_duplicate_unset_symbol() -> None:
    with pytest.raises(ValueError, match="duplicate kernel config symbol"):
        validate_config_line_tokens(["CONFIG_A=y", "# CONFIG_A is not set"])


def test_merge_config_lines_last_wins_by_symbol() -> None:
    base = ["CONFIG_A=y", "CONFIG_B=m"]
    override = ["CONFIG_B=n", "CONFIG_C=y"]
    assert merge_config_lines(base, override) == ["CONFIG_A=y", "CONFIG_B=n", "CONFIG_C=y"]


def test_merge_config_lines_override_can_unset_base_symbol() -> None:
    base = ["CONFIG_A=y"]
    override = ["# CONFIG_A is not set"]
    assert merge_config_lines(base, override) == ["# CONFIG_A is not set"]


def test_merge_config_lines_empty_override_returns_base() -> None:
    base = ["CONFIG_A=y"]
    assert merge_config_lines(base, []) == ["CONFIG_A=y"]


def test_build_profile_has_config_lines_and_validates() -> None:
    profile = BuildProfile(name="x", architecture="x86_64", config_lines=["CONFIG_A=y"])
    assert profile.config_lines == ["CONFIG_A=y"]


def test_build_profile_rejects_invalid_config_line() -> None:
    with pytest.raises(ValueError, match="invalid kernel config line"):
        BuildProfile(name="x", architecture="x86_64", config_lines=["CONFIG_A=y; evil"])


def test_build_profile_no_longer_accepts_config_fragments() -> None:
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        BuildProfile(name="x", architecture="x86_64", config_fragments=["/tmp/frag"])


def test_build_overrides_config_lines_validated() -> None:
    overrides = BuildOverrides(config_lines=["# CONFIG_A is not set"])
    assert overrides.config_lines == ["# CONFIG_A is not set"]
    with pytest.raises(ValueError, match="invalid kernel config line"):
        BuildOverrides(config_lines=["not a config line"])
