import pytest

from linux_debug_mcp.config import (
    BootOverrides,
    BuildOverrides,
    TargetProfile,
    merge_kernel_args,
)


def test_kernel_args_accepts_safe_tokens():
    overrides = BootOverrides(kernel_args=["dhash_entries=1", "nokaslr", "console=ttyS0,115200"])
    assert overrides.kernel_args == ["dhash_entries=1", "nokaslr", "console=ttyS0,115200"]


@pytest.mark.parametrize(
    "token",
    ["foo; rm -rf /", "a b", "x=$(id)", 'quote="bad"', "tab\tval", "pipe|x"],
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


def test_merge_kernel_args_dedups_by_key():
    base = ["console=ttyS0", "nokaslr", "dhash_entries=2"]
    override = ["dhash_entries=1", "quiet"]
    assert merge_kernel_args(base, override) == ["console=ttyS0", "nokaslr", "dhash_entries=1", "quiet"]


def test_merge_kernel_args_dedups_bare_flag():
    assert merge_kernel_args(["nokaslr", "ro"], ["nokaslr"]) == ["ro", "nokaslr"]
