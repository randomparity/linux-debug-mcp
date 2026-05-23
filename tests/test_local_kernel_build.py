from pathlib import Path

import pytest

from linux_debug_mcp.config import BuildProfile
from linux_debug_mcp.providers.local_kernel_build import LocalKernelBuildProvider


def test_plan_build_uses_per_run_output_and_argv_entries(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="x86_64-default", architecture="x86_64", jobs=8)

    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    assert plan.argv == ["make", "-C", str(source), f"O={output}", "ARCH=x86_64", "-j8", "bzImage"]
    assert plan.source_path == source
    assert plan.output_path == output
    assert plan.architecture == "x86_64"
    assert plan.targets == ["bzImage"]
    assert plan.timeout_seconds == 3600


def test_plan_build_appends_make_variables_after_provider_owned_args(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(
        name="clang",
        architecture="x86_64",
        targets=["bzImage", "modules"],
        make_variables={"LLVM": "1", "CC": "clang"},
    )

    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    assert plan.argv == [
        "make",
        "-C",
        str(source),
        f"O={output}",
        "ARCH=x86_64",
        "LLVM=1",
        "CC=clang",
        "bzImage",
        "modules",
    ]


def test_plan_build_rejects_unsupported_architecture(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="arm", architecture="arm64")

    with pytest.raises(ValueError, match="unsupported architecture"):
        provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)


def test_plan_build_rejects_unsupported_profile_policy(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="shared", architecture="x86_64", output_policy="shared")

    with pytest.raises(ValueError, match="unsupported output policy"):
        provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)


def test_plan_build_rejects_wrong_provider_name(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="remote", architecture="x86_64", provider_name="remote-kernel-build")

    with pytest.raises(ValueError, match="unsupported build provider"):
        provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)


def test_plan_build_rejects_config_fragments_until_supported(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(
        name="fragments",
        architecture="x86_64",
        config_fragments=[tmp_path / "debug.fragment"],
    )

    with pytest.raises(ValueError, match="config fragments are not supported"):
        provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)
