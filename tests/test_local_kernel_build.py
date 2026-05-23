import json
from pathlib import Path

import pytest

from linux_debug_mcp.config import BuildProfile
from linux_debug_mcp.domain import ErrorCategory
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


class FakeRunner:
    def __init__(self, *, tools: dict[str, str] | None = None, returncode: int = 0, output: str = "") -> None:
        self.tools = {"make": "/usr/bin/make"} if tools is None else tools
        self.returncode = returncode
        self.output = output
        self.commands: list[list[str]] = []

    def which(self, command: str) -> str | None:
        return self.tools.get(command)

    def run(self, argv: list[str], *, timeout: int, log_path: Path) -> int:
        self.commands.append(argv)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(self.output, encoding="utf-8")
        return self.returncode


def test_prepare_config_seeds_source_config_when_output_config_missing(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")

    provider = LocalKernelBuildProvider()
    config_path = provider.prepare_config(source_path=source, output_path=output)

    assert config_path == output / ".config"
    assert config_path.read_text(encoding="utf-8") == "CONFIG_TEST=y\n"


def test_prepare_config_uses_existing_output_config_without_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)
    (source / ".config").write_text("CONFIG_SOURCE=y\n", encoding="utf-8")
    (output / ".config").write_text("CONFIG_OUTPUT=y\n", encoding="utf-8")

    provider = LocalKernelBuildProvider()
    config_path = provider.prepare_config(source_path=source, output_path=output)

    assert config_path.read_text(encoding="utf-8") == "CONFIG_OUTPUT=y\n"


def test_prepare_config_fails_without_developer_config(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)

    provider = LocalKernelBuildProvider()

    with pytest.raises(ValueError, match="missing developer-prepared .config"):
        provider.prepare_config(source_path=source, output_path=output)


def test_execute_success_records_artifacts_and_summary(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    logs = tmp_path / "runs" / "run-1" / "logs"
    summaries = tmp_path / "runs" / "run-1" / "summaries"
    source.mkdir()
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    (output / "arch" / "x86" / "boot").mkdir(parents=True)
    (output / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    (output / "vmlinux").write_text("symbols", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=FakeRunner(output="ok\n"))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan, log_path=logs / "build.log", summary_path=summaries / "build-summary.json"
    )

    assert result.status == "succeeded"
    assert {artifact.kind for artifact in result.artifacts} == {
        "build-log",
        "kernel-config",
        "kernel-image",
        "vmlinux",
        "build-summary",
    }
    summary = json.loads((summaries / "build-summary.json").read_text(encoding="utf-8"))
    assert any(artifact["kind"] == "build-summary" for artifact in summary["artifacts"])
    assert (summaries / "build-summary.json").exists()


def test_execute_missing_required_tool_returns_missing_dependency(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider(runner=FakeRunner(tools={}))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64", required_tools=[])
    plan = provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)

    result = provider.execute_build(plan=plan, log_path=tmp_path / "build.log", summary_path=tmp_path / "summary.json")

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.MISSING_DEPENDENCY


def test_execute_rejects_required_artifact_directory(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "build"
    bzimage = output / "arch" / "x86" / "boot" / "bzImage"
    source.mkdir()
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    bzimage.mkdir(parents=True)
    provider = LocalKernelBuildProvider(runner=FakeRunner(output="ok\n"))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(plan=plan, log_path=tmp_path / "build.log", summary_path=tmp_path / "summary.json")

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.BUILD_FAILURE
    assert str(bzimage) in result.details["missing_artifacts"]


def test_execute_summary_write_failure_returns_infrastructure_failure(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "build"
    summary_parent = tmp_path / "summary-parent"
    source.mkdir()
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    (output / "arch" / "x86" / "boot").mkdir(parents=True)
    (output / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    summary_parent.write_text("not a directory", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=FakeRunner(output="ok\n"))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=tmp_path / "build.log",
        summary_path=summary_parent / "build-summary.json",
    )

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.INFRASTRUCTURE_FAILURE


def test_execute_checks_profile_required_tools(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider(runner=FakeRunner(tools={"make": "/usr/bin/make"}))
    profile = BuildProfile(name="clang", architecture="x86_64", required_tools=["clang"])
    plan = provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)

    result = provider.execute_build(plan=plan, log_path=tmp_path / "build.log", summary_path=tmp_path / "summary.json")

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.MISSING_DEPENDENCY
    assert result.details["missing_tools"] == ["clang"]


def test_execute_nonzero_make_returns_build_failure_with_redacted_tail(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "build"
    source.mkdir()
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=FakeRunner(returncode=2, output="token=secret\nfailed\n"))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(plan=plan, log_path=tmp_path / "build.log", summary_path=tmp_path / "summary.json")

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.BUILD_FAILURE
    assert "token=[REDACTED]" in result.diagnostic
