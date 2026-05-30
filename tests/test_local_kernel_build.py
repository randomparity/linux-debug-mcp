import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from conftest import add_merge_config_script

from linux_debug_mcp.config import BuildProfile
from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.providers.local_kernel_build import (
    BuildIdMissing,
    ConfigGenerationError,
    LocalKernelBuildProvider,
    MissingConfigError,
    ReadelfUnavailable,
    _default_job_count,
    _extract_build_id,
)

# Task 4 R2-F6: the build success path now calls `_extract_build_id` against
# vmlinux. Tests in this file that exercise provider.execute_build produce
# fake vmlinux text files via FakeRunner, so the real readelf invocation
# would fail. The autouse fixture in tests/conftest.py default-stubs
# `_extract_build_id` to a constant. The direct-call `test_extract_build_id_*`
# tests below capture the original function reference at module-load time
# (before the fixture runs) and patch `subprocess.run` deeper to exercise
# the real `_extract_build_id` body.


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

    with patch("linux_debug_mcp.providers.local_kernel_build._default_job_count", return_value=4):
        plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    assert plan.argv == [
        "make",
        "-C",
        str(source),
        f"O={output}",
        "ARCH=x86_64",
        "-j4",
        "LLVM=1",
        "CC=clang",
        "bzImage",
        "modules",
    ]


def test_plan_build_defaults_jobs_to_half_cpus_when_unset(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")

    with patch("linux_debug_mcp.providers.local_kernel_build._default_job_count", return_value=24):
        plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    assert plan.argv == ["make", "-C", str(source), f"O={output}", "ARCH=x86_64", "-j24", "bzImage"]


def test_plan_build_explicit_jobs_overrides_the_default(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="x86_64-default", architecture="x86_64", jobs=3)

    with patch("linux_debug_mcp.providers.local_kernel_build._default_job_count", return_value=24):
        plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    assert "-j3" in plan.argv
    assert "-j24" not in plan.argv


@pytest.mark.parametrize(
    ("usable", "expected"),
    [(48, 24), (47, 24), (3, 2), (2, 1), (1, 1)],
)
def test_default_job_count_is_at_least_half_of_usable_cpus(usable: int, expected: int) -> None:
    with patch(
        "linux_debug_mcp.providers.local_kernel_build.os.sched_getaffinity",
        return_value=set(range(usable)),
    ):
        assert _default_job_count() == expected


def test_default_job_count_falls_back_to_cpu_count_without_affinity() -> None:
    with (
        patch(
            "linux_debug_mcp.providers.local_kernel_build.os.sched_getaffinity",
            side_effect=AttributeError,
        ),
        patch("linux_debug_mcp.providers.local_kernel_build.os.cpu_count", return_value=8),
    ):
        assert _default_job_count() == 4


def test_plan_build_carries_base_config(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="debug", architecture="x86_64", base_config=["defconfig", "kvm_guest.config"])

    plan = provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)

    assert plan.base_config == ["defconfig", "kvm_guest.config"]


def test_plan_build_base_config_defaults_empty(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")

    plan = provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)

    assert plan.base_config == []


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


def test_plan_build_threads_config_lines_into_plan(tmp_path: Path) -> None:
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(
        name="frag",
        architecture="x86_64",
        config_lines=["CONFIG_DEBUG_INFO=y"],
    )

    plan = provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)

    assert plan.config_lines == ["CONFIG_DEBUG_INFO=y"]
    assert not any("CONFIG_DEBUG_INFO" in arg for arg in plan.argv)


class FakeRunner:
    def __init__(
        self,
        *,
        tools: dict[str, str] | None = None,
        returncode: int = 0,
        returncodes: list[int] | None = None,
        output: str = "",
    ) -> None:
        self.tools = {"make": "/usr/bin/make"} if tools is None else tools
        self.returncode = returncode
        self.returncodes = returncodes
        self.output = output
        self.commands: list[list[str]] = []
        self.environments: list[dict[str, str]] = []
        self.cwds: list[Path | None] = []

    def which(self, command: str) -> str | None:
        return self.tools.get(command)

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        self.commands.append(argv)
        self.environments.append(env)
        self.cwds.append(cwd)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(self.output, encoding="utf-8")
        if self.returncodes is not None:
            index = min(len(self.commands) - 1, len(self.returncodes) - 1)
            return self.returncodes[index]
        return self.returncode


def test_plan_build_sanitizes_host_make_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    monkeypatch.setenv("MAKEFLAGS", "-j128 --keep-going")
    monkeypatch.setenv("MFLAGS", "-j128")
    monkeypatch.setenv("GNUMAKEFLAGS", "--warn-undefined-variables")
    monkeypatch.setenv("KCFLAGS", "-Werror")
    monkeypatch.setenv("KBUILD_OUTPUT", "/tmp/hidden-output")
    provider = LocalKernelBuildProvider()
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")

    plan = provider.plan_build(source_path=tmp_path / "linux", output_path=tmp_path / "build", profile=profile)

    assert "PATH" in plan.environment
    assert "MAKEFLAGS" not in plan.environment
    assert "MFLAGS" not in plan.environment
    assert "GNUMAKEFLAGS" not in plan.environment
    assert "KCFLAGS" not in plan.environment
    assert "KBUILD_OUTPUT" not in plan.environment


class ConfigGeneratingRunner(FakeRunner):
    """FakeRunner that writes ``<output>/.config`` when one of ``creates`` (matched on the make
    target — the last argv token) runs successfully, modelling ``make defconfig`` seeding a config."""

    def __init__(self, *, output_path: Path, creates: set[str] | None = None, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.output_path = output_path
        self.creates = creates if creates is not None else {"defconfig"}

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        returncode = super().run(argv, timeout=timeout, log_path=log_path, env=env, cwd=cwd)
        if returncode == 0 and argv and argv[-1] in self.creates:
            self.output_path.mkdir(parents=True, exist_ok=True)
            (self.output_path / ".config").write_text("CONFIG_GENERATED=y\n", encoding="utf-8")
        return returncode


def _config_plan(provider: LocalKernelBuildProvider, source: Path, output: Path, **profile_kwargs: object):
    profile = BuildProfile(name="cfg", architecture="x86_64", **profile_kwargs)  # type: ignore[arg-type]
    return provider.plan_build(source_path=source, output_path=output, profile=profile)


def test_prepare_config_uses_existing_output_config_without_regenerating(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)
    (source / ".config").write_text("CONFIG_SOURCE=y\n", encoding="utf-8")
    (output / ".config").write_text("CONFIG_OUTPUT=y\n", encoding="utf-8")
    runner = FakeRunner()
    provider = LocalKernelBuildProvider(runner=runner)
    plan = _config_plan(provider, source, output, base_config=["defconfig"])

    config_path = provider.prepare_config(plan=plan, log_dir=tmp_path / "logs")

    assert config_path.read_text(encoding="utf-8") == "CONFIG_OUTPUT=y\n"
    assert runner.commands == []


def test_prepare_config_prefers_source_config_over_base_config(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    runner = FakeRunner()
    provider = LocalKernelBuildProvider(runner=runner)
    plan = _config_plan(provider, source, output, base_config=["defconfig"])

    config_path = provider.prepare_config(plan=plan, log_dir=tmp_path / "logs")

    assert config_path == output / ".config"
    assert config_path.read_text(encoding="utf-8") == "CONFIG_TEST=y\n"
    assert runner.commands == []


def test_prepare_config_generates_from_base_config(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)
    runner = ConfigGeneratingRunner(output_path=output, output="ok\n")
    provider = LocalKernelBuildProvider(runner=runner)
    plan = _config_plan(provider, source, output, base_config=["defconfig"])

    config_path = provider.prepare_config(plan=plan, log_dir=tmp_path / "logs")

    assert config_path == output / ".config"
    assert runner.commands == [["make", "-C", str(source), f"O={output}", "ARCH=x86_64", "defconfig"]]


def test_prepare_config_runs_base_config_targets_in_order(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)
    runner = ConfigGeneratingRunner(output_path=output, creates={"kvm_guest.config"}, output="ok\n")
    provider = LocalKernelBuildProvider(runner=runner)
    plan = _config_plan(provider, source, output, base_config=["defconfig", "kvm_guest.config"])

    provider.prepare_config(plan=plan, log_dir=tmp_path / "logs")

    assert [command[-1] for command in runner.commands] == ["defconfig", "kvm_guest.config"]


def test_prepare_config_raises_when_base_config_produces_no_config(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)
    runner = FakeRunner(output="ok\n")  # returns 0 but never writes .config
    provider = LocalKernelBuildProvider(runner=runner)
    plan = _config_plan(provider, source, output, base_config=["defconfig"])

    with pytest.raises(ConfigGenerationError, match="produced no .config"):
        provider.prepare_config(plan=plan, log_dir=tmp_path / "logs")


def test_prepare_config_raises_on_base_config_nonzero_exit(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)
    runner = FakeRunner(returncode=2, output="token=secret\ndefconfig boom\n")
    provider = LocalKernelBuildProvider(runner=runner)
    plan = _config_plan(provider, source, output, base_config=["defconfig"])

    with pytest.raises(ConfigGenerationError) as excinfo:
        provider.prepare_config(plan=plan, log_dir=tmp_path / "logs")

    assert "token=[REDACTED]" in (excinfo.value.diagnostic or "")
    assert excinfo.value.log_path is not None
    assert excinfo.value.log_path.name == "config-base-00-defconfig.log"


def test_prepare_config_missing_config_without_base_config(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    source.mkdir()
    output.mkdir(parents=True)
    runner = FakeRunner()
    provider = LocalKernelBuildProvider(runner=runner)
    plan = _config_plan(provider, source, output)

    with pytest.raises(MissingConfigError) as excinfo:
        provider.prepare_config(plan=plan, log_dir=tmp_path / "logs")

    assert "base_config" in excinfo.value.suggested_fix
    assert runner.commands == []


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
    (output / "include" / "config").mkdir(parents=True)
    (output / "include" / "config" / "kernel.release").write_text("6.9.0-test\n", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=FakeRunner(output="ok\n"))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan, log_path=logs / "build.log", summary_path=summaries / "build-summary.json"
    )

    assert result.status == "succeeded"
    assert result.details["kernel_release"] == "6.9.0-test"
    assert {artifact.kind for artifact in result.artifacts} == {
        "build-log",
        "kernel-config",
        "kernel-image",
        "vmlinux",
        "build-summary",
    }
    summary = json.loads((summaries / "build-summary.json").read_text(encoding="utf-8"))
    assert any(artifact["kind"] == "build-summary" for artifact in summary["artifacts"])
    assert summary["environment"] == {
        "mode": "sanitized",
        "passed_keys": sorted(plan.environment),
    }
    assert summary["kernel_release"] == "6.9.0-test"
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


def test_execute_early_infrastructure_failure_records_source_revision(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "build"
    log_parent = tmp_path / "log-parent"
    source.mkdir()
    log_parent.write_text("not a directory", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=FakeRunner(output="ok\n"))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=log_parent / "build.log",
        summary_path=tmp_path / "summary.json",
    )

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert result.details["source_revision"]["commit"] is None
    assert result.details["source_revision"]["dirty"] is None
    assert result.details["source_revision"]["reason"]


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


def test_execute_nonzero_summary_write_failure_returns_infrastructure_failure(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "build"
    summary_parent = tmp_path / "summary-parent"
    source.mkdir()
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    summary_parent.write_text("not a directory", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=FakeRunner(returncode=2, output="failed\n"))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=tmp_path / "build.log",
        summary_path=summary_parent / "build-summary.json",
    )

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.INFRASTRUCTURE_FAILURE


def test_log_tail_reads_recent_suffix_and_redacts(tmp_path: Path) -> None:
    log_path = tmp_path / "build.log"
    log_path.write_text("a" * 5000 + " token=secret\n", encoding="utf-8")
    provider = LocalKernelBuildProvider()

    tail = provider._log_tail(log_path, limit=32)

    assert tail is not None
    assert len(tail) <= 64
    assert "token=[REDACTED]" in tail


def test_source_revision_for_non_git_tree_records_unknown_reason(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    provider = LocalKernelBuildProvider()

    revision = provider.detect_source_revision(source)

    assert revision["commit"] is None
    assert revision["dirty"] is None
    assert revision["reason"]


def test_source_revision_for_git_tree_records_commit_and_dirty_state(tmp_path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    source = tmp_path / "linux"
    source.mkdir()
    subprocess.run(["git", "init"], cwd=source, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=source, check=True)
    (source / "README").write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "add", "README"], cwd=source, check=True)
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "commit", "-m", "initial"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
    )
    expected_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    (source / "dirty").write_text("untracked\n", encoding="utf-8")
    provider = LocalKernelBuildProvider()

    revision = provider.detect_source_revision(source)

    assert revision == {"commit": expected_commit, "dirty": True, "reason": None}


def _make_run_dir(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "linux"
    add_merge_config_script(source)
    (source / ".config").write_text("CONFIG_BASE=y\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "run-1"
    output = run_dir / "build"
    (output / "arch" / "x86" / "boot").mkdir(parents=True)
    (output / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    return source, output


def test_execute_applies_config_lines_before_main_make(tmp_path: Path) -> None:
    source, output = _make_run_dir(tmp_path)
    runner = FakeRunner(output="ok\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(
        name="frag", architecture="x86_64", config_lines=["CONFIG_DEBUG_INFO=y", "# CONFIG_FOO is not set"]
    )
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "succeeded"
    # Three runner calls in order: merge_config.sh, olddefconfig, main make.
    assert runner.commands[0] == [
        str(source / "scripts" / "kconfig" / "merge_config.sh"),
        "-m",
        "-O",
        str(output),
        str(output / ".config"),
        str(output.parent / "inputs" / "override.config"),
    ]
    assert runner.commands[1] == ["make", "-C", str(source), f"O={output}", "ARCH=x86_64", "olddefconfig"]
    assert runner.commands[2] == plan.argv
    assert runner.cwds[0] == output
    override = (output.parent / "inputs" / "override.config").read_text(encoding="utf-8")
    assert override == "CONFIG_DEBUG_INFO=y\n# CONFIG_FOO is not set\n"


def test_execute_without_config_lines_runs_only_main_make(tmp_path: Path) -> None:
    source, output = _make_run_dir(tmp_path)
    runner = FakeRunner(output="ok\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "succeeded"
    assert runner.commands == [plan.argv]
    assert not (output.parent / "inputs" / "override.config").exists()


def test_execute_config_merge_nonzero_returns_configuration_error(tmp_path: Path) -> None:
    source, output = _make_run_dir(tmp_path)
    runner = FakeRunner(returncode=1, output="token=secret\nmerge boom\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(name="frag", architecture="x86_64", config_lines=["CONFIG_DEBUG_INFO=y"])
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.CONFIGURATION_ERROR
    assert "config merge failed" in result.summary
    assert "token=[REDACTED]" in result.diagnostic


def test_execute_olddefconfig_nonzero_returns_configuration_error(tmp_path: Path) -> None:
    source, output = _make_run_dir(tmp_path)
    runner = FakeRunner(returncodes=[0, 2], output="token=secret\nolddefconfig boom\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(name="frag", architecture="x86_64", config_lines=["CONFIG_DEBUG_INFO=y"])
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.CONFIGURATION_ERROR
    assert "olddefconfig failed" in result.summary
    assert "token=[REDACTED]" in result.diagnostic
    # merge_config.sh then olddefconfig ran; the main make never started
    assert len(runner.commands) == 2


def test_execute_generates_base_config_before_main_make(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    output = tmp_path / "runs" / "run-1" / "build"
    (output / "arch" / "x86" / "boot").mkdir(parents=True)
    (output / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    runner = ConfigGeneratingRunner(output_path=output, output="ok\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(name="x86_64-default", architecture="x86_64", base_config=["defconfig"])
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "succeeded"
    # No config_lines on this profile: generation (defconfig) then the main make, nothing between.
    assert [command[-1] for command in runner.commands] == ["defconfig", "bzImage"]


def test_execute_base_config_then_config_lines_then_main_make(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    add_merge_config_script(source)
    output = tmp_path / "runs" / "run-1" / "build"
    (output / "arch" / "x86" / "boot").mkdir(parents=True)
    (output / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    runner = ConfigGeneratingRunner(output_path=output, output="ok\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(
        name="x86_64-debug",
        architecture="x86_64",
        base_config=["defconfig"],
        config_lines=["CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y"],
    )
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "succeeded"
    assert runner.commands[0][-1] == "defconfig"
    assert runner.commands[1][0].endswith("merge_config.sh")
    assert runner.commands[2][-1] == "olddefconfig"
    assert runner.commands[3][-1] == "bzImage"


def test_execute_base_config_nonzero_returns_configuration_error_with_log_artifact(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    output = tmp_path / "runs" / "run-1" / "build"
    output.mkdir(parents=True)
    runner = FakeRunner(returncode=2, output="token=secret\ndefconfig boom\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(name="x86_64-default", architecture="x86_64", base_config=["defconfig"])
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.CONFIGURATION_ERROR
    assert "token=[REDACTED]" in (result.diagnostic or "")
    config_logs = [artifact for artifact in result.artifacts if artifact.kind == "config-log"]
    assert len(config_logs) == 1
    assert config_logs[0].path.endswith("config-base-00-defconfig.log")


def test_execute_without_config_or_base_config_returns_suggested_fix(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    output = tmp_path / "runs" / "run-1" / "build"
    output.mkdir(parents=True)
    runner = FakeRunner(output="ok\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(name="nobase", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.CONFIGURATION_ERROR
    assert "base_config" in result.details["suggested_fix"]
    assert runner.commands == []


def test_execute_config_lines_without_merge_script_fails(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / ".config").write_text("CONFIG_BASE=y\n", encoding="utf-8")
    output = tmp_path / "runs" / "run-1" / "build"
    (output / "arch" / "x86" / "boot").mkdir(parents=True)
    (output / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    runner = FakeRunner(output="ok\n")
    provider = LocalKernelBuildProvider(runner=runner)
    profile = BuildProfile(name="frag", architecture="x86_64", config_lines=["CONFIG_DEBUG_INFO=y"])
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    result = provider.execute_build(
        plan=plan,
        log_path=output.parent / "logs" / "build.log",
        summary_path=output.parent / "summaries" / "build-summary.json",
    )

    assert result.status == "failed"
    assert result.error_category == ErrorCategory.CONFIGURATION_ERROR
    assert "merge_config.sh not found" in result.summary


def test_execute_summary_records_source_revision(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    output = tmp_path / "runs" / "run-1" / "build"
    summaries = tmp_path / "runs" / "run-1" / "summaries"
    source.mkdir()
    (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    (output / "arch" / "x86" / "boot").mkdir(parents=True)
    (output / "arch" / "x86" / "boot" / "bzImage").write_text("kernel", encoding="utf-8")
    provider = LocalKernelBuildProvider(runner=FakeRunner(output="ok\n"))
    profile = BuildProfile(name="x86_64-default", architecture="x86_64")
    plan = provider.plan_build(source_path=source, output_path=output, profile=profile)

    provider.execute_build(
        plan=plan,
        log_path=tmp_path / "runs" / "run-1" / "logs" / "build.log",
        summary_path=summaries / "build-summary.json",
    )

    summary = json.loads((summaries / "build-summary.json").read_text(encoding="utf-8"))
    assert summary["source_revision"]["commit"] is None
    assert summary["source_revision"]["dirty"] is None
    assert summary["source_revision"]["reason"]


def test_extract_build_id_returns_hex_on_success(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"")
    fake = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=(
            "    Owner          Data size  Description\n"
            "    GNU            0x14       NT_GNU_BUILD_ID (unique build ID bitstring)\n"
            "    Build ID: 0123456789abcdef0123456789abcdef01234567\n"  # pragma: allowlist secret
        ),
        stderr="",
    )
    with patch(
        "linux_debug_mcp.providers.local_kernel_build.subprocess.run",
        return_value=fake,
    ):
        assert _extract_build_id(vmlinux) == "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


def test_extract_build_id_raises_readelf_unavailable_on_missing_binary(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"")
    with (
        patch(
            "linux_debug_mcp.providers.local_kernel_build.subprocess.run",
            side_effect=FileNotFoundError("readelf"),
        ),
        pytest.raises(ReadelfUnavailable),
    ):
        _extract_build_id(vmlinux)


def test_extract_build_id_raises_readelf_unavailable_on_nonzero_exit(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"")
    fake = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error")
    with (
        patch(
            "linux_debug_mcp.providers.local_kernel_build.subprocess.run",
            return_value=fake,
        ),
        pytest.raises(ReadelfUnavailable),
    ):
        _extract_build_id(vmlinux)


def test_extract_build_id_raises_readelf_unavailable_on_timeout(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"")
    with (
        patch(
            "linux_debug_mcp.providers.local_kernel_build.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["readelf"], timeout=10),
        ),
        pytest.raises(ReadelfUnavailable),
    ):
        _extract_build_id(vmlinux)


def test_extract_build_id_raises_build_id_missing_when_no_note(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"")
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout="no notes here\n", stderr="")
    with (
        patch(
            "linux_debug_mcp.providers.local_kernel_build.subprocess.run",
            return_value=fake,
        ),
        pytest.raises(BuildIdMissing),
    ):
        _extract_build_id(vmlinux)
