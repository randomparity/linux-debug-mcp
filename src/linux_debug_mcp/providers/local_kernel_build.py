from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from linux_debug_mcp.config import BuildProfile


@dataclass(frozen=True)
class BuildPlan:
    argv: list[str]
    source_path: Path
    output_path: Path
    architecture: str
    targets: list[str]
    profile_name: str
    timeout_seconds: int
    required_tools: list[str]


class LocalKernelBuildProvider:
    name = "local-kernel-build"
    supported_architectures = ["x86_64"]

    def plan_build(self, *, source_path: Path, output_path: Path, profile: BuildProfile) -> BuildPlan:
        if profile.provider_name != self.name:
            raise ValueError(f"unsupported build provider: {profile.provider_name}")
        if profile.architecture not in self.supported_architectures:
            raise ValueError(f"unsupported architecture: {profile.architecture}")
        if profile.output_policy != "per_run":
            raise ValueError(f"unsupported output policy: {profile.output_policy}")
        if profile.config_fragments:
            raise ValueError("config fragments are not supported by the local Sprint 1 provider")
        argv = ["make", "-C", str(source_path), f"O={output_path}", "ARCH=x86_64"]
        if profile.jobs is not None:
            argv.append(f"-j{profile.jobs}")
        argv.extend(f"{key}={value}" for key, value in profile.make_variables.items())
        argv.extend(profile.targets)
        return BuildPlan(
            argv=argv,
            source_path=source_path,
            output_path=output_path,
            architecture=profile.architecture,
            targets=list(profile.targets),
            profile_name=profile.name,
            timeout_seconds=profile.command_timeout_seconds,
            required_tools=profile.effective_required_tools(),
        )
