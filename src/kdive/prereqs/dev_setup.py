from __future__ import annotations

import sys
from pathlib import Path

from kdive.domain import PrerequisiteCheck, PrerequisiteStatus
from kdive.prereqs.handlers import prerequisites_handler
from kdive.prereqs.tools import HostPrerequisitesHandlerRequest, HostPrerequisitesRuntime

USAGE = "Usage: python -m kdive.prereqs.dev_setup check-host"


def _parse_prerequisite_checks(raw_checks: list[object]) -> list[PrerequisiteCheck]:
    return [PrerequisiteCheck.model_validate(check) for check in raw_checks]


def format_prerequisite_checks(checks: list[PrerequisiteCheck]) -> list[str]:
    return [f"{check.status.value:7} {check.check_id}: {check.message}" for check in checks]


def check_host() -> int:
    response = prerequisites_handler(
        request=HostPrerequisitesHandlerRequest(
            artifact_root=Path(".kdive"),
            source_path=None,
            enable_libvirt_check=False,
            build_profile=None,
            target_profile=None,
            rootfs_profile=None,
        ),
        runtime=HostPrerequisitesRuntime(),
    )
    checks = _parse_prerequisite_checks(response.data["checks"])
    failed = [check for check in checks if check.status is PrerequisiteStatus.FAILED]
    for line in format_prerequisite_checks(checks):
        print(line)
    if failed:
        print()
        print("Host prerequisite checks failed. Install the missing OS-level tools and rerun `just setup`.")
        return 1
    return 0


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if args != ["check-host"]:
        print(USAGE, file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(check_host())


if __name__ == "__main__":
    main()
