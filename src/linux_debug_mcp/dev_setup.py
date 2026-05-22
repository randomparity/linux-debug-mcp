from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from linux_debug_mcp.server import prerequisites_handler

USAGE = "Usage: python -m linux_debug_mcp.dev_setup check-host"


def format_prerequisite_checks(checks: list[dict[str, Any]]) -> list[str]:
    return [f"{check['status']:7} {check['check_id']}: {check['message']}" for check in checks]


def check_host() -> int:
    response = prerequisites_handler(
        artifact_root=Path(".linux-debug-mcp"),
        source_path=None,
        enable_libvirt_check=False,
    )
    checks = response.data["checks"]
    failed = [check for check in checks if check["status"] == "failed"]
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
