set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    just --list

setup: check-uv sync-dev check-host install-hooks
    @echo "Development environment is ready."

check-uv:
    @if ! command -v uv >/dev/null 2>&1; then \
        echo "uv is required. Install it from https://docs.astral.sh/uv/getting-started/installation/"; \
        exit 1; \
    fi
    uv --version

sync-dev: check-uv
    uv venv --allow-existing
    uv pip install -e '.[dev,test]'

check-host: sync-dev
    @echo "Running host.check_prerequisites"
    uv run python -c 'from pathlib import Path; from linux_debug_mcp.server import prerequisites_handler; response = prerequisites_handler(artifact_root=Path(".linux-debug-mcp"), source_path=None, enable_libvirt_check=False); checks = response.data["checks"]; failed = [check for check in checks if check["status"] == "failed"]; [print(f"{check['\''status'\'']:7} {check['\''check_id'\'']}: {check['\''message'\'']}") for check in checks]; print("\nHost prerequisite checks failed. Install the missing OS-level tools and rerun `just setup`.") if failed else None; raise SystemExit(1 if failed else 0)'

install-hooks: sync-dev
    uv run detect-secrets scan > .secrets.baseline
    uv run pre-commit install
    uv run pre-commit run --all-files

lint: sync-dev
    uv run ruff check .
    uv run ruff format --check .

format: sync-dev
    uv run ruff check --fix .
    uv run ruff format .

test: sync-dev
    uv run python -m pytest
