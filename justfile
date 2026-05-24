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
    uv run python -m linux_debug_mcp.dev_setup check-host

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

check-docs:
    ! rg -n "sprin[t]|Sprin[t]|SPRIN[T]" README.md docs
