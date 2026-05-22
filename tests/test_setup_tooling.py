import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_justfile_defines_setup_workflow() -> None:
    justfile = (ROOT / "justfile").read_text(encoding="utf-8")

    for target in ["setup:", "check-uv:", "sync-dev:", "check-host:", "install-hooks:", "lint:", "test:"]:
        assert target in justfile

    assert "uv --version" in justfile
    assert "uv venv --allow-existing" in justfile
    assert "uv pip install -e '.[dev,test]'" in justfile
    assert "uv run pre-commit install" in justfile
    assert "host.check_prerequisites" in justfile


def test_pre_commit_config_installs_python_quality_and_secret_hooks() -> None:
    config = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")

    assert "astral-sh/ruff-pre-commit" in config
    assert "ruff-format" in config
    assert "detect-secrets" in config
    assert "pre-commit/pre-commit-hooks" in config


def test_pyproject_exposes_dev_tooling_extra() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "dev = [" in pyproject
    assert '"pre-commit' in pyproject
    assert '"ruff' in pyproject
    assert '"detect-secrets' in pyproject


def test_readme_documents_setup_target() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "just setup" in readme


def test_justfile_parses_when_just_is_available() -> None:
    if shutil.which("just") is None:
        return

    completed = subprocess.run(
        ["just", "--list"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "setup" in completed.stdout
