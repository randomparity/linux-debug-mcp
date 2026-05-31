import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _fake_command(bin_dir: Path, name: str) -> None:
    path = bin_dir / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)


def test_justfile_defines_setup_workflow() -> None:
    justfile = (ROOT / "justfile").read_text(encoding="utf-8")

    for target in ["setup:", "check-deps:", "sync-dev:", "check-host:", "install-hooks:", "lint:", "test:"]:
        assert target in justfile

    assert "./scripts/check-setup-deps.sh" in justfile
    assert "uv --version" in justfile
    assert "uv venv --allow-existing" in justfile
    assert "uv pip install -e '.[dev,test]'" in justfile
    assert "uv run pre-commit install" in justfile
    assert "uv run python -m kdive.prereqs.dev_setup check-host" in justfile
    assert "detect-secrets scan > .secrets.baseline" not in justfile
    assert "python -c" not in justfile
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


def test_setup_dependency_check_accumulates_missing_fedora_packages(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for command in ["uv", "make", "bash", "git"]:
        _fake_command(fake_bin, command)
    os_release = tmp_path / "os-release"
    os_release.write_text("ID=fedora\n", encoding="utf-8")

    completed = subprocess.run(
        ["/bin/bash", "scripts/check-setup-deps.sh"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": str(fake_bin), "KDIVE_OS_RELEASE": str(os_release)},
    )

    assert completed.returncode == 1
    assert (
        "Missing setup dependencies: qemu-system-x86_64, virsh, gdb, crash, virt-builder, "
        "virt-tar-out, virt-make-fs, guestfish, qemu-img, gcc or clang"
    ) in completed.stderr
    assert "dnf install" in completed.stderr
    assert "qemu-system-x86" in completed.stderr
    assert "libvirt-client" in completed.stderr
    assert "libguestfs-tools" in completed.stderr
    assert "gcc" in completed.stderr
    assert completed.stderr.count("dnf install") == 1
    assert completed.stderr.count("libguestfs-tools") == 1


def test_setup_dependency_check_accepts_clang_as_c_compiler(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for command in [
        "uv",
        "make",
        "bash",
        "git",
        "qemu-system-x86_64",
        "virsh",
        "gdb",
        "crash",
        "virt-builder",
        "virt-tar-out",
        "virt-make-fs",
        "guestfish",
        "qemu-img",
        "clang",
    ]:
        _fake_command(fake_bin, command)

    completed = subprocess.run(
        ["/bin/bash", "scripts/check-setup-deps.sh"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": str(fake_bin), "KDIVE_OS_RELEASE": str(tmp_path / "missing-os-release")},
    )

    assert completed.returncode == 0
    assert "Setup dependencies are present." in completed.stdout


def test_dev_setup_formats_prerequisite_checks() -> None:
    from kdive.domain import PrerequisiteCheck, PrerequisiteStatus
    from kdive.prereqs.dev_setup import format_prerequisite_checks

    assert format_prerequisite_checks(
        [
            PrerequisiteCheck(status=PrerequisiteStatus.PASSED, check_id="python.version", message="Python 3.13"),
            PrerequisiteCheck(status=PrerequisiteStatus.FAILED, check_id="tool.gdb", message="gdb was not found"),
        ]
    ) == [
        "passed  python.version: Python 3.13",
        "failed  tool.gdb: gdb was not found",
    ]


def test_dev_setup_imports_prerequisites_from_prereq_package() -> None:
    import ast

    from kdive.prereqs import dev_setup

    tree = ast.parse(Path(dev_setup.__file__).read_text(encoding="utf-8"))
    imports = [
        (node.module, alias.name) for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) for alias in node.names
    ]
    assert ("kdive.server", "prerequisites_handler") not in imports
    assert ("kdive.prereqs.handlers", "prerequisites_handler") in imports
    assert dev_setup.prerequisites_handler.__module__ == "kdive.prereqs.handlers"


def test_dev_setup_check_host_returns_nonzero_for_failed_checks(monkeypatch, capsys) -> None:
    from kdive.domain import PrerequisiteCheck, PrerequisiteStatus, ToolResponse
    from kdive.prereqs import dev_setup

    def fake_prerequisites_handler(**_kwargs: object) -> ToolResponse:
        return ToolResponse.success(
            summary="1 prerequisite checks failed",
            data={
                "checks": [
                    PrerequisiteCheck(
                        check_id="tool.gdb",
                        status=PrerequisiteStatus.FAILED,
                        message="gdb was not found",
                    ).model_dump(mode="json")
                ]
            },
        )

    monkeypatch.setattr(dev_setup, "prerequisites_handler", fake_prerequisites_handler)

    assert dev_setup.check_host() == 1
    output = capsys.readouterr().out
    assert "failed  tool.gdb: gdb was not found" in output
    assert "Host prerequisite checks failed" in output


def test_dev_setup_main_rejects_unknown_command(capsys) -> None:
    from kdive.prereqs.dev_setup import main

    try:
        main(["unknown"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("main should exit for unknown commands")

    assert "Usage:" in capsys.readouterr().err
