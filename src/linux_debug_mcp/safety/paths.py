from __future__ import annotations

import re
from pathlib import Path

from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind


class PathSafetyError(ValueError):
    pass


_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHELL_METACHARS = set(";|&`$<>\\")


def _resolve_existing_or_parent(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.exists():
        return expanded.resolve()
    parent = expanded.parent
    if not parent.exists():
        raise PathSafetyError(f"parent does not exist for path: {path}")
    return parent.resolve() / expanded.name


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def validate_artifact_root(
    artifact_root: Path,
    *,
    source_paths: list[Path],
    sensitive_paths: list[Path],
) -> Path:
    resolved = _resolve_existing_or_parent(artifact_root)
    home = Path.home().resolve()
    if resolved in {Path("/"), home}:
        raise PathSafetyError("artifact root is too broad")

    existing_parent = resolved if resolved.exists() else resolved.parent
    if not existing_parent.exists():
        raise PathSafetyError("artifact root parent does not exist")

    for source in source_paths:
        source_resolved = _resolve_existing_or_parent(source)
        if resolved == source_resolved or _is_relative_to(resolved, source_resolved):
            raise PathSafetyError("artifact root overlaps source path")

    for sensitive in sensitive_paths:
        sensitive_resolved = _resolve_existing_or_parent(sensitive)
        if resolved == sensitive_resolved or _is_relative_to(resolved, sensitive_resolved):
            raise PathSafetyError("artifact root overlaps sensitive path")

    return resolved


def validate_run_id(run_id: str) -> str:
    if not _RUN_ID_PATTERN.match(run_id):
        raise PathSafetyError("run ID contains unsafe characters")
    if run_id.startswith(".") or ".." in run_id or "/" in run_id:
        raise PathSafetyError("run ID contains unsafe path syntax")
    if any(char in _SHELL_METACHARS for char in run_id):
        raise PathSafetyError("run ID contains shell metacharacters")
    return run_id


def validate_source_path(source_path: Path) -> Path:
    resolved = source_path.expanduser().resolve()
    if not resolved.is_dir():
        raise PathSafetyError("source path is not a directory")
    if not (resolved / "Kconfig").exists() or not (resolved / "Makefile").exists():
        raise PathSafetyError("source path missing Linux tree marker")
    return resolved


def validate_guest_path(path: str) -> str:
    if not path.startswith("/"):
        raise PathSafetyError("guest path must be absolute")
    if "//" in path or "/../" in path or path.endswith("/.."):
        raise PathSafetyError("guest path contains unsafe path components")
    if any(char in _SHELL_METACHARS for char in path) or any(ord(char) < 32 for char in path):
        raise PathSafetyError("guest path contains unsafe characters")
    return path


def validate_secret_file_reference(ref: SecretReference, *, must_exist: bool = False) -> Path:
    if ref.kind != SecretReferenceKind.FILE:
        raise PathSafetyError("secret reference is not file-based")
    path = Path(ref.reference).expanduser()
    if not path.is_absolute():
        raise PathSafetyError("secret file reference must be absolute")
    resolved = path.resolve()
    if any(char in _SHELL_METACHARS for char in str(resolved)) or any(ord(char) < 32 for char in str(resolved)):
        raise PathSafetyError("secret file reference contains unsafe characters")
    if must_exist and not resolved.is_file():
        raise PathSafetyError("secret file reference does not exist")
    return resolved
