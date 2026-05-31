from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

ROOT = Path(__file__).parents[1]


def _is_exact_pin(specifier: SpecifierSet) -> bool:
    return len(specifier) == 1 and next(iter(specifier)).operator == "=="


def test_pyproject_dependency_specs_are_exact_and_match_lock() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked_versions = {package["name"]: package["version"] for package in lock["package"]}

    specs = list(pyproject["build-system"]["requires"])
    specs.extend(pyproject["project"]["dependencies"])
    for extra_specs in pyproject["project"]["optional-dependencies"].values():
        specs.extend(extra_specs)

    for spec in specs:
        requirement = Requirement(spec)

        assert _is_exact_pin(requirement.specifier), spec
        if requirement.name in locked_versions:
            assert str(requirement.specifier) == f"=={locked_versions[requirement.name]}"
