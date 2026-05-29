from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from linux_debug_mcp.safety.paths import PathSafetyError, confine_run_relative
from linux_debug_mcp.seams.target import KernelProvenance


@dataclass(frozen=True)
class ResolutionWarning:
    code: str
    detail: str


@dataclass(frozen=True)
class ResolvedSymbols:
    vmlinux_path: Path
    modules_path: Path | None
    warnings: list[ResolutionWarning]


class SymbolResolutionError(Exception):
    """A required symbol source could not be resolved inside the run sandbox."""

    def __init__(self, message: str, *, code: str = "symbol_resolution_failed") -> None:
        super().__init__(message)
        self.code = code


def resolve_symbols(provenance: KernelProvenance, *, run_dir: Path) -> ResolvedSymbols:
    """Resolve drgn-consumable paths from *provenance*, confined to *run_dir*.

    ``vmlinux_ref`` is required (missing/escaping/not-a-file is fatal).
    ``modules_ref`` is optional: absent or missing-bundle yields exactly one
    ``modules_debuginfo_missing`` warning, never a silent drop. This function
    does NOT verify build_id -- that is
    :func:`linux_debug_mcp.symbols.verify.verify_build_id`.
    """
    try:
        vmlinux_path = confine_run_relative(provenance.vmlinux_ref, run_dir=run_dir)
    except PathSafetyError as exc:
        raise SymbolResolutionError(f"vmlinux_ref is unsafe: {exc}") from exc
    if not vmlinux_path.is_file():
        raise SymbolResolutionError(f"vmlinux not found at {provenance.vmlinux_ref!r}")

    warnings: list[ResolutionWarning] = []
    modules_path: Path | None = None
    if provenance.modules_ref is None:
        warnings.append(ResolutionWarning(code="modules_debuginfo_missing", detail="no modules_ref recorded"))
    else:
        try:
            candidate = confine_run_relative(provenance.modules_ref, run_dir=run_dir)
        except PathSafetyError as exc:
            raise SymbolResolutionError(f"modules_ref is unsafe: {exc}") from exc
        if candidate.exists():
            modules_path = candidate
        else:
            warnings.append(
                ResolutionWarning(
                    code="modules_debuginfo_missing",
                    detail=f"modules bundle absent at {provenance.modules_ref!r}",
                )
            )
    return ResolvedSymbols(vmlinux_path=vmlinux_path, modules_path=modules_path, warnings=warnings)
