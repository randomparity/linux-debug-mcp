from __future__ import annotations

import contextlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import RootfsProfile
from kdive.debug.contracts import DebugRuntime
from kdive.debug.operations import (
    _configuration_failure,
    _debug_session_manifest_details,
    _enforce_debug_ownership_fence,
    _load_active_debug_session,
    _mi_session_artifacts,
    _persist_mi_debug_session,
    _preserved_debug_step_details,
    _teardown_stalled_debug_session,
)
from kdive.debug.policy import ensure_debug_operation_enabled, resolve_debug_profile
from kdive.debug.tools import DebugLoadModuleSymbolsRequest, DebugToolContext
from kdive.default_profiles import DEFAULT_ROOTFS_PROFILES
from kdive.domain import ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.providers.debug import (
    DebugSession,
    GdbMiError,
    GdbMiLoadedModule,
    GdbMiSessionRegistry,
    ProviderDebugError,
)
from kdive.providers.ssh import SshRunner, SubprocessSshRunner, build_ssh_argv
from kdive.safety.paths import PathSafetyError
from kdive.safety.redaction import Redactor

SSH_TIMEOUT_GRACE_SECONDS = 10

# Phase D (#82): a loadable kernel module's name (sysfs normalizes the source name's hyphens to
# underscores under /sys/module/, so the agent-facing name is the underscore form).
_MODULE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# The sysfs section files the module-symbol load sources; .text is mandatory (add-symbol-file's
# positional address), the rest are best-effort -s arguments.
_MODULE_SECTION_FILES = (".text", ".data", ".rodata", ".bss")
# Emitted by the remote reader when /sys/module/<name>/sections is absent (module not loaded).
_NO_MODULE_SENTINEL = "__NO_MODULE__"


@dataclass(frozen=True)
class ModuleSymbolLoadOptions:
    module: str
    sections: dict[str, str] | None = None
    ko_path: str | None = None
    rootfs_profiles: dict[str, RootfsProfile] | None = None
    ssh_runner: SshRunner | None = None
    module_ko_finder: Callable[[Path, str], Path | None] | None = None


@dataclass(frozen=True)
class _ResolvedModuleSymbolLoadRequest:
    session: DebugSession
    attachment: Any
    sections: dict[str, str]
    ko_path: Path


@dataclass(frozen=True)
class _CompletedModuleSymbolLoad:
    loaded_payload: dict[str, object]


def _read_module_sections(
    *,
    ssh_runner: SshRunner,
    rootfs_profile: RootfsProfile,
    known_hosts_path: Path,
    module_name: str,
    work_dir: Path,
    timeout: int = 15,
) -> dict[str, str]:
    """Read a module's runtime section base addresses from guest sysfs over SSH (ADR 0022)."""
    work_dir.mkdir(parents=True, exist_ok=True)
    section_list = " ".join(_MODULE_SECTION_FILES)
    script = (
        'd="/sys/module/$1/sections"; '
        f'if [ ! -d "$d" ]; then echo "{_NO_MODULE_SENTINEL}"; exit 0; fi; '
        f"for s in {section_list}; do "
        'if [ -r "$d/$s" ]; then printf "%s %s\\n" "$s" "$(cat "$d/$s")"; fi; done'
    )
    remote = ["sh", "-c", script, "kdive-sections", module_name]
    argv = build_ssh_argv(
        rootfs_profile=rootfs_profile,
        known_hosts_path=known_hosts_path,
        command=remote,
        command_timeout=timeout + SSH_TIMEOUT_GRACE_SECONDS,
    )
    result = ssh_runner.run(
        argv,
        timeout=timeout + SSH_TIMEOUT_GRACE_SECONDS,
        stdout_path=work_dir / "module-sections.out",
        stderr_path=work_dir / "module-sections.err",
    )
    stdout = getattr(result, "stdout", "") or ""
    if not stdout.strip() and (getattr(result, "timed_out", False) or getattr(result, "exit_status", 0) != 0):
        raise ProviderDebugError(
            f"could not reach the target over SSH to read module {module_name!r} section addresses",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"code": "ssh_unreachable", "module": module_name},
        )
    if _NO_MODULE_SENTINEL in stdout:
        raise ProviderDebugError(
            f"module {module_name!r} is not loaded on the target (no /sys/module/{module_name}/sections)",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"code": "module_not_loaded", "module": module_name},
        )
    sections: dict[str, str] = {}
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            sections[parts[0]] = parts[1]
    if ".text" not in sections:
        raise ProviderDebugError(
            f"could not read the .text section address for module {module_name!r}",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={
                "code": "section_addresses_unreadable",
                "module": module_name,
                "hint": "/sys/module/<name>/sections/* are root-readable; use a root-capable SSH identity",
            },
        )
    return sections


def _default_module_ko_finder(build_tree: Path, module_name: str) -> Path | None:
    spellings = [module_name, module_name.replace("_", "-"), module_name.replace("-", "_")]
    for suffix in (".ko.debug", ".ko"):
        for spelling in spellings:
            for found in sorted(build_tree.rglob(f"{spelling}{suffix}")):
                return found
    return None


def _load_module_symbols(
    *,
    artifact_root: Path,
    run_id: str,
    options: ModuleSymbolLoadOptions,
    runtime: DebugRuntime,
    debug_session_id: str | None = None,
) -> ToolResponse:
    """Load a loadable module's symbols at runtime addresses so breakpoints resolve."""
    store = ArtifactStore(artifact_root, create_root=False)
    if not (store.run_dir(run_id) / "manifest.json").is_file():
        return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
    if runtime.gdb_mi_engine is None or runtime.gdb_mi_sessions is None:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message="the gdb/MI engine is not available on this server instance",
            run_id=run_id,
            details={"code": "debug_engine_unavailable"},
            suggested_next_actions=["artifacts.get_manifest"],
        )
    redactor = Redactor()
    finder = options.module_ko_finder or _default_module_ko_finder
    try:
        completed = _locked_module_symbol_load(
            store=store,
            run_id=run_id,
            options=options,
            debug_session_id=debug_session_id,
            finder=finder,
            runtime=runtime,
            redactor=redactor,
        )
        if isinstance(completed, ToolResponse):
            return completed
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)
    except ProviderDebugError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value(exc.details),
            suggested_next_actions=["debug.start_session", "artifacts.get_manifest"],
        )
    except GdbMiError as exc:
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=redactor.redact_value(exc.details),
            suggested_next_actions=["debug.start_session", "artifacts.get_manifest"],
        )
    except OSError as exc:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message=redactor.redact_text(f"failed to record debug.load_module_symbols: {exc}"),
            run_id=run_id,
            details={"code": "debug_session_op_record_failed"},
            suggested_next_actions=["debug.end_session", "artifacts.get_manifest"],
        )
    return ToolResponse.success(
        summary=f"debug.load_module_symbols loaded {options.module}",
        run_id=run_id,
        data=redactor.redact_value({"loaded_module": completed.loaded_payload}),
        suggested_next_actions=["debug.set_breakpoint"],
    )


def debug_load_module_symbols_handler(
    *, request: DebugLoadModuleSymbolsRequest, runtime: DebugToolContext
) -> ToolResponse:
    return _load_module_symbols(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        options=ModuleSymbolLoadOptions(
            module=request.module,
            sections=request.sections,
            ko_path=request.ko_path,
        ),
        debug_session_id=request.debug_session_id,
        runtime=DebugRuntime(
            admission=runtime.admission,
            transaction=runtime.transaction,
            session_registry=runtime.session_registry,
            session_guard=runtime.session_guard,
            gdb_mi_engine=runtime.gdb_mi_engine,
            gdb_mi_sessions=runtime.gdb_mi_sessions,
        ),
    )


def _resolve_module_symbol_load_request(
    *,
    store: ArtifactStore,
    run_id: str,
    options: ModuleSymbolLoadOptions,
    debug_session_id: str | None,
    finder: Callable[[Path, str], Path | None],
    runtime: DebugRuntime,
    gdb_mi_sessions: GdbMiSessionRegistry[Any],
) -> _ResolvedModuleSymbolLoadRequest | ToolResponse:
    session = _load_active_debug_session(store, run_id, debug_session_id)
    _enforce_debug_ownership_fence(
        run_id=run_id,
        admission=runtime.admission,
        session_registry=runtime.session_registry,
    )
    profile = resolve_debug_profile(profile_name=session.selected_debug_profile, debug_profiles=runtime.debug_profiles)
    ensure_debug_operation_enabled(profile, "debug.load_module_symbols")
    module = options.module
    if not _MODULE_NAME_RE.match(module):
        return _configuration_failure(
            run_id=run_id,
            message=f"module must be a bare module identifier, got {module!r}",
            details={"code": "invalid_module_name", "module": module},
        )
    attachment = gdb_mi_sessions.require(session.session_id)
    resolved_sections = _resolve_module_sections(
        store=store,
        run_id=run_id,
        module=module,
        sections=options.sections,
        ssh_runner=options.ssh_runner,
        rootfs_profiles=options.rootfs_profiles,
    )
    existing = session.loaded_modules.get(module)
    if existing is not None:
        if existing.get(".text") == resolved_sections.get(".text"):
            return ToolResponse.success(
                summary=f"module {module} symbols already loaded",
                run_id=run_id,
                data={"loaded_module": {"name": module, "sections": existing}},
                suggested_next_actions=["debug.set_breakpoint"],
            )
        return _configuration_failure(
            run_id=run_id,
            message=f"module {module} .text address changed since it was loaded; re-attach (debug.end_session)",
            details={"code": "module_address_changed", "module": module},
        )
    resolved_ko = _resolve_module_ko(
        build_tree=store.run_dir(run_id) / "build",
        module=module,
        ko_path=options.ko_path,
        finder=finder,
    )
    if resolved_ko is None:
        return _configuration_failure(
            run_id=run_id,
            message=f"no module object (.ko/.ko.debug) found for {module} under the build tree",
            details={
                "code": "module_object_not_found",
                "module": module,
                "spellings_tried": [module, module.replace("_", "-"), module.replace("-", "_")],
            },
        )
    return _ResolvedModuleSymbolLoadRequest(
        session=session,
        attachment=attachment,
        sections=resolved_sections,
        ko_path=resolved_ko,
    )


def _locked_module_symbol_load(
    *,
    store: ArtifactStore,
    run_id: str,
    options: ModuleSymbolLoadOptions,
    debug_session_id: str | None,
    finder: Callable[[Path, str], Path | None],
    runtime: DebugRuntime,
    redactor: Redactor,
) -> _CompletedModuleSymbolLoad | ToolResponse:
    gdb_mi_engine = runtime.gdb_mi_engine
    gdb_mi_sessions = runtime.gdb_mi_sessions
    if gdb_mi_engine is None or gdb_mi_sessions is None:
        raise AssertionError("debug.load_module_symbols requires an initialized gdb/MI runtime")
    with store.debug_lock(run_id):
        resolved = _resolve_module_symbol_load_request(
            store=store,
            run_id=run_id,
            options=options,
            debug_session_id=debug_session_id,
            finder=finder,
            runtime=runtime,
            gdb_mi_sessions=gdb_mi_sessions,
        )
        if isinstance(resolved, ToolResponse):
            return resolved
        try:
            loaded = gdb_mi_engine.load_module_symbols(
                resolved.attachment,
                name=options.module,
                ko_path=resolved.ko_path,
                sections=resolved.sections,
            )
        except GdbMiError as exc:
            if exc.details.get("code") == "transport_stall":
                return _cleanup_stalled_module_symbol_load(
                    run_id=run_id,
                    session=resolved.session,
                    error=exc,
                    redactor=redactor,
                    runtime=runtime,
                )
            raise
        except ProviderDebugError:
            raise
        except Exception as exc:
            reaped = gdb_mi_sessions.reap(resolved.session.session_id)
            if reaped is not None:
                with contextlib.suppress(Exception):
                    gdb_mi_engine.force_resume(reaped)
            return ToolResponse.failure(
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                message=redactor.redact_text(f"the gdb/MI engine faulted during debug.load_module_symbols: {exc}"),
                run_id=run_id,
                details={"code": "debug_engine_faulted"},
                suggested_next_actions=["debug.end_session", "artifacts.get_manifest"],
            )
        return _record_module_symbol_load_success(
            store=store,
            run_id=run_id,
            module=options.module,
            session=resolved.session,
            loaded=loaded,
        )


def _cleanup_stalled_module_symbol_load(
    *,
    run_id: str,
    session: DebugSession,
    error: GdbMiError,
    redactor: Redactor,
    runtime: DebugRuntime,
) -> ToolResponse:
    gdb_mi_engine = runtime.gdb_mi_engine
    gdb_mi_sessions = runtime.gdb_mi_sessions
    if gdb_mi_engine is None or gdb_mi_sessions is None:
        raise AssertionError("debug.load_module_symbols requires an initialized gdb/MI runtime")
    reaped = gdb_mi_sessions.reap(session.session_id)
    if reaped is not None:
        with contextlib.suppress(Exception):
            gdb_mi_engine.force_resume(reaped)
    _teardown_stalled_debug_session(
        run_id=run_id,
        admission=runtime.admission,
        session_registry=runtime.session_registry,
        transaction=runtime.transaction,
        session_guard=runtime.session_guard,
    )
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=redactor.redact_text(str(error)),
        run_id=run_id,
        details={"code": "transport_stall"},
        suggested_next_actions=["debug.start_session", "debug.kdb", "debug.introspect.run"],
    )


def _record_module_symbol_load_success(
    *,
    store: ArtifactStore,
    run_id: str,
    module: str,
    session: DebugSession,
    loaded: GdbMiLoadedModule,
) -> _CompletedModuleSymbolLoad:
    ledger = dict(session.loaded_modules)
    ledger[module] = dict(loaded.sections)
    updated_session = session.model_copy(update={"loaded_modules": ledger})
    loaded_payload = loaded.model_dump(mode="json")
    _persist_mi_debug_session(store=store, run_id=run_id, session=updated_session)
    details = {
        **_debug_session_manifest_details(store=store, run_id=run_id, session=updated_session),
        **_preserved_debug_step_details(store, run_id),
        "loaded_module": loaded_payload,
    }
    store.record_step_result(
        run_id,
        StepResult(
            step_name="debug",
            status=StepStatus.SUCCEEDED,
            summary="debug.load_module_symbols succeeded",
            artifacts=_mi_session_artifacts(store=store, run_id=run_id, session=updated_session),
            details=details,
        ),
        replace_succeeded=True,
    )
    return _CompletedModuleSymbolLoad(loaded_payload=loaded_payload)


def _resolve_module_sections(
    *,
    store: ArtifactStore,
    run_id: str,
    module: str,
    sections: dict[str, str] | None,
    ssh_runner: SshRunner | None,
    rootfs_profiles: dict[str, RootfsProfile] | None,
) -> dict[str, str]:
    if sections is not None:
        return {str(name): str(address) for name, address in sections.items()}
    runner: SshRunner = ssh_runner or SubprocessSshRunner()
    manifest = store.load_manifest(run_id)
    profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    rootfs_name = manifest.request.rootfs_profile
    rootfs_profile = manifest.resolved_rootfs_profile or profiles.get(rootfs_name)
    if rootfs_profile is None:
        raise ProviderDebugError(
            f"unknown rootfs profile {rootfs_name!r} for module section discovery",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"code": "unknown_rootfs_profile", "rootfs_profile": rootfs_name},
        )
    return _read_module_sections(
        ssh_runner=runner,
        rootfs_profile=rootfs_profile,
        known_hosts_path=store.run_dir(run_id) / "sensitive" / "known_hosts",
        module_name=module,
        work_dir=store.run_dir(run_id) / "debug",
    )


def _resolve_module_ko(
    *,
    build_tree: Path,
    module: str,
    ko_path: str | None,
    finder: Callable[[Path, str], Path | None],
) -> Path | None:
    if ko_path is not None:
        resolved = Path(ko_path).expanduser().resolve()
        try:
            if not resolved.is_relative_to(build_tree.resolve()):
                raise PathSafetyError(f"module object path escapes the build tree: {ko_path}")
        except PathSafetyError as exc:
            raise ProviderDebugError(
                str(exc),
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"code": "module_object_unsafe_path"},
            ) from exc
        return resolved if resolved.is_file() else None
    return finder(build_tree, module)
