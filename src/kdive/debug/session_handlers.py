from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from kdive.config import DebugProfile
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ToolResponse
from kdive.providers.debug import GdbMiEngine, GdbMiSessionRegistry
from kdive.seams.guard import SessionGuard
from kdive.symbols.build_id import read_elf_build_id


def debug_start_session_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_profile: str | None = None,
    new_session: bool = False,
    debug_profiles: dict[str, DebugProfile] | None = None,
    transaction: TransportTransaction | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    recovery: bool = False,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    from kdive.server import _debug_start_session_handler

    return _debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profile=debug_profile,
        new_session=new_session,
        debug_profiles=debug_profiles,
        transaction=transaction,
        admission=admission,
        session_registry=session_registry,
        session_guard=session_guard,
        recovery=recovery,
        build_id_reader=build_id_reader,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )
