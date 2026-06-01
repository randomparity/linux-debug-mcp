from __future__ import annotations

from kdive.config import ALLOWED_DEBUG_OPERATIONS, DebugProfile
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.default_profiles import DEFAULT_DEBUG_PROFILES
from kdive.domain import ErrorCategory
from kdive.providers.debug import ProviderDebugError
from kdive.transport.core.base import ExecutionState, TransportSession


def ensure_debug_operation_enabled(profile: DebugProfile, operation: str) -> None:
    if operation not in set(ALLOWED_DEBUG_OPERATIONS):
        raise ProviderDebugError(
            "unsupported debug operation",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"operation": operation},
        )
    if operation not in profile.enabled_operations:
        raise ProviderDebugError(
            "debug operation is disabled by selected profile",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"debug_profile": profile.name, "operation": operation},
        )


def resolve_debug_profile(
    *,
    profile_name: str,
    debug_profiles: dict[str, DebugProfile] | None,
) -> DebugProfile:
    profiles = debug_profiles if debug_profiles is not None else DEFAULT_DEBUG_PROFILES
    try:
        return profiles[profile_name]
    except KeyError as exc:
        raise ProviderDebugError(
            "unknown debug profile",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"debug_profile": profile_name},
        ) from exc


def halt_debug_transport(
    *,
    session: TransportSession,
    admission: AdmissionService,
    session_registry: SessionRegistry,
) -> None:
    session_registry.write_record(session.model_copy(update={"execution_state": ExecutionState.HALTED}))
    halt_epoch = admission.note_execution_transition(session.target_key, session.generation)
    admission.cancel_ssh_tier(session.target_key, session.generation, halt_epoch=halt_epoch)
