"""local-drgn-introspect: live drgn-over-SSH introspection provider.

Spec: docs/superpowers/specs/2026-05-28-debug-introspect-run-design.md
"""

from __future__ import annotations

from dataclasses import dataclass

from kdive.domain import (
    ImplementationState,
    OperationSemantics,
    ProviderCapability,
    ProviderOperationCapability,
    TargetKind,
)
from kdive.providers.introspect import (
    SCRIPT_BYTE_CAP as SCRIPT_BYTE_CAP,
)
from kdive.providers.introspect import (
    TARGET_PYTHON_ARGV as TARGET_PYTHON_ARGV,
)
from kdive.providers.introspect import (
    WrapperRenderError as WrapperRenderError,
)
from kdive.providers.introspect import (
    render_vmcore_wrapper as render_vmcore_wrapper,
)
from kdive.providers.introspect import (
    render_vmcore_wrapper_skeleton as render_vmcore_wrapper_skeleton,
)
from kdive.providers.introspect import (
    render_wrapper as render_wrapper,
)
from kdive.providers.introspect import (
    render_wrapper_skeleton as render_wrapper_skeleton,
)
from kdive.providers.introspect import (
    user_script_sha256 as user_script_sha256,
)
from kdive.providers.local.introspect.drgn_live_wrapper import (
    WRAPPER_TEMPLATE as WRAPPER_TEMPLATE,
)
from kdive.providers.local.introspect.drgn_vmcore_wrapper import (
    VMCORE_WRAPPER_TEMPLATE as VMCORE_WRAPPER_TEMPLATE,
)
from kdive.providers.local.introspect.drgn_wrapper_common import (
    _WRAPPER_BODY as _WRAPPER_BODY,
)
from kdive.providers.local.introspect.drgn_wrapper_common import (
    RUNNER_DEFAULT_CAPS as RUNNER_DEFAULT_CAPS,
)


@dataclass(frozen=True)
class LocalDrgnIntrospectProvider:
    """Marker for the local drgn-introspect capability.

    The actual SSH invocation, wrapper render, and result parsing live in the
    handler (``server.debug_introspect_run_handler``) so they can share the
    ``_record_terminal_build_result``-style manifest-lock retry pattern and
    the redaction helpers. This provider object exists so the registry can
    declare ``local-drgn-introspect`` as a capability without bundling logic
    the handler already owns.
    """

    name: str = "local-drgn-introspect"


def local_drgn_introspect_capability() -> ProviderCapability:
    """Factory used by ``providers/plugins.py``. Spec §3.4 / §2 / ADR 0010.

    The live ssh-tier ops are ``concurrent_safe=False`` (admission-gated); the
    offline vmcore ops are ``concurrent_safe=True`` (interface-contracts §5.6
    rule 3 — never gated), advertised via per-operation overrides.
    """
    live_semantics = OperationSemantics(
        idempotent=False,
        retryable=True,
        destructive=False,
        cancelable=True,
        concurrent_safe=False,
    )
    vmcore_semantics = OperationSemantics(
        idempotent=False,
        retryable=True,
        destructive=False,
        cancelable=True,
        concurrent_safe=True,
    )
    vmcore_ops = {"debug.introspect.from_vmcore", "debug.introspect.from_vmcore_helper"}
    operations = [
        "debug.introspect.run",
        "debug.introspect.check_prerequisites",
        "debug.postmortem.check_prereqs",
        "debug.introspect.helper",
        "debug.introspect.from_vmcore",
        "debug.introspect.from_vmcore_helper",
    ]
    return ProviderCapability(
        provider_name="local-drgn-introspect",
        provider_version="0.2.0",
        provider_family="debug",
        implementation_state=ImplementationState.IMPLEMENTED,
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["ssh"],
        operations=operations,
        required_host_tools=["ssh"],
        destructive_permissions=[],
        access_methods=["ssh"],
        semantics=live_semantics,
        operation_capabilities=[
            ProviderOperationCapability(
                operation=op,
                semantics=(vmcore_semantics if op in vmcore_ops else live_semantics),
            )
            for op in operations
        ],
    )
