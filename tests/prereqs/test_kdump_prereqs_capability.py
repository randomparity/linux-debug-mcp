import asyncio

from kdive.config import ALLOWED_DEBUG_OPERATIONS
from kdive.providers.local.local_drgn_introspect import local_drgn_introspect_capability
from kdive.server import create_app


def test_op_in_allowed_debug_operations() -> None:
    assert "debug.postmortem.check_prereqs" in ALLOWED_DEBUG_OPERATIONS


def test_op_advertised_by_ssh_capability() -> None:
    cap = local_drgn_introspect_capability()
    assert "debug.postmortem.check_prereqs" in cap.operations
    assert "debug.introspect.check_prerequisites" in cap.operations  # unchanged
    # operations and operation_capabilities stay consistent
    assert cap.operations == [c.operation for c in cap.operation_capabilities]


def test_tool_registered() -> None:
    app = create_app()
    names = {t.name for t in asyncio.run(app.list_tools())}
    assert "debug.postmortem.check_prereqs" in names
