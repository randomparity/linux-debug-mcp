from linux_debug_mcp.domain import ErrorCategory


def test_stale_handle_category_value():
    assert ErrorCategory.STALE_HANDLE == "stale_handle"


def test_transport_conflict_category_value():
    assert ErrorCategory.TRANSPORT_CONFLICT == "transport_conflict"


def test_new_categories_are_distinct_members():
    values = {member.value for member in ErrorCategory}
    assert {"stale_handle", "transport_conflict"} <= values
