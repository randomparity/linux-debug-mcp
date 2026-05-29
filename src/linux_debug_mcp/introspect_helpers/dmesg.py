from __future__ import annotations

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec, NoArgs


class Output(Model):
    placeholder: bool = True


SPEC = HelperSpec(
    name="dmesg",
    version=1,
    script="emit({'placeholder': True})",
    args_model=NoArgs,
    output_model=Output,
)
