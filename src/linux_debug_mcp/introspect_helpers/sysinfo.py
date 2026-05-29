"""sysinfo helper: uts fields, boot cmdline, basic counters. Spec §7."""

from __future__ import annotations

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec, NoArgs


class Output(Model):
    release: str
    version: str
    machine: str
    nodename: str
    boot_cmdline: str
    cpus_online: int
    mem_total_pages: int


SCRIPT = r"""
uts = prog["init_uts_ns"].name
def _s(field):
    return field.string_().decode("utf-8", "replace")
emit({
    "release": _s(uts.release),
    "version": _s(uts.version),
    "machine": _s(uts.machine),
    "nodename": _s(uts.nodename),
    "boot_cmdline": prog["saved_command_line"].string_().decode("utf-8", "replace"),
    "cpus_online": int(prog["__num_online_cpus"].counter.value_()),
    "mem_total_pages": int(prog["_totalram_pages"].counter.value_()),
})
"""

SPEC = HelperSpec(name="sysinfo", version=1, script=SCRIPT, args_model=NoArgs, output_model=Output)
