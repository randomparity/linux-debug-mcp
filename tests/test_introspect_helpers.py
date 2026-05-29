import pytest

from linux_debug_mcp.introspect_helpers import HELPER_REGISTRY, built_in_helper_specs
from linux_debug_mcp.introspect_helpers.base import HelperSpec


def test_registry_names_are_unique_and_expected() -> None:
    names = [spec.name for spec in built_in_helper_specs()]
    assert len(names) == len(set(names))  # unique
    assert set(names) == {"sysinfo", "tasks", "dmesg", "modules", "slab", "irq"}


def test_registry_maps_name_to_spec() -> None:
    assert isinstance(HELPER_REGISTRY["sysinfo"], HelperSpec)
    assert HELPER_REGISTRY["sysinfo"].version >= 1


def test_every_spec_script_calls_emit() -> None:
    for spec in built_in_helper_specs():
        assert "emit(" in spec.script, spec.name


# --- sysinfo ---


def test_sysinfo_model_validates_sample() -> None:
    from linux_debug_mcp.introspect_helpers.sysinfo import Output

    Output.model_validate(
        {
            "release": "6.8.0",
            "version": "#1 SMP",
            "machine": "x86_64",
            "nodename": "vm",
            "boot_cmdline": "ro quiet",
            "cpus_online": 4,
            "mem_total_pages": 1048576,
        }
    )


def test_sysinfo_model_rejects_extra_field() -> None:
    from pydantic import ValidationError

    from linux_debug_mcp.introspect_helpers.sysinfo import Output

    with pytest.raises(ValidationError):
        Output.model_validate(
            {
                "release": "x",
                "version": "y",
                "machine": "z",
                "nodename": "n",
                "boot_cmdline": "",
                "cpus_online": 1,
                "mem_total_pages": 1,
                "extra": 1,
            }
        )


# --- tasks ---


def test_tasks_args_defaults() -> None:
    from linux_debug_mcp.introspect_helpers.tasks import Args

    a = Args()
    assert a.states == ["D"]
    assert a.include_stack is True
    assert a.limit == 200


def test_tasks_output_validates_sample() -> None:
    from linux_debug_mcp.introspect_helpers.tasks import Output

    Output.model_validate(
        {
            "tasks": [
                {
                    "pid": 1,
                    "tgid": 1,
                    "comm": "systemd",
                    "state": "S",
                    "kernel_stack": ["__schedule+0x1"],
                }
            ],
            "truncated": False,
        }
    )


# --- dmesg ---


def test_dmesg_args_default() -> None:
    from linux_debug_mcp.introspect_helpers.dmesg import Args

    assert Args().max_entries == 1000


def test_dmesg_output_validates_sample() -> None:
    from linux_debug_mcp.introspect_helpers.dmesg import Output

    Output.model_validate({"entries": [{"ts_usec": 1, "level": 6, "text": "boot"}], "truncated": False})


# --- modules ---


def test_modules_output_validates_sample() -> None:
    from linux_debug_mcp.introspect_helpers.modules import Output

    Output.model_validate(
        {
            "modules": [
                {
                    "name": "ext4",
                    "size": 1,
                    "refcount": 2,
                    "used_by": ["jbd2"],
                    "state": "live",
                }
            ]
        }
    )


# --- slab ---


def test_slab_output_validates_sample() -> None:
    from linux_debug_mcp.introspect_helpers.slab import Output

    Output.model_validate(
        {
            "caches": [
                {
                    "name": "kmalloc-64",
                    "active_objs": 10,
                    "num_objs": 20,
                    "objsize": 64,
                    "objs_per_slab": 64,
                }
            ]
        }
    )


# --- irq ---


def test_irq_output_validates_sample() -> None:
    from linux_debug_mcp.introspect_helpers.irq import Output

    Output.model_validate({"irqs": [{"irq": 0, "name": "timer", "counts_per_cpu": [10, 12], "affinity": [0, 1]}]})


def test_irq_name_nullable() -> None:
    from linux_debug_mcp.introspect_helpers.irq import Output

    Output.model_validate({"irqs": [{"irq": 1, "name": None, "counts_per_cpu": [0], "affinity": [0]}]})


def test_schema_snapshots_match_models() -> None:
    import json
    from pathlib import Path

    from linux_debug_mcp.introspect_helpers import built_in_helper_specs

    schema_dir = Path("src/linux_debug_mcp/introspect_helpers/schemas")
    for spec in built_in_helper_specs():
        snap = schema_dir / f"{spec.name}.v{spec.version}.json"
        assert snap.is_file(), f"missing snapshot for {spec.name} v{spec.version}"
        expected = json.dumps(spec.output_model.model_json_schema(), indent=2, sort_keys=True) + "\n"
        assert snap.read_text() == expected, f"{spec.name} model changed without a snapshot/version bump (spec §3.4)"


def test_helper_request_defaults() -> None:
    from linux_debug_mcp.domain import DebugIntrospectHelperRequest

    r = DebugIntrospectHelperRequest(run_id="r", target_ref="t", name="sysinfo")
    assert r.args == {}
    assert r.timeout_seconds == 30


def test_helper_request_forbids_extra() -> None:
    from pydantic import ValidationError

    from linux_debug_mcp.domain import DebugIntrospectHelperRequest

    with pytest.raises(ValidationError):
        DebugIntrospectHelperRequest(run_id="r", target_ref="t", name="sysinfo", bogus=1)
