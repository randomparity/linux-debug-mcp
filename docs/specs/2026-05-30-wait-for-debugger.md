# Wait-for-debugger frozen boot (gdbstub `wait=on`)

**Status:** Accepted (2026-05-30) · **Issue:** #104 · **Epic:** #100 (first-run readiness) ·
**ADR:** [0033](../adr/0033-wait-for-debugger-frozen-boot.md) ·
**Depends on:** the debug gdbstub boot path (`debug_gdbstub` / `gdbstub_endpoint`)

## Problem

Debug boot hardcodes `wait=off` on the QEMU gdbstub
(`src/linux_debug_mcp/providers/libvirt_qemu.py`, `render_domain_xml`:
`tcp:<host>:<port>,server=on,wait=off`). With `wait=off` the guest CPU free-runs the instant QEMU
launches, so the kernel has already executed `start_kernel` → `vfs_caches_init` → `dcache_init` long
before `debug.start_session` connects gdb. A breakpoint set after attach can never fire on those
early-init paths, so the dcache `dhash_entries=1` OOB (and any early-boot bug) cannot be caught
deterministically.

## Goal

A debug boot can be made to **freeze at the CPU reset vector** until a debugger attaches. With
`wait_for_debugger` enabled, `target.boot` launches the VM with gdbstub `wait=on`, returns
`SUCCEEDED`-frozen pointing at `debug.start_session`, and the guest executes **no** instructions until
`debug.start_session` attaches gdb and a later `debug.continue` releases it. Concretely (acceptance,
#104): on a `dhash_entries=1` boot a breakpoint at `dcache_init` / `__d_lookup` is hit deterministically
and `d_hash_shift` is inspectable at the fault.

Non-goals: changing any `debug.*` handler (a frozen VM is an ordinary gdbstub attach target at the reset
vector); QEMU `-S` global freeze (ADR 0033 decision 2); freezing a non-gdbstub boot (a configuration
error); discovering the guest IP before the CPU has run (no lease exists yet — out of scope for the boot
step).

## Design

### 1. `wait_for_debugger` on `TargetProfile`, override on `BootOverrides`

`TargetProfile` gains `wait_for_debugger: bool = False` (beside `debug_gdbstub` / `gdbstub_endpoint`).
`BootOverrides` gains a tri-state `wait_for_debugger: bool | None = None`. In `target_boot_handler`, at
the point where `kernel_args` and rootfs overrides are already merged into the resolved profiles, the
**effective** value is computed:

```
effective = override.wait_for_debugger if override.wait_for_debugger is not None else profile.wait_for_debugger
```

and applied with `resolved_target_profile.model_copy(update={"wait_for_debugger": effective})` only when
an override is present (mirroring the existing `kernel_args` override copy). `plan_boot` then reads the
single resolved `target_profile.wait_for_debugger`. `None` on the override means "inherit the profile",
exactly like `RootfsOverrides`' optional fields. A boot override of `wait_for_debugger` counts as a
"new boot override" for the §idempotency short-circuit, so requesting a frozen re-boot of an already
`SUCCEEDED` run re-plans instead of returning the prior (non-frozen) result.

### 2. `BootPlan.wait_for_debugger` drives the `wait=` token

`plan_boot` records `wait_for_debugger=target_profile.wait_for_debugger` on the immutable `BootPlan`.
`render_domain_xml` selects the gdbstub `wait=` token from it:

```
wait = "on" if plan.wait_for_debugger else "off"
# tcp:<host>:<port>,server=on,wait=<wait>
```

The gdbstub `qemu:commandline` block is still emitted only when `plan.debug_gdbstub and
plan.gdbstub_endpoint is not None` — unchanged. `wait_for_debugger` only flips the token within that
existing block.

### 3. Plan-time validation: `wait_for_debugger` requires `debug_gdbstub`

In `plan_boot`, after the effective `wait_for_debugger` is known and before the endpoint is parsed, if
`target_profile.wait_for_debugger and not target_profile.debug_gdbstub` the provider raises a
`ProviderBootError(category=CONFIGURATION_ERROR, "wait_for_debugger requires debug_gdbstub")`.
`TargetProfile` additionally carries a model-level validator (`mode="after"`) that rejects the same
combination at config-load time for static profiles; the plan-time gate is authoritative because an
override can set `wait_for_debugger` on a profile whose `debug_gdbstub` is its own (already-validated)
value, and the override path does not re-run model validation against the merged result. (A boot
override cannot set `debug_gdbstub`, so the override can only *add* `wait_for_debugger` to a target whose
`debug_gdbstub` is already fixed — the plan-time check catches `wait_for_debugger=True` over
`debug_gdbstub=False`.)

### 4. Frozen boot skips the readiness wait and returns `SUCCEEDED`-frozen

`execute_boot` runs define → start as today. After `start` succeeds it branches on
`plan.wait_for_debugger`:

- **Frozen (`wait_for_debugger=True`):** it does **not** call `stream_console`. The vCPU is blocked at
  the gdbstub, so the readiness marker can never print and a stream would block until
  `plan.timeout_seconds` and return `BOOT_TIMEOUT`. Instead it returns `SUCCEEDED` immediately with:
  - `details["console_status"] = "frozen"`
  - `details["wait_for_debugger"] = True`
  - `details["debug_boot"] = True` (it is a gdbstub boot)
  - `details["gdbstub_endpoint"] = {...}`
  - `details["matched_marker"] = None`, `details["console_snippet"] = ""`
  - `details["guest_ip"] = None`,
    `details["guest_ip_discovery"] = {"status": "skipped", "source": "lease", "reason": "wait_for_debugger"}`
  - `details["nokaslr_source"]`, `details["kernel_args"]` as today
  - `suggested_next_actions` (handler layer) = `["debug.start_session"]`
- **Normal (`wait_for_debugger=False`):** unchanged — `stream_console`, readiness/timeout branches, and
  guest-IP discovery on success exactly as today.

The frozen VM is a valid `debug.start_session` target: that handler requires
`boot_result.details["debug_boot"] is True` and a `gdbstub_endpoint` dict — both present — and gates on
`boot_result.status == SUCCEEDED`. No debug-tier change is needed; gdb attaches to a CPU stopped at the
reset vector, the caller sets a breakpoint (`debug.set_breakpoint dcache_init`), and `debug.continue`
releases the CPU, which then runs into the breakpoint deterministically.

### 5. Idempotency / short-circuit

A frozen boot records a terminal `SUCCEEDED` `StepResult` like any other and short-circuits on
re-invocation (returns the recorded frozen details). Re-running with a `wait_for_debugger` boot override
counts as a new boot override and re-plans (decision 1), so a run first booted non-frozen can be
re-booted frozen with `force_reboot`/override. The frozen `details` persist on disk, so a
`debug.start_session` after a server restart still reads `debug_boot` / `gdbstub_endpoint` from the
recorded result.

## Failure contract

| Situation | Boot status | `console_status` | Notable details | `suggested_next_actions` |
|---|---|---|---|---|
| `wait_for_debugger`, gdbstub boot, `start` OK | `SUCCEEDED` | `frozen` | `wait_for_debugger=True`, `debug_boot=True`, `guest_ip=null`/`skipped` | `["debug.start_session"]` |
| `wait_for_debugger=True`, `debug_gdbstub=False` | `FAILED` (plan) | — | `CONFIGURATION_ERROR` "wait_for_debugger requires debug_gdbstub" | n/a |
| `wait_for_debugger`, `virsh start` fails | `FAILED` | — | command-failure (cleanup per `cleanup_policy`) | n/a |
| `wait_for_debugger=False` (default), boot reaches marker | `SUCCEEDED` | `ready` | guest-IP discovery runs as today | `["target.run_tests", ...]` |
| Static `TargetProfile` with `wait_for_debugger` but no `debug_gdbstub` | n/a | n/a | rejected at config load (model validator) | n/a |

A frozen boot never streams the console and never discovers the IP, so it spends none of the
readiness-timeout or lease-poll budget; it returns as soon as `virsh start` succeeds.

## Affected code

- `src/linux_debug_mcp/config.py`: `TargetProfile.wait_for_debugger` (new field + model-level
  `debug_gdbstub`-required validator), `BootOverrides.wait_for_debugger` (new tri-state field).
- `src/linux_debug_mcp/providers/libvirt_qemu.py`: `BootPlan.wait_for_debugger` (new field set in
  `plan_boot`), `plan_boot` cross-field validation, `render_domain_xml` `wait=` token selection,
  `execute_boot` frozen branch (skip `stream_console`, skip discovery, return `SUCCEEDED`-frozen).
- `src/linux_debug_mcp/server.py`: `target_boot_handler` effective-`wait_for_debugger` merge from
  `BootOverrides`, `has_new_boot_overrides` to include `wait_for_debugger`, frozen-boot
  `suggested_next_actions`.
- No `domain.py` wire-model change and no JSON-schema snapshot regeneration (frozen facts ride
  `StepResult.details`; the new config fields are defaulted and backward-compatible).

## Verification

- Unit: `render_domain_xml` emits `wait=on` when `plan.wait_for_debugger` and `wait=off` otherwise; the
  gdbstub block is absent without `debug_gdbstub`.
- Unit: `plan_boot` raises `CONFIGURATION_ERROR` for `wait_for_debugger=True` + `debug_gdbstub=False`;
  succeeds and sets `BootPlan.wait_for_debugger=True` for the valid combination.
- Unit: `TargetProfile` model validator rejects `wait_for_debugger=True` + `debug_gdbstub=False` at
  construction; accepts both-true and both-false.
- Unit: `execute_boot` with a `FakeLibvirtRunner` — for a frozen plan it never calls `stream_console`,
  never calls `domifaddr`, returns `SUCCEEDED` with `console_status="frozen"`,
  `wait_for_debugger=True`, `debug_boot=True`, `guest_ip=None`,
  `guest_ip_discovery.status="skipped"`; for a non-frozen plan behavior is unchanged (existing tests).
- Unit: `execute_boot` frozen branch still returns `FAILED` when `virsh start` fails (the start-failure
  path runs before the frozen branch).
- Unit: `target_boot_handler` with injected profiles/provider — a `BootOverrides(wait_for_debugger=True)`
  over a `debug_gdbstub` profile yields a frozen `SUCCEEDED` boot with
  `suggested_next_actions=["debug.start_session"]`; an override `None` inherits the profile value;
  `wait_for_debugger` override marks the boot as a new override (re-plans an already-`SUCCEEDED` run).
- The env-gated `test_libvirt_boot_integration.py` / `test_qemu_gdbstub_integration.py` stay gated; no
  un-gating.
