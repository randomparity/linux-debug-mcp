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
  - `details["kernel_provenance"]` — added by the handler's success-branch capture (see the
    version-lock dependency below), **not** by the provider
  - `suggested_next_actions` (handler layer) = `["debug.start_session"]`
- **Normal (`wait_for_debugger=False`):** unchanged — `stream_console`, readiness/timeout branches, and
  guest-IP discovery on success exactly as today.

##### Load-bearing assumption: `virsh start` returns while the vCPU is frozen

The frozen branch depends on `virsh start` **returning** even though `wait=on` blocks the guest vCPU.
This holds because `wait=on` blocks only QEMU's vCPU thread at the gdbstub, while QEMU's main loop and
QMP monitor — which `virsh start` waits on — come up independently; libvirt considers the domain started
once the monitor handshake completes, not once the guest CPU runs. This is the single assumption the
whole feature rests on, and it is QEMU/libvirt-version-dependent, so it is called out here rather than
left implicit. **Failure mode if it is wrong on some host:** `start = self.runner.run(plan.start_argv,
timeout=plan.timeout_seconds, …)` is already bounded by the boot timeout, so a `virsh start` that blocked
would `timed_out` and return a `FAILED` command-failure (the existing `start` failure path) — a bounded
stall ending in `FAILED`, never an unbounded hang. The gated integration test (§Verification) is tasked
with confirming `virsh start` returns *promptly* (well under `timeout_seconds`) for a `wait=on` domain,
which is what distinguishes the intended fast frozen `SUCCEEDED` from this degenerate timeout.

The frozen branch returns the **same artifact set** as the normal success branch — the boot/console
log artifacts are created (the console log exists but is empty, the vCPU having printed nothing) and the
rotated-console-log handling runs unchanged — so the returned `artifacts` list shape is invariant across
frozen and normal success and no downstream artifact lookup sees a missing entry.

The frozen VM is a valid `debug.start_session` target: that handler requires
`boot_result.details["debug_boot"] is True` and a `gdbstub_endpoint` dict — both present — and gates on
`boot_result.status == SUCCEEDED`. No debug-tier code change is needed for **attach**: the attach path
reads no guest memory that is invalid at reset. `SessionGuard()` is wired with empty pre/post-attach
preconditions (`server.py:8654`), so `verify_attached` is a no-op — there is no running-kernel build-id
read over RSP at attach. `_run_mi_attach_probe` resolves the canonical probe symbol from the host-side
vmlinux ELF symbol table (`-data-evaluate-expression &symbol`, ADR 0020), which is independent of guest
execution. So gdb attaches to the CPU stopped at the reset vector and the MI handshake completes.

#### Success-path dependencies the frozen boot must preserve (version-lock + admission snapshot)

`debug.start_session` has **two** prerequisites that `target_boot_handler` produces on the boot-success
path, both keyed on `execution.status == StepStatus.SUCCEEDED` and **not** on `console_status`. A frozen
boot must satisfy both by returning `SUCCEEDED` and staying on the handler's success path; the implementer
MUST NOT gate the frozen branch (or these two handler steps) on `console_status == "ready"` or on the
guest-IP discovery path, or `debug.start_session` rejects every frozen boot before any breakpoint is set.

1. **`kernel_provenance` (version-lock).** `debug.start_session` runs `_verify_gdb_symbol_version_lock`
   (`server.py:5679`) *before* attaching, which **hard-requires** `boot_result.details["kernel_provenance"]`;
   when absent the handler returns `CONFIGURATION_ERROR` ("boot did not record a KernelProvenance"). It is
   captured in `target_boot_handler` on the `SUCCEEDED` branch (`server.py:1884`), entirely host-side
   (reads the build step's recorded `build_id` and the on-disk vmlinux/config artifacts — no guest
   execution). It is therefore one of the recorded frozen-boot details, set by the handler's existing
   capture, not by the provider.
2. **The admission `TargetSnapshot`.** `target_boot_handler` calls `_publish_boot_ready_snapshot`
   (`server.py:1916`) on the `SUCCEEDED` branch, publishing a `TargetSnapshot` carrying the gdbstub
   endpoint + rootfs/target identity. `debug.start_session` (and `target.run_tests`) require it via
   `_require_snapshot` (`server.py:655,692`) and fail without it. It needs no guest execution (it reads
   the recorded `gdbstub_endpoint` + the resolved rootfs profile), so a frozen `SUCCEEDED` boot publishes
   it unchanged — including the short-circuit republish path (`_short_circuit_boot_success`,
   `server.py:1617`) after a server restart. The snapshot's "READY" name is a label: for a frozen boot it
   provides the attach target identity, not a claim that the guest's userspace is up.

#### Breakpoint mechanism for the early-init target

The acceptance breakpoint must survive being set while the CPU sits at the reset vector. The debug tier
sets breakpoints through QEMU's gdbstub; under KVM, gdb breakpoints are inserted via
`KVM_SET_GUEST_DEBUG` (the gdbstub maps `Z0`/`Z1` to guest-debug state), so the breakpoint is honored by
the vCPU when its PC matches the **virtual** address resolved from the (KASLR-off) vmlinux symbols — it
does not depend on a guest-memory `int3` write landing in an already-mapped page at insert time. KASLR
is disabled on the debug profile (`DebugProfile.kaslr_policy="disabled"`, with `nokaslr` on the kernel
command line), so the symbol address gdb computes for `dcache_init` / `__d_lookup` equals the address the
kernel will execute at. The caller therefore: `debug.start_session` (attaches at reset) →
`debug.set_breakpoint dcache_init` → `debug.continue` (releases the vCPU) → the vCPU runs through the
decompressor and `start_kernel` into the breakpoint and HALTs, at which point `d_hash_shift` is
inspectable. This path is **not** unit-testable (it needs a real QEMU+KVM guest), so it is covered by a
gated integration test (§Verification), not asserted from the unit suite alone.

### 5. Idempotency / short-circuit

A frozen boot records a terminal `SUCCEEDED` `StepResult` like any other and short-circuits on
re-invocation (returns the recorded frozen details). Re-running with a `wait_for_debugger` boot override
counts as a new boot override and re-plans (decision 1), so a run first booted non-frozen can be
re-booted frozen with `force_reboot`/override. The frozen `details` persist on disk, so a
`debug.start_session` after a server restart still reads `debug_boot` / `gdbstub_endpoint` from the
recorded result.

### 6. Frozen-domain lifetime — no new leak surface

A frozen `SUCCEEDED` boot leaves a libvirt domain blocked at the reset vector. Its lifetime is identical
to a non-frozen debug boot's domain: it is reclaimed by the **same** `existing_domain` → `destroy` path
in `execute_boot` on any re-boot (a `force_reboot` or `wait_for_debugger`-override re-plan destroys the
prior frozen domain before defining the new one), and by `cleanup_policy="stop_on_failure"` on a failed
re-attempt. A frozen domain that is never attached-to (the agent never calls `debug.start_session`, or it
fails the version-lock gate) persists exactly as today's free-running debug domain does — there is no new
leak class; the frozen state does not change *which* component owns teardown, only that the vCPU is
blocked rather than running while the domain is alive.

## Failure contract

| Situation | Boot status | `console_status` | Notable details | `suggested_next_actions` |
|---|---|---|---|---|
| `wait_for_debugger`, gdbstub boot, `start` OK | `SUCCEEDED` | `frozen` | `wait_for_debugger=True`, `debug_boot=True`, `guest_ip=null`/`skipped` | `["debug.start_session"]` |
| `wait_for_debugger=True`, `debug_gdbstub=False` | `FAILED` (plan) | — | `CONFIGURATION_ERROR` "wait_for_debugger requires debug_gdbstub" | n/a |
| `wait_for_debugger`, `virsh start` fails | `FAILED` | — | command-failure (cleanup per `cleanup_policy`) | n/a |
| `wait_for_debugger=False` (default), boot reaches marker | `SUCCEEDED` | `ready` | guest-IP discovery runs as today | `["target.run_tests", ...]` |
| Static `TargetProfile` with `wait_for_debugger` but no `debug_gdbstub` | n/a | n/a | rejected at config load (model validator) | n/a |
| `target.run_tests` called against a frozen boot (wrong next action) | n/a | — | SSH connect fails (vCPU frozen, `guest_ip=null`) — same observable as the ADR 0032 `no_lease` case | n/a |

A frozen boot never streams the console and never discovers the IP, so it spends none of the
readiness-timeout or lease-poll budget; it returns as soon as `virsh start` succeeds. The admission
snapshot a frozen boot publishes means `target.run_tests` is *admitted* (the snapshot exists) but then
fails to SSH because the vCPU has not run — a degraded connect failure, not a clean rejection. The
frozen boot's `suggested_next_actions=["debug.start_session"]` steers the agent to the correct action;
`run_tests` is not blocked because the boot step cannot know the caller will not first `debug.continue`
the guest to readiness through a debug session.

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
- Unit: a frozen `SUCCEEDED` boot still records `details["kernel_provenance"]` (the handler's
  success-branch capture runs because the branch returns `SUCCEEDED`), so `_verify_gdb_symbol_version_lock`
  passes against it — i.e. `debug.start_session`'s version-lock gate is satisfied by a frozen boot. This
  is the regression guard for the §4 version-lock dependency.
- Unit: a frozen `SUCCEEDED` boot publishes the admission `TargetSnapshot` (inject an `AdmissionService`,
  assert `_require_snapshot` resolves the target after the frozen boot), the regression guard for the §4
  admission-snapshot dependency.
- Unit: the frozen branch returns the same `artifacts` shape as the normal success branch (console/boot
  log artifacts present), so the artifact list is invariant across frozen/normal success.
- Integration (env-gated, **skipped in CI**, new test in `test_qemu_gdbstub_integration.py`): the
  acceptance scenario end-to-end — boot a `debug_gdbstub` target with `wait_for_debugger=True`, assert
  the boot returns `SUCCEEDED`/`console_status="frozen"` without a readiness wait **and promptly** (well
  under `timeout_seconds`, confirming `virsh start` returns while the vCPU is frozen — the load-bearing
  assumption in §4); `debug.start_session` attaches to the reset-vector CPU; set a breakpoint at an
  early-init symbol (`dcache_init` / `start_kernel`); `debug.continue`; assert the breakpoint is hit and
  an early symbol is inspectable.
  This is the only place the headline acceptance criterion (deterministic early breakpoint) is provable;
  it requires a real QEMU+KVM guest and stays gated behind the existing tool/env guard.
- The env-gated `test_libvirt_boot_integration.py` / `test_qemu_gdbstub_integration.py` stay gated; no
  un-gating.
