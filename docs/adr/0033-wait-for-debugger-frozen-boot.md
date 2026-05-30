# ADR 0033 — wait-for-debugger frozen boot (gdbstub `wait=on`)

**Status:** Accepted (2026-05-30) · **Issue:** #104 · **Epic:** #100 (first-run readiness) ·
**Depends on:** the debug gdbstub boot path (`debug_gdbstub` / `gdbstub_endpoint`) ·
**Affects:** `src/kdive/config.py` (`TargetProfile.wait_for_debugger`,
`BootOverrides.wait_for_debugger`), `src/kdive/providers/libvirt_qemu.py`
(`BootPlan.wait_for_debugger`, `plan_boot` validation, `render_domain_xml` `wait=` selection,
`execute_boot` frozen branch), `src/kdive/server.py` (`target_boot_handler` override
resolution).
Spec: [2026-05-30-wait-for-debugger.md](../specs/2026-05-30-wait-for-debugger.md).

## Context

Debug boot hardcodes `wait=off` on the QEMU gdbstub
(`libvirt_qemu.py` `render_domain_xml`: `tcp:<host>:<port>,server=on,wait=off`). With `wait=off` the
guest CPU free-runs the moment QEMU starts, so by the time `debug.start_session` connects gdb, early
init (`start_kernel` → `vfs_caches_init` → `dcache_init`) has already executed. A breakpoint set after
attach can therefore never fire on the early-boot code paths where bugs like the dcache
`dhash_entries=1` OOB live — making early-boot debugging non-deterministic.

QEMU's gdbstub supports `wait=on`, which blocks the guest vCPU at the reset vector until a debugger
connects. The vCPU does not execute its first instruction until gdb attaches and resumes. That is
exactly the primitive needed for deterministic early-boot breakpoints. The decisions below are the ones
#104 leaves open and that have viable alternatives.

## Decision

### 1. The flag lives on `TargetProfile`, overridable per-run via `BootOverrides`

`wait_for_debugger: bool = False` is added to `TargetProfile` (declarative, beside the existing
`debug_gdbstub` / `gdbstub_endpoint` fields that already shape the gdbstub boot) and a tri-state
`wait_for_debugger: bool | None = None` to `BootOverrides`. The **effective** value is
`override if override is not None else profile_value`, computed in `target_boot_handler` exactly where
`kernel_args` / rootfs overrides are already merged. A standing debug target (e.g. `local-qemu-debug`)
can declare frozen-boot once; an ad-hoc run freezes a single boot without minting a new profile, via the
same `BootOverrides` mechanism that already carries `kernel_args` and rootfs overrides. The tri-state
override mirrors `RootfsOverrides`' existing `None`-means-inherit fields.

### 2. `wait=on` on the gdb device — not `-S`

The frozen-boot mechanism is selecting `wait=on` (vs `wait=off`) in the single existing `qemu:arg`
gdbstub string. `wait=on` blocks **only** the vCPU at the gdbstub and releases it on the first gdb
`continue`, which the debug tier already issues through normal execution control. The QEMU global `-S`
freeze (stop-at-startup, released by a monitor `cont`) was rejected: it freezes the whole machine
independent of the gdbstub, needs an out-of-band QMP/monitor `cont` the debug tier does not own, and
adds a second release path competing with gdb's. `wait=on` keeps a single release authority (the gdb
connection) and reuses the debug tier unchanged.

### 3. A frozen boot skips the readiness wait and returns `SUCCEEDED`-frozen

With `wait=on` the vCPU runs **no** instructions until gdb attaches, so the guest never prints the
readiness marker during `target.boot`. `execute_boot` therefore branches on `plan.wait_for_debugger`:
after `virsh start` succeeds it does **not** call `stream_console` (which would block until
`plan.timeout_seconds` and return `BOOT_TIMEOUT`). It returns `SUCCEEDED` immediately with
`details["console_status"] = "frozen"`, `details["wait_for_debugger"] = True`,
`details["debug_boot"] = True`, and `suggested_next_actions = ["debug.start_session"]`. The frozen VM is
an ordinary gdbstub attach target that happens to sit at the reset vector; no `debug.*` handler changes
are needed. `debug.start_session` already requires `boot_result.details["debug_boot"] is True` and reads
`gdbstub_endpoint` from the boot details — both are present on a frozen boot.

Guest-IP discovery (ADR 0032) is **skipped** on a frozen boot: the vCPU has not run, so no DHCP lease
exists yet. The frozen success records `guest_ip = None` with
`guest_ip_discovery = {"status": "skipped", "source": "lease", "reason": "wait_for_debugger"}`. The IP
becomes discoverable only after `debug.continue` releases the CPU and the guest boots — out of scope for
the boot step, which has already returned.

### 4. `wait_for_debugger=True` requires `debug_gdbstub=True`, enforced at plan time

`wait_for_debugger` is meaningless without a gdbstub to wait on. Because `debug_gdbstub` may come from
the profile while `wait_for_debugger` arrives via a `BootOverrides`, the authoritative cross-field check
lives in `plan_boot` (after the effective `wait_for_debugger` is known), not on the `TargetProfile`
model (which an override would bypass). `plan_boot` raises a `ProviderBootError` →
`CONFIGURATION_ERROR` when `wait_for_debugger` is set without `debug_gdbstub`. `TargetProfile` also
carries a model-level validator for the static-profile case so a malformed profile is rejected at config
load, but the plan-time gate is the contract.

### 5. No new wire model; the frozen facts ride `StepResult.details`

`console_status`, `wait_for_debugger`, and the existing `debug_boot` / `gdbstub_endpoint` /
`guest_ip_discovery` keys all ride the free-form `StepResult.details` dict that already carries provider
boot details, so there is no `domain.py` change and no JSON-schema snapshot to regenerate. `TargetProfile`
and `BootOverrides` are config models (not introspect-helper wire schemas), so adding a defaulted field is
backward-compatible: existing manifests that froze a `TargetProfile` without the field deserialize with
`wait_for_debugger=False`.

## Consequences

- A `local-qemu-debug` boot (or any `debug_gdbstub` target) can be frozen for deterministic early-boot
  breakpoints by setting `wait_for_debugger` on the profile or per-run override; the dcache
  `dhash_entries=1` reproduction becomes deterministic.
- A frozen `target.boot` returns `SUCCEEDED` **without** a running guest. An agent that treats boot
  success as "guest is up and SSH-reachable" must check `details["console_status"]`: `"frozen"` means
  the next action is `debug.start_session`, not `target.run_tests`. The `suggested_next_actions` and the
  `console_status`/`wait_for_debugger` details make this machine-readable.
- A frozen VM that is never attached-to stays blocked at reset, consuming the libvirt domain until the
  run's normal cleanup (`cleanup_policy`) or an explicit teardown reclaims it — the same lifetime a
  non-frozen debug boot's domain has.
- `wait_for_debugger` without `debug_gdbstub` is a configuration error, surfaced at plan time, so the
  flag cannot silently no-op.

## Considered & rejected

1. **Put the flag on `DebugProfile`.** Rejected: `DebugProfile` is consumed by `debug.start_session`,
   which runs *after* boot. The `wait=on` decision must be made when the domain XML is rendered, inside
   `target.boot`, which reads `TargetProfile` / `BootOverrides` and never sees the `DebugProfile`.
   Threading the debug profile into boot just to read one bool would couple the boot step to the debug
   layer it is otherwise independent of.
2. **Use QEMU `-S` (global stop-at-startup) instead of gdbstub `wait=on`.** Rejected (decision 2):
   `-S` needs an out-of-band monitor `cont` to release, introducing a second resume authority alongside
   gdb and an extra QMP dependency the debug tier does not own. `wait=on` confines both the freeze and
   the release to the gdb connection.
3. **Keep waiting for the readiness marker on a frozen boot (with a longer/shorter timeout).** Rejected
   (decision 3): the vCPU executes nothing until gdb resumes, so no marker can ever appear during
   `target.boot`. Any wait is dead time that ends in `BOOT_TIMEOUT`. A frozen boot must short-circuit the
   readiness wait, not tune it.
4. **Return a new non-`SUCCEEDED` boot status (e.g. `FROZEN`) for the wait-for-debugger case.** Rejected:
   `debug.start_session` gates on `boot_result.status == SUCCEEDED` and the manifest step-result state
   machine is `SUCCEEDED`/`FAILED`/`RUNNING`. A frozen boot *did* succeed at what it was asked to do
   (launch the VM frozen and ready for attach); modelling it as a distinct terminal status would force
   every boot consumer and the idempotency short-circuit to learn a fourth state. The frozen-ness is a
   `details` fact (`console_status="frozen"`), not a new status.
5. **Discover the guest IP anyway (best-effort) on a frozen boot.** Rejected (decision 3): the vCPU has
   not run, so there is provably no DHCP lease; polling `virsh domifaddr` would burn the full
   `attempts × (interval + call_timeout)` budget to learn `no_lease` every time. `skipped` with a
   `wait_for_debugger` reason is the honest, zero-cost answer.
